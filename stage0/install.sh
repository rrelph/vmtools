#!/usr/bin/env bash
# stage0/install.sh — boot a libvirt domain from a stage 0 build, exactly as
# its manifest describes it.
#
#   usage: install.sh --build <dir> --domain <name> --org-ca <ca.pub> [--pool images]
#                     [--debug-swap-qemu <path>] [--qemu <path>]
#
# <dir> is build.sh's output. Checks vmlinuz, initrd.img and OVMF.amdsev.fd
# against the manifest, uploads them to the pool as <name>-stage0-vmlinuz,
# <name>-stage0-initrd and <name>-stage0-ovmf, and sets the domain's
# <loader> to that firmware, its <kernel>, <initrd>, kernelHashes='yes' and
# <cmdline>. The firmware is the build's own, the one its measurements were
# computed with: a build without one (made before builds carried their
# firmware) is refused, since nothing here could say which firmware its
# measurement assumes. The command line comes from the manifest
# and nowhere else: it is a measured input that lives in the domain, not in
# the files (Phase 1 findings). The domain's vCPU count must be one the
# manifest has a measurement for; that measurement is printed at the end.
#
# --org-ca is the guest owner's organization CA public key (one ssh-ed25519
# line). The domain gets host_data = SHA-256 of its wire-format blob (design
# section 9) and the key itself as fw_cfg entry opt/org.vmtrust/org-ca.pub.
# Stage 0 refuses to start sshd unless the two agree, and the owner's tool
# checks host_data against its own copy of the key.
#
# The SEV features a guest launches with are a measured input too, and QEMU
# sets them, so the domain's QEMU follows the manifest's guest.features.
# Stage 0 starts the guest's own kernel by kexec, which needs DebugSwap
# (0x20); no QEMU release can set it yet, so a build with it boots the
# guest on --debug-swap-qemu, a QEMU built to set it when the environment
# variable QEMU_SEV_DEBUG_SWAP is 1, which the domain then passes
# (<qemu:env>). A build without it boots on --qemu (default
# /usr/bin/qemu-system-x86_64), without the variable: rolling a guest back
# to an older build puts it back on the QEMU that build was measured for.
#
# A guest's reboot must end its QEMU, so that what comes back is a fresh
# launch: <on_reboot>destroy</on_reboot>, whatever the build. QEMU 10.2.1
# cannot reset an SNP guest and stops anyway; QEMU master resets it in
# place, and the launch measurement after that reset (on an EPYC Milan
# host, 2026-10-09) matched none of the build's, so no owner's tool would
# accept it. The stop is a guest shutdown to libvirt, which the host's
# supervisor relaunches.
#
# Run as a user who can use virsh on the system connection, or set
# VIRSH="sudo -n virsh". The change takes effect at the domain's next start;
# a running domain is not touched (cvm finalize relies on this, Phase 4).

set -euo pipefail

die() { echo "install.sh: $*" >&2; exit 1; }

BUILD="" DOMAIN="" POOL=images ORG_CA="" DS_QEMU="" QEMU=/usr/bin/qemu-system-x86_64
while [ $# -gt 0 ]; do
    case "$1" in
        --build)  BUILD="$2"; shift 2 ;;
        --domain) DOMAIN="$2"; shift 2 ;;
        --pool)   POOL="$2"; shift 2 ;;
        --org-ca) ORG_CA="$2"; shift 2 ;;
        --debug-swap-qemu) DS_QEMU="$2"; shift 2 ;;
        --qemu)   QEMU="$2"; shift 2 ;;
        *) die "unknown argument: $1" ;;
    esac
done
[ -n "$BUILD" ] && [ -n "$DOMAIN" ] && [ -n "$ORG_CA" ] \
    || die "usage: install.sh --build <dir> --domain <name> --org-ca <ca.pub> [--pool images] [--debug-swap-qemu <path>] [--qemu <path>]"
M="$BUILD/manifest"
[ -r "$M" ] || die "no manifest in $BUILD"
read -ra V <<< "${VIRSH:-virsh}"
V+=(-c qemu:///system)

# get <key>: the value of one manifest line; exactly one must exist.
get() {
    local n
    n="$(grep -c "^$1 " "$M" || true)"
    [ "$n" = 1 ] || die "manifest: expected one '$1' line, found $n"
    grep "^$1 " "$M" | cut -d' ' -f2-
}
[ "$(get format)" = 1 ] || die "manifest: unknown format"
CMDLINE="$(get cmdline)"
grep -q '^ovmf\.file ' "$M" \
    || die "$BUILD predates builds that carry their firmware (its manifest has no ovmf.file): make a new build"
features="$(get guest.features)"
[[ "$features" =~ ^0x[0-9a-fA-F]+$ ]] || die "manifest: guest.features is not a hex number: $features"
# Which QEMU, and whether it is told to set DebugSwap.
if (( features & 0x20 )); then
    DS=1
    [ -n "$DS_QEMU" ] || die "$BUILD's guest features ($features) include DebugSwap: give --debug-swap-qemu"
    EMU="$DS_QEMU"
else
    DS=0
    EMU="$QEMU"
fi
[ -x "$EMU" ] || die "QEMU not found or not executable: $EMU"

for part in kernel initrd ovmf; do
    f="$BUILD/$(get "$part.file")"
    [ "$(sha256sum < "$f" | cut -d' ' -f1)" = "$(get "$part.sha256")" ] \
        || die "$f does not match the manifest"
done

# --- the org CA: one ssh-ed25519 key, its wire blob, and host_data ---
[ -r "$ORG_CA" ] || die "--org-ca: not readable: $ORG_CA"
[ "$(grep -c . "$ORG_CA")" = 1 ] || die "--org-ca: expected exactly one public key line"
read -r ca_type ca_b64 _ < "$ORG_CA"
[ "$ca_type" = ssh-ed25519 ] || die "--org-ca: not an ssh-ed25519 key"
blob="$(mktemp)"
trap 'rm -f "$blob"' EXIT
printf '%s' "$ca_b64" | base64 -d > "$blob" 2>/dev/null || die "--org-ca: the key is not valid base64"
# string "ssh-ed25519", then a 32-byte string: 51 bytes in all.
[ "$(stat -c %s "$blob")" = 51 ] || die "--org-ca: the key blob is not an Ed25519 key"
host_data_hex="$(sha256sum < "$blob" | cut -d' ' -f1)"
# 32 bytes, base64, as libvirt's <hostData> takes them.
host_data_b64="$(printf "$(printf '%s' "$host_data_hex" | sed 's/../\\x&/g')" | base64 -w0)"
CA_LINE="ssh-ed25519 $ca_b64"

xml="$(mktemp)"
trap 'rm -f "$xml" "$xml.new" "$blob"' EXIT
"${V[@]}" dumpxml --inactive "$DOMAIN" > "$xml"
vcpus="$(sed -n "s|.*<vcpu[^>]*>\([0-9]*\)</vcpu>.*|\1|p" "$xml")"
[ -n "$vcpus" ] || die "cannot read the vCPU count of $DOMAIN"
MEASUREMENT="$(get "measurement.vcpus.$vcpus")"

# --- upload ---
declare -A path
for part in kernel initrd ovmf; do
    f="$BUILD/$(get "$part.file")"
    case "$part" in kernel) vol=vmlinuz ;; *) vol="$part" ;; esac
    vol="$DOMAIN-stage0-$vol"
    "${V[@]}" vol-delete --pool "$POOL" "$vol" >/dev/null 2>&1 || true
    if [ "$part" = ovmf ]; then
        # World-readable: libvirt hands the kernel and initrd to QEMU's user
        # when the domain starts, but not the <loader>, which it expects to
        # be readable already (as /usr/share/ovmf is). A 0600 volume left
        # QEMU with "could not load PC BIOS" (2026-10-09). The
        # firmware is Ubuntu's, public, and checked against the manifest.
        volxml="$(mktemp)"
        printf '<volume><name>%s</name><capacity unit="bytes">%s</capacity><target><format type="raw"/><permissions><mode>0644</mode></permissions></target></volume>\n' \
            "$vol" "$(stat -c %s "$f")" > "$volxml"
        "${V[@]}" vol-create "$POOL" "$volxml" >/dev/null
        rm -f "$volxml"
    else
        "${V[@]}" vol-create-as "$POOL" "$vol" "$(stat -c %s "$f")" --format raw >/dev/null
    fi
    "${V[@]}" vol-upload --pool "$POOL" "$vol" "$f" >/dev/null   # it prints an empty line
    path[$part]="$("${V[@]}" vol-path --pool "$POOL" "$vol")"
done

# --- the domain ---
# XML text, escaped: the command line is the only value that could hold one.
esc() { sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g'; }
cmd_xml="$(printf '%s' "$CMDLINE" | esc)"
[ "$(grep -c '<loader' "$xml")" = 1 ] || die "$DOMAIN: expected exactly one <loader> line"
[ "$(grep -c '<loader[^>]*>[^<]*</loader>' "$xml")" = 1 ] \
    || die "$DOMAIN: expected its <loader> element on one line, with its path"
[ "$(grep -c "<launchSecurity type='sev-snp'" "$xml")" = 1 ] \
    || die "$DOMAIN: expected exactly one sev-snp <launchSecurity> line"
[ "$(grep -c '^[[:space:]]*<emulator>[^<]*</emulator>[[:space:]]*$' "$xml")" = 1 ] \
    || die "$DOMAIN: expected exactly one <emulator> line"
[ "$(grep -c '^[[:space:]]*<on_reboot>[a-z-]*</on_reboot>[[:space:]]*$' "$xml")" = 1 ] \
    || die "$DOMAIN: expected exactly one <on_reboot> line"
[ "$(grep -c '^<domain[ >]' "$xml")" = 1 ] || die "$DOMAIN: expected exactly one <domain> line"
emu_xml="$(printf '%s' "$EMU" | esc)"
QNS='http://libvirt.org/schemas/domain/qemu/1.0'
# Point the loader at the build's firmware, keeping its attributes. Drop any
# kernel, initrd and cmdline, then put the manifest's in after the loader.
# awk passes the values through ENVIRON, so nothing in them is code. The same
# for any earlier hostData and fw_cfg block: put the new ones in, host_data
# inside launchSecurity, the fw_cfg entry before <os>. The same for the
# emulator and the DebugSwap variable: drop the variable (and a
# <qemu:commandline> it leaves empty), then put it back if the build has
# DebugSwap, with the qemu namespace it needs on <domain>.
L="${path[ovmf]}" K="${path[kernel]}" I="${path[initrd]}" C="$cmd_xml" H="$host_data_b64" F="$CA_LINE" \
E="$emu_xml" D="$DS" N="$QNS" awk '
    held != "" {
        if (/^[[:space:]]*<qemu:env name=.QEMU_SEV_DEBUG_SWAP. /) next
        if (/^[[:space:]]*<\/qemu:commandline>[[:space:]]*$/) { held = ""; next }
        print held; held = ""
    }
    /^[[:space:]]*<qemu:env name=.QEMU_SEV_DEBUG_SWAP. / { next }
    /^[[:space:]]*<qemu:commandline>[[:space:]]*$/ { held = $0; next }
    /^<domain[ >]/ && ENVIRON["D"] == 1 && index($0, "xmlns:qemu=") == 0 {
        sub(/>[[:space:]]*$/, " xmlns:qemu=\047" ENVIRON["N"] "\047>")
    }
    /^<\/domain>/ && ENVIRON["D"] == 1 {
        print "  <qemu:commandline>"
        print "    <qemu:env name=\047QEMU_SEV_DEBUG_SWAP\047 value=\0471\047/>"
        print "  </qemu:commandline>"
    }
    /^[[:space:]]*<on_reboot>/ { sub(/<on_reboot>[a-z-]*</, "<on_reboot>destroy<") }
    /^[[:space:]]*<emulator>/ {
        i = index($0, ">"); j = index($0, "</emulator>")
        $0 = substr($0, 1, i) ENVIRON["E"] substr($0, j)
    }
    /<loader/ {
        i = index($0, ">"); j = index($0, "</loader>")
        $0 = substr($0, 1, i) ENVIRON["L"] substr($0, j)
    }
    /^[[:space:]]*<(kernel|initrd|cmdline)>.*<\/(kernel|initrd|cmdline)>[[:space:]]*$/ { next }
    /^[[:space:]]*<hostData>.*<\/hostData>[[:space:]]*$/ { next }
    /<sysinfo type=.fwcfg.>/ { skip = 1 }
    skip { if (/<\/sysinfo>/) skip = 0; next }
    /^[[:space:]]*<os[ >]/ {
        print "  <sysinfo type=\047fwcfg\047>"
        print "    <entry name=\047opt/org.vmtrust/org-ca.pub\047>" ENVIRON["F"] "</entry>"
        print "  </sysinfo>"
    }
    { print }
    /<loader/ {
        print "    <kernel>" ENVIRON["K"] "</kernel>"
        print "    <initrd>" ENVIRON["I"] "</initrd>"
        print "    <cmdline>" ENVIRON["C"] "</cmdline>"
    }
    /<launchSecurity type=.sev-snp./ { print "    <hostData>" ENVIRON["H"] "</hostData>" }' "$xml" \
  | sed "s|<launchSecurity type='sev-snp'[^>]*>|<launchSecurity type='sev-snp' kernelHashes='yes'>|" > "$xml.new"
"${V[@]}" define "$xml.new" >/dev/null

# Read it back: what libvirt holds is what gets measured.
"${V[@]}" dumpxml --inactive "$DOMAIN" > "$xml"
got="$(sed -n 's|.*<cmdline>\(.*\)</cmdline>.*|\1|p' "$xml")"
[ "$got" = "$cmd_xml" ] || die "$DOMAIN's command line is not the manifest's after define"
grep -q "kernelHashes='yes'" "$xml" || die "$DOMAIN has no kernelHashes='yes' after define"
grep -qF "<hostData>$host_data_b64</hostData>" "$xml" || die "$DOMAIN's host_data is not the org CA's after define"
grep -qF "<entry name='opt/org.vmtrust/org-ca.pub'>$CA_LINE</entry>" "$xml" \
    || die "$DOMAIN's fw_cfg org CA is not the one given after define"
grep -qF "<emulator>$emu_xml</emulator>" "$xml" || die "$DOMAIN's <emulator> is not $EMU after define"
grep -q '<on_reboot>destroy</on_reboot>' "$xml" || die "$DOMAIN's <on_reboot> is not destroy after define"
n="$(grep -c "<qemu:env name='QEMU_SEV_DEBUG_SWAP' value='1'/>" "$xml" || true)"
[ "$n" = "$DS" ] || die "$DOMAIN has $n QEMU_SEV_DEBUG_SWAP settings after define; its build wants $DS"
for part in kernel initrd; do
    grep -qF "<$part>${path[$part]}</$part>" "$xml" || die "$DOMAIN's <$part> is not ${path[$part]} after define"
done
[ "$(sed -n 's|.*<loader[^>]*>\([^<]*\)</loader>.*|\1|p' "$xml")" = "${path[ovmf]}" ] \
    || die "$DOMAIN's <loader> is not ${path[ovmf]} after define"

echo "$DOMAIN: stage 0 from $BUILD, $vcpus vCPUs"
echo "host_data $host_data_hex (org CA $CA_LINE)"
echo "qemu $EMU, guest features $features"
echo "measurement $MEASUREMENT"
