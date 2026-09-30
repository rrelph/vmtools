#!/usr/bin/env bash
# stage0/install.sh — boot a libvirt domain from a stage 0 build, exactly as
# its manifest describes it.
#
#   usage: install.sh --build <dir> --domain <name> --org-ca <ca.pub> [--pool images]
#
# <dir> is build.sh's output. Checks vmlinuz and initrd.img against the
# manifest, uploads them to the pool as <name>-stage0-vmlinuz and
# <name>-stage0-initrd, and sets the domain's <kernel>, <initrd>,
# kernelHashes='yes' and <cmdline>. The command line comes from the manifest
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
# Run as a user who can use virsh on the system connection, or set
# VIRSH="sudo -n virsh". The change takes effect at the domain's next start;
# a running domain is not touched (cvm finalize relies on this, Phase 4).

set -euo pipefail

die() { echo "install.sh: $*" >&2; exit 1; }

BUILD="" DOMAIN="" POOL=images ORG_CA=""
while [ $# -gt 0 ]; do
    case "$1" in
        --build)  BUILD="$2"; shift 2 ;;
        --domain) DOMAIN="$2"; shift 2 ;;
        --pool)   POOL="$2"; shift 2 ;;
        --org-ca) ORG_CA="$2"; shift 2 ;;
        *) die "unknown argument: $1" ;;
    esac
done
[ -n "$BUILD" ] && [ -n "$DOMAIN" ] && [ -n "$ORG_CA" ] \
    || die "usage: install.sh --build <dir> --domain <name> --org-ca <ca.pub> [--pool images]"
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

for part in kernel initrd; do
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
for part in kernel initrd; do
    f="$BUILD/$(get "$part.file")"
    vol="$DOMAIN-stage0-$([ "$part" = kernel ] && echo vmlinuz || echo initrd)"
    "${V[@]}" vol-delete --pool "$POOL" "$vol" >/dev/null 2>&1 || true
    "${V[@]}" vol-create-as "$POOL" "$vol" "$(stat -c %s "$f")" --format raw >/dev/null
    "${V[@]}" vol-upload --pool "$POOL" "$vol" "$f" >/dev/null   # it prints an empty line
    path[$part]="$("${V[@]}" vol-path --pool "$POOL" "$vol")"
done

# --- the domain ---
# XML text, escaped: the command line is the only value that could hold one.
esc() { sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g'; }
cmd_xml="$(printf '%s' "$CMDLINE" | esc)"
[ "$(grep -c '<loader' "$xml")" = 1 ] || die "$DOMAIN: expected exactly one <loader> line"
[ "$(grep -c "<launchSecurity type='sev-snp'" "$xml")" = 1 ] \
    || die "$DOMAIN: expected exactly one sev-snp <launchSecurity> line"
# Drop any kernel, initrd and cmdline, then put the manifest's in after the
# loader. awk passes the values through ENVIRON, so nothing in them is code.
# The same for any earlier hostData and fw_cfg block: put the new ones in,
# host_data inside launchSecurity, the fw_cfg entry before <os>.
K="${path[kernel]}" I="${path[initrd]}" C="$cmd_xml" H="$host_data_b64" F="$CA_LINE" awk '
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
for part in kernel initrd; do
    grep -qF "<$part>${path[$part]}</$part>" "$xml" || die "$DOMAIN's <$part> is not ${path[$part]} after define"
done

echo "$DOMAIN: stage 0 from $BUILD, $vcpus vCPUs"
echo "host_data $host_data_hex (org CA $CA_LINE)"
echo "measurement $MEASUREMENT"
