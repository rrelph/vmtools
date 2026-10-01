#!/usr/bin/env bash
# stage0/build.sh — build stage 0: kernel, initrd and command line for
# measured direct boot (design/attested-unlock-design.md, sections 5 and 6).
#
#   usage: build.sh --ovmf <OVMF.fd> --out <dir>
#                   [--vcpus 4[,8,...]] [--kernel <version>]
#
# Writes <dir>/vmlinuz, <dir>/initrd.img and <dir>/manifest. The manifest is
# the one record of the build: the files and their digests, the command line,
# the package versions, and the launch measurement a guest booted from it must
# report, per vCPU count. install.sh takes the command line from it; nothing
# else should keep a copy.
#
# Runs unprivileged on an Ubuntu 26.04 x86_64 machine with initramfs-tools-core,
# 3cpio, busybox-initramfs, klibc-utils, kmod, dhcpcd-base, openssh-server,
# cryptsetup-bin, lvm2, linux-modules-<kernel> and cargo installed (Milan has
# them), and sev-snp-measure on PATH or in ~/.local/bin. sev-snp-measure is
# Python and is used here only to compute the expected measurement, which the
# guest owner's own check then confirms or refuses. It must be the Python
# original, not this repository's Rust port (attest/sev-snp-measure): the
# published measurement comes from the original, and owners check it with the
# port and, if they choose, the original.
#
# - The agent is built here, from this repository's attest/, with
#   cargo --locked and every build path remapped (--remap-path-prefix), so the
#   binary does not depend on who builds it or where.
# - The kernel comes from the signed linux-image package, fetched with
#   apt-get download, not from the build host's /boot.
# - mkinitramfs runs from a private copy of initramfs-tools holding only
#   initramfs-tools-core's own files and four hooks (busybox, klibc, kmod,
#   dhcpcd), with its hard-coded /usr/share/initramfs-tools and host
#   modprobe.d paths rewritten to that copy and to an empty directory.
#   Nothing else the host has installed gets in. No namespaces, no root:
#   Ubuntu restricts unprivileged user namespaces by default.
# - SOURCE_DATE_EPOCH is fixed, so two builds from the same packages should
#   produce the same bytes (checked in Phase 1; see the findings).
#
# No organization's key is in the image: stage 0 reads the org CA from fw_cfg
# and checks it against host_data at boot (install.sh --org-ca sets both), so
# one build serves every guest.

set -euo pipefail

die() { echo "build.sh: $*" >&2; exit 1; }
umask 022
# Sorting, in the manifest and inside mkinitramfs, must not depend on who runs
# this (Phase 2: two locales, two orders).
export LC_ALL=C

KVER=7.0.0-34-generic
VCPU_TYPE=EPYC-Milan
OUT="" OVMF="" VCPUS=4
while [ $# -gt 0 ]; do
    case "$1" in
        --ovmf)   OVMF="$(realpath "$2")"; shift 2 ;;
        --out)    OUT="$2"; shift 2 ;;
        --vcpus)  VCPUS="$2"; shift 2 ;;
        --kernel) KVER="$2"; shift 2 ;;
        *) die "unknown argument: $1" ;;
    esac
done
[ -r "$OVMF" ] || die "--ovmf: not readable: $OVMF"
[ -n "$OUT" ] || die "--out is required"
[[ "$VCPUS" =~ ^[1-9][0-9]*(,[1-9][0-9]*)*$ ]] || die "--vcpus: a comma-separated list of counts"
MEASURE="$(command -v sev-snp-measure || echo "$HOME/.local/bin/sev-snp-measure")"
[ -x "$MEASURE" ] || die "sev-snp-measure not found; the manifest needs the expected measurement"
# The original prints exactly "sev-snp-measure X.Y.Z"; the port adds its own
# version and "(Rust port of sev-snp-measure X.Y.Z)", and is refused.
MEASURE_VERSION="$("$MEASURE" --version 2>/dev/null || true)"
[[ "$MEASURE_VERSION" =~ ^sev-snp-measure\ ([0-9]+\.[0-9]+\.[0-9]+)$ ]] \
    || die "$MEASURE is not the Python sev-snp-measure (--version printed: ${MEASURE_VERSION:-nothing})"
MEASURE_VERSION="${BASH_REMATCH[1]}"
command -v cargo >/dev/null || die "cargo not found; it builds the agent"

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/.." && pwd)"
# The vmtools commit this build is from, for the manifest. A build meant for
# guests is made from a clean checkout at the commit vmtrust pins; a tree with
# uncommitted changes to tracked files is recorded as such, never as the commit.
git -C "$REPO" rev-parse --verify -q HEAD >/dev/null \
    || die "$REPO is not a git checkout of vmtools; the manifest records its commit"
SRC_COMMIT="$(git -C "$REPO" rev-parse HEAD)"
[ -z "$(git -C "$REPO" status --porcelain --untracked-files=no)" ] || SRC_COMMIT="$SRC_COMMIT+changes"
SHARE=/usr/share/initramfs-tools
# 2026-09-28T00:00:00Z. Changing it changes the initrd, and so the measurement.
export SOURCE_DATE_EPOCH=1790553600

# The modules come from the host's /lib/modules, so they must be the same
# build as the kernel package.
kpkg="$(dpkg-query -W -f='${Version}' "linux-modules-$KVER" 2>/dev/null)" \
    || die "linux-modules-$KVER is not installed"

mkdir -p "$OUT"
OUT="$(realpath "$OUT")"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# --- the agent, with no path of this machine in it ---
# Rust embeds source paths (in panic messages, for one): the cargo registry's,
# this checkout's and the target directory's. Each is mapped to a fixed name.
# CARGO_ENCODED_RUSTFLAGS takes one flag per 0x1f-separated field, so a path
# with a space in it cannot split a flag.
CARGO_HOME_DIR="${CARGO_HOME:-$HOME/.cargo}"
US=$'\x1f'
# The checkout maps to /vmtrust, its name before vmtools was split out of
# vmtrust: the name is compiled into the agent, so renaming it would change
# every measurement for nothing.
export CARGO_ENCODED_RUSTFLAGS="--remap-path-prefix=$CARGO_HOME_DIR/registry/src=/cargo/registry/src${US}--remap-path-prefix=$REPO=/vmtrust${US}--remap-path-prefix=$WORK=/build"
cargo build --quiet --release --locked --manifest-path "$REPO/attest/Cargo.toml" \
    -p stage0-agent --target-dir "$WORK/target"
unset CARGO_ENCODED_RUSTFLAGS
AGENT="$WORK/target/release/stage0-agent"
if grep -aqF -e "$HOME" -e "$REPO" -e "$WORK" "$AGENT"; then
    die "the agent still contains a path of this machine"
fi

# --- kernel, from the signed package ---
( cd "$WORK" && apt-get download -q "linux-image-$KVER=$kpkg" >/dev/null )
# Where the package sits in Ubuntu's archive, relative to any mirror, so a
# guest owner can fetch the same file (the measurement guide).
kdeb_path="$(apt-get download --print-uris "linux-image-$KVER=$kpkg" | sed -n "s|^'[^']*/ubuntu/\\(pool/[^']*\\)'.*|\\1|p")"
[ -n "$kdeb_path" ] || die "no archive path for linux-image-$KVER=$kpkg"

# The firmware: the manifest names Ubuntu's package and version for it when
# --ovmf is byte-identical to that package's file, so a guest owner can fetch
# it from Ubuntu's archive too.
ovmf_lines=""
sys_fw="/usr/share/ovmf/$(basename "$OVMF")"
if [ -f "$sys_fw" ] && cmp -s "$OVMF" "$sys_fw"; then
    fw_pkg="$(dpkg -S "$sys_fw" 2>/dev/null | cut -d: -f1)"
    fw_ver="$(dpkg-query -W -f='${Version}' "$fw_pkg")"
    ( cd "$WORK" && apt-get download -q "$fw_pkg=$fw_ver" >/dev/null )
    fw_deb=("$WORK"/"$fw_pkg"_*.deb)
    [ -f "${fw_deb[0]}" ] || die "apt-get download produced no $fw_pkg package"
    fw_path="$(apt-get download --print-uris "$fw_pkg=$fw_ver" | sed -n "s|^'[^']*/ubuntu/\\(pool/[^']*\\)'.*|\\1|p")"
    ovmf_lines="ovmf.package $fw_pkg $fw_ver
ovmf.deb.path $fw_path
ovmf.deb.sha256 $(sha256sum < "${fw_deb[0]}" | cut -d' ' -f1)"
fi
deb=("$WORK"/linux-image-"$KVER"_*.deb)
[ -f "${deb[0]}" ] || die "apt-get download produced no linux-image-$KVER package"
dpkg-deb --fsys-tarfile "${deb[0]}" | tar -x -C "$WORK" "./boot/vmlinuz-$KVER"
install -m 0644 "$WORK/boot/vmlinuz-$KVER" "$OUT/vmlinuz"

# --- a controlled copy of initramfs-tools ---
S="$WORK/share"
E="$WORK/empty"
mkdir -p "$S/hooks" "$S/scripts" "$S/conf.d" "$S/conf-hooks.d" "$S/modules.d" "$E"
cp -a "$SHARE/init" "$SHARE/hook-functions" "$SHARE/modules" "$SHARE/dhcpcd-hooks" "$S/"
cp -a "$SHARE/scripts/functions" "$SHARE/scripts/local" "$SHARE/scripts/nfs" "$S/scripts/"
for h in zz-busybox-initramfs klibc-utils kmod dhcpcd; do
    cp -a "$SHARE/hooks/$h" "$S/hooks/"
done
# BUSYBOXDIR, which mkinitramfs requires when BUSYBOX=y.
cp -a "$SHARE/conf-hooks.d/busybox-initramfs" "$S/conf-hooks.d/"
cp -a /usr/sbin/mkinitramfs "$S/mkinitramfs"

C="$WORK/conf"
cp -a "$HERE/initramfs" "$C"
mkdir -p "$C/conf.d"
# Modes come from the checkout, and so from the umask of whoever made it
# (Phase 2: 664 in one build, 644 in another). Set them.
find "$C" -type d -exec chmod 0755 {} +
find "$C" -type f -exec chmod 0644 {} +
chmod 0755 "$C"/hooks/* "$C"/scripts/*/* "$C/wait-for-root"

# rewrite <file> <from> <to>: literal, and the text must be there, so a
# change in initramfs-tools stops the build instead of quietly letting the
# host's files back in. None of the strings contains '|'.
rewrite() {
    grep -qF -- "$2" "$1" || die "rewrite: '$2' not found in ${1#"$WORK"/}"
    sed -i "s|$(printf '%s' "$2" | sed 's/[.*^$[\\]/\\&/g')|$3|g" "$1"
}
for f in "$S/mkinitramfs" "$S/hook-functions" "$S/hooks/zz-busybox-initramfs" \
         "$S/hooks/kmod" "$S/hooks/dhcpcd" "$C/hooks/stage0"; do
    rewrite "$f" /usr/share/initramfs-tools "$S"
done
# The host's modprobe configuration stays out: sources only, never the
# destination paths inside the image.
rewrite "$S/mkinitramfs" '/etc/modprobe.d/*.conf /lib/modprobe.d/*.conf' "$E/*.conf"
rewrite "$S/hooks/kmod" 'echo /usr/lib/modprobe.d/*)" != "/usr/lib/modprobe.d/*"' "echo $E/*)\" != \"$E/*\""
rewrite "$S/hooks/kmod" 'cp -aZ /usr/lib/modprobe.d/*' "cp -aZ $E/*"
# mkinitramfs copies /etc/ld.so.conf* keeping the host's timestamps, and
# SOURCE_DATE_EPOCH only clamps times newer than itself: an older directory
# time on one host made two otherwise identical images differ (Phase 2).
rewrite "$S/mkinitramfs" 'cp -pPr /etc/ld.so.conf* "$DESTDIR"/etc/' 'cp -PR /etc/ld.so.conf* "$DESTDIR"/etc/'
if grep -qF /usr/share/initramfs-tools "$S/mkinitramfs" "$S/hook-functions" "$S"/hooks/* "$C/hooks/stage0"; then
    die "a /usr/share/initramfs-tools path survived the rewrite"
fi

# As an ordinary user, cp -p skips ownership and mkinitramfs writes uid/gid 0
# into the archive itself.
export STAGE0_AGENT="$AGENT"
sh "$S/mkinitramfs" -d "$C" -o "$OUT/initrd.img" "$KVER"

# --- the manifest ---
# One "key value" line each; the value is the rest of the line. Read it with
# grep and cut, never by sourcing it.
CMDLINE="$(cat "$HERE/cmdline")"
sha() { sha256sum < "$1" | cut -d' ' -f1; }
ver() { dpkg-query -W -f='${Version}' "$1"; }
M="$OUT/manifest"
{
    echo "# stage 0 build manifest (stage0/build.sh). Values run to the end of the line."
    echo "format 1"
    echo "source.commit $SRC_COMMIT"
    echo "kernel.file vmlinuz"
    echo "kernel.sha256 $(sha "$OUT/vmlinuz")"
    echo "kernel.package linux-image-$KVER $kpkg"
    echo "kernel.deb.sha256 $(sha "${deb[0]}")"
    echo "kernel.deb.path $kdeb_path"
    echo "initrd.file initrd.img"
    echo "initrd.sha256 $(sha "$OUT/initrd.img")"
    echo "initramfs-tools.package initramfs-tools-core $(ver initramfs-tools-core)"
    echo "cmdline $CMDLINE"
    echo "ovmf.sha256 $(sha "$OVMF")"
    [ -z "$ovmf_lines" ] || printf '%s\n' "$ovmf_lines"
    echo "vcpu.type $VCPU_TYPE"
    for n in ${VCPUS//,/ }; do
        m="$("$MEASURE" --mode snp --vcpus "$n" --vcpu-type "$VCPU_TYPE" --ovmf "$OVMF" \
             --kernel "$OUT/vmlinuz" --initrd "$OUT/initrd.img" --append "$CMDLINE")"
        [[ "$m" =~ ^[0-9a-f]{96}$ ]] || die "sev-snp-measure gave no measurement for $n vCPUs"
        echo "measurement.vcpus.$n $m"
    done
    echo "measurement.tool sev-snp-measure $MEASURE_VERSION"
    echo "agent.sha256 $(sha "$AGENT")"
    echo "agent.rustc $(rustc -V)"
    echo "source-date-epoch $SOURCE_DATE_EPOCH"
    # Every package that put a file in the image, at the version it was: the
    # image is assembled from the build host's installed packages, so two
    # hosts reproduce it only when these lines are identical.
    # A file counts only if the image's copy is byte for byte the host's:
    # busybox applet links, for one, share names with other packages' files.
    X="$WORK/unpacked"
    mkdir -p "$X"
    unmkinitramfs "$OUT/initrd.img" "$X" >/dev/null
    ( cd "$X" && find . -type f ) | sed 's|^\./||' | while read -r f; do
        [ -f "/$f" ] && cmp -s "$X/$f" "/$f" || continue
        # dpkg knows usr-merged files by either spelling.
        dpkg -S "/$f" 2>/dev/null || dpkg -S "/${f#usr/}" 2>/dev/null || true
    done | cut -d: -f1 | tr ',' '\n' | sed 's/^ *//' | sort -u | while read -r p; do
        echo "package $p $(ver "$p")"
    done
} > "$M"
cat "$M"
