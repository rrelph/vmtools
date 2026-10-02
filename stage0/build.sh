#!/usr/bin/env bash
# stage0/build.sh — build stage 0 from Ubuntu's archive alone.
#
#   usage: sudo build.sh --ovmf <OVMF.fd> --out <dir>
#                        [--vcpus 4[,8,...]] [--kernel <version>]
#                        [--snapshot <YYYYMMDDTHHMMSSZ>] [--allow-changes]
#
# Makes a throwaway Ubuntu 26.04 root from Ubuntu's archive as it was at one
# moment (snapshot.ubuntu.com; --snapshot, default now), puts this checkout's
# commit in it, and runs image.sh there as an unprivileged user. Everything
# the image is made of, and every tool that assembles, compresses and
# measures it, the agent's compiler included, comes from that root: nothing
# the build host has installed reaches stage 0, so updating or rebooting the
# host never changes what guests run, and the host need not be updated to
# rebuild. The manifest records the snapshot; with the commit, the kernel and
# the firmware, that is all a rebuild of the same bytes needs, on any machine
# with mmdebstrap.
#
# Writes <dir>/vmlinuz, <dir>/initrd.img and <dir>/manifest (image.sh says
# what they hold), owned by the user who ran sudo.
#
# Needs root, for mmdebstrap's root mode and the chroot: Ubuntu restricts
# unprivileged user namespaces by default. Needs mmdebstrap and the build
# host's Ubuntu archive keyring, which checks the snapshot's signatures; the
# root's own keyring checks them from then on. Network: the snapshot, and
# crates.io for the agent's locked dependencies.
#
# --allow-changes builds a checkout with uncommitted changes to tracked files,
# for development; the manifest then names the commit followed by +changes,
# and such a build is never for guests.

set -euo pipefail

die() { echo "build.sh: $*" >&2; exit 1; }
umask 022
export LC_ALL=C

KVER=7.0.0-34-generic
OUT="" OVMF="" VCPUS=4 SNAPSHOT="" CHANGES=0
while [ $# -gt 0 ]; do
    # Every option but --allow-changes takes a value. A pasted command that
    # wrapped between an option and its value leaves the option last, or
    # followed by another option: say so, not "unbound variable".
    case "$1" in
        --ovmf|--out|--vcpus|--kernel|--snapshot)
            [ $# -ge 2 ] && [ -n "$2" ] && [ "${2#--}" = "$2" ] \
                || die "$1 needs a value (if you pasted this command, check it was not split across lines)" ;;
    esac
    case "$1" in
        --ovmf)          OVMF="$(realpath "$2")"; shift 2 ;;
        --out)           OUT="$2"; shift 2 ;;
        --vcpus)         VCPUS="$2"; shift 2 ;;
        --kernel)        KVER="$2"; shift 2 ;;
        --snapshot)      SNAPSHOT="$2"; shift 2 ;;
        --allow-changes) CHANGES=1; shift ;;
        *) die "unknown argument: $1" ;;
    esac
done
[ "$(id -u)" = 0 ] || die "run with sudo: it makes and enters the build root (the image itself is built inside as an unprivileged user)"
[ -r "$OVMF" ] || die "--ovmf: not readable: $OVMF"
[ "$(basename "$OVMF")" = OVMF.amdsev.fd ] || die "--ovmf: expected a file named OVMF.amdsev.fd, ovmf-amdsev's"
[ -n "$OUT" ] || die "--out is required"
[[ "$VCPUS" =~ ^[1-9][0-9]*(,[1-9][0-9]*)*$ ]] || die "--vcpus: a comma-separated list of counts"
[[ "$KVER" =~ ^[0-9]+\.[0-9]+\.[0-9]+-[0-9]+-generic$ ]] || die "--kernel: a release such as 7.0.0-34-generic"
: "${SNAPSHOT:=$(date -u +%Y%m%dT%H%M%SZ)}"
[[ "$SNAPSHOT" =~ ^[0-9]{8}T[0-9]{6}Z$ ]] || die "--snapshot: a UTC time such as 20261002T120000Z"
command -v mmdebstrap >/dev/null || die "mmdebstrap not found (apt install mmdebstrap)"
# Nothing here reads the terminal, and nothing may: run from a terminal,
# mmdebstrap's apt touched it from a background process group at its install
# stage and the kernel stopped it (state T), silently and for good (Milan,
# 2026-10-02). Input from /dev/null from here on; sudo has already asked for
# its password.
exec </dev/null

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/.." && pwd)"
# The checkout is the operator's and this runs as root: git refuses another
# user's repository unless told this one is expected.
g() { git -c safe.directory="$REPO" -C "$REPO" "$@"; }
g rev-parse --verify -q HEAD >/dev/null || die "$REPO is not a git checkout of vmtools"
COMMIT="$(g rev-parse HEAD)"
if [ -n "$(g status --porcelain --untracked-files=no)" ] && [ "$CHANGES" = 0 ]; then
    die "$REPO has uncommitted changes to tracked files: commit them, or pass --allow-changes for a development build (never for guests)"
fi
# Whose the output is: the operator who ran sudo, not root.
OWNER="${SUDO_UID:-0}:${SUDO_GID:-0}"

# A new output directory is the operator's too, like the files in it: the
# runbook retires old builds with a plain rm -r.
[ -d "$OUT" ] || install -d -m 0755 -o "${OWNER%:*}" -g "${OWNER#*:}" "$OUT"
OUT="$(realpath "$OUT")"
WORK="$(mktemp -d)"
ROOT="$WORK/root"
B=/home/builder            # the build user's home inside the root
# Run as the build user, looked up inside the root: setpriv runs there, so
# the name resolves against the root's /etc/passwd. chroot --userspec looks
# it up on the host under uutils coreutils (Ubuntu 26.04's chroot), where
# there is no builder: "chroot: invalid user" (Milan, 2026-10-02).
AS_BUILDER=(setpriv --reuid=builder --regid=builder --init-groups)

# Never delete the root while anything is still mounted inside it: /dev is
# bound from the host. Unmount, check, and only then remove, on this file
# system alone.
cleanup() {
    local m
    for m in "$ROOT/dev" "$ROOT/proc"; do
        mountpoint -q "$m" 2>/dev/null && { umount "$m" || umount -l "$m" || true; }
    done
    if findmnt -rn -o TARGET | grep -qF "$ROOT/"; then
        echo "build.sh: something is still mounted under $ROOT; left in place, remove it by hand" >&2
        return
    fi
    rm -rf --one-file-system "$WORK"
}
trap cleanup EXIT

# --- the build root, from the snapshot ---
# The package lists are kept (image.sh downloads the kernel with apt), and
# so is the build user. The snapshot's signatures are checked with the build
# host's Ubuntu keyring; the root carries its own from then on.
U="https://snapshot.ubuntu.com/ubuntu/$SNAPSHOT"
PKGS="initramfs-tools-core,3cpio,busybox-initramfs,klibc-utils,kmod,dhcpcd-base"
PKGS="$PKGS,openssh-server,cryptsetup-bin,lvm2,util-linux,zstd,linux-modules-$KVER"
PKGS="$PKGS,cargo,rustc,git,ca-certificates,ovmf-amdsev"
echo "build.sh: making the build root from $U (a few minutes; mmdebstrap's progress follows)" >&2
# setsid: no controlling terminal at all, so nothing mmdebstrap runs can be
# stopped for touching one, even by opening /dev/tty itself.
setsid -w mmdebstrap --mode=root --variant=apt --include="$PKGS" \
    --skip=cleanup/apt/lists \
    --customize-hook='chroot "$1" useradd -m -U -s /bin/bash builder' \
    resolute "$ROOT" \
    "deb $U resolute main universe" \
    "deb $U resolute-updates main universe" \
    "deb $U resolute-security main universe" \
    || die "mmdebstrap failed (above)"

# A proxy with its own certificate authority, where the network needs one:
# apt checks signatures and cargo checksums whatever the transport, so this
# reaches no byte of the image.
if [ -n "${SSL_CERT_FILE:-}" ] && [ -r "$SSL_CERT_FILE" ]; then
    install -m 0644 "$SSL_CERT_FILE" "$ROOT/etc/ssl/certs/build-proxy-ca.crt"
    echo 'Acquire::https::CAInfo "/etc/ssl/certs/build-proxy-ca.crt";' > "$ROOT/etc/apt/apt.conf.d/99build-proxy-ca"
fi
cp /etc/resolv.conf "$ROOT/etc/resolv.conf"
mount -t proc proc "$ROOT/proc"
mount --bind /dev "$ROOT/dev"

# --- the firmware's package ---
# image.sh names ovmf-amdsev's version in the manifest when --ovmf is that
# package's file byte for byte. The root has the snapshot's newest; if the
# pinned firmware is an older one the snapshot still lists, use that.
install -m 0644 "$OVMF" "$ROOT$B/OVMF.amdsev.fd"
if ! cmp -s "$OVMF" "$ROOT/usr/share/ovmf/OVMF.amdsev.fd"; then
    for v in $(chroot "$ROOT" apt-cache madison ovmf-amdsev | awk '{print $3}'); do
        chroot "$ROOT" env DEBIAN_FRONTEND=noninteractive apt-get install -y -q --allow-downgrades \
            "ovmf-amdsev=$v" >/dev/null 2>&1 || continue
        cmp -s "$OVMF" "$ROOT/usr/share/ovmf/OVMF.amdsev.fd" && break
    done
    cmp -s "$OVMF" "$ROOT/usr/share/ovmf/OVMF.amdsev.fd" \
        || echo "build.sh: warning: --ovmf matches no ovmf-amdsev in the snapshot; the manifest will not name its package" >&2
fi

# --- the source: this commit, and nothing else of this checkout ---
g bundle create "$WORK/vmtools.bundle" HEAD 2>/dev/null
install -m 0644 "$WORK/vmtools.bundle" "$ROOT$B/vmtools.bundle"
[ "$CHANGES" = 0 ] || g diff --binary HEAD > "$ROOT$B/changes.patch"
chroot "$ROOT" "${AS_BUILDER[@]}" env -i HOME="$B" PATH=/usr/bin:/bin \
    bash -c "set -e; cd $B && git -c advice.detachedHead=false clone -q vmtools.bundle vmtools \
             && git -c advice.detachedHead=false -C vmtools checkout -q $COMMIT \
             && if [ -s $B/changes.patch ]; then git -C vmtools apply $B/changes.patch; fi"

# --- the image, built inside as the build user ---
ENVS=(HOME="$B" PATH=/usr/bin:/bin USER=builder LOGNAME=builder STAGE0_SNAPSHOT="$SNAPSHOT")
for v in http_proxy https_proxy HTTP_PROXY HTTPS_PROXY no_proxy NO_PROXY; do
    [ -z "${!v:-}" ] || ENVS+=("$v=${!v}")
done
if [ -e "$ROOT/etc/ssl/certs/build-proxy-ca.crt" ]; then
    ENVS+=(SSL_CERT_FILE=/etc/ssl/certs/build-proxy-ca.crt CARGO_HTTP_CAINFO=/etc/ssl/certs/build-proxy-ca.crt)
fi
echo "build.sh: building the agent, the calculator and the initrd in the root" >&2
chroot "$ROOT" "${AS_BUILDER[@]}" env -i "${ENVS[@]}" \
    bash "$B/vmtools/stage0/image.sh" --ovmf "$B/OVMF.amdsev.fd" --out "$B/out" \
         --vcpus "$VCPUS" --kernel "$KVER" >/dev/null \
    || die "image.sh failed in the build root (above)"

for f in vmlinuz initrd.img manifest; do
    install -m 0644 -o "${OWNER%:*}" -g "${OWNER#*:}" "$ROOT$B/out/$f" "$OUT/$f"
done
cat "$OUT/manifest"
