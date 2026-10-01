#!/usr/bin/env bash
# Differential test: run the Python sev-snp-measure and this port on the same
# inputs and require identical stdout, identical exit status, and
# byte-identical --dump-vmsa files.
#
#   tests/differential.sh PY_SEV_SNP_MEASURE [FIRMWARE.fd ...]
#
# PY_SEV_SNP_MEASURE is the Python tool (e.g. venv/bin/sev-snp-measure from
# `pip install sev-snp-measure==0.0.13`). Each extra firmware image is run
# through the whole matrix alongside the upstream fixtures; Ubuntu's
# OVMF.amdsev.fd is the one that matters for vmtrust.
#
# Only cases where both tools are meant to agree are compared. Inputs the
# port deliberately refuses (see README, "Differences") are not.
set -euo pipefail

py=${1:?usage: $0 PY_SEV_SNP_MEASURE [FIRMWARE.fd ...]}
shift
here=$(cd "$(dirname "$0")/.." && pwd)
(cd "$here" && cargo build --release --locked --quiet -p sev-snp-measure --bin sev-snp-measure)
# A workspace member builds into the workspace's target directory.
target=$(cd "$here" && cargo metadata --format-version 1 --no-deps |
    sed -n 's/.*"target_directory":"\([^"]*\)".*/\1/p')
rs="$target/release/sev-snp-measure"

fx="$here/tests/fixtures"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# Synthetic kernel and initrd: content only feeds SHA-256, so random bytes
# exercise the same path a real kernel does.
head -c 1048577 /dev/urandom > "$work/kernel"
head -c 333333 /dev/urandom > "$work/initrd"
: > "$work/empty"
head -c 540672 /dev/urandom > "$work/vars"

pass=0
fail=0

run_case() {
    local name=$1
    shift
    local d_py="$work/py" d_rs="$work/rs"
    rm -rf "$d_py" "$d_rs"
    mkdir "$d_py" "$d_rs"
    local out_py out_rs st_py=0 st_rs=0
    out_py=$(cd "$d_py" && "$py" "$@" 2>/dev/null) || st_py=$?
    out_rs=$(cd "$d_rs" && "$rs" "$@" 2>/dev/null) || st_rs=$?
    # Python reports a usage error as 2 and anything else as 1; so does the port.
    if [ "$out_py" != "$out_rs" ] || [ "$st_py" != "$st_rs" ]; then
        echo "FAIL $name: $*"
        echo "  python ($st_py): $out_py"
        echo "  rust   ($st_rs): $out_rs"
        fail=$((fail + 1))
        return
    fi
    if ! diff -r "$d_py" "$d_rs" >/dev/null; then
        echo "FAIL $name: VMSA dumps differ: $*"
        fail=$((fail + 1))
        return
    fi
    pass=$((pass + 1))
}

firmwares=("$fx/ovmf_AmdSev_suffix.bin" "$fx/ovmf_OvmfX64_suffix.bin" "$@")
cmdlines=("" "console=ttyS0 loglevel=7" "root=/dev/vda1 panic=-1 quiet äöü")

for fw in "${firmwares[@]}"; do
    f=$(basename "$fw")
    run_case "$f ovmf-hash" --mode snp:ovmf-hash --ovmf "$fw"
    for vmm in QEMU ec2 gce; do
        for vcpus in 0 1 2 4 8; do
            for feat in 0x1 0x21; do
                for sigargs in "--vcpu-type=EPYC-Milan" "--vcpu-type=EPYC-v4" \
                    "--vcpu-sig=0" "--vcpu-sig=0xa00f11" \
                    "--vcpu-family=25 --vcpu-model=17 --vcpu-stepping=0"; do
                    # shellcheck disable=SC2086 # sigargs is a list of words
                    run_case "$f snp" --mode snp --vmm-type "$vmm" --vcpus "$vcpus" \
                        $sigargs --guest-features "$feat" --ovmf "$fw" --dump-vmsa
                done
            done
            for cl in "${cmdlines[@]}"; do
                run_case "$f snp+kernel" --mode snp --vmm-type "$vmm" --vcpus "$vcpus" \
                    --vcpu-type EPYC-Milan --ovmf "$fw" --kernel "$work/kernel" \
                    --initrd "$work/initrd" --append "$cl"
                run_case "$f snp+kernel, no initrd" --mode snp --vmm-type "$vmm" \
                    --vcpus "$vcpus" --vcpu-type EPYC-Milan --ovmf "$fw" \
                    --kernel "$work/kernel" --append="$cl" --output-format base64 -v
                run_case "$f seves+kernel" --mode seves --vmm-type "$vmm" --vcpus "$vcpus" \
                    --vcpu-type EPYC-Rome --ovmf "$fw" --kernel "$work/kernel" \
                    --initrd "$work/initrd" --append "$cl" --dump-vmsa
                run_case "$f sev+kernel" --mode sev --ovmf "$fw" --kernel "$work/kernel" \
                    --initrd "$work/empty" --append "$cl"
            done
            run_case "$f seves" --mode seves --vmm-type "$vmm" --vcpus "$vcpus" \
                --vcpu-sig 0x800f12 --ovmf "$fw" --dump-vmsa
        done
    done
    run_case "$f sev" --mode sev --ovmf "$fw"
    run_case "$f snp verbose" -v --mode snp --vcpus 2 --vcpu-type EPYC-Genoa --ovmf "$fw"
    run_case "$f snp base64" --mode snp --vcpus 2 --vcpu-type EPYC-Turin --ovmf "$fw" \
        --output-format base64
    # A precalculated OVMF hash replaces the firmware's own.
    run_case "$f snp-ovmf-hash" --mode snp --vcpus 1 --vcpu-type EPYC-Milan --ovmf "$fw" \
        --snp-ovmf-hash 086e2e9149ebf45abdc3445fba5b2da8270bdbb04094d7a2c37faaa4b24af3aa16aff8c374c2a55c467a50da6d466b74
done

# SVSM: the upstream fixtures, by size and by file.
for vcpus in 1 2 4; do
    run_case "svsm size" --mode snp:svsm --vcpus "$vcpus" --vcpu-type EPYC-v4 \
        --ovmf "$fx/svsm_ovmf.fd" --svsm "$fx/svsm.bin" --vars-size 540672 --dump-vmsa
    run_case "svsm file" --mode snp:svsm --vcpus "$vcpus" --vcpu-sig 0xa00f11 \
        --ovmf "$fx/svsm_ovmf.fd" --svsm "$fx/svsm.bin" --vars-file "$work/vars"
done

# Errors both report the same way (status and empty stdout).
amd="$fx/ovmf_AmdSev_suffix.bin"
x64="$fx/ovmf_OvmfX64_suffix.bin"
run_case "err: no mode" --ovmf "$amd"
run_case "err: no ovmf" --mode snp
run_case "err: bad mode" --mode tdx --ovmf "$amd"
run_case "err: no vcpus" --mode snp --vcpu-type EPYC --ovmf "$amd"
run_case "err: no sig" --mode snp --vcpus 1 --ovmf "$amd"
run_case "err: bad type" --mode snp --vcpus 1 --vcpu-type EPYC-Zen9 --ovmf "$amd"
run_case "err: bad vmm" --mode snp --vcpus 1 --vcpu-type EPYC --vmm-type kvm --ovmf "$amd"
run_case "err: initrd w/o kernel" --mode snp --vcpus 1 --vcpu-type EPYC --ovmf "$amd" \
    --initrd "$work/initrd"
run_case "err: append w/o kernel" --mode sev --ovmf "$amd" --append x
run_case "err: x64 + kernel snp" --mode snp --vcpus 1 --vcpu-type EPYC --ovmf "$x64" \
    --kernel "$work/kernel"
run_case "err: x64 + kernel sev" --mode sev --ovmf "$x64" --kernel "$work/kernel"
run_case "err: svsm no vars" --mode snp:svsm --vcpus 1 --vcpu-type EPYC \
    --ovmf "$fx/svsm_ovmf.fd" --svsm "$fx/svsm.bin"
run_case "err: svsm vars 0" --mode snp:svsm --vcpus 1 --vcpu-type EPYC \
    --ovmf "$fx/svsm_ovmf.fd" --svsm "$fx/svsm.bin" --vars-size 0
run_case "err: vars both" --mode snp:svsm --vcpus 1 --vcpu-type EPYC \
    --ovmf "$fx/svsm_ovmf.fd" --svsm "$fx/svsm.bin" --vars-size 1 --vars-file "$work/vars"
run_case "err: dump sev" --mode sev --ovmf "$amd" --dump-vmsa
run_case "err: bad int" --mode snp --vcpus four --vcpu-type EPYC --ovmf "$amd"
run_case "err: bad features" --mode snp --vcpus 1 --vcpu-type EPYC --ovmf "$amd" \
    --guest-features 0xZZ
run_case "err: bad format" --mode snp --vcpus 1 --vcpu-type EPYC --ovmf "$amd" \
    --output-format raw
run_case "err: missing ovmf file" --mode snp --vcpus 1 --vcpu-type EPYC --ovmf "$work/nope"
run_case "err: unknown option" --mode snp --vcpus 1 --vcpu-type EPYC --ovmf "$amd" --frobnicate
run_case "err: hash outside snp" --mode seves --vcpus 1 --vcpu-type EPYC --ovmf "$amd" \
    --snp-ovmf-hash 00

echo "differential: $pass agree, $fail differ"
[ "$fail" -eq 0 ] && [ "$pass" -gt 0 ]
