# SEV-SNP attestation report fixtures

Genuine attestation reports from a disposable test guest, with the AMD
certificates that sign them, for offline tests of the unlock tool's verifier
(`design/attested-unlock-design.md` section 8). Captured on 2026-09-28 during
Phase 0; the full account is `design/phase0-findings.md`, Task 4.

Nothing here is secret. The reports are signed public statements, and the
certificates are AMD's public certificates. The one key in this directory,
`binding-hostkey.pub`, is a **public** test key, and its private half was
never committed. No guest owner's key, disk key or identity appears here.

## Where they came from

| | |
|---|---|
| Host | Milan (EPYC Milan), host kernel 7.0.0-34-generic, QEMU 10.2.1, libvirt 12.0.0 |
| Firmware | `ovmf-amdsev` 2025.11-3ubuntu7.2 (`/opt/cvm/firmware/OVMF.amdsev.fd`) |
| Guest | `phase0-test`, built by `cvm new` from this repo at `33332bb`; Ubuntu 26.04.1, kernel 7.0.0-34-generic, 4 vCPUs, policy `0x30000` |
| Tool | `snpguest` 0.10.0, built with `cargo install snpguest --version 0.10.0 --locked` (binary SHA-256 `55aa3dbd732c2fed18f2e93daf878c156d678078498f7e62d4a5fdf3eaba2336`) |
| TCB | reported_tcb: bootloader 4, TEE 0, SNP 28, microcode 222 |
| chip_id | `81969fb305757e921da203f0dacb237fd48fb04feb241c0943f8ddc511459d87b641ac3a7f1b75d9318b63546bdff58fdb0d884a884297ce190821aa1538089e` |

## The files

REPORT_DATA inputs, each 64 bytes:

| File | Contents |
|---|---|
| `rd-zero.bin` | 64 × `0x00` |
| `rd-ff.bin` | 64 × `0xff` |
| `rd-counting.bin` | bytes `0x00` … `0x3f` |
| `rd-binding.bin` | `SHA-512(binding-nonce.bin ‖ binding-hostkey.blob)`: the design's section 7 binding |

The inputs to the binding case:

| File | Contents |
|---|---|
| `binding-nonce.bin` | 32 bytes, `0xa0` … `0xbf` |
| `binding-hostkey.pub` | an Ed25519 OpenSSH public key standing in for a stage 0 host key |
| `binding-hostkey.blob` | its OpenSSH wire-format blob: the base64 field of the `.pub` line, decoded (51 bytes) |

Reports, 1184 bytes each (version 5, signature algorithm 1):

| File | REPORT_DATA | VMPL | Boot | Measurement |
|---|---|---|---|---|
| `report-zero-vmpl0.bin` | `rd-zero.bin` | 0 | OVMF only | `2cef0b36…a4b119c5` |
| `report-ff-vmpl0.bin` | `rd-ff.bin` | 0 | OVMF only | `2cef0b36…a4b119c5` |
| `report-counting-vmpl0.bin` | `rd-counting.bin` | 0 | OVMF only | `2cef0b36…a4b119c5` |
| `report-counting-vmpl1.bin` | `rd-counting.bin` | **1** | OVMF only | `2cef0b36…a4b119c5` |
| `report-binding-vmpl0.bin` | `rd-binding.bin` | 0 | OVMF only | `2cef0b36…a4b119c5` |
| `report-binding-tsm.bin` | `rd-binding.bin` | 0 | OVMF only | `2cef0b36…a4b119c5` |
| `report-zero-vmpl0-directboot.bin` | `rd-zero.bin` | 0 | measured direct boot | `9f2af610…972b1cf5` |

The full measurements:

- OVMF only: `2cef0b36c9a6d7b19912ce2131c938c6b0fac0a422bc778e435a1a0b1c59847680a3e6506370debf875416f9a4b119c5`
- Measured direct boot: `9f2af610c3117241388d18af9c98356566ea1d2a5d555df44ceb07c6fe75021a8c29b4a6a370e530f2827a01972b1cf5`

Both match what `sev-snp-measure` 0.0.13 predicts for 4 vCPUs of type
`EPYC-Milan` (the direct-boot inputs are below).

Certificates, fetched from AMD KDS inside the guest:

| File | SHA-256 |
|---|---|
| `certs/ark.pem` | `8c109952166431ffad8cb9a3d54f3d20ffbbb58164f0d54be3457bf0ece9e0d8` |
| `certs/ask.pem` | `8da3a65af1cb7cb90a21fac78431a2431a9ee7811f48c36569c53fb80ad31fee` |
| `certs/vcek.pem` | `c6b50882503c72a245987e9a6e7b93a19067b7b7cdba99339529907445cff61f` |

One VCEK signs every report here, because they share a chip and a TCB.

Added in Phase 1, fetched from AMD KDS on the workstation:

| File | SHA-256 |
|---|---|
| `certs/vcek-snp27.der` | `cc91dbc9098d319a6023b32d7da782c1b0494a3cedf0cc539ee32931ea00aca2` |

It is the genuine VCEK for the same chip at SNP SPL 27 instead of 28 (DER,
not PEM), so it chains to the ASK but is not the key that signed these
reports:

```bash
curl -sSf --proto =https -o certs/vcek-snp27.der \
  "https://kdsintf.amd.com/vcek/v1/Milan/<chip_id>?blSPL=04&teeSPL=00&snpSPL=27&ucodeSPL=222"
```

## How each was produced

The REPORT_DATA files were made on the workstation:

```bash
head -c 64 /dev/zero > rd-zero.bin
head -c 64 /dev/zero | tr '\0' '\377' > rd-ff.bin
printf "$(printf '\\x%02x' $(seq 0 63))" > rd-counting.bin
printf "$(printf '\\x%02x' $(seq 160 191))" > binding-nonce.bin
awk '{print $2}' binding-hostkey.pub | base64 -d > binding-hostkey.blob
cat binding-nonce.bin binding-hostkey.blob | sha512sum | awk '{print $1}' | xxd -r -p > rd-binding.bin
```

The reports were captured in the guest, as root. Each `snpguest` report went
through `/dev/sev-guest`; `report-binding-tsm.bin` went through configfs-tsm
instead:

```bash
snpguest report --vmpl 0 report-zero-vmpl0.bin rd-zero.bin      # likewise ff, counting, binding
snpguest report --vmpl 1 report-counting-vmpl1.bin rd-counting.bin
R=/sys/kernel/config/tsm/report/p0; mkdir $R
cat rd-binding.bin > $R/inblob; cat $R/outblob > report-binding-tsm.bin; rmdir $R
snpguest fetch ca pem certs milan -e vcek
snpguest fetch vcek pem certs report-zero-vmpl0.bin
```

`report-zero-vmpl0-directboot.bin` came from the same disk booted as
`phase0-direct`, which is `phase0-test`'s domain with `kernelHashes='yes'` and
these direct-boot inputs:

| | |
|---|---|
| kernel | `vmlinuz-7.0.0-34-generic`, SHA-256 `7efd88a7facf80874d781ccb2c2421f0aaaa575e3b94760430619e826f490117` |
| initrd | the test guest's initrd, which carries Phase 0 test hooks; SHA-256 `b779c6ac6f18c9f0350ac227dbaf01a3c1723e85a2c430a4d1ab32dd22522f4b` |
| cmdline | `root=/dev/mapper/ubuntu--vg-ubuntu--lv ro ip=dhcp console=tty0 console=ttyS0,115200 console=tty0 console=ttyS0,115200 crashkernel=2G-4G:320M,4G-32G:512M,32G-64G:1024M,64G-128G:2048M,128G-:4096M` |

The kernel and initrd are about 117 MB together and are not committed. This
report is for verifier tests that only need a second, different, genuine
measurement.

## What was verified, and how

- `snpguest verify certs certs` reported that the ARK is self-signed, the ASK
  is signed by the ARK, and the VCEK is signed by the ASK.
- `snpguest verify attestation certs <report>` reported `VEK signed the
  Attestation Report!` for all seven reports, with every reported TCB
  component matching the VCEK.
- REPORT_DATA (offset `0x50`, 64 bytes) of every report was compared
  byte-for-byte with its input file. All match.

## What a verifier test should get from each

| Fixture | Section 8 checks 1–4 | Then |
|---|---|---|
| `report-*-vmpl0.bin`, `report-binding-tsm.bin` | pass | measurement and policy per the test's expectations |
| `report-counting-vmpl1.bin` | pass: genuinely signed | **must fail check 7 (VMPL)**. Signature checks alone accept it. |
| `report-binding-vmpl0.bin` with `binding-nonce.bin` and `binding-hostkey.blob` | check 4 passes | the same report against any other nonce or host key must fail check 4 |
| any report, one byte flipped in the signed region (bytes `0x000`–`0x29f`) | check 2 must fail | |
| any report with `certs/vcek.pem` swapped for a VCEK of another chip or TCB | check 1 or 2 must fail | `certs/vcek-snp27.der` is one: it must fail both |

The tests that hold a verifier to this table are `attest/snp/tests/fixtures.rs`
(`cargo test --locked` in `attest/`).

Two gaps these fixtures do not cover:

- **`host_data` is all zeros** in every report, because Phase 0 set none.
  Check 8 needs a fixture made with `host_data` set.
- **The policy is `0x30000` throughout.** There is no debug-enabled or
  migration-agent report.

## snpguest's view of each report (added in Phase 2)

`snpguest-display/<report>.txt` is `snpguest display report` for each report
fixture, from snpguest 0.10.0 (`snpguest-display/VERSION`), recorded on Milan
by `sh snpguest-display.sh <snpguest>`. snpguest does not build on aarch64 (its
`rdrand` dependency is x86-only), so the recording is committed and
`attest/snp/tests/snpguest.rs` compares the snp crate's parse with it field by
field. Rerun the script after adding a report fixture.

## host_data set (added in Phase 3)

| File | Contents |
|---|---|
| `report-hostdata-vmpl0.bin` | a genuine report, REPORT_DATA all zeros, VMPL 0, from a guest launched with `host_data` = SHA-256 of `test-org-ca.pub`'s wire-format blob; measurement `ed1e7f51…` (the Phase 2 stage 0, 4 vCPUs) |
| `test-org-ca.pub` | the **public** half of the throwaway test org CA that `host_data` was set for (its private half was never committed) |

`report-hostdata-vmpl0.bin` was captured on Milan through configfs-tsm in the
booted test guest (same chip and TCB as the other reports, so `certs/vcek.pem`
signs it). `host_data` is `ec98f22c…d7d594`, which, written in base64, is the
CA's own `ssh-keygen -l` fingerprint, `SHA256:7JjyLNLH…X1ZQ`. It is the first
fixture with `host_data` set, so it is the one check 8's tests use.
