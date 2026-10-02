# vmtools

The open-source tools behind attested disk unlock for AMD SEV-SNP
confidential VMs:

| Path | What it is |
|---|---|
| `attest/vmt-unlock` | **The unlock tool a VM's owner runs.** It asks the VM's AMD processor for a signed report, checks it (the certificate chain to AMD, the launch measurement, the policy, the server unlock key the VM was started for, and more), and only then sends the disk passphrase. |
| `attest/stage0-agent` | The program inside stage 0, the small measured system a VM boots first: it answers the unlock tool's `attest` and `unlock` requests. It is built into stage 0's initrd by `stage0/build.sh`, never installed by anyone. |
| `attest/snp` | The library both share: report parsing, the checks, the certificates. |
| `attest/sev-snp-measure` | A Rust port of [virtee/sev-snp-measure](https://github.com/virtee/sev-snp-measure) 0.0.13, which computes a VM's expected launch measurement from its firmware, kernel, initrd and command line. Owners can use it to reproduce the measurement the unlock tool checks; same command line as the original. Apache-2.0, like the original (its `README.md`). |
| `attest/vmt-unzstd` | Decompresses a zstd file, checking every frame's checksum. Ubuntu compresses the contents of its `.deb` packages with zstd, which macOS's `tar` cannot read; this unpacks the kernel and firmware packages for the measurement. |
| `attest/fuzz` | Fuzz targets for the report and codec parsers (its own lock; development only). |
| `stage0/` | Builds stage 0 (`build.sh`, from Ubuntu's archive alone: kernel, initrd, command line and a manifest with the expected measurements; `image.sh` does the building inside its root) and points a libvirt domain at a build (`install.sh`). |

## Installing the unlock tool

Owners install `vmt-unlock` from a release tag, with the versions of every
library pinned by `Cargo.lock`:

```sh
cargo install --locked --git https://github.com/rrelph/vmtools --tag vmtools-0.6.0 vmt-unlock
```

Naming `vmt-unlock` matters: the workspace builds several programs, and
`stage0-agent` is not for owners.

## Reproducing the measurement (optional)

The unlock tool checks the VM's launch measurement against the value its
owner was sent. To compute that value themselves, owners build the
calculator and the unpacker (in every release from 0.5.0):

```sh
cargo install --locked --no-default-features --git https://github.com/rrelph/vmtools --tag vmtools-0.6.0 --root ~/vmt-measure sev-snp-measure vmt-unzstd
```

`--no-default-features` leaves out `snp-create-id-block`, the port's ID-block
tool, and the elliptic-curve code only it needs: the calculator then builds
on `sha2` alone, and `vmt-unzstd` on `ruzstd` and `twox-hash`. `--root`
keeps both in one folder, outside `~/.cargo/bin`.

The port is ours, so the original stays the independent check: it runs from
its own repository, at the v0.0.13 commit, on the Python a Mac already has
(its measurement calculator needs only Python's standard library). The
hosting operator's measurement guide walks through both. `stage0/build.sh`
computes the published measurement with the port too, built from its own
checkout: nothing in the chain installs Python or anything from PyPI.

### What a build of the workspace produces

- **`vmt-unlock`**, the unlock tool: the one program every owner installs.
- **`sev-snp-measure`** and **`vmt-unzstd`**, for owners who reproduce the
  measurement; and **`snp-create-id-block`**, the port's ID-block tool, which
  no guide uses (left out by `--no-default-features`).
- **`stage0-agent`**, stage 0's side of the unlock: built into stage 0's initrd
  by `stage0/build.sh`. It runs as root inside a VM's first boot and has no
  use on anyone's computer. `cargo install … vmt-unlock` does not build it.
- **`libder_derive-*.so`** (`.dylib` on a Mac), in `target/*/deps/`: not a
  program anyone runs, but a procedural macro, a compiled plugin that the
  Rust compiler loads while building, to write the DER-decoding code the
  X.509 certificate parser (`x509-cert`) uses. It is code from a dependency
  that runs at build time, with the build scripts listed below.
- Test binaries, with `cargo test`: `snp`, `fixtures`, `snpguest`, `guest`
  (the port's launch-digest vectors, from the original's test suite), and
  the programs' own.

## Versions

The workspace has one version, in `attest/Cargo.toml`, and every program
reports it (`--version`): a number names a release, meaning this source and
this `Cargo.lock`, not one program's changes. Releases are tagged
`vmtools-X.Y.Z`; CI fails a member that sets its own version and a tag that
does not match (`.github/scripts/check-versions.sh`). Tags up to
`vmt-unlock-0.5.0` predate the scheme: in those, `vmt-unlock` kept its own
version (0.4.0 at both `vmt-unlock-0.4.0` and `vmt-unlock-0.5.0`).

**A new version changes stage 0's measurement.** Cargo mixes each package's
version into the hashes compiled into the binary, so the stage 0 agent built
from a new release differs even where its source does not. Moving to a new
release does not by itself call for a stage 0 rebuild: the next rebuild (for
a kernel update, say) picks it up, with its new measurements.

## Building and testing

```sh
cd attest && cargo test --locked && cargo fmt --check
```

Every dependency is pinned exactly (`=` versions in `attest/Cargo.toml`, with
checksums in `Cargo.lock`). The port also has a differential test against
the Python original (`attest/sev-snp-measure/tests/differential.sh`; it needs
the original installed, so CI does not run it). Building compiles and runs code from some of them
at build time: build scripts (`libc`, `libm`, `num-traits`, `num-bigint-dig`,
`generic-array`, `zerocopy`, `proc-macro2`, `quote`) and one procedural macro
(`der_derive`, through `x509-cert`).

**Formatting changes measurements.** The stage 0 agent's binary, and so every
guest's launch measurement, changes with its source layout (line numbers are
compiled in), so a reformat of `attest/stage0-agent` or `attest/snp` belongs
with the stage 0 rebuild it causes. CI runs `cargo fmt --check`.

## Stage 0

`stage0/build.sh` builds stage 0 from Ubuntu's archive alone. It makes a
throwaway Ubuntu 26.04 root from the archive as it was at one moment
(`snapshot.ubuntu.com`, `--snapshot`, default now) with mmdebstrap, and runs
`stage0/image.sh` there as an unprivileged user: every file in the image,
every tool that assembles and compresses it, and the compiler that builds
the agent come from that root, never from the machine running the build. It
needs root (for mmdebstrap and the chroot) and writes a manifest that names
this repository's commit (`source.commit`), the snapshot
(`build.snapshot`), the kernel package and where it sits in Ubuntu's
archive, the firmware, every package that put a file in the image, the
build tools' versions, and the expected launch measurement per vCPU count.
The same commit, snapshot, kernel and firmware give the same bytes on any
machine.
`stage0/install.sh` sets a domain's kernel, initrd, command line, `host_data`
and the server unlock key in fw_cfg from a build. The hosting operator's
runbook (not in this repository) says when to rebuild and how to publish.

## Licence

MIT OR Apache-2.0, at your option (`LICENSE-MIT`, `LICENSE-APACHE`), except
`attest/sev-snp-measure`: a translation of IBM's Apache-2.0 Python, it is
Apache-2.0 only (`attest/sev-snp-measure/LICENSE`).
