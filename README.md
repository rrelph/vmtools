# vmtools

The open-source tools behind attested disk unlock for AMD SEV-SNP
confidential VMs:

| Path | What it is |
|---|---|
| `attest/vmt-unlock` | **The unlock tool a VM's owner runs.** It asks the VM's AMD processor for a signed report, checks it (the certificate chain to AMD, the launch measurement, the policy, the server unlock key the VM was started for, and more), and only then sends the disk passphrase. |
| `attest/stage0-agent` | The program inside stage 0, the small measured system a VM boots first: it answers the unlock tool's `attest` and `unlock` requests. It is built into stage 0's initrd by `stage0/build.sh`, never installed by anyone. |
| `attest/snp` | The library both share: report parsing, the checks, the certificates. |
| `attest/fuzz` | Fuzz targets for the report and codec parsers (its own lock; development only). |
| `stage0/` | Builds stage 0 (`build.sh`: kernel, initrd, command line and a manifest with the expected measurements) and points a libvirt domain at a build (`install.sh`). |

## Installing the unlock tool

Owners install `vmt-unlock` and nothing else, from a release tag, with the
versions of every library pinned by `Cargo.lock`:

```sh
cargo install --locked --git https://github.com/rrelph/vmtools --tag vmt-unlock-0.3.0 vmt-unlock
```

Naming `vmt-unlock` matters: the workspace has two binaries, and
`stage0-agent` is not for owners.

### What a build of the workspace produces

- **`vmt-unlock`**, the unlock tool: the one program an owner installs.
- **`stage0-agent`**, stage 0's side of the unlock: built into stage 0's initrd
  by `stage0/build.sh`. It runs as root inside a VM's first boot and has no
  use on anyone's computer. `cargo install … vmt-unlock` does not build it.
- **`libder_derive-*.so`** (`.dylib` on a Mac), in `target/*/deps/`: not a
  program anyone runs, but a procedural macro, a compiled plugin that the
  Rust compiler loads while building, to write the DER-decoding code the
  X.509 certificate parser (`x509-cert`) uses. It is code from a dependency
  that runs at build time, with the build scripts listed below.
- Test binaries, with `cargo test`: `snp`, `fixtures`, `snpguest`, and the
  two programs' own.

## Building and testing

```sh
cd attest && cargo test --locked && cargo fmt --check
```

Every dependency is pinned exactly (`=` versions in `attest/Cargo.toml`, with
checksums in `Cargo.lock`). Building compiles and runs code from some of them
at build time: build scripts (`libc`, `libm`, `num-traits`, `num-bigint-dig`,
`generic-array`, `zerocopy`, `proc-macro2`, `quote`) and one procedural macro
(`der_derive`, through `x509-cert`).

**Formatting changes measurements.** The stage 0 agent's binary, and so every
guest's launch measurement, changes with its source layout (line numbers are
compiled in), so a reformat of `attest/stage0-agent` or `attest/snp` belongs
with the stage 0 rebuild it causes. CI runs `cargo fmt --check`.

## Stage 0

`stage0/build.sh` runs unprivileged on Ubuntu 26.04 and writes a manifest
that names this repository's commit (`source.commit`), the kernel package and
where it sits in Ubuntu's archive, the firmware, every package that put a
file in the image, and the expected launch measurement per vCPU count.
`stage0/install.sh` sets a domain's kernel, initrd, command line, `host_data`
and the server unlock key in fw_cfg from a build. The hosting operator's
runbook (not in this repository) says when to rebuild and how to publish.

## Licence

MIT OR Apache-2.0, at your option (`LICENSE-MIT`, `LICENSE-APACHE`).
