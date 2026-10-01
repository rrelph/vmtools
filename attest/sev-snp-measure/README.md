# sev-snp-measure (Rust)

A Rust port of [virtee/sev-snp-measure](https://github.com/virtee/sev-snp-measure),
the Python tool that calculates the launch measurement of an AMD SEV, SEV-ES
or SEV-SNP guest from its firmware, kernel, initrd, command line and vCPU
setup.

It ports version **0.0.13** plus the one later upstream commit,
[`8f2b337`](https://github.com/virtee/sev-snp-measure/commit/8f2b337e38bc83f87cd30f3253cdfe8e3e12cc3a)
("Allow zero as value for vcpu sig & family"). Both programs are here:

| Program | Python | What it does |
|---|---|---|
| `sev-snp-measure` | `sevsnpmeasure/cli.py` | the launch measurement |
| `snp-create-id-block` | `sevsnpmeasure/id_block.py` | an SNP ID block and ID auth structure, signed with P-384 keys |

The command lines are the same, so a guide's command works with either tool
unchanged:

```bash
sev-snp-measure --mode snp --vcpus=4 --vcpu-type=EPYC-Milan \
    --ovmf=OVMF.amdsev.fd --kernel=vmlinuz --initrd=initrd.img \
    --append="console=ttyS0"
```

## Building

A member of the `attest/` workspace, pinned by its `Cargo.lock`. From
`attest/`:

```bash
cargo build --release --locked -p sev-snp-measure
cargo build --release --locked -p sev-snp-measure --no-default-features   # sev-snp-measure only
```

The measurement calculator depends on one crate, `sha2` (RustCrypto). The
`id-block` feature (on by default) adds `p384`, with its `pem` feature, for
`snp-create-id-block`; `--no-default-features` leaves it out, along with
its dependencies. Both come from the workspace's `=` pins. Unlike the rest
of the workspace, which is MIT OR Apache-2.0, this crate is Apache-2.0,
the license of the Python it translates.
Hex and base64 are written out in `src/util.rs`, and arguments are parsed
by hand, to keep the calculator's dependencies small.

## Layout

Each Python module has a Rust module with the same name and the same
functions, in the same order:

| Python (`sevsnpmeasure/`) | Rust (`src/`) |
|---|---|
| `gctx.py` | `gctx.rs` |
| `guest.py` | `guest.rs` (`calc_launch_digest` takes a `Params` struct) |
| `ovmf.py` (`OVMF`, `SVSM`) | `ovmf.rs` (`Ovmf`; `SVSM.sev_es_reset_eip` is `Ovmf::svsm_reset_eip`) |
| `sev_hashes.py` | `sev_hashes.rs` |
| `vmsa.py` | `vmsa.rs` |
| `vcpu_types.py`, `vmm_types.py`, `sev_mode.py` | the same names |
| `id_block.py` | `id_block.rs` and `src/bin/snp-create-id-block.rs` |
| `cli.py` | `src/bin/sev-snp-measure.rs` |

The ctypes structures are byte arrays with fields written at explicit
offsets. The VMSA's offsets come from the ctypes layout; the differential
test compares the resulting pages byte for byte (below).

## Testing

```bash
cargo test --locked -p sev-snp-measure    # from attest/
sev-snp-measure/tests/differential.sh path/to/python/sev-snp-measure [OVMF.amdsev.fd ...]
```

`cargo test` runs every upstream test, ported: all 29 launch-digest vectors
of `tests/test_guest.py` (SNP, SEV-ES, SEV, the ec2 and gce VMM types,
SVSM), `test_id_block.py`, `test_cli.py`, `test_sev_mode.py` and
`test_vcpu_types.py`. The fixtures in `tests/fixtures` and `tests/keyfile`
are upstream's, unchanged. One more test does what upstream's cannot: it
reads the signatures back out of the ID auth structure and verifies them.

`tests/differential.sh` runs the Python tool and this one side by side on
the same inputs. It covers each mode, VMM type, vCPU count (0–8),
signature form, guest-feature value and command line (including non-ASCII),
with and without kernel and initrd. It also runs the error cases. For each
run it requires the same stdout, the same exit status, and byte-identical
`--dump-vmsa` files. Any firmware image you pass is added to the matrix.

Last run: 1,427 cases. The Python side was installed from upstream commit
`8f2b337`, and the matrix included Ubuntu's `OVMF.amdsev.fd` from
`ovmf-amdsev` 2025.11-3ubuntu7.2 and 2026.05-2ubuntu2. All 1,427 agreed.
Against the released 0.0.13 from PyPI, 40 cases differed. Every one was
`--vcpu-sig=0` with QEMU: 0.0.13 rejects a zero signature, and `8f2b337`
fixes that. Kernel and initrd were random bytes, which exercise the same
code as real ones, since only their SHA-256 is measured.

## Differences from the Python version

Every valid input gives the same output as Python. The differences are on
inputs that Python either crashes on or handles by accident:

- **ID auth signatures.** Python's `cryptography` signs with a random
  nonce; RustCrypto derives the nonce deterministically (RFC 6979). Both
  produce valid ECDSA P-384 signatures, but `id-auth` differs between the
  tools, and between runs of the Python tool. `id-block`, `id_key_hash`
  and `author_key` are byte-identical.
- **Malformed firmware is refused rather than misread.** These cases are
  errors here:
  - a footer table or an entry that claims to extend past the start of
    the image (Python's negative slicing quietly reads a shorter one);
  - SEV metadata outside the image;
  - an image too small to hold a footer;
  - an image larger than the space below its end address.
- **Python's crashes become errors.** Python ends with a traceback, also
  exit status 1, where this tool prints `Error: …` instead:
  - `--vcpus` above 1 with firmware that has no AP reset address;
  - an `--snp-ovmf-hash` that is not 48 bytes;
  - a hashes table that would cross its page;
  - a non-page-sized region;
  - `--snp-ovmf-hash` outside SNP mode.

  `--vcpu-family` without `--vcpu-model` and `--vcpu-stepping` (a
  `TypeError` in Python) is a usage error here, exit status 2.
- **Numbers.** Negative values for `--vcpus`, `--vcpu-sig`, the family,
  model and stepping, `--guest-features` and `--vars-size` are refused.
  Python accepts them, and either fails later or computes with them.
- **Options must be spelled in full.** argparse also accepts any
  unambiguous prefix, such as `--vcpu-t` for `--vcpu-type`.
- **`snp-create-id-block`** refuses a `--measurement` that is not strict
  base64 of exactly 48 bytes. Python discards stray characters and uses the
  first 48 bytes of a longer value. It reports a missing `--measurement`
  as a usage error, where Python crashes. A key on a curve other than
  P-384 is refused when it is loaded, not when it is used.
- **`--version`** names this port and the upstream version it follows.
- **Library API.** `dump_vmsa` is a directory, not a flag; the
  command-line tool passes the working directory, as Python does.

## License

Apache-2.0, as upstream (`LICENSE`). The code is a translation of IBM's
Python, Copyright 2022- IBM Inc., and the test fixtures and keys are
upstream's.
