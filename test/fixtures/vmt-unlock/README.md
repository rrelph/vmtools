# OpenSSH certificate fixtures

Test keys and certificates for vmt-unlock's certificate checks
(`attest/vmt-unlock/src/cert.rs`), made with OpenSSH's own `ssh-keygen`
(OpenSSH_9.6p1 Ubuntu-3ubuntu13.19, with `TZ=UTC`) so the reader is tested
against what OpenSSH writes, not only against an encoder of our own.

Nothing here is secret: only public halves and certificates were committed,
and the private halves were deleted when they had been used. No owner's key
appears here.

| File | What it is |
|---|---|
| `unlock-key.pub` | the test server unlock key (a certificate authority) |
| `other-unlock-key.pub` | a different unlock key |
| `owner.pub` | the test owner's SSH key |
| `someone.pub` | a different SSH key |
| `year-cert.pub` | `owner.pub` signed with `unlock-key`, principal `unlock`, 2026-01-01 to 2027-01-01 |
| `other-ca-cert.pub` | the same, signed with `other-unlock-key` |
| `root-cert.pub` | the same, principal `root` |
| `forever-cert.pub` | the same, principal `unlock`, valid `always:forever` |
| `host-cert.pub` | a host certificate (`-h`), principal `unlock` |

Made with:

```bash
export TZ=UTC
ssh-keygen -q -t ed25519 -N '' -C 'test unlock key' -f unlock-key
ssh-keygen -q -t ed25519 -N '' -C 'another unlock key' -f other-unlock-key
ssh-keygen -q -t ed25519 -N '' -C 'test owner key' -f owner
ssh-keygen -q -t ed25519 -N '' -C 'someone else' -f someone
for n in year other-ca root forever host; do cp owner.pub $n.pub; done
ssh-keygen -q -s unlock-key -I owner -n unlock -O clear -V 20260101:20270101 year.pub
ssh-keygen -q -s other-unlock-key -I owner -n unlock -O clear -V 20260101:20270101 other-ca.pub
ssh-keygen -q -s unlock-key -I owner -n root -O clear -V 20260101:20270101 root.pub
ssh-keygen -q -s unlock-key -I owner -n unlock -O clear -V always:forever forever.pub
ssh-keygen -q -s unlock-key -I owner -h -n unlock -V 20260101:20270101 host.pub
```
