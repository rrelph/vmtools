# The unlock exchange, in full

What passes between a VM's stage 0 and its owner's unlock tool, `vmt-unlock`,
when the VM starts, and why each part is there. This describes the code in
this repository: `stage0/` (the boot scripts and `install.sh`),
`attest/stage0-agent` (the program stage 0 runs for each request),
`attest/vmt-unlock` (the owner's tool) and `attest/snp` (the report, the
binding and the checks, shared by both). Where this document and the code
disagree, the code is what runs; please fix whichever is wrong.

The design these implement, with its reasoning and open questions, is
`design/attested-unlock-design.md` in the provider's repository; its section
numbers (§7, check 8, …) are used here too.

## In brief: the conversation

The attestation and the unlock, as a dialogue between the owner's computer
and the VM, leaving out the SSH handshake. The rest of this document is the
detail behind each line.

**Before it starts.** When the VM starts, stage 0 makes a brand-new Ed25519
SSH host key, in memory. `stage0-agent` does not listen on anything: stage
0's sshd listens on port 2222, and for each request the owner's computer
makes over the SSH connection, sshd starts a fresh `stage0-agent`, hands it
the request as text, and returns what it prints. When the owner's computer
connects, its SSH layer records the host key the server actually presented:
*the session's host key*, whose private half the far end of this connection
holds.

**Owner's computer (`vmt-unlock`):** makes a nonce, 32 random bytes from
`/dev/urandom`, and sends it as text, 64 lowercase hex digits, as the SSH
command:

```
attest 3f9c…(64 hex digits)…a1
```

**VM (`stage0-agent`):** checks that the request is exactly `attest` and 64
hex digits, and decodes the nonce back to 32 bytes. Then:

1. It takes its own SSH host key in OpenSSH wire form: the 51 bytes you get
   by base64-decoding the middle field of its `.pub` line.
2. It computes `REPORT_DATA = SHA-512(nonce || host key blob)`: 64 bytes,
   exactly the size of the report's REPORT_DATA field.
3. It asks the AMD firmware for a report through the kernel's configfs-tsm,
   writing those 64 bytes, in binary, and asking for VMPL 0.
4. The firmware returns the report: 1184 bytes (0x4A0), signed by the chip's
   VCEK over bytes 0x000–0x29F.
5. It checks, as a sanity check and not a security check, that the report
   carries the REPORT_DATA it asked for, at VMPL 0.

It replies with three lines of text:

```
stage0-attest 1
host-key ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI…   (its host key, base64, as in a .pub file)
report 0200000000000000…                          (the 1184-byte report, as 2368 hex digits)
```

No certificates come with it: the owner's computer gets those from AMD.

**Owner's computer:** decodes the report from hex, and gets the VCEK, from
its cache or from AMD's key distribution service, by the report's chip ID and
firmware levels. Then it checks:

- **signatures:** the VCEK chains to AMD's ASK and ARK, which are compiled
  into the tool, and the report's ECDSA P-384 signature verifies under the
  VCEK;
- **REPORT_DATA, the binding:** it recomputes `SHA-512(nonce || host key
  blob)` from its own nonce and **the session's host key**, not the
  `host-key` line of the reply, which is only compared, for a warning;
- **everything else:** the measurement (the stage 0 build the owner
  accepts), the policy (debugging off, no migration agent, …), VMPL 0, the
  firmware minimums, and HOST_DATA, against the owner's own copy of the
  server unlock key.

Only if all of that passes does it send a second request, over the same
connection:

```
unlock
```

with the disk passphrase on that session's standard input, as raw bytes, no
newline added, then end of input.

**VM:** passes the bytes straight to `cryptsetup open`, never to a file,
loads the VM's own kernel and initrd from the opened disk to start by
kexec, with the passphrase in memory for that initrd, locks the disk again,
and replies:

```
stage0-unlock 1
unlocked /dev/vda3
```

Then stage 0 stops sshd and starts the VM's own kernel, whose initramfs
opens the disk with the passphrase stage 0 handed it, and the VM's own
system boots.

**Two bindings, two jobs.** REPORT_DATA binds the report to *this
connection, now*: a relaying host would have to present its own host key,
and then the hash cannot match; an old report carries an old nonce. HOST_DATA
binds the VM to *the owner's server unlock key*, the certificate authority
stage 0's sshd trusts. The hypervisor sets HOST_DATA at launch
(`SHA-256(unlock key blob)`, from the libvirt domain `install.sh` wrote), and
the hypervisor is not trusted: but it cannot change HOST_DATA after launch,
and the processor reports it, signed, in every report. So it may choose any
value, but cannot hide its choice: a key other than the owner's fails check
8 and nothing is sent, and stage 0 itself refuses to start sshd unless the
key it is given in fw_cfg hashes to its own HOST_DATA. The passphrase's
confidentiality rests on the measurement and REPORT_DATA; HOST_DATA decides
who may connect to stage 0 at all.

**What travels, and how:**

| What | Direction | Encoding |
|---|---|---|
| The nonce | owner's computer → VM | hex text, in the SSH command (`attest <64 hex>`) |
| Stage 0's host key | VM → owner's computer | base64, as in a `.pub` line (`host-key …`) |
| The report | VM → owner's computer | hex text, 2368 digits (`report …`) |
| The passphrase | owner's computer → VM | raw bytes, on standard input |

Binary appears only as hash inputs and in the configfs-tsm files; the
passphrase is the one thing sent as bare bytes. All of it travels inside the
SSH connection, encrypted to the host key the report vouches for.

## Who is involved, and whom each trusts

| Party | Runs | Trusted by the owner for |
|---|---|---|
| The owner's computer | `vmt-unlock`, OpenSSH's `ssh`, `ssh-keygen`, `ssh-add`, `curl` | everything: it holds the disk passphrase and the keys |
| The host (the provider's server, and the provider) | QEMU, libvirt, OVMF, the network path | **nothing**. It can stop the VM or refuse to start it, and that is all it should be able to do |
| The VM's processor (AMD SEV-SNP firmware) | the guest's memory encryption; signs reports | the report's contents, through AMD's certificate chain |
| AMD's key distribution service (KDS) | serves the VCEK for a chip and TCB | nothing: what it serves must chain to the ARK and ASK pinned in the tool |
| Stage 0, inside the VM | a measured kernel and initrd: sshd, `stage0-agent`, `cryptsetup` | only once the report proves it is the stage 0 the owner accepts |

The exchange is built so that the passphrase reaches stage 0 only, and only a
stage 0 whose identity, launch and SSH host key the processor has vouched for
in this very session. Every other party sees ciphertext or nothing.

## Before anything connects: what the launch fixes

The host prepares the VM's definition with `stage0/install.sh --build <dir>
--domain <name> --org-ca <unlock-key.pub>`, which sets:

- **Measured direct boot.** The domain boots the build's own firmware
  (`<loader>`, a copy of the snapshot's `OVMF.amdsev.fd`) and stage 0's kernel
  and initrd with the manifest's command line (`<kernel>`, `<initrd>`,
  `<cmdline>`, and `kernelHashes='yes'` on `<launchSecurity
  type='sev-snp'>`). OVMF hashes the last three into its own measured pages,
  so the launch **measurement** (the report's `MEASUREMENT`) covers firmware,
  kernel, initrd and command line.
  The command line is `root=/dev/mapper/ubuntu--vg-ubuntu--lv ro panic=-1
  console=tty0 console=ttyS0,115200` (`stage0/cmdline`); `panic=-1` turns
  every stage 0 panic into the end of the VM. The manifest gives one
  measurement per vCPU count; `install.sh` prints the one for the domain's.
- **SEV features `0x21`: SNPActive and DebugSwap.** They are in every vCPU's
  initial state, so the measurement covers them, and stage 0's kexec needs
  DebugSwap (see *After the unlock*). QEMU sets them, and no QEMU release can
  set DebugSwap yet: for a build whose manifest has it, `install.sh` points
  the domain at the QEMU given as `--debug-swap-qemu` (`<emulator>`), one
  built to set it when its environment has `QEMU_SEV_DEBUG_SWAP=1`, and sets
  that variable (`<qemu:env>`). A build without it gets the ordinary QEMU and
  no variable. The host could leave DebugSwap off, or set any other feature;
  either changes the measurement.
- **A reboot is a new launch** (`<on_reboot>destroy</on_reboot>`): the
  VM's reboot ends its QEMU, and the host starts it again from the
  beginning, measured as above. A QEMU that resets an SNP guest in place
  (QEMU master can) gave a measurement matching none of the build's, and the
  owner's tool would refuse it.
- **`host_data` = SHA-256 of the server unlock key's wire blob.** The key is
  one `ssh-ed25519` line. Its blob is the base64 field decoded (the OpenSSH
  wire form: string `"ssh-ed25519"`, then the 32-byte key; 51 bytes), so a
  comment or whitespace cannot change it. The host sets this 32-byte value at
  launch (`<hostData>`, base64); the processor reports it at offset `0xC0` of
  every report and the host cannot change it afterwards.
  `snp::binding::host_data_for_ca` is the one definition, used by stage 0 and
  by the tool.
- **The unlock key itself, in fw_cfg**, as the entry
  `opt/org.vmtrust/org-ca.pub` (the line `ssh-ed25519 <base64>`). The names
  `org-ca` and `org.vmtrust` predate the term "server unlock key"; they are
  part of what is measured and deployed, so they stay.

The guest policy (debug off, migration agent off, and so on) is fixed at
launch by the host's domain definition, not by `install.sh`; the owner checks
it in the report (check 6).

A **solo server**'s unlock key is its owner's own SSH key. An **organization
server** has a separate unlock key, and each person who may unlock holds a
certificate signed with it. Stage 0 cannot tell the two apart and does not
need to: it trusts one key as a certificate authority, and a key may sign its
own certificate.

## Stage 0 boots

In order, from `stage0/initramfs/scripts/init-premount/stage0` (before the
root device is looked for):

1. **SysRq off** (`/proc/sys/kernel/sysrq` = 0). The host controls the
   keyboard and the serial console; stage 0 reads neither, and this removes
   the one thing that would still act on a keypress.
2. **configfs mounted** if it is not, and `/sys/kernel/config/tsm/report`
   must exist (no configfs-tsm: not an SEV-SNP guest; panic).
3. **The unlock key from fw_cfg**, copied to `/run/stage0/org-ca.pub` (a
   tmpfs, mode 0700 directory), then **checked against `host_data`**:
   `stage0-agent --check-host-data /run/stage0/org-ca.pub` requires exactly
   one `ssh-ed25519` line, asks the processor for a report (REPORT_DATA all
   zeroes: only `host_data` is read, and the report is fresh, so it is this
   launch's), requires VMPL 0, and compares `host_data` with SHA-256 of the
   key's blob. On any mismatch it panics, sshd never starts, and `panic=-1`
   ends the VM. This argument form is reachable only from the boot script:
   sshd runs the agent with no arguments (below).
4. **DHCP** (`IP=dhcp configure_networking`; not `ip=` on the command line,
   which would configure the network a second time after root is mounted).
5. **A fresh Ed25519 host key**, `/run/stage0/host_ed25519`, made by
   `ssh-keygen` now. It exists only in this boot's memory, which SEV-SNP
   encrypts; never on disk, never in the image. Its fingerprint goes to the
   console.
6. **sshd**, on port 2222, with this configuration and nothing else:

   ```
   Port 2222
   HostKey /run/stage0/host_ed25519
   PidFile none
   TrustedUserCAKeys /run/stage0/org-ca.pub
   AuthorizedPrincipalsFile /etc/stage0/principals     # one line: unlock
   AuthorizedKeysFile none
   AllowUsers root
   PermitRootLogin prohibit-password
   PubkeyAuthentication yes
   PasswordAuthentication no
   KbdInteractiveAuthentication no
   UsePAM no
   PermitTTY no
   PermitUserRC no
   PermitUserEnvironment no
   DisableForwarding yes
   PermitTunnel no
   LoginGraceTime 30
   MaxAuthTries 3
   ClientAliveInterval 15
   ClientAliveCountMax 4
   ForceCommand /usr/sbin/stage0-agent
   ```

   So the only way in is as `root`, with a **certificate** signed by the key
   that `host_data` named, carrying the principal **`unlock`**; no plain
   keys, no passwords, no terminal, no forwarding, and whatever command the
   client asks for, sshd runs `stage0-agent`, which reads the request from
   `SSH_ORIGINAL_COMMAND`.

Then `scripts/local-top/stage0` waits, checking once a second, for
`/run/stage0/unlocked`, however long that takes.

The host cannot connect: it has no certificate from the unlock key, and it
cannot make one. It cannot swap the unlock key for its own either: stage 0
would refuse to start sshd (step 3), and the owner would see the wrong
`host_data` anyway (check 8).

## The owner's side, before connecting

`vmt-unlock <server>` reads `~/.config/vmt-unlock/<server>/config`
(`$XDG_CONFIG_HOME` respected; `attest/vmt-unlock/src/config.rs`), with
command-line options overriding it. From it:

- **The VM**: `host`, `port` (default 2222), `user` (default `root`), and
  optionally `jump` (passed to `ssh -J`; nothing depends on the jump host,
  whose traffic is the SSH connection's ciphertext).
- **The owner's SSH key**, `identity`, and **certificate**, `certificate`.
- **The unlock key's public half**, `unlock-key`: the **owner's own copy**,
  never one from the provider. Its blob gives the `host_data` the report
  must carry. This is what makes the unlock key self-checking: a key swapped
  on its way to the provider at enrollment means the VM was started for the
  swapped key, and check 8 fails at the first unlock, before any passphrase
  is sent.
- **`min-tcb`** (`bootloader:tee:snp:microcode`, decimal) and one or more
  **`measurement`** lines (96 hex digits each; during a rollover, two).

**A solo server's certificate** is made for this one unlock. When no
certificate is configured and `identity`'s `.pub` is the unlock key itself,
the tool first checks (`ssh-add -L`) that the SSH agent holds that key,
refusing with the `ssh-add` command to run if not, then signs, through the
agent, in the session's private folder:

```
ssh-keygen -q -U -s solo.pub -I "vmt-unlock solo <unix time>" -n unlock -O clear -V -1m:+5m solo.pub
```

`-U` keeps the private half in the agent. Valid from a minute ago (clock
skew) for five minutes, for the one principal stage 0 accepts, with no
extensions; gone with the session's folder.

**The certificate is checked before anything connects**
(`attest/vmt-unlock/src/cert.rs`). The one this unlock will present (the
configured `certificate`, or, with none configured, ssh's own default
`<identity>-cert.pub` if it exists; never a solo server's, which is made for
this unlock) is read and judged as stage 0's sshd would judge it, so a
certificate the VM would refuse is named here, with what is wrong, instead
of surfacing as ssh's `Permission denied (publickey)`. It is refused (exit
2) if it is a host certificate, does not name the principal `unlock`, was
signed with a key other than the config's `unlock-key`, certifies a
different key from `identity`'s `.pub`, or has ended (its valid-before time
at or before this computer's clock); a configured certificate that does not
exist is refused too. Within 30 days of its end, every unlock prints a
`WARNING:` line with the end date, in this computer's time zone, as
`ssh-keygen -L` shows it. A file that is not an Ed25519 certificate this
reads is left to OpenSSH. Only the certificate's fields are read here; its
signature is sshd's to verify. The clock that finally decides is the VM's:
a computer whose clock is far off can refuse a certificate the VM would
still take, and the message gives today's date so that shows.

**The passphrase source** is decided now but read later: from `--key-file`
(read first, byte for byte, so a wrong path fails before anything
connects), standard input (`--key-file -`), `$VMT_UNLOCK_PASSPHRASE`, or a
prompt (`Disk passphrase: `, echo off, on `/dev/tty`; the line ending is the
Enter key and is not sent). Every source but a file is read only after every
check has passed.

## One SSH connection, and the host key it records

Everything happens over **one** SSH connection: a ControlMaster, with each
request a session multiplexed over it (`attest/vmt-unlock/src/ssh.rs`). A
second, independent connection would not be bound to the report, and would
reopen the relay attack below.

The tool makes a private folder, `$XDG_RUNTIME_DIR/vmtu-<12 hex digits>` (or
under the system's temporary folder), mode 0700, for the control socket, a
private `known_hosts`, the master's log and any solo certificate. It is
removed when the tool finishes, after `ssh -O exit`.

Every `ssh` the tool runs carries:

```
-o BatchMode=yes
-o ControlPath=<folder>/c
-o UserKnownHostsFile=<folder>/known_hosts
-o GlobalKnownHostsFile=/dev/null
-o HostKeyAlgorithms=ssh-ed25519
-o HashKnownHosts=no -o UpdateHostKeys=no -o CheckHostIP=no
-o ConnectTimeout=20 -o ServerAliveInterval=10
-o RequestTTY=no -o ForwardAgent=no -o ClearAllForwardings=yes
-p <port>
-i <identity> -o IdentitiesOnly=yes          (when there is an identity)
-o CertificateFile=<certificate>              (configured, or the solo one)
-J <jump>                                     (when there is one)
```

The user's own `~/.ssh/config` still applies where these do not override it
(on a Mac, `UseKeychain` for the identity's passphrase, for instance).

1. **The master** connects with `-o ControlMaster=yes -o
   StrictHostKeyChecking=accept-new -N -f`: it accepts whatever host key
   stage 0 presents, since the tool cannot know it in advance (it was made at
   this boot), and records it in the private `known_hosts`. Authentication is
   the certificate. If this fails, the master's own error is shown and the
   tool stops (exit 3); nothing has been sent.
2. **The recorded key** is read back: there must be exactly one entry for
   this destination (`[host]:port`, or `host` on port 22), and it must be
   Ed25519. None, several, or another type is refused. Its wire blob is
   **the session's host key**: the key the client's SSH layer actually
   authenticated the server with, and so the key whose private half the far
   end of this connection holds. From here on, this blob is what the report
   must be bound to; anything the guest *says* its host key is, is compared
   only for a warning.
3. **Each request** first asks the master whether it is still there (`ssh -O
   check`); if not, the request fails (exit 3). It never reconnects, since a
   new connection would be unbound. Then it runs as a session over the master:
   `-o ControlMaster=no -o StrictHostKeyChecking=yes -T`, so even if the
   multiplexer were somehow bypassed, a fresh connection would have to present
   the recorded key, which only the attested stage 0 holds.

## Request 1: `attest <nonce>`

**The tool** makes a nonce of 32 bytes from `/dev/urandom` and runs, over the
master:

```
ssh … root@<host> attest <64 lowercase hex digits>
```

**sshd** sets `SSH_ORIGINAL_COMMAND` to `attest <hex>` and runs
`stage0-agent`. The agent splits it on ASCII whitespace and accepts exactly
two words, `attest` and 64 hex digits (32 bytes); anything else is refused.

**The agent**:

1. Reads its own host key, `/run/stage0/host_ed25519.pub`, and takes its wire
   blob.
2. Computes **REPORT_DATA = SHA-512(nonce || host key blob)**: 64 bytes,
   exactly the size of the report's REPORT_DATA field
   (`snp::binding::report_data_for`, the same function the tool checks with).
3. Asks the processor for a report through **configfs-tsm**: makes
   `/sys/kernel/config/tsm/report/stage0-<pid>`, requires its `provider` to
   be `sev_guest`, writes `0` to `privlevel` (VMPL 0) and the 64 bytes to
   `inblob`, reads `generation`, reads `outblob` (the report), reads
   `generation` again and refuses if it changed (another writer changed the
   request in between). The directory is removed however the request ends.
4. Parses the report as a guard, not a security check: if it is not for this
   REPORT_DATA at VMPL 0, it refuses rather than return it.
5. Replies on standard output, exactly three lines, and exits 0:

   ```
   stage0-attest 1
   host-key ssh-ed25519 <base64 of its host key blob>
   report <2368 hex digits: the 0x4A0-byte report>
   ```

   and logs `stage0-agent: attestation report served` on the console. No
   certificates: the owner fetches those, from AMD.

**The tool** requires exit status 0 and exactly those three lines, the first
exactly `stage0-attest 1` (anything else: exit 3, "not in the stage 0
format"). If the report does not parse (wrong length, unknown version), that
is a failed verification, not a transport error: evidence is kept and the
tool exits 1. If the `host-key` line is not the session's key, the tool says
so as a `WARNING`; the check that decides is check 4, against the session's
key, never against what the guest claims.

## The VCEK, from AMD

The report is signed with the **VCEK**, a key unique to the chip and its
firmware levels. The tool looks it up by the report's `CHIP_ID` and
`REPORTED_TCB` (using these before the report is verified is safe: a wrong
VCEK fails to chain, or fails the signature):

1. The cache, `$XDG_CACHE_HOME/vmt-unlock/vcek/` (or `~/.cache/…`, or
   `--vcek-cache`), file `milan-<chip_id hex>-<bl>-<tee>-<snp>-<ucode>.der`.
   Most unlocks need nothing more, and AMD learns nothing.
2. Otherwise, unless `--offline`, AMD KDS:
   `https://kdsintf.amd.com/vcek/v1/Milan/<chip_id hex>?blSPL=..&teeSPL=..&snpSPL=..&ucodeSPL=..`
   with `curl -sSf --proto =https --max-time 30` (through `--kds-proxy`, e.g.
   Tor's SOCKS port, if given). HTTPS is a convenience, not a check. The
   VCEK enters the cache only if it chains to the pinned certificates.

A zero `CHIP_ID` (policy MaskChipId) has no VCEK to fetch, and fails.

## The checks

`snp::verify::verify` runs all ten (the tenth only with `--chip-id`) and
reports every result, so a failure says everything that is wrong at once.
The verdict passes only if none fails. Report fields are read from these
offsets (little-endian; `attest/snp/src/report.rs`):

| Offset | Field | Used by |
|---|---|---|
| `0x000` | VERSION (2 to 5 accepted) | 3 |
| `0x008` | POLICY | 6 |
| `0x030` | VMPL | 7 |
| `0x034` | SIGNATURE_ALGO | 3 |
| `0x048` | KEY_INFO (SIGNING_KEY, MASK_CHIP_KEY) | 2 |
| `0x050` | REPORT_DATA (64) | 4 |
| `0x090` | MEASUREMENT (48) | 5 |
| `0x0C0` | HOST_DATA (32) | 8 |
| `0x180` | REPORTED_TCB | 1, 9 |
| `0x1A0` | CHIP_ID (64) | 1, 10 |
| `0x2A0` | SIGNATURE: r and s, 72 bytes each, little-endian | 2 |

The signed bytes are `0x000` to `0x29F`.

1. **Certificate chain, VCEK → ASK → ARK.** The ARK and ASK for Milan are
   compiled into the tool (`attest/snp/pins/`) and checked against their
   SHA-256 before use (`ARK_MILAN_SHA256`, `ASK_MILAN_SHA256` in
   `certs.rs`), and the ARK's own signature and the ASK's by the ARK are
   verified again. The VCEK must be signed by the ASK (RSASSA-PSS, SHA-384,
   48-byte salt), be
   for this report's `CHIP_ID` and `REPORTED_TCB`, and name a Milan product.
   A zero `CHIP_ID` fails. (Milan's are the only ARK and ASK there are here:
   see *Milan only, for now*.)
2. **Signature.** SIGNING_KEY must be 0 (the VCEK), MASK_CHIP_KEY clear, the
   signature field well formed (zeroes past the 48 bytes of r and of s, and in
   the reserved rest), and ECDSA P-384 with SHA-384 over bytes `0x000`–`0x29F`
   must verify under the VCEK.
3. **Version and algorithm.** A version this verifier knows, and
   SIGNATURE_ALGO 1 (ECDSA P-384 with SHA-384).
4. **The binding.** REPORT_DATA must equal SHA-512(this nonce || **this
   session's** host key blob). This is what ties the report to *this*
   connection, now.
5. **Measurement.** In the accepted set: the stage 0 build the owner accepts
   (firmware, kernel, initrd, command line), for the VM's vCPU count.
6. **Policy.** Debugging off, no migration agent, no CXL memory, reserved
   bit 17 set, SMT only if allowed (`--no-smt` forbids it), no bit this
   verifier does not know, and an ABI at or above `--min-abi`.
7. **VMPL 0**: the report was requested at the most privileged level.
8. **host_data** equals SHA-256 of the owner's own copy of the unlock key's
   blob: the VM was started for the owner's key. (Stage 0 has already refused
   to run with any other; this is the owner's own confirmation.)
9. **TCB** at or above `min-tcb`, each of the four components.
10. **CHIP_ID** in the allowlist, if `--chip-id` gave one; otherwise not run,
    and neither shown nor counted.

**If any check fails**, nothing is sent. The tool keeps the evidence, none of
it secret, in `./vmt-unlock-evidence-<unix time>/` (or `--save`'s folder):
`nonce.bin`, `report.bin`, `session-hostkey.pub`, `vcek.der` and
`verdict.txt`. It prints `VERIFICATION FAILED. The disk passphrase was not
sent.` and exits 1. The SSH connection closes; stage 0 keeps waiting.

## Request 2: `unlock`, the passphrase on stdin

**The tool** reads the passphrase now (unless a file already gave it) and
runs, over the same master:

```
ssh … root@<host> unlock          (standard input: the passphrase bytes, then end of file)
```

The bytes are exactly the passphrase: no newline is added (a prompted one
has its Enter removed; a `--key-file` is sent byte for byte, so a file
ending in a newline sends one). The tool's copy is zeroed once the session
ends. Inside SSH, the bytes are encrypted to the session whose host key the
report has just vouched for.

**The agent**, for `unlock` (exactly that one word):

1. Takes an exclusive lock on `/run/stage0/unlock.lock` (one unlock at a
   time), and refuses if `/run/stage0/unlocked` already exists.
2. Reads standard input to end of file, at most 8192 bytes (more, or none,
   is refused).
3. Finds **the** LUKS volume: every device in `/sys/class/block` whose first
   six bytes are `LUKS\xba\xbe`. Exactly one, or it refuses (stage 0 does not
   guess).
4. Opens it: `cryptsetup open --type luks --key-file=- <device>
   stage0_crypt`, the passphrase on cryptsetup's standard input, which is
   then closed. The key goes from the SSH channel to cryptsetup and is never
   written to a file. The agent's buffer is then zeroed (volatile writes, so
   the compiler cannot drop them).
5. Loads the VM's own kernel to start (design §10.2): `lvm vgchange -a y
   --sysinit`, waits up to 10 seconds for the command line's `root=` device,
   and mounts it read-only. From it:
   - **the volume's crypttab line**: the one line of `/etc/crypttab` whose
     source is `UUID=<the volume's LUKS UUID>` (or its `/dev/disk/by-uuid/`
     path), for its name and options. None, or more than one, is refused, and
     so is an option that would make the key file be ignored (`keyscript=`)
     or the volume not be LUKS (`plain`, `tcrypt`, `bitlk`);
   - **the kernel and initrd**: `/boot/vmlinuz` and `/boot/initrd.img`, which
     must be links to files beside them in `/boot`, named for the same version
     (`vmlinuz-<v>`, `initrd.img-<v>`), as Ubuntu keeps them.

   It assembles the initrd in an anonymous memory file (`memfd_create`, in
   no file system): a newc cpio archive holding `/cryptroot/stage0.key`
   (mode 0400, the passphrase's bytes), then the VM's initrd unchanged. The
   kernel unpacks the two in order, and the VM's archive never touches that
   file. The command line is this boot's (`/proc/cmdline`, the measured one,
   less any `initrd=` the firmware added), plus
   `cryptopts=target=<name>,source=UUID=<uuid>,key=/cryptroot/stage0.key,<options>,luks`
   (`luks` only if the options lack it): Ubuntu's cryptroot script then opens
   the volume with that file under its crypttab name, instead of asking.
   `kexec_file_load(2)` loads the three; the kernel keeps its own copy, and
   the agent zeroes the passphrase in the memory file and in its own buffers.
   Then it unmounts the root and locks the disk again (`lvm vgchange -a n`,
   `cryptsetup close`): the VM's initramfs opens it afresh. Any failure up
   to the load also locks the disk again and is refused, saying why; the VM
   keeps waiting.
6. Replies, exits 0, and logs `<device> unlocked; the guest's vmlinuz-<v> is
   loaded to start` on the console:

   ```
   stage0-unlock 1
   unlocked /dev/vda3
   ```

7. Writes `/run/stage0/unlocked` (the device; no secret), which releases
   the boot. The reply is written first: teardown, which follows, stops sshd.

A wrong passphrase is cryptsetup's failure (`No key available with this
passphrase.`), returned as an error; nothing changes, and stage 0 keeps
waiting for another attempt.

**The tool** reports success only if the session exited 0 and its output
begins with `stage0-unlock 1`, newline, `unlocked `. It then prints
`vmt-unlock: VM: unlocked <device>` and exits 0. Anything else is "the VM did
not unlock", with stage 0's error text, exit 4.

## After the unlock: the kexec

`local-top` sees the flag and stops every stage 0 process (sshd, its
session processes, the agent, dhcpcd): it gives the unlock session up to 10
seconds to deliver its reply, then kills, waits, kills harder; any survivor
is a panic. Then it runs `stage0-agent --kexec`, which requires
`/sys/kernel/kexec_loaded` to be `1` and starts the loaded kernel
(`reboot(LINUX_REBOOT_CMD_KEXEC)`). No SSH session can pass that argument.
If the kernel does not start, the script panics, and `panic=-1` ends the VM.

Nothing of stage 0 survives the kexec but what it loaded: no process, no
mount, no network setting, no file under `/run` (the host key among them).
initramfs-tools never mounts a root in stage 0 or reaches `init-bottom`.

The VM's own kernel and initramfs start as they would from a bootloader,
with the command line above: the initramfs finds
`/cryptroot/stage0.key`, opens the volume under its crypttab name, and boots
the VM's system, which removes the initramfs and the key file with it when
it takes over. The booted system has its own SSH host key, on the encrypted
disk, which is what the owner's ordinary logins check.

**The kexec needs DebugSwap.** In an SNP guest without it, the outgoing
kernel's `machine_kexec()` writes DR7 after it has torn down the GHCBs, the
write raises a #VC nothing can service, and the VM hangs; the kernel fix is
not upstream yet. With DebugSwap (SEV feature bit 5, `0x20`) the processor
swaps DR7 itself and the write is never intercepted. The launch sets it:
stage 0's measurements are computed with guest features `0x21` (SNPActive
and DebugSwap; `stage0/image.sh`, the manifest's `guest.features`), so a VM
launched without it reports another measurement, and the owner's tool
refuses it (check 5).

## Errors and exit status

The agent writes `stage0: error: <reason>` on standard error, exits 1, and
logs `stage0-agent: request refused: <reason>` on the console. It never puts
a secret in either.

The tool's exit status:

| Status | Meaning | Passphrase sent? |
|---|---|---|
| 0 | unlocked | yes |
| 1 | a check failed (or the report could not be read); evidence kept | no |
| 2 | usage or configuration error, including a certificate the VM would refuse | no |
| 3 | connection or protocol error | no |
| 4 | the VM did not unlock: it refused the passphrase, or could not start the system | yes, to the verified stage 0 |

## Why it holds

- **A relay.** The host could accept the owner's connection itself and pass
  the requests to the real VM, hoping to read the passphrase in the middle.
  To read it, the host must terminate SSH with a host key of its own, and
  then the session's host key (recorded by the client) is not the key stage 0
  bound into REPORT_DATA: check 4 fails. If the host instead forwards the
  bytes untouched, it reads nothing.
- **A replay.** An old report, even a genuine one from this VM, carries an
  old nonce: check 4 fails. The nonce is fresh for every attempt.
- **A different or modified guest.** Changed firmware, kernel, initrd or
  command line changes the measurement (check 5); debugging or a migration
  agent changes the policy (check 6); a guest that is not SEV-SNP has no
  report AMD's chain will sign (checks 1–2).
- **A substituted unlock key.** The host could launch the VM for a key of its
  own, to make itself a certificate. Then `host_data` is that key's (check 8
  fails for the owner), and if fw_cfg and `host_data` disagree, stage 0 never
  starts sshd.
- **Older firmware with known flaws**: check 9.
- **A substituted root filesystem.** The host could swap the encrypted disk,
  so that a genuine stage 0 opens a disk of the host's. That disk's LUKS
  header does not accept the owner's passphrase, so the unlock fails (exit 4).
  If the host somehow got a disk that did, the booted system would lack the
  owner's own SSH host key, and the owner's next login would warn (design
  §9.1).
- **The system that runs afterwards.** The measurement covers stage 0 only.
  The kernel and initrd stage 0 starts come from the encrypted disk the
  owner's passphrase just opened, which the host can damage but cannot
  read, nor write chosen content to; stage 0 hands the passphrase to them
  and to nothing else.
  Whatever the owner's own system then does, including asking the processor
  for reports (they carry the same launch measurement: a report proves how
  the VM was launched, not what it runs now), is the owner's system's doing.

What it cannot do: keep the VM running. The host can always stop it, or
refuse to start it. And the passphrase protects the disk only as well as its
own strength and the owner's computer protect it.

## Milan only, for now

Everything here is for **AMD EPYC Milan**, the only processor generation in
scope today. Each generation has its **own AMD root key (ARK) and signing
key (ASK)**, so supporting Genoa, Turin, Venice or any later generation is
not a matter of configuration: it needs that generation's ARK and ASK pinned
and their fingerprints recorded, as Milan's were (fetched twice, from two
places, and compared), and a way to choose the right chain for a report.
**Revisit all of the following then:**

- **The pinned chain:** `attest/snp/pins/ark-milan.der` and `ask-milan.der`,
  their SHA-256 constants, and `AmdChain::milan()` (`attest/snp/src/certs.rs`),
  which `vmt-unlock` uses unconditionally.
- **The VCEK's product check:** check 1 requires a Milan VCEK
  (`attest/snp/src/verify.rs`).
- **AMD KDS:** the VCEK's address names the product (`/vcek/v1/Milan/…`),
  and the cache's file names begin `milan-` (`attest/vmt-unlock/src/kds.rs`).
- **The TCB layout:** `Tcb::from_u64` reads Milan's (and Genoa's) layout
  (`attest/snp/src/report.rs`); later generations lay TCB_VERSION out
  differently, which the TCB minimums (check 9), the VCEK lookup and the
  VCEK match (check 1) all depend on.
- **Report versions and fields:** the parser accepts versions 2 to 5; a new
  generation may bring a newer version, or fields this verifier does not
  read.
- **The measurement:** it depends on the guest's vCPU type (the manifest's
  measurements, computed with `VCPU_TYPE=EPYC-Milan` in `stage0/image.sh`,
  and the measurement guide's `--vcpu-type=EPYC-Milan`), so a VM on another
  generation has other measurements.
- **`unlock-by-hand.sh`**, which is Milan only in the same ways.

**The report says which generation it came from.** From report version 3,
bytes `0x188`, `0x189` and `0x18A` are the CPUID family, model and stepping
of the processor that made it; the Milan reports in `test/fixtures/snp/`
(version 5) carry `0x19`, `0x01`, `0x01`: family 19h, model 01h. The VCEK
says so too (its product-name extension, `Milan-B0` on those). So with
several generations in service the tool can choose the chain from the
report itself, before verifying it: the fields are inside the signed bytes,
and a report that claims the wrong generation does not verify under the
chain that claim selects (check 1 or 2 fails). What the report's generation
cannot decide alone is which measurements and TCB minimums to accept: those
differ by generation, and come from the owner's configuration, per
generation.

## Doing it with standard commands

Nothing in the owner's side needs vmt-unlock. Every step can be done with
commands a Mac or a Linux machine already has, and `docs/unlock-by-hand.sh`
does them, as a sketch (below). Even the single connection is no exception:
vmt-unlock does no SSH of its own. It runs the stock `ssh` client and uses
OpenSSH's ControlMaster, which anyone can use from a shell.

| Step | With standard commands |
|---|---|
| Nonce | `openssl rand -hex 32` |
| One connection | `ssh -M -S <socket> -o UserKnownHostsFile=<private file> -o StrictHostKeyChecking=accept-new -N -f -p 2222 root@<vm>` opens it; every later `ssh -S <socket> root@<vm> …` rides it. This is exactly what vmt-unlock runs |
| The session's host key | read it from that private known_hosts file (not from the reply), and base64-decode it for the blob |
| A solo server's certificate | `ssh-keygen -U -s …` through the agent: also exactly what vmt-unlock runs |
| `attest` | `ssh -S <socket> root@<vm> attest $nonce`, and split the three reply lines with `sed` |
| REPORT_DATA | SHA-512 of the nonce's bytes and the blob (`openssl dgst -sha512`, or `shasum -a 512`), compared with the 64 bytes at 0x50 of the report (`od`, or `xxd`) |
| Measurement, HOST_DATA, VMPL, chip ID, TCB | fixed offsets in the report, read the same way and compared as hex |
| Policy | one 64-bit field, its bits tested with shell arithmetic |
| VCEK | `curl`, from AMD's KDS, by chip ID and TCB |
| Certificate chain | `openssl verify` (the VCEK, through the ASK, to an ARK whose SHA-256 you check first) |
| Sending the passphrase | `ssh -S <socket> root@<vm> unlock < file`, or read without echo and `printf '%s'` it in |

**The fiddly parts**, none impossible, each easy to get subtly wrong:

1. **The report's signature.** The report keeps ECDSA's r and s
   little-endian, each in a 72-byte field; `openssl dgst -sha384 -verify`
   wants them big-endian inside a DER structure. They have to be reversed,
   stripped of their padding, given a leading zero where the top bit is set,
   and wrapped in DER by hand. It is the step a hand-rolled version is most
   likely to botch; a wrong-endian signature fails safe, but a sloppy script
   might ignore the failure.
2. **The VCEK's AMD extensions.** The VCEK must be for this chip and these
   firmware levels, which sit in AMD-specific X.509 extensions:
   `openssl asn1parse` shows them as raw bytes, to be picked out and compared
   with the report.
3. **RSA-PSS.** The ASK and the VCEK are signed with RSA-PSS. OpenSSL 3 on
   Linux verifies the chain fine. macOS's `openssl` is LibreSSL, and whether
   its chain verification handles RSA-PSS is unconfirmed: check that first on
   a Mac.
4. **Failing safe.** The passphrase must never be sent unless every check
   passed. In a shell script, one unchecked exit status, or a comparison that
   treats an empty string as a match, quietly breaks that.
5. **The passphrase itself.** It must stay out of the command line and the
   environment (both visible in `ps`), out of files and shell history, and
   gain no newline: `cryptsetup` takes every byte.

**What vmt-unlock adds**, then, is not a capability. The connection, the
solo certificate and the VCEK download it delegates to `ssh`, `ssh-keygen`
and `curl`. What it does itself is the verification, in Rust: the report's
parsing, the ECDSA and RSA-PSS checks, the extensions, the binding, the same
way every time, tested against real reports from Milan, with one exit path
that sends nothing unless everything passed; and `--step`'s explanations,
the evidence it keeps on a failure, and its VCEK cache.

### `unlock-by-hand.sh`

A bash script, written for bash 3.2 and later (a Mac's own) but run only on
bash 5.2, that reads vmt-unlock's config and does the exchange with the commands above:

```
docs/unlock-by-hand.sh <config>                  attest, check, and only then unlock
docs/unlock-by-hand.sh --verify <dir> <config>   check saved evidence, send nothing
```

It runs most of the checks: the pinned ARK and ASK, the chain, the VCEK's
chip and TCB, the signature and signing key, the version, the binding, the
measurement, debugging and the migration agent off, VMPL 0, host_data and
the TCB minimums. It leaves out the policy's other bits and ABI, the VCEK's
product name, a VCEK cache, `--step` and evidence. `UNLOCK_BY_HAND_VCEK`
gives it a VCEK from a file instead of AMD (one vmt-unlock cached, say).
**It is a sketch, to show the exchange needs no special software: use
vmt-unlock to unlock a real VM.**

What it was tested against, on Linux (OpenSSL 3.0.13, OpenSSH 9.6):

- `--verify`, on the genuine reports in `test/fixtures/snp/`: the binding
  report, with its nonce and stand-in host key, passes every check but
  host_data (its host_data is zero); the host_data report passes host_data
  and fails the binding (its REPORT_DATA is zero). One byte flipped inside
  the signed area fails the signature; another nonce fails the binding; the
  same chip's VCEK at another TCB fails the TCB match and the signature.
- The live path, against a local sshd configured as stage 0's is
  (certificate only, principal `unlock`, a forced command) with a stand-in
  agent that answers `attest` with a genuine fixture report: the solo
  certificate signed through the agent and accepted by sshd, one connection,
  the session's host key recorded, the reply decoded, and every check run,
  which then refused, rightly, since the report was not made for that
  session; nothing reached the stand-in's `unlock`.

Not tested: on a Mac; against a real stage 0; the `unlock` that follows a
passing verification, which only a real stage 0 can give.

## Versions

Both replies begin with a format version, `stage0-attest 1` and
`stage0-unlock 1`; the tool accepts exactly `1`. A change to either reply's
format changes that number, and the stage 0 agent's binary, and so the
launch measurement of every stage 0 built from it.
