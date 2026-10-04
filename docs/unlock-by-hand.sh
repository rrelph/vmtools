#!/usr/bin/env bash
# unlock-by-hand.sh — the attested unlock with ordinary tools: bash, ssh,
# ssh-keygen, openssl, curl, od, sed, awk. A SKETCH, to show it can be done
# without vmt-unlock (docs/unlock-exchange.md, "Doing it with standard
# commands"). It is not a replacement: use vmt-unlock to unlock a real VM.
#
#   unlock-by-hand.sh <config>              attest, check, and only then unlock
#   unlock-by-hand.sh --verify <dir> <config>
#                                           check saved evidence, send nothing:
#                                           <dir> holds nonce.bin, report.bin,
#                                           session-hostkey.pub and vcek.der (or
#                                           vcek.pem), as vmt-unlock --save
#                                           writes them
#
# <config> is vmt-unlock's file (~/.config/vmt-unlock/<server>/config):
# host, port, user, identity, certificate, unlock-key, min-tcb, measurement.
#
# What it checks: the AMD chain (ARK -> ASK -> VCEK, the ARK and ASK pinned
# by SHA-256), the VCEK is for this chip and TCB, the report's signature,
# version and signing key, REPORT_DATA = SHA-512(nonce || this session's
# host key), the measurement, the policy (debug and migration agent off),
# VMPL 0, host_data = SHA-256(unlock key) and the TCB minimums. What it
# leaves out, which vmt-unlock does not: the policy's other bits and ABI,
# the VCEK's product name, a VCEK cache, --step, evidence on failure.
#
# Written for bash 3.2 and later (a Mac's own); run only on bash 5.2.
# Tested on Linux (OpenSSL 3) against the genuine reports in
# test/fixtures/snp, and against a local sshd standing in for stage 0. Not
# tested on a Mac: macOS's openssl is LibreSSL, whose verification of the
# ASK's and VCEK's RSA-PSS signatures is unconfirmed.
set -euo pipefail

die() { echo "unlock-by-hand: $*" >&2; exit 1; }
for t in ssh ssh-keygen openssl curl od sed awk; do
    command -v "$t" >/dev/null || die "needs $t"
done

# The ARK and ASK for Milan, as vmt-unlock pins them (attest/snp/src/certs.rs).
PINS="$(cd "$(dirname "${BASH_SOURCE[0]}")/../attest/snp/pins" && pwd)"
ARK_SHA256=69d063b45344d26a2e94e1f4210de49ef555308287d4c174445c95639a540bcd
ASK_SHA256=67d303bd3905fd38db8b20e0793699870e7fa612eaad5dec358293fd8c0bac1b

# --------------------------------------------------------------- helpers ---
# hex <file> <offset> <length>: bytes of a file as lowercase hex, in file order.
hex() { od -An -tx1 -v -j "$(($2))" -N "$(($3))" "$1" | tr -d ' \n'; }
# le <file> <offset> <length>: a little-endian number, as a decimal integer.
le() { echo $((16#$(hex "$1" "$2" "$3" | fold -w2 | awk '{a[NR]=$0} END {for (i = NR; i; i--) printf "%s", a[i]}'))); }
# unhex: hex on stdin to raw bytes on stdout (bash's printf makes any byte).
unhex() { local h; h="$(tr -d ' \n')"; printf '%b' "$(printf '%s' "$h" | sed 's/../\\x&/g')"; }
# The wire blob of an ssh-ed25519 public key line: its base64 field, decoded.
blob() { awk '{print $2}' | openssl base64 -d -A; }
sha() { openssl dgst "-$1" -r | cut -d' ' -f1; }

# One value from the config, ~ and the config's folder expanded for paths.
conf() {
    sed -n "s/^[[:space:]]*$1[[:space:]]*=[[:space:]]*\([^#]*\).*/\1/p" "$CONFIG" \
        | sed 's/[[:space:]]*$//' | head -n "${2:-1}"
}
path() {
    case "$1" in
        \~/*) printf '%s\n' "$HOME/${1#\~/}" ;;
        /*) printf '%s\n' "$1" ;;
        "") ;;
        *) printf '%s\n' "$(dirname "$CONFIG")/$1" ;;
    esac
}

FAILED=0
check() {  # check <name> <0 pass | 1 fail> [detail]
    if [ "$2" -eq 0 ]; then echo "  [PASS] $1"; else echo "  [FAIL] $1${3:+: $3}"; FAILED=1; fi
}
is() { [ "$1" = "$2" ] && echo 0 || echo 1; }

# ---------------------------------------------------------------- verify ---
# verify <dir>: <dir>/nonce.bin, report.bin, session-hostkey.pub, vcek.pem.
verify() {
    local d="$1" r="$1/report.bin" ok
    [ "$(wc -c < "$r" | tr -d ' ')" = 1184 ] || die "the report is not 1184 bytes"
    echo "checks:"

    # 1. The chain: the pinned ARK signs itself and the ASK, the ASK the VCEK
    # (RSA-PSS, which openssl verify handles).
    openssl x509 -inform DER -in "$PINS/ark-milan.der" -out "$d/ark.pem"
    openssl x509 -inform DER -in "$PINS/ask-milan.der" -out "$d/ask.pem"
    ok=$(is "$(sha sha256 < "$PINS/ark-milan.der"):$(sha sha256 < "$PINS/ask-milan.der")" "$ARK_SHA256:$ASK_SHA256")
    check "ARK and ASK are the pinned ones" "$ok"
    openssl verify -CAfile "$d/ark.pem" -untrusted "$d/ask.pem" "$d/vcek.pem" >/dev/null 2>&1 && ok=0 || ok=1
    check "VCEK -> ASK -> ARK" "$ok"

    # The VCEK must be for this report's chip and TCB: AMD's extensions, read
    # with asn1parse. 1.3.6.1.4.1.3704.1.4 is the chip id; .1.3.1/2/3/8 the
    # bootloader, TEE, SNP and microcode levels, each a DER INTEGER.
    local asn tcb_want
    asn="$(openssl asn1parse -in "$d/vcek.pem")"
    ext() { printf '%s\n' "$asn" | awk -v oid=":$1\$" '$0 ~ oid { getline; sub(/.*HEX DUMP\]:/, ""); print tolower($0); exit }'; }
    spl() { local v; v="$(ext "$1")"; echo $((16#${v:4})); }   # skip 02 <len>
    check "VCEK is for this chip_id" "$(is "$(ext 1.3.6.1.4.1.3704.1.4)" "$(hex "$r" 0x1A0 64)")"
    tcb_want="$(spl 1.3.6.1.4.1.3704.1.3.1):$(spl 1.3.6.1.4.1.3704.1.3.2):$(spl 1.3.6.1.4.1.3704.1.3.3):$(spl 1.3.6.1.4.1.3704.1.3.8)"
    local tcb
    tcb="$((16#$(hex "$r" 0x180 1))):$((16#$(hex "$r" 0x181 1))):$((16#$(hex "$r" 0x186 1))):$((16#$(hex "$r" 0x187 1)))"
    check "VCEK is for this reported TCB ($tcb)" "$(is "$tcb_want" "$tcb")"

    # 2. The signature: ECDSA P-384 over bytes 0x000-0x29F. The report keeps r
    # and s little-endian, each in 72 bytes; openssl wants them big-endian in
    # DER: SEQUENCE { INTEGER r, INTEGER s }.
    der_int() {  # 48 little-endian bytes as hex -> a DER INTEGER, as hex
        local be
        be="$(printf '%s' "$1" | fold -w2 | awk '{a[NR]=$0} END {for (i = NR; i; i--) printf "%s", a[i]}')"
        be="$(printf '%s' "$be" | sed 's/^\(00\)*//')"                   # no leading zero bytes...
        case "$be" in [89a-f]*) be="00$be" ;; esac                        # ...but one if the top bit is set
        printf '02%02x%s' $(( ${#be} / 2 )) "$be"
    }
    local ri si
    ri="$(der_int "$(hex "$r" 0x2A0 48)")"
    si="$(der_int "$(hex "$r" 0x2E8 48)")"
    printf '30%02x%s%s' $(( (${#ri} + ${#si}) / 2 )) "$ri" "$si" | unhex > "$d/sig.der"
    head -c $((0x2A0)) "$r" > "$d/signed.bin"
    openssl x509 -in "$d/vcek.pem" -pubkey -noout > "$d/vcek-pub.pem"
    openssl dgst -sha384 -verify "$d/vcek-pub.pem" -signature "$d/sig.der" "$d/signed.bin" >/dev/null 2>&1 && ok=0 || ok=1
    check "report signature" "$ok"
    # SIGNING_KEY (KEY_INFO bits 2-4) 0 means the VCEK signed it.
    check "signed by the VCEK" "$(is $(( ($(le "$r" 0x48 4) >> 2) & 7 )) 0)"

    # 3. Version 2 to 5, signature algorithm 1 (ECDSA P-384 with SHA-384).
    local v
    v="$(le "$r" 0 4)"
    [ "$v" -ge 2 ] && [ "$v" -le 5 ] && [ "$(le "$r" 0x34 4)" = 1 ] && ok=0 || ok=1
    check "version $v, signature algorithm" "$ok"

    # 4. The binding: SHA-512(nonce || the SESSION's host key), never the key
    # the guest claims.
    local want
    want="$({ cat "$d/nonce.bin"; blob < "$d/session-hostkey.pub"; } | sha sha512)"
    check "REPORT_DATA binds this nonce and this session's host key" "$(is "$(hex "$r" 0x50 64)" "$want")"

    # 5. The measurement: one of the config's.
    local m got
    got="$(hex "$r" 0x90 48)"; ok=1
    while IFS= read -r m; do [ "$(printf '%s' "$m" | tr 'A-F' 'a-f')" = "$got" ] && ok=0; done < <(conf measurement 99)
    check "measurement ${got:0:16}… is accepted" "$ok"

    # 6. The policy: debug (bit 19) and the migration agent (bit 18) off,
    # reserved bit 17 set.
    local p
    p="$(le "$r" 0x08 8)"
    [ $(( p >> 19 & 1 )) = 0 ] && [ $(( p >> 18 & 1 )) = 0 ] && [ $(( p >> 17 & 1 )) = 1 ] && ok=0 || ok=1
    check "policy $(printf '%#x' "$p"): no debug, no migration agent" "$ok"

    # 7. VMPL 0.
    check "VMPL 0" "$(is "$(le "$r" 0x30 4)" 0)"

    # 8. host_data: SHA-256 of the owner's own copy of the unlock key's blob.
    want="$(blob < "$(path "$(conf unlock-key)")" | sha sha256)"
    check "host_data is your server unlock key" "$(is "$(hex "$r" 0xC0 32)" "$want")"

    # 9. TCB at or above min-tcb, each of the four.
    local min
    min="$(conf min-tcb)"
    ok="$(awk -v a="$tcb" -v b="$min" 'BEGIN { n = split(a, x, ":"); split(b, y, ":"); bad = (n != 4)
        for (i = 1; i <= 4; i++) if (x[i] + 0 < y[i] + 0) bad = 1; print bad }')"
    check "TCB $tcb at or above $min" "$ok"

    [ "$FAILED" = 0 ]
}

# ------------------------------------------------------------------ main ---
if [ "${1:-}" = --verify ]; then
    [ $# = 3 ] || die "usage: unlock-by-hand.sh --verify <dir> <config>"
    CONFIG="$3"
    W="$(mktemp -d)"; trap 'rm -rf "$W"' EXIT
    cp "$2/nonce.bin" "$2/report.bin" "$2/session-hostkey.pub" "$W/"
    if [ -f "$2/vcek.pem" ]; then cp "$2/vcek.pem" "$W/"; else openssl x509 -inform DER -in "$2/vcek.der" -out "$W/vcek.pem"; fi
    if verify "$W"; then echo "every check passed"; else echo "VERIFICATION FAILED"; exit 1; fi
    exit 0
fi

[ $# = 1 ] || die "usage: unlock-by-hand.sh <config> | --verify <dir> <config>"
CONFIG="$1"
HOST="$(conf host)"; PORT="$(conf port)"; PORT="${PORT:-2222}"; USR="$(conf user)"; USR="${USR:-root}"
ID="$(path "$(conf identity)")"; CERT="$(path "$(conf certificate)")"; UK="$(path "$(conf unlock-key)")"
[ -n "$HOST" ] && [ -r "$UK" ] || die "the config needs host and a readable unlock-key"

# A private folder for the connection's socket, its known_hosts and the
# evidence; gone when this ends, with the connection.
W="$(mktemp -d)"; chmod 700 "$W"
trap 'ssh -o ControlPath="$W/c" -O exit "$USR@$HOST" 2>/dev/null; rm -rf "$W"' EXIT

# A solo server (no certificate; the SSH key IS the unlock key): sign a
# five-minute certificate through the SSH agent, as vmt-unlock does.
if [ -z "$CERT" ] && [ "$(awk '{print $2}' "$ID.pub")" = "$(awk '{print $2}' "$UK")" ]; then
    cp "$UK" "$W/solo.pub"
    ssh-keygen -q -U -s "$W/solo.pub" -I "unlock-by-hand" -n unlock -O clear -V -1m:+5m "$W/solo.pub" \
        || die "could not sign a certificate through the agent (ssh-add your key)"
    CERT="$W/solo-cert.pub"
fi

SSH=(ssh -o BatchMode=yes -o ControlPath="$W/c" -o UserKnownHostsFile="$W/known_hosts"
     -o GlobalKnownHostsFile=/dev/null -o HostKeyAlgorithms=ssh-ed25519 -o HashKnownHosts=no
     -o RequestTTY=no -o ForwardAgent=no -o LogLevel=ERROR -p "$PORT")
[ -n "$ID" ] && SSH+=(-i "$ID" -o IdentitiesOnly=yes)
[ -n "$CERT" ] && SSH+=(-o CertificateFile="$CERT")

# ONE connection: a master that accepts the host key stage 0 made at this
# boot and writes it down; every request then rides it, and a new
# connection would have to show the same key.
"${SSH[@]}" -o ControlMaster=yes -o StrictHostKeyChecking=accept-new -N -f "$USR@$HOST" \
    || die "could not connect"
want="$HOST"; [ "$PORT" = 22 ] || want="[$HOST]:$PORT"
awk -v h="$want" '$1 == h {print $2, $3}' "$W/known_hosts" > "$W/session-hostkey.pub"
[ "$(wc -l < "$W/session-hostkey.pub" | tr -d ' ')" = 1 ] || die "not exactly one recorded host key"
echo "session host key: $(ssh-keygen -lf "$W/session-hostkey.pub" | awk '{print $2}')"

# attest: 32 random bytes, sent as 64 hex digits.
openssl rand 32 > "$W/nonce.bin"
reply="$("${SSH[@]}" -o ControlMaster=no -o StrictHostKeyChecking=yes -T "$USR@$HOST" attest "$(hex "$W/nonce.bin" 0 32)")" \
    || die "attest failed"
[ "$(printf '%s\n' "$reply" | sed -n 1p)" = "stage0-attest 1" ] || die "not a stage 0 reply"
printf '%s\n' "$reply" | sed -n 's/^report //p' | unhex > "$W/report.bin"

# The VCEK from AMD, by chip_id and reported TCB.
r="$W/report.bin"
url="https://kdsintf.amd.com/vcek/v1/Milan/$(hex "$r" 0x1A0 64)?blSPL=$(printf %02d $((16#$(hex "$r" 0x180 1))))&teeSPL=$(printf %02d $((16#$(hex "$r" 0x181 1))))&snpSPL=$(printf %02d $((16#$(hex "$r" 0x186 1))))&ucodeSPL=$(printf %02d $((16#$(hex "$r" 0x187 1))))"
# UNLOCK_BY_HAND_VCEK=<file>: use a VCEK you already have (DER), instead,
# such as one vmt-unlock cached in ~/.cache/vmt-unlock/vcek/. It is checked
# exactly as a downloaded one is.
if [ -n "${UNLOCK_BY_HAND_VCEK:-}" ]; then
    cp "$UNLOCK_BY_HAND_VCEK" "$W/vcek.der"
else
    curl -sSf --proto =https --max-time 30 -o "$W/vcek.der" "$url" || die "could not fetch the VCEK"
fi
openssl x509 -inform DER -in "$W/vcek.der" -out "$W/vcek.pem"

if ! verify "$W"; then
    echo "VERIFICATION FAILED. The disk passphrase was not sent." >&2
    exit 1
fi

# Every check passed: the passphrase, read without echo, sent as its bytes
# with no newline over the SAME connection. printf is a shell builtin, so it
# never appears in a process list.
IFS= read -r -s -p "Disk passphrase: " pass < /dev/tty; echo
out="$(printf '%s' "$pass" | "${SSH[@]}" -o ControlMaster=no -o StrictHostKeyChecking=yes -T "$USR@$HOST" unlock)" \
    && ok=0 || ok=1
pass=""
case "$ok:$out" in 0:*"unlocked "*) ;; *) die "the VM did not unlock: $out" ;; esac
printf '%s\n' "$out" | sed -n 's/^unlocked /VM: unlocked /p'
