#!/usr/bin/env bash
# CliTest/test_passphrase_envelope.sh — TODO #268: the passphrase-encrypted
# private-key envelope, across all four CLIs.
#
# `HERRADURA ENCRYPTED PRIVATE KEY` was Python-only from v1.9.134 (TODO #166),
# so a key exported that way was unreadable by three of the four.  Since TODO
# #274 (v6.5.2) C and Java at least REFUSED `--passphrase` by name; before that
# they accepted it and wrote a CLEARTEXT private key with exit 0, which is the
# failure this file exists to keep closed.
#
# Four things are asserted, and the last two are the ones that matter:
#
#   1. A 4x4 writer x reader matrix.  The shape test_zkp_hybrid_family.sh
#      adopted after TODO #261 found a pair that had never interoperated
#      because every test compared against Python.
#   2. The recovered PEM is byte-for-byte the original, since the envelope's
#      whole point is that it composes with every other subcommand.
#   3. A wrong passphrase is REFUSED, in every language.  The envelope is
#      AEAD-authenticated, so this must fail on the tag rather than return
#      garbage that a later subcommand would misread.
#   4. FAIL CLOSED: an envelope handed to a subcommand that wants a cleartext
#      key must be refused BY NAME.  It is a valid DER SEQUENCE, so a CLI that
#      does not check the label parses it happily and reads salt/iterations/
#      nonce as key material -- a wrong answer with exit 0, the same shape as
#      the bug #274 found in the flag itself.
set -euo pipefail

DIR=$(dirname "$0")
ROOT=$(cd "$DIR/.." && pwd)
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
PASS=0; FAIL=0
pass() { echo "PASS $1"; PASS=$((PASS+1)); }
fail() { echo "FAIL $1"; FAIL=$((FAIL+1)); }

. "$DIR/lib_build.sh"
hkx_require_built c go

declare -A CLI=()
CLI[py]="python3 $ROOT/HerraduraCli/herradura.py"
CLI[c]="$ROOT/HerraduraCli/herradura_cli"
CLI[go]="$ROOT/HerraduraCli/herradura_cli_go"
LANGS="py c go"
if command -v javac >/dev/null 2>&1 && bash "$ROOT/bindings/java/build.sh" >/dev/null 2>&1; then
    CLI[java]="java -cp $ROOT/bindings/java herradurakex.HerraduraCli"
    LANGS="$LANGS java"
else
    echo "NOTE: java CLI absent (javac not installed) — 7 of 16 pairs skipped"
fi

PHRASE='correct horse battery staple'

# ── 1 & 2: writer x reader, and byte-identity with the cleartext original ────
for w in $LANGS; do
    # The cleartext control: the same build's plain genpkey output is not
    # comparable (keys are random), so each writer encrypts, then EVERY reader
    # must recover the identical bytes -- including the writer itself, which is
    # the control that makes the cross-language cells meaningful.
    ${CLI[$w]} genpkey --algo hkex-gf --passphrase "$PHRASE" \
        --out "$TMP/enc_$w.pem" >/dev/null 2>&1 || { fail "[$w] genpkey --passphrase"; continue; }
    if head -1 "$TMP/enc_$w.pem" | grep -q 'BEGIN HERRADURA ENCRYPTED PRIVATE KEY'; then
        pass "[$w] genpkey --passphrase writes the envelope label"
    else
        fail "[$w] genpkey --passphrase wrote the wrong label"; continue
    fi
    # A cleartext key must NOT be what landed on disk.
    if grep -q 'PRIVATE KEY' "$TMP/enc_$w.pem" && ! grep -q 'BEGIN HERRADURA HKEX-GF PRIVATE KEY' "$TMP/enc_$w.pem"; then
        pass "[$w] no cleartext private key on disk"
    else
        fail "[$w] wrote a CLEARTEXT private key for --passphrase"
    fi

    ref=""
    for r in $LANGS; do
        if ${CLI[$r]} pkey --decrypt --passphrase "$PHRASE" \
              --in "$TMP/enc_$w.pem" --out "$TMP/pl_${w}_${r}.pem" >/dev/null 2>&1 \
           && head -1 "$TMP/pl_${w}_${r}.pem" | grep -q 'BEGIN HERRADURA HKEX-GF PRIVATE KEY'; then
            pass "envelope $w-write -> $r-read"
        else
            fail "envelope $w-write -> $r-read"; continue
        fi
        if [ -z "$ref" ]; then
            ref="$TMP/pl_${w}_${r}.pem"
        elif cmp -s "$ref" "$TMP/pl_${w}_${r}.pem"; then
            pass "envelope $w-write -> $r-read recovers identical bytes"
        else
            fail "envelope $w-write -> $r-read recovered DIFFERENT bytes"
        fi
    done
done

# ── 3: a wrong passphrase is refused, not silently mis-decrypted ─────────────
for r in $LANGS; do
    if ${CLI[$r]} pkey --decrypt --passphrase "wrong-passphrase" \
          --in "$TMP/enc_py.pem" --out "$TMP/bad.pem" >/dev/null 2>&1; then
        fail "[$r] accepted a wrong passphrase"
    else
        pass "[$r] rejects a wrong passphrase"
    fi
done

# ── 4: fail closed, and say why ──────────────────────────────────────────────
for r in $LANGS; do
    out=$(${CLI[$r]} pkey --pubout --in "$TMP/enc_py.pem" --out /dev/null 2>&1) && rc=0 || rc=$?
    if [ "$rc" -eq 0 ]; then
        fail "[$r] read an ENCRYPTED PRIVATE KEY as though it were cleartext"
    elif echo "$out" | grep -qi 'passphrase-encrypted'; then
        pass "[$r] refuses an encrypted key and names the cause"
    else
        fail "[$r] refused, but the message does not name the cause: $(echo "$out" | tail -1)"
    fi
done

# ── 5: the pinned KAT envelope (TODO #268) ───────────────────────────────────
# Regenerate-and-diff cannot cover the CONSUME direction, which is where the
# bugs live; every CLI must decrypt this fixed artifact to a file this repo
# already contains.
KAT_PHRASE='HerraduraKEx TODO #268 KAT passphrase'
for r in $LANGS; do
    if ${CLI[$r]} pkey --decrypt --passphrase "$KAT_PHRASE" \
          --in "$ROOT/KAT/pem/enc_priv.pem" --out "$TMP/kat_$r.pem" >/dev/null 2>&1 \
       && cmp -s "$TMP/kat_$r.pem" "$ROOT/KAT/pem/n1024_alice_priv.pem"; then
        pass "[$r] KAT envelope decrypts to the pinned cleartext"
    else
        fail "[$r] KAT envelope did not reproduce KAT/pem/n1024_alice_priv.pem"
    fi
done

echo
echo "test_passphrase_envelope: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
