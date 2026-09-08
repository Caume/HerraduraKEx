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

# ── 6: leading-zero fields (TODO #280) ──────────────────────────────────────
# The salt, nonce, ciphertext and tag are FIXED-WIDTH byte strings carried as
# DER INTEGERs, and a minimal DER INTEGER cannot carry a leading 0x00: the
# writer emits the field one significant byte short, and a reader that strips a
# sign byte unconditionally and then asserts an exact width rejects it.  C and
# Go did exactly that for the life of the envelope, on about ONE KEY IN 64 --
# P(any of four random fields starts with 0x00) -- while Python and Java read
# the same file back correctly, because both restore the width from an integer.
#
# Section 2's matrix cannot catch it: it generates a fresh key each run, so it
# fails at random and passes 63 times out of 64.  These two artifacts are
# PINNED, and between them they put a leading zero in all four fields --
# zero_ct's ciphertext and zero_tag's tag, both over a salt and nonce that also
# start with 0x00.  The original KAT envelope could never have caught this: its
# salt starts 0x10 and its nonce 0x60.
for f in zero_ct zero_tag; do
    for r in $LANGS; do
        if ${CLI[$r]} pkey --decrypt --passphrase "$KAT_PHRASE" \
              --in "$ROOT/KAT/pem/enc_priv_$f.pem" --out "$TMP/z_${f}_$r.pem" >/dev/null 2>&1 \
           && cmp -s "$TMP/z_${f}_$r.pem" "$ROOT/KAT/pem/n64_alice_priv.pem"; then
            pass "[$r] leading-zero envelope ($f) decrypts to the pinned cleartext"
        else
            fail "[$r] leading-zero envelope ($f) not read back — a fixed-width field"
            fail "     whose first byte is 0x00 must be LEFT-PADDED, not width-asserted"
        fi
    done
done

# ── 7: a declared plaintext length that sizes an allocation (TODO #280) ─────
# Reversing the ciphertext-length comparison for section 6 removed the bound the
# old form gave for free: with `pt_len > len(ct)` rejected, pt_len could never
# exceed the ciphertext present.  It can now, so it is bounded explicitly.  The
# same probe found the bound MISSING ENTIRELY in Python, where
# `ct_int.to_bytes(pt_len)` on a declared 2^62 raised MemoryError -- the field
# class TODO #239/#240/#275 exist over, on a path they had not reached.  Java
# was safe but named the stdlib ("BigInteger out of int range") rather than the
# field.  Build the envelope here rather than pinning it: it is a one-field edit
# of an artifact this repo already ships.
python3 - "$ROOT" "$TMP" <<'PYEOF'
import base64, importlib.util, sys
root, tmp = sys.argv[1], sys.argv[2]
spec = importlib.util.spec_from_file_location("codec", root + "/HerraduraCli/codec.py")
c = importlib.util.module_from_spec(spec); spec.loader.exec_module(c)
src = root + "/KAT/pem/enc_priv_zero_tag.pem"
der = base64.b64decode("".join(l.strip() for l in open(src) if not l.startswith("-----")))
salt, it, nonce, ct, tag, ptlen = c.der_parse_seq(der)
hostile = c.der_seq(c.der_int(salt, 16), c.der_int(it), c.der_int(nonce, 32),
                    c.der_int(ct, ptlen), c.der_int(tag, 32), c.der_int(1 << 62))
open(tmp + "/hostile_ptlen.pem", "w").write(
    c.pem_wrap("HERRADURA ENCRYPTED PRIVATE KEY", hostile))
PYEOF
for r in $LANGS; do
    out=$(timeout 30 ${CLI[$r]} pkey --decrypt --passphrase "$KAT_PHRASE" \
              --in "$TMP/hostile_ptlen.pem" --out "$TMP/never.pem" 2>&1) && rc=0 || rc=$?
    if [ "$rc" -eq 124 ]; then
        fail "[$r] a declared 2^62 plaintext length hung — it must be bounded, not attempted"
    elif [ "$rc" -eq 0 ]; then
        fail "[$r] a declared 2^62 plaintext length was ACCEPTED"
    elif printf '%s' "$out" | grep -qi 'plaintext length'; then
        pass "[$r] refuses a declared 2^62 plaintext length, naming the field"
    else
        fail "[$r] refused a 2^62 plaintext length but did not name the field: $(printf '%s' "$out" | tail -1)"
    fi
done

echo
echo "test_passphrase_envelope: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
