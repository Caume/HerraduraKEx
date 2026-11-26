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
# TODO #372: 2^62 is now refused by the generic field cap (4 bytes) before the
# bound above is reached.  A length inside the cap is refused too: since #373 the
# ciphertext must be exactly the declared length, so that check names field 3
# before any allocation (the #280 bound, now behind it, still guards C and Go).
hostile32 = c.der_seq(c.der_int(salt, 16), c.der_int(it), c.der_int(nonce, 32),
                      c.der_int(ct, ptlen), c.der_int(tag, 32), c.der_int((1 << 32) - 1))
open(tmp + "/hostile_ptlen32.pem", "w").write(
    c.pem_wrap("HERRADURA ENCRYPTED PRIVATE KEY", hostile32))
PYEOF
for r in $LANGS; do
  for case in "2^62:hostile_ptlen:plaintext length|field 5 is 8 bytes \\(expected at most 4\\)" \
              "2^32-1:hostile_ptlen32:plaintext length|field 3 is encoded in [0-9]+ bytes \\(expected exactly 4294967295\\)"; do
    what=${case%%:*}; rest=${case#*:}; f=${rest%%:*}; want=${rest#*:}
    out=$(timeout 30 ${CLI[$r]} pkey --decrypt --passphrase "$KAT_PHRASE" \
              --in "$TMP/$f.pem" --out "$TMP/never.pem" 2>&1) && rc=0 || rc=$?
    if [ "$rc" -eq 124 ]; then
        fail "[$r] a declared $what plaintext length hung — it must be bounded, not attempted"
    elif [ "$rc" -eq 0 ]; then
        fail "[$r] a declared $what plaintext length was ACCEPTED"
    elif printf '%s' "$out" | grep -qiE "$want"; then
        pass "[$r] refuses a declared $what plaintext length, naming the field"
    else
        fail "[$r] refused a $what plaintext length but did not name the field: $(printf '%s' "$out" | tail -1)"
    fi
  done
done

# ── 8: every refusal pkey --decrypt owns, in the same words (TODO #397) ─────
# Until #397 C said `decrypt: iteration count out of range` without the count,
# the four disagreed on a wrong label and on a file that is not PEM, and C's
# fail-closed refusal printed `<file>` instead of the path.  Each envelope is a
# one-field edit of a real one; the unedited re-encoding is the accept-control.
${CLI[c]} genpkey --algo hkex-gf --passphrase "$PHRASE" --kdf-iterations 1 --out "$TMP/e8.pem"
${CLI[c]} genpkey --algo hkex-gf --out "$TMP/plain8.pem"
python3 - "$ROOT" "$TMP" <<'PYEOF'
import importlib.util, sys
root, tmp = sys.argv[1], sys.argv[2]
spec = importlib.util.spec_from_file_location("codec", root + "/HerraduraCli/codec.py")
c = importlib.util.module_from_spec(spec); spec.loader.exec_module(c)
label, der = c.pem_unwrap(open(tmp + "/e8.pem").read())
salt, it, nonce, ct, tag, ptl = c.der_parse_seq(der)
def emit(name, it=it, tag=tag):
    f = [c.der_int(salt, 16), c.der_int(it), c.der_int(nonce, 32), c.der_int(ct, ptl),
         c.der_int(tag, 32), c.der_int(ptl)]
    open(f"{tmp}/{name}.pem", "w").write(c.pem_wrap(label, c.der_seq(*f)))
emit("e8_same"); emit("e8_iter0", it=0); emit("e8_iterhi", it=100000001)
emit("e8_tag", tag=tag ^ 1)
PYEOF
echo garbage > "$TMP/e8_notpem.pem"
printf -- '-----BEGIN HERRADURA ENCRYPTED PRIVATE KEY-----\n!!!!\n-----END HERRADURA ENCRYPTED PRIVATE KEY-----\n' > "$TMP/e8_b64.pem"
: > "$TMP/e8_empty.pem"
E8_CASES=(
  "e8_iter0|$PHRASE|pkey --decrypt: iteration count out of range (0)"
  "e8_iterhi|$PHRASE|pkey --decrypt: iteration count out of range (100000001)"
  "e8_tag|$PHRASE|pkey --decrypt: wrong passphrase or corrupted/tampered file"
  "e8_same|wrong|pkey --decrypt: wrong passphrase or corrupted/tampered file"
  "plain8|$PHRASE|pkey --decrypt: expected PEM label 'HERRADURA ENCRYPTED PRIVATE KEY', got 'HERRADURA HKEX-GF PRIVATE KEY'"
  "e8_notpem|$PHRASE|pkey --decrypt: cannot parse PEM from: $TMP/e8_notpem.pem: PEM: missing BEGIN marker"
  # TODO #398, #400: every PEM refusal names its reason after the path.
  "e8_b64|$PHRASE|pkey --decrypt: cannot parse PEM from: $TMP/e8_b64.pem: PEM body is not valid base64: invalid character"
  "e8_empty|$PHRASE|pkey --decrypt: cannot parse PEM from: $TMP/e8_empty.pem: PEM: missing BEGIN marker"
)
for r in $LANGS; do
    if ${CLI[$r]} pkey --decrypt --passphrase "$PHRASE" --in "$TMP/e8_same.pem" \
          --out "$TMP/e8_ok_$r.pem" >/dev/null 2>&1 \
       && head -1 "$TMP/e8_ok_$r.pem" | grep -q 'BEGIN HERRADURA HKEX-GF PRIVATE KEY'; then
        pass "[$r] the re-encoded control envelope decrypts"
    else
        fail "[$r] the re-encoded control envelope does not decrypt"
    fi
    for case in "${E8_CASES[@]}"; do
        f=${case%%|*}; rest=${case#*|}; pw=${rest%%|*}; want=${rest#*|}
        out=$(${CLI[$r]} pkey --decrypt --passphrase "$pw" --in "$TMP/$f.pem" \
                  --out "$TMP/e8_never.pem" 2>&1) && rc=0 || rc=$?
        if [ "$rc" -ne 0 ] && [ "$(printf '%s' "$out" | head -1)" = "$want" ] && [ ! -e "$TMP/e8_never.pem" ]; then
            pass "[$r] $f: '$want'"
        else
            fail "[$r] $f: rc=$rc, got '$(printf '%s' "$out" | head -1)', want '$want'"
        fi
        rm -f "$TMP/e8_never.pem"
    done
    want="$TMP/e8.pem is a passphrase-encrypted private key; decrypt it first with \`pkey --decrypt --passphrase ... --in $TMP/e8.pem --out plain.pem\`"
    out=$(${CLI[$r]} pkey --pubout --in "$TMP/e8.pem" --out "$TMP/e8_never.pem" 2>&1) && rc=0 || rc=$?
    if [ "$rc" -ne 0 ] && printf '%s' "$out" | grep -qF -- "$want"; then
        pass "[$r] fail-closed refusal names the path in the shared words"
    else
        fail "[$r] fail-closed refusal: rc=$rc, got '$(printf '%s' "$out" | head -1)'"
    fi
done

# ── 9: every algorithm, every writer (TODO #399) ────────────────────────────
# Section 1 used hkex-gf alone, which is how C's genpkey wrote hpks-zkp-nl and
# hcred keys IN THE CLEAR under --passphrase, exit 0, without a test noticing:
# those two have raw bodies and bypassed the one write path that encrypts.
# Each writer's envelope is decrypted by itself and by C, and must give a key
# of the algorithm's own label (the label C's cleartext genpkey writes).
ALGOS9="hkex-gf hkex-rnl hpks hpks-nl hpke hpke-nl hpke-nl3 hpks-stern hpke-stern
        hpke-stern-kem hpks-zkp-nl oprf hpks-xmss hpks-wots hcred"
for t in $ALGOS9; do
    extra=""; [ "$t" = hpks-xmss ] && extra="--xmss-height 4"
    # To a file, not stdout: a WOTS/XMSS key must be a file since TODO #420.
    # shellcheck disable=SC2086
    ${CLI[c]} genpkey --algo "$t" $extra --out "$TMP/a9_want_$t.pem" >/dev/null 2>&1
    want=$(head -1 "$TMP/a9_want_$t.pem")
    for w in $LANGS; do
        # shellcheck disable=SC2086
        if ! ${CLI[$w]} genpkey --algo "$t" $extra --passphrase "$PHRASE" --kdf-iterations 1 \
                --out "$TMP/a9_${t}_$w.pem" >/dev/null 2>&1; then
            fail "[$w] genpkey --algo $t --passphrase failed"; continue
        fi
        if [ "$(head -1 "$TMP/a9_${t}_$w.pem")" != "-----BEGIN HERRADURA ENCRYPTED PRIVATE KEY-----" ]; then
            fail "[$w] genpkey --algo $t --passphrase wrote '$(head -1 "$TMP/a9_${t}_$w.pem")' (a CLEARTEXT key)"
            continue
        fi
        for r in $w c; do
            if ${CLI[$r]} pkey --decrypt --passphrase "$PHRASE" --in "$TMP/a9_${t}_$w.pem" \
                  --out "$TMP/a9_${t}_${w}_$r.pem" >/dev/null 2>&1 \
               && [ "$(head -1 "$TMP/a9_${t}_${w}_$r.pem")" = "$want" ]; then
                pass "[$w] $t envelope -> [$r] decrypts to '$want'"
            else
                fail "[$w] $t envelope -> [$r] did not decrypt to '$want'"
            fi
            [ "$w" = c ] && break
        done
    done
done

echo
echo "test_passphrase_envelope: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
