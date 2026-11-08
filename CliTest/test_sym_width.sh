#!/usr/bin/env bash
# CliTest/test_sym_width.sh — the WIDTH axis for the 256-fixed symmetric algos,
# and the raw hex key form (TODO #355, #356).
#
# THE CONTRACT.  `hske`, `hske-nla2`, `hske-nla3`, `fpe`, `twk`, `hske-duplex`
# and `hske-duplex3` run at 256 bits only, in all four CLIs: a key of any other
# width is REFUSED at enc/dec (and at fpe/twk), and so is a ciphertext whose
# declared width is not 256.  `hske-nla1` is NOT in scope: it has its own
# multi-width contract (test_narrow_width_matrix.sh, TODO #314).
#
# WHAT WAS WRONG (TODO #356).  Below 256 the four ports did four things.  C is
# compiled for one KEYBITS and zero-extended a narrow key into it; Python and Go
# ran at the key's width; Java refused some algos and ran others.  So at 128
# bits half of the (writer x reader) cells of hske, A2 and A3 decrypted to
# garbage with exit 0, and fpe/twk split two against two.  At 224 even a port
# reading its OWN ciphertext got garbage for A2/A3: NL-FSCX v2's inverse is
# computed as M^(n/2 - 1), which is M^-1 at powers of two only.  Nothing caught
# it because every CliTest invocation ran at 256 -- #313's lesson again.
#
# THE HEX FORM (TODO #355).  A file holding `0x` + hex digits is a key in all
# four CLIs (it was Python and Go only).  Its width is the DIGIT COUNT rounded
# up to a multiple of 32, never the value: the value rule ran a 64-digit key
# whose top 32 bits are zero at 224 bits.  §3 holds that rule by construction
# (a 64-digit key with a leading zero word must give the same ciphertext as the
# same value in a 256-bit SESSION KEY PEM), and at 32 bits through hske-nla1,
# which still accepts narrow widths, across all four CLIs.
#
# SHAPE.  §0 is the control that lets the matrix fail (a wrong key must not
# recover); §1 the 256-bit matrix, which is the accept-control for every
# refusal below; §2 the refusals, each against a fixture shown to be genuine;
# §3 the hex form; §4 the counts, asserted independently.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
PASS=0; FAIL=0

pass() { echo "PASS $1"; PASS=$((PASS+1)); }
fail() { echo "FAIL $1"; FAIL=$((FAIL+1)); }

declare -A CLI=()
CLI[py]="python3 $ROOT/HerraduraCli/herradura.py"
[ -x "$ROOT/HerraduraCli/herradura_cli" ]    && CLI[c]="$ROOT/HerraduraCli/herradura_cli"
[ -x "$ROOT/HerraduraCli/herradura_cli_go" ] && CLI[go]="$ROOT/HerraduraCli/herradura_cli_go"
if command -v javac >/dev/null 2>&1; then
    bash bindings/java/build.sh >/dev/null 2>&1
    CLI[java]="java -cp $ROOT/bindings/java herradurakex.HerraduraCli"
fi

LANGS=()
for l in py c go java; do
    [ -n "${CLI[$l]:-}" ] && LANGS+=("$l")
done
echo "Languages under test: ${LANGS[*]}"

# TODO #229: an unannounced absence reads as full coverage when it is not.
. "$ROOT/CliTest/lib_build.sh"
for l in c go; do
    [ -n "${CLI[$l]:-}" ] || echo "NOTE: $l CLI absent — $(hkx_why "$l")"
done
[ -n "${CLI[java]:-}" ] || echo "NOTE: java CLI absent — javac is not installed"

ALGOS="hske hske-nla2 hske-nla3"
TRIPS=0; REFUSALS=0; HEX=0
refused() { REFUSALS=$((REFUSALS+1)); }

MSG="$TMP/m.bin"; printf 'width matters 01' > "$MSG"
BLK="$TMP/b32.bin"; printf '0123456789abcdef0123456789abcdef' > "$BLK"
WANT="width matters"
recovered() { [ -f "$1" ] && head -c ${#WANT} "$1" | grep -q "^$WANT"; }

# Fixtures: SESSION KEY PEMs of any width, written by the Python codec so a
# 224-bit one exists at all (no genpkey width produces it: GF_POLY has no 224).
python3 - "$TMP" <<'PY'
import sys, random
sys.path.insert(0, "HerraduraCli")
import herradura as H
tmp = sys.argv[1]
rnd = random.Random(356)
for n in (128, 224, 256):
    k = rnd.getrandbits(n) | (1 << (n - 1)) | 0x10
    open(f"{tmp}/k{n}.pem", "w").write(H._encode_session_key(k, n))
open(f"{tmp}/other256.pem", "w").write(H._encode_session_key(rnd.getrandbits(256) | 1 << 255, 256))
# TODO #355's case: 64 hex digits whose top 32 bits are zero.
v = rnd.getrandbits(224) | (1 << 223) | 0x10
open(f"{tmp}/hex256.txt", "w").write("0x%064x\n" % v)
open(f"{tmp}/hex256.pem", "w").write(H._encode_session_key(v, 256))
open(f"{tmp}/hex32.txt", "w").write("0x0000beef\n")
open(f"{tmp}/hex1.txt", "w").write("0x1\n")
open(f"{tmp}/hexbad.txt", "w").write("0x12zz\n")
PY

# ── 0. THE CONTROL THAT LETS THE MATRIX FAIL ─────────────────────────────────
echo ""
echo "=== control: a different key must not recover the plaintext ==="
L0="${LANGS[0]}"
# shellcheck disable=SC2086
${CLI[$L0]} enc --algo hske-nla2 --key "$TMP/k256.pem" --in "$MSG" --out "$TMP/ctl.pem" \
    >/dev/null 2>&1 || fail "control: $L0 could not produce a 256-bit artifact"
rm -f "$TMP/o.bin"
# shellcheck disable=SC2086
if ${CLI[$L0]} dec --algo hske-nla2 --key "$TMP/other256.pem" --in "$TMP/ctl.pem" \
       --out "$TMP/o.bin" >/dev/null 2>&1 && recovered "$TMP/o.bin"; then
    fail "control: a DIFFERENT key recovered the plaintext — the matrix is vacuous"
else
    pass "control: a different key does not recover the plaintext"
fi

# ── 1. THE 256-BIT MATRIX: the accept-control for every refusal below ────────
echo ""
echo "=== 256 bits: every writer x reader pair ==="
for a in $ALGOS; do
    for e in "${LANGS[@]}"; do
        # shellcheck disable=SC2086
        if ! ${CLI[$e]} enc --algo "$a" --key "$TMP/k256.pem" --in "$MSG" \
                            --out "$TMP/ct_${a}_$e.pem" >/dev/null 2>&1; then
            fail "$a: $e could not encrypt at 256"
            continue
        fi
        for d in "${LANGS[@]}"; do
            rm -f "$TMP/o.bin"
            # shellcheck disable=SC2086
            if ${CLI[$d]} dec --algo "$a" --key "$TMP/k256.pem" --in "$TMP/ct_${a}_$e.pem" \
                              --out "$TMP/o.bin" >/dev/null 2>&1 && recovered "$TMP/o.bin"; then
                pass "$a 256: $e -> $d"; TRIPS=$((TRIPS+1))
            else
                fail "$a 256: $e -> $d did not round-trip"
            fi
        done
    done
done
for l in "${LANGS[@]}"; do
    for op in fpe twk; do
        # shellcheck disable=SC2086
        if ${CLI[$l]} $op --key "$TMP/k256.pem" --in "$BLK" --out "$TMP/o.bin" --encrypt \
               >/dev/null 2>&1 && [ -s "$TMP/o.bin" ]; then
            pass "$l $op accepts a 256-bit key"
        else
            fail "$l $op refuses a 256-bit key — the refusals below prove nothing"
        fi
    done
done

# ── 2. EVERY OTHER WIDTH IS REFUSED ──────────────────────────────────────────
echo ""
echo "=== a 128- or 224-bit key is refused, at enc, at dec, and by fpe / twk / duplex ==="
for n in 128 224; do
    for l in "${LANGS[@]}"; do
        for a in $ALGOS hske-duplex hske-duplex3; do
            rm -f "$TMP/o.pem"
            # shellcheck disable=SC2086
            if ${CLI[$l]} enc --algo "$a" --key "$TMP/k$n.pem" --in "$MSG" --out "$TMP/o.pem" \
                   >/dev/null 2>&1; then
                fail "$l enc $a ACCEPTED a $n-bit key"
            else
                pass "$l enc $a refuses a $n-bit key"; refused
            fi
        done
        for op in fpe twk; do
            # shellcheck disable=SC2086
            if ${CLI[$l]} $op --key "$TMP/k$n.pem" --in "$BLK" --out "$TMP/o.bin" --encrypt \
                   >/dev/null 2>&1; then
                fail "$l $op ACCEPTED a $n-bit key"
            else
                pass "$l $op refuses a $n-bit key"; refused
            fi
        done
    done
done
# dec with a narrow key, against a genuine 256-bit artifact (decrypted in §1).
for l in "${LANGS[@]}"; do
    for a in $ALGOS; do
        rm -f "$TMP/o.bin"
        # shellcheck disable=SC2086
        if ${CLI[$l]} dec --algo "$a" --key "$TMP/k128.pem" --in "$TMP/ct_${a}_$L0.pem" \
               --out "$TMP/o.bin" >/dev/null 2>&1; then
            fail "$l dec $a ACCEPTED a 128-bit key"
        else
            pass "$l dec $a refuses a 128-bit key"; refused
        fi
    done
done

# A ciphertext DECLARING 224 bits, with a genuine 256-bit key.  The rewrite is
# length-preserving (DER INTEGER 256 is 02 02 01 00, 224 is 02 02 00 e0), so a
# refusal cannot be a PEM that merely stopped parsing; the un-rewritten source
# decrypted in §1, which is this case's control.
relabel() {   # relabel <src> <dst>
    python3 - "$1" "$2" <<'PY'
import sys, base64
src, dst = sys.argv[1], sys.argv[2]
lines = open(src).read().strip().split('\n')
der = base64.b64decode(''.join(lines[1:-1]))
i = der.rfind(b'\x02\x02\x01\x00')
if i < 0:
    sys.exit("no nbits=256 DER INTEGER found in the ciphertext")
der = der[:i] + b'\x02\x02\x00\xe0' + der[i + 4:]
b64 = base64.b64encode(der).decode()
open(dst, 'w').write(lines[0] + '\n' + '\n'.join(b64[j:j + 64] for j in range(0, len(b64), 64))
                     + '\n' + lines[-1] + '\n')
PY
}
for a in $ALGOS; do
    relabel "$TMP/ct_${a}_$L0.pem" "$TMP/ct224_$a.pem"
    for l in "${LANGS[@]}"; do
        rm -f "$TMP/o.bin"
        # shellcheck disable=SC2086
        if ${CLI[$l]} dec --algo "$a" --key "$TMP/k256.pem" --in "$TMP/ct224_$a.pem" \
               --out "$TMP/o.bin" >/dev/null 2>&1; then
            fail "$l dec $a ACCEPTED a ciphertext declaring 224 bits"
        else
            pass "$l dec $a refuses a ciphertext declaring 224 bits"; refused
        fi
    done
done

# ── 3. THE HEX KEY FORM ──────────────────────────────────────────────────────
echo ""
echo "=== the 0x hex key form: same key as the PEM, width by digit count ==="
for l in "${LANGS[@]}"; do
    rm -f "$TMP/h.pem" "$TMP/p.pem"
    # shellcheck disable=SC2086
    ${CLI[$l]} enc --algo hske-nla2 --key "$TMP/hex256.pem" --in "$MSG" --out "$TMP/p.pem" \
        >/dev/null 2>&1 || true
    # shellcheck disable=SC2086
    if ${CLI[$l]} enc --algo hske-nla2 --key "$TMP/hex256.txt" --in "$MSG" --out "$TMP/h.pem" \
           >/dev/null 2>&1 && [ -s "$TMP/p.pem" ] && cmp -s "$TMP/h.pem" "$TMP/p.pem"; then
        pass "$l: a 64-digit hex key with a zero top word is the 256-bit PEM key"; HEX=$((HEX+1))
    else
        fail "$l: the 64-digit hex key did not reproduce the PEM key's ciphertext"
    fi
    cp "$TMP/h.pem" "$TMP/hct_$l.pem" 2>/dev/null || true
done
for e in "${LANGS[@]}"; do
    for d in "${LANGS[@]}"; do
        rm -f "$TMP/o.bin"
        # shellcheck disable=SC2086
        if ${CLI[$d]} dec --algo hske-nla2 --key "$TMP/hex256.txt" --in "$TMP/hct_$e.pem" \
               --out "$TMP/o.bin" >/dev/null 2>&1 && recovered "$TMP/o.bin"; then
            pass "hex key, hske-nla2: $e -> $d"; HEX=$((HEX+1))
        else
            fail "hex key, hske-nla2: $e -> $d did not round-trip"
        fi
    done
done
# 8 digits = 32 bits, through hske-nla1, the one symmetric algo that runs there.
want32="$(printf 'width matters' | head -c 4)"
for e in "${LANGS[@]}"; do
    rm -f "$TMP/a1.pem"
    # shellcheck disable=SC2086
    ${CLI[$e]} enc --algo hske-nla1 --key "$TMP/hex32.txt" --in "$MSG" --out "$TMP/a1_$e.pem" \
        >/dev/null 2>&1 || { fail "hex32: $e could not encrypt"; continue; }
    for d in "${LANGS[@]}"; do
        rm -f "$TMP/o.bin"
        # shellcheck disable=SC2086
        if ${CLI[$d]} dec --algo hske-nla1 --key "$TMP/hex32.txt" --in "$TMP/a1_$e.pem" \
               --out "$TMP/o.bin" >/dev/null 2>&1 \
           && [ "$(head -c 4 "$TMP/o.bin")" = "$want32" ]; then
            pass "hex 32-bit key, hske-nla1: $e -> $d"; HEX=$((HEX+1))
        else
            fail "hex 32-bit key, hske-nla1: $e -> $d did not round-trip"
        fi
    done
done
for l in "${LANGS[@]}"; do
    # shellcheck disable=SC2086
    if ${CLI[$l]} enc --algo hske-nla2 --key "$TMP/hex1.txt" --in "$MSG" --out "$TMP/o.pem" \
           >/dev/null 2>&1; then
        fail "$l: 0x1 (a 32-bit key) was accepted by hske-nla2"
    else
        pass "$l: 0x1 is a 32-bit key, and hske-nla2 refuses it"; refused
    fi
    # shellcheck disable=SC2086
    if ${CLI[$l]} enc --algo hske-nla1 --key "$TMP/hexbad.txt" --in "$MSG" --out "$TMP/o.pem" \
           >/dev/null 2>&1; then
        fail "$l: an invalid hex key (0x12zz) was accepted"
    else
        pass "$l: an invalid hex key is refused"; refused
    fi
done

# ── 4. The counts, asserted independently ────────────────────────────────────
# Round-trips: 3 algos x 4 x 4 = 48.  Hex: 4 + 16 + 16 = 36.  Refusals:
# 2 widths x 4 CLIs x 7 ops = 56, + 12 narrow-key dec, + 12 relabelled, + 8 hex = 88.
echo ""
echo "256-bit round-trips: $TRIPS   hex-key checks: $HEX   refusals: $REFUSALS"
if [ "${#LANGS[@]}" -eq 4 ]; then
    [ "$TRIPS" -eq 48 ]    || fail "expected 48 round-trips with all four CLIs, saw $TRIPS"
    [ "$HEX" -eq 36 ]      || fail "expected 36 hex-key checks with all four CLIs, saw $HEX"
    [ "$REFUSALS" -eq 88 ] || fail "expected 88 refusals with all four CLIs, saw $REFUSALS"
fi

echo ""
echo "Results: $PASS PASS / $FAIL FAIL (languages: ${LANGS[*]})"
hkx_require_asserted "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
