#!/usr/bin/env bash
# CliTest/test_twk_tweak_range.sh — TODO #375: `twk --bidx` / `--sector` name
# exactly one tweak in every CLI.
#
# The tweak is sector_be64 || bidx_be32.  Until #375 C read --bidx with
# (uint32_t)strtoul(s, NULL, 10) and Go with flag.Uint then uint32(), so
# --bidx 4294967296 encrypted under block 0's tweak, and C read "abc" as 0.
# C's --sector wrapped -1 to 2^64 - 1.  Java parsed both as SIGNED, refusing
# valid indices >= 2^31 and sectors >= 2^63.  Python died with an
# OverflowError traceback outside the field.  Now all four take decimal digits
# only, --bidx in [0, 2^32 - 1] and --sector in [0, 2^64 - 1].
#
# Sections:
#   1. accept-controls: every in-range value, in every CLI, gives one
#      ciphertext (byte-identical across the four), and decrypts back.
#   2. no aliasing: distinct accepted (sector, bidx) pairs give distinct
#      ciphertexts, and 007 names the same block as 7.
#   3. refusals, by name, with no output written: out-of-range, signed,
#      spaced, hex, exponent, underscore and empty values on both flags.
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
. "$ROOT/CliTest/lib_build.sh"
hkx_require_built c go java

PASS=0; FAIL=0
pass() { PASS=$((PASS+1)); }
fail() { echo "FAIL $1"; FAIL=$((FAIL+1)); }

bash "$ROOT/bindings/java/build.sh" >/dev/null 2>&1 || { echo "FAIL Java build" >&2; exit 1; }

declare -A CLI=(
    [py]="python3 $ROOT/HerraduraCli/herradura.py"
    [c]="$ROOT/HerraduraCli/herradura_cli"
    [go]="$ROOT/HerraduraCli/herradura_cli_go"
    [java]="java -cp $ROOT/bindings/java herradurakex.HerraduraCli"
)
LANGS=(py c go java)

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
python3 -c "import os; print('0x' + os.urandom(32).hex())" > "$TMP/sk.hex"
head -c 32 /dev/urandom > "$TMP/blk"

B_MAX=4294967295
S_MAX=18446744073709551615

# ── 1. accept-controls ──────────────────────────────────────────────────────
# "sector bidx" pairs, each a distinct tweak except where section 2 says so.
PAIRS=("0 0" "0 1" "0 7" "0 2147483648" "0 $B_MAX" "1 0"
       "9223372036854775808 0" "$S_MAX 0" "$S_MAX $B_MAX")
declare -A CT=()
for pair in "${PAIRS[@]}"; do
    set -- $pair; s=$1; b=$2; ref=""
    for c in "${LANGS[@]}"; do
        o="$TMP/ct_${c}_${s}_$b"
        if ! ${CLI[$c]} twk --encrypt --key "$TMP/sk.hex" --sector "$s" --bidx "$b" \
                --in "$TMP/blk" --out "$o" >/dev/null 2>"$TMP/err"; then
            fail "twk --sector $s --bidx $b ($c): refused: $(head -c 200 "$TMP/err")"; continue
        fi
        h=$(sha256sum < "$o" | cut -c1-64)
        if [ -z "$ref" ]; then ref=$h
        elif [ "$h" != "$ref" ]; then fail "twk --sector $s --bidx $b: $c's ciphertext differs"; continue
        fi
        ${CLI[$c]} twk --decrypt --key "$TMP/sk.hex" --sector "$s" --bidx "$b" \
            --in "$o" --out "$TMP/pt" >/dev/null 2>&1
        if cmp -s "$TMP/pt" "$TMP/blk"; then pass
        else fail "twk --sector $s --bidx $b ($c): decrypt does not round-trip"; fi
    done
    CT["$s $b"]=$ref
done

# ── 2. no aliasing ──────────────────────────────────────────────────────────
declare -A SEEN=()
for pair in "${PAIRS[@]}"; do
    h=${CT[$pair]}
    [ -n "$h" ] || continue
    if [ -n "${SEEN[$h]:-}" ]; then fail "($pair) and (${SEEN[$h]}) share a ciphertext: tweak alias"
    else SEEN[$h]=$pair; pass; fi
done
for c in "${LANGS[@]}"; do
    ${CLI[$c]} twk --encrypt --key "$TMP/sk.hex" --bidx 007 --in "$TMP/blk" \
        --out "$TMP/z_$c" >/dev/null 2>&1
    if [ "$(sha256sum < "$TMP/z_$c" | cut -c1-64)" = "${CT[0 7]}" ]; then pass
    else fail "twk --bidx 007 ($c) is not block 7"; fi
done

# ── 3. refusals ─────────────────────────────────────────────────────────────
BAD=(-1 abc +1 0x10 " 1" "1 " "" 1e3 1.5 1_0 -0)
for c in "${LANGS[@]}"; do
    for flag in --bidx --sector; do
        if [ "$flag" = --bidx ]; then max=$B_MAX; over=(4294967296 18446744073709551616)
        else max=$S_MAX; over=(18446744073709551616 99999999999999999999); fi
        for v in "${BAD[@]}" "${over[@]}"; do
            o="$TMP/r_$c"; rm -f "$o"
            if ${CLI[$c]} twk --encrypt --key "$TMP/sk.hex" "$flag" "$v" --in "$TMP/blk" \
                    --out "$o" >/dev/null 2>"$TMP/err"; then
                fail "twk $flag '$v' ($c): accepted"
            elif ! grep -qF -- "twk: $flag must be a decimal integer from 0 to $max, got '$v'" "$TMP/err"; then
                fail "twk $flag '$v' ($c): refused, but not by name: $(head -c 200 "$TMP/err")"
            elif [ -e "$o" ]; then
                fail "twk $flag '$v' ($c): refused, but wrote $o"
            else
                pass
            fi
        done
    done
done

echo
echo "Results: $PASS PASS / $FAIL FAIL (languages: ${LANGS[*]})"
[ "$FAIL" -eq 0 ] || exit 1
