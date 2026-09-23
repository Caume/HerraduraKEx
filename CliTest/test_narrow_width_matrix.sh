#!/usr/bin/env bash
# CliTest/test_narrow_width_matrix.sh — the WIDTH axis for HSKE-NL-A1.
#
# THIRD VERSION, and each rewrite was instructed by the one before it.  v8.3.1
# PINNED THE DEFECT, because TODO #313 was undecided between three routes and a
# script asserting the correct contract would have been red and would have had
# to be ignored — the allow-list CLAUDE.md's Testing section refuses to have.
# v9.0.0 asserted ROUTE 2, "all four CLIs REFUSE every width but 256", once
# #313 chose it.  This version asserts what route 2 was always a placeholder
# for: ALL FOUR AGREE.  TODO #314 gave every port one variable-width BitArray,
# and pass 6 relaxed the refusal — so the file is REWRITTEN rather than patched
# cell by cell, exactly as both previous headers instructed.
#
# THE CONTRACT, stated so a regression has something to fail against.  For
# `hske-nla1`, at EVERY legal BitArray width (BITARRAY.md §2: a multiple of 8
# from 16 to 256), a ciphertext written by any of the four CLIs must decrypt to
# the same plaintext under all four — the full (writer × reader) matrix, not
# each port against Python.  Two things are still refused, and they are refused
# for reasons about the FORMAT rather than about ports disagreeing: a width that
# is not a legal BitArray width (§2), and a ciphertext whose declared width
# disagrees with the key's (§3 — a mixed width is never coerced).
#
# WHAT WAS WRONG, which is what the matrix below now measures rather than
# asserts.  Three independent causes made the four ports produce four different
# keystreams below 256 (TODO #313): the KDF domain constant was truncated at
# OPPOSITE ENDS (Python HIGH bits, Go LOW bits); C's `load_sym_key` dropped the
# declared width and C stamped `nbits = 256` into every ciphertext whatever the
# key said; and Java was 256-fixed and agreed with neither.  All three are
# closed in the code: one `truncate` (§4.4) in one place per port, C's A1 path
# carries the key's own width end to end and STATES it in the artifact, and
# Java's NL-FSCX v1 round takes its rotation from the operand instead of from a
# static `N / 4`.
#
# WHY IT SHIPPED, which is why this file exists at all: nothing in the repo ran
# `hske-nla1` at a width other than 256.  A four-way divergence sat under a
# green 518-assertion cross-language matrix because the matrix only ever asked
# one width.  That is the standing lesson, and it is why this script sweeps
# widths rather than adding one more 256-bit assertion.
#
# SIX THINGS ABOUT THE SHAPE, before editing anything below.
#   1. THE MATRIX IS ITS OWN ACCEPT CONTROL, but only if it can fail.  A
#      comparison against a fixed plaintext passes trivially if every reader
#      writes the same bytes for any reason at all, so case 0 decrypts a
#      genuine artifact under the WRONG key and requires the result to DIFFER.
#      Without it, an `hske-nla1` that ignored the key entirely would score
#      64/64 — TODO #234's vacuous pass, inverted.
#   2. n = 256 IS IN THE SWEEP, not beside it.  It is the width everything else
#      in the repo pins, so a regression there must show up here too rather
#      than being someone else's problem.
#   3. THE REFUSALS THAT REMAIN ARE FORMAT REFUSALS, and both are length-
#      preserving REWRITES of a genuine artifact (DER INTEGER 256 is
#      `02 02 01 00`, 128 is `02 02 00 80`, 260 is `02 02 01 04` — all four
#      bytes, so no SEQUENCE length moves).  Each has its own control: the
#      un-rewritten artifact must still decrypt, or a rewrite that merely
#      corrupted the PEM would score as a refusal for the wrong reason.
#   4. encfile / decfile STILL REFUSE a narrow key, and that is not a leftover.
#      The `.hkx` container has no width field at all: its nonce is 32 octets,
#      its blocks are 32 octets and its tag is a 256-bit HFSCX-256 MAC.  Python,
#      Go and Java refused there long before #313.  A relaxation that reached
#      this path would be writing a container that cannot describe itself.
#   5. THE SCOPE CONTROL SURVIVES THE RELAXATION and is now pointing the other
#      way.  #313's guard was scoped to `hske-nla1`; `--algo hske` at a narrow
#      width was never in scope and must still behave as it did.  A relaxation
#      that quietly widened is as much a scope error as a guard that did.
#   6. BOTH COUNTS ARE ASSERTED INDEPENDENTLY of the per-case results — the
#      narrow round-trips and the refusals — so a loop that silently stopped
#      iterating, or one port quietly losing a check, cannot pass.
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

# 32 is the narrowest width this sweep uses; BITARRAY.md §2's floor is 16, and
# the floor is exercised by KAT/bitarray.json rather than by four CLI processes.
NARROW_WIDTHS="128 64 32"
ALL_WIDTHS="256 $NARROW_WIDTHS"
REFUSALS=0
NARROW_TRIPS=0
refused()  { REFUSALS=$((REFUSALS+1)); }

MSG="$TMP/m.bin"; printf 'ABCD' > "$MSG"
hx() { od -An -tx1 "$1" 2>/dev/null | tr -d ' \n'; }

# The A1 block is the KEY's width, so at n = 32 the recoverable prefix is the
# first 4 octets and at larger widths it is all of them, zero-padded.  Compare
# only the prefix that is actually carried.
expect_hex() {
    local bits="$1" nb=$((bits / 8)) want
    want="$(printf 'ABCD' | head -c "$nb" | od -An -tx1 | tr -d ' \n')"
    echo "$want"
}

# make_key <bits> — a session key of the given width, always via the Python CLI
# so the fixture itself is cross-language (test_malformed_pem_matrix.sh's rule).
# C cannot originate one: its genpkey has no --bits.
make_key() {
    local b="$1" p="${CLI[py]}" tag="${2:-sk}"
    # shellcheck disable=SC2086
    $p genpkey --algo hkex-gf --bits "$b" --out "$TMP/${tag}a$b.pem"  >/dev/null 2>&1
    # shellcheck disable=SC2086
    $p genpkey --algo hkex-gf --bits "$b" --out "$TMP/${tag}b$b.pem"  >/dev/null 2>&1
    # shellcheck disable=SC2086
    $p pkey --in "$TMP/${tag}b$b.pem" --pubout --out "$TMP/${tag}bp$b.pem" >/dev/null 2>&1
    # shellcheck disable=SC2086
    $p kex --algo hkex-gf --our "$TMP/${tag}a$b.pem" --their "$TMP/${tag}bp$b.pem" \
           --out "$TMP/$tag$b.pem" >/dev/null 2>&1
}

for b in $ALL_WIDTHS; do make_key "$b"; done
make_key 256 other          # an independent 256-bit key, for case 0

# ── 0. THE CONTROL THAT LETS THE MATRIX FAIL ─────────────────────────────────
# Decrypting a genuine artifact under a DIFFERENT key must not reproduce the
# plaintext.  If it does, every cell below is comparing something that does not
# depend on the key and the matrix proves nothing.
echo ""
echo "=== control: the matrix can fail (wrong key must not recover) ==="
# shellcheck disable=SC2086
${CLI[${LANGS[0]}]} enc --algo hske-nla1 --key "$TMP/sk256.pem" \
                        --in "$MSG" --out "$TMP/ct_ctl.pem" >/dev/null 2>&1 \
    || fail "control: ${LANGS[0]} could not produce a 256-bit artifact"
rm -f "$TMP/o.bin"
# shellcheck disable=SC2086
if ${CLI[${LANGS[0]}]} dec --algo hske-nla1 --key "$TMP/other256.pem" \
                           --in "$TMP/ct_ctl.pem" --out "$TMP/o.bin" >/dev/null 2>&1 \
   && [ "$(hx "$TMP/o.bin" | cut -c1-8)" = "$(expect_hex 256)" ]; then
    fail "control: a DIFFERENT key recovered the plaintext — the matrix is vacuous"
else
    pass "control: a different key does not recover the plaintext"
fi

# ── 1. THE MATRIX: every (writer × reader) pair, at every width ──────────────
echo ""
echo "=== the matrix: every writer x reader pair, at 256 / 128 / 64 / 32 ==="
for bits in $ALL_WIDTHS; do
    want="$(expect_hex "$bits")"
    for e in "${LANGS[@]}"; do
        # shellcheck disable=SC2086
        if ! ${CLI[$e]} enc --algo hske-nla1 --key "$TMP/sk$bits.pem" \
                            --in "$MSG" --out "$TMP/ct_${bits}_$e.pem" >/dev/null 2>&1; then
            fail "n=$bits: $e could not encrypt"
            continue
        fi
        for d in "${LANGS[@]}"; do
            rm -f "$TMP/o.bin"
            # shellcheck disable=SC2086
            if ${CLI[$d]} dec --algo hske-nla1 --key "$TMP/sk$bits.pem" \
                              --in "$TMP/ct_${bits}_$e.pem" --out "$TMP/o.bin" \
                              >/dev/null 2>&1 \
               && [ "$(hx "$TMP/o.bin" | cut -c1-${#want})" = "$want" ]; then
                pass "n=$bits: $e -> $d"
                [ "$bits" != 256 ] && NARROW_TRIPS=$((NARROW_TRIPS+1))
            else
                fail "n=$bits: $e -> $d did not round-trip (got $(hx "$TMP/o.bin" | cut -c1-16))"
            fi
        done
    done
done

# ── 2. A MIXED WIDTH IS NEVER COERCED (BITARRAY.md §3) ───────────────────────
# The key is a genuine 256-bit one; only the artifact's own nbits field says
# otherwise.  Before v9.0.0 this was the half that caught C's mislabelling; it
# is now the half that keeps the relaxation from becoming a coercion — a reader
# that simply believed the key, or simply believed the artifact, would pass the
# whole matrix above and silently mis-decrypt here.
relabel() {   # relabel <src> <dst> <4-byte DER replacement, hex>
    python3 - "$1" "$2" "$3" <<'PY'
import sys, base64
src, dst, repl = sys.argv[1], sys.argv[2], bytes.fromhex(sys.argv[3])
lines = open(src).read().strip().split('\n')
der = base64.b64decode(''.join(lines[1:-1]))
i = der.rfind(b'\x02\x02\x01\x00')       # DER INTEGER 256, the trailing nbits
if i < 0:
    sys.exit("no nbits=256 DER INTEGER found in the ciphertext")
assert len(repl) == 4, "the rewrite must be length-preserving"
der = der[:i] + repl + der[i + 4:]
b64 = base64.b64encode(der).decode()
body = '\n'.join(b64[j:j + 64] for j in range(0, len(b64), 64))
open(dst, 'w').write(lines[0] + '\n' + body + '\n' + lines[-1] + '\n')
PY
}

echo ""
echo "=== §3: a ciphertext declaring a width the key does not have ==="
relabel "$TMP/ct_256_${LANGS[0]}.pem" "$TMP/ct_mixed.pem" 02020080     # 128

# CONTROL for the rewrite: the un-rewritten artifact must still decrypt.
rm -f "$TMP/o.bin"
want256="$(expect_hex 256)"
# shellcheck disable=SC2086
if ${CLI[${LANGS[0]}]} dec --algo hske-nla1 --key "$TMP/sk256.pem" \
                           --in "$TMP/ct_256_${LANGS[0]}.pem" --out "$TMP/o.bin" \
                           >/dev/null 2>&1 \
   && [ "$(hx "$TMP/o.bin" | cut -c1-${#want256})" = "$want256" ]; then
    pass "relabel control: the un-rewritten artifact still decrypts"
else
    fail "relabel control: the source artifact does not decrypt — the cases below prove nothing"
fi

for l in "${LANGS[@]}"; do
    rm -f "$TMP/o.bin"
    # shellcheck disable=SC2086
    if ${CLI[$l]} dec --algo hske-nla1 --key "$TMP/sk256.pem" \
                      --in "$TMP/ct_mixed.pem" --out "$TMP/o.bin" >/dev/null 2>&1; then
        fail "$l dec COERCED a 128-bit-labelled ciphertext to a 256-bit key"
    else
        pass "$l dec refuses a mixed width (ct 128, key 256)"; refused
    fi
done

# ── 3. A WIDTH THAT IS NOT A LEGAL BitArray WIDTH (BITARRAY.md §2) ───────────
echo ""
echo "=== §2: a ciphertext declaring a width no BitArray can have ==="
relabel "$TMP/ct_256_${LANGS[0]}.pem" "$TMP/ct_badwidth.pem" 02020104   # 260
for l in "${LANGS[@]}"; do
    rm -f "$TMP/o.bin"
    # shellcheck disable=SC2086
    if ${CLI[$l]} dec --algo hske-nla1 --key "$TMP/sk256.pem" \
                      --in "$TMP/ct_badwidth.pem" --out "$TMP/o.bin" >/dev/null 2>&1; then
        fail "$l dec ACCEPTED a ciphertext declaring nbits=260"
    else
        pass "$l dec refuses an illegal width (260)"; refused
    fi
done

# ── 4. encfile / decfile: the .hkx container is 256-bit BY FORMAT ────────────
echo ""
echo "=== encfile / decfile: the container has no width field, so 256 only ==="
# shellcheck disable=SC2086
${CLI[${LANGS[0]}]} encfile --algo hske-nla1 --key "$TMP/sk256.pem" \
                            --in "$MSG" --out "$TMP/genuine.hkx" >/dev/null 2>&1 \
    || fail "encfile control: could not produce a genuine 256-bit .hkx"

for l in "${LANGS[@]}"; do
    # shellcheck disable=SC2086
    if ${CLI[$l]} encfile --algo hske-nla1 --key "$TMP/sk128.pem" \
                          --in "$MSG" --out "$TMP/f.hkx" >/dev/null 2>&1; then
        fail "$l encfile ACCEPTED a narrow key — the .hkx container cannot describe it"
    else
        pass "$l encfile refuses a narrow key"; refused
    fi
    rm -f "$TMP/o.bin"
    # shellcheck disable=SC2086
    if ${CLI[$l]} decfile --algo hske-nla1 --key "$TMP/sk128.pem" \
                          --in "$TMP/genuine.hkx" --out "$TMP/o.bin" >/dev/null 2>&1; then
        fail "$l decfile ACCEPTED a narrow key"
    else
        pass "$l decfile refuses a narrow key"; refused
    fi
done

# ── 5. SCOPE CONTROL: the relaxation is `hske-nla1`'s, not every algo's ──────
# #313's guard was scoped to hske-nla1 and so is its relaxation.  `--algo hske`
# at a narrow width was never in scope: it must behave exactly as it did.  Java
# is excluded because it was ALREADY 256-fixed for `hske` before either item —
# a pre-existing per-language scope decision.
echo ""
echo "=== scope control: --algo hske at a narrow width is unaffected ==="
for l in "${LANGS[@]}"; do
    [ "$l" = java ] && continue
    # shellcheck disable=SC2086
    if ${CLI[$l]} enc --algo hske --key "$TMP/sk128.pem" \
                      --in "$MSG" --out "$TMP/h.pem" >/dev/null 2>&1; then
        pass "scope: $l enc --algo hske still accepts a narrow key"
    else
        fail "scope: $l enc --algo hske now REFUSES a narrow key — the scope moved"
    fi
done

# ── 6. The two counts, asserted independently ────────────────────────────────
# Narrow round-trips: 3 widths x 4 writers x 4 readers = 48.
# Refusals: 4 CLIs x (mixed width + illegal width + encfile + decfile) = 16.
echo ""
echo "Narrow-width round-trips observed: $NARROW_TRIPS"
echo "Format refusals observed: $REFUSALS"
if [ "${#LANGS[@]}" -eq 4 ]; then
    [ "$NARROW_TRIPS" -eq 48 ] || {
        fail "expected 48 narrow round-trips with all four CLIs, saw $NARROW_TRIPS"
        echo "     FEWER means a cell stopped agreeing; MORE means a width was added" >&2
        echo "     without updating this count.  Re-read the header." >&2
    }
    [ "$REFUSALS" -eq 16 ] || {
        fail "expected 16 format refusals with all four CLIs, saw $REFUSALS"
        echo "     FEWER means a port lost a §2/§3 check or the .hkx guard; MORE means" >&2
        echo "     a refusal reaches somewhere this script does not describe." >&2
    }
fi

echo ""
echo "Results: $PASS PASS / $FAIL FAIL (languages: ${LANGS[*]})"
hkx_require_asserted "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
