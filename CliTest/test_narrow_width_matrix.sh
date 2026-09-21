#!/usr/bin/env bash
# CliTest/test_narrow_width_matrix.sh — TODO #313: HSKE-NL-A1 is 256-BIT ONLY,
# in all four CLIs, on every path that reaches its keystream.
#
# THIS SCRIPT ASSERTS THE CONTRACT.  Its previous version did not: it PINNED THE
# DEFECT, because #313 was undecided between three routes and a script asserting
# the correct contract would have been red and would have had to be ignored —
# the allow-list CLAUDE.md's Testing section refuses to have.  #313 chose ROUTE
# 2 (refuse n != 256 rather than converge the four truncation rules), the four
# CLIs now do it, and this file was REWRITTEN rather than patched cell by cell,
# exactly as its own header instructed.  The 12-cell expectation table is gone:
# under route 2 there is nothing to tabulate, because no narrow cell is
# reachable.
#
# THE CONTRACT, stated so a regression has something to fail against: for
# `hske-nla1`, every CLI must refuse — non-zero exit — any width other than 256,
# whether the width arrives on the KEY or on the CIPHERTEXT's own declared
# `nbits` field, at `enc`, `dec`, `encfile` and `decfile` alike.  Exiting 0 with
# the wrong bytes is the one outcome that is never acceptable, and it was the
# outcome in 16 of the reachable cells before v9.0.0: `hske-nla1` is a raw XOR
# keystream with NO authentication tag, so a wrong keystream is not a detectable
# event and `dec` wrote garbage and reported success.
#
# WHY REFUSING IS THE FIX AND NOT A WORKAROUND.  Three independent causes made
# the four ports disagree (see TODO #313): the KDF domain constant is truncated
# at OPPOSITE ENDS (Python HIGH bits, Go LOW bits); C's `load_sym_key` dropped
# the declared width entirely and C stamps `nbits = 256` into every ciphertext
# regardless; and Java is 256-fixed and agrees with neither. Converging them is
# route 1, and C cannot follow it — it is compiled for a single KEYBITS and
# cannot represent a 128-bit A1 operation at all, so a convergence today would
# leave C differing while reporting the divergence closed.  That needs TODO
# #314's variable-width BitArray.  Route 2 is available now and two of the four
# already did it somewhere on the path (Java at `enc`, C at `genpkey`).
#
# WHY IT SHIPPED, which is the whole reason this file exists: nothing in the
# repo ran `hske-nla1` at a width other than 256.  All 42 CliTest invocations
# feed from default-width session keys; the eleven `--bits 64` uses are
# HKEX-RNL, which since TODO #228 derives a 256-bit session key at every ring
# dimension; the `--bits 32` uses are the Stern matrix dimension N.  A four-way
# divergence sat under a green 518-assertion cross-language matrix because the
# matrix only ever asked one width.
#
# FOUR THINGS ABOUT THE SHAPE, before editing anything below.
#   1. The n=256 ACCEPT CONTROL runs first and is not optional.  A CLI that
#      cannot encrypt at all refuses every narrow case too and would read as a
#      perfect route-2 implementation — TODO #234's vacuous pass wearing the
#      shape of success.  If the control fails, the refusals below prove nothing.
#   2. The ciphertext-width case REWRITES a genuine artifact's `nbits` field
#      rather than minting a narrow one, because no CLI will mint one any more.
#      The rewrite is length-preserving (DER INTEGER 256 is `02 02 01 00` and
#      128 is `02 02 00 80` — both four bytes, so no SEQUENCE length moves) and
#      it has its OWN control: the un-rewritten artifact must still decrypt, or
#      a rewrite that merely corrupted the PEM would score as a refusal for the
#      wrong reason.  That is lib_malformed.sh's discipline.
#   3. There is a SCOPE control.  #313 authorised a guard on `hske-nla1`, not on
#      every symmetric algo, so `enc --algo hske` at a narrow width must still
#      be accepted where it was before.  A guard that quietly widened would
#      otherwise pass every assertion in this file.
#   4. The refusal COUNT is asserted independently of the per-case results, so
#      one port silently losing its guard cannot pass quietly.
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

NARROW_WIDTHS="128 64"
REFUSALS=0
refused() { REFUSALS=$((REFUSALS+1)); }

MSG="$TMP/m.bin"; printf 'ABCD' > "$MSG"
hx() { od -An -tx1 "$1" 2>/dev/null | tr -d ' \n'; }
REF="$(hx "$MSG")"

# make_key <bits> — a session key of the given width, always via the Python CLI
# so the fixture itself is cross-language (test_malformed_pem_matrix.sh's rule).
# C cannot originate one: its genpkey has no --bits.  `kex` is unaffected by
# this item and still produces narrow session keys; it is `hske-nla1` that
# refuses to consume them.
make_key() {
    local b="$1" p="${CLI[py]}"
    # shellcheck disable=SC2086
    $p genpkey --algo hkex-gf --bits "$b" --out "$TMP/a$b.pem"  >/dev/null 2>&1
    # shellcheck disable=SC2086
    $p genpkey --algo hkex-gf --bits "$b" --out "$TMP/b$b.pem"  >/dev/null 2>&1
    # shellcheck disable=SC2086
    $p pkey --in "$TMP/b$b.pem" --pubout --out "$TMP/bp$b.pem"  >/dev/null 2>&1
    # shellcheck disable=SC2086
    $p kex --algo hkex-gf --our "$TMP/a$b.pem" --their "$TMP/bp$b.pem" \
           --out "$TMP/sk$b.pem" >/dev/null 2>&1
}

for b in 256 $NARROW_WIDTHS; do make_key "$b"; done

# ── 0. ACCEPT CONTROL: at 256 bits every pair must still round-trip ──────────
echo ""
echo "=== control: n = 256, every pair must round-trip ==="
for e in "${LANGS[@]}"; do
    # shellcheck disable=SC2086
    if ! ${CLI[$e]} enc --algo hske-nla1 --key "$TMP/sk256.pem" \
                        --in "$MSG" --out "$TMP/ct_$e.pem" >/dev/null 2>&1; then
        fail "control n=256: $e could not encrypt"
        continue
    fi
    for d in "${LANGS[@]}"; do
        rm -f "$TMP/o.bin"
        # shellcheck disable=SC2086
        if ${CLI[$d]} dec --algo hske-nla1 --key "$TMP/sk256.pem" \
                          --in "$TMP/ct_$e.pem" --out "$TMP/o.bin" >/dev/null 2>&1 \
           && [ "$(hx "$TMP/o.bin" | cut -c1-${#REF})" = "$REF" ]; then
            pass "control n=256: $e -> $d"
        else
            fail "control n=256: $e -> $d did not round-trip"
        fi
    done
done

# ── 1. enc refuses a narrow KEY ──────────────────────────────────────────────
echo ""
echo "=== enc: a narrow session key must be refused ==="
for bits in $NARROW_WIDTHS; do
    for l in "${LANGS[@]}"; do
        # shellcheck disable=SC2086
        if ${CLI[$l]} enc --algo hske-nla1 --key "$TMP/sk$bits.pem" \
                          --in "$MSG" --out "$TMP/x.pem" >/dev/null 2>&1; then
            fail "n=$bits: $l enc ACCEPTED a narrow key — TODO #313 route 2 lost"
        else
            pass "n=$bits: $l enc refuses a narrow key"; refused
        fi
    done
done

# ── 2. dec refuses a narrow KEY ──────────────────────────────────────────────
# Against a GENUINE 256-bit ciphertext, so the only thing wrong is the key.
echo ""
echo "=== dec: a narrow session key must be refused ==="
for bits in $NARROW_WIDTHS; do
    for l in "${LANGS[@]}"; do
        rm -f "$TMP/o.bin"
        # shellcheck disable=SC2086
        if ${CLI[$l]} dec --algo hske-nla1 --key "$TMP/sk$bits.pem" \
                          --in "$TMP/ct_${LANGS[0]}.pem" --out "$TMP/o.bin" \
                          >/dev/null 2>&1; then
            fail "n=$bits: $l dec ACCEPTED a narrow key — it wrote $(hx "$TMP/o.bin" | cut -c1-16)…"
        else
            pass "n=$bits: $l dec refuses a narrow key"; refused
        fi
    done
done

# ── 3. dec refuses a narrow CIPHERTEXT-DECLARED width ────────────────────────
# The key is a genuine 256-bit one; only the artifact's own nbits field says
# otherwise.  This is the half that catches C's mislabelling from the other
# side: C stamps nbits=256 on everything, so a port that trusted only the key
# would still read a foreign narrow artifact at the wrong width.
echo ""
echo "=== dec: a ciphertext declaring a narrow width must be refused ==="
python3 - "$TMP/ct_${LANGS[0]}.pem" "$TMP/ct_relabelled.pem" <<'PY'
import sys, base64
src, dst = sys.argv[1], sys.argv[2]
lines = open(src).read().strip().split('\n')
der = base64.b64decode(''.join(lines[1:-1]))
# DER INTEGER 256 = 02 02 01 00; 128 = 02 02 00 80.  Same length, so no
# SEQUENCE length header moves and the artifact stays well-formed DER —
# the point is to change what it CLAIMS, not to corrupt it.
i = der.rfind(b'\x02\x02\x01\x00')
if i < 0:
    sys.exit("no nbits=256 DER INTEGER found in the ciphertext")
der = der[:i] + b'\x02\x02\x00\x80' + der[i + 4:]
b64 = base64.b64encode(der).decode()
body = '\n'.join(b64[j:j + 64] for j in range(0, len(b64), 64))
open(dst, 'w').write(lines[0] + '\n' + body + '\n' + lines[-1] + '\n')
PY

# CONTROL for the rewrite: the un-rewritten artifact must still decrypt.  A
# rewrite that merely corrupted the PEM would make every CLI below exit
# non-zero for the wrong reason and score as a clean pass.
rm -f "$TMP/o.bin"
# shellcheck disable=SC2086
if ${CLI[${LANGS[0]}]} dec --algo hske-nla1 --key "$TMP/sk256.pem" \
                           --in "$TMP/ct_${LANGS[0]}.pem" --out "$TMP/o.bin" \
                           >/dev/null 2>&1 \
   && [ "$(hx "$TMP/o.bin" | cut -c1-${#REF})" = "$REF" ]; then
    pass "relabel control: the un-rewritten artifact still decrypts"
else
    fail "relabel control: the source artifact does not decrypt — the cases below prove nothing"
fi

for l in "${LANGS[@]}"; do
    rm -f "$TMP/o.bin"
    # shellcheck disable=SC2086
    if ${CLI[$l]} dec --algo hske-nla1 --key "$TMP/sk256.pem" \
                      --in "$TMP/ct_relabelled.pem" --out "$TMP/o.bin" \
                      >/dev/null 2>&1; then
        fail "$l dec ACCEPTED a ciphertext declaring nbits=128"
    else
        pass "$l dec refuses a ciphertext declaring nbits=128"; refused
    fi
done

# ── 4. encfile / decfile refuse a narrow KEY ─────────────────────────────────
# Same seed derivation, same defect — and until v9.0.0 the C CLI was the one
# port that did not guard these two at all.
echo ""
echo "=== encfile / decfile: a narrow session key must be refused ==="
# shellcheck disable=SC2086
${CLI[${LANGS[0]}]} encfile --algo hske-nla1 --key "$TMP/sk256.pem" \
                            --in "$MSG" --out "$TMP/genuine.hkx" >/dev/null 2>&1 \
    || fail "encfile control: could not produce a genuine 256-bit .hkx"

for l in "${LANGS[@]}"; do
    # shellcheck disable=SC2086
    if ${CLI[$l]} encfile --algo hske-nla1 --key "$TMP/sk128.pem" \
                          --in "$MSG" --out "$TMP/f.hkx" >/dev/null 2>&1; then
        fail "$l encfile ACCEPTED a narrow key"
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

# ── 5. SCOPE CONTROL: the guard is `hske-nla1`'s, not every algo's ───────────
# #313 authorised refusing narrow widths for hske-nla1.  It did NOT authorise
# refusing them for `hske`, whose narrow-width behaviour is unmeasured and out
# of this item's scope.  Java is excluded because it was ALREADY 256-fixed for
# `hske` before this item — that is a pre-existing per-language scope decision,
# not something v9.0.0 did.
echo ""
echo "=== scope control: --algo hske at a narrow width is unaffected ==="
for l in "${LANGS[@]}"; do
    [ "$l" = java ] && continue
    # shellcheck disable=SC2086
    if ${CLI[$l]} enc --algo hske --key "$TMP/sk128.pem" \
                      --in "$MSG" --out "$TMP/h.pem" >/dev/null 2>&1; then
        pass "scope: $l enc --algo hske still accepts a narrow key"
    else
        fail "scope: $l enc --algo hske now REFUSES a narrow key — the #313 guard widened"
        echo "     #313 is scoped to hske-nla1.  Widening it to every symmetric algo is a" >&2
        echo "     separate decision with its own MAJOR cost; it must not happen by accident." >&2
    fi
done

# ── 6. The refusal count, asserted independently ─────────────────────────────
# 4 CLIs x (2 widths enc + 2 widths dec-key + 1 relabelled ct + encfile + decfile)
# = 4 x 7 = 28.  A per-case loop that silently stopped iterating, or one port
# quietly losing its guard, changes this number.
echo ""
echo "Narrow-width refusals observed: $REFUSALS"
if [ "${#LANGS[@]}" -eq 4 ] && [ "$REFUSALS" -ne 28 ]; then
    fail "expected 28 refusals with all four CLIs, saw $REFUSALS"
    echo "     FEWER means a port lost its guard on some path; MORE means the guard" >&2
    echo "     reaches somewhere this script does not describe.  Re-read the header." >&2
fi

echo ""
echo "Results: $PASS PASS / $FAIL FAIL (languages: ${LANGS[*]})"
hkx_require_asserted "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
