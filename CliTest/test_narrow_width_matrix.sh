#!/usr/bin/env bash
# CliTest/test_narrow_width_matrix.sh — TODO #313: what the four CLIs do with
# an HSKE-NL-A1 key narrower than 256 bits.
#
# READ THIS BEFORE CHANGING ANY EXPECTATION BELOW.  This script PINS A KNOWN
# DEFECT.  It does not assert that the behaviour is correct; it asserts that the
# behaviour is still exactly what TODO #313 recorded, so that the moment anyone
# changes it — by fixing it or by making it worse — a test says so.  #313 is
# still OPEN and undecided between three routes, and a script that asserted the
# CORRECT contract would be red today and would have to be ignored, which is the
# allow-list CLAUDE.md's Testing section refuses to have.
#
# THE CONTRACT THAT IS VIOLATED, stated so the fix has something to aim at: for
# every (encryptor, decryptor) pair, the decryptor must either reproduce the
# plaintext or exit non-zero.  Exiting 0 with the wrong bytes is the one outcome
# that is never acceptable.  `hske-nla1` is a raw XOR keystream with NO
# authentication tag, so a wrong keystream is not a detectable event: `dec`
# writes garbage and reports success.  8 of the 12 reachable cells do that
# today, at every narrow width tested.
#
# WHY IT SHIPPED, which is the whole reason this file exists: nothing in the
# repo ran `hske-nla1` at a width other than 256.  All 42 CliTest invocations
# feed from default-width session keys; the eleven `--bits 64` uses are
# HKEX-RNL, which since TODO #228 derives a 256-bit session key at every ring
# dimension; the `--bits 32` uses are the Stern matrix dimension N.  A four-way
# divergence sat under a green 518-assertion cross-language matrix because the
# matrix only ever asked one width.
#
# THE MECHANISM, three independent causes (see TODO #313):
#   1. The KDF domain constant is truncated at OPPOSITE ENDS.  Python takes its
#      HIGH n bits (`DC >> (256 - nbits)`), Go's RnlKdfSeed takes the LOW n bits
#      (`RnlKdfDC[32-n/8:]`).  At n=128 those are disjoint halves.
#   2. C ignores the declared width: `load_sym_key` zero-extends any session key
#      into a fixed KEYBITS BitArray, and C then LABELS its ciphertext nbits=256
#      regardless.  That last part is why (c -> go) works and (go -> c) does not:
#      Go honours the label, so it follows C up to 256, while C reads Go's
#      128-labelled ciphertext at 256 anyway.
#   3. Java is 256-fixed too and still differs from C.
#
# TWO THINGS THE PROBE FOUND THAT #313 DID NOT, and they matter to the decision:
#   * C's `genpkey` does not accept `--bits` at all (exit 2, "unrecognised
#     flag").  C already fails CLOSED when asked to create a narrow key; it fails
#     OPEN only when importing one made elsewhere.
#   * Java's `enc --algo hske-nla1` REFUSES a narrow key (exit 1).  Java already
#     does #313's route 2 on the encrypt side.  Its `dec`, however, returns
#     all-zero plaintext with exit 0 — wrong in the particularly bad way of
#     looking like a legitimately empty result.
#
# So two of the four already refuse at some point on the path, which is evidence
# for route 2 (refuse n != 256 everywhere) rather than route 1 (converge).
#
# WHEN #313 IS DECIDED, THIS SCRIPT MUST BE REWRITTEN, not patched cell by cell.
# Under route 2 every narrow cell becomes `refuse` and the expectation table
# collapses to one line.  Under route 1 every cell becomes `ok`.  Either way the
# table below is the thing that changes, and the failure message says so.
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

# ── The expectation table ────────────────────────────────────────────────────
# NARROW[enc,dec] is what a narrow-width (enc -> dec) pair does TODAY:
#   ok      the decryptor reproduces the plaintext
#   wrong   the decryptor exits 0 and writes the WRONG bytes   <-- the defect
#   refuse  the decryptor exits non-zero
# ENC_REFUSE lists encryptors that reject a narrow key outright, making their
# whole row unreachable.
declare -A NARROW=(
    [py,py]=ok     [py,c]=wrong  [py,go]=wrong  [py,java]=wrong
    [c,py]=wrong   [c,c]=ok      [c,go]=ok      [c,java]=wrong
    [go,py]=wrong  [go,c]=wrong  [go,go]=ok     [go,java]=wrong
)
ENC_REFUSE="java"

MSG="$TMP/m.bin"; printf 'ABCD' > "$MSG"
hx() { od -An -tx1 "$1" 2>/dev/null | tr -d ' \n'; }
REF="$(hx "$MSG")"

# make_key <bits> — a session key of the given width, always via the Python CLI
# so the fixture itself is cross-language (test_malformed_pem_matrix.sh's rule).
# C cannot originate one: its genpkey has no --bits.
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

# observe <enc> <dec> <bits> — prints ok | wrong | refuse for one cell.
observe() {
    local e="$1" d="$2" b="$3" ct="$TMP/ct_${1}_${3}.pem" out="$TMP/o.bin"
    rm -f "$out"
    # shellcheck disable=SC2086
    if ! ${CLI[$d]} dec --algo hske-nla1 --key "$TMP/sk$b.pem" \
                        --in "$ct" --out "$out" >/dev/null 2>&1; then
        echo refuse; return
    fi
    if [ "$(hx "$out" | cut -c1-${#REF})" = "$REF" ]; then echo ok; else echo wrong; fi
}

# ── 1. ACCEPT CONTROL: at 256 bits every pair must agree ─────────────────────
# Without this the rest is meaningless: a CLI that cannot encrypt at all would
# score every narrow cell as `refuse` and look like a clean route-2 fix.
echo ""
echo "=== control: n = 256, every pair must round-trip ==="
make_key 256
for e in "${LANGS[@]}"; do
    # shellcheck disable=SC2086
    if ! ${CLI[$e]} enc --algo hske-nla1 --key "$TMP/sk256.pem" \
                        --in "$MSG" --out "$TMP/ct_${e}_256.pem" >/dev/null 2>&1; then
        fail "control n=256: $e could not encrypt"
        continue
    fi
    for d in "${LANGS[@]}"; do
        if [ "$(observe "$e" "$d" 256)" = ok ]; then
            pass "control n=256: $e -> $d"
        else
            fail "control n=256: $e -> $d did not round-trip"
        fi
    done
done

# ── 2. THE NARROW MATRIX ─────────────────────────────────────────────────────
SILENT_WRONG=0
for bits in 128 64; do
    echo ""
    echo "=== n = $bits ==="
    make_key "$bits"
    for e in "${LANGS[@]}"; do
        # shellcheck disable=SC2086
        if ${CLI[$e]} enc --algo hske-nla1 --key "$TMP/sk$bits.pem" \
                          --in "$MSG" --out "$TMP/ct_${e}_${bits}.pem" >/dev/null 2>&1; then
            enc_ok=1
        else
            enc_ok=0
        fi

        case " $ENC_REFUSE " in
            *" $e "*)
                if [ "$enc_ok" -eq 0 ]; then
                    pass "n=$bits: $e enc refuses a narrow key (already #313 route 2)"
                else
                    fail "n=$bits: $e enc now ACCEPTS a narrow key — it used to refuse."
                    echo "     TODO #313 may have been decided; rewrite this script's table." >&2
                fi
                continue ;;
        esac

        if [ "$enc_ok" -eq 0 ]; then
            fail "n=$bits: $e enc now REFUSES a narrow key — it used to accept."
            echo "     TODO #313 may have been decided; rewrite this script's table." >&2
            continue
        fi

        for d in "${LANGS[@]}"; do
            want="${NARROW[$e,$d]:-}"
            [ -n "$want" ] || { fail "n=$bits: no expectation recorded for $e -> $d"; continue; }
            got="$(observe "$e" "$d" "$bits")"
            if [ "$got" = "$want" ]; then
                if [ "$want" = wrong ]; then
                    SILENT_WRONG=$((SILENT_WRONG+1))
                    pass "n=$bits: $e -> $d still silently wrong (KNOWN, TODO #313)"
                else
                    pass "n=$bits: $e -> $d $got"
                fi
            else
                fail "n=$bits: $e -> $d is '$got', recorded as '$want'."
                echo "     This cell CHANGED.  If it is now 'ok' or 'refuse' where it was" >&2
                echo "     'wrong', TODO #313 has been acted on and this script must be" >&2
                echo "     REWRITTEN (see its header), not patched cell by cell." >&2
            fi
        done
    done
done

# ── 3. The headline number, so a partial fix cannot pass quietly ─────────────
echo ""
echo "Cells exiting 0 with the WRONG plaintext: $SILENT_WRONG  (TODO #313, still OPEN)"
if [ "${#LANGS[@]}" -eq 4 ] && [ "$SILENT_WRONG" -ne 16 ]; then
    fail "expected 16 silently-wrong cells across the two widths with all four CLIs, saw $SILENT_WRONG"
    echo "     Both directions matter: fewer means #313 was partly acted on, more means" >&2
    echo "     it got worse.  Either way, re-read the header before editing the table." >&2
fi

echo ""
echo "Results: $PASS PASS / $FAIL FAIL (languages: ${LANGS[*]})"
hkx_require_asserted "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
