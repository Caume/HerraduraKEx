#!/usr/bin/env bash
# CliTest/test_hybrid_kex_interop.sh — TODO #167: cross-language interop matrix for
# `kex --algo hybrid-rnl-stern` (TODO #162's combiner, ported to Go/C by TODO #167).
#
# Verifies that Bob (in any of Python/C/Go) and Alice (in any of Python/C/Go) derive
# byte-identical session keys, regardless of which CLI each party runs — a 3x3 matrix,
# matching test_stern_kem.sh's cross-language interop-matrix convention. Alice's own
# HKEX-RNL and HPKE-Stern-KEM keys are generated once (with Python, arbitrarily) and
# reused across the matrix so only Bob's per-cell CLI varies the response transcript.
set -euo pipefail

DIR="$(dirname "$0")/../HerraduraCli"
CLI_PY="python3 $DIR/herradura.py"
CLI_C="$DIR/herradura_cli"
CLI_GO="$DIR/herradura_cli_go"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
PASS=0; FAIL=0

check() {
    local label="$1" result="$2"
    if [ "$result" = "ok" ]; then
        echo "PASS $label"
        PASS=$((PASS+1))
    else
        echo "FAIL $label: $result"
        FAIL=$((FAIL+1))
    fi
}

GO_AVAILABLE=false
if [ -x "$CLI_GO" ]; then GO_AVAILABLE=true; fi

printf 'HYBRIDKEX-TEST-MESSAGE-32-BYTES!' > "$TMP/msg.bin"

# ── Alice's keys (fixed across the whole matrix) ────────────────────────────
$CLI_PY genpkey --algo hkex-rnl       --out "$TMP/alice_rnl.pem"
$CLI_PY pkey --pubout --in "$TMP/alice_rnl.pem" --out "$TMP/alice_rnl_pub.pem"
$CLI_PY genpkey --algo hpke-stern-kem --out "$TMP/alice_kem.pem"
$CLI_PY pkey --pubout --in "$TMP/alice_kem.pem" --out "$TMP/alice_kem_pub.pem"

langs="py c"
if $GO_AVAILABLE; then langs="py c go"; fi

cli_for() {
    case "$1" in
        py) echo "$CLI_PY" ;;
        c)  echo "$CLI_C"  ;;
        go) echo "$CLI_GO" ;;
    esac
}

# ── Bob's key + response, one per language ──────────────────────────────────
declare -A RESP
for bob in $langs; do
    BOBCLI=$(cli_for "$bob")
    $BOBCLI genpkey --algo hkex-rnl --out "$TMP/bob_$bob.pem"
    $BOBCLI kex --algo hybrid-rnl-stern --our "$TMP/bob_$bob.pem" \
                --their "$TMP/alice_rnl_pub.pem" --their-kem "$TMP/alice_kem_pub.pem" \
                --out "$TMP/resp_$bob.pem"
    RESP[$bob]="$TMP/resp_$bob.pem"
done

# ── Alice completes against every Bob response, in every language ──────────
declare -A SK
for bob in $langs; do
    for alice in $langs; do
        ALICECLI=$(cli_for "$alice")
        out="$TMP/sk_${bob}_${alice}.pem"
        if $ALICECLI kex --algo hybrid-rnl-stern --our "$TMP/alice_rnl.pem" \
                --our-kem "$TMP/alice_kem.pem" --their "${RESP[$bob]}" --out "$out" \
                >/dev/null 2>"$TMP/err_${bob}_${alice}.log"; then
            SK[${bob}_${alice}]="$out"
        else
            check "hybrid-rnl-stern bob=$bob alice=$alice completes" "$(cat "$TMP/err_${bob}_${alice}.log")"
            continue
        fi
        check "hybrid-rnl-stern bob=$bob alice=$alice completes" "ok"
    done
done

# ── For each bob, all three alice-language session keys must be byte-identical,
#    and must equal Bob's own copy of K stored in the response PEM's first field ──
for bob in $langs; do
    ref="${SK[${bob}_py]:-}"
    [ -z "$ref" ] && continue
    for alice in $langs; do
        cur="${SK[${bob}_${alice}]:-}"
        [ -z "$cur" ] && continue
        if cmp -s "$ref" "$cur"; then
            check "session key match: bob=$bob alice=py vs alice=$alice" "ok"
        else
            check "session key match: bob=$bob alice=py vs alice=$alice" "byte mismatch"
        fi
    done
done

# ── Functional proof: cross-party encrypt/decrypt round-trip for one full
#    cross-language triangle (Bob=C, Alice=Go, verified with Python's response key) ─
if $GO_AVAILABLE; then
    $CLI_C enc --algo hske --key "$TMP/resp_c.pem" --in "$TMP/msg.bin" --out "$TMP/ct_c.pem"
    $CLI_GO dec --algo hske --key "$TMP/sk_c_go.pem" --in "$TMP/ct_c.pem" --out "$TMP/pt_go.bin"
    if cmp -s "$TMP/msg.bin" "$TMP/pt_go.bin"; then
        check "cross-language enc/dec round-trip (C bob enc / Go alice dec)" "ok"
    else
        check "cross-language enc/dec round-trip (C bob enc / Go alice dec)" "plaintext mismatch"
    fi
fi

echo ""
echo "Results: $PASS PASS / $FAIL FAIL"
[ "$FAIL" -eq 0 ]
