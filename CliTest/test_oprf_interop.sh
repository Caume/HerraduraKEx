#!/usr/bin/env bash
# CliTest/test_oprf_interop.sh — Cross-language OPRF interoperability tests (TODO #80 Batch 6)
# Tests all 6 key×blind×eval×unblind language combinations across Python, C, Go.
set -euo pipefail

PY="python3 HerraduraCli/herradura.py"
CC="./HerraduraCli/herradura_cli"
GO="./HerraduraCli/herradura_cli_go"
PASS=0; FAIL=0

check() {
    local desc="$1"; shift
    if "$@" 2>/dev/null; then
        echo "PASS: $desc"; PASS=$((PASS+1))
    else
        echo "FAIL: $desc"; FAIL=$((FAIL+1))
    fi
}

T=$(mktemp -d)
trap 'rm -rf "$T"' EXIT
printf '%s' "interop-test-input" > "$T/input.bin"

echo "=== OPRF cross-language interop tests ==="

run_combo() {
    local key_cli="$1" blind_cli="$2" eval_cli="$3" unblind_cli="$4" label="$5"
    $key_cli genpkey --algo oprf --out "$T/srv_${label}.pem"
    $blind_cli oprf-blind --in "$T/input.bin" --out "$T/state_${label}.pem"
    $eval_cli oprf-eval --key "$T/srv_${label}.pem" --in "$T/state_${label}.pem" --out "$T/eval_${label}.pem"
    local out
    out=$($unblind_cli oprf-unblind --state "$T/state_${label}.pem" --eval "$T/eval_${label}.pem" | tr -d '\n')
    echo "$out"
}

# Reference: all-Python
REF=$(run_combo "$PY" "$PY" "$PY" "$PY" "pp")
check "Python→Python (baseline, 64 chars)" test "${#REF}" -eq 64

# Python key, C blind+eval, Go unblind
OUT=$(run_combo "$PY" "$CC" "$CC" "$GO" "pcc_gu")
check "Python key / C blind+eval / Go unblind" test "${#OUT}" -eq 64

# Python key, Go blind+eval, C unblind
OUT=$(run_combo "$PY" "$GO" "$GO" "$CC" "pgg_cu")
check "Python key / Go blind+eval / C unblind" test "${#OUT}" -eq 64

# C key, Python blind+eval, Go unblind
OUT=$(run_combo "$CC" "$PY" "$PY" "$GO" "cpp_gu")
check "C key / Python blind+eval / Go unblind" test "${#OUT}" -eq 64

# C key, Go blind+eval, Python unblind
OUT=$(run_combo "$CC" "$GO" "$GO" "$PY" "cgg_pu")
check "C key / Go blind+eval / Python unblind" test "${#OUT}" -eq 64

# Go key, Python blind+eval, C unblind
OUT=$(run_combo "$GO" "$PY" "$PY" "$CC" "gpp_cu")
check "Go key / Python blind+eval / C unblind" test "${#OUT}" -eq 64

# Go key, C blind+eval, Python unblind
OUT=$(run_combo "$GO" "$CC" "$CC" "$PY" "gcc_pu")
check "Go key / C blind+eval / Python unblind" test "${#OUT}" -eq 64

# Cross-language eval: Python blind, C eval, Go unblind (mixed eval)
$PY genpkey --algo oprf --out "$T/srv_x.pem"
$PY oprf-blind --in "$T/input.bin" --out "$T/state_x.pem"
$CC oprf-eval --key "$T/srv_x.pem" --in "$T/state_x.pem" --out "$T/eval_xc.pem"
OUT_C=$($GO oprf-unblind --state "$T/state_x.pem" --eval "$T/eval_xc.pem" | tr -d '\n')
$GO oprf-eval --key "$T/srv_x.pem" --in "$T/state_x.pem" --out "$T/eval_xg.pem"
OUT_G=$($PY oprf-unblind --state "$T/state_x.pem" --eval "$T/eval_xg.pem" | tr -d '\n')
check "C eval == Go eval (same alpha+key → same beta)" test "$OUT_C" = "$OUT_G"

echo ""
echo "Results: $PASS passed, $FAIL failed"
test "$FAIL" -eq 0
