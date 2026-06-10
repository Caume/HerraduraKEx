#!/usr/bin/env bash
# CliTest/test_go_oprf.sh — Go CLI OPRF integration tests (TODO #80 Batch 3)
set -euo pipefail

CLI="./HerraduraCli/herradura_cli_go"
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

echo "=== OPRF Go CLI tests ==="

# 1. Key generation
$CLI genpkey --algo oprf --out "$T/srv.pem"
check "genpkey --algo oprf produces OPRF PRIVATE KEY PEM" \
    grep -q "HERRADURA OPRF PRIVATE KEY" "$T/srv.pem"

# 2. Blind
printf '%s' "test-input-value" > "$T/input.bin"
$CLI oprf-blind --in "$T/input.bin" --out "$T/state.pem"
check "oprf-blind produces CLIENT STATE PEM" \
    grep -q "HERRADURA OPRF CLIENT STATE" "$T/state.pem"

# 3. Eval
$CLI oprf-eval --key "$T/srv.pem" --in "$T/state.pem" --out "$T/eval.pem"
check "oprf-eval produces EVALUATION PEM" \
    grep -q "HERRADURA OPRF EVALUATION" "$T/eval.pem"

# 4. Unblind produces 64-char hex
OUT=$($CLI oprf-unblind --state "$T/state.pem" --eval "$T/eval.pem" | tr -d '\n')
check "oprf-unblind output is 64-char hex" test "${#OUT}" -eq 64

# 5. Determinism
$CLI oprf-blind --in "$T/input.bin" --out "$T/state2.pem"
$CLI oprf-eval  --key "$T/srv.pem"  --in "$T/state2.pem" --out "$T/eval2.pem"
OUT2=$($CLI oprf-unblind --state "$T/state2.pem" --eval "$T/eval2.pem" | tr -d '\n')
check "OPRF is deterministic: same input+key → same output" test "$OUT" = "$OUT2"

# 6. Different input → different output
printf '%s' "different-input" > "$T/input2.bin"
$CLI oprf-blind --in "$T/input2.bin" --out "$T/state3.pem"
$CLI oprf-eval  --key "$T/srv.pem"   --in "$T/state3.pem" --out "$T/eval3.pem"
OUT3=$($CLI oprf-unblind --state "$T/state3.pem" --eval "$T/eval3.pem" | tr -d '\n')
check "Different input → different PRF output" test "$OUT" != "$OUT3"

# 7. Different key → different output
$CLI genpkey --algo oprf --out "$T/srv2.pem"
$CLI oprf-blind --in "$T/input.bin"  --out "$T/state4.pem"
$CLI oprf-eval  --key "$T/srv2.pem"  --in "$T/state4.pem" --out "$T/eval4.pem"
OUT4=$($CLI oprf-unblind --state "$T/state4.pem" --eval "$T/eval4.pem" | tr -d '\n')
check "Different server key → different PRF output" test "$OUT" != "$OUT4"

echo ""
echo "Results: $PASS passed, $FAIL failed"
test "$FAIL" -eq 0
