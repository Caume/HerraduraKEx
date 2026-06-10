#!/usr/bin/env bash
# CliTest/test_go_pake.sh — Go CLI aPAKE integration tests (TODO #80 Batch 4-Go)
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

echo "=== aPAKE Go CLI tests ==="

# 1. Generate OPRF server key
$CLI genpkey --algo oprf --out "$T/oprf.pem"
check "OPRF server key generated" grep -q "HERRADURA OPRF PRIVATE KEY" "$T/oprf.pem"

# 2. pake-register: produces PAKE RECORD PEM
$CLI pake-register --key "$T/oprf.pem" --password s3cr3t --out "$T/record.pem"
check "pake-register produces PAKE RECORD PEM" grep -q "HERRADURA PAKE RECORD" "$T/record.pem"

# 3. pake-demo: correct password succeeds
$CLI pake-demo --key "$T/oprf.pem" --password s3cr3t > "$T/demo_out.txt"
check "pake-demo: correct password shows session key" \
    grep -q "aPAKE login succeeded" "$T/demo_out.txt"
check "pake-demo: wrong password correctly rejected" \
    grep -q "correctly rejects wrong password" "$T/demo_out.txt"

# 4. pake-demo: session key is 64-char hex
SK=$(grep "session key:" "$T/demo_out.txt" | sed 's/.*session key: //' | tr -d '\n')
check "pake-demo: session key is 64-char hex" test "${#SK}" -eq 64

# 5. Different passwords → different session keys
$CLI pake-demo --key "$T/oprf.pem" --password pass1 > "$T/demo1.txt"
$CLI pake-demo --key "$T/oprf.pem" --password pass2 > "$T/demo2.txt"
SK1=$(grep "session key:" "$T/demo1.txt" | sed 's/.*session key: //' | tr -d '\n')
SK2=$(grep "session key:" "$T/demo2.txt" | sed 's/.*session key: //' | tr -d '\n')
check "Different passwords → different session keys" test "$SK1" != "$SK2"

# 6. Different OPRF keys → different session keys for same password
$CLI genpkey --algo oprf --out "$T/oprf2.pem"
$CLI pake-demo --key "$T/oprf.pem"  --password same-pw > "$T/demo3.txt"
$CLI pake-demo --key "$T/oprf2.pem" --password same-pw > "$T/demo4.txt"
SK3=$(grep "session key:" "$T/demo3.txt" | sed 's/.*session key: //' | tr -d '\n')
SK4=$(grep "session key:" "$T/demo4.txt" | sed 's/.*session key: //' | tr -d '\n')
check "Different OPRF keys → different session keys" test "$SK3" != "$SK4"

echo ""
echo "Results: $PASS passed, $FAIL failed"
test "$FAIL" -eq 0
