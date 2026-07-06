#!/usr/bin/env bash
# CliTest/test_zkbpp.sh — ZKB++ (nl-zkbpp) interop tests (TODO #122 Batch 2)
#
# Checks:
#  1. Python genpkey + sign nl-zkbpp + Python verify
#  2. C     genpkey + sign nl-zkbpp + C     verify
#  3. Go    genpkey + sign nl-zkbpp + Go    verify
#  4. Python sign → C     verify
#  5. Python sign → Go    verify
#  6. C     sign → Python verify
#  7. C     sign → Go    verify
#  8. Go    sign → Python verify
#  9. Go    sign → C     verify
# 10. Wrong-message rejection (Python verifier)

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

PY="python3 ${ROOT}/HerraduraCli/herradura.py"
C="${ROOT}/HerraduraCli/herradura_cli"
GO="${ROOT}/HerraduraCli/herradura_cli_go"
MSG="${ROOT}/CliTest/test_input.txt"

PASS=0
FAIL=0

check() {
    local desc="$1"; shift
    if "$@" > /dev/null 2>&1; then
        echo "PASS: ${desc}"
        PASS=$((PASS+1))
    else
        echo "FAIL: ${desc}"
        FAIL=$((FAIL+1))
    fi
}

fail_check() {
    local desc="$1"; shift
    if ! "$@" > /dev/null 2>&1; then
        echo "PASS: ${desc}"
        PASS=$((PASS+1))
    else
        echo "FAIL: ${desc} (expected failure but succeeded)"
        FAIL=$((FAIL+1))
    fi
}

TMP=$(mktemp -d)
trap 'rm -rf "${TMP}"' EXIT

# Create a test message
echo "ZKB++ interop test message" > "${TMP}/msg.txt"
echo "wrong message for rejection test" > "${TMP}/wrong.txt"

# Generate keys for each implementation
${PY} genpkey --algo hpks-zkp-nl --out "${TMP}/py_priv.pem"
${PY} pkey --in "${TMP}/py_priv.pem" --pubout --out "${TMP}/py_pub.pem"

${C} genpkey --algo hpks-zkp-nl --out "${TMP}/c_priv.pem"
${C} pkey --in "${TMP}/c_priv.pem" --pubout --out "${TMP}/c_pub.pem"

${GO} genpkey --algo hpks-zkp-nl --out "${TMP}/go_priv.pem"
${GO} pkey --in "${TMP}/go_priv.pem" --pubout --out "${TMP}/go_pub.pem"

# 1. Python sign + Python verify
${PY} sign --algo nl-zkbpp --key "${TMP}/py_priv.pem" --in "${TMP}/msg.txt" --out "${TMP}/py_sig.pem"
check "1. Python sign → Python verify" \
    ${PY} verify --algo nl-zkbpp --pubkey "${TMP}/py_pub.pem" \
        --in "${TMP}/msg.txt" --sig "${TMP}/py_sig.pem"

# 2. C sign + C verify
${C} sign --algo nl-zkbpp --key "${TMP}/c_priv.pem" --in "${TMP}/msg.txt" --out "${TMP}/c_sig.pem"
check "2. C sign → C verify" \
    ${C} verify --algo nl-zkbpp --pubkey "${TMP}/c_pub.pem" \
        --in "${TMP}/msg.txt" --sig "${TMP}/c_sig.pem"

# 3. Go sign + Go verify
${GO} sign --algo nl-zkbpp --key "${TMP}/go_priv.pem" --in "${TMP}/msg.txt" --out "${TMP}/go_sig.pem"
check "3. Go sign → Go verify" \
    ${GO} verify --algo nl-zkbpp --pubkey "${TMP}/go_pub.pem" \
        --in "${TMP}/msg.txt" --sig "${TMP}/go_sig.pem"

# 4. Python sign → C verify
check "4. Python sign → C verify" \
    ${C} verify --algo nl-zkbpp --pubkey "${TMP}/py_pub.pem" \
        --in "${TMP}/msg.txt" --sig "${TMP}/py_sig.pem"

# 5. Python sign → Go verify
check "5. Python sign → Go verify" \
    ${GO} verify --algo nl-zkbpp --pubkey "${TMP}/py_pub.pem" \
        --in "${TMP}/msg.txt" --sig "${TMP}/py_sig.pem"

# 6. C sign → Python verify
check "6. C sign → Python verify" \
    ${PY} verify --algo nl-zkbpp --pubkey "${TMP}/c_pub.pem" \
        --in "${TMP}/msg.txt" --sig "${TMP}/c_sig.pem"

# 7. C sign → Go verify
check "7. C sign → Go verify" \
    ${GO} verify --algo nl-zkbpp --pubkey "${TMP}/c_pub.pem" \
        --in "${TMP}/msg.txt" --sig "${TMP}/c_sig.pem"

# 8. Go sign → Python verify
check "8. Go sign → Python verify" \
    ${PY} verify --algo nl-zkbpp --pubkey "${TMP}/go_pub.pem" \
        --in "${TMP}/msg.txt" --sig "${TMP}/go_sig.pem"

# 9. Go sign → C verify
check "9. Go sign → C verify" \
    ${C} verify --algo nl-zkbpp --pubkey "${TMP}/go_pub.pem" \
        --in "${TMP}/msg.txt" --sig "${TMP}/go_sig.pem"

# 10. Wrong-message rejection (Python verifier)
fail_check "10. Wrong-message rejection (Python verifier)" \
    ${PY} verify --algo nl-zkbpp --pubkey "${TMP}/py_pub.pem" \
        --in "${TMP}/wrong.txt" --sig "${TMP}/py_sig.pem"

echo ""
echo "Results: ${PASS} passed, ${FAIL} failed"
[ "${FAIL}" -eq 0 ]
