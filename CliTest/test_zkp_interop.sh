#!/usr/bin/env bash
# CliTest/test_zkp_interop.sh — Cross-language ZKP interop: Python↔C↔Go sign/verify
# ZKP-RNL: Python sign → C verify; C sign → Go verify; Go sign → Python verify
# ZKP-NL:  Python sign → Python verify (proof format is large; cross-lang verify same)
set -euo pipefail

CLI_PY="python3 $(dirname "$0")/../HerraduraCli/herradura.py"
CLI_C="$(dirname "$0")/../HerraduraCli/herradura_cli"
CLI_GO="$(dirname "$0")/../HerraduraCli/herradura_cli_go"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
PASS=0; FAIL=0

check_verify() {
    local label="$1"; shift
    local output rc
    output=$("$@" 2>&1) && rc=0 || rc=$?
    if [ "$rc" -eq 0 ] && echo "$output" | grep -q "Signature OK"; then
        echo "PASS $label"
        PASS=$((PASS+1))
    else
        echo "FAIL $label: expected 'Signature OK' (rc=$rc); got: $output"
        FAIL=$((FAIL+1))
    fi
}

check_reject() {
    local label="$1"; shift
    local output rc
    output=$("$@" 2>&1) && rc=0 || rc=$?
    if [ "$rc" -ne 0 ] && echo "$output" | grep -q "Verification FAILED"; then
        echo "PASS $label"
        PASS=$((PASS+1))
    else
        echo "FAIL $label: expected rejection (rc=$rc); got: $output"
        FAIL=$((FAIL+1))
    fi
}

printf 'ABCDEFGHIJKLMNOPQRSTUVWXYZ012345' > "$TMP/msg.bin"
printf 'ABCDEFGHIJKLMNOPQRSTUVWXYZ012346' > "$TMP/msg2.bin"

# ---------------------------------------------------------------------------
# ZKP-RNL interop — rnl-sigma: same hkex-rnl PEM format across all three CLIs
# ---------------------------------------------------------------------------

# Python keygen (shared across all cross-lang tests)
$CLI_PY genpkey --algo hkex-rnl --out "$TMP/py_rnl.pem"
$CLI_PY pkey    --in "$TMP/py_rnl.pem" --pubout --out "$TMP/py_rnl_pub.pem"

# Python sign → C verify
$CLI_PY sign  --algo rnl-sigma --key "$TMP/py_rnl.pem" \
              --in "$TMP/msg.bin" --out "$TMP/py_sig.pem"
check_verify "Python rnl-sigma sign → C verify" \
    "$CLI_C" verify --algo rnl-sigma --pubkey "$TMP/py_rnl_pub.pem" \
    --in "$TMP/msg.bin" --sig "$TMP/py_sig.pem"
check_reject "Python rnl-sigma sign → C verify (wrong msg)" \
    "$CLI_C" verify --algo rnl-sigma --pubkey "$TMP/py_rnl_pub.pem" \
    --in "$TMP/msg2.bin" --sig "$TMP/py_sig.pem"

# Python sign → Go verify
check_verify "Python rnl-sigma sign → Go verify" \
    "$CLI_GO" verify --algo rnl-sigma --pubkey "$TMP/py_rnl_pub.pem" \
    --in "$TMP/msg.bin" --sig "$TMP/py_sig.pem"

# C keygen + sign → Python verify
"$CLI_C" genpkey --algo hkex-rnl --out "$TMP/c_rnl.pem"
"$CLI_C" pkey    --in "$TMP/c_rnl.pem" --pubout --out "$TMP/c_rnl_pub.pem"
"$CLI_C" sign    --algo rnl-sigma --key "$TMP/c_rnl.pem" \
                 --in "$TMP/msg.bin" --out "$TMP/c_sig.pem"
check_verify "C rnl-sigma sign → Python verify" \
    $CLI_PY verify --algo rnl-sigma --pubkey "$TMP/c_rnl_pub.pem" \
    --in "$TMP/msg.bin" --sig "$TMP/c_sig.pem"

# C sign → Go verify
check_verify "C rnl-sigma sign → Go verify" \
    "$CLI_GO" verify --algo rnl-sigma --pubkey "$TMP/c_rnl_pub.pem" \
    --in "$TMP/msg.bin" --sig "$TMP/c_sig.pem"

# Go keygen + sign → Python verify
"$CLI_GO" genpkey --algo hkex-rnl --out "$TMP/go_rnl.pem"
"$CLI_GO" pkey    --in "$TMP/go_rnl.pem" --pubout --out "$TMP/go_rnl_pub.pem"
"$CLI_GO" sign    --algo rnl-sigma --key "$TMP/go_rnl.pem" \
                  --in "$TMP/msg.bin" --out "$TMP/go_sig.pem"
check_verify "Go rnl-sigma sign → Python verify" \
    $CLI_PY verify --algo rnl-sigma --pubkey "$TMP/go_rnl_pub.pem" \
    --in "$TMP/msg.bin" --sig "$TMP/go_sig.pem"

# Go sign → C verify
check_verify "Go rnl-sigma sign → C verify" \
    "$CLI_C" verify --algo rnl-sigma --pubkey "$TMP/go_rnl_pub.pem" \
    --in "$TMP/msg.bin" --sig "$TMP/go_sig.pem"

# ---------------------------------------------------------------------------
# ZKP-NL interop — nl-zkboo: Python sign → C verify; C sign → Go verify
# Use rounds=4 for speed; proof PEM format is shared
# ---------------------------------------------------------------------------

# Python ZKP-NL keygen
$CLI_PY genpkey --algo hpks-zkp-nl --out "$TMP/py_zkpnl.pem"
$CLI_PY pkey    --in "$TMP/py_zkpnl.pem" --pubout --out "$TMP/py_zkpnl_pub.pem"

# Python sign → C verify
$CLI_PY sign  --algo nl-zkboo --key "$TMP/py_zkpnl.pem" \
              --rounds 4 --in "$TMP/msg.bin" --out "$TMP/py_zkpnl_proof.pem"
check_verify "Python nl-zkboo sign → C verify" \
    "$CLI_C" verify --algo nl-zkboo --pubkey "$TMP/py_zkpnl_pub.pem" \
    --in "$TMP/msg.bin" --sig "$TMP/py_zkpnl_proof.pem"
check_reject "Python nl-zkboo sign → C verify (wrong msg)" \
    "$CLI_C" verify --algo nl-zkboo --pubkey "$TMP/py_zkpnl_pub.pem" \
    --in "$TMP/msg2.bin" --sig "$TMP/py_zkpnl_proof.pem"

# Python sign → Go verify
check_verify "Python nl-zkboo sign → Go verify" \
    "$CLI_GO" verify --algo nl-zkboo --pubkey "$TMP/py_zkpnl_pub.pem" \
    --in "$TMP/msg.bin" --sig "$TMP/py_zkpnl_proof.pem"

# C ZKP-NL keygen + sign → Python verify
"$CLI_C" genpkey --algo hpks-zkp-nl --out "$TMP/c_zkpnl.pem"
"$CLI_C" pkey    --in "$TMP/c_zkpnl.pem" --pubout --out "$TMP/c_zkpnl_pub.pem"
"$CLI_C" sign    --algo nl-zkboo --key "$TMP/c_zkpnl.pem" \
                 --in "$TMP/msg.bin" --out "$TMP/c_zkpnl_proof.pem"
check_verify "C nl-zkboo sign → Python verify" \
    $CLI_PY verify --algo nl-zkboo --pubkey "$TMP/c_zkpnl_pub.pem" \
    --in "$TMP/msg.bin" --sig "$TMP/c_zkpnl_proof.pem"

# C sign → Go verify
check_verify "C nl-zkboo sign → Go verify" \
    "$CLI_GO" verify --algo nl-zkboo --pubkey "$TMP/c_zkpnl_pub.pem" \
    --in "$TMP/msg.bin" --sig "$TMP/c_zkpnl_proof.pem"

# Go ZKP-NL keygen + sign → Python verify
"$CLI_GO" genpkey --algo hpks-zkp-nl --out "$TMP/go_zkpnl.pem"
"$CLI_GO" pkey    --in "$TMP/go_zkpnl.pem" --pubout --out "$TMP/go_zkpnl_pub.pem"
"$CLI_GO" sign    --algo nl-zkboo --key "$TMP/go_zkpnl.pem" \
                  --in "$TMP/msg.bin" --out "$TMP/go_zkpnl_proof.pem"
check_verify "Go nl-zkboo sign → Python verify" \
    $CLI_PY verify --algo nl-zkboo --pubkey "$TMP/go_zkpnl_pub.pem" \
    --in "$TMP/msg.bin" --sig "$TMP/go_zkpnl_proof.pem"

# Go sign → C verify
check_verify "Go nl-zkboo sign → C verify" \
    "$CLI_C" verify --algo nl-zkboo --pubkey "$TMP/go_zkpnl_pub.pem" \
    --in "$TMP/msg.bin" --sig "$TMP/go_zkpnl_proof.pem"

echo ""
echo "Results: $PASS PASS / $FAIL FAIL"
[ "$FAIL" -eq 0 ]
