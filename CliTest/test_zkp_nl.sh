#!/usr/bin/env bash
# CliTest/test_zkp_nl.sh — Python CLI: ZKP-NL (NL-FSCX ZKBoo) sign/verify round-trip
set -euo pipefail

CLI="python3 $(dirname "$0")/../HerraduraCli/herradura.py"
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

# ── ZKP-NL (hpks-zkp-nl, rounds=4 for speed) ─────────────────────────────────
$CLI genpkey --algo hpks-zkp-nl --out "$TMP/zkpnl.pem"
$CLI pkey    --in "$TMP/zkpnl.pem" --pubout --out "$TMP/zkpnl_pub.pem"
$CLI sign    --algo nl-zkboo --key "$TMP/zkpnl.pem" \
             --rounds 4 --in "$TMP/msg.bin" --out "$TMP/zkpnl_proof.pem"

check_verify "nl-zkboo verify correct msg" \
    $CLI verify --algo nl-zkboo --pubkey "$TMP/zkpnl_pub.pem" \
    --in "$TMP/msg.bin" --sig "$TMP/zkpnl_proof.pem"

check_reject "nl-zkboo verify wrong msg" \
    $CLI verify --algo nl-zkboo --pubkey "$TMP/zkpnl_pub.pem" \
    --in "$TMP/msg2.bin" --sig "$TMP/zkpnl_proof.pem"

# Wrong pubkey rejection
$CLI genpkey --algo hpks-zkp-nl --out "$TMP/zkpnl_other.pem"
$CLI pkey    --in "$TMP/zkpnl_other.pem" --pubout --out "$TMP/zkpnl_other_pub.pem"
check_reject "nl-zkboo verify wrong pubkey" \
    $CLI verify --algo nl-zkboo --pubkey "$TMP/zkpnl_other_pub.pem" \
    --in "$TMP/msg.bin" --sig "$TMP/zkpnl_proof.pem"

echo ""
echo "Results: $PASS PASS / $FAIL FAIL"
[ "$FAIL" -eq 0 ]
