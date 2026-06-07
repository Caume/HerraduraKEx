#!/usr/bin/env bash
# CliTest/test_zkp_rnl.sh — Python CLI: ZKP-RNL (Ring-LWR Sigma-protocol) sign/verify round-trip
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

# ── ZKP-RNL (n=256, default) ─────────────────────────────────────────────────
$CLI genpkey --algo hkex-rnl --out "$TMP/rnl.pem"
$CLI pkey    --in "$TMP/rnl.pem" --pubout --out "$TMP/rnl_pub.pem"
$CLI sign    --algo rnl-sigma --key "$TMP/rnl.pem" \
             --in "$TMP/msg.bin" --out "$TMP/rnl_sig.pem"

check_verify "rnl-sigma verify correct msg" \
    $CLI verify --algo rnl-sigma --pubkey "$TMP/rnl_pub.pem" \
    --in "$TMP/msg.bin" --sig "$TMP/rnl_sig.pem"

check_reject "rnl-sigma verify wrong msg" \
    $CLI verify --algo rnl-sigma --pubkey "$TMP/rnl_pub.pem" \
    --in "$TMP/msg2.bin" --sig "$TMP/rnl_sig.pem"

# Wrong pubkey rejection: signature from one key must not verify under another
$CLI genpkey --algo hkex-rnl --out "$TMP/rnl_other.pem"
$CLI pkey    --in "$TMP/rnl_other.pem" --pubout --out "$TMP/rnl_other_pub.pem"
check_reject "rnl-sigma verify wrong pubkey" \
    $CLI verify --algo rnl-sigma --pubkey "$TMP/rnl_other_pub.pem" \
    --in "$TMP/msg.bin" --sig "$TMP/rnl_sig.pem"

echo ""
echo "Results: $PASS PASS / $FAIL FAIL"
[ "$FAIL" -eq 0 ]
