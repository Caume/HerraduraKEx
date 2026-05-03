#!/usr/bin/env bash
# CliTest/test_sign.sh — sign/verify for HPKS, HPKS-NL, HPKS-Stern-F (pass and reject cases)
set -euo pipefail

CLI="python3 $(dirname "$0")/../HerraduraCli/herradura.py"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
PASS=0; FAIL=0

# Run a verify command; expect "Signature OK" and exit 0.
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

# Run a verify command; expect "Verification FAILED" and non-zero exit.
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

# Reference messages
printf 'ABCDEFGHIJKLMNOPQRSTUVWXYZ012345' > "$TMP/msg32.bin"   # 32 bytes (256-bit block)
printf 'ABCDEFGHIJKLMNOPQRSTUVWXYZ012346' > "$TMP/msg32b.bin"  # differs in last byte
printf 'Test' > "$TMP/msg4.bin"                                 # 4 bytes (32-bit block)
printf 'Fail' > "$TMP/msg4b.bin"                                # different 4 bytes

# ---------------------------------------------------------------------------
# HPKS and HPKS-NL (Schnorr over GF(2^256)*)
# ---------------------------------------------------------------------------

for algo in hpks hpks-nl; do
    $CLI genpkey --algo "$algo" --out "$TMP/${algo}.pem"
    $CLI pkey    --in "$TMP/${algo}.pem" --pubout --out "$TMP/${algo}_pub.pem"
    $CLI sign    --algo "$algo" --key "$TMP/${algo}.pem" \
                 --in "$TMP/msg32.bin" --out "$TMP/${algo}_sig.pem"

    check_verify "verify $algo correct msg" \
        $CLI verify --algo "$algo" --pubkey "$TMP/${algo}_pub.pem" \
        --in "$TMP/msg32.bin" --sig "$TMP/${algo}_sig.pem"

    check_reject "verify $algo wrong msg" \
        $CLI verify --algo "$algo" --pubkey "$TMP/${algo}_pub.pem" \
        --in "$TMP/msg32b.bin" --sig "$TMP/${algo}_sig.pem"
done

# Cross-key rejection: signature made with hpks key must not verify under a different hpks key
$CLI genpkey --algo hpks --out "$TMP/hpks_other.pem"
$CLI pkey    --in "$TMP/hpks_other.pem" --pubout --out "$TMP/hpks_other_pub.pem"
check_reject "verify hpks wrong key" \
    $CLI verify --algo hpks --pubkey "$TMP/hpks_other_pub.pem" \
    --in "$TMP/msg32.bin" --sig "$TMP/hpks_sig.pem"

# ---------------------------------------------------------------------------
# HPKS-Stern-F (Fiat-Shamir over code-based ZKP; n=32 for speed)
# ---------------------------------------------------------------------------

$CLI genpkey --algo hpks-stern --bits 32 --out "$TMP/hpks_stern.pem"
$CLI pkey    --in "$TMP/hpks_stern.pem" --pubout --out "$TMP/hpks_stern_pub.pem"
$CLI sign    --algo hpks-stern --key "$TMP/hpks_stern.pem" \
             --in "$TMP/msg4.bin" --out "$TMP/hpks_stern_sig.pem"

check_verify "verify hpks-stern correct msg n=32" \
    $CLI verify --algo hpks-stern --pubkey "$TMP/hpks_stern_pub.pem" \
    --in "$TMP/msg4.bin" --sig "$TMP/hpks_stern_sig.pem"

check_reject "verify hpks-stern wrong msg n=32" \
    $CLI verify --algo hpks-stern --pubkey "$TMP/hpks_stern_pub.pem" \
    --in "$TMP/msg4b.bin" --sig "$TMP/hpks_stern_sig.pem"

echo ""
echo "Results: $PASS PASS / $FAIL FAIL"
[ "$FAIL" -eq 0 ]
