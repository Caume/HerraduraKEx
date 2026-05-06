#!/usr/bin/env bash
# CliTest/test_c_sign.sh — C CLI: sign/verify pass and reject cases (hpks, hpks-nl, hpks-stern)
set -euo pipefail

CLI="$(dirname "$0")/../HerraduraCli/herradura_cli"
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

printf 'ABCDEFGHIJKLMNOPQRSTUVWXYZ012345' > "$TMP/msg32.bin"
printf 'ABCDEFGHIJKLMNOPQRSTUVWXYZ012346' > "$TMP/msg32b.bin"

# ── HPKS and HPKS-NL (Schnorr over GF(2^256)*) ──────────────────────────────
for algo in hpks hpks-nl; do
    "$CLI" genpkey --algo "$algo" --out "$TMP/${algo}.pem"
    "$CLI" pkey    --in "$TMP/${algo}.pem" --pubout --out "$TMP/${algo}_pub.pem"
    "$CLI" sign    --algo "$algo" --key "$TMP/${algo}.pem" \
                   --in "$TMP/msg32.bin" --out "$TMP/${algo}_sig.pem"

    check_verify "verify $algo correct msg" \
        "$CLI" verify --algo "$algo" --pubkey "$TMP/${algo}_pub.pem" \
        --in "$TMP/msg32.bin" --sig "$TMP/${algo}_sig.pem"

    check_reject "verify $algo wrong msg" \
        "$CLI" verify --algo "$algo" --pubkey "$TMP/${algo}_pub.pem" \
        --in "$TMP/msg32b.bin" --sig "$TMP/${algo}_sig.pem"
done

# Cross-key rejection
"$CLI" genpkey --algo hpks --out "$TMP/hpks_other.pem"
"$CLI" pkey    --in "$TMP/hpks_other.pem" --pubout --out "$TMP/hpks_other_pub.pem"
check_reject "verify hpks wrong key" \
    "$CLI" verify --algo hpks --pubkey "$TMP/hpks_other_pub.pem" \
    --in "$TMP/msg32.bin" --sig "$TMP/hpks_sig.pem"

# ── HPKS-Stern-F (N=256, rounds=32) ─────────────────────────────────────────
"$CLI" genpkey --algo hpks-stern --out "$TMP/hpks_stern.pem"
"$CLI" pkey    --in "$TMP/hpks_stern.pem" --pubout --out "$TMP/hpks_stern_pub.pem"
"$CLI" sign    --algo hpks-stern --key "$TMP/hpks_stern.pem" \
               --in "$TMP/msg32.bin" --out "$TMP/hpks_stern_sig.pem"

check_verify "verify hpks-stern correct msg N=256" \
    "$CLI" verify --algo hpks-stern --pubkey "$TMP/hpks_stern_pub.pem" \
    --in "$TMP/msg32.bin" --sig "$TMP/hpks_stern_sig.pem"

check_reject "verify hpks-stern wrong msg N=256" \
    "$CLI" verify --algo hpks-stern --pubkey "$TMP/hpks_stern_pub.pem" \
    --in "$TMP/msg32b.bin" --sig "$TMP/hpks_stern_sig.pem"

echo ""
echo "Results: $PASS PASS / $FAIL FAIL"
[ "$FAIL" -eq 0 ]
