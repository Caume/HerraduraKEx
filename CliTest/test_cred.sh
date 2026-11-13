#!/usr/bin/env bash
# CliTest/test_cred.sh — Python CLI HCRED cred-issue / cred-prove / cred-verify tests
set -euo pipefail

CLI="python3 $(dirname "$0")/../HerraduraCli/herradura.py"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
PASS=0; FAIL=0

check() {
    local label="$1"; shift
    local output rc
    output=$("$@" 2>&1) && rc=0 || rc=$?
    if [ "$rc" -eq 0 ]; then
        echo "PASS $label"
        PASS=$((PASS+1))
    else
        echo "FAIL $label (rc=$rc): $output"
        FAIL=$((FAIL+1))
    fi
}

check_fail() {
    local label="$1"; shift
    local output rc
    output=$("$@" 2>&1) && rc=0 || rc=$?
    if [ "$rc" -ne 0 ]; then
        echo "PASS $label (rejected as expected)"
        PASS=$((PASS+1))
    else
        echo "FAIL $label: expected rejection but got rc=0; output: $output"
        FAIL=$((FAIL+1))
    fi
}

# ── Key generation ─────────────────────────────────────────────────────────
$CLI genpkey --algo hcred      --out "$TMP/user_priv.pem"  2>/dev/null
$CLI pkey    --pubout --in "$TMP/user_priv.pem" --out "$TMP/user_pub.pem"
$CLI genpkey --algo hpks-stern --out "$TMP/issuer_priv.pem" 2>/dev/null
$CLI pkey    --pubout --in "$TMP/issuer_priv.pem" --out "$TMP/issuer_pub.pem"

# ── cred-prove / cred-verify (proof only) ──────────────────────────────────
$CLI cred-prove   --in "$TMP/user_priv.pem" --msg "hello" --rounds 16 \
                  --out "$TMP/proof.pem"  2>/dev/null

check "proof verify (pubkey)"  $CLI cred-verify --min-rounds 16 --proof "$TMP/proof.pem" \
    --pubkey "$TMP/user_pub.pem" --msg "hello"
check "proof verify (privkey)" $CLI cred-verify --min-rounds 16 --proof "$TMP/proof.pem" \
    --pubkey "$TMP/user_priv.pem" --msg "hello"

check_fail "wrong-msg reject" $CLI cred-verify --min-rounds 16 --proof "$TMP/proof.pem" \
    --pubkey "$TMP/user_pub.pem" --msg "wrong"

# ── cred-issue / cred-verify (credential) ──────────────────────────────────
$CLI cred-issue  --our "$TMP/issuer_priv.pem" --in "$TMP/user_pub.pem" \
                 --rounds 16 --out "$TMP/cred.pem" 2>/dev/null

check "cred+proof verify" $CLI cred-verify --min-rounds 16 --proof "$TMP/proof.pem" \
    --pubkey "$TMP/user_pub.pem" --msg "hello" \
    --cred "$TMP/cred.pem" --issuer "$TMP/issuer_pub.pem"

# Wrong issuer → should reject
$CLI genpkey --algo hpks-stern --out "$TMP/other_issuer.pem" 2>/dev/null
$CLI pkey    --pubout --in "$TMP/other_issuer.pem" --out "$TMP/other_issuer_pub.pem"
check_fail "wrong-issuer reject" $CLI cred-verify --min-rounds 16 --proof "$TMP/proof.pem" \
    --pubkey "$TMP/user_pub.pem" --msg "hello" \
    --cred "$TMP/cred.pem" --issuer "$TMP/other_issuer_pub.pem"

# ── The verifier's round floor (TODO #364) ─────────────────────────────────
# The accept-controls are the --min-rounds 16 cases above.  Each refusal is
# matched on the floor's message, so a refusal for another reason cannot pass.
check_floor() {
    local label="$1"; shift
    local output rc
    output=$("$@" 2>&1) && rc=0 || rc=$?
    if [ "$rc" -ne 0 ] && echo "$output" | grep -q "below the --min-rounds floor"; then
        echo "PASS $label"
        PASS=$((PASS+1))
    else
        echo "FAIL $label: expected the round-floor refusal (rc=$rc); got: $output"
        FAIL=$((FAIL+1))
    fi
}
check_floor "16-round proof refused at the default floor (219)" $CLI cred-verify \
    --proof "$TMP/proof.pem" --pubkey "$TMP/user_pub.pem" --msg "hello"
check_floor "16-round proof refused at --min-rounds 17" $CLI cred-verify \
    --min-rounds 17 --proof "$TMP/proof.pem" --pubkey "$TMP/user_pub.pem" --msg "hello"
$CLI cred-issue --our "$TMP/issuer_priv.pem" --in "$TMP/user_pub.pem" \
    --rounds 8 --out "$TMP/cred8.pem" 2>/dev/null
check "8-round credential accepted at --min-rounds 8 (control)" $CLI cred-verify \
    --min-rounds 8 --proof "$TMP/proof.pem" --pubkey "$TMP/user_pub.pem" --msg "hello" \
    --cred "$TMP/cred8.pem" --issuer "$TMP/issuer_pub.pem"
check_floor "8-round credential refused at --min-rounds 16" $CLI cred-verify \
    --min-rounds 16 --proof "$TMP/proof.pem" --pubkey "$TMP/user_pub.pem" --msg "hello" \
    --cred "$TMP/cred8.pem" --issuer "$TMP/issuer_pub.pem"

# ── Summary ────────────────────────────────────────────────────────────────
echo ""
echo "Results: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
