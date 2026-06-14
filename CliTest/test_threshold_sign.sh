#!/usr/bin/env bash
# CliTest/test_threshold_sign.sh — HPKS-T threshold signing tests (Python CLI)
# Tests 3-of-3 threshold Schnorr sign+verify via Python CLI.
set -euo pipefail

HERRADURA="python3 $(dirname "$0")/../HerraduraCli/herradura.py"
TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

echo "=== HPKS-T threshold signing test (Python CLI) ==="

echo "Hello threshold world" > "$TMPDIR/msg.txt"

# Generate 3 keys
$HERRADURA genpkey --algo hpks-nl --out "$TMPDIR/alice.pem"
$HERRADURA genpkey --algo hpks-nl --out "$TMPDIR/bob.pem"
$HERRADURA genpkey --algo hpks-nl --out "$TMPDIR/carol.pem"

# Phase 1: commit
$HERRADURA threshold-commit \
  --key "$TMPDIR/alice.pem" \
  --commit-out "$TMPDIR/alice_commit.pem" \
  --nonce-out  "$TMPDIR/alice_nonce.pem"

$HERRADURA threshold-commit \
  --key "$TMPDIR/bob.pem" \
  --commit-out "$TMPDIR/bob_commit.pem" \
  --nonce-out  "$TMPDIR/bob_nonce.pem"

$HERRADURA threshold-commit \
  --key "$TMPDIR/carol.pem" \
  --commit-out "$TMPDIR/carol_commit.pem" \
  --nonce-out  "$TMPDIR/carol_nonce.pem"

# Phase 2: aggregate (coordinator)
$HERRADURA threshold-aggregate \
  --commits "$TMPDIR/alice_commit.pem" "$TMPDIR/bob_commit.pem" "$TMPDIR/carol_commit.pem" \
  --in "$TMPDIR/msg.txt" \
  --out "$TMPDIR/aggregate.pem"

# Phase 3: respond (each signer)
$HERRADURA threshold-respond \
  --key "$TMPDIR/alice.pem" \
  --commits "$TMPDIR/alice_commit.pem" "$TMPDIR/bob_commit.pem" "$TMPDIR/carol_commit.pem" \
  --aggregate "$TMPDIR/aggregate.pem" \
  --nonce "$TMPDIR/alice_nonce.pem" \
  --out "$TMPDIR/alice_partial.pem"

$HERRADURA threshold-respond \
  --key "$TMPDIR/bob.pem" \
  --commits "$TMPDIR/alice_commit.pem" "$TMPDIR/bob_commit.pem" "$TMPDIR/carol_commit.pem" \
  --aggregate "$TMPDIR/aggregate.pem" \
  --nonce "$TMPDIR/bob_nonce.pem" \
  --out "$TMPDIR/bob_partial.pem"

$HERRADURA threshold-respond \
  --key "$TMPDIR/carol.pem" \
  --commits "$TMPDIR/alice_commit.pem" "$TMPDIR/bob_commit.pem" "$TMPDIR/carol_commit.pem" \
  --aggregate "$TMPDIR/aggregate.pem" \
  --nonce "$TMPDIR/carol_nonce.pem" \
  --out "$TMPDIR/carol_partial.pem"

# Phase 4: combine (coordinator)
$HERRADURA threshold-combine \
  --aggregate "$TMPDIR/aggregate.pem" \
  --partials "$TMPDIR/alice_partial.pem" "$TMPDIR/bob_partial.pem" "$TMPDIR/carol_partial.pem" \
  --out "$TMPDIR/final_sig.pem"

# Verify
result=$($HERRADURA verify --algo hpks-t --in "$TMPDIR/msg.txt" --sig "$TMPDIR/final_sig.pem")
if [ "$result" = "Signature OK" ]; then
  echo "[PASS] 3-of-3 threshold sign + verify"
else
  echo "[FAIL] verification returned: $result"
  exit 1
fi

# Tamper test: wrong message should fail
echo "tampered" > "$TMPDIR/tampered.txt"
result=$($HERRADURA verify --algo hpks-t --in "$TMPDIR/tampered.txt" --sig "$TMPDIR/final_sig.pem" 2>&1 || true)
if echo "$result" | grep -q "FAILED"; then
  echo "[PASS] tampered message correctly rejected"
else
  echo "[FAIL] tampered message was not rejected: $result"
  exit 1
fi

echo "=== All Python threshold tests PASSED ==="
