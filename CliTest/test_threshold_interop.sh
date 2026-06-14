#!/usr/bin/env bash
# CliTest/test_threshold_interop.sh — cross-language HPKS-T interop tests
# Tests that Python, C, and Go CLIs produce interoperable threshold signatures.
# Requires: HerraduraCli/herradura_cli (C) and HerraduraCli/herradura_cli_go (Go).
set -euo pipefail

SCRIPT_DIR="$(dirname "$0")"
PY="python3 $SCRIPT_DIR/../HerraduraCli/herradura.py"
C="$SCRIPT_DIR/../HerraduraCli/herradura_cli"
GO="$SCRIPT_DIR/../HerraduraCli/herradura_cli_go"

if [ ! -x "$C" ]; then
  echo "SKIP: C CLI not found at $C (run build_c.sh first)"
  exit 0
fi
if [ ! -x "$GO" ]; then
  echo "SKIP: Go CLI not found at $GO (run build_go.sh first)"
  exit 0
fi

TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT
MSG="$TMPDIR/msg.txt"
echo "cross-language threshold signing" > "$MSG"

pass() { echo "[PASS] $1"; }
fail() { echo "[FAIL] $1: $2"; exit 1; }
check_verify() {
  local result
  result=$("$@" 2>&1 || true)
  echo "$result" | grep -q "Signature OK" || fail "verify" "$result"
}

# ── Helper: run 4-phase threshold sign with given CLIs ─────────────────────
# Usage: threshold_sign <commit_cli> <agg_cli> <respond_cli> <combine_cli> <msg> <key_a> <key_b>
#        writes final sig to $TMPDIR/result_sig.pem
threshold_sign() {
  local cc="$1" ac="$2" rc="$3" bc="$4" msg="$5" ka="$6" kb="$7"
  # Phase 1
  $cc threshold-commit --key "$ka" --commit-out "$TMPDIR/ca.pem" --nonce-out "$TMPDIR/na.pem"
  $cc threshold-commit --key "$kb" --commit-out "$TMPDIR/cb.pem" --nonce-out "$TMPDIR/nb.pem"
  # Phase 2
  $ac threshold-aggregate --commit "$TMPDIR/ca.pem" --commit "$TMPDIR/cb.pem" \
    --in "$msg" --out "$TMPDIR/agg.pem"
  # Phase 3
  $rc threshold-respond --key "$ka" --commit "$TMPDIR/ca.pem" --commit "$TMPDIR/cb.pem" \
    --aggregate "$TMPDIR/agg.pem" --nonce "$TMPDIR/na.pem" --out "$TMPDIR/pa.pem"
  $rc threshold-respond --key "$kb" --commit "$TMPDIR/ca.pem" --commit "$TMPDIR/cb.pem" \
    --aggregate "$TMPDIR/agg.pem" --nonce "$TMPDIR/nb.pem" --out "$TMPDIR/pb.pem"
  # Phase 4
  $bc threshold-combine --aggregate "$TMPDIR/agg.pem" \
    --partial "$TMPDIR/pa.pem" --partial "$TMPDIR/pb.pem" --out "$TMPDIR/result_sig.pem"
}

# ── Python variant of threshold_sign (uses --commits / --partials nargs+) ──
py_threshold_sign() {
  local msg="$1" ka="$2" kb="$3"
  $PY threshold-commit --key "$ka" --commit-out "$TMPDIR/ca.pem" --nonce-out "$TMPDIR/na.pem"
  $PY threshold-commit --key "$kb" --commit-out "$TMPDIR/cb.pem" --nonce-out "$TMPDIR/nb.pem"
  $PY threshold-aggregate --commits "$TMPDIR/ca.pem" "$TMPDIR/cb.pem" \
    --in "$msg" --out "$TMPDIR/agg.pem"
  $PY threshold-respond --key "$ka" \
    --commits "$TMPDIR/ca.pem" "$TMPDIR/cb.pem" \
    --aggregate "$TMPDIR/agg.pem" --nonce "$TMPDIR/na.pem" --out "$TMPDIR/pa.pem"
  $PY threshold-respond --key "$kb" \
    --commits "$TMPDIR/ca.pem" "$TMPDIR/cb.pem" \
    --aggregate "$TMPDIR/agg.pem" --nonce "$TMPDIR/nb.pem" --out "$TMPDIR/pb.pem"
  $PY threshold-combine --aggregate "$TMPDIR/agg.pem" \
    --partials "$TMPDIR/pa.pem" "$TMPDIR/pb.pem" --out "$TMPDIR/result_sig.pem"
}

echo "=== HPKS-T cross-language interop tests ==="

# Generate shared keys with Python
$PY genpkey --algo hpks-nl --out "$TMPDIR/alice.pem"
$PY genpkey --algo hpks-nl --out "$TMPDIR/bob.pem"

# 1. Pure Python
py_threshold_sign "$MSG" "$TMPDIR/alice.pem" "$TMPDIR/bob.pem"
$PY verify --algo hpks-t --in "$MSG" --sig "$TMPDIR/result_sig.pem" | grep -q "Signature OK" || fail "pure Python" "verify failed"
$C  verify --algo hpks-t --in "$MSG" --sig "$TMPDIR/result_sig.pem" | grep -q "Signature OK" || fail "pure Python sig, C verify" "verify failed"
$GO verify --algo hpks-t --in "$MSG" --sig "$TMPDIR/result_sig.pem" | grep -q "Signature OK" || fail "pure Python sig, Go verify" "verify failed"
pass "Python sign → Python/C/Go verify"

# 2. C sign, verify with all
threshold_sign "$C" "$C" "$C" "$C" "$MSG" "$TMPDIR/alice.pem" "$TMPDIR/bob.pem"
$PY verify --algo hpks-t --in "$MSG" --sig "$TMPDIR/result_sig.pem" | grep -q "Signature OK" || fail "C sig, Python verify" "verify failed"
$C  verify --algo hpks-t --in "$MSG" --sig "$TMPDIR/result_sig.pem" | grep -q "Signature OK" || fail "C sign, C verify" "verify failed"
$GO verify --algo hpks-t --in "$MSG" --sig "$TMPDIR/result_sig.pem" | grep -q "Signature OK" || fail "C sig, Go verify" "verify failed"
pass "C sign → Python/C/Go verify"

# 3. Go sign, verify with all
threshold_sign "$GO" "$GO" "$GO" "$GO" "$MSG" "$TMPDIR/alice.pem" "$TMPDIR/bob.pem"
$PY verify --algo hpks-t --in "$MSG" --sig "$TMPDIR/result_sig.pem" | grep -q "Signature OK" || fail "Go sig, Python verify" "verify failed"
$C  verify --algo hpks-t --in "$MSG" --sig "$TMPDIR/result_sig.pem" | grep -q "Signature OK" || fail "Go sig, C verify" "verify failed"
$GO verify --algo hpks-t --in "$MSG" --sig "$TMPDIR/result_sig.pem" | grep -q "Signature OK" || fail "Go sign, Go verify" "verify failed"
pass "Go sign → Python/C/Go verify"

# 4. Mixed: Python commits, C aggregates, Go responds, C combines
$PY threshold-commit --key "$TMPDIR/alice.pem" --commit-out "$TMPDIR/ca.pem" --nonce-out "$TMPDIR/na.pem"
$PY threshold-commit --key "$TMPDIR/bob.pem"   --commit-out "$TMPDIR/cb.pem" --nonce-out "$TMPDIR/nb.pem"
$C  threshold-aggregate --commit "$TMPDIR/ca.pem" --commit "$TMPDIR/cb.pem" --in "$MSG" --out "$TMPDIR/agg.pem"
$GO threshold-respond --key "$TMPDIR/alice.pem" \
    --commit "$TMPDIR/ca.pem" --commit "$TMPDIR/cb.pem" \
    --aggregate "$TMPDIR/agg.pem" --nonce "$TMPDIR/na.pem" --out "$TMPDIR/pa.pem"
$GO threshold-respond --key "$TMPDIR/bob.pem" \
    --commit "$TMPDIR/ca.pem" --commit "$TMPDIR/cb.pem" \
    --aggregate "$TMPDIR/agg.pem" --nonce "$TMPDIR/nb.pem" --out "$TMPDIR/pb.pem"
$C  threshold-combine --aggregate "$TMPDIR/agg.pem" \
    --partial "$TMPDIR/pa.pem" --partial "$TMPDIR/pb.pem" --out "$TMPDIR/result_sig.pem"
$PY verify --algo hpks-t --in "$MSG" --sig "$TMPDIR/result_sig.pem" | grep -q "Signature OK" || fail "mixed interop" "Python verify failed"
$C  verify --algo hpks-t --in "$MSG" --sig "$TMPDIR/result_sig.pem" | grep -q "Signature OK" || fail "mixed interop" "C verify failed"
$GO verify --algo hpks-t --in "$MSG" --sig "$TMPDIR/result_sig.pem" | grep -q "Signature OK" || fail "mixed interop" "Go verify failed"
pass "Mixed (Python commit, C aggregate, Go respond, C combine) → all CLIs verify"

echo "=== All HPKS-T interop tests PASSED ==="
