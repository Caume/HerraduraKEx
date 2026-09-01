#!/usr/bin/env bash
# CliTest/test_threshold_interop.sh — cross-language HPKS-T interop tests
# Tests that Python, C, Go, and Java CLIs produce interoperable threshold
# signatures. Requires: HerraduraCli/herradura_cli (C) and
# HerraduraCli/herradura_cli_go (Go); Java is optional (TODO #260) and
# degrades to a NOTE — skipping only Java's rows — if no JDK is installed.
set -euo pipefail

SCRIPT_DIR="$(dirname "$0")"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
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

HAVE_JAVA=1
if command -v javac >/dev/null 2>&1; then
  bash "$ROOT/bindings/java/build.sh" >/dev/null 2>&1
  JAVA="java -cp $ROOT/bindings/java herradurakex.HerraduraCli"
else
  HAVE_JAVA=0
  echo "NOTE: javac not found — skipping Java's threshold-* rows"
fi

TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT
MSG="$TMPDIR/msg.txt"
echo "cross-language threshold signing" > "$MSG"

pass() { echo "[PASS] $1"; }
fail() { echo "[FAIL] $1: $2"; exit 1; }

# ── Helper: run 4-phase threshold sign with given CLIs, C/Go's repeated-flag
# shape (--commit / --partial once per value) ───────────────────────────────
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

# ── nargs-style variant (--commits / --partials, space-separated multiple
# values in one flag) — Python's and Java's shape, unlike C/Go's repeated
# flag above. Java's --ring uses a THIRD, comma-separated convention
# elsewhere in the CLI surface; threshold-* is not that one. ────────────────
nargs_threshold_sign() {
  local cli="$1" msg="$2" ka="$3" kb="$4"
  $cli threshold-commit --key "$ka" --commit-out "$TMPDIR/ca.pem" --nonce-out "$TMPDIR/na.pem"
  $cli threshold-commit --key "$kb" --commit-out "$TMPDIR/cb.pem" --nonce-out "$TMPDIR/nb.pem"
  $cli threshold-aggregate --commits "$TMPDIR/ca.pem" "$TMPDIR/cb.pem" \
    --in "$msg" --out "$TMPDIR/agg.pem"
  $cli threshold-respond --key "$ka" \
    --commits "$TMPDIR/ca.pem" "$TMPDIR/cb.pem" \
    --aggregate "$TMPDIR/agg.pem" --nonce "$TMPDIR/na.pem" --out "$TMPDIR/pa.pem"
  $cli threshold-respond --key "$kb" \
    --commits "$TMPDIR/ca.pem" "$TMPDIR/cb.pem" \
    --aggregate "$TMPDIR/agg.pem" --nonce "$TMPDIR/nb.pem" --out "$TMPDIR/pb.pem"
  $cli threshold-combine --aggregate "$TMPDIR/agg.pem" \
    --partials "$TMPDIR/pa.pem" "$TMPDIR/pb.pem" --out "$TMPDIR/result_sig.pem"
}

verify_all() {
  local label="$1"
  $PY verify --algo hpks-t --in "$MSG" --sig "$TMPDIR/result_sig.pem" | grep -q "Signature OK" \
    || fail "$label" "Python verify failed"
  $C  verify --algo hpks-t --in "$MSG" --sig "$TMPDIR/result_sig.pem" | grep -q "Signature OK" \
    || fail "$label" "C verify failed"
  $GO verify --algo hpks-t --in "$MSG" --sig "$TMPDIR/result_sig.pem" | grep -q "Signature OK" \
    || fail "$label" "Go verify failed"
  if [ "$HAVE_JAVA" -eq 1 ]; then
    $JAVA verify --algo hpks-t --in "$MSG" --sig "$TMPDIR/result_sig.pem" | grep -q "Signature OK" \
      || fail "$label" "Java verify failed"
  fi
  pass "$label → Python/C/Go$([ "$HAVE_JAVA" -eq 1 ] && echo "/Java") verify"
}

echo "=== HPKS-T cross-language interop tests ==="

# Generate shared keys with Python
$PY genpkey --algo hpks-nl --out "$TMPDIR/alice.pem"
$PY genpkey --algo hpks-nl --out "$TMPDIR/bob.pem"

# 1. Pure Python
nargs_threshold_sign "$PY" "$MSG" "$TMPDIR/alice.pem" "$TMPDIR/bob.pem"
verify_all "Python sign"

# 2. C sign, verify with all
threshold_sign "$C" "$C" "$C" "$C" "$MSG" "$TMPDIR/alice.pem" "$TMPDIR/bob.pem"
verify_all "C sign"

# 3. Go sign, verify with all
threshold_sign "$GO" "$GO" "$GO" "$GO" "$MSG" "$TMPDIR/alice.pem" "$TMPDIR/bob.pem"
verify_all "Go sign"

# 4. Java sign, verify with all (nargs-style, like Python — TODO #260)
if [ "$HAVE_JAVA" -eq 1 ]; then
  nargs_threshold_sign "$JAVA" "$MSG" "$TMPDIR/alice.pem" "$TMPDIR/bob.pem"
  verify_all "Java sign"
fi

# 5. Mixed: Python commits, C aggregates, Go responds, Java combines (or C
# if Java is unavailable) — a genuine cross-CLI protocol run, not just
# cross-CLI verification of a single-CLI-produced signature.
$PY threshold-commit --key "$TMPDIR/alice.pem" --commit-out "$TMPDIR/ca.pem" --nonce-out "$TMPDIR/na.pem"
$PY threshold-commit --key "$TMPDIR/bob.pem"   --commit-out "$TMPDIR/cb.pem" --nonce-out "$TMPDIR/nb.pem"
$C  threshold-aggregate --commit "$TMPDIR/ca.pem" --commit "$TMPDIR/cb.pem" --in "$MSG" --out "$TMPDIR/agg.pem"
$GO threshold-respond --key "$TMPDIR/alice.pem" \
    --commit "$TMPDIR/ca.pem" --commit "$TMPDIR/cb.pem" \
    --aggregate "$TMPDIR/agg.pem" --nonce "$TMPDIR/na.pem" --out "$TMPDIR/pa.pem"
$GO threshold-respond --key "$TMPDIR/bob.pem" \
    --commit "$TMPDIR/ca.pem" --commit "$TMPDIR/cb.pem" \
    --aggregate "$TMPDIR/agg.pem" --nonce "$TMPDIR/nb.pem" --out "$TMPDIR/pb.pem"
if [ "$HAVE_JAVA" -eq 1 ]; then
  $JAVA threshold-combine --aggregate "$TMPDIR/agg.pem" \
      --partials "$TMPDIR/pa.pem" "$TMPDIR/pb.pem" --out "$TMPDIR/result_sig.pem"
  verify_all "Mixed (Python commit, C aggregate, Go respond, Java combine)"
else
  $C  threshold-combine --aggregate "$TMPDIR/agg.pem" \
      --partial "$TMPDIR/pa.pem" --partial "$TMPDIR/pb.pem" --out "$TMPDIR/result_sig.pem"
  verify_all "Mixed (Python commit, C aggregate, Go respond, C combine)"
fi

echo "=== All HPKS-T interop tests PASSED ==="
