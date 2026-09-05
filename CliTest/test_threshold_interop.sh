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

# ── TODO #270: flag-SPELLING portability ───────────────────────────────────
# The list flags had two spellings for the same capability: `--commits a b` in
# Python and Java, `--commit a --commit b` in C and Go, and `--partials` /
# `--partial` likewise.  All four implemented threshold signing and emitted
# identical PEMs, so every parity check before TODO #267's flag matrix passed --
# a documented command line simply did not port between CLIs.  This file is the
# evidence: the helpers above still carry one branch per shape because that is
# what it cost every caller.
#
# Since v6.4.0 all four accept BOTH names with BOTH syntaxes.  The assertions
# below drive each CLI with the spelling it historically did NOT accept, which is
# the only way to catch a regression that removes one of the two.
echo "--- TODO #270: both flag spellings, all CLIs ---"
CLIS=("$PY" "$C" "$GO")
CLINAMES=(python c go)
if [ "$HAVE_JAVA" -eq 1 ]; then CLIS+=("$JAVA"); CLINAMES+=(java); fi

$PY threshold-commit --key "$TMPDIR/alice.pem" --commit-out "$TMPDIR/sa.pem" --nonce-out "$TMPDIR/sna.pem"
$PY threshold-commit --key "$TMPDIR/bob.pem"   --commit-out "$TMPDIR/sb.pem" --nonce-out "$TMPDIR/snb.pem"

for i in "${!CLIS[@]}"; do
  cli="${CLIS[$i]}"; name="${CLINAMES[$i]}"
  # Every syntax must yield the SAME aggregate from that CLI: plural-multi,
  # singular-repeated, plural-repeated, and singular-multi.
  $cli threshold-aggregate --commits "$TMPDIR/sa.pem" "$TMPDIR/sb.pem" \
      --in "$MSG" --out "$TMPDIR/sp1.pem" 2>/dev/null \
      || fail "spelling ($name)" "--commits a b rejected"
  $cli threshold-aggregate --commit "$TMPDIR/sa.pem" --commit "$TMPDIR/sb.pem" \
      --in "$MSG" --out "$TMPDIR/sp2.pem" 2>/dev/null \
      || fail "spelling ($name)" "--commit a --commit b rejected"
  $cli threshold-aggregate --commits "$TMPDIR/sa.pem" --commits "$TMPDIR/sb.pem" \
      --in "$MSG" --out "$TMPDIR/sp3.pem" 2>/dev/null \
      || fail "spelling ($name)" "--commits a --commits b rejected"
  $cli threshold-aggregate --commit "$TMPDIR/sa.pem" "$TMPDIR/sb.pem" \
      --in "$MSG" --out "$TMPDIR/sp4.pem" 2>/dev/null \
      || fail "spelling ($name)" "--commit a b rejected"
  cmp -s "$TMPDIR/sp1.pem" "$TMPDIR/sp2.pem" \
      || fail "spelling ($name)" "plural and singular gave DIFFERENT aggregates"
  cmp -s "$TMPDIR/sp1.pem" "$TMPDIR/sp3.pem" \
      || fail "spelling ($name)" "repeated-plural gave a different aggregate"
  cmp -s "$TMPDIR/sp1.pem" "$TMPDIR/sp4.pem" \
      || fail "spelling ($name)" "multi-value singular gave a different aggregate"
  pass "spelling: all four --commits/--commit syntaxes agree ($name)"

  # Mixing the two NAMES is refused, not silently concatenated: the list order is
  # consensus-critical, so picking one would be a wrong signature, not an error.
  if $cli threshold-aggregate --commits "$TMPDIR/sa.pem" --commit "$TMPDIR/sb.pem" \
       --in "$MSG" --out "$TMPDIR/sx.pem" >/dev/null 2>&1; then
    fail "spelling ($name)" "mixing --commits and --commit was ACCEPTED"
  fi
  pass "spelling: mixing --commits with --commit is refused ($name)"

  # One diagnostic, four CLIs.  These messages diverged until v6.4.0 ("at least
  # one --commit required" in C and Go), which is the same wrong-but-plausible
  # class TODO #269 found in Go's `rand --bytes -1`.
  # `|| true`: the CLI exits 1 here by design, and `set -o pipefail` would make
  # the substitution itself fail under `set -e` before the message is examined.
  msg=$($cli threshold-aggregate --in "$MSG" --out "$TMPDIR/sx.pem" 2>&1 | tail -1 || true)
  case "$msg" in
    *"--commits (or --commit) is required"*) pass "spelling: missing-flag message ($name)" ;;
    *) fail "spelling ($name)" "missing-flag message differs: $msg" ;;
  esac
done

# ── TODO #272: C's 64-value cap must REFUSE, never truncate ────────────────
# C collects list-flag values into a fixed 64-entry array and used to stop
# filling it silently, returning success: a ceremony with more than 64 signers
# produced an aggregate over the FIRST 64 while Python, Go and Java used every
# one, so the same command line gave a DIFFERENT signature depending on which CLI
# aggregated it, with no diagnostic anywhere.  Found while verifying TODO #270.
# The limit itself is TODO #272; that it fails loudly is asserted here.
echo "--- TODO #272: C refuses more list values than it can hold ---"
many=""
i=0; while [ $i -lt 70 ]; do many="$many $TMPDIR/sa.pem"; i=$((i+1)); done
if $C threshold-aggregate --commits $many --in "$MSG" --out "$TMPDIR/over.pem" >/dev/null 2>&1; then
  fail "over-limit" "C accepted 70 --commits values; it holds 64 and must refuse, not truncate"
fi
pass "over-limit: C refuses 70 --commits values instead of silently using 64"

# The boundary itself must still work, or the guard above is just an off-by-one.
few=""
i=0; while [ $i -lt 64 ]; do few="$few $TMPDIR/sa.pem"; i=$((i+1)); done
$C threshold-aggregate --commits $few --in "$MSG" --out "$TMPDIR/at64.pem" >/dev/null 2>&1 \
  || fail "over-limit" "C rejected exactly 64 --commits values, which is within its capacity"
pass "over-limit: C still accepts exactly 64"

echo "=== All HPKS-T interop tests PASSED ==="
