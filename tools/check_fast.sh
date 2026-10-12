#!/usr/bin/env bash
# tools/check_fast.sh — run CI's cheap consistency checks locally (TODO #341).
#
# Covers the spec/, document, KAT-currency and tooling checks that CI runs
# spread across several jobs: about 5 minutes on an aarch64 SBC, where the test
# harnesses and the findings gates take hours.  No build is needed.  Use it as a
# pre-push check for the doc/spec class of failure.
#
#   bash tools/check_fast.sh              run every check
#   bash tools/check_fast.sh --skip-kat   leave out the KAT regenerate-and-diff
#                                         checks (generate_kat.py is ~4 min)
#   bash tools/check_fast.sh --list       print the commands and exit
#   bash tools/check_fast.sh --verify-ci  check this list against CI instead of
#                                         running it (what CI itself runs)
#
# Like run_findings_gates.py, a failure does not stop the run: everything runs
# and the failures are listed at the end, because one doc edit often breaks
# several checks at once.
#
# The list mirrors CI and is held to it in BOTH directions by --verify-ci:
# every command below must appear verbatim in .github/workflows/ci.yml or in a
# CliTest/ script CI runs, and every checker CI invokes must be listed here.
# So a check added to CI fails until it is added here, and one removed from CI
# fails until it is removed here.

set -u
cd "$(dirname "$0")/.." || exit 2

COMMANDS=(
  "python3 spec/generate_spec.py --check --require-schema"
  "python3 spec/check_security_md.py"
  "python3 spec/check_language_parity.py"
  "python3 spec/check_docs_consistency.py"
  "python3 SecurityProofsCode/check_part_index.py --require-counts"
  "python3 tools/check_runnable_coverage.py"
  "python3 tools/check_docker_mirror.py"
  "python3 tools/check_rate_format.py"
  "python3 KAT/generate_kat.py --check"
  "python3 KAT/generate_pem_kat.py --check"
  "python3 KAT/generate_bitarray_kat.py --check"
)

# Invocations CI makes that are consistency checkers but deliberately NOT part
# of this script, each with a reason.  --verify-ci fails on an entry that no
# longer matches anything in CI.
NOT_FAST=(
  "SecurityProofsCode/run_findings_gates.py|the findings gates take hours (analysis-findings job)"
)

verify_ci() {
  local ci=.github/workflows/ci.yml corpus err=0 cmd inv entry pat
  corpus=$(cat "$ci" CliTest/*.sh)
  for cmd in "${COMMANDS[@]}"; do
    if ! grep -qF -- "$cmd" <<<"$corpus"; then
      echo "FAIL: '$cmd' is listed here but CI never runs it (ci.yml or CliTest/)"
      err=1
    fi
  done
  # Every checker-shaped invocation in ci.yml must be listed here or in NOT_FAST.
  while IFS= read -r inv; do
    [ -z "$inv" ] && continue
    local found=0
    for cmd in "${COMMANDS[@]}"; do
      case "$cmd" in *"$inv"*) found=1 ;; esac
    done
    for entry in "${NOT_FAST[@]}"; do
      case "$inv" in *"${entry%%|*}"*) found=1 ;; esac
    done
    if [ "$found" = 0 ]; then
      echo "FAIL: CI runs '$inv', which is neither in COMMANDS nor in NOT_FAST"
      err=1
    fi
  done < <(grep -oE 'python3 [A-Za-z_/]+/(check_[a-z_]+|generate_[a-z_]+|run_findings_gates)\.py' "$ci" | sed 's/^python3 //' | sort -u)
  for entry in "${NOT_FAST[@]}"; do
    pat=${entry%%|*}
    if ! grep -qF -- "$pat" "$ci"; then
      echo "FAIL: NOT_FAST names '$pat', which CI no longer runs -- delete the entry"
      err=1
    fi
  done
  if [ "$err" = 0 ]; then
    echo "*** OK: tools/check_fast.sh lists ${#COMMANDS[@]} checks, all run by CI, and misses none ***"
  else
    echo "*** FAILED: tools/check_fast.sh and CI disagree (TODO #341) ***"
  fi
  return $err
}

skip_kat=0
case "${1:-}" in
  --list) printf '%s\n' "${COMMANDS[@]}"; exit 0 ;;
  --verify-ci) verify_ci; exit $? ;;
  --skip-kat) skip_kat=1 ;;
  "") ;;
  *) echo "usage: $0 [--skip-kat | --list | --verify-ci]" >&2; exit 2 ;;
esac

failed=()
ran=0
for cmd in "${COMMANDS[@]}"; do
  if [ "$skip_kat" = 1 ] && [[ "$cmd" == *" KAT/"* ]]; then
    echo "--- SKIP: $cmd (--skip-kat)"
    continue
  fi
  echo "--- $cmd"
  start=$SECONDS
  if out=$($cmd 2>&1); then
    echo "    ok ($((SECONDS - start)) s)"
  else
    echo "$out" | tail -n 25 | sed 's/^/    | /'
    echo "    FAILED ($((SECONDS - start)) s)"
    failed+=("$cmd")
  fi
  ran=$((ran + 1))
done

echo
if [ ${#failed[@]} -eq 0 ]; then
  echo "*** OK: $ran fast check(s) passed ***"
  exit 0
fi
echo "*** FAILED: ${#failed[@]} of $ran fast check(s) ***"
printf '    %s\n' "${failed[@]}"
exit 1
