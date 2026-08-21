# CliTest/lib_dfr.sh — shared QC-MDPC decoding-failure-rate (DFR) retry policy.
# TODO #221; the policy itself was established by TODO #195.
#
# The QC-MDPC BGF decoder behind `--algo hpke-stern-kem` (and the KEM half of
# `--algo hybrid-rnl-stern`) has a measured, nonzero decoding failure rate at its
# current toy parameters: 0.225% per encapsulation, 45/20000 trials, 95% CI
# [0.159%, 0.291%] — see SecurityProofsCode/qcmdpc_bgf_failure_rate.py. A DFR
# event is an expected protocol outcome, not a bug, so a CI script that
# decapsulates must retry a bounded number of times with fresh randomness rather
# than failing the run.
#
# All 45 measured failures were clean `None` returns — the decoder self-detects
# every failure it hits and never silently accepts a wrong key — which is what
# makes a retry safe: it absorbs the measured DFR without masking a real bug,
# provided callers retry ONLY on the signature below and report honestly once
# retries are exhausted.
#
# Usage — source this file, then wrap the decapsulating step in a retry loop:
#
#     . "$(dirname "$0")/lib_dfr.sh"
#     attempt=1
#     while :; do
#         ... produce a fresh encapsulation ...
#         if $CLI dec --algo hpke-stern-kem ... 2>"$TMP/err.log"; then break; fi
#         if dfr_is_event "$(cat "$TMP/err.log")" && [ "$attempt" -lt "$MAX_DFR_RETRIES" ]; then
#             dfr_report_retry "my-label" "$attempt"
#             attempt=$((attempt+1)); continue
#         fi
#         break   # not a DFR event, or retries exhausted — let the caller fail honestly
#     done
#
# Retrying the encapsulation alone (rather than the keypair) is the cheaper unit
# and is what test_hybrid_kex_interop.sh does; either is valid, since the failure
# depends on the (key, error-vector) pair. Note that a genuinely weak key would
# make retries correlated rather than independent, so exhausting the budget is
# not proof of a bug — the weak-key classes are the subject of TODO #218.
#
# Residual failure probability with p = 0.00225 and N independent retries is
# p^N: 1.1e-8 at N=3, 5.8e-14 at N=5. Per CI run, multiply by the number of
# independent encapsulations the script performs.

# Bounded retry budget. 3 is TODO #195's original choice and is ample.
MAX_DFR_RETRIES=${MAX_DFR_RETRIES:-3}

# Matches every DFR message the four CLIs emit. Python/C/Go/Java all print one of:
#   "dec: HPKE-Stern-KEM BGF decoding failed (DFR event or corrupt ciphertext)"
#   "kex hybrid-rnl-stern: HPKE-Stern-KEM decapsulation failed (DFR event or corrupt ciphertext)"
# Deliberately narrow: anything else must surface as a real failure.
DFR_ERR_PATTERN='DFR event or corrupt ciphertext|decapsulation failed|BGF decoding failed'

# dfr_is_event <text> — true when the text carries the known DFR signature.
dfr_is_event() {
    printf '%s' "$1" | grep -qE "$DFR_ERR_PATTERN"
}

# dfr_report_retry <label> <attempt> — uniform, greppable INFO line on stderr.
dfr_report_retry() {
    echo "INFO $1: QC-MDPC BGF DFR event on attempt $2 of $MAX_DFR_RETRIES" \
         "(expected ~0.225%/encapsulation, TODO #195) — retrying with fresh randomness" >&2
}
