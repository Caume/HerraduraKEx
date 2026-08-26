# CliTest/lib_dfr.sh — shared QC-MDPC decoding-failure-rate (DFR) retry policy.
# TODO #221; the policy itself was established by TODO #195 and rewritten by
# TODO #235.
#
# The QC-MDPC BGF decoder behind `--algo hpke-stern-kem` (and the KEM half of
# `--algo hybrid-rnl-stern`) has a measured, nonzero decoding failure rate at its
# current toy parameters: 0.225% per encapsulation, 45/20000 trials, 95% CI
# [0.159%, 0.291%] — see SecurityProofsCode/qcmdpc_bgf_failure_rate.py. A DFR
# event is an expected protocol outcome, not a bug, so a CI script that
# decapsulates must retry a bounded number of times with fresh randomness rather
# than failing the run.
#
# ── What TODO #235 changed, and why this file was rewritten ──────────────────
#
# Until #235, decapsulation reported failure: a distinct return value in the
# library and a distinct exit status plus stderr message at the CLI. That signal
# WAS the GJS reaction oracle (TODO #218 §5, §6), so #235's FO transform removed
# it. Decapsulation now always returns a key — a pseudorandom one derived from
# the private key and the ciphertext when decoding fails.
#
# The observable consequence for these scripts: **a DFR event is now a mismatch,
# not an error.** The CLI exits 0, writes an output file, and the bytes are
# wrong. There is no message to grep for, and the old `dfr_is_event` predicate
# has been deleted rather than left to match nothing — a stale caller would turn
# every DFR event into a hard red, which is exactly what TODO #221 exists to
# prevent. A script still using it fails loudly under `set -e`.
#
# ── How a DFR event is told apart from a real bug now ────────────────────────
#
# It is not told apart on a single attempt, and it does not need to be. Decoding
# is deterministic given (key, ciphertext), so:
#
#   * a DFR event is a property of one (key, error-vector) pair — an independent
#     fresh encapsulation misses it with probability 1 - 0.00225;
#   * a genuine bug (a wire-format disagreement, a broken language pair, a
#     wrong-key derivation) is deterministic and reproduces on every attempt.
#
# So the policy is unchanged in shape and in its residual-error math: retry the
# whole encapsulate-decapsulate step a bounded number of times against FRESH
# randomness, and treat a mismatch that survives the budget as a real failure.
# Residual false-red probability is still p^N: 1.1e-8 at N=3, 5.8e-14 at N=5.
#
# What is genuinely lost is the old file's assurance that "the decoder
# self-detects every failure it hits and never silently accepts a wrong key".
# Post-#235 a caller cannot distinguish the two, by design. Bounded retries
# absorb both the same way, but a script must now compare OUTPUT BYTES to notice
# anything at all — a script that only checks the exit status of `dec` no longer
# tests the KEM, it tests that the CLI starts.
#
# Usage — source this file, then retry the whole round-trip on a mismatch:
#
#     . "$(dirname "$0")/lib_dfr.sh"
#     attempt=1
#     while :; do
#         ... produce a fresh encapsulation ...
#         $CLI dec --algo hpke-stern-kem ... --out "$TMP/out.bin"
#         cmp -s "$TMP/msg.bin" "$TMP/out.bin" && break     # success
#         if dfr_retryable "$attempt"; then
#             dfr_report_retry "my-label" "$attempt"
#             attempt=$((attempt+1)); continue
#         fi
#         break   # budget exhausted — let the caller fail honestly
#     done
#
# Retrying the encapsulation alone (rather than the keypair) is the cheaper unit
# and is what test_hybrid_kex_interop.sh does; either is valid, since the failure
# depends on the (key, error-vector) pair. Note that a genuinely weak key would
# make retries correlated rather than independent, so exhausting the budget is
# not proof of a bug — but #235 Part 1 now screens the weak-key classes TODO
# #218 §4 measured out of keygen, so this is a much smaller worry than it was.

# Bounded retry budget. 3 is TODO #195's original choice and is ample.
MAX_DFR_RETRIES=${MAX_DFR_RETRIES:-3}

# dfr_retryable <attempt> — true while the budget has an attempt left.
dfr_retryable() {
    [ "$1" -lt "$MAX_DFR_RETRIES" ]
}

# dfr_report_retry <label> <attempt> — uniform, greppable INFO line on stderr.
dfr_report_retry() {
    echo "INFO $1: QC-MDPC BGF DFR event (output mismatch) on attempt $2 of" \
         "$MAX_DFR_RETRIES (expected ~0.225%/encapsulation, TODO #195/#235)" \
         "— retrying with fresh randomness" >&2
}
