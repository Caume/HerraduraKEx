# CliTest/lib_dfr.sh — shared QC-MDPC decoding-failure-rate (DFR) retry policy.
# TODO #221; the policy itself was established by TODO #195 and rewritten by
# TODO #235.
#
# ── WHAT TODO #276 CHANGED, AND WHY THIS POLICY IS STILL HERE ────────────────
#
# This file was written when the KEM ran at toy parameters (r=523, d=15, t=18)
# with a MEASURED decoding failure rate of 0.225%-0.264% per encapsulation —
# high enough to be hit in ordinary CI, which is the whole reason for a shared
# retry policy. v7.0.0 moved the KEM to BIKE-128 (r=12323, d=71, t=134) with
# BIKE's decoder, whose published DFR target is 2^-128. **At these parameters a
# retry here is expected never to fire.**
#
# That makes this policy look like dead code, and TODO #276 asked for it to be
# re-justified rather than left asserting something vacuous. Three reasons it
# stays, and the third changes how a firing retry should be read:
#
#   1. The 2^-128 is INHERITED, not measured here. What ships is a
#      reimplementation of BIKE's decoder over a suite-specific FSCX-based PRF;
#      its equivalence to BIKE's is established by testing, not by proof. A
#      nonzero rate is not excluded by anything in this repository.
#   2. ci.yml's guard — every script that decapsulates must source this file —
#      is a coverage check on SCRIPTS, not a claim about the rate. Dropping it
#      would let a new script check `dec`'s exit status and call that a test,
#      which since TODO #235 tests only that the CLI starts.
#   3. **A retry that fires is now a signal, not noise.** At the toy parameters
#      a mismatch was overwhelmingly likely to be an expected DFR event; at
#      BIKE-128 it is overwhelmingly likely to be a BUG — a wire-format
#      disagreement, a broken language pair, a decoder ported wrong. The retry
#      still happens (a real DFR event must not turn CI red on one sample), but
#      dfr_report_retry says so loudly and names #276, so a firing retry is
#      something to investigate rather than to scroll past.
#
# The mechanics below are unchanged; only the reading of a fired retry is.
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
# Residual false-red probability is p^N, where p was 0.00225 at the toy
# parameters: 1.1e-8 at N=3, 5.8e-14 at N=5.  At BIKE-128 the same arithmetic is
# vacuous rather than reassuring — p is believed to be 2^-128 — so the budget is
# kept for the reasons above, not for this bound.
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

# dfr_report_retry <label> <attempt> — uniform, greppable line on stderr.
#
# WARN, not INFO, since TODO #276: at BIKE-128 the expected DFR is 2^-128, so a
# mismatch here is far more likely to be a bug than an expected decoding
# failure.  It still retries — one sample cannot tell the two apart, and a
# genuine DFR event must not turn CI red — but it should not read as routine.
dfr_report_retry() {
    echo "WARN $1: QC-MDPC output mismatch on attempt $2 of $MAX_DFR_RETRIES" \
         "— retrying with fresh randomness. At BIKE-128 (r=12323, TODO #276)" \
         "the expected DFR is 2^-128, so this is far more likely a BUG than a" \
         "decoding failure: investigate rather than ignore" >&2
}
