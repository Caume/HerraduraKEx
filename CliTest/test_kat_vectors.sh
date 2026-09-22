#!/usr/bin/env bash
# CliTest/test_kat_vectors.sh — TODO #190: KAT/classical_quartet.json is current
# (the Python reference regenerates it byte-for-byte) and independently
# cross-checks against the Go herradura package.
#
# TODO #226 adds KAT/hkex_rnl.json on the same terms: the same generator emits
# both, --check covers both, and the Go verifier recomputes both.
#
# TODO #296 adds KAT/sampler_replay.json, and it needs no step of its own here:
# all four consumers below already read it.  --check REGENERATES it, which is
# Python's half (the generator drives the shipped samplers against the pinned
# stream, so a diff IS the Python replay) and also diffs the generated C view
# KAT/sampler_replay_vector.h; verify_kat.go, verify_kat_c and -- over in
# test_java_bindings.sh -- herradurakex.KatVerify each replay the same stream
# through their own port.  Four ports against one pinned vector is four ports
# against each other, so there is no separate cross-language step to write.
#
# TODO #297 adds KAT/operation_replay.json on exactly the same terms, one level
# up: whole randomised OPERATIONS rather than leaf samplers, with a fixed
# statement alongside the fixed stream.  Same four consumers, same generated C
# view (KAT/operation_replay_vector.h), same argument -- so again no step of its
# own.  If you add a THIRD vector of this shape, the thing to check is that all
# four consumers follow it, not that this script grew a section.
#
# TODO #303 adds a ROW rather than a vector -- hcred_prove_kkw, the operation
# TODO #302 §6 found pinned nowhere -- and it is the first one whose cost is
# worth knowing before you run this by hand.  One n=256 KKW prove, measured on
# an aarch64 SBC: C 0.7 s, Java 8.6 s, Go 38.5 s, Python 40.8 s -- the compiled
# consumers are NOT uniformly cheap, Go's KKW sits at interpreted-Python speed
# -- so `--check` and the Go cross-check each get about that much slower.  Go
# was already paying ~33 s per n=256 KKW VERIFY seven times over in the
# hcred_kkw[n256] block below, so this is about a sixth more of a cost that was
# already there, not a new order of magnitude.  n=256 is
# forced (HCRED_N and Hcred.N are compile-time constants) and
# (N_par, M, tau) = (4, 4, 2) is the cost choice; the generator asserts what
# that triple must still exercise.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

echo "=== KAT/generate_kat.py --check ==="
python3 KAT/generate_kat.py --check

# TODO #314: the BitArray conformance vectors.  --check verifies BOTH that
# bitarray.json is current AND that the generated C header transposed from it
# still matches -- the two cannot drift, on KAT/hcred_kkw_vector.h's precedent
# (TODO #266).  C is pass 2 and the FIRST port in the gating set; Go, Python and
# Java join one per release (BITARRAY.md 8), each adding its consumer here.
# Until the second port lands this is ONE implementation against ONE pinned
# answer, which is more than currency and less than the cross-implementation
# check BITARRAY.md 7 describes; said out loud rather than left to look like
# more than it is.  The per-port conformance REPORT is deliberately not a gate:
# an unconverted port is expected to diverge, and CLAUDE.md's Testing section
# allows no failing test.
echo "=== KAT/generate_bitarray_kat.py --check (TODO #314) ==="
python3 KAT/generate_bitarray_kat.py --check

echo "=== KAT/verify_bitarray_c.c (C conformance, TODO #314 pass 2) ==="
if ! cc -O2 -o KAT/verify_bitarray_c KAT/verify_bitarray_c.c 2>/tmp/hkx_ba_cc.log; then
    echo "FAIL: could not compile KAT/verify_bitarray_c.c"
    cat /tmp/hkx_ba_cc.log
    exit 1
fi
KAT/verify_bitarray_c
rm -f KAT/verify_bitarray_c

echo "=== KAT/verify_kat.go (Go cross-check) ==="
go run KAT/verify_kat.go

# TODO #266: C's consumer.  C had no KAT verifier of any kind before this, and
# is where two of the three KKW port bugs were -- both of them reader
# disagreements about a byte layout, which is what consuming another
# implementation's transcript catches and a self-round-trip cannot.  Compiled on
# demand rather than tracked, per TODO #229.
echo "=== KAT/verify_kat_c.c (C cross-check, TODO #266) ==="
# stderr is captured rather than discarded: herradura.h emits an SDF_ROUNDS
# #pragma message on every include, but discarding all of stderr to hide it
# would also hide a genuine compile error, leaving only a confusing "no such
# file" from the run below.  Show it only when the compile actually fails.
if ! cc -O2 -o KAT/verify_kat_c KAT/verify_kat_c.c 2>/tmp/hkx_kkw_cc.log; then
    echo "FAIL: could not compile KAT/verify_kat_c.c"
    cat /tmp/hkx_kkw_cc.log
    exit 1
fi
./KAT/verify_kat_c

# Both files must exist; a missing one would otherwise pass silently, since
# --check only compares what it regenerates.
for f in KAT/classical_quartet.json KAT/hkex_rnl.json KAT/nl_fscx_v3.json \
         KAT/hcred_kkw.json KAT/sampler_replay.json \
         KAT/sampler_replay_vector.h KAT/operation_replay.json \
         KAT/operation_replay_vector.h; do
    [ -s "$f" ] || { echo "FAIL: $f missing or empty"; exit 1; }
done

echo "PASS test_kat_vectors"
