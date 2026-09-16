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
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

echo "=== KAT/generate_kat.py --check ==="
python3 KAT/generate_kat.py --check

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
         KAT/sampler_replay_vector.h; do
    [ -s "$f" ] || { echo "FAIL: $f missing or empty"; exit 1; }
done

echo "PASS test_kat_vectors"
