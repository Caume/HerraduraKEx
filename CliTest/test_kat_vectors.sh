#!/usr/bin/env bash
# CliTest/test_kat_vectors.sh — TODO #190: KAT/classical_quartet.json is current
# (the Python reference regenerates it byte-for-byte) and independently
# cross-checks against the Go herradura package.
#
# TODO #226 adds KAT/hkex_rnl.json on the same terms: the same generator emits
# both, --check covers both, and the Go verifier recomputes both.
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
cc -O2 -o KAT/verify_kat_c KAT/verify_kat_c.c 2>/dev/null
./KAT/verify_kat_c

# Both files must exist; a missing one would otherwise pass silently, since
# --check only compares what it regenerates.
for f in KAT/classical_quartet.json KAT/hkex_rnl.json KAT/nl_fscx_v3.json \
         KAT/hcred_kkw.json; do
    [ -s "$f" ] || { echo "FAIL: $f missing or empty"; exit 1; }
done

echo "PASS test_kat_vectors"
