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

# Both files must exist; a missing one would otherwise pass silently, since
# --check only compares what it regenerates.
for f in KAT/classical_quartet.json KAT/hkex_rnl.json KAT/nl_fscx_v3.json \
         KAT/hcred_kkw.json; do
    [ -s "$f" ] || { echo "FAIL: $f missing or empty"; exit 1; }
done

echo "PASS test_kat_vectors"
