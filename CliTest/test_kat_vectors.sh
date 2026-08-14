#!/usr/bin/env bash
# CliTest/test_kat_vectors.sh — TODO #190: KAT/classical_quartet.json is
# current (Python reference regenerates it byte-for-byte) and independently
# cross-checks against the Go herradura package.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

echo "=== KAT/generate_kat.py --check ==="
python3 KAT/generate_kat.py --check

echo "=== KAT/verify_kat.go (Go cross-check) ==="
go run KAT/verify_kat.go

echo "PASS test_kat_vectors"
