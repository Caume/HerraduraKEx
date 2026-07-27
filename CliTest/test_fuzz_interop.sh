#!/usr/bin/env bash
# CliTest/test_fuzz_interop.sh — fast subset of the TODO #136 property-based
# interop fuzzer (CliTest/fuzz_interop.py), wired into the regular CliTest
# suite. For a larger soak run:
#   python3 CliTest/fuzz_interop.py --cases 2000
# (a few thousand cases per protocol take several minutes — each case spawns
# multiple CLI subprocesses; the Python CLI's interpreter startup dominates).
set -euo pipefail
cd "$(dirname "$0")/.."
python3 CliTest/fuzz_interop.py --cases 8 --seed 0
