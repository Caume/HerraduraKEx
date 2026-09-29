#!/usr/bin/env bash
# TODO #139: Docker quickstart entrypoint. Builds every host-portable target
# (C, Go, ARM Thumb-2, NASM i386 — Python needs no build step; Arduino is
# excluded, see Dockerfile) and runs a smoke test: the C/Go/Python security
# test suites plus one CLI integration test (CliTest/test_c_interop.sh,
# which exercises Python<->C interop and therefore needs both built).
#
# RUNTIME, measured rather than estimated (TODO #326).  This header used to
# say "under a minute (modern x86_64) to several minutes (e.g. an ARM SBC)".
# That was written at TODO #139 and is now out by an order of magnitude: the
# full run takes ~75-90 MINUTES on an aarch64 SBC, because ~190 numbered-test
# items have landed since and [50] HCRED-KKW alone is a ~38.5 s-per-prove path
# in Go.  The 256-bit GF(2^n)* benchmarks ([33]/[34]) are still a long pole --
# a single gf_pow call cannot be interrupted mid-operation, so -t caps the
# iteration count and not the wall clock.
#
# That figure is not cosmetic: it is the input to whether CI runs this script,
# so HERRADURA_SMOKE_ROUNDS and HERRADURA_SMOKE_TIME below exist to let a
# caller trade coverage for time.  Their DEFAULTS ARE THE SHIPPED BEHAVIOUR --
# `docker run` is byte-identical to before this change.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

# Reduced caps for a caller that wants the SCRIPT exercised rather than the
# cryptography re-measured -- which is CI's case, since all twelve jobs already
# run every target here at full size.  Defaults unchanged (TODO #326).
ROUNDS="${HERRADURA_SMOKE_ROUNDS:-50}"
TIMECAP="${HERRADURA_SMOKE_TIME:-1.0}"

echo "############################################"
echo "# HerraduraKEx quickstart — build matrix"
echo "############################################"

./build_c.sh
echo
./build_go.sh
echo
./build_arm.sh
echo
./build_asm_i386.sh

echo
echo "############################################"
echo "# Test suites (capped for a fast smoke run)"
echo "############################################"

echo "--- C ---"
./CryptosuiteTests/Herradura_tests_c -r "$ROUNDS" -t "$TIMECAP"

echo "--- Go ---"
(cd CryptosuiteTests && go run Herradura_tests.go -r "$ROUNDS" -t "$TIMECAP")

echo "--- Python ---"
python3 CryptosuiteTests/Herradura_tests.py -r "$ROUNDS" -t "$TIMECAP"

echo "--- ARM Thumb-2 (qemu-arm) ---"
./run_arm.sh tests -r "$ROUNDS" -t "$TIMECAP"

echo "--- NASM i386 (qemu-i386) ---"
./run_asm_i386.sh tests

echo
echo "############################################"
echo "# CLI integration smoke test"
echo "############################################"
bash CliTest/test_c_interop.sh

echo
echo "All builds and smoke tests completed successfully."
