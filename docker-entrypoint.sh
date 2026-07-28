#!/usr/bin/env bash
# TODO #139: Docker quickstart entrypoint. Builds every host-portable target
# (C, Go, ARM Thumb-2, NASM i386 — Python needs no build step; Arduino is
# excluded, see Dockerfile) and runs a smoke test: the C/Go/Python security
# test suites plus one CLI integration test (CliTest/test_c_interop.sh,
# which exercises Python<->C interop and therefore needs both built).
#
# Total runtime varies a lot by host: the 256-bit GF(2^n)* benchmarks
# ([33]/[34] etc.) are the long pole and can each take several seconds per
# row on modest hardware even with -t capping per-test wall clock (a single
# gf_pow call can't be interrupted mid-operation). Expect anywhere from
# under a minute (modern x86_64) to several minutes (e.g. an ARM SBC).
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

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
./CryptosuiteTests/Herradura_tests_c -r 50 -t 1.0

echo "--- Go ---"
(cd CryptosuiteTests && go run Herradura_tests.go -r 50 -t 1.0)

echo "--- Python ---"
python3 CryptosuiteTests/Herradura_tests.py -r 50 -t 1.0

echo "--- ARM Thumb-2 (qemu-arm) ---"
./run_arm.sh tests -r 50 -t 1.0

echo "--- NASM i386 (qemu-i386) ---"
./run_asm_i386.sh tests

echo
echo "############################################"
echo "# CLI integration smoke test"
echo "############################################"
bash CliTest/test_c_interop.sh

echo
echo "All builds and smoke tests completed successfully."
