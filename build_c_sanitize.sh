#!/usr/bin/env bash
# HerraduraKEx — C sanitizer build script (TODO #188)
# Compiles the suite, test suite, and CLI with AddressSanitizer +
# UndefinedBehaviorSanitizer for local/CI memory-safety and UB auditing.
# Complements the manual constant-time audit (TODO #129/#182) and the
# Fuzz/ harness (TODO #130/#187), neither of which alone catches every
# memory-safety bug a normal, non-adversarial run can trip.
#
# Output binaries use an _asan suffix so they don't collide with the plain
# build_c.sh outputs (same rationale as build_c.sh's _c suffix vs. Go's
# unsuffixed default).
#
# Dependencies:
#   clang (with -fsanitize=address,undefined support)
#     sudo apt-get install -y clang
#
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

VERSION="1.0.0"
SUITE_SRC="Herradura cryptographic suite.c"
SUITE_BIN="Herradura cryptographic suite_asan"
TESTS_SRC="CryptosuiteTests/Herradura_tests.c"
TESTS_BIN="CryptosuiteTests/Herradura_tests_asan"
CLI_SRC="HerraduraCli/herradura_cli.c"
CLI_BIN="HerraduraCli/herradura_cli_asan"

SAN_FLAGS="-fsanitize=address,undefined -fno-sanitize-recover=all -g -O1"

# ── dependency check ──────────────────────────────────────────────────────────
if ! command -v clang &>/dev/null; then
    echo "ERROR: clang not found."
    echo "  Install: sudo apt-get install -y clang"
    exit 1
fi

echo "=== HerraduraKEx v${VERSION} — C sanitizer build (ASan+UBSan) ==="

echo "  Compiling suite..."
clang ${SAN_FLAGS} -o "${SUITE_BIN}" "${SUITE_SRC}"
echo "    -> ${SUITE_BIN}"

echo "  Compiling tests..."
clang ${SAN_FLAGS} -o "${TESTS_BIN}" "${TESTS_SRC}"
echo "    -> ${TESTS_BIN}"

echo "  Compiling CLI..."
clang ${SAN_FLAGS} -o "${CLI_BIN}" "${CLI_SRC}"
echo "    -> ${CLI_BIN}"

echo ""
echo "Build complete. Run:"
echo "  ./${TESTS_BIN} [-r ROUNDS] [-t SECONDS]      # security tests under ASan+UBSan"
echo "  ./${CLI_BIN} --help                          # CLI under ASan+UBSan"
echo ""
echo "ASan/UBSan abort on the first detected issue (-fno-sanitize-recover=all);"
echo "a clean exit means nothing was caught in that run, not that nothing exists."
