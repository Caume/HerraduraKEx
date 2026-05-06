#!/usr/bin/env bash
# HerraduraKEx v1.5.26 — C build script
# Compiles the cryptographic suite, test suite, and CLI using gcc.
#
# Output binaries use the _c suffix to prevent collision with the Go build,
# which defaults to the same stem when invoked without -o.
#
# Dependencies:
#   gcc   — sudo apt-get install -y gcc
#
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

VERSION="1.5.26"
SUITE_SRC="Herradura cryptographic suite.c"
SUITE_BIN="Herradura cryptographic suite_c"
TESTS_SRC="CryptosuiteTests/Herradura_tests.c"
TESTS_BIN="CryptosuiteTests/Herradura_tests_c"
CLI_SRC="HerraduraCli/herradura_cli.c"
CLI_BIN="HerraduraCli/herradura_cli"

# ── dependency check ──────────────────────────────────────────────────────────
if ! command -v gcc &>/dev/null; then
    echo "ERROR: gcc not found."
    echo "  Install: sudo apt-get install -y gcc"
    exit 1
fi

echo "=== HerraduraKEx v${VERSION} — C build ==="

echo "  Compiling suite..."
gcc -O2 -o "${SUITE_BIN}" "${SUITE_SRC}"
echo "    -> ${SUITE_BIN}"

echo "  Compiling tests..."
gcc -O2 -o "${TESTS_BIN}" "${TESTS_SRC}"
echo "    -> ${TESTS_BIN}"

echo "  Compiling CLI..."
gcc -O2 -o "${CLI_BIN}" "${CLI_SRC}"
echo "    -> ${CLI_BIN}"

echo ""
echo "Build complete. Run:"
echo "  ./${SUITE_BIN}"
echo "  ./${TESTS_BIN} [-r ROUNDS] [-t SECONDS]"
echo "  ./${CLI_BIN} --help"
