#!/usr/bin/env bash
# HerraduraKEx v1.5.8 — Go build script
# Compiles the cryptographic suite and test suite using go build.
#
# Dependencies:
#   go   — sudo apt-get install -y golang-go
#           (or install from https://go.dev/dl/ for a newer version)
#
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

VERSION="1.5.8"
SUITE_SRC="Herradura cryptographic suite.go"
SUITE_BIN="Herradura cryptographic suite_go"
TESTS_DIR="CryptosuiteTests"
TESTS_BIN="Herradura_tests_go"

# ── dependency check ──────────────────────────────────────────────────────────
if ! command -v go &>/dev/null; then
    echo "ERROR: go not found."
    echo "  Install: sudo apt-get install -y golang-go"
    echo "  Or download: https://go.dev/dl/"
    exit 1
fi

echo "=== HerraduraKEx v${VERSION} — Go build ==="

echo "  Compiling suite..."
go build -o "${SUITE_BIN}" "${SUITE_SRC}"
echo "    -> ${SUITE_BIN}"

echo "  Compiling tests..."
(cd "${TESTS_DIR}" && go build -o "${TESTS_BIN}" Herradura_tests.go)
echo "    -> ${TESTS_DIR}/${TESTS_BIN}"

echo ""
echo "Build complete. Run:"
echo "  ./${SUITE_BIN}"
echo "  ./${TESTS_DIR}/${TESTS_BIN} [-r ROUNDS] [-t SECONDS]"
