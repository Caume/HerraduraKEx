#!/usr/bin/env bash
# HerraduraKEx v1.5.8 — NASM i386 run script
# Runs the suite and test binaries under qemu-i386 (user-mode emulation).
#
# Dependencies:
#   qemu-i386   — sudo apt-get install -y qemu-user
#
# Build first with: ./build_asm_i386.sh
#
# Usage:
#   ./run_asm_i386.sh                         # run suite then tests
#   ./run_asm_i386.sh suite                   # run suite only
#   ./run_asm_i386.sh tests [-r N] [-t S]     # run tests (flags ignored by asm, shown for parity)
#
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

SUITE_BIN="Herradura cryptographic suite_i386"
TESTS_BIN="CryptosuiteTests/Herradura_tests_i386"

# ── dependency check ──────────────────────────────────────────────────────────
if ! command -v qemu-i386 &>/dev/null; then
    echo "ERROR: qemu-i386 not found."
    echo "  Install: sudo apt-get install -y qemu-user"
    exit 1
fi

if [ ! -f "${SUITE_BIN}" ] || [ ! -f "${TESTS_BIN}" ]; then
    echo "ERROR: binaries not found — run ./build_asm_i386.sh first."
    exit 1
fi

MODE="${1:-all}"
shift || true

case "${MODE}" in
    suite)
        echo "=== NASM i386 — Suite ==="
        qemu-i386 "./${SUITE_BIN}"
        ;;
    tests)
        echo "=== NASM i386 — Tests ==="
        qemu-i386 "./${TESTS_BIN}"
        ;;
    all|*)
        echo "=== NASM i386 — Suite ==="
        qemu-i386 "./${SUITE_BIN}"
        echo ""
        echo "=== NASM i386 — Tests ==="
        qemu-i386 "./${TESTS_BIN}"
        ;;
esac
