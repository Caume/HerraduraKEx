#!/usr/bin/env bash
# HerraduraKEx v1.5.8 — ARM Thumb-2 run script
# Runs the suite and test binaries under qemu-arm (user-mode emulation).
#
# Dependencies:
#   qemu-arm   — sudo apt-get install -y qemu-user
#
# Build first with: ./build_arm.sh
#
# Usage:
#   ./run_arm.sh                         # run suite then tests
#   ./run_arm.sh suite                   # run suite only
#   ./run_arm.sh tests [-r N] [-t S]     # run tests with optional flags
#
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

SUITE_BIN="Herradura cryptographic suite_arm"
TESTS_BIN="CryptosuiteTests/Herradura_tests_arm"
ARM_SYSROOT="/usr/arm-linux-gnueabi"

# ── dependency check ──────────────────────────────────────────────────────────
if ! command -v qemu-arm &>/dev/null; then
    echo "ERROR: qemu-arm not found."
    echo "  Install: sudo apt-get install -y qemu-user"
    exit 1
fi

if [ ! -f "${SUITE_BIN}" ] || [ ! -f "${TESTS_BIN}" ]; then
    echo "ERROR: binaries not found — run ./build_arm.sh first."
    exit 1
fi

MODE="${1:-all}"
shift || true

case "${MODE}" in
    suite)
        echo "=== ARM Thumb-2 — Suite ==="
        qemu-arm -L "${ARM_SYSROOT}" "./${SUITE_BIN}"
        ;;
    tests)
        echo "=== ARM Thumb-2 — Tests ==="
        qemu-arm -L "${ARM_SYSROOT}" "./${TESTS_BIN}" "$@"
        ;;
    all|*)
        echo "=== ARM Thumb-2 — Suite ==="
        qemu-arm -L "${ARM_SYSROOT}" "./${SUITE_BIN}"
        echo ""
        echo "=== ARM Thumb-2 — Tests ==="
        qemu-arm -L "${ARM_SYSROOT}" "./${TESTS_BIN}" "$@"
        ;;
esac
