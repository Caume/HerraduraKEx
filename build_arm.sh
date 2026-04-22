#!/usr/bin/env bash
# HerraduraKEx v1.5.8 — ARM Thumb-2 build script
# Cross-compiles the suite and tests from ARM Thumb-2 assembly using
# arm-linux-gnueabi-gcc.  Produces ELF binaries runnable under qemu-arm.
#
# Dependencies (build):
#   arm-linux-gnueabi-gcc + ARM sysroot
#     sudo apt-get install -y gcc-arm-linux-gnueabi libc6-armel-cross
#
# Dependencies (run — see run_arm.sh):
#   qemu-arm
#     sudo apt-get install -y qemu-user
#
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

VERSION="1.5.8"
SUITE_SRC="Herradura cryptographic suite.s"
SUITE_BIN="Herradura cryptographic suite_arm"
TESTS_SRC="CryptosuiteTests/Herradura_tests.s"
TESTS_BIN="CryptosuiteTests/Herradura_tests_arm"

ARM_CC="arm-linux-gnueabi-gcc"
ARM_SYSROOT_LIB="/usr/arm-linux-gnueabi/lib"

# ── dependency checks ─────────────────────────────────────────────────────────
if ! command -v "${ARM_CC}" &>/dev/null; then
    echo "ERROR: ${ARM_CC} not found."
    echo "  Install: sudo apt-get install -y gcc-arm-linux-gnueabi"
    exit 1
fi

if [ ! -f "${ARM_SYSROOT_LIB}/crt1.o" ]; then
    echo "ERROR: ARM sysroot not found at ${ARM_SYSROOT_LIB}/crt1.o"
    echo "  Install: sudo apt-get install -y libc6-armel-cross"
    exit 1
fi

echo "=== HerraduraKEx v${VERSION} — ARM Thumb-2 build ==="

echo "  Compiling suite..."
"${ARM_CC}" -O2 \
    -L"${ARM_SYSROOT_LIB}" \
    -B"${ARM_SYSROOT_LIB}" \
    -o "${SUITE_BIN}" "${SUITE_SRC}"
echo "    -> ${SUITE_BIN}"

echo "  Compiling tests..."
"${ARM_CC}" -O2 \
    -L"${ARM_SYSROOT_LIB}" \
    -B"${ARM_SYSROOT_LIB}" \
    -o "${TESTS_BIN}" "${TESTS_SRC}"
echo "    -> ${TESTS_BIN}"

echo ""
echo "Build complete. Run with: ./run_arm.sh"
echo "  (requires qemu-arm — sudo apt-get install -y qemu-user)"
