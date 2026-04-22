#!/usr/bin/env bash
# HerraduraKEx v1.5.8 — NASM i386 build script
# Assembles the suite and tests from NASM i386 source using nasm + ld.
# Produces static ELF32 binaries runnable under qemu-i386.
#
# Dependencies (build):
#   nasm     — sudo apt-get install -y nasm
#   ld       — sudo apt-get install -y binutils
#
# Dependencies (run — see run_asm_i386.sh):
#   qemu-i386
#     sudo apt-get install -y qemu-user
#
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

VERSION="1.5.8"
SUITE_SRC="Herradura cryptographic suite.asm"
SUITE_OBJ="/tmp/herr_suite32.o"
SUITE_BIN="Herradura cryptographic suite_i386"
TESTS_SRC="CryptosuiteTests/Herradura_tests.asm"
TESTS_OBJ="/tmp/herr_tests32.o"
TESTS_BIN="CryptosuiteTests/Herradura_tests_i386"

# ── dependency checks ─────────────────────────────────────────────────────────
if ! command -v nasm &>/dev/null; then
    echo "ERROR: nasm not found."
    echo "  Install: sudo apt-get install -y nasm"
    exit 1
fi

if ! command -v x86_64-linux-gnu-ld &>/dev/null && ! command -v ld &>/dev/null; then
    echo "ERROR: linker (ld / x86_64-linux-gnu-ld) not found."
    echo "  Install: sudo apt-get install -y binutils"
    exit 1
fi

# Prefer the explicit cross linker; fall back to system ld if capable
if command -v x86_64-linux-gnu-ld &>/dev/null; then
    LD="x86_64-linux-gnu-ld"
else
    LD="ld"
fi

echo "=== HerraduraKEx v${VERSION} — NASM i386 build ==="

echo "  Assembling suite..."
nasm -f elf32 "${SUITE_SRC}" -o "${SUITE_OBJ}"
${LD} -m elf_i386 -o "${SUITE_BIN}" "${SUITE_OBJ}"
rm -f "${SUITE_OBJ}"
echo "    -> ${SUITE_BIN}"

echo "  Assembling tests..."
nasm -f elf32 "${TESTS_SRC}" -o "${TESTS_OBJ}"
${LD} -m elf_i386 -o "${TESTS_BIN}" "${TESTS_OBJ}"
rm -f "${TESTS_OBJ}"
echo "    -> ${TESTS_BIN}"

echo ""
echo "Build complete. Run with: ./run_asm_i386.sh"
echo "  (requires qemu-i386 — sudo apt-get install -y qemu-user)"
