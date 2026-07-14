#!/usr/bin/env bash
# HerraduraKEx v1.5.8 — NASM i386 build script
# Assembles the suite and tests from NASM i386 source using nasm + ld.
# Produces static ELF32 binaries runnable under qemu-i386.
#
# Dependencies (build):
#   nasm     — sudo apt-get install -y nasm
#   ld with elf_i386 emulation — one of:
#     x86_64 host : sudo apt-get install -y binutils
#     ARM64 host  : sudo apt-get install -y binutils-x86-64-linux-gnu
#                or sudo apt-get install -y binutils-i686-linux-gnu
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

# Find a linker that actually supports the elf_i386 emulation.
# The native ld on ARM64 hosts only knows aarch64/arm emulations, so we probe
# each candidate rather than assuming presence implies elf_i386 support.
find_i386_linker() {
    local candidates=(
        x86_64-linux-gnu-ld   # binutils-x86-64-linux-gnu  (works on any host arch)
        i686-linux-gnu-ld     # binutils-i686-linux-gnu    (works on any host arch)
        ld                    # system linker (supports elf_i386 on x86_64 hosts only)
    )
    for ld_bin in "${candidates[@]}"; do
        if command -v "${ld_bin}" &>/dev/null; then
            local help_output
            help_output="$("${ld_bin}" --help 2>&1)"
            if grep -q 'elf_i386' <<<"${help_output}"; then
                echo "${ld_bin}"
                return 0
            fi
        fi
    done
    return 1
}

if ! LD=$(find_i386_linker); then
    echo "ERROR: no linker with elf_i386 emulation found."
    echo "  x86_64 host : sudo apt-get install -y binutils"
    echo "  ARM64 host  : sudo apt-get install -y binutils-x86-64-linux-gnu"
    echo "             or sudo apt-get install -y binutils-i686-linux-gnu"
    exit 1
fi

echo "=== HerraduraKEx v${VERSION} — NASM i386 build ==="
echo "  Linker: ${LD}"

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
