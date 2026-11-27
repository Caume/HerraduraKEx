#!/usr/bin/env bash
# HerraduraKEx — NASM i386 build script
# Assembles the demos (demos/i386/<algorithm>.asm, one program per algorithm
# over the shared demos/i386/core.asm; TODO #425) and the tests from NASM i386
# source using nasm + ld.
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

VERSION="$(sed -nE '1s/.*\(v([0-9]+\.[0-9]+\.[0-9]+)\).*/\1/p' README.md)"  # README title is the one version source
: "${VERSION:=unknown}"
DEMO_DIR="demos/i386"
DEMO_OBJ="/tmp/herr_demo32.o"
DEMO_SRCS=()
for SRC in "${DEMO_DIR}"/*.asm; do
    [ "$(basename "${SRC}")" = "core.asm" ] || DEMO_SRCS+=("${SRC}")
done
if (( ${#DEMO_SRCS[@]} == 0 )); then
    echo "ERROR: no demo programs under ${DEMO_DIR}"; exit 1
fi
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

# ── TODO #234 / #350 gate guard ───────────────────────────────────────────────
# The test harness and (since TODO #350) the suite demo count "[FAIL]" markers
# inside print_str, so every message has to go out through it.  print_str_raw
# skips the counter and exists only for the gate's own verdict lines, which
# carry the marker themselves.
for SRC in "${DEMO_DIR}/core.asm" "${DEMO_SRCS[@]}" "${TESTS_SRC}"; do
    UNGATED=$(grep -n 'call[[:space:]]\+print_str_raw' "${SRC}" | grep -v 'GATE-EXEMPT' || true)
    if [ -n "${UNGATED}" ]; then
        echo "ERROR: ungated print_str_raw call site(s) in ${SRC}:"
        echo "${UNGATED}"
        echo "  Use 'call print_str' so the [FAIL] gate sees the output (TODO #234/#350),"
        echo "  or mark the line GATE-EXEMPT if it must bypass the counter."
        exit 1
    fi
done
echo "  Linker: ${LD}"

# Each demo %includes core.asm, so nasm is told where it is.
echo "  Assembling ${#DEMO_SRCS[@]} demos..."
for SRC in "${DEMO_SRCS[@]}"; do
    BIN="${SRC%.asm}_i386"
    nasm -f elf32 -i "${DEMO_DIR}/" "${SRC}" -o "${DEMO_OBJ}"
    ${LD} -m elf_i386 -o "${BIN}" "${DEMO_OBJ}"
    echo "    -> ${BIN}"
done
rm -f "${DEMO_OBJ}"

echo "  Assembling tests..."
nasm -f elf32 "${TESTS_SRC}" -o "${TESTS_OBJ}"
${LD} -m elf_i386 -o "${TESTS_BIN}" "${TESTS_OBJ}"
rm -f "${TESTS_OBJ}"
echo "    -> ${TESTS_BIN}"

echo ""
echo "Build complete. Run with: ./run_asm_i386.sh"
echo "  (requires qemu-i386 — sudo apt-get install -y qemu-user)"
