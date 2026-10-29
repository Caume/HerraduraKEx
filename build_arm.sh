#!/usr/bin/env bash
# HerraduraKEx v1.5.8 — ARM Thumb-2 build script
# Cross-compiles the suite and tests from ARM Thumb-2 assembly using
# arm-linux-gnueabi-gcc.  Produces ELF binaries runnable under qemu-arm.
#
# Dependencies (build):
#   arm-linux-gnueabi-gcc + ARM sysroot
#     sudo apt-get install -y gcc-arm-linux-gnueabi libc6-dev-armel-cross
#   (libc6-armel-cross alone is runtime-only — no crt1.o/headers to link
#    against; libc6-dev-armel-cross is the actual cross-dev package, found
#    via TODO #139's Docker quickstart work)
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
    echo "  Install: sudo apt-get install -y libc6-dev-armel-cross"
    exit 1
fi

echo "=== HerraduraKEx v${VERSION} — ARM Thumb-2 build ==="

# ── TODO #234 gate guard ──────────────────────────────────────────────────────
# The test harness counts "[FAIL]" markers inside hprintf, so every printf call
# site has to route through it.  A bare `bl printf` silently leaves its output
# ungated; the three that legitimately need one are marked GATE-EXEMPT.
UNGATED=$(grep -n 'bl[[:space:]]\+printf' "${TESTS_SRC}" | grep -v 'GATE-EXEMPT' || true)
if [ -n "${UNGATED}" ]; then
    echo "ERROR: ungated printf call site(s) in ${TESTS_SRC}:"
    echo "${UNGATED}"
    echo "  Use 'bl hprintf' so the [FAIL] gate sees the output (TODO #234),"
    echo "  or mark the line GATE-EXEMPT if it must bypass the counter."
    exit 1
fi

# ── TODO #349 IT-flag guard ───────────────────────────────────────────────────
# Under .syntax unified a plain `sub` / `add` / ... assembles to the .W form,
# which does NOT set the flags, so an IT block straight after it tests whatever
# an earlier instruction left.  rnl_poly_mul's and rnl_ntt's `sub; it mi; addmi #q`
# reductions did exactly that: c*s came out wrong and the ZKP-RNL signer rejected
# all 200 attempts, while HKEX-RNL -- both parties sharing the same multiply --
# still agreed.  Use the S form, or mark the line FLAGS-OK if the flags an IT
# reads really are an earlier instruction's.
for SRC in "${SUITE_SRC}" "${TESTS_SRC}"; do
    STALE=$(awk -v F="${SRC}" '
        prev ~ /^[[:space:]]+(add|sub|rsb|adc|sbc|and|orr|eor|bic|lsl|lsr|asr|ror|mul|mov|mvn|uxth|uxtb|ldr|str)[[:space:]]/ &&
        prev !~ /FLAGS-OK/ && $0 ~ /^[[:space:]]+it[te]*[[:space:]]+[a-z][a-z]/ {
            print F ":" NR-1 ": " prev
        }
        { prev = $0 }' "${SRC}")
    if [ -n "${STALE}" ]; then
        echo "ERROR: an IT block reads flags the instruction before it does not set:"
        echo "${STALE}"
        echo "  Use the flag-setting form (subs, adds, ...) or mark it FLAGS-OK (TODO #349)."
        exit 1
    fi
done

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
