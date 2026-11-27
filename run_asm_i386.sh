#!/usr/bin/env bash
# HerraduraKEx v1.5.8 — NASM i386 run script
# Runs the demo and test binaries under qemu-i386 (user-mode emulation).
#
# Dependencies:
#   qemu-i386   — sudo apt-get install -y qemu-user
#
# Build first with: ./build_asm_i386.sh
#
# Usage:
#   ./run_asm_i386.sh                         # run every demo, then the tests
#   ./run_asm_i386.sh suite                   # run every demo (demos/i386/*, TODO #425)
#   ./run_asm_i386.sh suite hpks hske         # run the named demo(s) only
#   ./run_asm_i386.sh tests [-r N] [-t S]     # run tests
#
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

DEMO_DIR="demos/i386"
TESTS_BIN="CryptosuiteTests/Herradura_tests_i386"

# ── dependency check ──────────────────────────────────────────────────────────
if ! command -v qemu-i386 &>/dev/null; then
    echo "ERROR: qemu-i386 not found."
    echo "  Install: sudo apt-get install -y qemu-user"
    exit 1
fi

if [ ! -f "${TESTS_BIN}" ]; then
    echo "ERROR: binaries not found — run ./build_asm_i386.sh first."
    exit 1
fi


# Every demo is gated on its own: exit status 0 AND the OK line, so a crash, a
# [FAIL] or a demo that stops early all fail the run (TODO #350, #425).
run_demos() {
    local NAMES=("$@") N BIN OUT RC FAILED=0
    if (( ${#NAMES[@]} == 0 )); then
        for BIN in "${DEMO_DIR}"/*_i386; do
            [ -e "${BIN}" ] && NAMES+=("$(basename "${BIN}" _i386)")
        done
    fi
    if (( ${#NAMES[@]} == 0 )); then
        echo "ERROR: no demo binaries in ${DEMO_DIR} — run ./build_asm_i386.sh first."
        exit 1
    fi
    for N in "${NAMES[@]}"; do
        BIN="${DEMO_DIR}/${N}_i386"
        [ -f "${BIN}" ] || { echo "ERROR: ${BIN} not found — build first."; exit 1; }
        echo "=== NASM i386 — demo ${N} ==="
        set +e
        OUT="$(qemu-i386 "./${BIN}" 2>&1)"
        RC=$?
        set -e
        printf '%s\n' "${OUT}"
        if (( RC != 0 )) || ! grep -q '\*\*\* OK: no check reported' <<<"${OUT}"; then
            echo "ERROR: demo ${N} failed (exit ${RC})" >&2
            FAILED=$((FAILED + 1))
        fi
        echo ""
    done
    if (( FAILED > 0 )); then
        echo "*** ${FAILED} of ${#NAMES[@]} demo(s) FAILED ***"
        exit 1
    fi
    echo "*** all ${#NAMES[@]} demo(s) passed ***"
}

MODE="${1:-all}"
shift || true

case "${MODE}" in
    suite)
        run_demos "$@"
        ;;
    tests)
        echo "=== NASM i386 — Tests ==="
        qemu-i386 "./${TESTS_BIN}"
        ;;
    all|*)
        run_demos
        echo ""
        echo "=== NASM i386 — Tests ==="
        qemu-i386 "./${TESTS_BIN}"
        ;;
esac
