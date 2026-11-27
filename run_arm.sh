#!/usr/bin/env bash
# HerraduraKEx v1.5.8 — ARM Thumb-2 run script
# Runs the demo and test binaries under qemu-arm (user-mode emulation).
#
# Dependencies:
#   qemu-arm   — sudo apt-get install -y qemu-user
#
# Build first with: ./build_arm.sh
#
# Usage:
#   ./run_arm.sh                         # run every demo, then the tests
#   ./run_arm.sh suite                   # run every demo (demos/arm/*, TODO #425)
#   ./run_arm.sh suite hpks hske         # run the named demo(s) only
#   ./run_arm.sh tests [-r N] [-t S]     # run tests
#
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

DEMO_DIR="demos/arm"
TESTS_BIN="CryptosuiteTests/Herradura_tests_arm"
ARM_SYSROOT="/usr/arm-linux-gnueabi"

# ── dependency check ──────────────────────────────────────────────────────────
if ! command -v qemu-arm &>/dev/null; then
    echo "ERROR: qemu-arm not found."
    echo "  Install: sudo apt-get install -y qemu-user"
    exit 1
fi

if [ ! -f "${TESTS_BIN}" ]; then
    echo "ERROR: binaries not found — run ./build_arm.sh first."
    exit 1
fi


# Every demo is gated on its own: exit status 0 AND the OK line, so a crash, a
# [FAIL] or a demo that stops early all fail the run (TODO #350, #425).
run_demos() {
    local NAMES=("$@") N BIN OUT RC FAILED=0
    if (( ${#NAMES[@]} == 0 )); then
        for BIN in "${DEMO_DIR}"/*_arm; do
            [ -e "${BIN}" ] && NAMES+=("$(basename "${BIN}" _arm)")
        done
    fi
    if (( ${#NAMES[@]} == 0 )); then
        echo "ERROR: no demo binaries in ${DEMO_DIR} — run ./build_arm.sh first."
        exit 1
    fi
    for N in "${NAMES[@]}"; do
        BIN="${DEMO_DIR}/${N}_arm"
        [ -f "${BIN}" ] || { echo "ERROR: ${BIN} not found — build first."; exit 1; }
        echo "=== ARM Thumb-2 — demo ${N} ==="
        set +e
        OUT="$(qemu-arm -L "${ARM_SYSROOT}" "./${BIN}" 2>&1)"
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
        echo "=== ARM Thumb-2 — Tests ==="
        qemu-arm -L "${ARM_SYSROOT}" "./${TESTS_BIN}" "$@"
        ;;
    all|*)
        run_demos
        echo ""
        echo "=== ARM Thumb-2 — Tests ==="
        qemu-arm -L "${ARM_SYSROOT}" "./${TESTS_BIN}" "$@"
        ;;
esac
