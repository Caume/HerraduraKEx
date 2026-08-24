#!/usr/bin/env bash
# HerraduraKEx v1.6.1 — Arduino (AVR) run script
# Runs the ATmega2560 ELF binaries under simavr (AVR cycle-accurate emulator).
# Output appears on the emulated UART0; simavr writes it to stderr with ANSI
# color codes.  Both firmware UART output and simavr status lines go to stderr.
#
# Dependencies:
#   simavr   — sudo apt-get install -y simavr
#
# Build first with: ./build_arduino.sh
#
# Usage:
#   ./run_arduino.sh                   # run suite then tests
#   ./run_arduino.sh suite             # run suite only
#   ./run_arduino.sh tests             # run tests only
#
# TIMEOUT (default 90s): the firmware loops forever, so simavr never exits on
# its own.  Set TIMEOUT=0 to disable (Ctrl-C to stop).
#
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

SUITE_ELF="Herradura cryptographic suite_avr.elf"
TESTS_ELF="CryptosuiteTests/Herradura_tests_avr.elf"
MCU="atmega2560"
FREQ="16000000"
TIMEOUT="${TIMEOUT:-90}"

# ── dependency check ──────────────────────────────────────────────────────────
if ! command -v simavr &>/dev/null; then
    echo "ERROR: simavr not found."
    echo "  Install: sudo apt-get install -y simavr"
    exit 1
fi

# ── TODO #234: the [FAIL] gate ───────────────────────────────────────────────
# The firmware never exits — it loops forever, so simavr runs under `timeout`
# and there is no exit status to propagate.  The harness therefore prints its
# verdict over the UART at the end of every pass, and we read it back here.
#
# Absence of the OK line is a failure too: a hang, a watchdog reset, or a
# TIMEOUT shorter than one pass all end with no verdict at all, and until this
# check existed every one of them left the `arduino` CI job green.
gate_check() {
    local LOG="$1"
    local CLEAN
    CLEAN="$(sed 's/\x1b\[[0-9;]*m//g' "${LOG}")"

    if grep -q '\*\*\* FAILED:' <<<"${CLEAN}"; then
        echo "" >&2
        echo "ERROR: the AVR test harness reported failing checks (TODO #234):" >&2
        grep '\*\*\* FAILED:' <<<"${CLEAN}" | sort -u | sed 's/^/    /' >&2
        return 1
    fi

    if ! grep -q '\*\*\* OK: no check reported' <<<"${CLEAN}"; then
        echo "" >&2
        echo "ERROR: the AVR test harness never printed a verdict (TODO #234)." >&2
        echo "  Expected '*** OK: no check reported [FAIL] ***' from at least one" >&2
        echo "  completed pass.  A hang, a reset, or a TIMEOUT (${TIMEOUT}s) shorter" >&2
        echo "  than a single pass all look like this." >&2
        return 1
    fi

    echo "  gate: a full pass completed with no [FAIL] (TODO #234)" >&2
}

run_elf() {
    local ELF="$1"
    local LABEL="$2"
    local GATE="${3:-nogate}"
    if [ ! -f "${ELF}" ]; then
        echo "ERROR: ${ELF} not found — run ./build_arduino.sh first."
        exit 1
    fi
    echo "=== Arduino (ATmega2560) — ${LABEL} ===" >&2

    local LOG
    LOG="$(mktemp)"
    # shellcheck disable=SC2064
    trap "rm -f '${LOG}'" RETURN

    if (( TIMEOUT > 0 )); then
        timeout "${TIMEOUT}" simavr -m "${MCU}" -f "${FREQ}" "${ELF}" 2>&1 \
            | tee "${LOG}" >&2 || true
    else
        simavr -m "${MCU}" -f "${FREQ}" "${ELF}" 2>&1 | tee "${LOG}" >&2
    fi

    if [ "${GATE}" = "gate" ]; then
        gate_check "${LOG}" || exit 1
    fi
}

MODE="${1:-all}"

case "${MODE}" in
    suite)
        run_elf "${SUITE_ELF}" "Suite"
        ;;
    tests)
        run_elf "${TESTS_ELF}" "Tests" gate
        ;;
    all|*)
        run_elf "${SUITE_ELF}" "Suite"
        echo ""
        run_elf "${TESTS_ELF}" "Tests" gate
        ;;
esac
