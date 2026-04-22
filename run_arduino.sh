#!/usr/bin/env bash
# HerraduraKEx v1.5.8 — Arduino (AVR) run script
# Runs the ATmega2560 ELF binaries under simavr (AVR cycle-accurate emulator).
# Output appears on the emulated UART0 (simavr maps it to stdout).
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
# Note: simavr exits automatically when the firmware calls exit() or loops
#       forever after the last Serial.print.  If it hangs, Ctrl-C to stop.
#
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

SUITE_ELF="Herradura cryptographic suite_avr.elf"
TESTS_ELF="CryptosuiteTests/Herradura_tests_avr.elf"
MCU="atmega2560"
FREQ="16000000"

# ── dependency check ──────────────────────────────────────────────────────────
if ! command -v simavr &>/dev/null; then
    echo "ERROR: simavr not found."
    echo "  Install: sudo apt-get install -y simavr"
    exit 1
fi

run_elf() {
    local ELF="$1"
    local LABEL="$2"
    if [ ! -f "${ELF}" ]; then
        echo "ERROR: ${ELF} not found — run ./build_arduino.sh first."
        exit 1
    fi
    echo "=== Arduino (ATmega2560) — ${LABEL} ==="
    simavr -m "${MCU}" -f "${FREQ}" "${ELF}" 2>/dev/null
}

MODE="${1:-all}"

case "${MODE}" in
    suite)
        run_elf "${SUITE_ELF}" "Suite"
        ;;
    tests)
        run_elf "${TESTS_ELF}" "Tests"
        ;;
    all|*)
        run_elf "${SUITE_ELF}" "Suite"
        echo ""
        run_elf "${TESTS_ELF}" "Tests"
        ;;
esac
