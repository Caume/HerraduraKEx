#!/usr/bin/env bash
# HerraduraKEx — Arduino (AVR) run script
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
#   ./run_arduino.sh                   # run every demo, then the tests
#   ./run_arduino.sh suite             # run every demo (demos/arduino/*, TODO #425)
#   ./run_arduino.sh suite hpks        # run the named demo(s) only
#   ./run_arduino.sh tests             # run tests only
#
# TIMEOUT (default 90s): the firmware loops forever, so simavr never exits on
# its own.  Set TIMEOUT=0 to disable (Ctrl-C to stop).  A demo is stopped at
# its first verdict line instead, so twenty of them do not cost twenty
# timeouts; TIMEOUT still bounds one that never prints one.
#
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

DEMO_DIR="demos/arduino"
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

# ── TODO #234 / #350: the [FAIL] gate ────────────────────────────────────────
# The firmware never exits — it loops forever, so simavr runs under `timeout`
# and there is no exit status to propagate.  The harness (TODO #234) and the
# suite demo (TODO #350) therefore print their verdict over the UART at the end
# of every pass, and we read it back here.  Every pass is scored: a FAILED on
# any of them fails the run.
#
# Absence of the OK line is a failure too: a hang, a watchdog reset, or a
# TIMEOUT shorter than one pass all end with no verdict at all, and until this
# check existed every one of them left the `arduino` CI job green.  The suite
# demo is the case in point: until TODO #350 it hung in its first HKEX-RNL
# multiply (its strings filled RAM and the stack ran into .bss), and nothing
# noticed, because nothing ran it.
gate_check() {
    local LOG="$1"
    local LABEL="$2"
    local CLEAN
    CLEAN="$(sed 's/\x1b\[[0-9;]*m//g' "${LOG}")"

    if grep -q '\*\*\* FAILED:' <<<"${CLEAN}"; then
        echo "" >&2
        echo "ERROR: the AVR ${LABEL} reported failing checks (TODO #234/#350):" >&2
        grep '\*\*\* FAILED:' <<<"${CLEAN}" | sort -u | sed 's/^/    /' >&2
        return 1
    fi

    if ! grep -q '\*\*\* OK: no check reported' <<<"${CLEAN}"; then
        echo "" >&2
        echo "ERROR: the AVR ${LABEL} never printed a verdict (TODO #234/#350)." >&2
        echo "  Expected '*** OK: no check reported [FAIL] ***' from at least one" >&2
        echo "  completed pass.  A hang, a reset, or a TIMEOUT (${TIMEOUT}s) shorter" >&2
        echo "  than a single pass all look like this." >&2
        return 1
    fi

    echo "  gate: ${LABEL}: a full pass completed with no [FAIL] (TODO #234/#350)" >&2
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
        gate_check "${LOG}" "${LABEL}" || exit 1
    fi
}

# One demo firmware, stopped at its first verdict: each demo is one pass of
# one algorithm, and the LCG is never reseeded, so a second pass decides
# nothing the first did not.
run_demo() {
    local NAME="$1"
    local ELF="${DEMO_DIR}/${NAME}/${NAME}_avr.elf"
    if [ ! -f "${ELF}" ]; then
        echo "ERROR: ${ELF} not found — run ./build_arduino.sh first."
        exit 1
    fi
    echo "=== Arduino (ATmega2560) — demo ${NAME} ===" >&2
    local LOG PID T=0
    LOG="$(mktemp)"
    simavr -m "${MCU}" -f "${FREQ}" "${ELF}" >"${LOG}" 2>&1 &
    PID=$!
    while kill -0 "${PID}" 2>/dev/null; do
        if sed 's/\x1b\[[0-9;]*m//g' "${LOG}" | grep -q '\*\*\* \(OK: no check reported\|FAILED:\)'; then
            break
        fi
        if (( TIMEOUT > 0 && T >= TIMEOUT * 4 )); then break; fi
        sleep 0.25
        T=$((T + 1))
    done
    kill "${PID}" 2>/dev/null || true
    wait "${PID}" 2>/dev/null || true
    cat "${LOG}" >&2
    gate_check "${LOG}" "demo ${NAME}" || { rm -f "${LOG}"; exit 1; }
    rm -f "${LOG}"
}

run_demos() {
    local NAMES=("$@") D
    if (( ${#NAMES[@]} == 0 )); then
        for D in "${DEMO_DIR}"/*/; do
            D="$(basename "${D}")"
            [ "${D}" = "libraries" ] || NAMES+=("${D}")
        done
    fi
    (( ${#NAMES[@]} > 0 )) || { echo "ERROR: no demos under ${DEMO_DIR}"; exit 1; }
    for D in "${NAMES[@]}"; do run_demo "${D}"; done
    echo "  gate: ${#NAMES[@]} demo(s), each a full pass with no [FAIL] (TODO #425)" >&2
}

MODE="${1:-all}"
shift || true

case "${MODE}" in
    suite)
        run_demos "$@"
        ;;
    tests)
        run_elf "${TESTS_ELF}" "Tests" gate
        ;;
    all|*)
        run_demos
        echo ""
        run_elf "${TESTS_ELF}" "Tests" gate
        ;;
esac
