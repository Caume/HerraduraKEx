#!/usr/bin/env bash
# HerraduraKEx — Arduino (AVR) build script
# Compiles the demo sketches (demos/arduino/<name>/<name>.ino, one per
# algorithm, over the Herradura32 library; TODO #425) and the test harness to
# ATmega2560 ELF binaries by linking against the Arduino core library.
#
# Target board: Arduino Mega 2560 (ATmega2560, 8 KB SRAM)
# Note: ATmega328P (Uno, 2 KB SRAM) is insufficient — the Ring-LWR
#       polynomial arrays require ~2.5 KB BSS, exceeding its memory.
#
# Dependencies (build):
#   avr-gcc + avr-libc + Arduino core headers
#     sudo apt-get install -y gcc-avr avr-libc arduino-core
#
# Dependencies (run — see run_arduino.sh):
#   simavr
#     sudo apt-get install -y simavr
#
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

VERSION="$(sed -nE '1s/.*\(v([0-9]+\.[0-9]+\.[0-9]+)\).*/\1/p' README.md)"  # README title is the one version source
: "${VERSION:=unknown}"

DEMO_DIR="demos/arduino"
DEMO_LIB="${DEMO_DIR}/libraries/Herradura32/src"
TESTS_INO="CryptosuiteTests/Herradura_tests.ino"
TESTS_ELF="CryptosuiteTests/Herradura_tests_avr.elf"

MCU="atmega2560"
F_CPU="16000000UL"
ARDUINO_CORE="/usr/share/arduino/hardware/arduino/avr/cores/arduino"
ARDUINO_VARIANT="/usr/share/arduino/hardware/arduino/avr/variants/mega"
BUILD_DIR="/tmp/herr_avr_build"

AVR_FLAGS="-O2 -mmcu=${MCU} -DF_CPU=${F_CPU} -I${ARDUINO_CORE} -I${ARDUINO_VARIANT} -I${DEMO_LIB}"

# ── dependency checks ─────────────────────────────────────────────────────────
if ! command -v avr-gcc &>/dev/null; then
    echo "ERROR: avr-gcc not found."
    echo "  Install: sudo apt-get install -y gcc-avr"
    exit 1
fi

if ! command -v avr-g++ &>/dev/null; then
    echo "ERROR: avr-g++ not found."
    echo "  Install: sudo apt-get install -y gcc-avr"
    exit 1
fi

if [ ! -f "${ARDUINO_CORE}/Arduino.h" ]; then
    echo "ERROR: Arduino core headers not found at ${ARDUINO_CORE}"
    echo "  Install: sudo apt-get install -y arduino-core"
    exit 1
fi

if [ ! -f "${ARDUINO_VARIANT}/pins_arduino.h" ]; then
    echo "ERROR: ATmega2560 variant headers not found at ${ARDUINO_VARIANT}"
    echo "  Install: sudo apt-get install -y arduino-core"
    exit 1
fi

# ── build Arduino core library ────────────────────────────────────────────────
echo "=== HerraduraKEx v${VERSION} — Arduino (ATmega2560) build ==="

mkdir -p "${BUILD_DIR}/core"

echo "  Compiling Arduino core (.c)..."
for SRC in "${ARDUINO_CORE}"/*.c; do
    BASE="$(basename "${SRC}" .c)"
    avr-gcc ${AVR_FLAGS} -c -o "${BUILD_DIR}/core/${BASE}.o" "${SRC}"
done

echo "  Compiling Arduino core (.cpp)..."
for SRC in "${ARDUINO_CORE}"/*.cpp; do
    BASE="$(basename "${SRC}" .cpp)"
    avr-g++ ${AVR_FLAGS} -c -o "${BUILD_DIR}/core/${BASE}.o" "${SRC}"
done

echo "  Assembling Arduino core (.S)..."
for SRC in "${ARDUINO_CORE}"/*.S; do
    BASE="$(basename "${SRC}" .S)"
    avr-gcc ${AVR_FLAGS} -x assembler-with-cpp \
        -c -o "${BUILD_DIR}/core/${BASE}.o" "${SRC}"
done

CORE_OBJS=( "${BUILD_DIR}"/core/*.o )

# ── helper: build one .ino target ────────────────────────────────────────────
build_ino() {
    local INO="$1"
    local ELF="$2"
    local LABEL="$3"
    local OBJ="${BUILD_DIR}/$(basename "${INO}" .ino).o"
    local WRAPPER="${BUILD_DIR}/$(basename "${INO}" .ino)_wrap.cpp"

    echo "  Compiling ${LABEL}..."

    # Arduino IDE prepends #include <Arduino.h> before compiling .ino files
    printf '#include <Arduino.h>\n' > "${WRAPPER}"
    cat "${INO}" >> "${WRAPPER}"

    avr-g++ ${AVR_FLAGS} -c -o "${OBJ}" "${WRAPPER}"

    echo "  Linking ${LABEL}..."
    avr-gcc -mmcu="${MCU}" -o "${ELF}" "${OBJ}" "${CORE_OBJS[@]}"

    echo "    -> ${ELF}"
    avr-size "${ELF}" 2>/dev/null || true
    ram_guard "${ELF}" "${LABEL}"
}

# ── TODO #350 RAM guard ───────────────────────────────────────────────────────
# .data and .bss sit at the bottom of the ATmega2560's 8 KB of SRAM and the stack
# grows down towards them, with nothing to stop it.  Until TODO #350 the suite's
# string literals alone took 3.4 KB of .data (a literal without F() is copied to
# RAM at boot), which left ~360 bytes of stack: the demo hung in its first
# HKEX-RNL multiply, silently.  Keep the headroom below in every firmware, and
# put new strings in flash with F().
RAM_BYTES=8192
MIN_STACK_BYTES=2048
ram_guard() {
    local ELF="$1"
    local LABEL="$2"
    local SIZES DATA BSS FREE
    SIZES=$(avr-size "${ELF}" | awk 'NR == 2 { print $2, $3 }')
    read -r DATA BSS <<<"${SIZES}"
    FREE=$(( RAM_BYTES - DATA - BSS ))
    if (( FREE < MIN_STACK_BYTES )); then
        echo "ERROR: ${LABEL}: .data (${DATA}) + .bss (${BSS}) leave ${FREE} bytes of"
        echo "  SRAM for the stack; at least ${MIN_STACK_BYTES} are required (TODO #350)."
        echo "  Move string literals to flash with F(\"...\")."
        exit 1
    fi
    echo "    RAM: ${FREE} of ${RAM_BYTES} bytes left for the stack (guard: >= ${MIN_STACK_BYTES})"
}

# ── build the demos and the tests ─────────────────────────────────────────────
N_DEMOS=0
for INO in "${DEMO_DIR}"/*/*.ino; do
    NAME="$(basename "${INO}" .ino)"
    [ "$(basename "$(dirname "${INO}")")" = "${NAME}" ] || {
        echo "ERROR: ${INO}: an Arduino sketch must sit in a directory of its own name"; exit 1; }
    build_ino "${INO}" "${DEMO_DIR}/${NAME}/${NAME}_avr.elf" "demo ${NAME}"
    N_DEMOS=$((N_DEMOS + 1))
done
(( N_DEMOS > 0 )) || { echo "ERROR: no demo sketches under ${DEMO_DIR}"; exit 1; }
echo ""
build_ino "${TESTS_INO}" "${TESTS_ELF}" "tests"

echo ""
echo "Build complete. Run with: ./run_arduino.sh"
echo "  (requires simavr — sudo apt-get install -y simavr)"
