#!/usr/bin/env bash
# HerraduraKEx v1.5.8 — Arduino (AVR) build script
# Compiles the suite and test .ino files to ATmega2560 ELF binaries
# by linking against the Arduino core library.
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

VERSION="1.5.8"

SUITE_INO="Herradura cryptographic suite.ino"
SUITE_ELF="Herradura cryptographic suite_avr.elf"
TESTS_INO="CryptosuiteTests/Herradura_tests.ino"
TESTS_ELF="CryptosuiteTests/Herradura_tests_avr.elf"

MCU="atmega2560"
F_CPU="16000000UL"
ARDUINO_CORE="/usr/share/arduino/hardware/arduino/avr/cores/arduino"
ARDUINO_VARIANT="/usr/share/arduino/hardware/arduino/avr/variants/mega"
BUILD_DIR="/tmp/herr_avr_build"

AVR_FLAGS="-O2 -mmcu=${MCU} -DF_CPU=${F_CPU} -I${ARDUINO_CORE} -I${ARDUINO_VARIANT}"

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
}

# ── build suite and tests ─────────────────────────────────────────────────────
build_ino "${SUITE_INO}" "${SUITE_ELF}" "suite"
echo ""
build_ino "${TESTS_INO}" "${TESTS_ELF}" "tests"

echo ""
echo "Build complete. Run with: ./run_arduino.sh"
echo "  (requires simavr — sudo apt-get install -y simavr)"
