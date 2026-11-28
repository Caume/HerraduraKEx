#!/usr/bin/env bash
# tools/check_arduino_cli.sh — TODO #427 item 2: the Arduino IDE path.
#
# build_arduino.sh compiles the demos with raw avr-g++ and -I flags, which is not
# how a user builds them.  The Arduino IDE (and arduino-cli) finds the shared
# code as a LIBRARY: demos/arduino/libraries/Herradura32, with its
# library.properties and src/Herradura32.h.  This compiles every sketch
# demos/arduino/<name>/<name>.ino the way the IDE would, for the Mega 2560:
#
#   arduino-cli compile --fqbn arduino:avr:mega --libraries demos/arduino/libraries
#
# and fails on any sketch that does not build.
#
# CONTROL, shown to fire: the first sketch compiled WITHOUT --libraries must
# fail, so it is the library path, not a stray copy elsewhere, that resolves
# Herradura32.h.
#
# Needs arduino-cli with the arduino:avr core (`arduino-cli core install
# arduino:avr`).  Without them nothing is asserted, and the script exits 2.
# Run by ci.yml's arduino job.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

FQBN="${FQBN:-arduino:avr:mega}"
LIBS="demos/arduino/libraries"
if ! command -v arduino-cli >/dev/null 2>&1; then
    echo "check_arduino_cli: arduino-cli not found; nothing checked" >&2; exit 2
fi
if ! arduino-cli core list 2>/dev/null | grep -q '^arduino:avr '; then
    echo "check_arduino_cli: the arduino:avr core is not installed" \
         "(arduino-cli core install arduino:avr); nothing checked" >&2; exit 2
fi

TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
sketches=()
for d in demos/arduino/*/; do
    n=$(basename "$d")
    [ "$n" = libraries ] && continue
    [ -f "$d$n.ino" ] && sketches+=("$n")
done
if [ ${#sketches[@]} -eq 0 ]; then
    echo "check_arduino_cli: no sketches under demos/arduino" >&2; exit 1
fi

PASS=0; FAIL=0
for n in "${sketches[@]}"; do
    if arduino-cli compile --fqbn "$FQBN" --libraries "$LIBS" --build-path "$TMP/$n" \
            "demos/arduino/$n" >"$TMP/$n.log" 2>&1; then
        echo "  [PASS] $n compiles for $FQBN"; PASS=$((PASS + 1))
    else
        echo "  [FAIL] $n does not compile for $FQBN:"; tail -15 "$TMP/$n.log" | sed 's/^/      /'
        FAIL=$((FAIL + 1))
    fi
done

c="${sketches[0]}"
if arduino-cli compile --fqbn "$FQBN" --build-path "$TMP/ctl" "demos/arduino/$c" \
        >"$TMP/ctl.log" 2>&1; then
    echo "  [FAIL] CONTROL: $c compiled WITHOUT --libraries, so the check does not" \
         "show that the library resolves Herradura32.h"; FAIL=$((FAIL + 1))
elif grep -q 'Herradura32.h' "$TMP/ctl.log"; then
    echo "  [PASS] CONTROL: $c without --libraries fails on Herradura32.h"; PASS=$((PASS + 1))
else
    echo "  [FAIL] CONTROL: $c without --libraries failed, but not on Herradura32.h:"
    tail -10 "$TMP/ctl.log" | sed 's/^/      /'; FAIL=$((FAIL + 1))
fi

echo
echo "check_arduino_cli: $PASS passed, $FAIL failed (${#sketches[@]} sketches)"
if [ $FAIL -ne 0 ]; then
    echo "*** FAILED: $FAIL ***"; exit 1
fi
echo "*** OK: every demo sketch builds as an Arduino IDE sketch over the Herradura32 library ***"
