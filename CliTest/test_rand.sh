#!/usr/bin/env bash
# CliTest/test_rand.sh — HDRBG `rand` deterministic generation, cross-language KAT (TODO #119)
# Covers: determinism, byte-identical KAT, personalization separation,
# reseed-changes-stream, and state checkpoint/resume continuity (incl. cross-language).
#
# FOUR languages since TODO #269 (v6.3.0).  Java shipped Hdrbg.java complete and
# no `rand` subcommand at all, so this file ran 3-wide in a four-language repo and
# nothing said so -- TODO #261's primitive manifest passed here because the
# PRIMITIVE was present, and it took #267's CLI-surface matrix to see that the
# subcommand was not.  Java's column is what makes the cross-state block below a
# real 4x4: the HDRBG STATE PEM is a wire format, and a checkpoint one CLI writes
# must resume in any other.
#
# Java degrades to a NOTE rather than a failure when javac is absent, matching
# test_v3_family.sh; the py/c/go assertions still run.
set -euo pipefail

DIR=$(dirname "$0")
PY="python3 $DIR/../HerraduraCli/herradura.py"
C="$DIR/../HerraduraCli/herradura_cli"
GO="$DIR/../HerraduraCli/herradura_cli_go"
JAVA=""
if command -v javac >/dev/null 2>&1; then
    bash "$DIR/../bindings/java/build.sh" >/dev/null 2>&1
    JAVA="java -cp $DIR/../bindings/java herradurakex.HerraduraCli"
fi
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
PASS=0; FAIL=0

# TODO #229: the compiled CLIs are no longer tracked in git, so this guard is
# live.  It exits non-zero rather than 0 — a skipped run asserted nothing and
# must not read as a pass.  See CliTest/lib_build.sh.
. "$(dirname "$0")/lib_build.sh"
hkx_require_built c go

check() { # check LABEL FILE_A FILE_B  (pass if identical)
    if cmp -s "$2" "$3"; then echo "PASS $1"; PASS=$((PASS+1));
    else echo "FAIL $1"; FAIL=$((FAIL+1)); fi
}
check_differ() { # pass if files DIFFER
    if cmp -s "$2" "$3"; then echo "FAIL $1 (identical, expected differ)"; FAIL=$((FAIL+1));
    else echo "PASS $1"; PASS=$((PASS+1)); fi
}

printf 'this-is-a-fixed-32-byte-seed-12345' > "$TMP/seed.bin"
declare -A CLI=( [py]="$PY" [c]="$C" [go]="$GO" )
IMPLS=(py c go)
if [ -n "$JAVA" ]; then
    CLI[java]="$JAVA"; IMPLS+=(java)
else
    echo "NOTE: java CLI absent (javac not installed) — rand is asserted 3-wide," \
         "not 4-wide; the TODO #269 port is NOT covered by this run."
fi

# Determinism + 3-language KAT (same seed → byte-identical 96-byte hex)
for impl in "${IMPLS[@]}"; do
    ${CLI[$impl]} rand --seed "$TMP/seed.bin" --bytes 96 --hex --out "$TMP/k_$impl.hex"
done
for impl in "${IMPLS[@]}"; do
    [ "$impl" = py ] && continue
    check "rand KAT py==$impl" "$TMP/k_py.hex" "$TMP/k_$impl.hex"
done

# Personalization separation (per language) + cross-language KAT for one pers
for impl in "${IMPLS[@]}"; do
    ${CLI[$impl]} rand --seed "$TMP/seed.bin" --personalization "ctx-A" --bytes 48 --hex --out "$TMP/pa_$impl.hex"
done
for impl in "${IMPLS[@]}"; do
    [ "$impl" = py ] && continue
    check "rand pers KAT py==$impl" "$TMP/pa_py.hex" "$TMP/pa_$impl.hex"
done
check_differ "rand pers vs no-pers" "$TMP/pa_py.hex" "$TMP/k_py.hex"

# State checkpoint/resume continuity, per language: gen 32 + resume 32 == one-shot 64
for impl in "${IMPLS[@]}"; do
    ${CLI[$impl]} rand --seed "$TMP/seed.bin" --state "$TMP/st_$impl.pem" --bytes 32 --out "$TMP/s1_$impl.bin"
    ${CLI[$impl]} rand --state "$TMP/st_$impl.pem" --bytes 32 --out "$TMP/s2_$impl.bin"
    cat "$TMP/s1_$impl.bin" "$TMP/s2_$impl.bin" > "$TMP/s12_$impl.bin"
    ${CLI[$impl]} rand --seed "$TMP/seed.bin" --bytes 64 --out "$TMP/s64_$impl.bin"
    check "rand resume continuity ($impl)" "$TMP/s12_$impl.bin" "$TMP/s64_$impl.bin"
done

# Cross-language state: each producer writes a checkpoint, every consumer resumes it
for prod in "${IMPLS[@]}"; do
    ${CLI[$prod]} rand --seed "$TMP/seed.bin" --state "$TMP/xs_$prod.pem" --bytes 32 --out "$TMP/xs1_$prod.bin"
    for cons in "${IMPLS[@]}"; do
        cp "$TMP/xs_$prod.pem" "$TMP/xs_${prod}_${cons}.pem"
        ${CLI[$cons]} rand --state "$TMP/xs_${prod}_${cons}.pem" --bytes 32 --out "$TMP/xs2_${prod}_${cons}.bin"
        cat "$TMP/xs1_$prod.bin" "$TMP/xs2_${prod}_${cons}.bin" > "$TMP/xs12_${prod}_${cons}.bin"
        check "rand cross-state $prod->$cons" "$TMP/xs12_${prod}_${cons}.bin" "$TMP/s64_py.bin"
    done
done

# The HDRBG STATE PEM is a wire artifact, so every writer must emit the SAME
# bytes for the same checkpoint -- not merely bytes the others happen to parse.
# A writer that encoded `blocks` at a different DER width would resume correctly
# everywhere and still be producing a different file.
for prod in "${IMPLS[@]}"; do
    [ "$prod" = py ] && continue
    check "rand state PEM bytes py==$prod" "$TMP/xs_py.pem" "$TMP/xs_$prod.pem"
done

# Reseed changes the stream
for impl in "${IMPLS[@]}"; do
    ${CLI[$impl]} rand --seed "$TMP/seed.bin" --state "$TMP/rs_$impl.pem" --bytes 0 --out /dev/null 2>/dev/null \
        || ${CLI[$impl]} rand --seed "$TMP/seed.bin" --state "$TMP/rs_$impl.pem" --bytes 1 --out /dev/null
    cp "$TMP/rs_$impl.pem" "$TMP/rs2_$impl.pem"
    printf 'extra-entropy' > "$TMP/re.bin"
    ${CLI[$impl]} rand --state "$TMP/rs2_$impl.pem" --reseed "$TMP/re.bin" --bytes 32 --out "$TMP/after_$impl.bin"
    ${CLI[$impl]} rand --state "$TMP/rs_$impl.pem" --bytes 32 --out "$TMP/noreseed_$impl.bin"
    check_differ "rand reseed-changes-stream ($impl)" "$TMP/after_$impl.bin" "$TMP/noreseed_$impl.bin"
done

# Error paths must agree across all four.  These were never asserted, and Go's
# `--bytes -1` diverged for years because -1 was doing double duty as its
# "not given" sentinel: it reported "nothing to do" where the other three report
# "--bytes must be non-negative" (TODO #269 fixed it via the file's own isSet).
# A wrong-but-plausible diagnostic is exactly what nobody notices by hand.
check_msg() { # check_msg LABEL EXPECTED_SUBSTRING -- CMD...
    local label="$1" want="$2"; shift 3
    local got
    got=$("$@" 2>&1 | tail -1) || true
    if [ "${got#*"$want"}" != "$got" ]; then echo "PASS $label"; PASS=$((PASS+1));
    else echo "FAIL $label (got: $got)"; FAIL=$((FAIL+1)); fi
}
for impl in "${IMPLS[@]}"; do
    check_msg "rand err no-seed-no-state ($impl)" "one of --seed or --state is required" -- \
        ${CLI[$impl]} rand --bytes 8
    check_msg "rand err nothing-to-do ($impl)" "nothing to do" -- \
        ${CLI[$impl]} rand --seed "$TMP/seed.bin"
    check_msg "rand err negative-bytes ($impl)" "--bytes must be non-negative" -- \
        ${CLI[$impl]} rand --seed "$TMP/seed.bin" --bytes -1
done

echo
echo "test_rand: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
