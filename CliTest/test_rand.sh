#!/usr/bin/env bash
# CliTest/test_rand.sh — HDRBG `rand` deterministic generation, cross-language KAT (TODO #119)
# Covers: determinism, Python/C/Go byte-identical KAT, personalization separation,
# reseed-changes-stream, and state checkpoint/resume continuity (incl. cross-language).
set -euo pipefail

DIR=$(dirname "$0")
PY="python3 $DIR/../HerraduraCli/herradura.py"
C="$DIR/../HerraduraCli/herradura_cli"
GO="$DIR/../HerraduraCli/herradura_cli_go"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
PASS=0; FAIL=0

for bin in "$C" "$GO"; do
    if [ ! -x "$bin" ]; then
        echo "SKIP: $bin not built (run build_c.sh / build_go.sh)"; exit 0
    fi
done

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

# Determinism + 3-language KAT (same seed → byte-identical 96-byte hex)
for impl in py c go; do
    ${CLI[$impl]} rand --seed "$TMP/seed.bin" --bytes 96 --hex --out "$TMP/k_$impl.hex"
done
check "rand KAT py==c" "$TMP/k_py.hex" "$TMP/k_c.hex"
check "rand KAT py==go" "$TMP/k_py.hex" "$TMP/k_go.hex"

# Personalization separation (per language) + cross-language KAT for one pers
for impl in py c go; do
    ${CLI[$impl]} rand --seed "$TMP/seed.bin" --personalization "ctx-A" --bytes 48 --hex --out "$TMP/pa_$impl.hex"
done
check        "rand pers KAT py==c"  "$TMP/pa_py.hex" "$TMP/pa_c.hex"
check        "rand pers KAT py==go" "$TMP/pa_py.hex" "$TMP/pa_go.hex"
check_differ "rand pers vs no-pers" "$TMP/pa_py.hex" "$TMP/k_py.hex"

# State checkpoint/resume continuity, per language: gen 32 + resume 32 == one-shot 64
for impl in py c go; do
    ${CLI[$impl]} rand --seed "$TMP/seed.bin" --state "$TMP/st_$impl.pem" --bytes 32 --out "$TMP/s1_$impl.bin"
    ${CLI[$impl]} rand --state "$TMP/st_$impl.pem" --bytes 32 --out "$TMP/s2_$impl.bin"
    cat "$TMP/s1_$impl.bin" "$TMP/s2_$impl.bin" > "$TMP/s12_$impl.bin"
    ${CLI[$impl]} rand --seed "$TMP/seed.bin" --bytes 64 --out "$TMP/s64_$impl.bin"
    check "rand resume continuity ($impl)" "$TMP/s12_$impl.bin" "$TMP/s64_$impl.bin"
done

# Cross-language state: each producer writes a checkpoint, every consumer resumes it
for prod in py c go; do
    ${CLI[$prod]} rand --seed "$TMP/seed.bin" --state "$TMP/xs_$prod.pem" --bytes 32 --out "$TMP/xs1_$prod.bin"
    for cons in py c go; do
        cp "$TMP/xs_$prod.pem" "$TMP/xs_${prod}_${cons}.pem"
        ${CLI[$cons]} rand --state "$TMP/xs_${prod}_${cons}.pem" --bytes 32 --out "$TMP/xs2_${prod}_${cons}.bin"
        cat "$TMP/xs1_$prod.bin" "$TMP/xs2_${prod}_${cons}.bin" > "$TMP/xs12_${prod}_${cons}.bin"
        check "rand cross-state $prod->$cons" "$TMP/xs12_${prod}_${cons}.bin" "$TMP/s64_py.bin"
    done
done

# Reseed changes the stream
for impl in py c go; do
    ${CLI[$impl]} rand --seed "$TMP/seed.bin" --state "$TMP/rs_$impl.pem" --bytes 0 --out /dev/null 2>/dev/null \
        || ${CLI[$impl]} rand --seed "$TMP/seed.bin" --state "$TMP/rs_$impl.pem" --bytes 1 --out /dev/null
    cp "$TMP/rs_$impl.pem" "$TMP/rs2_$impl.pem"
    printf 'extra-entropy' > "$TMP/re.bin"
    ${CLI[$impl]} rand --state "$TMP/rs2_$impl.pem" --reseed "$TMP/re.bin" --bytes 32 --out "$TMP/after_$impl.bin"
    ${CLI[$impl]} rand --state "$TMP/rs_$impl.pem" --bytes 32 --out "$TMP/noreseed_$impl.bin"
    check_differ "rand reseed-changes-stream ($impl)" "$TMP/after_$impl.bin" "$TMP/noreseed_$impl.bin"
done

echo
echo "test_rand: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
