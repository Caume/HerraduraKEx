#!/usr/bin/env bash
# CliTest/test_duplex.sh — HSKE-NL-V2-Duplex AEAD enc/dec cross-language interop (TODO #118)
# Covers all 9 producer/consumer pairs across the Python, C, and Go CLIs, plus
# tamper rejection (wrong --ad, wrong key, mutated ciphertext), a multi-block
# arbitrary-length message, and an empty-plaintext round-trip.
set -euo pipefail

DIR=$(dirname "$0")
PY="python3 $DIR/../HerraduraCli/herradura.py"
C="$DIR/../HerraduraCli/herradura_cli"
GO="$DIR/../HerraduraCli/herradura_cli_go"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
PASS=0; FAIL=0

for bin in "$DIR/../HerraduraCli/herradura_cli" "$DIR/../HerraduraCli/herradura_cli_go"; do
    if [ ! -x "$bin" ]; then
        echo "SKIP: $bin not built (run build_c.sh / build_go.sh)"; exit 0
    fi
done

# Shared 256-bit symmetric key via HKEX-GF
$PY genpkey --algo hkex-gf --out "$TMP/alice.pem"
$PY pkey    --in "$TMP/alice.pem" --pubout --out "$TMP/alice_pub.pem"
$PY genpkey --algo hkex-gf --out "$TMP/bob.pem"
$PY pkey    --in "$TMP/bob.pem"   --pubout --out "$TMP/bob_pub.pem"
$PY kex     --algo hkex-gf --our "$TMP/alice.pem" --their "$TMP/bob_pub.pem" \
            --out "$TMP/sk.pem"

# Arbitrary-length, multi-block plaintext (the duplex AEAD's whole point)
printf 'HSKE-NL-V2-Duplex single-pass AEAD: arbitrary-length message spanning multiple 16-byte rate blocks (well over 32 bytes).' > "$TMP/msg.bin"
AD="duplex-test-context"

declare -A CLI=( [py]="$PY" [c]="$C" [go]="$GO" )

for enc in py c go; do
    ${CLI[$enc]} enc --algo hske-duplex --ad "$AD" \
        --key "$TMP/sk.pem" --in "$TMP/msg.bin" --out "$TMP/ct_$enc.pem"
    for dec in py c go; do
        if ${CLI[$dec]} dec --algo hske-duplex --ad "$AD" \
              --key "$TMP/sk.pem" --in "$TMP/ct_$enc.pem" --out "$TMP/pt_${enc}_${dec}.bin" \
           && cmp -s "$TMP/msg.bin" "$TMP/pt_${enc}_${dec}.bin"; then
            echo "PASS duplex $enc-enc -> $dec-dec"; PASS=$((PASS+1))
        else
            echo "FAIL duplex $enc-enc -> $dec-dec"; FAIL=$((FAIL+1))
        fi
        # wrong AD must be rejected
        if ${CLI[$dec]} dec --algo hske-duplex --ad "wrong-ad" \
              --key "$TMP/sk.pem" --in "$TMP/ct_$enc.pem" --out "$TMP/bad.bin" 2>/dev/null; then
            echo "FAIL duplex $enc-enc -> $dec-dec accepted wrong --ad"; FAIL=$((FAIL+1))
        else
            echo "PASS duplex $enc-enc -> $dec-dec rejects wrong --ad"; PASS=$((PASS+1))
        fi
    done
done

# Empty-plaintext round-trip (each producer -> Python consumer)
: > "$TMP/empty.bin"
for enc in py c go; do
    ${CLI[$enc]} enc --algo hske-duplex --ad "$AD" \
        --key "$TMP/sk.pem" --in "$TMP/empty.bin" --out "$TMP/ect_$enc.pem"
    if $PY dec --algo hske-duplex --ad "$AD" \
          --key "$TMP/sk.pem" --in "$TMP/ect_$enc.pem" --out "$TMP/ept_$enc.bin" \
       && cmp -s "$TMP/empty.bin" "$TMP/ept_$enc.bin"; then
        echo "PASS duplex empty-pt $enc-enc -> py-dec"; PASS=$((PASS+1))
    else
        echo "FAIL duplex empty-pt $enc-enc -> py-dec"; FAIL=$((FAIL+1))
    fi
done

# Mutated ciphertext must be rejected: flip a base64 char in the PEM body
$PY enc --algo hske-duplex --ad "$AD" --key "$TMP/sk.pem" --in "$TMP/msg.bin" --out "$TMP/ct_mut.pem"
awk 'NR==2{ c=substr($0,1,1); n=(c=="A"?"B":"A"); print n substr($0,2); next } {print}' \
    "$TMP/ct_mut.pem" > "$TMP/ct_mut2.pem"
if $PY dec --algo hske-duplex --ad "$AD" \
      --key "$TMP/sk.pem" --in "$TMP/ct_mut2.pem" --out "$TMP/bad_mut.bin" 2>/dev/null; then
    echo "FAIL duplex mutated ciphertext accepted"; FAIL=$((FAIL+1))
else
    echo "PASS duplex mutated ciphertext rejected"; PASS=$((PASS+1))
fi

# Wrong key must be rejected
$PY genpkey --algo hkex-gf --out "$TMP/eve.pem"
$PY pkey    --in "$TMP/eve.pem" --pubout --out "$TMP/eve_pub.pem"
$PY kex     --algo hkex-gf --our "$TMP/eve.pem" --their "$TMP/bob_pub.pem" \
            --out "$TMP/sk_eve.pem"
if $PY dec --algo hske-duplex --ad "$AD" \
      --key "$TMP/sk_eve.pem" --in "$TMP/ct_py.pem" --out "$TMP/bad2.bin" 2>/dev/null; then
    echo "FAIL duplex wrong key accepted"; FAIL=$((FAIL+1))
else
    echo "PASS duplex wrong key rejected"; PASS=$((PASS+1))
fi

echo
echo "test_duplex: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
