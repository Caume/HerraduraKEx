#!/usr/bin/env bash
# CliTest/test_aead.sh — HSKE-NL-AEAD enc/dec --aead cross-language interop (TODO #95)
# Covers all 9 producer/consumer pairs across the Python, C, and Go CLIs,
# plus tamper rejection (wrong --ad, wrong key).
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

printf 'ABCDEFGHIJKLMNOPQRSTUVWXYZ012345' > "$TMP/msg.bin"
AD="aead-test-context"

declare -A CLI=( [py]="$PY" [c]="$C" [go]="$GO" )

for enc in py c go; do
    ${CLI[$enc]} enc --algo hske-nla1 --aead --ad "$AD" \
        --key "$TMP/sk.pem" --in "$TMP/msg.bin" --out "$TMP/ct_$enc.pem"
    for dec in py c go; do
        if ${CLI[$dec]} dec --algo hske-nla1 --ad "$AD" \
              --key "$TMP/sk.pem" --in "$TMP/ct_$enc.pem" --out "$TMP/pt_${enc}_${dec}.bin" \
           && cmp -s "$TMP/msg.bin" "$TMP/pt_${enc}_${dec}.bin"; then
            echo "PASS aead $enc-enc -> $dec-dec"; PASS=$((PASS+1))
        else
            echo "FAIL aead $enc-enc -> $dec-dec"; FAIL=$((FAIL+1))
        fi
        # wrong AD must be rejected
        if ${CLI[$dec]} dec --algo hske-nla1 --ad "wrong-ad" \
              --key "$TMP/sk.pem" --in "$TMP/ct_$enc.pem" --out "$TMP/bad.bin" 2>/dev/null; then
            echo "FAIL aead $enc-enc -> $dec-dec accepted wrong --ad"; FAIL=$((FAIL+1))
        else
            echo "PASS aead $enc-enc -> $dec-dec rejects wrong --ad"; PASS=$((PASS+1))
        fi
    done
done

# Wrong key must be rejected (key commitment sanity)
$PY genpkey --algo hkex-gf --out "$TMP/eve.pem"
$PY pkey    --in "$TMP/eve.pem" --pubout --out "$TMP/eve_pub.pem"
$PY kex     --algo hkex-gf --our "$TMP/eve.pem" --their "$TMP/bob_pub.pem" \
            --out "$TMP/sk_eve.pem"
if $PY dec --algo hske-nla1 --ad "$AD" \
      --key "$TMP/sk_eve.pem" --in "$TMP/ct_py.pem" --out "$TMP/bad2.bin" 2>/dev/null; then
    echo "FAIL aead wrong key accepted"; FAIL=$((FAIL+1))
else
    echo "PASS aead wrong key rejected"; PASS=$((PASS+1))
fi

echo
echo "test_aead: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
