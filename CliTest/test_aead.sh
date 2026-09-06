#!/usr/bin/env bash
# CliTest/test_aead.sh — HSKE-NL-AEAD enc/dec --aead cross-language interop (TODO #95)
# Covers all 16 producer/consumer pairs across the Python, C, Go and Java CLIs,
# plus tamper rejection (wrong --ad, flipped auth tag, flipped ciphertext,
# wrong key).
#
# Java joined in TODO #273, which took the matrix from 9 pairs to 16.  It was
# not CLI wiring: bindings/java/ had no AEAD primitive at all, and `enc --aead`
# silently wrote format tag 1 — plain, UNAUTHENTICATED HSKE-NL-A1 — with exit 0
# until TODO #274 made it refuse the flag by name.  So the direction that
# matters most here is java-enc -> {py,c,go}-dec: it is the one that would have
# produced an unauthenticated artifact the other three read as authentic.
#
# The 4x4 shape is deliberate, and is the one test_zkp_hybrid_family.sh adopted
# after TODO #261 found a pair that had never interoperated because every test
# compared against Python.
set -euo pipefail

DIR=$(dirname "$0")
PY="python3 $DIR/../HerraduraCli/herradura.py"
C="$DIR/../HerraduraCli/herradura_cli"
GO="$DIR/../HerraduraCli/herradura_cli_go"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
PASS=0; FAIL=0

# TODO #229: the compiled CLIs are no longer tracked in git, so this guard is
# live.  It exits non-zero rather than 0 — a skipped run asserted nothing and
# must not read as a pass.  See CliTest/lib_build.sh.
. "$(dirname "$0")/lib_build.sh"
hkx_require_built c go

# Java is built on demand.  Unlike c/go it degrades to a NOTE rather than a hard
# failure, matching the other Java-inclusive scripts: javac may not be installed.
# The NOTE is printed so an absence never reads as coverage.
JAVA_OK=0
if command -v javac >/dev/null 2>&1; then
    bash "$DIR/../bindings/java/build.sh" >/dev/null 2>&1 && JAVA_OK=1
fi
[ "$JAVA_OK" -eq 1 ] || echo "NOTE: java CLI absent (javac not installed) — 7 of 16 pairs skipped"

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
LANGS="py c go"
if [ "$JAVA_OK" -eq 1 ]; then
    CLI[java]="java -cp $DIR/../bindings/java herradurakex.HerraduraCli"
    LANGS="$LANGS java"
fi

for enc in $LANGS; do
    ${CLI[$enc]} enc --algo hske-nla1 --aead --ad "$AD" \
        --key "$TMP/sk.pem" --in "$TMP/msg.bin" --out "$TMP/ct_$enc.pem"
    for dec in $LANGS; do
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

# -- Tampered artifact: a flipped auth tag and a flipped ciphertext ----------
# The wrong-key and wrong-ad cases above vary the DECRYPTOR's inputs; these two
# vary the ARTIFACT, which is the axis a reader that ignored the tag would pass.
# Crafted once with the Python codec and fed to every language.
for field in tag ct; do
    HCODEC_DIR="$DIR/../HerraduraCli" python3 - "$TMP/ct_py.pem" "$TMP/bad_$field.pem" "$field" <<'PYEOF'
import os, sys
sys.path.insert(0, os.environ['HCODEC_DIR'])
from codec import pem_unwrap, pem_wrap, der_parse_seq, der_seq, der_int
src, dst, field = sys.argv[1], sys.argv[2], sys.argv[3]
label, der = pem_unwrap(open(src).read())
i = list(der_parse_seq(der))
# format tag 2: SEQUENCE(2, nonce[32], ct[32], auth_tag[32], nbits)
i[3 if field == 'tag' else 2] ^= 1
open(dst, 'w').write(pem_wrap(label, der_seq(
    der_int(i[0]), der_int(i[1], 32), der_int(i[2], 32),
    der_int(i[3], 32), der_int(i[4]))))
PYEOF
    for dec in $LANGS; do
        if ${CLI[$dec]} dec --algo hske-nla1 --ad "$AD" \
              --key "$TMP/sk.pem" --in "$TMP/bad_$field.pem" --out "$TMP/bad3.bin" 2>/dev/null; then
            echo "FAIL aead $dec-dec accepted a flipped $field"; FAIL=$((FAIL+1))
        else
            echo "PASS aead $dec-dec rejects a flipped $field"; PASS=$((PASS+1))
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
