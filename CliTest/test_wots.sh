#!/usr/bin/env bash
# CliTest/test_wots.sh — HPKS-WOTS-F one-time signature CLI, cross-language interop (TODO #120)
# Covers: keygen/pubout/sign/verify round-trip, 9-way cross-CLI interop,
# one-time reuse refusal, and tamper rejection.
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

printf 'HPKS-WOTS-F one-time signature message — arbitrary length is fine.' > "$TMP/msg.bin"
declare -A CLI=( [py]="$PY" [c]="$C" [go]="$GO" )

# 9-way interop: each signer generates a fresh one-time key, every verifier checks
for s in py c go; do
    ${CLI[$s]} genpkey --algo hpks-wots --out "$TMP/k_$s.pem" 2>/dev/null
    ${CLI[$s]} pkey --in "$TMP/k_$s.pem" --pubout --out "$TMP/k_${s}_pub.pem"
    ${CLI[$s]} sign --algo hpks-wots --key "$TMP/k_$s.pem" --in "$TMP/msg.bin" \
        --out "$TMP/sig_$s.pem" 2>/dev/null
    for v in py c go; do
        if ${CLI[$v]} verify --algo hpks-wots --pubkey "$TMP/k_${s}_pub.pem" \
              --in "$TMP/msg.bin" --sig "$TMP/sig_$s.pem" >/dev/null 2>&1; then
            echo "PASS wots $s-sign -> $v-verify"; PASS=$((PASS+1))
        else
            echo "FAIL wots $s-sign -> $v-verify"; FAIL=$((FAIL+1))
        fi
    done
done

# One-time reuse must be refused in every language
for s in py c go; do
    if ${CLI[$s]} sign --algo hpks-wots --key "$TMP/k_$s.pem" --in "$TMP/msg.bin" \
          --out "$TMP/reuse_$s.pem" 2>/dev/null; then
        echo "FAIL wots $s reuse allowed"; FAIL=$((FAIL+1))
    else
        echo "PASS wots $s one-time reuse refused"; PASS=$((PASS+1))
    fi
done

# Tampered message must fail verification (cross-language)
printf 'tampered message' > "$TMP/bad.bin"
for v in py c go; do
    if ${CLI[$v]} verify --algo hpks-wots --pubkey "$TMP/k_py_pub.pem" \
          --in "$TMP/bad.bin" --sig "$TMP/sig_py.pem" >/dev/null 2>&1; then
        echo "FAIL wots $v accepted tampered message"; FAIL=$((FAIL+1))
    else
        echo "PASS wots $v rejects tampered message"; PASS=$((PASS+1))
    fi
done

# Wrong public key must fail (sig_py verified against k_c_pub)
for v in py c go; do
    if ${CLI[$v]} verify --algo hpks-wots --pubkey "$TMP/k_c_pub.pem" \
          --in "$TMP/msg.bin" --sig "$TMP/sig_py.pem" >/dev/null 2>&1; then
        echo "FAIL wots $v accepted wrong public key"; FAIL=$((FAIL+1))
    else
        echo "PASS wots $v rejects wrong public key"; PASS=$((PASS+1))
    fi
done

echo
echo "test_wots: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
