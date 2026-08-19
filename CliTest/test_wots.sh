#!/usr/bin/env bash
# CliTest/test_wots.sh — HPKS-WOTS-F one-time signature CLI, cross-language interop (TODO #120)
# Covers: keygen/pubout/sign/verify round-trip, 9-way cross-CLI interop,
# one-time reuse refusal, and tamper rejection.
# Also covers HPKS-XMSS-F (TODO #208): 9-way C/Go/Python interop, multi-leaf
# signing (leaf index advances and does not reuse), leaf exhaustion, and
# tamper rejection — mirroring the WOTS coverage above.
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


# ── HPKS-XMSS-F (TODO #208): h=3 (8 leaves) keeps 4-language keygen fast ────

# 9-way interop: each signer generates a fresh tree, signs leaf 0, every
# verifier checks.
for s in py c go; do
    ${CLI[$s]} genpkey --algo hpks-xmss --xmss-height 3 --out "$TMP/xk_$s.pem" 2>/dev/null
    ${CLI[$s]} pkey --in "$TMP/xk_$s.pem" --pubout --out "$TMP/xk_${s}_pub.pem"
    ${CLI[$s]} sign --algo hpks-xmss --key "$TMP/xk_$s.pem" --in "$TMP/msg.bin" \
        --out "$TMP/xsig_$s.pem" 2>/dev/null
    for v in py c go; do
        if ${CLI[$v]} verify --algo hpks-xmss --pubkey "$TMP/xk_${s}_pub.pem" \
              --in "$TMP/msg.bin" --sig "$TMP/xsig_$s.pem" >/dev/null 2>&1; then
            echo "PASS xmss $s-sign -> $v-verify"; PASS=$((PASS+1))
        else
            echo "FAIL xmss $s-sign -> $v-verify"; FAIL=$((FAIL+1))
        fi
    done
done

# Signing again with the same key must advance to leaf 1 (not reuse leaf 0),
# and that new signature must still verify in every language.
for s in py c go; do
    ${CLI[$s]} sign --algo hpks-xmss --key "$TMP/xk_$s.pem" --in "$TMP/msg.bin" \
        --out "$TMP/xsig2_$s.pem" 2>/dev/null
    for v in py c go; do
        if ${CLI[$v]} verify --algo hpks-xmss --pubkey "$TMP/xk_${s}_pub.pem" \
              --in "$TMP/msg.bin" --sig "$TMP/xsig2_$s.pem" >/dev/null 2>&1; then
            echo "PASS xmss $s-sign(leaf1) -> $v-verify"; PASS=$((PASS+1))
        else
            echo "FAIL xmss $s-sign(leaf1) -> $v-verify"; FAIL=$((FAIL+1))
        fi
    done
done

# Leaf exhaustion: an h=1 (2-leaf) key must refuse a 3rd sign in every language.
for s in py c go; do
    ${CLI[$s]} genpkey --algo hpks-xmss --xmss-height 1 --out "$TMP/xsmall_$s.pem" 2>/dev/null
    ${CLI[$s]} sign --algo hpks-xmss --key "$TMP/xsmall_$s.pem" --in "$TMP/msg.bin" \
        --out "$TMP/xsmall_sig0_$s.pem" >/dev/null 2>&1
    ${CLI[$s]} sign --algo hpks-xmss --key "$TMP/xsmall_$s.pem" --in "$TMP/msg.bin" \
        --out "$TMP/xsmall_sig1_$s.pem" >/dev/null 2>&1
    if ${CLI[$s]} sign --algo hpks-xmss --key "$TMP/xsmall_$s.pem" --in "$TMP/msg.bin" \
          --out "$TMP/xsmall_sig2_$s.pem" 2>/dev/null; then
        echo "FAIL xmss $s leaf exhaustion not enforced"; FAIL=$((FAIL+1))
    else
        echo "PASS xmss $s leaf exhaustion enforced"; PASS=$((PASS+1))
    fi
done

# Tampered message must fail verification (cross-language)
for v in py c go; do
    if ${CLI[$v]} verify --algo hpks-xmss --pubkey "$TMP/xk_py_pub.pem" \
          --in "$TMP/bad.bin" --sig "$TMP/xsig_py.pem" >/dev/null 2>&1; then
        echo "FAIL xmss $v accepted tampered message"; FAIL=$((FAIL+1))
    else
        echo "PASS xmss $v rejects tampered message"; PASS=$((PASS+1))
    fi
done

# Wrong public key must fail (xsig_py verified against xk_c_pub)
for v in py c go; do
    if ${CLI[$v]} verify --algo hpks-xmss --pubkey "$TMP/xk_c_pub.pem" \
          --in "$TMP/msg.bin" --sig "$TMP/xsig_py.pem" >/dev/null 2>&1; then
        echo "FAIL xmss $v accepted wrong public key"; FAIL=$((FAIL+1))
    else
        echo "PASS xmss $v rejects wrong public key"; PASS=$((PASS+1))
    fi
done

echo
echo "test_wots: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
