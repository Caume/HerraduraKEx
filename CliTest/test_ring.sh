#!/usr/bin/env bash
# CliTest/test_ring.sh — HPKS-Stern-Ring anonymous ring signatures, cross-language (TODO #121)
# Covers: sign-by-member / verify-by-ring success, 9-way cross-CLI interop,
# anonymity (any member can sign), non-member sign refusal, tamper rejection,
# and wrong-ring rejection.
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

# Three ring members (hpks-stern keypairs) + an outsider
for m in 0 1 2; do
    $PY genpkey --algo hpks-stern --out "$TMP/m$m.pem" 2>/dev/null
    $PY pkey --in "$TMP/m$m.pem" --pubout --out "$TMP/m${m}_pub.pem" 2>/dev/null
done
$PY genpkey --algo hpks-stern --out "$TMP/outsider.pem" 2>/dev/null
RING="$TMP/m0_pub.pem,$TMP/m1_pub.pem,$TMP/m2_pub.pem"
printf 'anonymous ring signature test message' > "$TMP/msg.bin"

declare -A CLI=( [py]="$PY" [c]="$C" [go]="$GO" )

# 9-way interop: signer language signs as member 1, every verifier checks
for s in py c go; do
    ${CLI[$s]} sign --algo hpks-ring --key "$TMP/m1.pem" --ring "$RING" \
        --in "$TMP/msg.bin" --out "$TMP/sig_$s.pem" 2>/dev/null
    for v in py c go; do
        if ${CLI[$v]} verify --algo hpks-ring --ring "$RING" \
              --in "$TMP/msg.bin" --sig "$TMP/sig_$s.pem" >/dev/null 2>&1; then
            echo "PASS ring $s-sign -> $v-verify"; PASS=$((PASS+1))
        else
            echo "FAIL ring $s-sign -> $v-verify"; FAIL=$((FAIL+1))
        fi
    done
done

# Anonymity: each of the three members can sign and the ring verifies (Python)
for m in 0 1 2; do
    ${CLI[py]} sign --algo hpks-ring --key "$TMP/m$m.pem" --ring "$RING" \
        --in "$TMP/msg.bin" --out "$TMP/anon_$m.pem" 2>/dev/null
    if ${CLI[py]} verify --algo hpks-ring --ring "$RING" \
          --in "$TMP/msg.bin" --sig "$TMP/anon_$m.pem" >/dev/null 2>&1; then
        echo "PASS ring member-$m signs anonymously"; PASS=$((PASS+1))
    else
        echo "FAIL ring member-$m signs anonymously"; FAIL=$((FAIL+1))
    fi
done

# Non-member cannot sign (signer key not in ring)
for s in py c go; do
    if ${CLI[$s]} sign --algo hpks-ring --key "$TMP/outsider.pem" --ring "$RING" \
          --in "$TMP/msg.bin" --out "$TMP/bad_$s.pem" 2>/dev/null; then
        echo "FAIL ring $s non-member signed"; FAIL=$((FAIL+1))
    else
        echo "PASS ring $s non-member sign refused"; PASS=$((PASS+1))
    fi
done

# Tampered message must fail verification (every language)
printf 'tampered message' > "$TMP/tampered.bin"
for v in py c go; do
    if ${CLI[$v]} verify --algo hpks-ring --ring "$RING" \
          --in "$TMP/tampered.bin" --sig "$TMP/sig_py.pem" >/dev/null 2>&1; then
        echo "FAIL ring $v accepted tampered message"; FAIL=$((FAIL+1))
    else
        echo "PASS ring $v rejects tampered message"; PASS=$((PASS+1))
    fi
done

# Wrong ring (member 0 swapped for outsider) must fail
$PY pkey --in "$TMP/outsider.pem" --pubout --out "$TMP/outsider_pub.pem" 2>/dev/null
WRONG_RING="$TMP/outsider_pub.pem,$TMP/m1_pub.pem,$TMP/m2_pub.pem"
for v in py c go; do
    if ${CLI[$v]} verify --algo hpks-ring --ring "$WRONG_RING" \
          --in "$TMP/msg.bin" --sig "$TMP/sig_py.pem" >/dev/null 2>&1; then
        echo "FAIL ring $v accepted wrong ring"; FAIL=$((FAIL+1))
    else
        echo "PASS ring $v rejects wrong ring"; PASS=$((PASS+1))
    fi
done

echo
echo "test_ring: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
