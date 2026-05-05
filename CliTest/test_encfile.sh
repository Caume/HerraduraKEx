#!/usr/bin/env bash
# CliTest/test_encfile.sh — encfile/decfile round-trips, tag rejection, edge cases
set -euo pipefail

CLI="python3 $(dirname "$0")/../HerraduraCli/herradura.py"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
PASS=0; FAIL=0

check_roundtrip() {
    local label="$1" orig="$2" plain="$3"
    if cmp -s "$orig" "$plain"; then
        echo "PASS $label"
        PASS=$((PASS+1))
    else
        echo "FAIL $label: decrypted output does not match original"
        FAIL=$((FAIL+1))
    fi
}

check_reject() {
    local label="$1"; shift
    local output rc
    output=$("$@" 2>&1) && rc=0 || rc=$?
    if [ "$rc" -ne 0 ]; then
        echo "PASS $label"
        PASS=$((PASS+1))
    else
        echo "FAIL $label: expected decfile to exit non-zero; got rc=0; output: $output"
        FAIL=$((FAIL+1))
    fi
}

# ---------------------------------------------------------------------------
# Key material: HKEX-GF key exchange → shared secret
# ---------------------------------------------------------------------------

$CLI genpkey --algo hkex-gf --out "$TMP/alice.pem"
$CLI pkey    --in "$TMP/alice.pem" --pubout --out "$TMP/alice_pub.pem"
$CLI genpkey --algo hkex-gf --out "$TMP/bob.pem"
$CLI pkey    --in "$TMP/bob.pem"   --pubout --out "$TMP/bob_pub.pem"
$CLI kex     --algo hkex-gf --our "$TMP/alice.pem" --their "$TMP/bob_pub.pem" \
             --out "$TMP/sk.pem"

# ---------------------------------------------------------------------------
# Main round-trip: 1 MiB random file
# ---------------------------------------------------------------------------

dd if=/dev/urandom of="$TMP/large.bin" count=2048 bs=512 2>/dev/null

$CLI encfile --algo hske-nla1 --key "$TMP/sk.pem" \
             --in "$TMP/large.bin" --out "$TMP/large.hkx"
$CLI decfile --algo hske-nla1 --key "$TMP/sk.pem" \
             --in "$TMP/large.hkx" --out "$TMP/large_dec.bin"
check_roundtrip "encfile/decfile 1 MiB round-trip" "$TMP/large.bin" "$TMP/large_dec.bin"

# ---------------------------------------------------------------------------
# Tag rejection: flip one byte in the ciphertext body
# ---------------------------------------------------------------------------

python3 - <<'PYEOF' "$TMP/large.hkx" "$TMP/large_tampered.hkx"
import sys
data = bytearray(open(sys.argv[1], 'rb').read())
# ciphertext body starts at byte 45 (4 magic + 1 algo + 8 len + 32 nonce)
# flip a byte in the middle of the ciphertext, well before the 32-byte tag
mid = 45 + (len(data) - 45 - 32) // 2
data[mid] ^= 0xFF
open(sys.argv[2], 'wb').write(data)
PYEOF

check_reject "decfile rejects tampered ciphertext" \
    $CLI decfile --algo hske-nla1 --key "$TMP/sk.pem" \
    --in "$TMP/large_tampered.hkx" --out "$TMP/large_tampered_dec.bin"

# ---------------------------------------------------------------------------
# Edge cases: 0-byte, 1-byte, 32-byte (one full block)
# ---------------------------------------------------------------------------

for size in 0 1 32; do
    python3 -c "import os; open('$TMP/edge_${size}.bin','wb').write(os.urandom($size))"
    $CLI encfile --algo hske-nla1 --key "$TMP/sk.pem" \
                 --in "$TMP/edge_${size}.bin" --out "$TMP/edge_${size}.hkx"
    $CLI decfile --algo hske-nla1 --key "$TMP/sk.pem" \
                 --in "$TMP/edge_${size}.hkx" --out "$TMP/edge_${size}_dec.bin"
    check_roundtrip "encfile/decfile ${size}-byte edge case" \
        "$TMP/edge_${size}.bin" "$TMP/edge_${size}_dec.bin"
done

echo ""
echo "Results: $PASS PASS / $FAIL FAIL"
[ "$FAIL" -eq 0 ]
