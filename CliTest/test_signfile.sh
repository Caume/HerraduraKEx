#!/usr/bin/env bash
# CliTest/test_signfile.sh — sign/verify large files with --digest hfscx-256; dgst determinism
set -euo pipefail

CLI="python3 $(dirname "$0")/../HerraduraCli/herradura.py"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
PASS=0; FAIL=0

check_verify() {
    local label="$1"; shift
    local output rc
    output=$("$@" 2>&1) && rc=0 || rc=$?
    if [ "$rc" -eq 0 ] && echo "$output" | grep -q "Signature OK"; then
        echo "PASS $label"
        PASS=$((PASS+1))
    else
        echo "FAIL $label: expected 'Signature OK' (rc=$rc); got: $output"
        FAIL=$((FAIL+1))
    fi
}

check_reject() {
    local label="$1"; shift
    local output rc
    output=$("$@" 2>&1) && rc=0 || rc=$?
    if [ "$rc" -ne 0 ] && echo "$output" | grep -q "Verification FAILED"; then
        echo "PASS $label"
        PASS=$((PASS+1))
    else
        echo "FAIL $label: expected rejection (rc=$rc); got: $output"
        FAIL=$((FAIL+1))
    fi
}

# ---------------------------------------------------------------------------
# Test file: 1 MiB random data
# ---------------------------------------------------------------------------

dd if=/dev/urandom of="$TMP/large.bin" count=2048 bs=512 2>/dev/null

# ---------------------------------------------------------------------------
# dgst determinism: same file → identical hex output across two runs
# ---------------------------------------------------------------------------

DGST1=$($CLI dgst --in "$TMP/large.bin")
DGST2=$($CLI dgst --in "$TMP/large.bin")
if [ "$DGST1" = "$DGST2" ]; then
    echo "PASS dgst determinism"
    PASS=$((PASS+1))
else
    echo "FAIL dgst determinism: '$DGST1' != '$DGST2'"
    FAIL=$((FAIL+1))
fi

# ---------------------------------------------------------------------------
# Sign + verify with --digest hfscx-256 for each signing algorithm
# ---------------------------------------------------------------------------

for algo in hpks hpks-nl hpks-stern; do
    extra_bits=""
    [ "$algo" = "hpks-stern" ] && extra_bits="--bits 32"

    $CLI genpkey --algo "$algo" $extra_bits --out "$TMP/${algo}.pem"
    $CLI pkey    --in "$TMP/${algo}.pem" --pubout --out "$TMP/${algo}_pub.pem"

    $CLI sign   --algo "$algo" --key "$TMP/${algo}.pem" \
                --in "$TMP/large.bin" --digest hfscx-256 \
                --out "$TMP/${algo}_large.sig"

    check_verify "verify $algo --digest hfscx-256 correct file" \
        $CLI verify --algo "$algo" --pubkey "$TMP/${algo}_pub.pem" \
        --in "$TMP/large.bin" --digest hfscx-256 \
        --sig "$TMP/${algo}_large.sig"

    # Append one byte → different digest → verification must fail
    python3 -c "
import shutil, sys
shutil.copy('$TMP/large.bin', '$TMP/large_plus1.bin')
open('$TMP/large_plus1.bin', 'ab').write(b'X')
"
    check_reject "verify $algo --digest hfscx-256 modified file" \
        $CLI verify --algo "$algo" --pubkey "$TMP/${algo}_pub.pem" \
        --in "$TMP/large_plus1.bin" --digest hfscx-256 \
        --sig "$TMP/${algo}_large.sig"
done

echo ""
echo "Results: $PASS PASS / $FAIL FAIL"
[ "$FAIL" -eq 0 ]
