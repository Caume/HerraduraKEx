#!/usr/bin/env bash
# CliTest/test_keygen.sh — generate every key type; assert PEM headers and non-empty output
set -euo pipefail

CLI="python3 $(dirname "$0")/../HerraduraCli/herradura.py"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
PASS=0; FAIL=0

check() {
    local label="$1" file="$2" expected_header="$3"
    if [ ! -s "$file" ]; then
        echo "FAIL $label: output file is empty"
        FAIL=$((FAIL+1)); return
    fi
    if ! grep -qF "$expected_header" "$file"; then
        echo "FAIL $label: expected header '$expected_header' not found"
        FAIL=$((FAIL+1)); return
    fi
    echo "PASS $label"
    PASS=$((PASS+1))
}

# Classical and NL algorithms (default 256 bits)
for algo in hkex-gf hpks hpks-nl hpke hpke-nl; do
    $CLI genpkey --algo "$algo" --out "$TMP/${algo}.pem"
    check "genpkey $algo" "$TMP/${algo}.pem" "BEGIN HERRADURA"
    $CLI pkey --in "$TMP/${algo}.pem" --pubout --out "$TMP/${algo}_pub.pem"
    check "pkey pubout $algo" "$TMP/${algo}_pub.pem" "PUBLIC KEY"
done

# HKEX-RNL (smaller n=64 for speed)
$CLI genpkey --algo hkex-rnl --bits 64 --out "$TMP/hkex-rnl.pem"
check "genpkey hkex-rnl n=64" "$TMP/hkex-rnl.pem" "BEGIN HERRADURA"
$CLI pkey --in "$TMP/hkex-rnl.pem" --pubout --out "$TMP/hkex-rnl_pub.pem"
check "pkey pubout hkex-rnl" "$TMP/hkex-rnl_pub.pem" "PUBLIC KEY"

# Stern algorithms (n=32 for speed)
for algo in hpks-stern hpke-stern; do
    $CLI genpkey --algo "$algo" --bits 32 --out "$TMP/${algo}.pem"
    check "genpkey $algo n=32" "$TMP/${algo}.pem" "BEGIN HERRADURA"
    $CLI pkey --in "$TMP/${algo}.pem" --pubout --out "$TMP/${algo}_pub.pem"
    check "pkey pubout $algo" "$TMP/${algo}_pub.pem" "PUBLIC KEY"
done

echo ""
echo "Results: $PASS PASS / $FAIL FAIL"
[ "$FAIL" -eq 0 ]
