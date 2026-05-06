#!/usr/bin/env bash
# CliTest/test_c_keygen.sh — C CLI: generate all 8 key types; assert PEM headers
set -euo pipefail

CLI="$(dirname "$0")/../HerraduraCli/herradura_cli"
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

for algo in hkex-gf hkex-rnl hpks hpks-nl hpke hpke-nl hpks-stern hpke-stern; do
    "$CLI" genpkey --algo "$algo" --out "$TMP/${algo}.pem"
    check "genpkey $algo" "$TMP/${algo}.pem" "BEGIN HERRADURA"
    "$CLI" pkey --in "$TMP/${algo}.pem" --pubout --out "$TMP/${algo}_pub.pem"
    check "pkey pubout $algo" "$TMP/${algo}_pub.pem" "PUBLIC KEY"
done

echo ""
echo "Results: $PASS PASS / $FAIL FAIL"
[ "$FAIL" -eq 0 ]
