#!/usr/bin/env bash
# CliTest/test_java_keygen.sh — TODO #198: Java CLI (herradurakex.HerraduraCli)
# smoke test — generate each classical-quartet key type, assert PEM headers,
# and exercise pkey --text/--pubout, mirroring test_c_keygen.sh's pattern.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if ! command -v javac >/dev/null 2>&1; then
    echo "SKIP test_java_keygen: javac not found (install a JDK to run this test)"
    exit 0
fi

bash bindings/java/build.sh >/dev/null

CLI="java -cp bindings/java herradurakex.HerraduraCli"
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

for algo in hkex-gf hpks hpke; do
    $CLI genpkey --algo "$algo" --out "$TMP/${algo}.pem"
    check "genpkey $algo" "$TMP/${algo}.pem" "BEGIN HERRADURA"
    $CLI pkey --in "$TMP/${algo}.pem" --pubout --out "$TMP/${algo}_pub.pem"
    check "pkey pubout $algo" "$TMP/${algo}_pub.pem" "PUBLIC KEY"
done

# ── pkey --text: sanity-check field presence and hex width ─────────────────
TEXT_OUT=$($CLI pkey --in "$TMP/hpks.pem" --text)
if echo "$TEXT_OUT" | grep -q "^algorithm : hpks$" \
    && echo "$TEXT_OUT" | grep -qE "^private   : [0-9a-f]{64}$" \
    && echo "$TEXT_OUT" | grep -qE "^public    : [0-9a-f]{64}$"; then
    echo "PASS pkey --text hpks"
    PASS=$((PASS+1))
else
    echo "FAIL pkey --text hpks: unexpected output:"
    echo "$TEXT_OUT"
    FAIL=$((FAIL+1))
fi

# ── genpkey hkex-rnl (TODO #199): keygen + pkey --pubout round trip ────────
if $CLI genpkey --algo hkex-rnl --out "$TMP/rnl.pem" \
    && $CLI pkey --in "$TMP/rnl.pem" --pubout --out "$TMP/rnl_pub.pem"; then
    check "genpkey hkex-rnl" "$TMP/rnl.pem" "HKEX-RNL PRIVATE KEY"
    check "pkey pubout hkex-rnl" "$TMP/rnl_pub.pem" "HKEX-RNL PUBLIC KEY"
else
    echo "FAIL genpkey/pkey hkex-rnl"
    FAIL=$((FAIL+1))
fi

# ── genpkey rejects unsupported algos honestly (no silent wrong output) ────
if $CLI genpkey --algo hpke-stern --out "$TMP/should_fail.pem" 2>"$TMP/err.log"; then
    echo "FAIL genpkey hpke-stern should be rejected (out of this Java CLI's scope)"
    FAIL=$((FAIL+1))
else
    echo "PASS genpkey hpke-stern correctly rejected: $(cat "$TMP/err.log")"
    PASS=$((PASS+1))
fi

echo ""
echo "Results: $PASS PASS / $FAIL FAIL"
[ "$FAIL" -eq 0 ]
