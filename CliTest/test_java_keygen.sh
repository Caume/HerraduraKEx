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

# ── genpkey hpks-stern/hpke-stern/hpke-stern-kem (TODO #200) ───────────────
for algo in hpks-stern hpke-stern; do
    $CLI genpkey --algo "$algo" --out "$TMP/${algo}.pem" 2>/dev/null
    check "genpkey $algo" "$TMP/${algo}.pem" "PRIVATE KEY"
    $CLI pkey --in "$TMP/${algo}.pem" --pubout --out "$TMP/${algo}_pub.pem" 2>/dev/null
    check "pkey pubout $algo" "$TMP/${algo}_pub.pem" "PUBLIC KEY"
done
$CLI genpkey --algo hpke-stern-kem --out "$TMP/kem.pem"
check "genpkey hpke-stern-kem" "$TMP/kem.pem" "HPKE-STERN-KEM PRIVATE KEY"
$CLI pkey --in "$TMP/kem.pem" --pubout --out "$TMP/kem_pub.pem"
check "pkey pubout hpke-stern-kem" "$TMP/kem_pub.pem" "HPKE-STERN-KEM PUBLIC KEY"

# ── genpkey oprf/hpks-wots/hpks-xmss (TODO #201) ────────────────────────────
$CLI genpkey --algo oprf --out "$TMP/oprf.pem"
check "genpkey oprf" "$TMP/oprf.pem" "OPRF PRIVATE KEY"

$CLI genpkey --algo hpks-wots --out "$TMP/wots.pem" 2>/dev/null
check "genpkey hpks-wots" "$TMP/wots.pem" "HPKS-WOTS PRIVATE KEY"
$CLI pkey --in "$TMP/wots.pem" --pubout --out "$TMP/wots_pub.pem"
check "pkey pubout hpks-wots" "$TMP/wots_pub.pem" "HPKS-WOTS PUBLIC KEY"

$CLI genpkey --algo hpks-xmss --xmss-height 3 --out "$TMP/xmss.pem" 2>/dev/null
check "genpkey hpks-xmss" "$TMP/xmss.pem" "HPKS-XMSS PRIVATE KEY"
$CLI pkey --in "$TMP/xmss.pem" --pubout --out "$TMP/xmss_pub.pem"
check "pkey pubout hpks-xmss" "$TMP/xmss_pub.pem" "HPKS-XMSS PUBLIC KEY"

# ── genpkey hcred (TODO #202) ────────────────────────────────────────────
$CLI genpkey --algo hcred --out "$TMP/hcred.pem"
check "genpkey hcred" "$TMP/hcred.pem" "HCRED PRIVATE KEY"
$CLI pkey --in "$TMP/hcred.pem" --pubout --out "$TMP/hcred_pub.pem"
check "pkey pubout hcred" "$TMP/hcred_pub.pem" "HCRED PUBLIC KEY"

# ── genpkey rejects unsupported algos honestly (no silent wrong output) ────
if $CLI genpkey --algo hpks-zkp-nl --out "$TMP/should_fail.pem" 2>"$TMP/err.log"; then
    echo "FAIL genpkey hpks-zkp-nl should be rejected (out of this Java CLI's scope)"
    FAIL=$((FAIL+1))
else
    echo "PASS genpkey hpks-zkp-nl correctly rejected: $(cat "$TMP/err.log")"
    PASS=$((PASS+1))
fi

echo ""
echo "Results: $PASS PASS / $FAIL FAIL"
[ "$FAIL" -eq 0 ]
