#!/usr/bin/env bash
# CliTest/test_java_stern_interop.sh — TODO #200: Java <-> Python CLI
# interop for HPKS-Stern-F, HPKE-Stern-F (demo), and HPKE-Stern-KEM (real
# QC-MDPC/BGF Niederreiter KEM), mirroring test_java_interop.sh's pattern:
# Python-generated keys/signatures/ciphertexts consumed by the Java CLI
# and vice versa.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if ! command -v javac >/dev/null 2>&1; then
    echo "SKIP test_java_stern_interop: javac not found (install a JDK to run this test)"
    exit 0
fi

bash bindings/java/build.sh >/dev/null

CLI_JAVA="java -cp bindings/java herradurakex.HerraduraCli"
CLI_PY="python3 $ROOT/HerraduraCli/herradura.py"
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

# QC-MDPC/BGF has a measured ~0.225% decoding failure rate per
# encapsulation (TODO #195) — a legitimate, rare event, not a bug.
# Retry with a fresh keypair/encapsulation on that specific error, up to
# MAX_DFR_RETRIES times, mirroring test_hybrid_kex_interop.sh's pattern.
. "$(dirname "$0")/lib_dfr.sh"   # shared retry budget + signature (TODO #221)

kem_roundtrip() {
    local label="$1" gen_cmd="$2" pub_cmd="$3" enc_cmd="$4" dec_cmd="$5" priv="$6" pub="$7" ct="$8" out="$9"
    local attempt=0
    while :; do
        attempt=$((attempt+1))
        eval "$gen_cmd" >/dev/null 2>&1
        eval "$pub_cmd" >/dev/null 2>&1
        eval "$enc_cmd" >/dev/null 2>&1
        local dec_output rc
        dec_output=$(eval "$dec_cmd" 2>&1) && rc=0 || rc=$?
        if [ "$rc" -eq 0 ]; then
            check_roundtrip "$label" "$TMP/msg.bin" "$out"
            return
        fi
        if dfr_is_event "$dec_output" && [ "$attempt" -lt "$MAX_DFR_RETRIES" ]; then
            echo "INFO $label: DFR event on attempt $attempt, retrying with a fresh keypair"
            continue
        fi
        echo "FAIL $label: dec failed (rc=$rc): $dec_output"
        FAIL=$((FAIL+1))
        return
    done
}

printf 'JAVA-PYTHON-STERN-INTEROP-32BYTE' > "$TMP/msg.bin"

# ── HPKS-Stern-F — sign in one language, verify in the other ───────────────
$CLI_JAVA genpkey --algo hpks-stern --out "$TMP/hpks_j.pem" 2>/dev/null
$CLI_JAVA pkey    --in "$TMP/hpks_j.pem" --pubout --out "$TMP/hpks_j_pub.pem" 2>/dev/null
$CLI_JAVA sign    --algo hpks-stern --key "$TMP/hpks_j.pem" --in "$TMP/msg.bin" --out "$TMP/sig_j.pem" --rounds 16 2>/dev/null
check_verify "hpks-stern: Java sign -> Python verify" \
    $CLI_PY verify --algo hpks-stern --pubkey "$TMP/hpks_j_pub.pem" --in "$TMP/msg.bin" --sig "$TMP/sig_j.pem"

$CLI_PY  genpkey --algo hpks-stern --out "$TMP/hpks_p.pem" 2>/dev/null
$CLI_PY  pkey    --in "$TMP/hpks_p.pem" --pubout --out "$TMP/hpks_p_pub.pem" 2>/dev/null
$CLI_PY  sign    --algo hpks-stern --key "$TMP/hpks_p.pem" --in "$TMP/msg.bin" --out "$TMP/sig_p.pem" --rounds 16 2>/dev/null
check_verify "hpks-stern: Python sign -> Java verify" \
    $CLI_JAVA verify --algo hpks-stern --pubkey "$TMP/hpks_p_pub.pem" --in "$TMP/msg.bin" --sig "$TMP/sig_p.pem"

# ── HPKE-Stern-F (demo Niederreiter KEM) — both directions ─────────────────
$CLI_JAVA genpkey --algo hpke-stern --out "$TMP/hpke_j.pem" 2>/dev/null
$CLI_JAVA pkey    --in "$TMP/hpke_j.pem" --pubout --out "$TMP/hpke_j_pub.pem" 2>/dev/null
$CLI_JAVA enc --algo hpke-stern --pubkey "$TMP/hpke_j_pub.pem" --in "$TMP/msg.bin" --out "$TMP/hpke_j2p.pem" 2>/dev/null
$CLI_PY  dec --algo hpke-stern --key "$TMP/hpke_j.pem" --in "$TMP/hpke_j2p.pem" --out "$TMP/hpke_j2p_out.bin" 2>/dev/null
check_roundtrip "hpke-stern: Java enc -> Python dec" "$TMP/msg.bin" "$TMP/hpke_j2p_out.bin"

$CLI_PY  genpkey --algo hpke-stern --out "$TMP/hpke_p.pem" 2>/dev/null
$CLI_PY  pkey    --in "$TMP/hpke_p.pem" --pubout --out "$TMP/hpke_p_pub.pem" 2>/dev/null
$CLI_PY  enc --algo hpke-stern --pubkey "$TMP/hpke_p_pub.pem" --in "$TMP/msg.bin" --out "$TMP/hpke_p2j.pem" 2>/dev/null
$CLI_JAVA dec --algo hpke-stern --key "$TMP/hpke_p.pem" --in "$TMP/hpke_p2j.pem" --out "$TMP/hpke_p2j_out.bin" 2>/dev/null
check_roundtrip "hpke-stern: Python enc -> Java dec" "$TMP/msg.bin" "$TMP/hpke_p2j_out.bin"

# ── HPKE-Stern-KEM (real QC-MDPC/BGF) — both directions, DFR-retry aware ───
kem_roundtrip "hpke-stern-kem: Java enc -> Python dec" \
    "$CLI_JAVA genpkey --algo hpke-stern-kem --out $TMP/kem_j.pem" \
    "$CLI_JAVA pkey --in $TMP/kem_j.pem --pubout --out $TMP/kem_j_pub.pem" \
    "$CLI_JAVA enc --algo hpke-stern-kem --pubkey $TMP/kem_j_pub.pem --in $TMP/msg.bin --out $TMP/kem_j2p.pem" \
    "$CLI_PY dec --algo hpke-stern-kem --key $TMP/kem_j.pem --in $TMP/kem_j2p.pem --out $TMP/kem_j2p_out.bin" \
    "$TMP/kem_j.pem" "$TMP/kem_j_pub.pem" "$TMP/kem_j2p.pem" "$TMP/kem_j2p_out.bin"

kem_roundtrip "hpke-stern-kem: Python enc -> Java dec" \
    "$CLI_PY genpkey --algo hpke-stern-kem --out $TMP/kem_p.pem" \
    "$CLI_PY pkey --in $TMP/kem_p.pem --pubout --out $TMP/kem_p_pub.pem" \
    "$CLI_PY enc --algo hpke-stern-kem --pubkey $TMP/kem_p_pub.pem --in $TMP/msg.bin --out $TMP/kem_p2j.pem" \
    "$CLI_JAVA dec --algo hpke-stern-kem --key $TMP/kem_p.pem --in $TMP/kem_p2j.pem --out $TMP/kem_p2j_out.bin" \
    "$TMP/kem_p.pem" "$TMP/kem_p_pub.pem" "$TMP/kem_p2j.pem" "$TMP/kem_p2j_out.bin"

echo ""
echo "Results: $PASS PASS / $FAIL FAIL"
[ "$FAIL" -eq 0 ]
