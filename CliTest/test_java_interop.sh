#!/usr/bin/env bash
# CliTest/test_java_interop.sh — TODO #198: Java <-> Python CLI interop for
# the classical quartet, mirroring test_c_interop.sh/test_go_interop.sh's
# pattern: Python-generated keys/ciphertexts consumed by the Java CLI and
# vice versa, proving byte-for-byte PEM/DER wire-format compatibility.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if ! command -v javac >/dev/null 2>&1; then
    echo "SKIP test_java_interop: javac not found (install a JDK to run this test)"
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

printf 'JAVA-PYTHON-INTEROP-TEST-32BYTE!' > "$TMP/msg.bin"

# ── HKEX-GF: Java Alice <-> Python Bob must derive the same SESSION KEY PEM ──
$CLI_JAVA genpkey --algo hkex-gf --out "$TMP/alice.pem"
$CLI_JAVA pkey    --in "$TMP/alice.pem" --pubout --out "$TMP/alice_pub.pem"
$CLI_PY  genpkey --algo hkex-gf --out "$TMP/bob.pem"
$CLI_PY  pkey    --in "$TMP/bob.pem"   --pubout --out "$TMP/bob_pub.pem"
$CLI_JAVA kex --algo hkex-gf --our "$TMP/alice.pem" --their "$TMP/bob_pub.pem" --out "$TMP/alice_sk.pem"
$CLI_PY  kex --algo hkex-gf --our "$TMP/bob.pem"   --their "$TMP/alice_pub.pem" --out "$TMP/bob_sk.pem"
if cmp -s "$TMP/alice_sk.pem" "$TMP/bob_sk.pem"; then
    echo "PASS hkex-gf key agreement (Java alice / Python bob)"
    PASS=$((PASS+1))
else
    echo "FAIL hkex-gf key agreement (Java alice / Python bob): session key PEMs differ"
    FAIL=$((FAIL+1))
fi

# ── HSKE (using the shared key above) — both directions ─────────────────────
$CLI_JAVA enc --algo hske --key "$TMP/alice_sk.pem" --in "$TMP/msg.bin" --out "$TMP/j2p.pem"
$CLI_PY  dec --algo hske --key "$TMP/bob_sk.pem"   --in "$TMP/j2p.pem" --out "$TMP/j2p_out.bin"
check_roundtrip "hske: Java enc -> Python dec" "$TMP/msg.bin" "$TMP/j2p_out.bin"

$CLI_PY  enc --algo hske --key "$TMP/bob_sk.pem"   --in "$TMP/msg.bin" --out "$TMP/p2j.pem"
$CLI_JAVA dec --algo hske --key "$TMP/alice_sk.pem" --in "$TMP/p2j.pem" --out "$TMP/p2j_out.bin"
check_roundtrip "hske: Python enc -> Java dec" "$TMP/msg.bin" "$TMP/p2j_out.bin"

# ── HPKE — Python keypair, Java encrypts; Java keypair, Python encrypts ─────
$CLI_PY  genpkey --algo hpke --out "$TMP/hpke_py.pem"
$CLI_PY  pkey    --in "$TMP/hpke_py.pem" --pubout --out "$TMP/hpke_py_pub.pem"
$CLI_JAVA enc --algo hpke --pubkey "$TMP/hpke_py_pub.pem" --in "$TMP/msg.bin" --out "$TMP/hpke_j2p.pem"
$CLI_PY  dec --algo hpke --key "$TMP/hpke_py.pem" --in "$TMP/hpke_j2p.pem" --out "$TMP/hpke_j2p_out.bin"
check_roundtrip "hpke: Java enc -> Python dec" "$TMP/msg.bin" "$TMP/hpke_j2p_out.bin"

$CLI_JAVA genpkey --algo hpke --out "$TMP/hpke_j.pem"
$CLI_JAVA pkey    --in "$TMP/hpke_j.pem" --pubout --out "$TMP/hpke_j_pub.pem"
$CLI_PY  enc --algo hpke --pubkey "$TMP/hpke_j_pub.pem" --in "$TMP/msg.bin" --out "$TMP/hpke_p2j.pem"
$CLI_JAVA dec --algo hpke --key "$TMP/hpke_j.pem" --in "$TMP/hpke_p2j.pem" --out "$TMP/hpke_p2j_out.bin"
check_roundtrip "hpke: Python enc -> Java dec" "$TMP/msg.bin" "$TMP/hpke_p2j_out.bin"

# ── HPKS — sign in one language, verify in the other, both directions ──────
$CLI_JAVA genpkey --algo hpks --out "$TMP/hpks_j.pem"
$CLI_JAVA pkey    --in "$TMP/hpks_j.pem" --pubout --out "$TMP/hpks_j_pub.pem"
$CLI_JAVA sign    --algo hpks --key "$TMP/hpks_j.pem" --in "$TMP/msg.bin" --out "$TMP/sig_j.pem"
check_verify "hpks: Java sign -> Python verify" \
    $CLI_PY verify --algo hpks --pubkey "$TMP/hpks_j_pub.pem" --in "$TMP/msg.bin" --sig "$TMP/sig_j.pem"

$CLI_PY  genpkey --algo hpks --out "$TMP/hpks_p.pem"
$CLI_PY  pkey    --in "$TMP/hpks_p.pem" --pubout --out "$TMP/hpks_p_pub.pem"
$CLI_PY  sign    --algo hpks --key "$TMP/hpks_p.pem" --in "$TMP/msg.bin" --out "$TMP/sig_p.pem"
check_verify "hpks: Python sign -> Java verify" \
    $CLI_JAVA verify --algo hpks --pubkey "$TMP/hpks_p_pub.pem" --in "$TMP/msg.bin" --sig "$TMP/sig_p.pem"

# ── dgst (hfscx-256) — digests must match byte-for-byte ─────────────────────
J_HASH=$($CLI_JAVA dgst --algo hfscx-256 --in "$TMP/msg.bin")
P_HASH=$($CLI_PY  dgst --algo hfscx-256 --in "$TMP/msg.bin")
if [ "$J_HASH" = "$P_HASH" ]; then
    echo "PASS dgst hfscx-256 match ($J_HASH)"
    PASS=$((PASS+1))
else
    echo "FAIL dgst hfscx-256 mismatch: java=$J_HASH python=$P_HASH"
    FAIL=$((FAIL+1))
fi

# ── encfile/decfile (.hkx container) — both directions ──────────────────────
$CLI_JAVA encfile --algo hske-nla1 --key "$TMP/alice_sk.pem" --in "$TMP/msg.bin" --out "$TMP/j2p.hkx"
$CLI_PY  decfile --algo hske-nla1 --key "$TMP/alice_sk.pem" --in "$TMP/j2p.hkx" --out "$TMP/j2p_hkx_out.bin"
check_roundtrip "encfile: Java -> Python decfile" "$TMP/msg.bin" "$TMP/j2p_hkx_out.bin"

$CLI_PY  encfile --algo hske-nla1 --key "$TMP/alice_sk.pem" --in "$TMP/msg.bin" --out "$TMP/p2j.hkx"
$CLI_JAVA decfile --algo hske-nla1 --key "$TMP/alice_sk.pem" --in "$TMP/p2j.hkx" --out "$TMP/p2j_hkx_out.bin"
check_roundtrip "encfile: Python -> Java decfile" "$TMP/msg.bin" "$TMP/p2j_hkx_out.bin"

echo ""
echo "Results: $PASS PASS / $FAIL FAIL"
[ "$FAIL" -eq 0 ]
