#!/usr/bin/env bash
# CliTest/test_java_nl_interop.sh — TODO #199: Java <-> Python CLI interop
# for the NL/PQC quartet (hkex-rnl, hske-nla1, hske-nla2, hpks-nl, hpke-nl),
# mirroring test_java_interop.sh's pattern for the classical quartet:
# Python-generated keys/ciphertexts consumed by the Java CLI and vice versa,
# proving byte-for-byte PEM/DER wire-format compatibility.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if ! command -v javac >/dev/null 2>&1; then
    echo "SKIP test_java_nl_interop: javac not found (install a JDK to run this test)"
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

printf 'JAVA-PYTHON-NL-INTEROP-TEST-32BB' | head -c 32 > "$TMP/msg.bin"

# ── HKEX-RNL: two-round handshake, Java Bob <-> Python Alice ────────────────
# Step 1: Alice (Python) generates her keypair and publishes her pubkey.
$CLI_PY  genpkey --algo hkex-rnl --out "$TMP/alice.pem"
$CLI_PY  pkey    --in "$TMP/alice.pem" --pubout --out "$TMP/alice_pub.pem"
# Step 2: Bob (Java) generates his keypair, responds to Alice's pubkey.
$CLI_JAVA genpkey --algo hkex-rnl --out "$TMP/bob.pem"
$CLI_JAVA kex --algo hkex-rnl --our "$TMP/bob.pem" --their "$TMP/alice_pub.pem" --out "$TMP/bob_resp.pem"
# Step 3: Alice (Python) completes the handshake using Bob's response.
$CLI_PY  kex --algo hkex-rnl --our "$TMP/alice.pem" --their "$TMP/bob_resp.pem" --out "$TMP/alice_sk.pem"

# Bob's own session key is embedded as the first field of his RESPONSE PEM;
# Alice's completed SESSION KEY PEM must carry the identical value.
python3 - "$TMP/bob_resp.pem" "$TMP/alice_sk.pem" <<'PYEOF'
import sys
sys.path.insert(0, "HerraduraCli")
import codec
bob_label, bob_der = codec.pem_unwrap(open(sys.argv[1]).read())
alice_label, alice_der = codec.pem_unwrap(open(sys.argv[2]).read())
k_bob = codec.der_parse_seq(bob_der)[0]
k_alice = codec.der_parse_seq(alice_der)[0]
sys.exit(0 if k_bob == k_alice else 1)
PYEOF
if [ $? -eq 0 ]; then
    echo "PASS hkex-rnl key agreement (Java bob / Python alice)"
    PASS=$((PASS+1))
else
    echo "FAIL hkex-rnl key agreement (Java bob / Python alice): reconciled keys differ"
    FAIL=$((FAIL+1))
fi

# Reverse roles: Java Alice <-> Python Bob.
$CLI_JAVA genpkey --algo hkex-rnl --out "$TMP/jalice.pem"
$CLI_JAVA pkey    --in "$TMP/jalice.pem" --pubout --out "$TMP/jalice_pub.pem"
$CLI_PY  genpkey --algo hkex-rnl --out "$TMP/pbob.pem"
$CLI_PY  kex --algo hkex-rnl --our "$TMP/pbob.pem" --their "$TMP/jalice_pub.pem" --out "$TMP/pbob_resp.pem"
$CLI_JAVA kex --algo hkex-rnl --our "$TMP/jalice.pem" --their "$TMP/pbob_resp.pem" --out "$TMP/jalice_sk.pem"
python3 - "$TMP/pbob_resp.pem" "$TMP/jalice_sk.pem" <<'PYEOF'
import sys
sys.path.insert(0, "HerraduraCli")
import codec
b_label, b_der = codec.pem_unwrap(open(sys.argv[1]).read())
a_label, a_der = codec.pem_unwrap(open(sys.argv[2]).read())
k_b = codec.der_parse_seq(b_der)[0]
k_a = codec.der_parse_seq(a_der)[0]
sys.exit(0 if k_b == k_a else 1)
PYEOF
if [ $? -eq 0 ]; then
    echo "PASS hkex-rnl key agreement (Python bob / Java alice)"
    PASS=$((PASS+1))
else
    echo "FAIL hkex-rnl key agreement (Python bob / Java alice): reconciled keys differ"
    FAIL=$((FAIL+1))
fi

# ── Classical hkex-gf session keys, used as symmetric keys for hske-nla1/a2 ──
$CLI_JAVA genpkey --algo hkex-gf --out "$TMP/a.pem"
$CLI_JAVA pkey    --in "$TMP/a.pem" --pubout --out "$TMP/a_pub.pem"
$CLI_PY  genpkey --algo hkex-gf --out "$TMP/b.pem"
$CLI_PY  pkey    --in "$TMP/b.pem"   --pubout --out "$TMP/b_pub.pem"
$CLI_JAVA kex --algo hkex-gf --our "$TMP/a.pem" --their "$TMP/b_pub.pem" --out "$TMP/a_sk.pem"
$CLI_PY  kex --algo hkex-gf --our "$TMP/b.pem" --their "$TMP/a_pub.pem" --out "$TMP/b_sk.pem"

# ── HSKE-NL-A1 (counter-mode) — both directions ──────────────────────────────
$CLI_JAVA enc --algo hske-nla1 --key "$TMP/a_sk.pem" --in "$TMP/msg.bin" --out "$TMP/nla1_j2p.pem"
$CLI_PY  dec --algo hske-nla1 --key "$TMP/b_sk.pem" --in "$TMP/nla1_j2p.pem" --out "$TMP/nla1_j2p_out.bin"
check_roundtrip "hske-nla1: Java enc -> Python dec" "$TMP/msg.bin" "$TMP/nla1_j2p_out.bin"

$CLI_PY  enc --algo hske-nla1 --key "$TMP/b_sk.pem" --in "$TMP/msg.bin" --out "$TMP/nla1_p2j.pem"
$CLI_JAVA dec --algo hske-nla1 --key "$TMP/a_sk.pem" --in "$TMP/nla1_p2j.pem" --out "$TMP/nla1_p2j_out.bin"
check_roundtrip "hske-nla1: Python enc -> Java dec" "$TMP/msg.bin" "$TMP/nla1_p2j_out.bin"

# ── HSKE-NL-A2 (revolve-mode) — both directions ──────────────────────────────
$CLI_JAVA enc --algo hske-nla2 --key "$TMP/a_sk.pem" --in "$TMP/msg.bin" --out "$TMP/nla2_j2p.pem"
$CLI_PY  dec --algo hske-nla2 --key "$TMP/b_sk.pem" --in "$TMP/nla2_j2p.pem" --out "$TMP/nla2_j2p_out.bin"
check_roundtrip "hske-nla2: Java enc -> Python dec" "$TMP/msg.bin" "$TMP/nla2_j2p_out.bin"

$CLI_PY  enc --algo hske-nla2 --key "$TMP/b_sk.pem" --in "$TMP/msg.bin" --out "$TMP/nla2_p2j.pem"
$CLI_JAVA dec --algo hske-nla2 --key "$TMP/a_sk.pem" --in "$TMP/nla2_p2j.pem" --out "$TMP/nla2_p2j_out.bin"
check_roundtrip "hske-nla2: Python enc -> Java dec" "$TMP/msg.bin" "$TMP/nla2_p2j_out.bin"

# ── HPKE-NL — Python keypair, Java encrypts; Java keypair, Python encrypts ──
$CLI_PY  genpkey --algo hpke-nl --out "$TMP/hpkenl_py.pem"
$CLI_PY  pkey    --in "$TMP/hpkenl_py.pem" --pubout --out "$TMP/hpkenl_py_pub.pem"
$CLI_JAVA enc --algo hpke-nl --pubkey "$TMP/hpkenl_py_pub.pem" --in "$TMP/msg.bin" --out "$TMP/hpkenl_j2p.pem"
$CLI_PY  dec --algo hpke-nl --key "$TMP/hpkenl_py.pem" --in "$TMP/hpkenl_j2p.pem" --out "$TMP/hpkenl_j2p_out.bin"
check_roundtrip "hpke-nl: Java enc -> Python dec" "$TMP/msg.bin" "$TMP/hpkenl_j2p_out.bin"

$CLI_JAVA genpkey --algo hpke-nl --out "$TMP/hpkenl_j.pem"
$CLI_JAVA pkey    --in "$TMP/hpkenl_j.pem" --pubout --out "$TMP/hpkenl_j_pub.pem"
$CLI_PY  enc --algo hpke-nl --pubkey "$TMP/hpkenl_j_pub.pem" --in "$TMP/msg.bin" --out "$TMP/hpkenl_p2j.pem"
$CLI_JAVA dec --algo hpke-nl --key "$TMP/hpkenl_j.pem" --in "$TMP/hpkenl_p2j.pem" --out "$TMP/hpkenl_p2j_out.bin"
check_roundtrip "hpke-nl: Python enc -> Java dec" "$TMP/msg.bin" "$TMP/hpkenl_p2j_out.bin"

# ── HPKS-NL — sign in one language, verify in the other, both directions ────
$CLI_JAVA genpkey --algo hpks-nl --out "$TMP/hpksnl_j.pem"
$CLI_JAVA pkey    --in "$TMP/hpksnl_j.pem" --pubout --out "$TMP/hpksnl_j_pub.pem"
$CLI_JAVA sign    --algo hpks-nl --key "$TMP/hpksnl_j.pem" --in "$TMP/msg.bin" --out "$TMP/signl_j.pem"
check_verify "hpks-nl: Java sign -> Python verify" \
    $CLI_PY verify --algo hpks-nl --pubkey "$TMP/hpksnl_j_pub.pem" --in "$TMP/msg.bin" --sig "$TMP/signl_j.pem"

$CLI_PY  genpkey --algo hpks-nl --out "$TMP/hpksnl_p.pem"
$CLI_PY  pkey    --in "$TMP/hpksnl_p.pem" --pubout --out "$TMP/hpksnl_p_pub.pem"
$CLI_PY  sign    --algo hpks-nl --key "$TMP/hpksnl_p.pem" --in "$TMP/msg.bin" --out "$TMP/signl_p.pem"
check_verify "hpks-nl: Python sign -> Java verify" \
    $CLI_JAVA verify --algo hpks-nl --pubkey "$TMP/hpksnl_p_pub.pem" --in "$TMP/msg.bin" --sig "$TMP/signl_p.pem"

echo ""
echo "Results: $PASS PASS / $FAIL FAIL"
[ "$FAIL" -eq 0 ]
