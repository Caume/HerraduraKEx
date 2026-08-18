#!/usr/bin/env bash
# CliTest/test_java_hcred_interop.sh — TODO #202: Java <-> Python CLI
# interop for HCRED (hybrid Ring-LWR + Stern-F credential), mirroring
# test_java_stern_interop.sh's pattern. Uses small ZKBoo/Stern-F round
# counts (8) for CI speed — production defaults (219) are exercised
# manually/interactively, not in this smoke test.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if ! command -v javac >/dev/null 2>&1; then
    echo "SKIP test_java_hcred_interop: javac not found (install a JDK to run this test)"
    exit 0
fi

bash bindings/java/build.sh >/dev/null

CLI_JAVA="java -cp bindings/java herradurakex.HerraduraCli"
CLI_PY="python3 $ROOT/HerraduraCli/herradura.py"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
PASS=0; FAIL=0
ROUNDS=8

check() {
    local label="$1" rc="$2"
    if [ "$rc" -eq 0 ]; then
        echo "PASS $label"
        PASS=$((PASS+1))
    else
        echo "FAIL $label (rc=$rc)"
        FAIL=$((FAIL+1))
    fi
}

# ── Java user + issuer; Python verifies the proof and the credential ───────
$CLI_JAVA genpkey --algo hcred --out "$TMP/ju.pem" 2>/dev/null
$CLI_JAVA pkey --in "$TMP/ju.pem" --pubout --out "$TMP/ju_pub.pem"
$CLI_JAVA genpkey --algo hpks-stern --out "$TMP/ji.pem" 2>/dev/null
$CLI_JAVA pkey --in "$TMP/ji.pem" --pubout --out "$TMP/ji_pub.pem" 2>/dev/null
$CLI_JAVA cred-issue --our "$TMP/ji.pem" --in "$TMP/ju_pub.pem" --rounds $ROUNDS --out "$TMP/jcred.pem" 2>/dev/null
$CLI_JAVA cred-prove --in "$TMP/ju.pem" --msg "java-side presentation" --rounds $ROUNDS --out "$TMP/jproof.pem" 2>/dev/null
set +e
$CLI_PY cred-verify --proof "$TMP/jproof.pem" --pubkey "$TMP/ju_pub.pem" \
    --cred "$TMP/jcred.pem" --issuer "$TMP/ji_pub.pem" --msg "java-side presentation" >/dev/null 2>&1
check "hcred: Java user/issuer/proof -> Python verify (proof + credential)" $?
set -e

# ── Python user + issuer; Java verifies the proof and the credential ───────
$CLI_PY genpkey --algo hcred --bits 256 --out "$TMP/pu.pem" >/dev/null 2>&1
$CLI_PY pkey --in "$TMP/pu.pem" --pubout --out "$TMP/pu_pub.pem" >/dev/null 2>&1
$CLI_PY genpkey --algo hpks-stern --out "$TMP/pi.pem" >/dev/null 2>&1
$CLI_PY pkey --in "$TMP/pi.pem" --pubout --out "$TMP/pi_pub.pem" >/dev/null 2>&1
$CLI_PY cred-issue --our "$TMP/pi.pem" --in "$TMP/pu_pub.pem" --rounds $ROUNDS --out "$TMP/pcred.pem" >/dev/null 2>&1
$CLI_PY cred-prove --in "$TMP/pu.pem" --msg "python-side presentation" --rounds $ROUNDS --out "$TMP/pproof.pem" >/dev/null 2>&1
set +e
$CLI_JAVA cred-verify --proof "$TMP/pproof.pem" --pubkey "$TMP/pu_pub.pem" \
    --cred "$TMP/pcred.pem" --issuer "$TMP/pi_pub.pem" --msg "python-side presentation" >/dev/null 2>&1
check "hcred: Python user/issuer/proof -> Java verify (proof + credential)" $?
set -e

# ── Tamper rejection: a proof verified against a different presentation
#    message must fail, in both languages ───────────────────────────────────
set +e
$CLI_PY cred-verify --proof "$TMP/jproof.pem" --pubkey "$TMP/ju_pub.pem" --msg "wrong message" >/dev/null 2>&1
tamper_py_rc=$?
set -e
if [ "$tamper_py_rc" -ne 0 ]; then
    echo "PASS hcred: Python rejects Java proof replayed against a different message"
    PASS=$((PASS+1))
else
    echo "FAIL hcred: Python accepted a tampered-message replay"
    FAIL=$((FAIL+1))
fi

set +e
$CLI_JAVA cred-verify --proof "$TMP/pproof.pem" --pubkey "$TMP/pu_pub.pem" --msg "wrong message" >/dev/null 2>&1
tamper_j_rc=$?
set -e
if [ "$tamper_j_rc" -ne 0 ]; then
    echo "PASS hcred: Java rejects Python proof replayed against a different message"
    PASS=$((PASS+1))
else
    echo "FAIL hcred: Java accepted a tampered-message replay"
    FAIL=$((FAIL+1))
fi

echo ""
echo "Results: $PASS PASS / $FAIL FAIL"
[ "$FAIL" -eq 0 ]
