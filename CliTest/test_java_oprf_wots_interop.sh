#!/usr/bin/env bash
# CliTest/test_java_oprf_wots_interop.sh — TODO #201: Java <-> Python CLI
# interop for OPRF (oprf-blind/oprf-eval/oprf-unblind) and
# HPKS-WOTS-F/HPKS-XMSS-F, mirroring test_java_stern_interop.sh's pattern.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if ! command -v javac >/dev/null 2>&1; then
    echo "SKIP test_java_oprf_wots_interop: javac not found (install a JDK to run this test)"
    exit 0
fi

bash bindings/java/build.sh >/dev/null

CLI_JAVA="java -cp bindings/java herradurakex.HerraduraCli"
CLI_PY="python3 $ROOT/HerraduraCli/herradura.py"
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

# ── OPRF: Java client blinds, Python server evals, Java unblinds; the
#    result must equal Python's direct (non-oblivious) evaluation ──────────
$CLI_PY  genpkey --algo oprf --out "$TMP/oprf_k.pem" 2>/dev/null
printf 'JAVA-PYTHON-OPRF-INTEROP-TEST' > "$TMP/oin.bin"
$CLI_JAVA oprf-blind --in "$TMP/oin.bin" --out "$TMP/ostate.pem"
$CLI_PY  oprf-eval --key "$TMP/oprf_k.pem" --in "$TMP/ostate.pem" --out "$TMP/oeval.pem" 2>/dev/null
$CLI_JAVA oprf-unblind --state "$TMP/ostate.pem" --eval "$TMP/oeval.pem" --out "$TMP/of1.hex"

$CLI_JAVA genpkey --algo oprf --out "$TMP/oprf_k2.pem"
$CLI_JAVA oprf-eval --key "$TMP/oprf_k2.pem" --in "$TMP/ostate.pem" --out "$TMP/oeval2.pem"
$CLI_PY  oprf-unblind --state "$TMP/ostate.pem" --eval "$TMP/oeval2.pem" --out "$TMP/of2.hex" 2>/dev/null

# Cross-check both unblinded outputs against Python's direct (non-oblivious)
# F(k, x) computed from the same OPRF key and input — proves the value
# itself is correct, not just that the round trip produced *some* output.
oprf_direct_hex() {
    python3 - "$1" "$2" <<'EOF'
import sys
sys.path.insert(0, "HerraduraCli")
from herradura import _load_oprf_key
import importlib.util
spec = importlib.util.spec_from_file_location("suite", "Herradura cryptographic suite.py")
suite = importlib.util.module_from_spec(spec)
spec.loader.exec_module(suite)
k, _ = _load_oprf_key(sys.argv[1])
x = open(sys.argv[2], 'rb').read()
print(suite.oprf_direct(x, k).to_bytes(32, 'big').hex())
EOF
}
EXPECT1=$(oprf_direct_hex "$TMP/oprf_k.pem" "$TMP/oin.bin")
GOT1=$(cat "$TMP/of1.hex")
if [ "$GOT1" = "$EXPECT1" ]; then
    echo "PASS oprf: Java blind -> Python eval -> Java unblind matches oprf_direct"
    PASS=$((PASS+1))
else
    echo "FAIL oprf: Java blind -> Python eval -> Java unblind mismatch (got=$GOT1 expect=$EXPECT1)"
    FAIL=$((FAIL+1))
fi

EXPECT2=$(oprf_direct_hex "$TMP/oprf_k2.pem" "$TMP/oin.bin")
GOT2=$(cat "$TMP/of2.hex")
if [ "$GOT2" = "$EXPECT2" ]; then
    echo "PASS oprf: Java eval -> Python unblind matches oprf_direct"
    PASS=$((PASS+1))
else
    echo "FAIL oprf: Java eval -> Python unblind mismatch (got=$GOT2 expect=$EXPECT2)"
    FAIL=$((FAIL+1))
fi

# ── HPKS-WOTS-F — sign in one language, verify in the other ────────────────
$CLI_JAVA genpkey --algo hpks-wots --out "$TMP/wots_j.pem" 2>/dev/null
$CLI_JAVA pkey    --in "$TMP/wots_j.pem" --pubout --out "$TMP/wots_j_pub.pem"
printf 'JAVA-PYTHON-WOTS-INTEROP-TEST!!' > "$TMP/wmsg.bin"
$CLI_JAVA sign    --algo hpks-wots --key "$TMP/wots_j.pem" --in "$TMP/wmsg.bin" --out "$TMP/wsig_j.pem" 2>/dev/null
check_verify "hpks-wots: Java sign -> Python verify" \
    $CLI_PY verify --algo hpks-wots --pubkey "$TMP/wots_j_pub.pem" --in "$TMP/wmsg.bin" --sig "$TMP/wsig_j.pem"

$CLI_PY  genpkey --algo hpks-wots --out "$TMP/wots_p.pem" 2>/dev/null
$CLI_PY  pkey    --in "$TMP/wots_p.pem" --pubout --out "$TMP/wots_p_pub.pem" 2>/dev/null
$CLI_PY  sign    --algo hpks-wots --key "$TMP/wots_p.pem" --in "$TMP/wmsg.bin" --out "$TMP/wsig_p.pem" 2>/dev/null
check_verify "hpks-wots: Python sign -> Java verify" \
    $CLI_JAVA verify --algo hpks-wots --pubkey "$TMP/wots_p_pub.pem" --in "$TMP/wmsg.bin" --sig "$TMP/wsig_p.pem"

# ── HPKS-XMSS-F (h=3, small for speed) — sign in one language, verify in
#    the other, at two distinct leaves each ─────────────────────────────────
$CLI_JAVA genpkey --algo hpks-xmss --xmss-height 3 --out "$TMP/xmss_j.pem" 2>/dev/null
$CLI_JAVA pkey    --in "$TMP/xmss_j.pem" --pubout --out "$TMP/xmss_j_pub.pem"
printf 'JAVA-PYTHON-XMSS-INTEROP-TEST!!' > "$TMP/xmsg.bin"
$CLI_JAVA sign    --algo hpks-xmss --key "$TMP/xmss_j.pem" --in "$TMP/xmsg.bin" --out "$TMP/xsig_j0.pem" 2>/dev/null
$CLI_JAVA sign    --algo hpks-xmss --key "$TMP/xmss_j.pem" --in "$TMP/xmsg.bin" --out "$TMP/xsig_j1.pem" 2>/dev/null
check_verify "hpks-xmss: Java sign (leaf 0) -> Python verify" \
    $CLI_PY verify --algo hpks-xmss --pubkey "$TMP/xmss_j_pub.pem" --in "$TMP/xmsg.bin" --sig "$TMP/xsig_j0.pem"
check_verify "hpks-xmss: Java sign (leaf 1) -> Python verify" \
    $CLI_PY verify --algo hpks-xmss --pubkey "$TMP/xmss_j_pub.pem" --in "$TMP/xmsg.bin" --sig "$TMP/xsig_j1.pem"

$CLI_PY  genpkey --algo hpks-xmss --xmss-height 3 --out "$TMP/xmss_p.pem" 2>/dev/null
$CLI_PY  pkey    --in "$TMP/xmss_p.pem" --pubout --out "$TMP/xmss_p_pub.pem" 2>/dev/null
$CLI_PY  sign    --algo hpks-xmss --key "$TMP/xmss_p.pem" --in "$TMP/xmsg.bin" --out "$TMP/xsig_p0.pem" 2>/dev/null
check_verify "hpks-xmss: Python sign (leaf 0) -> Java verify" \
    $CLI_JAVA verify --algo hpks-xmss --pubkey "$TMP/xmss_p_pub.pem" --in "$TMP/xmsg.bin" --sig "$TMP/xsig_p0.pem"

echo ""
echo "Results: $PASS PASS / $FAIL FAIL"
[ "$FAIL" -eq 0 ]
