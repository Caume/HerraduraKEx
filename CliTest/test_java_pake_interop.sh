#!/usr/bin/env bash
# CliTest/test_java_pake_interop.sh — TODO #203: Java <-> Python CLI
# interop for aPAKE (pake-register / pake-demo), mirroring test_pake.sh's
# pattern. There is no cross-language pake-login flow upstream (pake-demo
# runs both sides locally in one call, matching the Python reference's own
# demo-only scope), so the interop check here is: (a) each CLI's
# pake-register output decodes cleanly in the other language, and (b) each
# CLI's pake-demo self-consistently accepts the right password and
# rejects the wrong one.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if ! command -v javac >/dev/null 2>&1; then
    echo "SKIP test_java_pake_interop: javac not found (install a JDK to run this test)"
    exit 0
fi

bash bindings/java/build.sh >/dev/null

CLI_JAVA="java -cp bindings/java herradurakex.HerraduraCli"
CLI_PY="python3 $ROOT/HerraduraCli/herradura.py"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
PASS=0; FAIL=0

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

# ── Java pake-register output decodes cleanly under the Python CLI ─────────
$CLI_JAVA genpkey --algo oprf --out "$TMP/jk.pem"
$CLI_JAVA pake-register --key "$TMP/jk.pem" --username alice --password "correct horse battery staple" --out "$TMP/jrec.pem"
set +e
python3 - "$TMP/jrec.pem" >/dev/null 2>&1 <<'EOF'
import sys
sys.path.insert(0, "HerraduraCli")
from herradura import _load_pake_record
_load_pake_record(sys.argv[1])
EOF
check "aPAKE: Java pake-register record decodes under Python" $?
set -e

# ── Python pake-register output decodes cleanly under the Java CLI ─────────
$CLI_PY genpkey --algo oprf --out "$TMP/pk.pem" >/dev/null 2>&1
$CLI_PY pake-register --key "$TMP/pk.pem" --username bob --password "s3cr3t" --out "$TMP/prec.pem" >/dev/null 2>&1
set +e
cat > "$TMP/DecPake.java" <<'EOF'
import herradurakex.Codec;
import herradurakex.Hpake;
import java.nio.file.*;
public class DecPake {
    public static void main(String[] a) throws Exception {
        String pem = new String(Files.readAllBytes(Paths.get(a[0])));
        Codec.decodePakeRecord(pem);
    }
}
EOF
javac -cp bindings/java -d "$TMP" "$TMP/DecPake.java" >/dev/null 2>&1
java -cp "bindings/java:$TMP" DecPake "$TMP/prec.pem" >/dev/null 2>&1
check "aPAKE: Python pake-register record decodes under Java" $?
set -e

# ── pake-demo: both CLIs accept the correct password and reject the wrong
#    one, and produce a 64-char-hex session key ─────────────────────────────
JAVA_OUT=$($CLI_JAVA pake-demo --key "$TMP/jk.pem" --username alice --password "correct horse battery staple")
if echo "$JAVA_OUT" | grep -q "aPAKE login succeeded" && echo "$JAVA_OUT" | grep -q "correctly rejects wrong password"; then
    echo "PASS aPAKE: Java pake-demo accepts correct / rejects wrong password"
    PASS=$((PASS+1))
else
    echo "FAIL aPAKE: Java pake-demo unexpected output: $JAVA_OUT"
    FAIL=$((FAIL+1))
fi
JAVA_SK=$(echo "$JAVA_OUT" | grep "session key:" | sed 's/.*session key: //' | tr -d '\r\n')
if [ "${#JAVA_SK}" -eq 64 ]; then
    echo "PASS aPAKE: Java pake-demo session key is 64-char hex"
    PASS=$((PASS+1))
else
    echo "FAIL aPAKE: Java pake-demo session key wrong length: '$JAVA_SK'"
    FAIL=$((FAIL+1))
fi

PY_OUT=$($CLI_PY pake-demo --key "$TMP/pk.pem" --username bob --password "s3cr3t" 2>/dev/null)
if echo "$PY_OUT" | grep -q "aPAKE login succeeded" && echo "$PY_OUT" | grep -q "correctly rejects wrong password"; then
    echo "PASS aPAKE: Python pake-demo accepts correct / rejects wrong password"
    PASS=$((PASS+1))
else
    echo "FAIL aPAKE: Python pake-demo unexpected output: $PY_OUT"
    FAIL=$((FAIL+1))
fi

echo ""
echo "Results: $PASS PASS / $FAIL FAIL"
[ "$FAIL" -eq 0 ]
