#!/usr/bin/env bash
# CliTest/test_java_codec.sh — TODO #197: cross-check the Java PEM/DER codec
# against Python-CLI-produced key files (both directions). SKIPs (exit 0)
# if javac is not available, matching test_java_bindings.sh's pattern.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CLI_PY="python3 $ROOT/HerraduraCli/herradura.py"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
PASS=0; FAIL=0

if ! command -v javac >/dev/null 2>&1; then
    echo "SKIP test_java_codec.sh: javac not found"
    exit 0
fi

bash "$ROOT/bindings/java/build.sh" >/dev/null

check() {
    local label="$1" cond="$2"
    if [ "$cond" = "0" ]; then
        echo "PASS $label"; PASS=$((PASS+1))
    else
        echo "FAIL $label"; FAIL=$((FAIL+1))
    fi
}

# ── Java round-trip self-test (Codec-only, no cross-language files) ────────
if java -cp "$ROOT/bindings/java" herradurakex.CodecTest > "$TMP/java_roundtrip.out" 2>&1; then
    check "java codec round-trip" 0
else
    cat "$TMP/java_roundtrip.out"
    check "java codec round-trip" 1
fi

# ── Python-produced key decoded by Java ─────────────────────────────────────
$CLI_PY genpkey --algo hkex-gf --out "$TMP/py_priv.pem"
$CLI_PY pkey --in "$TMP/py_priv.pem" --pubout --out "$TMP/py_pub.pem"

py_priv_hex=$(python3 -c "
import sys; sys.path.insert(0, '$ROOT/HerraduraCli')
from codec import pem_unwrap, der_parse_seq
label, der = pem_unwrap(open('$TMP/py_priv.pem').read())
priv, pub, nbits = der_parse_seq(der)
print(f'{priv:x}')
print(f'{pub:x}')
print(nbits)
")
java_priv_hex=$(java -cp "$ROOT/bindings/java" herradurakex.CodecTest decode-priv "$TMP/py_priv.pem")

if [ "$py_priv_hex" = "$java_priv_hex" ]; then
    check "python-produced private key decoded by Java" 0
else
    echo "  python: $py_priv_hex"
    echo "  java:   $java_priv_hex"
    check "python-produced private key decoded by Java" 1
fi

py_pub_hex=$(python3 -c "
import sys; sys.path.insert(0, '$ROOT/HerraduraCli')
from codec import pem_unwrap, der_parse_seq
label, der = pem_unwrap(open('$TMP/py_pub.pem').read())
pub, nbits = der_parse_seq(der)
print(f'{pub:x}')
print(nbits)
")
java_pub_hex=$(java -cp "$ROOT/bindings/java" herradurakex.CodecTest decode-pub "$TMP/py_pub.pem")

if [ "$py_pub_hex" = "$java_pub_hex" ]; then
    check "python-produced public key decoded by Java" 0
else
    echo "  python: $py_pub_hex"
    echo "  java:   $java_pub_hex"
    check "python-produced public key decoded by Java" 1
fi

# ── Java-produced key decoded by Python ─────────────────────────────────────
priv_val=$(python3 -c "import random; print(f'{random.getrandbits(256):x}')")

# Derive pub with the Python suite directly (importlib, filename has spaces).
pub_val=$(python3 - "$priv_val" <<PYEOF
import sys, importlib.util
priv = int(sys.argv[1], 16)
spec = importlib.util.spec_from_file_location("suite", "$ROOT/Herradura cryptographic suite.py")
suite = importlib.util.module_from_spec(spec)
spec.loader.exec_module(suite)
print(f'{suite.gf_pow(suite.GF_GEN, priv, suite.GF_POLY[256], 256):x}')
PYEOF
)

java -cp "$ROOT/bindings/java" herradurakex.CodecTest encode-priv "$priv_val" "$pub_val" "$TMP/java_priv.pem"

py_decoded=$(python3 -c "
import sys; sys.path.insert(0, '$ROOT/HerraduraCli')
from codec import pem_unwrap, der_parse_seq
label, der = pem_unwrap(open('$TMP/java_priv.pem').read())
priv, pub, nbits = der_parse_seq(der)
print(f'{priv:x}')
print(f'{pub:x}')
print(nbits)
")
expected=$(printf '%s\n%s\n256' "$priv_val" "$pub_val")

if [ "$py_decoded" = "$expected" ]; then
    check "java-produced private key decoded by Python" 0
else
    echo "  expected: $expected"
    echo "  python:   $py_decoded"
    check "java-produced private key decoded by Python" 1
fi

echo "== test_java_codec.sh: $PASS passed, $FAIL failed =="
[ "$FAIL" -eq 0 ]
