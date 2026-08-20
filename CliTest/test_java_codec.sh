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

# ── Session-key DER width parity (TODO #219) ────────────────────────────────
# The session-key field is MINIMAL-width in every implementation, unlike the
# fixed-width private/public key fields. Java once padded it to nbits/8, which
# emits a redundant leading 0x00 — non-canonical DER, and byte-different from
# python/c/go — whenever the key's top byte is 0x00 and the next byte is below
# 0x80. That is about 1 session key in 512, so random-key tests only caught it
# as a rare cross-language CI flake. These vectors hit the case deterministically.
#
#   [0] top byte 0x00, next byte < 0x80  -> the regression trigger
#   [1] two leading zero bytes
#   [2] top byte 0x00, next byte >= 0x80 -> DER sign byte makes both agree
#   [3] no leading zero, high bit set    -> both emit a sign byte
#   [4] no leading zero, high bit clear  -> plain case
#   [5] small value                      -> width shrinks to a few bytes
#   [6] zero                             -> minimum width is 1, not 0
SESSION_VECTORS=(
    "002abbccddeeff00112233445566778899aabbccddeeff00112233445566778f"
    "00002abbccddeeff00112233445566778899aabbccddeeff001122334455667f"
    "00aabbccddeeff00112233445566778899aabbccddeeff00112233445566778f"
    "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778f11"
    "2abbccddeeff00112233445566778899aabbccddeeff00112233445566778f11"
    "42"
    "0"
)

PY_ENCODE_SESSION='
import sys, importlib.util
spec = importlib.util.spec_from_file_location("hcli", sys.argv[1])
m = importlib.util.module_from_spec(spec)
sys.modules["hcli"] = m
try:
    spec.loader.exec_module(m)
except SystemExit:
    pass
sys.stdout.write(m._encode_session_key(int(sys.argv[2], 16), 256))
'

PY_DECODE_SESSION='
import sys
sys.path.insert(0, sys.argv[1])
from codec import pem_unwrap, der_parse_seq
label, der = pem_unwrap(open(sys.argv[2]).read())
key, nbits = der_parse_seq(der)
print(f"{key:x}", nbits)
'

for v in "${SESSION_VECTORS[@]}"; do
    python3 -c "$PY_ENCODE_SESSION" "$ROOT/HerraduraCli/herradura.py" "$v" > "$TMP/py_session.pem"
    java -cp "$ROOT/bindings/java" herradurakex.CodecTest encode-session "$v" 256 "$TMP/java_session.pem"

    if cmp -s "$TMP/py_session.pem" "$TMP/java_session.pem"; then
        check "session-key PEM byte-identical python/java (0x${v:0:8})" 0
    else
        echo "  python: $(grep -v -- '-----' "$TMP/py_session.pem" | tr -d '\n')"
        echo "  java:   $(grep -v -- '-----' "$TMP/java_session.pem" | tr -d '\n')"
        check "session-key PEM byte-identical python/java (0x${v:0:8})" 1
    fi

    # The value must still survive a Java-encode -> Python-decode round trip.
    py_rt=$(python3 -c "$PY_DECODE_SESSION" "$ROOT/HerraduraCli" "$TMP/java_session.pem")
    expect_rt=$(python3 -c 'import sys; print(f"{int(sys.argv[1], 16):x}", 256)' "$v")
    if [ "$py_rt" = "$expect_rt" ]; then
        check "java session key decodes unchanged in python (0x${v:0:8})" 0
    else
        echo "  expected: $expect_rt"
        echo "  got:      $py_rt"
        check "java session key decodes unchanged in python (0x${v:0:8})" 1
    fi
done

echo "== test_java_codec.sh: $PASS passed, $FAIL failed =="
[ "$FAIL" -eq 0 ]
