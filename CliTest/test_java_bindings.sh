#!/usr/bin/env bash
# CliTest/test_java_bindings.sh — TODO #192: builds and exercises the
# pure-Java herradurakex binding: KAT cross-check + round-trip self-test.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if ! command -v javac >/dev/null 2>&1; then
    echo "SKIP test_java_bindings: javac not found (install a JDK to run this test)"
    exit 0
fi

echo "=== bindings/java/build.sh ==="
bash bindings/java/build.sh

# TODO #314 pass 5: the Java BitArray conformance consumer.  It lives here
# rather than in test_kat_vectors.sh because this is where the Java toolchain is
# already built and on the path; the other three consumers run there.  ALL FOUR
# ports are now held to KAT/bitarray.json, which is what BITARRAY.md §8's pass 6
# was waiting for -- "the four agree" stops being a property of four people's
# care at one width and becomes a property of the code.
echo "=== herradurakex.VerifyBitArray (Java conformance, TODO #314 pass 5) ==="
java -cp bindings/java herradurakex.VerifyBitArray KAT/bitarray.json

echo "=== herradurakex.KatVerify ==="
java -cp bindings/java herradurakex.KatVerify KAT/classical_quartet.json

echo "=== herradurakex.SelfTest ==="
java -cp bindings/java herradurakex.SelfTest

echo "PASS test_java_bindings"
