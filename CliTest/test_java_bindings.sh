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

echo "=== herradurakex.KatVerify ==="
java -cp bindings/java herradurakex.KatVerify KAT/classical_quartet.json

echo "=== herradurakex.SelfTest ==="
java -cp bindings/java herradurakex.SelfTest

echo "PASS test_java_bindings"
