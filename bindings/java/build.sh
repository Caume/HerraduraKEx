#!/usr/bin/env bash
# Compiles the herradurakex Java package and its KAT verifier
# (TODO #192). Run from the repo root or from bindings/java/.
set -euo pipefail
cd "$(dirname "$0")"

javac -d . herradurakex/*.java
echo "Compiled bindings/java/herradurakex/*.class"
