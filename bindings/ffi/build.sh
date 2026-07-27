#!/usr/bin/env bash
# Builds libherradura_ffi.{so,dylib} from herradura_shim.c for the Python
# ctypes and Go cgo bindings under bindings/ffi/.
set -euo pipefail
cd "$(dirname "$0")"

case "$(uname -s)" in
    Darwin) OUT=libherradura_ffi.dylib; SHARED_FLAGS="-dynamiclib" ;;
    *)      OUT=libherradura_ffi.so;    SHARED_FLAGS="-shared" ;;
esac

gcc -O2 -fPIC -fvisibility=hidden $SHARED_FLAGS -o "$OUT" herradura_shim.c
echo "Built bindings/ffi/$OUT"
