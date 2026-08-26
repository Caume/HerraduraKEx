#!/usr/bin/env bash
# CliTest/test_malformed_pem_matrix.sh — TODO #240: the four CLIs must agree
# about which artifacts are malformed.
#
# TODO #239 range-checked every PEM field that sizes an allocation in the C CLI
# and stopped there.  The other three still multiplied wire counts straight into
# an allocation length, so a four-byte edit to a signature produced a MemoryError
# traceback (Python), "fatal error: out of memory" with a goroutine dump (Go), or
# a NegativeArraySizeException from `d * 2` wrapping past 2^31 (Java) — while C
# printed one line and exited 1.
#
# That divergence is the defect this script pins.  The bounds are a wire
# contract, not an implementation detail: an artifact one CLI refuses must not be
# one another accepts.  Every case is generated ONCE with the Python CLI and fed
# to all four, so the fixtures themselves are cross-language.
#
# The case table lives in CliTest/lib_malformed.sh, shared with
# test_weak_key_rejection.sh (which runs the same cases against the C CLI alone,
# and therefore also under the sanitizers job, where TODO #239's stack overflow
# is visible).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
PASS=0; FAIL=0

pass() { echo "PASS $1"; PASS=$((PASS+1)); }
fail() { echo "FAIL $1"; FAIL=$((FAIL+1)); }

declare -A CLI=()
CLI[py]="python3 $ROOT/HerraduraCli/herradura.py"
[ -x "$ROOT/HerraduraCli/herradura_cli" ]    && CLI[c]="$ROOT/HerraduraCli/herradura_cli"
[ -x "$ROOT/HerraduraCli/herradura_cli_go" ] && CLI[go]="$ROOT/HerraduraCli/herradura_cli_go"
if command -v javac >/dev/null 2>&1; then
    bash bindings/java/build.sh >/dev/null 2>&1
    # -Xmx is the JVM's version of the address-space cap the other three get
    # from ulimit -v; see lib_malformed.sh's HKX_MAL_VLIMIT note.
    CLI[java]="java -Xmx1g -cp $ROOT/bindings/java herradurakex.HerraduraCli"
fi

LANGS=()
for l in py c go java; do
    [ -n "${CLI[$l]:-}" ] && LANGS+=("$l")
done
echo "Languages under test: ${LANGS[*]}"

# TODO #229: an unannounced absence reads as full coverage when it is not.
. "$ROOT/CliTest/lib_build.sh"
for l in c go; do
    [ -n "${CLI[$l]:-}" ] || echo "NOTE: $l CLI absent — $(hkx_why "$l")"
done
[ -n "${CLI[java]:-}" ] || echo "NOTE: java CLI absent — javac is not installed"

. "$ROOT/CliTest/lib_malformed.sh"
HKX_MAL_ROOT="$ROOT"
HKX_MAL_DIR="$TMP"
hkx_mal_fixtures "$TMP"

for l in "${LANGS[@]}"; do
    echo ""
    echo "=== $l ==="
    # 2 GiB of address space is generous for every case here and tight enough
    # that a missing bound fails fast; the JVM is capped with -Xmx instead.
    if [ "$l" = java ]; then HKX_MAL_VLIMIT=""; else HKX_MAL_VLIMIT=2000000; fi
    export HKX_MAL_VLIMIT
    # shellcheck disable=SC2086
    hkx_mal_suite "$l" ${CLI[$l]}
done

echo ""
echo "Results: $PASS PASS / $FAIL FAIL (languages: ${LANGS[*]})"
[ "$FAIL" -eq 0 ]
