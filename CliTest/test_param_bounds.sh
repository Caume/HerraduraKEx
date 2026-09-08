#!/usr/bin/env bash
# CliTest/test_param_bounds.sh — TODO #278: a CLI's own bound constant must be
# applied on EVERY path that consumes the parameter, not only the decode path.
#
# WHY THIS EXISTS.  The width axis (spec/check_language_parity.py's PARAMETERS
# table) compares a constant's VALUE across the four languages.  It found the
# XMSS height cap at 20 in all four — and enforcement in two.  Python's
# `_XMSS_MAX_H` and Java's `Codec.XMSS_MAX_H` each carry a comment naming
# themselves "genpkey's --xmss-height cap", and genpkey was the one path in
# both that never applied it:
#
#   Java    `1 << 32` wraps on an int (the shift uses the low 5 bits), so
#           `--xmss-height 32` reported "h=32, 1 leaves", wrote a ONE-leaf tree
#           labelled h = 32, and exited 0.  Nothing could read it back, Java
#           included — its own decode path bounds h to [1,20].
#   Python  no wraparound, so the same input asks for 2^32 leaves and the
#           process never returns.
#
# No source-level check can see this: the constant exists, at the same value,
# in all four.  Only running the CLI does.  Hence a script, and hence the
# out-of-range cases run BEFORE the accept-control — an in-range XMSS keygen
# costs minutes in Python and Java, and a rejection must be fast by definition.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

PASS=0; FAIL=0
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

CLIS=()
CLI_NAMES=()
add_cli() { CLIS+=("$1"); CLI_NAMES+=("$2"); }

add_cli "python3 HerraduraCli/herradura.py" python
[ -x HerraduraCli/herradura_cli ]    && add_cli "./HerraduraCli/herradura_cli" c
[ -x HerraduraCli/herradura_cli_go ] && add_cli "./HerraduraCli/herradura_cli_go" go
if command -v javac >/dev/null 2>&1; then
    bash bindings/java/build.sh >/dev/null 2>&1 || true
    [ -f bindings/java/herradurakex/HerraduraCli.class ] && \
        add_cli "java -cp bindings/java herradurakex.HerraduraCli" java
fi

echo "CLIs under test: ${CLI_NAMES[*]}"

# --- (a) --xmss-height outside [1,20] is refused, promptly, by every CLI ------
# 21 is one past the cap; 32 is the int-shift wraparound; 0 and -1 are the
# low end, where Python's `or 10` used to make 0 silently mean 10.
before_fail=$FAIL
for h in 0 -1 21 32 64; do
    for i in "${!CLIS[@]}"; do
        name="${CLI_NAMES[$i]}"
        out=$(timeout 30 ${CLIS[$i]} genpkey --algo hpks-xmss --xmss-height "$h" \
                  --out "$TMP/x.pem" 2>&1) && rc=0 || rc=$?
        if [ "$rc" -eq 124 ]; then
            echo "FAIL [$name] --xmss-height $h: no answer in 30s (an out-of-range"
            echo "     height must be refused, not attempted)"
            FAIL=$((FAIL+1))
        elif [ "$rc" -eq 0 ]; then
            echo "FAIL [$name] --xmss-height $h accepted (exit 0): $(echo "$out" | tail -1)"
            FAIL=$((FAIL+1))
        elif ! printf '%s' "$out" | grep -q 'xmss-height must be in \[1,20\]'; then
            echo "FAIL [$name] --xmss-height $h refused, but not with the shared"
            echo "     message: $(echo "$out" | tail -1)"
            FAIL=$((FAIL+1))
        else
            PASS=$((PASS+1))
        fi
    done
done
if [ "$FAIL" -eq "$before_fail" ]; then
    echo "PASS out-of-range --xmss-height refused by all ${#CLIS[@]} CLIs (5 values)"
fi

# --- (b) accept-control ------------------------------------------------------
# Without it, a CLI that refused EVERY height would score a perfect pass above.
# h=1 is the cheapest in-range value; the C CLI is the fast one, so run the
# control there when it is built and fall back to Python otherwise.
ctrl_idx=-1
for i in "${!CLI_NAMES[@]}"; do
    [ "${CLI_NAMES[$i]}" = "c" ] && ctrl_idx=$i
done
[ "$ctrl_idx" -lt 0 ] && ctrl_idx=0
ctrl_name="${CLI_NAMES[$ctrl_idx]}"
if timeout 300 ${CLIS[$ctrl_idx]} genpkey --algo hpks-xmss --xmss-height 1 \
        --out "$TMP/ok.pem" >/dev/null 2>&1 && [ -s "$TMP/ok.pem" ]; then
    echo "PASS accept-control: [$ctrl_name] --xmss-height 1 produces a key"
    PASS=$((PASS+1))
else
    echo "FAIL accept-control: [$ctrl_name] --xmss-height 1 produced no key —"
    echo "     the rejections above prove nothing if every height is refused"
    FAIL=$((FAIL+1))
fi

echo
echo "Results: $PASS PASS / $FAIL FAIL"
[ "$FAIL" -eq 0 ]
