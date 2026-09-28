#!/usr/bin/env bash
# TODO #324: build and RUN every C translation unit that includes herradura.h
# with uninitialised locals poisoned, so a BitArray whose width was never set is
# a deterministic abort rather than whatever the stack happened to hold.
#
# WHY THIS IS A SCRIPT.  TODO #314 pass 2 introduced the technique and pass 3
# recorded its limit -- "a tool that enumerates sites enumerates the sites you
# point it at".  TODO #315 then widened it and wrote that "the whole C tree is
# poison-built and RUN now", naming seven targets.  That was true of the act and
# not of the tree: it was a manual invocation that left NO artifact, so it could
# not be re-run, could not be checked, and did not cover a file added later.
# The tree has TEN such translation units.  The three #315's list omitted --
# bindings/ffi/herradura_shim.c, benchmarks/v3_consumer_cost.c and
# docs/examples/c/hello_herradura.c -- ALL THREE carried the defect, and the
# shim's was a stack smash on every call for seventeen releases.
#
# So the set is DISCOVERED, not enumerated, on run_findings_gates.py's model
# (TODO #289): a list is exactly what makes "nobody got round to it" look
# identical to "it passes".  A TU that includes herradura.h and is not covered
# here is an ERROR.
#
# TWO SHAPES, and the distinction is what hid the shim.  A TU with main() is
# built and RUN -- poisoning is a run-time detector, so building alone proves
# nothing.  A TU WITHOUT main() is a library; it has nothing to run, which is
# precisely why the shim's defect survived a sweep that ran things.  Those are
# built into a driver that exercises them, and for the shim that driver already
# existed and was run by nothing (see the coverage guard in ci.yml).
set -uo pipefail

cd "$(dirname "$0")/.."
POISON="-ftrivial-auto-var-init=pattern"
CC="${CC:-gcc}"
CFLAGS="-O2 -I. $POISON"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

fail=0; ran=0; built=0
note() { printf '  %-46s %s\n' "$1" "$2"; }

# ---- discover every TU that includes herradura.h -------------------------
mapfile -t TUS < <(grep -rl '#include.*herradura\.h' --include='*.c' . \
                   | sed 's|^\./||' | sort)
echo "Poisoned build ($POISON)"
echo "Discovered ${#TUS[@]} translation unit(s) including herradura.h:"
printf '  %s\n' "${TUS[@]}"
echo

# ---- TUs with main(): build and RUN --------------------------------------
echo "== with main(): built and RUN =="
for tu in "${TUS[@]}"; do
    grep -qE '^[[:space:]]*int[[:space:]]+main[[:space:]]*\(' "$tu" || continue
    bin="$TMP/$(echo "$tu" | tr '/ ' '__').bin"
    if ! $CC $CFLAGS -o "$bin" "$tu" -lm 2>"$TMP/cc.log"; then
        note "$tu" "BUILD FAILED"; sed 's/^/      /' "$TMP/cc.log" | head -5
        fail=1; continue
    fi
    built=$((built+1))
    # REDUCED WORK, not a shortened timeout.  These are width smoke runs, not
    # benchmarks, and a bad width aborts on the first operation -- but "treat a
    # timeout as a pass" would be exactly the vacuous pass this repo refuses
    # (#234), so a TU that is slow gets a smaller JOB via its own documented
    # knob and still has to finish.  dudect_timing_audit takes its round count
    # as argv[1] (default 4000, measured at 211 s under poison); the CLI needs a
    # subcommand to do anything at all.  A TU with no knob runs whole, and its
    # elapsed time is printed so a slow newcomer is visible rather than quietly
    # doubling this step.
    case "$tu" in
      CryptosuiteTests/*)                   args=(-r 2 -t 0.05) ;;
      SecurityProofsCode/dudect_timing_audit.c) args=(10) ;;
      HerraduraCli/herradura_cli.c)         args=(--help) ;;
      *)                                    args=() ;;
    esac
    t_start=$SECONDS
    if timeout 600 "$bin" "${args[@]}" >"$TMP/run.log" 2>&1; then
        note "$tu" "ok (built + ran, $((SECONDS-t_start))s)"; ran=$((ran+1))
    else
        rc=$?
        note "$tu" "RAN AND FAILED (exit $rc)"
        grep -iE 'herradura:|E_WIDTH|smash|Abort|Segmentation' "$TMP/run.log" \
            | head -3 | sed 's/^/      /'
        tail -3 "$TMP/run.log" | sed 's/^/      /'
        fail=1
    fi
done

# ---- TUs without main(): a library needs a driver ------------------------
echo
echo "== without main(): a library has nothing to run, so it needs a driver =="
for tu in "${TUS[@]}"; do
    grep -qE '^[[:space:]]*int[[:space:]]+main[[:space:]]*\(' "$tu" && continue
    case "$tu" in
      bindings/ffi/herradura_shim.c)
        # Its driver is the harness that existed and that no job ran.
        so="$TMP/libherradura_ffi.so"
        if ! $CC $CFLAGS -shared -fPIC -o "$so" "$tu" -lm 2>"$TMP/cc.log"; then
            note "$tu" "BUILD FAILED"; head -5 "$TMP/cc.log" | sed 's/^/      /'
            fail=1; continue
        fi
        built=$((built+1))
        cp "$so" bindings/ffi/libherradura_ffi.so
        if timeout 600 python3 bindings/ffi/python/test_ffi_correctness.py \
             >"$TMP/run.log" 2>&1; then
            note "$tu" "ok (built + driven by test_ffi_correctness.py)"
            ran=$((ran+1))
        else
            note "$tu" "DRIVER FAILED"
            grep -iE 'smash|Abort|Segmentation|E_WIDTH|FAIL' "$TMP/run.log" \
                | head -3 | sed 's/^/      /'
            fail=1
        fi
        ;;
      *)
        note "$tu" "NO DRIVER — add one or say why here (TODO #324)"
        fail=1
        ;;
    esac
done

# ---- the width guard's two spellings must agree --------------------------
echo
echo "== ba_nbytes' inline guard vs ba_check_width =="
if $CC $CFLAGS -o "$TMP/wg" tools/check_ba_width_guard.c -lm 2>"$TMP/cc.log"; then
    if timeout 120 "$TMP/wg" | sed 's/^/  /'; then :; else fail=1; fi
else
    echo "  BUILD FAILED"; head -5 "$TMP/cc.log" | sed 's/^/      /'; fail=1
fi

echo
echo "Discovered ${#TUS[@]}, built $built, ran $ran."
if [ "$fail" -ne 0 ]; then
    echo "*** FAILED: the poisoned build found at least one problem ***"
    exit 1
fi
echo "*** OK: every discovered translation unit builds, runs and is width-clean ***"
