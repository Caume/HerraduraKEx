#!/usr/bin/env bash
# CliTest/test_pem_reader_diff.sh — TODO #403: the four PEM readers, compared on
# generated input.
#
# SPEC.md §10.1 says every reader gives a file the same verdict: the same label
# and DER bytes, or the same refusal text.  test_malformed_pem_matrix.sh checks
# that on ~100 hand-picked files; the fuzz harnesses in Fuzz/ check only that a
# reader does not crash, and none covered Java.  This script feeds the SAME
# generated inputs (Fuzz/pem_diff/gen_cases.py: structured blocks straddling
# each §10.1 rule, and byte-level mutations of every KAT/pem/*.pem) to one small
# driver per language (Fuzz/pem_diff/), each calling its reader in process on
# the bytes as that CLI reads a file, and fails on any case where two disagree.
#
# A differential cannot see a rule all four readers get wrong the same way
# (CLAUDE.md, #298); that is what the matrix's named cases are for.  What it
# adds is volume: its first run found the one disagreement the matrix missed,
# the END-label refusal echoing unscreened bytes (#403).
#
# The verdict has two parts:
#   * agreement -- every case's result line is identical across the readers;
#   * coverage  -- the cases the readers agree on reach an accept and every one
#     of §10.1's twelve refusals, so a generator that drifted into producing one
#     kind of input cannot pass vacuously.
#
# HKX_PEMDIFF_SEEDS (default "1 2 3") and HKX_PEMDIFF_COUNT (default 20000 per
# seed) size the run; a failure prints the seed and case index, which
# `gen_cases.py SEED COUNT | sed -n IDX+1p` reproduces.
#
# Claimed by ci.yml's cross-lang-compat job (gcc, Go and a JDK installed).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
SEEDS="${HKX_PEMDIFF_SEEDS:-1 2 3}"
COUNT="${HKX_PEMDIFF_COUNT:-20000}"
PASS=0; FAIL=0
pass() { echo "PASS $1"; PASS=$((PASS+1)); }
fail() { echo "FAIL $1"; FAIL=$((FAIL+1)); }

# ── the drivers ───────────────────────────────────────────────────────────────
declare -A RUN=()
RUN[py]="python3 $ROOT/Fuzz/pem_diff/pem_diff_py.py"
if command -v gcc >/dev/null 2>&1 && gcc -O2 -o "$TMP/pem_diff_c" Fuzz/pem_diff/pem_diff_c.c; then
    RUN[c]="$TMP/pem_diff_c"
else echo "NOTE: C driver not built (gcc absent or the build failed)"; fi
if command -v go >/dev/null 2>&1 && go build -buildvcs=false -o "$TMP/pem_diff_go" ./Fuzz/pem_diff/go/; then
    RUN[go]="$TMP/pem_diff_go"
else echo "NOTE: Go driver not built (go absent or the build failed)"; fi
if command -v javac >/dev/null 2>&1 && bash bindings/java/build.sh >/dev/null \
   && javac -cp bindings/java -d "$TMP" Fuzz/pem_diff/PemDiff.java; then
    RUN[java]="java -cp $ROOT/bindings/java:$TMP PemDiff"
else echo "NOTE: Java driver not built (javac absent or the build failed)"; fi
LANGS=()
for l in c go py java; do [ -n "${RUN[$l]:-}" ] && LANGS+=("$l"); done
echo "Readers under test: ${LANGS[*]}"
if [ "${#LANGS[@]}" -lt 2 ]; then
    echo "FAIL test_pem_reader_diff: fewer than two readers, so nothing was compared." >&2
    [ "${HKX_ALLOW_SKIP:-0}" = "1" ] && exit 0
    exit 2
fi
REF="${LANGS[0]}"

# ── run every seed through every reader ───────────────────────────────────────
for seed in $SEEDS; do
    python3 Fuzz/pem_diff/gen_cases.py "$seed" "$COUNT" > "$TMP/cases_$seed.hex"
    for l in "${LANGS[@]}"; do
        if ! ${RUN[$l]} < "$TMP/cases_$seed.hex" > "$TMP/out_${seed}_$l" 2> "$TMP/err_$l"; then
            fail "seed $seed: the $l driver exited non-zero: $(head -c 300 "$TMP/err_$l")"
            continue
        fi
        n=$(wc -l < "$TMP/out_${seed}_$l")
        if [ "$n" -ne "$COUNT" ]; then
            fail "seed $seed: the $l driver answered $n of $COUNT cases"
        fi
    done
done
[ "$FAIL" -eq 0 ] || { echo "Results: $PASS PASS / $FAIL FAIL (readers: ${LANGS[*]})"; exit 1; }

# ── agreement and coverage ────────────────────────────────────────────────────
python3 - "$TMP" "$COUNT" "$REF" "${LANGS[@]}" -- $SEEDS > "$TMP/verdict" <<'PYEOF' || true
import sys
tmp, count, ref = sys.argv[1], int(sys.argv[2]), sys.argv[3]
k = sys.argv.index('--')
langs, seeds = sys.argv[4:k], sys.argv[k + 1:]

KINDS = {
    'OK': None,
    'PEM: missing BEGIN marker': 'eq', 'PEM: text before the BEGIN line': 'eq',
    'PEM: malformed BEGIN line': 'eq', 'PEM: missing END marker': 'eq',
    'PEM: malformed END line': 'eq', "PEM: END label '": 'prefix',
    'PEM: text after the END line': 'eq', 'PEM: empty body': 'eq',
    'PEM body is not valid base64: invalid character': 'eq',
    'PEM body is not valid base64: misplaced padding': 'eq',
    'PEM body is not valid base64: length is not a multiple of 4': 'eq',
    'PEM body is not valid base64: non-zero bits after the last byte': 'eq',
}
seen = dict.fromkeys(KINDS, 0)
unknown = []

def show(line):
    f = line.split(' ')
    if f[0] == 'ERR':
        return 'ERR ' + repr(bytes.fromhex(f[1]) if f[1] != '-' else b'')
    lab = bytes.fromhex(f[1]) if f[1] != '-' else b''
    der = bytes.fromhex(f[2]) if f[2] != '-' else b''
    return 'OK label=%r der=%d bytes %s' % (lab, len(der), der[:12].hex())

bad = 0
for s in seeds:
    outs = {l: open(f'{tmp}/out_{s}_{l}').read().split('\n')[:count] for l in langs}
    cases = open(f'{tmp}/cases_{s}.hex').read().split('\n')
    for i in range(count):
        rs = {l: outs[l][i] for l in langs}
        r0 = rs[ref]
        if any(r != r0 for r in rs.values()):
            bad += 1
            if bad <= 8:
                print(f'DIFF seed {s} case {i}: input {bytes.fromhex(cases[i])[:160]!r}')
                for l in langs:
                    print(f'    {l:5} {show(rs[l])}')
            continue
        f = r0.split(' ')
        if f[0] == 'OK':
            seen['OK'] += 1
            continue
        msg = bytes.fromhex(f[1]).decode('latin-1') if f[1] != '-' else ''
        for kind, how in KINDS.items():
            if how == 'eq' and msg == kind or how == 'prefix' and msg.startswith(kind):
                seen[kind] += 1
                break
        else:
            unknown.append(msg)

total = count * len(seeds)
print(f'AGREE {total - bad} {total}')
for kind, n in seen.items():
    print(f'KIND {n} {kind}')
for m in sorted(set(unknown))[:5]:
    print(f'UNKNOWN {m!r}')
PYEOF

grep '^DIFF\|^    ' "$TMP/verdict" || true
read -r _ agree total < <(grep '^AGREE' "$TMP/verdict" || echo "AGREE 0 0")
if [ "$total" -gt 0 ] && [ "$agree" -eq "$total" ]; then
    pass "all ${#LANGS[@]} readers agree on all $total generated cases (seeds: $SEEDS)"
else
    fail "readers disagree on $((total - agree)) of $total cases (first ones above)"
fi
while read -r _ n kind; do
    if [ "$n" -gt 0 ]; then pass "coverage: $n cases reach '$kind'"
    else fail "coverage: no agreed case reaches '$kind' (the generator no longer exercises it, or every case that did is a disagreement above)"; fi
done < <(grep '^KIND' "$TMP/verdict")
if grep -q '^UNKNOWN' "$TMP/verdict"; then
    fail "a refusal text outside SPEC.md §10.1: $(grep '^UNKNOWN' "$TMP/verdict" | head -3 | tr '\n' ' ')"
fi

echo ""
echo "Results: $PASS PASS / $FAIL FAIL (readers: ${LANGS[*]})"
[ "$FAIL" -eq 0 ]
