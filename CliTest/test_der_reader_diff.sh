#!/usr/bin/env bash
# CliTest/test_der_reader_diff.sh — TODO #404: the four DER parsers, compared on
# generated input.
#
# test_pem_reader_diff.sh (TODO #403) holds the PEM readers to one verdict; this
# does the same for the DER SEQUENCE-of-INTEGERs parser behind them.  The same
# generated inputs (Fuzz/der_diff/gen_cases.py: SEQUENCEs built to straddle the
# length, tag, sign and trailing-byte rules, and byte edits of the DER in every
# KAT PEM) go to one driver per language (Fuzz/der_diff/), each running its
# CLI's generic DER steps in process.  The test fails when two parsers:
#   * give an input different verdicts (one accepts, another refuses), or
#   * accept it with different values, encoded widths or leads (TODO #373);
# and when any parser CRASHES (an exception that is not its refusal), even if
# the others agree.
#
# Refusal TEXTS are not compared: the structural ones were never one set across
# the four, and their checks run in a different order in each, so a file
# breaking two rules is refused for a different one.  Only #372's and #373's
# texts are shared (see TODO #404).
#
# Coverage: the agreed cases must reach an accept, an accept of more than 16
# items (past the C CLI's store), and each kind of refusal (named by the Go
# parser's text), so a drifting generator cannot pass vacuously.
#
# Then three CLI cells, through the four real CLIs: a key with 17 DER items, one
# whose 17th item is negative, and one with an INTEGER length past 2^31.  Before
# TODO #404 the C CLI stopped at item 16 (it said "16 DER items" and never saw
# item 17) and the Java CLI crashed on the third ("error: -1").
#
# HKX_DERDIFF_SEEDS (default "1 2 3") and HKX_DERDIFF_COUNT (default 20000 per
# seed) size the run.  Claimed by ci.yml's cross-lang-compat job.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
SEEDS="${HKX_DERDIFF_SEEDS:-1 2 3}"
COUNT="${HKX_DERDIFF_COUNT:-20000}"
PASS=0; FAIL=0
pass() { echo "PASS $1"; PASS=$((PASS+1)); }
fail() { echo "FAIL $1"; FAIL=$((FAIL+1)); }

# ── the drivers ───────────────────────────────────────────────────────────────
declare -A RUN=()
RUN[py]="python3 $ROOT/Fuzz/der_diff/der_diff_py.py"
if command -v gcc >/dev/null 2>&1 && gcc -O2 -o "$TMP/der_diff_c" Fuzz/der_diff/der_diff_c.c; then
    RUN[c]="$TMP/der_diff_c"
else echo "NOTE: C driver not built (gcc absent or the build failed)"; fi
if command -v go >/dev/null 2>&1 && go build -buildvcs=false -o "$TMP/der_diff_go" ./Fuzz/der_diff/go/; then
    RUN[go]="$TMP/der_diff_go"
else echo "NOTE: Go driver not built (go absent or the build failed)"; fi
if command -v javac >/dev/null 2>&1 && bash bindings/java/build.sh >/dev/null \
   && javac -cp bindings/java -d "$TMP" Fuzz/der_diff/herradurakex/DerDiff.java; then
    RUN[java]="java -cp $ROOT/bindings/java:$TMP herradurakex.DerDiff"
else echo "NOTE: Java driver not built (javac absent or the build failed)"; fi
LANGS=()
for l in go c py java; do [ -n "${RUN[$l]:-}" ] && LANGS+=("$l"); done
echo "Parsers under test: ${LANGS[*]}"
if [ "${#LANGS[@]}" -lt 2 ]; then
    echo "FAIL test_der_reader_diff: fewer than two parsers, so nothing was compared." >&2
    [ "${HKX_ALLOW_SKIP:-0}" = "1" ] && exit 0
    exit 2
fi

# ── run every seed through every parser ───────────────────────────────────────
for seed in $SEEDS; do
    python3 Fuzz/der_diff/gen_cases.py "$seed" "$COUNT" > "$TMP/cases_$seed.hex"
    for l in "${LANGS[@]}"; do
        if ! ${RUN[$l]} < "$TMP/cases_$seed.hex" > "$TMP/out_${seed}_$l" 2> "$TMP/err_$l"; then
            fail "seed $seed: the $l driver exited non-zero: $(head -c 300 "$TMP/err_$l")"
            continue
        fi
        n=$(wc -l < "$TMP/out_${seed}_$l")
        [ "$n" -eq "$COUNT" ] || fail "seed $seed: the $l driver answered $n of $COUNT cases"
    done
done
[ "$FAIL" -eq 0 ] || { echo "Results: $PASS PASS / $FAIL FAIL (parsers: ${LANGS[*]})"; exit 1; }

# ── agreement, crashes and coverage ───────────────────────────────────────────
python3 - "$TMP" "$COUNT" "${LANGS[@]}" -- $SEEDS > "$TMP/verdict" <<'PYEOF' || true
import sys
tmp, count = sys.argv[1], int(sys.argv[2])
k = sys.argv.index('--')
langs, seeds = sys.argv[3:k], sys.argv[k + 1:]
oracle = 'go' if 'go' in langs else None     # coverage is named by Go's texts

KINDS = ['OK', 'OK, more than 16 items', 'bytes after the DER SEQUENCE',
         'DER length not in its shortest form', 'is a negative INTEGER', 'is an empty INTEGER',
         'DER: not a SEQUENCE', 'DER: SEQUENCE body truncated', 'DER: expected INTEGER tag',
         'DER: INTEGER length exceeds SEQUENCE body', 'length field too large',
         'empty length field']
seen = dict.fromkeys(KINDS, 0)

def msg(line):
    f = line.split(' ', 1)
    return bytes.fromhex(f[1]).decode('utf-8', 'replace') if f[0] == 'ERR' and len(f) > 1 else ''

def key(line):                                   # what must agree
    return line if line.startswith('OK') else 'ERR'

bad = crashes = 0
for s in seeds:
    outs = {l: open(f'{tmp}/out_{s}_{l}').read().split('\n')[:count] for l in langs}
    cases = open(f'{tmp}/cases_{s}.hex').read().split('\n')
    for i in range(count):
        rs = {l: outs[l][i] for l in langs}
        exc = [l for l in langs if msg(rs[l]).startswith('EXC ')]
        if exc:
            crashes += 1
            if crashes <= 5:
                print(f'CRASH seed {s} case {i} ({", ".join(exc)}): input {cases[i][:96]}')
                for l in exc:
                    print(f'    {l:5} {msg(rs[l])[:150]}')
        if len({key(r) for r in rs.values()}) > 1:
            bad += 1
            if bad <= 8:
                print(f'DIFF seed {s} case {i}: input {cases[i][:96]}')
                for l in langs:
                    r = rs[l]
                    print(f'    {l:5} ' + (r[:150] if r.startswith('OK') else 'ERR ' + msg(r)[:140]))
            continue
        if oracle is None:
            continue
        r = rs[oracle]
        if r.startswith('OK'):
            seen['OK'] += 1
            if r.count(' ') > 16:
                seen['OK, more than 16 items'] += 1
            continue
        m = msg(r)
        for kind in KINDS[2:]:
            if kind in m:
                seen[kind] += 1
                break

total = count * len(seeds)
print(f'AGREE {total - bad} {total}')
print(f'CRASHES {crashes}')
if oracle:
    for kind, n in seen.items():
        print(f'KIND {n} {kind}')
PYEOF

grep '^DIFF\|^CRASH\|^    ' "$TMP/verdict" || true
read -r _ agree total < <(grep '^AGREE' "$TMP/verdict" || echo "AGREE 0 0")
if [ "$total" -gt 0 ] && [ "$agree" -eq "$total" ]; then
    pass "all ${#LANGS[@]} parsers give the same verdict, values and encodings on all $total cases (seeds: $SEEDS)"
else
    fail "parsers disagree on $((total - agree)) of $total cases (first ones above)"
fi
read -r _ crashes < <(grep '^CRASHES' "$TMP/verdict" || echo "CRASHES -1")
if [ "$crashes" -eq 0 ]; then pass "no parser crashed on any case"
else fail "a parser crashed on $crashes cases (first ones above)"; fi
if grep -q '^KIND' "$TMP/verdict"; then
    while read -r _ n kind; do
        if [ "$n" -gt 0 ]; then pass "coverage: $n agreed cases reach '$kind'"
        else fail "coverage: no agreed case reaches '$kind' (the generator no longer exercises it, or every case that did is a disagreement above)"; fi
    done < <(grep '^KIND' "$TMP/verdict")
else
    echo "NOTE: coverage n/a -- it is named by the Go parser's texts, and Go is not under test"
fi

# ── CLI cells: past item 16, and a length past 2^31 ───────────────────────────
declare -A CLI=()
CLI[py]="python3 $ROOT/HerraduraCli/herradura.py"
[ -x HerraduraCli/herradura_cli ]    && CLI[c]="$ROOT/HerraduraCli/herradura_cli"
[ -x HerraduraCli/herradura_cli_go ] && CLI[go]="$ROOT/HerraduraCli/herradura_cli_go"
[ -n "${RUN[java]:-}" ] && CLI[java]="java -cp $ROOT/bindings/java herradurakex.HerraduraCli"
python3 - "$TMP" <<'PYEOF'
import os, sys
sys.path.insert(0, os.path.join(os.getcwd(), 'HerraduraCli'))
import codec
t, lab = sys.argv[1], 'HERRADURA HKEX-GF PRIVATE KEY'
items = [codec.der_int(i + 1) for i in range(17)]
open(f'{t}/k17.pem', 'w').write(codec.pem_wrap(lab, codec.der_seq(*items)))
items[16] = b'\x02\x01\x83'
open(f'{t}/k17neg.pem', 'w').write(codec.pem_wrap(lab, codec.der_seq(*items)))
big = bytearray(codec.der_seq(codec.der_int(1), codec.der_int(2)) + b'\x02\x84\xff\xff\xff\xff')
big[1] = len(big) - 2
open(f'{t}/kbig.pem', 'w').write(codec.pem_wrap(lab, bytes(big)))
# the control: a real three-item key, which every CLI must read
open(f'{t}/k3.pem', 'w').write(codec.pem_wrap(lab, codec.der_seq(
    codec.der_int(5, 32), codec.der_int(9, 32), codec.der_int(256))))
PYEOF
cell() {   # name, file, expected text ('' = must succeed)
    local name="$1" f="$2" want="$3" l out rc
    for l in c go py java; do
        [ -n "${CLI[$l]:-}" ] || continue
        out=$(${CLI[$l]} pkey --in "$TMP/$f" --pubout --out "$TMP/o_$l.pem" 2>&1) && rc=0 || rc=$?
        if [ -z "$want" ]; then
            if [ "$rc" -eq 0 ]; then pass "$name ($l)"; else fail "$name ($l): rc=$rc $out"; fi
        elif [ "$rc" -ne 0 ] && [[ "$out" == *"$want"* ]]; then pass "$name ($l)"
        else fail "$name ($l): rc=$rc, expected '$want': $out"; fi
    done
}
cell "a 3-item key reads (control)" k3.pem ""
cell "17 DER items: refused with the true count" k17.pem \
    "malformed PEM 'HERRADURA HKEX-GF PRIVATE KEY': 17 DER items, expected 3"
cell "item 17 negative: refused at item 17" k17neg.pem \
    "malformed PEM 'HERRADURA HKEX-GF PRIVATE KEY': field 16 is a negative INTEGER"
for l in go py java; do        # C names a structural refusal by the file
    [ -n "${CLI[$l]:-}" ] || continue
    out=$(${CLI[$l]} pkey --in "$TMP/kbig.pem" --pubout --out "$TMP/o.pem" 2>&1) && rc=0 || rc=$?
    if [ "$rc" -ne 0 ] && [[ "$out" == *"DER: INTEGER length exceeds SEQUENCE body"* ]]; then
        pass "an INTEGER length past 2^31: refused by name ($l)"
    else fail "an INTEGER length past 2^31 ($l): rc=$rc: $out"; fi
done
if [ -n "${CLI[c]:-}" ]; then
    out=$(${CLI[c]} pkey --in "$TMP/kbig.pem" --pubout --out "$TMP/o.pem" 2>&1) && rc=0 || rc=$?
    if [ "$rc" -ne 0 ] && [[ "$out" == *"cannot parse DER from:"* ]]; then
        pass "an INTEGER length past 2^31: refused (c)"
    else fail "an INTEGER length past 2^31 (c): rc=$rc: $out"; fi
fi

echo ""
echo "Results: $PASS PASS / $FAIL FAIL (parsers: ${LANGS[*]})"
[ "$FAIL" -eq 0 ]
