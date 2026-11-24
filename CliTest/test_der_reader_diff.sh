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
#   * give an input different verdicts (one accepts, another refuses),
#   * accept it with different values, encoded widths or leads (TODO #373), or
#   * refuse it with different TEXTS (TODO #405: SPEC.md section 10.2 names the
#     one refusal a malformed SEQUENCE gets, the first fault of a left-to-right
#     walk, and every CLI's der_seq_check / DerSeqCheck / derSeqCheck prints it);
# and when any parser CRASHES (an exception that is not its refusal), even if
# the others agree.
#
# Coverage: the agreed cases must reach an accept, an accept of more than 16
# items (past the C CLI's store), and each of section 10.2's refusals, so a
# drifting generator cannot pass vacuously.
#
# Then CLI cells, through the four real CLIs, each refusal checked by its full
# text: a key with 17 DER items, one whose 17th item is negative, one with an
# INTEGER length past 2^31 (before TODO #404 the C CLI stopped at item 16 and the
# Java CLI crashed on it, "error: -1"), and one structural fault per kind of
# section 10.2 refusal, the envelope `pkey --decrypt` reads among them (before
# TODO #405 the C CLI named none of them: "cannot parse DER from: PATH").
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
oracle = langs[0]                  # the texts agree, so any parser names the kind

KINDS = ['OK', 'OK, more than 16 items', 'not a DER SEQUENCE', 'DER length field truncated',
         'DER length field longer than 4 bytes', 'DER length not in its shortest form',
         'DER SEQUENCE body truncated', 'bytes after the DER SEQUENCE', 'is not an INTEGER',
         'runs past the DER SEQUENCE', 'is an empty INTEGER', 'is a negative INTEGER']
seen = dict.fromkeys(KINDS, 0)

def msg(line):
    f = line.split(' ', 1)
    return bytes.fromhex(f[1]).decode('utf-8', 'replace') if f[0] == 'ERR' and len(f) > 1 else ''

def key(line):                     # what must agree: the whole line (TODO #405)
    return line

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
for kind, n in seen.items():
    print(f'KIND {n} {kind}')
PYEOF

grep '^DIFF\|^CRASH\|^    ' "$TMP/verdict" || true
read -r _ agree total < <(grep '^AGREE' "$TMP/verdict" || echo "AGREE 0 0")
if [ "$total" -gt 0 ] && [ "$agree" -eq "$total" ]; then
    pass "all ${#LANGS[@]} parsers give the same verdict, values, encodings and refusal text on all $total cases (seeds: $SEEDS)"
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
    fail "coverage: the comparison printed no KIND lines"
fi

# ── CLI cells: past item 16, a length past 2^31, and section 10.2's refusals ──
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
def put(name, der, label=lab):
    open(f'{t}/{name}.pem', 'w').write(codec.pem_wrap(label, bytes(der)))
i1, i2 = codec.der_int(1), codec.der_int(2)
items = [codec.der_int(i + 1) for i in range(17)]
put('k17', codec.der_seq(*items))
items[16] = b'\x02\x01\x83'
put('k17neg', codec.der_seq(*items))
big = bytearray(codec.der_seq(i1, i2) + b'\x02\x84\xff\xff\xff\xff')
big[1] = len(big) - 2
put('kbig', big)
# one structural fault per kind of SPEC.md section 10.2 refusal
put('knotseq', b'\x31' + codec.der_seq(i1, i2)[1:])
put('klenlong', b'\x30\x85\x00\x00\x00\x00\x06' + i1 + i2)
put('ktrunc', codec.der_seq(i1, i2)[:-1])
put('klentrunc', b'\x30\x04' + i1 + b'\x02')
put('ktag', codec.der_seq(i1, b'\x04\x01\x02'))
# the envelope pkey --decrypt reads: field 1 is not an INTEGER
put('kenv', codec.der_seq(i1, b'\x04\x01\x02', i1, i1, i1, i1), 'HERRADURA ENCRYPTED PRIVATE KEY')
# the control: a real three-item key, which every CLI must read
put('k3', codec.der_seq(codec.der_int(5, 32), codec.der_int(9, 32), codec.der_int(256)))
PYEOF
cell() {   # name, file, expected text ('' = must succeed), command (default: pkey)
    local name="$1" f="$2" want="$3" how="${4:-pkey}" l out rc
    for l in c go py java; do
        [ -n "${CLI[$l]:-}" ] || continue
        if [ "$how" = decrypt ]; then
            out=$(${CLI[$l]} pkey --decrypt --passphrase pw --in "$TMP/$f" --out "$TMP/o_$l.pem" 2>&1) && rc=0 || rc=$?
        else
            out=$(${CLI[$l]} pkey --in "$TMP/$f" --pubout --out "$TMP/o_$l.pem" 2>&1) && rc=0 || rc=$?
        fi
        if [ -z "$want" ]; then
            if [ "$rc" -eq 0 ]; then pass "$name ($l)"; else fail "$name ($l): rc=$rc $out"; fi
        elif [ "$rc" -ne 0 ] && [[ "$out" == *"$want"* ]]; then pass "$name ($l)"
        else fail "$name ($l): rc=$rc, expected '$want': $out"; fi
    done
}
K="malformed PEM 'HERRADURA HKEX-GF PRIVATE KEY'"
cell "a 3-item key reads (control)" k3.pem ""
cell "17 DER items: refused with the true count" k17.pem "$K: 17 DER items, expected 3"
cell "item 17 negative: refused at item 17" k17neg.pem "$K: field 16 is a negative INTEGER"
cell "an INTEGER length past 2^31" kbig.pem "$K: field 2 runs past the DER SEQUENCE"
cell "not a SEQUENCE" knotseq.pem "$K: not a DER SEQUENCE"
cell "a 5-byte length field" klenlong.pem "$K: DER length field longer than 4 bytes"
cell "a body past the end" ktrunc.pem "$K: DER SEQUENCE body truncated"
cell "a length field cut off" klentrunc.pem "$K: DER length field truncated"
cell "an item that is not an INTEGER" ktag.pem "$K: field 1 is not an INTEGER (tag 0x04)"
cell "pkey --decrypt: an envelope item that is not an INTEGER" kenv.pem \
    "malformed PEM 'HERRADURA ENCRYPTED PRIVATE KEY': field 1 is not an INTEGER (tag 0x04)" decrypt

echo ""
echo "Results: $PASS PASS / $FAIL FAIL (parsers: ${LANGS[*]})"
[ "$FAIL" -eq 0 ]
