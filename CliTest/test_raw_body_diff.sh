#!/usr/bin/env bash
# CliTest/test_raw_body_diff.sh — TODO #406 / #407: the four CLIs' raw-body PEM
# readers, compared on generated input.
#
# test_pem_reader_diff.sh and test_der_reader_diff.sh (TODO #403, #404) hold the
# PEM reader and the DER parser to one verdict.  Eight artifacts carry no DER:
# their body is packed bytes, a 4-byte n (and rounds, and for HCRED a W) and then
# fixed blocks and per-round length bytes.  Each CLI reads them with its own
# code, in C inline in the subcommands, so there is no in-process driver to
# compare; this test runs the four real CLIs, each through the subcommand that
# reads the artifact:
#   ZKP-NL PRIVATE KEY, HCRED PRIVATE KEY   pkey --pubout       (output hashed)
#   ZKP-NL PUBLIC KEY, ZKP-NL PROOF          verify --algo nl-zkboo
#   ZKP-NL-PP SIGNATURE                      verify --algo nl-zkbpp
#   ZKP-RNL PROOF                            verify --algo rnl-sigma
#   HCRED PUBLIC KEY                         cred-issue
#   HCRED PROOF                              cred-verify
# on seeded mutations of a fixture of each (Fuzz/raw_body_diff/gen_cases.py:
# header and per-round length fields set to edge values, truncation, trailing
# bytes, byte edits).  Each run is OK (for a key, with the hash of what it
# wrote), FAILED (read, then verification failed) or REFUSED, and the test fails
#   * on any CRASH: a Python traceback, a Go panic, a Java "Index ... out of
#     bounds" or other raw JDK message, an ASan report, an exit status other
#     than 0 or 1 -- whatever the other CLIs say;
#   * when the CLIs give a case different results, unless it is one of TODO
#     #408's recorded non-canonical encodings (below), which is counted and
#     printed as KNOWN.
# Coverage: every artifact's agreed cases must reach REFUSED, and its other
# outcomes as listed in FLOOR, so a drifting generator cannot pass vacuously.
#
# Then named cells, through all four CLIs:
#   * controls: every unmutated fixture, at n = 8 and n = 64 for ZKP-NL, is read
#     by every CLI (a key to the same public key);
#   * TODO #407's refusals, by their full text: a ZKBoo view and a ZKB++ gate
#     field shorter than n needs (before #407: a heap over-read in C, a panic
#     in Go, a traceback in Python, a raw index message in Java) and an HCRED W
#     out of range (before #407 the C CLI read it unbounded);
#   * TODO #408's KNOWN cells, printed with each CLI's verdict: encodings no
#     writer produces that some or all CLIs accept.  The divergent ones double
#     as the comparison's negative control: it must flag them.
#   * the crash detector's own controls: a traceback, a panic and a raw JDK
#     message from stand-in commands must each be classed CRASH.
#
# HKX_RAWDIFF_SEEDS (default "1"), HKX_RAWDIFF_COUNT (mutations per artifact,
# default 60) and HKX_RAWDIFF_HCPROOF (HCRED proofs, default 6; Python verifies
# one in about 6 s on an SBC) size the run; HKX_RAWDIFF_C_BIN runs another C
# build, e.g. HerraduraCli/herradura_cli_asan.  Claimed by ci.yml's
# cross-lang-compat job.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
SEEDS="${HKX_RAWDIFF_SEEDS:-1}"
COUNT="${HKX_RAWDIFF_COUNT:-60}"
HCCOUNT="${HKX_RAWDIFF_HCPROOF:-6}"
JOBS="$(nproc 2>/dev/null || echo 2)"
PASS=0; FAIL=0
pass() { echo "PASS $1"; PASS=$((PASS+1)); }
fail() { echo "FAIL $1"; FAIL=$((FAIL+1)); }

# ── the CLIs ──────────────────────────────────────────────────────────────────
declare -A CLI=()
CLI[py]="python3 $ROOT/HerraduraCli/herradura.py"
CBIN="${HKX_RAWDIFF_C_BIN:-$ROOT/HerraduraCli/herradura_cli}"
[ -x "$CBIN" ] && CLI[c]="$CBIN"
[ -x HerraduraCli/herradura_cli_go ] && CLI[go]="$ROOT/HerraduraCli/herradura_cli_go"
if command -v javac >/dev/null 2>&1 && bash bindings/java/build.sh >/dev/null; then
    CLI[java]="java -cp $ROOT/bindings/java herradurakex.HerraduraCli"
else echo "NOTE: Java CLI not built (javac absent or the build failed)"; fi
LANGS=()
for l in c go py java; do [ -n "${CLI[$l]:-}" ] && LANGS+=("$l"); done
echo "CLIs under test: ${LANGS[*]}"
if [ "${#LANGS[@]}" -lt 2 ]; then
    echo "FAIL test_raw_body_diff: fewer than two CLIs, so nothing was compared." >&2
    [ "${HKX_ALLOW_SKIP:-0}" = "1" ] && exit 0
    exit 2
fi

# ── fixtures, written by one CLI (the first available) ────────────────────────
FX="$TMP/fx"; mkdir -p "$FX" "$TMP/cases" "$TMP/out"
P="${CLI[${LANGS[0]}]}"
echo "raw-body differential message" > "$FX/m.txt"
mk() { $P "$@" >/dev/null 2>"$TMP/mk.err" || { echo "FAIL fixture: ${LANGS[0]} $*: $(head -c 300 "$TMP/mk.err")"; exit 1; }; }
for b in 8 64; do
    s=""; [ "$b" = 64 ] && s=64
    mk genpkey --algo hpks-zkp-nl --bits "$b" --out "$FX/zk$s.pem"
    mk pkey --in "$FX/zk$s.pem" --pubout --out "$FX/zk${s}_pub.pem"
    mk sign --algo nl-zkboo --key "$FX/zk$s.pem" --in "$FX/m.txt" --rounds 4 --out "$FX/zkboo$s.pem"
    mk sign --algo nl-zkbpp --key "$FX/zk$s.pem" --in "$FX/m.txt" --rounds 4 --out "$FX/zkbpp$s.pem"
done
mk genpkey --algo hkex-rnl --out "$FX/rs.pem"
mk pkey --in "$FX/rs.pem" --pubout --out "$FX/rs_pub.pem"
mk sign --algo rnl-sigma --key "$FX/rs.pem" --in "$FX/m.txt" --out "$FX/rnlsig.pem"
mk genpkey --algo hpks-stern --out "$FX/iss.pem"
mk pkey --in "$FX/iss.pem" --pubout --out "$FX/iss_pub.pem"
mk genpkey --algo hcred --out "$FX/hc.pem"
mk pkey --in "$FX/hc.pem" --pubout --out "$FX/hc_pub.pem"
mk cred-issue --our "$FX/iss.pem" --in "$FX/hc_pub.pem" --rounds 4 --out "$FX/cred.pem"
mk cred-prove --in "$FX/hc.pem" --msg nonce --rounds 4 --out "$FX/hcproof.pem"

# ── one run: LANG KIND FILE -> "FILE LANG VERDICT | detail" ───────────────────
cat > "$TMP/run.sh" <<'SHEOF'
#!/usr/bin/env bash
lang=$1 kind=$2 f=$3
cmd_var="CLI_$lang"; X="${!cmd_var}"
o="$f.$lang.out"
case $kind in
  zkpriv|hcpriv) a=(pkey --in "$f" --pubout --out "$o") ;;
  zkpub)   a=(verify --algo nl-zkboo --min-rounds 4 --pubkey "$f" --in "$FX/m.txt" --sig "$FX/zkboo.pem") ;;
  zkboo)   a=(verify --algo nl-zkboo --min-rounds 4 --pubkey "$FX/zk_pub.pem" --in "$FX/m.txt" --sig "$f") ;;
  zkbpp)   a=(verify --algo nl-zkbpp --min-rounds 4 --pubkey "$FX/zk_pub.pem" --in "$FX/m.txt" --sig "$f") ;;
  zkboo64) a=(verify --algo nl-zkboo --min-rounds 4 --pubkey "$FX/zk64_pub.pem" --in "$FX/m.txt" --sig "$f") ;;
  zkbpp64) a=(verify --algo nl-zkbpp --min-rounds 4 --pubkey "$FX/zk64_pub.pem" --in "$FX/m.txt" --sig "$f") ;;
  rnlsig)  a=(verify --algo rnl-sigma --pubkey "$FX/rs_pub.pem" --in "$FX/m.txt" --sig "$f") ;;
  hcpub)   a=(cred-issue --our "$FX/iss.pem" --in "$f" --rounds 4 --out "$o") ;;
  hcproof) a=(cred-verify --min-rounds 4 --cred "$FX/cred.pem" --issuer "$FX/iss_pub.pem"
              --pubkey "$FX/hc_pub.pem" --proof "$f" --msg nonce) ;;
  *) echo "$(basename "$f") $lang BADKIND | $kind"; exit 0 ;;
esac
so=$($X "${a[@]}" 2>"$o.err"); rc=$?
all="$so $(head -c 2000 "$o.err")"
if [ $rc -ne 0 ] && [ $rc -ne 1 ]; then v="CRASH(rc=$rc)"
elif printf '%s' "$all" | grep -Eq 'Traceback|panic:|goroutine [0-9]|AddressSanitizer|UndefinedBehaviorSanitizer|runtime error|out of bounds|IndexError|KeyError|TypeError|NullPointer|Cannot invoke|/ by zero|Exception'; then
    v=CRASH
elif [ $rc -eq 0 ]; then
    case $kind in zkpriv|hcpriv) v="OK:$(md5sum < "$o" | cut -c1-12)" ;; *) v=OK ;; esac
elif printf '%s' "$so" | grep -q FAIL; then v=FAILED
else v=REFUSED; fi
echo "$(basename "$f") $lang $v | $(printf '%s' "$all" | tr '\n' ' ' | cut -c1-200)"
rm -f "$o" "$o.err"
SHEOF
chmod +x "$TMP/run.sh"
export FX
# Under HKX_RAWDIFF_C_BIN=...asan, a refusal exits through die() with its
# allocations live; LeakSanitizer would report each one.  The test hunts
# over-reads, not leaks at exit (the sanitizers job covers leaks).
export ASAN_OPTIONS="${ASAN_OPTIONS:-detect_leaks=0}"
for l in "${LANGS[@]}"; do export "CLI_$l=${CLI[$l]}"; done

# ── crash detector controls: each stand-in must be classed CRASH ──────────────
printf '#!/bin/sh\npython3 -c "[][1]"\n' > "$TMP/fake_py"
printf '#!/bin/sh\necho "panic: runtime error: index out of range [3] with length 3" >&2; exit 2\n' > "$TMP/fake_go"
printf '#!/bin/sh\necho "error: Index 3 out of bounds for length 3" >&2; exit 1\n' > "$TMP/fake_java"
chmod +x "$TMP/fake_py" "$TMP/fake_go" "$TMP/fake_java"
for f in py go java; do
    r=$(CLI_fake="$TMP/fake_$f" "$TMP/run.sh" fake zkpriv "$FX/zk.pem")
    case "$r" in *" fake CRASH"*) pass "control: a stand-in $f crash is classed CRASH" ;;
                 *) fail "control: a stand-in $f crash was classed: $r" ;; esac
done

# ── controls: every fixture is read by every CLI ──────────────────────────────
CTRL="zkpriv:zk.pem zkpub:zk_pub.pem zkboo:zkboo.pem zkbpp:zkbpp.pem zkboo64:zkboo64.pem
      zkbpp64:zkbpp64.pem rnlsig:rnlsig.pem hcpriv:hc.pem hcpub:hc_pub.pem hcproof:hcproof.pem"
mkdir -p "$TMP/ctrl"
for kf in $CTRL; do cp "$FX/${kf#*:}" "$TMP/ctrl/${kf#*:}"; done
for kf in $CTRL; do for l in "${LANGS[@]}"; do echo "$l ${kf%%:*} $TMP/ctrl/${kf#*:}"; done; done \
    | xargs -P "$JOBS" -n 3 "$TMP/run.sh" > "$TMP/ctrl.txt"
for kf in $CTRL; do
    f="${kf#*:}"
    vs=$(grep "^$f " "$TMP/ctrl.txt" | awk '{print $3}' | sort -u)
    if [ "$(echo "$vs" | wc -l)" -eq 1 ] && [[ "$vs" == OK* ]]; then
        pass "control: all ${#LANGS[@]} CLIs read the unmutated $f ($vs)"
    else fail "control: the unmutated $f: $(grep "^$f " "$TMP/ctrl.txt" | cut -c1-160 | tr '\n' ';')"; fi
done

# ── the generated cases ───────────────────────────────────────────────────────
: > "$TMP/list.txt"
for seed in $SEEDS; do
    python3 Fuzz/raw_body_diff/gen_cases.py "$seed" "$FX" "$TMP/cases" "$COUNT" "$HCCOUNT" >> "$TMP/list.txt"
done
ncases=$(wc -l < "$TMP/list.txt")
while read -r kind name _; do for l in "${LANGS[@]}"; do echo "$l $kind $TMP/cases/$name"; done; done \
    < "$TMP/list.txt" | xargs -P "$JOBS" -n 3 "$TMP/run.sh" > "$TMP/res.txt"

python3 - "$TMP" "$FX" "${LANGS[@]}" > "$TMP/verdict" <<'PYEOF' || true
import base64, sys
tmp, fx, langs = sys.argv[1], sys.argv[2], sys.argv[3:]

def body(path):
    t = open(path).read().split('\n')
    return base64.b64decode(''.join(l for l in t[1:] if l and not l.startswith('-----')))

def u32(b, o=0):
    return int.from_bytes(b[o:o + 4], 'big')

# TODO #408's recorded non-canonical encodings: a disagreement on a case of
# this shape is KNOWN, not a failure, until #408 makes every CLI refuse it.
def known(kind, b):
    if kind in ('hcpriv', 'hcpub'):
        n = u32(b)
        if n not in (32, 64, 128, 256):
            return None
        lay = [(3, 65537), (2, 4096), (3, 65537)] if kind == 'hcpriv' else [(2, 4096), (3, 65537)]
        if len(b) != 4 + sum(w for w, _ in lay) * n + n // 8 + (n // 2 + 7) // 8:
            return None
        off = 4
        for w, lim in lay:
            for i in range(n):
                if int.from_bytes(b[off + w * i:off + w * (i + 1)], 'big') >= lim:
                    return 'HCRED coefficient not below q / p'
            off += w * n
        return None
    if kind == 'zkbpp':
        n0 = u32(body(f'{fx}/zkbpp.pem'))
        n = u32(b)
        if n != n0 and 0 < n and (n + 7) // 8 == (n0 + 7) // 8:
            return 'ZKB++ proof n differs from the key n'
    return None

kinds = {}
for line in open(f'{tmp}/list.txt'):
    k, name, how = line.split()
    kinds[name] = (k, how)
res = {}
for line in open(f'{tmp}/res.txt'):
    head, _, detail = line.partition(' | ')
    name, lang, v = head.split(' ')
    res.setdefault(name, {})[lang] = (v, detail.strip())

seen = {}
bad = crashes = nknown = missing = 0
for name, (kind, how) in sorted(kinds.items()):
    r = res.get(name, {})
    if set(r) != set(langs):
        missing += 1
        continue
    cr = [l for l in langs if r[l][0].startswith('CRASH')]
    if cr:
        crashes += 1
        if crashes <= 6:
            print(f'CRASH {name} ({how}): ' + '; '.join(f'{l} {r[l][1][:140]}' for l in cr))
        continue
    vs = {r[l][0] for l in langs}
    if len(vs) > 1:
        why = known(kind, body(f'{tmp}/cases/{name}'))
        if why:
            nknown += 1
            if nknown <= 6:
                print(f'KNOWN #408 {name} ({how}), {why}: ' + ', '.join(f'{l} {r[l][0]}' for l in langs))
            continue
        bad += 1
        if bad <= 8:
            print(f'DIFF {name} ({how}):')
            for l in langs:
                print(f'    {l:5} {r[l][0]:20} {r[l][1][:120]}')
        continue
    v = r[langs[0]][0].split(':')[0]
    seen[(kind, v)] = seen.get((kind, v), 0) + 1

print(f'CASES {len(kinds)} MISSING {missing}')
print(f'DISAGREE {bad}')
print(f'CRASHES {crashes}')
print(f'KNOWNCOUNT {nknown}')
FLOOR = {'zkpriv': 'OK REFUSED', 'hcpriv': 'OK REFUSED', 'zkpub': 'FAILED REFUSED',
         'zkboo': 'FAILED REFUSED', 'zkbpp': 'FAILED REFUSED', 'rnlsig': 'FAILED REFUSED',
         'hcpub': 'OK REFUSED', 'hcproof': 'REFUSED'}
for kind, outs in FLOOR.items():
    for v in outs.split():
        print(f'KIND {seen.get((kind, v), 0)} {kind} {v}')
PYEOF

grep '^DIFF \|^CRASH \|^KNOWN #408\|^    ' "$TMP/verdict" || true
read -r _ ntot _ nmiss < <(grep '^CASES' "$TMP/verdict" || echo "CASES 0 MISSING 0")
if [ "$ntot" -eq "$ncases" ] && [ "$nmiss" -eq 0 ] && [ "$ntot" -gt 0 ]; then
    pass "every CLI answered all $ntot generated cases (seeds: $SEEDS)"
else fail "of $ncases generated cases, $ntot were listed and $nmiss lack an answer from some CLI"; fi
read -r _ nbad < <(grep '^DISAGREE' "$TMP/verdict" || echo "DISAGREE -1")
read -r _ nknown < <(grep '^KNOWNCOUNT' "$TMP/verdict" || echo "KNOWNCOUNT 0")
if [ "$nbad" -eq 0 ]; then
    pass "all ${#LANGS[@]} CLIs give every generated case the same result ($nknown TODO #408 KNOWN cases set aside)"
else fail "the CLIs disagree on $nbad generated cases (first ones above)"; fi
read -r _ ncr < <(grep '^CRASHES' "$TMP/verdict" || echo "CRASHES -1")
if [ "$ncr" -eq 0 ]; then pass "no CLI crashed on any generated case"
else fail "a CLI crashed on $ncr generated cases (first ones above)"; fi
if grep -q '^KIND' "$TMP/verdict"; then
    while read -r _ n kind v; do
        if [ "$n" -gt 0 ]; then pass "coverage: $n agreed $kind cases are $v"
        else fail "coverage: no agreed $kind case is $v (the generator no longer reaches it)"; fi
    done < <(grep '^KIND' "$TMP/verdict")
else fail "coverage: the comparison printed no KIND lines"; fi

# ── named cells: TODO #407's refusals and TODO #408's KNOWN encodings ─────────
python3 - "$FX" "$TMP/cells" <<'PYEOF'
import base64, os, sys
fx, out = sys.argv[1], sys.argv[2]
os.makedirs(out, exist_ok=True)
def rd(f):
    t = open(f'{fx}/{f}').read().split('\n')
    return t[0][11:-5], bytearray(base64.b64decode(''.join(l for l in t[1:] if l and not l.startswith('-----'))))
def wr(name, lab, b):
    open(f'{out}/{name}.pem', 'w').write(
        f'-----BEGIN {lab}-----\n{base64.encodebytes(bytes(b)).decode()}-----END {lab}-----\n')
def zkboo_views(b):                   # [(len offset, view offset, len)] for both views of every round
    p, v = 8, []
    while p < len(b):
        q = p + 97
        l1 = int.from_bytes(b[q:q + 2], 'big')
        r = q + 2 + l1
        l2 = int.from_bytes(b[r:r + 2], 'big')
        v.append(((q, q + 2, l1), (r, r + 2, l2)))
        p = r + 2 + l2
    return v
def zkbpp_gates(b):                   # [(gates_len offset, has_share2 offset)] per round
    nb = (int.from_bytes(b[:4], 'big') + 7) // 8
    p, g = 8, []
    while p < len(b):
        o = p + 33 + nb + 32
        h = o + 1 + b[o]
        g.append((o, h))
        p = h + 1 + (nb if b[h] else 0)
    return g
def shorten_view(b, rnd, which):
    lo, vo, l = zkboo_views(b)[rnd][which]
    d = bytearray(b)
    del d[vo + l - 1]
    d[lo:lo + 2] = (l - 1).to_bytes(2, 'big')
    return d
for s in ('', '64'):
    lab, b = rd(f'zkboo{s}.pem')
    wr(f'short_v1{s}', lab, shorten_view(b, 0, 0))
    wr(f'short_v2{s}', lab, shorten_view(b, 1, 1))
    lab, b = rd(f'zkbpp{s}.pem')
    o, _ = zkbpp_gates(b)[0]
    d = bytearray(b); gl = d[o]
    del d[o + 1:o + 1 + gl]
    d[o] = 0
    wr(f'short_g{s}', lab, d)
lab, b = rd('hcproof.pem')
for w in (0, 257):
    d = bytearray(b); d[4:8] = w.to_bytes(4, 'big')
    wr(f'w{w}', lab, d)
# TODO #408's KNOWN encodings, each made from a valid artifact
lab, b = rd('zkboo.pem')
lo, vo, l = zkboo_views(b)[0][0]
d = bytearray(b); d.insert(vo + l, 0); d[lo:lo + 2] = (l + 1).to_bytes(2, 'big')
wr('k_view_long', lab, d)
lab, b = rd('zkbpp.pem')
g = zkbpp_gates(b)
d = bytearray(b)
h = next(h for _, h in g if d[h] == 1)
d[h] = 2
wr('k_has2', lab, d)
o, _ = g[0]
d = bytearray(b); d.insert(o + 1 + d[o], 0); d[o] += 1
wr('k_gate_extra', lab, d)
d = bytearray(b); d[0:4] = (1).to_bytes(4, 'big')
wr('k_n1', lab, d)
lab, b = rd('hc.pem')
d = bytearray(b); n = int.from_bytes(d[:4], 'big')
mo = 4 + 3 * n + 2 * n                      # m[0], a Z_q coefficient
d[mo:mo + 3] = (65537 + int.from_bytes(d[mo:mo + 3], 'big')).to_bytes(3, 'big')
wr('k_hc_coef', lab, d)
PYEOF
CELLS="zkboo:short_v1 zkboo:short_v2 zkboo64:short_v164 zkboo64:short_v264 zkbpp:short_g zkbpp64:short_g64
       hcproof:w0 hcproof:w257 zkboo:k_view_long zkbpp:k_has2 zkbpp:k_gate_extra zkbpp:k_n1 hcpriv:k_hc_coef"
for kc in $CELLS; do for l in "${LANGS[@]}"; do echo "$l ${kc%%:*} $TMP/cells/${kc#*:}.pem"; done; done \
    | xargs -P "$JOBS" -n 3 "$TMP/run.sh" > "$TMP/cells.txt"
want() {   # cell, expected text: every CLI must refuse with it
    local c="$1" t="$2" l line ok=1
    for l in "${LANGS[@]}"; do
        line=$(grep "^$c.pem $l " "$TMP/cells.txt" || true)
        case "$line" in *" REFUSED | "*"$t"*) ;; *) ok=0; echo "    $l: ${line:0:200}" ;; esac
    done
    if [ $ok = 1 ]; then pass "$c: every CLI refuses it: $t"; else fail "$c: not refused as '$t' by every CLI (above)"; fi
}
want short_v1     "malformed PEM 'HERRADURA ZKP-NL PROOF': round 0 view_p1 is 40 bytes, n=8 needs 41"
want short_v2     "malformed PEM 'HERRADURA ZKP-NL PROOF': round 1 view_p2 is 40 bytes, n=8 needs 41"
want short_v164   "malformed PEM 'HERRADURA ZKP-NL PROOF': round 0 view_p1 is 110 bytes, n=64 needs 111"
want short_v264   "malformed PEM 'HERRADURA ZKP-NL PROOF': round 1 view_p2 is 110 bytes, n=64 needs 111"
want short_g      "malformed PEM 'HERRADURA ZKP-NL-PP SIGNATURE': round 0 gates_p2 is 0 bytes, n=8 needs 1"
want short_g64    "malformed PEM 'HERRADURA ZKP-NL-PP SIGNATURE': round 0 gates_p2 is 0 bytes, n=64 needs 8"
want w0           "HCRED proof: W out of range (0)"
want w257         "HCRED proof: W out of range (257)"
# TODO #408: printed, not scored; the divergent ones must be flagged by the
# comparison (the same rule the generated cases go through).
for c in k_view_long k_has2 k_gate_extra k_n1 k_hc_coef; do
    vs=$(grep "^$c.pem " "$TMP/cells.txt" | awk '{print $2 "=" $3}' | sort | tr '\n' ' ')
    echo "KNOWN #408 $c: $vs"
done
for c in k_gate_extra k_n1 k_hc_coef; do
    n=$(grep "^$c.pem " "$TMP/cells.txt" | awk '{print $3}' | sort -u | wc -l)
    if [ "$n" -gt 1 ]; then pass "control: the comparison flags $c, where the CLIs differ (TODO #408)"
    else fail "control: $c no longer divides the CLIs: TODO #408 may have landed; move it to a refusal cell"; fi
done

echo "Results: $PASS PASS / $FAIL FAIL (CLIs: ${LANGS[*]})"
[ "$FAIL" -eq 0 ]
