#!/usr/bin/env bash
# CliTest/test_raw_body_diff.sh — TODO #406 / #407 / #408 / #409: the four CLIs'
# raw-body PEM readers, compared on generated input.
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
#   * when the CLIs give a case different results (the comparison's own
#     negative control: one planted disagreement must be flagged).
# Coverage: every artifact's agreed cases must reach REFUSED, and its other
# outcomes as listed in FLOOR, so a drifting generator cannot pass vacuously.
#
# Then named cells, through all four CLIs:
#   * controls: every unmutated fixture, at n = 12 (so that bits above n exist)
#     and n = 64 for ZKP-NL, is read by every CLI (a key to the same public key);
#   * TODO #407's refusals, by their full text: a ZKBoo view and a ZKB++ gate
#     field shorter than n needs (before #407: a heap over-read in C, a panic
#     in Go, a traceback in Python, a raw index message in Java) and an HCRED W
#     out of range (before #407 the C CLI read it unbounded);
#   * TODO #408's refusals, by their full text: each a VALID artifact
#     re-encoded in a way no writer produces, which before #408 some or all
#     CLIs accepted -- a view or gate field one byte long, has_share2 other
#     than (e != 2), a proof n other than the key's, a bit above n in a key or
#     proof field, an HCRED value not below q or p, an HCRED has_aux of 2, and
#     an HCRED aux block the challenge does not open (verification FAILED);
#   * TODO #409's ZKBoo cells, each verification FAILED in every CLI: a
#     signature whose prover used a WRONG A (before #409 every CLI accepted it:
#     the verifier never related the output shares to y), and one bit changed
#     in a valid signature's view -- gate-byte bits 7, 0 and 1, the share's bit
#     n - 1, an output share -- which before #409 the verifier never read; the
#     wrong-A signature is made for ZKB++ too, which was never affected;
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
for b in 12 64; do
    s=""; [ "$b" = 64 ] && s=64
    mk genpkey --algo hpks-zkp-nl --bits "$b" --out "$FX/zk$s.pem"
    mk pkey --in "$FX/zk$s.pem" --pubout --out "$FX/zk${s}_pub.pem"
    mk sign --algo nl-zkboo --key "$FX/zk$s.pem" --in "$FX/m.txt" --rounds 4 --out "$FX/zkboo$s.pem"
    mk sign --algo nl-zkbpp --key "$FX/zk$s.pem" --in "$FX/m.txt" --rounds 4 --out "$FX/zkbpp$s.pem"
done
# TODO #409: the key pair's B and y with another A (its lowest bit flipped), so
# that a signature made from it proves a witness the public key does not have.
# Such a proof survives only if every round's recomputed challenge re-matches,
# (1/3)^rounds; at the default 219 rounds that is 2^-347, where 4 would fail
# this test one run in 81.
python3 - "$FX/zk.pem" "$FX/zk_wrongA.pem" <<'PYEOF'
import base64, sys
t = open(sys.argv[1]).read().split('\n'); lab = t[0][11:-5]
b = bytearray(base64.b64decode(''.join(l for l in t[1:] if l and not l.startswith('-----'))))
nb = (int.from_bytes(b[:4], 'big') + 7) // 8
b[4 + nb - 1] ^= 1
open(sys.argv[2], 'w').write(f'-----BEGIN {lab}-----\n{base64.encodebytes(bytes(b)).decode()}-----END {lab}-----\n')
PYEOF
mk sign --algo nl-zkboo --key "$FX/zk_wrongA.pem" --in "$FX/m.txt" --out "$FX/zkboo_wrongA.pem"
mk sign --algo nl-zkbpp --key "$FX/zk_wrongA.pem" --in "$FX/m.txt" --out "$FX/zkbpp_wrongA.pem"
# The has_share2 cells need a ZKB++ round with e = 2 and one without, and the
# has_aux cells an HCRED round with an aux block and one without.  The
# challenge decides which a round is, so sign until a fixture has both: a
# choice of fixture, not of verdict (each try misses with probability
# (2/3)^8 + (1/3)^8 = 3.9% for ZKB++, (2/3)^4 + (1/3)^4 = 21% for HCRED).
has_both() {   # file, kind
    python3 - "$1" "$2" <<'PYEOF'
import base64, sys
t = open(sys.argv[1]).read().split('\n')
b = base64.b64decode(''.join(l for l in t[1:] if l and not l.startswith('-----')))
n = int.from_bytes(b[:4], 'big'); seen = set()
if sys.argv[2] == 'zkbpp':
    nb, p = (n + 7) // 8, 8
    while p < len(b):
        o = p + 33 + nb + 32; h = o + 1 + b[o]
        seen.add(b[p + 32] == 2); p = h + 1 + (nb if b[h] else 0)
else:
    rows, nd = n // 2, 5 * n; nbb = rows * n.bit_length()
    fixed = 96 + 3 * (n + nbb + nd + 1 + 2 * rows + n) * 3 + 64 + (2 * n + nbb + nd) * 3
    p = 12
    while p < len(b):
        h = p + fixed; seen.add(b[h]); p = h + 1 + ((n + nbb + nd) * 3 if b[h] else 0)
sys.exit(0 if len(seen) == 2 else 1)
PYEOF
}
for try in 1 2 3 4 5 6 7 8 9 10; do
    mk sign --algo nl-zkbpp --key "$FX/zk.pem" --in "$FX/m.txt" --rounds 8 --out "$FX/zkbpp8r.pem"
    has_both "$FX/zkbpp8r.pem" zkbpp && break
done
mk genpkey --algo hkex-rnl --out "$FX/rs.pem"
mk pkey --in "$FX/rs.pem" --pubout --out "$FX/rs_pub.pem"
mk sign --algo rnl-sigma --key "$FX/rs.pem" --in "$FX/m.txt" --out "$FX/rnlsig.pem"
mk genpkey --algo hpks-stern --out "$FX/iss.pem"
mk pkey --in "$FX/iss.pem" --pubout --out "$FX/iss_pub.pem"
mk genpkey --algo hcred --out "$FX/hc.pem"
mk pkey --in "$FX/hc.pem" --pubout --out "$FX/hc_pub.pem"
mk cred-issue --our "$FX/iss.pem" --in "$FX/hc_pub.pem" --rounds 4 --out "$FX/cred.pem"
for try in 1 2 3 4 5 6 7 8 9 10; do
    mk cred-prove --in "$FX/hc.pem" --msg nonce --rounds 4 --out "$FX/hcproof.pem"
    has_both "$FX/hcproof.pem" hcproof && break
done

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
echo "$(basename "$f") $lang $v | $(printf '%s' "$all" | tr '\n' ' ' | cut -c1-500)"
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
CTRL="zkpriv:zk.pem zkpub:zk_pub.pem zkboo:zkboo.pem zkbpp:zkbpp.pem zkbpp:zkbpp8r.pem zkboo64:zkboo64.pem
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

cat > "$TMP/compare.py" <<'PYEOF'
import base64, sys
tmp, resfile, langs = sys.argv[1], sys.argv[2], sys.argv[3:]

def body(path):
    t = open(path).read().split('\n')
    return base64.b64decode(''.join(l for l in t[1:] if l and not l.startswith('-----')))

def u32(b, o=0):
    return int.from_bytes(b[o:o + 4], 'big')

kinds = {}
for line in open(f'{tmp}/list.txt'):
    k, name, how = line.split()
    kinds[name] = (k, how)
res = {}
for line in open(resfile):
    head, _, detail = line.partition(' |')
    name, lang, v = head.split()[:3]
    res.setdefault(name, {})[lang] = (v, detail.strip())

seen = {}
bad = crashes = missing = 0
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
FLOOR = {'zkpriv': 'OK REFUSED', 'hcpriv': 'OK REFUSED', 'zkpub': 'FAILED REFUSED',
         'zkboo': 'FAILED REFUSED', 'zkbpp': 'FAILED REFUSED', 'rnlsig': 'FAILED REFUSED',
         'hcpub': 'OK REFUSED', 'hcproof': 'REFUSED'}
for kind, outs in FLOOR.items():
    for v in outs.split():
        print(f'KIND {seen.get((kind, v), 0)} {kind} {v}')
PYEOF
python3 "$TMP/compare.py" "$TMP" "$TMP/res.txt" "${LANGS[@]}" > "$TMP/verdict" || true
# The comparison's negative control: the same results with ONE verdict changed
# must be reported as one disagreement.
awk -v l="${LANGS[0]}" '!done && $2 == l { sub(/^[^ ]+ [^ ]+ [^ ]+/, $1 " " $2 " PLANTED"); done = 1 } { print }' \
    "$TMP/res.txt" > "$TMP/res_planted.txt"
python3 "$TMP/compare.py" "$TMP" "$TMP/res_planted.txt" "${LANGS[@]}" > "$TMP/verdict_planted" || true

grep '^DIFF \|^CRASH \|^    ' "$TMP/verdict" || true
read -r _ ntot _ nmiss < <(grep '^CASES' "$TMP/verdict" || echo "CASES 0 MISSING 0")
if [ "$ntot" -eq "$ncases" ] && [ "$nmiss" -eq 0 ] && [ "$ntot" -gt 0 ]; then
    pass "every CLI answered all $ntot generated cases (seeds: $SEEDS)"
else fail "of $ncases generated cases, $ntot were listed and $nmiss lack an answer from some CLI"; fi
read -r _ nbad < <(grep '^DISAGREE' "$TMP/verdict" || echo "DISAGREE -1")
if [ "$nbad" -eq 0 ]; then
    pass "all ${#LANGS[@]} CLIs give every generated case the same result"
else fail "the CLIs disagree on $nbad generated cases (first ones above)"; fi
read -r _ nplant < <(grep '^DISAGREE' "$TMP/verdict_planted" || echo "DISAGREE -1")
if [ "$nplant" -eq $((nbad + 1)) ]; then pass "control: one planted verdict change is reported as one disagreement"
else fail "control: a planted verdict change gave $nplant disagreements, expected $((nbad + 1))"; fi
read -r _ ncr < <(grep '^CRASHES' "$TMP/verdict" || echo "CRASHES -1")
if [ "$ncr" -eq 0 ]; then pass "no CLI crashed on any generated case"
else fail "a CLI crashed on $ncr generated cases (first ones above)"; fi
if grep -q '^KIND' "$TMP/verdict"; then
    while read -r _ n kind v; do
        if [ "$n" -gt 0 ]; then pass "coverage: $n agreed $kind cases are $v"
        else fail "coverage: no agreed $kind case is $v (the generator no longer reaches it)"; fi
    done < <(grep '^KIND' "$TMP/verdict")
else fail "coverage: the comparison printed no KIND lines"; fi


# ── named cells: TODO #407's and #408's refusals by their text; #409's ───────
# Each is made from a valid fixture; cells.lst says what every CLI must do:
# "KIND FILE TEXT" (refuse with TEXT) or "KIND FILE =FAILED" (verify, and fail).
python3 - "$FX" "$TMP/cells" <<'PYEOF'
import base64, os, sys
fx, out = sys.argv[1], sys.argv[2]
os.makedirs(out, exist_ok=True)
lst = open(f'{out}/cells.lst', 'w')
def rd(f):
    t = open(f'{fx}/{f}').read().split('\n')
    return t[0][11:-5], bytearray(base64.b64decode(''.join(l for l in t[1:] if l and not l.startswith('-----'))))
def cell(kind, name, lab, b, want):
    open(f'{out}/{name}.pem', 'w').write(
        f'-----BEGIN {lab}-----\n{base64.encodebytes(bytes(b)).decode()}-----END {lab}-----\n')
    lst.write(f'{kind} {name} {want}\n')
def u32(b, o=0): return int.from_bytes(b[o:o + 4], 'big')
def zkboo_views(b):        # per round: ((len off, view off, len) for view_p1, for view_p2)
    p, v = 8, []
    while p < len(b):
        q = p + 97; l1 = int.from_bytes(b[q:q + 2], 'big')
        r = q + 2 + l1; l2 = int.from_bytes(b[r:r + 2], 'big')
        v.append(((q, q + 2, l1), (r, r + 2, l2))); p = r + 2 + l2
    return v
def zkbpp_rounds(b):       # per round: (round off, e, gates_len off, has_share2 off)
    nb = (u32(b) + 7) // 8; p, g = 8, []
    while p < len(b):
        o = p + 33 + nb + 32; h = o + 1 + b[o]
        g.append((p, b[p + 32], o, h)); p = h + 1 + (nb if b[h] else 0)
    return g
def resize_view(b, rnd, which, delta):
    lo, vo, l = zkboo_views(b)[rnd][which]
    d = bytearray(b)
    if delta < 0: del d[vo + l - 1]
    else: d.insert(vo + l, 0)
    d[lo:lo + 2] = (l + delta).to_bytes(2, 'big')
    return d, l + delta, l
def resize_gates(b, delta):
    _, _, o, _ = zkbpp_rounds(b)[0]
    d = bytearray(b); gl = d[o]
    if delta < 0: del d[o + gl]
    else: d.insert(o + 1 + gl, 0)
    d[o] = gl + delta
    return d, gl + delta, gl
P, PP = 'HERRADURA ZKP-NL PROOF', 'HERRADURA ZKP-NL-PP SIGNATURE'
for s, n in (('', 12), ('64', 64)):
    lab, b = rd(f'zkboo{s}.pem')
    for which, rnd, name in ((0, 0, 'view_p1'), (1, 1, 'view_p2')):
        for delta, tag in ((-1, 'short'), (1, 'long')):     # #407 short, #408 long
            d, got, need = resize_view(b, rnd, which, delta)
            cell(f'zkboo{s}', f'{tag}_{name}{s}', lab, d,
                 f"malformed PEM '{P}': round {rnd} {name} is {got} bytes, n={n} needs {need}")
    lab, b = rd(f'zkbpp{s}.pem')
    for delta, tag in ((-1, 'short'), (1, 'long')):
        d, got, need = resize_gates(b, delta)
        cell(f'zkbpp{s}', f'{tag}_gates{s}', lab, d,
             f"malformed PEM '{PP}': round 0 gates_p2 is {got} bytes, n={n} needs {need}")
# #408: a proof over another n (13 has the key's byte width, 1 does not)
for kind, f, pn in (('zkboo', 'zkboo.pem', 1), ('zkbpp', 'zkbpp.pem', 13)):
    lab, b = rd(f); d = bytearray(b); d[0:4] = pn.to_bytes(4, 'big')
    cell(kind, f'n{pn}_{kind}', lab, d, f'proof n mismatch with pubkey n ({pn} vs 12)')
# #408: has_share2 other than (e != 2), both ways, at n = 12 with 8 rounds
lab, b = rd('zkbpp8r.pem'); g = zkbpp_rounds(b); nb = 2
j, (p, e, o, h) = next((j, r) for j, r in enumerate(g) if r[1] != 2)
d = bytearray(b); d[h] = 2
cell('zkbpp', 'has_share2_2', lab, d, f"malformed PEM '{PP}': round {j} has_share2 is 2, e={e} needs 1")
j, (p, e, o, h) = next((j, r) for j, r in enumerate(g) if r[1] == 2)
d = bytearray(b); d[h] = 1; d[h + 1:h + 1] = bytes(nb)
cell('zkbpp', 'share2_unneeded', lab, d, f"malformed PEM '{PP}': round {j} has_share2 is 1, e=2 needs 0")
# #408: a bit above n = 12 (nb = 2: the top four bits of the first byte)
lab, b = rd('zkboo.pem'); _, vo, _ = zkboo_views(b)[0][0]
d = bytearray(b); d[vo] |= 0x80
cell('zkboo', 'bits_view_share', lab, d, f"malformed PEM '{P}': round 0 view_p1 share has bits above n=12")
lab, b = rd('zkbpp.pem'); p, e, o, h = zkbpp_rounds(b)[0]
d = bytearray(b); d[p + 33] |= 0x80
cell('zkbpp', 'bits_out_e', lab, d, f"malformed PEM '{PP}': round 0 out_e has bits above n=12")
lab, b = rd('zk.pem'); d = bytearray(b); d[4] |= 0x80
cell('zkpriv', 'bits_A', lab, d, f"malformed PEM '{lab}': A has bits above n=12")
lab, b = rd('zk_pub.pem'); d = bytearray(b); d[6] |= 0x80
cell('zkpub', 'bits_y', lab, d, f"malformed PEM '{lab}': y has bits above n=12")
# #409: ZKBoo signatures the verifier must fail.  A prover with a wrong A ...
for kind, f in (('zkboo', 'zkboo_wrongA.pem'), ('zkbpp', 'zkbpp_wrongA.pem')):
    lab, b = rd(f)
    cell(kind, f'wrongA_{kind}', lab, b, '=FAILED')
# ... and one bit of a valid view (n = 12, nb = 2: share | tape | out | gates)
lab, b = rd('zkboo.pem'); V = zkboo_views(b)
for rnd, which, wname, off, bit, name in (
        (0, 0, 'p1', 2 * 2 + 32, 7, 'gate_bit7'), (0, 0, 'p1', 2 * 2 + 32, 0, 'gate_bit0'),
        (1, 1, 'p2', 2 * 2 + 32 + 1, 1, 'gate_bit1'), (0, 0, 'p1', 0, 3, 'share_bit11'),
        (1, 1, 'p2', 0, 3, 'share_bit11'), (0, 1, 'p2', 2 + 32 + 1, 0, 'out_bit0')):
    _, vo, _ = V[rnd][which]
    d = bytearray(b); d[vo + off] ^= 1 << bit
    cell('zkboo', f'{name}_{wname}_r{rnd}', lab, d, '=FAILED')
# #408: HCRED values not below q / p, in each artifact
def bump(f, off, w, by):
    lab, b = rd(f); d = bytearray(b)
    v = int.from_bytes(d[off:off + w], 'big') + by
    d[off:off + w] = v.to_bytes(w, 'big')
    return lab, d, v
lab, b = rd('hc.pem'); hn = u32(b)
lab, d, v = bump('hc.pem', 4 + 3 * hn + 2 * hn, 3, 65537)          # m[0]
cell('hcpriv', 'hc_priv_m', lab, d, f"malformed PEM '{lab}': value {v} at byte {4 + 5 * hn} is not below 65537")
lab, d, v = bump('hc.pem', 4 + 3 * hn, 2, 4096)                      # C[0]
cell('hcpriv', 'hc_priv_C', lab, d, f"malformed PEM '{lab}': value {v} at byte {4 + 3 * hn} is not below 4096")
lab, d, v = bump('hc_pub.pem', 4 + 2 * hn, 3, 65537)                # m[0]
cell('hcpub', 'hc_pub_m', lab, d, f"malformed PEM '{lab}': value {v} at byte {4 + 2 * hn} is not below 65537")
lab, b = rd('hcproof.pem'); n = u32(b); R = u32(b, 8)
rows, nd = n // 2, 5 * n; nbb = rows * n.bit_length()
outs = 3 * (n + nbb + nd + 1 + 2 * rows + n) * 3
fixed = 96 + outs + 64 + (2 * n + nbb + nd) * 3; aux = (n + nbb + nd) * 3
p, rs = 12, []
for r in range(R):
    h = p + fixed; rs.append((p, h, b[h])); p = h + 1 + (aux if b[h] else 0)
a1 = rs[0][0] + 96 + outs + 64
lab, d, v = bump('hcproof.pem', a1, 3, 65537)
cell('hcproof', 'hc_proof_a1', lab, d, f"malformed PEM '{lab}': value {v} at byte {a1} is not below 65537")
j, (p, h, ha) = next((j, r) for j, r in enumerate(rs) if r[2] == 1)
d = bytearray(b); d[h] = 2
cell('hcproof', 'has_aux_2', lab, d, f"malformed PEM '{lab}': round {j} has_aux is 2, expected 0 or 1")
j, (p, h, ha) = next((j, r) for j, r in enumerate(rs) if r[2] == 0)
d = bytearray(b); d[h] = 1; d[h + 1:h + 1] = bytes(aux)
cell('hcproof', 'aux_unneeded', lab, d, '=FAILED')
# #407: an HCRED W out of range
for w in (0, 257):
    d = bytearray(b); d[4:8] = w.to_bytes(4, 'big')
    cell('hcproof', f'w{w}', lab, d, f'HCRED proof: W out of range ({w})')
PYEOF
while read -r kind name _; do for l in "${LANGS[@]}"; do echo "$l $kind $TMP/cells/$name.pem"; done; done \
    < "$TMP/cells/cells.lst" | xargs -P "$JOBS" -n 3 "$TMP/run.sh" > "$TMP/cells.txt"
while read -r kind name want; do
    ok=1
    for l in "${LANGS[@]}"; do
        line=$(grep "^$name.pem $l " "$TMP/cells.txt" || true)
        if [ "$want" = "=FAILED" ]; then
            case "$line" in *" FAILED | "*) ;; *) ok=0; echo "    $l: ${line:0:200}" ;; esac
        else
            case "$line" in *" REFUSED | "*"$want"*) ;; *) ok=0; echo "    $l: ${line:0:200}" ;; esac
        fi
    done
    if [ "$want" = "=FAILED" ]; then w="fails verification"; else w="refuses it: $want"; fi
    if [ $ok = 1 ]; then pass "$name: every CLI $w"; else fail "$name: not every CLI $w (above)"; fi
done < "$TMP/cells/cells.lst"

echo "Results: $PASS PASS / $FAIL FAIL (CLIs: ${LANGS[*]})"
[ "$FAIL" -eq 0 ]
