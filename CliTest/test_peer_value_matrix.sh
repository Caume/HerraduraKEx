#!/usr/bin/env bash
# CliTest/test_peer_value_matrix.sh — TODO #371: every CLI refuses a degenerate
# value supplied by the OTHER party, and a width it does not run, instead of
# computing with it.
#
# WHY THIS FILE EXISTS.  Up to v15.0.0's #371, over the four CLIs:
#
#   * a peer HKEX-GF or HPKE public key of 0 or 1 was accepted by Go and Python
#     (C and Java refused).  The shared secret is then 0 or 1 -- a constant.
#   * an HPKS / HPKS-NL public key of 1 made Go and Python print "Signature OK"
#     for a signature ANYONE can make: R = g^s for any s verifies against any
#     message, because pub^e = 1.
#   * an HPKE ciphertext whose R is 0 or 1 was decrypted by C, Go and Python
#     under a constant key (Java refused).
#   * an all-zero HKEX-RNL peer value C (Alice's public key, or C_B in Bob's
#     response, plain or hybrid) was accepted by all four.  s * 0 = 0, so K_raw
#     is a constant and the session key depends only on the two public nonces.
#   * a valid 128-bit key from the Go or Python CLI was read at 256 bits by C,
#     which exited 0 with a wrong shared key, a ciphertext nobody could decrypt,
#     and a valid signature refused; Java failed inside its arithmetic.
#
# test_weak_key_rejection.sh (TODO #141) covered the GF cases for the C CLI
# only, which is how the Go and Python gaps went unseen; it stays as the C
# sanitizer run.  This is the four-CLI version, plus RNL and widths.
#
# Rules followed (CLAUDE.md, "Rules for writing tests"):
#   * accept-controls first -- every cell runs the genuine artifact (exit 0),
#     and the GF cells also the valid elements 2 and 2^n - 1, so a CLI that
#     refuses everything cannot pass;
#   * every refusal must carry the new check's OWN message, so a case that
#     fails for an incidental reason (hpke-nl's weak-key screen also refuses
#     0 and 1) does not count as the check firing;
#   * the RNL guard's two bounds are each isolated (sparse at full range,
#     clustered at full count), and both sides of the count boundary are run.
#
# Claimed by ci.yml's cross-lang-compat job (all four CLIs built).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
PASS=0; FAIL=0

declare -A CLI=()
CLI[py]="python3 $ROOT/HerraduraCli/herradura.py"
[ -x "$ROOT/HerraduraCli/herradura_cli" ]    && CLI[c]="$ROOT/HerraduraCli/herradura_cli"
[ -x "$ROOT/HerraduraCli/herradura_cli_go" ] && CLI[go]="$ROOT/HerraduraCli/herradura_cli_go"
if command -v javac >/dev/null 2>&1; then
    bash bindings/java/build.sh >/dev/null 2>&1
    CLI[java]="java -Xmx1g -cp $ROOT/bindings/java herradurakex.HerraduraCli"
fi
LANGS=()
for l in py c go java; do
    [ -n "${CLI[$l]:-}" ] && LANGS+=("$l")
done
echo "Languages under test: ${LANGS[*]}"

. "$ROOT/CliTest/lib_build.sh"
for l in c go; do
    [ -n "${CLI[$l]:-}" ] || echo "NOTE: $l CLI absent — $(hkx_why "$l")"
done
[ -n "${CLI[java]:-}" ] || echo "NOTE: java CLI absent — javac is not installed"
if [ -z "${CLI[c]:-}" ]; then
    echo "FAIL test_peer_value_matrix: needs the C CLI for its fixtures, so nothing" \
         "was asserted (run ./build_c.sh)." >&2
    [ "${HKX_ALLOW_SKIP:-0}" = "1" ] && exit 0
    exit 2
fi

pass() { echo "PASS $1"; PASS=$((PASS+1)); }
fail() { echo "FAIL $1"; FAIL=$((FAIL+1)); }

GF_MSG='identity/zero element (rejected: degenerate key)'
RNL_MSG='failed entropy check (rejected: degenerate key)'
WIDTH_MSG='this CLI runs n = 256'

# run <lang> <args...>: sets RC and OUT (stdout+stderr), never aborts the script.
run() {
    local l=$1; shift
    set +e
    OUT=$(timeout 300 ${CLI[$l]} "$@" 2>&1 </dev/null)
    RC=$?
    set -e
}

# ── Fixtures (C CLI, n = 256) ────────────────────────────────────────────────
F="$TMP/fx"; mkdir -p "$F"
C=${CLI[c]}
q() { "$@" >/dev/null 2>&1; }
for t in hkex-gf hpke hpke-nl hpke-nl3 hpks hpks-nl hkex-rnl hpke-stern-kem; do
    q $C genpkey --algo "$t" --out "$F/$t.pem"
    q $C pkey --in "$F/$t.pem" --pubout --out "$F/${t}_pub.pem"
done
q $C genpkey --algo hkex-rnl --out "$F/rnl2.pem"
printf 'peer value test message, 32 byte' > "$F/msg.bin"
for a in hpke hpke-nl hpke-nl3; do
    q $C enc --algo $a --pubkey "$F/${a}_pub.pem" --in "$F/msg.bin" --out "$F/ct_$a.pem"
done
for a in hpks hpks-nl; do
    q $C sign --algo $a --key "$F/$a.pem" --in "$F/msg.bin" --out "$F/sig_$a.pem"
done
q $C kex --algo hkex-rnl --our "$F/rnl2.pem" --their "$F/hkex-rnl_pub.pem" --out "$F/rnl_resp.pem"
q $C kex --algo hybrid-rnl-stern --our "$F/rnl2.pem" --their "$F/hkex-rnl_pub.pem" \
    --their-kem "$F/hpke-stern-kem_pub.pem" --out "$F/hyb_resp.pem"

# ── Crafting, in one python call ─────────────────────────────────────────────
#   g_<fixture>_<tag>.pem : DER item 0 (the GF value) replaced
#   r_<fixture>_<item>_<tag>.pem : an RNL polynomial item replaced
#   forged_<algo>.pem / one_<algo>.pem : a signature anyone can make, and pub = 1
python3 - "$ROOT/HerraduraCli" "$F" <<'PY'
import os, sys
sys.path.insert(0, sys.argv[1])
F = sys.argv[2]
from codec import der_int, der_seq, der_parse_seq, pem_wrap, pem_unwrap, pack_poly, unpack_poly
import herradura as H
from primitives import BitArray, gf_pow, fscx_revolve, hpks_nl_challenge
n = 256
def load(fx):
    label, der = pem_unwrap(open(os.path.join(F, fx)).read())
    return label, der_parse_seq(der)
import json, re
ROWS = json.load(open(os.path.join(sys.argv[1], '..', 'spec', 'herradura-protocol-spec.json')))['pem_der_field_caps']
def widths(label, f):
    """TODO #373: each field's fixed width from pem_der_field_caps (None for a
    minimal field), so a crafted value is encoded the way its writer encodes
    it and reaches the peer-value screen rather than the encoding check."""
    ev = lambda e: eval(re.sub(r'f(\d+)', lambda m: 'F[%s]' % m.group(1), e).replace('/', '//'),
                        {'min': min, 'F': f})
    for r in ROWS:
        if r['label'] == label and r['min_items'] <= len(f) <= r['max_items'] and (not r['when'] or ev(r['when'])):
            w = {c['field']: ev(c['cap']) for c in r['caps'] if c['exact']}
            return [w.get(i) for i in range(len(f))]
    return [None] * len(f)
def write(name, label, items):
    ws = widths(label, items)
    open(os.path.join(F, name), 'w').write(pem_wrap(label, der_seq(
        *[der_int(x, w) if w else der_int(x) for x, w in zip(items, ws)])))
GF = {'zero': 0, 'one': 1, 'two': 2, 'allones': (1 << n) - 1}
for fx in ('hkex-gf_pub', 'hpke_pub', 'hpke-nl_pub', 'hpke-nl3_pub', 'hpks_pub', 'hpks-nl_pub',
           'ct_hpke', 'ct_hpke-nl', 'ct_hpke-nl3'):
    label, it = load(fx + '.pem')
    for tag, v in GF.items():
        write(f'g_{fx}_{tag}.pem', label, [v] + it[1:])
# RNL: C (2 bits per packed coefficient slot, as the encoders write it).
N, P = H.RNLN, H.RNLP
zero = [0] * N
sparse = [0] * N
for i in range(N // 8):
    sparse[i] = P - 1                    # count bound only: full range, n/8 non-zero
clustered = [1 + (i % (P // 8 - 1)) for i in range(N)]   # range bound only: all non-zero
at_count = [0] * N
for i in range(N // 4):
    at_count[i] = P - 1                  # exactly n/4 non-zero: must PASS the guard
below_count = [0] * N
for i in range(N // 4 - 1):
    below_count[i] = P - 1               # n/4 - 1: must FAIL it
SHAPES = {'zero': zero, 'sparse': sparse, 'clustered': clustered,
          'atcount': at_count, 'belowcount': below_count}
for fx, idx in (('hkex-rnl_pub', 0), ('rnl_resp', 1), ('hyb_resp', 1)):
    label, it = load(fx + '.pem')
    for tag, poly in SHAPES.items():
        packed, _nb = pack_poly(poly, 2)
        it2 = list(it); it2[idx] = packed
        write(f'r_{fx}_{tag}.pem', label, it2)
# A signature valid under pub = 1 for ANY message: R = g^s, e recomputed.
msg = open(os.path.join(F, 'msg.bin'), 'rb').read()
m = BitArray(n, int.from_bytes(msg[:n // 8].ljust(n // 8, b'\0'), 'big'))
s = 0x1234567
R = BitArray(n, gf_pow(3, s, H.GF_POLY[n], n))
for algo in ('hpks', 'hpks-nl'):
    e = fscx_revolve(R, m, n // 4) if algo == 'hpks' else hpks_nl_challenge(R, m)
    open(os.path.join(F, f'forged_{algo}.pem'), 'w').write(H._encode_schnorr_sig(s, R.uint, e.uint, n))
    write(f'one_{algo}.pem', H._PUB_ALGOS[algo], [1, n])
PY

# ── GF(2^n)* peer values ─────────────────────────────────────────────────────
# cell|fixture|argv ({X} = the crafted artifact)
GF_CELLS=(
    "kex hkex-gf --their|hkex-gf_pub|kex --algo hkex-gf --our $F/hkex-gf.pem --their {X} --out {O}"
    "enc hpke --pubkey|hpke_pub|enc --algo hpke --pubkey {X} --in $F/msg.bin --out {O}"
    "enc hpke-nl --pubkey|hpke-nl_pub|enc --algo hpke-nl --pubkey {X} --in $F/msg.bin --out {O}"
    "enc hpke-nl3 --pubkey|hpke-nl3_pub|enc --algo hpke-nl3 --pubkey {X} --in $F/msg.bin --out {O}"
    "dec hpke (ciphertext R)|ct_hpke|dec --algo hpke --key $F/hpke.pem --in {X} --out {O}"
    "dec hpke-nl (ciphertext R)|ct_hpke-nl|dec --algo hpke-nl --key $F/hpke-nl.pem --in {X} --out {O}"
    "dec hpke-nl3 (ciphertext R)|ct_hpke-nl3|dec --algo hpke-nl3 --key $F/hpke-nl3.pem --in {X} --out {O}"
    "verify hpks --pubkey|hpks_pub|verify --algo hpks --pubkey {X} --in $F/msg.bin --sig $F/sig_hpks.pem"
    "verify hpks-nl --pubkey|hpks-nl_pub|verify --algo hpks-nl --pubkey {X} --in $F/msg.bin --sig $F/sig_hpks-nl.pem"
)
for l in "${LANGS[@]}"; do
    for row in "${GF_CELLS[@]}"; do
        IFS='|' read -r cell fx argv <<<"$row"
        a=${argv//\{O\}/$TMP/out_$l.pem}
        # accept-control: the genuine artifact
        run "$l" ${a//\{X\}/$F/$fx.pem}
        if [ "$RC" -eq 0 ]; then pass "[$l] $cell: genuine accepted"
        else fail "[$l] $cell: genuine REFUSED (rc=$RC): ${OUT:0:160}"; fi
        # valid group elements other than the genuine one -- kex and enc only:
        # dec and verify of a substituted value fail on the arithmetic, which
        # would not distinguish the guard from the maths.
        case "$cell" in kex*|enc*)
            for tag in two allones; do
                run "$l" ${a//\{X\}/$F/g_${fx}_$tag.pem}
                if [ "$RC" -eq 0 ]; then pass "[$l] $cell: valid element ($tag) accepted"
                else fail "[$l] $cell: valid element ($tag) REFUSED (rc=$RC): ${OUT:0:160}"; fi
            done ;;
        esac
        for tag in zero one; do
            run "$l" ${a//\{X\}/$F/g_${fx}_$tag.pem}
            if [ "$RC" -ne 0 ] && grep -qF "$GF_MSG" <<<"$OUT"; then
                pass "[$l] $cell: $tag refused by the degenerate-value check"
            else
                fail "[$l] $cell: $tag NOT refused by the degenerate-value check (rc=$RC): ${OUT:0:160}"
            fi
        done
    done
    # A signature anyone can make, under pub = 1: never "Signature OK".
    for algo in hpks hpks-nl; do
        run "$l" verify --algo $algo --pubkey "$F/one_$algo.pem" --in "$F/msg.bin" --sig "$F/forged_$algo.pem"
        if [ "$RC" -ne 0 ] && ! grep -q 'Signature OK' <<<"$OUT" && grep -qF "$GF_MSG" <<<"$OUT"; then
            pass "[$l] verify $algo: forged signature under pub = 1 refused"
        else
            fail "[$l] verify $algo: forged signature under pub = 1 (rc=$RC): ${OUT:0:160}"
        fi
    done
done

# The forgery must be a real one, or the case above proves nothing: the same
# signature verifies under pub = 1 by the raw Schnorr equation.
python3 - "$ROOT/HerraduraCli" "$F" <<'PY' && pass "control: the forged signature satisfies g^s * 1^e == R" || fail "control: the forged signature is not a forgery"
import os, sys
sys.path.insert(0, sys.argv[1])
from codec import der_parse_seq, pem_unwrap
from primitives import gf_pow, gf_mul
import herradura as H
for algo in ('hpks', 'hpks-nl'):
    _, d = pem_unwrap(open(os.path.join(sys.argv[2], f'forged_{algo}.pem')).read())
    s, R, e, n = der_parse_seq(d)
    p = H.GF_POLY[n]
    assert gf_mul(gf_pow(3, s, p, n), gf_pow(1, e, p, n), p, n) == R
PY

# ── HKEX-RNL peer values ─────────────────────────────────────────────────────
RNL_CELLS=(
    "kex hkex-rnl --their C|hkex-rnl_pub|kex --algo hkex-rnl --our $F/rnl2.pem --their {X} --out {O}"
    "kex hkex-rnl response C_B|rnl_resp|kex --algo hkex-rnl --our $F/hkex-rnl.pem --their {X} --out {O}"
    "kex hybrid --their C|hkex-rnl_pub|kex --algo hybrid-rnl-stern --our $F/rnl2.pem --their {X} --their-kem $F/hpke-stern-kem_pub.pem --out {O}"
    "kex hybrid response C_B|hyb_resp|kex --algo hybrid-rnl-stern --our $F/hkex-rnl.pem --our-kem $F/hpke-stern-kem.pem --their {X} --out {O}"
)
for l in "${LANGS[@]}"; do
    for row in "${RNL_CELLS[@]}"; do
        IFS='|' read -r cell fx argv <<<"$row"
        a=${argv//\{O\}/$TMP/out_$l.pem}
        run "$l" ${a//\{X\}/$F/$fx.pem}
        if [ "$RC" -eq 0 ]; then pass "[$l] $cell: genuine accepted"
        else fail "[$l] $cell: genuine REFUSED (rc=$RC): ${OUT:0:160}"; fi
        # exactly n/4 non-zero clears the count bound; it must not be refused
        # BY THE GUARD (the key it yields is wrong, so the exchange itself may
        # still be fine or fail later -- what is asserted is the guard's verdict).
        run "$l" ${a//\{X\}/$F/r_${fx}_atcount.pem}
        if grep -qF "$RNL_MSG" <<<"$OUT"; then
            fail "[$l] $cell: n/4 non-zero (the boundary) refused by the guard: ${OUT:0:160}"
        else pass "[$l] $cell: n/4 non-zero (the boundary) passes the guard"; fi
        for tag in zero sparse clustered belowcount; do
            run "$l" ${a//\{X\}/$F/r_${fx}_$tag.pem}
            if [ "$RC" -ne 0 ] && grep -qF "$RNL_MSG" <<<"$OUT"; then
                pass "[$l] $cell: $tag refused by the peer-value guard"
            else
                fail "[$l] $cell: $tag NOT refused by the peer-value guard (rc=$RC): ${OUT:0:160}"
            fi
        done
    done
done

# ── Widths: a 128-bit key from a CLI that runs 128 ───────────────────────────
# Which CLIs run the GF family at 128 bits is the spec's key_parameter_sets row
# (TODO #379; C joined in #383, Java is #384).  A CLI that runs the width must
# agree with the others that do; one that does not must refuse, naming the
# width -- never exit 0 with a wrong answer.
GF128_PORTS=$(python3 -c "import json,sys; d=json.load(open(sys.argv[1]))
print(' '.join(next(r['ports'] for r in d['key_parameter_sets']['rows'] if r['algo']=='hkex-gf' and r['bits']==128)))" \
    "$ROOT/spec/herradura-protocol-spec.json")
[ -n "$GF128_PORTS" ] || { echo "FAIL no hkex-gf 128 row in the spec"; exit 1; }
W="$TMP/w"; mkdir -p "$W"
PY=${CLI[py]}
q $PY genpkey --algo hkex-gf --bits 128 --out "$W/a.pem"; q $PY pkey --in "$W/a.pem" --pubout --out "$W/a_pub.pem"
q $PY genpkey --algo hkex-gf --bits 128 --out "$W/b.pem"; q $PY pkey --in "$W/b.pem" --pubout --out "$W/b_pub.pem"
q $PY kex --algo hkex-gf --our "$W/a.pem" --their "$W/b_pub.pem" --out "$W/sk_ref.pem"
q $PY genpkey --algo hpke --bits 128 --out "$W/e.pem"; q $PY pkey --in "$W/e.pem" --pubout --out "$W/e_pub.pem"
q $PY genpkey --algo hpks --bits 128 --out "$W/s.pem"; q $PY pkey --in "$W/s.pem" --pubout --out "$W/s_pub.pem"
printf 'sixteen byte msg' > "$W/m.bin"
q $PY sign --algo hpks --key "$W/s.pem" --in "$W/m.bin" --out "$W/sig.pem"
for l in "${LANGS[@]}"; do
    case " $GF128_PORTS " in *" $l "*) runs=1 ;; *) runs=0 ;; esac
    run "$l" kex --algo hkex-gf --our "$W/b.pem" --their "$W/a_pub.pem" --out "$W/sk_$l.pem"
    if [ $runs = 1 ]; then
        if [ "$RC" -eq 0 ] && cmp -s "$W/sk_$l.pem" "$W/sk_ref.pem"; then pass "[$l] 128-bit kex agrees with Python"
        else fail "[$l] 128-bit kex (rc=$RC): ${OUT:0:160}"; fi
    elif [ "$RC" -ne 0 ] && grep -qF "$WIDTH_MSG" <<<"$OUT"; then pass "[$l] 128-bit kex refused, naming the width"
    else fail "[$l] 128-bit kex not refused by the width check (rc=$RC): ${OUT:0:160}"; fi

    rm -f "$W/ct_$l.pem" "$W/d_$l.bin"
    run "$l" enc --algo hpke --pubkey "$W/e_pub.pem" --in "$W/m.bin" --out "$W/ct_$l.pem"
    if [ $runs = 1 ]; then
        q $PY dec --algo hpke --key "$W/e.pem" --in "$W/ct_$l.pem" --out "$W/d_$l.bin" || true
        if [ "$RC" -eq 0 ] && cmp -s "$W/d_$l.bin" "$W/m.bin"; then pass "[$l] 128-bit hpke enc round-trips"
        else fail "[$l] 128-bit hpke enc (rc=$RC): ${OUT:0:160}"; fi
    elif [ "$RC" -ne 0 ] && grep -qF "$WIDTH_MSG" <<<"$OUT"; then pass "[$l] 128-bit hpke enc refused, naming the width"
    else fail "[$l] 128-bit hpke enc not refused by the width check (rc=$RC): ${OUT:0:160}"; fi

    run "$l" verify --algo hpks --pubkey "$W/s_pub.pem" --in "$W/m.bin" --sig "$W/sig.pem"
    if [ $runs = 1 ]; then
        if [ "$RC" -eq 0 ]; then pass "[$l] 128-bit hpks verify accepts a valid signature"
        else fail "[$l] 128-bit hpks verify (rc=$RC): ${OUT:0:160}"; fi
    elif [ "$RC" -ne 0 ] && grep -qF "$WIDTH_MSG" <<<"$OUT"; then pass "[$l] 128-bit hpks verify refused, naming the width"
    else fail "[$l] 128-bit hpks verify not refused by the width check (rc=$RC): ${OUT:0:160}"; fi
done

echo ""
echo "Results: $PASS PASS / $FAIL FAIL"
[ "$FAIL" -eq 0 ]
