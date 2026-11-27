#!/usr/bin/env bash
# CliTest/test_hpks_s_bound.sh — TODO #423: an HPKS / HPKS-NL scalar s lies below
# ord(g), in every signer's output and in every verifier's acceptance.
#
# g = 3 generates the whole of GF(2^n)* at n = 64 and 256 but only a subgroup of
# index 15 at n = 32 and index 3 at n = 128.  g^s depends on s mod ord(g), and
# the signers reduced s mod 2^n - 1, so s + ord(g) (when it still fits in n
# bits) was a second encoding that every verifier accepted.  Signers now reduce
# s mod ord(g), and verifiers refuse s >= ord(g).  This script re-encodes honest
# signatures; it never builds one without the key.
#
# Cells:
#   table    from the shipped Python suite, per n: g^ord(g) = 1 and g^(ord/p) != 1
#            for every prime p | ord(g) -- the table is the EXACT order.
#   signer   per CLI, n in {32, 128}, hpks and hpks-nl: K signatures, each with
#            s < ord(g).
#   accept   per (signer, verifier) at n in {32, 64, 128, 256}, hpks and hpks-nl:
#            the honest signature verifies.
#   refused  per verifier, n in {32, 128}, hpks and hpks-nl: an honest signature
#            with s re-encoded as s + ord(g) is refused with the shared message.
# Negative controls, each shown to FIRE: a wrong table (index 1 at n = 128) fails
# the table cell; a signer stand-in that re-encodes s + ord(g) wherever it fits
# fails every signer cell; a verifier stand-in that reduces s mod ord(g) first
# fails every refused cell.
# Claimed by ci.yml's cross-lang-compat job.
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
PASS=0; FAIL=0
pass() { echo "PASS $1"; PASS=$((PASS+1)); }
fail() { echo "FAIL $1"; FAIL=$((FAIL+1)); }

declare -A CLI=()
CLI[py]="python3 $ROOT/HerraduraCli/herradura.py"
[ -x HerraduraCli/herradura_cli ] && CLI[c]="$ROOT/HerraduraCli/herradura_cli"
[ -x HerraduraCli/herradura_cli_go ] && CLI[go]="$ROOT/HerraduraCli/herradura_cli_go"
if command -v javac >/dev/null 2>&1 && bash bindings/java/build.sh >/dev/null; then
    CLI[java]="java -cp $ROOT/bindings/java herradurakex.HerraduraCli"
else echo "NOTE: Java CLI not built (javac absent or the build failed)"; fi
LANGS=()
for l in c go py java; do [ -n "${CLI[$l]:-}" ] && LANGS+=("$l"); done
echo "CLIs under test: ${LANGS[*]}"
if [ "${#LANGS[@]}" -lt 2 ]; then
    echo "FAIL test_hpks_s_bound: fewer than two CLIs." >&2
    [ "${HKX_ALLOW_SKIP:-0}" = "1" ] && exit 0
    exit 2
fi
export HKX_ROOT="$ROOT"
MSG_RE="signature scalar s is not below the order of g"
K=16   # signer cell: an unreduced signer survives with prob (1/3)^16 ~ 2e-8 at n = 128

cat > "$TMP/s.py" <<'EOF'
import importlib.util, math, os, sys
R = os.environ['HKX_ROOT']; sys.path.insert(0, os.path.join(R, 'HerraduraCli'))
spec = importlib.util.spec_from_file_location('cli', os.path.join(R, 'HerraduraCli', 'herradura.py'))
cli = importlib.util.module_from_spec(spec); spec.loader.exec_module(cli)
S = cli._suite_mod
FACT = {32: [3, 5, 17, 257, 65537], 64: [3, 5, 17, 257, 641, 65537, 6700417],
        128: [3, 5, 17, 257, 641, 65537, 274177, 6700417, 67280421310721],
        256: [3, 5, 17, 257, 641, 65537, 274177, 6700417, 67280421310721,
              59649589127497217, 5704689200685129054721]}
def exact_order(n):
    """ord(g), computed here from 2^n - 1's factorisation -- not read from the
    code under test, so this script works against a build without the table."""
    N = (1 << n) - 1; assert math.prod(FACT[n]) == N
    o = N
    for p in FACT[n]:
        if S.gf_pow(S.GF_GEN, o // p, S.GF_POLY[n], n) == 1:
            o //= p
    return o

def check_table(order_of):
    bad = []
    for n in FACT:
        o = order_of(n)
        if S.gf_pow(S.GF_GEN, o, S.GF_POLY[n], n) != 1:
            bad.append(f"n={n}: g^ord != 1")
        for p in FACT[n]:
            if o % p == 0 and S.gf_pow(S.GF_GEN, o // p, S.GF_POLY[n], n) == 1:
                bad.append(f"n={n}: g^(ord/{p}) = 1, so ord(g) is smaller")
    return bad

cmd = sys.argv[1]
if cmd == 'table':                     # table [n=index override]: the SHIPPED table
    over = dict(tuple(int(x) for x in a.split('=')) for a in sys.argv[2:])
    if not hasattr(S, 'gf_gen_order') and not over:
        print('the suite has no gf_gen_order'); sys.exit(0)
    bad = check_table(lambda n: ((1 << n) - 1) // over[n] if n in over else S.gf_gen_order(n))
    bad += [f"n={n}: the suite says {S.gf_gen_order(n)}, the order is {exact_order(n)}"
            for n in FACT if n not in over and hasattr(S, 'gf_gen_order')
            and S.gf_gen_order(n) != exact_order(n)]
    print('\n'.join(bad) if bad else 'exact')
elif cmd == 'below':                   # below SIG -> yes/no
    s, _R, _e, n = cli._decode_schnorr_sig(sys.argv[2])
    print('yes' if s < exact_order(n) else 'no')
elif cmd in ('plus', 'mod'):           # plus|mod SIG OUT  (re-encode s)
    s, Rv, e, n = cli._decode_schnorr_sig(sys.argv[2]); o = exact_order(n)
    if cmd == 'plus':
        if s + o >= (1 << n):
            sys.exit(3)                # no second n-bit encoding of this s
        s += o
    else:
        s %= o
    open(sys.argv[3], 'w').write(cli._encode_schnorr_sig(s, Rv, e, n))
EOF

# ── table ─────────────────────────────────────────────────────────────────────
got=$(python3 "$TMP/s.py" table)
[ "$got" = exact ] && pass "table: gf_gen_order(n) is the exact order of g at n = 32, 64, 128, 256" \
    || fail "table: $got"
got=$(python3 "$TMP/s.py" table 128=1)
[ "$got" != exact ] && pass "control: a table claiming index 1 at n = 128 is caught ($got)" \
    || fail "control: a wrong table entry passed the table cell"

echo "s-bound probe" > "$TMP/m"
G="${CLI[c]:-${CLI[py]}}"
for algo in hpks hpks-nl; do for n in 32 64 128 256; do
    $G genpkey --algo $algo --bits $n --out "$TMP/${algo}_$n.pem" >/dev/null 2>&1
    $G pkey --in "$TMP/${algo}_$n.pem" --pubout --out "$TMP/${algo}_${n}_pub.pem" >/dev/null 2>&1
done; done

signer_cells() {   # signer_cells LANG X
    local l=$1 X=$2 algo n i bad
    for algo in hpks hpks-nl; do for n in 32 128; do
        bad=0
        for ((i = 0; i < K; i++)); do
            $X sign --algo $algo --key "$TMP/${algo}_$n.pem" --in "$TMP/m" --out "$TMP/sg_$l.pem" >/dev/null 2>&1 || { bad=$((bad+1)); continue; }
            [ "$(python3 "$TMP/s.py" below "$TMP/sg_$l.pem")" = yes ] || bad=$((bad+1))
        done
        [ $bad -eq 0 ] && pass "$l: signer: $algo n=$n, $K signatures all have s < ord(g)" \
            || fail "$l: signer: $algo n=$n, $bad of $K signatures have s >= ord(g) (or failed)"
    done; done
}
for l in "${LANGS[@]}"; do signer_cells "$l" "${CLI[$l]}"; done

# honest signatures from every signer, and one re-encodable signature per (algo, n)
for algo in hpks hpks-nl; do for n in 32 64 128 256; do
    for s in "${LANGS[@]}"; do
        ${CLI[$s]} sign --algo $algo --key "$TMP/${algo}_$n.pem" --in "$TMP/m" --out "$TMP/h_${algo}_${n}_$s.pem" >/dev/null 2>&1
    done
done; done
for algo in hpks hpks-nl; do for n in 32 128; do
    found=0
    for ((i = 0; i < 40 && found == 0; i++)); do
        $G sign --algo $algo --key "$TMP/${algo}_$n.pem" --in "$TMP/m" --out "$TMP/re_src.pem" >/dev/null 2>&1
        python3 "$TMP/s.py" plus "$TMP/re_src.pem" "$TMP/re_${algo}_$n.pem" && found=1
    done
    [ $found -eq 1 ] || { fail "fixture: no re-encodable $algo n=$n signature in 40 tries"; exit 1; }
done; done

verifier_cells() {   # verifier_cells LANG X
    local l=$1 X=$2 algo n s out
    for algo in hpks hpks-nl; do for n in 32 64 128 256; do
        for s in "${LANGS[@]}"; do
            $X verify --algo $algo --pubkey "$TMP/${algo}_${n}_pub.pem" --in "$TMP/m" --sig "$TMP/h_${algo}_${n}_$s.pem" >/dev/null 2>&1 \
                && pass "$l: accept: $algo n=$n signed by $s" || fail "$l: accept: $algo n=$n signed by $s was refused"
        done
    done; done
    for algo in hpks hpks-nl; do for n in 32 128; do
        out=$($X verify --algo $algo --pubkey "$TMP/${algo}_${n}_pub.pem" --in "$TMP/m" --sig "$TMP/re_${algo}_$n.pem" 2>&1) \
            && fail "$l: refused: $algo n=$n s + ord(g) ACCEPTED" \
            || { grep -qF -- "$MSG_RE" <<<"$out" && pass "$l: refused: $algo n=$n s + ord(g)" \
                 || fail "$l: refused: $algo n=$n s + ord(g) refused without the shared message: $(tail -1 <<<"$out")"; }
    done; done
}
for l in "${LANGS[@]}"; do verifier_cells "$l" "${CLI[$l]}"; done

# ── negative controls ─────────────────────────────────────────────────────────
cat > "$TMP/plus_signer" <<EOF
#!/usr/bin/env bash
out=""; prev=""
for a in "\$@"; do [ "\$prev" = --out ] && out=\$a; prev=\$a; done
$G "\$@" || exit \$?
[ "\$1" = sign ] && python3 "$TMP/s.py" plus "\$out" "\$out.p" && mv "\$out.p" "\$out"
exit 0
EOF
cat > "$TMP/mod_verifier" <<EOF
#!/usr/bin/env bash
args=(); prev=""
for a in "\$@"; do
    if [ "\$prev" = --sig ]; then python3 "$TMP/s.py" mod "\$a" "\$a.m" || exit 3; a="\$a.m"; fi
    args+=("\$a"); prev=\$a
done
exec $G "\${args[@]}"
EOF
chmod +x "$TMP/plus_signer" "$TMP/mod_verifier"
before=$FAIL; pbefore=$PASS
signer_cells plus "$TMP/plus_signer" >"$TMP/c1.out"
got1=$(grep -c '^FAIL plus: signer:' "$TMP/c1.out")
verifier_cells modv "$TMP/mod_verifier" >"$TMP/c2.out"
got2=$(grep -c '^FAIL modv: refused:' "$TMP/c2.out")
got2a=$(grep -c '^FAIL modv: accept:' "$TMP/c2.out")
FAIL=$before; PASS=$pbefore
[ "$got1" -eq 4 ] && pass "control: a signer that re-encodes s + ord(g) fails all 4 signer cells" \
    || fail "control: a re-encoding signer failed $got1/4 signer cells"
[ "$got2" -eq 4 ] && [ "$got2a" -eq 0 ] && pass "control: a verifier that reduces s first fails all 4 refused cells and no accept cell" \
    || fail "control: a reducing verifier failed $got2/4 refused and $got2a accept cells"

echo
echo "test_hpks_s_bound: $PASS passed, $FAIL failed"
[ $FAIL -eq 0 ] && echo "*** OK: every HPKS / HPKS-NL signer and verifier keeps s below ord(g) ***"
[ $FAIL -eq 0 ]
