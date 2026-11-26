#!/usr/bin/env bash
# CliTest/test_ring_challenge_bound.sh — TODO #421: an HPKS-Ring challenge is a
# trit, and a verifier refuses any other byte.
#
# Each (member, round) entry of a ring signature carries its challenge b as one
# byte.  Every verifier sends a b other than 0 or 1 to the b = 2 check, while the
# per-round sum takes b mod 3, so re-encoding a b = 2 round as 5 changes neither,
# and an honest signature acquired 2^(number of b = 2 rounds) encodings that all
# verified (malleability; all four short-form verifiers and Python's long form).
# This script re-encodes an honest signature; it does not build one.
#
# Cells, per CLI:  ACCEPT the honest short-form (N = 256) and long-form
# (N = 2304) signature; REFUSE member 0's b = 2 rounds re-encoded as 5, its b = 0
# rounds as 3, its b = 1 rounds as 4, its first b = 2 round as 254, and the long form's b = 2
# rounds as 5.
# Negative control, shown to FIRE: a stand-in that reduces every challenge byte
# mod 3 before verifying must fail every re-encoded cell and no accept cell.
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
    echo "FAIL test_ring_challenge_bound: fewer than two CLIs." >&2
    [ "${HKX_ALLOW_SKIP:-0}" = "1" ] && exit 0
    exit 2
fi

# reenc IN OUT MODE -- rewrite member 0's challenges (the responses are untouched).
# MODE: plusN:B adds N to every b equal to B; high adds 252 to member 0's first
#       b = 2 round (byte 254, the same residue mod 3);
#       mod3 reduces every challenge mod 3 (used by the control stand-in).
cat > "$TMP/reenc.py" <<'EOF'
import importlib.util, os, sys
R = os.environ['HKX_ROOT']; sys.path.insert(0, os.path.join(R, 'HerraduraCli'))
spec = importlib.util.spec_from_file_location('cli', os.path.join(R, 'HerraduraCli', 'herradura.py'))
cli = importlib.util.module_from_spec(spec); spec.loader.exec_module(cli)
src, dst, mode = sys.argv[1:4]
(cm, ch, rs), k, rounds, n = cli._unpack_ring_sig(src)
if mode == 'high':
    r = next((r for r in range(rounds) if ch[0][r] == 2), None)
    if r is None:
        sys.exit("reenc: member 0 has no b = 2 round to re-encode")
    ch[0][r] += 252
elif mode == 'mod3':
    ch = [[b % 3 for b in row] for row in ch]
else:
    add, which = (int(x) for x in mode[4:].split(':'))
    hit = 0
    for r in range(rounds):
        if ch[0][r] == which:
            ch[0][r] += add; hit += 1
    if hit == 0:
        sys.exit(f"reenc: member 0 has no b = {which} round to re-encode")
open(dst, 'w').write(cli._pack_ring_sig((cm, ch, rs), n))
EOF
export HKX_ROOT="$ROOT"
G="${CLI[c]:-${CLI[py]}}"
echo "ring challenge-bound probe" > "$TMP/m"
for form in short long; do
    lv=""; [ $form = long ] && lv="--level 128"
    for i in 0 1; do
        $G genpkey --algo hpks-stern $lv --out "$TMP/${form}_k$i.pem" >/dev/null 2>&1
        $G pkey --in "$TMP/${form}_k$i.pem" --pubout --out "$TMP/${form}_p$i.pem" >/dev/null 2>&1
    done
    $G sign --algo hpks-ring --key "$TMP/${form}_k1.pem" --ring "$TMP/${form}_p0.pem,$TMP/${form}_p1.pem" \
        --in "$TMP/m" --out "$TMP/${form}.sig" --rounds 32 >/dev/null 2>&1
    [ -s "$TMP/${form}.sig" ] || { fail "fixture: $form ring signature"; exit 1; }
done
SHORT_CASES=("plus3:2" "plus3:0" "plus3:1" "high")
for m in "${SHORT_CASES[@]}"; do
    python3 "$TMP/reenc.py" "$TMP/short.sig" "$TMP/short_$m.sig" "$m" || { fail "fixture: re-encode $m"; exit 1; }
done
python3 "$TMP/reenc.py" "$TMP/long.sig" "$TMP/long_plus3:2.sig" "plus3:2" || { fail "fixture: long re-encode"; exit 1; }
N_REENC=$(( ${#SHORT_CASES[@]} + 1 ))

vfy() {  # vfy X FORM SIG
    $1 verify --algo hpks-ring --ring "$TMP/$2_p0.pem,$TMP/$2_p1.pem" --in "$TMP/m" \
        --sig "$3" --min-rounds 32 >/dev/null 2>&1
}

cells() {
    local l=$1 X=$2 m
    for form in short long; do
        vfy "$X" $form "$TMP/$form.sig" && pass "$l: accept: honest $form-form ring signature" \
            || fail "$l: accept: honest $form-form ring signature refused"
    done
    for m in "${SHORT_CASES[@]}"; do
        vfy "$X" short "$TMP/short_$m.sig" && fail "$l: reencoded: short $m ACCEPTED" \
            || pass "$l: reencoded: short $m refused"
    done
    vfy "$X" long "$TMP/long_plus3:2.sig" && fail "$l: reencoded: long plus3:2 ACCEPTED" \
        || pass "$l: reencoded: long plus3:2 refused"
}
for l in "${LANGS[@]}"; do cells "$l" "${CLI[$l]}"; done

# ── negative control ──────────────────────────────────────────────────────────
cat > "$TMP/mod3_cli" <<EOF
#!/usr/bin/env bash
args=()
while [ \$# -gt 0 ]; do
    if [ "\$1" = --sig ]; then python3 "$TMP/reenc.py" "\$2" "\$2.mod3" mod3 || exit 3; args+=(--sig "\$2.mod3"); shift 2
    else args+=("\$1"); shift; fi
done
exec $G "\${args[@]}"
EOF
chmod +x "$TMP/mod3_cli"
before=$FAIL; pbefore=$PASS
cells mod3 "$TMP/mod3_cli" >"$TMP/mod3.out"
got_r=$(grep -c '^FAIL mod3: reencoded:' "$TMP/mod3.out")
got_a=$(grep -c '^FAIL mod3: accept:' "$TMP/mod3.out")
FAIL=$before; PASS=$pbefore
[ "$got_r" -eq "$N_REENC" ] && [ "$got_a" -eq 0 ] \
    && pass "control: a mod-3-reducing verifier fails all $N_REENC re-encoded cells and no accept cell" \
    || fail "control: a mod-3-reducing verifier failed $got_r/$N_REENC re-encoded and $got_a accept cells"

echo
echo "test_ring_challenge_bound: $PASS passed, $FAIL failed"
[ $FAIL -eq 0 ] && echo "*** OK: every CLI refuses an HPKS-Ring challenge byte outside {0, 1, 2} ***"
[ $FAIL -eq 0 ]
