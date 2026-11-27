#!/usr/bin/env bash
# CliTest/test_ring.sh — HPKS-Ring is disabled in every CLI (TODO #422), and the
# shipped ring verifier keeps its checks for the redesign (TODO #421).
#
# HPKS-Ring is existentially forgeable with no member's secret key (TODO #415,
# SECURITY.md), so `sign` and `verify --algo hpks-ring` refuse in all four CLIs
# BEFORE reading any file, until #415's redesign.  This script used to be the
# ring's 16-way interop test (TODO #121); that coverage is retired with it.
#
# Cells, per CLI:
#   accept   the same CLI signs and verifies --algo hpks-stern (so a CLI that
#            refuses everything fails here).
#   refused  sign --algo hpks-ring with a valid member key: non-zero exit, the
#            shared message, and no --out file; verify --algo hpks-ring of a
#            GENUINE ring signature (made by the shipped Python library with the
#            member's real key): non-zero exit and the shared message; verify
#            --algo hpks-ring --sig of a path that does not exist: the shared
#            message, not a file error (the refusal precedes every read).
# Library cells (shipped Python suite, N = 256 and N = 2304): a genuine ring
# signature verifies, the same signature on another message is refused, and its
# first b = 2 entry re-encoded as 5 is refused (TODO #421; C, Go and Java hold
# the same bound in their harness test [20] / SelfTest [26]).
# Negative controls, each shown to FIRE: a stand-in that prints the message but
# exits 0 fails every exit-status cell; a stand-in that refuses everything with a
# generic error fails every accept and message cell.
# Claimed by ci.yml's native-interop job.
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
PASS=0; FAIL=0
pass() { echo "PASS $1"; PASS=$((PASS+1)); }
fail() { echo "FAIL $1"; FAIL=$((FAIL+1)); }

# shellcheck source=CliTest/lib_build.sh
. "$ROOT/CliTest/lib_build.sh"
hkx_require_built c go

declare -A CLI=()
CLI[py]="python3 $ROOT/HerraduraCli/herradura.py"
CLI[c]="$ROOT/HerraduraCli/herradura_cli"
CLI[go]="$ROOT/HerraduraCli/herradura_cli_go"
if command -v javac >/dev/null 2>&1 && bash bindings/java/build.sh >/dev/null 2>&1; then
    CLI[java]="java -cp $ROOT/bindings/java herradurakex.HerraduraCli"
else echo "NOTE: javac not found — skipping Java's cells"; fi
LANGS=()
for l in c go py java; do [ -n "${CLI[$l]:-}" ] && LANGS+=("$l"); done
echo "CLIs under test: ${LANGS[*]}"

MSG="hpks-ring is disabled: a ring signature can be forged without any member's secret key"
G="${CLI[c]}"
printf 'ring disabled probe' > "$TMP/m"
printf 'another message' > "$TMP/m2"
for m in 0 1; do
    $G genpkey --algo hpks-stern --out "$TMP/k$m.pem" >/dev/null 2>&1
    $G pkey --in "$TMP/k$m.pem" --pubout --out "$TMP/p$m.pem" >/dev/null 2>&1
done
RING="$TMP/p0.pem,$TMP/p1.pem"

# A genuine ring signature, made by the shipped Python library with member 1's
# real key (no CLI can make one now), packed in the CLI wire format.
cat > "$TMP/lib.py" <<'EOF'
import importlib.util, os, sys
R = os.environ['HKX_ROOT']; sys.path.insert(0, os.path.join(R, 'HerraduraCli'))
spec = importlib.util.spec_from_file_location('cli', os.path.join(R, 'HerraduraCli', 'herradura.py'))
cli = importlib.util.module_from_spec(spec); spec.loader.exec_module(cli)
S = cli._suite_mod
mode = sys.argv[1]

def keys(n, k=2):
    if n > 256:
        out = [S.stern_l_keygen(n) for _ in range(k)]          # (seed, e, syn)
        return [(sd, sy) for sd, _e, sy in out], [e for _sd, e, _sy in out]
    out = [S.stern_f_keygen(n) for _ in range(k)]              # (seed, e, syn)
    return [(sd, sy) for sd, _e, sy in out], [e for _sd, e, _sy in out]

def sign(msg, e, j, ring, n, rounds):
    if n > 256:
        return S.hpks_stern_l_ring_sign(msg, e, j, ring, n, rounds)
    return S.hpks_stern_ring_sign(msg, e, j, ring, n, rounds)

def verify(msg, sig, ring, n):
    if n > 256:
        return S.hpks_stern_l_ring_verify(msg, sig, ring, n)
    return S.hpks_stern_ring_verify(msg, sig, ring, n)

if mode == 'pem':                       # pem KEY0 KEY1 MSGFILE OUT
    ring, es = [], []
    for kp in sys.argv[2:4]:
        _a, (e_int, seed_int, n) = cli._decode_privkey(kp)
        seed = cli._stern_seed(seed_int, n)
        ring.append((seed, cli._stern_syn(seed_int, e_int, n))); es.append(e_int)
    msg = cli._stern_msg(cli.hfscx_256(open(sys.argv[4], 'rb').read()), n)
    sig = S.hpks_stern_ring_sign(msg, es[1], 1, ring, n, 32)
    assert S.hpks_stern_ring_verify(msg, sig, ring, n)
    open(sys.argv[5], 'w').write(cli._pack_ring_sig(sig, n))
else:                                   # lib N -- the three library cells
    n = int(sys.argv[2]); rounds = 4
    ring, es = keys(n)
    msg = cli._stern_msg(cli.hfscx_256(b'library cell'), n)
    other = cli._stern_msg(cli.hfscx_256(b'another message'), n)
    sig = sign(msg, es[1], 1, ring, n, rounds)
    print('honest', 'ok' if verify(msg, sig, ring, n) else 'refused')
    print('other-msg', 'ok' if verify(other, sig, ring, n) else 'refused')
    chals = sig[1]
    hit = next(((i, r) for i, row in enumerate(chals) for r, b in enumerate(row) if b == 2), None)
    if hit is None:
        print('b2-as-5', 'n/a')
    else:
        chals[hit[0]][hit[1]] = 5
        print('b2-as-5', 'ok' if verify(msg, sig, ring, n) else 'refused')
EOF
export HKX_ROOT="$ROOT"
python3 "$TMP/lib.py" pem "$TMP/k0.pem" "$TMP/k1.pem" "$TMP/m" "$TMP/genuine.sig" \
    || { fail "fixture: genuine ring signature from the library"; exit 1; }

cells() {
    local l=$1 X=$2 out rc
    # accept-control: the same CLI is not refusing everything
    if $X sign --algo hpks-stern --rounds 4 --key "$TMP/k0.pem" --in "$TMP/m" --out "$TMP/st_$l.sig" >/dev/null 2>&1 \
       && $X verify --algo hpks-stern --min-rounds 4 --pubkey "$TMP/p0.pem" --in "$TMP/m" --sig "$TMP/st_$l.sig" >/dev/null 2>&1; then
        pass "$l: accept: hpks-stern signs and verifies"
    else fail "$l: accept: hpks-stern sign/verify failed"; fi

    rm -f "$TMP/r_$l.sig"
    out=$($X sign --algo hpks-ring --key "$TMP/k1.pem" --ring "$RING" --in "$TMP/m" --out "$TMP/r_$l.sig" 2>&1); rc=$?
    [ $rc -ne 0 ] && pass "$l: refused: sign exits non-zero" || fail "$l: refused: sign exited 0"
    grep -qF -- "$MSG" <<<"$out" && pass "$l: message: sign names the reason" \
        || fail "$l: message: sign said: $(head -c 120 <<<"$out")"
    [ ! -e "$TMP/r_$l.sig" ] && pass "$l: refused: sign wrote nothing" || fail "$l: refused: sign wrote --out"

    out=$($X verify --algo hpks-ring --ring "$RING" --in "$TMP/m" --sig "$TMP/genuine.sig" 2>&1); rc=$?
    [ $rc -ne 0 ] && pass "$l: refused: verify of a genuine signature exits non-zero" \
        || fail "$l: refused: verify of a genuine signature exited 0"
    grep -qF -- "$MSG" <<<"$out" && pass "$l: message: verify names the reason" \
        || fail "$l: message: verify said: $(head -c 120 <<<"$out")"

    out=$($X verify --algo hpks-ring --ring "$RING" --in "$TMP/m" --sig "$TMP/does-not-exist" 2>&1); rc=$?
    { [ $rc -ne 0 ] && grep -qF -- "$MSG" <<<"$out"; } && pass "$l: message: the refusal precedes every file read" \
        || fail "$l: message: verify with a missing --sig said: $(head -c 120 <<<"$out")"
}
for l in "${LANGS[@]}"; do cells "$l" "${CLI[$l]}"; done

for n in 256 2304; do
    res=$(python3 "$TMP/lib.py" lib $n 2>&1) || { fail "library N=$n: crashed: $(tail -1 <<<"$res")"; continue; }
    [ "$(grep '^honest ' <<<"$res")" = "honest ok" ] && pass "library N=$n: accept: a genuine ring signature verifies" \
        || fail "library N=$n: accept: genuine signature: $res"
    [ "$(grep '^other-msg ' <<<"$res")" = "other-msg refused" ] && pass "library N=$n: another message is refused" \
        || fail "library N=$n: another message: $res"
    case "$(grep '^b2-as-5 ' <<<"$res")" in
        "b2-as-5 refused") pass "library N=$n: b = 2 re-encoded as 5 is refused (TODO #421)" ;;
        "b2-as-5 n/a")     echo "n/a  library N=$n: no b = 2 entry to re-encode (not scored)" ;;
        *)                 fail "library N=$n: b = 2 re-encoded as 5: $res" ;;
    esac
done

# ── negative controls ─────────────────────────────────────────────────────────
N_RC=2; N_ACC_MSG=4
cat > "$TMP/exit0_cli" <<EOF
#!/usr/bin/env bash
for a in "\$@"; do [ "\$a" = hpks-ring ] && { echo "sign: --algo $MSG" >&2; exit 0; }; done
exec $G "\$@"
EOF
cat > "$TMP/refuse_cli" <<'EOF'
#!/usr/bin/env bash
echo "error: refused" >&2; exit 1
EOF
chmod +x "$TMP/exit0_cli" "$TMP/refuse_cli"
before=$FAIL; pbefore=$PASS
cells exit0 "$TMP/exit0_cli" >"$TMP/c1.out"
got1=$(grep -c '^FAIL exit0: refused:.*exit' "$TMP/c1.out")
cells refuse "$TMP/refuse_cli" >"$TMP/c2.out"
got2=$(grep -cE '^FAIL refuse: (accept|message):' "$TMP/c2.out")
FAIL=$before; PASS=$pbefore
[ "$got1" -eq "$N_RC" ] && pass "control: a CLI that prints the message but exits 0 fails all $N_RC exit-status cells" \
    || fail "control: an exit-0 CLI failed $got1/$N_RC exit-status cells"
[ "$got2" -eq "$N_ACC_MSG" ] && pass "control: a CLI that refuses everything fails all $N_ACC_MSG accept and message cells" \
    || fail "control: a refuse-everything CLI failed $got2/$N_ACC_MSG accept and message cells"

echo
echo "test_ring: $PASS passed, $FAIL failed"
[ $FAIL -eq 0 ] && echo "*** OK: hpks-ring is disabled in every CLI; the library verifier keeps its checks ***"
[ $FAIL -eq 0 ]
