#!/usr/bin/env bash
# CliTest/test_round_floor.sh — TODO #364: the verifier's Fiat-Shamir round floor,
# as a 4-language (C/Go/Python/Java) signer x verifier matrix.
#
# WHY THIS FILE EXISTS.  Since TODO #236 the round count travels in the artifact,
# and until v15.0.0 every reader accepted any count in [1, 4096].  So the SIGNER
# chose the verifier's soundness: one Stern-F or ZKBoo-(2,3) round can be
# answered without the witness for two of its three challenges, and under
# Fiat-Shamir a forger grinds the commitment until the challenge is one of those.
# A 1-round artifact verified in all four CLIs.  Now `verify` and `cred-verify`
# refuse fewer than `--min-rounds N` (default 219, the 128-bit count).
#
# A floor all four ports got wrong the same way would pass every cross-port
# check (CLAUDE.md, #298), so the subject here is each VERIFIER's own refusal,
# matched on the floor's own message, with the same artifact accepted at
# `--min-rounds` equal to its count as the accept-control.  Artifacts are made
# at low round counts, so the matrix is cheap; the default-flags interop cell
# (219 rounds both sides) is run once per verifier on the C signer's output.
#
# Also (TODO #390): signatures above 255 rounds, where C and Go used the round
# index's low byte; see that section below.
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
    CLI[java]="java -cp $ROOT/bindings/java herradurakex.HerraduraCli"
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
# The HCRED rows need the C CLI: Python's HCRED keys default to n = 32, which C
# and Java refuse, and C is the fast n = 256 prover.
if [ -z "${CLI[c]:-}" ] || [ "${#LANGS[@]}" -lt 2 ]; then
    echo "FAIL test_round_floor: needs the C CLI and at least one other, so nothing" \
         "was asserted (run ./build_c.sh and ./build_go.sh)." >&2
    [ "${HKX_ALLOW_SKIP:-0}" = "1" ] && exit 0
    exit 2
fi

pass() { echo "PASS $1"; PASS=$((PASS+1)); }
fail() { echo "FAIL $1"; FAIL=$((FAIL+1)); }

accepts() {   # label, then the verify argv
    local label="$1"; shift
    local out rc
    out=$("$@" 2>&1) && rc=0 || rc=$?
    if [ "$rc" -eq 0 ] && echo "$out" | grep -q "OK"; then pass "$label"
    else fail "$label (rc=$rc): $out"; fi
}
floored() {   # label, then the verify argv — must be refused BY THE FLOOR
    local label="$1"; shift
    local out rc
    out=$("$@" 2>&1) && rc=0 || rc=$?
    if [ "$rc" -ne 0 ] && echo "$out" | grep -q "below the --min-rounds floor"; then pass "$label"
    else fail "$label: expected the round-floor refusal (rc=$rc): $out"; fi
}
refused() {   # label, then argv — any non-zero exit
    local label="$1"; shift
    if "$@" >/dev/null 2>&1; then fail "$label: accepted"; else pass "$label"; fi
}

C=${CLI[c]}
printf 'round floor test message' > "$TMP/msg.bin"
$C genpkey --algo hpks-stern  --out "$TMP/st.pem" 2>/dev/null
$C pkey --in "$TMP/st.pem" --pubout --out "$TMP/st_pub.pem"
$C genpkey --algo hpks-zkp-nl --out "$TMP/zk.pem" 2>/dev/null
$C pkey --in "$TMP/zk.pem" --pubout --out "$TMP/zk_pub.pem"
for m in 1 2 3; do
    $C genpkey --algo hpks-stern --out "$TMP/m$m.pem" 2>/dev/null
    $C pkey --in "$TMP/m$m.pem" --pubout --out "$TMP/m${m}_pub.pem"
done
RING="$TMP/m1_pub.pem,$TMP/m2_pub.pem,$TMP/m3_pub.pem"
$C genpkey --algo hcred --out "$TMP/hc.pem" 2>/dev/null
$C pkey --in "$TMP/hc.pem" --pubout --out "$TMP/hc_pub.pem"

# Low-round artifacts from every signer.  R = 2 so that --min-rounds 3 is a
# refusal one above the declared count and --min-rounds 2 the control at it.
R=2
for s in "${LANGS[@]}"; do
    S=${CLI[$s]}
    $S sign --algo hpks-stern --key "$TMP/st.pem" --in "$TMP/msg.bin" \
            --rounds $R --out "$TMP/st_$s.pem" 2>/dev/null
    $S sign --algo hpks-ring --key "$TMP/m1.pem" --ring "$RING" --in "$TMP/msg.bin" \
            --rounds $R --out "$TMP/ring_$s.pem" 2>/dev/null
    $S sign --algo nl-zkboo --key "$TMP/zk.pem" --in "$TMP/msg.bin" \
            --rounds $R --out "$TMP/zb_$s.pem" 2>/dev/null
    $S sign --algo nl-zkbpp --key "$TMP/zk.pem" --in "$TMP/msg.bin" \
            --rounds $R --out "$TMP/zp_$s.pem" 2>/dev/null
done
$C cred-prove --in "$TMP/hc.pem" --msg nonce --rounds $R --out "$TMP/proof.pem" 2>/dev/null
$C cred-issue --our "$TMP/st.pem" --in "$TMP/hc_pub.pem" --rounds $R --out "$TMP/cred.pem" 2>/dev/null
$C cred-issue --our "$TMP/st.pem" --in "$TMP/hc_pub.pem" --rounds 1 --out "$TMP/cred1.pem" 2>/dev/null
# Default flags: 219 rounds.
$C sign --algo hpks-stern --key "$TMP/st.pem" --in "$TMP/msg.bin" --out "$TMP/st_dflt.pem" 2>/dev/null

for v in "${LANGS[@]}"; do
    V=${CLI[$v]}
    echo "=== verifier: $v ==="
    for s in "${LANGS[@]}"; do
        st=(verify --algo hpks-stern --pubkey "$TMP/st_pub.pem" --in "$TMP/msg.bin" --sig "$TMP/st_$s.pem")
        rg=(verify --algo hpks-ring --ring "$RING" --in "$TMP/msg.bin" --sig "$TMP/ring_$s.pem")
        zb=(verify --algo nl-zkboo --pubkey "$TMP/zk_pub.pem" --in "$TMP/msg.bin" --sig "$TMP/zb_$s.pem")
        zp=(verify --algo nl-zkbpp --pubkey "$TMP/zk_pub.pem" --in "$TMP/msg.bin" --sig "$TMP/zp_$s.pem")
        for row in st rg zb zp; do
            declare -n argv=$row
            accepts "$row $s->$v at --min-rounds $R (control)" $V "${argv[@]}" --min-rounds $R
            floored "$row $s->$v refused at the default floor"   $V "${argv[@]}"
            floored "$row $s->$v refused at --min-rounds $((R+1))" $V "${argv[@]}" --min-rounds $((R+1))
            unset -n argv
        done
    done
    pr=(cred-verify --proof "$TMP/proof.pem" --pubkey "$TMP/hc_pub.pem" --msg nonce)
    accepts "hcred proof c->$v at --min-rounds $R (control)" $V "${pr[@]}" --min-rounds $R
    floored "hcred proof c->$v refused at the default floor" $V "${pr[@]}"
    floored "hcred proof c->$v refused at --min-rounds $((R+1))" $V "${pr[@]}" --min-rounds $((R+1))
    accepts "hcred credential c->$v at --min-rounds $R (control)" $V "${pr[@]}" --min-rounds $R \
        --cred "$TMP/cred.pem" --issuer "$TMP/st_pub.pem"
    # The proof passes at --min-rounds 2; the 1-round credential must not.
    floored "hcred 1-round credential c->$v refused at --min-rounds $R" $V "${pr[@]}" --min-rounds $R \
        --cred "$TMP/cred1.pem" --issuer "$TMP/st_pub.pem"
    accepts "hpks-stern default flags c->$v (219 rounds)" \
        $V verify --algo hpks-stern --pubkey "$TMP/st_pub.pem" --in "$TMP/msg.bin" --sig "$TMP/st_dflt.pem"
    for bad in 0 4097; do
        refused "$v verify refuses --min-rounds $bad" \
            $V verify --algo hpks-stern --pubkey "$TMP/st_pub.pem" --in "$TMP/msg.bin" \
            --sig "$TMP/st_dflt.pem" --min-rounds $bad
    done
done

# ── Round index above 255 (TODO #390) ─────────────────────────────────────────
# Each round's challenge advances the Fiat-Shamir state by nl_fscx_v1(ch_st, i)
# with i the WHOLE round index.  C and Go used i & 0xFF, so above 255 rounds their
# signatures and Python's / Java's did not verify in each other.  hpks-stern,
# hpks-ring and the HCRED credential (cred-issue) share the derivation; each is
# signed at RR rounds by every CLI and verified by every CLI at the default floor.
# A rule all four got wrong would pass that matrix, so stern_ref restates the rule
# and checks each signer's hpks-stern challenges against it; its low-byte variant
# must disagree, which shows the check can fire.
RR=300
stern_ref() { python3 - "$ROOT" "$1" "$TMP/msg.bin" <<'PYEOF'
import os, sys
sys.path.insert(0, os.path.join(sys.argv[1], "HerraduraCli"))
import herradura as H
S = H._suite_mod
commits, chals, _resp, n = H._unpack_stern_sig(sys.argv[2])
data = S.hfscx_256(open(sys.argv[3], "rb").read())   # sign's default --digest hfscx-256
msg = S.BitArray(n, int.from_bytes(data[:n // 8].ljust(n // 8, b"\0"), "big"))
def derive(idx):
    st = S._stern_hash(n, msg, *[c for t in commits for c in t])
    out = []
    for i in range(len(commits)):
        st = S.nl_fscx_v1(st, S.BitArray(n, idx(i)))
        out.append((st.uint & 0xFFFFFFFF) % 3)
    return out
whole = derive(lambda i: i) == list(chals)
low = derive(lambda i: i & 0xFF) == list(chals)
print("whole" if whole and not low else "low" if low else "neither")
PYEOF
}
for s in "${LANGS[@]}"; do
    S=${CLI[$s]}
    $S sign --algo hpks-stern --key "$TMP/st.pem" --in "$TMP/msg.bin" \
            --rounds $RR --out "$TMP/st${RR}_$s.pem" 2>/dev/null || fail "hpks-stern $RR-round sign ($s)"
    $S sign --algo hpks-ring --key "$TMP/m1.pem" --ring "$RING" --in "$TMP/msg.bin" \
            --rounds $RR --out "$TMP/ring${RR}_$s.pem" 2>/dev/null || fail "hpks-ring $RR-round sign ($s)"
    $S cred-issue --our "$TMP/st.pem" --in "$TMP/hc_pub.pem" --rounds $RR \
            --out "$TMP/cred${RR}_$s.pem" 2>/dev/null || fail "cred-issue $RR rounds ($s)"
    got=$(stern_ref "$TMP/st${RR}_$s.pem" 2>&1 | tail -1)
    if [ "$got" = whole ]; then pass "hpks-stern $RR rounds ($s): challenges use the whole round index"
    else fail "hpks-stern $RR rounds ($s): challenges follow the '$got' rule, not the whole index"; fi
done
for v in "${LANGS[@]}"; do
    V=${CLI[$v]}
    for s in "${LANGS[@]}"; do
        accepts "hpks-stern $RR rounds $s->$v" $V verify --algo hpks-stern \
            --pubkey "$TMP/st_pub.pem" --in "$TMP/msg.bin" --sig "$TMP/st${RR}_$s.pem"
        accepts "hpks-ring $RR rounds $s->$v" $V verify --algo hpks-ring \
            --ring "$RING" --in "$TMP/msg.bin" --sig "$TMP/ring${RR}_$s.pem"
        accepts "hcred credential $RR rounds $s->$v" $V cred-verify --proof "$TMP/proof.pem" \
            --pubkey "$TMP/hc_pub.pem" --msg nonce --min-rounds $R \
            --cred "$TMP/cred${RR}_$s.pem" --issuer "$TMP/st_pub.pem"
    done
done

echo
echo "Results: $PASS PASS / $FAIL FAIL (languages: ${LANGS[*]})"
[ "$FAIL" -eq 0 ]
