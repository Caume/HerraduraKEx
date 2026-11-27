#!/usr/bin/env bash
# CliTest/test_ring.sh — HPKS-Ring, 4x4 across the CLIs (TODO #415).
#
# The ring is ONE Stern proof over the ring's block-diagonal statement (SPEC.md
# §11.2); it replaced the OR-composition, which was forgeable with no member's
# key.  Every CLI signs, every CLI verifies, at N = 256 with 4 rounds (the
# verifiers are given --min-rounds 4).  The long form runs 4x4 in
# test_stern_128.sh, every width in test_width_matrix.sh, and a wrong witness
# in test_wrong_secret_matrix.sh.
#
# Cells:
#   accept   s -> v for every signer and verifier, the ring given to the
#            verifier in another order (the signature binds the canonical,
#            sorted ring); a one-member ring signed by C, verified by each CLI.
#   refused  per verifier, of C's signature: another message; a ring with a
#            member replaced; a sub-ring and a super-ring (the declared k); one
#            changed byte; the signature's own round count without
#            --min-rounds (the 219 floor); a ring that lists a member twice; and
#            a version-1 signature (HERRADURA HPKS-RING SIGNATURE, the forgeable
#            OR-composition), named and refused.  Per signer: a signer whose key
#            is not in --ring, with no --out file written.
# Negative controls, each shown to FIRE: a stand-in that prints "Signature OK"
# and exits 0 fails every verify-refusal cell; a stand-in that refuses
# everything fails every accept cell.
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

R=4
G="${CLI[c]}"
printf 'ring probe' > "$TMP/m"
printf 'another message' > "$TMP/m2"
for m in 0 1 2 x; do
    $G genpkey --algo hpks-stern --out "$TMP/k$m.pem" >/dev/null 2>&1
    $G pkey --in "$TMP/k$m.pem" --pubout --out "$TMP/p$m.pem" >/dev/null 2>&1
done
RING="$TMP/p0.pem,$TMP/p1.pem,$TMP/p2.pem"
SHUF="$TMP/p2.pem,$TMP/p0.pem,$TMP/p1.pem"
idx=0
for s in "${LANGS[@]}"; do
    ${CLI[$s]} sign --algo hpks-ring --rounds $R --key "$TMP/k$((idx % 3)).pem" --ring "$RING" \
        --in "$TMP/m" --out "$TMP/s_$s.pem" >/dev/null 2>&1 || fail "fixture: $s ring sign"
    idx=$((idx + 1))
done
$G sign --algo hpks-ring --rounds $R --key "$TMP/k0.pem" --ring "$TMP/p0.pem" \
    --in "$TMP/m" --out "$TMP/s_one.pem" >/dev/null 2>&1 || fail "fixture: one-member ring sign"
# the version-1 label over an arbitrary body: verify must name it and refuse it
{ echo "-----BEGIN HERRADURA HPKS-RING SIGNATURE-----"; echo "MAMCAQE="
  echo "-----END HERRADURA HPKS-RING SIGNATURE-----"; } > "$TMP/v1.pem"
python3 - "$TMP/s_c.pem" "$TMP/s_bad.pem" <<'EOF'
import sys
lines = open(sys.argv[1]).read().split('\n')
mid = len(lines) // 2                 # one base64 character in the middle of the body
row = lines[mid]
lines[mid] = row[:10] + ('A' if row[10] != 'A' else 'B') + row[11:]
open(sys.argv[2], 'w').write('\n'.join(lines))
EOF

V1MSG="version-1 HPKS-Ring signature"
accept_cells() {   # $1 label, $2.. the verifier command
    local l=$1; shift; local X="$*" s out
    for s in "${LANGS[@]}"; do
        out=$($X verify --algo hpks-ring --min-rounds $R --ring "$SHUF" --in "$TMP/m" --sig "$TMP/s_$s.pem" 2>&1)
        [ $? -eq 0 ] && grep -q "Signature OK" <<<"$out" && pass "$l: accept: $s -> $l (ring in another order)" \
            || fail "$l: accept: $s -> $l said: $(tail -1 <<<"$out")"
    done
    out=$($X verify --algo hpks-ring --min-rounds $R --ring "$TMP/p0.pem" --in "$TMP/m" --sig "$TMP/s_one.pem" 2>&1)
    [ $? -eq 0 ] && grep -q "Signature OK" <<<"$out" && pass "$l: accept: a one-member ring" \
        || fail "$l: accept: one-member ring said: $(tail -1 <<<"$out")"
}
refuse() {   # $1 label, $2 expected text, $3.. the command
    local l=$1 want=$2; shift 2; local out rc
    out=$("$@" 2>&1); rc=$?
    if [ $rc -ne 0 ] && grep -qF -- "$want" <<<"$out" && ! grep -q "Signature OK" <<<"$out"; then pass "$l"
    else fail "$l: rc=$rc: $(tail -1 <<<"$out" | head -c 160)"; fi
}
refuse_cells() {
    local l=$1; shift; local X="$*"
    refuse "$l: refused: another message" "Verification FAILED" \
        $X verify --algo hpks-ring --min-rounds $R --ring "$RING" --in "$TMP/m2" --sig "$TMP/s_c.pem"
    refuse "$l: refused: a ring with a member replaced" "Verification FAILED" \
        $X verify --algo hpks-ring --min-rounds $R --ring "$TMP/p0.pem,$TMP/p1.pem,$TMP/px.pem" --in "$TMP/m" --sig "$TMP/s_c.pem"
    refuse "$l: refused: a sub-ring" "signature ring size 3 != 2 provided members" \
        $X verify --algo hpks-ring --min-rounds $R --ring "$TMP/p0.pem,$TMP/p1.pem" --in "$TMP/m" --sig "$TMP/s_c.pem"
    refuse "$l: refused: a super-ring" "signature ring size 3 != 4 provided members" \
        $X verify --algo hpks-ring --min-rounds $R --ring "$RING,$TMP/px.pem" --in "$TMP/m" --sig "$TMP/s_c.pem"
    refuse "$l: refused: one changed byte" "" \
        $X verify --algo hpks-ring --min-rounds $R --ring "$RING" --in "$TMP/m" --sig "$TMP/s_bad.pem"
    refuse "$l: refused: $R rounds under the default floor" "below the --min-rounds floor" \
        $X verify --algo hpks-ring --ring "$RING" --in "$TMP/m" --sig "$TMP/s_c.pem"
    refuse "$l: refused: a ring listing a member twice" "lists the member" \
        $X verify --algo hpks-ring --min-rounds $R --ring "$TMP/p0.pem,$TMP/p0.pem,$TMP/p1.pem" --in "$TMP/m" --sig "$TMP/s_c.pem"
    refuse "$l: refused: a version-1 signature, by name" "$V1MSG" \
        $X verify --algo hpks-ring --min-rounds $R --ring "$RING" --in "$TMP/m" --sig "$TMP/v1.pem"
}
N_REFUSE=8
for l in "${LANGS[@]}"; do accept_cells "$l" ${CLI[$l]}; done
for l in "${LANGS[@]}"; do refuse_cells "$l" ${CLI[$l]}; done
for s in "${LANGS[@]}"; do
    rm -f "$TMP/no_$s.pem"
    refuse "$s: refused: a signer whose key is not in --ring" "is not in --ring" \
        ${CLI[$s]} sign --algo hpks-ring --rounds $R --key "$TMP/kx.pem" --ring "$RING" --in "$TMP/m" --out "$TMP/no_$s.pem"
    [ ! -e "$TMP/no_$s.pem" ] && pass "$s: refused: nothing written for a non-member" \
        || fail "$s: a non-member's refused sign wrote --out"
done

# ── negative controls ─────────────────────────────────────────────────────────
cat > "$TMP/ok_cli" <<'EOF'
#!/usr/bin/env bash
echo "Signature OK"; exit 0
EOF
cat > "$TMP/refuse_cli" <<'EOF'
#!/usr/bin/env bash
echo "error: refused" >&2; exit 1
EOF
chmod +x "$TMP/ok_cli" "$TMP/refuse_cli"
before=$FAIL; pbefore=$PASS
refuse_cells okcli "$TMP/ok_cli" >"$TMP/c1.out"
got1=$(grep -c '^FAIL okcli: refused:' "$TMP/c1.out")
accept_cells refusecli "$TMP/refuse_cli" >"$TMP/c2.out"
got2=$(grep -c '^FAIL refusecli: accept:' "$TMP/c2.out")
FAIL=$before; PASS=$pbefore
N_ACC=$(( ${#LANGS[@]} + 1 ))
[ "$got1" -eq "$N_REFUSE" ] && pass "control: a verifier that always says OK fails all $N_REFUSE refusal cells" \
    || fail "control: an always-OK verifier failed $got1/$N_REFUSE refusal cells"
[ "$got2" -eq "$N_ACC" ] && pass "control: a CLI that refuses everything fails all $N_ACC accept cells" \
    || fail "control: a refuse-everything CLI failed $got2/$N_ACC accept cells"

echo
echo "test_ring: $PASS passed, $FAIL failed"
[ $FAIL -eq 0 ] && echo "*** OK: HPKS-Ring signs and verifies 4x4 and refuses what it must ***"
[ $FAIL -eq 0 ]
