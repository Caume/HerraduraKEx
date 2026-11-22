#!/usr/bin/env bash
# CliTest/test_stern_128.sh — TODO #382 stage 2: Stern-F's 128-bit parameter
# set, N = 2304 (k = 1152, t = 144), as a 4-language (C/Go/Python/Java) matrix.
#
# The long form (SPEC.md §11) carries its vectors as N/8-byte strings and its
# commitments, message and Fiat-Shamir state at 256 bits; every artifact keeps
# the short form's PEM layout with n = 2304.  This file checks, at that N:
#
#   keys        genpkey --level 128 in every CLI; every CLI's pkey --pubout of
#               every key is byte-identical, and --text agrees (level 128)
#   hpks-stern  every CLI signs, every CLI verifies (4x4), at a reduced round
#               count; one 219-round C signature verified at the default floor
#   hpks-ring   a two-member ring, 4x4
#   hpke-stern  every CLI encrypts a 32-byte block, every CLI decrypts it
#   hcred       a long-form issuer's credential, issued by every CLI and checked
#               by every CLI's cred-verify
#
# A rule all four ports got wrong the same way would pass every matrix above
# (CLAUDE.md, #298), so two checks are about ONE implementation each:
#   - the matrix rule, restated here from SPEC.md's text with the suite's
#     HFSCX-256 and nothing else, must reproduce a key's public syndrome, and
#     its error must have weight N/16;
#   - a signature's DER fields must have the long form's sizes (32-byte
#     commitments, N/8-byte responses).
# Every acceptance has rejection controls beside it: a changed message, a
# corrupted response, the wrong key, and a short-form signature against a
# long-form key, each refused by every verifier.
#
# Claimed by ci.yml's cross-lang-compat job (all four CLIs built).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
PASS=0; FAIL=0
R=8          # reduced Fiat-Shamir rounds for the matrix (verifiers get --min-rounds)
N=2304

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
# The HCRED rows need the C CLI (its n = 256 HCRED prover; Python's defaults to 32).
if [ -z "${CLI[c]:-}" ] || [ "${#LANGS[@]}" -lt 2 ]; then
    echo "FAIL test_stern_128: needs the C CLI and at least one other, so nothing" \
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
rejects() {   # label, then the verify argv — must exit non-zero with no "OK"
    local label="$1"; shift
    local out rc
    out=$("$@" 2>&1) && rc=0 || rc=$?
    if [ "$rc" -ne 0 ] && ! echo "$out" | grep -q "Signature OK\|Credential OK"; then pass "$label"
    else fail "$label: expected a refusal (rc=$rc): $out"; fi
}

head -c 200 /dev/urandom > "$TMP/msg.bin"
printf 'other message' > "$TMP/msg2.bin"
printf 'thirty-two bytes of plaintext!!\n' > "$TMP/pt.bin"     # exactly 32 bytes

# ── Keys ──────────────────────────────────────────────────────────────────────
for s in "${LANGS[@]}"; do
    ${CLI[$s]} genpkey --algo hpks-stern --level 128 --out "$TMP/k_$s.pem" 2>/dev/null \
        || fail "genpkey --level 128 ($s)"
done
${CLI[c]} genpkey --algo hpks-stern --bits $N --out "$TMP/kb.pem" 2>/dev/null \
    && pass "genpkey --bits $N names the same set (c)" || fail "genpkey --bits $N (c)"
for s in "${LANGS[@]}"; do
    ref=""
    for v in "${LANGS[@]}"; do
        ${CLI[$v]} pkey --in "$TMP/k_$s.pem" --pubout --out "$TMP/p_${s}_$v.pem" 2>/dev/null \
            || { fail "pkey --pubout of $s's key ($v)"; continue; }
        if [ -z "$ref" ]; then ref="$TMP/p_${s}_$v.pem"
        elif cmp -s "$ref" "$TMP/p_${s}_$v.pem"; then pass "$s's key: $v's public key matches"
        else fail "$s's key: $v's public key differs"; fi
    done
    cp "$ref" "$TMP/k_${s}_pub.pem"
done
# --text: the whole dump, alike in every CLI (one layout since TODO #386),
# ending in the 128-bit row's level and estimate.
for s in "${LANGS[@]}"; do
    t_ref=""
    for v in "${LANGS[@]}"; do
        out=$(${CLI[$v]} pkey --in "$TMP/k_$s.pem" --text 2>/dev/null)
        if ! echo "$out" | grep -q "^level *: 128\$"; then fail "$s's key: $v's --text has no 'level : 128'"; continue; fi
        if ! echo "$out" | grep -q "^n *: $N\$"; then fail "$s's key: $v's --text does not say n = $N"; continue; fi
        if [ -z "$t_ref" ]; then t_ref="$out"
        elif [ "$out" = "$t_ref" ]; then pass "$s's key: $v's --text matches"
        else fail "$s's key: $v's --text differs"; fi
    done
done

# ── One implementation at a time: the matrix rule and the error weight ───────
# Restated from SPEC.md §11 with the suite's hash and nothing else: sk =
# HFSCX-256-DS(0x31, 0x06 || seed); row i = chunk(i, 0) || ... || chunk(i, 8),
# chunk(i, c) = HFSCX-256(i_hi || i_lo || c) with sk as the initial chaining
# value; the public syndrome's bit i is row i . e.  The negative control (row
# index's low byte only, the short form's habit) must disagree.
stern_ref() { python3 - "$ROOT" "$1" "$2" <<'PYEOF'
import os, sys
sys.path.insert(0, os.path.join(sys.argv[1], "HerraduraCli"))
import herradura as H
S = H._suite_mod
_, (e, seed, n) = H._decode_privkey(sys.argv[2])
_, (syn, seed2, n2) = H._decode_pubkey(sys.argv[3])
nb = n // 8
sk = S.BitArray(256, int.from_bytes(S.hfscx_256_ds(0x31, bytes([6]) + seed.to_bytes(nb, "big")), "big"))
def syndrome(idx):
    s = 0
    for i in range(n // 2):
        row = b"".join(S.hfscx_256(bytes([idx(i) >> 8, idx(i) & 0xFF, c]), iv=sk) for c in range(n // 256))
        s |= (bin(int.from_bytes(row, "big") & e).count("1") & 1) << i
    return s
ok = n == n2 == 2304 and seed == seed2 and bin(e).count("1") == n // 16
print("rule" if ok and syndrome(lambda i: i) == syn and syndrome(lambda i: i & 0xFF) != syn
      else "weight" if not ok else "no-rule")
PYEOF
}
for s in c go; do
    [ -n "${CLI[$s]:-}" ] || continue
    got=$(stern_ref "$TMP/k_$s.pem" "$TMP/k_${s}_pub.pem" 2>&1 | tail -1)
    if [ "$got" = rule ]; then pass "$s's key: syndrome follows SPEC.md's matrix rule, weight N/16"
    else fail "$s's key: independent check says '$got'"; fi
done

# ── hpks-stern ────────────────────────────────────────────────────────────────
for s in "${LANGS[@]}"; do
    ${CLI[$s]} sign --algo hpks-stern --key "$TMP/k_$s.pem" --in "$TMP/msg.bin" \
        --rounds $R --out "$TMP/s_$s.pem" 2>/dev/null || fail "hpks-stern sign ($s)"
done
# The layout, read off the DER: item 2 is rounds x 3 x 32 bytes, item 4 rounds x 2 x N/8.
layout=$(python3 - "$ROOT" "$TMP/s_c.pem" "$R" <<'PYEOF'
import os, sys
sys.path.insert(0, os.path.join(sys.argv[1], "HerraduraCli"))
import herradura as H
label, der = H._read_pem(sys.argv[2])
enc = H._codec_mod.der_scan(der, label)
r = int(sys.argv[3])
print("ok" if [w for w, _ in enc][2] == r * 96 and [w for w, _ in enc][4] == r * 2 * 288 else enc)
PYEOF
)
[ "$layout" = ok ] && pass "c's signature: 32-byte commitments, N/8-byte responses" \
                  || fail "c's signature layout: $layout"
for v in "${LANGS[@]}"; do
    V=${CLI[$v]}
    for s in "${LANGS[@]}"; do
        accepts "hpks-stern $s->$v" $V verify --algo hpks-stern --pubkey "$TMP/k_${s}_pub.pem" \
            --in "$TMP/msg.bin" --sig "$TMP/s_$s.pem" --min-rounds $R
    done
done
# Rejection controls, each against every verifier.
python3 - "$ROOT" "$TMP/s_go.pem" "$TMP/s_bad.pem" <<'PYEOF'
import os, sys
sys.path.insert(0, os.path.join(sys.argv[1], "HerraduraCli"))
import herradura as H
commits, chals, resps, n = H._unpack_stern_sig(sys.argv[2])
a, v = resps[-1]
resps[-1] = (a, v ^ 1)            # one bit of the last response
open(sys.argv[3], "w").write(H._pack_stern_sig((commits, chals, resps), n))
PYEOF
${CLI[c]} genpkey --algo hpks-stern --bits 256 --out "$TMP/k256.pem" 2>/dev/null
${CLI[c]} sign --algo hpks-stern --key "$TMP/k256.pem" --in "$TMP/msg.bin" --rounds $R \
    --out "$TMP/s256.pem" 2>/dev/null
for v in "${LANGS[@]}"; do
    V=${CLI[$v]}
    rejects "hpks-stern changed message ($v)" $V verify --algo hpks-stern \
        --pubkey "$TMP/k_go_pub.pem" --in "$TMP/msg2.bin" --sig "$TMP/s_go.pem" --min-rounds $R
    rejects "hpks-stern corrupted response ($v)" $V verify --algo hpks-stern \
        --pubkey "$TMP/k_go_pub.pem" --in "$TMP/msg.bin" --sig "$TMP/s_bad.pem" --min-rounds $R
    rejects "hpks-stern wrong key ($v)" $V verify --algo hpks-stern \
        --pubkey "$TMP/k_py_pub.pem" --in "$TMP/msg.bin" --sig "$TMP/s_go.pem" --min-rounds $R
    rejects "hpks-stern N=256 signature, N=2304 key ($v)" $V verify --algo hpks-stern \
        --pubkey "$TMP/k_go_pub.pem" --in "$TMP/msg.bin" --sig "$TMP/s256.pem" --min-rounds $R
    rejects "hpks-stern $R-round signature at the default floor ($v)" $V verify --algo hpks-stern \
        --pubkey "$TMP/k_go_pub.pem" --in "$TMP/msg.bin" --sig "$TMP/s_go.pem"
done
# The production count, at the default floor.
${CLI[c]} sign --algo hpks-stern --key "$TMP/k_c.pem" --in "$TMP/msg.bin" \
    --out "$TMP/s219.pem" 2>/dev/null || fail "hpks-stern 219-round sign (c)"
for v in "${LANGS[@]}"; do
    accepts "hpks-stern 219 rounds c->$v (default floor)" ${CLI[$v]} verify --algo hpks-stern \
        --pubkey "$TMP/k_c_pub.pem" --in "$TMP/msg.bin" --sig "$TMP/s219.pem"
done

# ── hpks-ring ─────────────────────────────────────────────────────────────────
RING="$TMP/k_c_pub.pem,$TMP/k_go_pub.pem"
for s in "${LANGS[@]}"; do
    key="$TMP/k_c.pem"; [ "$s" = c ] || key="$TMP/k_go.pem"   # each signer, either member
    ${CLI[$s]} sign --algo hpks-ring --key "$key" --ring "$RING" --in "$TMP/msg.bin" \
        --rounds 4 --out "$TMP/r_$s.pem" 2>/dev/null || fail "hpks-ring sign ($s)"
done
for v in "${LANGS[@]}"; do
    for s in "${LANGS[@]}"; do
        accepts "hpks-ring $s->$v" ${CLI[$v]} verify --algo hpks-ring --ring "$RING" \
            --in "$TMP/msg.bin" --sig "$TMP/r_$s.pem" --min-rounds 4
    done
    rejects "hpks-ring changed message ($v)" ${CLI[$v]} verify --algo hpks-ring --ring "$RING" \
        --in "$TMP/msg2.bin" --sig "$TMP/r_c.pem" --min-rounds 4
done

# ── hpke-stern (the demo KEM) ─────────────────────────────────────────────────
${CLI[c]} genpkey --algo hpke-stern --level 128 --out "$TMP/e.pem" 2>/dev/null
${CLI[c]} pkey --in "$TMP/e.pem" --pubout --out "$TMP/e_pub.pem" 2>/dev/null
for s in "${LANGS[@]}"; do
    ${CLI[$s]} enc --algo hpke-stern --pubkey "$TMP/e_pub.pem" --in "$TMP/pt.bin" \
        --out "$TMP/ct_$s.pem" 2>/dev/null || fail "hpke-stern enc ($s)"
done
for v in "${LANGS[@]}"; do
    for s in "${LANGS[@]}"; do
        if ${CLI[$v]} dec --algo hpke-stern --key "$TMP/e.pem" --in "$TMP/ct_$s.pem" \
               --out "$TMP/d.bin" 2>/dev/null && cmp -s "$TMP/d.bin" "$TMP/pt.bin"; then
            pass "hpke-stern $s->$v"
        else fail "hpke-stern $s->$v: plaintext differs"; fi
    done
done
head -c 33 /dev/urandom > "$TMP/pt33.bin"
for s in "${LANGS[@]}"; do
    if ${CLI[$s]} enc --algo hpke-stern --pubkey "$TMP/e_pub.pem" --in "$TMP/pt33.bin" \
           --out "$TMP/x.pem" >/dev/null 2>&1; then
        fail "hpke-stern accepted a 33-byte plaintext ($s): the block is 32 bytes at N = $N"
    else pass "hpke-stern refuses a 33-byte plaintext ($s)"; fi
done

# ── hcred: a long-form issuer ─────────────────────────────────────────────────
${CLI[c]} genpkey --algo hcred --out "$TMP/hc.pem" 2>/dev/null
${CLI[c]} pkey --in "$TMP/hc.pem" --pubout --out "$TMP/hc_pub.pem" 2>/dev/null
${CLI[c]} cred-prove --in "$TMP/hc.pem" --msg nonce --rounds 4 --out "$TMP/proof.pem" 2>/dev/null
for s in "${LANGS[@]}"; do
    ${CLI[$s]} cred-issue --our "$TMP/k_c.pem" --in "$TMP/hc_pub.pem" --rounds 4 \
        --out "$TMP/cred_$s.pem" 2>/dev/null || fail "cred-issue ($s)"
done
for v in "${LANGS[@]}"; do
    for s in "${LANGS[@]}"; do
        accepts "hcred credential $s->$v" ${CLI[$v]} cred-verify --proof "$TMP/proof.pem" \
            --pubkey "$TMP/hc_pub.pem" --msg nonce --min-rounds 4 \
            --cred "$TMP/cred_$s.pem" --issuer "$TMP/k_c_pub.pem"
    done
    rejects "hcred credential, wrong issuer ($v)" ${CLI[$v]} cred-verify --proof "$TMP/proof.pem" \
        --pubkey "$TMP/hc_pub.pem" --msg nonce --min-rounds 4 \
        --cred "$TMP/cred_c.pem" --issuer "$TMP/k_go_pub.pem"
done

# ── Levels the table does not list ────────────────────────────────────────────
for s in "${LANGS[@]}"; do
    if ${CLI[$s]} genpkey --algo hcred --level 128 --out "$TMP/x.pem" >/dev/null 2>&1; then
        fail "genpkey --algo hcred --level 128 accepted ($s): hcred's own key has no 128-bit set"
    else pass "genpkey --algo hcred --level 128 refused ($s)"; fi
done

echo
echo "Results: $PASS PASS / $FAIL FAIL (languages: ${LANGS[*]})"
[ "$FAIL" -eq 0 ]
