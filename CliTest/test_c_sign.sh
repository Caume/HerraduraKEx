#!/usr/bin/env bash
# CliTest/test_c_sign.sh — C CLI: sign/verify pass and reject cases (hpks, hpks-nl, hpks-stern)
set -euo pipefail

CLI="$(dirname "$0")/../HerraduraCli/herradura_cli"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
PASS=0; FAIL=0

check_verify() {
    local label="$1"; shift
    local output rc
    output=$("$@" 2>&1) && rc=0 || rc=$?
    if [ "$rc" -eq 0 ] && echo "$output" | grep -q "Signature OK"; then
        echo "PASS $label"
        PASS=$((PASS+1))
    else
        echo "FAIL $label: expected 'Signature OK' (rc=$rc); got: $output"
        FAIL=$((FAIL+1))
    fi
}

check_reject() {
    local label="$1"; shift
    local output rc
    output=$("$@" 2>&1) && rc=0 || rc=$?
    if [ "$rc" -ne 0 ] && echo "$output" | grep -q "Verification FAILED"; then
        echo "PASS $label"
        PASS=$((PASS+1))
    else
        echo "FAIL $label: expected rejection (rc=$rc); got: $output"
        FAIL=$((FAIL+1))
    fi
}

printf 'ABCDEFGHIJKLMNOPQRSTUVWXYZ012345' > "$TMP/msg32.bin"
printf 'ABCDEFGHIJKLMNOPQRSTUVWXYZ012346' > "$TMP/msg32b.bin"

# ── HPKS and HPKS-NL (Schnorr over GF(2^256)*) ──────────────────────────────
for algo in hpks hpks-nl; do
    "$CLI" genpkey --algo "$algo" --out "$TMP/${algo}.pem"
    "$CLI" pkey    --in "$TMP/${algo}.pem" --pubout --out "$TMP/${algo}_pub.pem"
    "$CLI" sign    --algo "$algo" --key "$TMP/${algo}.pem" \
                   --in "$TMP/msg32.bin" --out "$TMP/${algo}_sig.pem"

    check_verify "verify $algo correct msg" \
        "$CLI" verify --algo "$algo" --pubkey "$TMP/${algo}_pub.pem" \
        --in "$TMP/msg32.bin" --sig "$TMP/${algo}_sig.pem"

    check_reject "verify $algo wrong msg" \
        "$CLI" verify --algo "$algo" --pubkey "$TMP/${algo}_pub.pem" \
        --in "$TMP/msg32b.bin" --sig "$TMP/${algo}_sig.pem"
done

# Cross-key rejection
"$CLI" genpkey --algo hpks --out "$TMP/hpks_other.pem"
"$CLI" pkey    --in "$TMP/hpks_other.pem" --pubout --out "$TMP/hpks_other_pub.pem"
check_reject "verify hpks wrong key" \
    "$CLI" verify --algo hpks --pubkey "$TMP/hpks_other_pub.pem" \
    --in "$TMP/msg32.bin" --sig "$TMP/hpks_sig.pem"

# ── HPKS-Stern-F (N=256, rounds=32) ─────────────────────────────────────────
"$CLI" genpkey --algo hpks-stern --out "$TMP/hpks_stern.pem"
"$CLI" pkey    --in "$TMP/hpks_stern.pem" --pubout --out "$TMP/hpks_stern_pub.pem"
"$CLI" sign    --algo hpks-stern --key "$TMP/hpks_stern.pem" \
               --in "$TMP/msg32.bin" --out "$TMP/hpks_stern_sig.pem"

check_verify "verify hpks-stern correct msg N=256" \
    "$CLI" verify --algo hpks-stern --pubkey "$TMP/hpks_stern_pub.pem" \
    --in "$TMP/msg32.bin" --sig "$TMP/hpks_stern_sig.pem"

check_reject "verify hpks-stern wrong msg N=256" \
    "$CLI" verify --algo hpks-stern --pubkey "$TMP/hpks_stern_pub.pem" \
    --in "$TMP/msg32b.bin" --sig "$TMP/hpks_stern_sig.pem"

# ── HPKS-Stern-F at round counts other than the build's SDF_ROUNDS (TODO #236) ─
# The round count is a per-signature wire field, not a compile-time constant.
# Until v3.1.0 the C reader compared it against SDF_ROUNDS and rejected any
# mismatch, so a stock build (SDF_ROUNDS=32) could neither produce nor consume
# the 219 rounds needed for 128-bit Fiat-Shamir soundness.  These cases must
# pass against a stock ./build_c.sh binary.
for r in 64 219; do
    "$CLI" sign --algo hpks-stern --rounds "$r" --key "$TMP/hpks_stern.pem" \
                --in "$TMP/msg32.bin" --out "$TMP/stern_r$r.pem" 2>/dev/null

    check_verify "hpks-stern round-trip at --rounds $r (SDF_ROUNDS is 32)" \
        "$CLI" verify --algo hpks-stern --pubkey "$TMP/hpks_stern_pub.pem" \
        --in "$TMP/msg32.bin" --sig "$TMP/stern_r$r.pem"

    check_reject "hpks-stern wrong msg at --rounds $r" \
        "$CLI" verify --algo hpks-stern --pubkey "$TMP/hpks_stern_pub.pem" \
        --in "$TMP/msg32b.bin" --sig "$TMP/stern_r$r.pem"
done

# A signature at one round count must not verify as another: re-signing the same
# message at 64 and at 219 must give distinct, non-interchangeable artifacts.
if cmp -s "$TMP/stern_r64.pem" "$TMP/stern_r219.pem"; then
    echo "FAIL hpks-stern r=64 and r=219 signatures are byte-identical"
    FAIL=$((FAIL+1))
else
    echo "PASS hpks-stern r=64 and r=219 produce distinct signatures"
    PASS=$((PASS+1))
fi

# --rounds is bounded on the way in; an out-of-range value is refused rather
# than reaching malloc.
check_fails() {
    local label="$1"; shift
    local output rc
    output=$("$@" 2>&1) && rc=0 || rc=$?
    if [ "$rc" -ne 0 ]; then
        echo "PASS $label"
        PASS=$((PASS+1))
    else
        echo "FAIL $label: expected non-zero exit; got: $output"
        FAIL=$((FAIL+1))
    fi
}

for bad in 0 4097; do
    check_fails "hpks-stern sign refuses --rounds $bad" \
        "$CLI" sign --algo hpks-stern --rounds "$bad" \
        --key "$TMP/hpks_stern.pem" --in "$TMP/msg32.bin" --out "$TMP/nope.pem"
done

# A PEM whose declared round count is out of range must be refused by the
# reader, not acted on.  Rewrite item[1] of the DER SEQUENCE to 32767.
python3 - "$TMP" <<'PYTAMPER'
import base64, sys
tmp = sys.argv[1]
raw = open(tmp + "/stern_r219.pem").read()
der = bytearray(base64.b64decode(
    "".join(l for l in raw.splitlines() if "-----" not in l)))
i = der.find(bytes([0x02, 0x02, 0x00, 0xDB]))     # INTEGER 219
if i < 0:
    sys.exit("could not locate the rounds INTEGER in the test signature")
der[i+2:i+4] = bytes([0x7F, 0xFF])                # claim 32767 rounds
b64 = base64.b64encode(bytes(der)).decode()
open(tmp + "/stern_tampered.pem", "w").write(
    "-----BEGIN HERRADURA SIGNATURE-----\n"
    + "\n".join(b64[j:j+64] for j in range(0, len(b64), 64))
    + "\n-----END HERRADURA SIGNATURE-----\n")
PYTAMPER

check_fails "hpks-stern verify refuses an out-of-range round count in the PEM" \
    "$CLI" verify --algo hpks-stern --pubkey "$TMP/hpks_stern_pub.pem" \
    --in "$TMP/msg32.bin" --sig "$TMP/stern_tampered.pem"

echo ""
echo "Results: $PASS PASS / $FAIL FAIL"
[ "$FAIL" -eq 0 ]
