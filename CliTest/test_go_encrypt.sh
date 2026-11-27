#!/usr/bin/env bash
# CliTest/test_go_encrypt.sh — Go CLI: enc/dec round-trips for all encryption algorithms
set -euo pipefail

CLI="$(dirname "$0")/../HerraduraCli/herradura_cli_go"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
PASS=0; FAIL=0

check_roundtrip() {
    local label="$1" orig="$2" plain="$3"
    if cmp -s "$orig" "$plain"; then
        echo "PASS $label"
        PASS=$((PASS+1))
    else
        echo "FAIL $label: decrypted output does not match original"
        FAIL=$((FAIL+1))
    fi
}

# Reference plaintext
printf 'ABCDEFGHIJKLMNOPQRSTUVWXYZ012345' > "$TMP/msg32.bin"   # 32 bytes (256-bit)

# ── HKEX-GF kex → symmetric enc/dec (hske, hske-nla1, hske-nla2) ─────────────
"$CLI" genpkey --algo hkex-gf --out "$TMP/alice_gf.pem"
"$CLI" pkey    --in "$TMP/alice_gf.pem" --pubout --out "$TMP/alice_gf_pub.pem"
"$CLI" genpkey --algo hkex-gf --out "$TMP/bob_gf.pem"
"$CLI" pkey    --in "$TMP/bob_gf.pem"   --pubout --out "$TMP/bob_gf_pub.pem"
"$CLI" kex     --algo hkex-gf --our "$TMP/alice_gf.pem" --their "$TMP/bob_gf_pub.pem" \
               --out "$TMP/sk_gf.pem"

for algo in hske hske-nla1 hske-nla2; do
    "$CLI" enc --algo "$algo" --key "$TMP/sk_gf.pem" \
               --in "$TMP/msg32.bin" --out "$TMP/${algo}_ct.pem"
    "$CLI" dec --algo "$algo" --key "$TMP/sk_gf.pem" \
               --in "$TMP/${algo}_ct.pem" --out "$TMP/${algo}_plain.bin"
    check_roundtrip "$algo enc/dec" "$TMP/msg32.bin" "$TMP/${algo}_plain.bin"
done

# ── HKEX-RNL 2-round kex → hske enc/dec (cross-party) ───────────────────────
"$CLI" genpkey --algo hkex-rnl --out "$TMP/alice_rnl.pem"
"$CLI" pkey    --in "$TMP/alice_rnl.pem" --pubout --out "$TMP/alice_rnl_pub.pem"
"$CLI" genpkey --algo hkex-rnl --out "$TMP/bob_rnl.pem"
# Bob step 1: respond to Alice's public key
"$CLI" kex --algo hkex-rnl --our "$TMP/bob_rnl.pem" --their "$TMP/alice_rnl_pub.pem" \
           --out "$TMP/bob_rnl_resp.pem"
# Alice step 2: complete key exchange
"$CLI" kex --algo hkex-rnl --our "$TMP/alice_rnl.pem" --their "$TMP/bob_rnl_resp.pem" \
           --out "$TMP/alice_rnl_sk.pem"
# Cross-party: Bob encrypts with K_B; Alice decrypts with K_A (K_A == K_B iff kex succeeded)
"$CLI" enc --algo hske --key "$TMP/bob_rnl_resp.pem" \
           --in "$TMP/msg32.bin" --out "$TMP/hkex_rnl_ct.pem"
"$CLI" dec --algo hske --key "$TMP/alice_rnl_sk.pem" \
           --in "$TMP/hkex_rnl_ct.pem" --out "$TMP/hkex_rnl_plain.bin"
check_roundtrip "hkex-rnl kex + hske enc/dec (cross-party)" "$TMP/msg32.bin" "$TMP/hkex_rnl_plain.bin"

# ── Asymmetric HPKE / HPKE-NL ────────────────────────────────────────────────
for algo in hpke hpke-nl; do
    "$CLI" genpkey --algo "$algo" --out "$TMP/${algo}.pem"
    "$CLI" pkey    --in "$TMP/${algo}.pem" --pubout --out "$TMP/${algo}_pub.pem"
    "$CLI" enc --algo "$algo" --pubkey "$TMP/${algo}_pub.pem" \
               --in "$TMP/msg32.bin" --out "$TMP/${algo}_ct.pem"
    "$CLI" dec --algo "$algo" --key "$TMP/${algo}.pem" \
               --in "$TMP/${algo}_ct.pem" --out "$TMP/${algo}_plain.bin"
    check_roundtrip "$algo enc/dec" "$TMP/msg32.bin" "$TMP/${algo}_plain.bin"
done

# ── HPKE-Stern-F: enc/dec --algo hpke-stern are refused (TODO #413) ──────────
# Its ciphertext carried the error vector, so anyone holding it decrypted it.
# The hpke enc/dec round-trips above are the accept-control; the key itself
# still signs as a Stern key.
"$CLI" genpkey --algo hpke-stern --out "$TMP/hpke_stern.pem"
"$CLI" pkey    --in "$TMP/hpke_stern.pem" --pubout --out "$TMP/hpke_stern_pub.pem"
for sub in enc dec; do
    if [ $sub = enc ]; then kf=(--pubkey "$TMP/hpke_stern_pub.pem"); else kf=(--key "$TMP/hpke_stern.pem"); fi
    rm -f "$TMP/hpke_stern_out"
    if "$CLI" $sub --algo hpke-stern "${kf[@]}" --in "$TMP/msg32.bin" --out "$TMP/hpke_stern_out" \
            2>"$TMP/hpke_stern_err"; then
        echo "FAIL $sub --algo hpke-stern was accepted"; FAIL=$((FAIL+1))
    elif [ -e "$TMP/hpke_stern_out" ] || ! grep -q 'hpke-stern-kem' "$TMP/hpke_stern_err"; then
        echo "FAIL $sub --algo hpke-stern: refused without the pointer to hpke-stern-kem, or wrote output"
        FAIL=$((FAIL+1))
    else
        echo "PASS $sub --algo hpke-stern refused"; PASS=$((PASS+1))
    fi
done
"$CLI" sign --algo hpks-stern --rounds 2 --key "$TMP/hpke_stern.pem" --in "$TMP/msg32.bin" --out "$TMP/hpke_stern_sig.pem"
if "$CLI" verify --algo hpks-stern --min-rounds 2 --pubkey "$TMP/hpke_stern_pub.pem" \
        --in "$TMP/msg32.bin" --sig "$TMP/hpke_stern_sig.pem" >/dev/null 2>&1; then
    echo "PASS an hpke-stern key still signs"; PASS=$((PASS+1))
else
    echo "FAIL an hpke-stern key no longer signs"; FAIL=$((FAIL+1))
fi

echo ""
echo "Results: $PASS PASS / $FAIL FAIL"
[ "$FAIL" -eq 0 ]
