#!/usr/bin/env bash
# CliTest/test_c_encrypt.sh — C CLI: enc/dec round-trips for all encryption algorithms
set -euo pipefail

CLI="$(dirname "$0")/../HerraduraCli/herradura_cli"
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

# Reference plaintexts
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

# ── HPKE-Stern-F KEM (N=256) ─────────────────────────────────────────────────
"$CLI" genpkey --algo hpke-stern --out "$TMP/hpke_stern.pem"
"$CLI" pkey    --in "$TMP/hpke_stern.pem" --pubout --out "$TMP/hpke_stern_pub.pem"
"$CLI" enc --algo hpke-stern --pubkey "$TMP/hpke_stern_pub.pem" \
           --in "$TMP/msg32.bin" --out "$TMP/hpke_stern_ct.pem"
"$CLI" dec --algo hpke-stern --key "$TMP/hpke_stern.pem" \
           --in "$TMP/hpke_stern_ct.pem" --out "$TMP/hpke_stern_plain.bin"
check_roundtrip "hpke-stern enc/dec N=256" "$TMP/msg32.bin" "$TMP/hpke_stern_plain.bin"

echo ""
echo "Results: $PASS PASS / $FAIL FAIL"
[ "$FAIL" -eq 0 ]
