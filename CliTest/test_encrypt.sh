#!/usr/bin/env bash
# CliTest/test_encrypt.sh — enc/dec round-trips for all Herradura encryption algorithms
set -euo pipefail

CLI="python3 $(dirname "$0")/../HerraduraCli/herradura.py"
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

# Reference plaintexts sized to match each block width
printf 'ABCDEFGHIJKLMNOPQRSTUVWXYZ012345' > "$TMP/msg32.bin"  # 32 bytes (256-bit block)
printf 'TESTMSG!' > "$TMP/msg8.bin"                            # 8 bytes (64-bit block)
printf 'Test' > "$TMP/msg4.bin"                                # 4 bytes (32-bit block)

# ---------------------------------------------------------------------------
# HKEX-GF key exchange → symmetric enc/dec (hske, hske-nla1, hske-nla2)
# ---------------------------------------------------------------------------

$CLI genpkey --algo hkex-gf --out "$TMP/alice_gf.pem"
$CLI pkey    --in "$TMP/alice_gf.pem" --pubout --out "$TMP/alice_gf_pub.pem"
$CLI genpkey --algo hkex-gf --out "$TMP/bob_gf.pem"
$CLI pkey    --in "$TMP/bob_gf.pem"   --pubout --out "$TMP/bob_gf_pub.pem"
$CLI kex     --algo hkex-gf --our "$TMP/alice_gf.pem" --their "$TMP/bob_gf_pub.pem" \
             --out "$TMP/sk_gf.pem"

for algo in hske hske-nla1 hske-nla2; do
    $CLI enc --algo "$algo" --key "$TMP/sk_gf.pem" \
             --in "$TMP/msg32.bin" --out "$TMP/${algo}_ct.pem"
    $CLI dec --algo "$algo" --key "$TMP/sk_gf.pem" \
             --in "$TMP/${algo}_ct.pem" --out "$TMP/${algo}_plain.bin"
    check_roundtrip "$algo enc/dec" "$TMP/msg32.bin" "$TMP/${algo}_plain.bin"
done

# ---------------------------------------------------------------------------
# HKEX-RNL 2-round kex (n=64) — Bob responds, Alice completes; cross-party enc/dec
# ---------------------------------------------------------------------------

$CLI genpkey --algo hkex-rnl --bits 64 --out "$TMP/alice_rnl.pem"
$CLI pkey    --in "$TMP/alice_rnl.pem" --pubout --out "$TMP/alice_rnl_pub.pem"
$CLI genpkey --algo hkex-rnl --bits 64 --out "$TMP/bob_rnl.pem"

# Step 1: Bob responds to Alice's public key (writes RESPONSE PEM containing K_B)
$CLI kex --algo hkex-rnl --our "$TMP/bob_rnl.pem" --their "$TMP/alice_rnl_pub.pem" \
         --out "$TMP/bob_rnl_resp.pem"
# Step 2: Alice completes (writes SESSION KEY PEM containing K_A)
$CLI kex --algo hkex-rnl --our "$TMP/alice_rnl.pem" --their "$TMP/bob_rnl_resp.pem" \
         --out "$TMP/alice_rnl_sk.pem"

# Bob encrypts with K_B (RESPONSE PEM); Alice decrypts with K_A (SESSION KEY PEM).
# If K_A = K_B the round-trip succeeds, validating the reconciliation property.
$CLI enc --algo hske --key "$TMP/bob_rnl_resp.pem" \
         --in "$TMP/msg8.bin" --out "$TMP/hkex_rnl_ct.pem"
$CLI dec --algo hske --key "$TMP/alice_rnl_sk.pem" \
         --in "$TMP/hkex_rnl_ct.pem" --out "$TMP/hkex_rnl_plain.bin"
check_roundtrip "hkex-rnl kex + hske enc/dec (cross-party)" "$TMP/msg8.bin" "$TMP/hkex_rnl_plain.bin"

# ---------------------------------------------------------------------------
# Asymmetric HPKE / HPKE-NL
# ---------------------------------------------------------------------------

$CLI genpkey --algo hpke    --out "$TMP/alice_hpke.pem"
$CLI pkey    --in "$TMP/alice_hpke.pem" --pubout --out "$TMP/alice_hpke_pub.pem"
$CLI enc --algo hpke --pubkey "$TMP/alice_hpke_pub.pem" \
         --in "$TMP/msg32.bin" --out "$TMP/hpke_ct.pem"
$CLI dec --algo hpke --key "$TMP/alice_hpke.pem" \
         --in "$TMP/hpke_ct.pem" --out "$TMP/hpke_plain.bin"
check_roundtrip "hpke enc/dec" "$TMP/msg32.bin" "$TMP/hpke_plain.bin"

$CLI genpkey --algo hpke-nl --out "$TMP/alice_hpke_nl.pem"
$CLI pkey    --in "$TMP/alice_hpke_nl.pem" --pubout --out "$TMP/alice_hpke_nl_pub.pem"
$CLI enc --algo hpke-nl --pubkey "$TMP/alice_hpke_nl_pub.pem" \
         --in "$TMP/msg32.bin" --out "$TMP/hpke_nl_ct.pem"
$CLI dec --algo hpke-nl --key "$TMP/alice_hpke_nl.pem" \
         --in "$TMP/hpke_nl_ct.pem" --out "$TMP/hpke_nl_plain.bin"
check_roundtrip "hpke-nl enc/dec" "$TMP/msg32.bin" "$TMP/hpke_nl_plain.bin"

# ---------------------------------------------------------------------------
# HPKE-Stern-F KEM demo (n=32; block = 4 bytes)
# ---------------------------------------------------------------------------

$CLI genpkey --algo hpke-stern --bits 32 --out "$TMP/stern_hpke.pem"
$CLI pkey    --in "$TMP/stern_hpke.pem" --pubout --out "$TMP/stern_hpke_pub.pem"
$CLI enc --algo hpke-stern --pubkey "$TMP/stern_hpke_pub.pem" \
         --in "$TMP/msg4.bin" --out "$TMP/hpke_stern_ct.pem"
$CLI dec --algo hpke-stern --key "$TMP/stern_hpke.pem" \
         --in "$TMP/hpke_stern_ct.pem" --out "$TMP/hpke_stern_plain.bin"
check_roundtrip "hpke-stern enc/dec n=32" "$TMP/msg4.bin" "$TMP/hpke_stern_plain.bin"

echo ""
echo "Results: $PASS PASS / $FAIL FAIL"
[ "$FAIL" -eq 0 ]
