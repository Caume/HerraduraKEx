#!/usr/bin/env bash
# CliTest/test_vectors.sh — key-agreement correctness: both parties must derive matching secrets
set -euo pipefail

CLI="python3 $(dirname "$0")/../HerraduraCli/herradura.py"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
PASS=0; FAIL=0

check() {
    local label="$1" result="$2"
    if [ "$result" = "ok" ]; then
        echo "PASS $label"
        PASS=$((PASS+1))
    else
        echo "FAIL $label: $result"
        FAIL=$((FAIL+1))
    fi
}

# ---------------------------------------------------------------------------
# HKEX-GF — both parties must produce an identical SESSION KEY PEM
#
# g^{ab} = g^{ba} in GF(2^n)*, so both DER-encoded outputs must be equal.
# ---------------------------------------------------------------------------

$CLI genpkey --algo hkex-gf --out "$TMP/alice_gf.pem"
$CLI pkey    --in "$TMP/alice_gf.pem" --pubout --out "$TMP/alice_gf_pub.pem"
$CLI genpkey --algo hkex-gf --out "$TMP/bob_gf.pem"
$CLI pkey    --in "$TMP/bob_gf.pem"   --pubout --out "$TMP/bob_gf_pub.pem"

$CLI kex --algo hkex-gf --our "$TMP/alice_gf.pem" --their "$TMP/bob_gf_pub.pem" \
         --out "$TMP/alice_sk.pem"
$CLI kex --algo hkex-gf --our "$TMP/bob_gf.pem"   --their "$TMP/alice_gf_pub.pem" \
         --out "$TMP/bob_sk.pem"

if cmp -s "$TMP/alice_sk.pem" "$TMP/bob_sk.pem"; then
    check "hkex-gf key agreement" "ok"
else
    check "hkex-gf key agreement" "session key PEMs differ"
fi

# ---------------------------------------------------------------------------
# HKEX-RNL (n=64) — cross-party encryption must round-trip
#
# Bob encrypts with K_B (RESPONSE PEM); Alice decrypts with K_A (SESSION KEY PEM).
# Success proves K_A = K_B, validating the Peikert reconciliation property.
# ---------------------------------------------------------------------------

printf 'KEXTEST!' > "$TMP/msg8.bin"   # 8 bytes matches the n=64 block size

$CLI genpkey --algo hkex-rnl --bits 64 --out "$TMP/alice_rnl.pem"
$CLI pkey    --in "$TMP/alice_rnl.pem" --pubout --out "$TMP/alice_rnl_pub.pem"
$CLI genpkey --algo hkex-rnl --bits 64 --out "$TMP/bob_rnl.pem"

# Step 1 — Bob responds; RESPONSE PEM holds K_B, C_B, hint
$CLI kex --algo hkex-rnl --our "$TMP/bob_rnl.pem" --their "$TMP/alice_rnl_pub.pem" \
         --out "$TMP/bob_rnl_resp.pem"
# Step 2 — Alice completes; SESSION KEY PEM holds K_A
$CLI kex --algo hkex-rnl --our "$TMP/alice_rnl.pem" --their "$TMP/bob_rnl_resp.pem" \
         --out "$TMP/alice_rnl_sk.pem"

# Bob-side encrypt (K_B), Alice-side decrypt (K_A)
$CLI enc --algo hske --key "$TMP/bob_rnl_resp.pem" \
         --in "$TMP/msg8.bin" --out "$TMP/rnl_ct_bob.pem"
$CLI dec --algo hske --key "$TMP/alice_rnl_sk.pem" \
         --in "$TMP/rnl_ct_bob.pem" --out "$TMP/rnl_plain_alice.bin"

if cmp -s "$TMP/msg8.bin" "$TMP/rnl_plain_alice.bin"; then
    check "hkex-rnl key agreement (Bob enc / Alice dec)" "ok"
else
    check "hkex-rnl key agreement (Bob enc / Alice dec)" "plaintext mismatch — K_A ≠ K_B"
fi

# Alice-side encrypt (K_A), Bob-side decrypt (K_B)
$CLI enc --algo hske --key "$TMP/alice_rnl_sk.pem" \
         --in "$TMP/msg8.bin" --out "$TMP/rnl_ct_alice.pem"
$CLI dec --algo hske --key "$TMP/bob_rnl_resp.pem" \
         --in "$TMP/rnl_ct_alice.pem" --out "$TMP/rnl_plain_bob.bin"

if cmp -s "$TMP/msg8.bin" "$TMP/rnl_plain_bob.bin"; then
    check "hkex-rnl key agreement (Alice enc / Bob dec)" "ok"
else
    check "hkex-rnl key agreement (Alice enc / Bob dec)" "plaintext mismatch — K_A ≠ K_B"
fi

echo ""
echo "Results: $PASS PASS / $FAIL FAIL"
[ "$FAIL" -eq 0 ]
