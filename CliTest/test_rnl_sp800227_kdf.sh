#!/usr/bin/env bash
# CliTest/test_rnl_sp800227_kdf.sh — TODO #165: HKEX-RNL's --kdf sp800227 context binding.
#
# Verifies: (1) Alice and Bob derive the same session key with --kdf sp800227, matching
# test_vectors.sh's plain-hkex-rnl style via a cross-party encrypt/decrypt round-trip;
# (2) mismatched --kdf flags between the two parties produce different (not matching)
# session keys, since sp800227 is opt-in and not silently compatible with the default;
# (3) --kdf sp800227 is rejected on --algo hkex-gf, where it isn't defined.
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

check_fail() {
    local label="$1"; shift
    local output rc
    output=$("$@" 2>&1) && rc=0 || rc=$?
    if [ "$rc" -ne 0 ]; then
        echo "PASS $label (rejected as expected)"
        PASS=$((PASS+1))
    else
        echo "FAIL $label: expected rejection but got rc=0; output: $output"
        FAIL=$((FAIL+1))
    fi
}

printf 'SP800227-KDF-TEST-32-BYTE-MSG!!!' > "$TMP/msg.bin"

$CLI genpkey --algo hkex-rnl --out "$TMP/alice.pem"
$CLI pkey    --pubout --in "$TMP/alice.pem" --out "$TMP/alice_pub.pem"
$CLI genpkey --algo hkex-rnl --out "$TMP/bob.pem"

# ── Both sides use --kdf sp800227: must agree ───────────────────────────────
$CLI kex --algo hkex-rnl --kdf sp800227 --our "$TMP/bob.pem" \
         --their "$TMP/alice_pub.pem" --out "$TMP/response.pem"
$CLI kex --algo hkex-rnl --kdf sp800227 --our "$TMP/alice.pem" \
         --their "$TMP/response.pem" --out "$TMP/alice_session.pem"

$CLI enc --algo hske --key "$TMP/response.pem" \
         --in "$TMP/msg.bin" --out "$TMP/ct_bob.pem"
$CLI dec --algo hske --key "$TMP/alice_session.pem" \
         --in "$TMP/ct_bob.pem" --out "$TMP/pt_alice.bin"
if cmp -s "$TMP/msg.bin" "$TMP/pt_alice.bin"; then
    check "sp800227 key agreement (Bob enc / Alice dec)" "ok"
else
    check "sp800227 key agreement (Bob enc / Alice dec)" "plaintext mismatch"
fi

$CLI enc --algo hske --key "$TMP/alice_session.pem" \
         --in "$TMP/msg.bin" --out "$TMP/ct_alice.pem"
$CLI dec --algo hske --key "$TMP/response.pem" \
         --in "$TMP/ct_alice.pem" --out "$TMP/pt_bob.bin"
if cmp -s "$TMP/msg.bin" "$TMP/pt_bob.bin"; then
    check "sp800227 key agreement (Alice enc / Bob dec)" "ok"
else
    check "sp800227 key agreement (Alice enc / Bob dec)" "plaintext mismatch"
fi

# ── Mismatched --kdf flags must NOT silently agree ──────────────────────────
$CLI genpkey --algo hkex-rnl --out "$TMP/bob2.pem"
$CLI kex --algo hkex-rnl --kdf sp800227 --our "$TMP/bob2.pem" \
         --their "$TMP/alice_pub.pem" --out "$TMP/response2.pem"
$CLI kex --algo hkex-rnl --our "$TMP/alice.pem" \
         --their "$TMP/response2.pem" --out "$TMP/alice_session2.pem"
# Bob used sp800227 (embeds a differently-derived K in his own response PEM); Alice
# completed with the default (--kdf none) — the two derived keys must differ.
$CLI enc --algo hske --key "$TMP/alice_session2.pem" \
         --in "$TMP/msg.bin" --out "$TMP/ct_mismatch.pem"
if $CLI dec --algo hske --key "$TMP/response2.pem" \
            --in "$TMP/ct_mismatch.pem" --out "$TMP/pt_mismatch.bin" 2>/dev/null \
   && cmp -s "$TMP/msg.bin" "$TMP/pt_mismatch.bin"; then
    check "mismatched --kdf flags must not agree" "keys matched despite mismatched --kdf — binding is not opt-in-safe"
else
    check "mismatched --kdf flags must not agree" "ok"
fi

# ── --kdf sp800227 is undefined for hkex-gf ─────────────────────────────────
$CLI genpkey --algo hkex-gf --out "$TMP/gf.pem"
check_fail "sp800227 rejected on hkex-gf" \
    $CLI kex --algo hkex-gf --kdf sp800227 --our "$TMP/gf.pem" \
             --their "$TMP/gf.pem" --out "$TMP/unused.pem"

echo ""
echo "Results: $PASS PASS / $FAIL FAIL"
[ "$FAIL" -eq 0 ]
