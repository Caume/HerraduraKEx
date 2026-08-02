#!/usr/bin/env bash
# CliTest/test_encrypted_pem.sh — TODO #166: passphrase-encrypted private-key PEM export.
#
# Verifies: (1) genpkey --passphrase produces a distinctly-labeled encrypted PEM;
# (2) using it directly (without decrypting) fails cleanly with a helpful message rather
# than a crash or silent misinterpretation; (3) pkey --decrypt with the correct
# passphrase recovers the byte-for-byte original cleartext PEM, which then works
# normally with pkey --pubout; (4) a wrong passphrase is rejected cleanly, not a crash
# or silently-wrong output; (5) the encrypted PEM round-trips for a non-trivial key
# (hkex-rnl, larger DER payload than hkex-gf).
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

PASSPHRASE="correct horse battery staple"

# ── Basic encrypt / decrypt round-trip (hkex-gf) ────────────────────────────
$CLI genpkey --algo hkex-gf --passphrase "$PASSPHRASE" --out "$TMP/enc_gf.pem"

if head -1 "$TMP/enc_gf.pem" | grep -q 'BEGIN HERRADURA ENCRYPTED PRIVATE KEY'; then
    check "encrypted PEM has distinct label" "ok"
else
    check "encrypted PEM has distinct label" "unexpected label: $(head -1 "$TMP/enc_gf.pem")"
fi

check_fail "direct use of encrypted PEM without --decrypt" \
    $CLI pkey --pubout --in "$TMP/enc_gf.pem" --out "$TMP/unused.pem"

$CLI pkey --decrypt --in "$TMP/enc_gf.pem" --passphrase "$PASSPHRASE" --out "$TMP/plain_gf.pem"
$CLI genpkey --algo hkex-gf --out "$TMP/plain_gf_direct.pem"   # cleartext reference for label check
if head -1 "$TMP/plain_gf.pem" | grep -q 'BEGIN HERRADURA HKEX-GF PRIVATE KEY'; then
    check "decrypted PEM has original cleartext label" "ok"
else
    check "decrypted PEM has original cleartext label" "unexpected label: $(head -1 "$TMP/plain_gf.pem")"
fi

# Decrypted key must work normally with any other subcommand.
$CLI pkey --pubout --in "$TMP/plain_gf.pem" --out "$TMP/pub_gf.pem"
if [ -s "$TMP/pub_gf.pem" ] && head -1 "$TMP/pub_gf.pem" | grep -q 'BEGIN HERRADURA HKEX-GF PUBLIC KEY'; then
    check "decrypted key usable with pkey --pubout" "ok"
else
    check "decrypted key usable with pkey --pubout" "pubout did not produce a valid public key PEM"
fi

# ── Wrong passphrase is rejected cleanly ────────────────────────────────────
check_fail "wrong passphrase rejected" \
    $CLI pkey --decrypt --in "$TMP/enc_gf.pem" --passphrase "wrong password entirely" \
             --out "$TMP/unused2.pem"

# ── Round-trip for a larger key (hkex-rnl) ──────────────────────────────────
$CLI genpkey --algo hkex-rnl --passphrase "$PASSPHRASE" --out "$TMP/enc_rnl.pem"
$CLI pkey --decrypt --in "$TMP/enc_rnl.pem" --passphrase "$PASSPHRASE" --out "$TMP/plain_rnl.pem"
$CLI pkey --pubout --in "$TMP/plain_rnl.pem" --out "$TMP/pub_rnl.pem"
if [ -s "$TMP/pub_rnl.pem" ]; then
    check "hkex-rnl encrypted key round-trip" "ok"
else
    check "hkex-rnl encrypted key round-trip" "pubout produced empty output"
fi

# ── Cleartext genpkey (no --passphrase) is unaffected ───────────────────────
$CLI genpkey --algo hkex-gf --out "$TMP/plain_default.pem"
if head -1 "$TMP/plain_default.pem" | grep -q 'BEGIN HERRADURA HKEX-GF PRIVATE KEY'; then
    check "default genpkey (no --passphrase) still produces cleartext PEM" "ok"
else
    check "default genpkey (no --passphrase) still produces cleartext PEM" "unexpected label"
fi

echo ""
echo "Results: $PASS PASS / $FAIL FAIL"
[ "$FAIL" -eq 0 ]
