#!/usr/bin/env bash
# CliTest/test_hybrid_kex.sh — TODO #162: hybrid HKEX-RNL + HPKE-Stern-KEM combiner.
#
# Verifies: (1) Alice and Bob derive the same combined session key via cross-party
# encrypt/decrypt round-trips, matching test_vectors.sh's hkex-rnl style; (2) a wrong
# HPKE-Stern-KEM private key on Alice's side causes a clean decapsulation-failure
# rejection rather than a silently-wrong session key; (3) two independent runs produce
# different session keys (freshness — no accidental determinism).
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

printf 'HYBRIDKEX-TEST-MESSAGE-32-BYTES!' > "$TMP/msg.bin"

# ── Key generation ─────────────────────────────────────────────────────────
$CLI genpkey --algo hkex-rnl      --out "$TMP/alice_rnl.pem"
$CLI pkey    --pubout --in "$TMP/alice_rnl.pem" --out "$TMP/alice_rnl_pub.pem"
$CLI genpkey --algo hpke-stern-kem --out "$TMP/alice_kem.pem"
$CLI pkey    --pubout --in "$TMP/alice_kem.pem" --out "$TMP/alice_kem_pub.pem"
$CLI genpkey --algo hkex-rnl      --out "$TMP/bob_rnl.pem"

# ── Bob encapsulates, Alice decapsulates — DFR-retry aware (TODO #221) ─────
# Alice's completion runs the QC-MDPC BGF decoder, which has a measured ~0.225%
# failure rate per encapsulation. Since TODO #235 that failure is silent —
# implicit rejection means Alice's completion always exits 0 and simply derives a
# session key Bob disagrees with — so the retry is keyed on the key-agreement
# round-trip below rather than on an error message, and Bob's step is redone for
# a fresh encapsulation. A mismatch surviving the budget falls through and is
# reported honestly.
. "$(dirname "$0")/lib_dfr.sh"
attempt=1
while :; do
    $CLI kex --algo hybrid-rnl-stern --our "$TMP/bob_rnl.pem" \
             --their "$TMP/alice_rnl_pub.pem" --their-kem "$TMP/alice_kem_pub.pem" \
             --out "$TMP/response.pem"

    $CLI kex --algo hybrid-rnl-stern --our "$TMP/alice_rnl.pem" --our-kem "$TMP/alice_kem.pem" \
             --their "$TMP/response.pem" --out "$TMP/alice_session.pem"

    # Bob encrypts under his session key, Alice decrypts under hers: this is the
    # only observable that still distinguishes agreement from a DFR event.
    $CLI enc --algo hske --key "$TMP/response.pem" \
             --in "$TMP/msg.bin" --out "$TMP/ct_bob.pem"
    $CLI dec --algo hske --key "$TMP/alice_session.pem" \
             --in "$TMP/ct_bob.pem" --out "$TMP/pt_alice.bin"
    cmp -s "$TMP/msg.bin" "$TMP/pt_alice.bin" && break

    if dfr_retryable "$attempt"; then
        dfr_report_retry "hybrid-rnl-stern alice completes" "$attempt"
        attempt=$((attempt+1))
        continue
    fi
    break   # budget exhausted — the check below reports the mismatch
done

# ── Cross-party encrypt/decrypt round-trips prove K_alice == K_bob ─────────
if cmp -s "$TMP/msg.bin" "$TMP/pt_alice.bin"; then
    check "hybrid-rnl-stern key agreement (Bob enc / Alice dec)" "ok"
else
    check "hybrid-rnl-stern key agreement (Bob enc / Alice dec)" "plaintext mismatch"
fi

$CLI enc --algo hske --key "$TMP/alice_session.pem" \
         --in "$TMP/msg.bin" --out "$TMP/ct_alice.pem"
$CLI dec --algo hske --key "$TMP/response.pem" \
         --in "$TMP/ct_alice.pem" --out "$TMP/pt_bob.bin"
if cmp -s "$TMP/msg.bin" "$TMP/pt_bob.bin"; then
    check "hybrid-rnl-stern key agreement (Alice enc / Bob dec)" "ok"
else
    check "hybrid-rnl-stern key agreement (Alice enc / Bob dec)" "plaintext mismatch"
fi

# ── Missing required flags are rejected cleanly ─────────────────────────────
check_fail "missing --their-kem on Bob's step" \
    $CLI kex --algo hybrid-rnl-stern --our "$TMP/bob_rnl.pem" \
             --their "$TMP/alice_rnl_pub.pem" --out "$TMP/unused1.pem"

check_fail "missing --our-kem on Alice's step" \
    $CLI kex --algo hybrid-rnl-stern --our "$TMP/alice_rnl.pem" \
             --their "$TMP/response.pem" --out "$TMP/unused2.pem"

# ── Wrong HPKE-Stern-KEM private key → a silently different session key ──────
# Before TODO #235 this asserted a clean rejection. That rejection WAS the GJS
# reaction oracle (TODO #218 §5, §6): it told the caller whether decapsulation
# had succeeded. Under implicit rejection the completion must instead succeed
# and derive a key that simply does not agree with Bob's — indistinguishable
# from a DFR event, which is the point. The assertion is therefore inverted:
# exit 0, and a session key that differs from the legitimate one.
$CLI genpkey --algo hpke-stern-kem --out "$TMP/eve_kem.pem"
if $CLI kex --algo hybrid-rnl-stern --our "$TMP/alice_rnl.pem" --our-kem "$TMP/eve_kem.pem" \
            --their "$TMP/response.pem" --out "$TMP/eve_session.pem" 2>/dev/null; then
    check "wrong --our-kem (Eve's KEM key) is not reported" "ok"
else
    check "wrong --our-kem (Eve's KEM key) is not reported" \
          "decapsulation reported a failure — the GJS oracle is back"
fi
if cmp -s "$TMP/alice_session.pem" "$TMP/eve_session.pem"; then
    check "wrong --our-kem yields a different session key" "keys agree — the KEM half is not binding"
else
    check "wrong --our-kem yields a different session key" "ok"
fi

# ── Freshness: two independent runs must not produce the same session key ──
$CLI genpkey --algo hkex-rnl      --out "$TMP/bob_rnl2.pem"
$CLI kex --algo hybrid-rnl-stern --our "$TMP/bob_rnl2.pem" \
         --their "$TMP/alice_rnl_pub.pem" --their-kem "$TMP/alice_kem_pub.pem" \
         --out "$TMP/response2.pem"
if cmp -s "$TMP/response.pem" "$TMP/response2.pem"; then
    check "freshness across independent runs" "response PEMs are identical — not fresh"
else
    check "freshness across independent runs" "ok"
fi

echo ""
echo "Results: $PASS PASS / $FAIL FAIL"
[ "$FAIL" -eq 0 ]
