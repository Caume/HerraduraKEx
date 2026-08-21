#!/usr/bin/env bash
# CliTest/test_stern_kem.sh — HPKE-Stern-KEM (QC-MDPC BGF) interop smoke tests
# Tests Python, C, and Go CLIs with cross-language key and ciphertext interop.
set -euo pipefail

CLI_C="$(dirname "$0")/../HerraduraCli/herradura_cli"
CLI_PY="python3 $(dirname "$0")/../HerraduraCli/herradura.py"
CLI_GO="$(dirname "$0")/../HerraduraCli/herradura_cli_go"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
PASS=0; FAIL=0

# 32-byte (256-bit block) plaintext — matches HSKE block size exactly
printf 'ABCDEFGHIJKLMNOPQRSTUVWXYZ012345' > "$TMP/msg.bin"

check() {
    local label="$1" orig="$2" plain="$3"
    if cmp -s "$orig" "$plain"; then
        echo "PASS $label"
        PASS=$((PASS+1))
    else
        echo "FAIL $label"
        FAIL=$((FAIL+1))
    fi
}

# ── DFR retry policy (TODO #221) ──────────────────────────────────────────────
# Every decapsulation below can hit the QC-MDPC BGF decoder's measured ~0.225%
# decoding failure rate. With 9 independent encapsulations in this script that is
# roughly a 2% chance of a spurious red run, which is what TODO #195's retry
# canary fixed for test_hybrid_kex_interop.sh but never reached here.
. "$(dirname "$0")/lib_dfr.sh"

# kem_roundtrip <label> <enc-cli> <recipient-pub> <dec-cli> <recipient-priv> <tag>
# Encapsulates, decapsulates, and compares against the plaintext. On the known
# DFR signature it retries with a *fresh* encapsulation; anything else, or an
# exhausted budget, is reported as a genuine failure with the CLI's own message.
kem_roundtrip() {
    local label="$1" enc_cli="$2" pub="$3" dec_cli="$4" key="$5" tag="$6"
    local ct="$TMP/${tag}_ct.pem" out="$TMP/${tag}_dec.bin" err="$TMP/${tag}_err.log"
    local attempt=1
    while :; do
        $enc_cli enc --algo hpke-stern-kem --pubkey "$pub" \
                     --in "$TMP/msg.bin" --out "$ct"
        if $dec_cli dec --algo hpke-stern-kem --key "$key" \
                        --in "$ct" --out "$out" 2>"$err"; then
            check "$label" "$TMP/msg.bin" "$out"
            return 0
        fi
        if dfr_is_event "$(cat "$err")" && [ "$attempt" -lt "$MAX_DFR_RETRIES" ]; then
            dfr_report_retry "$label" "$attempt"
            attempt=$((attempt+1))
            continue
        fi
        echo "FAIL $label: $(cat "$err")"
        FAIL=$((FAIL+1))
        return 0
    done
}

# ── Keygen for each CLI ───────────────────────────────────────────────────────
$CLI_PY genpkey --algo hpke-stern-kem --out "$TMP/py_priv.pem"
$CLI_PY pkey    --in "$TMP/py_priv.pem" --pubout --out "$TMP/py_pub.pem"

"$CLI_C" genpkey --algo hpke-stern-kem --out "$TMP/c_priv.pem"
"$CLI_C" pkey    --in "$TMP/c_priv.pem"  --pubout --out "$TMP/c_pub.pem"

GO_AVAILABLE=false
if [ -x "$CLI_GO" ] && "$CLI_GO" genpkey --algo hpke-stern-kem --out "$TMP/go_priv.pem" 2>/dev/null; then
    GO_AVAILABLE=true
    "$CLI_GO" pkey --in "$TMP/go_priv.pem" --pubout --out "$TMP/go_pub.pem"
fi

# ── Python self-round-trip ────────────────────────────────────────────────────
kem_roundtrip "Python → Python" "$CLI_PY" "$TMP/py_pub.pem" "$CLI_PY" "$TMP/py_priv.pem" py_py

# ── C self-round-trip ─────────────────────────────────────────────────────────
kem_roundtrip "C → C" "$CLI_C" "$TMP/c_pub.pem" "$CLI_C" "$TMP/c_priv.pem" c_c

# ── Python enc → C dec ────────────────────────────────────────────────────────
kem_roundtrip "Python enc → C dec" "$CLI_PY" "$TMP/c_pub.pem" "$CLI_C" "$TMP/c_priv.pem" py_c

# ── C enc → Python dec ────────────────────────────────────────────────────────
kem_roundtrip "C enc → Python dec" "$CLI_C" "$TMP/py_pub.pem" "$CLI_PY" "$TMP/py_priv.pem" c_py

# ── Go interop (if built) ─────────────────────────────────────────────────────
if [ "$GO_AVAILABLE" = true ]; then
    # Go self
    kem_roundtrip "Go → Go" "$CLI_GO" "$TMP/go_pub.pem" "$CLI_GO" "$TMP/go_priv.pem" go_go

    # Python enc → Go dec
    kem_roundtrip "Python enc → Go dec" "$CLI_PY" "$TMP/go_pub.pem" "$CLI_GO" "$TMP/go_priv.pem" py_go

    # Go enc → Python dec
    kem_roundtrip "Go enc → Python dec" "$CLI_GO" "$TMP/py_pub.pem" "$CLI_PY" "$TMP/py_priv.pem" go_py

    # C enc → Go dec
    kem_roundtrip "C enc → Go dec" "$CLI_C" "$TMP/go_pub.pem" "$CLI_GO" "$TMP/go_priv.pem" c_go

    # Go enc → C dec
    kem_roundtrip "Go enc → C dec" "$CLI_GO" "$TMP/c_pub.pem" "$CLI_C" "$TMP/c_priv.pem" go_c
fi

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo "Results: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
