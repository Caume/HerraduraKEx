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
$CLI_PY enc --algo hpke-stern-kem --pubkey "$TMP/py_pub.pem" \
             --in "$TMP/msg.bin" --out "$TMP/py_py_ct.pem"
$CLI_PY dec --algo hpke-stern-kem --key "$TMP/py_priv.pem" \
             --in "$TMP/py_py_ct.pem" --out "$TMP/py_py_dec.bin"
check "Python → Python" "$TMP/msg.bin" "$TMP/py_py_dec.bin"

# ── C self-round-trip ─────────────────────────────────────────────────────────
"$CLI_C" enc --algo hpke-stern-kem --pubkey "$TMP/c_pub.pem" \
              --in "$TMP/msg.bin" --out "$TMP/c_c_ct.pem"
"$CLI_C" dec --algo hpke-stern-kem --key "$TMP/c_priv.pem" \
              --in "$TMP/c_c_ct.pem" --out "$TMP/c_c_dec.bin"
check "C → C" "$TMP/msg.bin" "$TMP/c_c_dec.bin"

# ── Python enc → C dec ────────────────────────────────────────────────────────
$CLI_PY enc --algo hpke-stern-kem --pubkey "$TMP/c_pub.pem" \
             --in "$TMP/msg.bin" --out "$TMP/py_c_ct.pem"
"$CLI_C" dec --algo hpke-stern-kem --key "$TMP/c_priv.pem" \
              --in "$TMP/py_c_ct.pem" --out "$TMP/py_c_dec.bin"
check "Python enc → C dec" "$TMP/msg.bin" "$TMP/py_c_dec.bin"

# ── C enc → Python dec ────────────────────────────────────────────────────────
"$CLI_C" enc --algo hpke-stern-kem --pubkey "$TMP/py_pub.pem" \
              --in "$TMP/msg.bin" --out "$TMP/c_py_ct.pem"
$CLI_PY dec --algo hpke-stern-kem --key "$TMP/py_priv.pem" \
             --in "$TMP/c_py_ct.pem" --out "$TMP/c_py_dec.bin"
check "C enc → Python dec" "$TMP/msg.bin" "$TMP/c_py_dec.bin"

# ── Go interop (if built) ─────────────────────────────────────────────────────
if [ "$GO_AVAILABLE" = true ]; then
    # Go self
    "$CLI_GO" enc --algo hpke-stern-kem --pubkey "$TMP/go_pub.pem" \
                  --in "$TMP/msg.bin" --out "$TMP/go_go_ct.pem"
    "$CLI_GO" dec --algo hpke-stern-kem --key "$TMP/go_priv.pem" \
                  --in "$TMP/go_go_ct.pem" --out "$TMP/go_go_dec.bin"
    check "Go → Go" "$TMP/msg.bin" "$TMP/go_go_dec.bin"

    # Python enc → Go dec
    $CLI_PY enc --algo hpke-stern-kem --pubkey "$TMP/go_pub.pem" \
                 --in "$TMP/msg.bin" --out "$TMP/py_go_ct.pem"
    "$CLI_GO" dec --algo hpke-stern-kem --key "$TMP/go_priv.pem" \
                  --in "$TMP/py_go_ct.pem" --out "$TMP/py_go_dec.bin"
    check "Python enc → Go dec" "$TMP/msg.bin" "$TMP/py_go_dec.bin"

    # Go enc → Python dec
    "$CLI_GO" enc --algo hpke-stern-kem --pubkey "$TMP/py_pub.pem" \
                  --in "$TMP/msg.bin" --out "$TMP/go_py_ct.pem"
    $CLI_PY dec --algo hpke-stern-kem --key "$TMP/py_priv.pem" \
                 --in "$TMP/go_py_ct.pem" --out "$TMP/go_py_dec.bin"
    check "Go enc → Python dec" "$TMP/msg.bin" "$TMP/go_py_dec.bin"

    # C enc → Go dec
    "$CLI_C" enc --algo hpke-stern-kem --pubkey "$TMP/go_pub.pem" \
                  --in "$TMP/msg.bin" --out "$TMP/c_go_ct.pem"
    "$CLI_GO" dec --algo hpke-stern-kem --key "$TMP/go_priv.pem" \
                  --in "$TMP/c_go_ct.pem" --out "$TMP/c_go_dec.bin"
    check "C enc → Go dec" "$TMP/msg.bin" "$TMP/c_go_dec.bin"

    # Go enc → C dec
    "$CLI_GO" enc --algo hpke-stern-kem --pubkey "$TMP/c_pub.pem" \
                  --in "$TMP/msg.bin" --out "$TMP/go_c_ct.pem"
    "$CLI_C" dec --algo hpke-stern-kem --key "$TMP/c_priv.pem" \
                 --in "$TMP/go_c_ct.pem" --out "$TMP/go_c_dec.bin"
    check "Go enc → C dec" "$TMP/msg.bin" "$TMP/go_c_dec.bin"
fi

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo "Results: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
