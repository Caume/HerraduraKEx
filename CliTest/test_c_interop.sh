#!/usr/bin/env bash
# CliTest/test_c_interop.sh — C↔Python interop smoke tests: encfile and sign/verify
set -euo pipefail

CLI_C="$(dirname "$0")/../HerraduraCli/herradura_cli"
CLI_PY="python3 $(dirname "$0")/../HerraduraCli/herradura.py"
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

# ── Shared key via C HKEX-GF ─────────────────────────────────────────────────
"$CLI_C" genpkey --algo hkex-gf --out "$TMP/alice.pem"
"$CLI_C" pkey    --in "$TMP/alice.pem" --pubout --out "$TMP/alice_pub.pem"
"$CLI_C" genpkey --algo hkex-gf --out "$TMP/bob.pem"
"$CLI_C" pkey    --in "$TMP/bob.pem"   --pubout --out "$TMP/bob_pub.pem"
"$CLI_C" kex     --algo hkex-gf --our "$TMP/alice.pem" --their "$TMP/bob_pub.pem" \
                 --out "$TMP/sk.pem"

dd if=/dev/urandom of="$TMP/plain.bin" count=32 bs=512 2>/dev/null

# ── C encfile → Python decfile ────────────────────────────────────────────────
"$CLI_C" encfile --algo hske-nla1 --key "$TMP/sk.pem" \
                 --in "$TMP/plain.bin" --out "$TMP/c2py.hkx"
$CLI_PY decfile --algo hske-nla1 --key "$TMP/sk.pem" \
                --in "$TMP/c2py.hkx" --out "$TMP/c2py_out.bin"
check_roundtrip "C encfile → Python decfile" "$TMP/plain.bin" "$TMP/c2py_out.bin"

# ── Python encfile → C decfile ────────────────────────────────────────────────
$CLI_PY encfile --algo hske-nla1 --key "$TMP/sk.pem" \
                --in "$TMP/plain.bin" --out "$TMP/py2c.hkx"
"$CLI_C" decfile --algo hske-nla1 --key "$TMP/sk.pem" \
                 --in "$TMP/py2c.hkx" --out "$TMP/py2c_out.bin"
check_roundtrip "Python encfile → C decfile" "$TMP/plain.bin" "$TMP/py2c_out.bin"

# ── C sign → Python verify (hpks) ────────────────────────────────────────────
printf 'ABCDEFGHIJKLMNOPQRSTUVWXYZ012345' > "$TMP/msg.bin"
"$CLI_C" genpkey --algo hpks --out "$TMP/hpks.pem"
"$CLI_C" pkey    --in "$TMP/hpks.pem" --pubout --out "$TMP/hpks_pub.pem"
"$CLI_C" sign    --algo hpks --key "$TMP/hpks.pem" \
                 --in "$TMP/msg.bin" --out "$TMP/hpks_sig.pem"
check_verify "C sign → Python verify (hpks)" \
    $CLI_PY verify --algo hpks --pubkey "$TMP/hpks_pub.pem" \
    --in "$TMP/msg.bin" --sig "$TMP/hpks_sig.pem"

# ── Python sign → C verify (hpks) ────────────────────────────────────────────
$CLI_PY genpkey --algo hpks --out "$TMP/hpks_py.pem"
$CLI_PY pkey    --in "$TMP/hpks_py.pem" --pubout --out "$TMP/hpks_py_pub.pem"
$CLI_PY sign    --algo hpks --key "$TMP/hpks_py.pem" \
                --in "$TMP/msg.bin" --out "$TMP/hpks_py_sig.pem"
check_verify "Python sign → C verify (hpks)" \
    "$CLI_C" verify --algo hpks --pubkey "$TMP/hpks_py_pub.pem" \
    --in "$TMP/msg.bin" --sig "$TMP/hpks_py_sig.pem"

echo ""
echo "Results: $PASS PASS / $FAIL FAIL"
[ "$FAIL" -eq 0 ]
