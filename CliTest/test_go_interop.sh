#!/usr/bin/env bash
# CliTest/test_go_interop.sh — Go↔Python and Go↔C interop: encfile, sign/verify, dgst
set -euo pipefail

CLI_GO="$(dirname "$0")/../HerraduraCli/herradura_cli_go"
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

check_dgst() {
    local label="$1" a="$2" b="$3"
    if [ "$a" = "$b" ]; then
        echo "PASS $label"
        PASS=$((PASS+1))
    else
        echo "FAIL $label: dgst mismatch"
        echo "  got:      $a"
        echo "  expected: $b"
        FAIL=$((FAIL+1))
    fi
}

# ── Shared session key via Go HKEX-GF ────────────────────────────────────────
"$CLI_GO" genpkey --algo hkex-gf --out "$TMP/alice.pem"
"$CLI_GO" pkey    --in "$TMP/alice.pem" --pubout --out "$TMP/alice_pub.pem"
"$CLI_GO" genpkey --algo hkex-gf --out "$TMP/bob.pem"
"$CLI_GO" pkey    --in "$TMP/bob.pem"   --pubout --out "$TMP/bob_pub.pem"
"$CLI_GO" kex     --algo hkex-gf --our "$TMP/alice.pem" --their "$TMP/bob_pub.pem" \
                  --out "$TMP/sk.pem"

dd if=/dev/urandom of="$TMP/plain.bin" count=32 bs=512 2>/dev/null
printf 'ABCDEFGHIJKLMNOPQRSTUVWXYZ012345' > "$TMP/msg.bin"

# ── Go encfile → Python decfile ───────────────────────────────────────────────
"$CLI_GO" encfile --algo hske-nla1 --key "$TMP/sk.pem" \
                  --in "$TMP/plain.bin" --out "$TMP/go2py.hkx"
$CLI_PY decfile --algo hske-nla1 --key "$TMP/sk.pem" \
                --in "$TMP/go2py.hkx" --out "$TMP/go2py_out.bin"
check_roundtrip "Go encfile → Python decfile" "$TMP/plain.bin" "$TMP/go2py_out.bin"

# ── Python encfile → Go decfile ───────────────────────────────────────────────
$CLI_PY encfile --algo hske-nla1 --key "$TMP/sk.pem" \
                --in "$TMP/plain.bin" --out "$TMP/py2go.hkx"
"$CLI_GO" decfile --algo hske-nla1 --key "$TMP/sk.pem" \
                  --in "$TMP/py2go.hkx" --out "$TMP/py2go_out.bin"
check_roundtrip "Python encfile → Go decfile" "$TMP/plain.bin" "$TMP/py2go_out.bin"

# ── Go encfile → C decfile ────────────────────────────────────────────────────
"$CLI_GO" encfile --algo hske-nla1 --key "$TMP/sk.pem" \
                  --in "$TMP/plain.bin" --out "$TMP/go2c.hkx"
"$CLI_C" decfile --algo hske-nla1 --key "$TMP/sk.pem" \
                 --in "$TMP/go2c.hkx" --out "$TMP/go2c_out.bin"
check_roundtrip "Go encfile → C decfile" "$TMP/plain.bin" "$TMP/go2c_out.bin"

# ── C encfile → Go decfile ────────────────────────────────────────────────────
"$CLI_C" encfile --algo hske-nla1 --key "$TMP/sk.pem" \
                 --in "$TMP/plain.bin" --out "$TMP/c2go.hkx"
"$CLI_GO" decfile --algo hske-nla1 --key "$TMP/sk.pem" \
                  --in "$TMP/c2go.hkx" --out "$TMP/c2go_out.bin"
check_roundtrip "C encfile → Go decfile" "$TMP/plain.bin" "$TMP/c2go_out.bin"

# ── Go sign → Python verify (hpks) ───────────────────────────────────────────
"$CLI_GO" genpkey --algo hpks --out "$TMP/hpks.pem"
"$CLI_GO" pkey    --in "$TMP/hpks.pem" --pubout --out "$TMP/hpks_pub.pem"
"$CLI_GO" sign    --algo hpks --key "$TMP/hpks.pem" \
                  --in "$TMP/msg.bin" --out "$TMP/hpks_sig.pem"
check_verify "Go sign → Python verify (hpks)" \
    $CLI_PY verify --algo hpks --pubkey "$TMP/hpks_pub.pem" \
    --in "$TMP/msg.bin" --sig "$TMP/hpks_sig.pem"

# ── Python sign → Go verify (hpks) ───────────────────────────────────────────
$CLI_PY genpkey --algo hpks --out "$TMP/hpks_py.pem"
$CLI_PY pkey    --in "$TMP/hpks_py.pem" --pubout --out "$TMP/hpks_py_pub.pem"
$CLI_PY sign    --algo hpks --key "$TMP/hpks_py.pem" \
                --in "$TMP/msg.bin" --out "$TMP/hpks_py_sig.pem"
check_verify "Python sign → Go verify (hpks)" \
    "$CLI_GO" verify --algo hpks --pubkey "$TMP/hpks_py_pub.pem" \
    --in "$TMP/msg.bin" --sig "$TMP/hpks_py_sig.pem"

# ── Go sign → C verify (hpks) ────────────────────────────────────────────────
check_verify "Go sign → C verify (hpks)" \
    "$CLI_C" verify --algo hpks --pubkey "$TMP/hpks_pub.pem" \
    --in "$TMP/msg.bin" --sig "$TMP/hpks_sig.pem"

# ── C sign → Go verify (hpks) ────────────────────────────────────────────────
"$CLI_C" genpkey --algo hpks --out "$TMP/hpks_c.pem"
"$CLI_C" pkey    --in "$TMP/hpks_c.pem" --pubout --out "$TMP/hpks_c_pub.pem"
"$CLI_C" sign    --algo hpks --key "$TMP/hpks_c.pem" \
                 --in "$TMP/msg.bin" --out "$TMP/hpks_c_sig.pem"
check_verify "C sign → Go verify (hpks)" \
    "$CLI_GO" verify --algo hpks --pubkey "$TMP/hpks_c_pub.pem" \
    --in "$TMP/msg.bin" --sig "$TMP/hpks_c_sig.pem"

# ── dgst output agreement (hfscx-256, Go vs Python vs C) ─────────────────────
dgst_go=$("$CLI_GO" dgst --algo hfscx-256 --in "$TMP/msg.bin")
dgst_py=$($CLI_PY   dgst --algo hfscx-256 --in "$TMP/msg.bin")
dgst_c=$( "$CLI_C"  dgst --algo hfscx-256 --in "$TMP/msg.bin")
check_dgst "dgst Go vs Python (hfscx-256)" "$dgst_go" "$dgst_py"
check_dgst "dgst Go vs C (hfscx-256)"      "$dgst_go" "$dgst_c"

echo ""
echo "Results: $PASS PASS / $FAIL FAIL"
[ "$FAIL" -eq 0 ]
