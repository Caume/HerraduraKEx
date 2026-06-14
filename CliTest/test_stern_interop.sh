#!/usr/bin/env bash
# test_stern_interop.sh — 6-direction HPKS-Stern-F cross-language sign/verify matrix
# Tests all combinations: Python→Python, Python→C, Python→Go,
#                          C→C, C→Python, C→Go,
#                          Go→Go, Go→Python, Go→C
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$SCRIPT_DIR/.." && pwd)"
PY="$REPO/HerraduraCli/herradura.py"
C_CLI="$REPO/HerraduraCli/herradura_cli"
GO_CLI="$REPO/HerraduraCli/herradura_cli_go"
SUITE="$REPO/Herradura cryptographic suite.py"

pass=0; fail=0
PASS() { echo "PASS $*"; pass=$((pass+1)); }
FAIL() { echo "FAIL $*"; fail=$((fail+1)); }

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

echo "hello stern" > "$tmpdir/msg.txt"

# --------------------------------------------------------------------------
# Generate one key per implementation
# --------------------------------------------------------------------------
python3 "$PY" genpkey --algo hpks-stern --out "$tmpdir/py_priv.pem" 2>/dev/null
python3 "$PY" pkey    --in "$tmpdir/py_priv.pem" --pubout --out "$tmpdir/py_pub.pem" 2>/dev/null

"$C_CLI" genpkey --algo hpks-stern --out "$tmpdir/c_priv.pem"
"$C_CLI" pkey    --algo hpks-stern --in "$tmpdir/c_priv.pem" --pubout --out "$tmpdir/c_pub.pem"

"$GO_CLI" genpkey --algo hpks-stern --out "$tmpdir/go_priv.pem" 2>/dev/null
"$GO_CLI" pkey    -in "$tmpdir/go_priv.pem" -pubout -out "$tmpdir/go_pub.pem"

# --------------------------------------------------------------------------
# Sign with each implementation
# --------------------------------------------------------------------------
python3 "$PY" sign  --algo hpks-stern --key "$tmpdir/py_priv.pem" \
    --in "$tmpdir/msg.txt" --out "$tmpdir/sig_py.pem" 2>/dev/null

"$C_CLI" sign --algo hpks-stern --key "$tmpdir/c_priv.pem" \
    --in "$tmpdir/msg.txt" --out "$tmpdir/sig_c.pem"

"$GO_CLI" sign --algo hpks-stern --key "$tmpdir/go_priv.pem" \
    --in "$tmpdir/msg.txt" --out "$tmpdir/sig_go.pem" 2>/dev/null

# --------------------------------------------------------------------------
# Verify: all 9 combinations (signer → verifier)
# --------------------------------------------------------------------------
verify_py()  { python3 "$PY" verify --algo hpks-stern --pubkey "$1" --in "$tmpdir/msg.txt" --sig "$2" 2>/dev/null | grep -q "Signature OK"; }
verify_c()   { "$C_CLI"   verify --algo hpks-stern --pubkey "$1" --in "$tmpdir/msg.txt" --sig "$2" | grep -q "Signature OK"; }
verify_go()  { "$GO_CLI"  verify --algo hpks-stern --pubkey "$1" --in "$tmpdir/msg.txt" --sig "$2" 2>/dev/null | grep -q "Signature OK"; }

for signer in py c go; do
    pub="$tmpdir/${signer}_pub.pem"
    sig="$tmpdir/sig_${signer}.pem"
    for verifier in py c go; do
        label="${signer}→${verifier} hpks-stern"
        case "$verifier" in
            py) verify_py "$pub" "$sig" && PASS "$label" || FAIL "$label" ;;
            c)  verify_c  "$pub" "$sig" && PASS "$label" || FAIL "$label" ;;
            go) verify_go "$pub" "$sig" && PASS "$label" || FAIL "$label" ;;
        esac
    done
done

echo ""
echo "Results: $pass PASS / $fail FAIL"
[ "$fail" -eq 0 ]
