#!/usr/bin/env bash
# CliTest/test_weak_key_rejection.sh — TODO #141: hand-craft PEM files whose
# public-key field is the GF(2^n)* identity (1) or zero (0), feed them to
# `kex`/`enc`/`verify`, and assert a clean non-zero exit rather than a crash
# or a false "Signature OK" / successful encryption.
set -euo pipefail

CLI="$(dirname "$0")/../HerraduraCli/herradura_cli"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
PASS=0; FAIL=0

pass() { echo "PASS $1"; PASS=$((PASS+1)); }
fail() { echo "FAIL $1"; FAIL=$((FAIL+1)); }

# Rewrite the first DER INTEGER inside a PEM block's body to $1 (0 or 1),
# keeping the rest of the SEQUENCE (e.g. the trailing n field) intact.
craft_degenerate_pub() {
    local in_pem="$1" out_pem="$2" value="$3"
    python3 - "$in_pem" "$out_pem" "$value" <<'PYEOF'
import sys, base64

in_path, out_path, value = sys.argv[1], sys.argv[2], int(sys.argv[3])

with open(in_path) as f:
    text = f.read()
lines = text.strip().splitlines()
label = lines[0][11:-5]
body = base64.b64decode(''.join(lines[1:-1]))

# body: 0x30 len [0x02 len bytes...] ...  -- patch the first INTEGER's value.
assert body[0] == 0x30
# Locate first nested INTEGER (tag 0x02) and its length.
i = 2 if body[1] < 0x80 else 2 + (body[1] & 0x7f)
assert body[i] == 0x02
lb = body[i + 1]
if lb < 0x80:
    hdr_len = 2
else:
    n_bytes = lb & 0x7f
    hdr_len = 2 + n_bytes
    lb = int.from_bytes(body[i + 2:i + 2 + n_bytes], 'big')
old_int_end = i + hdr_len + lb

new_int = bytes([0x02, 1, value])
# Rebuild: everything before the integer, the new integer, everything after.
seq_start = 2 if body[1] < 0x80 else 2 + (body[1] & 0x7f)
new_body = body[seq_start:i] + new_int + body[old_int_end:]

def encode_length(n):
    if n < 0x80:
        return bytes([n])
    elif n < 0x100:
        return bytes([0x81, n])
    else:
        return bytes([0x82, n >> 8, n & 0xff])

new_der = b'\x30' + encode_length(len(new_body)) + new_body
b64 = base64.encodebytes(new_der).decode('ascii').strip()
with open(out_path, 'w') as f:
    f.write(f"-----BEGIN {label}-----\n{b64}\n-----END {label}-----\n")
PYEOF
}

# ── HKEX-GF: kex with a degenerate peer public key ──
"$CLI" genpkey --algo hkex-gf --out "$TMP/alice.pem"
"$CLI" genpkey --algo hkex-gf --out "$TMP/bob.pem"
"$CLI" pkey --in "$TMP/bob.pem" --pubout --out "$TMP/bob_pub.pem"
for v in 0 1; do
    craft_degenerate_pub "$TMP/bob_pub.pem" "$TMP/bob_pub_bad_$v.pem" "$v"
    if "$CLI" kex --algo hkex-gf --our "$TMP/alice.pem" --their "$TMP/bob_pub_bad_$v.pem" \
        --out "$TMP/shared_bad_$v.pem" 2>"$TMP/kex_err_$v.txt"; then
        fail "kex hkex-gf rejects degenerate peer pub ($v): CLI exited 0"
    else
        pass "kex hkex-gf rejects degenerate peer pub ($v)"
    fi
done

# ── HPKE: enc with a degenerate recipient public key ──
"$CLI" genpkey --algo hpke --out "$TMP/carol.pem"
"$CLI" pkey --in "$TMP/carol.pem" --pubout --out "$TMP/carol_pub.pem"
echo "secret message" > "$TMP/msg.txt"
for v in 0 1; do
    craft_degenerate_pub "$TMP/carol_pub.pem" "$TMP/carol_pub_bad_$v.pem" "$v"
    if "$CLI" enc --algo hpke --pubkey "$TMP/carol_pub_bad_$v.pem" --in "$TMP/msg.txt" \
        --out "$TMP/ct_bad_$v.pem" 2>"$TMP/enc_err_$v.txt"; then
        fail "enc hpke rejects degenerate recipient pub ($v): CLI exited 0"
    else
        pass "enc hpke rejects degenerate recipient pub ($v)"
    fi
done

# ── HPKS: verify against a degenerate signer public key ──
"$CLI" genpkey --algo hpks --out "$TMP/dave.pem"
"$CLI" pkey --in "$TMP/dave.pem" --pubout --out "$TMP/dave_pub.pem"
echo "sign me" > "$TMP/smsg.txt"
"$CLI" sign --algo hpks --key "$TMP/dave.pem" --in "$TMP/smsg.txt" --out "$TMP/sig.pem"
for v in 0 1; do
    craft_degenerate_pub "$TMP/dave_pub.pem" "$TMP/dave_pub_bad_$v.pem" "$v"
    if out=$("$CLI" verify --algo hpks --pubkey "$TMP/dave_pub_bad_$v.pem" --in "$TMP/smsg.txt" \
        --sig "$TMP/sig.pem" 2>"$TMP/verify_err_$v.txt"); then
        fail "verify hpks rejects degenerate signer pub ($v): CLI exited 0 (output: $out)"
    elif [ "$out" = "Signature OK" ]; then
        fail "verify hpks rejects degenerate signer pub ($v): reported Signature OK"
    else
        pass "verify hpks rejects degenerate signer pub ($v)"
    fi
done

echo ""
echo "Results: $PASS PASS / $FAIL FAIL"
[ "$FAIL" -eq 0 ]
