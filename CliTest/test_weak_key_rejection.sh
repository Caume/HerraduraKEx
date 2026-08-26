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

# ═════════════════════════════════════════════════════════════════════════════
# TODO #239 — PEM length/count fields that size an allocation must be bounded
# before they are used.  Each case below rewrites one INTEGER item of an
# otherwise-genuine PEM to a value the reader used to trust.
# ═════════════════════════════════════════════════════════════════════════════

HCODEC_DIR="$(cd "$(dirname "$0")/../HerraduraCli" && pwd)"
export HCODEC_DIR

# Rewrite item $3 of a DER SEQUENCE PEM to the integer $4.
craft_item() {
    python3 - "$1" "$2" "$3" "$4" <<'PYEOF'
import os, sys
sys.path.insert(0, os.environ['HCODEC_DIR'])
from codec import der_int, der_seq, pem_wrap, pem_unwrap, der_parse_seq

in_path, out_path, idx, value = sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4])
label, der = pem_unwrap(open(in_path).read())
items = list(der_parse_seq(der))
items[idx] = value
open(out_path, 'w').write(pem_wrap(label, der_seq(*[der_int(x) for x in items])))
PYEOF
}

# ── HPKS-RING: signature-declared k / rounds / payload length ──
"$CLI" genpkey --algo hpks-stern --out "$TMP/rm1.pem" 2>/dev/null
"$CLI" genpkey --algo hpks-stern --out "$TMP/rm2.pem" 2>/dev/null
"$CLI" pkey --algo hpks-stern --in "$TMP/rm1.pem" --pubout --out "$TMP/rm1_pub.pem" 2>/dev/null
"$CLI" pkey --algo hpks-stern --in "$TMP/rm2.pem" --pubout --out "$TMP/rm2_pub.pem" 2>/dev/null
RING="$TMP/rm1_pub.pem,$TMP/rm2_pub.pem"
echo "ring message" > "$TMP/rmsg.txt"
"$CLI" sign --algo hpks-ring --key "$TMP/rm1.pem" --ring "$RING" \
    --in "$TMP/rmsg.txt" --out "$TMP/rsig.pem" 2>/dev/null

# Control: the untouched signature must still verify.
if out=$("$CLI" verify --algo hpks-ring --pubkey "$TMP/rm1_pub.pem" --ring "$RING" \
         --in "$TMP/rmsg.txt" --sig "$TMP/rsig.pem" 2>&1) && [ "$out" = "Signature OK" ]; then
    pass "verify hpks-ring accepts the genuine signature"
else
    fail "verify hpks-ring accepts the genuine signature: got '$out'"
fi

# item 0 = k, item 1 = rounds, item 3 = the k*rounds entry blob.
#   k / rounds unbounded drove `blen = k * rounds * entry` and stern_ring_alloc.
#   A blob longer than (k, rounds) describe used to be silently truncated.
ring_reject() {   # <name> <item-index> <value>
    craft_item "$TMP/rsig.pem" "$TMP/rsig_bad.pem" "$2" "$3"
    if out=$("$CLI" verify --algo hpks-ring --pubkey "$TMP/rm1_pub.pem" --ring "$RING" \
             --in "$TMP/rmsg.txt" --sig "$TMP/rsig_bad.pem" 2>&1); then
        fail "verify hpks-ring rejects $1: CLI exited 0"
    elif [ "$out" = "Verification FAILED" ]; then
        fail "verify hpks-ring rejects $1: reached the verifier instead of being rejected"
    else
        pass "verify hpks-ring rejects $1"
    fi
}
ring_reject "k = 2^30"              0 1073741824
ring_reject "k = 2^31-1"            0 2147483647
ring_reject "k = 65 (> RING_MAX_K)" 0 65
ring_reject "rounds = 2^30"         1 1073741824
ring_reject "rounds = 0"            1 0
# Shrinking rounds leaves the payload longer than k*rounds describes.
ring_reject "payload longer than k*rounds"  1 1

# ── HPKE-Stern-KEM: private-key-declared QC-MDPC row weight d ──
# d sizes der_right_align()'s writes into QCMDPC_D*2-byte stack buffers, so an
# out-of-range value was a stack-buffer-overflow WRITE, not merely a big read.
"$CLI" genpkey --algo hpke-stern-kem --out "$TMP/kem.pem" 2>/dev/null
if "$CLI" pkey --algo hpke-stern-kem --in "$TMP/kem.pem" --pubout --out "$TMP/kem_pub.pem" 2>/dev/null; then
    pass "pkey hpke-stern-kem accepts the genuine private key"
else
    fail "pkey hpke-stern-kem accepts the genuine private key"
fi
for d in 16 2147483647; do
    craft_item "$TMP/kem.pem" "$TMP/kem_bad.pem" 5 "$d"
    if "$CLI" pkey --algo hpke-stern-kem --in "$TMP/kem_bad.pem" --pubout \
        --out "$TMP/kem_pub_bad.pem" 2>/dev/null; then
        fail "pkey hpke-stern-kem rejects row weight d=$d: CLI exited 0"
    else
        pass "pkey hpke-stern-kem rejects row weight d=$d"
    fi
done

# ── HPKS-XMSS: key-declared height and signature-declared depth ──
# h sizes `1 << h` leaves and the num_leaves*KEYBYTES allocation behind them;
# `1 << h` is undefined for h >= 32.
"$CLI" genpkey --algo hpks-xmss --xmss-height 2 --out "$TMP/x.pem" 2>/dev/null
"$CLI" pkey --algo hpks-xmss --in "$TMP/x.pem" --pubout --out "$TMP/x_pub.pem" 2>/dev/null
echo "xmss message" > "$TMP/xmsg.txt"
"$CLI" sign --algo hpks-xmss --key "$TMP/x.pem" --in "$TMP/xmsg.txt" --out "$TMP/xsig.pem" 2>/dev/null
for h in 0 31 2147483647; do
    craft_item "$TMP/x.pem" "$TMP/x_bad.pem" 1 "$h"
    if "$CLI" pkey --algo hpks-xmss --in "$TMP/x_bad.pem" --pubout \
        --out "$TMP/x_pub_bad.pem" 2>/dev/null; then
        fail "pkey hpks-xmss rejects height h=$h: CLI exited 0"
    else
        pass "pkey hpks-xmss rejects height h=$h"
    fi
    craft_item "$TMP/xsig.pem" "$TMP/xsig_bad.pem" 3 "$h"
    if out=$("$CLI" verify --algo hpks-xmss --pubkey "$TMP/x_pub.pem" \
             --in "$TMP/xmsg.txt" --sig "$TMP/xsig_bad.pem" 2>&1); then
        fail "verify hpks-xmss rejects signature depth=$h: CLI exited 0"
    elif [ "$out" = "Verification FAILED" ]; then
        fail "verify hpks-xmss rejects signature depth=$h: reached the verifier"
    else
        pass "verify hpks-xmss rejects signature depth=$h"
    fi
done

# ── HSKE-NL-V2-Duplex: ciphertext-declared length ──
# Item 2 is the declared ct length; it sizes two allocations, and a payload
# longer than it claims used to be truncated rather than rejected.
# The duplex takes a 256-bit symmetric key, produced by an HKEX-GF agreement.
"$CLI" genpkey --algo hkex-gf --out "$TMP/da.pem"
"$CLI" genpkey --algo hkex-gf --out "$TMP/db.pem"
"$CLI" pkey --in "$TMP/db.pem" --pubout --out "$TMP/db_pub.pem"
"$CLI" kex --algo hkex-gf --our "$TMP/da.pem" --their "$TMP/db_pub.pem" --out "$TMP/dk.pem"
printf 'duplex plaintext spanning several 16-byte rate blocks, well over 32 bytes' > "$TMP/dmsg.txt"
"$CLI" enc --algo hske-duplex --ad ctx --key "$TMP/dk.pem" \
    --in "$TMP/dmsg.txt" --out "$TMP/dct.pem" 2>/dev/null
if "$CLI" dec --algo hske-duplex --ad ctx --key "$TMP/dk.pem" \
    --in "$TMP/dct.pem" --out "$TMP/dpt.txt" 2>/dev/null; then
    pass "dec hske-duplex accepts the genuine ciphertext"
else
    fail "dec hske-duplex accepts the genuine ciphertext"
fi
for n in 1 4294967296; do
    craft_item "$TMP/dct.pem" "$TMP/dct_bad.pem" 2 "$n"
    if "$CLI" dec --algo hske-duplex --ad ctx --key "$TMP/dk.pem" \
        --in "$TMP/dct_bad.pem" --out "$TMP/dpt_bad.txt" 2>/dev/null; then
        fail "dec hske-duplex rejects declared ct length $n: CLI exited 0"
    else
        pass "dec hske-duplex rejects declared ct length $n"
    fi
done

echo ""
echo "Results: $PASS PASS / $FAIL FAIL"
[ "$FAIL" -eq 0 ]
