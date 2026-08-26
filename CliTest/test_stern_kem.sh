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
# Encapsulates, decapsulates, and compares against the plaintext. Since TODO
# #235 a DFR event is an output MISMATCH, not an error — decapsulation always
# exits 0 — so the retry is keyed on the comparison, and a mismatch surviving
# the budget is reported as a genuine failure. A nonzero exit is never a DFR
# event any more and fails immediately.
kem_roundtrip() {
    local label="$1" enc_cli="$2" pub="$3" dec_cli="$4" key="$5" tag="$6"
    local ct="$TMP/${tag}_ct.pem" out="$TMP/${tag}_dec.bin" err="$TMP/${tag}_err.log"
    local attempt=1
    while :; do
        $enc_cli enc --algo hpke-stern-kem --pubkey "$pub" \
                     --in "$TMP/msg.bin" --out "$ct"
        if ! $dec_cli dec --algo hpke-stern-kem --key "$key" \
                          --in "$ct" --out "$out" 2>"$err"; then
            echo "FAIL $label: dec exited nonzero: $(cat "$err")"
            FAIL=$((FAIL+1))
            return 0
        fi
        if cmp -s "$TMP/msg.bin" "$out"; then
            check "$label" "$TMP/msg.bin" "$out"
            return 0
        fi
        if dfr_retryable "$attempt"; then
            dfr_report_retry "$label" "$attempt"
            attempt=$((attempt+1))
            continue
        fi
        check "$label" "$TMP/msg.bin" "$out"   # report the mismatch honestly
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

# ── TODO #235 Part 1: the weak-key screen ─────────────────────────────────────
# Every key each CLI emits must have distance-spectrum multiplicity <= 5 in both
# private polynomials. TODO #218 §4 puts the DFR cliff between 6 and 7, and
# honest unscreened keygen reaches 6 at ~1 key in 4800 — rare enough that this
# check would not have caught the gap by sampling, which is exactly why it reads
# the emitted key rather than counting rejections.
CHECK_MULT="$(dirname "$0")/../HerraduraCli"
screen_check() {
    local label="$1" pem="$2"
    local mult
    mult=$(cd "$CHECK_MULT" && python3 -c '
import sys
sys.argv = ["x"]
import importlib.util
spec = importlib.util.spec_from_file_location("hcli", "herradura.py")
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
sup0, sup1, _, _ = m._decode_kem_privkey(sys.argv[1] if False else "'"$pem"'")
def mm(sup, r=523):
    c = {}
    sl = sorted(sup)
    for i in range(len(sl)):
        for j in range(i + 1, len(sl)):
            d = (sl[j] - sl[i]) % r
            d = min(d, r - d)
            c[d] = c.get(d, 0) + 1
    return max(c.values())
print(max(mm(sup0), mm(sup1)))
')
    if [ "$mult" -le 5 ]; then
        echo "PASS $label (max spectrum multiplicity $mult <= 5)"
        PASS=$((PASS+1))
    else
        echo "FAIL $label (max spectrum multiplicity $mult > 5 — weak-key screen not applied)"
        FAIL=$((FAIL+1))
    fi
}
screen_check "weak-key screen: Python keygen" "$TMP/py_priv.pem"
screen_check "weak-key screen: C keygen"      "$TMP/c_priv.pem"
if $GO_AVAILABLE; then
    screen_check "weak-key screen: Go keygen" "$TMP/go_priv.pem"
fi

# ── TODO #235 Part 2: implicit rejection ──────────────────────────────────────
# A corrupt ciphertext must NOT be reported. Before #235 decapsulation exited
# nonzero with a distinct message, and that signal was the GJS reaction oracle
# (TODO #218 §5, §6). It must now decapsulate to a pseudorandom key: exit 0,
# wrong plaintext, and — because the key is a function of (private key,
# ciphertext) and nothing else — the SAME wrong plaintext every time, under
# every CLI, and a DIFFERENT one under a different private key.
# The adversarial input is a WELL-FORMED ciphertext that this key cannot decode:
# an honest encapsulation to somebody else's public key. Corrupting the PEM
# instead would only exercise the DER/base64 reader, whose rejection is a
# separate and legitimate one (TODO #239/#240) and not the GJS oracle.
$CLI_PY genpkey --algo hpke-stern-kem --out "$TMP/ir_other_priv.pem"
$CLI_PY pkey --in "$TMP/ir_other_priv.pem" --pubout --out "$TMP/ir_other_pub.pem"
$CLI_PY enc --algo hpke-stern-kem --pubkey "$TMP/ir_other_pub.pem" \
            --in "$TMP/msg.bin" --out "$TMP/ir_ct_bad.pem"

ir_rc=0
$CLI_PY dec --algo hpke-stern-kem --key "$TMP/py_priv.pem" \
            --in "$TMP/ir_ct_bad.pem" --out "$TMP/ir_py.bin" 2>/dev/null || ir_rc=$?
if [ "$ir_rc" -eq 0 ]; then
    echo "PASS corrupt ciphertext is not reported (implicit rejection)"
    PASS=$((PASS+1))
else
    echo "FAIL corrupt ciphertext is not reported (implicit rejection): rc=$ir_rc — the GJS oracle is back"
    FAIL=$((FAIL+1))
fi

if cmp -s "$TMP/msg.bin" "$TMP/ir_py.bin"; then
    echo "FAIL corrupt ciphertext does not recover the plaintext"
    FAIL=$((FAIL+1))
else
    echo "PASS corrupt ciphertext does not recover the plaintext"
    PASS=$((PASS+1))
fi

# Deterministic: the rejection key is a PRF of (private key, ciphertext).
$CLI_PY dec --algo hpke-stern-kem --key "$TMP/py_priv.pem" \
            --in "$TMP/ir_ct_bad.pem" --out "$TMP/ir_py2.bin" 2>/dev/null
if cmp -s "$TMP/ir_py.bin" "$TMP/ir_py2.bin"; then
    echo "PASS implicit-rejection key is deterministic in (key, ciphertext)"
    PASS=$((PASS+1))
else
    echo "FAIL implicit-rejection key is deterministic in (key, ciphertext)"
    FAIL=$((FAIL+1))
fi

# Key-dependent: a different private key must give a different rejection key,
# or z is not secret and the transform buys nothing.
$CLI_PY dec --algo hpke-stern-kem --key "$TMP/c_priv.pem" \
            --in "$TMP/ir_ct_bad.pem" --out "$TMP/ir_other.bin" 2>/dev/null
if cmp -s "$TMP/ir_py.bin" "$TMP/ir_other.bin"; then
    echo "FAIL implicit-rejection key depends on the private key"
    FAIL=$((FAIL+1))
else
    echo "PASS implicit-rejection key depends on the private key"
    PASS=$((PASS+1))
fi

# Cross-language: every CLI must derive the SAME rejection key. This is a wire
# contract like any other — a ciphertext one CLI implicitly rejects must not be
# one another accepts, and the derived secret must match either way.
ir_cross() {
    local label="$1" cli="$2" out="$3"
    $cli dec --algo hpke-stern-kem --key "$TMP/py_priv.pem" \
             --in "$TMP/ir_ct_bad.pem" --out "$out" 2>/dev/null
    if cmp -s "$TMP/ir_py.bin" "$out"; then
        echo "PASS $label"
        PASS=$((PASS+1))
    else
        echo "FAIL $label"
        FAIL=$((FAIL+1))
    fi
}
ir_cross "implicit-rejection key agrees: Python vs C" "$CLI_C" "$TMP/ir_c.bin"
if $GO_AVAILABLE; then
    ir_cross "implicit-rejection key agrees: Python vs Go" "$CLI_GO" "$TMP/ir_go.bin"
fi

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo "Results: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
