#!/usr/bin/env bash
# CliTest/test_zkp_hybrid_family.sh — TODO #261: the five algo tags the Java CLI
# was missing until v6.0.0, exercised as a full FOUR-WAY matrix.
#
#   hpks-zkp-nl        genpkey/pkey        C, Go, Python, Java
#   nl-zkboo           sign/verify         C, Go, Python, Java   (ZKBoo)
#   nl-zkbpp           sign/verify         C, Go, Python, Java   (ZKB++)
#   rnl-sigma          sign/verify         C, Go, Python, Java   (Ring-LWR Sigma)
#   hybrid-rnl-stern   kex (two-round)     C, Go, Python, Java
#
# WHY A FULL MATRIX AND NOT "each against Python".  This script exists because
# the every-implementation-against-Python shape is exactly what let two real
# wire splits ship undetected.  When TODO #261 ported these tags to Java it
# found that `nl-zkboo` and `rnl-sigma` had NEVER interoperated between
# {C, Go} and Python: C passes `msg.b, KEYBYTES` and Go `msgPad(inBytes, 32)`,
# while Python hashed the raw, unpadded message — so each side rejected the
# other's signatures. Python's own nl-zkbpp branch carried the fix with the
# comment "Pad/truncate to 32 bytes to match C/Go behavior"; nl-zkboo and
# rnl-sigma were simply missed. Nothing caught it because no test signed with
# one implementation and verified with another for these tags. A 4x4 matrix
# does; a star topology around Python would have reported Python-vs-Python and
# gone green.
#
# What this guards, in order of what would hurt most if it broke:
#   1. every (signer, verifier) pair interoperates — 16 combinations per
#      signature tag, not 4.
#   2. the hybrid's two rounds agree on the SESSION KEY across every
#      (responder, completer) pair. A hybrid kex that "succeeds" on both sides
#      while deriving different keys is the failure mode TODO #235's implicit
#      rejection makes silent, so comparing bytes is the only real check.
#   3. verification actually REJECTS a tampered message, with a non-zero exit
#      status — a verifier that always prints "Signature OK" would pass (1).
#   4. hpks-zkp-nl keypairs are byte-identical whichever CLI derives the public
#      half.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

. "$(dirname "$0")/lib_build.sh"

CLI_PY="python3 $ROOT/HerraduraCli/herradura.py"
CLI_C="$ROOT/HerraduraCli/herradura_cli"
CLI_GO="$ROOT/HerraduraCli/herradura_cli_go"
CLI_JAVA="java -cp $ROOT/bindings/java herradurakex.HerraduraCli"

hkx_require_built c go

LANGS="c go py"
if [ -f "$ROOT/bindings/java/herradurakex/HerraduraCli.class" ]; then
    LANGS="c go py java"
else
    echo "NOTE: bindings/java not compiled — skipping the Java column."
    echo "      (run bindings/java/build.sh; native-java builds it in CI)"
fi

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
PASS=0; FAIL=0

ok()  { echo "PASS $1"; PASS=$((PASS+1)); }
bad() { echo "FAIL $1"; FAIL=$((FAIL+1)); }

cli_for() {
    case "$1" in
        py)   echo "$CLI_PY" ;;
        c)    echo "$CLI_C" ;;
        go)   echo "$CLI_GO" ;;
        java) echo "$CLI_JAVA" ;;
    esac
}

# Session/response keys are DER SEQUENCEs whose field 0 is the key; compare that
# rather than the whole PEM, since Bob's response carries C_B/hint/syn too.
key_of() {
    python3 - "$1" <<'PY'
import sys
sys.path.insert(0, "HerraduraCli")
from codec import der_parse_seq, pem_unwrap
print(der_parse_seq(pem_unwrap(open(sys.argv[1]).read())[1])[0])
PY
}

printf 'the four-way ZKP/hybrid interop message\n' > "$TMP/msg.bin"
printf 'a DIFFERENT message, must not verify\n'    > "$TMP/bad.bin"

# ── 1. hpks-zkp-nl keygen, and pubout agreement ────────────────────────────
echo "── hpks-zkp-nl: keygen + pkey --pubout ──"
for l in $LANGS; do
    CLI=$(cli_for "$l")
    if $CLI genpkey --algo hpks-zkp-nl --out "$TMP/zk_$l.pem" >/dev/null 2>&1; then
        ok "[$l] genpkey --algo hpks-zkp-nl"
    else
        bad "[$l] genpkey --algo hpks-zkp-nl"; continue
    fi
done

# One canonical key for the signature matrices; every CLI must derive the same
# public half from it.
ZK_PRIV="$TMP/zk_$(echo "$LANGS" | awk '{print $1}').pem"
REF_PUB=""
for l in $LANGS; do
    CLI=$(cli_for "$l")
    if ! $CLI pkey --in "$ZK_PRIV" --pubout --out "$TMP/zkpub_$l.pem" >/dev/null 2>&1; then
        bad "[$l] pkey --pubout on a ZKP-NL key"; continue
    fi
    if [ -z "$REF_PUB" ]; then
        REF_PUB="$TMP/zkpub_$l.pem"; ok "[$l] pkey --pubout (reference)"
    elif cmp -s "$REF_PUB" "$TMP/zkpub_$l.pem"; then
        ok "[$l] pkey --pubout byte-identical to reference"
    else
        bad "[$l] pkey --pubout byte-identical to reference"
    fi
done

# ── 2. HKEX-RNL key for rnl-sigma and the hybrid's lattice half ────────────
$CLI_PY genpkey --algo hkex-rnl --out "$TMP/rnl_a.pem"
$CLI_PY pkey --in "$TMP/rnl_a.pem" --pubout --out "$TMP/rnl_a_pub.pem"
$CLI_PY genpkey --algo hkex-rnl --out "$TMP/rnl_b.pem"
$CLI_PY genpkey --algo hpke-stern-kem --out "$TMP/kem_a.pem"
$CLI_PY pkey --in "$TMP/kem_a.pem" --pubout --out "$TMP/kem_a_pub.pem"

# ── 3. Signature tags: the full (signer x verifier) matrix ─────────────────
# 24 rounds rather than the 219 CLI default: soundness is not what this script
# tests, and 219 rounds x 16 pairs x 3 tags is minutes of pure repetition.
ZKP_ROUNDS=24

sig_matrix() {   # sig_matrix <algo> <keyfile> <pubfile> [extra sign args...]
    local algo="$1" key="$2" pub="$3"; shift 3
    echo "── $algo: $(echo $LANGS | wc -w)x$(echo $LANGS | wc -w) sign/verify matrix ──"
    for s in $LANGS; do
        local SCLI; SCLI=$(cli_for "$s")
        if ! $SCLI sign --algo "$algo" --key "$key" --in "$TMP/msg.bin" \
                        --out "$TMP/${algo}_$s.sig" "$@" >/dev/null 2>&1; then
            bad "[$s] sign --algo $algo"; continue
        fi
        for v in $LANGS; do
            local VCLI; VCLI=$(cli_for "$v")
            if $VCLI verify --algo "$algo" --pubkey "$pub" --in "$TMP/msg.bin" \
                            --sig "$TMP/${algo}_$s.sig" >/dev/null 2>&1; then
                ok "[$s->$v] $algo verifies"
            else
                bad "[$s->$v] $algo verifies"
            fi
        done
    done
    # (3) Every verifier must REJECT a tampered message, non-zero exit. Without
    # this the whole matrix above is satisfied by a verifier that never says no.
    local first; first=$(echo "$LANGS" | awk '{print $1}')
    for v in $LANGS; do
        local VCLI; VCLI=$(cli_for "$v")
        if $VCLI verify --algo "$algo" --pubkey "$pub" --in "$TMP/bad.bin" \
                        --sig "$TMP/${algo}_$first.sig" >/dev/null 2>&1; then
            bad "[$v] $algo REJECTS a tampered message (it accepted one)"
        else
            ok "[$v] $algo rejects a tampered message"
        fi
    done
}

sig_matrix nl-zkboo "$ZK_PRIV"        "$REF_PUB"           --rounds "$ZKP_ROUNDS"
sig_matrix nl-zkbpp "$ZK_PRIV"        "$REF_PUB"           --rounds "$ZKP_ROUNDS"
sig_matrix rnl-sigma "$TMP/rnl_a.pem" "$TMP/rnl_a_pub.pem"

# ── 4. hybrid-rnl-stern: (responder x completer), compared on the KEY ──────
echo "── hybrid-rnl-stern: $(echo $LANGS | wc -w)x$(echo $LANGS | wc -w) responder/completer matrix ──"
for b in $LANGS; do
    BCLI=$(cli_for "$b")
    if ! $BCLI kex --algo hybrid-rnl-stern --our "$TMP/rnl_b.pem" \
                   --their "$TMP/rnl_a_pub.pem" --their-kem "$TMP/kem_a_pub.pem" \
                   --out "$TMP/hyb_$b.pem" >/dev/null 2>&1; then
        bad "[$b] hybrid-rnl-stern responds (round 1)"; continue
    fi
    ok "[$b] hybrid-rnl-stern responds (round 1)"
    KB=$(key_of "$TMP/hyb_$b.pem")
    for a in $LANGS; do
        ACLI=$(cli_for "$a")
        if ! $ACLI kex --algo hybrid-rnl-stern --our "$TMP/rnl_a.pem" \
                       --their "$TMP/hyb_$b.pem" --our-kem "$TMP/kem_a.pem" \
                       --out "$TMP/hybk_${b}_$a.pem" >/dev/null 2>&1; then
            bad "[$b->$a] hybrid-rnl-stern completes (round 2)"; continue
        fi
        KA=$(key_of "$TMP/hybk_${b}_$a.pem")
        # Comparing BYTES, not exit status: since TODO #235 the KEM half rejects
        # implicitly, so a decoding failure or a combiner mismatch completes
        # successfully and differs only here.
        if [ "$KA" = "$KB" ]; then
            ok "[$b->$a] hybrid-rnl-stern session keys agree"
        else
            bad "[$b->$a] hybrid-rnl-stern session keys agree"
        fi
    done
done

echo ""
echo "Results: $PASS PASS / $FAIL FAIL"
[ "$FAIL" -eq 0 ]
