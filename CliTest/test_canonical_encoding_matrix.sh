#!/usr/bin/env bash
# CliTest/test_canonical_encoding_matrix.sh — TODO #372 and #368: every CLI
# refuses an artifact that is a SECOND encoding of a valid one, or that carries
# a value no writer could have produced.
#
# WHY THIS FILE EXISTS.  Before v15.0.0 all four CLIs accepted bytes after a
# PEM's DER SEQUENCE on every one of the 45 DER labels, bytes after a raw-body
# PEM's last field (ZKP-NL, ZKP-RNL, HCRED; Python and Go refused it only for
# the HCRED keys), and bytes after an .hkx file's auth tag.  Over 143 DER
# fields, a value of 2^4096+1 was accepted in 33 by Python, 71 by C, 67 by Go
# and 56 by Java -- truncated, ignored or used -- and every HPKS verifier
# ignored the stored challenge e, so a signature had unboundedly many
# encodings that all said "Signature OK".  An .hkx length near 2^64 also sent C
# past its buffer (an abort under FORTIFY) and panicked Go.  Four parts:
#
#   A. Trailing DER: each label's genuine artifact (accept-control), then one
#      byte and one extra INTEGER after the SEQUENCE; the text is
#          malformed PEM '<label>': <k> bytes after the DER SEQUENCE
#   B. Trailing raw body: one byte after the last field of each raw-body PEM;
#          malformed PEM '<label>': <k> bytes after its last field
#      and the same for an .hkx file ("decfile: <k> bytes after the auth tag"),
#      plus three plaintext lengths that overflow the length arithmetic.
#   C. Field caps: spec/herradura-protocol-spec.json's pem_der_field_caps says
#      how wide each field may be.  For every row a cell's genuine artifact
#      matches, each field is set ONE BYTE past its cap.  A field no other cap
#      reads must be refused with
#          <label>: field <i> is <k> bytes (expected at most <cap>)
#      A width or count field (one another cap reads) is often refused first by
#      that CLI's own width check, so it needs only a clean refusal.  Every row
#      must be matched by some cell, so a new layout without a fixture fails.
#   D. HPKS: a signature whose stored e is not the recomputed one, and one whose
#      n is not the public key's, are refused.
#
# Not a crash, not a timeout, and the exact text where one is given.
# Claimed by ci.yml's cross-lang-compat job (all four CLIs built).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
PASS=0; FAIL=0

declare -A CLI=()
CLI[py]="python3 $ROOT/HerraduraCli/herradura.py"
[ -x "$ROOT/HerraduraCli/herradura_cli" ]    && CLI[c]="$ROOT/HerraduraCli/herradura_cli"
[ -x "$ROOT/HerraduraCli/herradura_cli_go" ] && CLI[go]="$ROOT/HerraduraCli/herradura_cli_go"
if command -v javac >/dev/null 2>&1; then
    bash bindings/java/build.sh >/dev/null 2>&1
    CLI[java]="java -Xmx1g -cp $ROOT/bindings/java herradurakex.HerraduraCli"
fi
LANGS=()
for l in py c go java; do
    [ -n "${CLI[$l]:-}" ] && LANGS+=("$l")
done
if [ -z "${CLI[c]:-}" ]; then
    echo "FAIL test_canonical_encoding_matrix: needs the C CLI for its fixtures, so" \
         "nothing was asserted (run ./build_c.sh)." >&2
    [ "${HKX_ALLOW_SKIP:-0}" = "1" ] && exit 0
    exit 2
fi

pass() { echo "PASS $1"; PASS=$((PASS+1)); }
fail() { echo "FAIL $1"; FAIL=$((FAIL+1)); }

CRASH_RE='Traceback \(most recent call last\)|^panic: |^goroutine [0-9]+ \[|fatal error|runtime: out of memory|MemoryError|OverflowError|Exception in thread|OutOfMemoryError|java\.lang\.[A-Za-z]*Error|AddressSanitizer|Segmentation fault|buffer overflow detected|Aborted'
CASE_TIMEOUT="${HKX_DER_TIMEOUT:-120}"

# shellcheck source=CliTest/lib_der_fixtures.sh
source "$ROOT/CliTest/lib_der_fixtures.sh"
C=${CLI[c]}

# Extra fixtures: the CIPHERTEXT and SIGNATURE layouts the templates above do
# not reach, and the raw-body and .hkx artifacts.
q $C enc --algo hske --key "$F/sk.pem" --in "$F/msg.bin" --out "$F/ct_hske.pem"
q $C enc --algo hske-nla1 --key "$F/sk.pem" --in "$F/msg.bin" --out "$F/ct_nla1.pem"
q $C enc --algo hske-nla1 --aead --key "$F/sk.pem" --in "$F/msg.bin" --out "$F/ct_aead.pem"
q $C enc --algo hske-duplex --key "$F/sk.pem" --in "$F/msg.bin" --out "$F/ct_duplex.pem"
q $C genpkey --algo hpks-zkp-nl --out "$F/zk.pem"
q $C pkey --in "$F/zk.pem" --pubout --out "$F/zk_pub.pem"
q $C sign --algo nl-zkboo --key "$F/zk.pem" --in "$F/msg.bin" --out "$F/zkboo.pem"
q $C sign --algo nl-zkbpp --key "$F/zk.pem" --in "$F/msg.bin" --out "$F/zkbpp.pem"
q $C sign --algo rnl-sigma --key "$F/hkex-rnl.pem" --in "$F/msg.bin" --out "$F/sigma.pem"
head -c 100 /dev/urandom > "$F/plain.bin"
q $C encfile --algo hske-nla1 --key "$F/sk.pem" --in "$F/plain.bin" --out "$F/f.hkx"

# Cells: "label|fixture|argv".  Every DER template, plus the layouts above.
CELLS=()
for label in "${!T[@]}"; do
    CELLS+=("$label|${T[$label]}")
done
CELLS+=("HERRADURA CIPHERTEXT|ct_hske.pem|dec --algo hske --key {F}/sk.pem --in {X} --out {O}")
CELLS+=("HERRADURA CIPHERTEXT|ct_nla1.pem|dec --algo hske-nla1 --key {F}/sk.pem --in {X} --out {O}")
CELLS+=("HERRADURA CIPHERTEXT|ct_aead.pem|dec --algo hske-nla1 --key {F}/sk.pem --in {X} --out {O}")
CELLS+=("HERRADURA CIPHERTEXT|ct_duplex.pem|dec --algo hske-duplex --key {F}/sk.pem --in {X} --out {O}")
CELLS+=("HERRADURA CIPHERTEXT|ct_hpke-stern.pem|dec --algo hpke-stern --key {F}/hpke-stern.pem --in {X} --out {O}")
CELLS+=("HERRADURA CIPHERTEXT|ct_hpke-stern-kem.pem|dec --algo hpke-stern-kem --key {F}/hpke-stern-kem.pem --in {X} --out {O}")
CELLS+=("HERRADURA SIGNATURE|sig_hpks-stern.pem|verify --algo hpks-stern --min-rounds 1 --pubkey {F}/hpks-stern_pub.pem --in {F}/msg.bin --sig {X}")
CELLS+=("HERRADURA SIGNATURE|sig_hpks-nl.pem|verify --algo hpks-nl --pubkey {F}/hpks-nl_pub.pem --in {F}/msg.bin --sig {X}")
RAW_CELLS=(
    "HERRADURA ZKP-NL PRIVATE KEY|zk.pem|sign --algo nl-zkboo --key {X} --in {F}/msg.bin --out {O}"
    "HERRADURA ZKP-NL PUBLIC KEY|zk_pub.pem|verify --algo nl-zkboo --min-rounds 1 --pubkey {X} --in {F}/msg.bin --sig {F}/zkboo.pem"
    "HERRADURA ZKP-NL PROOF|zkboo.pem|verify --algo nl-zkboo --min-rounds 1 --pubkey {F}/zk_pub.pem --in {F}/msg.bin --sig {X}"
    "HERRADURA ZKP-NL-PP SIGNATURE|zkbpp.pem|verify --algo nl-zkbpp --min-rounds 1 --pubkey {F}/zk_pub.pem --in {F}/msg.bin --sig {X}"
    "HERRADURA ZKP-RNL PROOF|sigma.pem|verify --algo rnl-sigma --min-rounds 1 --pubkey {F}/hkex-rnl_pub.pem --in {F}/msg.bin --sig {X}"
    "HERRADURA HCRED PRIVATE KEY|hcred.pem|cred-prove --in {X} --msg n --rounds 2 --out {O}"
    "HERRADURA HCRED PUBLIC KEY|hcred_pub.pem|cred-verify --min-rounds 1 --proof {F}/proof.pem --pubkey {X} --msg n --cred {F}/cred.pem --issuer {F}/hpks-stern_pub.pem"
    "HERRADURA HCRED PROOF|proof.pem|cred-verify --min-rounds 1 --proof {X} --pubkey {F}/hcred_pub.pem --msg n --cred {F}/cred.pem --issuer {F}/hpks-stern_pub.pem"
)

# ── Crafting, all in one python call ─────────────────────────────────────────
#   V/<n>/t1.pem, t2.pem        DER: one byte / one INTEGER after the SEQUENCE
#   V/<n>/r1.pem                raw: one byte after the last field
#   V/<n>/c<i>.pem              DER: field i one byte past its cap
#   plan lines on stdout:       CAP|<n>|<i>|<want text or ''>
#   V/f*.hkx                    .hkx variants
V="$TMP/var"; mkdir -p "$V"
PLAN="$TMP/plan"
printf '%s\n' "${CELLS[@]}" > "$TMP/cells"
printf '%s\n' "${RAW_CELLS[@]}" > "$TMP/raw_cells"
python3 - "$ROOT" "$F" "$V" "$TMP/cells" "$TMP/raw_cells" > "$PLAN" <<'PY'
import json, os, re, struct, sys
root, F, V, cells_f, raw_f = sys.argv[1:6]
sys.path.insert(0, os.path.join(root, "HerraduraCli"))
from codec import der_int, pem_wrap, pem_unwrap, _read_length

rows = json.load(open(os.path.join(root, "spec", "herradura-protocol-spec.json")))["pem_der_field_caps"]

def items(der):
    """Raw (tag+length+content) INTEGER encodings and their values."""
    off = 1; L, off = _read_length(der, off); end = off + L; out = []
    while off < end:
        start = off; off += 1; vl, off = _read_length(der, off)
        out.append((der[start:off + vl], int.from_bytes(der[off:off + vl], "big"))); off += vl
    return out

def seq(raws):
    body = b"".join(raws)
    n = len(body)
    ln = bytes([n]) if n < 128 else bytes([0x80 | ((n.bit_length() + 7) // 8)]) + n.to_bytes((n.bit_length() + 7) // 8, "big")
    return b"\x30" + ln + body

def ev(expr, f):
    e = re.sub(r"f(\d+)", lambda m: "F[%s]" % m.group(1), expr).replace("/", "//")
    return eval(e, {"min": min, "F": f})

def match(label, f):
    for r in rows:
        if r["label"] == label and r["min_items"] <= len(f) <= r["max_items"]:
            if not r["when"] or ev(r["when"], f):
                return r
    return None

used = set()
for i, line in enumerate(open(cells_f).read().splitlines()):
    label, fx, _ = line.split("|", 2)
    text = open(os.path.join(F, fx)).read()
    plabel, der = pem_unwrap(text)
    d = os.path.join(V, str(i)); os.makedirs(d, exist_ok=True)
    open(os.path.join(d, "t1.pem"), "w").write(pem_wrap(plabel, der + b"\x00"))
    open(os.path.join(d, "t2.pem"), "w").write(pem_wrap(plabel, der + der_int(5)))
    its = items(der)
    f = [v for _, v in its]
    r = match(plabel, f)
    if r is None:
        print("NOROW|%d|%s|%d" % (i, plabel, len(f)))
        continue
    used.add((r["label"], r["min_items"], r["max_items"], r["when"]))
    refs = set()
    for c in r["caps"]:
        refs |= {int(x) for x in re.findall(r"f(\d+)", c["cap"])}
    if r["when"]:
        refs |= {int(x) for x in re.findall(r"f(\d+)", r["when"])}
    for c in r["caps"]:
        k = c["field"]
        if k >= len(f):
            continue
        cap = ev(c["cap"], f)
        raws = [raw for raw, _ in its]
        raws[k] = der_int(1 << (8 * cap))          # cap + 1 significant bytes
        open(os.path.join(d, "c%d.pem" % k), "w").write(pem_wrap(plabel, seq(raws)))
        want = "" if k in refs else "%s: field %d is %d bytes (expected at most %d)" % (plabel, k, cap + 1, cap)
        print("CAP|%d|%d|%s" % (i, k, want))
for r in rows:
    key = (r["label"], r["min_items"], r["max_items"], r["when"])
    if key not in used and r["label"] not in ("HERRADURA DIGEST", "HERRADURA PAKE RECORD"):
        print("UNUSED|%s|%d..%d|%s" % key)

for i, line in enumerate(open(raw_f).read().splitlines()):
    label, fx, _ = line.split("|", 2)
    plabel, body = pem_unwrap(open(os.path.join(F, fx)).read())
    d = os.path.join(V, "raw%d" % i); os.makedirs(d, exist_ok=True)
    open(os.path.join(d, "r1.pem"), "w").write(pem_wrap(plabel, body + b"\x00"))

raw = open(os.path.join(F, "f.hkx"), "rb").read()
open(os.path.join(V, "f_t1.hkx"), "wb").write(raw + b"\x00")
for pl in (2**64 - 32, 2**63, 2**32):
    open(os.path.join(V, "f_pl%d.hkx" % pl), "wb").write(b"HKX1\x01" + struct.pack(">Q", pl) + bytes(128))
PY

RUN="$TMP/run"
run() {     # run <lang> <fixture> <artifact> <argv template> -> RC, OUT
    local lang="$1" fx="$2" art="$3" tpl="$4"
    rm -rf "$RUN"; mkdir -p "$RUN"
    cp "$art" "$RUN/x.pem"
    [ -f "$F/$fx.idx" ] && cp "$F/$fx.idx" "$RUN/x.pem.idx"
    local argv=${tpl//\{X\}/$RUN/x.pem}
    argv=${argv//\{F\}/$F}
    argv=${argv//\{O\}/$RUN/out.pem}
    # shellcheck disable=SC2086
    OUT=$( (if [ "$lang" != java ]; then ulimit -v 4000000 2>/dev/null || true; fi
            timeout "$CASE_TIMEOUT" ${CLI[$lang]} $argv) 2>&1 </dev/null) && RC=0 || RC=$?
}
refused() { # refused <desc> [exact substring]
    local desc="$1" want="${2:-}"
    if [ "$RC" -eq 0 ]; then
        fail "$desc: exited 0"
    elif [ "$RC" -eq 124 ]; then
        fail "$desc: timed out after ${CASE_TIMEOUT}s"
    elif echo "$OUT" | grep -qE "$CRASH_RE"; then
        fail "$desc: crashed — $(echo "$OUT" | grep -m1 -E "$CRASH_RE")"
    elif [ -n "$want" ] && ! echo "$OUT" | grep -qF -- "$want"; then
        fail "$desc: refused, but without \"$want\" — $(echo "$OUT" | grep -v -i warning | head -1)"
    else
        pass "$desc"
    fi
}

while IFS='|' read -r kind a b c; do
    case "$kind" in
        NOROW)  fail "coverage: cell $a ('$b', $c items) matches no pem_der_field_caps row" ;;
        UNUSED) fail "coverage: pem_der_field_caps row '$a' $b ${c:+when $c }is matched by no cell here" ;;
    esac
done < "$PLAN"
[ "$FAIL" -eq 0 ] && pass "coverage: every pem_der_field_caps row is matched by a cell"

for lang in "${LANGS[@]}"; do
    echo ""
    echo "=== $lang ==="
    # ── A + C: DER cells ──
    i=0
    for cell in "${CELLS[@]}"; do
        IFS='|' read -r label fx tpl <<<"$cell"
        run "$lang" "$fx" "$F/$fx" "$tpl"
        if [ "$RC" -ne 0 ]; then
            fail "[$lang] $label ($fx): genuine artifact refused (exit $RC) — $(echo "$OUT" | grep -v -i warning | head -1); its cases are skipped"
            i=$((i+1)); continue
        fi
        pass "[$lang] $label ($fx): genuine artifact accepted"
        run "$lang" "$fx" "$V/$i/t1.pem" "$tpl"
        refused "[$lang] $label ($fx): 1 byte after the SEQUENCE" \
            "malformed PEM '$label': 1 bytes after the DER SEQUENCE"
        run "$lang" "$fx" "$V/$i/t2.pem" "$tpl"
        refused "[$lang] $label ($fx): an INTEGER after the SEQUENCE" \
            "malformed PEM '$label': 3 bytes after the DER SEQUENCE"
        while IFS='|' read -r kind ci k want; do
            [ "$kind" = CAP ] && [ "$ci" = "$i" ] || continue
            run "$lang" "$fx" "$V/$i/c$k.pem" "$tpl"
            refused "[$lang] $label ($fx): field $k one byte past its cap${want:+ (exact text)}" "$want"
        done < "$PLAN"
        i=$((i+1))
    done
    # ── B: raw bodies and .hkx ──
    i=0
    for cell in "${RAW_CELLS[@]}"; do
        IFS='|' read -r label fx tpl <<<"$cell"
        run "$lang" "$fx" "$F/$fx" "$tpl"
        if [ "$RC" -ne 0 ]; then
            fail "[$lang] $label: genuine artifact refused (exit $RC) — $(echo "$OUT" | head -1)"
        else
            pass "[$lang] $label: genuine artifact accepted"
            run "$lang" "$fx" "$V/raw$i/r1.pem" "$tpl"
            refused "[$lang] $label: 1 byte after the last field" \
                "malformed PEM '$label': 1 bytes after its last field"
        fi
        i=$((i+1))
    done
    HKX="decfile --algo hske-nla1 --key {F}/sk.pem --in {X} --out {O}"
    run "$lang" f.hkx "$F/f.hkx" "$HKX"
    if [ "$RC" -eq 0 ] && cmp -s "$RUN/out.pem" "$F/plain.bin"; then
        pass "[$lang] .hkx: genuine file decrypts to the plaintext"
    else
        fail "[$lang] .hkx: genuine file did not round-trip (exit $RC)"
    fi
    run "$lang" f.hkx "$V/f_t1.hkx" "$HKX"
    refused "[$lang] .hkx: 1 byte after the auth tag" "decfile: 1 bytes after the auth tag"
    for pl in 18446744073709551584 9223372036854775808 4294967296; do
        run "$lang" f.hkx "$V/f_pl$pl.hkx" "$HKX"
        refused "[$lang] .hkx: plaintext length $pl" "decfile: file truncated"
    done
done

# ── D: HPKS stored challenge and width ───────────────────────────────────────
python3 - "$ROOT" "$F" <<'PY'
import os, sys
sys.path.insert(0, os.path.join(sys.argv[1], "HerraduraCli"))
from codec import der_int, der_seq, der_parse_seq, pem_wrap, pem_unwrap
F = sys.argv[2]
for a in ("hpks", "hpks-nl"):
    label, der = pem_unwrap(open(os.path.join(F, "sig_%s.pem" % a)).read())
    s, R, e, n = der_parse_seq(der)
    nb = n // 8
    open(os.path.join(F, "sig_%s_e.pem" % a), "w").write(
        pem_wrap(label, der_seq(der_int(s, nb), der_int(R, nb), der_int(e ^ 1, nb), der_int(n))))
    open(os.path.join(F, "sig_%s_n.pem" % a), "w").write(
        pem_wrap(label, der_seq(der_int(s, nb), der_int(R, nb), der_int(e, nb), der_int(128))))
PY
for lang in "${LANGS[@]}"; do
    for a in hpks hpks-nl; do
        tpl="verify --algo $a --pubkey {F}/${a}_pub.pem --in {F}/msg.bin --sig {X}"
        run "$lang" "sig_$a.pem" "$F/sig_$a.pem" "$tpl"
        if [ "$RC" -ne 0 ]; then
            fail "[$lang] $a: genuine signature refused (exit $RC)"; continue
        fi
        pass "[$lang] $a: genuine signature verifies"
        run "$lang" "sig_$a.pem" "$F/sig_${a}_e.pem" "$tpl"
        refused "[$lang] $a: stored e is not the recomputed e" \
            "signature challenge e is not the recomputed one"
        run "$lang" "sig_$a.pem" "$F/sig_${a}_n.pem" "$tpl"
        refused "[$lang] $a: signature n differs from the public key's"
    done
done

echo ""
echo "Results: $PASS PASS / $FAIL FAIL (languages: ${LANGS[*]})"
[ "$FAIL" -eq 0 ]
