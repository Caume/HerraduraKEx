#!/usr/bin/env bash
# CliTest/test_der_items_matrix.sh — TODO #367: every CLI refuses a DER-SEQUENCE
# PEM with the wrong number of items, and a width or fixed-size field out of
# range, cleanly — one line, exit 1 — instead of crashing.
#
# WHY THIS FILE EXISTS.  Before v15.0.0, over 1794 malformed variants of 90
# (command, artifact slot) cells, the Go CLI panicked or ran out of memory in 365
# and Python printed a traceback in 299; C and Java failed cleanly in all.  A peer's
# public key and an HKEX-RNL response -- inputs the OTHER party supplies -- were
# among them: a well-formed DER SEQUENCE with too few INTEGERs panicked Go with
# `index out of range`.  Two fixes, both checked here:
#
#   PART A, item counts.  spec/generate_spec.py's PEM_DER_ITEMS says how many
#   DER INTEGERs each label carries.  Every CLI checks it in its one
#   PEM-to-integers loader and prints the same text:
#       malformed PEM '<label>': <k> DER items, expected <min>[..<max>]
#   For every label the spec lists, this script feeds each CLI the genuine
#   artifact (accept-control: exit 0) and then k = 0, min-1 and max+1 items,
#   and requires that exact message.  The templates must cover the spec's labels
#   in both directions, so a new label without a test fails here.
#
#   PART B, field bounds.  A width or count that sizes a buffer or a
#   polynomial (an HKEX-RNL ring dimension, a Stern or GF width, a QC-MDPC r or
#   d, an HSKE session-key width), and a value too large for its fixed-size
#   field, must never reach a panic, an OverflowError, an out-of-memory abort
#   or a minutes-long loop.  The texts differ by CLI (each already had its own
#   bound messages).  Cases marked strict must be REFUSED by all four -- among
#   them Go's old peer-ring gap: Go read only its OWN key's ring dimension and
#   ignored the peer's, so a 512-ring peer key exited 0.  Cases marked safe
#   need only not crash: a CLI that never reads the field may exit 0, which is
#   printed as a NOTE (the cross-CLI acceptance difference this TODO measured
#   and left to its own follow-up).
#
# A crash is recognised by its signature (Traceback, `panic:`, a goroutine dump,
# OutOfMemoryError, ...) and a hang by the per-case timeout -- a non-zero exit
# alone is NOT a refusal, which is exactly the hole lib_malformed.sh had for Go
# panics until this TODO.
#
# Claimed by ci.yml's cross-lang-compat job (all four CLIs built).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
PASS=0; FAIL=0; NOTES=0

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
echo "Languages under test: ${LANGS[*]}"

. "$ROOT/CliTest/lib_build.sh"
for l in c go; do
    [ -n "${CLI[$l]:-}" ] || echo "NOTE: $l CLI absent — $(hkx_why "$l")"
done
[ -n "${CLI[java]:-}" ] || echo "NOTE: java CLI absent — javac is not installed"
if [ -z "${CLI[c]:-}" ]; then
    echo "FAIL test_der_items_matrix: needs the C CLI for its fixtures, so nothing" \
         "was asserted (run ./build_c.sh)." >&2
    [ "${HKX_ALLOW_SKIP:-0}" = "1" ] && exit 0
    exit 2
fi

pass() { echo "PASS $1"; PASS=$((PASS+1)); }
fail() { echo "FAIL $1"; FAIL=$((FAIL+1)); }

CRASH_RE='Traceback \(most recent call last\)|^panic: |^goroutine [0-9]+ \[|fatal error|runtime: out of memory|MemoryError|OverflowError|Exception in thread|OutOfMemoryError|java\.lang\.[A-Za-z]*Error|AddressSanitizer|Segmentation fault'
CASE_TIMEOUT="${HKX_DER_TIMEOUT:-120}"

# ── Fixtures and templates (shared with test_canonical_encoding_matrix.sh) ──
# shellcheck source=CliTest/lib_der_fixtures.sh
source "$ROOT/CliTest/lib_der_fixtures.sh"

# ── Coverage: the spec's labels, both directions ─────────────────────────────
mapfile -t SPEC_ROWS < <(python3 - "$ROOT/spec/herradura-protocol-spec.json" <<'PY'
import json, sys
for r in json.load(open(sys.argv[1]))["pem_der_items"]:
    print(f'{r["label"]}|{r["min"]}|{r["max"]}')
PY
)
declare -A IN_SPEC=()
for row in "${SPEC_ROWS[@]}"; do
    label=${row%%|*}; IN_SPEC["$label"]=1
    if [ -z "${T[$label]:-}" ] && [ -z "${NO_READER[$label]:-}" ]; then
        fail "coverage: spec label '$label' has no template here"
    fi
done
for label in "${!T[@]}" "${!NO_READER[@]}"; do
    [ -n "${IN_SPEC[$label]:-}" ] || fail "coverage: template '$label' is not in spec pem_der_items"
done
[ "$FAIL" -eq 0 ] && pass "coverage: ${#T[@]} templates + ${#NO_READER[@]} no-reader labels = ${#SPEC_ROWS[@]} spec rows"

# ── Crafting: every variant once, in one python call ─────────────────────────
#   arity:  V/<fixture>/a<k>.pem   = the first k items (k > count: padded with 0)
#   bounds: V/<fixture>/b<i>_<v>.pem = item i replaced by v
V="$TMP/var"; mkdir -p "$V"
HUGE='2**4096+1'
BOUNDS=(
    # fixture|item|value|template label|what|mode
    #   strict: every CLI reads the field, so every CLI must REFUSE it;
    #   safe:   it must not crash or hang.  Some CLIs never read the field (C
    #           sizes most fields from its compiled widths) and exit 0 on it;
    #           that is printed as a NOTE, and is the cross-CLI acceptance
    #           question TODO #367 measured and left to its own TODO.
    #   TODO #371 made every WIDTH field strict: each CLI now refuses a width it
    #   does not run instead of reading the artifact at its own.  What is left
    #   as safe is the masking / over-wide-value class (a nonce, hint length,
    #   support or blob wider than its field), still recorded as NOTEs.
    "hkex-rnl.pem|2|7|HERRADURA HKEX-RNL PRIVATE KEY|our RNL ring n=7|strict"
    "hkex-rnl.pem|2|2147483647|HERRADURA HKEX-RNL PRIVATE KEY|our RNL ring n=2^31-1|strict"
    "hkex-rnl.pem|3|$HUGE|HERRADURA HKEX-RNL PRIVATE KEY|RNL nonce wider than 32 bytes|safe"
    "hkex-rnl_pub.pem|2|7|HERRADURA HKEX-RNL PUBLIC KEY|peer RNL ring n=7|strict"
    "hkex-rnl_pub.pem|2|512|HERRADURA HKEX-RNL PUBLIC KEY|peer RNL ring n=512 (not ours)|strict"
    "hkex-rnl_pub.pem|2|2147483647|HERRADURA HKEX-RNL PUBLIC KEY|peer RNL ring n=2^31-1|strict"
    "rnl_resp.pem|3|512|HERRADURA HKEX-RNL RESPONSE|response ring n=512 (not ours)|strict"
    "rnl_resp.pem|4|2147483647|HERRADURA HKEX-RNL RESPONSE|response hint length 2^31-1|safe"
    "hyb_resp.pem|3|7|HERRADURA HYBRID-RNL-STERN RESPONSE|hybrid response ring n=7|strict"
    "hyb_resp.pem|7|7|HERRADURA HYBRID-RNL-STERN RESPONSE|hybrid response QC-MDPC r=7|strict"
    "hpks-stern.pem|2|7|HERRADURA HPKS-STERN PRIVATE KEY|Stern key n=7|strict"
    "hpks-stern.pem|2|2147483647|HERRADURA HPKS-STERN PRIVATE KEY|Stern key n=2^31-1|strict"
    "hpke-stern_pub.pem|2|7|HERRADURA HPKE-STERN PUBLIC KEY|HPKE-Stern public key n=7|strict"
    "hpke-stern-kem.pem|2|$HUGE|HERRADURA HPKE-STERN-KEM PRIVATE KEY|QC-MDPC support wider than its field|safe"
    "hpke-stern-kem_pub.pem|1|7|HERRADURA HPKE-STERN-KEM PUBLIC KEY|QC-MDPC public key r=7|strict"
    "ct_hpke-stern-kem.pem|2|7|HPKE-STERN-KEM CT|QC-MDPC ciphertext r=7|strict"
    "hkex-gf.pem|2|7|HERRADURA HKEX-GF PRIVATE KEY|GF key n=7|strict"
    "hkex-gf.pem|2|65536|HERRADURA HKEX-GF PRIVATE KEY|GF key n=65536|strict"
    "hpke_pub.pem|1|7|HERRADURA HPKE PUBLIC KEY|GF public key n=7|strict"
    "hpks.pem|1|$HUGE|HPKS THRESHOLD|threshold key: public value wider than n|safe"
    "hpks-wots.pem|0|$HUGE|HERRADURA HPKS-WOTS PRIVATE KEY|WOTS seed wider than 32 bytes|safe"
    "hpks-xmss.pem|3|$HUGE|HERRADURA HPKS-XMSS PRIVATE KEY|XMSS leaf blob wider than its field|safe"
    "sk.pem|1|7|HERRADURA SESSION KEY|session key width 7|strict"
    "sk.pem|1|0|SESSION KEY NLA1|session key width 0 (hske-nla1)|strict"
    "c1.pem|2|7|HERRADURA HPKST COMMITMENT|threshold commitment n=7|strict"
)
T["HPKE-STERN-KEM CT"]="ct_hpke-stern-kem.pem|dec --algo hpke-stern-kem --key {F}/hpke-stern-kem.pem --in {X} --out {O}"
T["HPKS THRESHOLD"]="hpks.pem|threshold-commit --key {X} --commit-out {O} --nonce-out {O}.n"
T["SESSION KEY NLA1"]="sk.pem|enc --algo hske-nla1 --key {X} --in {F}/msg.bin --out {O}"

# "fixture|min|max" for every spec label that has a reader.
ARITY=()
for row in "${SPEC_ROWS[@]}"; do
    IFS='|' read -r label lo hi <<<"$row"
    [ -n "${T[$label]:-}" ] || continue
    ARITY+=("${T[$label]%%|*}|$lo|$hi")
done
python3 - "$ROOT/HerraduraCli" "$F" "$V" "${ARITY[@]}" "--" "${BOUNDS[@]}" <<'PY'
import os, sys
sys.path.insert(0, sys.argv[1])
from codec import der_int, der_seq, der_parse_seq, pem_wrap, pem_unwrap
F, V = sys.argv[2], sys.argv[3]
args = sys.argv[4:]
cut = args.index("--")
def items(fx):
    label, der = pem_unwrap(open(os.path.join(F, fx)).read())
    return label, der_parse_seq(der)
def write(fx, name, label, its):
    d = os.path.join(V, fx)
    os.makedirs(d, exist_ok=True)
    open(os.path.join(d, name), "w").write(pem_wrap(label, der_seq(*[der_int(x) for x in its])))
for spec in args[:cut]:
    fx, lo, hi = spec.split("|")
    label, its = items(fx)
    for k in sorted({0, int(lo) - 1, int(hi) + 1} - {-1}):
        write(fx, f"a{k}.pem", label, (its + [0] * k)[:k])
for spec in args[cut + 1:]:
    fx, idx, val = spec.split("|")[:3]
    label, its = items(fx)
    its[int(idx)] = eval(val)
    write(fx, f"b{idx}_{val.replace('*', 'p').replace('+', 'q')}.pem", label, its)
PY

# run <lang> <fixture> <artifact path> <argv template>  -> sets RC and OUT
RUN="$TMP/run"
run() {
    local lang="$1" fx="$2" art="$3" tpl="$4"
    rm -rf "$RUN"; mkdir -p "$RUN"
    cp "$art" "$RUN/x.pem"
    # One-time and stateful keys sign once: give every run a fresh index file.
    [ -f "$F/$fx.idx" ] && cp "$F/$fx.idx" "$RUN/x.pem.idx"
    local argv=${tpl//\{X\}/$RUN/x.pem}
    argv=${argv//\{F\}/$F}
    argv=${argv//\{O\}/$RUN/out.pem}
    # shellcheck disable=SC2086
    # 4 GB of address space makes a missing bound fail fast instead of
    # swapping; the JVM reserves far more than it commits, so it gets -Xmx.
    OUT=$( (if [ "$lang" != java ]; then ulimit -v 4000000 2>/dev/null || true; fi
            timeout "$CASE_TIMEOUT" ${CLI[$lang]} $argv) 2>&1 </dev/null) && RC=0 || RC=$?
}

# refused <desc> [required substring]: non-zero, not a crash, not a timeout.
refused() {
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

declare -A CTL=()
for lang in "${LANGS[@]}"; do
    echo ""
    echo "=== $lang ==="
    # ── Part A: item counts ──
    for row in "${SPEC_ROWS[@]}"; do
        IFS='|' read -r label lo hi <<<"$row"
        [ -n "${T[$label]:-}" ] || continue
        fx=${T[$label]%%|*}; tpl=${T[$label]#*|}
        run "$lang" "$fx" "$F/$fx" "$tpl"
        if [ "$RC" -ne 0 ]; then
            fail "[$lang] '$label': genuine artifact refused (exit $RC) — $(echo "$OUT" | grep -v -i warning | head -1); its cases are skipped"
            continue
        fi
        pass "[$lang] '$label': genuine artifact accepted"
        want_txt="$lo"; [ "$lo" = "$hi" ] || want_txt="$lo..$hi"
        for v in "$V/$fx"/a*.pem; do
            k=$(basename "$v" .pem); k=${k#a}
            run "$lang" "$fx" "$v" "$tpl"
            refused "[$lang] '$label' with $k items" \
                "malformed PEM '$label': $k DER items, expected $want_txt"
        done
    done
    # ── Part B: field bounds ──
    for b in "${BOUNDS[@]}"; do
        IFS='|' read -r fx idx val tlabel what mode <<<"$b"
        tpl=${T[$tlabel]#*|}
        v="$V/$fx/b${idx}_$(echo "$val" | sed 's/\*/p/g; s/+/q/g').pem"
        key="$lang|$tlabel"
        if [ -z "${CTL[$key]:-}" ]; then
            run "$lang" "$fx" "$F/$fx" "$tpl"
            CTL[$key]=$RC
            [ "$RC" -eq 0 ] && pass "[$lang] bounds control for $tlabel accepted"
        fi
        if [ "${CTL[$key]}" -ne 0 ]; then
            fail "[$lang] $what: control refused (exit ${CTL[$key]}); case skipped"
            continue
        fi
        run "$lang" "$fx" "$v" "$tpl"
        if [ "$mode" = safe ] && [ "$RC" -eq 0 ]; then
            echo "NOTE [$lang] $what: accepted (exit 0); this CLI does not read the field"
            NOTES=$((NOTES+1))
            pass "[$lang] $what: no crash"
        else
            refused "[$lang] $what"
        fi
    done
done

echo ""
echo "Results: $PASS PASS / $FAIL FAIL, $NOTES unread-field NOTEs (languages: ${LANGS[*]})"
[ "$FAIL" -eq 0 ]
