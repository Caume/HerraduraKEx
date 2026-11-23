#!/usr/bin/env bash
# CliTest/test_pkey_text_matrix.sh — TODO #374: `pkey --text` describes every
# private key in every CLI, and `genpkey --algo hpks-zkp-nl --bits` means what
# it says.
#
# Until #374, `pkey --text` printed NOTHING and exited 0 on five key types in
# Python (hpks-zkp-nl, hpke-stern-kem, hpks-wots, hpks-xmss, oprf) and three in
# Go (hpke-stern-kem, hpks-wots, hpks-xmss) -- each CLI's if/switch chain had no
# branch and no default.  C, Go and Java refused an OPRF key as an
# "unrecognised label", so test_oprf.sh's "pkey --text works on OPRF key" held
# only in Python, which printed nothing.  C printed `n : 256` for an n = 1024
# hkex-rnl key.  And Python, Go and Java read an explicit `--bits 256` on
# hpks-zkp-nl as "flag omitted" (256 is the flag's default), so a caller asking
# for n = 256 got an n = 8 key and exit 0; the wire cap is 64.
#
# Sections:
#   1. every producer x consumer x key type: --text exits 0 and its first line
#      is `algorithm : <algo>`; for hkex-rnl, hpks-zkp-nl and hcred the `n`
#      line also matches the default width (hcred: TODO #369).
#   2. oprf has no public half: every CLI refuses `pkey --pubout` on it, after
#      an accept-control (--pubout on an hpks key succeeds).
#   3. genpkey hpks-zkp-nl --bits: omitted -> n = 8, 64 -> n = 64 (accept-
#      controls), 256 and 7 -> refused, in all four CLIs (C gained --bits in
#      TODO #379; until then this section ran on py, go and java only).
#   4. (TODO #386, #387) the WHOLE --text output: for every key, the four CLIs
#      print the same bytes.  Section 1 compared only the first line, which is
#      how Python's hkex-rnl dump (its packed values without their leading
#      zeros) and four different hkex-rnl, three hcred and two Stern layouts
#      all passed it.
#   5. (TODO #386) each dump ends in the key's key_parameter_sets row --
#      `level : <level>` where the row has one, then `security : <estimate>` --
#      read here from spec/herradura-protocol-spec.json, not from any CLI;
#      WOTS and XMSS, which no row describes, carry neither line.
#   6. (TODO #386) a public key is refused by label in every CLI with one
#      message (Python died in a traceback), after an accept-control.
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
. "$ROOT/CliTest/lib_build.sh"
hkx_require_built c go java

PASS=0; FAIL=0
pass() { PASS=$((PASS+1)); }
fail() { echo "FAIL $1"; FAIL=$((FAIL+1)); }

bash "$ROOT/bindings/java/build.sh" >/dev/null 2>&1 || { echo "FAIL Java build" >&2; exit 1; }

declare -A CLI=(
    [py]="python3 $ROOT/HerraduraCli/herradura.py"
    [c]="$ROOT/HerraduraCli/herradura_cli"
    [go]="$ROOT/HerraduraCli/herradura_cli_go"
    [java]="java -cp $ROOT/bindings/java herradurakex.HerraduraCli"
)
LANGS=(py c go java)
ALGOS=(hkex-gf hpks hpks-nl hpke hpke-nl hpke-nl3 hkex-rnl hpks-stern hpke-stern
       hpke-stern-kem hcred hpks-wots hpks-xmss hpks-zkp-nl oprf)

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

# field <text> <name> — value of the `name : value` line, spaces squeezed.
field() { printf '%s\n' "$1" | tr -s ' ' | sed -n "s/^$2 : //p" | head -1; }

# ── 1. --text on every key type ─────────────────────────────────────────────
for p in "${LANGS[@]}"; do
    for a in "${ALGOS[@]}"; do
        k="$TMP/${p}_$a.pem"; x=()
        [ "$a" = hpks-xmss ] && x=(--xmss-height 2)
        if ! ${CLI[$p]} genpkey --algo "$a" "${x[@]}" --out "$k" >/dev/null 2>"$TMP/err"; then
            fail "genpkey $a ($p): $(head -c 200 "$TMP/err")"; continue
        fi
        want_n=""
        # TODO #369: hcred's default is n = 256 in all four (Python's was 32).
        case "$a" in hkex-rnl) want_n=1024 ;; hpks-zkp-nl) want_n=8 ;; hcred) want_n=256 ;; esac
        for c in "${LANGS[@]}"; do
            out=$(${CLI[$c]} pkey --in "$k" --text 2>"$TMP/err"); rc=$?
            first=$(printf '%s\n' "$out" | head -1 | tr -s ' ')
            if [ $rc -ne 0 ]; then
                fail "pkey --text $a ($p -> $c): exit $rc: $(head -c 200 "$TMP/err")"
            elif [ "$first" != "algorithm : $a" ]; then
                fail "pkey --text $a ($p -> $c): first line '$first', want 'algorithm : $a'"
            elif [ -n "$want_n" ] && [ "$(field "$out" n)" != "$want_n" ]; then
                fail "pkey --text $a ($p -> $c): n = '$(field "$out" n)', want $want_n"
            else
                pass
            fi
        done
    done
done

# ── 2. oprf has no public key ───────────────────────────────────────────────
for c in "${LANGS[@]}"; do
    if ${CLI[$c]} pkey --in "$TMP/py_hpks.pem" --pubout --out "$TMP/ctl.pub" >/dev/null 2>&1 \
            && [ -s "$TMP/ctl.pub" ]; then
        pass
    else
        fail "accept-control: pkey --pubout on an hpks key failed ($c)"; continue
    fi
    rm -f "$TMP/o.pub"
    if ${CLI[$c]} pkey --in "$TMP/py_oprf.pem" --pubout --out "$TMP/o.pub" >/dev/null 2>"$TMP/err"; then
        fail "pkey --pubout on an oprf key exited 0 ($c)"
    elif ! grep -q "oprf has no public key" "$TMP/err"; then
        fail "pkey --pubout oprf ($c): refused, but not by name: $(head -c 200 "$TMP/err")"
    else
        pass
    fi
done

# ── 3. genpkey hpks-zkp-nl --bits ───────────────────────────────────────────
for c in py go java c; do
    for case_ in "none 8" "64 64" "256 refuse" "7 refuse"; do
        set -- $case_; b=$1; want=$2; k="$TMP/zb_${c}_$b.pem"; rm -f "$k"
        bits=(); [ "$b" != none ] && bits=(--bits "$b")
        ${CLI[$c]} genpkey --algo hpks-zkp-nl "${bits[@]}" --out "$k" >/dev/null 2>"$TMP/err"; rc=$?
        if [ "$want" = refuse ]; then
            if [ $rc -eq 0 ]; then
                fail "genpkey hpks-zkp-nl --bits $b ($c): accepted (exit 0)"
            elif ! grep -q -- "--bits must be a positive even integer <= 64, got $b" "$TMP/err"; then
                fail "genpkey hpks-zkp-nl --bits $b ($c): refused, but not by name: $(head -c 200 "$TMP/err")"
            else
                pass
            fi
        else
            got=$(field "$(${CLI[$c]} pkey --in "$k" --text 2>/dev/null)" n)
            if [ $rc -ne 0 ]; then
                fail "genpkey hpks-zkp-nl --bits $b ($c): exit $rc: $(head -c 200 "$TMP/err")"
            elif [ "$got" != "$want" ]; then
                fail "genpkey hpks-zkp-nl --bits $b ($c): n = '$got', want $want"
            else
                pass
            fi
        fi
    done
done

# ── 4. the whole dump, identical in all four CLIs ───────────────────────────
for p in "${LANGS[@]}"; do
    for a in "${ALGOS[@]}"; do
        k="$TMP/${p}_$a.pem"; [ -s "$k" ] || continue
        ref=""
        for c in "${LANGS[@]}"; do
            ${CLI[$c]} pkey --in "$k" --text > "$TMP/t_$c" 2>/dev/null
            if [ -z "$ref" ]; then ref="$TMP/t_$c"
            elif cmp -s "$ref" "$TMP/t_$c"; then pass
            else fail "pkey --text $a ($p's key): ${LANGS[0]} and $c differ: $(diff "$ref" "$TMP/t_$c" | head -3 | cut -c1-120 | tr '\n' ' ')"; fi
        done
    done
done

# ── 5. the parameter-set lines, against the spec ────────────────────────────
python3 - "$ROOT/spec/herradura-protocol-spec.json" > "$TMP/rows" <<'PYEOF'
import json, sys
for r in json.load(open(sys.argv[1]))["key_parameter_sets"]["rows"]:
    if r["default"]:
        print("%s\t%s\t%s" % (r["algo"], r["level"] or "", r["security"]))
PYEOF
for a in "${ALGOS[@]}"; do
    row=$(awk -F'\t' -v a="$a" '$1 == a' "$TMP/rows")
    for c in "${LANGS[@]}"; do
        k="$TMP/${c}_$a.pem"; [ -s "$k" ] || continue
        out=$(${CLI[$c]} pkey --in "$k" --text 2>/dev/null)
        if [ -z "$row" ]; then
            if printf '%s\n' "$out" | grep -q '^level  *:\|^security  *:'; then
                fail "pkey --text $a ($c): parameter lines on a key no row describes"
            else pass; fi
            continue
        fi
        lvl=$(printf '%s' "$row" | cut -f2); sec=$(printf '%s' "$row" | cut -f3)
        want="security  : $sec"; [ -n "$lvl" ] && want=$(printf 'level     : %s\n%s' "$lvl" "$want")
        tail_n=$(printf '%s\n' "$want" | wc -l)
        got=$(printf '%s\n' "$out" | tail -n "$tail_n")
        if [ "$got" = "$want" ]; then pass
        else fail "pkey --text $a ($c): ends '$got', want '$want'"; fi
    done
done

# ── 6. a public key is refused by label ─────────────────────────────────────
${CLI[py]} pkey --in "$TMP/py_hpks.pem" --pubout --out "$TMP/pub.pem" >/dev/null 2>&1
for c in "${LANGS[@]}"; do
    if ${CLI[$c]} pkey --in "$TMP/py_hpks.pem" --text >/dev/null 2>&1; then pass
    else fail "accept-control: pkey --text on an hpks private key failed ($c)"; fi
    for mode in --text --pubout; do
        ${CLI[$c]} pkey --in "$TMP/pub.pem" $mode --out "$TMP/x.pem" >/dev/null 2>"$TMP/err"; rc=$?
        if [ $rc -eq 0 ]; then fail "pkey $mode on a public key exited 0 ($c)"
        elif grep -qE 'Traceback|panic:|Exception in thread' "$TMP/err"; then
            fail "pkey $mode on a public key crashed ($c): $(head -c 200 "$TMP/err")"
        elif ! grep -qF "pkey: 'HERRADURA HPKS PUBLIC KEY' is a public key (pkey reads a private key)" "$TMP/err"; then
            fail "pkey $mode on a public key ($c): not refused by label: $(head -c 200 "$TMP/err")"
        else pass; fi
    done
done

echo
echo "Results: $PASS PASS / $FAIL FAIL (languages: ${LANGS[*]})"
[ "$FAIL" -eq 0 ] || exit 1
