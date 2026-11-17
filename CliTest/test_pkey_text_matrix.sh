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
#      is `algorithm : <algo>`; for hkex-rnl and hpks-zkp-nl the `n` line also
#      matches the key.
#   2. oprf has no public half: every CLI refuses `pkey --pubout` on it, after
#      an accept-control (--pubout on an hpks key succeeds).
#   3. genpkey hpks-zkp-nl --bits: omitted -> n = 8, 64 -> n = 64 (accept-
#      controls), 256 and 7 -> refused.  C has no --bits (an acknowledged
#      cli_surface_gaps row), so this section runs on py, go and java only.
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
        # Python's HCRED default is n = 32; C and Java support n = 256 only and
        # refuse it by name (the TUTORIAL's HCRED section).  Not this test's subject.
        [ "$a" = hcred ] && [ "$p" = py ] && x=(--bits 256)
        if ! ${CLI[$p]} genpkey --algo "$a" "${x[@]}" --out "$k" >/dev/null 2>"$TMP/err"; then
            fail "genpkey $a ($p): $(head -c 200 "$TMP/err")"; continue
        fi
        want_n=""
        case "$a" in hkex-rnl) want_n=1024 ;; hpks-zkp-nl) want_n=8 ;; esac
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
for c in py go java; do
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

echo
echo "Results: $PASS PASS / $FAIL FAIL (languages: ${LANGS[*]})"
[ "$FAIL" -eq 0 ] || exit 1
