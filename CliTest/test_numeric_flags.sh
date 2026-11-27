#!/usr/bin/env bash
# CliTest/test_numeric_flags.sh — TODO #380: every numeric flag is a decimal
# integer in a stated range, parsed the same way by all four CLIs.
#
# Until #380 no CLI had one strict parser.  C mixed atoi and strtol with no
# end-pointer check, so `rand --bytes abc` wrote 0 bytes and exited 0.  Go's
# flag.Int read 0x10 as 16.  Python and Go read an explicit `sign --rounds 0`
# as omitted and signed at 219; Java wrote a 0-round signature; Go and Java
# signed 5000 rounds, which every verifier refuses; Python crashed on -1 and
# hung on 100000.  Python's genpkey took --kdf-iterations 0 and wrote an
# envelope only it would read.  Now each flag goes through one parser per CLI
# (C dec_range_arg, Go decRangeArg, Java decRangeArg, Python _dec_range_arg):
#
#   genpkey --kdf-iterations   1..100000000
#   genpkey --xmss-height      1..20
#   rand --bytes               0..33554432 (one seed's worth of DRBG output)
#   sign / cred-issue / cred-prove --rounds, verify / cred-verify --min-rounds,
#   cred-verify --rounds (C, Go)                                      1..4096
#
# (twk --sector / --bidx: test_twk_tweak_range.sh, TODO #375.  genpkey --bits
# belongs to TODO #379.)
#
# Sections:
#   1. accept-controls: the low edge (and 007) of each range works in every CLI.
#   2. refusals: 12 bad values per flag site, each refused by the shared message,
#      with no output written and no crash.
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
# A refusal is immediate; an answer that takes this long is the bug (Python
# used to hang on `sign --rounds 100000` and `--kdf-iterations 99999999999`).
T=${HKX_NUM_TIMEOUT:-60}
CRASH='Traceback \(most recent|Exception in thread|panic:|goroutine [0-9]+ \[|\tat java\.'

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
F="$TMP/fx"; mkdir -p "$F"

# ── fixtures (C, the fast CLI) ──────────────────────────────────────────────
C=${CLI[c]}
fx() { "$@" >/dev/null 2>"$TMP/fx_err" || { echo "FAIL fixture: $*: $(head -c 300 "$TMP/fx_err")" >&2; exit 1; }; }
head -c 32 /dev/urandom > "$F/seed.bin"
printf 'numeric flags' > "$F/msg.bin"
fx $C genpkey --algo hpks-stern --out "$F/st.pem"
fx $C pkey --in "$F/st.pem" --pubout --out "$F/st_pub.pem"
fx $C genpkey --algo hpks-stern --out "$F/st2.pem"
fx $C pkey --in "$F/st2.pem" --pubout --out "$F/st2_pub.pem"
fx $C genpkey --algo hpks-zkp-nl --out "$F/zk.pem"
fx $C genpkey --algo hcred --out "$F/hc.pem"
fx $C pkey --in "$F/hc.pem" --pubout --out "$F/hc_pub.pem"
fx $C sign --algo hpks-stern --rounds 2 --key "$F/st.pem" --in "$F/msg.bin" --out "$F/sig.pem"
fx $C cred-issue --our "$F/st.pem" --in "$F/hc_pub.pem" --rounds 2 --out "$F/cred.pem"
fx $C cred-prove --in "$F/hc.pem" --msg m --rounds 2 --out "$F/proof.pem"

# ── 1. accept-controls ──────────────────────────────────────────────────────
ok() { # ok LABEL CMD... : the command must exit 0 without crashing
    local label=$1; shift
    if timeout "$T" "$@" >"$TMP/so" 2>"$TMP/err" < /dev/null && ! grep -qE "$CRASH" "$TMP/err"; then pass
    else fail "$label: $(head -c 200 "$TMP/err")"; fi
}
ref64=""; ref7=""
for c in "${LANGS[@]}"; do
    X=${CLI[$c]}
    ok "rand --bytes 0 ($c)" $X rand --seed "$F/seed.bin" --bytes 0 --out "$TMP/r0_$c"
    if [ -e "$TMP/r0_$c" ] && [ ! -s "$TMP/r0_$c" ]; then pass
    else fail "rand --bytes 0 ($c): output is not empty"; fi
    for spec in "64:r64" "7:r7" "007:r007"; do
        ok "rand --bytes ${spec%%:*} ($c)" $X rand --seed "$F/seed.bin" --bytes "${spec%%:*}" \
            --out "$TMP/${spec#*:}_$c"
    done
    h=$(sha256sum < "$TMP/r64_$c" | cut -c1-64)
    if [ -z "$ref64" ] || [ "$h" = "$ref64" ]; then ref64=$h; pass
    else fail "rand --bytes 64 ($c): output differs from the other CLIs"; fi
    if [ "$(wc -c < "$TMP/r7_$c")" -eq 7 ] && cmp -s "$TMP/r7_$c" "$TMP/r007_$c"; then pass
    else fail "rand --bytes 007 ($c) is not --bytes 7"; fi

    ok "genpkey --kdf-iterations 1 ($c)" $X genpkey --algo hkex-gf --passphrase p \
        --kdf-iterations 1 --out "$TMP/env_$c"
    ok "pkey --decrypt of a 1-iteration envelope ($c)" $X pkey --decrypt --passphrase p \
        --in "$TMP/env_$c" --out "$TMP/envpt_$c"
    ok "genpkey --xmss-height 1 ($c)" $X genpkey --algo hpks-xmss --xmss-height 1 --out "$TMP/xm_$c"

    for a in hpks-stern nl-zkboo nl-zkbpp hpks-ring; do
        k="$F/st.pem"; ring=(); case $a in nl-*) k="$F/zk.pem" ;; esac
        [ "$a" = hpks-ring ] && ring=(--ring "$F/st_pub.pem,$F/st2_pub.pem")
        ok "sign --algo $a --rounds 1 ($c)" $X sign --algo "$a" --key "$k" "${ring[@]}" \
            --in "$F/msg.bin" --rounds 1 --out "$TMP/s_${a}_$c"
    done
    ok "verify --min-rounds 1 of $c's 1-round hpks-stern ($c)" $X verify --algo hpks-stern \
        --pubkey "$F/st_pub.pem" --in "$F/msg.bin" --sig "$TMP/s_hpks-stern_$c" --min-rounds 1
    ok "cred-issue --rounds 1 ($c)" $X cred-issue --our "$F/st.pem" --in "$F/hc_pub.pem" \
        --rounds 1 --out "$TMP/cred_$c"
    ok "cred-prove --rounds 1 ($c)" $X cred-prove --in "$F/hc.pem" --msg m --rounds 1 \
        --out "$TMP/proof_$c"
    ok "cred-verify --min-rounds 1 of $c's 1-round artifacts ($c)" $X cred-verify \
        --proof "$TMP/proof_$c" --pubkey "$F/hc_pub.pem" --cred "$TMP/cred_$c" \
        --issuer "$F/st_pub.pem" --msg m --min-rounds 1
done
for c in c go; do   # cred-verify --rounds exists in C and Go only
    ok "cred-verify --rounds 2 of a 2-round proof ($c)" ${CLI[$c]} cred-verify --rounds 2 \
        --proof "$F/proof.pem" --pubkey "$F/hc_pub.pem" --msg m --min-rounds 2
done

# ── 2. refusals ─────────────────────────────────────────────────────────────
# "cmd|flag|lo|hi|langs|argv"; {V} is the value under test, {O} an output path.
SITES=(
"genpkey|--kdf-iterations|1|100000000|py c go java|genpkey --algo hkex-gf --passphrase p --kdf-iterations {V} --out {O}"
"genpkey|--xmss-height|1|20|py c go java|genpkey --algo hpks-xmss --xmss-height {V} --out {O}"
"rand|--bytes|0|33554432|py c go java|rand --seed $F/seed.bin --bytes {V} --out {O}"
"sign|--rounds|1|4096|py c go java|sign --algo hpks-stern --key $F/st.pem --in $F/msg.bin --rounds {V} --out {O}"
"sign|--rounds|1|4096|py c go java|sign --algo hpks-ring --key $F/st.pem --ring $F/st_pub.pem,$F/st2_pub.pem --in $F/msg.bin --rounds {V} --out {O}"
"sign|--rounds|1|4096|py c go java|sign --algo nl-zkboo --key $F/zk.pem --in $F/msg.bin --rounds {V} --out {O}"
"sign|--rounds|1|4096|py c go java|sign --algo nl-zkbpp --key $F/zk.pem --in $F/msg.bin --rounds {V} --out {O}"
"verify|--min-rounds|1|4096|py c go java|verify --algo hpks-stern --pubkey $F/st_pub.pem --in $F/msg.bin --sig $F/sig.pem --min-rounds {V}"
"cred-issue|--rounds|1|4096|py c go java|cred-issue --our $F/st.pem --in $F/hc_pub.pem --rounds {V} --out {O}"
"cred-prove|--rounds|1|4096|py c go java|cred-prove --in $F/hc.pem --msg m --rounds {V} --out {O}"
"cred-verify|--min-rounds|1|4096|py c go java|cred-verify --proof $F/proof.pem --pubkey $F/hc_pub.pem --msg m --min-rounds {V}"
"cred-verify|--rounds|1|4096|c go|cred-verify --proof $F/proof.pem --pubkey $F/hc_pub.pem --msg m --min-rounds 2 --rounds {V}"
)
BAD=(-1 abc +1 0x10 " 1" "" 1e3 1.5 1_0 18446744073709551616)
for site in "${SITES[@]}"; do
    IFS='|' read -r cmd flag lo hi langs argv <<< "$site"
    vals=("${BAD[@]}" "$((hi + 1))")
    [ "$lo" -gt 0 ] && vals+=("$((lo - 1))")
    for c in $langs; do
        for v in "${vals[@]}"; do
            o="$TMP/out_$c"; rm -f "$o"
            # Split argv on spaces ({V} is substituted after, so it may hold any
            # value, including a space or nothing at all).
            read -r -a words <<< "${argv//\{O\}/$o}"
            for i in "${!words[@]}"; do [ "${words[$i]}" = "{V}" ] && words[$i]=$v; done
            want="$cmd: $flag must be a decimal integer from $lo to $hi, got '$v'"
            timeout "$T" ${CLI[$c]} "${words[@]}" >"$TMP/so" 2>"$TMP/err" < /dev/null
            rc=$?
            if [ "$rc" -eq 124 ]; then
                fail "$cmd $flag '$v' ($c, ${argv%% --*}): no answer in ${T}s"
            elif [ "$rc" -eq 0 ]; then
                fail "$cmd $flag '$v' ($c, ${argv%% --*}): accepted"
            elif grep -qE "$CRASH" "$TMP/err"; then
                fail "$cmd $flag '$v' ($c): crashed: $(grep -m1 -E "$CRASH" "$TMP/err")"
            elif ! grep -qF -- "$want" "$TMP/err"; then
                fail "$cmd $flag '$v' ($c, ${argv%% --*}): refused, but not by the shared message: $(tail -1 "$TMP/err" | head -c 200)"
            elif [ -e "$o" ] || grep -q "BEGIN HERRADURA" "$TMP/so"; then
                fail "$cmd $flag '$v' ($c): refused, but wrote output"
            else
                pass
            fi
        done
    done
done

echo
echo "Results: $PASS PASS / $FAIL FAIL (languages: ${LANGS[*]})"
[ "$FAIL" -eq 0 ] || exit 1
