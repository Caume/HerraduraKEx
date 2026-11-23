#!/usr/bin/env bash
# CliTest/test_arg_hygiene.sh — TODO #381: one rule for the SHAPE of a command
# line, in every CLI.
#
# Until #381:
#   - C read a directory as an empty file: `sign --in .` signed the empty
#     message and `dgst --in .` printed the empty-input digest, exit 0.
#   - A value-taking flag with no value: Java stored a trailing `--out` as the
#     string "true" and genpkey wrote the private key to a file named `true`;
#     C ignored it and wrote to stdout.  `--out --algo hpks` gave Go and C an
#     output file named "--algo".
#   - Stray positional arguments were ignored by C and Go (Go stopped parsing at
#     the first one, so `genpkey extra --algo hpks` ran without its --algo) and
#     folded into the previous value by Java (`--algo "hpks extra"`).
#   - `--flag=value` worked in Python and Go only; Go also read `--pubout=x`.
#   - Go defaulted 19 --in / --out flags to "-": an omitted --in read stdin and
#     an omitted --out wrote stdout, where Python and Java refused.  C did the
#     same for enc, dec and sign --out.
#
# The rule now, in all four:
#   - `--in DIR` is refused ("Is a directory").
#   - A value-taking flag needs a value: at the end of argv, or followed by
#     another flag of its subcommand, it is refused.
#   - A token that is neither a flag nor a flag's value is refused.
#   - `--flag=value` is `--flag value`; a boolean flag takes no value.
#   - A flag Python's argparse requires is required in every CLI; stdin and
#     stdout are spelled `-`.
# Python's refusals come from argparse in its own words, so each case accepts
# argparse's message for Python and the shared one for C, Go and Java.
#
# Sections:
#   1. accept-controls: one complete command per subcommand runs in every CLI;
#      `--flag=value` gives the same result as `--flag value`; `-` reads stdin
#      and writes stdout.
#   2. refusals, by name, with no output written and no crash.
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
CRASH='Traceback \(most recent|Exception in thread|panic:|goroutine [0-9]+ \[|\tat java\.'

T=$(mktemp -d)
trap 'rm -rf "$T"' EXIT
PY=${CLI[py]}; CC=${CLI[c]}

# ── fixtures (C) ────────────────────────────────────────────────────────────
fix() { "$@" >/dev/null 2>&1 || { echo "FAIL fixture: $*" >&2; exit 1; }; }
fix $CC genpkey --algo hkex-gf --out $T/a.pem;  fix $CC pkey --in $T/a.pem --pubout --out $T/ap.pem
fix $CC genpkey --algo hkex-gf --out $T/b.pem;  fix $CC pkey --in $T/b.pem --pubout --out $T/bp.pem
fix $CC kex --algo hkex-gf --our $T/a.pem --their $T/bp.pem --out $T/sk.pem
fix $CC genpkey --algo hpks --out $T/s.pem;     fix $CC pkey --in $T/s.pem --pubout --out $T/sp.pem
printf 'hello' > $T/m; head -c 32 /dev/urandom > $T/m32; mkdir $T/dir
fix $CC sign --algo hpks --key $T/s.pem --in $T/m --out $T/sig.pem
fix $CC enc --algo hske --key $T/sk.pem --in $T/m --out $T/ct.pem
fix $CC encfile --key $T/sk.pem --in $T/m --out $T/ef.hkx
fix $CC genpkey --algo hpks-nl --out $T/ka.pem; fix $CC genpkey --algo hpks-nl --out $T/kb.pem
fix $CC threshold-commit --key $T/ka.pem --commit-out $T/ca.pem --nonce-out $T/na.pem
fix $CC threshold-commit --key $T/kb.pem --commit-out $T/cb.pem --nonce-out $T/nb.pem
fix $CC threshold-aggregate --commit $T/ca.pem --commit $T/cb.pem --in $T/m --out $T/agg.pem
fix $CC threshold-respond --key $T/ka.pem --commit $T/ca.pem --commit $T/cb.pem \
        --aggregate $T/agg.pem --nonce $T/na.pem --out $T/pa.pem
fix $CC threshold-respond --key $T/kb.pem --commit $T/ca.pem --commit $T/cb.pem \
        --aggregate $T/agg.pem --nonce $T/nb.pem --out $T/pb.pem
fix $CC genpkey --algo oprf --out $T/oprf.pem
fix $CC oprf-blind --in $T/m --out $T/state.pem
fix $CC oprf-eval --key $T/oprf.pem --in $T/state.pem --out $T/eval.pem
fix $CC genpkey --algo hcred --out $T/u.pem;    fix $CC pkey --pubout --in $T/u.pem --out $T/up.pem
fix $CC genpkey --algo hpks-stern --out $T/is.pem
fix $CC cred-prove --in $T/u.pem --msg x --rounds 1 --out $T/pr.pem

# "subcommand | flags Python's argparse requires | a complete command" -- {O}
# and {P} are output paths.  Each required flag is a flag followed by ONE value.
CMDS=(
"genpkey|--algo|genpkey --algo hpks --out {O}"
"pkey|--in|pkey --in $T/a.pem --pubout --out {O}"
"kex|--algo --our --their --out|kex --algo hkex-gf --our $T/a.pem --their $T/bp.pem --out {O}"
"enc|--algo --in --out|enc --algo hske --key $T/sk.pem --in $T/m --out {O}"
"dec|--algo --in --out|dec --algo hske --key $T/sk.pem --in $T/ct.pem --out {O}"
"sign|--algo --key --in --out|sign --algo hpks --key $T/s.pem --in $T/m --out {O}"
"verify|--algo --in --sig|verify --algo hpks --pubkey $T/sp.pem --in $T/m --sig $T/sig.pem"
"threshold-commit|--key --commit-out --nonce-out|threshold-commit --key $T/ka.pem --commit-out {O} --nonce-out {P}"
"threshold-aggregate|--in --out|threshold-aggregate --commit $T/ca.pem --commit $T/cb.pem --in $T/m --out {O}"
"threshold-respond|--key --aggregate --nonce --out|threshold-respond --key $T/ka.pem --commit $T/ca.pem --commit $T/cb.pem --aggregate $T/agg.pem --nonce $T/na.pem --out {O}"
"threshold-combine|--aggregate --out|threshold-combine --aggregate $T/agg.pem --partial $T/pa.pem --partial $T/pb.pem --out {O}"
"encfile|--key --in --out|encfile --key $T/sk.pem --in $T/m --out {O}"
"decfile|--key --in --out|decfile --key $T/sk.pem --in $T/ef.hkx --out {O}"
"dgst|--in|dgst --in $T/m"
"fpe|--key --in|fpe --key $T/sk.pem --in $T/m32 --encrypt --out {O}"
"twk|--key --in|twk --key $T/sk.pem --in $T/m32 --encrypt --out {O}"
"oprf-blind|--in|oprf-blind --in $T/m --out {O}"
"oprf-eval|--key --in|oprf-eval --key $T/oprf.pem --in $T/state.pem --out {O}"
"oprf-unblind|--state --eval|oprf-unblind --state $T/state.pem --eval $T/eval.pem"
"pake-register|--key|pake-register --key $T/oprf.pem --password pw --out {O}"
"pake-demo|--key|pake-demo --key $T/oprf.pem --password pw"
"cred-issue|--our --in|cred-issue --our $T/is.pem --in $T/up.pem --out {O}"
"cred-prove|--in|cred-prove --in $T/u.pem --msg x --rounds 1 --out {O}"
"cred-verify|--proof --pubkey|cred-verify --proof $T/pr.pem --pubkey $T/up.pem --msg x --min-rounds 1"
)
outs() { local s=${1//\{O\}/$T/o1}; printf '%s' "${s//\{P\}/$T/o2}"; }

# ── 1. accept-controls ──────────────────────────────────────────────────────
for c in "${LANGS[@]}"; do
    for e in "${CMDS[@]}"; do
        sub=${e%%|*}; argv=$(outs "${e##*|}")
        # shellcheck disable=SC2086  # argv is a word list on purpose
        if ${CLI[$c]} $argv >"$T/so" 2>"$T/err" < /dev/null; then pass
        else fail "$sub ($c): the complete command was refused: $(head -c 200 "$T/err")"; fi
    done
    # --flag=value is --flag value.
    if ${CLI[$c]} dgst --algo=hfscx-256 --in="$T/m" >"$T/eq" 2>"$T/err" \
            && ${CLI[$c]} dgst --algo hfscx-256 --in "$T/m" >"$T/sp" 2>>"$T/err" \
            && [ -s "$T/eq" ] && cmp -s "$T/eq" "$T/sp"; then pass
    else fail "dgst --in=FILE ($c): not the same as --in FILE: $(head -c 200 "$T/err")"; fi
    rm -f "$T/eqk.pem"
    if ${CLI[$c]} pkey --in="$T/s.pem" --pubout --out="$T/eqk.pem" >/dev/null 2>"$T/err" \
            && cmp -s "$T/eqk.pem" "$T/sp.pem"; then pass
    else fail "pkey --in=FILE --out=FILE ($c): $(head -c 200 "$T/err")"; fi
    # "-" reads stdin and writes stdout.
    if ${CLI[$c]} dgst --in - < "$T/m" >"$T/sd" 2>"$T/err" && cmp -s "$T/sd" "$T/sp"; then pass
    else fail "dgst --in - ($c): stdin not read: $(head -c 200 "$T/err")"; fi
    if ${CLI[$c]} enc --algo hske --key "$T/sk.pem" --in - --out - < "$T/m" >"$T/so.pem" 2>"$T/err" \
            && ${CLI[$c]} dec --algo hske --key "$T/sk.pem" --in "$T/so.pem" --out "$T/pt" 2>>"$T/err" \
            && [ "$(head -c 5 "$T/pt")" = hello ]; then pass
    else fail "enc --in - --out - ($c): $(head -c 200 "$T/err")"; fi
done

# ── 2. refusals ─────────────────────────────────────────────────────────────
# "name | shared message (C, Go, Java) | Python's (argparse) | argv"; both are
# fixed strings, and "{F}" in a message is the flag under test.
CASES=()
for e in "${CMDS[@]}"; do
    sub=${e%%|*}; r=${e#*|}; req=${r%%|*}; argv=${r#*|}
    for f in $req; do
        # shellcheck disable=SC2001
        d=$(printf '%s\n' "$argv" | sed -E "s# $f [^ ]+##")
        CASES+=("$sub without $f|$f|$f|$d")
    done
done
for spec in "sign|sign --algo hpks --key $T/s.pem --in $T/dir --out {O}" \
            "enc|enc --algo hske --key $T/sk.pem --in $T/dir --out {O}" \
            "encfile|encfile --key $T/sk.pem --in $T/dir --out {O}" \
            "dgst|dgst --in $T/dir" \
            "oprf-blind|oprf-blind --in $T/dir --out {O}"; do
    CASES+=("${spec%%|*} --in DIR|Is a directory|Is a directory|${spec#*|}")
done
CASES+=(
"genpkey, --out at the end|--out needs a value|--out: expected one argument|genpkey --algo hpks --out"
"genpkey, --out before --algo|--out needs a value|--out: expected one argument|genpkey --out --algo hpks"
"dgst, --in at the end|--in needs a value|--in: expected one argument|dgst --in"
"threshold-aggregate, empty --commit|--commit needs a value|--commit: expected at least one argument|threshold-aggregate --commit --in $T/m --out {O}"
"genpkey, stray after --algo|unexpected argument 'extra'|unrecognized arguments: extra|genpkey --algo hpks extra --out {O}"
"genpkey, stray before --algo|unexpected argument 'extra'|unrecognized arguments: extra|genpkey extra --algo hpks --out {O}"
"pkey, stray after a boolean|unexpected argument 'extra'|unrecognized arguments: extra|pkey --in $T/s.pem --pubout extra --out {O}"
"pkey --pubout=x|--pubout takes no value|--pubout: ignored explicit argument 'x'|pkey --in $T/s.pem --pubout=x --out {O}"
"enc --aead=false|--aead takes no value|--aead: ignored explicit argument 'false'|enc --algo hske-nla1 --key $T/sk.pem --in $T/m --aead=false --out {O}"
)

for c in "${LANGS[@]}"; do
    for case in "${CASES[@]}"; do
        IFS='|' read -r name want want_py argv <<< "$case"
        [ "$c" = py ] && want=$want_py
        o="$T/o1"; rm -f "$T/o1" "$T/o2" "$ROOT/true"
        # shellcheck disable=SC2086
        if ${CLI[$c]} $(outs "$argv") >"$T/so" 2>"$T/err" < /dev/null; then
            fail "$name ($c): accepted"
        elif grep -qE "$CRASH" "$T/err"; then
            fail "$name ($c): crashed: $(grep -m1 -E "$CRASH" "$T/err")"
        elif ! grep -qiF -- "$want" "$T/err"; then
            fail "$name ($c): refused, but not by name: $(head -c 200 "$T/err")"
        elif [[ $name == *without* ]] && ! grep -qi "required" "$T/err"; then
            fail "$name ($c): refused, but not as a missing flag: $(head -c 200 "$T/err")"
        elif [ -e "$o" ] || [ -e "$T/o2" ] || [ -e "$ROOT/true" ] || grep -q "BEGIN HERRADURA" "$T/so"; then
            fail "$name ($c): refused, but wrote output"
        else
            pass
        fi
    done
done

echo
echo "Results: $PASS PASS / $FAIL FAIL (languages: ${LANGS[*]})"
[ "$FAIL" -eq 0 ] || exit 1
