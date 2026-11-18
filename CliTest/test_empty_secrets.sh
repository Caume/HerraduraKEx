#!/usr/bin/env bash
# CliTest/test_empty_secrets.sh — TODO #376: an empty or missing secret is
# refused by name in every CLI, never silently replaced.
#
# Until #376:
#   - genpkey --passphrase '': Python and Go read '' as "no passphrase" and
#     wrote the private key in the CLEAR (exit 0); C and Java encrypted it
#     under '', which Python and Go then could not decrypt.
#   - genpkey --kdf-iterations N without --passphrase: Python and Go ignored it.
#   - pake-register without --password: C and Go registered "demo-password";
#     Python prompted and, with no terminal, died with an EOFError traceback.
#     With --password '' C, Go and Java registered the empty password.
#   - pake-demo --password '': accepted by all four.
#
# Sections:
#   1. accept-controls: a non-empty passphrase encrypts, and every CLI's
#      envelope decrypts under every other CLI; pake-register with a password
#      and pake-demo with or without one succeed.
#   2. legacy: an envelope written under '' (as C and Java did before #376)
#      still decrypts in all four with `pkey --decrypt --passphrase ''`.
#   3. refusals, by name, with no output written and no traceback.
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
ENC_LABEL="BEGIN HERRADURA ENCRYPTED PRIVATE KEY"
CRASH='Traceback \(most recent|Exception in thread|panic:|goroutine [0-9]+ \[|\tat java\.'

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
${CLI[c]} genpkey --algo oprf --out "$TMP/oprf.pem" >/dev/null 2>&1 \
    || { echo "FAIL could not write the OPRF key fixture" >&2; exit 1; }

# ── 1. accept-controls ──────────────────────────────────────────────────────
for w in "${LANGS[@]}"; do
    if ! ${CLI[$w]} genpkey --algo hkex-gf --passphrase "pw $w" --kdf-iterations 1000 \
            --out "$TMP/env_$w.pem" >/dev/null 2>"$TMP/err"; then
        fail "genpkey --passphrase ($w): refused: $(head -c 200 "$TMP/err")"; continue
    fi
    if grep -qF "$ENC_LABEL" "$TMP/env_$w.pem"; then pass
    else fail "genpkey --passphrase ($w): output is not an encrypted envelope"; continue; fi
    ref=""
    for r in "${LANGS[@]}"; do
        if ${CLI[$r]} pkey --decrypt --passphrase "pw $w" --in "$TMP/env_$w.pem" \
                --out "$TMP/pt_${w}_$r" >/dev/null 2>"$TMP/err" \
                && grep -q "BEGIN HERRADURA" "$TMP/pt_${w}_$r" \
                && ! grep -qF "$ENC_LABEL" "$TMP/pt_${w}_$r"; then
            h=$(sha256sum < "$TMP/pt_${w}_$r" | cut -c1-64)
            if [ -z "$ref" ] || [ "$h" = "$ref" ]; then ref=$h; pass
            else fail "$w's envelope decrypts differently under $r"; fi
        else
            fail "$w's envelope does not decrypt under $r: $(head -c 200 "$TMP/err")"
        fi
    done
done
for c in "${LANGS[@]}"; do
    if ${CLI[$c]} pake-register --key "$TMP/oprf.pem" --password s3cr3t \
            --out "$TMP/rec_$c" >/dev/null 2>"$TMP/err" < /dev/null \
            && grep -q "BEGIN HERRADURA PAKE RECORD" "$TMP/rec_$c"; then pass
    else fail "pake-register --password s3cr3t ($c): $(head -c 200 "$TMP/err")"; fi
    for pw in "" "--password x"; do
        # Captured, not piped: under pipefail, `| grep -q` closing early can
        # kill the CLI with SIGPIPE before its last line.
        # shellcheck disable=SC2086  # $pw is zero or two words on purpose
        if ${CLI[$c]} pake-demo --key "$TMP/oprf.pem" $pw >"$TMP/so" 2>"$TMP/err" < /dev/null \
                && grep -q "login succeeded" "$TMP/so"; then pass
        else fail "pake-demo ${pw:-(no --password)} ($c): $(head -c 200 "$TMP/err")"; fi
    done
done

# ── 2. legacy: an envelope under '' still decrypts ──────────────────────────
# No CLI writes one any more, so build it with the Python CLI's own envelope
# writer, the routine C and Java's pre-#376 genpkey output matches.
if python3 - "$ROOT/HerraduraCli" "$TMP/env_c.pem" "pw c" "$TMP/legacy.pem" <<'EOF'
import sys, importlib.util
sys.path.insert(0, sys.argv[1])
spec = importlib.util.spec_from_file_location("hcli", sys.argv[1] + "/herradura.py")
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
plain = m._decrypt_pem(open(sys.argv[2]).read(), sys.argv[3])
open(sys.argv[4], "w").write(m._encrypt_pem(plain, "", 1000))
EOF
then
    for r in "${LANGS[@]}"; do
        if ${CLI[$r]} pkey --decrypt --passphrase '' --in "$TMP/legacy.pem" \
                --out "$TMP/lpt_$r" >/dev/null 2>"$TMP/err" \
                && cmp -s "$TMP/lpt_$r" "$TMP/pt_c_c"; then pass
        else fail "pkey --decrypt --passphrase '' ($r): legacy envelope unreadable: $(head -c 200 "$TMP/err")"; fi
    done
else
    fail "could not build the legacy '' envelope"
fi

# ── 3. refusals ─────────────────────────────────────────────────────────────
# "name | expected stderr | argv" — {O} is the output path that must not appear.
CASES=(
"genpkey --passphrase ''|genpkey: --passphrase must not be empty|genpkey --algo hkex-gf --passphrase '' --out {O}"
"genpkey --passphrase '' --kdf-iterations|genpkey: --passphrase must not be empty|genpkey --algo hkex-gf --passphrase '' --kdf-iterations 1000 --out {O}"
"genpkey --kdf-iterations alone|genpkey: --kdf-iterations requires --passphrase|genpkey --algo hkex-gf --kdf-iterations 1000 --out {O}"
"pake-register, no --password|pake-register: --password required|pake-register --key $TMP/oprf.pem --out {O}"
"pake-register --password ''|pake-register: --password must not be empty|pake-register --key $TMP/oprf.pem --password '' --out {O}"
"pake-demo --password ''|pake-demo: --password must not be empty|pake-demo --key $TMP/oprf.pem --password ''"
)
for c in "${LANGS[@]}"; do
    for case in "${CASES[@]}"; do
        name=${case%%|*}; rest=${case#*|}; want=${rest%%|*}; argv=${rest#*|}
        o="$TMP/r_$c"; rm -f "$o"
        eval "set -- ${argv//\{O\}/$o}"
        if ${CLI[$c]} "$@" >"$TMP/so" 2>"$TMP/err" < /dev/null; then
            fail "$name ($c): accepted"
        elif grep -qE "$CRASH" "$TMP/err"; then
            fail "$name ($c): crashed: $(grep -m1 -E "$CRASH" "$TMP/err")"
        elif ! grep -qF -- "$want" "$TMP/err"; then
            fail "$name ($c): refused, but not by name: $(head -c 200 "$TMP/err")"
        elif [ -e "$o" ] || grep -q "BEGIN HERRADURA\|session key" "$TMP/so"; then
            fail "$name ($c): refused, but wrote output"
        else
            pass
        fi
    done
done

echo
echo "Results: $PASS PASS / $FAIL FAIL (languages: ${LANGS[*]})"
[ "$FAIL" -eq 0 ] || exit 1
