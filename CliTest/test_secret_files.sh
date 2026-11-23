#!/usr/bin/env bash
# CliTest/test_secret_files.sh — TODO #396: passphrases and passwords from a file.
#
# Until #396 the only way to give genpkey/pkey a passphrase, or pake-register/
# pake-demo a password, was on the command line, where any local user can read
# it (ps, /proc/<pid>/cmdline) and where it lands in shell history.  Each now
# takes a file form, --passphrase-file / --password-file (`-` = stdin), with one
# meaning in all four CLIs:
#
#   the secret is the file's bytes with at most ONE trailing \n or \r\n removed;
#   refused: both forms given, `-` when another input is stdin, an unreadable
#   file, more than 1024 bytes, a NUL, any other CR/LF, invalid UTF-8.
#   Then the inline flag's own checks (#376) apply unchanged.
#
# Sections, per CLI:
#   1. accept-controls: a key encrypted inline decrypts from the file form and
#      the reverse, to the same bytes; CRLF and stdin; exactly 1024 bytes; a
#      non-ASCII UTF-8 passphrase written by C decrypts in every CLI from a file;
#      pake-register and pake-demo take the file form.
#   2. refusals: each case is refused with the shared message, writes no output,
#      and does not crash.
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

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
F="$TMP/fx"; mkdir -p "$F"
C=${CLI[c]}
fx() { "$@" >/dev/null 2>"$TMP/fx_err" || { echo "FAIL fixture: $*: $(head -c 300 "$TMP/fx_err")" >&2; exit 1; }; }

# ── fixtures ────────────────────────────────────────────────────────────────
printf 'pw\n'   > "$F/pw_lf"
printf 'pw\r\n' > "$F/pw_crlf"
printf 'pw'     > "$F/pw_bare"
printf 'p\xc3\xa4ssw\xc3\xb6rd\n' > "$F/pw_utf8"          # "pässwörd"
head -c 1024 /dev/zero | tr '\0' a > "$F/pw_1024"
{ head -c 1024 /dev/zero | tr '\0' a; printf '\n'; } > "$F/pw_1024_lf"
head -c 1025 /dev/zero | tr '\0' a > "$F/bad_1025"
printf 'a\nb\n' > "$F/bad_twoline"
printf 'a\rb'   > "$F/bad_cr"
printf 'a\0b'   > "$F/bad_nul"
printf '\xff\xfe' > "$F/bad_utf8"
printf '\xed\xa0\x80' > "$F/bad_surrogate"               # U+D800, refused by strict UTF-8
printf '\xc0\xaf' > "$F/bad_overlong"
printf '\n'     > "$F/empty_lf"
fx $C genpkey --algo oprf --out "$F/oprf.pem"
fx $C genpkey --algo hkex-gf --passphrase "$(printf 'p\xc3\xa4ssw\xc3\xb6rd')" --kdf-iterations 1 \
    --out "$F/c_utf8.pem"
fx $C pkey --decrypt --passphrase "$(printf 'p\xc3\xa4ssw\xc3\xb6rd')" --in "$F/c_utf8.pem" \
    --out "$F/c_utf8_plain.pem"

for L in "${LANGS[@]}"; do
    X=${CLI[$L]}
    D="$TMP/$L"; mkdir -p "$D"

    # ── 1. accept-controls ──────────────────────────────────────────────────
    if $X genpkey --algo hkex-gf --passphrase pw --kdf-iterations 1 --out "$D/inl.pem" 2>/dev/null \
       && $X pkey --decrypt --passphrase pw --in "$D/inl.pem" --out "$D/inl_plain.pem" 2>/dev/null; then
        pass
        for pf in pw_lf pw_crlf pw_bare; do
            if $X pkey --decrypt --passphrase-file "$F/$pf" --in "$D/inl.pem" --out "$D/f_$pf.pem" 2>/dev/null \
               && cmp -s "$D/inl_plain.pem" "$D/f_$pf.pem"; then pass
            else fail "pkey --decrypt --passphrase-file $pf matches inline ($L)"; fi
        done
        if $X pkey --decrypt --passphrase-file - --in "$D/inl.pem" --out "$D/stdin.pem" < "$F/pw_lf" 2>/dev/null \
           && cmp -s "$D/inl_plain.pem" "$D/stdin.pem"; then pass
        else fail "pkey --decrypt --passphrase-file - ($L)"; fi
    else
        fail "inline genpkey/pkey --passphrase accept-control ($L)"
    fi
    if $X genpkey --algo hkex-gf --passphrase-file "$F/pw_lf" --kdf-iterations 1 --out "$D/fil.pem" 2>/dev/null \
       && $X pkey --decrypt --passphrase pw --in "$D/fil.pem" --out /dev/null 2>/dev/null; then pass
    else fail "genpkey --passphrase-file, decrypted inline ($L)"; fi
    if $X genpkey --algo hkex-gf --passphrase-file "$F/pw_1024" --kdf-iterations 1 --out "$D/k1024.pem" 2>/dev/null \
       && $X pkey --decrypt --passphrase-file "$F/pw_1024_lf" --in "$D/k1024.pem" --out /dev/null 2>/dev/null; then pass
    else fail "a 1024-byte passphrase file is accepted ($L)"; fi
    if $X pkey --decrypt --passphrase-file "$F/pw_utf8" --in "$F/c_utf8.pem" --out "$D/utf8.pem" 2>/dev/null \
       && cmp -s "$F/c_utf8_plain.pem" "$D/utf8.pem"; then pass
    else fail "a UTF-8 passphrase C took inline decrypts from a file ($L)"; fi
    if $X pake-register --key "$F/oprf.pem" --password-file "$F/pw_lf" --out "$D/rec.pem" 2>/dev/null \
       && grep -q "BEGIN HERRADURA PAKE RECORD" "$D/rec.pem"; then pass
    else fail "pake-register --password-file ($L)"; fi
    # Captured, not piped: under pipefail, `| grep -q` exiting at the first match
    # would SIGPIPE the CLI's second line and fail the cell at random.
    if $X pake-demo --key "$F/oprf.pem" --password-file "$F/pw_lf" >"$D/demo.txt" 2>/dev/null \
       && grep -q "login succeeded" "$D/demo.txt"; then pass
    else fail "pake-demo --password-file ($L)"; fi

    # ── 2. refusals ─────────────────────────────────────────────────────────
    # refuse <name> <expected stderr substring> <cmd...>; output goes to $D/out
    refuse() {
        local name=$1 want=$2; shift 2
        rm -f "$D/out"
        "$@" >"$TMP/so" 2>"$TMP/se" </dev/null
        local rc=$?
        if [ $rc -eq 0 ]; then fail "$name: accepted ($L)"; return; fi
        if grep -Eq "$CRASH" "$TMP/se"; then fail "$name: crashed ($L): $(head -c 200 "$TMP/se")"; return; fi
        if ! grep -qF -- "$want" "$TMP/se"; then fail "$name: message ($L): $(head -c 200 "$TMP/se")"; return; fi
        if [ -e "$D/out" ]; then fail "$name: wrote output ($L)"; return; fi
        pass
    }
    G="genpkey --algo hkex-gf --kdf-iterations 1 --out $D/out"
    refuse "both forms" "genpkey: give only one of --passphrase or --passphrase-file" \
        $X $G --passphrase pw --passphrase-file "$F/pw_lf"
    refuse "unreadable" "genpkey: cannot read --passphrase-file $TMP/nope" \
        $X $G --passphrase-file "$TMP/nope"
    refuse "1025 bytes" "genpkey: --passphrase-file holds more than 1024 bytes" \
        $X $G --passphrase-file "$F/bad_1025"
    refuse "two lines" "genpkey: --passphrase-file must hold one line" \
        $X $G --passphrase-file "$F/bad_twoline"
    refuse "bare CR" "genpkey: --passphrase-file must hold one line" \
        $X $G --passphrase-file "$F/bad_cr"
    refuse "NUL" "genpkey: --passphrase-file holds a NUL byte" \
        $X $G --passphrase-file "$F/bad_nul"
    refuse "invalid UTF-8" "genpkey: --passphrase-file is not valid UTF-8" \
        $X $G --passphrase-file "$F/bad_utf8"
    refuse "surrogate" "genpkey: --passphrase-file is not valid UTF-8" \
        $X $G --passphrase-file "$F/bad_surrogate"
    refuse "overlong" "genpkey: --passphrase-file is not valid UTF-8" \
        $X $G --passphrase-file "$F/bad_overlong"
    refuse "empty after the line ending (#376)" "genpkey: --passphrase must not be empty" \
        $X $G --passphrase-file "$F/empty_lf"
    refuse "pkey both forms" "pkey: give only one of --passphrase or --passphrase-file" \
        $X pkey --decrypt --passphrase pw --passphrase-file "$F/pw_lf" --in "$D/fil.pem" --out "$D/out"
    refuse "pkey stdin twice" "pkey: --passphrase-file -: another input already reads stdin" \
        $X pkey --decrypt --passphrase-file - --in - --out "$D/out"
    refuse "pkey without --decrypt" "pkey: --passphrase is only meaningful with --decrypt" \
        $X pkey --passphrase-file "$F/pw_lf" --in "$D/inl_plain.pem" --pubout --out "$D/out"
    refuse "pkey wrong passphrase from a file" "pkey --decrypt: wrong passphrase or corrupted/tampered file" \
        $X pkey --decrypt --passphrase-file "$F/pw_utf8" --in "$D/fil.pem" --out "$D/out"
    refuse "pake-register both forms" "pake-register: give only one of --password or --password-file" \
        $X pake-register --key "$F/oprf.pem" --password pw --password-file "$F/pw_lf" --out "$D/out"
    refuse "pake-register empty (#376)" "pake-register: --password must not be empty" \
        $X pake-register --key "$F/oprf.pem" --password-file "$F/empty_lf" --out "$D/out"
    refuse "pake-register stdin twice" "pake-register: --password-file -: another input already reads stdin" \
        $X pake-register --key - --password-file - --out "$D/out"
    refuse "pake-demo empty (#376)" "pake-demo: --password must not be empty" \
        $X pake-demo --key "$F/oprf.pem" --password-file "$F/empty_lf"
    refuse "pake-demo stdin twice" "pake-demo: --password-file -: another input already reads stdin" \
        $X pake-demo --key - --password-file -
done

echo "Results: $PASS PASS / $FAIL FAIL (languages: ${LANGS[*]})"
hkx_require_asserted "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
