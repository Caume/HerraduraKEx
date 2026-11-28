#!/usr/bin/env bash
# CliTest/test_ots_state.sh — TODO #419, #420: a one-time-signature key's state
# is read fail-CLOSED, and a one-time key must be a file.
#
# <key>.idx is the only thing that stops a WOTS key signing twice or an XMSS
# key reusing a leaf.  Every port used to read it fail-OPEN: a missing, empty or
# unparseable file read as 0 (unused), and the four parsers disagreed on the
# same bytes (Go refused `garbage`, C refused `1x`, Python and Java signed).  An
# empty file is what a crash between O_TRUNC and the data reaching disk leaves.
# And with the key on stdin (`--key -`) there is no path to put the sidecar
# beside: C and Go kept the state in ./-.idx, shared by every key ever piped in
# from that directory, and Java kept none, so a WOTS key read from stdin signed
# twice.
#
# Cells, per CLI:
#   accept  a fresh WOTS key signs (.idx `0\n` -> `1\n`); `0` with no newline
#           signs; a fresh XMSS key (h = 2) signs at leaf 0 (.idx -> 1); `3\n`
#           signs at the last leaf (.idx -> 4).
#   damaged (WOTS) missing, empty, `garbage`, `1x`, `-1`, ` 0`, `0 `, `00`,
#           `01`, `0\n\n`, `0\r\n`, `+0`, `2`, `99999999999`, a symlink to a
#           file holding `0\n`, a directory, a FIFO (refused, not a hang:
#           every reader opens before it checks, CodeQL toctou, TODO #427 --
#           C and Python with O_NONBLOCK, Go and Java under a 3 s open
#           deadline, so this cell reaches the open itself; with the deadline
#           removed both hang here); (XMSS) missing, empty, `garbage`,
#           `-1`, `01`, `5` (> 2^h).  Each must exit non-zero, write NO
#           signature, and leave the .idx exactly as it was.
#   used    WOTS `1` and XMSS `4` (= 2^h, exhausted) are refused the same way.
#   stdin   sign --key - and --key /dev/stdin (WOTS, XMSS), genpkey --out -
#           and genpkey with no --out (WOTS, XMSS): refused, nothing written to
#           stdout or --out, and no ./-.idx created.
# Negative controls, each shown to FIRE: a stand-in that, when the real CLI
# refuses a damaged .idx, resets it to `0` and signs (the old fail-open read)
# must fail every damaged cell and no other; a stand-in that spools a stdin key
# to a fresh temporary file and signs it there must fail every stdin cell.
# Claimed by ci.yml's cross-lang-compat job.
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
TMP=$(mktemp -d)
trap 'chmod -R u+w "$TMP" 2>/dev/null; rm -rf "$TMP"' EXIT
PASS=0; FAIL=0
pass() { echo "PASS $1"; PASS=$((PASS+1)); }
fail() { echo "FAIL $1"; FAIL=$((FAIL+1)); }

declare -A CLI=()
CLI[py]="python3 $ROOT/HerraduraCli/herradura.py"
[ -x HerraduraCli/herradura_cli ] && CLI[c]="$ROOT/HerraduraCli/herradura_cli"
[ -x HerraduraCli/herradura_cli_go ] && CLI[go]="$ROOT/HerraduraCli/herradura_cli_go"
if command -v javac >/dev/null 2>&1 && bash bindings/java/build.sh >/dev/null; then
    CLI[java]="java -cp $ROOT/bindings/java herradurakex.HerraduraCli"
else echo "NOTE: Java CLI not built (javac absent or the build failed)"; fi
LANGS=()
for l in c go py java; do [ -n "${CLI[$l]:-}" ] && LANGS+=("$l"); done
echo "CLIs under test: ${LANGS[*]}"
if [ "${#LANGS[@]}" -lt 2 ]; then
    echo "FAIL test_ots_state: fewer than two CLIs, so the cells ran on too few ports." >&2
    [ "${HKX_ALLOW_SKIP:-0}" = "1" ] && exit 0
    exit 2
fi

G="${CLI[py]}"
echo "one-time state probe" > "$TMP/m"

WOTS_DAMAGED=("" "garbage" "1x" "-1" " 0" "0 " "00" "01" $'0\n\n' $'0\r\n' "+0" "2" "99999999999")
XMSS_DAMAGED=("" "garbage" "-1" "01" "5")
show() { printf '%q' "$1"; }

# refused NAME KEY -- sign must exit non-zero, write no signature, and leave the
# .idx byte-identical (or still absent / still a link / still a directory).
refused() {
    local name=$1 X=$2 key=$3 algo=$4 d; d=$(dirname "$key")
    local before; before=$(ls -ld "$key.idx" 2>/dev/null | awk '{print $1}'; cat "$key.idx" 2>/dev/null | od -An -c)
    rm -f "$d/s.sig"
    if ( cd "$d" && $X sign --algo "$algo" --key "$key" --in "$TMP/m" --out "$d/s.sig" ) >/dev/null 2>&1; then
        fail "$name: signed (exit 0)"
    elif [ -e "$d/s.sig" ]; then
        fail "$name: refused but a signature file exists"
    elif [ "$before" != "$(ls -ld "$key.idx" 2>/dev/null | awk '{print $1}'; cat "$key.idx" 2>/dev/null | od -An -c)" ]; then
        fail "$name: refused but the .idx changed"
    else pass "$name"; fi
}

# signs NAME X KEY ALGO WANT -- sign must succeed and leave .idx == WANT.
signs() {
    local name=$1 X=$2 key=$3 algo=$4 want=$5 d; d=$(dirname "$key")
    rm -f "$d/s.sig"
    if ! ( cd "$d" && $X sign --algo "$algo" --key "$key" --in "$TMP/m" --out "$d/s.sig" ) >/dev/null 2>"$d/err"; then
        fail "$name: refused: $(head -c 160 "$d/err")"
    elif [ ! -s "$d/s.sig" ]; then fail "$name: exit 0 but no signature"
    elif [ "$(cat "$key.idx")" != "$want" ]; then fail "$name: .idx is '$(cat "$key.idx")', want '$want'"
    else pass "$name"; fi
}

# fifo_refused NAME X KEY -- like refused, for a .idx that is a FIFO: reading it
# to compare would block, so the cell checks the FIFO is still there, and a
# sign that hangs on opening it fails after 20 s.
fifo_refused() {
    local name=$1 X=$2 key=$3 d rc; d=$(dirname "$key")
    rm -f "$d/s.sig"
    ( cd "$d" && timeout 20 $X sign --algo hpks-wots --key "$key" --in "$TMP/m" --out "$d/s.sig" ) >/dev/null 2>&1
    rc=$?
    if [ $rc -eq 0 ]; then fail "$name: signed (exit 0)"
    elif [ $rc -eq 124 ]; then fail "$name: hung opening the FIFO (timed out after 20 s)"
    elif [ -e "$d/s.sig" ]; then fail "$name: refused but a signature file exists"
    elif [ ! -p "$key.idx" ]; then fail "$name: refused but the .idx is no longer the FIFO"
    else pass "$name"; fi
}

# put KEY CONTENT -- set <key>.idx to CONTENT exactly (no added newline).
put() { rm -rf "$1.idx"; printf '%s' "$2" > "$1.idx"; }

state_cells() {
    local l=$1 X=$2 d="$TMP/s_$1" c
    rm -rf "$d"; mkdir -p "$d"
    $X genpkey --algo hpks-wots --out "$d/w.pem" >/dev/null 2>&1
    $X genpkey --algo hpks-xmss --xmss-height 2 --out "$d/x.pem" >/dev/null 2>&1
    cp "$d/w.pem" "$d/w2.pem"; cp "$d/w.pem.idx" "$d/w2.pem.idx"
    cp "$d/x.pem" "$d/x2.pem"; cp "$d/x.pem.idx" "$d/x2.pem.idx"
    [ -s "$d/w.pem" ] && [ -s "$d/x.pem" ] || { fail "$l: fixture keys"; return; }

    # accept-controls first: a broken reader that refuses everything fails these
    signs "$l: accept: fresh WOTS key signs" "$X" "$d/w2.pem" hpks-wots "1"
    put "$d/w2.pem" "0"
    signs "$l: accept: WOTS .idx '0' (no newline) signs" "$X" "$d/w2.pem" hpks-wots "1"
    signs "$l: accept: fresh XMSS key signs at leaf 0" "$X" "$d/x2.pem" hpks-xmss "1"
    put "$d/x2.pem" $'3\n'
    signs "$l: accept: XMSS .idx '3' signs the last leaf" "$X" "$d/x2.pem" hpks-xmss "4"

    rm -f "$d/w.pem.idx"; refused "$l: damaged: WOTS .idx missing" "$X" "$d/w.pem" hpks-wots
    for c in "${WOTS_DAMAGED[@]}"; do
        put "$d/w.pem" "$c"; refused "$l: damaged: WOTS .idx $(show "$c")" "$X" "$d/w.pem" hpks-wots
    done
    rm -rf "$d/w.pem.idx"; printf '0\n' > "$d/zero"; ln -s "$d/zero" "$d/w.pem.idx"
    refused "$l: damaged: WOTS .idx a symlink to '0'" "$X" "$d/w.pem" hpks-wots
    rm -f "$d/w.pem.idx"; mkdir "$d/w.pem.idx"
    refused "$l: damaged: WOTS .idx a directory" "$X" "$d/w.pem" hpks-wots
    rm -rf "$d/w.pem.idx"; mkfifo "$d/w.pem.idx"
    fifo_refused "$l: damaged: WOTS .idx a FIFO" "$X" "$d/w.pem"
    rm -rf "$d/w.pem.idx"
    rm -f "$d/x.pem.idx"; refused "$l: damaged: XMSS .idx missing" "$X" "$d/x.pem" hpks-xmss
    for c in "${XMSS_DAMAGED[@]}"; do
        put "$d/x.pem" "$c"; refused "$l: damaged: XMSS .idx $(show "$c")" "$X" "$d/x.pem" hpks-xmss
    done

    put "$d/w.pem" $'1\n'; refused "$l: used: WOTS .idx '1'" "$X" "$d/w.pem" hpks-wots
    put "$d/x.pem" $'4\n'; refused "$l: used: XMSS .idx '4' (exhausted)" "$X" "$d/x.pem" hpks-xmss

    # #420: a one-time key must be a file.  Run in an empty directory so a
    # ./-.idx would be seen; the key handed in has a valid, unused state.
    local e="$d/stdin"; mkdir -p "$e"
    local a k
    for a in hpks-wots hpks-xmss; do
        k=$d/w.pem; [ $a = hpks-xmss ] && k=$d/x.pem
        put "$k" $'0\n'
        for src in - /dev/stdin; do
            rm -f "$e/s.sig"
            if ( cd "$e" && $X sign --algo $a --key $src --in "$TMP/m" --out "$e/s.sig" < "$k" ) >/dev/null 2>&1; then
                fail "$l: stdin: sign $a --key $src signed"
            elif [ -e "$e/s.sig" ] || [ -e "$e/-.idx" ]; then
                fail "$l: stdin: sign $a --key $src refused but left a signature or ./-.idx"
            elif [ "$(cat "$k.idx")" != "0" ]; then
                fail "$l: stdin: sign $a --key $src changed the key's .idx"
            else pass "$l: stdin: sign $a --key $src refused"; fi
        done
        for how in "--out -" ""; do
            local hx=""; [ $a = hpks-xmss ] && hx="--xmss-height 2"
            if ( cd "$e" && $X genpkey --algo $a $hx $how ) >"$e/o" 2>/dev/null; then
                fail "$l: stdin: genpkey $a ${how:-(no --out)} succeeded"
            elif [ -s "$e/o" ] || [ -e "$e/-.idx" ]; then
                fail "$l: stdin: genpkey $a ${how:-(no --out)} refused but wrote a key or ./-.idx"
            else pass "$l: stdin: genpkey $a ${how:-(no --out)} refused"; fi
        done
    done
}

for l in "${LANGS[@]}"; do state_cells "$l" "${CLI[$l]}"; done
N_DAMAGED=$(( 1 + ${#WOTS_DAMAGED[@]} + 3 + 1 + ${#XMSS_DAMAGED[@]} ))
N_STDIN=8

# ── negative controls ─────────────────────────────────────────────────────────
# 1. the old fail-open read: when the CLI refuses a missing/damaged .idx, reset
#    it to 0 and sign.  It must fail every damaged cell, and no accept or used one.
cat > "$TMP/lenient_cli" <<EOF
#!/usr/bin/env bash
out=\$($G "\$@" 2>&1 >/dev/null); rc=\$?
if [ \$rc -ne 0 ] && [ "\$1" = sign ] && grep -q 'one-time-signature state file' <<<"\$out"; then
    for ((i=1; i<=\$#; i++)); do [ "\${!i}" = --key ] && { j=\$((i+1)); key=\${!j}; }; done
    rm -rf "\$key.idx"; echo 0 > "\$key.idx"
    exec $G "\$@"
fi
[ -n "\$out" ] && echo "\$out" >&2
exit \$rc
EOF
chmod +x "$TMP/lenient_cli"
before=$FAIL; pbefore=$PASS
state_cells lenient "$TMP/lenient_cli" >"$TMP/lenient.out"
got_d=$(grep -c '^FAIL lenient: damaged:' "$TMP/lenient.out")
got_o=$(grep '^FAIL lenient:' "$TMP/lenient.out" | grep -vc '^FAIL lenient: damaged:')
FAIL=$before; PASS=$pbefore
[ "$got_d" -eq "$N_DAMAGED" ] && [ "$got_o" -eq 0 ] \
    && pass "control: a fail-open reader fails all $N_DAMAGED damaged cells and no other" \
    || fail "control: a fail-open reader failed $got_d/$N_DAMAGED damaged cells and $got_o others"

# 2. a CLI that spools a stdin key (or a stdout genpkey) through a temporary file
#    signs or writes where the real ones refuse -- every stdin cell must catch it.
cat > "$TMP/spool_cli" <<EOF
#!/usr/bin/env bash
t=\$(mktemp -d); trap 'rm -rf "\$t"' EXIT
args=(); out=""; i=0
while [ \$# -gt 0 ]; do
    if [ "\$1" = --key ] && { [ "\$2" = - ] || [ "\$2" = /dev/stdin ]; }; then
        cat > "\$t/k.pem"; echo 0 > "\$t/k.pem.idx"; args+=(--key "\$t/k.pem"); shift 2
    elif [ "\$1" = --out ]; then out=\$2; shift 2
    else args+=("\$1"); shift; fi
done
if [ "\${args[0]}" = genpkey ] && { [ -z "\$out" ] || [ "\$out" = - ]; }; then
    $G "\${args[@]}" --out "\$t/g.pem" >/dev/null 2>&1 && cat "\$t/g.pem"; exit
fi
exec $G "\${args[@]}" \${out:+--out "\$out"}
EOF
chmod +x "$TMP/spool_cli"
before=$FAIL; pbefore=$PASS
state_cells spool "$TMP/spool_cli" >"$TMP/spool.out"
got=$(grep -c '^FAIL spool: stdin:' "$TMP/spool.out")
FAIL=$before; PASS=$pbefore
[ "$got" -eq "$N_STDIN" ] && pass "control: a stdin-spooling CLI fails all $N_STDIN stdin cells" \
    || fail "control: a stdin-spooling CLI failed $got/$N_STDIN stdin cells"

echo
echo "test_ots_state: $PASS passed, $FAIL failed"
[ $FAIL -eq 0 ] && echo "*** OK: one-time-signature state is read fail-closed and a one-time key must be a file ***"
[ $FAIL -eq 0 ]
