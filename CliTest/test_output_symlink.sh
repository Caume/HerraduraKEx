#!/usr/bin/env bash
# CliTest/test_output_symlink.sh — TODO #417: no CLI writes through a symbolic
# link, and no one-time signature is released without its leaf being consumed.
#
# Every CLI writer used to create its output with open(O_CREAT | O_TRUNC) and
# no O_NOFOLLOW.  A symlink at the output path was followed: its target was
# truncated and overwritten and, because O_CREAT's mode applies only on
# creation, kept its mode -- so a private key written over a world-readable file
# stayed world-readable (#395's 0600 defeated), and a dangling link created a
# file wherever it pointed.  The same review found that sign wrote a WOTS/XMSS
# signature BEFORE burning its leaf in the <key>.idx sidecar, and C and Go
# discarded a failed burn: an unwritable sidecar released a signature and left
# the leaf for the next sign to reuse.
#
# Cells, per CLI:
#   writers   ACCEPT a new path (created 0600), an existing regular file
#             (overwritten, mode kept) and /dev/null (a device); REFUSE a symlink to an existing file
#             (target byte-identical, link still a link), a dangling symlink
#             (nothing created), and a symlinked encfile --out (the binary
#             writer, a second code path in every CLI).
#   state     ACCEPT: a WOTS key signs once, verifies, and refuses a second
#             sign; XMSS signs twice at two different leaves.  REFUSE: with the
#             .idx unwritable (mode 0444) or a symlink, sign exits non-zero AND
#             no signature file exists afterwards -- for WOTS and XMSS.
# Negative controls, each shown to FIRE: a stand-in CLI that writes through the
# shell's `>` (which follows links) must fail the three symlink writer cells; a
# stand-in that signs against a COPY of the key (so its burn lands elsewhere,
# the old sig-before-burn behaviour seen from outside) must fail the
# unwritable-state cells.
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
    echo "FAIL test_output_symlink: fewer than two CLIs, so the cells ran on too few ports." >&2
    [ "${HKX_ALLOW_SKIP:-0}" = "1" ] && exit 0
    exit 2
fi
if [ "$(id -u)" = 0 ]; then
    # root ignores a 0444 mode, so the unwritable-state cells could not fail
    echo "NOTE: running as root -- the unwritable-.idx cells are n/a"
    ROOT_USER=1
else ROOT_USER=0; fi

mode() { stat -c '%a' "$1" 2>/dev/null || stat -f '%Lp' "$1"; }
G="${CLI[py]}"
echo "symlink probe message" > "$TMP/m"
$G genpkey --algo hkex-gf --out "$TMP/g1.pem" >/dev/null 2>&1
$G genpkey --algo hkex-gf --out "$TMP/g2.pem" >/dev/null 2>&1
$G pkey --in "$TMP/g2.pem" --pubout --out "$TMP/g2p.pem" >/dev/null 2>&1
$G kex --algo hkex-gf --our "$TMP/g1.pem" --their "$TMP/g2p.pem" --out "$TMP/sk.pem" >/dev/null 2>&1
[ -s "$TMP/sk.pem" ] || { fail "fixture: session key"; exit 1; }

# writer_cells LANG CMD -- the five writer cells against one CLI command.
writer_cells() {
    local l=$1 X=$2 d="$TMP/w_$1"
    mkdir -p "$d"
    # ACCEPT: new path, created 0600
    if $X genpkey --algo hkex-gf --out "$d/new.pem" >/dev/null 2>&1 \
       && grep -q "BEGIN HERRADURA" "$d/new.pem" && [ "$(mode "$d/new.pem")" = 600 ]; then
        pass "$l: genpkey to a new path writes it 0600"
    else fail "$l: genpkey to a new path (exit, PEM or mode $(mode "$d/new.pem" 2>/dev/null))"; fi
    # ACCEPT: an existing regular file is overwritten and keeps its mode
    printf 'old\n' > "$d/reg.pem"; chmod 0640 "$d/reg.pem"
    if $X genpkey --algo hkex-gf --out "$d/reg.pem" >/dev/null 2>&1 \
       && grep -q "BEGIN HERRADURA" "$d/reg.pem" && [ "$(mode "$d/reg.pem")" = 640 ]; then
        pass "$l: genpkey over an existing regular file overwrites it, mode kept"
    else fail "$l: genpkey over an existing regular file"; fi
    # ACCEPT: a device that is not a link (O_TRUNC does not apply to it)
    if $X genpkey --algo hkex-gf --out /dev/null >/dev/null 2>&1; then
        pass "$l: genpkey to /dev/null (a device, not a link) succeeds"
    else fail "$l: genpkey to /dev/null"; fi
    # REFUSE: symlink to an existing world-readable file
    printf 'VICTIM\n' > "$d/victim"; chmod 0644 "$d/victim"; cp "$d/victim" "$d/victim.orig"
    ln -s "$d/victim" "$d/link.pem"
    if ! $X genpkey --algo hkex-gf --out "$d/link.pem" >/dev/null 2>"$d/e1" \
       && cmp -s "$d/victim" "$d/victim.orig" && [ -L "$d/link.pem" ]; then
        pass "$l: genpkey through a symlink is refused, target untouched"
    else fail "$l: genpkey through a symlink (target now: $(head -c 40 "$d/victim" | tr '\n' ' '))"; fi
    # REFUSE: dangling symlink creates nothing
    ln -s "$d/nowhere" "$d/dangle.pem"
    if ! $X genpkey --algo hkex-gf --out "$d/dangle.pem" >/dev/null 2>&1 && [ ! -e "$d/nowhere" ]; then
        pass "$l: genpkey through a dangling symlink is refused, nothing created"
    else fail "$l: genpkey through a dangling symlink created $d/nowhere"; fi
    # REFUSE: the binary writer (encfile --out) through a symlink
    printf 'VICTIM2\n' > "$d/victim2"; chmod 0644 "$d/victim2"; cp "$d/victim2" "$d/victim2.orig"
    ln -s "$d/victim2" "$d/link.hkx"
    if ! $X encfile --algo hske-nla1 --key "$TMP/sk.pem" --in "$TMP/m" --out "$d/link.hkx" >/dev/null 2>&1 \
       && cmp -s "$d/victim2" "$d/victim2.orig"; then
        pass "$l: encfile --out through a symlink is refused, target untouched"
    else fail "$l: encfile --out through a symlink"; fi
}

# state_cells LANG CMD
state_cells() {
    local l=$1 X=$2 d="$TMP/s_$1" a
    mkdir -p "$d"
    # ACCEPT: WOTS signs once, verifies, refuses a second sign
    $X genpkey --algo hpks-wots --out "$d/w.pem" >/dev/null 2>&1
    $X pkey --in "$d/w.pem" --pubout --out "$d/wp.pem" >/dev/null 2>&1
    if $X sign --algo hpks-wots --key "$d/w.pem" --in "$TMP/m" --out "$d/w.sig" >/dev/null 2>&1 \
       && $X verify --algo hpks-wots --pubkey "$d/wp.pem" --in "$TMP/m" --sig "$d/w.sig" >/dev/null 2>&1; then
        pass "$l: hpks-wots signs once and the signature verifies"
    else fail "$l: hpks-wots control sign/verify"; fi
    if ! $X sign --algo hpks-wots --key "$d/w.pem" --in "$TMP/m" --out "$d/w2.sig" >/dev/null 2>&1 && [ ! -s "$d/w2.sig" ]; then
        pass "$l: hpks-wots refuses a second sign"
    else fail "$l: hpks-wots signed twice"; fi
    # ACCEPT: XMSS signs twice at two different leaves
    $X genpkey --algo hpks-xmss --xmss-height 2 --out "$d/x.pem" >/dev/null 2>&1
    $X sign --algo hpks-xmss --key "$d/x.pem" --in "$TMP/m" --out "$d/x1.sig" >/dev/null 2>&1
    $X sign --algo hpks-xmss --key "$d/x.pem" --in "$TMP/m" --out "$d/x2.sig" >/dev/null 2>&1
    if [ -s "$d/x1.sig" ] && [ -s "$d/x2.sig" ] && ! cmp -s "$d/x1.sig" "$d/x2.sig" && [ "$(tr -d ' \n' < "$d/x.pem.idx")" = 2 ]; then
        pass "$l: hpks-xmss signs at two leaves and the sidecar reads 2"
    else fail "$l: hpks-xmss control (sidecar: $(cat "$d/x.pem.idx" 2>/dev/null))"; fi
    for a in hpks-wots "hpks-xmss --xmss-height 2"; do
        local n=${a%% *}
        # REFUSE: .idx unwritable
        if [ "$ROOT_USER" = 1 ]; then echo "n/a  $l: $n with an unwritable .idx (root)"; else
            $X genpkey --algo $a --out "$d/ro_$n.pem" >/dev/null 2>&1
            [ -e "$d/ro_$n.pem.idx" ] || echo 0 > "$d/ro_$n.pem.idx"
            chmod 0444 "$d/ro_$n.pem.idx"
            $X sign --algo $n --key "$d/ro_$n.pem" --in "$TMP/m" --out "$d/ro_$n.sig" >/dev/null 2>&1; local rc=$?
            if [ $rc -ne 0 ] && [ ! -s "$d/ro_$n.sig" ]; then
                pass "$l: $n with an unwritable .idx exits $rc and releases no signature"
            else fail "$l: $n with an unwritable .idx released a signature (exit $rc)"; fi
        fi
        # REFUSE: .idx is a symlink
        $X genpkey --algo $a --out "$d/ln_$n.pem" >/dev/null 2>&1
        printf '0\n' > "$d/ln_$n.victim"; chmod 0644 "$d/ln_$n.victim"
        rm -f "$d/ln_$n.pem.idx"; ln -s "$d/ln_$n.victim" "$d/ln_$n.pem.idx"
        $X sign --algo $n --key "$d/ln_$n.pem" --in "$TMP/m" --out "$d/ln_$n.sig" >/dev/null 2>&1; local rc2=$?
        if [ $rc2 -ne 0 ] && [ ! -s "$d/ln_$n.sig" ] && [ "$(cat "$d/ln_$n.victim")" = 0 ]; then
            pass "$l: $n with a symlinked .idx exits $rc2, releases no signature, target untouched"
        else fail "$l: $n with a symlinked .idx (exit $rc2)"; fi
    done
}

for l in "${LANGS[@]}"; do writer_cells "$l" "${CLI[$l]}"; done
for l in "${LANGS[@]}"; do state_cells "$l" "${CLI[$l]}"; done

# ── negative controls ─────────────────────────────────────────────────────────
# 1. a CLI writing through the shell's `>` (follows links, and given umask 077 so
#    that is its only difference) fails exactly the 3 symlink cells.
cat > "$TMP/follow_cli" <<EOF
#!/usr/bin/env bash
umask 077   # 0600 on creation, like the real CLIs: the ONLY difference is \`>\` following links
args=(); out=""
while [ \$# -gt 0 ]; do
    if [ "\$1" = --out ]; then out=\$2; shift 2; else args+=("\$1"); shift; fi
done
if [ -n "\$out" ]; then $G "\${args[@]}" --out - > "\$out"; else $G "\${args[@]}"; fi
EOF
chmod +x "$TMP/follow_cli"
before=$FAIL; pbefore=$PASS
writer_cells follow "$TMP/follow_cli" >"$TMP/follow.out"
got=$((FAIL - before)); FAIL=$before; PASS=$pbefore
[ $got -eq 3 ] && pass "control: a link-following writer fails exactly the 3 symlink cells" \
    || fail "control: a link-following writer failed $got cells, not 3"

# 2. a signer that burns a COPY of the key's state releases a signature with the
#    real .idx unwritable -- the unwritable-state cells must catch it.
cat > "$TMP/copy_cli" <<EOF
#!/usr/bin/env bash
if [ "\$1" = sign ]; then
    args=(); key=""
    for ((i=1; i<=\$#; i++)); do
        a=\${!i}
        if [ "\$a" = --key ]; then j=\$((i+1)); key=\${!j}; fi
    done
    c=\$(mktemp -d); cp "\$key" "\$c/k.pem"; [ -e "\$key.idx" ] && cp "\$key.idx" "\$c/k.pem.idx"; chmod u+w "\$c/k.pem.idx" 2>/dev/null
    set -- "\${@/#\$key/\$c/k.pem}"
    $G "\$@"; rc=\$?; rm -rf "\$c"; exit \$rc
fi
exec $G "\$@"
EOF
chmod +x "$TMP/copy_cli"
if [ "$ROOT_USER" = 1 ]; then echo "n/a  control: sig-before-burn stand-in (root)"; else
    before=$FAIL; pbefore=$PASS
    state_cells copy "$TMP/copy_cli" >"$TMP/copy.out"
    got=$(grep -c "^FAIL copy: .*unwritable" "$TMP/copy.out"); FAIL=$before; PASS=$pbefore
    [ "$got" -eq 2 ] && pass "control: a signer that burns elsewhere fails both unwritable-.idx cells" \
        || fail "control: a signer that burns elsewhere failed $got unwritable-.idx cells, not 2"
fi

echo
echo "test_output_symlink: $PASS passed, $FAIL failed"
[ $FAIL -eq 0 ] && echo "*** OK: no CLI writes through a symlink or releases an unburned one-time signature ***"
[ $FAIL -eq 0 ]
