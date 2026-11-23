#!/usr/bin/env bash
# CliTest/test_malformed_pem_matrix.sh — TODO #240: the four CLIs must agree
# about which artifacts are malformed.
#
# TODO #239 range-checked every PEM field that sizes an allocation in the C CLI
# and stopped there.  The other three still multiplied wire counts straight into
# an allocation length, so a four-byte edit to a signature produced a MemoryError
# traceback (Python), "fatal error: out of memory" with a goroutine dump (Go), or
# a NegativeArraySizeException from `d * 2` wrapping past 2^31 (Java) — while C
# printed one line and exited 1.
#
# That divergence is the defect this script pins.  The bounds are a wire
# contract, not an implementation detail: an artifact one CLI refuses must not be
# one another accepts.  Every case is generated ONCE with the Python CLI and fed
# to all four, so the fixtures themselves are cross-language.
#
# The case table lives in CliTest/lib_malformed.sh, shared with
# test_weak_key_rejection.sh (which runs the same cases against the C CLI alone,
# and therefore also under the sanitizers job, where TODO #239's stack overflow
# is visible).
#
# TODO #275 added the SECOND table, hkx_mal_suite_packed.  Eight PEM labels are
# not DER at all — they size their fields from a 4-byte `n` header — so
# hkx_mal_craft, which rewrites one item of a DER SEQUENCE, could not express a
# single case against them and this matrix had no coverage of them whatsoever.
# What that hid was not a robustness gap: at rounds == 0 a ZKP verifier's
# per-round loop runs zero times and reports success, and three of these four
# CLIs accepted an 89-byte PEM of eight null bytes as a valid nl-zkboo signature
# for any message under any key.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
PASS=0; FAIL=0

pass() { echo "PASS $1"; PASS=$((PASS+1)); }
fail() { echo "FAIL $1"; FAIL=$((FAIL+1)); }

declare -A CLI=()
CLI[py]="python3 $ROOT/HerraduraCli/herradura.py"
[ -x "$ROOT/HerraduraCli/herradura_cli" ]    && CLI[c]="$ROOT/HerraduraCli/herradura_cli"
[ -x "$ROOT/HerraduraCli/herradura_cli_go" ] && CLI[go]="$ROOT/HerraduraCli/herradura_cli_go"
if command -v javac >/dev/null 2>&1; then
    bash bindings/java/build.sh >/dev/null 2>&1
    # -Xmx is the JVM's version of the address-space cap the other three get
    # from ulimit -v; see lib_malformed.sh's HKX_MAL_VLIMIT note.
    CLI[java]="java -Xmx1g -cp $ROOT/bindings/java herradurakex.HerraduraCli"
fi

LANGS=()
for l in py c go java; do
    [ -n "${CLI[$l]:-}" ] && LANGS+=("$l")
done
echo "Languages under test: ${LANGS[*]}"

# TODO #229: an unannounced absence reads as full coverage when it is not.
. "$ROOT/CliTest/lib_build.sh"
for l in c go; do
    [ -n "${CLI[$l]:-}" ] || echo "NOTE: $l CLI absent — $(hkx_why "$l")"
done
[ -n "${CLI[java]:-}" ] || echo "NOTE: java CLI absent — javac is not installed"

. "$ROOT/CliTest/lib_malformed.sh"
HKX_MAL_ROOT="$ROOT"
HKX_MAL_DIR="$TMP"
hkx_mal_fixtures "$TMP"
hkx_mal_fixtures_packed "$TMP"   # TODO #275; reuses rm1.pem from the DER set

for l in "${LANGS[@]}"; do
    echo ""
    echo "=== $l ==="
    # 2 GiB of address space is generous for every case here and tight enough
    # that a missing bound fails fast; the JVM is capped with -Xmx instead.
    if [ "$l" = java ]; then HKX_MAL_VLIMIT=""; else HKX_MAL_VLIMIT=2000000; fi
    export HKX_MAL_VLIMIT
    # shellcheck disable=SC2086
    hkx_mal_suite "$l" ${CLI[$l]}
    # shellcheck disable=SC2086
    hkx_mal_suite_packed "$l" ${CLI[$l]}
done

# ── TODO #398: one base64 grammar for every reader ─────────────────────────
# Until #398 C and Python skipped any character outside the alphabet (one `!`
# in a key and `pkey --pubout` exited 0), Python also took '=' mid-body, and
# all four took a body with its padding stripped or with non-zero bits under
# it.  The grammar now is: the alphabet A-Z a-z 0-9 + /; space, tab, CR and LF
# anywhere between characters; padding REQUIRED, '=' only as the last one or
# two characters; the bits under the padding zero.  Anything else is refused
# with "PEM body is not valid base64: <reason>" in all four.
#
# The fixtures are pinned KATs, one per padding count, because a fresh key's
# DER length -- and with it the padding -- depends on its random bytes:
#   pad 0  n64_alice_priv.pem    read by pkey --pubout
#   pad 1  enc_priv.pem          read by pkey --decrypt (the envelope reader)
#   pad 2  n1024_alice_priv.pem  read by pkey --pubout
echo ""
echo "=== TODO #398: base64 grammar ==="
B64=$TMP/b64; mkdir -p "$B64"
KATP="$ROOT/KAT/pem"
KAT_PASS="HerraduraKEx TODO #268 KAT passphrase"
CRASH='Traceback \(most recent|Exception in thread|panic:|goroutine [0-9]+ \[|\tat java\.'
declare -A B64_FX=([0]=n64_alice_priv [1]=enc_priv [2]=n1024_alice_priv)

# b64_mut <pad> <op> <out>: rewrite the fixture's body; header and footer kept.
b64_mut() {
    python3 - "$KATP/${B64_FX[$1]}.pem" "$2" "$3" <<'PYEOF'
import sys
src, op, out = sys.argv[1], sys.argv[2], sys.argv[3]
lines = open(src, 'rb').read().decode('ascii').strip('\n').split('\n')
head, foot, body = lines[0], lines[-1], ''.join(lines[1:-1])
A = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
wrap = lambda t, w: '\n'.join(t[i:i + w] for i in range(0, len(t), w))
sep = '\n'
if op == 'crlf':        text, sep = wrap(body, 76), '\r\n'
elif op == 'cronly':    text, sep = wrap(body, 76).replace('\n', '\r'), '\r'
elif op == 'spaces':    text = wrap(' \t'.join(body[i:i + 10] for i in range(0, len(body), 10)), 80)
elif op == 'wrap64':    text = wrap(body, 64)
elif op == 'oneline':   text = body
elif op == 'blankline': w = wrap(body, 76).split('\n'); text = '\n'.join(w[:1] + [''] + w[1:])
elif op == 'trailsp':   text = '\n'.join(l + ' \t' for l in wrap(body, 76).split('\n'))
elif op == 'bang':      text = wrap(body[:10] + '!' + body[11:], 76)
elif op == 'urlsafe':   text = wrap(body[:10] + '_' + body[11:], 76)
elif op == 'vtab':      text = wrap(body[:10] + '\v' + body[10:], 76)
elif op == 'nonascii':  text = wrap(body[:10] + 'é' + body[11:], 76)
elif op == 'junk':      text = '!!!!'
elif op == 'midpad':    text = wrap(body[:8] + '=' + body[9:], 76)
elif op == 'extrapad':  text = wrap(body + '=', 76)
elif op == 'afterpad':  text = wrap(body + 'AAAA', 76)
elif op == 'nopad':     text = wrap(body.rstrip('='), 76)
elif op == 'drop1':     text = wrap(body[:-1], 76)
elif op == 'add1':      text = wrap(body + 'A', 76)
elif op == 'bits':
    core = body.rstrip('=')
    v = A.index(core[-1])
    assert v & 1 == 0, 'the fixture is not canonical'
    text = wrap(core[:-1] + A[v | 1] + body[len(core):], 76)
else: sys.exit('unknown op ' + op)
open(out, 'wb').write(sep.join([head, text, foot]).encode('latin-1') + sep.encode())
PYEOF
}

# b64_run <lang> <pad> <file> <out>: the reader for that fixture.
b64_run() {
    local X=${CLI[$1]}
    if [ "$2" = 1 ]; then
        $X pkey --decrypt --passphrase "$KAT_PASS" --in "$3" --out "$4"
    else
        $X pkey --in "$3" --pubout --out "$4"
    fi
}

# The fixtures' padding counts are what this section's coverage rests on.
for p in 0 1 2; do
    f="$KATP/${B64_FX[$p]}.pem"
    got=$(sed '1d;$d' "$f" | tr -cd '=' | wc -c)
    if [ "$got" -eq "$p" ]; then pass "b64 fixture ${B64_FX[$p]} has $p padding character(s)"
    else fail "b64 fixture ${B64_FX[$p]} has $got padding character(s), not $p"; fi
done

for p in 0 1 2; do
    for op in crlf cronly spaces wrap64 oneline blankline trailsp; do b64_mut $p $op "$B64/p${p}_$op.pem"; done
    for op in bang urlsafe vtab nonascii junk midpad extrapad drop1 add1; do b64_mut $p $op "$B64/p${p}_$op.pem"; done
    [ "$p" -gt 0 ] && for op in afterpad nopad bits; do b64_mut $p $op "$B64/p${p}_$op.pem"; done
done

for l in "${LANGS[@]}"; do
    for p in 0 1 2; do
        # Accept-controls first: the pristine fixture, then every layout the
        # grammar allows, each to the same bytes.
        if ! b64_run "$l" $p "$KATP/${B64_FX[$p]}.pem" "$B64/ref_${l}_$p" >/dev/null 2>&1; then
            fail "b64 pad $p: pristine ${B64_FX[$p]} is refused ($l)"; continue
        fi
        pass "b64 pad $p: pristine ${B64_FX[$p]} reads ($l)"
        for op in crlf cronly spaces wrap64 oneline blankline trailsp; do
            rm -f "$B64/out"
            if b64_run "$l" $p "$B64/p${p}_$op.pem" "$B64/out" >/dev/null 2>&1 \
               && cmp -s "$B64/ref_${l}_$p" "$B64/out"; then
                pass "b64 pad $p: $op reads to the same bytes ($l)"
            else
                fail "b64 pad $p: $op is refused or reads differently ($l)"
            fi
        done
        # Refusals: by name, with nothing written and no crash.
        cases=("bang|invalid character" "urlsafe|invalid character" "vtab|invalid character"
               "nonascii|invalid character" "junk|invalid character"
               "midpad|misplaced padding" "extrapad|misplaced padding")
        if [ "$p" -eq 0 ]; then
            cases+=("drop1|length is not a multiple of 4" "add1|length is not a multiple of 4")
        else
            cases+=("afterpad|misplaced padding" "nopad|length is not a multiple of 4"
                    "bits|non-zero bits after the last byte")
        fi
        for c in "${cases[@]}"; do
            op=${c%%|*}; want="PEM body is not valid base64: ${c#*|}"
            rm -f "$B64/out"
            rc=0; b64_run "$l" $p "$B64/p${p}_$op.pem" "$B64/out" >"$B64/so" 2>"$B64/se" || rc=$?
            if [ $rc -eq 0 ]; then fail "b64 pad $p: $op accepted ($l)"
            elif grep -Eq "$CRASH" "$B64/se"; then fail "b64 pad $p: $op crashed ($l): $(head -c 200 "$B64/se")"
            elif ! grep -qF -- "$want" "$B64/se"; then fail "b64 pad $p: $op message ($l): $(head -c 200 "$B64/se")"
            elif [ -e "$B64/out" ]; then fail "b64 pad $p: $op wrote output ($l)"
            else pass "b64 pad $p: $op refused: ${want#PEM body is not valid base64: } ($l)"; fi
        done
    done
    # The envelope reader names its path too, as in TODO #397's other refusals.
    rc=0; b64_run "$l" 1 "$B64/p1_bang.pem" "$B64/out" 2>"$B64/se" >/dev/null || rc=$?
    want="pkey --decrypt: cannot parse PEM from: $B64/p1_bang.pem: PEM body is not valid base64: invalid character"
    if [ $rc -ne 0 ] && grep -qF -- "$want" "$B64/se"; then pass "b64: pkey --decrypt names the path and the reason ($l)"
    else fail "b64: pkey --decrypt message ($l): $(head -c 200 "$B64/se")"; fi
done

# ── TODO #400: one framing for every reader ────────────────────────────────
# Until #400 C, Go and Java searched for the BEGIN and END markers anywhere, so
# text before or after the block, a second block, and an END line naming another
# label all read (Python refused the first three, under one vague message).  The
# framing now: only whitespace before the BEGIN line and after the END line; the
# BEGIN line `-----BEGIN <label>-----` then only spaces or tabs, the label 1-79
# printable ASCII characters; the END line at the start of a line, repeating the
# label; a body of at least one byte.  Fixture: n64_alice_priv.pem (pkey
# --pubout), and the envelope for the --decrypt reader.
echo ""
echo "=== TODO #400: PEM framing ==="
FR=$TMP/frame; mkdir -p "$FR"
fr_mut() {
    python3 - "$1" "$2" "$3" <<'PYEOF'
import sys
src, op, out = sys.argv[1], sys.argv[2], sys.argv[3]
t = open(src).read()
lines = t.rstrip('\n').split('\n')
head, foot, body = lines[0], lines[-1], lines[1:-1]
label = head[len('-----BEGIN '):-5]
j = lambda *ls: '\n'.join(ls) + '\n'
ops = {
    'leadblank':  '\n\n' + t,
    'leadspace':  '  \t\n' + t,
    'trailblank': t + '\n  \t\n\n',
    'noeol':      t.rstrip('\n'),
    'beginsp':    j(head + ' \t', *body, foot),
    'pre':        'a comment line\n' + t,
    'presame':    'note: ' + t,
    'nobegin':    j(*body, foot),
    'post':       t + 'a trailing line\n',
    'two':        t + t,
    'postsame':   j(head, *body, foot + 'x'),
    'mism':       j(head, *body, foot.replace(label, 'HERRADURA OTHER KEY')),
    'noend':      j(head, *body),
    'endindent':  j(head, *body, '  ' + foot),
    'endopen':    j(head, *body, foot[:-5]),
    'beginextra': j(head + ' extra', *body, foot),
    'beginopen':  j(head[:-5], *body, foot),
    'nolabel':    j('-----BEGIN -----', *body, '-----END -----'),
    'label80':    j('-----BEGIN ' + 'L' * 80 + '-----', *body, '-----END ' + 'L' * 80 + '-----'),
    'label79':    j('-----BEGIN ' + 'L' * 79 + '-----', *body, '-----END ' + 'L' * 79 + '-----'),
    'ctrllabel':  j('-----BEGIN HERRADURA\x01KEY-----', *body, '-----END HERRADURA\x01KEY-----'),
    'emptybody':  j(head, foot),
    'blankbody':  j(head, '   ', '', foot),
}
open(out, 'w').write(ops[op])
PYEOF
}
FX=$KATP/n64_alice_priv.pem
FR_OK="leadblank leadspace trailblank noeol beginsp"
FR_BAD=("pre|PEM: text before the BEGIN line" "presame|PEM: text before the BEGIN line"
        "nobegin|PEM: missing BEGIN marker"
        "post|PEM: text after the END line" "two|PEM: text after the END line"
        "postsame|PEM: text after the END line"
        "mism|PEM: END label 'HERRADURA OTHER KEY' does not match BEGIN label 'HERRADURA HKEX-RNL PRIVATE KEY'"
        "noend|PEM: missing END marker"
        "endindent|PEM: malformed END line" "endopen|PEM: malformed END line"
        "beginextra|PEM: malformed BEGIN line" "beginopen|PEM: malformed BEGIN line"
        "nolabel|PEM: malformed BEGIN line" "label80|PEM: malformed BEGIN line"
        "ctrllabel|PEM: malformed BEGIN line"
        "emptybody|PEM: empty body" "blankbody|PEM: empty body")
for op in $FR_OK label79; do fr_mut "$FX" $op "$FR/$op.pem"; done
for c in "${FR_BAD[@]}"; do fr_mut "$FX" "${c%%|*}" "$FR/${c%%|*}.pem"; done
fr_mut "$KATP/enc_priv.pem" post "$FR/enc_post.pem"

for l in "${LANGS[@]}"; do
    X=${CLI[$l]}
    if ! $X pkey --in "$FX" --pubout --out "$FR/ref_$l" >/dev/null 2>&1; then
        fail "frame: pristine fixture is refused ($l)"; continue
    fi
    pass "frame: pristine fixture reads ($l)"
    for op in $FR_OK; do
        rm -f "$FR/out"
        if $X pkey --in "$FR/$op.pem" --pubout --out "$FR/out" >/dev/null 2>&1 \
           && cmp -s "$FR/ref_$l" "$FR/out"; then pass "frame: $op reads to the same bytes ($l)"
        else fail "frame: $op is refused or reads differently ($l)"; fi
    done
    for c in "${FR_BAD[@]}"; do
        op=${c%%|*}; want=${c#*|}
        rm -f "$FR/out"
        rc=0; $X pkey --in "$FR/$op.pem" --pubout --out "$FR/out" >/dev/null 2>"$FR/se" || rc=$?
        if [ $rc -eq 0 ]; then fail "frame: $op accepted ($l)"
        elif grep -Eq "$CRASH" "$FR/se"; then fail "frame: $op crashed ($l): $(head -c 200 "$FR/se")"
        elif ! grep -qF -- "$want" "$FR/se"; then fail "frame: $op message ($l): $(head -c 200 "$FR/se")"
        elif [ -e "$FR/out" ]; then fail "frame: $op wrote output ($l)"
        else pass "frame: $op refused: $want ($l)"; fi
    done
    # The boundary: a 79-character label passes the framing and is then refused
    # as an unknown label -- by the loader, not as a malformed BEGIN line.
    rc=0; $X pkey --in "$FR/label79.pem" --pubout --out "$FR/out" >/dev/null 2>"$FR/se" || rc=$?
    if [ $rc -ne 0 ] && ! grep -q 'PEM: malformed BEGIN line' "$FR/se" && ! grep -Eq "$CRASH" "$FR/se"; then
        pass "frame: a 79-character label passes the framing ($l)"
    else fail "frame: label79 ($l): rc=$rc $(head -c 200 "$FR/se")"; fi
    # The envelope reader names its path and the reason.
    rc=0; $X pkey --decrypt --passphrase "$KAT_PASS" --in "$FR/enc_post.pem" --out "$FR/out" \
        >/dev/null 2>"$FR/se" || rc=$?
    want="pkey --decrypt: cannot parse PEM from: $FR/enc_post.pem: PEM: text after the END line"
    if [ $rc -ne 0 ] && grep -qF -- "$want" "$FR/se"; then pass "frame: pkey --decrypt names the path and the reason ($l)"
    else fail "frame: pkey --decrypt message ($l): $(head -c 200 "$FR/se")"; fi
done

echo ""
echo "Results: $PASS PASS / $FAIL FAIL (languages: ${LANGS[*]})"
[ "$FAIL" -eq 0 ]
