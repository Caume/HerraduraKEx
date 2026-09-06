#!/usr/bin/env bash
# CliTest/test_unknown_flags.sh — TODO #274: an unrecognised flag must be a hard
# error in every CLI, never a silent fall-through to a weaker default.
#
# C and Java scanned argv for the flags they wanted and ignored everything else,
# so a flag they do not implement was accepted with exit 0 and no diagnostic.
# That is not cosmetic.  Two measured instances, both fail-OPEN on a security
# property, both confirmed against pre-#274 binaries:
#
#   enc --aead            Java has no --aead (TODO #273), so it wrote format tag 1
#                         -- plain, UNAUTHENTICATED HSKE-NL-A1 -- where C, Go and
#                         Python write tag 2 with an authentication tag.
#   genpkey --passphrase   C and Java have no --passphrase (TODO #268), so they
#                         wrote a CLEARTEXT `HERRADURA <algo> PRIVATE KEY` where
#                         Python writes `HERRADURA ENCRYPTED PRIVATE KEY`.  The
#                         caller asked for a protected key and got a long-lived
#                         secret unprotected on disk, reported as success.
#
# Go and Python already refused unknown flags (flag.FlagSet and argparse
# respectively); this asserts all four agree.
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

PASS=0; FAIL=0
pass() { echo "PASS $1"; PASS=$((PASS+1)); }
fail() { echo "FAIL $1"; FAIL=$((FAIL+1)); }

declare -A CLI=()
CLI[py]="python3 $ROOT/HerraduraCli/herradura.py"
[ -x "$ROOT/HerraduraCli/herradura_cli" ]    && CLI[c]="$ROOT/HerraduraCli/herradura_cli"
[ -x "$ROOT/HerraduraCli/herradura_cli_go" ] && CLI[go]="$ROOT/HerraduraCli/herradura_cli_go"
if command -v javac >/dev/null 2>&1; then
    bash "$ROOT/bindings/java/build.sh" >/dev/null 2>&1
    CLI[java]="java -cp $ROOT/bindings/java herradurakex.HerraduraCli"
fi

LANGS=()
for l in py c go java; do [ -n "${CLI[$l]:-}" ] && LANGS+=("$l"); done
echo "Languages under test: ${LANGS[*]}"
. "$ROOT/CliTest/lib_build.sh"
for l in c go; do
    [ -n "${CLI[$l]:-}" ] || echo "NOTE: $l CLI absent — $(hkx_why "$l")"
done
[ -n "${CLI[java]:-}" ] || echo "NOTE: java CLI absent — javac is not installed"
if [ "${#LANGS[@]}" -lt 2 ]; then
    echo "FAIL test_unknown_flags: fewer than 2 CLIs available, so nothing was compared." >&2
    [ "${HKX_ALLOW_SKIP:-0}" = "1" ] && exit 0
    exit 2
fi

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
echo "unknown-flag test message" > "$TMP/msg.txt"

# ── Fixtures (Python, so every CLI reads the same artifacts) ────────────────
PY="${CLI[py]}"
$PY genpkey --algo hkex-gf --out "$TMP/a.pem"  >/dev/null 2>&1
$PY genpkey --algo hkex-gf --out "$TMP/b.pem"  >/dev/null 2>&1
$PY pkey --in "$TMP/b.pem" --pubout --out "$TMP/b_pub.pem" >/dev/null 2>&1
$PY kex --algo hkex-gf --our "$TMP/a.pem" --their "$TMP/b_pub.pem" \
    --out "$TMP/sess.pem" >/dev/null 2>&1
$PY genpkey --algo hpks --out "$TMP/hpks.pem" >/dev/null 2>&1

# ── 1. CONTROL: the same command WITHOUT the bogus flag must succeed ────────
# A CLI that refused everything would score a clean sweep on section 2 below.
echo "--- control: valid invocations still succeed ---"
for l in "${LANGS[@]}"; do
    if ${CLI[$l]} dgst --algo hfscx-256 --in "$TMP/msg.txt" --out "$TMP/d_$l.pem" >/dev/null 2>&1; then
        pass "control ($l): dgst with only valid flags succeeds"
    else
        fail "control ($l): dgst with only valid flags was refused — the rejection tests below prove nothing"
    fi
done

# ── 2. An unrecognised flag is refused, and the message names it ────────────
echo "--- unrecognised flags are refused, with the flag named ---"
for l in "${LANGS[@]}"; do
    for probe in "dgst --algo hfscx-256 --in $TMP/msg.txt --nosuchflag" \
                 "genpkey --algo hpks --out $TMP/g_$l.pem --totallybogus" \
                 "sign --algo hpks --key $TMP/hpks.pem --in $TMP/msg.txt --out $TMP/s_$l.pem --zzz"; do
        sub=${probe%% *}
        out=$(${CLI[$l]} $probe 2>&1); rc=$?
        if [ $rc -eq 0 ]; then
            fail "unknown-flag ($l, $sub): exit 0 — the flag was accepted and ignored"
            continue
        fi
        # The diagnostic must name the offending flag, or the operator cannot
        # tell an unknown flag from any other failure.
        bad=$(printf '%s\n' $probe | grep -o -- '--[a-z]*' | tail -1)
        case "$out" in
            *"${bad#--}"*) pass "unknown-flag ($l, $sub): refused, message names ${bad}" ;;
            *) fail "unknown-flag ($l, $sub): refused (exit $rc) but message does not name ${bad}: $(echo "$out"|head -1)" ;;
        esac
    done
done

# ── 3. THE SECURITY CASE: never silently downgrade to the weaker branch ─────
# `enc --aead` must EITHER produce an authenticated ciphertext (format tag 2)
# OR fail.  Producing tag 1 with exit 0 is the bug: the caller asked for
# authenticated encryption and got confidentiality only.
echo "--- security: enc --aead never degrades to unauthenticated ---"
fmt_tag() {
    python3 - "$1" <<'PYEOF'
import base64, sys
lines = [l.strip() for l in open(sys.argv[1]) if l.strip() and not l.startswith('-----')]
d = base64.b64decode(''.join(lines))
# SEQUENCE, then the first INTEGER is the format tag.
o = 2 if d[1] < 0x80 else 2 + (d[1] & 0x7f)
assert d[o] == 0x02
print(d[o + 2])
PYEOF
}
for l in "${LANGS[@]}"; do
    rm -f "$TMP/aead_$l.pem"
    if ${CLI[$l]} enc --algo hske-nla1 --aead --key "$TMP/sess.pem" \
           --in "$TMP/msg.txt" --out "$TMP/aead_$l.pem" >/dev/null 2>&1; then
        tag=$(fmt_tag "$TMP/aead_$l.pem" 2>/dev/null || echo "?")
        if [ "$tag" = "2" ]; then
            pass "aead ($l): --aead accepted and produced an AEAD ciphertext (format tag 2)"
        else
            fail "aead ($l): --aead exited 0 but produced format tag $tag — UNAUTHENTICATED"
        fi
    else
        pass "aead ($l): --aead refused outright (no --aead in this CLI)"
    fi
done

# `genpkey --passphrase` must EITHER write an encrypted key OR fail.  Writing a
# cleartext private key with exit 0 is the same bug on a longer-lived secret.
echo "--- security: genpkey --passphrase never yields a cleartext key ---"
for l in "${LANGS[@]}"; do
    rm -f "$TMP/pp_$l.pem"
    if ${CLI[$l]} genpkey --algo hpks --passphrase hunter2 \
           --out "$TMP/pp_$l.pem" >/dev/null 2>&1; then
        if head -1 "$TMP/pp_$l.pem" | grep -q "ENCRYPTED PRIVATE KEY"; then
            pass "passphrase ($l): --passphrase accepted and the key is encrypted"
        else
            fail "passphrase ($l): --passphrase exited 0 but wrote $(head -1 "$TMP/pp_$l.pem") — CLEARTEXT"
        fi
    else
        pass "passphrase ($l): --passphrase refused outright (no envelope in this CLI)"
    fi
done

# ── 4. Every flag spec/ records as missing from a CLI must be REFUSED there ─
# Derived from spec/'s own cli_surface_gaps, so a flag that gets ported and has
# its gap row deleted stops being probed here automatically.
echo "--- every recorded flag gap is refused, not ignored ---"
GAPS=$(python3 - <<'PYEOF'
import json, os
spec = json.load(open(os.path.join("spec", "herradura-protocol-spec.json")))
for g in spec["cli_surface_gaps"]:
    if g.get("kind") != "flag":
        continue
    for lang in g["missing_from"]:
        print("%s\t%s\t%s" % ({"python": "py"}.get(lang, lang), g["subcommand"], g["flag"]))
PYEOF
)
while IFS=$'\t' read -r lang sub flag; do
    [ -n "$lang" ] || continue
    [ -n "${CLI[$lang]:-}" ] || continue
    # Python is excluded HERE, and only here.  These probes deliberately omit
    # every other argument, and argparse reports the missing REQUIRED ones before
    # it ever reaches an unrecognised flag -- so its exit status and message say
    # nothing about the flag under test.  That is not a gap in coverage: argparse
    # rejects by construction from a declared argument list, and section 2 proves
    # it three times over with complete command lines.  The CLIs this section
    # exists for are C and Java, which had no allow-list at all before #274.
    [ "$lang" = "py" ] && continue
    out=$(${CLI[$lang]} "$sub" "$flag" 2>&1); rc=$?
    if [ $rc -eq 0 ]; then
        fail "gap ($lang, $sub $flag): accepted with exit 0, but spec/ records it as missing here"
        continue
    fi
    # A non-zero exit alone proves nothing here: the probe deliberately omits
    # every other argument, so a CLI would exit non-zero on the missing required
    # ones even if it had silently accepted the flag.  Require the diagnostic to
    # NAME the probed flag, which only the unknown-flag path does.
    case "$out" in
        *"${flag#--}"*) pass "gap ($lang, $sub $flag): refused, message names it" ;;
        *) fail "gap ($lang, $sub $flag): exit $rc but the message does not name ${flag}, so it may have been ignored and failed for another reason: $(echo "$out"|head -1)" ;;
    esac
done <<< "$GAPS"

# ── 5. Flag ARITY: a typo after a BOOLEAN flag must still be caught ─────────
# The validator has to tell a typo from a flag-shaped VALUE, because a file
# literally named "--weird.pem" is legal input (Python and Go both accept one).
# Skipping the token after ANY known flag would reopen the hole on boolean
# flags: `enc --aead --typo` would read --typo as --aead's value, and --aead
# takes none.  Both directions are asserted, on the CLIs that have --aead.
echo "--- flag arity: typo after a boolean flag, vs a flag-shaped value ---"
printf 'flag-shaped-value probe\n' > "$TMP/--weird.txt"
for l in "${LANGS[@]}"; do
    # (a) a flag-shaped VALUE must be accepted, not misread as a flag
    if ${CLI[$l]} dgst --algo hfscx-256 --in "$TMP/--weird.txt" \
           --out "$TMP/w_$l.pem" >/dev/null 2>&1; then
        pass "arity ($l): a file named --weird.txt is accepted as a value"
    else
        fail "arity ($l): a flag-shaped VALUE was rejected — it is legal input in py and go"
    fi
    # (b) a typo immediately after a BOOLEAN flag must still be refused.  Only
    #     meaningful where --aead exists; where it does not, the CLI refuses at
    #     --aead itself, which section 3 already covers.
    if ${CLI[$l]} enc --algo hske-nla1 --aead --nosuchflag --key "$TMP/sess.pem" \
           --in "$TMP/msg.txt" --out "$TMP/ar_$l.pem" >/dev/null 2>&1; then
        fail "arity ($l): --nosuchflag after the boolean --aead was accepted with exit 0"
    else
        pass "arity ($l): a typo following the boolean --aead is refused"
    fi
done

echo
echo "Results: $PASS PASS / $FAIL FAIL (languages: ${LANGS[*]})"
[ "$FAIL" -eq 0 ] || exit 1
