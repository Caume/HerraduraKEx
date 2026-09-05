#!/usr/bin/env bash
# CliTest/test_kdf_matrix.sh — TODO #269: `kex --kdf`, as a 4-language
# (C/Go/Python/Java) matrix over both the VALUE SET and the derived key.
#
# WHY THIS FILE EXISTS.  Two reasons, and the second is the surprising one.
#
# (1) Java had no `--kdf` at all until v6.5.0.  TODO #267's flag matrix is what
#     surfaced that, as it surfaced `--digest` before it.
#
# (2) `--kdf hfscx-256` had NEVER been tested across languages in ANY pair.  The
#     only script in this directory that mentioned the flag was
#     test_rnl_sp800227_kdf.sh, which is Python-vs-Python by construction --
#     sp800227 exists in no other CLI.  So C and Go had shipped the flag since
#     before 2.0.0 with nothing anywhere asserting that their post-hash agreed
#     with Python's, or with each other's.  It does; that is now checked rather
#     than assumed.
#
# WHY THE VALUE SET IS PART OF THE SUBJECT.  TODO #267's matrix is at FLAG
# granularity: it knows a CLI defines `--kdf`, not which values that CLI accepts.
# Two divergences lived under that floor, both found by TODO #269 and both fixed
# or recorded here:
#
#   * `--kdf none` -- Python's own DEFAULT value, printed in its help text -- was
#     a hard error in C and Go, so a command line copied from the Python CLI
#     failed against the other two.  Now accepted by all four as a no-op alias.
#   * `--kdf sp800227` (TODO #165) is Python-only and stays that way.  It is
#     asserted REJECTED in the other three, which is the safe direction: a peer
#     asking for it gets an error, never a silently different session key.
#
# WHAT EARNS THE FILE is the same negative control test_digest_matrix.sh needed.
# A CLI that parsed `--kdf` and ignored it would pass every positive cell -- all
# four would emit the un-hashed key and all four would agree.  So the hashed and
# un-hashed keys are also asserted DIFFERENT, and a responder and completer that
# disagree about the flag are asserted NOT to derive the same key.
#
# Claimed by ci.yml's cross-lang-compat job (all four CLIs built).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
PASS=0; FAIL=0

declare -A CLI=()
CLI[py]="python3 $ROOT/HerraduraCli/herradura.py"
[ -x "$ROOT/HerraduraCli/herradura_cli" ]    && CLI[c]="$ROOT/HerraduraCli/herradura_cli"
[ -x "$ROOT/HerraduraCli/herradura_cli_go" ] && CLI[go]="$ROOT/HerraduraCli/herradura_cli_go"
if command -v javac >/dev/null 2>&1; then
    bash bindings/java/build.sh >/dev/null 2>&1
    CLI[java]="java -cp $ROOT/bindings/java herradurakex.HerraduraCli"
fi

LANGS=()
for l in py c go java; do
    [ -n "${CLI[$l]:-}" ] && LANGS+=("$l")
done
echo "Languages under test: ${LANGS[*]}"

# TODO #229: name every absence out loud.
. "$ROOT/CliTest/lib_build.sh"
for l in c go; do
    [ -n "${CLI[$l]:-}" ] || echo "NOTE: $l CLI absent — $(hkx_why "$l")"
done
[ -n "${CLI[java]:-}" ] || echo "NOTE: java CLI absent — javac is not installed"
if [ -z "${CLI[java]:-}" ]; then
    echo "NOTE: Java is the language TODO #269 fixed, so this run does NOT cover" \
         "the regression it was written for."
fi
if [ "${#LANGS[@]}" -lt 2 ]; then
    echo "FAIL test_kdf_matrix: fewer than 2 CLIs available, so no cross-language" \
         "pair was compared and nothing was asserted (build C/Go, install a JDK)." >&2
    [ "${HKX_ALLOW_SKIP:-0}" = "1" ] && exit 0
    exit 2
fi

pass() { echo "PASS $1"; PASS=$((PASS+1)); }
fail() { echo "FAIL $1"; FAIL=$((FAIL+1)); }

rejects() {   # label, then the argv — MUST exit non-zero
    local label="$1"; shift
    local out rc
    out=$("$@" >/dev/null 2>&1) && rc=0 || rc=$?
    if [ "$rc" -ne 0 ]; then pass "$label"
    else fail "$label: accepted, but this value is not in the CLI's value set"; fi
}

# ── 1. hkex-gf: the session key itself, byte-compared across all four ───────
#
# hkex-gf is deterministic given (our, their), so every CLI must emit the
# BYTE-IDENTICAL session-key PEM in each mode.  That is a stronger assertion
# than a round-trip and it is available here only because there is no nonce.
echo "=== hkex-gf: session-key bytes, ${#LANGS[@]} CLIs x 3 modes ==="
${CLI[py]} genpkey --algo hkex-gf --out "$TMP/a.pem"  >/dev/null 2>&1
${CLI[py]} pkey --in "$TMP/a.pem" --pubout --out "$TMP/ap.pem" >/dev/null 2>&1
${CLI[py]} genpkey --algo hkex-gf --out "$TMP/b.pem"  >/dev/null 2>&1
${CLI[py]} pkey --in "$TMP/b.pem" --pubout --out "$TMP/bp.pem" >/dev/null 2>&1

for l in "${LANGS[@]}"; do
    ${CLI[$l]} kex --algo hkex-gf --our "$TMP/a.pem" --their "$TMP/bp.pem" \
               --out "$TMP/gf_omit_$l.pem" >/dev/null 2>&1 \
        || fail "hkex-gf $l: kex with --kdf omitted failed"
    ${CLI[$l]} kex --algo hkex-gf --our "$TMP/a.pem" --their "$TMP/bp.pem" \
               --kdf none --out "$TMP/gf_none_$l.pem" >/dev/null 2>&1 \
        || fail "hkex-gf $l: --kdf none rejected (Python's own default value)"
    ${CLI[$l]} kex --algo hkex-gf --our "$TMP/a.pem" --their "$TMP/bp.pem" \
               --kdf hfscx-256 --out "$TMP/gf_hash_$l.pem" >/dev/null 2>&1 \
        || fail "hkex-gf $l: --kdf hfscx-256 rejected"
done

for mode in omit none hash; do
    for l in "${LANGS[@]}"; do
        [ "$l" = "py" ] && continue
        if cmp -s "$TMP/gf_${mode}_py.pem" "$TMP/gf_${mode}_$l.pem"; then
            pass "hkex-gf --kdf $mode: py == $l (byte-identical)"
        else
            fail "hkex-gf --kdf $mode: py != $l — the post-hash disagrees across CLIs"
        fi
    done
done

# `none` must be a pure alias for omitting the flag, in every CLI: the point of
# accepting it was compatibility, not a third behaviour.
for l in "${LANGS[@]}"; do
    if cmp -s "$TMP/gf_omit_$l.pem" "$TMP/gf_none_$l.pem"; then
        pass "hkex-gf $l: --kdf none == flag omitted"
    else
        fail "hkex-gf $l: --kdf none differs from omitting the flag — 'none' is not a no-op"
    fi
done

# THE NEGATIVE CONTROL.  Without this, a CLI that parsed --kdf and ignored it
# passes every assertion above.
for l in "${LANGS[@]}"; do
    if cmp -s "$TMP/gf_none_$l.pem" "$TMP/gf_hash_$l.pem"; then
        fail "hkex-gf $l: --kdf hfscx-256 produced the SAME key as --kdf none — the flag is parsed and ignored"
    else
        pass "hkex-gf $l: --kdf hfscx-256 changes the derived key"
    fi
done

# ── 2. hkex-rnl: responder x completer, under the flag ─────────────────────
#
# Two-round and nonce-bearing, so the keys are not byte-comparable across runs.
# Agreement is asserted the way test_rnl_sp800227_kdf.sh asserts it: the
# responder's RESPONSE PEM carries Bob's key and is usable directly as an
# `enc --key`, so a cross-party encrypt/decrypt round-trip is the check.
echo "=== hkex-rnl --kdf hfscx-256: ${#LANGS[@]}x${#LANGS[@]} responder x completer ==="
printf 'KDF-MATRIX-TEST-32-BYTE-MESSAGE!' > "$TMP/msg.bin"
${CLI[py]} genpkey --algo hkex-rnl --out "$TMP/ra.pem" >/dev/null 2>&1
${CLI[py]} pkey --in "$TMP/ra.pem" --pubout --out "$TMP/rap.pem" >/dev/null 2>&1
${CLI[py]} genpkey --algo hkex-rnl --out "$TMP/rb.pem" >/dev/null 2>&1

for r in "${LANGS[@]}"; do
    if ! ${CLI[$r]} kex --algo hkex-rnl --kdf hfscx-256 --our "$TMP/rb.pem" \
             --their "$TMP/rap.pem" --out "$TMP/resp_$r.pem" >/dev/null 2>&1; then
        fail "hkex-rnl responder $r: --kdf hfscx-256 response failed"
        continue
    fi
    for c in "${LANGS[@]}"; do
        if ! ${CLI[$c]} kex --algo hkex-rnl --kdf hfscx-256 --our "$TMP/ra.pem" \
                 --their "$TMP/resp_$r.pem" --out "$TMP/sess_${r}_${c}.pem" >/dev/null 2>&1; then
            fail "hkex-rnl $r->$c: completion failed"
            continue
        fi
        # Bob (the responder) encrypts with his own response PEM; Alice
        # decrypts with the session key her completion produced.
        if ${CLI[$r]} enc --algo hske --key "$TMP/resp_$r.pem" --in "$TMP/msg.bin" \
                     --out "$TMP/ct_${r}_${c}.pem" >/dev/null 2>&1 \
           && ${CLI[$c]} dec --algo hske --key "$TMP/sess_${r}_${c}.pem" \
                     --in "$TMP/ct_${r}_${c}.pem" --out "$TMP/pt_${r}_${c}.bin" >/dev/null 2>&1 \
           && cmp -s "$TMP/msg.bin" "$TMP/pt_${r}_${c}.bin"; then
            pass "hkex-rnl --kdf hfscx-256 $r->$c: keys agree"
        else
            fail "hkex-rnl --kdf hfscx-256 $r->$c: keys DISAGREE"
        fi
    done
done

# THE NEGATIVE CONTROL for the two-round path: a responder that applied the
# post-hash and a completer that did not must NOT land on the same key.  Both
# sides passing the same --kdf is a protocol requirement, not a formality.
echo "=== hkex-rnl: mismatched --kdf must not agree ==="
for l in "${LANGS[@]}"; do
    ${CLI[$l]} kex --algo hkex-rnl --kdf hfscx-256 --our "$TMP/rb.pem" \
               --their "$TMP/rap.pem" --out "$TMP/mm_resp_$l.pem" >/dev/null 2>&1
    ${CLI[$l]} kex --algo hkex-rnl --our "$TMP/ra.pem" \
               --their "$TMP/mm_resp_$l.pem" --out "$TMP/mm_sess_$l.pem" >/dev/null 2>&1
    ${CLI[$l]} enc --algo hske --key "$TMP/mm_sess_$l.pem" --in "$TMP/msg.bin" \
               --out "$TMP/mm_ct_$l.pem" >/dev/null 2>&1
    if ${CLI[$l]} dec --algo hske --key "$TMP/mm_resp_$l.pem" --in "$TMP/mm_ct_$l.pem" \
                 --out "$TMP/mm_pt_$l.bin" >/dev/null 2>&1 \
       && cmp -s "$TMP/msg.bin" "$TMP/mm_pt_$l.bin"; then
        fail "hkex-rnl $l: responder with --kdf and completer without derived the SAME key"
    else
        pass "hkex-rnl $l: mismatched --kdf does not agree"
    fi
done

# ── 3. The value set itself ────────────────────────────────────────────────
#
# This is the axis TODO #267's flag matrix does not reach, and the reason
# spec/generate_spec.py grew CLI_FLAG_VALUES.  Asserted here so the curated
# table has something executable standing behind it.
echo "=== --kdf value set ==="
for l in "${LANGS[@]}"; do
    rejects "kex $l: --kdf bogus-value rejected" \
        ${CLI[$l]} kex --algo hkex-gf --our "$TMP/a.pem" --their "$TMP/bp.pem" \
        --kdf bogus-value --out "$TMP/vs_$l.pem"
done

# sp800227 (TODO #165) is Python-only.  Python must ACCEPT it on hkex-rnl -- an
# accept-control, without which "everyone rejects it" would pass trivially --
# and the other three must reject it BY VALUE rather than silently ignoring it.
if ${CLI[py]} kex --algo hkex-rnl --kdf sp800227 --our "$TMP/rb.pem" \
             --their "$TMP/rap.pem" --out "$TMP/sp_resp.pem" >/dev/null 2>&1; then
    pass "kex py: --kdf sp800227 accepted on hkex-rnl (accept-control)"
else
    fail "kex py: --kdf sp800227 rejected by the one CLI that implements it"
fi
for l in "${LANGS[@]}"; do
    [ "$l" = "py" ] && continue
    rejects "kex $l: --kdf sp800227 rejected (Python-only, TODO #165)" \
        ${CLI[$l]} kex --algo hkex-rnl --kdf sp800227 --our "$TMP/rb.pem" \
        --their "$TMP/rap.pem" --out "$TMP/sp_$l.pem"
done

echo
echo "test_kdf_matrix: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ] || exit 1
