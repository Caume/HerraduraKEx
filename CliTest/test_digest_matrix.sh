#!/usr/bin/env bash
# CliTest/test_digest_matrix.sh — TODO #269: the `--digest hfscx-256` pre-hash,
# as a 4-language (C/Go/Python/Java) signer x verifier matrix.
#
# WHY THIS FILE EXISTS.  Java's CLI had no `--digest` at all until v6.1.2, while
# the other three have taken it since well before.  TODO #267's flag matrix is
# what surfaced that; no test could have, and the reason is structural: every
# signature test in this repo either signs and verifies within ONE language, or
# compares PEM BYTES.  A signature over the raw message and a signature over its
# digest are both well-formed HPKS SIGNATURE PEMs of identical shape, so byte
# comparison sees nothing, and a single-language round-trip agrees with itself.
# The gap is only visible when one language signs and ANOTHER verifies, with the
# flag set on both sides.
#
# WHY THE MESSAGE IS 768 BYTES.  Every signature path in the suite pads-or-
# TRUNCATES the message to the key width (32 bytes at n=256), which is precisely
# why `--digest` exists.  A message at or under 32 bytes is its own truncation,
# so the raw and digest paths are both stable and the bug hides.  Past 32 bytes
# the two disagree, and before this fix Java could not produce or check a
# signature the other three considered valid over such a message at all.
#
# WHAT ACTUALLY EARNS THE FILE is the NEGATIVE control, not the matrix.  A CLI
# that PARSED `--digest` and then ignored it would pass every positive cell
# here -- all four would sign the raw message and all four would agree.  That is
# not a hypothetical: it is exactly how Java passed every existing signature test
# while being unable to interoperate on this flag.  So each pair is also checked
# to FAIL across the flag: a signature made with `--digest` must not verify
# without it, and vice versa.
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

# TODO #229: name every absence out loud.  This script's whole subject is a gap
# between languages, so a run missing the language that HAD the gap would print
# a wall of PASS lines and assert nothing about it.
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
    echo "FAIL test_digest_matrix: fewer than 2 CLIs available, so no cross-language" \
         "pair was compared and nothing was asserted (build C/Go, install a JDK)." >&2
    [ "${HKX_ALLOW_SKIP:-0}" = "1" ] && exit 0
    exit 2
fi

pass() { echo "PASS $1"; PASS=$((PASS+1)); }
fail() { echo "FAIL $1"; FAIL=$((FAIL+1)); }

# 768 bytes — 24x the 32-byte key width, so raw and pre-hashed differ.
python3 -c "import sys; sys.stdout.buffer.write(bytes(range(256))*3)" > "$TMP/msg.bin"

verify_ok() {   # label, then the verify argv
    local label="$1"; shift
    local out rc
    out=$("$@" 2>&1) && rc=0 || rc=$?
    if [ "$rc" -eq 0 ] && echo "$out" | grep -q "Signature OK"; then pass "$label"
    else fail "$label (rc=$rc): $out"; fi
}
verify_rejects() {  # label, then the verify argv — MUST NOT report success
    local label="$1"; shift
    local out rc
    out=$("$@" 2>&1) && rc=0 || rc=$?
    if [ "$rc" -ne 0 ] || ! echo "$out" | grep -q "Signature OK"; then pass "$label"
    else fail "$label: verification SUCCEEDED across the --digest flag, so the flag" \
              "is being parsed and ignored"; fi
}

for algo in hpks hpks-nl; do
    echo "=== $algo: sign/verify --digest hfscx-256, ${#LANGS[@]}x${#LANGS[@]} ==="
    ${CLI[py]} genpkey --algo "$algo" --out "$TMP/k.pem" >/dev/null 2>&1
    ${CLI[py]} pkey --in "$TMP/k.pem" --pubout --out "$TMP/p.pem" >/dev/null 2>&1

    for s in "${LANGS[@]}"; do
        # Two signatures over the same message: one pre-hashed, one raw.
        ${CLI[$s]} sign --algo "$algo" --key "$TMP/k.pem" --in "$TMP/msg.bin" \
                   --out "$TMP/dig_$s.pem" --digest hfscx-256 >/dev/null 2>&1
        ${CLI[$s]} sign --algo "$algo" --key "$TMP/k.pem" --in "$TMP/msg.bin" \
                   --out "$TMP/raw_$s.pem" >/dev/null 2>&1

        for v in "${LANGS[@]}"; do
            verify_ok "$algo digest $s->$v" \
                ${CLI[$v]} verify --algo "$algo" --pubkey "$TMP/p.pem" \
                --in "$TMP/msg.bin" --sig "$TMP/dig_$s.pem" --digest hfscx-256
            # The raw path must keep interoperating too: this fix must not have
            # changed what a plain `sign` produces.
            verify_ok "$algo raw    $s->$v" \
                ${CLI[$v]} verify --algo "$algo" --pubkey "$TMP/p.pem" \
                --in "$TMP/msg.bin" --sig "$TMP/raw_$s.pem"
            # The controls: the two paths must be distinguishable in both
            # directions, or the flag is decorative.
            verify_rejects "$algo digest-sig verified WITHOUT --digest $s->$v" \
                ${CLI[$v]} verify --algo "$algo" --pubkey "$TMP/p.pem" \
                --in "$TMP/msg.bin" --sig "$TMP/dig_$s.pem"
            verify_rejects "$algo raw-sig verified WITH --digest $s->$v" \
                ${CLI[$v]} verify --algo "$algo" --pubkey "$TMP/p.pem" \
                --in "$TMP/msg.bin" --sig "$TMP/raw_$s.pem" --digest hfscx-256
        done
    done
done

# ── threshold-aggregate --digest ───────────────────────────────────────────
# The third call site of the same pre-hash, and a separate code path in all four
# CLIs: the aggregate is what binds the message, so a signer that pre-hashes and
# an aggregator that does not produce a signature nobody can verify.  Rotated
# over the aggregator only -- the rest of the protocol carries no --digest.
#
# NOTE the flag-name split this has to work around: `--commits a b` in Python and
# Java, `--commit a --commit b` in C and Go.  Same capability, two spellings;
# that is TODO #270, and this branch is what it costs every caller.
echo "=== hpks-t: threshold-aggregate --digest, aggregator rotated ==="
${CLI[py]} genpkey --algo hpks --out "$TMP/ta.pem" >/dev/null 2>&1
${CLI[py]} genpkey --algo hpks --out "$TMP/tb.pem" >/dev/null 2>&1
${CLI[py]} threshold-commit --key "$TMP/ta.pem" --commit-out "$TMP/ca.pem" \
           --nonce-out "$TMP/na.pem" >/dev/null 2>&1
${CLI[py]} threshold-commit --key "$TMP/tb.pem" --commit-out "$TMP/cb.pem" \
           --nonce-out "$TMP/nb.pem" >/dev/null 2>&1

for agg in "${LANGS[@]}"; do
    case "$agg" in
        c|go) commits=(--commit "$TMP/ca.pem" --commit "$TMP/cb.pem") ;;
        *)    commits=(--commits "$TMP/ca.pem" "$TMP/cb.pem") ;;
    esac
    if ! ${CLI[$agg]} threshold-aggregate "${commits[@]}" --in "$TMP/msg.bin" \
         --out "$TMP/agg.pem" --digest hfscx-256 >/dev/null 2>&1; then
        fail "hpks-t threshold-aggregate --digest ($agg): aggregation failed"
        continue
    fi
    ${CLI[py]} threshold-respond --key "$TMP/ta.pem" --commits "$TMP/ca.pem" "$TMP/cb.pem" \
        --aggregate "$TMP/agg.pem" --nonce "$TMP/na.pem" --out "$TMP/pa.pem" >/dev/null 2>&1
    ${CLI[py]} threshold-respond --key "$TMP/tb.pem" --commits "$TMP/ca.pem" "$TMP/cb.pem" \
        --aggregate "$TMP/agg.pem" --nonce "$TMP/nb.pem" --out "$TMP/pb.pem" >/dev/null 2>&1
    ${CLI[py]} threshold-combine --aggregate "$TMP/agg.pem" \
        --partials "$TMP/pa.pem" "$TMP/pb.pem" --out "$TMP/tsig.pem" >/dev/null 2>&1

    for v in "${LANGS[@]}"; do
        verify_ok "hpks-t digest agg=$agg -> $v" \
            ${CLI[$v]} verify --algo hpks-t --in "$TMP/msg.bin" \
            --sig "$TMP/tsig.pem" --digest hfscx-256
        verify_rejects "hpks-t digest-agg verified WITHOUT --digest agg=$agg -> $v" \
            ${CLI[$v]} verify --algo hpks-t --in "$TMP/msg.bin" --sig "$TMP/tsig.pem"
    done
done

# ── An unrecognised --digest must not silently sign the raw message ────────
# Python rejects via argparse `choices` and Java by name, and both always did.
# C and Go compared against "hfscx-256" and IGNORED anything else, so a
# misspelled flag there signed the raw message and reported success -- fail-OPEN
# on a security-relevant option, with the weaker branch as the fallback. This
# block was a two-language assertion plus a NOTE naming C and Go until TODO #269
# fixed both (`digest_value` in herradura_cli.c, `digestValue` in
# herradura_cli.go); it is now asserted for all four.
#
# The bug was invisible to TODO #267's flag matrix by construction: that matrix
# records that a CLI DEFINES --digest, never which values it accepts. It is the
# reason spec/generate_spec.py grew CLI_FLAG_VALUES, and this loop is the
# executable half of that table.
#
# `none` is also checked, in both directions: it must be accepted (it is the
# documented default in all four) and it must mean the same thing as omitting
# the flag, or "reject everything unknown" would have been satisfied by a CLI
# that rejected the legal value too.
echo "=== --digest value set: unknown rejected, none accepted, all four ==="
for l in "${LANGS[@]}"; do
    if ${CLI[$l]} sign --algo hpks --key "$TMP/k.pem" --in "$TMP/msg.bin" \
       --out "$TMP/bogus.pem" --digest hfscx256 >/dev/null 2>&1; then
        fail "$l: sign --digest hfscx256 (misspelled) was accepted — fail-open, the raw message was signed"
    else
        pass "$l: sign --digest hfscx256 (misspelled) rejected"
    fi
    if ${CLI[$l]} sign --algo hpks --key "$TMP/k.pem" --in "$TMP/msg.bin" \
       --out "$TMP/dnone_$l.pem" --digest none >/dev/null 2>&1; then
        pass "$l: sign --digest none accepted"
    else
        fail "$l: sign --digest none rejected — it is the documented default value"
    fi
    # `--digest none` must verify against a signature made with the flag
    # omitted: the two spellings are one behaviour.
    verify_ok "$l: --digest none == flag omitted" \
        ${CLI[$l]} verify --algo hpks --pubkey "$TMP/p.pem" \
        --in "$TMP/msg.bin" --sig "$TMP/dnone_$l.pem"
done

echo
echo "Results: $PASS PASS / $FAIL FAIL (languages: ${LANGS[*]})"
[ "$FAIL" -eq 0 ]
