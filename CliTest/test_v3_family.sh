#!/usr/bin/env bash
# CliTest/test_v3_family.sh — TODO #255: the five NL-FSCX v3 consumers at the
# CLI, across every implementation that ships each one.
#
#   hske-nla3      C, Go, Python, Java   (--algo)
#   hpke-nl3       C, Go, Python, Java   (--algo, own PEM labels)
#   hske-duplex3   C, Go, Python, Java   (--algo; TODO #260 added Java's duplex in v5.3.8)
#   fpe --v3       C, Go, Python, Java   (flag; TODO #260 added Java's fpe/twk in v5.3.6)
#   twk --v3       C, Go, Python, Java   (flag)
#
# Java columns above degrade to a NOTE rather than failing outright if
# bindings/java is not compiled (HAVE_JAVA below) -- see native-interop's
# coverage-guard step, which still requires this script be claimed by
# exactly one native-* job regardless.
#
# WHY A FLAG AND NOT A SUBCOMMAND, for fpe/twk: recorded in TODO #255 and
# SECURITY.md's FPE-V3 row.  Both are already filed in spec/ by CLI binding
# rather than by --algo tag, the flag keeps every other option identical between
# the two variants, and a second pair of subcommands would have doubled a
# surface TODO #241 already found confusing.  This script therefore exercises
# them as `fpe --v3` / `twk --v3`, and asserts the flag actually changes the
# output -- a flag that parses and is then ignored would round-trip perfectly.
#
# What this guards, in order of what would hurt most if it broke:
#   1. every v3 artifact is byte-identical across implementations.  These are
#      new wire formats; nothing else pins them at the CLI layer.
#   2. every v3 variant is domain-separated from its v2 counterpart, and the
#      duplex is separated at the PARSER (format tag 4 vs 3) rather than only by
#      a tag mismatch 160 rounds later.
#   3. fpe --v3 and twk --v3 do not collide at a 12-byte context -- the exact
#      shape of the TODO #241 bug, in new code.
#   4. round-trips, including across implementations.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

. "$(dirname "$0")/lib_build.sh"

CLI_PY="python3 $ROOT/HerraduraCli/herradura.py"
CLI_C="$ROOT/HerraduraCli/herradura_cli"
CLI_GO="$ROOT/HerraduraCli/herradura_cli_go"
CLI_JAVA="java -cp $ROOT/bindings/java herradurakex.HerraduraCli"

hkx_require_built c go

HAVE_JAVA=1
if ! [ -f "$ROOT/bindings/java/herradurakex/HerraduraCli.class" ]; then
    HAVE_JAVA=0
    echo "NOTE: bindings/java not compiled — skipping the Java columns."
    echo "      (run bindings/java/build.sh; native-java builds it in CI)"
fi

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
PASS=0; FAIL=0

ok()    { echo "PASS $1"; PASS=$((PASS+1)); }
bad()   { echo "FAIL $1"; FAIL=$((FAIL+1)); }
same()  { if cmp -s "$2" "$3"; then ok "$1"; else bad "$1"; fi; }
diff_() { if cmp -s "$2" "$3"; then bad "$1"; else ok "$1"; fi; }
rejects() {   # rejects "<name>" <command...>  — the command MUST exit non-zero
    local name="$1"; shift
    if "$@" >/dev/null 2>&1; then bad "$name (accepted)"; else ok "$name"; fi
}

cli_for() {
    case "$1" in
        py)   echo "$CLI_PY" ;;
        c)    echo "$CLI_C" ;;
        go)   echo "$CLI_GO" ;;
        java) echo "$CLI_JAVA" ;;
    esac
}

# ── Inputs every implementation accepts ──────────────────────────────────────
$CLI_PY genpkey --algo hkex-gf --out "$TMP/a.pem"              >/dev/null
$CLI_PY genpkey --algo hkex-gf --out "$TMP/b.pem"              >/dev/null
$CLI_PY pkey --in "$TMP/b.pem" --pubout --out "$TMP/bpub.pem"  >/dev/null
$CLI_PY kex --algo hkex-gf --our "$TMP/a.pem" --their "$TMP/bpub.pem" \
            --out "$TMP/sk.pem"                                >/dev/null
head -c 32 /dev/urandom > "$TMP/pt.bin"

[ "$HAVE_JAVA" -eq 1 ] && sym_langs="py c go java" || sym_langs="py c go"
[ "$HAVE_JAVA" -eq 1 ] && nla3_langs="py c go java" || nla3_langs="py c go"

# ── 1. hske-nla3 ─────────────────────────────────────────────────────────────
for l in $nla3_langs; do
    CLI=$(cli_for "$l")
    $CLI enc --algo hske-nla3 --key "$TMP/sk.pem" --in "$TMP/pt.bin" \
             --out "$TMP/nla3_$l.pem"
    $CLI dec --algo hske-nla3 --key "$TMP/sk.pem" --in "$TMP/nla3_$l.pem" \
             --out "$TMP/nla3_rt_$l.bin"
    same "[$l] hske-nla3 round-trip" "$TMP/pt.bin" "$TMP/nla3_rt_$l.bin"
done
for l in $nla3_langs; do
    [ "$l" = py ] && continue
    same "hske-nla3: python vs $l byte-identical" "$TMP/nla3_py.pem" "$TMP/nla3_$l.pem"
done
# v3 must differ from v2 on the same key and plaintext.
$CLI_PY enc --algo hske-nla2 --key "$TMP/sk.pem" --in "$TMP/pt.bin" --out "$TMP/nla2.pem"
diff_ "hske-nla3 differs from hske-nla2" "$TMP/nla3_py.pem" "$TMP/nla2.pem"

# ── 2. hpke-nl3 ──────────────────────────────────────────────────────────────
# Its own PEM labels, so keygen must round-trip through every implementation too.
for l in $nla3_langs; do
    CLI=$(cli_for "$l")
    $CLI genpkey --algo hpke-nl3 --out "$TMP/h_$l.pem" >/dev/null
    grep -q "HERRADURA HPKE-NL3 PRIVATE KEY" "$TMP/h_$l.pem" \
        && ok "[$l] hpke-nl3 genpkey emits the HPKE-NL3 label" \
        || bad "[$l] hpke-nl3 genpkey emits the HPKE-NL3 label"
    $CLI pkey --in "$TMP/h_$l.pem" --pubout --out "$TMP/hpub_$l.pem" >/dev/null
done
# Every (encryptor, decryptor) pair, on one key, so the ciphertext format is
# pinned in both directions rather than only against Python.
for enc in $nla3_langs; do
    ECLI=$(cli_for "$enc")
    $ECLI enc --algo hpke-nl3 --pubkey "$TMP/hpub_py.pem" --in "$TMP/pt.bin" \
              --out "$TMP/hpke3_$enc.pem"
    for dec in $nla3_langs; do
        DCLI=$(cli_for "$dec")
        $DCLI dec --algo hpke-nl3 --key "$TMP/h_py.pem" --in "$TMP/hpke3_$enc.pem" \
                  --out "$TMP/hpke3_${enc}_$dec.bin"
        same "hpke-nl3: $enc encrypt -> $dec decrypt" \
             "$TMP/pt.bin" "$TMP/hpke3_${enc}_$dec.bin"
    done
done

# ── 3. hske-duplex3 ──────────────────────────────────────────────────────────
for l in $sym_langs; do
    CLI=$(cli_for "$l")
    $CLI enc --algo hske-duplex3 --key "$TMP/sk.pem" --in "$TMP/pt.bin" \
             --ad "v3-header" --out "$TMP/dpx3_$l.pem"
    $CLI dec --algo hske-duplex3 --key "$TMP/sk.pem" --in "$TMP/dpx3_$l.pem" \
             --ad "v3-header" --out "$TMP/dpx3_rt_$l.bin"
    same "[$l] hske-duplex3 round-trip" "$TMP/pt.bin" "$TMP/dpx3_rt_$l.bin"
    # A tag that authenticates anything is worse than no tag.
    rejects "[$l] hske-duplex3 rejects a changed --ad" \
        $CLI dec --algo hske-duplex3 --key "$TMP/sk.pem" --in "$TMP/dpx3_$l.pem" \
                 --ad "v3-header-X" --out "$TMP/void.bin"
done
# Cross-implementation decrypt.  The nonce is random per encryption, so the
# ciphertexts are not comparable byte-for-byte -- decryptability is the contract.
for enc in $sym_langs; do
    for dec in $sym_langs; do
        [ "$enc" = "$dec" ] && continue
        DCLI=$(cli_for "$dec")
        $DCLI dec --algo hske-duplex3 --key "$TMP/sk.pem" --in "$TMP/dpx3_$enc.pem" \
                  --ad "v3-header" --out "$TMP/dx.bin"
        same "hske-duplex3: $enc encrypt -> $dec decrypt" "$TMP/pt.bin" "$TMP/dx.bin"
    done
done
# Format tag 4 vs 3: each variant must refuse the other's artifact AT THE
# PARSER, not 160 rounds later as an opaque tag mismatch.
$CLI_PY enc --algo hske-duplex --key "$TMP/sk.pem" --in "$TMP/pt.bin" \
            --ad "v3-header" --out "$TMP/dpx2.pem"
for l in $sym_langs; do
    CLI=$(cli_for "$l")
    rejects "[$l] hske-duplex3 refuses a v2 (format 3) ciphertext" \
        $CLI dec --algo hske-duplex3 --key "$TMP/sk.pem" --in "$TMP/dpx2.pem" \
                 --ad "v3-header" --out "$TMP/void.bin"
    rejects "[$l] hske-duplex refuses a v3 (format 4) ciphertext" \
        $CLI dec --algo hske-duplex --key "$TMP/sk.pem" --in "$TMP/dpx3_py.pem" \
                 --ad "v3-header" --out "$TMP/void.bin"
done

# ── 4. fpe --v3 / twk --v3 ───────────────────────────────────────────────────
# Same colliding shape test_fpe_twk.sh uses: ctx is exactly the 12 bytes
# sector_be64 || bidx_be32, all printable so it can be passed as --context.
COLLIDE_CTX='0123456789:;'
COLLIDE_SECTOR=3472611983179986487    # int.from_bytes(b'01234567', 'big')
COLLIDE_BIDX=943274555                # int.from_bytes(b'89:;',     'big')

for l in $sym_langs; do
    CLI=$(cli_for "$l")
    $CLI fpe --v3 --key "$TMP/sk.pem" --context "$COLLIDE_CTX" \
             --encrypt --in "$TMP/pt.bin" --out "$TMP/fpe3_$l.bin"
    $CLI fpe --v3 --key "$TMP/sk.pem" --context "$COLLIDE_CTX" \
             --decrypt --in "$TMP/fpe3_$l.bin" --out "$TMP/fpe3_rt_$l.bin"
    same "[$l] fpe --v3 round-trip" "$TMP/pt.bin" "$TMP/fpe3_rt_$l.bin"

    $CLI twk --v3 --key "$TMP/sk.pem" --sector "$COLLIDE_SECTOR" --bidx "$COLLIDE_BIDX" \
             --encrypt --in "$TMP/pt.bin" --out "$TMP/twk3_$l.bin"
    $CLI twk --v3 --key "$TMP/sk.pem" --sector "$COLLIDE_SECTOR" --bidx "$COLLIDE_BIDX" \
             --decrypt --in "$TMP/twk3_$l.bin" --out "$TMP/twk3_rt_$l.bin"
    same "[$l] twk --v3 round-trip" "$TMP/pt.bin" "$TMP/twk3_rt_$l.bin"

    # The v2 forms, for the separation assertions below.
    $CLI fpe --key "$TMP/sk.pem" --context "$COLLIDE_CTX" \
             --encrypt --in "$TMP/pt.bin" --out "$TMP/fpe2_$l.bin"
    $CLI twk --key "$TMP/sk.pem" --sector "$COLLIDE_SECTOR" --bidx "$COLLIDE_BIDX" \
             --encrypt --in "$TMP/pt.bin" --out "$TMP/twk2_$l.bin"

    # A flag that parses and is then ignored would pass every round-trip above.
    diff_ "[$l] fpe --v3 output differs from fpe" "$TMP/fpe3_$l.bin" "$TMP/fpe2_$l.bin"
    diff_ "[$l] twk --v3 output differs from twk" "$TMP/twk3_$l.bin" "$TMP/twk2_$l.bin"
    # TODO #241's bug, in new code: the two must not collide at a 12-byte ctx.
    diff_ "[$l] fpe --v3 and twk --v3 are domain-separated" \
          "$TMP/fpe3_$l.bin" "$TMP/twk3_$l.bin"
    # ...nor across the version boundary, in either direction.
    diff_ "[$l] fpe --v3 does not collide with twk (v2)" \
          "$TMP/fpe3_$l.bin" "$TMP/twk2_$l.bin"
    diff_ "[$l] twk --v3 does not collide with fpe (v2)" \
          "$TMP/twk3_$l.bin" "$TMP/fpe2_$l.bin"
done

for l in $sym_langs; do
    [ "$l" = py ] && continue
    same "fpe --v3: python vs $l byte-identical" "$TMP/fpe3_py.bin" "$TMP/fpe3_$l.bin"
    same "twk --v3: python vs $l byte-identical" "$TMP/twk3_py.bin" "$TMP/twk3_$l.bin"
done

for enc in $sym_langs; do
    for dec in $sym_langs; do
        [ "$enc" = "$dec" ] && continue
        DCLI=$(cli_for "$dec")
        $DCLI fpe --v3 --key "$TMP/sk.pem" --context "$COLLIDE_CTX" \
                  --decrypt --in "$TMP/fpe3_$enc.bin" --out "$TMP/fx.bin"
        same "fpe --v3: $enc encrypt -> $dec decrypt" "$TMP/pt.bin" "$TMP/fx.bin"
        $DCLI twk --v3 --key "$TMP/sk.pem" --sector "$COLLIDE_SECTOR" \
                  --bidx "$COLLIDE_BIDX" --decrypt --in "$TMP/twk3_$enc.bin" \
                  --out "$TMP/ty.bin"
        same "twk --v3: $enc encrypt -> $dec decrypt" "$TMP/pt.bin" "$TMP/ty.bin"
    done
done

# Decrypting a v3 artifact WITHOUT --v3 must not recover the plaintext.  These
# are unauthenticated permutations, so there is no error to raise -- the only
# observable is that the output is wrong, which is exactly what to assert.
$CLI_PY fpe --key "$TMP/sk.pem" --context "$COLLIDE_CTX" \
            --decrypt --in "$TMP/fpe3_py.bin" --out "$TMP/fpe_wrongver.bin"
diff_ "fpe without --v3 does not undo fpe --v3" "$TMP/pt.bin" "$TMP/fpe_wrongver.bin"
$CLI_PY twk --key "$TMP/sk.pem" --sector "$COLLIDE_SECTOR" --bidx "$COLLIDE_BIDX" \
            --decrypt --in "$TMP/twk3_py.bin" --out "$TMP/twk_wrongver.bin"
diff_ "twk without --v3 does not undo twk --v3" "$TMP/pt.bin" "$TMP/twk_wrongver.bin"

# ── 5. No key check anywhere in the v3 paths (TODO #255) ─────────────────────
# hske-nla2 refuses keys with delta(K) in {0, 2^(n-1)}; hske-nla3 must NOT,
# because that class does not exist for v3 (SecurityProofs-8.md §11.34.4).  A
# zero session key is the canonical member: delta(0) = 0.
# Built through the repo's own codec rather than hand-rolled DER, so the PEM is
# a genuine artifact all four CLIs parse and the assertion is about the key
# check, not about a malformed file.
python3 - "$ROOT" "$TMP/zero_sk.pem" <<'PY'
import sys, os
sys.path.insert(0, os.path.join(sys.argv[1], "HerraduraCli"))
from codec import der_seq, der_int, pem_wrap
der = der_seq(der_int(0, 32), der_int(256))
open(sys.argv[2], "w").write(pem_wrap("HERRADURA SESSION KEY", der))
PY
for l in $sym_langs; do
    CLI=$(cli_for "$l")
    rejects "[$l] hske-nla2 still refuses the affine-weak zero key" \
        $CLI enc --algo hske-nla2 --key "$TMP/zero_sk.pem" --in "$TMP/pt.bin" \
                 --out "$TMP/void.pem"
    if $CLI enc --algo hske-nla3 --key "$TMP/zero_sk.pem" --in "$TMP/pt.bin" \
                --out "$TMP/nla3_zero_$l.pem" >/dev/null 2>&1; then
        ok "[$l] hske-nla3 accepts it — v3 has no weak-key class"
    else
        bad "[$l] hske-nla3 accepts it — v3 has no weak-key class"
    fi
done

echo ""
echo "Results: $PASS PASS / $FAIL FAIL"
[ "$FAIL" -eq 0 ]
