#!/usr/bin/env bash
# CliTest/test_fpe_twk.sh — TODO #242: `fpe` and `twk` at the CLI, across
# every implementation that ships them (C, Go, Python, and — since TODO
# #260's v5.3.6 — Java, optionally: this script degrades to a NOTE and
# 3-way coverage if no JDK is installed).
#
# These two subcommands had no CliTest script at all until this one, which is
# how the defect TODO #241 found survived: through v3.3.1 both derived their
# subkey as the unseparated HFSCX-256(key || tweak), so a 12-byte fpe context
# equal to twk's sector_be64 || bidx_be32 made the two subcommands the identical
# function -- `twk --decrypt` recovered what `fpe --encrypt` produced, in every
# implementation. See SecurityProofs-7.md §11.24.
#
# What this script guards, in order of what would hurt most if it broke:
#   1. the two primitives are domain-separated and no longer collide;
#   2. the key||tweak boundary is length-encoded, so distinct (key, tweak)
#      pairs cannot alias;
#   3. C, Go and Python agree byte-for-byte -- this is a wire contract, and
#      until now nothing checked it for these two subcommands;
#   4. round-trips still work, including across implementations.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

. "$(dirname "$0")/lib_build.sh"

CLI_PY="python3 $ROOT/HerraduraCli/herradura.py"
CLI_C="$ROOT/HerraduraCli/herradura_cli"
CLI_GO="$ROOT/HerraduraCli/herradura_cli_go"

hkx_require_built c go

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
PASS=0; FAIL=0

ok()   { echo "PASS $1"; PASS=$((PASS+1)); }
bad()  { echo "FAIL $1"; FAIL=$((FAIL+1)); }
same() { if cmp -s "$2" "$3"; then ok "$1"; else bad "$1"; fi; }
diff_() { if cmp -s "$2" "$3"; then bad "$1"; else ok "$1"; fi; }

HAVE_JAVA=0
if command -v javac >/dev/null 2>&1; then
    bash "$ROOT/bindings/java/build.sh" >/dev/null 2>&1
    CLI_JAVA="java -cp $ROOT/bindings/java herradurakex.HerraduraCli"
    HAVE_JAVA=1
else
    echo "NOTE: javac not found — skipping Java's fpe/twk rows"
fi

cli_for() {
    case "$1" in
        py)   echo "$CLI_PY" ;;
        c)    echo "$CLI_C"  ;;
        go)   echo "$CLI_GO" ;;
        java) echo "$CLI_JAVA" ;;
    esac
}

# ── A session key PEM every implementation accepts ───────────────────────────
# (The `0x...` hex-key shorthand is a Python-CLI convenience the C CLI rejects,
# so a real HERRADURA SESSION KEY PEM is the only portable input here.)
$CLI_PY genpkey --algo hkex-gf --out "$TMP/a.pem"      >/dev/null
$CLI_PY pkey --in "$TMP/a.pem" --pubout --out "$TMP/apub.pem" >/dev/null
$CLI_PY genpkey --algo hkex-gf --out "$TMP/b.pem"      >/dev/null
$CLI_PY pkey --in "$TMP/b.pem" --pubout --out "$TMP/bpub.pem" >/dev/null
$CLI_PY kex --algo hkex-gf --our "$TMP/a.pem" --their "$TMP/bpub.pem" \
            --out "$TMP/sk.pem" >/dev/null

head -c 32 /dev/urandom > "$TMP/pt.bin"

# The colliding shape, spelled out: ctx must be the 12 bytes
# sector_be64 || bidx_be32, and every byte of it is printable ASCII so it can
# be passed as a --context string.
COLLIDE_CTX='0123456789:;'
COLLIDE_SECTOR=3472611983179986487    # int.from_bytes(b'01234567', 'big')
COLLIDE_BIDX=943274555                # int.from_bytes(b'89:;',     'big')

[ "$HAVE_JAVA" -eq 1 ] && langs="py c go java" || langs="py c go"

# ── 1. Round-trips, per implementation ───────────────────────────────────────
for l in $langs; do
    CLI=$(cli_for "$l")
    $CLI fpe --key "$TMP/sk.pem" --context "$COLLIDE_CTX" \
             --encrypt --in "$TMP/pt.bin" --out "$TMP/fpe_$l.bin"
    $CLI fpe --key "$TMP/sk.pem" --context "$COLLIDE_CTX" \
             --decrypt --in "$TMP/fpe_$l.bin" --out "$TMP/fpe_rt_$l.bin"
    same "[$l] fpe encrypt->decrypt round-trip" "$TMP/pt.bin" "$TMP/fpe_rt_$l.bin"

    $CLI twk --key "$TMP/sk.pem" --sector "$COLLIDE_SECTOR" --bidx "$COLLIDE_BIDX" \
             --encrypt --in "$TMP/pt.bin" --out "$TMP/twk_$l.bin"
    $CLI twk --key "$TMP/sk.pem" --sector "$COLLIDE_SECTOR" --bidx "$COLLIDE_BIDX" \
             --decrypt --in "$TMP/twk_$l.bin" --out "$TMP/twk_rt_$l.bin"
    same "[$l] twk encrypt->decrypt round-trip" "$TMP/pt.bin" "$TMP/twk_rt_$l.bin"
done

# ── 2. The regression this script exists for ─────────────────────────────────
# fpe and twk must NOT agree on the input that used to make them identical.
for l in $langs; do
    diff_ "[$l] fpe and twk are domain-separated (no collision)" \
          "$TMP/fpe_$l.bin" "$TMP/twk_$l.bin"
done

# And twk --decrypt must NOT recover a plaintext that fpe --encrypt produced.
for l in $langs; do
    CLI=$(cli_for "$l")
    $CLI twk --key "$TMP/sk.pem" --sector "$COLLIDE_SECTOR" --bidx "$COLLIDE_BIDX" \
             --decrypt --in "$TMP/fpe_$l.bin" --out "$TMP/cross_$l.bin"
    diff_ "[$l] twk --decrypt does not undo fpe --encrypt" \
          "$TMP/pt.bin" "$TMP/cross_$l.bin"
done

# ── 3. Cross-implementation agreement (the wire contract) ────────────────────
for l in $langs; do
    [ "$l" = py ] && continue
    same "fpe: python vs $l agree byte-for-byte" "$TMP/fpe_py.bin" "$TMP/fpe_$l.bin"
    same "twk: python vs $l agree byte-for-byte" "$TMP/twk_py.bin" "$TMP/twk_$l.bin"
done

# Cross-implementation decrypt, both directions on each pair.
for enc in $langs; do
    for dec in $langs; do
        [ "$enc" = "$dec" ] && continue
        DCLI=$(cli_for "$dec")
        $DCLI fpe --key "$TMP/sk.pem" --context "$COLLIDE_CTX" \
                  --decrypt --in "$TMP/fpe_$enc.bin" --out "$TMP/x.bin"
        same "fpe: $enc encrypt -> $dec decrypt" "$TMP/pt.bin" "$TMP/x.bin"
        $DCLI twk --key "$TMP/sk.pem" --sector "$COLLIDE_SECTOR" --bidx "$COLLIDE_BIDX" \
                  --decrypt --in "$TMP/twk_$enc.bin" --out "$TMP/y.bin"
        same "twk: $enc encrypt -> $dec decrypt" "$TMP/pt.bin" "$TMP/y.bin"
    done
done

# ── 4. Tweak separation within each primitive ────────────────────────────────
# A different context, sector or block index must give a different ciphertext,
# or the tweak is not reaching the subkey at all.
for l in $langs; do
    CLI=$(cli_for "$l")
    $CLI fpe --key "$TMP/sk.pem" --context "other-context" \
             --encrypt --in "$TMP/pt.bin" --out "$TMP/fpe_ctx2_$l.bin"
    diff_ "[$l] fpe: a different --context gives different output" \
          "$TMP/fpe_$l.bin" "$TMP/fpe_ctx2_$l.bin"

    $CLI twk --key "$TMP/sk.pem" --sector $((COLLIDE_SECTOR + 1)) --bidx "$COLLIDE_BIDX" \
             --encrypt --in "$TMP/pt.bin" --out "$TMP/twk_sec2_$l.bin"
    diff_ "[$l] twk: a different --sector gives different output" \
          "$TMP/twk_$l.bin" "$TMP/twk_sec2_$l.bin"

    $CLI twk --key "$TMP/sk.pem" --sector "$COLLIDE_SECTOR" --bidx $((COLLIDE_BIDX + 1)) \
             --encrypt --in "$TMP/pt.bin" --out "$TMP/twk_bix2_$l.bin"
    diff_ "[$l] twk: a different --bidx gives different output" \
          "$TMP/twk_$l.bin" "$TMP/twk_bix2_$l.bin"
done

# ── 5. A different key must give a different ciphertext ──────────────────────
$CLI_PY genpkey --algo hkex-gf --out "$TMP/c.pem" >/dev/null
$CLI_PY pkey --in "$TMP/c.pem" --pubout --out "$TMP/cpub.pem" >/dev/null
$CLI_PY kex --algo hkex-gf --our "$TMP/a.pem" --their "$TMP/cpub.pem" \
            --out "$TMP/sk2.pem" >/dev/null
$CLI_PY fpe --key "$TMP/sk2.pem" --context "$COLLIDE_CTX" \
            --encrypt --in "$TMP/pt.bin" --out "$TMP/fpe_key2.bin"
diff_ "fpe: a different session key gives different output" \
      "$TMP/fpe_py.bin" "$TMP/fpe_key2.bin"

# ── 6. Exactly one 32-byte block, one mode (TODO #377) ───────────────────────
# Until v16.0.0 every CLI cut longer input to its first 32 bytes (exit 0, and
# nothing round-tripped) and zero-padded shorter input -- on the right in
# Python, C and Java, on the LEFT in Go, so Go's ciphertext differed at every
# length but 32.  The sections above only ever fed 32 bytes.  Now any other
# length is refused by name, with no output written; and C and Go, which
# encrypted when given both --encrypt and --decrypt, refuse that as Python and
# Java did.  Sections 1-3 are this section's accept-control at v2; the --v3
# rows below are its accept-control at v3.
tweak_args() {   # the tweak flags for $1 (fpe | twk)
    if [ "$1" = fpe ]; then echo "--context $COLLIDE_CTX"
    else echo "--sector $COLLIDE_SECTOR --bidx $COLLIDE_BIDX"; fi
}
refused() {      # label, expected stderr substring, command...
    local label=$1 want=$2; shift 2
    rm -f "$TMP/r_out.bin"
    local out rc
    out=$("$@" --out "$TMP/r_out.bin" 2>&1) && rc=0 || rc=$?
    if [ "$rc" -eq 0 ]; then bad "$label: accepted (rc=0)"
    elif [ "$rc" -gt 2 ]; then bad "$label: crashed (rc=$rc): $out"
    elif ! grep -qF -- "$want" <<<"$out"; then bad "$label: wrong message: $out"
    elif [ -e "$TMP/r_out.bin" ]; then bad "$label: refused but wrote output"
    else ok "$label"; fi
}
for n in 0 1 31 33 64; do head -c "$n" /dev/urandom > "$TMP/len$n.bin"; done
for l in $langs; do
    CLI=$(cli_for "$l")
    for cmd in fpe twk; do
        # accept-control at v3: a 32-byte block round-trips
        # shellcheck disable=SC2046
        $CLI $cmd --key "$TMP/sk.pem" $(tweak_args $cmd) --v3 --encrypt \
                  --in "$TMP/pt.bin" --out "$TMP/v3_$cmd.bin"
        # shellcheck disable=SC2046
        $CLI $cmd --key "$TMP/sk.pem" $(tweak_args $cmd) --v3 --decrypt \
                  --in "$TMP/v3_$cmd.bin" --out "$TMP/v3_rt_$cmd.bin"
        same "[$l] $cmd --v3: a 32-byte block round-trips" "$TMP/pt.bin" "$TMP/v3_rt_$cmd.bin"
        for mode in --encrypt --decrypt; do
            for n in 0 1 31 33 64; do
                for v in "" --v3; do
                    # shellcheck disable=SC2046
                    refused "[$l] $cmd $mode $v: $n-byte --in refused" \
                        "$cmd: --in must be exactly 32 bytes (one block), got $n" \
                        $CLI $cmd --key "$TMP/sk.pem" $(tweak_args $cmd) $mode $v \
                                  --in "$TMP/len$n.bin"
                done
            done
        done
        if [ "$l" = py ]; then want="not allowed with argument"
        else want="$cmd: exactly one of --encrypt or --decrypt required"; fi
        # shellcheck disable=SC2046
        refused "[$l] $cmd --encrypt --decrypt refused" "$want" \
            $CLI $cmd --key "$TMP/sk.pem" $(tweak_args $cmd) --encrypt --decrypt \
                      --in "$TMP/pt.bin"
    done
done

echo ""
echo "Results: $PASS PASS / $FAIL FAIL"
[ "$FAIL" -eq 0 ]
