#!/usr/bin/env bash
# CliTest/test_single_block_enc.sh — TODO #378: a single-block `enc` refuses
# input longer than its block, and `--ad` / `--aead` are refused wherever they
# would be ignored, in every CLI.
#
# Until #378, in all four CLIs:
#   - enc --algo hske | hske-nla1 | hske-nla2 | hske-nla3 | hpke | hpke-nl |
#     hpke-nl3 | hpke-stern | hpke-stern-kem on input longer than one block
#     kept the first block, dropped the rest and exited 0; `dec` handed back a
#     prefix of the message.
#   - enc --algo hske --ad X wrote byte-for-byte the ciphertext of no --ad, and
#     dec --algo hske --ad X was accepted: the associated data the caller asked
#     to bind was dropped without a word.  --aead on hske / hpke was accepted
#     and ignored.  dec --algo hske-nla1 --ad X on a format-1 (non-AEAD)
#     ciphertext ignored X.
#   - Python and Go read `--ad ''` as "no --ad", so `enc --algo hske-nla1
#     --ad ''` passed their "--ad requires --aead" check.
#
# Sections:
#   1. accept-controls.  At the block boundary (exactly one block) every
#      single-block algo encrypts in every CLI and decrypts under every CLI to
#      the input; a short input still comes back zero-padded; hske-nla1 at a
#      64-bit key (a SECOND width, so the block is the key's 8 bytes, not a
#      hard-coded 32) round-trips 8 bytes; --ad binds where it belongs
#      (hske-duplex, hske-duplex3, hske-nla1 --aead), including `--ad ''`,
#      and a wrong --ad fails the tag; hske-duplex takes a 64-byte input.
#   2. refusals, by name, with no output written and no crash.
#
# The hpke-stern-kem `dec` cases below never read the decapsulated bytes: the
# refusal fires on the flag before any decapsulation, and its accept-control
# only asks that the same command without --ad is not refused.  Implicit
# rejection makes `dec` exit 0 on a DFR event, so a decoding failure cannot
# change either verdict -- there is nothing for lib_dfr.sh's retry to retry.
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
PY=${CLI[py]}; CC=${CLI[c]}

# ── fixtures ────────────────────────────────────────────────────────────────
# A 256-bit session key, a 64-bit one (only the Python CLI's genpkey takes
# --bits), and one key pair per asymmetric algo.
fix() { "$@" >/dev/null 2>&1 || { echo "FAIL fixture: $*" >&2; exit 1; }; }
for b in 256 64; do
    fix $PY genpkey --algo hkex-gf --bits $b --out "$TMP/ga$b.pem"
    fix $PY genpkey --algo hkex-gf --bits $b --out "$TMP/gb$b.pem"
    fix $PY pkey --in "$TMP/gb$b.pem" --pubout --out "$TMP/gbp$b.pem"
    fix $PY kex --algo hkex-gf --our "$TMP/ga$b.pem" --their "$TMP/gbp$b.pem" --out "$TMP/sk$b.pem"
done
SK="$TMP/sk256.pem"; SK64="$TMP/sk64.pem"
for a in hpke hpke-nl hpke-nl3 hpke-stern-kem; do
    fix $CC genpkey --algo $a --out "$TMP/$a.pem"
    fix $CC pkey --in "$TMP/$a.pem" --pubout --out "$TMP/$a.pub.pem"
done
SYM1=(hske hske-nla1 hske-nla2 hske-nla3)          # single-block, --key
ASYM1=(hpke hpke-nl hpke-nl3)                      # single-block, --pubkey
# (hpke-stern left this list when TODO #413 removed its enc/dec, v21.0.0.)
# keyflag <algo>: the enc key arguments for an algo; deckey: the dec ones.
keyflag() { case $1 in hske*) echo "--key $SK" ;; *) echo "--pubkey $TMP/$1.pub.pem" ;; esac; }
deckey()  { case $1 in hske*) echo "--key $SK" ;; *) echo "--key $TMP/$1.pem" ;; esac; }

head -c 32 /dev/urandom > "$TMP/m32"
head -c 33 /dev/urandom > "$TMP/m33"
head -c 64 /dev/urandom > "$TMP/m64"
head -c 8  /dev/urandom > "$TMP/m8"
head -c 9  /dev/urandom > "$TMP/m9"
printf 'short' > "$TMP/m5"
{ cat "$TMP/m5"; head -c 27 /dev/zero; } > "$TMP/m5pad"

# run <out> <cli> <args...>: run quietly, stderr to $TMP/err.
run() { local o=$1; shift; "$@" >"$TMP/so" 2>"$TMP/err" < /dev/null; }

# ── 1. accept-controls ──────────────────────────────────────────────────────
# One block exactly: every writer, every reader.
for a in "${SYM1[@]}" "${ASYM1[@]}"; do
    for w in "${LANGS[@]}"; do
        ct="$TMP/ct_${a}_$w.pem"
        # shellcheck disable=SC2046  # keyflag is two words on purpose
        if ! run "$ct" ${CLI[$w]} enc --algo $a $(keyflag $a) --in "$TMP/m32" --out "$ct"; then
            fail "enc --algo $a, 32 bytes ($w): refused: $(head -c 200 "$TMP/err")"; continue
        fi
        pass
        for r in "${LANGS[@]}"; do
            # shellcheck disable=SC2046
            if run x ${CLI[$r]} dec --algo $a $(deckey $a) --in "$ct" --out "$TMP/pt" \
                    && cmp -s "$TMP/pt" "$TMP/m32"; then pass
            else fail "dec --algo $a ($w -> $r): 32-byte block does not round-trip: $(head -c 200 "$TMP/err")"; fi
        done
    done
done
for w in "${LANGS[@]}"; do
    c=${CLI[$w]}
    # A short input is still accepted and comes back zero-padded to the block.
    if run x $c enc --algo hske --key "$SK" --in "$TMP/m5" --out "$TMP/s.pem" \
            && run x $c dec --algo hske --key "$SK" --in "$TMP/s.pem" --out "$TMP/pt" \
            && cmp -s "$TMP/pt" "$TMP/m5pad"; then pass
    else fail "enc --algo hske, 5 bytes ($w): not accepted and zero-padded: $(head -c 200 "$TMP/err")"; fi
    # Second width: at a 64-bit key the hske-nla1 block is 8 bytes.
    if run x $c enc --algo hske-nla1 --key "$SK64" --in "$TMP/m8" --out "$TMP/n8.pem" \
            && run x $c dec --algo hske-nla1 --key "$SK64" --in "$TMP/n8.pem" --out "$TMP/pt" \
            && cmp -s "$TMP/pt" "$TMP/m8"; then pass
    else fail "enc --algo hske-nla1 at 64 bits, 8 bytes ($w): $(head -c 200 "$TMP/err")"; fi
    # The KEM encrypts one 32-byte block (no decapsulation here; see header).
    if run x $c enc --algo hpke-stern-kem --pubkey "$TMP/hpke-stern-kem.pub.pem" \
            --in "$TMP/m32" --out "$TMP/kem_$w.pem" && grep -q "BEGIN HERRADURA" "$TMP/kem_$w.pem"; then pass
    else fail "enc --algo hpke-stern-kem, 32 bytes ($w): $(head -c 200 "$TMP/err")"; fi
    # --ad where it belongs: bound into the tag, '' included.
    for spec in "hske-duplex|m64" "hske-duplex3|m64" "hske-nla1 --aead|m32"; do
        alg=${spec%|*}; m=${spec#*|}; da=${alg%% *}
        for ad in hdr ''; do
            # shellcheck disable=SC2086  # $alg is one or two words on purpose
            if run x $c enc --algo $alg --key "$SK" --in "$TMP/$m" --ad "$ad" --out "$TMP/a.pem" \
                    && run x $c dec --algo $da --key "$SK" --in "$TMP/a.pem" --ad "$ad" --out "$TMP/pt" \
                    && cmp -s "$TMP/pt" "$TMP/$m"; then pass
            else fail "enc --algo $alg --ad '$ad' ($w): no round trip: $(head -c 200 "$TMP/err")"; continue; fi
            # The AD is bound: a different one fails the tag.  Shows the
            # accept-control above is not passing by ignoring --ad.
            if run x $c dec --algo $da --key "$SK" --in "$TMP/a.pem" --ad "other" --out "$TMP/pt"; then
                fail "dec --algo $da ($w): a wrong --ad was accepted"
            else pass; fi
        done
    done
    # The same commands the refusals below use, without the offending flag,
    # are accepted -- including dec of the KEM ciphertext (see header).
    for a in "${SYM1[@]}" "${ASYM1[@]}" hpke-stern-kem; do
        ct="$TMP/ct_${a}_c.pem"; [ "$a" = hpke-stern-kem ] && ct="$TMP/kem_$w.pem"
        # shellcheck disable=SC2046
        if run x $c dec --algo "$a" $(deckey $a) --in "$ct" --out "$TMP/pt"; then pass
        else fail "dec --algo $a, no --ad ($w): refused: $(head -c 200 "$TMP/err")"; fi
    done
done

# ── 2. refusals ─────────────────────────────────────────────────────────────
# "name | expected stderr | argv" — {O} is the output path that must not appear.
CASES=()
B32="encrypts one 32-byte block; --in is"
for a in "${SYM1[@]}" "${ASYM1[@]}" hpke-stern-kem; do
    kf=$(keyflag $a)
    CASES+=("enc $a, 33 bytes|enc: --algo $a $B32 33 bytes (|enc --algo $a $kf --in $TMP/m33 --out {O}")
done
CASES+=(
"enc hske, 64 bytes|enc: --algo hske $B32 64 bytes (use --algo hske-duplex or encfile|enc --algo hske --key $SK --in $TMP/m64 --out {O}"
"enc hpke, 64 bytes|enc: --algo hpke $B32 64 bytes (for longer input, encrypt a key|enc --algo hpke --pubkey $TMP/hpke.pub.pem --in $TMP/m64 --out {O}"
"enc hske-nla1 at 64 bits, 9 bytes|enc: --algo hske-nla1 encrypts one 8-byte block; --in is 9 bytes|enc --algo hske-nla1 --key $SK64 --in $TMP/m9 --out {O}"
"enc hske-nla1 --aead, 33 bytes|enc: --algo hske-nla1 $B32 33 bytes|enc --algo hske-nla1 --aead --key $SK --in $TMP/m33 --out {O}"
"enc hske-nla1 --ad X, no --aead|enc: --ad requires --aead|enc --algo hske-nla1 --key $SK --in $TMP/m32 --ad X --out {O}"
"enc hske-nla1 --ad '', no --aead|enc: --ad requires --aead|enc --algo hske-nla1 --key $SK --in $TMP/m32 --ad '' --out {O}"
"enc hske --ad ''|enc: --ad is only for --algo hske-duplex, hske-duplex3 or hske-nla1, not 'hske'|enc --algo hske --key $SK --in $TMP/m32 --ad '' --out {O}"
"dec hske-nla1 format 1 --ad X|dec: --ad given, but this hske-nla1 ciphertext is not an AEAD one|dec --algo hske-nla1 --key $SK --in $TMP/ct_hske-nla1_c.pem --ad X --out {O}"
"dec hske-nla1 format 1 --ad ''|dec: --ad given, but this hske-nla1 ciphertext is not an AEAD one|dec --algo hske-nla1 --key $SK --in $TMP/ct_hske-nla1_c.pem --ad '' --out {O}"
)
for a in hske hske-nla2 hske-nla3 "${ASYM1[@]}" hpke-stern-kem; do
    kf=$(keyflag $a); dk=$(deckey $a)
    ct="$TMP/ct_${a}_c.pem"; [ "$a" = hpke-stern-kem ] && ct="$TMP/kem_c.pem"
    CASES+=("enc $a --ad X|enc: --ad is only for --algo hske-duplex, hske-duplex3 or hske-nla1, not '$a'|enc --algo $a $kf --in $TMP/m32 --ad X --out {O}")
    CASES+=("dec $a --ad X|dec: --ad is only for --algo hske-duplex, hske-duplex3 or hske-nla1, not '$a'|dec --algo $a $dk --in $ct --ad X --out {O}")
done
for a in hske hske-nla2 hske-nla3 hske-duplex hske-duplex3 "${ASYM1[@]}" hpke-stern-kem; do
    kf=$(keyflag $a)
    CASES+=("enc $a --aead|enc: --aead is only for --algo hske-nla1, not '$a'|enc --algo $a $kf --in $TMP/m32 --aead --out {O}")
done

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
        elif [ -e "$o" ] || grep -q "BEGIN HERRADURA" "$TMP/so"; then
            fail "$name ($c): refused, but wrote output"
        else
            pass
        fi
    done
done

echo
echo "Results: $PASS PASS / $FAIL FAIL (languages: ${LANGS[*]})"
[ "$FAIL" -eq 0 ] || exit 1
