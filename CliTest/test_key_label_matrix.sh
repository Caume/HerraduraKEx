#!/usr/bin/env bash
# CliTest/test_key_label_matrix.sh — TODO #366: every CLI refuses a key whose PEM
# label the operation does not accept, per spec's `key_label_acceptance` table.
#
# WHY THIS FILE EXISTS.  Until v15.0.0 no CLI compared a key's label with the
# operation: `sign --algo hpks-stern --key <HKEX-GF private key>` signed in all
# four, using a DH exponent as a Stern error vector, and Go signed HPKS-WOTS with
# one.  The table now lives in spec/generate_spec.py (KEY_LABEL_SITES) and is
# emitted into all four CLIs.  A table row a CLI forgets to enforce, or enforces
# by some other path with some other message, fails here.
#
# For each CLI and each row:
#   * accept-control: the row's HOME key (the one its fixtures were made with)
#     must succeed, exit 0;
#   * every other label the row accepts (the GF / Stern families) must not be
#     refused BY THE LABEL CHECK -- it may still fail later, e.g. a family key
#     cannot verify a signature another key made;
#   * two keys must be refused by the label check, matched on its own message:
#     the home key type in the opposite role (private <-> public; for the HCRED
#     slots of role "either" the private key is instead a second accept-control,
#     since their loaders derive the public fields from it), and the first
#     key type in REFUSE_ORDER the row does not accept -- hpke-nl3 for the GF
#     rows, hkex-gf for the Stern rows (the confusions TODO #366 measured).
# The script's command templates must cover the spec's rows exactly, both
# directions, so a new row without a test fails rather than going unchecked.
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

. "$ROOT/CliTest/lib_build.sh"
for l in c go; do
    [ -n "${CLI[$l]:-}" ] || echo "NOTE: $l CLI absent — $(hkx_why "$l")"
done
[ -n "${CLI[java]:-}" ] || echo "NOTE: java CLI absent — javac is not installed"
# Fixtures come from the C CLI (fast, n = 256 everywhere).
if [ -z "${CLI[c]:-}" ]; then
    echo "FAIL test_key_label_matrix: needs the C CLI for its fixtures, so nothing" \
         "was asserted (run ./build_c.sh)." >&2
    [ "${HKX_ALLOW_SKIP:-0}" = "1" ] && exit 0
    exit 2
fi

pass() { echo "PASS $1"; PASS=$((PASS+1)); }
fail() { echo "FAIL $1"; FAIL=$((FAIL+1)); }

# ── Fixtures ────────────────────────────────────────────────────────────────
F="$TMP/fx"; mkdir -p "$F"
C=${CLI[c]}
TAGS="hkex-gf hkex-rnl hpks hpks-nl hpke hpke-nl hpke-nl3 hpks-stern hpke-stern
      hpke-stern-kem hpks-zkp-nl oprf hpks-xmss hpks-wots hcred"
for t in $TAGS; do
    extra=(); [ "$t" = hpks-xmss ] && extra=(--xmss-height 4)
    $C genpkey --algo "$t" "${extra[@]}" --out "$F/$t.pem" 2>/dev/null
    $C pkey --in "$F/$t.pem" --pubout --out "$F/${t}_pub.pem" 2>/dev/null || true
done
printf 'key label test message, 32 by.' > "$F/msg.bin"
for a in hpke hpke-nl hpke-nl3 hpke-stern hpke-stern-kem; do
    $C enc --algo $a --pubkey "$F/${a}_pub.pem" --in "$F/msg.bin" --out "$F/ct_$a.pem" 2>/dev/null
done
signwith() {   # algo, key tag, extra sign args...
    local a=$1 t=$2; shift 2
    cp "$F/$t.pem" "$TMP/sk.pem"; [ -f "$F/$t.pem.idx" ] && cp "$F/$t.pem.idx" "$TMP/sk.pem.idx"
    $C sign --algo "$a" --key "$TMP/sk.pem" --in "$F/msg.bin" "$@" --out "$F/sig_$a.pem" 2>/dev/null
}
signwith hpks hpks; signwith hpks-nl hpks-nl; signwith rnl-sigma hkex-rnl
signwith hpks-xmss hpks-xmss; signwith hpks-wots hpks-wots
signwith hpks-stern hpks-stern --rounds 2
signwith nl-zkboo hpks-zkp-nl --rounds 2; signwith nl-zkbpp hpks-zkp-nl --rounds 2
$C genpkey --algo hpks-stern --out "$F/m2.pem" 2>/dev/null
$C pkey --in "$F/m2.pem" --pubout --out "$F/m2_pub.pem"
signwith hpks-ring hpks-stern --rounds 2 --ring "$F/hpks-stern_pub.pem,$F/m2_pub.pem"
$C genpkey --algo hkex-rnl --out "$F/rnl2.pem"
$C pkey --in "$F/rnl2.pem" --pubout --out "$F/rnl2_pub.pem"
$C kex --algo hybrid-rnl-stern --our "$F/rnl2.pem" --their "$F/hkex-rnl_pub.pem" \
       --their-kem "$F/hpke-stern-kem_pub.pem" --out "$F/hyb_resp.pem" 2>/dev/null
$C oprf-blind --in "$F/msg.bin" --out "$F/oprf_state.pem" 2>/dev/null
$C cred-prove --in "$F/hcred.pem" --msg n --rounds 2 --out "$F/proof.pem" 2>/dev/null
$C cred-issue --our "$F/hpks-stern.pem" --in "$F/hcred_pub.pem" --rounds 2 --out "$F/cred.pem" 2>/dev/null
$C threshold-commit --key "$F/hpks.pem" --commit-out "$F/commit.pem" --nonce-out "$F/nonce.pem"
$C threshold-aggregate --commits "$F/commit.pem" --in "$F/msg.bin" --out "$F/agg.pem" 2>/dev/null

# ── Templates: "cmd|algo|flag" -> "home tag|argv" ({X} key, {F} fixtures, {O} out)
declare -A T=()
T["kex|hkex-gf|--our"]="hkex-gf|kex --algo hkex-gf --our {X} --their {F}/hkex-gf_pub.pem --out {O}"
T["kex|hkex-gf|--their"]="hkex-gf|kex --algo hkex-gf --our {F}/hkex-gf.pem --their {X} --out {O}"
T["kex|hkex-rnl|--our"]="hkex-rnl|kex --algo hkex-rnl --our {X} --their {F}/hkex-rnl_pub.pem --out {O}"
T["kex|hkex-rnl|--their"]="hkex-rnl|kex --algo hkex-rnl --our {F}/rnl2.pem --their {X} --out {O}"
T["kex|hybrid-rnl-stern|--our"]="hkex-rnl|kex --algo hybrid-rnl-stern --our {X} --their {F}/hkex-rnl_pub.pem --their-kem {F}/hpke-stern-kem_pub.pem --out {O}"
T["kex|hybrid-rnl-stern|--their"]="hkex-rnl|kex --algo hybrid-rnl-stern --our {F}/rnl2.pem --their {X} --their-kem {F}/hpke-stern-kem_pub.pem --out {O}"
T["kex|hybrid-rnl-stern|--their-kem"]="hpke-stern-kem|kex --algo hybrid-rnl-stern --our {F}/rnl2.pem --their {F}/hkex-rnl_pub.pem --their-kem {X} --out {O}"
T["kex|hybrid-rnl-stern|--our-kem"]="hpke-stern-kem|kex --algo hybrid-rnl-stern --our {F}/hkex-rnl.pem --our-kem {X} --their {F}/hyb_resp.pem --out {O}"
for a in hpke hpke-nl hpke-nl3 hpke-stern hpke-stern-kem; do
    T["enc|$a|--pubkey"]="$a|enc --algo $a --pubkey {X} --in {F}/msg.bin --out {O}"
    T["dec|$a|--key"]="$a|dec --algo $a --key {X} --in {F}/ct_$a.pem --out {O}"
done
for a in hpks hpks-nl hpks-stern rnl-sigma nl-zkboo nl-zkbpp hpks-xmss hpks-wots; do
    case $a in
        rnl-sigma) h=hkex-rnl;; nl-zkboo|nl-zkbpp) h=hpks-zkp-nl;; *) h=$a;;
    esac
    r=(); m=()
    case $a in hpks-stern|nl-zkboo|nl-zkbpp) r=(--rounds 2); m=(--min-rounds 2);; esac
    T["sign|$a|--key"]="$h|sign --algo $a ${r[*]:-} --key {X} --in {F}/msg.bin --out {O}"
    T["verify|$a|--pubkey"]="$h|verify --algo $a ${m[*]:-} --pubkey {X} --in {F}/msg.bin --sig {F}/sig_$a.pem"
done
T["sign|hpks-ring|--key"]="hpks-stern|sign --algo hpks-ring --rounds 2 --key {X} --ring {F}/hpks-stern_pub.pem,{F}/m2_pub.pem --in {F}/msg.bin --out {O}"
T["verify|hpks-ring|--ring"]="hpks-stern|verify --algo hpks-ring --min-rounds 2 --ring {X},{F}/m2_pub.pem --in {F}/msg.bin --sig {F}/sig_hpks-ring.pem"
T["threshold-commit||--key"]="hpks|threshold-commit --key {X} --commit-out {O} --nonce-out {O}.nonce"
T["threshold-respond||--key"]="hpks|threshold-respond --key {X} --commits {F}/commit.pem --aggregate {F}/agg.pem --nonce {F}/nonce.pem --out {O}"
T["oprf-eval||--key"]="oprf|oprf-eval --key {X} --in {F}/oprf_state.pem --out {O}"
T["pake-register||--key"]="oprf|pake-register --key {X} --password p --out {O}"
T["pake-demo||--key"]="oprf|pake-demo --key {X} --password p"
T["cred-issue||--our"]="hpks-stern|cred-issue --our {X} --in {F}/hcred_pub.pem --rounds 2 --out {O}"
T["cred-issue||--in"]="hcred|cred-issue --our {F}/hpks-stern.pem --in {X} --rounds 2 --out {O}"
T["cred-prove||--in"]="hcred|cred-prove --in {X} --msg n --rounds 2 --out {O}"
T["cred-verify||--pubkey"]="hcred|cred-verify --min-rounds 2 --proof {F}/proof.pem --pubkey {X} --msg n"
T["cred-verify||--issuer"]="hpks-stern|cred-verify --min-rounds 2 --proof {F}/proof.pem --pubkey {F}/hcred_pub.pem --msg n --cred {F}/cred.pem --issuer {X}"

# The spec's rows: "cmd|algo|flag|role|tag,tag,...".
mapfile -t ROWS < <(python3 - "$ROOT/spec/herradura-protocol-spec.json" <<'EOF'
import json, sys
for r in json.load(open(sys.argv[1]))["key_label_acceptance"]:
    print("|".join([r["subcommand"], r["algo"], r["flag"], r["role"], ",".join(r["accepts"])]))
EOF
)
declare -A SEEN=()
for row in "${ROWS[@]}"; do
    IFS='|' read -r cmd algo flag role accepts <<< "$row"
    SEEN["$cmd|$algo|$flag"]=1
    [ -n "${T[$cmd|$algo|$flag]:-}" ] && pass "template for spec row $cmd|$algo|$flag" \
        || fail "spec row $cmd|$algo|$flag has no template in this script"
done
for k in "${!T[@]}"; do
    [ -n "${SEEN[$k]:-}" ] || fail "template $k has no row in spec key_label_acceptance"
done

# Refusal candidates, nearest confusion first.
REFUSE_ORDER="hpke-nl3 hkex-gf hpks-stern hkex-rnl hpke-stern-kem hpks-zkp-nl oprf hcred"

keyfile() {   # tag role -> fixture path ("" if that key has no such role)
    local p="$F/$1.pem"; [ "$2" = pub ] && p="$F/${1}_pub.pem"
    [ -f "$p" ] && echo "$p" || echo ""
}
run_cell() {   # lang template key-path -> sets OUT, RC
    local lang=$1 argv=$2 src=$3
    rm -rf "$TMP/w"; mkdir -p "$TMP/w"
    cp "$src" "$TMP/w/k.pem"; [ -f "$src.idx" ] && cp "$src.idx" "$TMP/w/k.pem.idx"
    argv=${argv//\{X\}/$TMP/w/k.pem}; argv=${argv//\{F\}/$F}; argv=${argv//\{O\}/$TMP/w/out.pem}
    # shellcheck disable=SC2086
    OUT=$(timeout 600 ${CLI[$lang]} $argv 2>&1 </dev/null) && RC=0 || RC=$?
}

for lang in "${LANGS[@]}"; do
    echo "=== CLI: $lang ==="
    for row in "${ROWS[@]}"; do
        IFS='|' read -r cmd algo flag role accepts <<< "$row"
        tmpl=${T[$cmd|$algo|$flag]:-}; [ -n "$tmpl" ] || continue
        home=${tmpl%%|*}; argv=${tmpl#*|}
        id="$lang $cmd${algo:+ --algo $algo} $flag"
        # role "either" (HCRED): the slot is a public one that also takes the
        # private key, so the private key is a second accept-control rather
        # than the opposite-role refusal.
        other=priv; [ "$role" = priv ] && other=pub
        if [ "$role" = either ]; then role=pub; other=""
            run_cell "$lang" "$argv" "$(keyfile "$home" priv)"
            if [ "$RC" -eq 0 ]; then pass "$id: $home private key accepted (role either)"
            else fail "$id: $home private key refused (rc=$RC): $(echo "$OUT" | head -2)"; fi
        fi
        # accept-control
        run_cell "$lang" "$argv" "$(keyfile "$home" "$role")"
        if [ "$RC" -eq 0 ]; then pass "$id: $home accepted (control)"
        else fail "$id: $home key refused (rc=$RC): $(echo "$OUT" | grep -v -i warning | head -2)"; fi
        # the rest of the family: not refused by the label check
        for t in ${accepts//,/ }; do
            [ "$t" = "$home" ] && continue
            run_cell "$lang" "$argv" "$(keyfile "$t" "$role")"
            if echo "$OUT" | grep -q "wrong key type"; then fail "$id: family key $t refused: $OUT"
            else pass "$id: family key $t not refused by the label check"; fi
        done
        # refusals, matched on the check's own message
        foreign=""
        for t in $REFUSE_ORDER; do
            case ",$accepts," in *",$t,"*) continue;; esac
            [ -n "$(keyfile "$t" "$role")" ] && { foreign=$t; break; }
        done
        for probe in "$home:$other" "$foreign:$role"; do
            t=${probe%%:*}; rr=${probe#*:}
            [ -n "$t" ] && [ -n "$rr" ] || continue
            src=$(keyfile "$t" "$rr"); [ -n "$src" ] || continue
            run_cell "$lang" "$argv" "$src"
            if [ "$RC" -ne 0 ] && echo "$OUT" | grep -q "wrong key type: $flag holds"; then
                pass "$id: $t $rr key refused"
            else fail "$id: $t $rr key not refused by the label check (rc=$RC): $(echo "$OUT" | head -2)"; fi
        done
    done
done

echo
echo "Results: $PASS PASS / $FAIL FAIL (languages: ${LANGS[*]})"
[ "$FAIL" -eq 0 ]
