#!/usr/bin/env bash
# CliTest/test_width_matrix.sh — TODO #383: every operation at every listed width.
#
# genpkey's parameter-set table (spec/generate_spec.py key_parameter_sets, TODO
# #379) lists, per algorithm and width, the CLIs that run it.  test_key_params.sh
# holds genpkey to that table; this script holds every OPERATION to it.  For
# each row of the GF(2^n) family (hkex-gf, hpks, hpks-nl, hpke, hpke-nl,
# hpke-nl3) at every width, and for every pair (writer, reader) of the CLIs the
# row lists:
#   - pkey --pubout writes byte-identical public PEMs and pkey --text identical
#     text, whichever CLI reads the key;
#   - hkex-gf: kex agrees in both directions, with and without --kdf hfscx-256;
#     the --kdf key is HFSCX-256 of the raw n-bit secret, labelled n = 256
#     (TODO #389), and works as an HSKE key;
#   - hpks / hpks-nl: the writer's signature verifies under the reader, with
#     and without --digest hfscx-256, and a one-byte-longer message does NOT
#     (the negative control, so a verifier that accepts everything fails);
#   - hpke*: the writer encrypts to the reader's key and the reader decrypts.
#   - hpks-stern (TODO #383 stage 2): as hpks, at SR reduced rounds (the
#     verifier is given --min-rounds SR); and an hpks-ring signature by the
#     writer over a ring of every listed CLI's key verifies under the reader,
#     and not on a changed message.  hpke-stern runs the hpke* checks.
# A CLI the row does not list must refuse the key (pkey --text, enc, verify),
# naming the width, without crashing -- never exit 0 with a wrong answer.
#
# Widths come from the spec, so a CLI added to a row (TODO #384: Java) is
# tested the moment the row says it runs.
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
. "$ROOT/CliTest/lib_build.sh"
hkx_require_built c go java

declare -A CLI=(
    [py]="python3 $ROOT/HerraduraCli/herradura.py"
    [c]="$ROOT/HerraduraCli/herradura_cli"
    [go]="$ROOT/HerraduraCli/herradura_cli_go"
    [java]="java -cp $ROOT/bindings/java herradurakex.HerraduraCli"
)
LANGS=(py c go java)
bash "$ROOT/bindings/java/build.sh" >/dev/null 2>&1

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
PASS=0; FAIL=0; NA=0
pass() { PASS=$((PASS+1)); }
fail() { echo "FAIL $1"; FAIL=$((FAIL+1)); }

GF_ALGOS="hkex-gf hpks hpks-nl hpke hpke-nl hpke-nl3 hpks-stern hpke-stern"
SR=16   # Stern-F rounds: soundness is not under test, interop is
python3 - "$ROOT/spec/herradura-protocol-spec.json" "$GF_ALGOS" > "$TMP/rows" <<'EOF'
import json, sys
algos = sys.argv[2].split()
for r in json.load(open(sys.argv[1]))["key_parameter_sets"]["rows"]:
    if r["algo"] in algos and r["bits"] > 0 and not r["withdrawn"]:
        print(r["algo"], r["bits"], int(r["default"]), ",".join(r["ports"]))
EOF
[ -s "$TMP/rows" ] || { echo "FAIL no GF parameter-set rows in the spec"; exit 1; }
has_port() { case ",$1," in *",$2,"*) return 0 ;; *) return 1 ;; esac; }

# q: run quietly; RC holds the exit status, ERR the stderr
q() { local c=$1; shift; ${CLI[$c]} "$@" >"$TMP/out" 2>"$TMP/err"; RC=$?; }

# refused: the last q exited 1 or 2 naming the width, without a crash
refused() {  # label
    if [ "$RC" -eq 0 ]; then fail "$1: accepted (exit 0)"
    elif [ "$RC" -gt 2 ] || grep -qE 'Traceback|panic:|Exception in thread|Aborted' "$TMP/err"; then
        fail "$1: crashed (rc=$RC): $(head -c 160 "$TMP/err")"
    elif ! grep -qE 'n is [0-9]+|this CLI runs n' "$TMP/err" "$TMP/out"; then
        fail "$1: refused, but without naming the width: $(head -c 160 "$TMP/err")"
    else pass; fi
}

while read -r a n dflt ports; do
    D="$TMP/$a-$n"; mkdir -p "$D"
    nb=$((n / 8)); head -c "$nb" /dev/urandom > "$D/m.bin"
    # one keypair per listed CLI
    gens=()
    for g in "${LANGS[@]}"; do
        has_port "$ports" "$g" || continue
        q "$g" genpkey --algo "$a" --bits "$n" --out "$D/$g.pem"
        if [ "$RC" -ne 0 ]; then fail "$a/$n genpkey ($g): rc=$RC $(head -c 160 "$TMP/err")"; continue; fi
        q "$g" pkey --in "$D/$g.pem" --pubout --out "$D/${g}_pub.pem"
        if [ "$RC" -ne 0 ]; then fail "$a/$n pubout ($g): rc=$RC"; continue; fi
        ${CLI[$g]} pkey --in "$D/$g.pem" --text > "$D/${g}_text" 2>/dev/null
        gens+=("$g")
    done
    [ "${#gens[@]}" -gt 0 ] || { fail "$a/$n: no CLI wrote a key"; continue; }
    ref=${gens[0]}

    for g in "${gens[@]}"; do
        for r in "${gens[@]}"; do
            L="$a/$n $g->$r"
            q "$r" pkey --in "$D/$g.pem" --pubout --out "$D/x.pem"
            if [ "$RC" -eq 0 ] && cmp -s "$D/x.pem" "$D/${g}_pub.pem"; then pass
            else fail "$L: pkey --pubout differs (rc=$RC)"; fi
            # Java's Stern --text dump has other fields (bits, syndrome, no e_int):
            # the whole-dump divergence TODO #386 covers, not a width defect --
            # reported as n/a, never scored as a pass.
            if [[ $a == *-stern && ( $g == java || $r == java ) && $g != "$r" ]]; then
                NA=$((NA+1))
            elif ${CLI[$r]} pkey --in "$D/$g.pem" --text 2>/dev/null | cmp -s - "$D/${g}_text"; then pass
            else fail "$L: pkey --text differs"; fi
            case $a in
            hkex-gf)
                rm -f "$D/k1.pem" "$D/k2.pem" "$D/k3.pem"
                q "$r" kex --algo hkex-gf --our "$D/$r.pem" --their "$D/${g}_pub.pem" --out "$D/k1.pem"
                q "$g" kex --algo hkex-gf --our "$D/$g.pem" --their "$D/${r}_pub.pem" --out "$D/k2.pem"
                if [ -s "$D/k1.pem" ] && cmp -s "$D/k1.pem" "$D/k2.pem"; then pass; else fail "$L: kex disagrees"; fi
                # TODO #389: --kdf hfscx-256 at EVERY width.  Both directions agree;
                # the key is the whole HFSCX-256 digest of the raw n-bit g^ab (k1,
                # at n/8 bytes), labelled n = 256 -- checked against Python's
                # suite, an assertion about one implementation, since all CLIs
                # agreeing on a wrong rule would pass the cmp; and the reader can
                # use it as an HSKE key.
                q "$r" kex --algo hkex-gf --kdf hfscx-256 --our "$D/$r.pem" --their "$D/${g}_pub.pem" --out "$D/k3.pem"
                q "$g" kex --algo hkex-gf --kdf hfscx-256 --our "$D/$g.pem" --their "$D/${r}_pub.pem" --out "$D/k2.pem"
                if [ -s "$D/k3.pem" ] && cmp -s "$D/k3.pem" "$D/k2.pem"; then pass; else fail "$L: kex --kdf disagrees"; fi
                if python3 - "$ROOT" "$D/k1.pem" "$D/k3.pem" "$n" <<'EOF'
import base64, os, sys
sys.path.insert(0, os.path.join(sys.argv[1], "HerraduraCli"))
from primitives import hfscx_256
def ints(p):
    der = base64.b64decode("".join(l for l in open(p).read().split("\n") if l and not l.startswith("-----")))
    out, i = [], 2 if der[1] < 0x80 else 2 + (der[1] & 0x7f)
    while i < len(der):
        L = der[i + 1]; out.append(int.from_bytes(der[i + 2:i + 2 + L], "big")); i += 2 + L
    return out
n = int(sys.argv[4]); raw, rn = ints(sys.argv[2]); sk, sn = ints(sys.argv[3])
want = int.from_bytes(hfscx_256(raw.to_bytes(n // 8, "big")), "big")
sys.exit(0 if (rn, sn, sk) == (n, 256, want) else 1)
EOF
                then pass; else fail "$L: kex --kdf is not HFSCX-256(g^ab at n/8 bytes) labelled n = 256"; fi
                head -c 32 /dev/urandom > "$D/h.bin"; rm -f "$D/h.pem" "$D/h.out"
                q "$g" enc --algo hske --key "$D/k3.pem" --in "$D/h.bin" --out "$D/h.pem"
                q "$r" dec --algo hske --key "$D/k3.pem" --in "$D/h.pem" --out "$D/h.out"
                if [ "$RC" -eq 0 ] && cmp -s "$D/h.bin" "$D/h.out"; then pass
                else fail "$L: the --kdf session key does not work as an HSKE key"; fi ;;
            hpks|hpks-nl)
                for dg in "" "--digest hfscx-256"; do
                    q "$g" sign --algo "$a" $dg --key "$D/$g.pem" --in "$D/m.bin" --out "$D/s.pem"
                    [ "$RC" -eq 0 ] || { fail "$L: sign $dg (rc=$RC) $(head -c 160 "$TMP/err")"; continue; }
                    q "$r" verify --algo "$a" $dg --pubkey "$D/${g}_pub.pem" --in "$D/m.bin" --sig "$D/s.pem"
                    if [ "$RC" -eq 0 ]; then pass; else fail "$L: verify $dg refused a valid signature (rc=$RC)"; fi
                    { cat "$D/m.bin"; printf x; } > "$D/m2.bin"
                    q "$r" verify --algo "$a" $dg --pubkey "$D/${g}_pub.pem" --in "$D/m2.bin" --sig "$D/s.pem"
                    if [ "$RC" -eq 1 ] && grep -q 'Verification FAILED' "$TMP/out"; then pass
                    else fail "$L: verify $dg on a changed message: rc=$RC, not 'Verification FAILED'"; fi
                done ;;
            hpks-stern)
                { cat "$D/m.bin"; printf x; } > "$D/m2.bin"
                for dg in "" "--digest hfscx-256"; do
                    q "$g" sign --algo hpks-stern $dg --rounds $SR --key "$D/$g.pem" --in "$D/m.bin" --out "$D/s.pem"
                    [ "$RC" -eq 0 ] || { fail "$L: sign $dg (rc=$RC) $(head -c 160 "$TMP/err")"; continue; }
                    q "$r" verify --algo hpks-stern $dg --min-rounds $SR --pubkey "$D/${g}_pub.pem" --in "$D/m.bin" --sig "$D/s.pem"
                    if [ "$RC" -eq 0 ]; then pass; else fail "$L: verify $dg refused a valid signature (rc=$RC) $(head -c 160 "$TMP/err")"; fi
                    q "$r" verify --algo hpks-stern $dg --min-rounds $SR --pubkey "$D/${g}_pub.pem" --in "$D/m2.bin" --sig "$D/s.pem"
                    if [ "$RC" -eq 1 ] && grep -q 'Verification FAILED' "$TMP/out"; then pass
                    else fail "$L: verify $dg on a changed message: rc=$RC, not 'Verification FAILED'"; fi
                done
                ring=$(printf "$D/%s_pub.pem," "${gens[@]}"); ring=${ring%,}
                if [ "${#gens[@]}" -lt 2 ]; then ring="$ring,$ring"; fi
                q "$g" sign --algo hpks-ring --rounds $SR --key "$D/$g.pem" --ring "$ring" --in "$D/m.bin" --out "$D/rs.pem"
                if [ "$RC" -ne 0 ]; then fail "$L: ring sign (rc=$RC) $(head -c 160 "$TMP/err")"
                else
                    q "$r" verify --algo hpks-ring --min-rounds $SR --ring "$ring" --in "$D/m.bin" --sig "$D/rs.pem"
                    if [ "$RC" -eq 0 ]; then pass; else fail "$L: ring verify refused a valid signature (rc=$RC) $(head -c 160 "$TMP/err")"; fi
                    q "$r" verify --algo hpks-ring --min-rounds $SR --ring "$ring" --in "$D/m2.bin" --sig "$D/rs.pem"
                    if [ "$RC" -eq 1 ] && grep -q 'Verification FAILED' "$TMP/out"; then pass
                    else fail "$L: ring verify on a changed message: rc=$RC, not 'Verification FAILED'"; fi
                fi ;;
            hpke*)
                rm -f "$D/ct.pem" "$D/d.bin"
                q "$g" enc --algo "$a" --pubkey "$D/${r}_pub.pem" --in "$D/m.bin" --out "$D/ct.pem"
                [ "$RC" -eq 0 ] || { fail "$L: enc (rc=$RC) $(head -c 160 "$TMP/err")"; continue; }
                q "$r" dec --algo "$a" --key "$D/$r.pem" --in "$D/ct.pem" --out "$D/d.bin"
                if [ "$RC" -eq 0 ] && cmp -s "$D/d.bin" "$D/m.bin"; then pass
                else fail "$L: dec of $g's ciphertext (rc=$RC)"; fi ;;
            esac
        done
    done

    # a CLI the row does not list refuses the key, naming the width
    for c in "${LANGS[@]}"; do
        has_port "$ports" "$c" && continue
        q "$c" pkey --in "$D/$ref.pem" --text;                              refused "$a/$n pkey --text ($c)"
        case $a in
        hpke*)  q "$c" enc --algo "$a" --pubkey "$D/${ref}_pub.pem" --in "$D/m.bin" --out "$D/ct_$c.pem"
                refused "$a/$n enc ($c)" ;;
        hpks*)  sr=(); vr=()
                [ "$a" = hpks-stern ] && { sr=(--rounds $SR); vr=(--min-rounds $SR); }
                q "$ref" sign --algo "$a" "${sr[@]}" --key "$D/$ref.pem" --in "$D/m.bin" --out "$D/s.pem"
                q "$c" verify --algo "$a" "${vr[@]}" --pubkey "$D/${ref}_pub.pem" --in "$D/m.bin" --sig "$D/s.pem"
                refused "$a/$n verify ($c)" ;;
        hkex-gf) q "$c" kex --algo hkex-gf --our "$D/$ref.pem" --their "$D/${ref}_pub.pem" --out "$D/k_$c.pem"
                refused "$a/$n kex ($c)" ;;
        esac
    done
done < "$TMP/rows"

# Mixed widths: a 64-bit key used with a 128-bit peer key, ciphertext or
# signature is refused with "<what> n is 128, <key> n is 64" -- never reduced
# into the key's width and answered with exit 0.  Accept-control first: the
# same CLI's same-width operation succeeds.
runs_both() { local a=$1 c=$2 p64 p128
    p64=$(awk -v a="$a" '$1==a && $2==64 {print $4}' "$TMP/rows")
    p128=$(awk -v a="$a" '$1==a && $2==128 {print $4}' "$TMP/rows")
    has_port "$p64" "$c" && has_port "$p128" "$c"; }
mixed() {  # label want-message
    if [ "$RC" -ne 0 ] && [ "$RC" -le 2 ] && grep -qF "$2" "$TMP/err"; then pass
    else fail "$1: rc=$RC, not refused with '$2': $(head -c 160 "$TMP/err")"; fi; }
M="$TMP/mix"; mkdir -p "$M"; head -c 8 /dev/urandom > "$M/m.bin"
for c in "${LANGS[@]}"; do
    for a in hkex-gf hpke hpks hpke-stern hpks-stern; do
        runs_both "$a" "$c" || continue
        q "$c" genpkey --algo "$a" --bits 64  --out "$M/k64.pem"
        q "$c" genpkey --algo "$a" --bits 128 --out "$M/k128.pem"
        q "$c" pkey --in "$M/k64.pem"  --pubout --out "$M/k64_pub.pem"
        q "$c" pkey --in "$M/k128.pem" --pubout --out "$M/k128_pub.pem"
        case $a in
        hkex-gf)
            q "$c" kex --algo hkex-gf --our "$M/k64.pem" --their "$M/k64_pub.pem" --out "$M/ok.pem"
            [ "$RC" -eq 0 ] && pass || fail "mixed control: same-width kex ($c) rc=$RC"
            q "$c" kex --algo hkex-gf --our "$M/k64.pem" --their "$M/k128_pub.pem" --out "$M/x.pem"
            mixed "mixed-width kex ($c)" "their public key n is 128, our private key n is 64" ;;
        hpke)
            q "$c" enc --algo hpke --pubkey "$M/k64_pub.pem" --in "$M/m.bin" --out "$M/ct64.pem"
            q "$c" dec --algo hpke --key "$M/k64.pem" --in "$M/ct64.pem" --out "$M/d.bin"
            [ "$RC" -eq 0 ] && cmp -s "$M/d.bin" "$M/m.bin" && pass || fail "mixed control: same-width dec ($c) rc=$RC"
            q "$c" enc --algo hpke --pubkey "$M/k128_pub.pem" --in "$M/m.bin" --out "$M/ct128.pem"
            q "$c" dec --algo hpke --key "$M/k64.pem" --in "$M/ct128.pem" --out "$M/d.bin"
            mixed "mixed-width dec ($c)" "ciphertext n is 128, private key n is 64" ;;
        hpks)
            q "$c" sign --algo hpks --key "$M/k64.pem" --in "$M/m.bin" --out "$M/s64.pem"
            q "$c" verify --algo hpks --pubkey "$M/k64_pub.pem" --in "$M/m.bin" --sig "$M/s64.pem"
            [ "$RC" -eq 0 ] && pass || fail "mixed control: same-width verify ($c) rc=$RC"
            q "$c" sign --algo hpks --key "$M/k128.pem" --in "$M/m.bin" --out "$M/s128.pem"
            q "$c" verify --algo hpks --pubkey "$M/k64_pub.pem" --in "$M/m.bin" --sig "$M/s128.pem"
            mixed "mixed-width verify ($c)" "signature n is 128, public key n is 64" ;;
        hpke-stern)   # TODO #383 stage 2: Python and Go decrypted this with exit 0
            q "$c" enc --algo hpke-stern --pubkey "$M/k64_pub.pem" --in "$M/m.bin" --out "$M/ct64.pem"
            q "$c" dec --algo hpke-stern --key "$M/k64.pem" --in "$M/ct64.pem" --out "$M/d.bin"
            [ "$RC" -eq 0 ] && cmp -s "$M/d.bin" "$M/m.bin" && pass || fail "mixed control: same-width hpke-stern dec ($c) rc=$RC"
            q "$c" enc --algo hpke-stern --pubkey "$M/k128_pub.pem" --in "$M/m.bin" --out "$M/ct128.pem"
            q "$c" dec --algo hpke-stern --key "$M/k64.pem" --in "$M/ct128.pem" --out "$M/d.bin"
            mixed "mixed-width hpke-stern dec ($c)" "ciphertext n is 128, private key n is 64" ;;
        hpks-stern)   # Go panicked, Python failed inside its hash
            q "$c" sign --algo hpks-stern --rounds $SR --key "$M/k64.pem" --in "$M/m.bin" --out "$M/s64.pem"
            q "$c" verify --algo hpks-stern --min-rounds $SR --pubkey "$M/k64_pub.pem" --in "$M/m.bin" --sig "$M/s64.pem"
            [ "$RC" -eq 0 ] && pass || fail "mixed control: same-width hpks-stern verify ($c) rc=$RC"
            q "$c" sign --algo hpks-stern --rounds $SR --key "$M/k128.pem" --in "$M/m.bin" --out "$M/s128.pem"
            q "$c" verify --algo hpks-stern --min-rounds $SR --pubkey "$M/k64_pub.pem" --in "$M/m.bin" --sig "$M/s128.pem"
            mixed "mixed-width hpks-stern verify ($c)" "signature n is 128, public key n is 64"
            # a ring: members of two widths, and a signature of another width
            q "$c" genpkey --algo hpks-stern --bits 64 --out "$M/j64.pem"
            q "$c" pkey --in "$M/j64.pem" --pubout --out "$M/j64_pub.pem"
            q "$c" sign --algo hpks-ring --rounds $SR --key "$M/k64.pem" --ring "$M/k64_pub.pem,$M/j64_pub.pem" --in "$M/m.bin" --out "$M/rs64.pem"
            q "$c" verify --algo hpks-ring --min-rounds $SR --ring "$M/k64_pub.pem,$M/j64_pub.pem" --in "$M/m.bin" --sig "$M/rs64.pem"
            [ "$RC" -eq 0 ] && pass || fail "mixed control: same-width ring verify ($c) rc=$RC"
            q "$c" sign --algo hpks-ring --rounds $SR --key "$M/k64.pem" --ring "$M/k64_pub.pem,$M/k128_pub.pem" --in "$M/m.bin" --out "$M/x.pem"
            mixed "mixed-width ring members ($c)" "all ring members must share the same n"
            q "$c" verify --algo hpks-ring --min-rounds $SR --ring "$M/k128_pub.pem,$M/k128_pub.pem" --in "$M/m.bin" --sig "$M/rs64.pem"
            mixed "mixed-width ring signature ($c)" "signature n=64 != ring n=128" ;;
        esac
    done
done

echo
echo "Results: $PASS PASS / $FAIL FAIL / $NA n/a (languages: ${LANGS[*]})"
[ "$NA" -eq 0 ] || echo "n/a: $NA Stern pkey --text cells with Java on one side (TODO #386)"
[ "$PASS" -gt 0 ] || exit 2
[ "$FAIL" -eq 0 ] || exit 1
