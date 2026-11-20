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
#   - hcred (TODO #383 stage 3): the writer's presentation proof verifies under
#     the reader, and not under another message; a credential the writer issues
#     over the reader's key, under an n-bit hpks-stern issuer key, verifies under
#     the reader, and not under another issuer's key.
#   - hkex-rnl (TODO #383 stage 4), at every ring the spec lists (32-256 and the
#     deployed 1024): the reader responds to the writer's public key and the
#     writer completes, with and without --kdf hfscx-256, and both hold one
#     session key, declared n = 256 at every ring (TODO #228); the same over
#     hybrid-rnl-stern, with the writer's HPKE-Stern-KEM key; and the writer's
#     rnl-sigma proof verifies under the reader, and not on a changed message.
# A CLI the row does not list must refuse the key (pkey --text, enc, verify),
# naming the width, without crashing -- never exit 0 with a wrong answer.
#
# Widths come from the spec, so a CLI added to a row (TODO #384: Java) is
# tested the moment the row says it runs.
#
# hybrid-rnl-stern decapsulates the QC-MDPC KEM, so a session-key mismatch
# there retries under lib_dfr.sh's policy (TODO #221, #276).
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
. "$ROOT/CliTest/lib_build.sh"
. "$ROOT/CliTest/lib_dfr.sh"
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
PASS=0; FAIL=0; NA=0; NA_STERN=0; NA_HCRED=0; NA_RNL=0
pass() { PASS=$((PASS+1)); }
fail() { echo "FAIL $1"; FAIL=$((FAIL+1)); }

GF_ALGOS="hkex-gf hpks hpks-nl hpke hpke-nl hpke-nl3 hpks-stern hpke-stern hcred hkex-rnl"
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

# der_ints: a DER SEQUENCE PEM's INTEGERs, one per line, in hex (a 1024-ring
# polynomial is past Python's decimal-conversion limit)
der_ints() { python3 - "$1" <<'PYEOF'
import base64, sys
der = base64.b64decode("".join(l for l in open(sys.argv[1]).read().split("\n")
                               if l and not l.startswith("-----")))
i = 2 if der[1] < 0x80 else 2 + (der[1] & 0x7f)
while i < len(der):
    L, j = der[i + 1], i + 2
    if L & 0x80:
        nb = L & 0x7f; L = int.from_bytes(der[j:j + nb], "big"); j += nb
    print(format(int.from_bytes(der[j:j + L], "big"), "x")); i = j + L
PYEOF
}
first_int() { [ -s "$1" ] && der_ints "$1" | head -1; }
last_int()  { [ -s "$1" ] && der_ints "$1" | tail -1; }

# rnl_pair: the reader $2 responds to the writer $1's key, the writer completes
# with the reader's response; both must hold one key, and the completion
# declares n = 256.  $3 = algo, rest = extra kex flags.  hybrid-rnl-stern
# decapsulates the writer's KEM key, so a mismatch there retries (lib_dfr.sh).
rnl_pair() { local g=$1 r=$2 a=$3; shift 3; local attempt=0 kem1=() kem2=() k1 k2
    if [ "$a" = hybrid-rnl-stern ]; then
        kem1=(--their-kem "$D/kem_${g}_pub.pem"); kem2=(--our-kem "$D/kem_$g.pem")
    fi
    while :; do
        rm -f "$D/resp.pem" "$D/sk.pem"
        q "$r" kex --algo "$a" "$@" --our "$D/$r.pem" --their "$D/${g}_pub.pem" "${kem1[@]}" --out "$D/resp.pem"
        [ "$RC" -eq 0 ] || { fail "$L: $a $* respond (rc=$RC) $(head -c 160 "$TMP/err")"; return; }
        q "$g" kex --algo "$a" "$@" --our "$D/$g.pem" "${kem2[@]}" --their "$D/resp.pem" --out "$D/sk.pem"
        [ "$RC" -eq 0 ] || { fail "$L: $a $* complete (rc=$RC) $(head -c 160 "$TMP/err")"; return; }
        k1=$(first_int "$D/resp.pem"); k2=$(first_int "$D/sk.pem")
        if [ -n "$k1" ] && [ "$k1" = "$k2" ]; then break; fi
        if [ "$a" = hybrid-rnl-stern ] && dfr_retryable "$attempt"; then
            attempt=$((attempt+1)); dfr_report_retry "$L $a" "$attempt"; continue
        fi
        fail "$L: $a $* -- the two sides hold different session keys"; return
    done
    pass
    if [ "$(last_int "$D/sk.pem")" = 100 ]; then pass   # 0x100 = 256
    else fail "$L: $a $* session key declares n = 0x$(last_int "$D/sk.pem"), not 256"; fi
}

# refused: the last q exited 1 or 2 naming the width, without a crash
refused() {  # label
    if [ "$RC" -eq 0 ]; then fail "$1: accepted (exit 0)"
    elif [ "$RC" -gt 2 ] || grep -qE 'Traceback|panic:|Exception in thread|Aborted' "$TMP/err"; then
        fail "$1: crashed (rc=$RC): $(head -c 160 "$TMP/err")"
    elif ! grep -qE 'n is [0-9]+|this CLI runs n|n must be [0-9]+, got [0-9]+' "$TMP/err" "$TMP/out"; then
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
        if [ "$a" = hkex-rnl ]; then   # the hybrid's KEM half, one key per CLI
            q "$g" genpkey --algo hpke-stern-kem --out "$D/kem_$g.pem"
            q "$g" pkey --in "$D/kem_$g.pem" --pubout --out "$D/kem_${g}_pub.pem"
        fi
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
            # Java's Stern --text dump has other fields (bits, syndrome, no e_int),
            # hcred's has three layouts at every width, 256 included (Python:
            # seed_H, y big-endian, W; C: seed_H, y low byte first; Go and Java: W):
            # the whole-dump divergence TODO #386 covers.  hkex-rnl's has four at
            # every ring, 1024 included (Go: s_packed, C_packed, n_A; Python: the
            # same without the packed values' leading zeros; C: s_packed alone;
            # Java: five coefficients of s and C), TODO #387.  Neither is a width
            # defect -- reported as n/a, never scored as a pass.
            if [[ $a == *-stern && ( $g == java || $r == java ) && $g != "$r" ]]; then
                NA=$((NA+1)); NA_STERN=$((NA_STERN+1))
            elif [[ $a == hcred && $g != "$r" ]]; then
                NA=$((NA+1)); NA_HCRED=$((NA_HCRED+1))
            elif [[ $a == hkex-rnl && $g != "$r" ]]; then
                NA=$((NA+1)); NA_RNL=$((NA_RNL+1))
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
            hcred)
                # one proof and one issuer key per CLI, made the first time it is needed
                for c in "$g" "$r"; do
                    [ -s "$D/pf_$c.pem" ] || q "$c" cred-prove --rounds $SR --in "$D/$c.pem" --msg hello --out "$D/pf_$c.pem"
                    if [ ! -s "$D/iss_$c.pem" ]; then
                        q "$c" genpkey --algo hpks-stern --bits "$n" --out "$D/iss_$c.pem"
                        q "$c" pkey --in "$D/iss_$c.pem" --pubout --out "$D/iss_${c}_pub.pem"
                    fi
                done
                if [ ! -s "$D/iss_x_pub.pem" ]; then   # the wrong issuer, for the control
                    q "$ref" genpkey --algo hpks-stern --bits "$n" --out "$D/iss_x.pem"
                    q "$ref" pkey --in "$D/iss_x.pem" --pubout --out "$D/iss_x_pub.pem"
                fi
                q "$r" cred-verify --min-rounds $SR --proof "$D/pf_$g.pem" --pubkey "$D/${g}_pub.pem" --msg hello
                if [ "$RC" -eq 0 ]; then pass; else fail "$L: cred-verify refused a valid proof (rc=$RC) $(head -c 160 "$TMP/err")"; fi
                q "$r" cred-verify --min-rounds $SR --proof "$D/pf_$g.pem" --pubkey "$D/${g}_pub.pem" --msg hellp
                if [ "$RC" -eq 1 ] && grep -q 'Verification FAILED (proof)' "$TMP/out"; then pass
                else fail "$L: cred-verify under another message: rc=$RC, not 'Verification FAILED (proof)'"; fi
                rm -f "$D/cr.pem"
                q "$g" cred-issue --rounds $SR --in "$D/${r}_pub.pem" --our "$D/iss_$g.pem" --out "$D/cr.pem"
                if [ "$RC" -ne 0 ]; then fail "$L: cred-issue (rc=$RC) $(head -c 160 "$TMP/err")"
                else
                    q "$r" cred-verify --min-rounds $SR --proof "$D/pf_$r.pem" --pubkey "$D/${r}_pub.pem" --msg hello \
                        --cred "$D/cr.pem" --issuer "$D/iss_${g}_pub.pem"
                    if [ "$RC" -eq 0 ] && grep -q 'Credential OK' "$TMP/out"; then pass
                    else fail "$L: cred-verify refused $g's credential (rc=$RC) $(head -c 160 "$TMP/err")"; fi
                    q "$r" cred-verify --min-rounds $SR --proof "$D/pf_$r.pem" --pubkey "$D/${r}_pub.pem" --msg hello \
                        --cred "$D/cr.pem" --issuer "$D/iss_x_pub.pem"
                    if [ "$RC" -eq 1 ] && grep -q 'Verification FAILED (credential)' "$TMP/out"; then pass
                    else fail "$L: credential under another issuer: rc=$RC, not 'Verification FAILED (credential)'"; fi
                fi ;;
            hkex-rnl)
                rnl_pair "$g" "$r" hkex-rnl
                rnl_pair "$g" "$r" hkex-rnl --kdf hfscx-256
                rnl_pair "$g" "$r" hybrid-rnl-stern
                { cat "$D/m.bin"; printf x; } > "$D/m2.bin"
                q "$g" sign --algo rnl-sigma --key "$D/$g.pem" --in "$D/m.bin" --out "$D/s.pem"
                if [ "$RC" -ne 0 ]; then fail "$L: rnl-sigma sign (rc=$RC) $(head -c 160 "$TMP/err")"
                else
                    q "$r" verify --algo rnl-sigma --pubkey "$D/${g}_pub.pem" --in "$D/m.bin" --sig "$D/s.pem"
                    if [ "$RC" -eq 0 ]; then pass; else fail "$L: rnl-sigma verify refused a valid proof (rc=$RC) $(head -c 160 "$TMP/err")"; fi
                    q "$r" verify --algo rnl-sigma --pubkey "$D/${g}_pub.pem" --in "$D/m2.bin" --sig "$D/s.pem"
                    if [ "$RC" -eq 1 ] && grep -q 'Verification FAILED' "$TMP/out"; then pass
                    else fail "$L: rnl-sigma verify on a changed message: rc=$RC, not 'Verification FAILED'"; fi
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
        hcred)  q "$ref" cred-prove --rounds $SR --in "$D/$ref.pem" --out "$D/pf_x.pem"
                q "$c" cred-verify --min-rounds $SR --proof "$D/pf_x.pem" --pubkey "$D/${ref}_pub.pem"
                refused "$a/$n cred-verify ($c)" ;;
        hkex-rnl) q "$c" kex --algo hkex-rnl --our "$D/$ref.pem" --their "$D/${ref}_pub.pem" --out "$D/k_$c.pem"
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
rnl_mixed() {  # label: refused as a ring size mismatch naming our 64, then 128
    if [ "$RC" -ne 0 ] && [ "$RC" -le 2 ] && grep -qiE 'ring size mismatch.*\b64\b.*\b128\b' "$TMP/err"; then pass
    else fail "$1: rc=$RC, not refused as a ring size mismatch (64, then 128): $(head -c 160 "$TMP/err")"; fi; }
M="$TMP/mix"; mkdir -p "$M"; head -c 8 /dev/urandom > "$M/m.bin"
for c in "${LANGS[@]}"; do
    for a in hkex-gf hpke hpks hpke-stern hpks-stern hcred hkex-rnl; do
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
        hcred)   # TODO #383 stage 3: Go panicked on both; Python failed the credential unnamed
            q "$c" cred-prove --rounds $SR --in "$M/k64.pem" --out "$M/p64.pem"
            q "$c" cred-verify --min-rounds $SR --proof "$M/p64.pem" --pubkey "$M/k64_pub.pem"
            [ "$RC" -eq 0 ] && pass || fail "mixed control: same-width cred-verify ($c) rc=$RC"
            q "$c" cred-prove --rounds $SR --in "$M/k128.pem" --out "$M/p128.pem"
            q "$c" cred-verify --min-rounds $SR --proof "$M/p128.pem" --pubkey "$M/k64_pub.pem"
            mixed "mixed-width hcred proof ($c)" "proof n is 128, public key n is 64"
            q "$c" genpkey --algo hpks-stern --bits 64  --out "$M/i64.pem"
            q "$c" genpkey --algo hpks-stern --bits 128 --out "$M/i128.pem"
            q "$c" pkey --in "$M/i64.pem"  --pubout --out "$M/i64_pub.pem"
            q "$c" pkey --in "$M/i128.pem" --pubout --out "$M/i128_pub.pem"
            q "$c" cred-issue --rounds $SR --in "$M/k64_pub.pem" --our "$M/i64.pem" --out "$M/c64.pem"
            q "$c" cred-verify --min-rounds $SR --proof "$M/p64.pem" --pubkey "$M/k64_pub.pem" --cred "$M/c64.pem" --issuer "$M/i64_pub.pem"
            [ "$RC" -eq 0 ] && pass || fail "mixed control: same-width credential ($c) rc=$RC"
            q "$c" cred-issue --rounds $SR --in "$M/k64_pub.pem" --our "$M/i128.pem" --out "$M/c128.pem"
            q "$c" cred-verify --min-rounds $SR --proof "$M/p64.pem" --pubkey "$M/k64_pub.pem" --cred "$M/c128.pem" --issuer "$M/i64_pub.pem"
            mixed "mixed-width hcred credential ($c)" "credential n is 128, issuer key n is 64" ;;
        hkex-rnl)   # TODO #383 stage 4.  The four CLIs word it four ways, each
                    # naming our ring and then the other's; C's hybrid read
                    # neither ring until now.
            q "$c" genpkey --algo hpke-stern-kem --out "$M/kem.pem"
            q "$c" pkey --in "$M/kem.pem" --pubout --out "$M/kem_pub.pem"
            for ka in hkex-rnl hybrid-rnl-stern; do
                kem1=(); kem2=()
                [ "$ka" = hybrid-rnl-stern ] && { kem1=(--their-kem "$M/kem_pub.pem"); kem2=(--our-kem "$M/kem.pem"); }
                q "$c" kex --algo "$ka" --our "$M/k64.pem" --their "$M/k64_pub.pem" "${kem1[@]}" --out "$M/r64.pem"
                [ "$RC" -eq 0 ] && pass || fail "mixed control: same-ring $ka respond ($c) rc=$RC"
                q "$c" kex --algo "$ka" --our "$M/k64.pem" --their "$M/r64.pem" "${kem2[@]}" --out "$M/ok.pem"
                [ "$RC" -eq 0 ] && pass || fail "mixed control: same-ring $ka complete ($c) rc=$RC"
                q "$c" kex --algo "$ka" --our "$M/k64.pem" --their "$M/k128_pub.pem" "${kem1[@]}" --out "$M/x.pem"
                rnl_mixed "mixed-ring $ka respond ($c)"
                q "$c" kex --algo "$ka" --our "$M/k128.pem" --their "$M/k128_pub.pem" "${kem1[@]}" --out "$M/r128.pem"
                q "$c" kex --algo "$ka" --our "$M/k64.pem" --their "$M/r128.pem" "${kem2[@]}" --out "$M/x.pem"
                rnl_mixed "mixed-ring $ka complete ($c)"
            done
            q "$c" sign --algo rnl-sigma --key "$M/k64.pem" --in "$M/m.bin" --out "$M/s64.pem"
            q "$c" verify --algo rnl-sigma --pubkey "$M/k64_pub.pem" --in "$M/m.bin" --sig "$M/s64.pem"
            [ "$RC" -eq 0 ] && pass || fail "mixed control: same-ring rnl-sigma verify ($c) rc=$RC"
            q "$c" sign --algo rnl-sigma --key "$M/k128.pem" --in "$M/m.bin" --out "$M/s128.pem"
            q "$c" verify --algo rnl-sigma --pubkey "$M/k64_pub.pem" --in "$M/m.bin" --sig "$M/s128.pem"
            rnl_mixed "mixed-ring rnl-sigma verify ($c)" ;;
        esac
    done
done

echo
echo "Results: $PASS PASS / $FAIL FAIL / $NA n/a (languages: ${LANGS[*]})"
[ "$NA" -eq 0 ] || echo "n/a: $NA_STERN Stern pkey --text cells with Java on one side, $NA_HCRED hcred pkey --text cells across CLIs (TODO #386), $NA_RNL hkex-rnl ones (TODO #387)"
[ "$PASS" -gt 0 ] || exit 2
[ "$FAIL" -eq 0 ] || exit 1
