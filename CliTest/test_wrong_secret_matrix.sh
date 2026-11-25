#!/usr/bin/env bash
# CliTest/test_wrong_secret_matrix.sh — TODO #410: every acceptance decision a
# CLI makes, probed with a WRONG SECRET, through all four CLIs.
#
# #409's ZKBoo verifier accepted a proof made from any witness, in all four
# ports, because every check that existed tampered an honest artifact or ran a
# weaker cheat than a real adversary's.  This test runs the adversary's first
# move against each decision instead: make the artifact through the honest code
# path, but with a secret that does not match the public statement, and require
# every CLI to reject it.  Three kinds of wrong secret:
#   OTHER    a second key pair's secret (sign with key 2, verify under key 1);
#   SPLICED  key 1's public fields with another secret in the private-key file
#            (CliTest/wrong_secret/splice.py), where the file carries both;
#   CHEAT    #409's own cheat: a wrong witness proving the TRUE statement.  The
#            honest CLIs never produce one -- they derive Stern's syndrome and
#            RNL's C from the secret they hold, and HCRED's prover refuses -- so
#            CliTest/wrong_secret/cheat_sign.py runs the Python CLI with that
#            derivation patched, and exits 3 if the patch is never reached.
# Covered: hpks, hpks-nl, rnl-sigma, hpks-stern (N = 256 and 2304), hpks-ring
# (both widths), hpks-wots, hpks-xmss, HCRED proofs and credentials,
# hske-nla1 --aead, hske-duplex, hske-duplex3, encfile / decfile, and pkey
# --decrypt; nl-zkboo / nl-zkbpp are test_raw_body_diff.sh's wrongA cells.
#
# Every cell has an ACCEPT-CONTROL beside it (the honest artifact, or the
# patched prover handed the true key), so a CLI that rejects everything fails.
# The negative control: a stand-in verifier that accepts everything must fail
# the wrong-secret cells.  A wrong-witness proof survives only by a challenge
# coincidence; every one is made at the shipped round count (Stern 219, HCRED
# 32: (1/3)^32 = 5e-16), so no cell is a sampled verdict.
#
# hpks-t was a KNOWN cell until TODO #412 (v20.0.0) bound the signature to
# --pubkey's group; it now has ordinary cells.
# hpke-stern was a KNOWN cell until TODO #413 (v21.0.0) retired its enc/dec.
# KNOWN cells record a defect this test found and a TODO now owns.  Each passes
# while the defect stands and FAILS once it is fixed, so the fix must turn the
# cell into an ordinary one.  None is open.
# Claimed by ci.yml's cross-lang-compat job.
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
H="$ROOT/CliTest/wrong_secret"
PASS=0; FAIL=0; KNOWN=0
pass() { echo "PASS $1"; PASS=$((PASS+1)); }
fail() { echo "FAIL $1"; FAIL=$((FAIL+1)); }

declare -A CLI=()
CLI[py]="python3 $ROOT/HerraduraCli/herradura.py"
[ -x HerraduraCli/herradura_cli ] && CLI[c]="$ROOT/HerraduraCli/herradura_cli"
[ -x HerraduraCli/herradura_cli_go ] && CLI[go]="$ROOT/HerraduraCli/herradura_cli_go"
if command -v javac >/dev/null 2>&1 && bash bindings/java/build.sh >/dev/null; then
    CLI[java]="java -cp $ROOT/bindings/java herradurakex.HerraduraCli"
else echo "NOTE: Java CLI not built (javac absent or the build failed)"; fi
LANGS=()
for l in c go py java; do [ -n "${CLI[$l]:-}" ] && LANGS+=("$l"); done
echo "CLIs under test: ${LANGS[*]}"
if [ "${#LANGS[@]}" -lt 2 ]; then
    echo "FAIL test_wrong_secret_matrix: fewer than two CLIs, so nothing was compared." >&2
    [ "${HKX_ALLOW_SKIP:-0}" = "1" ] && exit 0
    exit 2
fi
G="${CLI[${LANGS[0]}]}"           # writes the keys
X="python3 $H/cheat_sign.py"
echo "wrong-secret probe message" > "$TMP/m"

# One CLI run, classed: OK (verified / decrypted to the plaintext), FAILED
# (exit 1 with a verdict), REFUSED (any other clean exit), CRASH (a trace).
classify() {   # output, rc, [plain file to compare]
    case "$1" in *Traceback*|*"panic:"*|*"Exception in thread"*|*AddressSanitizer*) echo CRASH; return ;; esac
    if [ -n "${3:-}" ]; then
        if [ "$2" -ne 0 ]; then echo REFUSED; elif cmp -s "$TMP/o" "$3"; then echo OK; else echo GARBAGE; fi
        return
    fi
    case "$2:$1" in 0:*OK*) echo OK ;; 1:*FAIL*) echo FAILED ;; 0:*) echo "ODD" ;; *) echo REFUSED ;; esac
}
# cell NAME WANT ARGS... -- run ARGS under every CLI.  WANT is OK (the control),
# BAD (FAILED or REFUSED in every CLI), or KNOWN:N (every CLI says OK: the defect
# TODO #N records).  PLAIN=file compares a decryption's output with it.
cell() {
    local name=$1 want=$2; shift 2
    local r="" ok=1 l out rc v
    for l in "${LANGS[@]}"; do
        rm -f "$TMP/o"
        out=$(eval "${VERIFIER:-${CLI[$l]}} $*" 2>&1); rc=$?
        v=$(classify "$out" "$rc" "${PLAIN:-}")
        r="$r $l=$v"
        case "$want:$v" in OK:OK|BAD:FAILED|BAD:REFUSED|KNOWN*:OK) ;; *) ok=0 ;; esac
    done
    if [ $ok = 1 ]; then
        case "$want" in
            KNOWN*) echo "KNOWN $name (TODO #${want#KNOWN:}):$r"; KNOWN=$((KNOWN+1)) ;;
            *) pass "$name ($want):$r" ;;
        esac
    else
        case "$want" in
            KNOWN*) fail "$name: no longer the defect TODO #${want#KNOWN:} records -- make it an ordinary cell:$r" ;;
            *) fail "$name (want $want):$r" ;;
        esac
    fi
}
mk()  { $G genpkey "$@" >/dev/null 2>&1 || { fail "fixture: genpkey $*"; exit 1; }; }
pub() { $G pkey --in "$1" --pubout --out "$2" >/dev/null 2>&1 || { fail "fixture: pubout $1"; exit 1; }; }
need() { [ -s "$1" ] || { fail "fixture: $2 wrote nothing"; return 1; }; }
splice() { python3 "$H/splice.py" "$@" || { fail "fixture: splice $*"; exit 1; }; }

# ── Schnorr-family and RNL signatures: every CLI signs, every CLI verifies ────
mk --algo hkex-rnl --out "$TMP/r1.pem"; mk --algo hkex-rnl --out "$TMP/r2.pem"; pub "$TMP/r1.pem" "$TMP/r1p.pem"
splice der0donor "$TMP/r1.pem" "$TMP/r1x.pem" "$TMP/r2.pem"
for a in hpks hpks-nl; do
    mk --algo $a --out "$TMP/${a}1.pem"; mk --algo $a --out "$TMP/${a}2.pem"; pub "$TMP/${a}1.pem" "$TMP/${a}1p.pem"
    splice der0flip "$TMP/${a}1.pem" "$TMP/${a}1x.pem"
done
for s in "${LANGS[@]}"; do
    P="${CLI[$s]}"
    for a in hpks hpks-nl; do
        for k in 1 2 1x; do $P sign --algo $a --key "$TMP/${a}$k.pem" --in "$TMP/m" --out "$TMP/${a}_${s}_$k" >/dev/null 2>&1; done
        need "$TMP/${a}_${s}_1" "$s sign $a" &&
            cell "$a signed by $s: control" OK verify --algo $a --pubkey "$TMP/${a}1p.pem" --in "$TMP/m" --sig "$TMP/${a}_${s}_1"
        need "$TMP/${a}_${s}_2" "$s sign $a" &&
            cell "$a signed by $s: OTHER key" BAD verify --algo $a --pubkey "$TMP/${a}1p.pem" --in "$TMP/m" --sig "$TMP/${a}_${s}_2"
        need "$TMP/${a}_${s}_1x" "$s sign $a (spliced)" &&
            cell "$a signed by $s: SPLICED secret" BAD verify --algo $a --pubkey "$TMP/${a}1p.pem" --in "$TMP/m" --sig "$TMP/${a}_${s}_1x"
    done
    for k in 1 2; do $P sign --algo rnl-sigma --key "$TMP/r$k.pem" --in "$TMP/m" --out "$TMP/rnl_${s}_$k" >/dev/null 2>&1; done
    need "$TMP/rnl_${s}_1" "$s sign rnl-sigma" &&
        cell "rnl-sigma signed by $s: control" OK verify --algo rnl-sigma --pubkey "$TMP/r1p.pem" --in "$TMP/m" --sig "$TMP/rnl_${s}_1"
    need "$TMP/rnl_${s}_2" "$s sign rnl-sigma" &&
        cell "rnl-sigma signed by $s: OTHER key" BAD verify --algo rnl-sigma --pubkey "$TMP/r1p.pem" --in "$TMP/m" --sig "$TMP/rnl_${s}_2"
done
$X "$TMP/r1.pem" -- sign --algo rnl-sigma --key "$TMP/r1.pem"  --in "$TMP/m" --out "$TMP/rnl_c0" 2>/dev/null
$X "$TMP/r1.pem" -- sign --algo rnl-sigma --key "$TMP/r1x.pem" --in "$TMP/m" --out "$TMP/rnl_cx" 2>/dev/null
need "$TMP/rnl_c0" "patched rnl-sigma" &&
    cell "rnl-sigma CHEAT control (patched prover, true s)" OK verify --algo rnl-sigma --pubkey "$TMP/r1p.pem" --in "$TMP/m" --sig "$TMP/rnl_c0"
need "$TMP/rnl_cx" "patched rnl-sigma" &&
    cell "rnl-sigma CHEAT: wrong s, true C" BAD verify --algo rnl-sigma --pubkey "$TMP/r1p.pem" --in "$TMP/m" --sig "$TMP/rnl_cx"

# ── Stern-F and the ring, at N = 256 and N = 2304 ─────────────────────────────
for lv in 256 2304; do
    o=""; [ $lv = 2304 ] && o="--level 128"
    for k in 1 2 3; do mk --algo hpks-stern $o --out "$TMP/t${lv}_$k.pem"; pub "$TMP/t${lv}_$k.pem" "$TMP/t${lv}_${k}p.pem"; done
    splice der0donor "$TMP/t${lv}_1.pem" "$TMP/t${lv}_1x.pem" "$TMP/t${lv}_2.pem"
    for s in "${LANGS[@]}"; do
        P="${CLI[$s]}"
        $P sign --algo hpks-stern --key "$TMP/t${lv}_2.pem" --in "$TMP/m" --out "$TMP/st_${lv}_${s}" >/dev/null 2>&1
        need "$TMP/st_${lv}_${s}" "$s sign hpks-stern N=$lv" &&
            cell "hpks-stern N=$lv signed by $s: OTHER key" BAD verify --algo hpks-stern --pubkey "$TMP/t${lv}_1p.pem" --in "$TMP/m" --sig "$TMP/st_${lv}_${s}"
    done
    $X "$TMP/t${lv}_1.pem" -- sign --algo hpks-stern --key "$TMP/t${lv}_1.pem"  --in "$TMP/m" --out "$TMP/st_${lv}_c0" 2>/dev/null
    $X "$TMP/t${lv}_1.pem" -- sign --algo hpks-stern --key "$TMP/t${lv}_1x.pem" --in "$TMP/m" --out "$TMP/st_${lv}_cx" 2>/dev/null
    need "$TMP/st_${lv}_c0" "patched hpks-stern N=$lv" &&
        cell "hpks-stern N=$lv CHEAT control" OK verify --algo hpks-stern --pubkey "$TMP/t${lv}_1p.pem" --in "$TMP/m" --sig "$TMP/st_${lv}_c0"
    need "$TMP/st_${lv}_cx" "patched hpks-stern N=$lv" &&
        cell "hpks-stern N=$lv CHEAT: wrong e, true syndrome" BAD verify --algo hpks-stern --pubkey "$TMP/t${lv}_1p.pem" --in "$TMP/m" --sig "$TMP/st_${lv}_cx"
    R="$TMP/t${lv}_1p.pem,$TMP/t${lv}_3p.pem"
    $X "$TMP/t${lv}_1.pem" -- sign --algo hpks-ring --key "$TMP/t${lv}_1.pem"  --ring "$R" --in "$TMP/m" --out "$TMP/rg_${lv}_c0" 2>/dev/null
    $X "$TMP/t${lv}_1.pem" -- sign --algo hpks-ring --key "$TMP/t${lv}_1x.pem" --ring "$R" --in "$TMP/m" --out "$TMP/rg_${lv}_cx" 2>/dev/null
    $G sign --algo hpks-ring --key "$TMP/t${lv}_2.pem" --ring "$TMP/t${lv}_2p.pem,$TMP/t${lv}_3p.pem" --in "$TMP/m" --out "$TMP/rg_${lv}_o" >/dev/null 2>&1
    need "$TMP/rg_${lv}_c0" "ring N=$lv" &&
        cell "hpks-ring N=$lv control" OK verify --algo hpks-ring --ring "$R" --in "$TMP/m" --sig "$TMP/rg_${lv}_c0"
    need "$TMP/rg_${lv}_cx" "ring N=$lv" &&
        cell "hpks-ring N=$lv CHEAT: a member's seed, a wrong e" BAD verify --algo hpks-ring --ring "$R" --in "$TMP/m" --sig "$TMP/rg_${lv}_cx"
    need "$TMP/rg_${lv}_o" "ring N=$lv" &&
        cell "hpks-ring N=$lv: a non-member's ring signature, presented for this ring" BAD verify --algo hpks-ring --ring "$R" --in "$TMP/m" --sig "$TMP/rg_${lv}_o"
done

# ── hash-based one-time and tree signatures ───────────────────────────────────
for a in hpks-wots "hpks-xmss --xmss-height 3"; do
    n=${a%% *}
    mk --algo $a --out "$TMP/${n}1.pem"; mk --algo $a --out "$TMP/${n}2.pem"; pub "$TMP/${n}1.pem" "$TMP/${n}1p.pem"
    $G sign --algo $n --key "$TMP/${n}1.pem" --in "$TMP/m" --out "$TMP/${n}_1" >/dev/null 2>&1
    $G sign --algo $n --key "$TMP/${n}2.pem" --in "$TMP/m" --out "$TMP/${n}_2" >/dev/null 2>&1
    need "$TMP/${n}_1" "sign $n" && cell "$n control" OK verify --algo $n --pubkey "$TMP/${n}1p.pem" --in "$TMP/m" --sig "$TMP/${n}_1"
    need "$TMP/${n}_2" "sign $n" && cell "$n OTHER key" BAD verify --algo $n --pubkey "$TMP/${n}1p.pem" --in "$TMP/m" --sig "$TMP/${n}_2"
done

# ── HPKS-T: the signature must be --pubkey's group's (TODO #412) ─────────────
for i in a b z; do mk --algo hpks --out "$TMP/k$i.pem"; pub "$TMP/k$i.pem" "$TMP/k${i}p.pem"; done
for i in a b; do $G threshold-commit --key "$TMP/k$i.pem" --commit-out "$TMP/c$i.pem" --nonce-out "$TMP/n$i.pem" >/dev/null 2>&1; done
$G threshold-aggregate --commit "$TMP/ca.pem" --commit "$TMP/cb.pem" --in "$TMP/m" --out "$TMP/agg.pem" >/dev/null 2>&1
for i in a b; do
    $G threshold-respond --key "$TMP/k$i.pem" --commit "$TMP/ca.pem" --commit "$TMP/cb.pem" \
        --aggregate "$TMP/agg.pem" --nonce "$TMP/n$i.pem" --out "$TMP/p$i.pem" >/dev/null 2>&1
done
$G threshold-combine --aggregate "$TMP/agg.pem" --partial "$TMP/pa.pem" --partial "$TMP/pb.pem" --out "$TMP/t.pem" >/dev/null 2>&1
need "$TMP/t.pem" "threshold-combine" && {
    cell "hpks-t control (the group's keys)" OK verify --algo hpks-t --pubkey "$TMP/kap.pem,$TMP/kbp.pem" --in "$TMP/m" --sig "$TMP/t.pem"
    cell "hpks-t control (the group's keys, other order)" OK verify --algo hpks-t --pubkey "$TMP/kbp.pem,$TMP/kap.pem" --in "$TMP/m" --sig "$TMP/t.pem"
    cell "hpks-t: an unrelated key" BAD verify --algo hpks-t --pubkey "$TMP/kzp.pem" --in "$TMP/m" --sig "$TMP/t.pem"
    cell "hpks-t: one member alone" BAD verify --algo hpks-t --pubkey "$TMP/kap.pem" --in "$TMP/m" --sig "$TMP/t.pem"
    cell "hpks-t: the group and an outsider" BAD verify --algo hpks-t --pubkey "$TMP/kap.pem,$TMP/kbp.pem,$TMP/kzp.pem" --in "$TMP/m" --sig "$TMP/t.pem"
    cell "hpks-t: no --pubkey" BAD verify --algo hpks-t --in "$TMP/m" --sig "$TMP/t.pem"
}

# ── HCRED proofs and credentials (n = 32, 32 rounds) ──────────────────────────
for i in u1 u2; do mk --algo hcred --bits 32 --out "$TMP/$i.pem"; pub "$TMP/$i.pem" "$TMP/${i}p.pem"; done
for i in is ix; do mk --algo hpks-stern --out "$TMP/$i.pem"; pub "$TMP/$i.pem" "$TMP/${i}p.pem"; done
splice hcred_s "$TMP/u1.pem" "$TMP/u1x.pem" "$TMP/u2.pem"
for i in u1 u2; do $G cred-prove --in "$TMP/$i.pem" --msg hello --rounds 32 --out "$TMP/pr_$i" >/dev/null 2>&1; done
$X "$TMP/u1.pem" -- cred-prove --in "$TMP/u1.pem"  --msg hello --rounds 32 --out "$TMP/pr_c0" 2>/dev/null
$X "$TMP/u1.pem" -- cred-prove --in "$TMP/u1x.pem" --msg hello --rounds 32 --out "$TMP/pr_cx" 2>/dev/null
$G cred-issue --our "$TMP/is.pem" --in "$TMP/u1p.pem" --rounds 32 --out "$TMP/cr_u1" >/dev/null 2>&1
$G cred-issue --our "$TMP/is.pem" --in "$TMP/u2p.pem" --rounds 32 --out "$TMP/cr_u2" >/dev/null 2>&1
$G cred-issue --our "$TMP/ix.pem" --in "$TMP/u1p.pem" --rounds 32 --out "$TMP/cr_x" >/dev/null 2>&1
V="cred-verify --min-rounds 32 --msg hello"
need "$TMP/pr_u1" "cred-prove" && cell "HCRED proof control" OK $V --proof "$TMP/pr_u1" --pubkey "$TMP/u1p.pem"
need "$TMP/pr_u2" "cred-prove" && cell "HCRED proof OTHER key" BAD $V --proof "$TMP/pr_u2" --pubkey "$TMP/u1p.pem"
need "$TMP/pr_c0" "patched cred-prove" && cell "HCRED CHEAT control" OK $V --proof "$TMP/pr_c0" --pubkey "$TMP/u1p.pem"
need "$TMP/pr_cx" "patched cred-prove" && cell "HCRED CHEAT: wrong s, true statement" BAD $V --proof "$TMP/pr_cx" --pubkey "$TMP/u1p.pem"
need "$TMP/cr_u1" "cred-issue" && {
    cell "credential control" OK $V --proof "$TMP/pr_u1" --pubkey "$TMP/u1p.pem" --cred "$TMP/cr_u1" --issuer "$TMP/isp.pem"
    cell "credential from ANOTHER issuer" BAD $V --proof "$TMP/pr_u1" --pubkey "$TMP/u1p.pem" --cred "$TMP/cr_x" --issuer "$TMP/isp.pem"
    cell "credential of ANOTHER holder" BAD $V --proof "$TMP/pr_u1" --pubkey "$TMP/u1p.pem" --cred "$TMP/cr_u2" --issuer "$TMP/isp.pem"
    cell "holder 2's proof with holder 1's credential" BAD $V --proof "$TMP/pr_u2" --pubkey "$TMP/u2p.pem" --cred "$TMP/cr_u1" --issuer "$TMP/isp.pem"
}

# ── authenticated decryption ──────────────────────────────────────────────────
for i in 1 2 3; do mk --algo hkex-gf --out "$TMP/g$i.pem"; done
pub "$TMP/g2.pem" "$TMP/g2p.pem"
$G kex --algo hkex-gf --our "$TMP/g1.pem" --their "$TMP/g2p.pem" --out "$TMP/k1.pem" >/dev/null 2>&1
$G kex --algo hkex-gf --our "$TMP/g3.pem" --their "$TMP/g2p.pem" --out "$TMP/k2.pem" >/dev/null 2>&1
head -c 32 /dev/urandom > "$TMP/p32"; head -c 3000 /dev/urandom > "$TMP/p3k"
flip() { python3 - "$1" "$2" <<'PYEOF'
import sys, base64
t = open(sys.argv[1]).read().split('\n')
b = bytearray(base64.b64decode(''.join(l for l in t[1:] if l and not l.startswith('-----'))))
b[len(b) // 2] ^= 1
open(sys.argv[2], 'w').write(t[0] + '\n' + base64.encodebytes(bytes(b)).decode() + t[0].replace('BEGIN', 'END') + '\n')
PYEOF
}
for a in "hske-nla1 --aead:p32" "hske-duplex:p3k" "hske-duplex3:p3k"; do
    alg=${a%%:*}; p=${a##*:}; t=${alg%% *}
    $G enc --algo $alg --key "$TMP/k1.pem" --in "$TMP/$p" --out "$TMP/ct_$t" >/dev/null 2>&1
    need "$TMP/ct_$t" "enc $alg" || continue
    flip "$TMP/ct_$t" "$TMP/ct_${t}_x"
    PLAIN="$TMP/$p" cell "$t control" OK dec --algo $t --key "$TMP/k1.pem" --in "$TMP/ct_$t" --out "$TMP/o"
    PLAIN="$TMP/$p" cell "$t under the WRONG key" BAD dec --algo $t --key "$TMP/k2.pem" --in "$TMP/ct_$t" --out "$TMP/o"
    PLAIN="$TMP/$p" cell "$t with one bit flipped" BAD dec --algo $t --key "$TMP/k1.pem" --in "$TMP/ct_${t}_x" --out "$TMP/o"
done
$G encfile --algo hske-nla1 --key "$TMP/k1.pem" --in "$TMP/p3k" --out "$TMP/f.hkx" >/dev/null 2>&1
if need "$TMP/f.hkx" "encfile"; then
    python3 -c "import sys;b=bytearray(open(sys.argv[1],'rb').read());b[len(b)//2]^=1;open(sys.argv[2],'wb').write(b)" "$TMP/f.hkx" "$TMP/fx.hkx"
    python3 -c "import sys;b=open(sys.argv[1],'rb').read();open(sys.argv[2],'wb').write(b[:-40])" "$TMP/f.hkx" "$TMP/ft.hkx"
    PLAIN="$TMP/p3k" cell "decfile control" OK decfile --algo hske-nla1 --key "$TMP/k1.pem" --in "$TMP/f.hkx" --out "$TMP/o"
    PLAIN="$TMP/p3k" cell "decfile under the WRONG key" BAD decfile --algo hske-nla1 --key "$TMP/k2.pem" --in "$TMP/f.hkx" --out "$TMP/o"
    PLAIN="$TMP/p3k" cell "decfile with one bit flipped" BAD decfile --algo hske-nla1 --key "$TMP/k1.pem" --in "$TMP/fx.hkx" --out "$TMP/o"
    PLAIN="$TMP/p3k" cell "decfile truncated by 40 bytes" BAD decfile --algo hske-nla1 --key "$TMP/k1.pem" --in "$TMP/ft.hkx" --out "$TMP/o"
fi
$G genpkey --algo hkex-gf --passphrase right --out "$TMP/env.pem" >/dev/null 2>&1
$G pkey --decrypt --in "$TMP/env.pem" --passphrase right --out "$TMP/env_plain.pem" >/dev/null 2>&1
if need "$TMP/env_plain.pem" "pkey --decrypt"; then
    PLAIN="$TMP/env_plain.pem" cell "pkey --decrypt control" OK pkey --decrypt --in "$TMP/env.pem" --passphrase right --out "$TMP/o"
    PLAIN="$TMP/env_plain.pem" cell "pkey --decrypt under the WRONG passphrase" BAD pkey --decrypt --in "$TMP/env.pem" --passphrase wrong --out "$TMP/o"
fi

# ── HPKE-Stern-F: retired (TODO #413) ───────────────────────────────────────
# Until v21.0.0 the ciphertext carried e', and K = hash(seed, e') needs only the
# PUBLIC seed, so the plaintext came from the ciphertext and public key alone
# (a KNOWN cell here).  enc and dec --algo hpke-stern are now refused, a v20
# ciphertext included; the key still signs, which is the accept-control.
mk --algo hpke-stern --out "$TMP/hs.pem"; pub "$TMP/hs.pem" "$TMP/hsp.pem"
python3 - "$TMP/hsp.pem" "$TMP/hs_ct" <<'PYEOF'
import sys, os
root = os.getcwd()
sys.path.insert(0, os.path.join(root, 'HerraduraCli'))
import herradura as H
pub, out = sys.argv[1], sys.argv[2]
syn, seed, n = H._read_pem_ints(pub)[1]
S = H._suite_mod
K, ct, e = S.hpke_stern_f_encap_with_e(S.BitArray(n, seed), n)
E = S.fscx_revolve(S.BitArray(n, int.from_bytes(b'x' * (n // 8), 'big')), K, n // 4)
u = lambda v: v if isinstance(v, int) else v.uint
der = H.der_seq(H.der_int(u(ct), n // 8), H.der_int(u(e), n // 8), H.der_int(u(K), n // 8),
                H.der_int(E.uint, n // 8), H.der_int(n))
open(out, 'w').write(H.pem_wrap('HERRADURA CIPHERTEXT', der))
PYEOF
if need "$TMP/hs_ct" "a v20-format hpke-stern ciphertext"; then
    cell "hpke-stern key control: it still signs as a Stern key" OK \
        sign --algo hpks-stern --key "$TMP/hs.pem" --in "$TMP/m" --out "$TMP/hs_sig" \
        "&&" "${CLI[${LANGS[0]}]}" verify --algo hpks-stern --pubkey "$TMP/hsp.pem" --in "$TMP/m" --sig "$TMP/hs_sig"
    cell "enc --algo hpke-stern (retired)" BAD enc --algo hpke-stern --pubkey "$TMP/hsp.pem" --in "$TMP/p32" --out "$TMP/o"
    PLAIN="$TMP/p32" cell "dec --algo hpke-stern of a v20 ciphertext, with the key" BAD \
        dec --algo hpke-stern --key "$TMP/hs.pem" --in "$TMP/hs_ct" --out "$TMP/o"
fi

# ── negative control: a verifier that accepts everything must fail the cells ─
printf '#!/bin/sh\necho "Signature OK"\nexit 0\n' > "$TMP/yes"; chmod +x "$TMP/yes"
before=$FAIL
VERIFIER="$TMP/yes" cell "(control) an accept-everything verifier on hpks OTHER" BAD \
    verify --algo hpks --pubkey "$TMP/hpks1p.pem" --in "$TMP/m" --sig "$TMP/hpks_${LANGS[0]}_2" >/dev/null
if [ $FAIL -eq $((before + 1)) ]; then FAIL=$before; pass "control: an accept-everything verifier fails a wrong-secret cell"
else fail "control: an accept-everything verifier passed a wrong-secret cell"; fi

echo "Results: $PASS PASS / $FAIL FAIL / $KNOWN KNOWN (CLIs: ${LANGS[*]})"
[ "$FAIL" -eq 0 ]
