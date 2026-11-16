# CliTest/lib_der_fixtures.sh -- the C-built fixture set and the one argv
# template per DER-SEQUENCE label that test_der_items_matrix.sh (TODO #367) and
# test_canonical_encoding_matrix.sh (TODO #372) both drive.  Sourced, not run:
# expects $TMP and the CLI[] array (CLI[c] must be set) from the caller, and
# defines $F (the fixture directory), T[label]="fixture|argv" ({X} = artifact
# under test, {F} = fixture directory, {O} = output) and NO_READER[label].

# ── Fixtures (C CLI, n = 256) ────────────────────────────────────────────────
F="$TMP/fx"; mkdir -p "$F"
C=${CLI[c]}
q() { "$@" >/dev/null 2>&1; }
for t in hkex-gf hkex-rnl hpks hpks-nl hpke hpke-nl hpke-nl3 hpks-stern hpke-stern \
         hpke-stern-kem oprf hpks-wots hcred; do
    q $C genpkey --algo "$t" --out "$F/$t.pem"
    q $C pkey --in "$F/$t.pem" --pubout --out "$F/${t}_pub.pem" || true
done
q $C genpkey --algo hpks-xmss --xmss-height 2 --out "$F/hpks-xmss.pem"
q $C pkey --in "$F/hpks-xmss.pem" --pubout --out "$F/hpks-xmss_pub.pem"
q $C genpkey --algo hpks-stern --out "$F/m2.pem"; q $C pkey --in "$F/m2.pem" --pubout --out "$F/m2_pub.pem"
q $C genpkey --algo hkex-rnl --out "$F/rnl2.pem"; q $C pkey --in "$F/rnl2.pem" --pubout --out "$F/rnl2_pub.pem"
printf 'der item count test message, 32' > "$F/msg.bin"
for a in hpke hpke-nl hpke-nl3 hpke-stern hpke-stern-kem; do
    q $C enc --algo $a --pubkey "$F/${a}_pub.pem" --in "$F/msg.bin" --out "$F/ct_$a.pem"
done
for a in hpks hpks-nl; do
    q $C sign --algo $a --key "$F/$a.pem" --in "$F/msg.bin" --out "$F/sig_$a.pem"
done
q $C sign --algo hpks-stern --rounds 2 --key "$F/hpks-stern.pem" --in "$F/msg.bin" --out "$F/sig_hpks-stern.pem"
cp "$F/hpks-wots.pem" "$F/w1.pem"; cp "$F/hpks-wots.pem.idx" "$F/w1.pem.idx" 2>/dev/null || true
q $C sign --algo hpks-wots --key "$F/w1.pem" --in "$F/msg.bin" --out "$F/sig_hpks-wots.pem"
cp "$F/hpks-xmss.pem" "$F/x1.pem"; cp "$F/hpks-xmss.pem.idx" "$F/x1.pem.idx" 2>/dev/null || true
q $C sign --algo hpks-xmss --key "$F/x1.pem" --in "$F/msg.bin" --out "$F/sig_hpks-xmss.pem"
q $C sign --algo hpks-ring --rounds 2 --key "$F/hpks-stern.pem" \
    --ring "$F/hpks-stern_pub.pem,$F/m2_pub.pem" --in "$F/msg.bin" --out "$F/sig_ring.pem"
q $C kex --algo hkex-rnl --our "$F/rnl2.pem" --their "$F/hkex-rnl_pub.pem" --out "$F/rnl_resp.pem"
q $C kex --algo hybrid-rnl-stern --our "$F/rnl2.pem" --their "$F/hkex-rnl_pub.pem" \
    --their-kem "$F/hpke-stern-kem_pub.pem" --out "$F/hyb_resp.pem"
q $C kex --algo hkex-gf --our "$F/hkex-gf.pem" --their "$F/hkex-gf_pub.pem" --out "$F/sk.pem"
q $C oprf-blind --in "$F/msg.bin" --out "$F/oprf_state.pem"
q $C oprf-eval --key "$F/oprf.pem" --in "$F/oprf_state.pem" --out "$F/oprf_eval.pem"
q $C genpkey --algo hpks --out "$F/t2.pem"
q $C threshold-commit --key "$F/hpks.pem" --commit-out "$F/c1.pem" --nonce-out "$F/n1.pem"
q $C threshold-commit --key "$F/t2.pem" --commit-out "$F/c2.pem" --nonce-out "$F/n2.pem"
q $C threshold-aggregate --commit "$F/c1.pem" --commit "$F/c2.pem" --in "$F/msg.bin" --out "$F/agg.pem"
q $C threshold-respond --key "$F/hpks.pem" --commit "$F/c1.pem" --commit "$F/c2.pem" \
    --aggregate "$F/agg.pem" --nonce "$F/n1.pem" --out "$F/p1.pem"
q $C threshold-respond --key "$F/t2.pem" --commit "$F/c1.pem" --commit "$F/c2.pem" \
    --aggregate "$F/agg.pem" --nonce "$F/n2.pem" --out "$F/p2.pem"
q $C threshold-combine --aggregate "$F/agg.pem" --partial "$F/p1.pem" --partial "$F/p2.pem" \
    --out "$F/tsig.pem"
q $C cred-prove --in "$F/hcred.pem" --msg n --rounds 2 --out "$F/proof.pem"
q $C cred-issue --our "$F/hpks-stern.pem" --in "$F/hcred_pub.pem" --rounds 2 --out "$F/cred.pem"
head -c 32 /dev/urandom > "$F/seed.bin"
q $C rand --seed "$F/seed.bin" --bytes 8 --state "$F/drbg.pem" --out "$TMP/r.bin"
q $C genpkey --algo hkex-gf --passphrase pw --out "$F/enc_priv.pem"

# ── Templates: label -> "fixture|argv" ({X} = artifact under test, {F}, {O}) ──
declare -A T=()
T["HERRADURA HKEX-GF PRIVATE KEY"]="hkex-gf.pem|kex --algo hkex-gf --our {X} --their {F}/hkex-gf_pub.pem --out {O}"
T["HERRADURA HKEX-GF PUBLIC KEY"]="hkex-gf_pub.pem|kex --algo hkex-gf --our {F}/hkex-gf.pem --their {X} --out {O}"
T["HERRADURA HPKS PRIVATE KEY"]="hpks.pem|sign --algo hpks --key {X} --in {F}/msg.bin --out {O}"
T["HERRADURA HPKS PUBLIC KEY"]="hpks_pub.pem|verify --algo hpks --pubkey {X} --in {F}/msg.bin --sig {F}/sig_hpks.pem"
T["HERRADURA HPKS-NL PRIVATE KEY"]="hpks-nl.pem|sign --algo hpks-nl --key {X} --in {F}/msg.bin --out {O}"
T["HERRADURA HPKS-NL PUBLIC KEY"]="hpks-nl_pub.pem|verify --algo hpks-nl --pubkey {X} --in {F}/msg.bin --sig {F}/sig_hpks-nl.pem"
T["HERRADURA HPKE PRIVATE KEY"]="hpke.pem|dec --algo hpke --key {X} --in {F}/ct_hpke.pem --out {O}"
T["HERRADURA HPKE PUBLIC KEY"]="hpke_pub.pem|enc --algo hpke --pubkey {X} --in {F}/msg.bin --out {O}"
T["HERRADURA HPKE-NL PRIVATE KEY"]="hpke-nl.pem|dec --algo hpke-nl --key {X} --in {F}/ct_hpke-nl.pem --out {O}"
T["HERRADURA HPKE-NL PUBLIC KEY"]="hpke-nl_pub.pem|enc --algo hpke-nl --pubkey {X} --in {F}/msg.bin --out {O}"
T["HERRADURA HPKE-NL3 PRIVATE KEY"]="hpke-nl3.pem|dec --algo hpke-nl3 --key {X} --in {F}/ct_hpke-nl3.pem --out {O}"
T["HERRADURA HPKE-NL3 PUBLIC KEY"]="hpke-nl3_pub.pem|enc --algo hpke-nl3 --pubkey {X} --in {F}/msg.bin --out {O}"
T["HERRADURA HKEX-RNL PRIVATE KEY"]="hkex-rnl.pem|kex --algo hkex-rnl --our {X} --their {F}/rnl2_pub.pem --out {O}"
T["HERRADURA HKEX-RNL PUBLIC KEY"]="hkex-rnl_pub.pem|kex --algo hkex-rnl --our {F}/rnl2.pem --their {X} --out {O}"
T["HERRADURA HKEX-RNL RESPONSE"]="rnl_resp.pem|kex --algo hkex-rnl --our {F}/hkex-rnl.pem --their {X} --out {O}"
T["HERRADURA HYBRID-RNL-STERN RESPONSE"]="hyb_resp.pem|kex --algo hybrid-rnl-stern --our {F}/hkex-rnl.pem --our-kem {F}/hpke-stern-kem.pem --their {X} --out {O}"
T["HERRADURA HPKS-STERN PRIVATE KEY"]="hpks-stern.pem|sign --algo hpks-stern --rounds 2 --key {X} --in {F}/msg.bin --out {O}"
T["HERRADURA HPKS-STERN PUBLIC KEY"]="hpks-stern_pub.pem|verify --algo hpks-stern --min-rounds 1 --pubkey {X} --in {F}/msg.bin --sig {F}/sig_hpks-stern.pem"
T["HERRADURA HPKE-STERN PRIVATE KEY"]="hpke-stern.pem|dec --algo hpke-stern --key {X} --in {F}/ct_hpke-stern.pem --out {O}"
T["HERRADURA HPKE-STERN PUBLIC KEY"]="hpke-stern_pub.pem|enc --algo hpke-stern --pubkey {X} --in {F}/msg.bin --out {O}"
T["HERRADURA HPKE-STERN-KEM PRIVATE KEY"]="hpke-stern-kem.pem|dec --algo hpke-stern-kem --key {X} --in {F}/ct_hpke-stern-kem.pem --out {O}"
T["HERRADURA HPKE-STERN-KEM PUBLIC KEY"]="hpke-stern-kem_pub.pem|enc --algo hpke-stern-kem --pubkey {X} --in {F}/msg.bin --out {O}"
T["HERRADURA HPKS-WOTS PRIVATE KEY"]="hpks-wots.pem|sign --algo hpks-wots --key {X} --in {F}/msg.bin --out {O}"
T["HERRADURA HPKS-WOTS PUBLIC KEY"]="hpks-wots_pub.pem|verify --algo hpks-wots --pubkey {X} --in {F}/msg.bin --sig {F}/sig_hpks-wots.pem"
T["HERRADURA HPKS-WOTS SIGNATURE"]="sig_hpks-wots.pem|verify --algo hpks-wots --pubkey {F}/hpks-wots_pub.pem --in {F}/msg.bin --sig {X}"
T["HERRADURA HPKS-XMSS PRIVATE KEY"]="hpks-xmss.pem|sign --algo hpks-xmss --key {X} --in {F}/msg.bin --out {O}"
T["HERRADURA HPKS-XMSS PUBLIC KEY"]="hpks-xmss_pub.pem|verify --algo hpks-xmss --pubkey {X} --in {F}/msg.bin --sig {F}/sig_hpks-xmss.pem"
T["HERRADURA HPKS-XMSS SIGNATURE"]="sig_hpks-xmss.pem|verify --algo hpks-xmss --pubkey {F}/hpks-xmss_pub.pem --in {F}/msg.bin --sig {X}"
T["HERRADURA HPKS-RING SIGNATURE"]="sig_ring.pem|verify --algo hpks-ring --min-rounds 1 --ring {F}/hpks-stern_pub.pem,{F}/m2_pub.pem --in {F}/msg.bin --sig {X}"
T["HERRADURA OPRF PRIVATE KEY"]="oprf.pem|oprf-eval --key {X} --in {F}/oprf_state.pem --out {O}"
T["HERRADURA OPRF CLIENT STATE"]="oprf_state.pem|oprf-eval --key {F}/oprf.pem --in {X} --out {O}"
T["HERRADURA OPRF EVALUATION"]="oprf_eval.pem|oprf-unblind --state {F}/oprf_state.pem --eval {X}"
T["HERRADURA HPKST COMMITMENT"]="c1.pem|threshold-aggregate --commit {X} --commit {F}/c2.pem --in {F}/msg.bin --out {O}"
T["HERRADURA HPKST NONCE"]="n1.pem|threshold-respond --key {F}/hpks.pem --commit {F}/c1.pem --commit {F}/c2.pem --aggregate {F}/agg.pem --nonce {X} --out {O}"
T["HERRADURA HPKST AGGREGATE"]="agg.pem|threshold-respond --key {F}/hpks.pem --commit {F}/c1.pem --commit {F}/c2.pem --aggregate {X} --nonce {F}/n1.pem --out {O}"
T["HERRADURA HPKST PARTIAL"]="p1.pem|threshold-combine --aggregate {F}/agg.pem --partial {X} --partial {F}/p2.pem --out {O}"
T["HERRADURA HPKST SIGNATURE"]="tsig.pem|verify --algo hpks-t --in {F}/msg.bin --sig {X}"
T["HERRADURA HCRED CREDENTIAL"]="cred.pem|cred-verify --min-rounds 1 --proof {F}/proof.pem --pubkey {F}/hcred_pub.pem --msg n --cred {X} --issuer {F}/hpks-stern_pub.pem"
T["HERRADURA SESSION KEY"]="sk.pem|enc --algo hske --key {X} --in {F}/msg.bin --out {O}"
T["HERRADURA HDRBG STATE"]="drbg.pem|rand --state {X} --bytes 8 --out {O}"
T["HERRADURA ENCRYPTED PRIVATE KEY"]="enc_priv.pem|pkey --decrypt --passphrase pw --in {X} --out {O}"
T["HERRADURA CIPHERTEXT"]="ct_hpke.pem|dec --algo hpke --key {F}/hpke.pem --in {X} --out {O}"
T["HERRADURA SIGNATURE"]="sig_hpks.pem|verify --algo hpks --pubkey {F}/hpks_pub.pem --in {F}/msg.bin --sig {X}"
# Labels no subcommand reads back: there is no reader to probe.
declare -A NO_READER=(
    ["HERRADURA DIGEST"]="dgst writes it; nothing reads it"
    ["HERRADURA PAKE RECORD"]="pake-register writes it; pake-demo runs both sides in one process"
)
