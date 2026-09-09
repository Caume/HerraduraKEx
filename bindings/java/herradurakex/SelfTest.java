package herradurakex;

import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * TODO #192/#199/#200/#201/#202/#203: end-to-end round-trip smoke test
 * for the herradurakex Java package, with fresh random keys each run —
 * complements KatVerify's fixed-vector cross-check. Covers the classical
 * quartet ({@link Herradura}), the NL/PQC quartet ({@link HerraduraNl}),
 * HPKS-Stern-F/HPKE-Stern-F/HPKE-Stern-KEM ({@link Stern}), the OPRF
 * ({@link Oprf}), HPKS-WOTS-F/HPKS-XMSS-F ({@link Wots}, {@link Xmss}),
 * HCRED ({@link Hcred}), aPAKE ({@link ZkpNl}, {@link Hpake}), the
 * 78.C forward-secret ratchet ({@link Ratchet}, TODO #260), HDRBG
 * ({@link Hdrbg}, TODO #96/#260), HPKS-T ({@link HpksT}, TODO
 * #98/#260), FPE/twk ({@link FpeTwk}, TODO #78.A/#78.B/#260),
 * HSKE-NL-V2/V3-Duplex ({@link Duplex}, TODO #95/#255/#260), and
 * HPKS-Stern-Ring ({@link SternRing}, TODO #78.I/#260). Exits non-zero
 * on any failure.
 *
 * TODO #261 (asymmetry #2): each check below now carries a stable numeric
 * ID, {@code PASS [N] name} / {@code FAIL [N] name}, the same citable-ID
 * convention C/Go/Python's {@code [1]}-{@code [48]} test suites use
 * (e.g. CHANGELOG.md's "test [45] runs its Stern-F sub-check at
 * rounds=32"). The numbering is this file's own — one check per
 * protocol here where C/Go/Python often split correctness and
 * Eve-resistance into separate numbered tests per bit-width — so a
 * Java {@code [N]} does NOT name the same test as a same-numbered C/Go/
 * Python one; cite it as "SelfTest.java's check [N]" to avoid ambiguity.
 * In file order: [1] hkex_gf [2] hske [3] hpks [4] hpke [5] hkex_rnl
 * [6] hske_nl_a1 [7] hske_nl_a2 [8] hske_nl_a3 [9] hpke_nl3 [10] hpks_nl
 * [11] hpke_nl [12] hpks_stern_f [13] hpke_stern_f [14] hpke_stern_kem
 * [15] oprf [16] hpks_wots_f [17] hpks_xmss_f [18] hcred [19] zkp_nl
 * [20] hpake [21] ratchet [22] hdrbg [23] hpks_t [24] fpe_twk [25] duplex
 * [26] hpks_stern_ring [27] rnl_m_blind_guard [28] zkp_nl_zkboo
 * [29] zkp_nl_zkbpp [30] rnl_sigma [31] hcred_kkw
 * [32] qcmdpc_weak_key_screen [33] hske_nl_aead
 * [34] qcprf_seed_expansion. New checks append at [35]
 * onward; a check's
 * number is never reassigned once given, matching TODO.md/TODO_DONE.md's
 * own numbering discipline (TODO #154).
 *
 * Usage: java -cp bindings/java herradurakex.SelfTest
 */
public final class SelfTest {
    private SelfTest() { }

    private static String toHex(byte[] b) {
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte x : b) sb.append(String.format("%02x", x));
        return sb.toString();
    }

    public static void main(String[] args) {
        SecureRandom rng = new SecureRandom();
        int fails = 0;

        // HKEX-GF: both parties must derive the same shared secret.
        {
            BigInteger alicePriv = new BigInteger(Herradura.N, rng).and(Herradura.MASK);
            BigInteger bobPriv = new BigInteger(Herradura.N, rng).and(Herradura.MASK);
            BigInteger alicePub = Herradura.hkexGfPubkey(alicePriv);
            BigInteger bobPub = Herradura.hkexGfPubkey(bobPriv);
            BigInteger skAlice = Herradura.hkexGfAgree(alicePriv, bobPub);
            BigInteger skBob = Herradura.hkexGfAgree(bobPriv, alicePub);
            if (!skAlice.equals(skBob)) {
                System.out.println("FAIL [1] hkex_gf round-trip: shared secrets differ");
                fails++;
            } else {
                System.out.println("PASS [1] hkex_gf round-trip");
            }
        }

        // HSKE: decrypt(encrypt(pt)) == pt.
        {
            BigInteger key = new BigInteger(Herradura.N, rng).and(Herradura.MASK);
            BigInteger pt = new BigInteger(Herradura.N, rng).and(Herradura.MASK);
            BigInteger ct = Herradura.hskeEncrypt(pt, key);
            BigInteger recovered = Herradura.hskeDecrypt(ct, key);
            if (!recovered.equals(pt)) {
                System.out.println("FAIL [2] hske round-trip");
                fails++;
            } else {
                System.out.println("PASS [2] hske round-trip");
            }
        }

        // HPKS: sign/verify, plus a tampered-message rejection check.
        {
            BigInteger priv = new BigInteger(Herradura.N, rng).and(Herradura.MASK);
            BigInteger pub = Herradura.hkexGfPubkey(priv);
            BigInteger msg = new BigInteger(Herradura.N, rng).and(Herradura.MASK);
            Herradura.Signature sig = Herradura.hpksSign(msg, priv, rng);
            boolean ok = Herradura.hpksVerify(msg, pub, sig.r, sig.s);
            boolean rejectsTamper = !Herradura.hpksVerify(msg.xor(BigInteger.ONE), pub, sig.r, sig.s);
            if (!ok || !rejectsTamper) {
                System.out.println("FAIL [3] hpks round-trip (verify=" + ok + " rejects_tamper=" + rejectsTamper + ")");
                fails++;
            } else {
                System.out.println("PASS [3] hpks round-trip");
            }
        }

        // HPKE: decrypt(encrypt(pt)) == pt.
        {
            BigInteger priv = new BigInteger(Herradura.N, rng).and(Herradura.MASK);
            BigInteger pub = Herradura.hkexGfPubkey(priv);
            BigInteger pt = new BigInteger(Herradura.N, rng).and(Herradura.MASK);
            Herradura.Ciphertext enc = Herradura.hpkeEncrypt(pt, pub, rng);
            BigInteger recovered = Herradura.hpkeDecrypt(enc.ct, enc.r, priv);
            if (!recovered.equals(pt)) {
                System.out.println("FAIL [4] hpke round-trip");
                fails++;
            } else {
                System.out.println("PASS [4] hpke round-trip");
            }
        }

        // HKEX-RNL: both parties must reconcile to the same raw K (pre-KDF),
        // and the CLI-level contributory KDF composition must also agree.
        {
            int n = Herradura.N;
            int[] mBase = HerraduraNl.rnlMPoly(n);
            int[] aRand = HerraduraNl.rnlRandPoly(n, HerraduraNl.RNLQ, rng);
            int[] mBlind = HerraduraNl.rnlPolyAdd(mBase, aRand, HerraduraNl.RNLQ);
            HerraduraNl.RnlKeypair alice = HerraduraNl.rnlKeygen(mBlind, n, HerraduraNl.RNLQ, HerraduraNl.RNLP, rng);
            HerraduraNl.RnlKeypair bob = HerraduraNl.rnlKeygen(mBlind, n, HerraduraNl.RNLQ, HerraduraNl.RNLP, rng);
            HerraduraNl.RnlAgreeResult bobAgree = HerraduraNl.rnlAgree(
                bob.s, alice.c, HerraduraNl.RNLQ, HerraduraNl.RNLP, HerraduraNl.RNLPP, n, n);
            BigInteger aliceKey = HerraduraNl.rnlAgree(
                alice.s, bob.c, HerraduraNl.RNLQ, HerraduraNl.RNLP, HerraduraNl.RNLPP, n, n, bobAgree.hint);
            byte[] nA = new byte[32], nB = new byte[32];
            rng.nextBytes(nA);
            rng.nextBytes(nB);
            BigInteger kAlice = HerraduraNl.rnlContributoryKdf(aliceKey, n, nA, nB);
            BigInteger kBob = HerraduraNl.rnlContributoryKdf(bobAgree.key, n, nA, nB);
            if (!bobAgree.key.equals(aliceKey) || !kAlice.equals(kBob)) {
                System.out.println("FAIL [5] hkex_rnl round-trip: reconciled keys differ");
                fails++;
            } else {
                System.out.println("PASS [5] hkex_rnl round-trip");
            }
        }

        // HSKE-NL-A1 (counter-mode): decrypt(encrypt(pt)) == pt.
        {
            BigInteger key = new BigInteger(Herradura.N, rng).and(Herradura.MASK);
            BigInteger nonce = new BigInteger(Herradura.N, rng).and(Herradura.MASK);
            BigInteger pt = new BigInteger(Herradura.N, rng).and(Herradura.MASK);
            BigInteger ct = HerraduraNl.hskeNlA1Encrypt(pt, key, nonce);
            BigInteger recovered = HerraduraNl.hskeNlA1Decrypt(ct, key, nonce);
            if (!recovered.equals(pt)) {
                System.out.println("FAIL [6] hske_nl_a1 round-trip");
                fails++;
            } else {
                System.out.println("PASS [6] hske_nl_a1 round-trip");
            }
        }

        // HSKE-NL-A2 (revolve-mode): decrypt(encrypt(pt)) == pt.
        {
            BigInteger key;
            do {
                key = new BigInteger(Herradura.N, rng).and(Herradura.MASK);
            } while (!HerraduraNl.nlV2KeyIsValid(key));
            BigInteger pt = new BigInteger(Herradura.N, rng).and(Herradura.MASK);
            BigInteger ct = HerraduraNl.hskeNlA2Encrypt(pt, key);
            BigInteger recovered = HerraduraNl.hskeNlA2Decrypt(ct, key);
            if (!recovered.equals(pt)) {
                System.out.println("FAIL [7] hske_nl_a2 round-trip");
                fails++;
            } else {
                System.out.println("PASS [7] hske_nl_a2 round-trip");
            }
        }

        // HSKE-NL-A3 and HPKE-NL3 (NL-FSCX v3, TODO #255).  Deliberately NO
        // nlV2KeyIsValid filter on the key: v3 has no weak-key class, so the
        // filter above would be testing a screen that does not exist.  The
        // v3 != v2 check is what would catch a chi layer that degenerated to
        // the identity -- a round-trip alone would not.
        {
            BigInteger key = new BigInteger(Herradura.N, rng).and(Herradura.MASK);
            BigInteger pt = new BigInteger(Herradura.N, rng).and(Herradura.MASK);
            BigInteger ct = HerraduraNl.hskeNlA3Encrypt(pt, key);
            boolean rt = HerraduraNl.hskeNlA3Decrypt(ct, key).equals(pt);
            boolean differsFromV2 =
                    !ct.equals(HerraduraNl.nlFscxRevolveV2(pt, key, HerraduraNl.R3_VALUE));
            if (!rt || !differsFromV2) {
                System.out.println("FAIL [8] hske_nl_a3 round-trip (rt=" + rt
                        + " differs_from_v2=" + differsFromV2 + ")");
                fails++;
            } else {
                System.out.println("PASS [8] hske_nl_a3 round-trip");
            }

            BigInteger priv = new BigInteger(Herradura.N, rng).and(Herradura.MASK);
            BigInteger pub = Herradura.hkexGfPubkey(priv);
            Herradura.Ciphertext enc3 = HerraduraNl.hpkeNl3Encrypt(pt, pub, rng);
            BigInteger rec3 = enc3 == null ? null
                    : HerraduraNl.hpkeNl3Decrypt(enc3.ct, enc3.r, priv);
            if (enc3 == null || !pt.equals(rec3)) {
                System.out.println("FAIL [9] hpke_nl3 round-trip");
                fails++;
            } else {
                System.out.println("PASS [9] hpke_nl3 round-trip");
            }
        }

        // HPKS-NL: sign/verify, plus a tampered-message rejection check.
        {
            BigInteger priv = new BigInteger(Herradura.N, rng).and(Herradura.MASK);
            BigInteger pub = Herradura.hkexGfPubkey(priv);
            BigInteger msg = new BigInteger(Herradura.N, rng).and(Herradura.MASK);
            Herradura.Signature sig = HerraduraNl.hpksNlSign(msg, priv, rng);
            boolean ok = HerraduraNl.hpksNlVerify(msg, pub, sig.r, sig.s);
            boolean rejectsTamper = !HerraduraNl.hpksNlVerify(msg.xor(BigInteger.ONE), pub, sig.r, sig.s);
            if (!ok || !rejectsTamper) {
                System.out.println("FAIL [10] hpks_nl round-trip (verify=" + ok + " rejects_tamper=" + rejectsTamper + ")");
                fails++;
            } else {
                System.out.println("PASS [10] hpks_nl round-trip");
            }
        }

        // HPKE-NL: decrypt(encrypt(pt)) == pt.
        {
            BigInteger priv = new BigInteger(Herradura.N, rng).and(Herradura.MASK);
            BigInteger pub = Herradura.hkexGfPubkey(priv);
            BigInteger pt = new BigInteger(Herradura.N, rng).and(Herradura.MASK);
            Herradura.Ciphertext enc = HerraduraNl.hpkeNlEncrypt(pt, pub, rng);
            BigInteger recovered = HerraduraNl.hpkeNlDecrypt(enc.ct, enc.r, priv);
            if (enc == null || !pt.equals(recovered)) {
                System.out.println("FAIL [11] hpke_nl round-trip");
                fails++;
            } else {
                System.out.println("PASS [11] hpke_nl round-trip");
            }
        }

        // HPKS-Stern-F: sign/verify, tampered-message and corrupted-syndrome
        // rejection (TODO #131 regression), at a small demo round count.
        {
            Stern.SternKeypair kp = Stern.sternFKeygen(rng);
            BigInteger msg = new BigInteger(Herradura.N, rng).and(Herradura.MASK);
            // Use the full demo round count (not a smaller value): the
            // corrupted-syndrome check below only fails deterministically on
            // a round that draws challenge b=2 (only b=2 references the
            // syndrome), so too few rounds makes this assertion flaky by
            // Stern's own (2/3)^rounds soundness bound — e.g. 8 rounds
            // skips b=2 entirely ~3.9% of the time by chance.
            Stern.SternSignature sig = Stern.hpksSternFSign(msg, kp.e, kp.seed, Stern.SDFR, rng);
            boolean ok = Stern.hpksSternFVerify(msg, sig, kp.seed, kp.syndrome);
            boolean rejectsTamper = !Stern.hpksSternFVerify(msg.xor(BigInteger.ONE), sig, kp.seed, kp.syndrome);
            boolean rejectsCorruptSyn = !Stern.hpksSternFVerify(msg, sig, kp.seed, kp.syndrome.xor(BigInteger.ONE));
            if (!ok || !rejectsTamper || !rejectsCorruptSyn) {
                System.out.println("FAIL [12] hpks_stern_f round-trip (verify=" + ok
                    + " rejects_tamper=" + rejectsTamper + " rejects_corrupt_syn=" + rejectsCorruptSyn + ")");
                fails++;
            } else {
                System.out.println("PASS [12] hpks_stern_f round-trip");
            }
        }

        // HPKE-Stern-F (demo Niederreiter KEM): decap(encap()) derives the
        // same session key.
        {
            BigInteger seed = new BigInteger(Herradura.N, rng).and(Herradura.MASK);
            Stern.SternEncapResult enc = Stern.hpkeSternFEncapWithE(seed, rng);
            BigInteger recovered = Stern.hpkeSternFDecap(enc.eP, seed);
            if (!enc.k.equals(recovered)) {
                System.out.println("FAIL [13] hpke_stern_f round-trip");
                fails++;
            } else {
                System.out.println("PASS [13] hpke_stern_f round-trip");
            }
        }

        // HPKE-Stern-KEM (real QC-MDPC/BGF): decap(encap()) derives the
        // same session key. A small batch to keep the smoke test fast;
        // dedicated DFR measurement lives in SecurityProofsCode (TODO #195).
        {
            Stern.QcMdpcKeypair kp = Stern.qcmdpcKeygen(rng);
            boolean pubMatches = kp.hPub.equals(Stern.qcmdpcPubFromPriv(kp.h0, kp.h1));
            boolean anyMismatch = false;
            int trials = 20;
            for (int i = 0; i < trials; i++) {
                Stern.QcMdpcEncapResult enc = Stern.qcmdpcEncap(kp.hPub, rng);
                BigInteger recovered = Stern.qcmdpcDecapBgf(enc.syn, kp.sup0, kp.sup1);
                // Under implicit rejection (TODO #235) decapsulation always
                // returns a key, so a DFR event is a mismatch rather than a
                // null — still a legitimate outcome (~0.225% measured, TODO
                // #195), so only flag it if every one of a small batch misses.
                if (recovered.equals(enc.k)) { anyMismatch = false; break; }
                anyMismatch = true;
            }
            if (!pubMatches || anyMismatch) {
                System.out.println("FAIL [14] hpke_stern_kem round-trip (pub_matches=" + pubMatches
                    + " all_" + trials + "_trials_failed=" + anyMismatch + ")");
                fails++;
            } else {
                System.out.println("PASS [14] hpke_stern_kem round-trip");
            }
        }

        // OPRF: blind/eval/unblind must equal the direct (non-oblivious) evaluation.
        {
            BigInteger k = Oprf.keygen(rng);
            byte[] x = "self-test oprf input".getBytes(java.nio.charset.StandardCharsets.US_ASCII);
            Oprf.Blinded blinded = Oprf.blind(x, rng);
            BigInteger beta = Oprf.eval(blinded.alpha, k);
            BigInteger f1 = Oprf.unblind(beta, blinded.r);
            BigInteger f2 = Oprf.direct(x, k);
            if (!f1.equals(f2)) {
                System.out.println("FAIL [15] oprf round-trip: blind/eval/unblind != direct");
                fails++;
            } else {
                System.out.println("PASS [15] oprf round-trip");
            }
        }

        // HPKS-WOTS-F: sign/verify plus a tampered-message rejection check.
        {
            byte[] seed = new byte[32];
            rng.nextBytes(seed);
            Wots.Keypair kp = Wots.keygen(seed, 0);
            byte[] msg = "self-test wots message".getBytes(java.nio.charset.StandardCharsets.US_ASCII);
            Wots.Signature sig = Wots.sign(msg, seed, 0);
            boolean ok = Wots.verify(msg, sig.sig, kp.pk);
            boolean rejectsTamper = !Wots.verify("tampered".getBytes(java.nio.charset.StandardCharsets.US_ASCII), sig.sig, kp.pk);
            if (!ok || !rejectsTamper) {
                System.out.println("FAIL [16] hpks_wots_f round-trip (verify=" + ok + " rejects_tamper=" + rejectsTamper + ")");
                fails++;
            } else {
                System.out.println("PASS [16] hpks_wots_f round-trip");
            }
        }

        // HPKS-XMSS-F: two distinct leaves both sign/verify against the same
        // root, plus tampered-message rejection (small h for speed).
        {
            byte[] seed = new byte[32];
            rng.nextBytes(seed);
            Xmss.Keypair kp = Xmss.keygen(seed, 3);
            byte[] msg = "self-test xmss message".getBytes(java.nio.charset.StandardCharsets.US_ASCII);
            Xmss.Signature sig0 = Xmss.sign(msg, seed, kp.leafHashes, 0);
            Xmss.Signature sig1 = Xmss.sign(msg, seed, kp.leafHashes, 1);
            boolean ok = Xmss.verify(msg, sig0, kp.root) && Xmss.verify(msg, sig1, kp.root);
            boolean rejectsTamper = !Xmss.verify("tampered".getBytes(java.nio.charset.StandardCharsets.US_ASCII), sig0, kp.root);
            if (!ok || !rejectsTamper) {
                System.out.println("FAIL [17] hpks_xmss_f round-trip (verify=" + ok + " rejects_tamper=" + rejectsTamper + ")");
                fails++;
            } else {
                System.out.println("PASS [17] hpks_xmss_f round-trip");
            }
        }

        // HCRED: prove/verify completeness, plus replay/tamper/wrong-key/
        // split-witness rejection and an issuer credential round-trip.
        // Uses the library's own demo round count (4) to keep the smoke
        // test fast; CliTest/test_java_hcred_interop.sh exercises more
        // rounds via the CLI.
        {
            int rounds = Hcred.DEMO_ROUNDS;
            int[] mBase = HerraduraNl.rnlMPoly(Herradura.N);
            int[] aRand = HerraduraNl.rnlRandPoly(Herradura.N, HerraduraNl.RNLQ, rng);
            int[] mBlind = HerraduraNl.rnlPolyAdd(mBase, aRand, HerraduraNl.RNLQ);
            Hcred.UserKeypair kp = Hcred.userKeygen(mBlind, rng);
            BigInteger seedH = new BigInteger(Herradura.N, rng).and(Herradura.MASK);
            BigInteger y = Hcred.syndrome(seedH, kp.e);
            byte[] msg = "self-test hcred presentation".getBytes(java.nio.charset.StandardCharsets.US_ASCII);
            byte[] tamperMsg = "tampered".getBytes(java.nio.charset.StandardCharsets.US_ASCII);

            boolean ok, rejectsTamper, rejectsCorruptSyn, rejectsWrongKey, rejectsSplitWitness, credOk;
            try {
                Hcred.Proof proof = Hcred.prove(kp.s, mBlind, kp.c, seedH, y, rounds, msg, rng);
                ok = Hcred.verify(mBlind, kp.c, seedH, y, proof, rounds, msg);
                rejectsTamper = !Hcred.verify(mBlind, kp.c, seedH, y, proof, rounds, tamperMsg);
                rejectsCorruptSyn = !Hcred.verify(mBlind, kp.c, seedH, y.xor(BigInteger.ONE), proof, rounds, msg);

                Hcred.UserKeypair kp2 = Hcred.userKeygen(mBlind, rng);
                rejectsWrongKey = !Hcred.verify(mBlind, kp2.c, seedH, y, proof, rounds, msg);

                boolean splitCaught;
                try {
                    Hcred.prove(kp2.s, mBlind, kp2.c, seedH, y, rounds, msg, rng);
                    splitCaught = false;
                } catch (IllegalArgumentException e) {
                    splitCaught = true;
                }
                rejectsSplitWitness = splitCaught;

                Stern.SternKeypair isk = Stern.sternFKeygen(rng);
                Stern.SternSignature credSig = Hcred.issue(mBlind, kp.c, seedH, y, Herradura.N, isk.e, isk.seed, 8, rng);
                credOk = Hcred.credVerify(mBlind, kp.c, seedH, y, Herradura.N, credSig, isk.seed, isk.syndrome);
            } catch (IllegalArgumentException e) {
                ok = rejectsTamper = rejectsCorruptSyn = rejectsWrongKey = rejectsSplitWitness = credOk = false;
            }
            if (!ok || !rejectsTamper || !rejectsCorruptSyn || !rejectsWrongKey || !rejectsSplitWitness || !credOk) {
                System.out.println("FAIL [18] hcred round-trip (verify=" + ok + " rejects_tamper=" + rejectsTamper
                    + " rejects_corrupt_syn=" + rejectsCorruptSyn + " rejects_wrong_key=" + rejectsWrongKey
                    + " rejects_split_witness=" + rejectsSplitWitness + " cred_verify=" + credOk + ")");
                fails++;
            } else {
                System.out.println("PASS [18] hcred round-trip");
            }
        }

        // ZKP-NL (the ZKBoo circuit underlying aPAKE's mutual-auth proof):
        // prove/verify, plus tampered-message and wrong-y rejection.
        {
            int n = 32, rounds = 16;
            BigInteger mask = BigInteger.ONE.shiftLeft(n).subtract(BigInteger.ONE);
            BigInteger a = new BigInteger(n, rng).and(mask);
            BigInteger b = new BigInteger(n, rng).and(mask);
            BigInteger y = ZkpNl.nlFscxV1General(a, b, n);
            byte[] msg = "self-test zkp-nl".getBytes(java.nio.charset.StandardCharsets.US_ASCII);
            java.util.List<ZkpNl.ProofRound> proof = ZkpNl.prove(a, b, y, n, rounds, msg, rng);
            boolean ok = ZkpNl.verify(b, y, n, rounds, msg, proof);
            boolean rejectsTamper = !ZkpNl.verify(b, y, n, rounds,
                "tampered".getBytes(java.nio.charset.StandardCharsets.US_ASCII), proof);
            boolean rejectsWrongY = !ZkpNl.verify(b, y.xor(BigInteger.ONE), n, rounds, msg, proof);
            if (!ok || !rejectsTamper || !rejectsWrongY) {
                System.out.println("FAIL [19] zkp_nl round-trip (verify=" + ok + " rejects_tamper=" + rejectsTamper
                    + " rejects_wrong_y=" + rejectsWrongY + ")");
                fails++;
            } else {
                System.out.println("PASS [19] zkp_nl round-trip");
            }
        }

        // aPAKE: register + login with the correct password succeeds and
        // derives a session key; login with the wrong password fails.
        {
            BigInteger oprfKey = Oprf.keygen(rng);
            byte[] password = "self-test pake password".getBytes(java.nio.charset.StandardCharsets.US_ASCII);
            Hpake.Record record = Hpake.register("self-test-user", password, oprfKey, rng);
            byte[] sk = Hpake.loginDemo(record, password, oprfKey, rng);
            byte[] wrongSk = Hpake.loginDemo(record,
                "wrong password".getBytes(java.nio.charset.StandardCharsets.US_ASCII), oprfKey, rng);
            if (sk == null || wrongSk != null) {
                System.out.println("FAIL [20] hpake round-trip (correct_login=" + (sk != null)
                    + " wrong_login_rejected=" + (wrongSk == null) + ")");
                fails++;
            } else {
                System.out.println("PASS [20] hpake round-trip");
            }
        }

        // Ratchet (78.C): forward secrecy & message-key uniqueness across
        // steps, and state divergence between two independently-seeded chains.
        {
            BigInteger state = Ratchet.init("self-test-ratchet-seed".getBytes(java.nio.charset.StandardCharsets.US_ASCII));
            java.util.Set<String> msgKeys = new java.util.HashSet<>();
            for (int i = 0; i < 5; i++) {
                Object[] r = Ratchet.advance(state);
                state = (BigInteger) r[0];
                byte[] mk = (byte[]) r[1];
                msgKeys.add(new BigInteger(1, mk).toString(16));
            }
            boolean allDistinct = msgKeys.size() == 5;

            BigInteger s1 = Ratchet.init("seed-alice".getBytes(java.nio.charset.StandardCharsets.US_ASCII));
            BigInteger s2 = Ratchet.init("seed-bob".getBytes(java.nio.charset.StandardCharsets.US_ASCII));
            for (int i = 0; i < 3; i++) {
                s1 = (BigInteger) Ratchet.advance(s1)[0];
                s2 = (BigInteger) Ratchet.advance(s2)[0];
            }
            boolean chainsDiverge = !s1.equals(s2);

            if (!allDistinct || !chainsDiverge) {
                System.out.println("FAIL [21] ratchet round-trip (all_distinct=" + allDistinct
                    + " chains_diverge=" + chainsDiverge + ")");
                fails++;
            } else {
                System.out.println("PASS [21] ratchet round-trip");
            }
        }

        // HDRBG (#96): cross-language KAT, determinism from a fixed seed,
        // personalization/reseed separation, the block-limit guard, and a
        // monobit sanity check -- matching C/Go/Python test [29]'s
        // granularity exactly (TODO #260 step 2).
        {
            byte[] katEntropy = new byte[32];
            for (int i = 0; i < 32; i++) katEntropy[i] = (byte) i;
            Hdrbg dk = Hdrbg.seed(katEntropy, "HDRBG-KAT".getBytes(java.nio.charset.StandardCharsets.US_ASCII));
            String kat1 = toHex(dk.generate(80));
            byte[] resEntropy = new byte[16];
            java.util.Arrays.fill(resEntropy, (byte) 0xa5);
            dk.reseed(resEntropy);
            String kat2 = toHex(dk.generate(32));
            boolean katOk = kat1.equals("cd3e576bee89501a3760fb96fc05b6a3029c26f405e8667c71f311fc39ab1b23"
                    + "90620f2641a2a2dabf28cf35ae991d6b9fc254509a7720de24cbd9c603cd718e"
                    + "089ea95dc62208133b3475fadb10ef6d")
                && kat2.equals("bd5324b039a98172fae214390fe9bcc928f3bd65231213efd9162664b5e756bf");

            byte[] entropy = "self-test-hdrbg-entropy-01234567".getBytes(java.nio.charset.StandardCharsets.US_ASCII);
            Hdrbg d1 = Hdrbg.seed(entropy, "pers".getBytes(java.nio.charset.StandardCharsets.US_ASCII));
            Hdrbg d2 = Hdrbg.seed(entropy, "pers".getBytes(java.nio.charset.StandardCharsets.US_ASCII));
            Hdrbg d2b = Hdrbg.seed(entropy, "different-pers".getBytes(java.nio.charset.StandardCharsets.US_ASCII));
            byte[] out1 = d1.generate(96);
            byte[] out2 = d2.generate(96);
            byte[] out2b = d2b.generate(96);
            boolean deterministic = java.util.Arrays.equals(out1, out2);
            boolean persSeparates = !java.util.Arrays.equals(out1, out2b);

            Hdrbg d3 = Hdrbg.seed(entropy, "pers".getBytes(java.nio.charset.StandardCharsets.US_ASCII));
            byte[] pre = d3.generate(32);
            d3.reseed("fresh-entropy".getBytes(java.nio.charset.StandardCharsets.US_ASCII));
            byte[] post = d3.generate(32);
            boolean reseedSeparates = !java.util.Arrays.equals(pre, post) && d3.blocksGenerated() == 1;

            boolean limitEnforced;
            try {
                Hdrbg d4 = Hdrbg.seed(entropy);
                java.lang.reflect.Field blocksField = Hdrbg.class.getDeclaredField("blocks");
                blocksField.setAccessible(true);
                blocksField.setLong(d4, Hdrbg.DRBG_MAX_BLOCKS);
                d4.generate(32);
                limitEnforced = false;
            } catch (IllegalStateException expected) {
                limitEnforced = true;
            } catch (ReflectiveOperationException e) {
                limitEnforced = false;
            }

            Hdrbg d5 = Hdrbg.seed("ent-monobit".getBytes(java.nio.charset.StandardCharsets.US_ASCII));
            byte[] stream = d5.generate(8192);
            int ones = 0;
            for (byte b : stream) ones += Integer.bitCount(b & 0xFF);
            double frac = ones / (8192.0 * 8);
            boolean monoOk = frac >= 0.48 && frac <= 0.52;

            if (!katOk || !deterministic || !persSeparates || !reseedSeparates || !limitEnforced || !monoOk) {
                System.out.println("FAIL [22] hdrbg round-trip (kat=" + katOk + " deterministic=" + deterministic
                    + " pers_separates=" + persSeparates + " reseed_separates=" + reseedSeparates
                    + " limit_enforced=" + limitEnforced + " monobit=" + monoOk + ")");
                fails++;
            } else {
                System.out.println("PASS [22] hdrbg round-trip");
            }
        }

        // HPKS-T (#98): n-of-n threshold/aggregate Schnorr — 3 signers must
        // jointly produce a signature that verifies against the aggregate
        // public key, and a tampered response scalar must be rejected.
        {
            int n = 3;
            java.util.List<BigInteger> secrets = new java.util.ArrayList<>();
            java.util.List<BigInteger> pubkeys = new java.util.ArrayList<>();
            for (int i = 0; i < n; i++) {
                BigInteger sk = new BigInteger(Herradura.N, rng).and(Herradura.MASK);
                secrets.add(sk);
                pubkeys.add(Herradura.gfPow(Herradura.GF_GEN, sk));
            }
            BigInteger msg = new BigInteger(Herradura.N, rng).and(Herradura.MASK);
            HpksT.Signature sig = HpksT.sign(secrets, pubkeys, msg, rng);
            boolean ok = HpksT.verify(sig.cAgg, sig.r, sig.s, msg);
            boolean rejectsTamper = !HpksT.verify(sig.cAgg, sig.r, sig.s.xor(BigInteger.ONE), msg);
            if (!ok || !rejectsTamper) {
                System.out.println("FAIL [23] hpks_t round-trip (verify=" + ok + " rejects_tamper=" + rejectsTamper + ")");
                fails++;
            } else {
                System.out.println("PASS [23] hpks_t round-trip");
            }
        }

        // FPE (78.A) / twk (78.B), v2 and v3: round-trip, and TODO #241/#242's
        // regression guard -- a 12-byte fpe ctx equal to twk's
        // sector_be64||bidx_be32 must NOT produce the same subkey/ciphertext
        // (the bug that made the two subcommands the same function pre-v4.0.0).
        {
            byte[] key = "self-test-fpe-twk-key-material!!".getBytes(java.nio.charset.StandardCharsets.US_ASCII);
            byte[] ctx = "self-test12b".getBytes(java.nio.charset.StandardCharsets.US_ASCII);
            BigInteger pt = new BigInteger(Herradura.N, rng).and(Herradura.MASK);

            BigInteger fpeCt = FpeTwk.fpeEncrypt(pt, key, ctx);
            boolean fpeRt = FpeTwk.fpeDecrypt(fpeCt, key, ctx).equals(pt);

            long sector = 0x0102030405060708L;
            int bidx = 0x090A0B0C;
            BigInteger twkCt = FpeTwk.twkEncrypt(pt, key, sector, bidx);
            boolean twkRt = FpeTwk.twkDecrypt(twkCt, key, sector, bidx).equals(pt);

            BigInteger fpeCtV3 = FpeTwk.fpeV3Encrypt(pt, key, ctx);
            boolean fpeV3Rt = FpeTwk.fpeV3Decrypt(fpeCtV3, key, ctx).equals(pt);
            BigInteger twkCtV3 = FpeTwk.twkV3Encrypt(pt, key, sector, bidx);
            boolean twkV3Rt = FpeTwk.twkV3Decrypt(twkCtV3, key, sector, bidx).equals(pt);

            java.nio.ByteBuffer tweakBuf = java.nio.ByteBuffer.allocate(12);
            tweakBuf.putLong(sector).putInt(bidx);
            BigInteger fpeCtWithTwkTweakAsCtx = FpeTwk.fpeEncrypt(pt, key, tweakBuf.array());
            boolean domainSeparated = !fpeCtWithTwkTweakAsCtx.equals(twkCt);
            boolean v2v3Separated = !fpeCt.equals(fpeCtV3) && !twkCt.equals(twkCtV3);

            // C/Go/Python test [46]'s key||tweak boundary-encoding guard: the
            // derivation must length-prefix the key, or (key[:2], ctx=key[2:3])
            // and (key[:1], ctx=key[1:3]) collide -- same raw concatenated
            // bytes, different (key, ctx) split.
            byte[] keyAB = java.util.Arrays.copyOfRange(key, 0, 2);
            byte[] ctxC = java.util.Arrays.copyOfRange(key, 2, 3);
            byte[] keyA = java.util.Arrays.copyOfRange(key, 0, 1);
            byte[] ctxBC = java.util.Arrays.copyOfRange(key, 1, 3);
            BigInteger split1 = FpeTwk.fpeEncrypt(pt, keyAB, ctxC);
            BigInteger split2 = FpeTwk.fpeEncrypt(pt, keyA, ctxBC);
            boolean keyBoundarySeparated = !split1.equals(split2);

            if (!fpeRt || !twkRt || !fpeV3Rt || !twkV3Rt || !domainSeparated || !v2v3Separated || !keyBoundarySeparated) {
                System.out.println("FAIL [24] fpe_twk round-trip (fpe=" + fpeRt + " twk=" + twkRt
                    + " fpe_v3=" + fpeV3Rt + " twk_v3=" + twkV3Rt + " domain_separated=" + domainSeparated
                    + " v2v3_separated=" + v2v3Separated + " key_boundary_separated=" + keyBoundarySeparated + ")");
                fails++;
            } else {
                System.out.println("PASS [24] fpe_twk round-trip");
            }
        }

        // HSKE-NL-V2-Duplex / V3-Duplex (#95 Option 2 / TODO #255, RESEARCH
        // CONSTRUCTION): round-trip, tampered-ciphertext rejection, and
        // tampered-AD rejection, for both permutation versions.
        {
            BigInteger key = new BigInteger(Herradura.N, rng).and(Herradura.MASK);
            byte[] pt = "self-test duplex plaintext, several blocks long".getBytes(java.nio.charset.StandardCharsets.US_ASCII);
            byte[] ad = "self-test-duplex-ad".getBytes(java.nio.charset.StandardCharsets.US_ASCII);

            Duplex.EncResult r2 = Duplex.v2Encrypt(key, pt, ad, rng);
            byte[] dec2 = Duplex.v2Decrypt(key, r2.nonce, r2.ct, r2.tag, ad);
            byte[] ct2Tampered = r2.ct.clone();
            ct2Tampered[0] ^= 1;
            boolean v2RejectsCt = Duplex.v2Decrypt(key, r2.nonce, ct2Tampered, r2.tag, ad) == null;
            boolean v2RejectsAd = Duplex.v2Decrypt(key, r2.nonce, r2.ct, r2.tag,
                "self-test-duplex-ad-2".getBytes(java.nio.charset.StandardCharsets.US_ASCII)) == null;
            boolean v2Ok = java.util.Arrays.equals(dec2, pt);

            Duplex.EncResult r3 = Duplex.v3Encrypt(key, pt, ad, rng);
            byte[] dec3 = Duplex.v3Decrypt(key, r3.nonce, r3.ct, r3.tag, ad);
            byte[] ct3Tampered = r3.ct.clone();
            ct3Tampered[0] ^= 1;
            boolean v3RejectsCt = Duplex.v3Decrypt(key, r3.nonce, ct3Tampered, r3.tag, ad) == null;
            boolean v3RejectsAd = Duplex.v3Decrypt(key, r3.nonce, r3.ct, r3.tag,
                "self-test-duplex-ad-2".getBytes(java.nio.charset.StandardCharsets.US_ASCII)) == null;
            boolean v3Ok = java.util.Arrays.equals(dec3, pt);

            if (!v2Ok || !v2RejectsCt || !v2RejectsAd || !v3Ok || !v3RejectsCt || !v3RejectsAd) {
                System.out.println("FAIL [25] duplex round-trip (v2_ok=" + v2Ok + " v2_rejects_ct=" + v2RejectsCt
                    + " v2_rejects_ad=" + v2RejectsAd + " v3_ok=" + v3Ok + " v3_rejects_ct=" + v3RejectsCt
                    + " v3_rejects_ad=" + v3RejectsAd + ")");
                fails++;
            } else {
                System.out.println("PASS [25] duplex round-trip");
            }
        }

        // HPKS-Stern-Ring (78.I): OR-composed Stern ring signature -- any one
        // of a 4-member ring signs, verify succeeds without revealing which
        // member, a tampered message is rejected, and a signature "signed" with
        // a secret matching no ring member's syndrome is rejected too.
        {
            int k = 4;
            // 8 rounds gives only (2/3)^8 ~= 3.9% soundness error -- enough
            // to make rejects_forgery flake in CI (TODO #260 caught this
            // the same way CLAUDE.md's Testing section describes for [45]:
            // a probabilistic property was asserted as if deterministic).
            // 32 rounds matches this suite's other Stern-F self-test round
            // counts and drops the error to ~2e-6, negligible for CI.
            int demoRounds = 32;
            java.util.List<Stern.SternKeypair> keys = new java.util.ArrayList<>();
            java.util.List<SternRing.RingKey> ringPub = new java.util.ArrayList<>();
            for (int i = 0; i < k; i++) {
                Stern.SternKeypair kp = Stern.sternFKeygen(rng);
                keys.add(kp);
                ringPub.add(new SternRing.RingKey(kp.seed, kp.syndrome));
            }
            int j = 2;
            BigInteger msg = new BigInteger(Herradura.N, rng).and(Herradura.MASK);
            SternRing.RingSignature sig = SternRing.sign(msg, keys.get(j).e, j, ringPub, demoRounds, rng);
            boolean ok = SternRing.verify(msg, sig, ringPub);
            boolean rejectsTamper = !SternRing.verify(msg.xor(BigInteger.ONE), sig, ringPub);
            BigInteger badE = new BigInteger(Herradura.N, rng).and(Herradura.MASK);
            SternRing.RingSignature forged = SternRing.sign(msg, badE, 0, ringPub, demoRounds, rng);
            boolean rejectsForgery = !SternRing.verify(msg, forged, ringPub);
            if (!ok || !rejectsTamper || !rejectsForgery) {
                System.out.println("FAIL [26] hpks_stern_ring round-trip (verify=" + ok
                    + " rejects_tamper=" + rejectsTamper + " rejects_forgery=" + rejectsForgery + ")");
                fails++;
            } else {
                System.out.println("PASS [26] hpks_stern_ring round-trip");
            }
        }

        // [27] HKEX-RNL peer-m_blind substitution guard (TODO #261).
        // m_blind is chosen by the INITIATOR and its uniformity rests entirely
        // on that party's RNG (TODO #89), so the responder cannot verify the
        // draw -- only reject the degenerate shapes that break the construction
        // outright: a sparse m_blind makes C = round_p(m_blind*s) leak s almost
        // directly, and a clustered one collapses the rounding noise the
        // hardness argument depends on.  Shipped here, in C and in Go, and
        // untested in all four languages until TODO #261.
        // (a) is the accept-control: without it, a guard that rejected
        // everything would score a perfect pass on (b)-(e).
        {
            final int n = 256, q = HerraduraNl.RNLQ;
            int badAccept = 0, badReject = 0;

            // (a) accept-control: a genuine uniform draw must pass.
            int[] uniform = new int[n];
            for (int i = 0; i < n; i++) uniform[i] = rng.nextInt(q);
            if (!HerraduraNl.rnlValidateMBlind(uniform, q)) badReject++;

            // (b) the all-zero polynomial.
            if (HerraduraNl.rnlValidateMBlind(new int[n], q)) badAccept++;

            // (c) sparse: n/8 non-zero at full range -- isolates the count bound.
            int[] sparse = new int[n];
            for (int i = 0; i < n / 8; i++) sparse[i] = q - 1;
            if (HerraduraNl.rnlValidateMBlind(sparse, q)) badAccept++;

            // (d) clustered: all non-zero inside [1, q/8) -- isolates the range bound.
            int[] clustered = new int[n];
            for (int i = 0; i < n; i++) clustered[i] = 1 + rng.nextInt(q / 8 - 1);
            if (HerraduraNl.rnlValidateMBlind(clustered, q)) badAccept++;

            // (e) the count boundary, both sides.  Range is full in both, so
            //     only the non-zero count decides.
            int[] nzCounts = { n / 4, n / 4 - 1 };
            boolean[] want = { true, false };
            for (int k = 0; k < 2; k++) {
                int[] poly = new int[n];
                for (int i = 0; i < nzCounts[k]; i++) poly[i] = q - 1;
                boolean got = HerraduraNl.rnlValidateMBlind(poly, q);
                if (got != want[k]) { if (got) badAccept++; else badReject++; }
            }

            if (badAccept != 0 || badReject != 0) {
                System.out.println("FAIL [27] rnl_m_blind_guard (bad_accepts=" + badAccept
                    + " bad_rejects=" + badReject + ")");
                fails++;
            } else {
                System.out.println("PASS [27] rnl_m_blind_guard");
            }
        }

        // [28]/[29] ZKP-NL: the ZKBoo and ZKB++ proof systems (TODO #261).
        // Both were CLI-unreachable from Java until v6.0.0 -- ZKB++ was not
        // ported at all, and ZkpNl.java's class doc comment declared it out of
        // scope.  Each check is prove -> verify plus TWO rejection axes, because
        // a verifier that returns true unconditionally passes a round-trip.
        {
            int n = 8, rounds = 16;
            BigInteger[] kp = ZkpNl.keygen(n, rng);
            byte[] msg = new byte[32];
            rng.nextBytes(msg);
            byte[] other = msg.clone();
            other[0] ^= 0x01;

            java.util.List<ZkpNl.ProofRound> booPr =
                ZkpNl.prove(kp[0], kp[1], kp[2], n, rounds, msg, rng);
            boolean booOk = ZkpNl.verify(kp[1], kp[2], n, rounds, msg, booPr);
            boolean booMsg = !ZkpNl.verify(kp[1], kp[2], n, rounds, other, booPr);
            // A different statement (y+1) must not verify against this proof.
            boolean booStmt = !ZkpNl.verify(kp[1], kp[2].add(BigInteger.ONE), n,
                                            rounds, msg, booPr);
            if (!booOk || !booMsg || !booStmt) {
                System.out.println("FAIL [28] zkp_nl_zkboo prove/verify (verify=" + booOk
                    + " rejects_msg=" + booMsg + " rejects_stmt=" + booStmt + ")");
                fails++;
            } else {
                System.out.println("PASS [28] zkp_nl_zkboo prove/verify");
            }

            java.util.List<ZkpNl.PpRound> ppPr =
                ZkpNl.provePp(kp[0], kp[1], kp[2], n, rounds, msg, rng);
            boolean ppOk = ZkpNl.verifyPp(kp[1], kp[2], n, rounds, msg, ppPr);
            boolean ppMsg = !ZkpNl.verifyPp(kp[1], kp[2], n, rounds, other, ppPr);
            boolean ppStmt = !ZkpNl.verifyPp(kp[1], kp[2].add(BigInteger.ONE), n,
                                             rounds, msg, ppPr);
            // ZKB++ is the smaller transcript, and must actually be smaller:
            // two 16-byte seeds instead of two full views is the whole point.
            boolean ppSmaller = ppPr.get(0).seedP1.length == ZkpNl.ZKPP_SEED_BYTES;
            if (!ppOk || !ppMsg || !ppStmt || !ppSmaller) {
                System.out.println("FAIL [29] zkp_nl_zkbpp prove/verify (verify=" + ppOk
                    + " rejects_msg=" + ppMsg + " rejects_stmt=" + ppStmt
                    + " seed_len_ok=" + ppSmaller + ")");
                fails++;
            } else {
                System.out.println("PASS [29] zkp_nl_zkbpp prove/verify");
            }
        }

        // [30] ZKP-RNL Sigma-protocol (rnl-sigma), TODO #261.  No Java port at
        // any layer before v6.0.0.  Rejection sampling can legitimately fail,
        // so a null proof is reported rather than counted as a verify failure.
        {
            int n = 256;
            int[] mBase = HerraduraNl.rnlMPoly(n);
            int[] aRand = HerraduraNl.rnlRandPoly(n, HerraduraNl.RNLQ, rng);
            int[] m = HerraduraNl.rnlPolyAdd(mBase, aRand, HerraduraNl.RNLQ);
            HerraduraNl.RnlKeypair kp = HerraduraNl.rnlKeygen(
                m, n, HerraduraNl.RNLQ, HerraduraNl.RNLP, rng);
            byte[] msg = new byte[32];
            rng.nextBytes(msg);
            byte[] other = msg.clone();
            other[0] ^= 0x01;

            HerraduraNl.SigmaProof pr =
                HerraduraNl.rnlSigmaSign(kp.s, m, kp.c, n, msg, rng);
            if (pr == null) {
                System.out.println("FAIL [30] rnl_sigma sign/verify (rejection limit reached)");
                fails++;
            } else {
                boolean ok = HerraduraNl.rnlSigmaVerify(m, kp.c, n, msg, pr.w, pr.c, pr.z);
                boolean rejMsg = !HerraduraNl.rnlSigmaVerify(m, kp.c, n, other, pr.w, pr.c, pr.z);
                // A flipped response coefficient must break the rounding-slack
                // check, not merely the Fiat-Shamir replay.
                int[] zBad = pr.z.clone();
                zBad[0] += 1;
                boolean rejZ = !HerraduraNl.rnlSigmaVerify(m, kp.c, n, msg, pr.w, pr.c, zBad);
                if (!ok || !rejMsg || !rejZ) {
                    System.out.println("FAIL [30] rnl_sigma sign/verify (verify=" + ok
                        + " rejects_msg=" + rejMsg + " rejects_z=" + rejZ + ")");
                    fails++;
                } else {
                    System.out.println("PASS [30] rnl_sigma sign/verify");
                }
            }
        }

        // [31] HCRED-KKW prove/verify + rejection axes (TODO #266).
        //
        // KKW shipped in all four languages under TODO #261 verified only
        // STRUCTURALLY -- round-trips plus rejection checks written by hand
        // during each port and then thrown away.  Three of the four ports
        // carried a real transcription bug found that way (Go's inverted
        // aux-reveal condition; C's under-allocated commitment buffer and
        // flipped bit convention), and none of those checks survived as a
        // regression guard.  KAT/hcred_kkw.json now pins the VERIFY side
        // across all four languages (KatVerify consumes it here); this is the
        // PROVE side, which a consume-only vector cannot reach.
        //
        // (a) is the accept-control: without it a verifier that refused
        // everything would score a perfect 6/6 on the rejection axes.
        //
        // Note the shape difference from C/Go/Python: this port's proof fields
        // are final, so a tamper cannot be poked into a finished object -- each
        // axis rebuilds the proof with one value changed, which is closer to
        // what verification actually defends against anyway.
        {
            final int nPar = 4, mEmul = 4, tau = 2;
            int[] mBase = HerraduraNl.rnlMPoly(Herradura.N);
            int[] aRand = HerraduraNl.rnlRandPoly(Herradura.N, HerraduraNl.RNLQ, rng);
            int[] mBlind = HerraduraNl.rnlPolyAdd(mBase, aRand, HerraduraNl.RNLQ);
            Hcred.UserKeypair kp = Hcred.userKeygen(mBlind, rng);
            BigInteger seedH = new BigInteger(Herradura.N, rng).and(Herradura.MASK);
            BigInteger y = Hcred.syndrome(seedH, kp.e);
            byte[] msg = "HCRED-KKW test [31]".getBytes(java.nio.charset.StandardCharsets.US_ASCII);
            byte[] msg2 = "HCRED-KKW test [31]!".getBytes(java.nio.charset.StandardCharsets.US_ASCII);
            try {
                Hcred.HcredKkwProof p = Hcred.proveKkw(kp.s, mBlind, kp.c, seedH, y,
                        nPar, mEmul, tau, msg, rng);
                boolean okVerify = Hcred.verifyKkw(mBlind, kp.c, seedH, y, p, msg);
                boolean rejMsg = !Hcred.verifyKkw(mBlind, kp.c, seedH, y, p, msg2);

                int e0 = java.util.Collections.min(p.online.keySet());
                int r0 = java.util.Collections.min(p.pre.keySet());
                Hcred.KkwOnlineProof o0 = p.online.get(e0);

                boolean rejW = !Hcred.verifyKkw(mBlind, kp.c, seedH, y,
                        rebuildKkw(p, p.W + 1, e0, o0.pbar, o0.u, o0.t, r0, false), msg);
                boolean rejU = !Hcred.verifyKkw(mBlind, kp.c, seedH, y,
                        rebuildKkw(p, p.W, e0, o0.pbar, (o0.u + 1) % HerraduraNl.RNLQ,
                                o0.t, r0, false), msg);
                int[] tBad = o0.t.clone();
                tBad[0] = (tBad[0] + 1) % HerraduraNl.RNLQ;
                boolean rejT = !Hcred.verifyKkw(mBlind, kp.c, seedH, y,
                        rebuildKkw(p, p.W, e0, o0.pbar, o0.u, tBad, r0, false), msg);
                boolean rejRoot = !Hcred.verifyKkw(mBlind, kp.c, seedH, y,
                        rebuildKkw(p, p.W, e0, o0.pbar, o0.u, o0.t, r0, true), msg);
                boolean rejPbar = !Hcred.verifyKkw(mBlind, kp.c, seedH, y,
                        rebuildKkw(p, p.W, e0, (o0.pbar + 1) % nPar, o0.u, o0.t, r0, false), msg);

                if (!okVerify || !rejMsg || !rejW || !rejU || !rejT || !rejRoot || !rejPbar) {
                    System.out.println("FAIL [31] hcred_kkw prove/verify (verify=" + okVerify
                            + " rejects_msg=" + rejMsg + " rejects_W=" + rejW
                            + " rejects_u=" + rejU + " rejects_t=" + rejT
                            + " rejects_pre_root=" + rejRoot + " rejects_pbar=" + rejPbar + ")");
                    fails++;
                } else {
                    System.out.println("PASS [31] hcred_kkw prove/verify");
                }
            } catch (RuntimeException e) {
                System.out.println("FAIL [31] hcred_kkw prove/verify (" + e + ")");
                fails++;
            }
        }

        // [32] The QC-MDPC weak-key screen (TODO #261).  Stern.qcmdpcKeyIsStrong
        // rejects and redraws any private polynomial whose cyclic distance
        // spectrum has a multiplicity above QCMDPC_MAX_MULT = 5 -- the screen
        // TODO #235 Part 1 added to make the entire measured DFR tail
        // unreachable from keygen.  Until TODO #261 it was UNTESTED IN ALL FOUR
        // LANGUAGES: it is called only from qcmdpcKeygen, so nothing here, in
        // CryptosuiteTests/ or in CliTest/ ever exercised it, and a screen that
        // accepted everything would have passed the entire repo -- the same
        // four-way absence #261 found for rnlValidateMBlind before it became
        // [27] here and [49] in C/Go/Python.
        //
        // SCOPE: the screen covers KEYGEN only.  No PEM decode path checks an
        // imported key's spectrum, in any language, and that is a recorded
        // position rather than an oversight -- a supplied arithmetic-progression
        // key fails its own decapsulations, a self-inflicted denial of service
        // and not a confidentiality break
        // (SecurityProofsCode/qcmdpc_dfr_weak_keys.py section 4).
        //
        // The supports are PINNED, not sampled, so each case asserts a known
        // answer rather than a probable one, and each is exactly QCMDPC_D = 15
        // elements because C's counterpart takes a fixed-width QcMdpcPriv.
        // The same five vectors are used by C/Go/Python's [51].
        {
            // RE-DERIVED at BIKE-128's r = 12323, d = 71 by TODO #276.  The previous
            // set was 15 elements over r = 523 with an accept-control on a bound of 5;
            // the names no longer carry the number (bound/over became bound/over) so the
            // next parameter move cannot leave them lying.  A run of L consecutive
            // positions gives cyclic distance 1 a multiplicity of L-1.
            // 0..70 -- distance 1 occurs 70 times: the arithmetic progression
            // the screen exists to reject.
            int[] ap1 = {
                0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29,
                30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43,
                44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57,
                58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70 };
            // the same multiplicity at a non-unit step, so a screen keyed on
            // consecutive integers rather than on the spectrum fails here.
            int[] ap35 = {
                0, 35, 70, 105, 140, 175, 210, 245, 280, 315, 350, 385,
                420, 455, 490, 525, 560, 595, 630, 665, 700, 735, 770,
                805, 840, 875, 910, 945, 980, 1015, 1050, 1085, 1120,
                1155, 1190, 1225, 1260, 1295, 1330, 1365, 1400, 1435,
                1470, 1505, 1540, 1575, 1610, 1645, 1680, 1715, 1750,
                1785, 1820, 1855, 1890, 1925, 1960, 1995, 2030, 2065,
                2100, 2135, 2170, 2205, 2240, 2275, 2310, 2345, 2380,
                2415, 2450 };
            // max multiplicity exactly QCMDPC_MAX_MULT -- ACCEPTED, the boundary
            // from below.  Its run is {0..6}.
            int[] bound = {
                0, 1, 2, 3, 4, 5, 6, 146, 158, 514, 534, 631, 652, 791,
                1387, 1404, 1645, 1931, 2060, 2180, 2352, 2468, 2549,
                2714, 2986, 3365, 3493, 3729, 3991, 4338, 4459, 4475,
                4850, 5182, 5188, 5197, 5233, 5652, 5779, 5952, 6182,
                6365, 6374, 6407, 6471, 6475, 6689, 7099, 7276, 7666,
                7759, 7844, 7980, 8674, 8770, 9162, 9385, 9781, 9835,
                10487, 10523, 10552, 10743, 10880, 10902, 11159, 11175,
                11292, 11309, 11518, 12108 };
            // the run is {0..7} instead: multiplicity QCMDPC_MAX_MULT + 1.
            // A minimal pair with bound -- one element carries it over the line.
            int[] over = {
                0, 1, 2, 3, 4, 5, 6, 7, 40, 565, 1173, 1208, 1337, 1537,
                1895, 2017, 2588, 2958, 2964, 3057, 3159, 3251, 3514,
                3562, 4086, 4143, 4705, 4727, 4989, 5010, 5023, 5088,
                5200, 5310, 6069, 6161, 6505, 6553, 6806, 7189, 7203,
                7393, 7464, 7609, 7936, 8006, 8022, 8109, 8278, 8325,
                8387, 8630, 8780, 8894, 9077, 9805, 10206, 10252, 10591,
                10597, 10717, 10983, 10988, 11178, 11225, 11417, 11692,
                11747, 12066, 12270, 12313 };
            // The cyclic-fold discriminator: its run straddles zero
            // (12318..12322, 0..2), so the true multiplicity is
            // QCMDPC_MAX_MULT + 1 and it must be rejected -- but computed WITHOUT
            // min(d, r-d) the run splits in two and the largest count is
            // QCMDPC_MAX_MULT, so it would be accepted.  An implementation that
            // dropped the fold passes every other case here and fails only this one.
            int[] wrap = {
                0, 1, 2, 170, 330, 362, 800, 910, 1035, 1379, 1404,
                1720, 1968, 2088, 2493, 2587, 2677, 3186, 3193, 3213,
                3578, 3656, 3720, 3907, 3979, 3986, 4033, 4047, 4363,
                4424, 4462, 4517, 4639, 5289, 5561, 5691, 5804, 5839,
                5857, 5978, 6267, 6608, 6821, 6834, 7023, 8356, 8358,
                8415, 8618, 8883, 8898, 8920, 8946, 9352, 9603, 9721,
                9727, 9739, 10135, 10467, 10629, 10880, 11490, 11834,
                11879, 12182, 12318, 12319, 12320, 12321, 12322 };

            int badAccept = 0, badReject = 0, wrapMissed = 0, keygenOk = 0;

            // (a) accept-control, and the boundary from below.  Without it a
            //     screen that rejects EVERYTHING scores a perfect pass below.
            if (!Stern.qcmdpcKeyIsStrong(bound, bound)) badReject++;
            // (b) the arithmetic progression.
            if (Stern.qcmdpcKeyIsStrong(ap1, bound)) badAccept++;
            // (c) the same multiplicity at a non-unit step.
            if (Stern.qcmdpcKeyIsStrong(ap35, bound)) badAccept++;
            // (d) the boundary from above.
            if (Stern.qcmdpcKeyIsStrong(over, bound)) badAccept++;
            // (e) BOTH supports must be screened: a predicate testing sup0
            //     twice passes (a)-(d) and fails exactly here.
            if (Stern.qcmdpcKeyIsStrong(bound, over)) badAccept++;
            // (f) the cyclic-distance discriminator, counted on its own so a
            //     failure names the cause rather than a total.
            if (Stern.qcmdpcKeyIsStrong(wrap, bound)) wrapMissed++;

            // What keygen PRODUCES must be what the screen ACCEPTS -- no pinned
            // vector can assert that.
            for (int i = 0; i < 4; i++) {
                Stern.QcMdpcKeypair kp = Stern.qcmdpcKeygen(new java.security.SecureRandom());
                if (Stern.qcmdpcKeyIsStrong(kp.sup0, kp.sup1)) keygenOk++;
            }

            if (badAccept != 0 || badReject != 0 || wrapMissed != 0 || keygenOk != 4) {
                System.out.println("FAIL [32] qcmdpc_weak_key_screen (bad_accepts=" + badAccept
                        + " bad_rejects=" + badReject + " cyclic_fold_misses=" + wrapMissed
                        + " keygen_accepted=" + keygenOk + "/4)");
                fails++;
            } else {
                System.out.println("PASS [32] qcmdpc_weak_key_screen");
            }
        }

        // [33] HSKE-NL-AEAD round-trip + the three tamper axes (TODO #273).
        //
        // This port had no AEAD primitive at all until #273, and `enc --aead`
        // wrote plain HSKE-NL-A1 with exit 0.  So the check that earns its keep
        // is not the round-trip: it is that a MODIFIED tag, ciphertext or ad is
        // refused, which an implementation that merely decrypts would fail.
        // Byte-compatibility with the other three is covered by
        // CliTest/test_aead.sh's 4x4 matrix, which a self-test cannot reach.
        {
            int okRt = 0, okTag = 0, okCt = 0, okAd = 0, trials = 8;
            for (int i = 0; i < trials; i++) {
                BigInteger key = new BigInteger(Herradura.N, rng).and(Herradura.MASK);
                BigInteger nonce = new BigInteger(Herradura.N, rng).and(Herradura.MASK);
                byte[] ad = ("ad-" + i).getBytes(java.nio.charset.StandardCharsets.UTF_8);
                byte[] pt = new byte[40 + i];   // spans two 32-byte keystream blocks
                rng.nextBytes(pt);

                HerraduraNl.AeadCt c = HerraduraNl.hskeNlAeadEncrypt(key, nonce, ad, pt);
                if (c.ct.length != pt.length) continue;    // ct must not be block-padded
                byte[] back = HerraduraNl.hskeNlAeadDecrypt(key, nonce, ad, c.ct, c.tag);
                if (back != null && java.util.Arrays.equals(back, pt)) okRt++;

                byte[] badTag = c.tag.clone(); badTag[i % badTag.length] ^= 1;
                if (HerraduraNl.hskeNlAeadDecrypt(key, nonce, ad, c.ct, badTag) == null) okTag++;

                byte[] badCt = c.ct.clone(); badCt[i % badCt.length] ^= 1;
                if (HerraduraNl.hskeNlAeadDecrypt(key, nonce, ad, badCt, c.tag) == null) okCt++;

                byte[] badAd = ("ad-" + i + "!").getBytes(java.nio.charset.StandardCharsets.UTF_8);
                if (HerraduraNl.hskeNlAeadDecrypt(key, nonce, badAd, c.ct, c.tag) == null) okAd++;
            }
            if (okRt != trials || okTag != trials || okCt != trials || okAd != trials) {
                System.out.println("FAIL [33] hske_nl_aead (roundtrip=" + okRt
                        + "/" + trials + " tag_reject=" + okTag + " ct_reject=" + okCt
                        + " ad_reject=" + okAd + ")");
                fails++;
            } else {
                System.out.println("PASS [33] hske_nl_aead");
            }
        }

        // [34] The QC-MDPC PRF's seed expansion (TODO #277).
        //
        // A four-way PINNED vector, and it exists because the four languages
        // did not agree.  C XORed the counter into the TOP four bytes of the
        // seed while Python, Go and Java XORed it into the LOW bits, so the
        // FIRST 256-bit block agreed -- ctr is 0 there -- and every block after
        // it did not.  Nothing caught a 3-1 split for the life of the protocol:
        // the seed is freshly random at every keygen, only the resulting key
        // travels on the wire, and no vector ever asked one language to
        // reproduce another's expansion of a given seed.  Hence a vector rather
        // than a round-trip.
        //
        // Case (b) is deliberately the SECOND support drawn from one PRF, not
        // the first: the first is one block and would have passed throughout.
        {
            int[] expA = {
                0, 176, 178, 662, 850, 1264, 1593, 1779, 1858, 2350,
                2469, 2600, 2987, 3186, 3212, 3398, 3666, 3910, 3915,
                4648, 4711, 5007, 5061, 5167, 5434, 5645, 6096, 6231,
                6246, 6461, 6492, 6521, 6844, 7123, 7332, 7347, 7360,
                7412, 7503, 7820, 7994, 8072, 8745, 8754, 8918, 9159,
                9297, 9422, 9539, 9546, 9671, 9849, 9887, 10014, 10123,
                10258, 10275, 10298, 10652, 10799, 10839, 10869, 11002,
                11086, 11239, 11289, 11290, 11870, 12072, 12192, 12256 };
            int[] expB = {
                139, 169, 503, 600, 719, 779, 1908, 1924, 2306, 2372,
                2400, 2419, 2495, 2528, 2590, 3089, 3455, 3788, 3833,
                4002, 4122, 4263, 4389, 4638, 4859, 4981, 5074, 5135,
                5495, 5697, 5761, 5995, 6211, 6373, 6413, 6473, 6482,
                6651, 6756, 7130, 7258, 7496, 7706, 7889, 8079, 8194,
                8228, 8269, 8573, 8853, 9275, 9726, 9767, 9827, 9903,
                10102, 10317, 10335, 10343, 10402, 10742, 10873, 11340,
                11557, 11601, 11728, 11801, 11960, 11981, 12062, 12236 };
            int[] expC = {
                0, 688, 1264, 1593, 1908, 2306, 2400, 2528, 2590, 2987,
                3099, 3186, 3455, 3531, 4263, 4353, 4648, 4711, 4859,
                5007, 5061, 5074, 5434, 5645, 5975, 6096, 6211, 6231,
                6235, 6242, 6335, 6373, 6473, 6651, 7332, 7496, 7820,
                7994, 8072, 8079, 8754, 8759, 8853, 8918, 9159, 9422,
                9539, 9726, 9827, 9887, 9903, 10014, 10102, 10275,
                10402, 10742, 11290, 11340, 11960, 12072, 12118, 12192,
                12422, 12462, 12492, 12501, 12826, 12923, 12985, 13042,
                13102, 13341, 13603, 14247, 14695, 14742, 14792, 14818,
                14827, 14923, 15198, 15412, 15535, 15702, 15989, 16111,
                16233, 16238, 16445, 16961, 17304, 17490, 17877, 18318,
                18569, 18736, 18784, 18815, 18844, 19079, 19446, 19453,
                19670, 19683, 19826, 20029, 20212, 20517, 20551, 20896,
                21068, 21415, 21598, 21994, 22090, 22172, 22580, 22581,
                22621, 22658, 22975, 23122, 23162, 23196, 23227, 23409,
                23562, 23612, 23880, 24124, 24145, 24193, 24304, 24385 };
            int[] expD = {15116, 23126, 24012, 26239, 42936, 55252, 63878, 76470, 76783, 79122};
            // the draw width is a function of the modulus, not a constant
            int[][] widths = {{523, 2}, {1046, 2}, {12323, 2}, {24646, 2},
                              {49318, 2}, {81946, 3}, {1 << 24, 3}, {(1 << 24) + 1, 4}};

            // The moduli and weights come from the deployed constants, never
            // from literals: they were written 523/15 and 1046/18 here, which
            // pinned the vector to parameters this test does not own and went
            // stale the moment TODO #276 moved them.  The widths table below
            // keeps its literals on purpose -- that one tests idxBytes as a
            // FUNCTION of the modulus, so its moduli are the input, not a
            // parameter.
            Stern.QcMdpcPrf prf = new Stern.QcMdpcPrf(BigInteger.ONE);
            int[] gotA = prf.sparseSupport(Stern.QCMDPC_R, Stern.QCMDPC_D);
            int[] gotB = prf.sparseSupport(Stern.QCMDPC_R, Stern.QCMDPC_D); // crosses into ctr=1
            int[] gotC = new Stern.QcMdpcPrf(BigInteger.ONE)
                             .sparseSupport(2 * Stern.QCMDPC_R, Stern.QCMDPC_T);
            // past the old 16-bit ceiling: terminates, and agrees with the
            // others.  The 16-bit-only sampler could not serve this modulus and
            // did not refuse either -- its acceptance limit was zero, so it
            // rejected every draw and spun forever.
            int[] gotD = new Stern.QcMdpcPrf(BigInteger.valueOf(7)).sparseSupport(81946, 10);
            for (int[] v : new int[][]{gotA, gotB, gotC, gotD}) java.util.Arrays.sort(v);

            int badW = 0;
            for (int[] w : widths) if (Stern.QcMdpcPrf.idxBytes(w[0]) != w[1]) badW++;
            boolean guarded = false;
            try {
                new Stern.QcMdpcPrf(BigInteger.ONE).uniformIdx(0);
            } catch (IllegalArgumentException e) {
                guarded = true;
            }

            boolean okA = java.util.Arrays.equals(gotA, expA);
            boolean okB = java.util.Arrays.equals(gotB, expB);
            boolean okC = java.util.Arrays.equals(gotC, expC);
            boolean okD = java.util.Arrays.equals(gotD, expD);
            if (!okA || !okB || !okC || !okD || badW != 0 || !guarded) {
                System.out.println("FAIL [34] qcprf_seed_expansion (first=" + okA
                        + " second=" + okB + " 2r=" + okC + " m81946=" + okD
                        + " widths=" + badW + " guard=" + guarded + ")");
                fails++;
            } else {
                System.out.println("PASS [34] qcprf_seed_expansion");
            }
        }

        if (fails > 0) {
            System.out.println(fails + " test(s) FAILED");
            System.exit(1);
        }
        System.out.println("All round-trip self-tests passed.");
    }

    /**
     * Rebuild a KKW proof with one field changed, for [31]'s rejection axes.
     * The proof types are immutable by design, so a tamper is a reconstruction
     * rather than a poke; `flipRoot` xors the low bit of pre root `r0`.
     */
    private static Hcred.HcredKkwProof rebuildKkw(Hcred.HcredKkwProof p, int W, int e0,
            int pbar, int u, int[] t, int r0, boolean flipRoot) {
        java.util.Map<Integer, byte[]> pre = new java.util.TreeMap<>();
        for (java.util.Map.Entry<Integer, byte[]> e : p.pre.entrySet()) {
            byte[] root = e.getValue().clone();
            if (flipRoot && e.getKey() == r0) root[0] ^= 1;
            pre.put(e.getKey(), root);
        }
        java.util.Map<Integer, Hcred.KkwOnlineProof> online = new java.util.TreeMap<>();
        for (java.util.Map.Entry<Integer, Hcred.KkwOnlineProof> e : p.online.entrySet()) {
            Hcred.KkwOnlineProof o = e.getValue();
            if (e.getKey() == e0) {
                online.put(e.getKey(), new Hcred.KkwOnlineProof(
                        o.path, o.comH, pbar, o.aux, o.zin, t, u));
            } else {
                online.put(e.getKey(), o);
            }
        }
        return new Hcred.HcredKkwProof(W, p.nPar, p.m, p.tau, pre, online);
    }
}
