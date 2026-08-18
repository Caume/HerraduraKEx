package herradurakex;

import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * TODO #192/#199/#200/#201: end-to-end round-trip smoke test for the
 * herradurakex Java package, with fresh random keys each run —
 * complements KatVerify's fixed-vector cross-check. Covers the classical
 * quartet ({@link Herradura}), the NL/PQC quartet ({@link HerraduraNl}),
 * HPKS-Stern-F/HPKE-Stern-F/HPKE-Stern-KEM ({@link Stern}), the OPRF
 * ({@link Oprf}), and HPKS-WOTS-F/HPKS-XMSS-F ({@link Wots}, {@link Xmss}).
 * Exits non-zero on any failure.
 *
 * Usage: java -cp bindings/java herradurakex.SelfTest
 */
public final class SelfTest {
    private SelfTest() { }

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
                System.out.println("FAIL hkex_gf round-trip: shared secrets differ");
                fails++;
            } else {
                System.out.println("PASS hkex_gf round-trip");
            }
        }

        // HSKE: decrypt(encrypt(pt)) == pt.
        {
            BigInteger key = new BigInteger(Herradura.N, rng).and(Herradura.MASK);
            BigInteger pt = new BigInteger(Herradura.N, rng).and(Herradura.MASK);
            BigInteger ct = Herradura.hskeEncrypt(pt, key);
            BigInteger recovered = Herradura.hskeDecrypt(ct, key);
            if (!recovered.equals(pt)) {
                System.out.println("FAIL hske round-trip");
                fails++;
            } else {
                System.out.println("PASS hske round-trip");
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
                System.out.println("FAIL hpks round-trip (verify=" + ok + " rejects_tamper=" + rejectsTamper + ")");
                fails++;
            } else {
                System.out.println("PASS hpks round-trip");
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
                System.out.println("FAIL hpke round-trip");
                fails++;
            } else {
                System.out.println("PASS hpke round-trip");
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
                System.out.println("FAIL hkex_rnl round-trip: reconciled keys differ");
                fails++;
            } else {
                System.out.println("PASS hkex_rnl round-trip");
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
                System.out.println("FAIL hske_nl_a1 round-trip");
                fails++;
            } else {
                System.out.println("PASS hske_nl_a1 round-trip");
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
                System.out.println("FAIL hske_nl_a2 round-trip");
                fails++;
            } else {
                System.out.println("PASS hske_nl_a2 round-trip");
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
                System.out.println("FAIL hpks_nl round-trip (verify=" + ok + " rejects_tamper=" + rejectsTamper + ")");
                fails++;
            } else {
                System.out.println("PASS hpks_nl round-trip");
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
                System.out.println("FAIL hpke_nl round-trip");
                fails++;
            } else {
                System.out.println("PASS hpke_nl round-trip");
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
                System.out.println("FAIL hpks_stern_f round-trip (verify=" + ok
                    + " rejects_tamper=" + rejectsTamper + " rejects_corrupt_syn=" + rejectsCorruptSyn + ")");
                fails++;
            } else {
                System.out.println("PASS hpks_stern_f round-trip");
            }
        }

        // HPKE-Stern-F (demo Niederreiter KEM): decap(encap()) derives the
        // same session key.
        {
            BigInteger seed = new BigInteger(Herradura.N, rng).and(Herradura.MASK);
            Stern.SternEncapResult enc = Stern.hpkeSternFEncapWithE(seed, rng);
            BigInteger recovered = Stern.hpkeSternFDecap(enc.eP, seed);
            if (!enc.k.equals(recovered)) {
                System.out.println("FAIL hpke_stern_f round-trip");
                fails++;
            } else {
                System.out.println("PASS hpke_stern_f round-trip");
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
                // A null/mismatched result is a legitimate DFR event (~0.225%
                // measured, TODO #195), not necessarily a bug — only flag it
                // if it happens on every one of a small batch.
                if (recovered != null && recovered.equals(enc.k)) { anyMismatch = false; break; }
                anyMismatch = true;
            }
            if (!pubMatches || anyMismatch) {
                System.out.println("FAIL hpke_stern_kem round-trip (pub_matches=" + pubMatches
                    + " all_" + trials + "_trials_failed=" + anyMismatch + ")");
                fails++;
            } else {
                System.out.println("PASS hpke_stern_kem round-trip");
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
                System.out.println("FAIL oprf round-trip: blind/eval/unblind != direct");
                fails++;
            } else {
                System.out.println("PASS oprf round-trip");
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
                System.out.println("FAIL hpks_wots_f round-trip (verify=" + ok + " rejects_tamper=" + rejectsTamper + ")");
                fails++;
            } else {
                System.out.println("PASS hpks_wots_f round-trip");
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
                System.out.println("FAIL hpks_xmss_f round-trip (verify=" + ok + " rejects_tamper=" + rejectsTamper + ")");
                fails++;
            } else {
                System.out.println("PASS hpks_xmss_f round-trip");
            }
        }

        if (fails > 0) {
            System.out.println(fails + " test(s) FAILED");
            System.exit(1);
        }
        System.out.println("All round-trip self-tests passed.");
    }
}
