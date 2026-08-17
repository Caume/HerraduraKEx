package herradurakex;

import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * TODO #192/#199: end-to-end round-trip smoke test for the herradurakex
 * Java package, with fresh random keys each run — complements KatVerify's
 * fixed-vector cross-check. Covers the classical quartet ({@link Herradura})
 * and the NL/PQC quartet ({@link HerraduraNl}). Exits non-zero on any failure.
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

        if (fails > 0) {
            System.out.println(fails + " test(s) FAILED");
            System.exit(1);
        }
        System.out.println("All round-trip self-tests passed.");
    }
}
