package herradurakex;

import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * TODO #192: end-to-end round-trip smoke test for the herradurakex Java
 * package, with fresh random keys each run — complements KatVerify's
 * fixed-vector cross-check. Exits non-zero on any failure.
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

        if (fails > 0) {
            System.out.println(fails + " test(s) FAILED");
            System.exit(1);
        }
        System.out.println("All round-trip self-tests passed.");
    }
}
