package herradurakex;

import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * TODO #201: pure-Java port of the 2HashDH Oblivious PRF over GF(2^256)*.
 *
 * Byte-for-byte port of "Herradura cryptographic suite.py"'s oprf_keygen /
 * oprf_blind / oprf_eval / oprf_unblind / oprf_direct (TODO #80).
 *
 * F(k, x) = gf_pow(H(x), k), where H = HFSCX-256 hash-to-field. Oblivious
 * under CDH in GF(2^256)*: alpha = H(x)^r is computationally
 * indistinguishable from random without knowing x or r.
 *
 * Protocol: client calls {@link #blind} → (r, alpha); sends alpha to the
 * server. Server calls {@link #eval}(alpha, k) → beta; returns beta to the
 * client. Client calls {@link #unblind}(beta, r) → F(k, x), equal to
 * {@link #direct}(x, k).
 *
 * As documented by the Python reference: no formal UC/game-based proof is
 * given beyond "believed to reduce to One-More-GDH" (Bellare et al. 2000)
 * informally adapted to the GF(2^n)* setting — treat as research-grade,
 * not a hardened production OPRF.
 */
public final class Oprf {
    private Oprf() { }

    private static final BigInteger ORD = Herradura.MASK; // 2^256 - 1

    /** Random OPRF server key k in (1, ORD). */
    public static BigInteger keygen(SecureRandom rng) {
        while (true) {
            BigInteger k = new BigInteger(Herradura.N, rng).and(ORD);
            if (k.compareTo(BigInteger.ONE) > 0 && k.compareTo(ORD) < 0) {
                return k;
            }
        }
    }

    /** HFSCX-256(data) as a non-zero element of GF(2^256). */
    static BigInteger hashToField(byte[] data) {
        BigInteger v = new BigInteger(1, Hfscx256.hash(data)).and(ORD);
        return (v.signum() == 0) ? BigInteger.ONE : v;
    }

    public static final class Blinded {
        public final BigInteger r;     // secret blinding scalar (client keeps this)
        public final BigInteger alpha; // sent to the server
        Blinded(BigInteger r, BigInteger alpha) { this.r = r; this.alpha = alpha; }
    }

    /** Client: hash x and blind with a random invertible scalar r. */
    public static Blinded blind(byte[] x, SecureRandom rng) {
        BigInteger r;
        while (true) {
            r = new BigInteger(Herradura.N, rng).and(ORD);
            if (r.compareTo(BigInteger.ONE) > 0 && r.gcd(ORD).equals(BigInteger.ONE)) break;
        }
        BigInteger alpha = Herradura.gfPow(hashToField(x), r);
        return new Blinded(r, alpha);
    }

    /** Server: evaluate alpha^k in GF(2^256)*. */
    public static BigInteger eval(BigInteger alpha, BigInteger k) {
        return Herradura.gfPow(alpha.and(ORD), k.and(ORD));
    }

    /** Client: recover F(k, x) = H(x)^k from beta = H(x)^(kr). */
    public static BigInteger unblind(BigInteger beta, BigInteger r) {
        BigInteger rInv = r.modInverse(ORD);
        return Herradura.gfPow(beta.and(ORD), rInv);
    }

    /** Direct (non-oblivious) evaluation F(k, x) = H(x)^k — server-side use only. */
    public static BigInteger direct(byte[] x, BigInteger k) {
        return Herradura.gfPow(hashToField(x), k.and(ORD));
    }
}
