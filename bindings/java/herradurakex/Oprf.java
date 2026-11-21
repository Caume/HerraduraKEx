package herradurakex;

import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * TODO #201: pure-Java port of the 2HashDH Oblivious PRF over GF(2^n)*, at
 * n = 32, 64, 128 or 256 since TODO #385 (every method takes n).
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

    /** Random n-bit OPRF server key k in (1, 2^n - 1). */
    public static BigInteger keygen(int n, SecureRandom rng) {
        BigInteger ordN = Herradura.order(n);
        while (true) {
            BigInteger k = new BigInteger(n, rng).and(ordN);
            if (k.compareTo(BigInteger.ONE) > 0 && k.compareTo(ordN) < 0) {
                return k;
            }
        }
    }

    /** HFSCX-256(data) as a non-zero element of GF(2^n): below 256 bits, the
     * digest's HIGH n bits (BITARRAY.md 4.4's truncation, as the Stern-F hash
     * and HCRED's issuer message; TODO #385). */
    static BigInteger hashToField(byte[] data, int n) {
        BigInteger v = new BigInteger(1, Hfscx256.hash(data)).shiftRight(256 - n);
        return (v.signum() == 0) ? BigInteger.ONE : v;
    }

    public static final class Blinded {
        public final BigInteger r;     // secret blinding scalar (client keeps this)
        public final BigInteger alpha; // sent to the server
        Blinded(BigInteger r, BigInteger alpha) { this.r = r; this.alpha = alpha; }
    }

    /** Client: hash x to GF(2^n) and blind with a random invertible scalar r. */
    public static Blinded blind(byte[] x, int n, SecureRandom rng) {
        BigInteger ordN = Herradura.order(n);
        BigInteger r;
        while (true) {
            r = new BigInteger(n, rng).and(ordN);
            if (r.compareTo(BigInteger.ONE) > 0 && r.gcd(ordN).equals(BigInteger.ONE)) break;
        }
        return new Blinded(r, Herradura.gfPow(BitArray.fromBigInteger(hashToField(x, n), n), BitArray.fromBigInteger(r, n)).toBigInteger());
    }

    /** Server: evaluate alpha^k in GF(2^n)*. */
    public static BigInteger eval(BigInteger alpha, BigInteger k, int n) {
        BigInteger ordN = Herradura.order(n);
        return Herradura.gfPow(BitArray.fromBigInteger(alpha.and(ordN), n), BitArray.fromBigInteger(k.and(ordN), n)).toBigInteger();
    }

    /** Client: recover F(k, x) = H(x)^k from beta = H(x)^(kr). */
    public static BigInteger unblind(BigInteger beta, BigInteger r, int n) {
        BigInteger ordN = Herradura.order(n);
        return Herradura.gfPow(BitArray.fromBigInteger(beta.and(ordN), n), BitArray.fromBigInteger(r.modInverse(ordN), n)).toBigInteger();
    }

    /** Direct (non-oblivious) evaluation F(k, x) = H(x)^k — server-side use only. */
    public static BigInteger direct(byte[] x, BigInteger k, int n) {
        return Herradura.gfPow(BitArray.fromBigInteger(hashToField(x, n), n), BitArray.fromBigInteger(k.and(Herradura.order(n)), n)).toBigInteger();
    }
}
