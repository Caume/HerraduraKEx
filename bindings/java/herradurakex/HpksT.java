package herradurakex;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.List;

/**
 * TODO #260: pure-Java port of TODO #98 — HPKS-T, n-of-n MuSig2-style
 * threshold/aggregate Schnorr over GF(2^n)*, with an NL-FSCX v1 challenge.
 * C/Go/Python have carried this since it was added ("Herradura
 * cryptographic suite.{c,go,py}"'s #98 section); Java had neither the
 * primitive nor a demo/test for it until this file.
 *
 * <pre>
 *   mu_j    = HFSCX-256(L || C_j_bytes) mod ord, or 1 if that is 0   (rogue-key binding)
 *   L       = sorted 32-byte big-endian pubkeys, concatenated
 *   C_agg   = prod C_j^{mu_j}
 *   Sign:    R = prod g^{k_j};  e = nl_fscx_revolve_v1(R, msg, n/4);
 *            s_j = (k_j - a_j*mu_j*e) mod ord;  s = sum s_j mod ord
 *   Verify:  g^s * C_agg^e == R          (identical to single-party HPKS-NL verify)
 * </pre>
 *
 * All arithmetic is the same GF(2^256)* group {@link Herradura} uses for the
 * classical quartet — {@code gfMul}/{@code gfPow}/{@code GF_GEN} are reused
 * directly rather than re-implemented.
 */
public final class HpksT {
    private HpksT() { }

    private static final int N = Herradura.N;               // 256
    private static final int I_STEPS = Herradura.I_STEPS;    // 64
    private static final BigInteger ORD = Herradura.GROUP_ORDER; // 2^256 - 1
    private static final BigInteger GEN = Herradura.GF_GEN;

    /** mu_j = HFSCX-256(L || C_j_bytes) mod ord, remapped to 1 if that is 0
     * (an unbiasable-by-attacker-choice-of-key degenerate coefficient). */
    private static BigInteger muCoeff(byte[] lBytes, BigInteger cj) {
        byte[] cjBytes = Hfscx256.toFixedBytes(cj, N / 8);
        byte[] buf = new byte[lBytes.length + cjBytes.length];
        System.arraycopy(lBytes, 0, buf, 0, lBytes.length);
        System.arraycopy(cjBytes, 0, buf, lBytes.length, cjBytes.length);
        BigInteger mu = new BigInteger(1, Hfscx256.hash(buf, null)).mod(ORD);
        return mu.signum() == 0 ? BigInteger.ONE : mu;
    }

    /** L = sorted 32-byte big-endian pubkey encodings, concatenated — the
     * same lexicographic order as Python's {@code sorted()} on bytes and
     * Go's {@code bytes.Compare}, which for fixed-width big-endian
     * encodings is exactly numeric order. */
    private static byte[] buildL(List<BigInteger> pubkeys) {
        BigInteger[] sorted = pubkeys.toArray(new BigInteger[0]);
        java.util.Arrays.sort(sorted);
        byte[] out = new byte[sorted.length * (N / 8)];
        for (int i = 0; i < sorted.length; i++) {
            System.arraycopy(Hfscx256.toFixedBytes(sorted[i], N / 8), 0, out, i * (N / 8), N / 8);
        }
        return out;
    }

    /** Result of aggregating a group's public keys. */
    public static final class Aggregate {
        public final BigInteger cAgg;
        public final BigInteger[] coeffs; // mu_j, aligned with the input pubkeys order
        Aggregate(BigInteger cAgg, BigInteger[] coeffs) {
            this.cAgg = cAgg;
            this.coeffs = coeffs;
        }
    }

    /** Computes C_agg = prod C_j^{mu_j} and the per-signer mu coefficients,
     * aligned with {@code pubkeys}'s input order (not the sorted order used
     * internally to build L). */
    public static Aggregate aggregatePublicKeys(List<BigInteger> pubkeys) {
        byte[] lBytes = buildL(pubkeys);
        BigInteger[] coeffs = new BigInteger[pubkeys.size()];
        BigInteger agg = BigInteger.ONE;
        for (int j = 0; j < pubkeys.size(); j++) {
            BigInteger pk = pubkeys.get(j);
            coeffs[j] = muCoeff(lBytes, pk);
            agg = Herradura.gfMul(agg, Herradura.gfPow(pk, coeffs[j]));
        }
        return new Aggregate(agg, coeffs);
    }

    /** A threshold signature: the aggregate public key, the aggregate nonce,
     * and the aggregate response scalar. */
    public static final class Signature {
        public final BigInteger cAgg;
        public final BigInteger r;
        public final BigInteger s;
        Signature(BigInteger cAgg, BigInteger r, BigInteger s) {
            this.cAgg = cAgg;
            this.r = r;
            this.s = s;
        }
    }

    /** n-of-n threshold sign. {@code secrets.get(j)} must be the private
     * scalar for {@code pubkeys.get(j)} — both lists in the same (arbitrary,
     * not necessarily sorted) order. The challenge {@code e} is implicit;
     * verify re-derives it from R and msg. */
    public static Signature sign(List<BigInteger> secrets, List<BigInteger> pubkeys, BigInteger msg, SecureRandom rng) {
        int n = secrets.size();
        Aggregate agg = aggregatePublicKeys(pubkeys);

        BigInteger[] nonces = new BigInteger[n];
        BigInteger rVal = BigInteger.ONE;
        for (int j = 0; j < n; j++) {
            nonces[j] = new BigInteger(N, rng).and(Herradura.MASK);
            BigInteger rj = Herradura.gfPow(GEN, nonces[j]);
            rVal = Herradura.gfMul(rVal, rj);
        }

        BigInteger e = Hfscx256.nlFscxRevolveV1(rVal, msg, I_STEPS);

        BigInteger sAcc = BigInteger.ZERO;
        for (int j = 0; j < n; j++) {
            BigInteger ame = secrets.get(j).multiply(agg.coeffs[j]).multiply(e).mod(ORD);
            BigInteger sj = nonces[j].subtract(ame).mod(ORD);
            sAcc = sAcc.add(sj).mod(ORD);
        }

        return new Signature(agg.cAgg, rVal, sAcc);
    }

    /** Verify: g^s * C_agg^e == R, e = nl_fscx_revolve_v1(R, msg, n/4) —
     * structurally identical to single-party HPKS-NL verify. */
    public static boolean verify(BigInteger cAgg, BigInteger r, BigInteger s, BigInteger msg) {
        BigInteger e = Hfscx256.nlFscxRevolveV1(r, msg, I_STEPS);
        BigInteger lhs = Herradura.gfMul(Herradura.gfPow(GEN, s), Herradura.gfPow(cAgg, e));
        return lhs.equals(r);
    }
}
