package herradurakex;

import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * TODO #192: pure-Java port of the classical (v1.4.0) HerraduraKEx
 * quartet — HKEX-GF, HSKE, HPKS, HPKE — at n=256 bits.
 *
 * Mirrors "Herradura cryptographic suite.py"'s BitArray/fscx/gf_* functions
 * and the guarded protocol API (hkex_gf_agree/hpks_verify/hpke_encrypt/
 * hpke_decrypt, TODO #144) rather than herradura.h's constant-time C
 * implementation: java.math.BigInteger gives no constant-time guarantee
 * regardless, so there is nothing to gain from porting the C branchless
 * tricks, and the Python source is the more readable reference. Same
 * scope as bindings/ffi (TODO #137): the classical quartet only — NL/PQC
 * and Stern-F protocols are out of scope.
 *
 * All values are 256-bit unsigned integers represented as BigInteger,
 * always non-negative and less than 2^256. Every method that returns such
 * a value first masks it with {@link #MASK}.
 */
public final class Herradura {
    private Herradura() { }

    public static final int N = 256;
    public static final int I_STEPS = N / 4;       // 64
    public static final int R_STEPS = 3 * N / 4;    // 192
    public static final BigInteger GF_GEN = BigInteger.valueOf(3);
    public static final BigInteger GF_POLY = new BigInteger("425", 16);
    public static final BigInteger MASK = BigInteger.ONE.shiftLeft(N).subtract(BigInteger.ONE);
    public static final BigInteger GROUP_ORDER = MASK; // 2^n - 1, used for HPKS's s mod reduction

    // -----------------------------------------------------------------
    // Bit rotation over an N-bit value
    // -----------------------------------------------------------------

    public static BigInteger rol(BigInteger x, int bits) {
        bits = ((bits % N) + N) % N;
        if (bits == 0) return x.and(MASK);
        BigInteger left = x.shiftLeft(bits).and(MASK);
        BigInteger right = x.and(MASK).shiftRight(N - bits);
        return left.or(right);
    }

    public static BigInteger ror(BigInteger x, int bits) {
        return rol(x, N - (((bits % N) + N) % N));
    }

    // -----------------------------------------------------------------
    // FSCX: C = A ^ B ^ ROL(A) ^ ROL(B) ^ ROR(A) ^ ROR(B)
    // -----------------------------------------------------------------

    public static BigInteger fscx(BigInteger a, BigInteger b) {
        return a.xor(b).xor(rol(a, 1)).xor(rol(b, 1)).xor(ror(a, 1)).xor(ror(b, 1)).and(MASK);
    }

    public static BigInteger fscxRevolve(BigInteger a, BigInteger b, int steps) {
        BigInteger result = a.and(MASK);
        for (int i = 0; i < steps; i++) {
            result = fscx(result, b);
        }
        return result;
    }

    // -----------------------------------------------------------------
    // GF(2^256) arithmetic — carryless multiply mod GF_POLY, generator g=3
    // -----------------------------------------------------------------

    public static BigInteger gfMul(BigInteger a, BigInteger b) {
        BigInteger result = BigInteger.ZERO;
        BigInteger hb = BigInteger.ONE.shiftLeft(N - 1);
        a = a.and(MASK);
        b = b.and(MASK);
        for (int i = 0; i < N; i++) {
            if (b.testBit(0)) result = result.xor(a);
            boolean carry = a.and(hb).signum() != 0;
            a = a.shiftLeft(1).and(MASK);
            if (carry) a = a.xor(GF_POLY);
            b = b.shiftRight(1);
        }
        return result;
    }

    public static BigInteger gfPow(BigInteger base, BigInteger exp) {
        BigInteger result = BigInteger.ONE;
        base = base.and(MASK);
        exp = exp.and(MASK);
        for (int i = 0; i < N; i++) {
            if (exp.testBit(0)) result = gfMul(result, base);
            base = gfMul(base, base);
            exp = exp.shiftRight(1);
        }
        return result;
    }

    /** Rejects the additive zero and multiplicative identity g^0=1 — a
     * degenerate GF(2^n)* public element that collapses HKEX-GF/HPKS/HPKE
     * to trivially forgeable/decryptable cases (TODO #144/#131). */
    public static boolean gfPubIsValid(BigInteger pub) {
        pub = pub.and(MASK);
        return pub.signum() != 0 && !pub.equals(BigInteger.ONE);
    }

    // -----------------------------------------------------------------
    // HKEX-GF: C = g^a; C2 = g^b; sk = C2^a = C^b = g^{ab}
    // -----------------------------------------------------------------

    public static BigInteger hkexGfPubkey(BigInteger priv) {
        return gfPow(GF_GEN, priv);
    }

    /** Returns the shared secret, or null if theirPub is degenerate. */
    public static BigInteger hkexGfAgree(BigInteger myPriv, BigInteger theirPub) {
        if (!gfPubIsValid(theirPub)) return null;
        return gfPow(theirPub, myPriv);
    }

    // -----------------------------------------------------------------
    // HSKE: E = fscx_revolve(P, key, i); D = fscx_revolve(E, key, r) == P
    // -----------------------------------------------------------------

    public static BigInteger hskeEncrypt(BigInteger pt, BigInteger key) {
        return fscxRevolve(pt, key, I_STEPS);
    }

    public static BigInteger hskeDecrypt(BigInteger ct, BigInteger key) {
        return fscxRevolve(ct, key, R_STEPS);
    }

    // -----------------------------------------------------------------
    // HPKS (Schnorr): R = g^k; e = fscx_revolve(R, msg, i);
    // s = (k - priv*e) mod (2^n - 1); verify: g^s * pub^e == R
    // -----------------------------------------------------------------

    public static final class Signature {
        public final BigInteger r;
        public final BigInteger s;
        public Signature(BigInteger r, BigInteger s) { this.r = r; this.s = s; }
    }

    /** Signs with an explicit ephemeral scalar k — for deterministic/KAT use.
     * Real callers should use {@link #hpksSign(BigInteger, BigInteger, SecureRandom)}. */
    public static Signature hpksSign(BigInteger msg, BigInteger priv, BigInteger k) {
        BigInteger r = gfPow(GF_GEN, k);
        BigInteger e = fscxRevolve(r, msg, I_STEPS);
        BigInteger s = k.subtract(priv.multiply(e)).mod(GROUP_ORDER);
        return new Signature(r, s);
    }

    public static Signature hpksSign(BigInteger msg, BigInteger priv, SecureRandom rng) {
        BigInteger k = new BigInteger(N, rng).and(MASK);
        return hpksSign(msg, priv, k);
    }

    public static boolean hpksVerify(BigInteger msg, BigInteger pub, BigInteger r, BigInteger s) {
        if (!gfPubIsValid(pub)) return false;
        BigInteger e = fscxRevolve(r, msg, I_STEPS);
        BigInteger lhs = gfMul(gfPow(GF_GEN, s), gfPow(pub, e));
        return lhs.equals(r.and(MASK));
    }

    // -----------------------------------------------------------------
    // HPKE (El Gamal + fscx_revolve): enc_key = pub^r; E = fscx_revolve(P, enc_key, i);
    // dec_key = R^priv; D = fscx_revolve(E, dec_key, r_steps) == P
    // -----------------------------------------------------------------

    public static final class Ciphertext {
        public final BigInteger r;
        public final BigInteger ct;
        public Ciphertext(BigInteger r, BigInteger ct) { this.r = r; this.ct = ct; }
    }

    /** Encrypts with an explicit ephemeral scalar r — for deterministic/KAT use.
     * Real callers should use {@link #hpkeEncrypt(BigInteger, BigInteger, SecureRandom)}. */
    public static Ciphertext hpkeEncrypt(BigInteger pt, BigInteger pub, BigInteger r) {
        if (!gfPubIsValid(pub)) return null;
        BigInteger R = gfPow(GF_GEN, r);
        BigInteger encKey = gfPow(pub, r);
        BigInteger ct = fscxRevolve(pt, encKey, I_STEPS);
        return new Ciphertext(R, ct);
    }

    public static Ciphertext hpkeEncrypt(BigInteger pt, BigInteger pub, SecureRandom rng) {
        BigInteger r = new BigInteger(N, rng).and(MASK);
        return hpkeEncrypt(pt, pub, r);
    }

    public static BigInteger hpkeDecrypt(BigInteger ct, BigInteger r, BigInteger priv) {
        if (!gfPubIsValid(r)) return null;
        BigInteger decKey = gfPow(r, priv);
        return fscxRevolve(ct, decKey, R_STEPS);
    }
}
