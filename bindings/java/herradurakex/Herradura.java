package herradurakex;

import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * TODO #192: pure-Java port of the classical (v1.4.0) HerraduraKEx
 * quartet — HKEX-GF, HSKE, HPKS, HPKE — at n=256 bits.
 *
 * Mirrors "Herradura cryptographic suite.py"'s BitArray/fscx/gf_* functions
 * and the guarded protocol API (hkex_gf_agree/hpks_verify/hpke_encrypt/
 * hpke_decrypt, TODO #144). Same scope as bindings/ffi (TODO #137): the
 * classical quartet only — NL/PQC and Stern-F protocols are out of scope.
 *
 * <p>ALL VALUES ARE {@link BitArray} SINCE TODO #314 PASS 5, and the header
 * this replaces is why. It read: "rather than herradura.h's constant-time C
 * implementation: java.math.BigInteger gives no constant-time guarantee
 * regardless, so there is nothing to gain from porting the C branchless
 * tricks". That was true of BigInteger, and it is TODO #314's reason 3 stated
 * by the port itself — a security property conceded because of a dependency
 * choice. Over a {@code byte[]} there IS something to gain, so {@code fscx},
 * the rotations and the GF pair now run on octets with the same branch-free
 * structure C and Go use, and the width is carried WITH each value instead of
 * being a static property of the whole port.
 *
 * <p>{@link #MASK} and {@link #GROUP_ORDER} remain BigInteger: they belong to
 * the Schnorr arithmetic and to the codec's DER INTEGERs, which BITARRAY.md
 * does not govern. {@link BitArray#toBigInteger()} and
 * {@link BitArray#fromBigInteger} are the named crossing.
 */
public final class Herradura {
    private Herradura() { }

    public static final int N = 256;
    public static final int I_STEPS = N / 4;       // 64
    public static final int R_STEPS = 3 * N / 4;    // 192
    public static final BigInteger GF_GEN_INT = BigInteger.valueOf(3);
    /** The generator g = 3 as an N-bit value. */
    public static final BitArray GF_GEN = BitArray.fromUint(3, N);
    public static final BigInteger GF_POLY = new BigInteger("425", 16);
    public static final BigInteger MASK = BigInteger.ONE.shiftLeft(N).subtract(BigInteger.ONE);
    public static final BigInteger GROUP_ORDER = MASK; // 2^n - 1, used for HPKS's s mod reduction

    // -----------------------------------------------------------------
    // Bit rotation over an N-bit value
    // -----------------------------------------------------------------

    public static BitArray rol(BitArray x, int bits) { return x.rotLeft(bits); }

    public static BitArray ror(BitArray x, int bits) { return x.rotRight(bits); }

    // -----------------------------------------------------------------
    // FSCX: C = A ^ B ^ ROL(A) ^ ROL(B) ^ ROR(A) ^ ROR(B)
    // -----------------------------------------------------------------

    public static BitArray fscx(BitArray a, BitArray b) { return BitArray.fscx(a, b); }

    public static BitArray fscxRevolve(BitArray a, BitArray b, int steps) {
        return BitArray.fscxRevolve(a, b, steps);
    }

    // -----------------------------------------------------------------
    // GF(2^256) arithmetic — carryless multiply mod GF_POLY, generator g=3
    // -----------------------------------------------------------------

    /** a·b in GF(2^N).  Branch-free over the octets since TODO #314 pass 5. */
    public static BitArray gfMul(BitArray a, BitArray b) { return BitArray.gfMul(a, b); }

    /**
     * base^exp in GF(2^N)* with a full-width exponent.
     *
     * <p>SA-02/06: iterates exactly N times — no early exit on leading zero
     * bits of exp, so the loop count does not leak its bit-length.  The
     * per-bit conditional multiply remains; that residual is the same one C
     * and Go record.
     */
    public static BitArray gfPow(BitArray base, BitArray exp) {
        BitArray result = BitArray.fromUint(1, N);
        BitArray bb = base;
        for (int i = 0; i < N; i++) {          // fixed N iterations
            if (exp.bit(i) == 1) result = BitArray.gfMul(result, bb);
            bb = BitArray.gfMul(bb, bb);
        }
        return result;
    }

    /** Rejects the additive zero and multiplicative identity g^0=1 — a
     * degenerate GF(2^n)* public element that collapses HKEX-GF/HPKS/HPKE
     * to trivially forgeable/decryptable cases (TODO #144/#131). */
    public static boolean gfPubIsValid(BitArray pub) {
        return !pub.isZero() && !pub.equals(BitArray.fromUint(1, pub.size()));
    }

    // -----------------------------------------------------------------
    // HKEX-GF: C = g^a; C2 = g^b; sk = C2^a = C^b = g^{ab}
    // -----------------------------------------------------------------

    public static BitArray hkexGfPubkey(BitArray priv) {
        return gfPow(GF_GEN, priv);
    }

    /** Returns the shared secret, or null if theirPub is degenerate. */
    public static BitArray hkexGfAgree(BitArray myPriv, BitArray theirPub) {
        if (!gfPubIsValid(theirPub)) return null;
        return gfPow(theirPub, myPriv);
    }

    // -----------------------------------------------------------------
    // HSKE: E = fscx_revolve(P, key, i); D = fscx_revolve(E, key, r) == P
    // -----------------------------------------------------------------

    public static BitArray hskeEncrypt(BitArray pt, BitArray key) {
        return fscxRevolve(pt, key, I_STEPS);
    }

    public static BitArray hskeDecrypt(BitArray ct, BitArray key) {
        return fscxRevolve(ct, key, R_STEPS);
    }

    // -----------------------------------------------------------------
    // HPKS (Schnorr): R = g^k; e = fscx_revolve(R, msg, i);
    // s = (k - priv*e) mod (2^n - 1); verify: g^s * pub^e == R
    // -----------------------------------------------------------------

    public static final class Signature {
        public final BitArray r;
        public final BitArray s;
        public Signature(BitArray r, BitArray s) { this.r = r; this.s = s; }
    }

    /** Signs with an explicit ephemeral scalar k — for deterministic/KAT use.
     * Real callers should use {@link #hpksSign(BigInteger, BigInteger, SecureRandom)}. */
    public static Signature hpksSign(BitArray msg, BitArray priv, BitArray k) {
        BitArray r = gfPow(GF_GEN, k);
        BitArray e = fscxRevolve(r, msg, I_STEPS);
        // s = (k - priv*e) mod (2^N - 1).  The Schnorr scalar is an integer by
        // the protocol's own definition, so it crosses at the named boundary.
        BigInteger s = k.toBigInteger()
                        .subtract(priv.toBigInteger().multiply(e.toBigInteger()))
                        .mod(GROUP_ORDER);
        return new Signature(r, BitArray.fromBigInteger(s, N));
    }

    public static Signature hpksSign(BitArray msg, BitArray priv, SecureRandom rng) {
        return hpksSign(msg, priv, BitArray.random(N, rng));
    }

    public static boolean hpksVerify(BitArray msg, BitArray pub, BitArray r, BitArray s) {
        if (!gfPubIsValid(pub)) return false;
        BitArray e = fscxRevolve(r, msg, I_STEPS);
        BitArray lhs = gfMul(gfPow(GF_GEN, s), gfPow(pub, e));
        return lhs.equals(r);
    }

    // -----------------------------------------------------------------
    // HPKE (El Gamal + fscx_revolve): enc_key = pub^r; E = fscx_revolve(P, enc_key, i);
    // dec_key = R^priv; D = fscx_revolve(E, dec_key, r_steps) == P
    // -----------------------------------------------------------------

    public static final class Ciphertext {
        public final BitArray r;
        public final BitArray ct;
        public Ciphertext(BitArray r, BitArray ct) { this.r = r; this.ct = ct; }
    }

    /** Encrypts with an explicit ephemeral scalar r — for deterministic/KAT use.
     * Real callers should use {@link #hpkeEncrypt(BigInteger, BigInteger, SecureRandom)}. */
    public static Ciphertext hpkeEncrypt(BitArray pt, BitArray pub, BitArray r) {
        if (!gfPubIsValid(pub)) return null;
        BitArray R = gfPow(GF_GEN, r);
        BitArray encKey = gfPow(pub, r);
        BitArray ct = fscxRevolve(pt, encKey, I_STEPS);
        return new Ciphertext(R, ct);
    }

    public static Ciphertext hpkeEncrypt(BitArray pt, BitArray pub, SecureRandom rng) {
        return hpkeEncrypt(pt, pub, BitArray.random(N, rng));
    }

    public static BitArray hpkeDecrypt(BitArray ct, BitArray r, BitArray priv) {
        if (!gfPubIsValid(r)) return null;
        BitArray decKey = gfPow(r, priv);
        return fscxRevolve(ct, decKey, R_STEPS);
    }

    // -----------------------------------------------------------------
    // 78.H — Masking-Friendly FSCX (Boolean masking via GF(2) linearity)
    // TODO #261: ported from herradura.h / herradura.go / the Python suite
    // so this suite-internal primitive has four-language parity.
    //
    // FSCX(A^r, B, steps) ^ FSCX(r, 0, steps) == FSCX(A, B, steps)
    // because M = I^ROL^ROR is GF(2)-linear, so M^steps(A^r) == M^steps(A)^M^steps(r).
    //
    // The caller supplies a uniform random mask r; no secret bits of A are
    // exposed in any intermediate value computed by this method.
    // -----------------------------------------------------------------

    /** Computes fscxRevolve(a, b, steps) without exposing a: mask must be a
     * uniform random value. Returns fscxRevolve(a^mask, b, steps) ^
     * fscxRevolve(mask, 0, steps), which equals fscxRevolve(a, b, steps) by
     * GF(2)-linearity of M^steps. */
    public static BitArray fscxRevolveMasked(BitArray a, BitArray b, BitArray mask, int steps) {
        BitArray fm = fscxRevolve(a.xor(mask), b, steps);
        BitArray fz = fscxRevolve(mask, BitArray.zero(a.size()), steps);
        return fm.xor(fz);
    }

    public static final class Masked {
        public final BitArray result;
        public final BitArray mask;
        public Masked(BitArray result, BitArray mask) { this.result = result; this.mask = mask; }
    }

    /** HSKE encrypt with internal mask generation. Caller should discard/erase
     * {@code mask} after use (neither BigInteger nor an immutable BitArray can be zeroized in place). */
    public static Masked hskeEncryptMasked(BitArray pt, BitArray key, SecureRandom rng) {
        BitArray mask = BitArray.random(N, rng);
        return new Masked(fscxRevolveMasked(pt, key, mask, I_STEPS), mask);
    }

    /** HSKE decrypt with internal mask generation. */
    public static Masked hskeDecryptMasked(BitArray ct, BitArray key, SecureRandom rng) {
        BitArray mask = BitArray.random(N, rng);
        return new Masked(fscxRevolveMasked(ct, key, mask, R_STEPS), mask);
    }
}
