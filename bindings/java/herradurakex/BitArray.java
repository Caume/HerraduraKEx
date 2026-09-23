package herradurakex;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * BitArray — variable width, big-endian octets (TODO #314 pass 5).
 *
 * <p>BITARRAY.md is the normative specification; this is its Java port, and
 * KAT/bitarray.json is the conformance oracle all four ports are held to
 * (C pass 2, Go pass 3, Python pass 4, Java pass 5).
 *
 * <p>The width is carried WITH the value and is never passed alongside it.
 * That is the whole point of the type: TODO #313's four-way divergence begins
 * with two ports that were handed a declared width and ignored it, which is
 * only possible when the width and the value can be separated.  Before this
 * pass THIS port could not pose the question at all — it carried bare
 * {@link BigInteger} values against a static {@code Herradura.N = 256}, so a
 * width was not a property of a value but of the whole port.
 *
 * <p><b>CONSTANT TIME IS THE REASON THIS PORT IS THE ONE THAT GAINS.</b>
 * {@code Herradura}'s own header says it mirrors the Python source "rather
 * than herradura.h's constant-time C implementation: java.math.BigInteger
 * gives no constant-time guarantee regardless, so there is nothing to gain
 * from porting the C branchless tricks".  That was true of BigInteger and is
 * TODO #314's reason 3.  Over a {@code byte[]} there IS something to gain, so
 * the operations BITARRAY.md §4 marks CT are implemented here the way C and Go
 * implement them: every octet is touched, results are folded with masks rather
 * than branches, and no loop exits early on a data-dependent condition.  What
 * that buys is a branch-free STRUCTURE, the same one the other two ports have;
 * it is not a claim about what a JIT emits, and the suite still uses
 * {@code MessageDigest.isEqual} where constant time is load-bearing.
 *
 * <p>Instances are IMMUTABLE.  Every constructor copies its input and every
 * accessor returns a copy, so a width cannot be separated from its value after
 * the fact — the defect this type exists to remove, made unrepresentable
 * rather than merely discouraged.
 */
public final class BitArray {

    /** This port's capacity (BITARRAY.md §2: at least 256). */
    public static final int BA_MAX_BITS = 256;

    private final int nbits;
    private final byte[] b;   // big-endian; b[0] is the most significant octet

    private BitArray(int nbits, byte[] owned) {
        this.nbits = nbits;
        this.b = owned;       // caller guarantees this array is not shared
    }

    // ── width ──────────────────────────────────────────────────────────────

    /**
     * BITARRAY.md §2: a positive multiple of 8, at least 16, at most capacity.
     * The floor is not arbitrary — {@code fscx} reads the octet on both sides
     * of every position and degenerates below two octets, which is why C has
     * carried {@code #if KEYBYTES < 2 / #error} since v1.3.
     */
    private static void checkWidth(int n, String op) {
        if (n <= 0 || n % 8 != 0 || n < 16 || n > BA_MAX_BITS)
            throw new BaException(BaException.E_WIDTH, op);
    }

    /** BITARRAY.md §3: a binary operation REQUIRES equal widths, never coerced. */
    private void sameWidth(BitArray other, String op) {
        if (other == null) throw new BaException(BaException.E_WIDTH, op);
        if (this.nbits != other.nbits)
            throw new BaException(BaException.E_MIXED_WIDTH, op);
    }

    /** The width in bits, carried with the value. */
    public int size() { return nbits; }

    /** The active octet count — the one place a width becomes a loop bound. */
    public int nbytes() { return nbits / 8; }

    // ── construction and conversion (BITARRAY.md §4.1) ─────────────────────

    /** All-zero BitArray of width n. */
    public static BitArray zero(int n) {
        checkWidth(n, "zero");
        return new BitArray(n, new byte[n / 8]);
    }

    /**
     * Requires {@code data.length == n/8} EXACTLY: a length that does not match
     * the declared width is E_LENGTH, not a re-interpretation.
     */
    public static BitArray fromBytes(byte[] data, int n) {
        checkWidth(n, "from_bytes");
        if (data == null || data.length != n / 8)
            throw new BaException(BaException.E_LENGTH, "from_bytes");
        return new BitArray(n, Arrays.copyOf(data, data.length));
    }

    /**
     * Rejects {@code v >= 2^n} rather than masking (BITARRAY.md §4.1): masking
     * is how an out-of-range intermediate becomes a plausible in-range value
     * with nothing recording that it happened.
     */
    public static BitArray fromUint(long v, int n) {
        checkWidth(n, "from_uint");
        if (v < 0) throw new BaException(BaException.E_RANGE, "from_uint");
        if (n < 64 && Long.compareUnsigned(v, 1L << n) >= 0)
            throw new BaException(BaException.E_RANGE, "from_uint");
        int nb = n / 8;
        byte[] out = new byte[nb];
        for (int i = 0; i < 8 && i < nb; i++) out[nb - 1 - i] = (byte) (v >>> (8 * i));
        return new BitArray(n, out);
    }

    /** Requires exactly n/4 hex digits. */
    public static BitArray fromHex(String s, int n) {
        checkWidth(n, "from_hex");
        if (s == null || s.length() != n / 4)
            throw new BaException(BaException.E_LENGTH, "from_hex");
        int nb = n / 8;
        byte[] out = new byte[nb];
        for (int i = 0; i < nb; i++) {
            int hi = hexVal(s.charAt(2 * i)), lo = hexVal(s.charAt(2 * i + 1));
            if (hi < 0 || lo < 0) throw new BaException(BaException.E_HEXDIGIT, "from_hex");
            out[i] = (byte) ((hi << 4) | lo);
        }
        return new BitArray(n, out);
    }

    private static int hexVal(char c) {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    }

    /** n bits from the given source.  A short read is E_ENTROPY, never partial. */
    public static BitArray random(int n, SecureRandom rng) {
        checkWidth(n, "random");
        if (rng == null) throw new BaException(BaException.E_ENTROPY, "random");
        byte[] out = new byte[n / 8];
        rng.nextBytes(out);
        return new BitArray(n, out);
    }

    /**
     * BITARRAY.md §4.1: defined for {@code n <= 64} ONLY.
     *
     * <p>That bound was found by pass 2 and is a correction to the
     * specification rather than a concession to C: a port with no bignum
     * cannot return a 256-bit integer, and requiring it would force back in
     * exactly the {@code BigInteger} dependency this type removes.  The octet
     * string is the canonical form; {@link #toBigInteger()} is the named
     * boundary for the values that genuinely are integers.
     */
    public long toUint() {
        if (nbits > 64) throw new BaException(BaException.E_RANGE, "to_uint");
        long v = 0;
        for (int i = 0; i < b.length; i++) v = (v << 8) | (b[i] & 0xFFL);
        return v;
    }

    /** The canonical octets.  A copy: the stored array is never handed out. */
    public byte[] toBytes() { return Arrays.copyOf(b, b.length); }

    /** Exactly n/4 lowercase hex digits, zero-padded. */
    public String toHex() {
        StringBuilder s = new StringBuilder(2 * b.length);
        for (byte v : b) s.append(Character.forDigit((v >> 4) & 0xF, 16))
                          .append(Character.forDigit(v & 0xF, 16));
        return s.toString();
    }

    /** A value-distinct equal BitArray.  Immutable, so this returns itself. */
    public BitArray copy() { return this; }

    // ── the BigInteger boundary ────────────────────────────────────────────
    //
    // BigInteger no longer implements this type, and it still REPRESENTS the
    // objects BITARRAY.md does not govern: QC-MDPC dense polynomials, Stern and
    // HCRED syndromes, Z_q coefficients, OPRF and threshold scalars, and the
    // DER INTEGERs the codec reads and writes.  These two methods are the ONLY
    // door between the two worlds and are named so the boundary can be counted
    // — the counterpart of Go's NewBitArray / BigInt and Python's uint.

    /** Build from a BigInteger, MASKED to the width.  See the boundary note. */
    public static BitArray fromBigInteger(BigInteger v, int n) {
        checkWidth(n, "from_big_integer");
        if (v == null) throw new BaException(BaException.E_RANGE, "from_big_integer");
        int nb = n / 8;
        byte[] raw = v.and(BigInteger.ONE.shiftLeft(n).subtract(BigInteger.ONE)).toByteArray();
        byte[] out = new byte[nb];
        // toByteArray() is big-endian two's complement with a possible leading
        // zero sign octet, and it NORMALISES away leading zeros — which is
        // §1.1's whole argument against storing an integer.  Right-align.
        int copy = Math.min(raw.length, nb);
        System.arraycopy(raw, raw.length - copy, out, nb - copy, copy);
        return new BitArray(n, out);
    }

    /** The value as a BigInteger, non-negative.  See the boundary note. */
    public BigInteger toBigInteger() { return new BigInteger(1, b); }

    // ── bitwise (BITARRAY.md §4.2) — CT ────────────────────────────────────

    public BitArray xor(BitArray other) {
        sameWidth(other, "xor");
        byte[] out = new byte[b.length];
        for (int i = 0; i < b.length; i++) out[i] = (byte) (b[i] ^ other.b[i]);
        return new BitArray(nbits, out);
    }

    public BitArray and(BitArray other) {
        sameWidth(other, "and");
        byte[] out = new byte[b.length];
        for (int i = 0; i < b.length; i++) out[i] = (byte) (b[i] & other.b[i]);
        return new BitArray(nbits, out);
    }

    public BitArray or(BitArray other) {
        sameWidth(other, "or");
        byte[] out = new byte[b.length];
        for (int i = 0; i < b.length; i++) out[i] = (byte) (b[i] | other.b[i]);
        return new BitArray(nbits, out);
    }

    public BitArray not() {
        byte[] out = new byte[b.length];
        for (int i = 0; i < b.length; i++) out[i] = (byte) ~b[i];
        return new BitArray(nbits, out);
    }

    // ── rotation and shift (BITARRAY.md §4.3) ──────────────────────────────

    /**
     * Rotate left by s; negative s rotates right.  s is reduced modulo the
     * width MATHEMATICALLY — Java's % can return a negative remainder and must
     * be corrected, which the specification says out loud because a port that
     * does not is a silent divergence.
     */
    public BitArray rotLeft(int s) {
        int n = nbits;
        s = ((s % n) + n) % n;
        int nb = b.length;
        byte[] out = new byte[nb];
        int byteShift = s >> 3, bitShift = s & 7;
        if (bitShift == 0) {
            for (int i = 0; i < nb; i++) out[i] = b[(i + byteShift) % nb];
        } else {
            int rsh = 8 - bitShift;
            for (int i = 0; i < nb; i++) {
                int hi = b[(i + byteShift) % nb] & 0xFF;
                int lo = b[(i + byteShift + 1) % nb] & 0xFF;
                out[i] = (byte) ((hi << bitShift) | (lo >>> rsh));
            }
        }
        return new BitArray(n, out);
    }

    /** ROR(s), defined as the opposite rotation, so rotRight(s) == rotLeft(-s). */
    public BitArray rotRight(int s) { return rotLeft(-s); }

    /**
     * Numeric left shift within the width: bits past the top are DISCARDED,
     * vacated positions are ZERO, and {@code k >= n} yields zero.  That last
     * clause is stated rather than assumed because the expression is undefined
     * behaviour in C, a panic in Go, 0 in Python — and in THIS language a
     * ROTATION, since {@code <<} uses {@code k & 63}.  BITARRAY.md §4.3 exists
     * largely because of that fourth answer.
     */
    public BitArray shl(int k) {
        if (k < 0) throw new BaException(BaException.E_RANGE, "shl");
        int nb = b.length;
        byte[] out = new byte[nb];
        if (k >= nbits) return new BitArray(nbits, out);
        int byteShift = k / 8, bitShift = k % 8;
        if (bitShift == 0) {
            System.arraycopy(b, byteShift, out, 0, nb - byteShift);
        } else {
            for (int i = 0; i < nb - byteShift - 1; i++)
                out[i] = (byte) (((b[i + byteShift] & 0xFF) << bitShift)
                               | ((b[i + byteShift + 1] & 0xFF) >>> (8 - bitShift)));
            out[nb - byteShift - 1] = (byte) ((b[nb - 1] & 0xFF) << bitShift);
        }
        return new BitArray(nbits, out);
    }

    /** Numeric right shift within the width; see {@link #shl(int)}. */
    public BitArray shr(int k) {
        if (k < 0) throw new BaException(BaException.E_RANGE, "shr");
        int nb = b.length;
        byte[] out = new byte[nb];
        if (k >= nbits) return new BitArray(nbits, out);
        int byteShift = k / 8, bitShift = k % 8;
        if (bitShift == 0) {
            System.arraycopy(b, 0, out, byteShift, nb - byteShift);
        } else {
            for (int i = nb - 1; i > byteShift; i--)
                out[i] = (byte) (((b[i - byteShift] & 0xFF) >>> bitShift)
                               | ((b[i - byteShift - 1] & 0xFF) << (8 - bitShift)));
            out[byteShift] = (byte) ((b[0] & 0xFF) >>> bitShift);
        }
        return new BitArray(nbits, out);
    }

    // ── width change (BITARRAY.md §4.4) ────────────────────────────────────

    /**
     * Keep the HIGH m bits — the big-endian PREFIX.  A SLICE, which is the
     * whole argument for the rule: truncating a big-endian octet string is
     * slicing, where low-bit truncation is arithmetic, and arithmetic is where
     * the four ports diverged (TODO #313).
     */
    public BitArray truncate(int m) {
        checkWidth(m, "truncate");
        if (m > nbits) throw new BaException(BaException.E_WIDTH, "truncate");
        return new BitArray(m, Arrays.copyOf(b, m / 8));
    }

    /** Append (m - n)/8 zero octets on the LOW side. */
    public BitArray extend(int m) {
        checkWidth(m, "extend");
        if (m < nbits) throw new BaException(BaException.E_WIDTH, "extend");
        byte[] out = new byte[m / 8];
        System.arraycopy(b, 0, out, 0, b.length);
        return new BitArray(m, out);
    }

    /**
     * The operation protocol code should reach for: a narrowing that would
     * discard a set bit is E_LOSSY, not a result.
     */
    public BitArray resizeExact(int m) {
        checkWidth(m, "resize_exact");
        if (m >= nbits) return extend(m);
        for (int i = m / 8; i < b.length; i++)
            if (b[i] != 0) throw new BaException(BaException.E_LOSSY, "resize_exact");
        return truncate(m);
    }

    // ── comparison and inspection (BITARRAY.md §4.5) — CT ──────────────────

    /**
     * Width AND value.  A width mismatch is false rather than an error: an
     * equality test is a question, not an operation on a shared width.
     * Constant-time in the values — every octet is accumulated, no early exit,
     * which is precisely what {@code BigInteger.equals} could not offer.
     */
    @Override
    public boolean equals(Object o) {
        if (!(o instanceof BitArray)) return false;
        BitArray other = (BitArray) o;
        if (nbits != other.nbits) return false;
        int diff = 0;
        for (int i = 0; i < b.length; i++) diff |= b[i] ^ other.b[i];
        return diff == 0;
    }

    @Override
    public int hashCode() { return 31 * nbits + Arrays.hashCode(b); }

    /**
     * -1 / 0 / +1, unsigned big-endian lexicographic.  Constant-time: scans
     * every octet and folds, with no early exit.
     */
    public int compare(BitArray other) {
        sameWidth(other, "compare");
        int res = 0;
        for (int i = 0; i < b.length; i++) {
            int x = b[i] & 0xFF, y = other.b[i] & 0xFF;
            int gt = (x > y) ? 1 : 0, lt = (x < y) ? 1 : 0;
            int undecided = (res == 0) ? 1 : 0;
            res += undecided * (gt - lt);
        }
        return res;
    }

    /** Every active octet zero, accumulated without an early exit. */
    public boolean isZero() {
        int acc = 0;
        for (byte v : b) acc |= v;
        return acc == 0;
    }

    /** Set bits over all n/8 octets. */
    public int popcount() {
        int c = 0;
        for (byte v : b) c += Integer.bitCount(v & 0xFF);
        return c;
    }

    /** Bit i from the LSB: i = 0 is the low bit of the last octet. */
    public int bit(int i) {
        if (i < 0 || i >= nbits) throw new BaException(BaException.E_RANGE, "bit");
        return (b[b.length - 1 - i / 8] >>> (i % 8)) & 1;
    }

    @Override
    public String toString() { return "BitArray(" + nbits + ", 0x" + toHex() + ")"; }

    // ── integer arithmetic within the width ────────────────────────────────
    //
    // NOT part of BITARRAY.md, which specifies a BIT-STRING type: these are the
    // Java counterparts of herradura.h's ba_add256 / ba_sub256 / ba_mul256 and
    // Go's AddMod2n / SubMod2n / MulMod2n, ported rather than re-derived.  They
    // exist for the same reason those do — NL-FSCX v1 and v2 carry integer
    // addition into the round function — and keeping them here rather than
    // converting to BigInteger at each site is the point of the pass: a round
    // trip through a bignum is where a width gets lost.

    /** (this + other) mod 2^n. */
    public BitArray addMod2n(BitArray other) {
        sameWidth(other, "add");
        int nb = b.length;
        byte[] out = new byte[nb];
        int carry = 0;
        for (int i = nb - 1; i >= 0; i--) {
            int sum = (b[i] & 0xFF) + (other.b[i] & 0xFF) + carry;
            out[i] = (byte) sum;
            carry = sum >>> 8;
        }
        return new BitArray(nbits, out);
    }

    /** (this - other) mod 2^n. */
    public BitArray subMod2n(BitArray other) {
        sameWidth(other, "sub");
        int nb = b.length;
        byte[] out = new byte[nb];
        int borrow = 0;
        for (int i = nb - 1; i >= 0; i--) {
            int d = (b[i] & 0xFF) - (other.b[i] & 0xFF) - borrow;
            out[i] = (byte) d;
            borrow = (d < 0) ? 1 : 0;
        }
        return new BitArray(nbits, out);
    }

    /** (this * other) mod 2^n. */
    public BitArray mulMod2n(BitArray other) {
        sameWidth(other, "mul");
        int nb = b.length;
        long[] acc = new long[nb];
        for (int i = 0; i < nb; i++)
            for (int j = 0; j < nb - i; j++)
                acc[nb - 1 - i - j] += (b[nb - 1 - i] & 0xFFL) * (other.b[nb - 1 - j] & 0xFFL);
        byte[] out = new byte[nb];
        long carry = 0;
        for (int i = nb - 1; i >= 0; i--) {
            long sum = acc[i] + carry;
            out[i] = (byte) sum;
            carry = sum >>> 8;
        }
        return new BitArray(nbits, out);
    }

    /** (this + v) mod 2^n for a small non-negative v. */
    public BitArray addUint(long v) { return addMod2n(fromUint(v, nbits)); }

    /** this XOR v, with v taken as a value of this width. */
    public BitArray xorUint(long v) { return xor(fromUint(v, nbits)); }

    // ── suite primitives (BITARRAY.md §4.6) ────────────────────────────────

    /** a ^ b ^ ROL(a,1) ^ ROL(b,1) ^ ROR(a,1) ^ ROR(b,1) at the common width. */
    public static BitArray fscx(BitArray a, BitArray b) {
        a.sameWidth(b, "fscx");
        return a.xor(b).xor(a.rotLeft(1)).xor(b.rotLeft(1))
                .xor(a.rotRight(1)).xor(b.rotRight(1));
    }

    /** fscx applied i times with b held constant; i == 0 is the identity. */
    public static BitArray fscxRevolve(BitArray a, BitArray b, int steps) {
        if (steps < 0) throw new BaException(BaException.E_RANGE, "fscx_revolve");
        BitArray r = a;
        for (int i = 0; i < steps; i++) r = fscx(r, b);
        return r;
    }

    /**
     * The primitive polynomial for width n (BITARRAY.md §4.6).  A width with no
     * entry is E_NO_POLY — never a default.  The width SELECTS it, so a caller
     * cannot hand in one that does not match the operands.
     */
    public static BitArray gfPoly(int n) {
        switch (n) {
            case 32:  return fromUint(0x00400007L, n);
            case 64:  return fromUint(0x0000001BL, n);
            case 128: return fromUint(0x00000087L, n);
            case 256: return fromUint(0x00000425L, n);
            default:  throw new BaException(BaException.E_NO_POLY, "gf_poly");
        }
    }

    /**
     * a·b in GF(2^n) at the operands' common width.  Same schedule as the other
     * three ports: consume b from the LSB up while doubling a, both
     * constant-time in the operands.
     */
    public static BitArray gfMul(BitArray a, BitArray b) {
        a.sameWidth(b, "gf_mul");
        int n = a.nbits, nb = a.b.length;
        BitArray poly = gfPoly(n);
        byte[] r = new byte[nb];
        byte[] aa = Arrays.copyOf(a.b, nb);
        byte[] bb = Arrays.copyOf(b.b, nb);
        for (int i = 0; i < n; i++) {
            int bitMask = -(bb[nb - 1] & 1);
            for (int k = 0; k < nb; k++) r[k] ^= (byte) (aa[k] & bitMask);
            int carryMask = -((aa[0] >>> 7) & 1);
            aa = new BitArray(n, aa).shl(1).b;
            for (int k = 0; k < nb; k++) aa[k] ^= (byte) (poly.b[k] & carryMask);
            bb = new BitArray(n, bb).shr(1).b;
        }
        return new BitArray(n, r);
    }

    /** base^e in GF(2^n) for a machine-word exponent (BITARRAY.md §4.6). */
    public static BitArray gfPow(BitArray base, long e) {
        if (e < 0) throw new BaException(BaException.E_RANGE, "gf_pow");
        int n = base.nbits;
        gfPoly(n);                       // the width must have a polynomial
        BitArray r = fromUint(1, n), bb = base;
        while (e != 0) {
            if ((e & 1) != 0) r = gfMul(r, bb);
            bb = gfMul(bb, bb);
            e >>>= 1;
        }
        return r;
    }

    /** The 256-bit KDF domain constant (TODO #38). */
    public static final BitArray RNL_KDF_DC_256 = fromHex(
        "6a09e667bb67ae853c6ef372a54ff53a510e527f9b05688c1f83d9ab5be0cd19", 256);

    /**
     * ROL(k, n/8) XOR truncate(RNL_KDF_DC_256, n) — the TODO #313 site.
     *
     * <p>The truncation is §4.4's: the HIGH bits, the big-endian prefix.  THIS
     * PORT HAD NO SUCH FUNCTION before pass 5 — the expression was transcribed
     * at each call site against a 256-bit constant, which is TODO #312's shape
     * and is why "exactly one truncation, in one place" was not available here.
     */
    public static BitArray rnlKdfSeed(BitArray k) {
        return k.rotLeft(k.nbits / 8).xor(RNL_KDF_DC_256.truncate(k.nbits));
    }
}
