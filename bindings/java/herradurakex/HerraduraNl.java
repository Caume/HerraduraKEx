package herradurakex;

import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * TODO #199: pure-Java port of the NL/PQC (v1.5.0+) quartet — HKEX-RNL
 * (Ring-LWR key exchange), HSKE-NL-A1 (counter-mode) / HSKE-NL-A2
 * (revolve-mode), HPKS-NL (Schnorr with NL-FSCX v1 challenge), and HPKE-NL
 * (El Gamal with NL-FSCX v2) — plus the NL-FSCX v2 primitive and the
 * Ring-LWR ring arithmetic (negacyclic NTT over Z_65537) underlying
 * HKEX-RNL. NL-FSCX v1 already lives in {@link Hfscx256} (TODO #198,
 * needed there for HFSCX-256-DM/HSKE-NL-A1 file-container parity); this
 * class reuses {@link Hfscx256#nlFscxV1}/{@link Hfscx256#nlFscxRevolveV1}
 * rather than duplicating them.
 *
 * Byte-for-byte port of "Herradura cryptographic suite.py"'s nl_fscx_v2
 * family, _rnl_* ring-arithmetic helpers, and hkex_rnl_keygen/
 * hkex_rnl_agree, at n=RNLN=1024 (RNLQ=65537, RNLP=4096, RNLPP=4, RNLB=1 —
 * matching HerraduraCli/herradura.py's constants).
 */
public final class HerraduraNl {
    private HerraduraNl() { }

    private static final int N = Herradura.N;               // 256
    private static final BigInteger MASK = Herradura.MASK;

    /**
     * Ring dimension for HKEX-RNL (TODO #223).  Deliberately NOT tied to the key
     * width: the ring must be 1024 to reach 128-bit security, while the derived
     * session key stays 256 bits.  n=256 gives only ~32 Core-SVP bits and n=512
     * only ~87 (TODO #216); n=768 is unsound because x^768+1 factors over Z, so
     * the ring CRT-splits and the instance projects down to ~39 bits.
     */
    public static final int RNLN = 1024;
    public static final int RNLQ = 65537;  // prime modulus (2^16 + 1)
    public static final int RNLP = 4096;   // public-key rounding modulus
    public static final int RNLPP = 4;     // reconciliation modulus
    public static final int RNLB = 1;      // CBD(1) secret coefficients

    // -----------------------------------------------------------------
    // NL-FSCX v2: (fscx(A,B) + delta(B)) mod 2^n, delta(B) = ROL(B*(B+1)/2, n/4)
    // Bijective in A; exact inverse via M^{-1}.
    // -----------------------------------------------------------------

    private static BigInteger delta(BigInteger b) {
        // Matches "Herradura cryptographic suite.py"'s literal nl_fscx_v2 delta:
        // B * ((B+1) >> 1) mod 2^n — NOT (B*(B+1))>>1 (they differ when B is even).
        BigInteger bb = b.and(MASK);
        BigInteger t = bb.multiply(bb.add(BigInteger.ONE).shiftRight(1)).and(MASK);
        return Herradura.rol(t, N / 4);
    }

    public static BigInteger nlFscxV2(BigInteger a, BigInteger b) {
        return Herradura.fscx(a, b).add(delta(b)).and(MASK);
    }

    public static BigInteger nlFscxV2Inv(BigInteger y, BigInteger b) {
        BigInteger d = delta(b);
        BigInteger z = y.subtract(d).and(MASK);
        return b.xor(mInv(z));
    }

    /** Round constant (TODO #245): the 1-based round index is XORed into the
     * state before each step, so the cipher stops being F_B^steps. Without it
     * every round is the identical map, which is the self-similarity
     * SecurityProofs-7.md §11.25/§11.26 found against. An XOR constant leaves
     * xdp+ exactly invariant, so TODO #214's trail bounds carry over verbatim.
     * Wire-format breaking; see MIGRATING.md §9. */
    public static BigInteger nlFscxRevolveV2(BigInteger a, BigInteger b, int steps) {
        BigInteger d = delta(b);
        BigInteger result = a.and(MASK);
        for (int i = 1; i <= steps; i++) {
            result = Herradura.fscx(result.xor(BigInteger.valueOf(i)), b).add(d).and(MASK);
        }
        return result;
    }

    public static BigInteger nlFscxRevolveV2Inv(BigInteger y, BigInteger b, int steps) {
        BigInteger d = delta(b);
        BigInteger result = y.and(MASK);
        for (int i = steps; i >= 1; i--) {
            BigInteger z = result.subtract(d).and(MASK);
            result = b.xor(mInv(z)).xor(BigInteger.valueOf(i));   // undo the round constant
        }
        return result;
    }

    /** Rejects NL-FSCX v2 keys for which delta(B) collapses the permutation to
     * affine (delta in {0, 2^(n-1)}) — TODO #159/#168.
     *
     * <p>SCOPE (TODO #253): the affine class only, NOT the full set of
     * differentially weak keys.  Keys admitting a zero-weight differential
     * trail are a strictly larger family — every B with tz(delta(B)) &gt;= 4,
     * at every width including n=256 — and this check accepts all of it
     * except the two endpoints.  Deliberate: at n=256 such a key forfeits
     * about tz/2 of 192 rounds with probability ~2^-tz, so a random key loses
     * at most 3 rounds with probability 1/16.  See SecurityProofs-7.md
     * §11.28.3-§11.28.4. */
    public static boolean nlV2KeyIsValid(BigInteger b) {
        BigInteger d = delta(b);
        return !d.equals(BigInteger.ZERO) && !d.equals(BigInteger.ONE.shiftLeft(N - 1));
    }

    // -----------------------------------------------------------------
    // NL-FSCX v3 (TODO #255) — the v2 round followed by a Keccak-chi layer
    //
    // v3 is an ADDITION, not a replacement: v2 is untouched and every stored v2
    // artifact keeps working.  The round is
    //
    //     x -> chi( M(x ^ i ^ B) + delta(B) mod 2^n )
    //
    // i.e. exactly nlFscxV2 followed by chi over a partition of the state into
    // short odd rows.  chi is bijective on a row of odd length, so the layer is
    // a bijection on the whole state and the round stays invertible.
    //
    // THE PARTITION at n=256 is 256 = 47*5 + 3*7, the 5-rows first, so the LSB
    // is in a 5-row.  v3Rows derives it, and the same rule at any other width.
    //
    // MINIMUM ROW LENGTH 5 IS A HARD CONSTRAINT, not a preference.  Oddness
    // alone is NOT sufficient and 3 is odd: a 3-bit row admits a correlation-1
    // one-round linear approximation -- exhaustive over all 8 row-deltas and
    // both carry-ins -- which is a complete break at any round count.  At L=5
    // the worst is 0.875 and at L=7 it is 0.71875, for every key at every
    // width.  v3Rows emits only 5s and 7s, so the constraint holds by
    // construction.  See SecurityProofs-7.md §11.33.4 and §11.34.2.
    //
    // ROUND COUNT: R3_VALUE = 5n/8 = 160, DERIVED, not inherited from v2's
    // 3n/4.  chi gives the round an unconditional per-round differential trail
    // floor of 4 - log2(5) = 1.6781 bits -- the lowest active row of a pair
    // always shares its carry-in, so it always pays the same-carry cost -- and
    // §11.30.1's criterion s_diff * r >= n then needs r >= 153.  v2 has no such
    // floor at all.  See SecurityProofs-7.md §11.33, §11.34 and
    // SecurityProofsCode/nl_fscx_v3_round_count.py, nl_fscx_v3_weak_keys.py.
    //
    // NO KEY CHECK.  There is deliberately no nlV3KeyIsValid.  v2's two weak
    // classes are both artefacts of its round being linear-then-add-constant
    // and both dissolve under chi.  See §11.34.4 and §11.34.7.
    //
    // Ratings: DEMO-ONLY, exactly like v2.
    // -----------------------------------------------------------------

    /** NL-FSCX v3's round count at the suite's 256-bit width: 5n/8 = 160. */
    public static final int R3_VALUE = 5 * N / 8;

    /**
     * chi row partition for width {@code n}: 5-bit rows then 7-bit rows, the
     * unique such partition with the fewest 7-rows.  Both lengths are odd and
     * &gt;= 5, so the minimum-row-5 constraint holds by construction.  At
     * n = 256 this is 47 fives then 3 sevens.
     *
     * @throws IllegalArgumentException if {@code n} admits no such partition
     *         (n &lt; 5, or n in {6, 8, 9, 11, 13}); the deployed widths all do.
     */
    public static int[] v3Rows(int n) {
        for (int k = 0; k * 7 <= n; k++) {
            int rest = n - 7 * k;
            if (rest % 5 == 0) {
                int[] rows = new int[rest / 5 + k];
                for (int i = 0; i < rest / 5; i++) rows[i] = 5;
                for (int i = 0; i < k; i++) rows[rest / 5 + i] = 7;
                return rows;
            }
        }
        throw new IllegalArgumentException(
            "NL-FSCX v3: width " + n
            + " admits no all-odd row partition with every row >= 5");
    }

    /** Keccak chi on one row of length L held in the low bits of v:
     * out_i = b_i XOR ((NOT b_(i+1)) AND b_(i+2)), indices cyclic in the row. */
    private static int chiRow(int v, int L) {
        int out = 0;
        for (int i = 0; i < L; i++) {
            int bi = (v >>> i) & 1;
            int b1 = (v >>> ((i + 1) % L)) & 1;
            int b2 = (v >>> ((i + 2) % L)) & 1;
            out |= (bi ^ ((1 - b1) & b2)) << i;
        }
        return out;
    }

    /** Inverse of chi on a row of length L, by table.  Building it also asserts
     * chi is a bijection there -- the property the whole layer rests on. */
    private static int[] chiRowInvTable(int L) {
        int n = 1 << L;
        int[] inv = new int[n];
        boolean[] seen = new boolean[n];
        for (int x = 0; x < n; x++) {
            int y = chiRow(x, L);
            if (seen[y]) {
                throw new IllegalStateException(
                    "NL-FSCX v3: chi is not a bijection on a " + L + "-bit row");
            }
            seen[y] = true;
            inv[y] = x;
        }
        return inv;
    }

    private static final int[] CHI_INV5 = chiRowInvTable(5);
    private static final int[] CHI_INV7 = chiRowInvTable(7);

    private static int[] chiInvFor(int L) {
        if (L == 5) return CHI_INV5;
        if (L == 7) return CHI_INV7;
        return chiRowInvTable(L);
    }

    /** Apply the chi layer to a 256-bit value, row by row. */
    public static BigInteger nlChiV3(BigInteger x) {
        BigInteger v = x.and(MASK);
        BigInteger out = BigInteger.ZERO;
        int off = 0;
        for (int L : v3Rows(N)) {
            int row = v.shiftRight(off).and(BigInteger.valueOf((1L << L) - 1)).intValue();
            out = out.or(BigInteger.valueOf(chiRow(row, L)).shiftLeft(off));
            off += L;
        }
        return out;
    }

    /** Invert the chi layer. */
    public static BigInteger nlChiV3Inv(BigInteger y) {
        BigInteger v = y.and(MASK);
        BigInteger out = BigInteger.ZERO;
        int off = 0;
        for (int L : v3Rows(N)) {
            int row = v.shiftRight(off).and(BigInteger.valueOf((1L << L) - 1)).intValue();
            out = out.or(BigInteger.valueOf(chiInvFor(L)[row]).shiftLeft(off));
            off += L;
        }
        return out;
    }

    /** NL-FSCX v3: chi(nlFscxV2(a, b)).  Bijective in a for all b. */
    public static BigInteger nlFscxV3(BigInteger a, BigInteger b) {
        return nlChiV3(nlFscxV2(a, b));
    }

    /** Exact inverse of one nlFscxV3 step. */
    public static BigInteger nlFscxV3Inv(BigInteger y, BigInteger b) {
        return nlFscxV2Inv(nlChiV3Inv(y), b);
    }

    /** Iterate nlFscxV3 {@code steps} times (b held constant).  The round
     * constant is v2's, unchanged: an XOR constant leaves xdp+ exactly
     * invariant (TODO #245), and chi does not interact with that argument. */
    public static BigInteger nlFscxRevolveV3(BigInteger a, BigInteger b, int steps) {
        BigInteger d = delta(b);
        BigInteger result = a.and(MASK);
        for (int i = 1; i <= steps; i++) {
            result = nlChiV3(Herradura.fscx(result.xor(BigInteger.valueOf(i)), b)
                             .add(d).and(MASK));
        }
        return result;
    }

    /** Invert nlFscxRevolveV3. */
    public static BigInteger nlFscxRevolveV3Inv(BigInteger y, BigInteger b, int steps) {
        BigInteger d = delta(b);
        BigInteger result = y.and(MASK);
        for (int i = steps; i >= 1; i--) {
            BigInteger z = nlChiV3Inv(result).subtract(d).and(MASK);
            result = b.xor(mInv(z)).xor(BigInteger.valueOf(i));  // undo the round constant
        }
        return result;
    }

    // M^{-1} = M^{n/2-1}, bootstrapped once from fscx_revolve(1, 0, n/2-1) and
    // applied as an XOR of ROL(X, k) for each set bit k of that bootstrap value.
    private static int[] mInvRotations;

    private static synchronized int[] mInvRotationsTable() {
        if (mInvRotations == null) {
            BigInteger v = Herradura.fscxRevolve(BigInteger.ONE, BigInteger.ZERO, N / 2 - 1);
            int count = v.bitCount();
            int[] table = new int[count];
            int idx = 0;
            for (int k = 0; k < N; k++) {
                if (v.testBit(k)) table[idx++] = k;
            }
            mInvRotations = table;
        }
        return mInvRotations;
    }

    private static BigInteger mInv(BigInteger x) {
        BigInteger result = BigInteger.ZERO;
        for (int k : mInvRotationsTable()) {
            result = result.xor(Herradura.rol(x, k));
        }
        return result;
    }

    // -----------------------------------------------------------------
    // HKEX-RNL ring arithmetic — negacyclic Z_q[x]/(x^n+1), q = RNLQ = 65537
    // (Fermat prime 2^16+1, primitive root 3). Ports "Herradura cryptographic
    // suite.py"'s _ntt_inplace/_rnl_poly_mul et al.
    // -----------------------------------------------------------------

    private static long modPow(long base, long exp, long mod) {
        long result = 1;
        base %= mod;
        if (base < 0) base += mod;
        while (exp > 0) {
            if ((exp & 1) != 0) result = (result * base) % mod;
            base = (base * base) % mod;
            exp >>= 1;
        }
        return result;
    }

    private static void nttInplace(long[] a, int q, boolean invert) {
        int n = a.length;
        int j = 0;
        for (int i = 1; i < n; i++) {
            int bit = n >> 1;
            while ((j & bit) != 0) {
                j ^= bit;
                bit >>= 1;
            }
            j ^= bit;
            if (i < j) {
                long tmp = a[i]; a[i] = a[j]; a[j] = tmp;
            }
        }
        for (int length = 2; length <= n; length <<= 1) {
            long w = modPow(3, (q - 1) / length, q);
            if (invert) w = modPow(w, q - 2, q);
            for (int i = 0; i < n; i += length) {
                long wn = 1;
                int half = length >> 1;
                for (int k = 0; k < half; k++) {
                    long u = a[i + k];
                    long v = a[i + k + half] * wn % q;
                    a[i + k] = (u + v) % q;
                    a[i + k + half] = ((u - v) % q + q) % q;
                    wn = wn * w % q;
                }
            }
        }
        if (invert) {
            long invN = modPow(n, q - 2, q);
            for (int i = 0; i < n; i++) a[i] = a[i] * invN % q;
        }
    }

    /** Multiplies f*g in Z_q[x]/(x^n+1) via negacyclic NTT. */
    public static int[] rnlPolyMul(int[] f, int[] g, int q, int n) {
        long psi = modPow(3, (q - 1) / (2L * n), q);
        long psiInv = modPow(psi, q - 2, q);
        long[] fa = new long[n];
        long[] ga = new long[n];
        long pw = 1;
        for (int i = 0; i < n; i++) {
            fa[i] = f[i] * pw % q;
            ga[i] = g[i] * pw % q;
            pw = pw * psi % q;
        }
        nttInplace(fa, q, false);
        nttInplace(ga, q, false);
        long[] ha = new long[n];
        for (int i = 0; i < n; i++) ha[i] = fa[i] * ga[i] % q;
        nttInplace(ha, q, true);
        long pwInv = 1;
        int[] out = new int[n];
        for (int i = 0; i < n; i++) {
            out[i] = (int) (ha[i] * pwInv % q);
            pwInv = pwInv * psiInv % q;
        }
        return out;
    }

    public static int[] rnlPolyAdd(int[] f, int[] g, int q) {
        int n = f.length;
        int[] out = new int[n];
        for (int i = 0; i < n; i++) out[i] = (f[i] + g[i]) % q;
        return out;
    }

    /** Rounds each coefficient from Z_{fromQ} to Z_{toP} (nearest integer). */
    public static int[] rnlRound(int[] poly, int fromQ, int toP) {
        int[] out = new int[poly.length];
        for (int i = 0; i < poly.length; i++) {
            long c = poly[i];
            out[i] = (int) (((c * toP + fromQ / 2) / fromQ) % toP);
        }
        return out;
    }

    /** Lifts from Z_{fromP} to Z_{toQ} with centered rounding. */
    public static int[] rnlLift(int[] poly, int fromP, int toQ) {
        int[] out = new int[poly.length];
        for (int i = 0; i < poly.length; i++) {
            long c = poly[i];
            out[i] = (int) (((c * toQ + fromP / 2) / fromP) % toQ);
        }
        return out;
    }

    /** FSCX polynomial m(x) = 1 + x + x^(n-1) as a coefficient list in Z_q. */
    public static int[] rnlMPoly(int n) {
        int[] p = new int[n];
        p[0] = 1;
        p[1] = 1;
        p[n - 1] = 1;
        return p;
    }

    /** Uniform random polynomial in Z_q^n via 3-byte rejection sampling. */
    public static int[] rnlRandPoly(int n, int q, SecureRandom rng) {
        int threshold = (1 << 24) - (1 << 24) % q;
        int[] out = new int[n];
        byte[] buf = new byte[3];
        int idx = 0;
        while (idx < n) {
            rng.nextBytes(buf);
            int v = ((buf[0] & 0xff) << 16) | ((buf[1] & 0xff) << 8) | (buf[2] & 0xff);
            if (v < threshold) {
                out[idx++] = v % q;
            }
        }
        return out;
    }

    /** CBD(1) polynomial: coefficient = a - b (mod q), a/b each one random bit. */
    public static int[] rnlCbdPoly(int n, int q, SecureRandom rng) {
        byte[] raw = new byte[(n + 3) / 4];
        rng.nextBytes(raw);
        int[] out = new int[n];
        for (int i = 0; i < n; i++) {
            int shift = (i & 3) * 2;
            int a = (raw[i >> 2] >> shift) & 1;
            int b = (raw[i >> 2] >> (shift + 1)) & 1;
            out[i] = ((a - b) % q + q) % q;
        }
        return out;
    }

    /** 2-bit Peikert cross-rounding hint per coefficient. */
    public static int[] rnlHint(int[] kPoly, int q) {
        int[] hint = new int[kPoly.length];
        for (int i = 0; i < kPoly.length; i++) {
            long c = kPoly[i];
            hint[i] = (int) (((8 * c + q / 4) / q) % 4);
        }
        return hint;
    }

    /** Extracts keyBits key bits: 2 bits per coefficient from keyBits/2 coefficients. */
    public static BigInteger rnlReconcileBits(int[] kPoly, int[] hint, int q, int pp, int keyBits) {
        BigInteger val = BigInteger.ZERO;
        long qq = q / 4;
        int coeffs = keyBits / 2;
        for (int i = 0; i < coeffs; i++) {
            long c = kPoly[i];
            long h = hint[i];
            long b = ((4 * c + (2 * h + 1) * qq) / q) % pp;
            val = val.or(BigInteger.valueOf(b).shiftLeft(2 * i));
        }
        return val;
    }

    // -----------------------------------------------------------------
    // HKEX-RNL: keygen / agree
    // -----------------------------------------------------------------

    public static final class RnlKeypair {
        public final int[] s;   // private CBD(b) polynomial
        public final int[] c;   // public rounded polynomial
        public RnlKeypair(int[] s, int[] c) { this.s = s; this.c = c; }
    }

    /** Generates one party's (s, C) key pair given a (blinded) m polynomial. */
    public static RnlKeypair rnlKeygen(int[] mBlind, int n, int q, int p, SecureRandom rng) {
        int[] s = rnlCbdPoly(n, q, rng);
        int[] ms = rnlPolyMul(mBlind, s, q, n);
        int[] c = rnlRound(ms, q, p);
        return new RnlKeypair(s, c);
    }

    public static final class RnlAgreeResult {
        public final BigInteger key;
        public final int[] hint;
        public RnlAgreeResult(BigInteger key, int[] hint) { this.key = key; this.hint = hint; }
    }

    /** Reconciler path (generates and returns the hint alongside the key). */
    public static RnlAgreeResult rnlAgree(int[] s, int[] cOther, int q, int p, int pp, int n, int keyBits) {
        int[] cLifted = rnlLift(cOther, p, q);
        int[] kPoly = rnlPolyMul(s, cLifted, q, n);
        int[] hint = rnlHint(kPoly, q);
        return new RnlAgreeResult(rnlReconcileBits(kPoly, hint, q, pp, keyBits), hint);
    }

    /** Receiver path: reconciles using a hint supplied by the peer. */
    public static BigInteger rnlAgree(int[] s, int[] cOther, int q, int p, int pp, int n, int keyBits, int[] hint) {
        int[] cLifted = rnlLift(cOther, p, q);
        int[] kPoly = rnlPolyMul(s, cLifted, q, n);
        return rnlReconcileBits(kPoly, hint, q, pp, keyBits);
    }

    /** Returns true if poly looks like a uniform-random element of Z_q^n
     * (rejects sparse or narrow-range polys — TODO #? substitution guard). */
    public static boolean rnlValidateMBlind(int[] poly, int q) {
        int n = poly.length;
        int nz = 0;
        int min = Integer.MAX_VALUE, max = Integer.MIN_VALUE;
        for (int c : poly) {
            if (c != 0) nz++;
            if (c < min) min = c;
            if (c > max) max = c;
        }
        if (nz < n / 4) return false;
        return (max - min) >= q / 4;
    }

    /** Derives Alice's/Bob's C from her m_blind and s: C = round_p(m_blind * s). */
    public static int[] hkexRnlDeriveC(int[] mBlind, int[] s, int n) {
        int[] ms = rnlPolyMul(mBlind, s, RNLQ, n);
        return rnlRound(ms, RNLQ, RNLP);
    }

    /** Contributory KDF: HFSCX-256(K_raw_bytes || n_A || n_B). n_a/n_b must be 32 bytes. */
    public static BigInteger rnlContributoryKdf(BigInteger kRaw, int nBits, byte[] nA, byte[] nB) {
        byte[] kBytes = toFixedBytes(kRaw, nBits / 8);
        byte[] payload = new byte[kBytes.length + nA.length + nB.length];
        System.arraycopy(kBytes, 0, payload, 0, kBytes.length);
        System.arraycopy(nA, 0, payload, kBytes.length, nA.length);
        System.arraycopy(nB, 0, payload, kBytes.length + nA.length, nB.length);
        return new BigInteger(1, Hfscx256.hash(payload));
    }

    private static byte[] toFixedBytes(BigInteger v, int nbytes) {
        byte[] raw = v.and(MASK).toByteArray();
        byte[] out = new byte[nbytes];
        int rawStart = Math.max(0, raw.length - nbytes);
        int copyLen = raw.length - rawStart;
        System.arraycopy(raw, rawStart, out, nbytes - copyLen, copyLen);
        return out;
    }

    // -----------------------------------------------------------------
    // HSKE-NL-A1: counter-mode keystream:
    // base = K^nonce; seed = ROL(base, n/8) ^ RNL_KDF_DC_256 (n=256 => no shift);
    // ks = nl_fscx_revolve_v1(seed, base, n/4); E = P ^ ks.
    // -----------------------------------------------------------------

    public static BigInteger hskeNlA1Encrypt(BigInteger pt, BigInteger key, BigInteger nonce) {
        BigInteger base = key.xor(nonce).and(MASK);
        BigInteger seed = Herradura.rol(base, N / 8).xor(Hfscx256.RNL_KDF_DC_256).and(MASK);
        BigInteger ks = Hfscx256.nlFscxRevolveV1(seed, base, N / 4);
        return pt.xor(ks).and(MASK);
    }

    public static BigInteger hskeNlA1Decrypt(BigInteger ct, BigInteger key, BigInteger nonce) {
        return hskeNlA1Encrypt(ct, key, nonce); // XOR keystream is its own inverse
    }

    // -----------------------------------------------------------------
    // HSKE-NL-A2: revolve-mode, bijective NL-FSCX v2.
    // -----------------------------------------------------------------

    public static BigInteger hskeNlA2Encrypt(BigInteger pt, BigInteger key) {
        return nlFscxRevolveV2(pt, key, 3 * N / 4);
    }

    public static BigInteger hskeNlA2Decrypt(BigInteger ct, BigInteger key) {
        return nlFscxRevolveV2Inv(ct, key, 3 * N / 4);
    }

    // -----------------------------------------------------------------
    // HPKS-NL (Schnorr with NL-FSCX v1 challenge): same key/shape as
    // classical HPKS, only e = nl_fscx_revolve_v1(R, msg, n/4).
    // -----------------------------------------------------------------

    public static Herradura.Signature hpksNlSign(BigInteger msg, BigInteger priv, BigInteger k) {
        BigInteger r = Herradura.gfPow(Herradura.GF_GEN, k);
        BigInteger e = Hfscx256.nlFscxRevolveV1(r, msg, N / 4);
        BigInteger s = k.subtract(priv.multiply(e)).mod(Herradura.GROUP_ORDER);
        return new Herradura.Signature(r, s);
    }

    public static Herradura.Signature hpksNlSign(BigInteger msg, BigInteger priv, SecureRandom rng) {
        BigInteger k = new BigInteger(N, rng).and(MASK);
        return hpksNlSign(msg, priv, k);
    }

    public static boolean hpksNlVerify(BigInteger msg, BigInteger pub, BigInteger r, BigInteger s) {
        if (!Herradura.gfPubIsValid(pub)) return false;
        BigInteger e = Hfscx256.nlFscxRevolveV1(r, msg, N / 4);
        BigInteger lhs = Herradura.gfMul(Herradura.gfPow(Herradura.GF_GEN, s), Herradura.gfPow(pub, e));
        return lhs.equals(r.and(MASK));
    }

    // -----------------------------------------------------------------
    // HPKE-NL (El Gamal + NL-FSCX v2 revolve): same GF keypair shape as
    // classical HPKE, but the FSCX-revolve step is replaced by NL-FSCX v2.
    // -----------------------------------------------------------------

    public static Herradura.Ciphertext hpkeNlEncrypt(BigInteger pt, BigInteger pub, BigInteger r) {
        if (!Herradura.gfPubIsValid(pub)) return null;
        BigInteger bigR = Herradura.gfPow(Herradura.GF_GEN, r);
        BigInteger encKey = Herradura.gfPow(pub, r);
        BigInteger ct = nlFscxRevolveV2(pt, encKey, N / 4);
        return new Herradura.Ciphertext(bigR, ct);
    }

    /** Samples ephemeral scalars until the derived encryption key is a valid
     * (non-affine-degenerate) NL-FSCX v2 key, matching the CLI's resampling
     * loop (TODO #168) — returns null after 64 failed attempts. */
    public static Herradura.Ciphertext hpkeNlEncrypt(BigInteger pt, BigInteger pub, SecureRandom rng) {
        if (!Herradura.gfPubIsValid(pub)) return null;
        for (int i = 0; i < 64; i++) {
            BigInteger r = new BigInteger(N, rng).and(MASK);
            BigInteger bigR = Herradura.gfPow(Herradura.GF_GEN, r);
            BigInteger encKey = Herradura.gfPow(pub, r);
            if (nlV2KeyIsValid(encKey)) {
                BigInteger ct = nlFscxRevolveV2(pt, encKey, N / 4);
                return new Herradura.Ciphertext(bigR, ct);
            }
        }
        return null;
    }

    public static BigInteger hpkeNlDecrypt(BigInteger ct, BigInteger r, BigInteger priv) {
        if (!Herradura.gfPubIsValid(r)) return null;
        BigInteger decKey = Herradura.gfPow(r, priv);
        if (!nlV2KeyIsValid(decKey)) return null;
        return nlFscxRevolveV2Inv(ct, decKey, N / 4);
    }
}
