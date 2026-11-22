package herradurakex;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.List;

/**
 * Stern-F long form: N &gt; 256 (TODO #382 stage 2, v16.0.0).
 *
 * <p>The 128-bit parameter set is N = 2304, k = N/2 = 1152, t = N/16 = 144.
 * Its vectors are wider than BitArray's 256-bit capacity, so this path
 * carries them as BigIntegers (N/8 big-endian bytes on the wire) and keeps
 * BitArray for the 256-bit values.  The protocol is {@link Stern}'s; the
 * rules that change, all from Python's long-form block (SPEC.md §11):
 * <ul>
 * <li>hash: H_ds(x...) = HFSCX-256-DS(0x31, ds || x...), all 256 bits;
 *     commitments are 256 bits;</li>
 * <li>matrix: sk = H_6(seed); row i = chunk(i, 0) || ... || chunk(i, N/256-1),
 *     chunk(i, c) = HFSCX-256(i_hi || i_lo || c) with sk as the initial
 *     chaining value;</li>
 * <li>perm: {@link Stern#sternGenPerm} on the 256-bit k = H_5(piSeed), over
 *     N positions;</li>
 * <li>message: 256 bits; the Fiat-Shamir state advances by nl_fscx_v1 at
 *     256 bits.</li>
 * </ul>
 * Signatures reuse {@link Stern.SternSignature} and
 * {@link SternRing.RingSignature}: commitments are 256-bit values there.
 */
public final class SternL {
    private SternL() { }

    /** The long form's one listed code length (TODO #382). */
    public static final int STERN_LONG_N = 2304;
    static final int W = 256;
    static final int DS_PERM = 5;
    static final int DS_MATRIX = 6;

    public static boolean isLong(int n) { return n > Herradura.N; }

    static void check(int n) {
        if (n <= Herradura.N || n % 256 != 0)
            throw new IllegalArgumentException("Stern-F long form: N = " + n
                + " (expected a multiple of 256 above 256)");
    }

    /** v as exactly nb big-endian bytes (v must fit). */
    static byte[] fixed(BigInteger v, int nb) {
        byte[] raw = v.toByteArray();
        byte[] out = new byte[nb];
        int start = Math.max(0, raw.length - nb);
        System.arraycopy(raw, start, out, nb - (raw.length - start), raw.length - start);
        return out;
    }

    /** H_ds = HFSCX-256-DS(0x31, ds || items), all 256 bits. */
    static BigInteger hash(int ds, byte[]... items) {
        int len = 1;
        for (byte[] it : items) len += it.length;
        byte[] buf = new byte[len];
        buf[0] = (byte) ds;
        int off = 1;
        for (byte[] it : items) { System.arraycopy(it, 0, buf, off, it.length); off += it.length; }
        return new BigInteger(1, Hfscx256.hashDs(HerraduraNl.STERN_DS_HASH, buf));
    }

    static byte[] bytesN(BigInteger v, int n) { return fixed(v, n / 8); }

    /** The N/2 rows of H as N-bit BigIntegers. */
    public static BigInteger[] buildH(BigInteger seed, int n) {
        check(n);
        BitArray sk = BitArray.fromBigInteger(hash(DS_MATRIX, bytesN(seed, n)), W);
        int chunks = n / 256;
        BigInteger[] rows = new BigInteger[n / 2];
        for (int i = 0; i < n / 2; i++) {
            byte[] row = new byte[n / 8];
            for (int c = 0; c < chunks; c++) {
                byte[] d = Hfscx256.hash(new byte[] { (byte) (i >> 8), (byte) i, (byte) c }, sk);
                System.arraycopy(d, 0, row, 32 * c, 32);
            }
            rows[i] = new BigInteger(1, row);
        }
        return rows;
    }

    public static BigInteger syndrome(BigInteger seed, BigInteger e, int n) {
        return Stern.sternSyndromeH(buildH(seed, n), e);
    }

    static int[] genPerm(BigInteger piSeed, int n) {
        // Stern.sternGenPerm(k, n) runs its PRNG at k's width; k is 256 bits
        // and the permutation is over n positions.
        return genPermOnKey(BitArray.fromBigInteger(hash(DS_PERM, bytesN(piSeed, n)), W), n);
    }

    /** Stern.sternGenPerm's generator with the PRNG at the key's 256-bit width. */
    static int[] genPermOnKey(BitArray k, int n) {
        BitArray key = k.rotLeft(W / 8);
        int[] perm = new int[n];
        for (int i = 0; i < n; i++) perm[i] = i;
        BitArray st = k;
        int nb = W / 8;
        byte[] buf = new byte[nb];
        int cursor = nb;
        for (int i = n - 1; i > 0; i--) {
            int range = i + 1;
            if (cursor + 4 > nb) {
                st = Hfscx256.nlFscxV1(st, key);
                buf = st.toBytes();
                cursor = 0;
            }
            long v = ((long) (buf[cursor] & 0xff) << 24) | ((buf[cursor + 1] & 0xff) << 16)
                    | ((buf[cursor + 2] & 0xff) << 8) | (buf[cursor + 3] & 0xff);
            cursor += 4;
            int kk = (int) ((v * range) >> 32);
            int tmp = perm[i]; perm[i] = perm[kk]; perm[kk] = tmp;
        }
        return perm;
    }

    public static Stern.SternKeypair keygen(int n, SecureRandom rng) {
        check(n);
        BigInteger seed = new BigInteger(n, rng);
        BigInteger e = Stern.csprngWeightT(n, n / 16, rng);
        return new Stern.SternKeypair(seed, e, Stern.sternSyndromeH(buildH(seed, n), e));
    }

    /** One prover round on the caller's uniform r and pi (drawn in that
     * order): {c0, c1, c2, r, y, pi, sr, sy}. */
    private static BigInteger[] commit(BigInteger[] h, BigInteger e, BigInteger r, BigInteger pi, int n) {
        BigInteger y = e.xor(r);
        int[] perm = genPerm(pi, n);
        BigInteger hr = Stern.sternSyndromeH(h, r);
        BigInteger sr = Stern.sternApplyPerm(perm, r);
        BigInteger sy = Stern.sternApplyPerm(perm, y);
        return new BigInteger[] { hash(1, bytesN(pi, n), bytesN(hr, n)), hash(2, bytesN(sr, n)), hash(3, bytesN(sy, n)),
                                  r, y, pi, sr, sy };
    }

    private static BigInteger[] respond(int ch, BigInteger[] d) {
        switch (ch) {
            case 0: return new BigInteger[] { d[6], d[7] };
            case 1: return new BigInteger[] { d[5], d[3] };
            default: return new BigInteger[] { d[5], d[4] };
        }
    }

    private static BitArray fsState(BigInteger msg, BigInteger[] flatCommits) {
        byte[][] items = new byte[1 + flatCommits.length][];
        items[0] = fixed(msg, W / 8);
        for (int i = 0; i < flatCommits.length; i++) items[1 + i] = fixed(flatCommits[i], W / 8);
        return BitArray.fromBigInteger(hash(0, items), W);
    }

    private static final BigInteger WORD32 = BigInteger.valueOf(0xFFFFFFFFL);
    private static final BigInteger THREE = BigInteger.valueOf(3);

    private static int[] chain(BitArray st, int rounds) {
        int[] out = new int[rounds];
        for (int i = 0; i < rounds; i++) {
            st = Hfscx256.nlFscxV1(st, BitArray.fromUint(i, W));
            out[i] = st.toBigInteger().and(WORD32).mod(THREE).intValueExact();
        }
        return out;
    }

    static boolean checkRound(int b, BigInteger c0, BigInteger c1, BigInteger c2,
                              BigInteger a, BigInteger v, BigInteger[] h, BigInteger syn, int n) {
        if (a.signum() < 0 || v.signum() < 0 || a.bitLength() > n || v.bitLength() > n) return false;
        if (b == 0)
            return hash(2, bytesN(a, n)).equals(c1) && hash(3, bytesN(v, n)).equals(c2)
                && a.xor(v).bitCount() == n / 16;
        int[] perm = genPerm(a, n);
        BigInteger hv = Stern.sternSyndromeH(h, v);
        BigInteger sv = Stern.sternApplyPerm(perm, v);
        if (b == 1)
            return hash(1, bytesN(a, n), bytesN(hv, n)).equals(c0) && hash(2, bytesN(sv, n)).equals(c1);
        if (b == 2)
            return hash(1, bytesN(a, n), bytesN(hv.xor(syn), n)).equals(c0) && hash(3, bytesN(sv, n)).equals(c2);
        return false;
    }

    /** Long-form signature on a 256-bit msg. */
    public static Stern.SternSignature sign(BigInteger msg, BigInteger e, BigInteger seed,
                                            int rounds, int n, SecureRandom rng) {
        BigInteger[] h = buildH(seed, n);
        BigInteger[] c0 = new BigInteger[rounds], c1 = new BigInteger[rounds], c2 = new BigInteger[rounds];
        BigInteger[][] data = new BigInteger[rounds][];
        BigInteger[] flat = new BigInteger[3 * rounds];
        for (int i = 0; i < rounds; i++) {
            BigInteger r = new BigInteger(n, rng), pi = new BigInteger(n, rng);
            data[i] = commit(h, e, r, pi, n);
            c0[i] = data[i][0]; c1[i] = data[i][1]; c2[i] = data[i][2];
            flat[3 * i] = c0[i]; flat[3 * i + 1] = c1[i]; flat[3 * i + 2] = c2[i];
        }
        int[] ch = chain(fsState(msg, flat), rounds);
        BigInteger[] r0 = new BigInteger[rounds], r1 = new BigInteger[rounds];
        for (int i = 0; i < rounds; i++) {
            BigInteger[] rr = respond(ch[i], data[i]);
            r0[i] = rr[0]; r1[i] = rr[1];
        }
        return new Stern.SternSignature(c0, c1, c2, ch, r0, r1);
    }

    public static boolean verify(BigInteger msg, Stern.SternSignature sig, BigInteger seed,
                                 BigInteger syn, int n) {
        int rounds = sig.rounds();
        if (rounds == 0) return false;
        BigInteger[] flat = new BigInteger[3 * rounds];
        for (int i = 0; i < rounds; i++) {
            flat[3 * i] = sig.c0[i]; flat[3 * i + 1] = sig.c1[i]; flat[3 * i + 2] = sig.c2[i];
        }
        int[] ch = chain(fsState(msg, flat), rounds);
        for (int i = 0; i < rounds; i++) if (ch[i] != sig.challenges[i]) return false;
        BigInteger[] h = buildH(seed, n);
        for (int i = 0; i < rounds; i++)
            if (!checkRound(sig.challenges[i], sig.c0[i], sig.c1[i], sig.c2[i],
                            sig.resp0[i], sig.resp1[i], h, syn, n)) return false;
        return true;
    }

    /** SternRing's simulator, draw for draw, on the long-form primitives:
     * {c0, c1, c2, respA, respB}. */
    private static BigInteger[] simulate(int b, BigInteger syn, BigInteger[] h, int n, SecureRandom rng) {
        if (b == 0) {
            BigInteger sr = new BigInteger(n, rng);
            BigInteger sy = sr.xor(Stern.csprngWeightT(n, n / 16, rng));
            BigInteger piDum = new BigInteger(n, rng);
            return new BigInteger[] { hash(1, bytesN(piDum, n), bytesN(BigInteger.ZERO, n)),
                                      hash(2, bytesN(sr, n)), hash(3, bytesN(sy, n)), sr, sy };
        }
        BigInteger pi = new BigInteger(n, rng);
        BigInteger v = new BigInteger(n, rng);
        int[] perm = genPerm(pi, n);
        BigInteger hv = Stern.sternSyndromeH(h, v);
        BigInteger sv = Stern.sternApplyPerm(perm, v);
        BigInteger dum = new BigInteger(n, rng);
        if (b == 1)
            return new BigInteger[] { hash(1, bytesN(pi, n), bytesN(hv, n)), hash(2, bytesN(sv, n)),
                                      hash(3, bytesN(dum, n)), pi, v };
        return new BigInteger[] { hash(1, bytesN(pi, n), bytesN(hv.xor(syn), n)), hash(2, bytesN(dum, n)),
                                  hash(3, bytesN(sv, n)), pi, v };
    }

    private static BitArray ringState(BigInteger msg, BigInteger[][] c0, BigInteger[][] c1, BigInteger[][] c2) {
        int k = c0.length, rounds = c0[0].length;
        BigInteger[] flat = new BigInteger[3 * k * rounds];
        int idx = 0;
        for (int i = 0; i < k; i++)
            for (int r = 0; r < rounds; r++) {
                flat[idx++] = c0[i][r]; flat[idx++] = c1[i][r]; flat[idx++] = c2[i][r];
            }
        return fsState(msg, flat);
    }

    /** Long-form ring signature as member j (SternRing's member-major order
     * and challenge splitting). */
    public static SternRing.RingSignature ringSign(BigInteger msg, BigInteger e, int j,
                                                   List<SternRing.RingKey> ring, int rounds, int n,
                                                   SecureRandom rng) {
        int k = ring.size();
        BigInteger[][] c0 = new BigInteger[k][rounds], c1 = new BigInteger[k][rounds], c2 = new BigInteger[k][rounds];
        BigInteger[][] r0 = new BigInteger[k][rounds], r1 = new BigInteger[k][rounds];
        int[][] ch = new int[k][rounds];
        for (int i = 0; i < k; i++) {
            if (i == j) continue;
            BigInteger[] h = buildH(ring.get(i).seed, n);
            for (int r = 0; r < rounds; r++) {
                int b = SternRing.ringTrit(rng);
                ch[i][r] = b;
                BigInteger[] s = simulate(b, ring.get(i).syndrome, h, n, rng);
                c0[i][r] = s[0]; c1[i][r] = s[1]; c2[i][r] = s[2]; r0[i][r] = s[3]; r1[i][r] = s[4];
            }
        }
        BigInteger[] hj = buildH(ring.get(j).seed, n);
        BigInteger[][] data = new BigInteger[rounds][];
        for (int r = 0; r < rounds; r++) {
            BigInteger rv = new BigInteger(n, rng), pi = new BigInteger(n, rng);
            data[r] = commit(hj, e, rv, pi, n);
            c0[j][r] = data[r][0]; c1[j][r] = data[r][1]; c2[j][r] = data[r][2];
        }
        int[] joint = chain(ringState(msg, c0, c1, c2), rounds);
        for (int r = 0; r < rounds; r++) {
            int sim = 0;
            for (int i = 0; i < k; i++) if (i != j) sim += ch[i][r];
            int b = Math.floorMod(joint[r] - sim, 3);
            ch[j][r] = b;
            BigInteger[] rr = respond(b, data[r]);
            r0[j][r] = rr[0]; r1[j][r] = rr[1];
        }
        return new SternRing.RingSignature(c0, c1, c2, ch, r0, r1);
    }

    public static boolean ringVerify(BigInteger msg, SternRing.RingSignature sig,
                                     List<SternRing.RingKey> ring, int n) {
        int k = ring.size();
        if (k == 0 || sig.ringSize() != k) return false;
        int rounds = sig.rounds();
        int[] joint = chain(ringState(msg, sig.c0, sig.c1, sig.c2), rounds);
        for (int r = 0; r < rounds; r++) {
            int s = 0;
            for (int i = 0; i < k; i++) s += sig.challenges[i][r];
            if (s % 3 != joint[r]) return false;
        }
        for (int i = 0; i < k; i++) {
            BigInteger[] h = buildH(ring.get(i).seed, n);
            for (int r = 0; r < rounds; r++)
                if (!checkRound(sig.challenges[i][r], sig.c0[i][r], sig.c1[i][r], sig.c2[i][r],
                                sig.resp0[i][r], sig.resp1[i][r], h, ring.get(i).syndrome, n))
                    return false;
        }
        return true;
    }

    /** Long-form demo KEM: K = H_4(seed, e') (256 bits), ct = H e'^T. */
    public static Stern.SternEncapResult encapWithE(BigInteger seed, int n, SecureRandom rng) {
        BigInteger eP = Stern.csprngWeightT(n, n / 16, rng);
        BigInteger ct = Stern.sternSyndromeH(buildH(seed, n), eP);
        return new Stern.SternEncapResult(decapKnown(eP, seed, n), ct, eP);
    }

    public static BigInteger decapKnown(BigInteger eP, BigInteger seed, int n) {
        return hash(4, bytesN(seed, n), bytesN(eP, n));
    }
}
