package herradurakex;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;

/**
 * TODO #200: pure-Java port of the Stern identification protocol
 * (Fiat-Shamir signature, HPKS-Stern-F), its demo Niederreiter KEM
 * (HPKE-Stern-F), and the real QC-MDPC Niederreiter KEM with the BGF
 * bit-flipping decoder (HPKE-Stern-KEM, TODO #183/#195).
 *
 * Byte-for-byte port of "Herradura cryptographic suite.py"'s
 * stern_f_keygen / hpks_stern_f_sign / hpks_stern_f_verify /
 * hpke_stern_f_encap[_with_e] / hpke_stern_f_decap and its
 * qcmdpc_keygen / qcmdpc_encap / qcmdpc_bgf_decode / qcmdpc_decap_bgf,
 * fixed at n=256 (KEYBITS), matching this binding's existing scope
 * ({@link Herradura}, {@link HerraduraNl} are likewise fixed at 256 bits).
 *
 * Demo parameters (SecurityProofs-5.md Sec.11.8.4): N=256, t=16,
 * rounds=32 by default (~19-bit Fiat-Shamir soundness, illustration
 * only); production deployments need rounds &gt;= 219 for 128-bit
 * soundness. QC-MDPC toy parameters: r=523, d=15, t=18 (measured DFR
 * &#8776;0.225%, TODO #195) — these are the values shipped by the C/Go/
 * Python suite, not BIKE production scale, and must not be "improved"
 * without breaking cross-language ciphertext compatibility.
 *
 * The OR-composition ring-signature variant (HPKS-Stern-Ring) is out of
 * scope for this port.
 */
public final class Stern {
    private Stern() { }

    private static final int N = Herradura.N; // 256
    private static final BigInteger MASK = Herradura.MASK;

    public static final int SDFNR = N / 2;         // 128 parity rows
    public static final int SDFT = Math.max(2, N / 16); // 16
    public static final int SDFR = 32;              // demo Fiat-Shamir rounds
    public static final int STERN_F_PRODUCTION_ROUNDS = 219;

    public static final int QCMDPC_R = 523;
    public static final int QCMDPC_D = 15;
    public static final int QCMDPC_T = 18;
    public static final int QCMDPC_NB_ITER = 20;

    // -----------------------------------------------------------------
    // Shared helpers: weight-t sampling, domain-separated hash chain,
    // public-matrix PRF, syndrome, permutation PRNG
    // -----------------------------------------------------------------

    /** Uniform weight-t bit vector on n=256 positions via 4-byte rejection
     * sampling (eliminates modular bias), matching Python's
     * {@code _csprng_weight_t}. */
    static BigInteger csprngWeightT(int t, SecureRandom rng) {
        LinkedHashSet<Integer> chosen = new LinkedHashSet<>();
        long threshold = (1L << 32) - ((1L << 32) % N);
        byte[] buf = new byte[4];
        while (chosen.size() < t) {
            rng.nextBytes(buf);
            long v = ((long) (buf[0] & 0xff) << 24) | ((buf[1] & 0xff) << 16)
                    | ((buf[2] & 0xff) << 8) | (buf[3] & 0xff);
            if (v < threshold) chosen.add((int) (v % N));
        }
        BigInteger result = BigInteger.ZERO;
        for (int p : chosen) result = result.setBit(p);
        return result;
    }

    /** Chain-hashes items via NL-FSCX v1, domain-separated by {@code ds}
     * (0=challenge/default, 1=c0, 2=c1, 3=c2, 4=KEM-key), finalized with
     * HFSCX-256-DM. Matches Python's {@code _stern_hash}. */
    static BigInteger sternHash(int ds, BigInteger... items) {
        BigInteger h = BigInteger.valueOf(ds).and(MASK);
        for (BigInteger item : items) {
            BigInteger v = item.and(MASK);
            h = Hfscx256.nlFscxRevolveV1(h.xor(v), Herradura.rol(v, N / 8), N / 4);
        }
        byte[] digest = Hfscx256.hash(toFixedBytes(h, N / 8));
        return new BigInteger(1, digest); // n == 256, so no truncating shift needed
    }

    /** Row `row` of the public parity-check matrix H, via NL-FSCX v1 PRF
     * finalized with HFSCX-256. Matches Python's {@code _stern_matrix_row}. */
    static BigInteger sternMatrixRow(BigInteger seedInt, int row) {
        BigInteger seed = seedInt.and(MASK);
        BigInteger a0 = Herradura.rol(seed.xor(BigInteger.valueOf(row)).and(MASK), N / 8);
        BigInteger raw = Hfscx256.nlFscxRevolveV1(a0, seed, N / 4);
        byte[] digest = Hfscx256.hash(toFixedBytes(raw, N / 8));
        return new BigInteger(1, digest);
    }

    static BigInteger[] sternBuildH(BigInteger seedInt, int nRows) {
        BigInteger[] rows = new BigInteger[nRows];
        for (int i = 0; i < nRows; i++) rows[i] = sternMatrixRow(seedInt, i);
        return rows;
    }

    /** Syndrome s = H . e^T mod 2, from a precomputed matrix. */
    static BigInteger sternSyndromeH(BigInteger[] hRows, BigInteger eInt) {
        BigInteger s = BigInteger.ZERO;
        for (int i = 0; i < hRows.length; i++) {
            if ((hRows[i].and(eInt).bitCount() & 1) != 0) s = s.setBit(i);
        }
        return s;
    }

    /** Convenience wrapper: builds H fresh each call. */
    public static BigInteger sternSyndrome(BigInteger seedInt, BigInteger eInt) {
        return sternSyndromeH(sternBuildH(seedInt, SDFNR), eInt);
    }

    /** Fisher-Yates shuffle of [0..N-1] driven by an NL-FSCX v1 PRNG: one
     * 32-bit big-endian draw per swap position (Lemire multiply-shift),
     * matching Python's {@code _stern_gen_perm}. */
    static int[] sternGenPerm(BigInteger piSeed) {
        BigInteger key = Herradura.rol(piSeed.and(MASK), N / 8);
        int[] perm = new int[N];
        for (int i = 0; i < N; i++) perm[i] = i;
        BigInteger st = piSeed.and(MASK);
        int nb = N / 8;
        byte[] buf = new byte[nb];
        int cursor = nb; // force state advance on first draw
        for (int i = N - 1; i > 0; i--) {
            int range = i + 1;
            if (cursor + 4 > nb) {
                st = Hfscx256.nlFscxV1(st, key);
                buf = toFixedBytes(st, nb);
                cursor = 0;
            }
            long v = ((long) (buf[cursor] & 0xff) << 24) | ((buf[cursor + 1] & 0xff) << 16)
                    | ((buf[cursor + 2] & 0xff) << 8) | (buf[cursor + 3] & 0xff);
            cursor += 4;
            int k = (int) ((v * range) >> 32);
            int tmp = perm[i];
            perm[i] = perm[k];
            perm[k] = tmp;
        }
        return perm;
    }

    /** result[perm[i]] = v[i]. */
    static BigInteger sternApplyPerm(int[] perm, BigInteger vInt) {
        BigInteger result = BigInteger.ZERO;
        for (int i = 0; i < N; i++) {
            if (vInt.testBit(i)) result = result.setBit(perm[i]);
        }
        return result;
    }

    // -----------------------------------------------------------------
    // stern_f_keygen
    // -----------------------------------------------------------------

    public static final class SternKeypair {
        public final BigInteger seed;     // public matrix seed
        public final BigInteger e;        // private weight-t error vector
        public final BigInteger syndrome; // public: H . e^T
        SternKeypair(BigInteger seed, BigInteger e, BigInteger syndrome) {
            this.seed = seed; this.e = e; this.syndrome = syndrome;
        }
    }

    public static SternKeypair sternFKeygen(SecureRandom rng) {
        BigInteger seed = new BigInteger(N, rng).and(MASK);
        BigInteger e = csprngWeightT(SDFT, rng);
        BigInteger[] hRows = sternBuildH(seed, SDFNR);
        return new SternKeypair(seed, e, sternSyndromeH(hRows, e));
    }

    // -----------------------------------------------------------------
    // hpks_stern_f_sign / hpks_stern_f_verify — Stern's 3-move Sigma
    // protocol, Fiat-Shamir compiled, soundness (2/3)^rounds
    // -----------------------------------------------------------------

    public static final class SternSignature {
        public final BigInteger[] c0, c1, c2;
        public final int[] challenges;
        public final BigInteger[] resp0, resp1;
        SternSignature(BigInteger[] c0, BigInteger[] c1, BigInteger[] c2,
                        int[] challenges, BigInteger[] resp0, BigInteger[] resp1) {
            this.c0 = c0; this.c1 = c1; this.c2 = c2;
            this.challenges = challenges; this.resp0 = resp0; this.resp1 = resp1;
        }
        public int rounds() { return challenges.length; }
    }

    public static SternSignature hpksSternFSign(BigInteger msg, BigInteger eInt, BigInteger seed, int rounds, SecureRandom rng) {
        if (rounds < STERN_F_PRODUCTION_ROUNDS) {
            double bits = rounds * (Math.log(1.5) / Math.log(2));
            System.err.println(String.format(
                "warning: HPKS-Stern-F: rounds=%d gives ~%.1f-bit soundness; "
                + "production deployments require rounds >= %d for 128-bit soundness.",
                rounds, bits, STERN_F_PRODUCTION_ROUNDS));
        }
        BigInteger[] hRows = sternBuildH(seed, SDFNR);

        BigInteger[] c0 = new BigInteger[rounds];
        BigInteger[] c1 = new BigInteger[rounds];
        BigInteger[] c2 = new BigInteger[rounds];
        BigInteger[] rArr = new BigInteger[rounds];
        BigInteger[] yArr = new BigInteger[rounds];
        BigInteger[] piArr = new BigInteger[rounds];
        BigInteger[] srArr = new BigInteger[rounds];
        BigInteger[] syArr = new BigInteger[rounds];

        for (int i = 0; i < rounds; i++) {
            BigInteger r = csprngWeightT(SDFT, rng);
            BigInteger y = eInt.xor(r).and(MASK);
            BigInteger piSeed = new BigInteger(N, rng).and(MASK);
            int[] perm = sternGenPerm(piSeed);
            BigInteger hr = sternSyndromeH(hRows, r);
            BigInteger sr = sternApplyPerm(perm, r);
            BigInteger sy = sternApplyPerm(perm, y);
            c0[i] = sternHash(1, piSeed, hr);
            c1[i] = sternHash(2, sr);
            c2[i] = sternHash(3, sy);
            rArr[i] = r; yArr[i] = y; piArr[i] = piSeed; srArr[i] = sr; syArr[i] = sy;
        }

        int[] challenges = deriveChallenges(msg, c0, c1, c2, rounds);

        BigInteger[] resp0 = new BigInteger[rounds];
        BigInteger[] resp1 = new BigInteger[rounds];
        for (int i = 0; i < rounds; i++) {
            switch (challenges[i]) {
                case 0: resp0[i] = srArr[i]; resp1[i] = syArr[i]; break;
                case 1: resp0[i] = piArr[i]; resp1[i] = rArr[i]; break;
                default: resp0[i] = piArr[i]; resp1[i] = yArr[i]; break;
            }
        }
        return new SternSignature(c0, c1, c2, challenges, resp0, resp1);
    }

    public static SternSignature hpksSternFSign(BigInteger msg, BigInteger eInt, BigInteger seed, SecureRandom rng) {
        return hpksSternFSign(msg, eInt, seed, SDFR, rng);
    }

    /** Fiat-Shamir challenge hash chain: one seed hash over (msg, all
     * commits), then one NL-FSCX v1 step per round advances the state and
     * yields that round's trit — matches Python's chained
     * {@code ch_st = nl_fscx_v1(ch_st, BitArray(n, i))}. */
    private static int[] deriveChallenges(BigInteger msg, BigInteger[] c0, BigInteger[] c1, BigInteger[] c2, int rounds) {
        BigInteger[] flat = new BigInteger[1 + 3 * rounds];
        flat[0] = msg;
        for (int i = 0; i < rounds; i++) {
            flat[1 + 3 * i] = c0[i];
            flat[2 + 3 * i] = c1[i];
            flat[3 + 3 * i] = c2[i];
        }
        BigInteger chSt = sternHash(0, flat);
        int[] challenges = new int[rounds];
        BigInteger word32 = BigInteger.valueOf(0xFFFFFFFFL);
        for (int i = 0; i < rounds; i++) {
            chSt = Hfscx256.nlFscxV1(chSt, BigInteger.valueOf(i));
            challenges[i] = chSt.and(word32).mod(BigInteger.valueOf(3)).intValueExact();
        }
        return challenges;
    }

    public static boolean hpksSternFVerify(BigInteger msg, SternSignature sig, BigInteger seed, BigInteger syndrome) {
        int rounds = sig.rounds();
        int[] expected = deriveChallenges(msg, sig.c0, sig.c1, sig.c2, rounds);
        for (int i = 0; i < rounds; i++) {
            if (expected[i] != sig.challenges[i]) return false;
        }

        BigInteger[] hRows = sternBuildH(seed, SDFNR);
        for (int i = 0; i < rounds; i++) {
            int b = sig.challenges[i];
            if (b == 0) {
                BigInteger sr = sig.resp0[i], sy = sig.resp1[i];
                if (!sternHash(2, sr).equals(sig.c1[i])) return false;
                if (!sternHash(3, sy).equals(sig.c2[i])) return false;
                if (sr.bitCount() != SDFT) return false;
            } else if (b == 1) {
                BigInteger piSeed = sig.resp0[i], r = sig.resp1[i];
                if (r.bitCount() != SDFT) return false;
                int[] perm = sternGenPerm(piSeed);
                BigInteger hr = sternSyndromeH(hRows, r);
                if (!sternHash(1, piSeed, hr).equals(sig.c0[i])) return false;
                BigInteger sr = sternApplyPerm(perm, r);
                if (!sternHash(2, sr).equals(sig.c1[i])) return false;
            } else {
                BigInteger piSeed = sig.resp0[i], y = sig.resp1[i];
                int[] perm = sternGenPerm(piSeed);
                BigInteger hy = sternSyndromeH(hRows, y);
                if (!sternHash(1, piSeed, hy.xor(syndrome)).equals(sig.c0[i])) return false;
                BigInteger sy = sternApplyPerm(perm, y);
                if (!sternHash(3, sy).equals(sig.c2[i])) return false;
            }
        }
        return true;
    }

    // -----------------------------------------------------------------
    // hpke_stern_f_encap / _decap — demo Niederreiter KEM sharing the
    // same (seed, e, syndrome) keypair shape as HPKS-Stern-F
    // -----------------------------------------------------------------

    public static final class SternEncapResult {
        public final BigInteger k;   // n-bit session key
        public final BigInteger ct;  // n_rows-bit syndrome H . e'^T
        public final BigInteger eP;  // the fresh weight-t error (transmitted in the demo ciphertext)
        SternEncapResult(BigInteger k, BigInteger ct, BigInteger eP) { this.k = k; this.ct = ct; this.eP = eP; }
    }

    public static SternEncapResult hpkeSternFEncapWithE(BigInteger seed, SecureRandom rng) {
        BigInteger eP = csprngWeightT(SDFT, rng);
        BigInteger[] hRows = sternBuildH(seed, SDFNR);
        BigInteger ct = sternSyndromeH(hRows, eP);
        BigInteger k = sternHash(4, seed, eP.and(MASK));
        return new SternEncapResult(k, ct, eP);
    }

    /** Demo decap: the CLI's {@code hpke-stern} transmits e' in the clear
     * (the acknowledged demo weakness), so decap never needs to
     * brute-force enumerate weight-t candidates. */
    public static BigInteger hpkeSternFDecap(BigInteger eP, BigInteger seed) {
        return sternHash(4, seed, eP.and(MASK));
    }

    // -----------------------------------------------------------------
    // QC-MDPC Niederreiter KEM + BGF decoder (real, production-shaped
    // trapdoor at toy parameters; TODO #183/#195)
    // -----------------------------------------------------------------

    /** dense . sum(x^j for j in sup) mod (x^r - 1). */
    static BigInteger qcpMulSparse(BigInteger dense, int[] sup, int r) {
        BigInteger full = BigInteger.ONE.shiftLeft(r).subtract(BigInteger.ONE);
        BigInteger acc = BigInteger.ZERO;
        for (int j : sup) {
            BigInteger rotated = dense.shiftLeft(j).or(dense.shiftRight(r - j)).and(full);
            acc = acc.xor(rotated);
        }
        return acc;
    }

    /** a . b mod (x^r - 1), bit-by-bit shift-add over set bits of b. */
    static BigInteger qcpMul(BigInteger a, BigInteger b, int r) {
        BigInteger full = BigInteger.ONE.shiftLeft(r).subtract(BigInteger.ONE);
        BigInteger acc = BigInteger.ZERO;
        BigInteger bb = b;
        while (bb.signum() != 0) {
            int j = bb.getLowestSetBit();
            bb = bb.clearBit(j);
            acc = acc.xor(a.shiftLeft(j).or(a.shiftRight(r - j)).and(full));
        }
        return acc;
    }

    /** h^-1 mod (x^r - 1) via extended Euclid in GF(2)[x]. Throws
     * ArithmeticException if h is not invertible. */
    static BigInteger qcpInv(BigInteger h, int r) {
        BigInteger mod = BigInteger.ONE.shiftLeft(r).or(BigInteger.ONE);
        BigInteger a = mod, b = h;
        BigInteger u0 = BigInteger.ZERO, u1 = BigInteger.ONE;
        while (b.signum() != 0) {
            int da = a.bitLength() - 1, db = b.bitLength() - 1;
            if (da < db) {
                BigInteger ta = a; a = b; b = ta;
                BigInteger tu = u0; u0 = u1; u1 = tu;
                int td = da; da = db; db = td;
            }
            int sh = da - db;
            a = a.xor(b.shiftLeft(sh));
            u0 = u0.xor(u1.shiftLeft(sh));
        }
        if (!a.equals(BigInteger.ONE)) {
            throw new ArithmeticException("h not invertible mod x^r - 1");
        }
        for (int i = r; i < u0.bitLength(); i++) {
            if (u0.testBit(i)) {
                u0 = u0.xor(BigInteger.ONE.shiftLeft(i)).xor(BigInteger.ONE.shiftLeft(i - r));
            }
        }
        return u0;
    }

    /** NL-FSCX-v1-based XOF: 16 x 16-bit words per 256-bit block, consumed
     * highest-word-first (matches Python's list.pop()-from-end stack). */
    static final class QcMdpcPrf {
        private final BigInteger seed;
        private long ctr = 0;
        private int[] buf = new int[0];
        private int pos = 0;

        QcMdpcPrf(BigInteger seedInt) { this.seed = seedInt.and(MASK); }

        private static int[] refill(BigInteger seedInt, long ctr) {
            BigInteger x = seedInt.xor(BigInteger.valueOf(ctr)).and(MASK);
            BigInteger rolx = Herradura.rol(x, N / 8);
            BigInteger block = Hfscx256.nlFscxRevolveV1(rolx, x, N / 4);
            int[] words = new int[16];
            for (int k = 0; k < 16; k++) {
                words[k] = block.shiftRight(16 * k).and(BigInteger.valueOf(0xFFFF)).intValue();
            }
            return words;
        }

        int word16() {
            if (pos >= buf.length) {
                buf = refill(seed, ctr);
                ctr++;
                pos = 0;
            }
            int idx = buf.length - 1 - pos; // pop from the end
            pos++;
            return buf[idx];
        }

        int uniformIdx(int r) {
            int lim = (0x10000 / r) * r;
            while (true) {
                int w = word16();
                if (w < lim) return w % r;
            }
        }

        int[] sparseSupport(int r, int d) {
            LinkedHashSet<Integer> s = new LinkedHashSet<>();
            while (s.size() < d) s.add(uniformIdx(r));
            int[] out = new int[d];
            int idx = 0;
            for (int v : s) out[idx++] = v;
            return out;
        }
    }

    private static BigInteger supToPoly(int[] sup) {
        BigInteger v = BigInteger.ZERO;
        for (int j : sup) v = v.setBit(j);
        return v;
    }

    public static final class QcMdpcKeypair {
        public final int[] sup0, sup1; // private support sets (weight d each)
        public final BigInteger h0, h1; // private sparse polynomials
        public final BigInteger hPub;   // public key: h1 . h0^-1 mod (x^r-1)
        QcMdpcKeypair(int[] sup0, int[] sup1, BigInteger h0, BigInteger h1, BigInteger hPub) {
            this.sup0 = sup0; this.sup1 = sup1; this.h0 = h0; this.h1 = h1; this.hPub = hPub;
        }
    }

    static QcMdpcKeypair qcmdpcKeygen(BigInteger seedInt) {
        QcMdpcPrf prf = new QcMdpcPrf(seedInt);
        int r = QCMDPC_R, d = QCMDPC_D;
        while (true) {
            int[] sup0 = prf.sparseSupport(r, d);
            int[] sup1 = prf.sparseSupport(r, d);
            BigInteger h0 = supToPoly(sup0);
            BigInteger h1 = supToPoly(sup1);
            BigInteger h0Inv;
            try {
                h0Inv = qcpInv(h0, r);
            } catch (ArithmeticException e) {
                continue; // h0 not invertible — draw the next candidate from the same PRF stream
            }
            BigInteger hPub = qcpMul(h1, h0Inv, r);
            return new QcMdpcKeypair(sup0, sup1, h0, h1, hPub);
        }
    }

    public static QcMdpcKeypair qcmdpcKeygen(SecureRandom rng) {
        return qcmdpcKeygen(new BigInteger(N, rng).and(MASK));
    }

    /** Recomputes h_pub from a decoded private key (used by {@code pkey
     * --pubout}). */
    public static BigInteger qcmdpcPubFromPriv(BigInteger h0, BigInteger h1) {
        return qcpMul(h1, qcpInv(h0, QCMDPC_R), QCMDPC_R);
    }

    public static final class QcMdpcEncapResult {
        public final BigInteger syn;
        public final BigInteger k;
        QcMdpcEncapResult(BigInteger syn, BigInteger k) { this.syn = syn; this.k = k; }
    }

    static QcMdpcEncapResult qcmdpcEncap(BigInteger hPub, BigInteger seedInt) {
        QcMdpcPrf prf = new QcMdpcPrf(seedInt);
        int r = QCMDPC_R, t = QCMDPC_T;
        int[] supE = prf.sparseSupport(2 * r, t);
        BigInteger e0 = BigInteger.ZERO, e1 = BigInteger.ZERO;
        for (int j : supE) {
            if (j < r) e0 = e0.setBit(j);
            else e1 = e1.setBit(j - r);
        }
        BigInteger syn = e0.xor(qcpMul(e1, hPub, r));
        int rb = (r + 7) / 8;
        byte[] ebuf = new byte[2 * rb];
        System.arraycopy(toFixedBytesLE(e0, rb), 0, ebuf, 0, rb);
        System.arraycopy(toFixedBytesLE(e1, rb), 0, ebuf, rb, rb);
        BigInteger k = new BigInteger(1, Hfscx256.hash(ebuf));
        return new QcMdpcEncapResult(syn, k);
    }

    public static QcMdpcEncapResult qcmdpcEncap(BigInteger hPub, SecureRandom rng) {
        return qcmdpcEncap(hPub, new BigInteger(N, rng).and(MASK));
    }

    /** BGF (Black-Gray-Flip) decoder (Drucker-Gueron-Kostic 2019). Returns
     * {e0, e1} or null on decoding failure (a legitimate, measured
     * ~0.225% DFR event per encapsulation — TODO #195 — not necessarily a
     * bug). */
    static BigInteger[] qcmdpcBgfDecode(BigInteger synPub, int[] sup0, int[] sup1) {
        int r = QCMDPC_R, d = QCMDPC_D, nbIter = QCMDPC_NB_ITER;
        BigInteger s = qcpMulSparse(synPub, sup0, r);
        BigInteger e0 = BigInteger.ZERO, e1 = BigInteger.ZERO;
        int thFloor = (d + 1) / 2 + 2;

        for (int it = 0; it < nbIter; it++) {
            if (s.signum() == 0) break;
            int th = (it < 7) ? Math.max((int) Math.ceil(0.66 * d), thFloor) : Math.max(thFloor - 1, 8);
            int[] upc0 = computeUpc(s, sup0, r);
            int[] upc1 = computeUpc(s, sup1, r);
            List<Integer> black0 = new ArrayList<>(), black1 = new ArrayList<>();
            List<Integer> gray0 = new ArrayList<>(), gray1 = new ArrayList<>();
            for (int j = 0; j < r; j++) {
                if (upc0[j] >= th) black0.add(j);
                else if (upc0[j] >= th - 2) gray0.add(j);
                if (upc1[j] >= th) black1.add(j);
                else if (upc1[j] >= th - 2) gray1.add(j);
            }
            for (int j : black0) { e0 = e0.xor(BigInteger.ONE.shiftLeft(j)); s = s.xor(qcpMulSparse(BigInteger.ONE.shiftLeft(j), sup0, r)); }
            for (int j : black1) { e1 = e1.xor(BigInteger.ONE.shiftLeft(j)); s = s.xor(qcpMulSparse(BigInteger.ONE.shiftLeft(j), sup1, r)); }
            if (it == 0) {
                for (int pass = 0; pass < 2; pass++) {
                    List<Integer> g0 = (pass == 0) ? black0 : gray0;
                    List<Integer> g1 = (pass == 0) ? black1 : gray1;
                    int[] u0 = computeUpc(s, sup0, r);
                    int[] u1 = computeUpc(s, sup1, r);
                    for (int j : g0) {
                        if (u0[j] >= thFloor) { e0 = e0.xor(BigInteger.ONE.shiftLeft(j)); s = s.xor(qcpMulSparse(BigInteger.ONE.shiftLeft(j), sup0, r)); }
                    }
                    for (int j : g1) {
                        if (u1[j] >= thFloor) { e1 = e1.xor(BigInteger.ONE.shiftLeft(j)); s = s.xor(qcpMulSparse(BigInteger.ONE.shiftLeft(j), sup1, r)); }
                    }
                }
            }
        }
        return (s.signum() == 0) ? new BigInteger[] { e0, e1 } : null;
    }

    private static int[] computeUpc(BigInteger s, int[] sup, int r) {
        int[] upc = new int[r];
        for (int j = 0; j < r; j++) {
            int count = 0;
            for (int k : sup) {
                if (s.testBit((j + k) % r)) count++;
            }
            upc[j] = count;
        }
        return upc;
    }

    /** Decapsulate: BGF-decode, then derive K from the recovered error
     * vector. Returns null on a DFR event or corrupt ciphertext. */
    public static BigInteger qcmdpcDecapBgf(BigInteger syn, int[] sup0, int[] sup1) {
        BigInteger[] result = qcmdpcBgfDecode(syn, sup0, sup1);
        if (result == null) return null;
        int rb = (QCMDPC_R + 7) / 8;
        byte[] ebuf = new byte[2 * rb];
        System.arraycopy(toFixedBytesLE(result[0], rb), 0, ebuf, 0, rb);
        System.arraycopy(toFixedBytesLE(result[1], rb), 0, ebuf, rb, rb);
        return new BigInteger(1, Hfscx256.hash(ebuf));
    }

    // -----------------------------------------------------------------
    // Byte-serialization helpers
    // -----------------------------------------------------------------

    private static byte[] toFixedBytes(BigInteger v, int nbytes) {
        byte[] raw = v.and(MASK).toByteArray();
        byte[] out = new byte[nbytes];
        int rawStart = Math.max(0, raw.length - nbytes);
        int copyLen = raw.length - rawStart;
        System.arraycopy(raw, rawStart, out, nbytes - copyLen, copyLen);
        return out;
    }

    /** Little-endian fixed-width byte serialization — used only by the
     * QC-MDPC KDF inputs and h0/h1/h_pub wire format, which deliberately
     * (and unlike the rest of the suite) serialize little-endian. */
    static byte[] toFixedBytesLE(BigInteger v, int nbytes) {
        byte[] be = new byte[nbytes];
        byte[] raw = v.toByteArray();
        int rawStart = Math.max(0, raw.length - nbytes);
        int copyLen = raw.length - rawStart;
        System.arraycopy(raw, rawStart, be, nbytes - copyLen, copyLen);
        byte[] le = new byte[nbytes];
        for (int i = 0; i < nbytes; i++) le[i] = be[nbytes - 1 - i];
        return le;
    }
}
