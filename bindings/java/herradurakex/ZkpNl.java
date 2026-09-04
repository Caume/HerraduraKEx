package herradurakex;

import java.nio.charset.StandardCharsets;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * TODO #203: pure-Java port of ZKP-NL, a ZKBoo (3-party MPC-in-the-head)
 * Sigma protocol proving knowledge of {@code A} such that
 * {@code nl_fscx_v1(A, B) = y} for public {@code (B, y)}, without
 * revealing {@code A}.
 *
 * Byte-for-byte port of "Herradura cryptographic suite.py"'s
 * {@code _zkp_nl_rol}/{@code _zkp_nl_h}/{@code _zkp_nl_prg_bit}/
 * {@code _zkp_nl_evaluate_circuit}/{@code zkp_nl_prove}/
 * {@code zkp_nl_verify} — SecurityProofs-7.md Sec.11.10.3.
 *
 * Unlike {@link Herradura}/{@link Stern}/{@link Hcred} (fixed at n=256),
 * this circuit is parameterized by bit-width {@code n} and ported
 * generally (via {@link BigInteger}) because its only production
 * consumer in this binding, {@link Hpake}, needs it at {@code n=32}
 * (matching the Python reference's aPAKE parameters) rather than 256 —
 * the circuit itself has no dependency on {@link Herradura}'s
 * fixed-256-bit primitives, so genericity costs nothing extra to port.
 *
 * TODO #261 (v6.0.0): the ZKB++ transcript-encoding variant
 * ({@code zkp_nl_prove_pp}/{@code zkp_nl_verify_pp}, here
 * {@link #provePp}/{@link #verifyPp}) and {@link #keygen} are now ported
 * too, so the {@code hpks-zkp-nl}, {@code nl-zkboo} and {@code nl-zkbpp}
 * algo tags work in the Java CLI exactly as in C/Go/Python.  This class
 * doc used to declare both out of scope, on the grounds that the port
 * "exists only to give {@link Hpake} its mutual-authentication proof" —
 * which made three of the four languages' CLI surface unreachable here.
 */
public final class ZkpNl {
    private ZkpNl() { }

    // -----------------------------------------------------------------
    // Generic n-bit helpers (not tied to Herradura.N=256)
    // -----------------------------------------------------------------

    static BigInteger maskOf(int n) {
        return BigInteger.ONE.shiftLeft(n).subtract(BigInteger.ONE);
    }

    static BigInteger rol(BigInteger x, int r, int n) {
        BigInteger mask = maskOf(n);
        r = ((r % n) + n) % n;
        if (r == 0) return x.and(mask);
        BigInteger left = x.shiftLeft(r).and(mask);
        BigInteger right = x.and(mask).shiftRight(n - r);
        return left.or(right);
    }

    /** General n-bit NL-FSCX v1: fscx(A,B) XOR ROL((A+B) mod 2^n, n/4).
     * {@link Hfscx256#nlFscxV1} is the fixed-256-bit specialization of
     * this same formula. */
    public static BigInteger nlFscxV1General(BigInteger a, BigInteger b, int n) {
        BigInteger mask = maskOf(n);
        BigInteger fscx = a.xor(b).xor(rol(a, 1, n)).xor(rol(b, 1, n))
                           .xor(rol(a, n - 1, n)).xor(rol(b, n - 1, n)).and(mask);
        BigInteger sum = a.add(b).and(mask);
        return fscx.xor(rol(sum, n / 4, n)).and(mask);
    }

    private static byte[] h(byte[]... parts) {
        int total = 0;
        for (byte[] p : parts) total += p.length;
        byte[] buf = new byte[total];
        int off = 0;
        for (byte[] p : parts) { System.arraycopy(p, 0, buf, off, p.length); off += p.length; }
        return Hfscx256.hash(buf);
    }

    private static int prgBit(byte[] tapeKey, int gateId) {
        byte[] hh = h(tapeKey, be4(gateId));
        return hh[0] & 1;
    }

    private static byte[] be4(int v) {
        return new byte[] { (byte) (v >> 24), (byte) (v >> 16), (byte) (v >> 8), (byte) v };
    }

    private static byte[] toFixedBytes(BigInteger v, int nbytes) {
        byte[] raw = v.toByteArray();
        byte[] out = new byte[nbytes];
        int rawStart = Math.max(0, raw.length - nbytes);
        int copyLen = raw.length - rawStart;
        System.arraycopy(raw, rawStart, out, nbytes - copyLen, copyLen);
        return out;
    }

    private static byte[] slice(byte[] src, int off, int len) {
        byte[] out = new byte[len];
        System.arraycopy(src, off, out, 0, len);
        return out;
    }

    private static BigInteger randomBig(int nbytes, SecureRandom rng) {
        byte[] buf = new byte[nbytes];
        rng.nextBytes(buf);
        return new BigInteger(1, buf);
    }

    // -----------------------------------------------------------------
    // Keygen (TODO #261)
    // -----------------------------------------------------------------

    /** ZKP-NL keypair: (A private, B public, y = nl_fscx_v1(A, B) public).
     *  Returns {A, B, y}.  n must be a positive multiple of 2. */
    public static BigInteger[] keygen(int n, SecureRandom rng) {
        BigInteger mask = maskOf(n);
        int nb = (n + 7) / 8;
        BigInteger a = randomBig(nb, rng).and(mask);
        BigInteger b = randomBig(nb, rng).and(mask);
        BigInteger y = nlFscxV1General(a, b, n);
        return new BigInteger[] { a, b, y };
    }

    // -----------------------------------------------------------------
    // ZKBoo 3-party circuit for nl_fscx_v1(A, B) = fscx(A,B) XOR ROL((A+B) mod 2^n, n/4).
    // Only (A+B) mod 2^n's ripple-carry chain needs AND gates; fscx and
    // the rotation are XOR-linear (free in ZKBoo).
    // -----------------------------------------------------------------

    private static final class CircuitResult {
        BigInteger[] outShares; // [3]
        int[][][] gateViews;    // [3][n-1][3] = (a_bit, c_bit, and_out) per gate
    }

    private static CircuitResult evaluateCircuit(BigInteger[] shares, byte[][] tapes, BigInteger b, int n) {
        BigInteger mask = maskOf(n);
        int[][] carry = new int[n][3]; // carry[0] = {0,0,0}, never overwritten
        int[][][] gateViews = new int[3][n - 1][3];

        for (int i = 0; i < n - 1; i++) {
            int[] ai = new int[3], ci = new int[3];
            for (int p = 0; p < 3; p++) { ai[p] = shares[p].testBit(i) ? 1 : 0; ci[p] = carry[i][p]; }
            int bi = b.testBit(i) ? 1 : 0;
            int[] ri = new int[3];
            for (int p = 0; p < 3; p++) ri[p] = prgBit(tapes[p], i);

            int[] andOut = new int[3];
            for (int p = 0; p < 3; p++) {
                int p1 = (p + 1) % 3;
                andOut[p] = (ai[p] & ci[p]) ^ (ai[p] & ci[p1]) ^ (ai[p1] & ci[p]) ^ ri[p] ^ ri[p1];
                gateViews[p][i][0] = ai[p]; gateViews[p][i][1] = ci[p]; gateViews[p][i][2] = andOut[p];
            }
            for (int p = 0; p < 3; p++) {
                carry[i + 1][p] = (bi * ai[p]) ^ andOut[p] ^ (bi * ci[p]);
            }
        }

        BigInteger[] sumShares = { BigInteger.ZERO, BigInteger.ZERO, BigInteger.ZERO };
        for (int i = 0; i < n; i++) {
            for (int p = 0; p < 3; p++) {
                int bitI = (shares[p].testBit(i) ? 1 : 0) ^ (b.testBit(i) ? 1 : 0) ^ carry[i][p];
                if (bitI != 0) sumShares[p] = sumShares[p].setBit(i);
            }
        }
        BigInteger[] rotShares = new BigInteger[3];
        for (int p = 0; p < 3; p++) rotShares[p] = rol(sumShares[p], n / 4, n);

        BigInteger bConst = b.xor(rol(b, 1, n)).xor(rol(b, n - 1, n)).and(mask);
        BigInteger[] linShares = new BigInteger[3];
        for (int p = 0; p < 3; p++) {
            linShares[p] = shares[p].xor(rol(shares[p], 1, n)).xor(rol(shares[p], n - 1, n)).and(mask);
        }
        linShares[0] = linShares[0].xor(bConst);

        CircuitResult r = new CircuitResult();
        r.outShares = new BigInteger[3];
        for (int p = 0; p < 3; p++) r.outShares[p] = linShares[p].xor(rotShares[p]).and(mask);
        r.gateViews = gateViews;
        return r;
    }

    // -----------------------------------------------------------------
    // Prove / verify
    // -----------------------------------------------------------------

    public static final class ProofRound {
        public byte[] com0, com1, com2;
        public int e;
        public byte[] viewP1, viewP2;
    }

    private static byte[] packView(int pIdx, BigInteger[] shares, byte[][] tapes, BigInteger[] outShares,
                                    int[][][] gateViews, int nb, int n) {
        byte[] view = new byte[nb + 32 + nb + (n - 1)];
        System.arraycopy(toFixedBytes(shares[pIdx], nb), 0, view, 0, nb);
        System.arraycopy(tapes[pIdx], 0, view, nb, 32);
        System.arraycopy(toFixedBytes(outShares[pIdx], nb), 0, view, nb + 32, nb);
        int off = nb + 32 + nb;
        for (int i = 0; i < n - 1; i++) {
            int[] gv = gateViews[pIdx][i];
            view[off + i] = (byte) (gv[0] | (gv[1] << 1) | (gv[2] << 2));
        }
        return view;
    }

    private static final class UnpackedView {
        BigInteger share, outShare;
        byte[] tape;
        int[][] gv; // [n-1][3]
    }

    private static UnpackedView unpackView(byte[] viewBytes, int nb, int n) {
        UnpackedView v = new UnpackedView();
        v.share = new BigInteger(1, slice(viewBytes, 0, nb));
        v.tape = slice(viewBytes, nb, 32);
        v.outShare = new BigInteger(1, slice(viewBytes, nb + 32, nb));
        v.gv = new int[n - 1][3];
        int off = nb + 32 + nb;
        for (int k = 0; k < n - 1; k++) {
            int b3 = viewBytes[off + k] & 0xff;
            v.gv[k][0] = b3 & 1; v.gv[k][1] = (b3 >> 1) & 1; v.gv[k][2] = (b3 >> 2) & 1;
        }
        return v;
    }

    /** ZKBoo prover: prove knowledge of A such that nl_fscx_v1(A, B) = y. */
    public static List<ProofRound> prove(BigInteger a, BigInteger b, BigInteger y, int n, int rounds,
                                          byte[] msgBytes, SecureRandom rng) {
        BigInteger mask = maskOf(n);
        int nb = (n + 7) / 8;

        byte[][][] allComs = new byte[rounds][][];
        BigInteger[][] allShares = new BigInteger[rounds][];
        byte[][][] allTapes = new byte[rounds][][];
        BigInteger[][] allOutShares = new BigInteger[rounds][];
        int[][][][] allGateViews = new int[rounds][][][];
        List<byte[]> comBlockParts = new ArrayList<>(rounds * 3);

        for (int j = 0; j < rounds; j++) {
            BigInteger s0 = randomBig(nb, rng).and(mask);
            BigInteger s1 = randomBig(nb, rng).and(mask);
            BigInteger s2 = a.xor(s0).xor(s1).and(mask);
            BigInteger[] shares = { s0, s1, s2 };
            byte[][] tapes = new byte[3][];
            for (int p = 0; p < 3; p++) { tapes[p] = new byte[32]; rng.nextBytes(tapes[p]); }

            CircuitResult cr = evaluateCircuit(shares, tapes, b, n);
            byte[][] coms = new byte[3][];
            for (int p = 0; p < 3; p++) {
                coms[p] = h(be4(j), new byte[] { (byte) p }, tapes[p], toFixedBytes(cr.outShares[p], nb));
            }
            allComs[j] = coms; allShares[j] = shares; allTapes[j] = tapes;
            allOutShares[j] = cr.outShares; allGateViews[j] = cr.gateViews;
            comBlockParts.add(coms[0]); comBlockParts.add(coms[1]); comBlockParts.add(coms[2]);
        }
        byte[] comBlock = concatAll(comBlockParts);
        byte[] chSeed = h(comBlock, toFixedBytes(b, nb), toFixedBytes(y, nb), msgBytes);

        List<ProofRound> out = new ArrayList<>(rounds);
        for (int j = 0; j < rounds; j++) {
            byte[] hh = h(chSeed, be4(j));
            int e = (hh[0] & 0xff) % 3;
            int p1 = (e + 1) % 3, p2 = (e + 2) % 3;
            ProofRound rd = new ProofRound();
            rd.com0 = allComs[j][0]; rd.com1 = allComs[j][1]; rd.com2 = allComs[j][2];
            rd.e = e;
            rd.viewP1 = packView(p1, allShares[j], allTapes[j], allOutShares[j], allGateViews[j], nb, n);
            rd.viewP2 = packView(p2, allShares[j], allTapes[j], allOutShares[j], allGateViews[j], nb, n);
            out.add(rd);
        }
        return out;
    }

    private static byte[] concatAll(List<byte[]> parts) {
        int total = 0;
        for (byte[] p : parts) total += p.length;
        byte[] out = new byte[total];
        int off = 0;
        for (byte[] p : parts) { System.arraycopy(p, 0, out, off, p.length); off += p.length; }
        return out;
    }

    /** ZKBoo verifier: verify a proof that the prover knows A such that
     * nl_fscx_v1(A, B) = y. */
    public static boolean verify(BigInteger b, BigInteger y, int n, int rounds, byte[] msgBytes,
                                  List<ProofRound> proofRounds) {
        int nb = (n + 7) / 8;
        byte[][][] comsList = new byte[rounds][][];
        int[] challenges = new int[rounds];
        List<byte[]> comBlockParts = new ArrayList<>(rounds * 3);
        for (int j = 0; j < rounds; j++) {
            ProofRound r = proofRounds.get(j);
            comsList[j] = new byte[][] { r.com0, r.com1, r.com2 };
            challenges[j] = r.e;
            comBlockParts.add(r.com0); comBlockParts.add(r.com1); comBlockParts.add(r.com2);
        }
        byte[] comBlock = concatAll(comBlockParts);
        byte[] chSeed = h(comBlock, toFixedBytes(b, nb), toFixedBytes(y, nb), msgBytes);
        for (int j = 0; j < rounds; j++) {
            byte[] hh = h(chSeed, be4(j));
            if ((hh[0] & 0xff) % 3 != challenges[j]) return false;
        }

        for (int j = 0; j < rounds; j++) {
            int e = challenges[j];
            ProofRound resp = proofRounds.get(j);
            int p1 = (e + 1) % 3, p2 = (e + 2) % 3;
            UnpackedView v1 = unpackView(resp.viewP1, nb, n);
            UnpackedView v2 = unpackView(resp.viewP2, nb, n);

            byte[] cP1 = h(be4(j), new byte[] { (byte) p1 }, v1.tape, toFixedBytes(v1.outShare, nb));
            byte[] cP2 = h(be4(j), new byte[] { (byte) p2 }, v2.tape, toFixedBytes(v2.outShare, nb));
            if (!Arrays.equals(cP1, comsList[j][p1]) || !Arrays.equals(cP2, comsList[j][p2])) return false;

            int carryP1 = 0, carryP2 = 0;
            for (int i = 0; i < n - 1; i++) {
                int aiP1 = v1.share.testBit(i) ? 1 : 0;
                int aiP2 = v2.share.testBit(i) ? 1 : 0;
                int ciP1 = carryP1, ciP2 = carryP2;
                int bi = b.testBit(i) ? 1 : 0;
                int riP1 = prgBit(v1.tape, i), riP2 = prgBit(v2.tape, i);
                int expAndP1 = (aiP1 & ciP1) ^ (aiP1 & ciP2) ^ (aiP2 & ciP1) ^ riP1 ^ riP2;
                if (v1.gv[i][2] != expAndP1) return false;
                carryP1 = (bi * aiP1) ^ expAndP1 ^ (bi * ciP1);
                carryP2 = (bi * aiP2) ^ v2.gv[i][2] ^ (bi * ciP2);
            }
        }
        return true;
    }

    // -----------------------------------------------------------------
    // ZKB++ (ZKP-NL-PP) — Chase et al. 2017 (CCS) applied to the same
    // circuit.  TODO #261 (v6.0.0) ported this from the Python/Go/C
    // implementations; the transcript is smaller than the ZKBoo one above
    // because two of the three parties are sent as 16-byte PRG SEEDS
    // rather than as full views, and only the third party's AND-gate
    // outputs travel explicitly (bit-packed).
    // -----------------------------------------------------------------

    static final int ZKPP_SEED_BYTES = 16;   // 128-bit per-party PRG seed

    /** One ZKB++ round, as it appears on the wire. */
    public static final class PpRound {
        public byte[] comE;      // hidden party's 32-byte commitment
        public int e;            // hidden party index in {0,1,2}
        public byte[] outE;      // hidden party's output share (nb bytes)
        public byte[] seedP1;    // 16-byte seed of opened party e+1
        public byte[] seedP2;    // 16-byte seed of opened party e+2
        public byte[] gatesP2;   // bit-packed AND outputs of party e+2
        public byte[] share2;    // party 2's explicit input share; empty when e == 2
    }

    /** Derives (share, tape) for one party from its 16-byte seed. */
    private static Object[] ppDerive(byte[] seed, int nb, BigInteger mask) {
        byte[] sh = h(seed, "share".getBytes(StandardCharsets.US_ASCII));
        BigInteger share = new BigInteger(1, slice(sh, 0, nb)).and(mask);
        byte[] tape = h(seed, "tape".getBytes(StandardCharsets.US_ASCII));
        return new Object[] { share, tape };
    }

    private static byte[] ppTape(byte[] seed) {
        return h(seed, "tape".getBytes(StandardCharsets.US_ASCII));
    }

    /** Bit-packs 0/1 values LSB-first within each byte. */
    static byte[] ppPackBits(int[] bits) {
        byte[] out = new byte[(bits.length + 7) / 8];
        for (int k = 0; k < bits.length; k++) out[k >> 3] |= (byte) ((bits[k] & 1) << (k & 7));
        return out;
    }

    /** Inverse of {@link #ppPackBits}. */
    static int[] ppUnpackBits(byte[] data, int count) {
        int[] out = new int[count];
        for (int k = 0; k < count; k++) out[k] = ((data[k >> 3] & 0xff) >> (k & 7)) & 1;
        return out;
    }

    /** Recomputes party p's output share from its input share and per-position
     *  carries — the linear tail of {@link #evaluateCircuit}. */
    private static BigInteger ppOutShare(int p, BigInteger share, int[] carries, BigInteger b, int n) {
        BigInteger mask = maskOf(n);
        BigInteger sum = BigInteger.ZERO;
        for (int i = 0; i < n; i++) {
            int bitI = (share.testBit(i) ? 1 : 0) ^ (b.testBit(i) ? 1 : 0) ^ carries[i];
            if (bitI != 0) sum = sum.setBit(i);
        }
        BigInteger rot = rol(sum, n / 4, n);
        BigInteger lin = share.xor(rol(share, 1, n)).xor(rol(share, n - 1, n)).and(mask);
        if (p == 0) {   // public constant absorbed into party 0 only
            lin = lin.xor(b.xor(rol(b, 1, n)).xor(rol(b, n - 1, n)).and(mask));
        }
        return lin.xor(rot).and(mask);
    }

    private static byte[] ppCommit(int j, int p, byte[] seed, byte[] share2Bytes,
                                    byte[] gateBits, BigInteger outShare, int nb) {
        return h(be4(j), new byte[] { (byte) p }, seed, share2Bytes, gateBits,
                 toFixedBytes(outShare, nb));
    }

    /** ZKB++ prover: prove knowledge of A such that nl_fscx_v1(A, B) = y. */
    public static List<PpRound> provePp(BigInteger a, BigInteger b, BigInteger y, int n,
                                         int rounds, byte[] msgBytes, SecureRandom rng) {
        BigInteger mask = maskOf(n);
        int nb = (n + 7) / 8;

        byte[][][] allSeeds = new byte[rounds][3][];
        byte[][] allShare2 = new byte[rounds][];
        byte[][][] allGateBits = new byte[rounds][3][];
        BigInteger[][] allOutShares = new BigInteger[rounds][];
        byte[][][] allComs = new byte[rounds][3][];

        List<byte[]> comParts = new ArrayList<>(rounds * 3);
        List<byte[]> outParts = new ArrayList<>(rounds * 3);

        for (int j = 0; j < rounds; j++) {
            byte[][] seeds = new byte[3][ZKPP_SEED_BYTES];
            for (int p = 0; p < 3; p++) rng.nextBytes(seeds[p]);

            Object[] d0 = ppDerive(seeds[0], nb, mask);
            Object[] d1 = ppDerive(seeds[1], nb, mask);
            BigInteger s0 = (BigInteger) d0[0], s1 = (BigInteger) d1[0];
            BigInteger s2 = a.xor(s0).xor(s1).and(mask);
            byte[][] tapes = { (byte[]) d0[1], (byte[]) d1[1], ppTape(seeds[2]) };
            BigInteger[] shares = { s0, s1, s2 };

            CircuitResult cr = evaluateCircuit(shares, tapes, b, n);
            byte[][] gateBits = new byte[3][];
            for (int p = 0; p < 3; p++) {
                int[] bits = new int[n - 1];
                for (int i = 0; i < n - 1; i++) bits[i] = cr.gateViews[p][i][2];
                gateBits[p] = ppPackBits(bits);
            }

            byte[] s2Bytes = toFixedBytes(s2, nb);
            byte[][] coms = new byte[3][];
            for (int p = 0; p < 3; p++) {
                coms[p] = ppCommit(j, p, seeds[p], p == 2 ? s2Bytes : new byte[0],
                                   gateBits[p], cr.outShares[p], nb);
                comParts.add(coms[p]);
                outParts.add(toFixedBytes(cr.outShares[p], nb));
            }

            allSeeds[j] = seeds;
            allShare2[j] = s2Bytes;
            allGateBits[j] = gateBits;
            allOutShares[j] = cr.outShares;
            allComs[j] = coms;
        }

        // Fiat-Shamir: bind commitments, output shares, B, y, msg.
        byte[] chSeed = h(concatAll(comParts), concatAll(outParts),
                          toFixedBytes(b, nb), toFixedBytes(y, nb), msgBytes);

        List<PpRound> out = new ArrayList<>(rounds);
        for (int j = 0; j < rounds; j++) {
            int e = (h(chSeed, be4(j))[0] & 0xff) % 3;
            int p1 = (e + 1) % 3, p2 = (e + 2) % 3;
            PpRound r = new PpRound();
            r.comE = allComs[j][e];
            r.e = e;
            r.outE = toFixedBytes(allOutShares[j][e], nb);
            r.seedP1 = allSeeds[j][p1];
            r.seedP2 = allSeeds[j][p2];
            r.gatesP2 = allGateBits[j][p2];
            r.share2 = (e == 2) ? new byte[0] : allShare2[j];
            out.add(r);
        }
        return out;
    }

    /** ZKB++ verifier for {@link #provePp} proofs. */
    public static boolean verifyPp(BigInteger b, BigInteger y, int n, int rounds,
                                    byte[] msgBytes, List<PpRound> proofRounds) {
        BigInteger mask = maskOf(n);
        int nb = (n + 7) / 8;
        if (proofRounds.size() != rounds) return false;

        List<byte[]> comParts = new ArrayList<>(rounds * 3);
        List<byte[]> outParts = new ArrayList<>(rounds * 3);

        for (int j = 0; j < rounds; j++) {
            PpRound resp = proofRounds.get(j);
            int e = resp.e;
            if (e < 0 || e > 2) return false;
            int p1 = (e + 1) % 3, p2 = (e + 2) % 3;

            byte[] share2B = resp.share2;
            if (e != 2 && share2B.length != nb) return false;
            if (resp.gatesP2.length != (n - 1 + 7) / 8) return false;
            if (resp.seedP1.length != ZKPP_SEED_BYTES || resp.seedP2.length != ZKPP_SEED_BYTES) return false;
            if (resp.outE.length != nb) return false;

            BigInteger shareP1, shareP2;
            byte[] tapeP1, tapeP2;
            if (p1 == 2) {
                shareP1 = new BigInteger(1, share2B).and(mask);
                tapeP1 = ppTape(resp.seedP1);
            } else {
                Object[] d = ppDerive(resp.seedP1, nb, mask);
                shareP1 = (BigInteger) d[0]; tapeP1 = (byte[]) d[1];
            }
            if (p2 == 2) {
                shareP2 = new BigInteger(1, share2B).and(mask);
                tapeP2 = ppTape(resp.seedP2);
            } else {
                Object[] d = ppDerive(resp.seedP2, nb, mask);
                shareP2 = (BigInteger) d[0]; tapeP2 = (byte[]) d[1];
            }

            int[] gatesP2 = ppUnpackBits(resp.gatesP2, n - 1);
            int[] gatesP1 = new int[n - 1];
            int[] carries1 = new int[n], carries2 = new int[n];
            int c1 = 0, c2 = 0;
            for (int i = 0; i < n - 1; i++) {
                int a1 = shareP1.testBit(i) ? 1 : 0;
                int a2 = shareP2.testBit(i) ? 1 : 0;
                int bi = b.testBit(i) ? 1 : 0;
                int r1 = prgBit(tapeP1, i), r2 = prgBit(tapeP2, i);
                int andP1 = (a1 & c1) ^ (a1 & c2) ^ (a2 & c1) ^ r1 ^ r2;
                gatesP1[i] = andP1;
                c1 = (bi * a1) ^ andP1 ^ (bi * c1);
                c2 = (bi * a2) ^ gatesP2[i] ^ (bi * c2);
                carries1[i + 1] = c1;
                carries2[i + 1] = c2;
            }

            BigInteger outP1 = ppOutShare(p1, shareP1, carries1, b, n);
            BigInteger outP2 = ppOutShare(p2, shareP2, carries2, b, n);
            BigInteger outE = new BigInteger(1, resp.outE).and(mask);
            if (!outE.xor(outP1).xor(outP2).and(mask).equals(y)) return false;

            byte[] comP1 = ppCommit(j, p1, resp.seedP1, p1 == 2 ? share2B : new byte[0],
                                    ppPackBits(gatesP1), outP1, nb);
            byte[] comP2 = ppCommit(j, p2, resp.seedP2, p2 == 2 ? share2B : new byte[0],
                                    resp.gatesP2, outP2, nb);

            byte[][] coms = new byte[3][];
            coms[e] = resp.comE; coms[p1] = comP1; coms[p2] = comP2;
            BigInteger[] outs = new BigInteger[3];
            outs[e] = outE; outs[p1] = outP1; outs[p2] = outP2;
            for (int p = 0; p < 3; p++) {
                comParts.add(coms[p]);
                outParts.add(toFixedBytes(outs[p], nb));
            }
        }

        byte[] chSeed = h(concatAll(comParts), concatAll(outParts),
                          toFixedBytes(b, nb), toFixedBytes(y, nb), msgBytes);
        for (int j = 0; j < rounds; j++) {
            if ((h(chSeed, be4(j))[0] & 0xff) % 3 != proofRounds.get(j).e) return false;
        }
        return true;
    }
}
