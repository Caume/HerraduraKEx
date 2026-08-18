package herradurakex;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * TODO #202: pure-Java port of HCRED, the hybrid Ring-LWR + Stern-F
 * credential (TODO #128).
 *
 * Statement: "I hold a Ring-LWR secret s matching public key C AND the
 * positive support of s hashes to the issued code syndrome y." A single
 * ZKBoo-(2,3) MPCitH circuit proves both relations for the SAME witness s
 * by construction — m*s is linear in s since m is public, so the Ring-LWR
 * rounding check folds cheaply into the same circuit as the Stern-F
 * syndrome check, closing the witness-splitting/self-registered-key
 * forgery a naive two-branch composition would allow (SecurityProofs-5.md
 * Sec.11.10.9/11.10.10).
 *
 * Byte-for-byte port of "Herradura cryptographic suite.py"'s hcred_phi /
 * hcred_user_keygen / hcred_syndrome / _hcred_params / _HcredTape /
 * _hcred_mpc_round / _hcred_outputs / _hcred_commit / _hcred_stmt_hash /
 * _hcred_challenges / _hcred_witness / hcred_prove / hcred_verify /
 * hcred_issue / hcred_cred_verify.
 *
 * Fixed at n=256 (KEYBITS), matching this binding's existing scope
 * ({@link Herradura}, {@link HerraduraNl}, {@link Stern} are likewise
 * fixed at 256 bits) rather than the Python demo's n=32 default; n=256 is
 * explicitly supported upstream ("n=256 supported; slow in Python" —
 * {@code --bits 256} on the Python/C/Go CLIs) and lets this port reuse
 * {@link Stern}'s existing (256-bit-only) parity-check-matrix PRF
 * directly instead of introducing a second, arbitrary-width NL-FSCX v1
 * implementation just for HCRED.
 *
 * The KKW preprocessing-model transcript variant
 * ({@code hcred_prove_kkw}/{@code hcred_verify_kkw}, ~11x smaller proofs
 * at production parameters) is out of scope for this port — the
 * ZKBoo-(2,3) path here is sufficient for interop.
 */
public final class Hcred {
    private Hcred() { }

    private static final int N = Herradura.N;          // 256
    public static final int ROWS = N / 2;                // 128 syndrome rows
    public static final int ROW_BITS = 9;                 // ceil(log2(N+1))
    public static final int W_MAX = (int) (N / 4.0 + 4 * Math.sqrt(N * 3.0 / 16));
    public static final int EPS_BITS = 5;
    public static final int EPS_OFF = 16;
    public static final int DEMO_ROUNDS = 4;
    public static final int CLI_ROUNDS = 219; // production soundness default

    private static final int RNLQ = HerraduraNl.RNLQ;   // 65537
    private static final int RNLP = HerraduraNl.RNLP;   // 4096
    private static final int INV2 = (RNLQ + 1) / 2;      // modular inverse of 2 mod RNLQ

    // -----------------------------------------------------------------
    // Modular arithmetic helpers (Z_RNLQ)
    // -----------------------------------------------------------------

    private static int addmod(int a, int b) { int r = (a + b) % RNLQ; return r < 0 ? r + RNLQ : r; }
    private static int submod(int a, int b) { int r = (a - b) % RNLQ; return r < 0 ? r + RNLQ : r; }
    private static int mulmod(int a, int b) { return (int) (((long) a * b) % RNLQ); }
    private static int addmod3(int a, int b, int c) { return (a + b + c) % RNLQ; }

    // -----------------------------------------------------------------
    // hcred_phi / hcred_user_keygen / hcred_syndrome
    // -----------------------------------------------------------------

    /** Positive-support bitmap of a ternary polynomial (bit i = [s[i]==1]). */
    static BigInteger phi(int[] sPoly) {
        BigInteger e = BigInteger.ZERO;
        for (int i = 0; i < sPoly.length; i++) {
            if (sPoly[i] == 1) e = e.setBit(i);
        }
        return e;
    }

    public static final class UserKeypair {
        public final int[] s; // private Ring-LWR secret (CBD(1))
        public final int[] c; // public Ring-LWR rounded value
        public final BigInteger e; // phi(s), the Stern-F private error vector
        UserKeypair(int[] s, int[] c, BigInteger e) { this.s = s; this.c = c; this.e = e; }
    }

    /** User enrolment keys: Ring-LWR pair (s, C) plus e = phi(s). */
    public static UserKeypair userKeygen(int[] mPoly, SecureRandom rng) {
        HerraduraNl.RnlKeypair kp = HerraduraNl.rnlKeygen(mPoly, N, RNLQ, RNLP, rng);
        return new UserKeypair(kp.s, kp.c, phi(kp.s));
    }

    /** Code syndrome y = H . e^T mod 2 for the credential. */
    public static BigInteger syndrome(BigInteger seedH, BigInteger eInt) {
        return Stern.sternSyndromeH(Stern.sternBuildH(seedH, ROWS), eInt);
    }

    // -----------------------------------------------------------------
    // Serialization / hashing helpers
    // -----------------------------------------------------------------

    private static byte[] ser(int[] vec) {
        byte[] out = new byte[vec.length * 3];
        for (int i = 0; i < vec.length; i++) {
            int c = ((vec[i] % RNLQ) + RNLQ) % RNLQ;
            out[3 * i] = (byte) (c >> 16);
            out[3 * i + 1] = (byte) (c >> 8);
            out[3 * i + 2] = (byte) c;
        }
        return out;
    }

    private static byte[] be16(int v) { return new byte[] { (byte) (v >> 8), (byte) v }; }
    private static byte[] be32(int v) { return new byte[] { (byte) (v >> 24), (byte) (v >> 16), (byte) (v >> 8), (byte) v }; }

    private static byte[] concat(byte[]... parts) {
        int total = 0;
        for (byte[] p : parts) total += p.length;
        byte[] out = new byte[total];
        int off = 0;
        for (byte[] p : parts) { System.arraycopy(p, 0, out, off, p.length); off += p.length; }
        return out;
    }

    private static byte[] toFixedBytes(BigInteger v, int nbytes) {
        byte[] raw = v.toByteArray();
        byte[] out = new byte[nbytes];
        int rawStart = Math.max(0, raw.length - nbytes);
        int copyLen = raw.length - rawStart;
        System.arraycopy(raw, rawStart, out, nbytes - copyLen, copyLen);
        return out;
    }

    static byte[] stmtHash(int[] mPoly, int[] cPoly, BigInteger seedH, BigInteger ySynd, int n, byte[] msgBytes) {
        int rows = n / 2;
        return Hfscx256.hash(concat(
            "HCRED-stmt".getBytes(StandardCharsets.US_ASCII), be32(n),
            ser(mPoly), ser(cPoly), toFixedBytes(seedH, n / 8),
            toFixedBytes(ySynd, (rows + 7) / 8), msgBytes));
    }

    private static int[] deriveChallenges(byte[] stmt, byte[] comsSer, byte[] outsSer, int rounds) {
        byte[] seed = Hfscx256.hash(concat("HCRED-ch".getBytes(StandardCharsets.US_ASCII), stmt, comsSer, outsSer));
        int[] out = new int[rounds];
        int idx = 0, ctr = 0;
        while (idx < rounds) {
            byte[] blk = Hfscx256.hash(concat("HCRED-trit".getBytes(StandardCharsets.US_ASCII), seed, be32(ctr)));
            ctr++;
            for (int i = 0; i < blk.length && idx < rounds; i++) {
                int b = blk[i] & 0xff;
                if (b < 252) out[idx++] = b % 3;
            }
        }
        return out;
    }

    // -----------------------------------------------------------------
    // Counter-mode HFSCX-256 expander: uniform Z_RNLQ draws (3-byte
    // windows masked to 17 bits, rejection-sampled)
    // -----------------------------------------------------------------

    static final class HcredTape {
        private final byte[] seed;
        private int ctr = 0;
        private byte[] buf = new byte[0];
        private int pos = 0;

        HcredTape(byte[] seed) { this.seed = seed; }

        int draw() {
            while (true) {
                if (pos + 3 > buf.length) {
                    buf = Hfscx256.hash(concat("HCRED-tape".getBytes(StandardCharsets.US_ASCII), seed, be32(ctr)));
                    ctr++;
                    pos = 0;
                }
                int v = ((buf[pos] & 0xff) << 16) | ((buf[pos + 1] & 0xff) << 8) | (buf[pos + 2] & 0xff);
                pos += 3;
                v &= 0x1FFFF;
                if (v < RNLQ) return v;
            }
        }

        int[] draws(int k) {
            int[] out = new int[k];
            for (int i = 0; i < k; i++) out[i] = draw();
            return out;
        }
    }

    // -----------------------------------------------------------------
    // 3-party MPC gates (standard ZKBoo multiplication-gate simulation)
    // -----------------------------------------------------------------

    /** Full 3-party gate: out[j] = x[j]*y[j] + x[k]*y[j] + x[j]*y[k] + R[j]-R[k], k=(j+1)%3. */
    private static int[][] gateRound(int[][] x, int[][] y, int[][] r) {
        int m = x[0].length;
        int[][] out = new int[3][m];
        for (int j = 0; j < 3; j++) {
            int k = (j + 1) % 3;
            for (int i = 0; i < m; i++) {
                long v = (long) x[j][i] * y[j][i] + (long) x[k][i] * y[j][i]
                       + (long) x[j][i] * y[k][i] + r[j][i] - r[k][i];
                out[j][i] = (int) (((v % RNLQ) + RNLQ) % RNLQ);
            }
        }
        return out;
    }

    /** Single-party partial recompute (verifier side, only party c's gate value). */
    private static int[] gateC(int[] xC, int[] xK, int[] yC, int[] yK, int[] rC, int[] rK) {
        int m = xC.length;
        int[] out = new int[m];
        for (int i = 0; i < m; i++) {
            long v = (long) xC[i] * yC[i] + (long) xK[i] * yC[i] + (long) xC[i] * yK[i] + rC[i] - rK[i];
            out[i] = (int) (((v % RNLQ) + RNLQ) % RNLQ);
        }
        return out;
    }

    // -----------------------------------------------------------------
    // Per-round output shares
    // -----------------------------------------------------------------

    static final class Outputs {
        int[][] ter, bit, del, S, y, rnd; // [3][...]
        int[] W;                           // [3]
    }

    private static Outputs computeOutputs(int[][] shS, int[][] shB, int[][] shD, int[][] a, int[][] b,
                                           int[][] g, int[][] h, int[] mPoly, BigInteger[] hRows,
                                           int n, int rows, int rowBits) {
        int nb = shB[0].length, nd = shD[0].length;
        Outputs o = new Outputs();
        o.ter = new int[3][n]; o.bit = new int[3][nb]; o.del = new int[3][nd];
        o.W = new int[3]; o.S = new int[3][rows]; o.y = new int[3][rows]; o.rnd = new int[3][n];
        for (int j = 0; j < 3; j++) {
            int[] eJ = new int[n];
            for (int i = 0; i < n; i++) eJ[i] = mulmod(addmod(a[j][i], shS[j][i]), INV2);
            for (int i = 0; i < n; i++) o.ter[j][i] = submod(b[j][i], shS[j][i]);
            for (int i = 0; i < nb; i++) o.bit[j][i] = submod(g[j][i], shB[j][i]);
            for (int i = 0; i < nd; i++) o.del[j][i] = submod(h[j][i], shD[j][i]);
            int sumE = 0;
            for (int v : eJ) sumE = addmod(sumE, v);
            o.W[j] = sumE;
            for (int r = 0; r < rows; r++) {
                long acc = 0;
                BigInteger row = hRows[r];
                for (int i = 0; i < n; i++) if (row.testBit(i)) acc += eJ[i];
                long dec = 0;
                for (int t = 0; t < rowBits; t++) dec += (1L << t) * shB[j][r * rowBits + t];
                o.S[j][r] = (int) (((acc - dec) % RNLQ + RNLQ) % RNLQ);
                o.y[j][r] = shB[j][r * rowBits] % RNLQ;
            }
            int[] msJ = HerraduraNl.rnlPolyMul(mPoly, shS[j], RNLQ, n);
            for (int i = 0; i < n; i++) {
                long dec = 0;
                for (int t = 0; t < EPS_BITS; t++) dec += (1L << t) * shD[j][i * EPS_BITS + t];
                o.rnd[j][i] = (int) (((msJ[i] - dec) % RNLQ + RNLQ) % RNLQ);
            }
        }
        return o;
    }

    private static byte[] outsSerOne(Outputs o, int j) {
        return concat(ser(o.ter[j]), ser(o.bit[j]), ser(o.del[j]),
                       ser(new int[] { o.W[j] }), ser(o.S[j]), ser(o.y[j]), ser(o.rnd[j]));
    }

    private static byte[] outputsSer(Outputs o) {
        return concat(outsSerOne(o, 0), outsSerOne(o, 1), outsSerOne(o, 2));
    }

    // -----------------------------------------------------------------
    // One MPCitH execution of the unified circuit
    // -----------------------------------------------------------------

    private static final class McpRoundResult {
        byte[][] seeds;
        int[][] shS, shB, shD, a, b, g, h;
        Outputs outs;
    }

    private static McpRoundResult mpcRound(int[] sPoly, int[] betaBits, int[] deltaBits, int[] mPoly,
                                            BigInteger[] hRows, int n, int rows, int rowBits, SecureRandom rng) {
        int nb = rows * rowBits, nd = n * EPS_BITS;
        byte[][] seeds = new byte[3][];
        for (int i = 0; i < 3; i++) { seeds[i] = new byte[32]; rng.nextBytes(seeds[i]); }
        HcredTape[] tp = new HcredTape[3];
        for (int i = 0; i < 3; i++) tp[i] = new HcredTape(seeds[i]);

        int[][] shS = new int[3][];
        shS[0] = tp[0].draws(n); shS[1] = tp[1].draws(n);
        shS[2] = new int[n];
        for (int i = 0; i < n; i++) shS[2][i] = submod(submod(sPoly[i], shS[0][i]), shS[1][i]);

        int[][] shB = new int[3][];
        shB[0] = tp[0].draws(nb); shB[1] = tp[1].draws(nb);
        shB[2] = new int[nb];
        for (int i = 0; i < nb; i++) shB[2][i] = submod(submod(betaBits[i], shB[0][i]), shB[1][i]);

        int[][] shD = new int[3][];
        shD[0] = tp[0].draws(nd); shD[1] = tp[1].draws(nd);
        shD[2] = new int[nd];
        for (int i = 0; i < nd; i++) shD[2][i] = submod(submod(deltaBits[i], shD[0][i]), shD[1][i]);

        int[][] r1 = new int[3][], r2 = new int[3][], r3 = new int[3][], r4 = new int[3][];
        for (int p = 0; p < 3; p++) {
            r1[p] = tp[p].draws(n);
            r2[p] = tp[p].draws(n);
            r3[p] = tp[p].draws(nb);
            r4[p] = tp[p].draws(nd);
        }

        int[][] a = gateRound(shS, shS, r1);
        int[][] b = gateRound(a, shS, r2);
        int[][] g = gateRound(shB, shB, r3);
        int[][] h = gateRound(shD, shD, r4);

        Outputs outs = computeOutputs(shS, shB, shD, a, b, g, h, mPoly, hRows, n, rows, rowBits);

        McpRoundResult res = new McpRoundResult();
        res.seeds = seeds; res.shS = shS; res.shB = shB; res.shD = shD;
        res.a = a; res.b = b; res.g = g; res.h = h; res.outs = outs;
        return res;
    }

    private static byte[] commit(int j, byte[] seed, int[] auxS, int[] auxB, int[] auxD,
                                  int[] aJ, int[] bJ, int[] gJ, int[] hJ, Outputs outs, int rIdx, byte[] stmt) {
        byte[] aux = (j == 2) ? concat(ser(auxS), ser(auxB), ser(auxD)) : new byte[0];
        return Hfscx256.hash(concat(
            "HCRED-com".getBytes(StandardCharsets.US_ASCII), stmt, new byte[] { (byte) j }, be16(rIdx),
            seed, aux, ser(aJ), ser(bJ), ser(gJ), ser(hJ),
            ser(outs.ter[j]), ser(outs.bit[j]), ser(outs.del[j]),
            ser(new int[] { outs.W[j] }), ser(outs.S[j]), ser(outs.y[j]), ser(outs.rnd[j])));
    }

    // -----------------------------------------------------------------
    // Witness preparation
    // -----------------------------------------------------------------

    private static final class Witness {
        int W;
        int[] beta;
        int[] delta;
    }

    private static Witness prepareWitness(int[] sPoly, int[] mPoly, int[] cPoly, BigInteger[] hRows,
                                           BigInteger ySynd, int n, int rows, int rowBits) {
        BigInteger eInt = phi(sPoly);
        Witness w = new Witness();
        w.W = eInt.bitCount();
        w.beta = new int[rows * rowBits];
        int bi = 0;
        for (int r = 0; r < rows; r++) {
            int sR = hRows[r].and(eInt).bitCount();
            int ySyndBit = ySynd.testBit(r) ? 1 : 0;
            if ((sR & 1) != ySyndBit) {
                throw new IllegalArgumentException("hcred witness does not match syndrome y");
            }
            for (int t = 0; t < rowBits; t++) w.beta[bi++] = (sR >> t) & 1;
        }
        int[] ms = HerraduraNl.rnlPolyMul(mPoly, sPoly, RNLQ, n);
        int[] lift = HerraduraNl.rnlLift(cPoly, RNLP, RNLQ);
        int hq = RNLQ / 2;
        w.delta = new int[n * EPS_BITS];
        int di = 0;
        for (int i = 0; i < n; i++) {
            int d = ((ms[i] - lift[i]) % RNLQ + RNLQ) % RNLQ;
            if (d > hq) d -= RNLQ;
            int v = d + EPS_OFF;
            if (v < 0 || v >= (1 << EPS_BITS)) {
                throw new IllegalArgumentException("hcred witness does not match public key C");
            }
            for (int t = 0; t < EPS_BITS; t++) w.delta[di++] = (v >> t) & 1;
        }
        return w;
    }

    // -----------------------------------------------------------------
    // hcred_prove / hcred_verify
    // -----------------------------------------------------------------

    public static final class ProofRound {
        public byte[][] coms; // [3]
        Outputs outs;
        public byte[] seedC, seedC1;
        public int[] a1, b1, g1, h1;
        public int[] auxS, auxB, auxD; // null unless party 2 is opened
    }

    public static final class Proof {
        public int W;
        public List<ProofRound> rounds;
    }

    /** Produces a credential-presentation proof. Throws IllegalArgumentException
     * if the witness s doesn't match the syndrome y or the public key C. */
    public static Proof prove(int[] sPoly, int[] mPoly, int[] cPoly, BigInteger seedH, BigInteger ySynd,
                               int rounds, byte[] msgBytes, SecureRandom rng) {
        BigInteger[] hRows = Stern.sternBuildH(seedH, ROWS);
        Witness wit = prepareWitness(sPoly, mPoly, cPoly, hRows, ySynd, N, ROWS, ROW_BITS);
        byte[] stmt = stmtHash(mPoly, cPoly, seedH, ySynd, N, msgBytes);

        McpRoundResult[] execs = new McpRoundResult[rounds];
        for (int i = 0; i < rounds; i++) {
            execs[i] = mpcRound(sPoly, wit.beta, wit.delta, mPoly, hRows, N, ROWS, ROW_BITS, rng);
        }

        byte[][][] coms = new byte[rounds][3][];
        for (int ri = 0; ri < rounds; ri++) {
            McpRoundResult ex = execs[ri];
            for (int j = 0; j < 3; j++) {
                coms[ri][j] = commit(j, ex.seeds[j], ex.shS[2], ex.shB[2], ex.shD[2],
                                      ex.a[j], ex.b[j], ex.g[j], ex.h[j], ex.outs, ri, stmt);
            }
        }
        byte[][] comsFlat = new byte[rounds * 3][];
        for (int ri = 0; ri < rounds; ri++) System.arraycopy(coms[ri], 0, comsFlat, ri * 3, 3);
        byte[] comsSer = concat(comsFlat);
        byte[][] outsFlat = new byte[rounds][];
        for (int ri = 0; ri < rounds; ri++) outsFlat[ri] = outputsSer(execs[ri].outs);
        byte[] outsSer = concat(outsFlat);

        int[] chals = deriveChallenges(stmt, comsSer, outsSer, rounds);

        List<ProofRound> proofRounds = new ArrayList<>(rounds);
        for (int ri = 0; ri < rounds; ri++) {
            McpRoundResult ex = execs[ri];
            int c = chals[ri], cp1 = (c + 1) % 3;
            ProofRound rd = new ProofRound();
            rd.coms = coms[ri];
            rd.outs = ex.outs;
            rd.seedC = ex.seeds[c];
            rd.seedC1 = ex.seeds[cp1];
            rd.a1 = ex.a[cp1]; rd.b1 = ex.b[cp1]; rd.g1 = ex.g[cp1]; rd.h1 = ex.h[cp1];
            if (c == 2 || cp1 == 2) { rd.auxS = ex.shS[2]; rd.auxB = ex.shB[2]; rd.auxD = ex.shD[2]; }
            proofRounds.add(rd);
        }
        Proof p = new Proof();
        p.W = wit.W;
        p.rounds = proofRounds;
        return p;
    }

    /** Verifies a credential-presentation proof (single unified MPCitH). */
    public static boolean verify(int[] mPoly, int[] cPoly, BigInteger seedH, BigInteger ySynd, Proof proof,
                                  int rounds, byte[] msgBytes) {
        if (proof.W < 1 || proof.W > W_MAX) return false;
        if (proof.rounds.size() != rounds) return false;

        byte[] stmt = stmtHash(mPoly, cPoly, seedH, ySynd, N, msgBytes);
        byte[][] comsFlat = new byte[rounds * 3][];
        for (int ri = 0; ri < rounds; ri++) System.arraycopy(proof.rounds.get(ri).coms, 0, comsFlat, ri * 3, 3);
        byte[] comsSer = concat(comsFlat);
        byte[][] outsFlat = new byte[rounds][];
        for (int ri = 0; ri < rounds; ri++) outsFlat[ri] = outputsSer(proof.rounds.get(ri).outs);
        byte[] outsSer = concat(outsFlat);

        BigInteger[] hRows = Stern.sternBuildH(seedH, ROWS);
        int[] lift = HerraduraNl.rnlLift(cPoly, RNLP, RNLQ);
        int[] chals = deriveChallenges(stmt, comsSer, outsSer, rounds);

        for (int ri = 0; ri < rounds; ri++) {
            ProofRound rd = proof.rounds.get(ri);
            int c = chals[ri], cp1 = (c + 1) % 3;
            Outputs outs = rd.outs;
            int nb = outs.bit[0].length, nd = outs.del[0].length;

            for (int i = 0; i < N; i++) if (addmod3(outs.ter[0][i], outs.ter[1][i], outs.ter[2][i]) != 0) return false;
            for (int i = 0; i < nb; i++) if (addmod3(outs.bit[0][i], outs.bit[1][i], outs.bit[2][i]) != 0) return false;
            for (int i = 0; i < nd; i++) if (addmod3(outs.del[0][i], outs.del[1][i], outs.del[2][i]) != 0) return false;
            if (addmod3(outs.W[0], outs.W[1], outs.W[2]) != proof.W) return false;
            for (int r = 0; r < ROWS; r++) {
                if (addmod3(outs.S[0][r], outs.S[1][r], outs.S[2][r]) != 0) return false;
                int ySyndBit = ySynd.testBit(r) ? 1 : 0;
                if (addmod3(outs.y[0][r], outs.y[1][r], outs.y[2][r]) != ySyndBit) return false;
            }
            for (int i = 0; i < N; i++) {
                int expected = ((lift[i] - EPS_OFF) % RNLQ + RNLQ) % RNLQ;
                if (addmod3(outs.rnd[0][i], outs.rnd[1][i], outs.rnd[2][i]) != expected) return false;
            }

            if ((c == 2 || cp1 == 2) && (rd.auxS == null || rd.auxB == null || rd.auxD == null)) return false;

            HcredTape tC = new HcredTape(rd.seedC), tC1 = new HcredTape(rd.seedC1);
            int[] shSc = (c != 2) ? tC.draws(N) : rd.auxS.clone();
            int[] shBc = (c != 2) ? tC.draws(nb) : rd.auxB.clone();
            int[] shDc = (c != 2) ? tC.draws(nd) : rd.auxD.clone();
            int[] shSc1 = (cp1 != 2) ? tC1.draws(N) : rd.auxS.clone();
            int[] shBc1 = (cp1 != 2) ? tC1.draws(nb) : rd.auxB.clone();
            int[] shDc1 = (cp1 != 2) ? tC1.draws(nd) : rd.auxD.clone();
            int[] r1c = tC.draws(N), r2c = tC.draws(N), r3c = tC.draws(nb), r4c = tC.draws(nd);
            int[] r1c1 = tC1.draws(N), r2c1 = tC1.draws(N), r3c1 = tC1.draws(nb), r4c1 = tC1.draws(nd);

            int[] aC = gateC(shSc, shSc1, shSc, shSc1, r1c, r1c1);
            int[] bC = gateC(aC, rd.a1, shSc, shSc1, r2c, r2c1);
            int[] gC = gateC(shBc, shBc1, shBc, shBc1, r3c, r3c1);
            int[] hC = gateC(shDc, shDc1, shDc, shDc1, r4c, r4c1);

            int[][] shS3 = new int[3][], shB3 = new int[3][], shD3 = new int[3][];
            shS3[c] = shSc; shS3[cp1] = shSc1;
            shB3[c] = shBc; shB3[cp1] = shBc1;
            shD3[c] = shDc; shD3[cp1] = shDc1;
            int[][] a3 = new int[3][], b3 = new int[3][], g3 = new int[3][], h3 = new int[3][];
            a3[c] = aC; a3[cp1] = rd.a1;
            b3[c] = bC; b3[cp1] = rd.b1;
            g3[c] = gC; g3[cp1] = rd.g1;
            h3[c] = hC; h3[cp1] = rd.h1;

            for (int jj = 0; jj < 2; jj++) {
                int j = (jj == 0) ? c : cp1;
                int[] eJ = new int[N];
                for (int i = 0; i < N; i++) eJ[i] = mulmod(addmod(a3[j][i], shS3[j][i]), INV2);
                int[] oTer = new int[N];
                for (int i = 0; i < N; i++) oTer[i] = submod(b3[j][i], shS3[j][i]);
                int[] oBit = new int[nb];
                for (int i = 0; i < nb; i++) oBit[i] = submod(g3[j][i], shB3[j][i]);
                int[] oDel = new int[nd];
                for (int i = 0; i < nd; i++) oDel[i] = submod(h3[j][i], shD3[j][i]);
                int oW = 0;
                for (int v : eJ) oW = addmod(oW, v);
                if (!Arrays.equals(oTer, outs.ter[j]) || !Arrays.equals(oBit, outs.bit[j])
                        || !Arrays.equals(oDel, outs.del[j]) || oW != outs.W[j]) return false;
                for (int r = 0; r < ROWS; r++) {
                    long acc = 0;
                    BigInteger row = hRows[r];
                    for (int i = 0; i < N; i++) if (row.testBit(i)) acc += eJ[i];
                    long dec = 0;
                    for (int t = 0; t < ROW_BITS; t++) dec += (1L << t) * shB3[j][r * ROW_BITS + t];
                    int sVal = (int) (((acc - dec) % RNLQ + RNLQ) % RNLQ);
                    if (sVal != outs.S[j][r]) return false;
                    if ((shB3[j][r * ROW_BITS] % RNLQ) != outs.y[j][r]) return false;
                }
                int[] msJ = HerraduraNl.rnlPolyMul(mPoly, shS3[j], RNLQ, N);
                for (int i = 0; i < N; i++) {
                    long dec = 0;
                    for (int t = 0; t < EPS_BITS; t++) dec += (1L << t) * shD3[j][i * EPS_BITS + t];
                    int rndVal = (int) (((msJ[i] - dec) % RNLQ + RNLQ) % RNLQ);
                    if (rndVal != outs.rnd[j][i]) return false;
                }
                byte[] aux = (j == 2) ? concat(ser(rd.auxS), ser(rd.auxB), ser(rd.auxD)) : new byte[0];
                byte[] seedJ = (j == c) ? rd.seedC : rd.seedC1;
                byte[] com = Hfscx256.hash(concat(
                    "HCRED-com".getBytes(StandardCharsets.US_ASCII), stmt, new byte[] { (byte) j }, be16(ri),
                    seedJ, aux, ser(a3[j]), ser(b3[j]), ser(g3[j]), ser(h3[j]),
                    ser(outs.ter[j]), ser(outs.bit[j]), ser(outs.del[j]),
                    ser(new int[] { outs.W[j] }), ser(outs.S[j]), ser(outs.y[j]), ser(outs.rnd[j])));
                if (!Arrays.equals(com, rd.coms[j])) return false;
            }
        }
        return true;
    }

    // -----------------------------------------------------------------
    // Issuer credential: an HPKS-Stern-F signature over the statement
    // -----------------------------------------------------------------

    private static BigInteger issuerMsg(int[] mPoly, int[] cPoly, BigInteger seedH, BigInteger ySynd, int n) {
        byte[] digest = stmtHash(mPoly, cPoly, seedH, ySynd, n, "HCRED-issue".getBytes(StandardCharsets.US_ASCII));
        return new BigInteger(1, digest); // issuer_n == 256 fixed, no truncating shift needed
    }

    public static Stern.SternSignature issue(int[] mPoly, int[] cPoly, BigInteger seedH, BigInteger ySynd, int n,
                                              BigInteger issuerE, BigInteger issuerSeed, int rounds, SecureRandom rng) {
        BigInteger msg = issuerMsg(mPoly, cPoly, seedH, ySynd, n);
        return Stern.hpksSternFSign(msg, issuerE, issuerSeed, rounds, rng);
    }

    public static boolean credVerify(int[] mPoly, int[] cPoly, BigInteger seedH, BigInteger ySynd, int n,
                                      Stern.SternSignature credSig, BigInteger issuerSeed, BigInteger issuerSyn) {
        BigInteger msg = issuerMsg(mPoly, cPoly, seedH, ySynd, n);
        return Stern.hpksSternFVerify(msg, credSig, issuerSeed, issuerSyn);
    }
}
