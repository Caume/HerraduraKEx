package herradurakex;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

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
 * forgery a naive two-branch composition would allow (SecurityProofs-7.md
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
 * TODO #261: the KKW preprocessing-model transcript variant
 * ({@code hcred_prove_kkw}/{@code hcred_verify_kkw} in Python,
 * {@code HcredProveKkw}/{@code HcredVerifyKkw} in Go, {@code hcred_prove_kkw}/
 * {@code hcred_verify_kkw} in C, ~11x smaller proofs at production
 * parameters) is ported below as {@link #proveKkw}/{@link #verifyKkw},
 * translated from the Go port (search "HCRED-KKW"). Not wired to any CLI
 * in any language, so parity is this method pair plus demo output, not a
 * new {@code --algo}/{@code --transcript} flag.
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
    // HCRED-KKW: preprocessing-model MPCitH transcript (TODO #128 Batch 3 /
    // ported under TODO #261, translated from herradura/herradura.go's
    // HcredProveKkw/HcredVerifyKkw -- itself a port of Python's
    // hcred_prove_kkw/hcred_verify_kkw).  Same statement/circuit as
    // prove/verify above, encoded with the KKW (Katz-Kolesnikov-Wang 2018)
    // N-party preprocessing paradigm instead of ZKBoo-(2,3); see the Go
    // source's doc comment for the full protocol write-up.  Not wired to
    // any CLI in any language.
    // -----------------------------------------------------------------

    public static final int KKW_DEMO_N   = 4; // demo parties;      production: 64
    public static final int KKW_DEMO_M   = 8; // demo emulations;   production: 343
    public static final int KKW_DEMO_TAU = 4; // demo online execs; production: 27

    /** One multiplication gate: (xKind,xIdx,yKind,yIdx,zIdx).  xKind/yKind is
     * 'i' for an input wire ([0,n)=s, [n,n+nb)=beta, [n+nb,n+nb+nd)=delta) or
     * 'z' for a Z wire ([0,n)=a, [n,2n)=b, [2n,2n+nb)=g, [2n+nb,2n+nb+nd)=h). */
    private static final class KkwGate {
        final char xKind; final int xIdx; final char yKind; final int yIdx; final int zIdx;
        KkwGate(char xKind, int xIdx, char yKind, int yIdx, int zIdx) {
            this.xKind = xKind; this.xIdx = xIdx; this.yKind = yKind; this.yIdx = yIdx; this.zIdx = zIdx;
        }
    }

    private static KkwGate[] kkwGates(int n, int nb, int nd) {
        KkwGate[] gates = new KkwGate[2 * n + nb + nd];
        int k = 0;
        for (int i = 0; i < n; i++) gates[k++] = new KkwGate('i', i, 'i', i, i);                    // a = s^2
        for (int i = 0; i < n; i++) gates[k++] = new KkwGate('z', i, 'i', i, n + i);                 // b = a*s
        for (int i = 0; i < nb; i++) gates[k++] = new KkwGate('i', n + i, 'i', n + i, 2 * n + i);    // g = beta^2
        for (int i = 0; i < nd; i++)
            gates[k++] = new KkwGate('i', n + nb + i, 'i', n + nb + i, 2 * n + nb + i);              // h = delta^2
        return gates;
    }

    private static int kkwLevels(int N) { int l = 0, t = N; while (t > 1) { l++; t >>= 1; } return l; }
    private static int kkwNodeIdx(int l, int i) { return (1 << l) - 1 + i; }

    private static final byte[] TREE0 = "HCRED-tree0".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] TREE1 = "HCRED-tree1".getBytes(StandardCharsets.US_ASCII);

    /** Expands a binary seed tree; returns all 2N-1 nodes indexed by kkwNodeIdx. */
    private static byte[][] kkwTree(byte[] root, int N) {
        int levels = kkwLevels(N);
        byte[][] nodes = new byte[2 * N - 1][];
        nodes[kkwNodeIdx(0, 0)] = root;
        for (int l = 0; l < levels; l++) {
            for (int i = 0; i < (1 << l); i++) {
                byte[] par = nodes[kkwNodeIdx(l, i)];
                nodes[kkwNodeIdx(l + 1, 2 * i)] = Hfscx256.hash(concat(TREE0, par));
                nodes[kkwNodeIdx(l + 1, 2 * i + 1)] = Hfscx256.hash(concat(TREE1, par));
            }
        }
        return nodes;
    }

    /** One sibling-subtree entry in a KKW seed-tree opening. */
    public static final class KkwPathEntry {
        public final int l, i;
        public final byte[] node;
        KkwPathEntry(int l, int i, byte[] node) { this.l = l; this.i = i; this.node = node; }
    }

    /** Sibling path revealing every leaf except `hide` (log2 N entries). */
    private static List<KkwPathEntry> kkwTreeOpen(byte[][] nodes, int N, int hide) {
        int levels = kkwLevels(N);
        List<KkwPathEntry> out = new ArrayList<>(levels);
        int idx = hide;
        for (int l = levels; l >= 1; l--) {
            int sib = idx ^ 1;
            out.add(new KkwPathEntry(l, sib, nodes[kkwNodeIdx(l, sib)]));
            idx >>= 1;
        }
        return out;
    }

    private static void kkwExpand(byte[][] leavesOut, boolean[] known, int l, int idx, byte[] node, int levels) {
        if (l == levels) { leavesOut[idx] = node; known[idx] = true; return; }
        byte[] c0 = Hfscx256.hash(concat(TREE0, node));
        kkwExpand(leavesOut, known, l + 1, 2 * idx, c0, levels);
        byte[] c1 = Hfscx256.hash(concat(TREE1, node));
        kkwExpand(leavesOut, known, l + 1, 2 * idx + 1, c1, levels);
    }

    /** Rebuilds every leaf covered by a sibling path (all except the hidden one). */
    private static void kkwTreeRecover(byte[][] leavesOut, boolean[] known, List<KkwPathEntry> path, int N) {
        int levels = kkwLevels(N);
        for (KkwPathEntry pe : path) kkwExpand(leavesOut, known, pe.l, pe.i, pe.node, levels);
    }

    private static boolean kkwLeavesCoverAllExcept(boolean[] known, int N, int hide) {
        int cnt = 0;
        for (int i = 0; i < N; i++) {
            if (i == hide) { if (known[i]) return false; }
            else { if (!known[i]) return false; cnt++; }
        }
        return cnt == N - 1;
    }

    private static final class KkwShares {
        final int[] li, lz, lxy;
        KkwShares(int[] li, int[] lz, int[] lxy) { this.li = li; this.lz = lz; this.lxy = lxy; }
    }

    /** Derives one party's preprocessing shares from its seed.
     * Draw order: lambda_in (I), lambda_z (G), lambda_xy (G). */
    private static KkwShares kkwParty(byte[] seed, int I, int G) {
        HcredTape tp = new HcredTape(seed);
        return new KkwShares(tp.draws(I), tp.draws(G), tp.draws(G));
    }

    private static final class KkwPre {
        byte[][] nodes;
        int[][] lamIn, lamZ, lamXY;
        int[] aux;
        byte[][] coms; // filled by the caller after state commitments are computed
    }

    /** One preprocessing emulation from its root seed.  lamXY[N-1] is
     * corrected in place by aux so that sum_i [lambda_xy]_i ==
     * lambda_x*lambda_y per gate. */
    private static KkwPre kkwPre(byte[] root, int N, int I, int G, KkwGate[] gates) {
        KkwPre p = new KkwPre();
        p.nodes = kkwTree(root, N);
        int levels = kkwLevels(N);
        p.lamIn = new int[N][]; p.lamZ = new int[N][]; p.lamXY = new int[N][];
        for (int j = 0; j < N; j++) {
            KkwShares sh = kkwParty(p.nodes[kkwNodeIdx(levels, j)], I, G);
            p.lamIn[j] = sh.li; p.lamZ[j] = sh.lz; p.lamXY[j] = sh.lxy;
        }
        int[] tin = new int[I];
        for (int w = 0; w < I; w++) {
            long s = 0;
            for (int j = 0; j < N; j++) s += p.lamIn[j][w];
            tin[w] = (int) (((s % RNLQ) + RNLQ) % RNLQ);
        }
        int[] tz = new int[G];
        for (int w = 0; w < G; w++) {
            long s = 0;
            for (int j = 0; j < N; j++) s += p.lamZ[j][w];
            tz[w] = (int) (((s % RNLQ) + RNLQ) % RNLQ);
        }
        p.aux = new int[gates.length];
        for (int g = 0; g < gates.length; g++) {
            KkwGate gt = gates[g];
            long lx = gt.xKind == 'i' ? tin[gt.xIdx] : tz[gt.xIdx];
            long ly = gt.yKind == 'i' ? tin[gt.yIdx] : tz[gt.yIdx];
            long s = 0;
            for (int j = 0; j < N; j++) s += p.lamXY[j][g];
            long cor = (((lx * ly - s) % RNLQ) + RNLQ) % RNLQ;
            p.aux[g] = (int) cor;
            p.lamXY[N - 1][g] = (int) ((((long) p.lamXY[N - 1][g] + cor) % RNLQ + RNLQ) % RNLQ);
        }
        return p;
    }

    private static final byte[] KKWST = "HCRED-kkwst".getBytes(StandardCharsets.US_ASCII);

    /** Commits to party j's preprocessing state in emulation e. */
    private static byte[] kkwStateCom(int e, int j, byte[] seed, int[] aux) {
        if (aux != null) return Hfscx256.hash(concat(KKWST, be16(e), new byte[] { (byte) j }, seed, ser(aux)));
        return Hfscx256.hash(concat(KKWST, be16(e), new byte[] { (byte) j }, seed));
    }

    /** Applies the (linear) output map of the unified circuit to a wire
     * valuation -- used both for masked values zhat and per-party mask
     * shares, since the map is linear and so commutes with additive sharing.
     * vecIn has length I = n+nb+nd; vecZ has length G = 2n+nb+nd. */
    private static int[] kkwOutmap(int[] vecIn, int[] vecZ, int[] mPoly, BigInteger[] hRows,
                                    int n, int rows, int rowBits) {
        int nb = rows * rowBits;
        int nd = vecIn.length - n - nb;
        int[] out = new int[n + nb + nd + 1 + 2 * rows + n];
        int k = 0;
        for (int i = 0; i < n; i++) out[k++] = submod(vecZ[n + i], vecIn[i]);                 // b_ - s_
        for (int i = 0; i < nb; i++) out[k++] = submod(vecZ[2 * n + i], vecIn[n + i]);         // g_ - B_
        for (int i = 0; i < nd; i++) out[k++] = submod(vecZ[2 * n + nb + i], vecIn[n + nb + i]); // h_ - D_
        long wsum = 0;
        for (int i = 0; i < n; i++) wsum += (long) (vecZ[i] + vecIn[i]) * INV2;
        out[k++] = (int) (((wsum % RNLQ) + RNLQ) % RNLQ);
        for (int r = 0; r < rows; r++) {
            long acc = 0;
            for (int i = 0; i < n; i++) if (hRows[r].testBit(i)) acc += (long) (vecZ[i] + vecIn[i]) * INV2;
            long dec = 0;
            for (int t = 0; t < rowBits; t++) dec += (1L << t) * vecIn[n + r * rowBits + t];
            out[k++] = (int) ((((acc - dec) % RNLQ) + RNLQ) % RNLQ);
        }
        for (int r = 0; r < rows; r++)
            out[k++] = (int) (((long) vecIn[n + r * rowBits] % RNLQ + RNLQ) % RNLQ);
        int[] sNorm = new int[n];
        for (int i = 0; i < n; i++) sNorm[i] = ((vecIn[i] % RNLQ) + RNLQ) % RNLQ;
        int[] ms = HerraduraNl.rnlPolyMul(mPoly, sNorm, RNLQ, n);
        for (int i = 0; i < n; i++) {
            long dec = 0;
            for (int t = 0; t < EPS_BITS; t++) dec += (1L << t) * vecIn[n + nb + i * EPS_BITS + t];
            out[k++] = (int) ((((long) ms[i] - dec) % RNLQ + RNLQ) % RNLQ);
        }
        return out;
    }

    /** Public output values v_o, in kkwOutmap's order. */
    private static int[] kkwTargets(int W, BigInteger ySynd, int[] cPoly, int n, int rows, int rowBits) {
        int nb = rows * rowBits;
        int nd = n * EPS_BITS;
        int[] lift = HerraduraNl.rnlLift(cPoly, RNLP, RNLQ);
        int[] v = new int[n + nb + nd + 1 + 2 * rows + n];
        int k = n + nb + nd;
        v[k++] = ((W % RNLQ) + RNLQ) % RNLQ;
        k += rows; // zeros, already default-initialized
        for (int r = 0; r < rows; r++) v[k++] = ySynd.testBit(r) ? 1 : 0;
        for (int i = 0; i < n; i++) v[k++] = (((lift[i] - EPS_OFF) % RNLQ) + RNLQ) % RNLQ;
        return v;
    }

    private static final byte[] KKWTAG = "HCRED-kkw".getBytes(StandardCharsets.US_ASCII);

    /** `count` FS integers in [0,modulus) via rejection sampling from an
     * HFSCX stream.  1-byte windows for modulus <= 256, 2-byte windows above. */
    private static int[] kkwFsInts(String tag, byte[] material, int count, int modulus, boolean distinct) {
        int width = modulus > 256 ? 2 : 1;
        int space = 1 << (8 * width);
        int lim = (space / modulus) * modulus;
        int[] out = new int[count];
        int have = 0;
        java.util.Set<Integer> seen = distinct ? new java.util.HashSet<>() : null;
        int ctr = 0;
        byte[] tagBytes = tag.getBytes(StandardCharsets.US_ASCII);
        while (have < count) {
            byte[] blk = Hfscx256.hash(concat(KKWTAG, tagBytes, material, be32(ctr)));
            ctr++;
            for (int w = 0; w + width <= blk.length; w += width) {
                int v = 0;
                for (int b = 0; b < width; b++) v = (v << 8) | (blk[w + b] & 0xff);
                if (v < lim && have < count) {
                    v %= modulus;
                    if (distinct && !seen.add(v)) continue;
                    out[have++] = v;
                }
            }
        }
        return out;
    }

    /** The revealed data for one opened (online) emulation. */
    public static final class KkwOnlineProof {
        public final List<KkwPathEntry> path;
        public final byte[] comH;
        public final int pbar;
        public final int[] aux; // null iff pbar == nPar-1
        public final int[] zin;
        public final int[] t;
        public final int u;
        KkwOnlineProof(List<KkwPathEntry> path, byte[] comH, int pbar, int[] aux, int[] zin, int[] t, int u) {
            this.path = path; this.comH = comH; this.pbar = pbar; this.aux = aux;
            this.zin = zin; this.t = t; this.u = u;
        }
    }

    /** A KKW-encoded credential-presentation proof (TODO #261). */
    public static final class HcredKkwProof {
        public final int W;
        public final int nPar, m, tau;
        public final Map<Integer, byte[]> pre;             // e -> root seed, unopened only
        public final Map<Integer, KkwOnlineProof> online;
        HcredKkwProof(int W, int nPar, int m, int tau, Map<Integer, byte[]> pre, Map<Integer, KkwOnlineProof> online) {
            this.W = W; this.nPar = nPar; this.m = m; this.tau = tau; this.pre = pre; this.online = online;
        }
    }

    private static final class KkwOnlineState {
        final int[] zin;
        final int[][] tvec;
        final int[] zz;
        final KkwPre ps;
        int[] us;
        KkwOnlineState(int[] zin, int[][] tvec, int[] zz, KkwPre ps) {
            this.zin = zin; this.tvec = tvec; this.zz = zz; this.ps = ps;
        }
    }

    /** Produces a KKW-encoded credential-presentation proof (same
     * statement/circuit as {@link #prove}).  Production soundness needs
     * (nPar,m,tau) = (64,343,27) for 2^-128.  Throws
     * IllegalArgumentException if the witness s doesn't match the syndrome
     * y or the public key C, or nPar is not a power of two. */
    public static HcredKkwProof proveKkw(int[] sPoly, int[] mPoly, int[] cPoly, BigInteger seedH, BigInteger ySynd,
                                          int nPar, int m, int tau, byte[] msgBytes, SecureRandom rng) {
        if (nPar <= 0 || (nPar & (nPar - 1)) != 0)
            throw new IllegalArgumentException("proveKkw: nPar must be a power of two");
        if (tau < 1 || tau > m)
            throw new IllegalArgumentException("proveKkw: need 1 <= tau <= m");
        int rows = ROWS, rowBits = ROW_BITS;
        int nb = rows * rowBits;
        int nd = N * EPS_BITS;
        int I = N + nb + nd;
        int G = 2 * N + nb + nd;
        KkwGate[] gates = kkwGates(N, nb, nd);

        BigInteger[] hRows = Stern.sternBuildH(seedH, ROWS);
        Witness wit = prepareWitness(sPoly, mPoly, cPoly, hRows, ySynd, N, ROWS, ROW_BITS);
        int W = wit.W;
        int[] wIn = new int[I];
        for (int i = 0; i < N; i++) wIn[i] = ((sPoly[i] % RNLQ) + RNLQ) % RNLQ;
        System.arraycopy(wit.beta, 0, wIn, N, nb);
        System.arraycopy(wit.delta, 0, wIn, N + nb, nd);
        byte[] stmt = stmtHash(mPoly, cPoly, seedH, ySynd, N, msgBytes);

        // Preprocessing: M emulations, commit.
        byte[][] roots = new byte[m][];
        KkwPre[] pre = new KkwPre[m];
        byte[][] hEs = new byte[m][];
        int levels = kkwLevels(nPar);
        byte[] emTag = "HCRED-kkwem".getBytes(StandardCharsets.US_ASCII);
        for (int e = 0; e < m; e++) {
            byte[] root = new byte[32];
            rng.nextBytes(root);
            KkwPre p = kkwPre(root, nPar, I, G, gates);
            byte[][] coms = new byte[nPar][];
            for (int j = 0; j < nPar; j++) {
                int[] a = (j == nPar - 1) ? p.aux : null;
                coms[j] = kkwStateCom(e, j, p.nodes[kkwNodeIdx(levels, j)], a);
            }
            p.coms = coms;
            hEs[e] = Hfscx256.hash(concat(emTag, be16(e), concat(coms)));
            roots[e] = root;
            pre[e] = p;
        }
        byte[] hPre = Hfscx256.hash(concat("HCRED-kkwpre".getBytes(StandardCharsets.US_ASCII), stmt, concat(hEs)));

        // Challenge 1: cut-and-choose subset.
        int[] subset = kkwFsInts("c1", hPre, tau, m, true);
        Arrays.sort(subset);

        // Online phase for the tau selected emulations.
        Map<Integer, KkwOnlineState> online = new java.util.LinkedHashMap<>();
        for (int e : subset) {
            KkwPre ps = pre[e];
            int[] tin = new int[I];
            for (int w = 0; w < I; w++) {
                long s = 0;
                for (int j = 0; j < nPar; j++) s += ps.lamIn[j][w];
                tin[w] = (int) (((s % RNLQ) + RNLQ) % RNLQ);
            }
            int[] zin = new int[I];
            for (int w = 0; w < I; w++) zin[w] = (int) ((((long) wIn[w] + tin[w]) % RNLQ + RNLQ) % RNLQ);
            int[][] tvec = new int[nPar][gates.length];
            int[] zz = new int[G];
            for (int gidx = 0; gidx < gates.length; gidx++) {
                KkwGate g = gates[gidx];
                long zx = g.xKind == 'i' ? zin[g.xIdx] : zz[g.xIdx];
                long zy = g.yKind == 'i' ? zin[g.yIdx] : zz[g.yIdx];
                long acc = 0;
                for (int j = 0; j < nPar; j++) {
                    long lx = g.xKind == 'i' ? ps.lamIn[j][g.xIdx] : ps.lamZ[j][g.xIdx];
                    long ly = g.yKind == 'i' ? ps.lamIn[j][g.yIdx] : ps.lamZ[j][g.yIdx];
                    long t = -zx * ly - zy * lx + ps.lamXY[j][gidx] + ps.lamZ[j][g.zIdx];
                    if (j == 0) t += zx * zy;
                    t = ((t % RNLQ) + RNLQ) % RNLQ;
                    tvec[j][gidx] = (int) t;
                    acc += t;
                }
                zz[g.zIdx] = (int) (((acc % RNLQ) + RNLQ) % RNLQ);
            }
            online.put(e, new KkwOnlineState(zin, tvec, zz, ps));
        }

        // Batched output check.
        List<byte[]> mskParts = new ArrayList<>();
        for (int e : subset) {
            KkwOnlineState os = online.get(e);
            mskParts.add(ser(os.zin));
            for (int j = 0; j < nPar; j++) mskParts.add(ser(os.tvec[j]));
        }
        byte[] hMsk = Hfscx256.hash(concat("HCRED-kkwmsk".getBytes(StandardCharsets.US_ASCII),
                                            concat(mskParts.toArray(new byte[0][]))));
        int K = I + 1 + 2 * rows + N;
        byte[] rhoSeed = Hfscx256.hash(concat("HCRED-kkwrho".getBytes(StandardCharsets.US_ASCII), stmt, hPre, hMsk));
        int[] rho = new HcredTape(rhoSeed).draws(K);
        List<byte[]> comOns = new ArrayList<>();
        byte[] onTag = "HCRED-kkwon".getBytes(StandardCharsets.US_ASCII);
        for (int e : subset) {
            KkwOnlineState os = online.get(e);
            int[] us = new int[nPar];
            for (int j = 0; j < nPar; j++) {
                int[] lo = kkwOutmap(os.ps.lamIn[j], os.ps.lamZ[j], mPoly, hRows, N, rows, rowBits);
                long s = 0;
                for (int k = 0; k < K; k++) s += (long) rho[k] * lo[k];
                us[j] = (int) (((s % RNLQ) + RNLQ) % RNLQ);
            }
            os.us = us;
            for (int j = 0; j < nPar; j++) {
                byte[] buf = concat(onTag, be16(e), new byte[] { (byte) j }, ser(os.tvec[j]), ser(new int[] { us[j] }));
                comOns.add(Hfscx256.hash(buf));
            }
        }
        byte[] hOn = Hfscx256.hash(concat("HCRED-kkwhon".getBytes(StandardCharsets.US_ASCII),
                                           concat(comOns.toArray(new byte[0][]))));

        // Challenge 2: hidden party per online emulation.
        byte[] c2mat = concat(hPre, hMsk, hOn);
        int[] pbars = kkwFsInts("c2", c2mat, tau, nPar, false);

        // Assemble proof.
        boolean[] isOpen = new boolean[m];
        for (int e : subset) isOpen[e] = true;
        Map<Integer, byte[]> proofPre = new java.util.LinkedHashMap<>();
        for (int e = 0; e < m; e++) if (!isOpen[e]) proofPre.put(e, roots[e]);

        Map<Integer, KkwOnlineProof> proofOn = new java.util.LinkedHashMap<>();
        for (int k = 0; k < subset.length; k++) {
            int e = subset[k];
            int pb = pbars[k];
            KkwOnlineState os = online.get(e);
            List<KkwPathEntry> path = kkwTreeOpen(os.ps.nodes, nPar, pb);
            int[] aux = (pb != nPar - 1) ? os.ps.aux : null;
            proofOn.put(e, new KkwOnlineProof(path, os.ps.coms[pb], pb, aux, os.zin, os.tvec[pb], os.us[pb]));
        }
        return new HcredKkwProof(W, nPar, m, tau, proofPre, proofOn);
    }

    private static final class KkwEmu {
        final Map<Integer, KkwShares> shares;
        final Map<Integer, int[]> tvec;
        final int[] zz;
        KkwEmu(Map<Integer, KkwShares> shares, Map<Integer, int[]> tvec, int[] zz) {
            this.shares = shares; this.tvec = tvec; this.zz = zz;
        }
    }

    /** Verifies a KKW-encoded credential-presentation proof. */
    public static boolean verifyKkw(int[] mPoly, int[] cPoly, BigInteger seedH, BigInteger ySynd,
                                     HcredKkwProof proof, byte[] msgBytes) {
        int nPar = proof.nPar, m = proof.m, tau = proof.tau;
        if (nPar <= 0 || (nPar & (nPar - 1)) != 0 || tau < 1 || tau > m) return false;
        if (proof.W < 1 || proof.W > W_MAX) return false;
        if (proof.pre.size() != m - tau || proof.online.size() != tau) return false;

        int rows = ROWS, rowBits = ROW_BITS;
        int nb = rows * rowBits;
        int nd = N * EPS_BITS;
        int I = N + nb + nd;
        int G = 2 * N + nb + nd;
        KkwGate[] gates = kkwGates(N, nb, nd);
        BigInteger[] hRows = Stern.sternBuildH(seedH, ROWS);
        byte[] stmt = stmtHash(mPoly, cPoly, seedH, ySynd, N, msgBytes);
        int levels = kkwLevels(nPar);
        byte[] emTag = "HCRED-kkwem".getBytes(StandardCharsets.US_ASCII);

        byte[][] hEs = new byte[m][];
        Map<Integer, byte[][]> onLeaves = new java.util.LinkedHashMap<>();
        for (Map.Entry<Integer, byte[]> ent : proof.pre.entrySet()) {
            int e = ent.getKey();
            if (e < 0 || e >= m || hEs[e] != null) return false;
            KkwPre p = kkwPre(ent.getValue(), nPar, I, G, gates);
            byte[][] coms = new byte[nPar][];
            for (int j = 0; j < nPar; j++) {
                int[] a = (j == nPar - 1) ? p.aux : null;
                coms[j] = kkwStateCom(e, j, p.nodes[kkwNodeIdx(levels, j)], a);
            }
            hEs[e] = Hfscx256.hash(concat(emTag, be16(e), concat(coms)));
        }
        for (Map.Entry<Integer, KkwOnlineProof> ent : proof.online.entrySet()) {
            int e = ent.getKey();
            KkwOnlineProof od = ent.getValue();
            if (e < 0 || e >= m || hEs[e] != null) return false;
            int pb = od.pbar;
            if (pb < 0 || pb >= nPar) return false;
            if (pb != nPar - 1 && od.aux == null) return false;

            byte[][] leaves = new byte[nPar][];
            boolean[] known = new boolean[nPar];
            kkwTreeRecover(leaves, known, od.path, nPar);
            if (!kkwLeavesCoverAllExcept(known, nPar, pb)) return false;
            onLeaves.put(e, leaves);

            byte[][] coms = new byte[nPar][];
            for (int j = 0; j < nPar; j++) {
                if (j == pb) {
                    coms[j] = od.comH;
                } else {
                    int[] a = (j == nPar - 1) ? od.aux : null;
                    coms[j] = kkwStateCom(e, j, leaves[j], a);
                }
            }
            hEs[e] = Hfscx256.hash(concat(emTag, be16(e), concat(coms)));
        }
        for (byte[] h : hEs) if (h == null) return false;
        byte[] hPre = Hfscx256.hash(concat("HCRED-kkwpre".getBytes(StandardCharsets.US_ASCII), stmt, concat(hEs)));

        // Challenge-1 consistency.
        int[] subset = kkwFsInts("c1", hPre, tau, m, true);
        Arrays.sort(subset);
        int[] onlineKeys = new int[proof.online.size()];
        { int idx = 0; for (int e : proof.online.keySet()) onlineKeys[idx++] = e; }
        Arrays.sort(onlineKeys);
        if (!Arrays.equals(subset, onlineKeys)) return false;

        // Re-emulate opened parties online.
        Map<Integer, KkwEmu> emu = new java.util.LinkedHashMap<>();
        for (int e : subset) {
            KkwOnlineProof od = proof.online.get(e);
            int pb = od.pbar;
            int[] zin = od.zin;
            if (zin == null || zin.length != I || od.t == null || od.t.length != gates.length) return false;

            Map<Integer, KkwShares> shares = new java.util.LinkedHashMap<>();
            byte[][] leaves = onLeaves.get(e);
            for (int j = 0; j < nPar; j++) {
                if (j == pb) continue;
                KkwShares sh = kkwParty(leaves[j], I, G);
                if (j == nPar - 1) {
                    if (od.aux == null || od.aux.length != G) return false;
                    for (int g = 0; g < G; g++)
                        sh.lxy[g] = (int) ((((long) sh.lxy[g] + od.aux[g]) % RNLQ + RNLQ) % RNLQ);
                }
                shares.put(j, sh);
            }
            Map<Integer, int[]> tvec = new java.util.LinkedHashMap<>();
            for (int j : shares.keySet()) tvec.put(j, new int[gates.length]);
            int[] zz = new int[G];
            for (int gidx = 0; gidx < gates.length; gidx++) {
                KkwGate g = gates[gidx];
                long zx = g.xKind == 'i' ? zin[g.xIdx] : zz[g.xIdx];
                long zy = g.yKind == 'i' ? zin[g.yIdx] : zz[g.yIdx];
                long acc = od.t[gidx];
                for (Map.Entry<Integer, KkwShares> se : shares.entrySet()) {
                    int j = se.getKey();
                    KkwShares sh = se.getValue();
                    long lx = g.xKind == 'i' ? sh.li[g.xIdx] : sh.lz[g.xIdx];
                    long ly = g.yKind == 'i' ? sh.li[g.yIdx] : sh.lz[g.yIdx];
                    long t = -zx * ly - zy * lx + sh.lxy[gidx] + sh.lz[g.zIdx];
                    if (j == 0) t += zx * zy;
                    t = ((t % RNLQ) + RNLQ) % RNLQ;
                    tvec.get(j)[gidx] = (int) t;
                    acc += t;
                }
                zz[g.zIdx] = (int) (((acc % RNLQ) + RNLQ) % RNLQ);
            }
            emu.put(e, new KkwEmu(shares, tvec, zz));
        }

        // Batched output check + challenge-2 consistency.
        List<byte[]> mskParts = new ArrayList<>();
        for (int e : subset) {
            KkwOnlineProof od = proof.online.get(e);
            mskParts.add(ser(od.zin));
            KkwEmu em = emu.get(e);
            for (int j = 0; j < nPar; j++) {
                int[] tv = (j == od.pbar) ? od.t : em.tvec.get(j);
                mskParts.add(ser(tv));
            }
        }
        byte[] hMsk = Hfscx256.hash(concat("HCRED-kkwmsk".getBytes(StandardCharsets.US_ASCII),
                                            concat(mskParts.toArray(new byte[0][]))));
        int K = I + 1 + 2 * rows + N;
        byte[] rhoSeed = Hfscx256.hash(concat("HCRED-kkwrho".getBytes(StandardCharsets.US_ASCII), stmt, hPre, hMsk));
        int[] rho = new HcredTape(rhoSeed).draws(K);
        int[] targets = kkwTargets(proof.W, ySynd, cPoly, N, rows, rowBits);

        List<byte[]> comOns = new ArrayList<>();
        byte[] onTag = "HCRED-kkwon".getBytes(StandardCharsets.US_ASCII);
        for (int e : subset) {
            KkwOnlineProof od = proof.online.get(e);
            int pb = od.pbar;
            KkwEmu em = emu.get(e);
            long usum = ((long) od.u % RNLQ + RNLQ) % RNLQ;
            List<Integer> js = new ArrayList<>(em.shares.keySet());
            java.util.Collections.sort(js);
            for (int j : js) {
                KkwShares sh = em.shares.get(j);
                int[] lo = kkwOutmap(sh.li, sh.lz, mPoly, hRows, N, rows, rowBits);
                long s = 0;
                for (int k = 0; k < K; k++) s += (long) rho[k] * lo[k];
                usum = ((usum + s) % RNLQ + RNLQ) % RNLQ;
            }
            int[] zo = kkwOutmap(od.zin, em.zz, mPoly, hRows, N, rows, rowBits);
            long lhs = 0;
            for (int k = 0; k < K; k++) {
                long diff = (((long) zo[k] - targets[k]) % RNLQ + RNLQ) % RNLQ;
                lhs += (long) rho[k] * diff;
            }
            lhs = ((lhs % RNLQ) + RNLQ) % RNLQ;
            if (lhs != usum) return false;

            for (int j = 0; j < nPar; j++) {
                int[] tv; long uj;
                if (j == pb) {
                    tv = od.t; uj = od.u;
                } else {
                    tv = em.tvec.get(j);
                    KkwShares sh = em.shares.get(j);
                    int[] lo = kkwOutmap(sh.li, sh.lz, mPoly, hRows, N, rows, rowBits);
                    long s = 0;
                    for (int k = 0; k < K; k++) s += (long) rho[k] * lo[k];
                    uj = ((s % RNLQ) + RNLQ) % RNLQ;
                }
                int ujInt = (int) uj;
                byte[] buf = concat(onTag, be16(e), new byte[] { (byte) j }, ser(tv), ser(new int[] { ujInt }));
                comOns.add(Hfscx256.hash(buf));
            }
        }
        byte[] hOn = Hfscx256.hash(concat("HCRED-kkwhon".getBytes(StandardCharsets.US_ASCII),
                                           concat(comOns.toArray(new byte[0][]))));
        byte[] c2mat = concat(hPre, hMsk, hOn);
        int[] pbars = kkwFsInts("c2", c2mat, tau, nPar, false);
        int idx = 0;
        for (int e : subset) {
            if (proof.online.get(e).pbar != pbars[idx]) return false;
            idx++;
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
