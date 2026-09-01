package herradurakex;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.List;

/**
 * TODO #260: pure-Java port of TODO #78.I — HPKS-Stern-Ring, a code-based
 * ring/group signature built by OR-composing {@code k} HPKS-Stern-F
 * identification instances: prove knowledge of one secret key in a ring of
 * {@code k} public keys without revealing which one. C/Go/Python have
 * carried this since it was added ("Herradura cryptographic suite.{c,go,py}"'s
 * #78.I section); Java had neither the primitive nor a demo/test for it
 * until this file — the last of TODO #260's seven missing primitives.
 *
 * <p>Proof size: O(k * rounds). Security: EUF-CMA under SD(N,t) per ring
 * member. Reuses {@link Stern}'s package-visible helpers
 * ({@code csprngWeightT}, {@code sternHash}, {@code sternBuildH},
 * {@code sternSyndromeH}, {@code sternGenPerm}, {@code sternApplyPerm},
 * {@code SDFNR}/{@code SDFT}) rather than duplicating the underlying Stern
 * identification machinery — the ring construction adds only the
 * OR-composition (simulate every non-signer round, then splice the real
 * signer's per-round challenge in via challenge splitting) on top.
 *
 * <p>Non-signer rounds are simulated with a pre-chosen challenge {@code b}
 * (the standard Sigma-protocol HVZK simulator): draw whichever of
 * {@code (sr, sy)} / {@code (pi, r)} / {@code (pi, y)} that challenge's
 * response needs for real, fill the rest with uniform dummy values, and
 * compute the three commitments the same way the real signer would — so a
 * verifier cannot distinguish a simulated round from a genuine one without
 * the witness. The real signer's own per-round challenge is then fixed
 * <em>after</em> every commitment is on the transcript, via challenge
 * splitting (sum of all k challenges at round r must equal the joint
 * Fiat-Shamir challenge mod 3): {@code b_signer = joint_b - sum(other b's) (mod 3)}.
 */
public final class SternRing {
    private SternRing() { }

    private static final int N = Herradura.N; // 256
    private static final BigInteger MASK = Herradura.MASK;

    /** One ring member's public key: {@code (seed, syndrome)}, matching
     * {@link Stern.SternKeypair}'s public half. */
    public static final class RingKey {
        public final BigInteger seed;
        public final BigInteger syndrome;
        public RingKey(BigInteger seed, BigInteger syndrome) {
            this.seed = seed;
            this.syndrome = syndrome;
        }
    }

    /** A ring signature over {@code k} members and {@code rounds} rounds.
     * {@code commits0/1/2[i][r]}, {@code challenges[i][r]},
     * {@code resp0/1[i][r]} — indexed member-major, matching Python's
     * {@code all_commits}/{@code all_challenges}/{@code all_responses}. */
    public static final class RingSignature {
        public final BigInteger[][] c0, c1, c2;
        public final int[][] challenges;
        public final BigInteger[][] resp0, resp1;
        RingSignature(BigInteger[][] c0, BigInteger[][] c1, BigInteger[][] c2,
                      int[][] challenges, BigInteger[][] resp0, BigInteger[][] resp1) {
            this.c0 = c0; this.c1 = c1; this.c2 = c2;
            this.challenges = challenges; this.resp0 = resp0; this.resp1 = resp1;
        }
        public int ringSize() { return challenges.length; }
        public int rounds() { return challenges.length == 0 ? 0 : challenges[0].length; }
    }

    private static int floorMod3(int v) {
        int m = v % 3;
        return m < 0 ? m + 3 : m;
    }

    /** HVZK simulator for one Stern round given a pre-chosen challenge
     * {@code b}. Returns {@code {c0, c1, c2, resp0, resp1}}. Matches
     * Python's {@code _stern_simulate_round}. */
    private static Object[] simulateRound(int b, BigInteger syn, BigInteger[] hRows, SecureRandom rng) {
        if (b == 0) {
            BigInteger srSim = Stern.csprngWeightT(Stern.SDFT, rng);
            BigInteger sySim = new BigInteger(N, rng).and(MASK);
            BigInteger piDum = new BigInteger(N, rng).and(MASK);
            BigInteger c0 = Stern.sternHash(1, piDum, BigInteger.ZERO);
            BigInteger c1 = Stern.sternHash(2, srSim);
            BigInteger c2 = Stern.sternHash(3, sySim);
            return new Object[] { c0, c1, c2, srSim, sySim };
        } else if (b == 1) {
            BigInteger piSim = new BigInteger(N, rng).and(MASK);
            BigInteger rSim = Stern.csprngWeightT(Stern.SDFT, rng);
            int[] perm = Stern.sternGenPerm(piSim);
            BigInteger hrSim = Stern.sternSyndromeH(hRows, rSim);
            BigInteger srSim = Stern.sternApplyPerm(perm, rSim);
            BigInteger syDum = new BigInteger(N, rng).and(MASK);
            BigInteger c0 = Stern.sternHash(1, piSim, hrSim);
            BigInteger c1 = Stern.sternHash(2, srSim);
            BigInteger c2 = Stern.sternHash(3, syDum);
            return new Object[] { c0, c1, c2, piSim, rSim };
        } else {
            BigInteger piSim = new BigInteger(N, rng).and(MASK);
            BigInteger ySim = new BigInteger(N, rng).and(MASK);
            int[] perm = Stern.sternGenPerm(piSim);
            BigInteger hySim = Stern.sternSyndromeH(hRows, ySim);
            BigInteger sySim = Stern.sternApplyPerm(perm, ySim);
            BigInteger srDum = new BigInteger(N, rng).and(MASK);
            BigInteger c0 = Stern.sternHash(1, piSim, hySim.xor(syn));
            BigInteger c1 = Stern.sternHash(2, srDum);
            BigInteger c2 = Stern.sternHash(3, sySim);
            return new Object[] { c0, c1, c2, piSim, ySim };
        }
    }

    /** Member-major Fiat-Shamir seed hash over {@code (msg, all k*rounds*3
     * commits)}, matching Python's {@code flat} construction order (for i
     * in range(k): for r in range(rounds): flat += commits[i][r]) — the
     * ring construction, unlike single-party HPKS-Stern-F, cannot reuse
     * {@code Stern}'s round-major {@code deriveChallenges} helper. */
    private static BigInteger fiatShamirSeed(BigInteger msg, BigInteger[][] c0, BigInteger[][] c1, BigInteger[][] c2) {
        int k = c0.length, rounds = c0[0].length;
        BigInteger[] flat = new BigInteger[1 + 3 * k * rounds];
        flat[0] = msg;
        int idx = 1;
        for (int i = 0; i < k; i++) {
            for (int r = 0; r < rounds; r++) {
                flat[idx++] = c0[i][r];
                flat[idx++] = c1[i][r];
                flat[idx++] = c2[i][r];
            }
        }
        return Stern.sternHash(0, flat);
    }

    /** {@code joint_b[r]} for every round, derived by chaining
     * {@code ch_st = nl_fscx_v1(ch_st, r)} from the Fiat-Shamir seed —
     * matches Python's {@code hpks_stern_ring_sign}/{@code _verify}
     * shared derivation loop. */
    private static int[] jointChallenges(BigInteger seed, int rounds) {
        BigInteger chSt = seed;
        BigInteger word32 = BigInteger.valueOf(0xFFFFFFFFL);
        int[] joint = new int[rounds];
        for (int r = 0; r < rounds; r++) {
            chSt = Hfscx256.nlFscxV1(chSt, BigInteger.valueOf(r));
            joint[r] = chSt.and(word32).mod(BigInteger.valueOf(3)).intValueExact();
        }
        return joint;
    }

    /** Ring signature: prove knowledge of one HPKS-Stern-F key in a ring.
     *
     * @param eInt     the signer's weight-t error vector (secret key for {@code ringKeys.get(j)})
     * @param j        0-based index of the actual signer
     * @param ringKeys the ring's public keys
     */
    public static RingSignature sign(BigInteger msg, BigInteger eInt, int j, List<RingKey> ringKeys, int rounds, SecureRandom rng) {
        int k = ringKeys.size();
        BigInteger[][] c0 = new BigInteger[k][rounds];
        BigInteger[][] c1 = new BigInteger[k][rounds];
        BigInteger[][] c2 = new BigInteger[k][rounds];
        int[][] challenges = new int[k][rounds];
        BigInteger[][] resp0 = new BigInteger[k][rounds];
        BigInteger[][] resp1 = new BigInteger[k][rounds];

        // Step 1 — simulate non-signer members with pre-chosen challenges.
        for (int i = 0; i < k; i++) {
            if (i == j) continue;
            RingKey member = ringKeys.get(i);
            BigInteger[] hRowsI = Stern.sternBuildH(member.seed, Stern.SDFNR);
            for (int r = 0; r < rounds; r++) {
                int b = rng.nextInt(3);
                challenges[i][r] = b;
                Object[] sim = simulateRound(b, member.syndrome, hRowsI, rng);
                c0[i][r] = (BigInteger) sim[0];
                c1[i][r] = (BigInteger) sim[1];
                c2[i][r] = (BigInteger) sim[2];
                resp0[i][r] = (BigInteger) sim[3];
                resp1[i][r] = (BigInteger) sim[4];
            }
        }

        // Step 2 — commit phase for the real signer j.
        RingKey signerKey = ringKeys.get(j);
        BigInteger[] hRowsJ = Stern.sternBuildH(signerKey.seed, Stern.SDFNR);
        BigInteger[] rArr = new BigInteger[rounds];
        BigInteger[] yArr = new BigInteger[rounds];
        BigInteger[] piArr = new BigInteger[rounds];
        BigInteger[] srArr = new BigInteger[rounds];
        BigInteger[] syArr = new BigInteger[rounds];
        for (int r = 0; r < rounds; r++) {
            BigInteger rInt = Stern.csprngWeightT(Stern.SDFT, rng);
            BigInteger yInt = eInt.xor(rInt).and(MASK);
            BigInteger piSeed = new BigInteger(N, rng).and(MASK);
            int[] perm = Stern.sternGenPerm(piSeed);
            BigInteger hr = Stern.sternSyndromeH(hRowsJ, rInt);
            BigInteger sr = Stern.sternApplyPerm(perm, rInt);
            BigInteger sy = Stern.sternApplyPerm(perm, yInt);
            c0[j][r] = Stern.sternHash(1, piSeed, hr);
            c1[j][r] = Stern.sternHash(2, sr);
            c2[j][r] = Stern.sternHash(3, sy);
            rArr[r] = rInt; yArr[r] = yInt; piArr[r] = piSeed; srArr[r] = sr; syArr[r] = sy;
        }

        // Step 3 — Fiat-Shamir over msg + all k*rounds*3 commits (member-major).
        BigInteger seed = fiatShamirSeed(msg, c0, c1, c2);

        // Step 4 — assign the real signer's per-round challenge via challenge splitting.
        int[] joint = jointChallenges(seed, rounds);
        for (int r = 0; r < rounds; r++) {
            int simSum = 0;
            for (int i = 0; i < k; i++) if (i != j) simSum += challenges[i][r];
            challenges[j][r] = floorMod3(joint[r] - floorMod3(simSum));
        }

        // Step 5 — complete the real signer's responses.
        for (int r = 0; r < rounds; r++) {
            int b = challenges[j][r];
            if (b == 0) {
                resp0[j][r] = srArr[r]; resp1[j][r] = syArr[r];
            } else if (b == 1) {
                resp0[j][r] = piArr[r]; resp1[j][r] = rArr[r];
            } else {
                resp0[j][r] = piArr[r]; resp1[j][r] = yArr[r];
            }
        }

        return new RingSignature(c0, c1, c2, challenges, resp0, resp1);
    }

    public static RingSignature sign(BigInteger msg, BigInteger eInt, int j, List<RingKey> ringKeys, SecureRandom rng) {
        return sign(msg, eInt, j, ringKeys, Stern.SDFR, rng);
    }

    /** Verify an HPKS-Stern-Ring signature. Accepts any signature produced
     * by {@link #sign} for any member of {@code ringKeys} without
     * revealing which member signed. */
    public static boolean verify(BigInteger msg, RingSignature sig, List<RingKey> ringKeys) {
        int k = ringKeys.size();
        int rounds = sig.rounds();
        if (k != sig.ringSize()) return false;

        BigInteger seed = fiatShamirSeed(msg, sig.c0, sig.c1, sig.c2);
        int[] joint = jointChallenges(seed, rounds);
        for (int r = 0; r < rounds; r++) {
            int sum = 0;
            for (int i = 0; i < k; i++) sum += sig.challenges[i][r];
            if (floorMod3(sum) != joint[r]) return false;
        }

        for (int i = 0; i < k; i++) {
            RingKey member = ringKeys.get(i);
            BigInteger[] hRowsI = Stern.sternBuildH(member.seed, Stern.SDFNR);
            for (int r = 0; r < rounds; r++) {
                int b = sig.challenges[i][r];
                if (b == 0) {
                    BigInteger sr = sig.resp0[i][r], sy = sig.resp1[i][r];
                    if (!Stern.sternHash(2, sr).equals(sig.c1[i][r])) return false;
                    if (!Stern.sternHash(3, sy).equals(sig.c2[i][r])) return false;
                    if (sr.bitCount() != Stern.SDFT) return false;
                } else if (b == 1) {
                    BigInteger piSeed = sig.resp0[i][r], rInt = sig.resp1[i][r];
                    if (rInt.bitCount() != Stern.SDFT) return false;
                    int[] perm = Stern.sternGenPerm(piSeed);
                    BigInteger hr = Stern.sternSyndromeH(hRowsI, rInt);
                    if (!Stern.sternHash(1, piSeed, hr).equals(sig.c0[i][r])) return false;
                    BigInteger sr = Stern.sternApplyPerm(perm, rInt);
                    if (!Stern.sternHash(2, sr).equals(sig.c1[i][r])) return false;
                } else {
                    BigInteger piSeed = sig.resp0[i][r], yInt = sig.resp1[i][r];
                    int[] perm = Stern.sternGenPerm(piSeed);
                    BigInteger hy = Stern.sternSyndromeH(hRowsI, yInt);
                    if (!Stern.sternHash(1, piSeed, hy.xor(member.syndrome)).equals(sig.c0[i][r])) return false;
                    BigInteger sy = Stern.sternApplyPerm(perm, yInt);
                    if (!Stern.sternHash(3, sy).equals(sig.c2[i][r])) return false;
                }
            }
        }
        return true;
    }
}
