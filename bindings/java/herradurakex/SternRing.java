package herradurakex;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.List;

/**
 * HPKS-Ring: ONE Stern proof over a block-diagonal statement (TODO #415,
 * v20.0.0).  The pure-Java port of herradura.h's {@code stern_ring_sign} and
 * Python's {@code hpks_stern_ring_sign}, draw for draw; SPEC.md §11.2 is
 * normative and KAT/operation_replay.json pins both widths in all four ports.
 *
 * <p>Replaces the OR-composition of k Stern proofs (TODO #78.I, #260), which
 * was existentially forgeable with no member's key: it split each round's
 * challenge across the members mod 3, and a party without the witness answers
 * two of Stern's three challenges, so two keyless members covered every
 * residue.  Here each round has ONE challenge for one statement only a
 * member's key satisfies.
 *
 * <ul>
 * <li>statement: H~ = diag([H_1|s_1], ..., [H_k|s_k]) with the members sorted
 *     by seed || syndrome (duplicates refused); z = (x_1..x_k ; c), c a k-bit
 *     indicator, H~ z = 0 and z in S = { one c_p = 1, wt(x_p) = t, every other
 *     x_q = 0 }.</li>
 * <li>round: draws r (k blocks, then the indicator masked to k bits), pi_seed,
 *     salt1, salt2; c0 = H_1(pi_seed || H~ r), c1 = H_2(salt1 || Pi r),
 *     c2 = H_3(salt2 || Pi y), y = r + z.</li>
 * <li>wire: D = H_0(0x02 || n || k || rounds || msg || ring || c0 c1 c2 ...),
 *     then per round the unopened commitment and the opening; trits from
 *     H_6(D || ctr) bytes, 255 rejected; H_tag(x) = HFSCX-256-DS(0x32, tag || x).</li>
 * </ul>
 * Every vector is big-endian bytes: an n-bit block n/8, a syndrome n/16.
 */
public final class SternRing {
    private SternRing() { }

    static final int DS = 0x32;
    static final int VERSION = 2;
    public static final int MAX_MEMBERS = 1024;
    static final int T_CH = 0;
    static final int T_C0 = 1;
    static final int T_C1 = 2;
    static final int T_C2 = 3;
    static final int T_TAU = 4;
    static final int T_PI = 5;
    static final int T_XOF = 6;

    /** One ring member's public key: the n/8-byte seed and the n/16-byte
     * big-endian syndrome. */
    public static final class RingKey {
        public final byte[] seed;
        public final byte[] syndrome;
        public RingKey(BigInteger seed, BigInteger syndrome, int n) {
            this.seed = SternL.fixed(seed, n / 8);
            this.syndrome = SternL.fixed(syndrome, n / 16);
        }
    }

    static byte[] h(int tag, byte[]... items) {
        int len = 1;
        for (byte[] it : items) len += it.length;
        byte[] buf = new byte[len];
        buf[0] = (byte) tag;
        int off = 1;
        for (byte[] it : items) { System.arraycopy(it, 0, buf, off, it.length); off += it.length; }
        return Hfscx256.hashDs(DS, buf);
    }

    static boolean nOk(int n) {
        return n == 32 || n == 64 || n == 128 || n == 256
            || (n > Herradura.N && n % 256 == 0 && n <= SternL.STERN_LONG_N);
    }

    static int t(int n) { return Math.max(2, n / 16); }

    private static int[] perm(byte[] key, int N) {
        return SternL.genPermOnKey(BitArray.fromBytes(key, 256), N);
    }

    /** out[perm[i]] = v[i] over the bits of a big-endian byte string. */
    private static void applyPerm(byte[] out, int off, int[] perm, byte[] v, int voff, int nb) {
        for (int i = 0; i < nb * 8; i++) {
            int bit = (v[voff + nb - 1 - i / 8] >> (i % 8)) & 1;
            int p = perm[i];
            out[off + nb - 1 - p / 8] |= (byte) (bit << (p % 8));
        }
    }

    /** A ring in canonical order. */
    static final class Ring {
        final int n, k, nb, sb, kb, vlen;
        final byte[] enc;
        final byte[][] syns;
        final byte[][][] H;
        final int[] pos;

        Ring(List<RingKey> ring, int n) {
            if (!nOk(n)) throw new IllegalArgumentException("hpks-ring: n = " + n + " is not a Stern-F width");
            int k = ring.size();
            if (k < 1 || k > MAX_MEMBERS)
                throw new IllegalArgumentException("hpks-ring: ring has " + k + " members (expected 1.." + MAX_MEMBERS + ")");
            this.n = n; this.k = k; nb = n / 8; sb = n / 16; kb = (k + 7) / 8;
            vlen = k * nb + kb;
            byte[][] encs = new byte[k][];
            for (int i = 0; i < k; i++) {
                RingKey m = ring.get(i);
                if (m.seed.length != nb || m.syndrome.length != sb)
                    throw new IllegalArgumentException("hpks-ring: a ring member is not an n-bit Stern-F key");
                encs[i] = new byte[nb + sb];
                System.arraycopy(m.seed, 0, encs[i], 0, nb);
                System.arraycopy(m.syndrome, 0, encs[i], nb, sb);
            }
            Integer[] ord = new Integer[k];
            for (int i = 0; i < k; i++) ord[i] = i;
            Arrays.sort(ord, (a, b) -> Arrays.compareUnsigned(encs[a], encs[b]));
            enc = new byte[k * (nb + sb)];
            syns = new byte[k][];
            H = new byte[k][][];
            pos = new int[k];
            for (int i = 0; i < k; i++) {
                int o = ord[i];
                if (i > 0 && Arrays.equals(encs[o], encs[ord[i - 1]]))
                    throw new IllegalArgumentException("hpks-ring: the ring lists a member twice");
                pos[o] = i;
                System.arraycopy(encs[o], 0, enc, i * (nb + sb), nb + sb);
                syns[i] = Arrays.copyOfRange(encs[o], nb, nb + sb);
                BigInteger seed = new BigInteger(1, Arrays.copyOfRange(encs[o], 0, nb));
                BigInteger[] rows = n > Herradura.N ? SternL.buildH(seed, n) : Stern.sternBuildH(seed, n / 2, n);
                H[i] = new byte[rows.length][];
                for (int r = 0; r < rows.length; r++) H[i][r] = SternL.fixed(rows[r], nb);
            }
        }

        byte[] syn(int i, byte[] v, int off) {
            byte[] out = new byte[sb];
            for (int row = 0; row < n / 2; row++) {
                int p = 0;
                byte[] hr = H[i][row];
                for (int b = 0; b < nb; b++) p ^= Integer.bitCount((hr[b] & v[off + b]) & 0xff);
                if ((p & 1) == 1) out[sb - 1 - row / 8] |= (byte) (1 << (row % 8));
            }
            return out;
        }

        int indBit(byte[] v, int i) { return (v[k * nb + kb - 1 - i / 8] >> (i % 8)) & 1; }

        byte[] htilde(byte[] v) {
            byte[] out = new byte[k * sb];
            for (int i = 0; i < k; i++) {
                byte[] s = syn(i, v, i * nb);
                if (indBit(v, i) == 1) for (int b = 0; b < sb; b++) s[b] ^= syns[i][b];
                System.arraycopy(s, 0, out, i * sb, sb);
            }
            return out;
        }

        int[][] perms(byte[] piSeed) {
            int[][] p = new int[k + 1][];
            p[k] = perm(h(T_TAU, piSeed), k);
            for (int i = 0; i < k; i++)
                p[i] = perm(h(T_PI, piSeed, new byte[] { (byte) (i >> 8), (byte) i }), n);
            return p;
        }

        byte[] apply(int[][] P, byte[] v) {
            int[] tau = P[k];
            byte[] out = new byte[vlen];
            for (int i = 0; i < k; i++) {
                applyPerm(out, tau[i] * nb, P[i], v, i * nb, nb);
                if (indBit(v, i) == 1) out[k * nb + kb - 1 - tau[i] / 8] |= (byte) (1 << (tau[i] % 8));
            }
            return out;
        }

        boolean indCanonical(byte[] v, int off) {
            int top = 8 * kb - k;
            return top == 0 || ((v[off + k * nb] & 0xff) >> (8 - top)) == 0;
        }

        boolean inS(byte[] u, byte[] v) {
            int p = -1, count = 0;
            for (int i = 0; i < k; i++) if ((indBit(u, i) ^ indBit(v, i)) == 1) { p = i; count++; }
            if (count != 1) return false;
            for (int i = 0; i < k; i++) {
                int w = 0;
                for (int b = i * nb; b < (i + 1) * nb; b++) w += Integer.bitCount((u[b] ^ v[b]) & 0xff);
                if (i == p ? w != t(n) : w != 0) return false;
            }
            return true;
        }

        byte[] digest(int rounds, byte[] msg, byte[] commits) {
            byte[] hdr = { (byte) VERSION, (byte) (n >> 8), (byte) n, (byte) (k >> 8), (byte) k,
                           (byte) (rounds >> 8), (byte) rounds };
            return h(T_CH, hdr, msg, enc, commits);
        }
    }

    static int[] challenges(byte[] d, int rounds) {
        int[] out = new int[rounds];
        int got = 0;
        for (int ctr = 0; got < rounds; ctr++) {
            byte[] blk = h(T_XOF, Arrays.copyOf(d, 32),
                           new byte[] { (byte) (ctr >>> 24), (byte) (ctr >>> 16), (byte) (ctr >>> 8), (byte) ctr });
            for (int i = 0; i < 32 && got < rounds; i++) {
                int v = blk[i] & 0xff;
                if (v != 255) out[got++] = v % 3;
            }
        }
        return out;
    }

    /** The byte length of a ring signature whose digest is the first 32 bytes of d. */
    public static int sigLen(byte[] d, int k, int n, int rounds) {
        int vlen = k * (n / 8) + (k + 7) / 8;
        int len = 32;
        for (int b : challenges(d, rounds)) len += 96 + (b == 0 ? 2 * vlen : vlen);
        return len;
    }

    /** Ring-sign the 32-byte msg as ring member j (secret e); the ring may be
     * in any order.  Returns D, then per round the unopened commitment and the
     * opening. */
    public static byte[] sign(byte[] msg, BigInteger e, int j, List<RingKey> ringKeys, int n, int rounds,
                              SecureRandom rng) {
        if (msg.length != 32) throw new IllegalArgumentException("hpks-ring: the message is a 256-bit digest");
        if (rounds < 1 || rounds > 0xFFFF) throw new IllegalArgumentException("hpks-ring: rounds out of range");
        Ring R = new Ring(ringKeys, n);
        if (j < 0 || j >= R.k) throw new IllegalArgumentException("hpks-ring: signer index out of range");
        int jj = R.pos[j];
        if (e.signum() < 0 || e.bitLength() > n || e.bitCount() != t(n))
            throw new IllegalArgumentException("hpks-ring: the secret is not a weight-t n-bit vector");
        byte[] eb = SternL.fixed(e, R.nb);
        if (!Arrays.equals(R.syn(jj, eb, 0), R.syns[jj]))
            throw new IllegalArgumentException("hpks-ring: the secret key is not ring member j's");
        int vl = R.vlen, top = 8 * R.kb - R.k;
        byte[] z = new byte[vl];
        System.arraycopy(eb, 0, z, jj * R.nb, R.nb);
        z[R.k * R.nb + R.kb - 1 - jj / 8] |= (byte) (1 << (jj % 8));
        byte[][] rr = new byte[rounds][], yy = new byte[rounds][], uu = new byte[rounds][], vv = new byte[rounds][];
        byte[][] ps = new byte[rounds][], s1 = new byte[rounds][], s2 = new byte[rounds][];
        byte[] commits = new byte[96 * rounds];
        for (int i = 0; i < rounds; i++) {
            byte[] r = new byte[vl];
            rng.nextBytes(r);
            if (top > 0) r[R.k * R.nb] &= (byte) (0xff >>> top);
            ps[i] = new byte[32]; rng.nextBytes(ps[i]);
            s1[i] = new byte[32]; rng.nextBytes(s1[i]);
            s2[i] = new byte[32]; rng.nextBytes(s2[i]);
            byte[] y = new byte[vl];
            for (int a = 0; a < vl; a++) y[a] = (byte) (r[a] ^ z[a]);
            int[][] P = R.perms(ps[i]);
            rr[i] = r; yy[i] = y; uu[i] = R.apply(P, r); vv[i] = R.apply(P, y);
            System.arraycopy(h(T_C0, ps[i], R.htilde(r)), 0, commits, 96 * i, 32);
            System.arraycopy(h(T_C1, s1[i], uu[i]), 0, commits, 96 * i + 32, 32);
            System.arraycopy(h(T_C2, s2[i], vv[i]), 0, commits, 96 * i + 64, 32);
        }
        byte[] d = R.digest(rounds, msg, commits);
        int[] b = challenges(d, rounds);
        java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
        out.write(d, 0, 32);
        for (int i = 0; i < rounds; i++) {
            if (b[i] == 0) {
                out.write(commits, 96 * i, 32);
                out.write(s1[i], 0, 32); out.write(s2[i], 0, 32);
                out.write(uu[i], 0, vl); out.write(vv[i], 0, vl);
            } else {
                out.write(commits, 96 * i + (b[i] == 1 ? 64 : 32), 32);
                out.write(ps[i], 0, 32);
                out.write(b[i] == 1 ? s1[i] : s2[i], 0, 32);
                out.write(b[i] == 1 ? rr[i] : yy[i], 0, vl);
            }
        }
        return out.toByteArray();
    }

    /** True iff sig is a ring signature on the 32-byte msg by some member of
     * the ring (any order) at width n and this round count. */
    public static boolean verify(byte[] msg, byte[] sig, List<RingKey> ringKeys, int n, int rounds) {
        if (msg == null || msg.length != 32 || sig == null || sig.length < 32 || rounds < 1 || rounds > 0xFFFF)
            return false;
        Ring R;
        try {
            R = new Ring(ringKeys, n);
        } catch (IllegalArgumentException ex) {
            return false;
        }
        if (sig.length != sigLen(sig, R.k, n, rounds)) return false;
        int vl = R.vlen, pos = 32;
        int[] b = challenges(sig, rounds);
        byte[] commits = new byte[96 * rounds];
        for (int i = 0; i < rounds; i++) {
            byte[] a = Arrays.copyOfRange(sig, pos + 32, pos + 64), c = Arrays.copyOfRange(sig, pos + 64, pos + 96);
            byte[] w = Arrays.copyOfRange(sig, pos + 96, pos + 96 + vl);
            System.arraycopy(sig, pos, commits, 96 * i + (b[i] == 0 ? 0 : b[i] == 1 ? 64 : 32), 32);
            if (b[i] == 0) {
                byte[] w2 = Arrays.copyOfRange(sig, pos + 96 + vl, pos + 96 + 2 * vl);
                if (!R.indCanonical(w, 0) || !R.indCanonical(w2, 0) || !R.inS(w, w2)) return false;
                System.arraycopy(h(T_C1, a, w), 0, commits, 96 * i + 32, 32);
                System.arraycopy(h(T_C2, c, w2), 0, commits, 96 * i + 64, 32);
                pos += 96 + 2 * vl;
            } else {
                if (!R.indCanonical(w, 0)) return false;
                System.arraycopy(h(T_C0, a, R.htilde(w)), 0, commits, 96 * i, 32);
                byte[] pw = R.apply(R.perms(a), w);
                System.arraycopy(h(b[i] == 1 ? T_C1 : T_C2, c, pw), 0, commits, 96 * i + (b[i] == 1 ? 32 : 64), 32);
                pos += 96 + vl;
            }
        }
        return Arrays.equals(R.digest(rounds, msg, commits), Arrays.copyOf(sig, 32));
    }
}
