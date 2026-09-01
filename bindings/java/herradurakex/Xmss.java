package herradurakex;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * TODO #201: pure-Java port of HPKS-XMSS-F, the suite's stateful
 * multi-use hash-based signature scheme built on {@link Wots} leaves and
 * an RFC-6962-style Merkle accumulator (TODO #78.J, #97/#102/#120).
 *
 * Byte-for-byte port of "Herradura cryptographic suite.py"'s
 * haccum_leaf / haccum_node / haccum_root / haccum_prove / haccum_verify /
 * hpks_xmss_keygen / hpks_xmss_sign / hpks_xmss_verify. The haccum* methods
 * are {@code public} (TODO #261) so the accumulator is independently usable
 * here too, matching C/Go/Python where it is a general-purpose top-level
 * primitive rather than an XMSS-only implementation detail.
 *
 * <b>Statefulness</b>: this class is stateless — {@code leafIdx} is an
 * explicit parameter to every sign call, and callers MUST never sign with
 * the same leaf twice (that leaks a one-time WOTS key). Persisting the
 * next-unused leaf index is the caller's responsibility; {@link HerraduraCli}
 * mirrors the Python CLI's convention of a {@code <keyfile>.idx} sidecar
 * file holding the next index, with a hard failure once
 * {@code leafIdx >= 2^h} (key exhausted).
 */
public final class Xmss {
    private Xmss() { }

    public static final int DEFAULT_H = 10; // 1024 leaves

    // -----------------------------------------------------------------
    // Merkle accumulator (RFC 6962-style domain separation)
    // -----------------------------------------------------------------

    public static byte[] haccumLeaf(byte[] data) {
        byte[] tagged = new byte[data.length + 1];
        tagged[0] = 0x00;
        System.arraycopy(data, 0, tagged, 1, data.length);
        return Hfscx256.hash(tagged);
    }

    public static byte[] haccumNode(byte[] left, byte[] right) {
        byte[] tagged = new byte[1 + left.length + right.length];
        tagged[0] = 0x01;
        System.arraycopy(left, 0, tagged, 1, left.length);
        System.arraycopy(right, 0, tagged, 1 + left.length, right.length);
        return Hfscx256.hash(tagged);
    }

    /** Merkle root of leafHashes (each 32 bytes); pads to the next power of two. */
    public static byte[] haccumRoot(List<byte[]> leafHashes) {
        int n = leafHashes.size();
        if (n == 0) return new byte[32];
        int sz = 1;
        while (sz < n) sz <<= 1;
        byte[][] nodes = new byte[sz][];
        for (int i = 0; i < sz; i++) nodes[i] = (i < n) ? leafHashes.get(i) : new byte[32];
        while (sz > 1) {
            byte[][] next = new byte[sz / 2][];
            for (int i = 0; i < sz / 2; i++) next[i] = haccumNode(nodes[2 * i], nodes[2 * i + 1]);
            nodes = next;
            sz /= 2;
        }
        return nodes[0];
    }

    /** Sibling-hash proof path for the leaf at idx. */
    public static List<byte[]> haccumProve(List<byte[]> leafHashes, int idx) {
        int n = leafHashes.size();
        int sz = 1;
        while (sz < n) sz <<= 1;
        byte[][] nodes = new byte[sz][];
        for (int i = 0; i < sz; i++) nodes[i] = (i < n) ? leafHashes.get(i) : new byte[32];
        List<byte[]> proof = new ArrayList<>();
        int cur = idx;
        while (sz > 1) {
            proof.add(nodes[cur ^ 1]);
            byte[][] next = new byte[sz / 2][];
            for (int i = 0; i < sz / 2; i++) next[i] = haccumNode(nodes[2 * i], nodes[2 * i + 1]);
            nodes = next;
            sz /= 2;
            cur >>= 1;
        }
        return proof;
    }

    public static boolean haccumVerify(byte[] root, byte[] leafHash, List<byte[]> proof, int idx) {
        byte[] cur = leafHash;
        for (byte[] sib : proof) {
            cur = ((idx & 1) == 0) ? haccumNode(cur, sib) : haccumNode(sib, cur);
            idx >>= 1;
        }
        return Arrays.equals(cur, root);
    }

    // -----------------------------------------------------------------
    // XMSS-F keygen / sign / verify
    // -----------------------------------------------------------------

    public static final class Keypair {
        public final byte[] masterSeed;
        public final byte[] root;             // 32-byte Merkle root (the public key)
        public final List<byte[]> leafHashes; // 2^h leaf hashes, for fast proof generation
        public final int h;
        Keypair(byte[] masterSeed, byte[] root, List<byte[]> leafHashes, int h) {
            this.masterSeed = masterSeed; this.root = root; this.leafHashes = leafHashes; this.h = h;
        }
    }

    /** Builds a 2^h-leaf Merkle tree of WOTS-F public keys. Slow for large h. */
    public static Keypair keygen(byte[] masterSeed, int h) {
        int numLeaves = 1 << h;
        List<byte[]> leafHashes = new ArrayList<>(numLeaves);
        for (int idx = 0; idx < numLeaves; idx++) {
            Wots.Keypair kp = Wots.keygen(masterSeed, idx);
            leafHashes.add(haccumLeaf(Wots.pkBytes(kp.pk)));
        }
        byte[] root = haccumRoot(leafHashes);
        return new Keypair(masterSeed, root, leafHashes, h);
    }

    public static final class Signature {
        public final int leafIdx;
        public final BigInteger[] wotsSig; // length Wots.L
        public final List<byte[]> authPath; // length h
        public Signature(int leafIdx, BigInteger[] wotsSig, List<byte[]> authPath) {
            this.leafIdx = leafIdx; this.wotsSig = wotsSig; this.authPath = authPath;
        }
    }

    /** Signs at leafIdx. Callers must never reuse a leafIdx (see class doc). */
    public static Signature sign(byte[] msg, byte[] masterSeed, List<byte[]> leafHashes, int leafIdx) {
        Wots.Signature wotsSig = Wots.sign(msg, masterSeed, leafIdx);
        List<byte[]> authPath = haccumProve(leafHashes, leafIdx);
        return new Signature(leafIdx, wotsSig.sig, authPath);
    }

    /** Verifies by recovering the WOTS pk from (msg, sig) and checking the Merkle proof. */
    public static boolean verify(byte[] msg, Signature sig, byte[] root) {
        BigInteger[] recoveredPk = Wots.recoverPk(msg, sig.wotsSig);
        byte[] leafHash = haccumLeaf(Wots.pkBytes(recoveredPk));
        return haccumVerify(root, leafHash, sig.authPath, sig.leafIdx);
    }
}
