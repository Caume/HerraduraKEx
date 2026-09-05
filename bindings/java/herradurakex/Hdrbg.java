package herradurakex;

import java.math.BigInteger;

/**
 * TODO #260: pure-Java port of TODO #96 — HDRBG, a forward-secure
 * deterministic random bit generator built on the fast-key-erasure pattern
 * (Bernstein 2017) over the NL-FSCX v1 one-way function.  C/Go/Python have
 * carried this since it was added ("Herradura cryptographic suite.{c,go,py}"
 * §96 / {@code HDrbg}); Java had neither the primitive nor a demo/test for
 * it until this file.
 *
 * <pre>
 *   state_0     = HFSCX-256("DRBG-INIT" || len(entropy)_be8 || entropy || pers)
 *   output_i    = HFSCX-256(state_i || i_be8 || "DRBG-OUT")
 *   state_{i+1} = nl_fscx_revolve_v1(state_i, DRBG_DOMAIN, n/4)
 *   reseed      : state = HFSCX-256("DRBG-RESEED" || state || len(entropy)_be8 || entropy)
 * </pre>
 *
 * Backtracking resistance rests on the same NL-FSCX v1 OWF conjecture as the
 * 78.C ratchet ({@link Ratchet}, Theorem 16, SecurityProofs-5.md §11.8.3):
 * erasing {@code state_i} makes {@code output_i} unrecoverable from
 * {@code state_{i+1}}.  Java, like Python, cannot guarantee erasure of an
 * immutable {@link BigInteger} — for a hard erasure guarantee use the C
 * implementation.
 *
 * State-walk collision risk (NL-FSCX v1 is non-bijective) is characterised
 * in {@code SecurityProofsCode/nl_fscx_v1_ratchet_collision.py};
 * {@link #DRBG_MAX_BLOCKS} keeps walks far below the measured collision
 * distances.
 *
 * NON-GOALS: this is not a NIST SP 800-90A validated DRBG — no health
 * tests, no prediction-resistance requests, no entropy-source assessment.
 * It is a deterministic expander for seeds that are already full-entropy.
 */
public final class Hdrbg {
    private static final int N = Herradura.N;               // 256
    private static final int I_VALUE = N / 4;                // 64
    private static final int BLOCK = N / 8;                  // 32 bytes
    private static final BigInteger MASK = Herradura.MASK;

    /** Output blocks per seed/reseed (32 MiB) before reseed is required. */
    public static final long DRBG_MAX_BLOCKS = 1L << 20;

    /** "NL-FSCX-DRBG-V1\0", zero-padded to 32 bytes — byte-for-byte the same
     * domain constant as "Herradura cryptographic suite.{c,go,py}"'s
     * DRBG_DOMAIN / _DRBG_DOMAIN / drbgDomain. */
    private static final BigInteger DRBG_DOMAIN =
        new BigInteger("4E4C2D465343582D445242472D56310000000000000000000000000000000000", 16);

    private BigInteger state;
    private long blocks;

    private Hdrbg(BigInteger state) {
        this.state = state;
        this.blocks = 0;
    }

    /** Instantiates from full-entropy seed material (>= 32 bytes recommended). */
    public static Hdrbg seed(byte[] entropy, byte[] personalization) {
        byte[] buf = concat("DRBG-INIT".getBytes(java.nio.charset.StandardCharsets.US_ASCII),
            be8(entropy.length), entropy, personalization);
        byte[] h = Hfscx256.hash(buf, null);
        return new Hdrbg(new BigInteger(1, h).and(MASK));
    }

    public static Hdrbg seed(byte[] entropy) {
        return seed(entropy, new byte[0]);
    }

    /** Generates {@code nBytes} of output, ratcheting the state once per
     * 32-byte block. Throws {@link IllegalStateException} once
     * {@link #DRBG_MAX_BLOCKS} would be exceeded — call {@link #reseed}
     * first. */
    public byte[] generate(int nBytes) {
        long nBlocks = (nBytes + BLOCK - 1) / BLOCK;
        if (blocks + nBlocks > DRBG_MAX_BLOCKS) {
            throw new IllegalStateException("Hdrbg.generate: output limit reached — call reseed");
        }
        byte[] out = new byte[(int) (nBlocks * BLOCK)];
        int off = 0;
        while (off < out.length) {
            byte[] stateBytes = Hfscx256.toFixedBytes(state, BLOCK);
            byte[] buf = concat(stateBytes, be8(blocks), "DRBG-OUT".getBytes(java.nio.charset.StandardCharsets.US_ASCII));
            byte[] block = Hfscx256.hash(buf, null);
            System.arraycopy(block, 0, out, off, BLOCK);
            state = Hfscx256.nlFscxRevolveV1(state, DRBG_DOMAIN, I_VALUE);
            blocks++;
            off += BLOCK;
        }
        return java.util.Arrays.copyOf(out, nBytes);
    }

    /** Mixes fresh entropy into the state and resets the output-block counter. */
    public void reseed(byte[] entropy) {
        byte[] stateBytes = Hfscx256.toFixedBytes(state, BLOCK);
        byte[] buf = concat("DRBG-RESEED".getBytes(java.nio.charset.StandardCharsets.US_ASCII),
            stateBytes, be8(entropy.length), entropy);
        byte[] h = Hfscx256.hash(buf, null);
        state = new BigInteger(1, h).and(MASK);
        blocks = 0;
    }

    /** Resumes a checkpointed instance from a persisted (state, blocks) pair —
     * the read side of {@link #stateValue()}/{@link #blocksGenerated()}, needed
     * by the CLI's {@code rand --state} (TODO #269).
     *
     * {@code blocks} is carried, not reset: it is what makes DRBG_MAX_BLOCKS an
     * accounting over the whole life of a seed rather than per invocation, so a
     * resume that dropped it would silently hand back an unlimited generator. */
    public static Hdrbg resume(BigInteger state, long blocks) {
        if (state == null || state.signum() < 0) {
            throw new IllegalArgumentException("Hdrbg.resume: state must be non-negative");
        }
        if (blocks < 0 || blocks > DRBG_MAX_BLOCKS) {
            throw new IllegalArgumentException(
                "Hdrbg.resume: blocks out of range [0, " + DRBG_MAX_BLOCKS + "]: " + blocks);
        }
        Hdrbg d = new Hdrbg(state.and(MASK));
        d.blocks = blocks;
        return d;
    }

    /** The raw internal state, for checkpointing/inspection/testing — not
     * needed for ordinary use. */
    public BigInteger stateValue() {
        return state;
    }

    public long blocksGenerated() {
        return blocks;
    }

    private static byte[] be8(long v) {
        byte[] out = new byte[8];
        for (int i = 7; i >= 0; i--) {
            out[i] = (byte) (v & 0xff);
            v >>>= 8;
        }
        return out;
    }

    private static byte[] concat(byte[]... parts) {
        int total = 0;
        for (byte[] p : parts) total += p.length;
        byte[] out = new byte[total];
        int off = 0;
        for (byte[] p : parts) {
            System.arraycopy(p, 0, out, off, p.length);
            off += p.length;
        }
        return out;
    }
}
