package herradurakex;

import java.math.BigInteger;

/**
 * TODO #260: pure-Java port of 78.C — the forward-secret unidirectional
 * ratchet.  C/Go/Python have carried this since it was added (see
 * "Herradura cryptographic suite.{c,go,py}"'s 78.C section and
 * CryptosuiteTests test [27], "Ratchet (78.C) — forward secrecy & key
 * uniqueness"); Java had neither the primitive nor the test until this file.
 *
 * <pre>
 *   state_{i+1} = nl_fscx_revolve_v1(state_i, RATCHET_DOMAIN, 1)
 *   msg_key_i   = hfscx_256(state_i.bytes || 0x01)
 * </pre>
 *
 * Security rests on the same NL-FSCX v1 one-way-function conjecture as
 * HFSCX-256 itself (Theorem 16, SecurityProofs-5.md §11.8.3): erasing
 * {@code state_i} makes {@code msg_key_i} unrecoverable from
 * {@code state_{i+1}}.  Java, like Python, cannot guarantee erasure of an
 * immutable {@link BigInteger} — for a hard erasure guarantee use the C
 * implementation ({@code ratchet_erase} in herradura.h).  Callers should at
 * minimum drop every reference to a superseded state immediately after
 * {@link #advance}.
 */
public final class Ratchet {
    private Ratchet() { }

    private static final int N = Herradura.N;               // 256
    private static final BigInteger MASK = Herradura.MASK;

    /** "NL-FSCX-RATCHET-V1\0NL-FSCX-RATCHET-V", truncated to N/8 bytes —
     * byte-for-byte the same domain constant as "Herradura cryptographic
     * suite.{c,go,py}"'s RATCHET_DOMAIN / _RATCHET_DOMAIN / ratchetDomain. */
    private static final BigInteger RATCHET_DOMAIN =
        new BigInteger("4E4C2D465343582D524154434845542D5631004E4C2D465343582D5241544348", 16);

    /** Derives the initial ratchet state from a seed via
     * {@code hfscx_256(seed || 0x02)}. */
    public static BigInteger init(byte[] seed) {
        byte[] buf = java.util.Arrays.copyOf(seed, seed.length + 1);
        buf[seed.length] = 0x02;
        return new BigInteger(1, Hfscx256.hash(buf, null)).and(MASK);
    }

    /** One step. Returns {@code {nextState, msgKey}} — index 1 in the
     * returned array is the raw 32 message-key bytes, index 0 is the
     * BigInteger successor state. Caller MUST discard/drop the reference to
     * the previous state immediately. */
    public static Object[] advance(BigInteger state) {
        byte[] stateBytes = Hfscx256.toFixedBytes(state.and(MASK), N / 8);
        byte[] buf = java.util.Arrays.copyOf(stateBytes, stateBytes.length + 1);
        buf[stateBytes.length] = 0x01;
        byte[] msgKey = Hfscx256.hash(buf, null);
        BigInteger nextState = Hfscx256.nlFscxRevolveV1(state, RATCHET_DOMAIN, 1);
        return new Object[] { nextState, msgKey };
    }
}
