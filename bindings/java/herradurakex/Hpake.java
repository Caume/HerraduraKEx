package herradurakex;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.List;

/**
 * TODO #203: pure-Java port of aPAKE, the augmented Password-Authenticated
 * Key Exchange built on HKEX-RNL + {@link ZkpNl} + {@link Oprf} (TODO #80
 * Batch 4).
 *
 * The server's password record stores {@code F(oprf_key, password)} (the
 * OPRF output) rather than a plain password hash — an attacker who steals
 * the server database still needs to break CDH in GF(2^256)* (i.e. needs
 * {@code oprf_key}) to run an offline dictionary attack, unlike a plain
 * salted-hash PAKE.
 *
 * Byte-for-byte port of "Herradura cryptographic suite.py"'s
 * {@code _hpake_derive_zkp_witness}/{@code _hpake_rnl_kdf}/
 * {@code hpake_register}/{@code hpake_login_demo}.
 *
 * {@link #loginDemo} runs both the client and server sides of the
 * 3-message HKEX-RNL + ZKBoo exchange in one call, matching the Python
 * reference's own "demo" scope (a real 2-party network protocol would
 * split this into separate client/server round trips over the wire —
 * out of scope here, matching upstream).
 *
 * Per the suite's own documentation this is a research-grade
 * construction: no formal UC/SIM-BMP proof, only an informal reduction
 * to CDH (via {@link Oprf}) and the ZKBoo/NL-FSCX assumptions (via
 * {@link ZkpNl}) — treat it accordingly, not as a hardened production
 * aPAKE.
 */
public final class Hpake {
    private Hpake() { }

    public static final int ZKP_N = 32;   // ZKBoo witness width (demo; production: 256)
    public static final int ROUNDS = 16;  // soundness (2/3)^16 ~= 0.15%; production: 219

    private static final byte[] ZKP_A_LABEL = "ZKP-A".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] AUTH_LABEL = "PAKE-AUTH-v1".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] SESSION_LABEL = "PAKE-SESSION-v1".getBytes(StandardCharsets.US_ASCII);

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

    /** Domain-separates a ZKP_N-bit ZKBoo witness from the OPRF output. */
    static BigInteger deriveZkpWitness(byte[] pwOprfOutput) {
        BigInteger mask = BigInteger.ONE.shiftLeft(ZKP_N).subtract(BigInteger.ONE);
        return new BigInteger(1, Hfscx256.hash(concat(pwOprfOutput, ZKP_A_LABEL))).and(mask);
    }

    /** HKEX-RNL session KDF: nl_fscx_revolve_v1(ROL(K,n/8) XOR RNL_KDF_DC_256, K, n/4). */
    static byte[] rnlKdf(BigInteger kRaw) {
        BigInteger k = kRaw.and(Herradura.MASK);
        BigInteger state0 = Herradura.rol(k, Herradura.N / 8).xor(Hfscx256.RNL_KDF_DC_256).and(Herradura.MASK);
        BigInteger sk = Hfscx256.nlFscxRevolveV1(state0, k, Herradura.N / 4);
        return toFixedBytes(sk, Herradura.N / 8);
    }

    public static final class Record {
        public final String username;
        public final byte[] salt; // stored for record-shape parity; unused by loginDemo, matching upstream
        public final BigInteger b;
        public final BigInteger y;
        public Record(String username, byte[] salt, BigInteger b, BigInteger y) {
            this.username = username; this.salt = salt; this.b = b; this.y = y;
        }
    }

    /** Registration: server stores a record containing (username, salt, B, y)
     * where y = nl_fscx_v1(zkp_A, B) and zkp_A is derived from the OPRF
     * output of the password — the server cannot offline-attack passwords
     * without oprfKey. */
    public static Record register(String username, byte[] password, BigInteger oprfKey, SecureRandom rng) {
        byte[] salt = new byte[32];
        rng.nextBytes(salt);
        BigInteger pwOprfOut = Oprf.direct(password, oprfKey);
        byte[] pwOprfBytes = toFixedBytes(pwOprfOut, Herradura.N / 8);
        BigInteger zkpA = deriveZkpWitness(pwOprfBytes);
        BigInteger mask = BigInteger.ONE.shiftLeft(ZKP_N).subtract(BigInteger.ONE);
        BigInteger b = new BigInteger(ZKP_N, rng).and(mask);
        BigInteger y = ZkpNl.nlFscxV1General(zkpA, b, ZKP_N);
        return new Record(username, salt, b, y);
    }

    /** Both-sides demo login: performs the full 3-message HKEX-RNL + ZKBoo
     * exchange and returns the shared session key on success, or null if
     * the password is wrong. */
    public static byte[] loginDemo(Record record, byte[] password, BigInteger oprfKey, SecureRandom rng) {
        BigInteger pwOprfOut = Oprf.direct(password, oprfKey);
        byte[] pwOprfBytes = toFixedBytes(pwOprfOut, Herradura.N / 8);
        BigInteger zkpA = deriveZkpWitness(pwOprfBytes);

        BigInteger yCheck = ZkpNl.nlFscxV1General(zkpA, record.b, ZKP_N);
        if (!yCheck.equals(record.y)) return null; // fast local check, aborts before the ZKBoo proof

        int[] mBase = HerraduraNl.rnlMPoly(Herradura.N);
        int[] aRand = HerraduraNl.rnlRandPoly(Herradura.N, HerraduraNl.RNLQ, rng);
        int[] mBlind = HerraduraNl.rnlPolyAdd(mBase, aRand, HerraduraNl.RNLQ);

        HerraduraNl.RnlKeypair kpC = HerraduraNl.rnlKeygen(mBlind, Herradura.N, HerraduraNl.RNLQ, HerraduraNl.RNLP, rng);
        HerraduraNl.RnlKeypair kpS = HerraduraNl.rnlKeygen(mBlind, Herradura.N, HerraduraNl.RNLQ, HerraduraNl.RNLP, rng);

        // Ephemeral HKEX-RNL with contributory nonces (n_A from client, n_B
        // from server) — TODO #89's RNG-hardening fix, applied here the same
        // way plain kex --algo hkex-rnl applies it (HerraduraNl.rnlContributoryKdf).
        HerraduraNl.RnlAgreeResult agreeC = HerraduraNl.rnlAgree(
            kpC.s, kpS.c, HerraduraNl.RNLQ, HerraduraNl.RNLP, HerraduraNl.RNLPP, Herradura.N, Herradura.N);
        BigInteger kRawS = HerraduraNl.rnlAgree(
            kpS.s, kpC.c, HerraduraNl.RNLQ, HerraduraNl.RNLP, HerraduraNl.RNLPP, Herradura.N, Herradura.N, agreeC.hint);

        byte[] pakeNA = new byte[32];
        byte[] pakeNB = new byte[32];
        rng.nextBytes(pakeNA);
        rng.nextBytes(pakeNB);
        BigInteger kKdfC = HerraduraNl.rnlContributoryKdf(agreeC.key, Herradura.N, pakeNA, pakeNB);
        BigInteger kKdfS = HerraduraNl.rnlContributoryKdf(kRawS, Herradura.N, pakeNA, pakeNB);

        byte[] authMsgC = concat(toFixedBytes(kKdfC, Herradura.N / 8), AUTH_LABEL);
        List<ZkpNl.ProofRound> proof = ZkpNl.prove(zkpA, record.b, record.y, ZKP_N, ROUNDS, authMsgC, rng);

        byte[] authMsgS = concat(toFixedBytes(kKdfS, Herradura.N / 8), AUTH_LABEL);
        if (!ZkpNl.verify(record.b, record.y, ZKP_N, ROUNDS, authMsgS, proof)) return null;

        return Hfscx256.hash(concat(rnlKdf(kKdfC), SESSION_LABEL));
    }
}
