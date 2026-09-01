package herradurakex;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

/**
 * TODO #260 step 4: a narrated, protocol-by-protocol demo of the
 * herradurakex Java package, mirroring "Herradura cryptographic
 * suite.{c,go,py}"'s {@code main()} — the human-readable walkthrough the
 * other three languages ship, which {@link SelfTest} (a compact pass/fail
 * harness) does not replace. Every genuine-failure branch below prints a
 * line containing the literal marker {@code [FAIL]}; {@link #out} scans
 * every line for that marker exactly the way C's {@code hprintf}, Go's
 * stdout-capturing pipe, and Python's {@code print} shadow do (TODO
 * #258/#259), so this demo exits non-zero on a wrong verdict, not only on
 * a crash. A successful check is instead prefixed {@code +}.
 *
 * <p>Covers the classical quartet ({@link Herradura}), the NL/PQC quartet
 * including the v3 (TODO #255) variants ({@link HerraduraNl}),
 * HPKS-Stern-F/HPKE-Stern-F/HPKE-Stern-KEM and HPKS-Stern-Ring
 * ({@link Stern}, {@link SternRing}), HFSCX-256-DM ({@link Hfscx256}),
 * ZKP-NL ({@link ZkpNl}), HCRED ({@link Hcred}), HPKS-WOTS-F/HPKS-XMSS-F
 * ({@link Wots}, {@link Xmss}), HPKS-T ({@link HpksT}), HDRBG
 * ({@link Hdrbg}), fpe/twk both v2 and v3 ({@link FpeTwk}), the
 * HSKE-NL-V2/V3-Duplex research AEAD ({@link Duplex}), the 78.C
 * forward-secret ratchet ({@link Ratchet}), the 78.H masked HSKE
 * ({@link Herradura#hskeEncryptMasked}/{@link Herradura#hskeDecryptMasked},
 * TODO #261), OPRF ({@link Oprf}) and aPAKE ({@link Hpake}) — every
 * protocol {@code HerraduraCli.java} exposes, narrated the way the suite
 * files narrate them rather than as CLI invocations. A short EVE-bypass
 * section closes the walkthrough, matching the other three languages'
 * "Eve cannot break this without the secret" checks.
 *
 * <p>The Merkle accumulator (78.J) is not a standalone demo section here:
 * it is exercised implicitly by every {@link Xmss} keygen/sign/verify call,
 * the same way C/Go/Python's suite files use it only as XMSS's tree
 * (its {@code haccum*} methods are {@code public} in {@link Xmss}, TODO
 * #261, so it is callable independently too).
 *
 * <p>Not covered, matching {@code HerraduraCli.java}'s own out-of-scope
 * list: rnl-sigma, hybrid-rnl-stern, and HSKE-NL-AEAD (the {@code --aead}
 * counter-mode construction) — none of these are ported to Java at all, a
 * pre-existing gap outside TODO #260's seven-primitive scope.
 *
 * <p>Usage: {@code java -cp bindings/java herradurakex.Demo}
 */
public final class Demo {
    private Demo() { }

    private static int failures = 0;
    private static final List<String> failLines = new ArrayList<>();

    /** Prints text and scans it for the literal marker {@code [FAIL]},
     * counting and remembering the line if found -- the same idiom C's
     * {@code hprintf}, Go's stdout pipe, and Python's {@code print} shadow
     * use (TODO #258/#259), so a wrong verdict anywhere below fails the
     * whole run, not just a crash. */
    private static void out(String line) {
        if (line.contains("[FAIL]")) {
            failures++;
            failLines.add(line.trim());
        }
        System.out.println(line);
    }

    private static String hex(BigInteger v, int nbytes) {
        String h = v.toString(16);
        int width = nbytes * 2;
        if (h.length() < width) h = "0".repeat(width - h.length()) + h;
        return h;
    }

    private static String hex(byte[] b) {
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte x : b) sb.append(String.format("%02x", x));
        return sb.toString();
    }

    private static BigInteger rand(SecureRandom rng) {
        return new BigInteger(Herradura.N, rng).and(Herradura.MASK);
    }

    public static void main(String[] args) {
        SecureRandom rng = new SecureRandom();
        int n = Herradura.N;

        BigInteger a = rand(rng);         // Alice's private scalar (GF DH)
        BigInteger b = rand(rng);         // Bob's private scalar
        BigInteger preshared = rand(rng);
        BigInteger plaintext = rand(rng);
        BigInteger decoy = rand(rng);     // Eve's random value

        BigInteger C = Herradura.hkexGfPubkey(a);
        BigInteger C2 = Herradura.hkexGfPubkey(b);

        System.out.println("a         : " + hex(a, n / 8));
        System.out.println("b         : " + hex(b, n / 8));
        System.out.println("preshared : " + hex(preshared, n / 8));
        System.out.println("plaintext : " + hex(plaintext, n / 8));
        System.out.println("decoy     : " + hex(decoy, n / 8));
        System.out.println("C         : " + hex(C, n / 8));
        System.out.println("C2        : " + hex(C2, n / 8));

        // ── CLASSICAL protocols ──────────────────────────────────────────
        out("\n--- HKEX-GF [CLASSICAL — not PQC; Shor's algorithm breaks DLP]");
        System.out.println("    (DH over GF(2^" + n + ")*)");
        BigInteger sk = Herradura.hkexGfAgree(a, C2);
        BigInteger skBob = Herradura.hkexGfAgree(b, C);
        System.out.println("sk (Alice): " + hex(sk, n / 8));
        System.out.println("sk (Bob)  : " + hex(skBob, n / 8));
        out(sk.equals(skBob) ? "+ session keys agree!" : "[FAIL] session keys differ!");

        out("\n--- HSKE [CLASSICAL — not PQC; linear key recovery from 1 KPT pair]");
        System.out.println("    (fscx_revolve symmetric encryption)");
        BigInteger eHske = Herradura.fscxRevolve(plaintext, preshared, Herradura.I_STEPS);
        System.out.println("P (plain) : " + hex(plaintext, n / 8));
        System.out.println("E (Alice) : " + hex(eHske, n / 8));
        BigInteger dHske = Herradura.fscxRevolve(eHske, preshared, Herradura.R_STEPS);
        System.out.println("D (Bob)   : " + hex(dHske, n / 8));
        out(dHske.equals(plaintext) ? "+ plaintext correctly decrypted" : "[FAIL] decryption failed!");

        out("\n--- Masked HSKE (78.H) [GF(2)-linearity masking, TODO #261]");
        System.out.println("    (fscx_revolve_masked: no secret bits of the input exposed in any");
        System.out.println("     intermediate value, via M^steps(A^r) == M^steps(A)^M^steps(r))");
        {
            Herradura.Masked mCt = Herradura.hskeEncryptMasked(plaintext, preshared, rng);
            Herradura.Masked mPt = Herradura.hskeDecryptMasked(mCt.result, preshared, rng);
            out(mPt.result.equals(plaintext) && mCt.result.equals(eHske)
                    ? "+ masked encrypt/decrypt correct and matches unmasked fscx_revolve"
                    : "[FAIL] masked HSKE encrypt/decrypt failed!");
        }

        out("\n--- HPKS [CLASSICAL — not PQC; DLP + linear challenge]");
        System.out.println("    (Schnorr-like with fscx_revolve challenge)");
        {
            Herradura.Signature sig = Herradura.hpksSign(plaintext, a, rng);
            BigInteger e = Herradura.fscxRevolve(sig.r, plaintext, Herradura.I_STEPS);
            boolean verified = Herradura.hpksVerify(plaintext, C, sig.r, sig.s);
            System.out.println("P (msg)        : " + hex(plaintext, n / 8));
            System.out.println("R [Alice,sign] : " + hex(sig.r, n / 8));
            System.out.println("e [Alice,sign] : " + hex(e, n / 8));
            System.out.println("s [Alice,sign] : " + hex(sig.s, n / 8));
            out(verified ? "  [Bob,verify] : + Schnorr verified: g^s . C^e == R"
                          : "  [Bob,verify] : [FAIL] Schnorr verification failed!");
        }

        out("\n--- HPKE [CLASSICAL — not PQC; DLP + linear HSKE sub-protocol]");
        System.out.println("    (El Gamal + fscx_revolve)");
        {
            Herradura.Ciphertext enc = Herradura.hpkeEncrypt(plaintext, C, rng);
            BigInteger dec = enc == null ? null : Herradura.hpkeDecrypt(enc.ct, enc.r, a);
            System.out.println("P (plain) : " + hex(plaintext, n / 8));
            System.out.println("E (Bob)   : " + (enc == null ? "N/A" : hex(enc.ct, n / 8)));
            System.out.println("D (Alice) : " + (dec == null ? "N/A" : hex(dec, n / 8)));
            out(enc != null && plaintext.equals(dec) ? "+ plaintext correctly decrypted"
                                                       : "[FAIL] decryption failed!");
        }

        // ── PQC-HARDENED protocols ───────────────────────────────────────
        out("\n--- HSKE-NL-A1 [PQC-HARDENED — counter-mode with NL-FSCX v1]");
        {
            BigInteger nonce = rand(rng);
            BigInteger e = HerraduraNl.hskeNlA1Encrypt(plaintext, preshared, nonce);
            BigInteger d = HerraduraNl.hskeNlA1Decrypt(e, preshared, nonce);
            System.out.println("N (nonce) : " + hex(nonce, n / 8));
            System.out.println("P (plain) : " + hex(plaintext, n / 8));
            System.out.println("E (Alice) : " + hex(e, n / 8));
            System.out.println("D (Bob)   : " + hex(d, n / 8));
            out(d.equals(plaintext) ? "+ plaintext correctly decrypted" : "[FAIL] decryption failed!");
        }

        out("\n--- HSKE-NL-A2 [PQC-HARDENED — revolve-mode with NL-FSCX v2]");
        BigInteger a2Key = preshared;
        while (!HerraduraNl.nlV2KeyIsValid(a2Key)) a2Key = rand(rng);
        {
            BigInteger e = HerraduraNl.hskeNlA2Encrypt(plaintext, a2Key);
            BigInteger d = HerraduraNl.hskeNlA2Decrypt(e, a2Key);
            System.out.println("P (plain) : " + hex(plaintext, n / 8));
            System.out.println("E (Alice) : " + hex(e, n / 8));
            System.out.println("D (Bob)   : " + hex(d, n / 8));
            out(d.equals(plaintext) ? "+ plaintext correctly decrypted" : "[FAIL] decryption failed!");
        }

        out("\n--- HSKE-NL-A3 [PQC-HARDENED — NL-FSCX v3, TODO #255]");
        System.out.println("    (v3's chi layer has no affine-degenerate weak-key class -- no key filter)");
        {
            BigInteger e = HerraduraNl.hskeNlA3Encrypt(plaintext, preshared);
            BigInteger d = HerraduraNl.hskeNlA3Decrypt(e, preshared);
            System.out.println("P (plain) : " + hex(plaintext, n / 8));
            System.out.println("E (Alice) : " + hex(e, n / 8));
            System.out.println("D (Bob)   : " + hex(d, n / 8));
            out(d.equals(plaintext) ? "+ plaintext correctly decrypted" : "[FAIL] decryption failed!");
        }

        out("\n--- HKEX-RNL [PQC — Ring-LWR key exchange; conjectured quantum-resistant]");
        System.out.println("    (Ring-LWR, m(x)=1+x+x^{n-1}, n=" + n + ", q=" + HerraduraNl.RNLQ + ")");
        BigInteger skRnlA, skRnlB;
        {
            int[] mBase = HerraduraNl.rnlMPoly(n);
            int[] aRand = HerraduraNl.rnlRandPoly(n, HerraduraNl.RNLQ, rng);
            int[] mBlind = HerraduraNl.rnlPolyAdd(mBase, aRand, HerraduraNl.RNLQ);
            HerraduraNl.RnlKeypair alice = HerraduraNl.rnlKeygen(mBlind, n, HerraduraNl.RNLQ, HerraduraNl.RNLP, rng);
            HerraduraNl.RnlKeypair bob = HerraduraNl.rnlKeygen(mBlind, n, HerraduraNl.RNLQ, HerraduraNl.RNLP, rng);
            HerraduraNl.RnlAgreeResult bobAgree = HerraduraNl.rnlAgree(
                bob.s, alice.c, HerraduraNl.RNLQ, HerraduraNl.RNLP, HerraduraNl.RNLPP, n, n);
            BigInteger aliceKey = HerraduraNl.rnlAgree(
                alice.s, bob.c, HerraduraNl.RNLQ, HerraduraNl.RNLP, HerraduraNl.RNLPP, n, n, bobAgree.hint);
            byte[] nA = new byte[32], nB = new byte[32];
            rng.nextBytes(nA);
            rng.nextBytes(nB);
            skRnlA = HerraduraNl.rnlContributoryKdf(aliceKey, n, nA, nB);
            skRnlB = HerraduraNl.rnlContributoryKdf(bobAgree.key, n, nA, nB);
            System.out.println("n_A       : " + hex(nA));
            System.out.println("n_B       : " + hex(nB));
            System.out.println("sk (Alice): " + hex(skRnlA, n / 8));
            System.out.println("sk (Bob)  : " + hex(skRnlB, n / 8));
            out(skRnlA.equals(skRnlB) ? "+ contributory KDF session keys agree!"
                : "- session key disagrees (reconciliation failed, a nonzero-DFR Ring-LWR "
                  + "event this demo does not retry -- not a bug)");
        }

        out("\n--- HPKS-NL [NL-hardened Schnorr — NL-FSCX v1 challenge]");
        System.out.println("    (GF DLP still present; NL hardens linear challenge preimage)");
        BigInteger RNl2 = null; // captured for the HPKE-NL Eve section below
        {
            Herradura.Signature sig = HerraduraNl.hpksNlSign(plaintext, a, rng);
            BigInteger e = Hfscx256.nlFscxRevolveV1(sig.r, plaintext, Herradura.I_STEPS);
            boolean verified = HerraduraNl.hpksNlVerify(plaintext, C, sig.r, sig.s);
            System.out.println("P (msg)        : " + hex(plaintext, n / 8));
            System.out.println("R [Alice,sign] : " + hex(sig.r, n / 8));
            System.out.println("e [Alice,sign] : " + hex(e, n / 8));
            System.out.println("s [Alice,sign] : " + hex(sig.s, n / 8));
            out(verified ? "  [Bob,verify] : + HPKS-NL verified: g^s . C^e == R"
                          : "  [Bob,verify] : [FAIL] HPKS-NL verification failed!");
        }

        out("\n--- HPKE-NL [NL-hardened El Gamal — NL-FSCX v2 encryption]");
        System.out.println("    (GF DLP still present; NL hardens linear HSKE sub-protocol)");
        BigInteger eHpkeNl = null;
        {
            Herradura.Ciphertext enc = HerraduraNl.hpkeNlEncrypt(plaintext, C, rng);
            BigInteger dec = enc == null ? null : HerraduraNl.hpkeNlDecrypt(enc.ct, enc.r, a);
            if (enc != null) { eHpkeNl = enc.ct; RNl2 = enc.r; }
            System.out.println("P (plain) : " + hex(plaintext, n / 8));
            System.out.println("E (Bob)   : " + (enc == null ? "N/A" : hex(enc.ct, n / 8)));
            System.out.println("D (Alice) : " + (dec == null ? "N/A" : hex(dec, n / 8)));
            out(enc != null && plaintext.equals(dec) ? "+ plaintext correctly decrypted"
                                                       : "[FAIL] decryption failed!");
        }

        out("\n--- HPKE-NL3 [NL-hardened El Gamal — NL-FSCX v3, TODO #255]");
        {
            Herradura.Ciphertext enc = HerraduraNl.hpkeNl3Encrypt(plaintext, C, rng);
            BigInteger dec = enc == null ? null : HerraduraNl.hpkeNl3Decrypt(enc.ct, enc.r, a);
            System.out.println("P (plain) : " + hex(plaintext, n / 8));
            System.out.println("E (Bob)   : " + (enc == null ? "N/A" : hex(enc.ct, n / 8)));
            System.out.println("D (Alice) : " + (dec == null ? "N/A" : hex(dec, n / 8)));
            out(enc != null && plaintext.equals(dec) ? "+ plaintext correctly decrypted"
                                                       : "[FAIL] decryption failed!");
        }

        // ── Code-based PQC (Stern family) ────────────────────────────────
        Stern.SternKeypair sf = Stern.sternFKeygen(rng);
        out("\n--- HPKS-Stern-F [CODE-BASED PQC — EUF-CMA <= q_H/T_SD + eps_PRF]");
        System.out.println("    (N=" + n + ", t=" + Stern.SDFT + ", rounds=" + Stern.SDFR
            + "; soundness=(2/3)^" + Stern.SDFR + ")");
        Stern.SternSignature sfSig = Stern.hpksSternFSign(plaintext, sf.e, sf.seed, Stern.SDFR, rng);
        {
            System.out.println("seed     : " + hex(sf.seed, n / 8));
            System.out.println("msg      : " + hex(plaintext, n / 8));
            boolean ok = Stern.hpksSternFVerify(plaintext, sfSig, sf.seed, sf.syndrome);
            out(ok ? "+ HPKS-Stern-F signature verified" : "[FAIL] HPKS-Stern-F verification failed");
        }

        out("\n--- HPKE-Stern-F [CODE-BASED PQC — Niederreiter KEM, N=" + n + "]");
        System.out.println("    (brute-force decap infeasible at N=256; demo uses known e')");
        BigInteger sfKEnc;
        {
            Stern.SternEncapResult enc = Stern.hpkeSternFEncapWithE(sf.seed, rng);
            BigInteger dec = Stern.hpkeSternFDecap(enc.eP, sf.seed);
            sfKEnc = enc.k;
            System.out.println("K (encap): " + hex(enc.k, n / 8));
            System.out.println("K (decap): " + hex(dec, n / 8));
            System.out.println("    NOTE: decap uses known e' (demo only; production: QC-MDPC decoder)");
            out(enc.k.equals(dec) ? "+ HPKE-Stern-F session keys agree"
                                   : "[FAIL] HPKE-Stern-F key agreement failed");
        }

        out("\n--- HPKE-Stern-KEM [CODE-BASED PQC — real QC-MDPC/BGF Niederreiter KEM]");
        {
            Stern.QcMdpcKeypair kp = Stern.qcmdpcKeygen(rng);
            Stern.QcMdpcEncapResult enc = Stern.qcmdpcEncap(kp.hPub, rng);
            BigInteger dec = Stern.qcmdpcDecapBgf(enc.syn, kp.sup0, kp.sup1);
            System.out.println("K (encap): " + hex(enc.k, n / 8));
            System.out.println("K (decap): " + hex(dec, n / 8));
            System.out.println("    NOTE: implicit rejection (TODO #235) -- a DFR event decrypts to");
            System.out.println("    garbage rather than failing; ~0.225% measured (TODO #195)");
            out(enc.k.equals(dec) ? "+ HPKE-Stern-KEM session keys agree"
                                   : "- session key disagrees (a nonzero-DFR BGF decode event -- not a bug)");
        }

        out("\n--- HPKS-Stern-Ring (78.I) [CODE-BASED RING SIG — OR-composed Stern, N=" + n + ", k=3]");
        {
            int ringK = 3, ringRounds = Stern.SDFR;
            List<SternRing.RingKey> ringKeys = new ArrayList<>();
            List<BigInteger> ringE = new ArrayList<>();
            for (int i = 0; i < ringK; i++) {
                Stern.SternKeypair kp = Stern.sternFKeygen(rng);
                ringKeys.add(new SternRing.RingKey(kp.seed, kp.syndrome));
                ringE.add(kp.e);
            }
            SternRing.RingSignature rsig = SternRing.sign(plaintext, ringE.get(1), 1, ringKeys, ringRounds, rng);
            boolean ok = SternRing.verify(plaintext, rsig, ringKeys);
            out(ok ? "+ HPKS-Stern-Ring signature verified (k=" + ringK + ", signer=1)"
                    : "[FAIL] HPKS-Stern-Ring verification failed (k=" + ringK + ")");
        }

        // ── Hash / proofs / credentials ──────────────────────────────────
        out("\n--- HFSCX-256-DM [HASH — Merkle-Damgard over NL-FSCX v1, Davies-Meyer; 256-bit output]");
        {
            byte[] tv = "HFSCX-256 test vector".getBytes(java.nio.charset.StandardCharsets.US_ASCII);
            byte[] bareOut = Hfscx256.hash(tv, null);
            byte[] presBytes = Hfscx256.toFixedBytes(preshared, n / 8);
            byte[] macIv = new byte[32];
            byte[] ivConstBytes = Hfscx256.toFixedBytes(Hfscx256.IV_CONST, 32);
            for (int i = 0; i < 32; i++) macIv[i] = (byte) (presBytes[i] ^ ivConstBytes[i]);
            byte[] keyedOut = Hfscx256.hash(tv, new BigInteger(1, macIv));
            System.out.println("digest (bare)  : " + hex(bareOut));
            System.out.println("digest (keyed) : " + hex(keyedOut));
            out(bareOut.length == 32 ? "+ hash length correct (" + bareOut.length + " bytes)"
                                       : "[FAIL] hash length wrong (" + bareOut.length + " bytes)");
            out(!java.util.Arrays.equals(bareOut, keyedOut) ? "+ keyed != bare (key influences output)"
                : "[FAIL] keyed == bare (unexpected!)");
        }

        out("\n--- ZKP-NL [PROOF — NL-FSCX ZKBoo, MPC-in-the-head]");
        {
            int zn = 32, zrounds = 16;
            BigInteger mask = BigInteger.ONE.shiftLeft(zn).subtract(BigInteger.ONE);
            BigInteger zA = new BigInteger(zn, rng).and(mask);
            BigInteger zB = new BigInteger(zn, rng).and(mask);
            BigInteger zY = ZkpNl.nlFscxV1General(zA, zB, zn);
            byte[] msg = "ZKP-NL demo message".getBytes(java.nio.charset.StandardCharsets.US_ASCII);
            List<ZkpNl.ProofRound> proof = ZkpNl.prove(zA, zB, zY, zn, zrounds, msg, rng);
            boolean ok = ZkpNl.verify(zB, zY, zn, zrounds, msg, proof);
            System.out.println("    (n=" + zn + ", R=" + zrounds + ")");
            out(ok ? "+ ZKP-NL proof verified" : "[FAIL] ZKP-NL verify failed");
        }

        out("\n--- HCRED [CREDENTIAL — Ring-LWR + code syndrome via phi, MPCitH; n=32, R=4]");
        {
            int hcRounds = Hcred.DEMO_ROUNDS;
            int[] mBase = HerraduraNl.rnlMPoly(n);
            int[] aRand = HerraduraNl.rnlRandPoly(n, HerraduraNl.RNLQ, rng);
            int[] mBlind = HerraduraNl.rnlPolyAdd(mBase, aRand, HerraduraNl.RNLQ);
            Hcred.UserKeypair kp = Hcred.userKeygen(mBlind, rng);
            BigInteger seedH = rand(rng);
            BigInteger y = Hcred.syndrome(seedH, kp.e);
            Stern.SternKeypair isk = Stern.sternFKeygen(rng);
            Stern.SternSignature credSig = Hcred.issue(mBlind, kp.c, seedH, y, n, isk.e, isk.seed, 8, rng);
            boolean credOk = Hcred.credVerify(mBlind, kp.c, seedH, y, n, credSig, isk.seed, isk.syndrome);
            out(credOk ? "+ issuer credential (Stern-F over (m,C,seed_H,y)) verified"
                        : "[FAIL] issuer credential verify failed");
            byte[] nonce = "HCRED demo nonce".getBytes(java.nio.charset.StandardCharsets.US_ASCII);
            Hcred.Proof proof = Hcred.prove(kp.s, mBlind, kp.c, seedH, y, hcRounds, nonce, rng);
            System.out.println("enrolment: W=" + proof.W + " (weight of hidden e=phi(s))");
            boolean okPresent = Hcred.verify(mBlind, kp.c, seedH, y, proof, hcRounds, nonce);
            out(okPresent ? "+ HCRED presentation proof verified (unified circuit: Ring-LWR "
                    + "rounding + syndrome for the SAME s; e never revealed)"
                : "[FAIL] HCRED presentation verify failed");
            byte[] otherNonce = "other nonce".getBytes(java.nio.charset.StandardCharsets.US_ASCII);
            boolean replayRejected = !Hcred.verify(mBlind, kp.c, seedH, y, proof, hcRounds, otherNonce);
            out(replayRejected ? "+ HCRED replay under different nonce rejected"
                                 : "[FAIL] HCRED replay NOT rejected");
            System.out.println("  (demo uses R=4; production requires R=219)");

            // HCRED-KKW: the same statement/circuit, preprocessing-model
            // transcript (TODO #128 Batch 3 / ported under TODO #261).
            byte[] kkwNonce = "HCRED-KKW demo nonce".getBytes(java.nio.charset.StandardCharsets.US_ASCII);
            Hcred.HcredKkwProof kkwProof = Hcred.proveKkw(kp.s, mBlind, kp.c, seedH, y,
                    Hcred.KKW_DEMO_N, Hcred.KKW_DEMO_M, Hcred.KKW_DEMO_TAU, kkwNonce, rng);
            boolean kkwOk = Hcred.verifyKkw(mBlind, kp.c, seedH, y, kkwProof, kkwNonce);
            out(kkwOk ? "+ HCRED-KKW presentation proof verified (preprocessing MPCitH; "
                    + "N=4, M=8, tau=4 demo)"
                : "[FAIL] HCRED-KKW verify failed");
            byte[] kkwOtherNonce = "other nonce".getBytes(java.nio.charset.StandardCharsets.US_ASCII);
            boolean kkwReplayRejected = !Hcred.verifyKkw(mBlind, kp.c, seedH, y, kkwProof, kkwOtherNonce);
            out(kkwReplayRejected ? "+ HCRED-KKW replay under different nonce rejected"
                                    : "[FAIL] HCRED-KKW replay NOT rejected");
            System.out.println("  (production KKW: N=64, M=343, tau=27 for 2^-128 — "
                    + "~11x smaller than the ZKBoo path above at production rounds)");
        }

        // ── Hash-based signatures ────────────────────────────────────────
        out("\n--- HPKS-XMSS-F [PQC — hash-based many-time sig; WOTS-F chains + Merkle tree]");
        {
            byte[] xmssSeed = new byte[32];
            rng.nextBytes(xmssSeed);
            int xmssH = 3; // 8 leaves; production uses h=10
            Xmss.Keypair xkp = Xmss.keygen(xmssSeed, xmssH);
            byte[] xmssMsg = "HPKS-XMSS-F test message".getBytes(java.nio.charset.StandardCharsets.US_ASCII);
            Xmss.Signature sig0 = Xmss.sign(xmssMsg, xmssSeed, xkp.leafHashes, 0);
            Xmss.Signature sig1 = Xmss.sign(xmssMsg, xmssSeed, xkp.leafHashes, 1);
            boolean ok0 = Xmss.verify(xmssMsg, sig0, xkp.root);
            boolean ok1 = Xmss.verify(xmssMsg, sig1, xkp.root);
            boolean bad = Xmss.verify("tampered".getBytes(java.nio.charset.StandardCharsets.US_ASCII), sig0, xkp.root);
            out(ok0 && ok1 && !bad
                ? "+ HPKS-XMSS-F sign/verify correct (h=" + xmssH + ", 2 leaves, tamper rejected)"
                : "[FAIL] HPKS-XMSS-F: ok0=" + ok0 + " ok1=" + ok1 + " bad=" + bad);
        }

        out("\n--- HPKS-WOTS-F [PQC — one-time hash-based signature]");
        {
            byte[] wotsSeed = new byte[32];
            rng.nextBytes(wotsSeed);
            Wots.Keypair wkp = Wots.keygen(wotsSeed, 0);
            byte[] wotsMsg = "HPKS-WOTS-F test message".getBytes(java.nio.charset.StandardCharsets.US_ASCII);
            Wots.Signature sig = Wots.sign(wotsMsg, wotsSeed, 0);
            boolean ok = Wots.verify(wotsMsg, sig.sig, wkp.pk);
            boolean bad = Wots.verify("tampered".getBytes(java.nio.charset.StandardCharsets.US_ASCII), sig.sig, wkp.pk);
            out(ok && !bad ? "+ HPKS-WOTS-F sign/verify correct, tamper rejected"
                             : "[FAIL] HPKS-WOTS-F: ok=" + ok + " bad_accepted=" + bad);
        }

        // ── TODO #260's seven ported primitives ──────────────────────────
        out("\n--- HPKS-T [THRESHOLD — n-of-n MuSig2-style aggregate Schnorr over GF(2^n)*]");
        {
            int tN = 3;
            List<BigInteger> secrets = new ArrayList<>();
            List<BigInteger> pubkeys = new ArrayList<>();
            for (int i = 0; i < tN; i++) {
                BigInteger sk2 = rand(rng);
                secrets.add(sk2);
                pubkeys.add(Herradura.gfPow(Herradura.GF_GEN, sk2));
            }
            BigInteger msg = rand(rng);
            HpksT.Signature sig = HpksT.sign(secrets, pubkeys, msg, rng);
            boolean ok = HpksT.verify(sig.cAgg, sig.r, sig.s, msg);
            boolean bad = HpksT.verify(sig.cAgg, sig.r, sig.s.xor(BigInteger.ONE), msg);
            out(ok && !bad ? "+ HPKS-T " + tN + "-of-" + tN + " sign/verify correct, tamper rejected"
                             : "[FAIL] HPKS-T: ok=" + ok + " bad_accepted=" + bad);
        }

        out("\n--- HDRBG [FORWARD-SECURE DRBG — NL-FSCX v1 ratchet, fast-key-erasure]");
        {
            byte[] entropy = "demo-entropy-96".getBytes(java.nio.charset.StandardCharsets.US_ASCII);
            byte[] pers = "pers".getBytes(java.nio.charset.StandardCharsets.US_ASCII);
            Hdrbg d1 = Hdrbg.seed(entropy, pers);
            Hdrbg d2 = Hdrbg.seed(entropy, pers);
            byte[] out1 = d1.generate(64);
            byte[] out2 = d2.generate(64);
            d2.reseed("fresh-entropy".getBytes(java.nio.charset.StandardCharsets.US_ASCII));
            byte[] out3 = d2.generate(64);
            byte[] out4 = d1.generate(64);
            boolean ok = java.util.Arrays.equals(out1, out2) && !java.util.Arrays.equals(out3, out4)
                && out1.length == 64;
            out(ok ? "+ HDRBG determinism + reseed separation correct" : "[FAIL] HDRBG failed!");
        }

        out("\n--- fpe (78.A) [TWEAK CIPHER — 32-byte block, key+context tweak, v2 and v3]");
        System.out.println("    NOT format-preserving in the FF1/FF3-1 sense; see SECURITY.md");
        {
            byte[] fpeKey = "herradura-fpe-key-256bit-example".getBytes(java.nio.charset.StandardCharsets.US_ASCII);
            byte[] fpeCtx = "record:42".getBytes(java.nio.charset.StandardCharsets.US_ASCII);
            BigInteger ct2 = FpeTwk.fpeEncrypt(plaintext, fpeKey, fpeCtx);
            BigInteger rt2 = FpeTwk.fpeDecrypt(ct2, fpeKey, fpeCtx);
            BigInteger ct3 = FpeTwk.fpeV3Encrypt(plaintext, fpeKey, fpeCtx);
            BigInteger rt3 = FpeTwk.fpeV3Decrypt(ct3, fpeKey, fpeCtx);
            boolean v2v3Differ = !ct2.equals(ct3);
            out(rt2.equals(plaintext) && rt3.equals(plaintext) && v2v3Differ
                ? "+ fpe v2/v3 round-trip correct, v2 != v3 output"
                : "[FAIL] fpe round-trip failed (v2_rt=" + rt2.equals(plaintext)
                    + " v3_rt=" + rt3.equals(plaintext) + " v2v3_differ=" + v2v3Differ + ")");
        }

        out("\n--- twk (78.B) [TWEAKABLE WIDE-BLOCK CIPHER — sector/block-index tweak, v2 and v3]");
        {
            byte[] twkKey = "herradura-twk-key-256bit-example".getBytes(java.nio.charset.StandardCharsets.US_ASCII);
            BigInteger ct2 = FpeTwk.twkEncrypt(plaintext, twkKey, 7, 3);
            BigInteger rt2 = FpeTwk.twkDecrypt(ct2, twkKey, 7, 3);
            BigInteger ct3 = FpeTwk.twkV3Encrypt(plaintext, twkKey, 7, 3);
            BigInteger rt3 = FpeTwk.twkV3Decrypt(ct3, twkKey, 7, 3);
            boolean v2v3Differ = !ct2.equals(ct3);
            out(rt2.equals(plaintext) && rt3.equals(plaintext) && v2v3Differ
                ? "+ twk v2/v3 round-trip correct, v2 != v3 output"
                : "[FAIL] twk round-trip failed (v2_rt=" + rt2.equals(plaintext)
                    + " v3_rt=" + rt3.equals(plaintext) + " v2v3_differ=" + v2v3Differ + ")");
        }

        out("\n--- HSKE-NL-V2-Duplex [AEAD — MonkeyDuplex, nl_fscx_revolve_v2 sponge] [RESEARCH]");
        {
            BigInteger dpKey = rand(rng);
            byte[] dpPt = "HSKE-NL-V2-Duplex demo plaintext (47 B)".getBytes(java.nio.charset.StandardCharsets.US_ASCII);
            byte[] dpAd = "duplex-header-v1".getBytes(java.nio.charset.StandardCharsets.US_ASCII);
            Duplex.EncResult r = Duplex.v2Encrypt(dpKey, dpPt, dpAd, rng);
            byte[] dpDec = Duplex.v2Decrypt(dpKey, r.nonce, r.ct, r.tag, dpAd);
            byte[] badCt = r.ct.clone();
            if (badCt.length > 0) badCt[0] ^= 1;
            byte[] badCtDec = Duplex.v2Decrypt(dpKey, r.nonce, badCt, r.tag, dpAd);
            byte[] badAdDec = Duplex.v2Decrypt(dpKey, r.nonce, r.ct, r.tag,
                "duplex-header-v2".getBytes(java.nio.charset.StandardCharsets.US_ASCII));
            boolean ok = java.util.Arrays.equals(dpDec, dpPt) && badCtDec == null && badAdDec == null;
            out(ok ? "+ HSKE-NL-V2-Duplex round-trip + tamper/AD rejection correct [RESEARCH]"
                    : "[FAIL] HSKE-NL-V2-Duplex round-trip / tamper / AD rejection");
        }

        out("\n--- HSKE-NL-V3-Duplex [AEAD — MonkeyDuplex, nl_fscx_revolve_v3 sponge, TODO #255] [RESEARCH]");
        {
            BigInteger dpKey = rand(rng);
            byte[] dpPt = "HSKE-NL-V3-Duplex demo plaintext (47 B)".getBytes(java.nio.charset.StandardCharsets.US_ASCII);
            byte[] dpAd = "duplex-header-v1".getBytes(java.nio.charset.StandardCharsets.US_ASCII);
            Duplex.EncResult r = Duplex.v3Encrypt(dpKey, dpPt, dpAd, rng);
            byte[] dpDec = Duplex.v3Decrypt(dpKey, r.nonce, r.ct, r.tag, dpAd);
            byte[] badCt = r.ct.clone();
            if (badCt.length > 0) badCt[0] ^= 1;
            byte[] badCtDec = Duplex.v3Decrypt(dpKey, r.nonce, badCt, r.tag, dpAd);
            byte[] badAdDec = Duplex.v3Decrypt(dpKey, r.nonce, r.ct, r.tag,
                "duplex-header-v2".getBytes(java.nio.charset.StandardCharsets.US_ASCII));
            boolean ok = java.util.Arrays.equals(dpDec, dpPt) && badCtDec == null && badAdDec == null;
            out(ok ? "+ HSKE-NL-V3-Duplex round-trip + tamper/AD rejection correct [RESEARCH]"
                    : "[FAIL] HSKE-NL-V3-Duplex round-trip / tamper / AD rejection");
        }

        out("\n--- Forward-secret ratchet (78.C) [KDF CHAIN — NL-FSCX v1 advance]");
        {
            BigInteger state = Ratchet.init("demo-seed-78c".getBytes(java.nio.charset.StandardCharsets.US_ASCII));
            java.util.Set<String> keys = new java.util.HashSet<>();
            for (int i = 0; i < 5; i++) {
                Object[] r = Ratchet.advance(state);
                state = (BigInteger) r[0];
                keys.add(new BigInteger(1, (byte[]) r[1]).toString(16));
            }
            out(keys.size() == 5 ? "+ Ratchet: 5 distinct message keys"
                                   : "[FAIL] Ratchet: duplicate message keys!");
        }

        // ── OPRF / aPAKE ──────────────────────────────────────────────────
        out("\n--- OPRF [2HashDH oblivious PRF over GF(2^" + n + ")*]");
        {
            BigInteger k = Oprf.keygen(rng);
            byte[] x = "oprf-demo-input".getBytes(java.nio.charset.StandardCharsets.US_ASCII);
            Oprf.Blinded blinded = Oprf.blind(x, rng);
            BigInteger beta = Oprf.eval(blinded.alpha, k);
            BigInteger f1 = Oprf.unblind(beta, blinded.r);
            BigInteger f2 = Oprf.direct(x, k);
            out(f1.equals(f2) ? "+ OPRF blind/eval/unblind round-trip correct"
                                : "[FAIL] OPRF round-trip failed!");
        }

        out("\n*** aPAKE (80) — HKEX-RNL + ZKBoo + OPRF augmented PAKE");
        {
            BigInteger oprfKey = Oprf.keygen(rng);
            byte[] pw = "s3cr3t-pw".getBytes(java.nio.charset.StandardCharsets.US_ASCII);
            Hpake.Record record = Hpake.register("alice", pw, oprfKey, rng);
            byte[] skPake = Hpake.loginDemo(record, pw, oprfKey, rng);
            out(skPake != null ? "+ aPAKE login with correct password: session key established"
                                 : "[FAIL] aPAKE login with correct password failed!");
            byte[] badSk = Hpake.loginDemo(record, "wrong-pw".getBytes(java.nio.charset.StandardCharsets.US_ASCII), oprfKey, rng);
            out(badSk == null ? "+ aPAKE login with wrong password: correctly rejected"
                                : "[FAIL] aPAKE login with wrong password ACCEPTED (security failure)!");
        }

        // ── EVE bypass tests ──────────────────────────────────────────────
        System.out.println("\n\n*** EVE bypass TESTS");

        out("*** HPKS-NL — Eve cannot forge Schnorr without knowing private key a");
        {
            BigInteger rEve = Herradura.gfPow(Herradura.GF_GEN, rand(rng));
            BigInteger eEve = Hfscx256.nlFscxRevolveV1(rEve, decoy, Herradura.I_STEPS);
            BigInteger sEve = rand(rng);
            BigInteger lhs = Herradura.gfMul(Herradura.gfPow(Herradura.GF_GEN, sEve), Herradura.gfPow(C, eEve));
            out(lhs.equals(rEve) ? "[FAIL] Eve forged HPKS-NL signature (Eve wins)!"
                : "- Eve could not forge: g^s_eve . C^e_eve != R_eve  (DLP protection)");
        }

        out("*** HPKE-NL — Eve cannot decrypt without Alice's private key");
        if (eHpkeNl != null && RNl2 != null) {
            BigInteger eveKey = C.xor(RNl2);
            BigInteger dEve = HerraduraNl.nlFscxRevolveV2Inv(eHpkeNl, eveKey, Herradura.I_STEPS);
            out(dEve.equals(plaintext) ? "[FAIL] Eve decrypted plaintext (Eve wins)!"
                : "- Eve could not decrypt without Alice's private key (CDH + NL protection)");
        }

        out("*** HKEX-RNL — Eve cannot derive shared key from public ring polynomials");
        {
            BigInteger eveGuess = rand(rng);
            out(eveGuess.equals(skRnlA) ? "[FAIL] Eve guessed HKEX-RNL shared key (astronomically unlikely)!"
                : "- Eve random guess does not match shared key (Ring-LWR protection)");
        }

        out("*** HPKS-Stern-F — Eve cannot forge without solving SD(N,t)");
        {
            int r = sfSig.rounds();
            BigInteger[] c0 = new BigInteger[r], c1 = new BigInteger[r], c2 = new BigInteger[r];
            int[] challenges = new int[r];
            BigInteger[] resp0 = new BigInteger[r], resp1 = new BigInteger[r];
            for (int i = 0; i < r; i++) {
                c0[i] = rand(rng); c1[i] = rand(rng); c2[i] = rand(rng);
                challenges[i] = 0;
                resp0[i] = rand(rng); resp1[i] = rand(rng);
            }
            Stern.SternSignature eveSig = new Stern.SternSignature(c0, c1, c2, challenges, resp0, resp1);
            boolean forged = Stern.hpksSternFVerify(decoy, eveSig, sf.seed, sf.syndrome);
            out(forged ? "[FAIL] Eve forged HPKS-Stern-F (Eve wins)!"
                : "- Eve cannot forge: Fiat-Shamir mismatch  (SD + PRF protection)");
        }

        out("*** HPKE-Stern-F — Eve cannot derive session key from syndrome ciphertext");
        {
            BigInteger eveGuess = rand(rng);
            out(eveGuess.equals(sfKEnc) ? "[FAIL] Eve guessed HPKE-Stern-F session key (astronomically unlikely)!"
                : "- Eve random guess does not match session key  (SD protection)");
        }

        // Failure gate (TODO #258/#259's convention, carried to Java for
        // TODO #260 step 4): exit non-zero if any check reported [FAIL].
        if (failures > 0) {
            System.out.println("\n*** FAILED: " + failures + " check(s) reported [FAIL] ***");
            for (String line : failLines) System.out.println("    " + line);
            System.exit(1);
        }
        System.out.println("\n*** OK: no check reported [FAIL] ***");
    }
}
