package herradurakex;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * TODO #192: cross-language verifier for KAT/classical_quartet.json
 * (TODO #190). Recomputes every HKEX-GF/HSKE/HPKS/HPKE vector using this
 * package — not the Python reference that generated the file, nor the
 * Go herradura package that KAT/verify_kat.go already cross-checks it
 * against — and confirms byte-identical results.
 *
 * Uses a minimal hand-rolled parser for the KAT file's flat
 * "quoted-key": "quoted-value" / number pairs rather than pulling in a
 * JSON library dependency, since the file's structure is fixed and
 * simple (four top-level objects, each a flat string/int map).
 *
 * Usage: java -cp bindings/java herradurakex.KatVerify [path/to/classical_quartet.json]
 */
public final class KatVerify {
    private KatVerify() { }

    private static final Pattern OBJECT = Pattern.compile(
            "\"(hkex_gf|hske|hpks|hpke)\"\\s*:\\s*\\{([^}]*)\\}", Pattern.DOTALL);
    private static final Pattern FIELD = Pattern.compile(
            "\"(\\w+)\"\\s*:\\s*(?:\"([0-9a-fA-Fx]*)\"|(-?\\d+)|(true|false))");

    private static Map<String, String> parseObject(String body) {
        Map<String, String> fields = new HashMap<>();
        Matcher m = FIELD.matcher(body);
        while (m.find()) {
            String key = m.group(1);
            String val = m.group(2) != null ? m.group(2)
                    : m.group(3) != null ? m.group(3) : m.group(4);
            fields.put(key, val);
        }
        return fields;
    }

    private static BigInteger hex(Map<String, String> obj, String key) {
        return new BigInteger(obj.get(key), 16);
    }

    // ── HKEX-RNL (TODO #226) ────────────────────────────────────────────────
    // The ring vectors live in their own file: they are not part of the
    // classical quartet and their polynomials are far larger.

    private static final Pattern RNL_OBJECT = Pattern.compile(
            "\"(deployed|small_ring)\"\\s*:\\s*\\{([^}]*)\\}", Pattern.DOTALL);

    // ── NL-FSCX v3 (TODO #255) ──────────────────────────────────────────────
    // This Java CLI has no duplex, fpe or twk, so KAT/nl_fscx_v3.json's
    // hske_duplex3 and fpe_twk_v3 sets have nothing here to check them against;
    // KAT/verify_kat.go covers those.  What Java does port is the primitive
    // itself plus hske-nla3 and hpke-nl3, and those are checked below.
    private static final Pattern V3_OBJECT = Pattern.compile(
            "\"(nl_fscx_v3|hske_nla3|hpke_nl3)\"\\s*:\\s*\\{([^}]*)\\}", Pattern.DOTALL);

    private static int intField(Map<String, String> obj, String key) {
        return Integer.parseInt(obj.get(key));
    }

    /** Reads a fixed-width big-endian coefficient blob (generate_kat.py's poly_hex). */
    private static int[] unpackPoly(String hexs, int n, int bytesPerCoeff) {
        int[] out = new int[n];
        for (int i = 0; i < n; i++) {
            int v = 0;
            for (int k = 0; k < bytesPerCoeff; k++) {
                v = (v << 8) | Integer.parseInt(
                        hexs.substring((i * bytesPerCoeff + k) * 2,
                                       (i * bytesPerCoeff + k) * 2 + 2), 16);
            }
            out[i] = v;
        }
        return out;
    }

    private static String polyHex(int[] coeffs, int bytesPerCoeff) {
        StringBuilder sb = new StringBuilder();
        for (int c : coeffs) {
            for (int k = bytesPerCoeff - 1; k >= 0; k--) {
                sb.append(String.format("%02x", (c >> (8 * k)) & 0xFF));
            }
        }
        return sb.toString();
    }

    /** Packs `used` two-bit hint values, 4 per byte, LSB-first — C's rnl_hint layout. */
    private static String hintHex(int[] hint, int used) {
        byte[] raw = new byte[(used + 3) / 4];
        for (int i = 0; i < used; i++) {
            raw[i >> 2] |= (byte) ((hint[i] & 3) << ((i & 3) * 2));
        }
        StringBuilder sb = new StringBuilder();
        for (byte b : raw) {
            sb.append(String.format("%02x", b & 0xFF));
        }
        return sb.toString();
    }

    /**
     * Recomputes one HKEX-RNL handshake from the vector's fixed secrets.  The
     * secrets are inputs: a KAT fixes the randomness and tests the deterministic
     * parts — ring arithmetic, rounding, reconciliation, and the KDF.
     */
    private static boolean verifyRnl(String name, Map<String, String> v) {
        int n = intField(v, "n");
        int q = intField(v, "q"), p = intField(v, "p"), pp = intField(v, "pp");
        int keyBits = intField(v, "key_bits");
        int used = intField(v, "hint_coefficients");

        int[] mBlind = unpackPoly(v.get("m_blind"), n, 4);
        int[] sA = unpackPoly(v.get("alice_s"), n, 4);
        int[] sB = unpackPoly(v.get("bob_s"), n, 4);

        int[] cA = HerraduraNl.rnlRound(HerraduraNl.rnlPolyMul(mBlind, sA, q, n), q, p);
        int[] cB = HerraduraNl.rnlRound(HerraduraNl.rnlPolyMul(mBlind, sB, q, n), q, p);

        // Bob reconciles and publishes the hint; Alice consumes it.
        HerraduraNl.RnlAgreeResult bob = HerraduraNl.rnlAgree(sB, cA, q, p, pp, n, keyBits);
        BigInteger kAlice = HerraduraNl.rnlAgree(sA, cB, q, p, pp, n, keyBits, bob.hint);

        boolean ok = polyHex(cA, 2).equals(v.get("alice_C"))
                && polyHex(cB, 2).equals(v.get("bob_C"))
                && hintHex(bob.hint, used).equals(v.get("hint"))
                && kAlice.equals(new BigInteger(v.get("k_raw"), 16))
                && kAlice.equals(bob.key);

        // The session KDF applies only where the derived key is the full width;
        // the small-ring vector records session_key as null and is skipped.
        String wantSk = v.get("session_key");
        if (ok && wantSk != null) {
            // TODO #314 pass 5: the SIXTH transcribed copy of this derivation in
            // this port, now the one named truncation (BITARRAY.md §4.4).
            BitArray kA = BitArray.fromBigInteger(kAlice, keyBits);
            BigInteger sk = Hfscx256.nlFscxRevolveV1(
                    BitArray.rnlKdfSeed(kA), kA, keyBits / 4).toBigInteger();
            if (!sk.equals(new BigInteger(wantSk, 16))) {
                System.out.println("FAIL " + name + ": session_key got "
                        + sk.toString(16) + " want " + wantSk);
                return false;
            }
        }
        if (!ok) {
            System.out.println("FAIL " + name + ": C_A=" + polyHex(cA, 2).equals(v.get("alice_C"))
                    + " C_B=" + polyHex(cB, 2).equals(v.get("bob_C"))
                    + " hint=" + hintHex(bob.hint, used).equals(v.get("hint"))
                    + " k_raw=" + kAlice.equals(new BigInteger(v.get("k_raw"), 16))
                    + " agree=" + kAlice.equals(bob.key));
            return false;
        }
        System.out.println("PASS " + name + " (n=" + n + ", key_bits=" + keyBits + ")");
        return true;
    }

    /** Recomputes the Java-portable NL-FSCX v3 vectors.  Nothing here is
     * probabilistic: the four ports are byte-identical by design, so any
     * mismatch is a port bug rather than a tolerance question. */
    private static int verifyV3(Map<String, Map<String, String>> v3) {
        int fails = 0;

        Map<String, String> p = v3.get("nl_fscx_v3");
        int r3 = intField(p, "r3_steps");
        if (r3 != HerraduraNl.R3_VALUE) {
            System.out.println("FAIL nl_fscx_v3: vector says r3_steps=" + r3
                    + ", package says " + HerraduraNl.R3_VALUE);
            fails++;
        }
        BigInteger key = hex(p, "key"), pt = hex(p, "plaintext");
        BitArray revolve = HerraduraNl.nlFscxRevolveV3(
                BitArray.fromBigInteger(pt, Herradura.N), BitArray.fromBigInteger(key, Herradura.N), r3);
        if (!HerraduraNl.nlChiV3(BitArray.fromBigInteger(pt, Herradura.N)).toBigInteger().equals(hex(p, "chi_of_plaintext"))
                || !HerraduraNl.nlFscxV3(BitArray.fromBigInteger(pt, Herradura.N), BitArray.fromBigInteger(key, Herradura.N)).toBigInteger().equals(hex(p, "one_round"))
                || !revolve.toBigInteger().equals(hex(p, "revolve"))
                || !HerraduraNl.nlFscxRevolveV3Inv(revolve, BitArray.fromBigInteger(key, Herradura.N), r3)
                        .equals(BitArray.fromBigInteger(pt, Herradura.N))) {
            System.out.println("FAIL nl_fscx_v3: chi="
                    + HerraduraNl.nlChiV3(BitArray.fromBigInteger(pt, Herradura.N)).toBigInteger().equals(hex(p, "chi_of_plaintext"))
                    + " round=" + HerraduraNl.nlFscxV3(BitArray.fromBigInteger(pt, Herradura.N), BitArray.fromBigInteger(key, Herradura.N)).toBigInteger().equals(hex(p, "one_round"))
                    + " revolve=" + revolve.toBigInteger().equals(hex(p, "revolve"))
                    + " revolve_inv="
                    + HerraduraNl.nlFscxRevolveV3Inv(revolve, BitArray.fromBigInteger(key, Herradura.N), r3)
                        .equals(BitArray.fromBigInteger(pt, Herradura.N)));
            fails++;
        } else {
            System.out.println("PASS nl_fscx_v3");
        }

        Map<String, String> a = v3.get("hske_nla3");
        BigInteger got = HerraduraNl.hskeNlA3Encrypt(
                BitArray.fromBigInteger(hex(a, "plaintext"), Herradura.N),
                BitArray.fromBigInteger(hex(a, "key"), Herradura.N)).toBigInteger();
        if (!got.equals(hex(a, "ciphertext"))) {
            System.out.println("FAIL hske_nla3: got " + got.toString(16)
                    + " want " + a.get("ciphertext"));
            fails++;
        } else {
            System.out.println("PASS hske_nla3");
        }

        Map<String, String> e = v3.get("hpke_nl3");
        Herradura.Ciphertext ct = HerraduraNl.hpkeNl3Encrypt(
                BitArray.fromBigInteger(hex(e, "plaintext"), Herradura.N),
                BitArray.fromBigInteger(hex(e, "pub"), Herradura.N),
                BitArray.fromBigInteger(hex(e, "ephemeral_r"), Herradura.N));
        BitArray dec = ct == null ? null
                : HerraduraNl.hpkeNl3Decrypt(ct.ct, ct.r,
                        BitArray.fromBigInteger(hex(e, "priv"), Herradura.N));
        if (ct == null || !ct.r.toBigInteger().equals(hex(e, "R")) || !ct.ct.toBigInteger().equals(hex(e, "ciphertext"))
                || dec == null || !dec.toBigInteger().equals(hex(e, "plaintext"))) {
            System.out.println("FAIL hpke_nl3: R="
                    + (ct != null && ct.r.toBigInteger().equals(hex(e, "R")))
                    + " ct=" + (ct != null && ct.ct.toBigInteger().equals(hex(e, "ciphertext")))
                    + " decrypt_roundtrip=" + (dec != null && dec.toBigInteger().equals(hex(e, "plaintext"))));
            fails++;
        } else {
            System.out.println("PASS hpke_nl3");
        }
        return fails;
    }

    public static void main(String[] args) throws IOException {
        Path path = args.length > 0 ? Paths.get(args[0])
                : Paths.get("KAT", "classical_quartet.json");
        String text = new String(Files.readAllBytes(path));

        Map<String, Map<String, String>> objects = new HashMap<>();
        Matcher m = OBJECT.matcher(text);
        while (m.find()) {
            objects.put(m.group(1), parseObject(m.group(2)));
        }

        int fails = 0;

        // HKEX-GF
        {
            Map<String, String> v = objects.get("hkex_gf");
            BigInteger a = hex(v, "alice_priv"), b = hex(v, "bob_priv");
            BitArray aBa = BitArray.fromBigInteger(a, Herradura.N);
            BitArray bBa = BitArray.fromBigInteger(b, Herradura.N);
            BitArray C = Herradura.hkexGfPubkey(aBa), C2 = Herradura.hkexGfPubkey(bBa);
            BitArray sk = Herradura.hkexGfAgree(aBa, C2);
            BitArray skOther = Herradura.hkexGfAgree(bBa, C);
            BigInteger want = hex(v, "shared_secret");
            if (!sk.toBigInteger().equals(want) || !sk.equals(skOther)) {
                System.out.println("FAIL hkex_gf: got " + sk.toHex() + " want " + want.toString(16));
                fails++;
            } else {
                System.out.println("PASS hkex_gf");
            }
        }

        // HSKE
        {
            Map<String, String> v = objects.get("hske");
            BigInteger key = hex(v, "key"), pt = hex(v, "plaintext");
            BitArray ct = Herradura.hskeEncrypt(BitArray.fromBigInteger(pt, Herradura.N), BitArray.fromBigInteger(key, Herradura.N));
            BigInteger want = hex(v, "ciphertext");
            BitArray roundTrip = Herradura.hskeDecrypt(ct, BitArray.fromBigInteger(key, Herradura.N));
            if (!ct.toBigInteger().equals(want) || !roundTrip.toBigInteger().equals(pt)) {
                System.out.println("FAIL hske: got " + ct.toHex() + " want " + want.toString(16));
                fails++;
            } else {
                System.out.println("PASS hske");
            }
        }

        // HPKS
        {
            Map<String, String> v = objects.get("hpks");
            BigInteger pub = hex(v, "pub"), r = hex(v, "R"), s = hex(v, "s"), msg = hex(v, "message");
            boolean ok = Herradura.hpksVerify(BitArray.fromBigInteger(msg, Herradura.N), BitArray.fromBigInteger(pub, Herradura.N), BitArray.fromBigInteger(r, Herradura.N), BitArray.fromBigInteger(s, Herradura.N));
            if (!ok) {
                System.out.println("FAIL hpks: verify returned false");
                fails++;
            } else {
                System.out.println("PASS hpks");
            }
        }

        // HPKE
        {
            Map<String, String> v = objects.get("hpke");
            BigInteger priv = hex(v, "recipient_priv"), ephR = hex(v, "ephemeral_r");
            BigInteger pub = hex(v, "recipient_pub"), pt = hex(v, "plaintext");
            Herradura.Ciphertext enc = Herradura.hpkeEncrypt(BitArray.fromBigInteger(pt, Herradura.N), BitArray.fromBigInteger(pub, Herradura.N), BitArray.fromBigInteger(ephR, Herradura.N));
            BigInteger wantR = hex(v, "R"), wantCt = hex(v, "ciphertext");
            BitArray dec = Herradura.hpkeDecrypt(enc.ct, enc.r, BitArray.fromBigInteger(priv, Herradura.N));
            if (!enc.r.toBigInteger().equals(wantR) || !enc.ct.toBigInteger().equals(wantCt) || !dec.toBigInteger().equals(pt)) {
                System.out.println("FAIL hpke: R(got=" + enc.r.toHex() + " want=" + wantR.toString(16)
                        + ") ct(got=" + enc.ct.toHex() + " want=" + wantCt.toString(16)
                        + ") decrypt_roundtrip=" + dec.toBigInteger().equals(pt));
                fails++;
            } else {
                System.out.println("PASS hpke");
            }
        }

        // ── HKEX-RNL (TODO #226) ────────────────────────────────────────
        Path rnlPath = path.resolveSibling("hkex_rnl.json");
        if (!Files.exists(rnlPath)) {
            System.out.println("FAIL hkex_rnl: " + rnlPath + " not found");
            fails++;
        } else {
            String rnlText = new String(Files.readAllBytes(rnlPath));
            Matcher rm = RNL_OBJECT.matcher(rnlText);
            int seen = 0;
            while (rm.find()) {
                seen++;
                if (!verifyRnl("hkex_rnl " + rm.group(1), parseObject(rm.group(2)))) {
                    fails++;
                }
            }
            if (seen != 2) {
                System.out.println("FAIL hkex_rnl: expected 2 vector sets, parsed " + seen);
                fails++;
            }
        }

        // ── NL-FSCX v3 (TODO #255) ──────────────────────────────────────
        Path v3Path = path.resolveSibling("nl_fscx_v3.json");
        if (!Files.exists(v3Path)) {
            System.out.println("FAIL nl_fscx_v3: " + v3Path + " not found");
            fails++;
        } else {
            Map<String, Map<String, String>> v3 = new HashMap<>();
            Matcher vm = V3_OBJECT.matcher(new String(Files.readAllBytes(v3Path)));
            while (vm.find()) {
                v3.put(vm.group(1), parseObject(vm.group(2)));
            }
            if (v3.size() != 3) {
                System.out.println("FAIL nl_fscx_v3: expected 3 Java-portable vector "
                        + "sets, parsed " + v3.size());
                fails++;
            } else {
                fails += verifyV3(v3);
            }
        }

        // ── HCRED-KKW (TODO #266) ───────────────────────────────────────
        Path kkwPath = path.resolveSibling("hcred_kkw.json");
        if (!Files.exists(kkwPath)) {
            System.out.println("FAIL hcred_kkw: " + kkwPath + " not found");
            fails++;
        } else {
            fails += verifyKkw(new String(Files.readAllBytes(kkwPath)));
        }

        // ── sampler replay (TODO #296) ──────────────────────────────────
        Path replayPath = path.resolveSibling("sampler_replay.json");
        if (!Files.exists(replayPath)) {
            System.out.println("FAIL sampler_replay: " + replayPath + " not found");
            fails++;
        } else {
            fails += verifySamplerReplay(new String(Files.readAllBytes(replayPath)));
        }

        // ── operation replay (TODO #297) ────────────────────────────────
        Path opPath = path.resolveSibling("operation_replay.json");
        if (!Files.exists(opPath)) {
            System.out.println("FAIL operation_replay: " + opPath + " not found");
            fails++;
        } else {
            fails += verifyOperationReplay(new String(Files.readAllBytes(opPath)));
        }

        if (fails > 0) {
            System.out.println(fails + " vector set(s) FAILED");
            System.exit(1);
        }
        System.out.println("All KAT vectors verified against the Java herradurakex package.");
    }

    // ── TODO #296: fixed-stream sampler replay ──────────────────────────
    //
    // Replays the suite's leaf CSPRNG samplers against the vector's fixed
    // stream.  Java needs no hook and no global for this: every sampler here
    // already takes its SecureRandom as a parameter, so a subclass serving
    // pinned bytes drives the SHIPPED function directly.  Go, by contrast, has
    // to swap a package variable.
    //
    // Why this vector can exist at all: a sampler's output reaches no artifact,
    // so no ordinary KAT can pin it and none could (TODO #294).  Replacing the
    // entropy source makes a randomised primitive deterministic, and then the
    // four consumption orders can be held against each other -- which is the
    // only check this class of randomness admits.

    /** A SecureRandom that serves pinned bytes and counts what it served. */
    private static final class FixedRandom extends SecureRandom {
        private static final long serialVersionUID = 1L;
        private final byte[] data;
        private int pos;

        FixedRandom(byte[] data) { this.data = data; }

        @Override
        public void nextBytes(byte[] b) {
            if (pos + b.length > data.length) {
                throw new IllegalStateException(
                    "sampler replay: stream exhausted (" + b.length + " asked, "
                    + (data.length - pos) + " left)");
            }
            System.arraycopy(data, pos, b, 0, b.length);
            pos += b.length;
        }

        int consumed() { return pos; }
    }

    private static int replayCheck(String name, String got, String want) {
        if (!got.equals(want)) {
            System.out.println("FAIL " + name + ": got " + got + " want " + want);
            return 1;
        }
        System.out.println("PASS " + name);
        return 0;
    }

    @SuppressWarnings("unchecked")
    private static int verifySamplerReplay(String text) {
        int fails = 0;
        Map<String, Object> root = (Map<String, Object>) Json.parse(text);
        List<Object> rows = (List<Object>) root.get("samplers");
        if (rows == null || rows.isEmpty()) {
            System.out.println("FAIL sampler_replay: no samplers in the vector");
            return 1;
        }

        for (Object ro : rows) {
            Map<String, Object> r = (Map<String, Object>) ro;
            String name = (String) r.get("name");
            Map<String, Object> params = (Map<String, Object>) r.get("params");
            FixedRandom rng = new FixedRandom(unhexBytes((String) r.get("stream")));

            if ("rnl_cbd_poly".equals(name)) {
                int n = ((Number) params.get("n")).intValue();
                int q = ((Number) params.get("q")).intValue();
                fails += replayCheck("replay " + name,
                        polyHex(HerraduraNl.rnlCbdPoly(n, q, rng), 3),
                        (String) r.get("expect_poly"));
            } else if ("rnl_rand_poly".equals(name)) {
                int n = ((Number) params.get("n")).intValue();
                int q = ((Number) params.get("q")).intValue();
                fails += replayCheck("replay " + name,
                        polyHex(HerraduraNl.rnlRandPoly(n, q, rng), 3),
                        (String) r.get("expect_poly"));
            } else if ("stern_weight_t".equals(name)) {
                int n = ((Number) params.get("n")).intValue();
                int t = ((Number) params.get("t")).intValue();
                BigInteger e = Stern.csprngWeightT(t, rng);
                fails += replayCheck("replay " + name,
                        String.format("%0" + (n / 4) + "x", e),
                        (String) r.get("expect_value"));
                int wt = ((Number) r.get("expect_weight")).intValue();
                if (e.bitCount() != wt) {
                    System.out.println("FAIL replay " + name + ": weight "
                            + e.bitCount() + ", vector says " + wt);
                    fails++;
                }
            } else if ("oprf_blind_scalar".equals(name)) {
                int bits = ((Number) params.get("bits")).intValue();
                Oprf.Blinded bl = Oprf.blind(unhexBytes((String) params.get("input_hex")), rng);
                fails += replayCheck("replay " + name + " r",
                        String.format("%0" + (bits / 4) + "x", bl.r),
                        (String) r.get("expect_r"));
                fails += replayCheck("replay " + name + " alpha",
                        String.format("%0" + (bits / 4) + "x", bl.alpha),
                        (String) r.get("expect_alpha"));
            } else {
                System.out.println("FAIL sampler_replay: unknown sampler \"" + name
                        + "\" -- a row was added to the vector and no Java "
                        + "consumer follows it");
                fails++;
                continue;
            }

            // A null `consumed` means the four ports read at different
            // granularities and only the output is common; the row carries the
            // reason.  Anything else is asserted, and that half is what catches
            // a port reading ahead of or behind the others.
            Object consumed = r.get("consumed");
            if (consumed != null) {
                int want = ((Number) consumed).intValue();
                if (rng.consumed() != want) {
                    System.out.println("FAIL replay " + name + ": consumed "
                            + rng.consumed() + " stream bytes, vector says " + want);
                    fails++;
                } else {
                    System.out.println("PASS replay " + name + " consumed " + want + " bytes");
                }
            }
        }
        return fails;
    }

    // ── HCRED-KKW (TODO #266) ───────────────────────────────────────────────
    //
    // This is the one vector set here that is CONSUMED rather than recomputed.
    // hcredProveKkw is randomised (one root seed per emulation), so there is no
    // deterministic transcript for Java to reproduce; what it can do -- and what
    // the item is about -- is READ Python's transcript and accept it, then
    // reject each tampered variant.  Every KKW bug that has actually shipped was
    // a reader disagreement about a byte layout, which is exactly this.
    //
    // Only the n256 set is consumable: Hcred.N is a compile-time constant of
    // 256, as herradura.h's HCRED_N is, while Python and Go take the width as a
    // runtime argument and demo at 32.  That asymmetry is a TODO #266 finding
    // in its own right -- the four implementations have never proved the same
    // statement size.
    //
    // The flat regex parser above cannot read this file: it is nested (the
    // online proofs carry an array of path arrays), so this section uses the
    // minimal recursive-descent reader in Json.java rather than a dependency.
    // It lived here as a private nested class until TODO #314 pass 5 gave
    // KAT/bitarray.json a second Java consumer that needed the same reader.

    /** Minimal recursive-descent JSON reader: enough for this file's shapes. */

    @SuppressWarnings("unchecked")
    private static Map<String, Object> obj(Object o) { return (Map<String, Object>) o; }

    @SuppressWarnings("unchecked")
    private static java.util.List<Object> arr(Object o) { return (java.util.List<Object>) o; }

    private static int jint(Object o) { return (int) (long) (Long) o; }

    private static byte[] unhexBytes(String s) {
        byte[] out = new byte[s.length() / 2];
        for (int i = 0; i < out.length; i++)
            out[i] = (byte) Integer.parseInt(s.substring(2 * i, 2 * i + 2), 16);
        return out;
    }

    /** Decode the 3-bytes-per-coefficient encoding used for every Z_q vector. */
    private static int[] unpackVec(String hexs) {
        byte[] b = unhexBytes(hexs);
        int[] out = new int[b.length / 3];
        for (int i = 0; i < out.length; i++)
            out[i] = ((b[3 * i] & 0xff) << 16) | ((b[3 * i + 1] & 0xff) << 8) | (b[3 * i + 2] & 0xff);
        return out;
    }

    /**
     * Rebuild the proof, optionally with one tamper case applied.  A tamper has
     * to be applied HERE rather than to a finished object because this port's
     * proof fields are final -- which is the Java-idiomatic shape and also why
     * TODO #261's Java rejection checks could not poke W, pbar or u in place.
     *
     * Mirrors _kkw_apply_tamper in KAT/generate_kat.py, applyKkwTamper in
     * KAT/verify_kat.go and apply_tamper in KAT/verify_kat_c.c.  All four must
     * agree case for case: a mutation one applies and another does not silently
     * downgrades a rejection test into a second accept test.
     */
    private static Hcred.HcredKkwProof buildKkwProof(Map<String, Object> set, String tamper) {
        return buildKkwProofFrom(obj(set.get("proof")), tamper);
    }

    /** Rebuild a KKW proof from its on-disk object.  ONE reader for both
     *  vectors: hcred_kkw.json pins a transcript to CONSUME and
     *  operation_replay.json pins one this port must PRODUCE (TODO #303), and a
     *  second reader for the second vector would be a second opinion about the
     *  very byte layout every KKW bug so far has been a disagreement over. */
    private static Hcred.HcredKkwProof buildKkwProofFrom(Map<String, Object> pr, String tamper) {
        java.util.List<Object> params = arr(pr.get("params"));
        int nPar = jint(params.get(0)), m = jint(params.get(1)), tau = jint(params.get(2));
        int W = jint(pr.get("W"));
        if ("W".equals(tamper)) W += 1;

        Map<Integer, byte[]> pre = new java.util.TreeMap<>();
        for (Map.Entry<String, Object> e : obj(pr.get("pre")).entrySet())
            pre.put(Integer.valueOf(e.getKey()), unhexBytes((String) e.getValue()));
        if ("pre[0][0]".equals(tamper)) {
            Integer r0 = ((java.util.TreeMap<Integer, byte[]>) pre).firstKey();
            pre.get(r0)[0] ^= 1;
        }

        Map<Integer, Hcred.KkwOnlineProof> online = new java.util.TreeMap<>();
        java.util.TreeMap<String, Object> ons = new java.util.TreeMap<>(
                java.util.Comparator.comparingInt(Integer::parseInt));
        ons.putAll(obj(pr.get("online")));
        boolean first = true;
        for (Map.Entry<String, Object> e : ons.entrySet()) {
            Map<String, Object> od = obj(e.getValue());
            java.util.List<Hcred.KkwPathEntry> path = new java.util.ArrayList<>();
            for (Object pe : arr(od.get("path"))) {
                java.util.List<Object> t3 = arr(pe);
                path.add(new Hcred.KkwPathEntry(jint(t3.get(0)), jint(t3.get(1)),
                        unhexBytes((String) t3.get(2))));
            }
            int pbar = jint(od.get("pbar"));
            int u = jint(od.get("u"));
            int[] t = unpackVec((String) od.get("t"));
            Object auxo = od.get("aux");
            int[] aux = auxo == null ? null : unpackVec((String) auxo);
            if (first) {
                if ("online[0].pbar".equals(tamper)) pbar = (pbar + 1) % nPar;
                if ("online[0].u".equals(tamper))    u = (u + 1) % HerraduraNl.RNLQ;
                if ("online[0].t[0]".equals(tamper)) t[0] = (t[0] + 1) % HerraduraNl.RNLQ;
                first = false;
            }
            online.put(Integer.valueOf(e.getKey()), new Hcred.KkwOnlineProof(
                    path, unhexBytes((String) od.get("com_h")),
                    pbar, aux, unpackVec((String) od.get("zin")), t, u));
        }
        return new Hcred.HcredKkwProof(W, nPar, m, tau, pre, online);
    }

    private static int verifyKkw(String text) {
        Map<String, Object> root = obj(Json.parse(text));
        Map<String, Object> sets = obj(root.get("sets"));
        Map<String, Object> set = obj(sets.get("n256"));
        if (set == null) {
            System.out.println("FAIL hcred_kkw: set \"n256\" missing — Java is "
                    + "compiled for n=256 only and cannot consume the n32 set");
            return 1;
        }
        Map<String, Object> st = obj(set.get("statement"));
        int[] mPoly = unpackVec((String) st.get("m_poly"));
        int[] cPoly = unpackVec((String) st.get("C_poly"));
        BigInteger seedH = new BigInteger((String) st.get("seed_H"), 16);
        BigInteger y = new BigInteger((String) st.get("y"), 16);
        byte[] msg = unhexBytes((String) st.get("msg"));

        int fails = 0;
        if (Hcred.verifyKkw(mPoly, cPoly, seedH, y, buildKkwProof(set, null), msg)) {
            System.out.println("PASS hcred_kkw[n256] (Java accepts the pinned Python transcript)");
        } else {
            System.out.println("FAIL hcred_kkw[n256]: Java REJECTS the pinned Python "
                    + "transcript — the implementations disagree on the wire format");
            fails++;
        }
        // The accept is not self-validating: a verifier returning true
        // unconditionally would pass it.  Each tamper case must be rejected.
        java.util.List<Object> tamper = arr(set.get("tamper"));
        for (Object tco : tamper) {
            Map<String, Object> tc = obj(tco);
            String apply = (String) tc.get("apply");
            byte[] tmsg = msg;
            if ("msg".equals(apply)) {
                tmsg = java.util.Arrays.copyOf(msg, msg.length + 1);
                tmsg[msg.length] = '!';
            }
            if (Hcred.verifyKkw(mPoly, cPoly, seedH, y, buildKkwProof(set, apply), tmsg)) {
                System.out.println("FAIL hcred_kkw[n256] tamper \"" + tc.get("name") + "\" ACCEPTED");
                fails++;
            }
        }
        if (fails == 0)
            System.out.println("PASS hcred_kkw[n256] tamper (" + tamper.size() + "/"
                    + tamper.size() + " rejected)");
        return fails;
    }

    // ── TODO #297: fixed-stream OPERATION replay ────────────────────────
    //
    // One level above verifySamplerReplay.  A leaf row is one call with scalar
    // arguments; these rows supply a fixed STATEMENT as well as a fixed stream
    // and pin what a whole randomised operation produces, so the ORDER in which
    // it visits its samplers -- and any inline draw loop that is not a callable
    // sampler at all -- is held against the other three ports.  TODO #294's own
    // defect was of the second kind: rnlSigmaSign's mask draw is written out
    // inside the signing loop.
    //
    // Java needs nothing new here either: every operation below already takes
    // its SecureRandom as a parameter, so FixedRandom above drives the SHIPPED
    // code with no hook and no global.

    /** Report WHICH field of WHICH emulation diverged, rather than one
     *  serialize-and-diff: saying where two ports disagree is the whole point
     *  of the row, and every KKW bug found so far has been in one named field
     *  (an inverted aux-reveal condition, a mis-sized commitment buffer, a
     *  flipped bit convention). */
    private static int compareKkwProof(String name, Hcred.HcredKkwProof got,
                                       Hcred.HcredKkwProof want) {
        int[] fails = {0};
        java.util.function.BiConsumer<String, String> bad = (what, detail) -> {
            System.out.println("FAIL op " + name + ": " + what + " " + detail);
            fails[0]++;
        };
        if (got.W != want.W) bad.accept("W", "is " + got.W + ", vector says " + want.W);
        if (got.nPar != want.nPar || got.m != want.m || got.tau != want.tau)
            bad.accept("params", "are (" + got.nPar + "," + got.m + "," + got.tau
                    + "), vector says (" + want.nPar + "," + want.m + "," + want.tau + ")");
        // The unopened set is the cut-and-choose challenge, derived by
        // Fiat-Shamir from every emulation's commitments -- so a divergence in
        // ANY of the M preprocessing emulations, opened or not, moves it.
        if (!got.pre.keySet().equals(want.pre.keySet())) {
            bad.accept("unopened emulations", "are " + got.pre.keySet()
                    + ", vector says " + want.pre.keySet());
        } else {
            for (Map.Entry<Integer, byte[]> e : want.pre.entrySet())
                if (!java.util.Arrays.equals(got.pre.get(e.getKey()), e.getValue()))
                    bad.accept("pre[" + e.getKey() + "] root", "differs from the vector");
        }
        if (!got.online.keySet().equals(want.online.keySet())) {
            bad.accept("opened emulations", "are " + got.online.keySet()
                    + ", vector says " + want.online.keySet());
            return fails[0];
        }
        for (Map.Entry<Integer, Hcred.KkwOnlineProof> e : want.online.entrySet()) {
            Hcred.KkwOnlineProof w = e.getValue(), g = got.online.get(e.getKey());
            String pfx = "online[" + e.getKey() + "].";
            if (g.pbar != w.pbar)
                bad.accept(pfx + "pbar", "is " + g.pbar + ", vector says " + w.pbar);
            if (!java.util.Arrays.equals(g.comH, w.comH))
                bad.accept(pfx + "com_h", "differs from the vector");
            if (g.path.size() != w.path.size()) {
                bad.accept(pfx + "path length", "is " + g.path.size()
                        + ", vector says " + w.path.size());
            } else {
                for (int i = 0; i < w.path.size(); i++) {
                    Hcred.KkwPathEntry pg = g.path.get(i), pw = w.path.get(i);
                    if (pg.l != pw.l || pg.i != pw.i
                            || !java.util.Arrays.equals(pg.node, pw.node)) {
                        bad.accept(pfx + "path[" + i + "]", "differs from the vector");
                        break;
                    }
                }
            }
            // aux is revealed exactly when the hidden party is not party
            // nPar-1.  Reading that condition the wrong way round is the bug
            // the Go port actually shipped (TODO #266), so nullness is compared
            // before content.
            if ((g.aux == null) != (w.aux == null))
                bad.accept(pfx + "aux revealed", "is " + (g.aux != null)
                        + ", vector says " + (w.aux != null));
            else if (g.aux != null && !java.util.Arrays.equals(g.aux, w.aux))
                bad.accept(pfx + "aux", "differs from the vector");
            if (!java.util.Arrays.equals(g.zin, w.zin))
                bad.accept(pfx + "zin", "differs from the vector");
            if (!java.util.Arrays.equals(g.t, w.t))
                bad.accept(pfx + "t", "differs from the vector");
            if (g.u != w.u)
                bad.accept(pfx + "u", "is " + g.u + ", vector says " + w.u);
        }
        if (fails[0] == 0)
            System.out.println("PASS op " + name + " (" + want.online.size()
                    + " emulations opened, " + want.pre.size() + " unopened)");
        return fails[0];
    }

    /** Centered coefficients as 4-byte big-endian two's complement -- the
     *  encoding the vector uses because it is what C's int32_t already holds. */
    /** unpackVec's inverse: the protocol's own 3-bytes-per-coefficient
     *  encoding (Hcred.ser), which is how every Z_q vector travels here. */
    private static String packVec(int[] v) {
        StringBuilder sb = new StringBuilder();
        for (int c : v) sb.append(String.format("%06x", c & 0xFFFFFF));
        return sb.toString();
    }

    /** A support (or any int list) rendered for comparison against the
     *  vector's JSON array, SORTED -- a support is a set in Python and an
     *  array here, so the order is the port's and not the protocol's. */
    private static String intListStr(int[] v) {
        int[] c = v.clone();
        java.util.Arrays.sort(c);
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < c.length; i++) {
            if (i > 0) sb.append(',');
            sb.append(c[i]);
        }
        return sb.toString();
    }

    @SuppressWarnings("unchecked")
    private static String jsonIntListStr(Object o) {
        List<Object> l = (List<Object>) o;
        int[] v = new int[l.size()];
        for (int i = 0; i < v.length; i++) v[i] = ((Number) l.get(i)).intValue();
        return intListStr(v);
    }

    private static String i32Hex(int[] vals) {
        StringBuilder sb = new StringBuilder();
        for (int v : vals) sb.append(String.format("%08x", v));
        return sb.toString();
    }

    private static String hexOf(byte[] b) {
        StringBuilder sb = new StringBuilder();
        for (byte x : b) sb.append(String.format("%02x", x & 0xFF));
        return sb.toString();
    }

    @SuppressWarnings("unchecked")
    private static int verifyOperationReplay(String text) {
        int fails = 0;
        Map<String, Object> root = (Map<String, Object>) Json.parse(text);
        List<Object> rows = (List<Object>) root.get("operations");
        if (rows == null || rows.isEmpty()) {
            System.out.println("FAIL operation_replay: no operations in the vector");
            return 1;
        }

        for (Object ro : rows) {
            Map<String, Object> r = (Map<String, Object>) ro;
            String name = (String) r.get("name");
            Map<String, Object> params = (Map<String, Object>) r.get("params");
            Map<String, Object> stmt = (Map<String, Object>) r.get("statement");
            Map<String, Object> expect = (Map<String, Object>) r.get("expect");
            FixedRandom rng = new FixedRandom(unhexBytes((String) r.get("stream")));

            if ("stern_f_keygen".equals(name)) {
                int n = ((Number) params.get("n")).intValue();
                int nRows = ((Number) params.get("n_rows")).intValue();
                Stern.SternKeypair kp = Stern.sternFKeygen(rng);
                fails += replayCheck("op " + name + " seed",
                        String.format("%0" + (n / 4) + "x", kp.seed),
                        (String) expect.get("seed"));
                fails += replayCheck("op " + name + " e",
                        String.format("%0" + (n / 4) + "x", kp.e),
                        (String) expect.get("e"));
                fails += replayCheck("op " + name + " syndrome",
                        String.format("%0" + (nRows / 4) + "x", kp.syndrome),
                        (String) expect.get("syndrome"));

            } else if ("hpks_stern_f_sign".equals(name)) {
                int n = ((Number) params.get("n")).intValue();
                int rounds = ((Number) params.get("rounds")).intValue();
                BigInteger msg = new BigInteger((String) stmt.get("msg"), 16);
                BigInteger e = new BigInteger((String) stmt.get("e"), 16);
                BigInteger seed = new BigInteger((String) stmt.get("seed"), 16);
                Stern.SternSignature sig = Stern.hpksSternFSign(msg, e, seed, rounds, rng);
                List<Object> coms = (List<Object>) expect.get("commits");
                List<Object> chs = (List<Object>) expect.get("challenges");
                List<Object> resps = (List<Object>) expect.get("responses");
                String w = "%0" + (n / 4) + "x";
                int bad = -1;
                for (int i = 0; i < rounds; i++) {
                    List<Object> c = (List<Object>) coms.get(i);
                    if (!String.format(w, sig.c0[i]).equals(c.get(0))
                            || !String.format(w, sig.c1[i]).equals(c.get(1))
                            || !String.format(w, sig.c2[i]).equals(c.get(2))) { bad = i; break; }
                }
                if (bad >= 0) {
                    System.out.println("FAIL op " + name + ": commitments differ at round " + bad);
                    fails++;
                } else {
                    System.out.println("PASS op " + name + " commitments");
                }
                bad = -1;
                for (int i = 0; i < rounds; i++) {
                    if (sig.challenges[i] != ((Number) chs.get(i)).intValue()) { bad = i; break; }
                }
                if (bad >= 0) {
                    System.out.println("FAIL op " + name + ": challenge " + bad + " is "
                            + sig.challenges[bad] + ", vector says " + chs.get(bad));
                    fails++;
                } else {
                    System.out.println("PASS op " + name + " challenges");
                }
                // All three challenge values occur in this vector's stream, so
                // this one comparison covers all three response branches.
                bad = -1;
                for (int i = 0; i < rounds; i++) {
                    List<Object> p = (List<Object>) resps.get(i);
                    if (!String.format(w, sig.resp0[i]).equals(p.get(0))
                            || !String.format(w, sig.resp1[i]).equals(p.get(1))) { bad = i; break; }
                }
                if (bad >= 0) {
                    System.out.println("FAIL op " + name + ": response differs at round "
                            + bad + " (b=" + sig.challenges[bad] + ")");
                    fails++;
                } else {
                    System.out.println("PASS op " + name + " responses");
                }

            } else if ("zkp_nl_prove".equals(name)) {
                int n = ((Number) params.get("n")).intValue();
                int rounds = ((Number) params.get("rounds")).intValue();
                List<ZkpNl.ProofRound> proof = ZkpNl.prove(
                        new BigInteger((String) stmt.get("a"), 16),
                        new BigInteger((String) stmt.get("b"), 16),
                        new BigInteger((String) stmt.get("y"), 16),
                        n, rounds, unhexBytes((String) stmt.get("msg_hex")), rng);
                List<Object> want = (List<Object>) expect.get("rounds");
                int bad = -1;
                for (int i = 0; i < rounds; i++) {
                    Map<String, Object> wv = (Map<String, Object>) want.get(i);
                    ZkpNl.ProofRound pr = proof.get(i);
                    if (!hexOf(pr.com0).equals(wv.get("com_0"))
                            || !hexOf(pr.com1).equals(wv.get("com_1"))
                            || !hexOf(pr.com2).equals(wv.get("com_2"))) { bad = i; break; }
                }
                if (bad >= 0) {
                    System.out.println("FAIL op " + name + ": commitments differ at round " + bad);
                    fails++;
                } else {
                    System.out.println("PASS op " + name + " commitments");
                }
                bad = -1;
                for (int i = 0; i < rounds; i++) {
                    Map<String, Object> wv = (Map<String, Object>) want.get(i);
                    ZkpNl.ProofRound pr = proof.get(i);
                    if (pr.e != ((Number) wv.get("e")).intValue()
                            || !hexOf(pr.viewP1).equals(wv.get("view_p1"))
                            || !hexOf(pr.viewP2).equals(wv.get("view_p2"))) { bad = i; break; }
                }
                if (bad >= 0) {
                    System.out.println("FAIL op " + name + ": views differ at round " + bad
                            + " (e=" + proof.get(bad).e + ")");
                    fails++;
                } else {
                    System.out.println("PASS op " + name + " views");
                }

            } else if ("hpks_stern_ring_sign".equals(name)) {
                // Two divergences lived in this operation and neither was
                // visible to any other check: the challenge trit had three
                // schemes across the four ports, and the b = 0 dummy
                // commitment was a CONSTANT in C and Go, which identified the
                // real signer from the public signature.  See ringTrit and
                // simulateRound in SternRing.java.
                int n = ((Number) params.get("n")).intValue();
                int k = ((Number) params.get("k")).intValue();
                int rounds = ((Number) params.get("rounds")).intValue();
                int j = ((Number) params.get("j")).intValue();
                List<Object> seeds = (List<Object>) stmt.get("seeds");
                List<Object> syns = (List<Object>) stmt.get("syndromes");
                List<SternRing.RingKey> ring = new ArrayList<SternRing.RingKey>();
                for (int i = 0; i < k; i++) {
                    ring.add(new SternRing.RingKey(
                            new BigInteger((String) seeds.get(i), 16),
                            new BigInteger((String) syns.get(i), 16)));
                }
                BigInteger msg = new BigInteger((String) stmt.get("msg"), 16);
                BigInteger e = new BigInteger((String) stmt.get("e"), 16);
                SternRing.RingSignature sig = SternRing.sign(msg, e, j, ring, rounds, rng);
                List<Object> coms = (List<Object>) expect.get("commits");
                List<Object> chs = (List<Object>) expect.get("challenges");
                List<Object> resps = (List<Object>) expect.get("responses");
                String w = "%0" + (n / 4) + "x";
                int bi = -1, br = -1;
                for (int i = 0; i < k && bi < 0; i++) {
                    List<Object> mc = (List<Object>) coms.get(i);
                    for (int rr2 = 0; rr2 < rounds; rr2++) {
                        List<Object> c = (List<Object>) mc.get(rr2);
                        if (!String.format(w, sig.c0[i][rr2]).equals(c.get(0))
                                || !String.format(w, sig.c1[i][rr2]).equals(c.get(1))
                                || !String.format(w, sig.c2[i][rr2]).equals(c.get(2))) {
                            bi = i; br = rr2; break;
                        }
                    }
                }
                if (bi >= 0) {
                    System.out.println("FAIL op " + name + ": commitments differ at member "
                            + bi + " round " + br);
                    fails++;
                } else {
                    System.out.println("PASS op " + name + " commitments");
                }
                bi = -1; br = -1;
                for (int i = 0; i < k && bi < 0; i++) {
                    List<Object> mb = (List<Object>) chs.get(i);
                    for (int rr2 = 0; rr2 < rounds; rr2++) {
                        if (sig.challenges[i][rr2] != ((Number) mb.get(rr2)).intValue()) {
                            bi = i; br = rr2; break;
                        }
                    }
                }
                if (bi >= 0) {
                    System.out.println("FAIL op " + name + ": challenge at member " + bi
                            + " round " + br + " is " + sig.challenges[bi][br]);
                    fails++;
                } else {
                    System.out.println("PASS op " + name + " challenges");
                }
                bi = -1; br = -1;
                for (int i = 0; i < k && bi < 0; i++) {
                    List<Object> mr = (List<Object>) resps.get(i);
                    for (int rr2 = 0; rr2 < rounds; rr2++) {
                        List<Object> p = (List<Object>) mr.get(rr2);
                        if (!String.format(w, sig.resp0[i][rr2]).equals(p.get(0))
                                || !String.format(w, sig.resp1[i][rr2]).equals(p.get(1))) {
                            bi = i; br = rr2; break;
                        }
                    }
                }
                if (bi >= 0) {
                    System.out.println("FAIL op " + name + ": response differs at member "
                            + bi + " round " + br + " (b=" + sig.challenges[bi][br] + ")");
                    fails++;
                } else {
                    System.out.println("PASS op " + name + " responses");
                }
                // Must still VERIFY: the fix changed a dummy commitment no
                // verifier checks, and a vector alone would not say so.
                if (!SternRing.verify(msg, sig, ring)) {
                    System.out.println("FAIL op " + name + " verifies");
                    fails++;
                } else {
                    System.out.println("PASS op " + name + " verifies");
                }

            } else if ("rnl_sigma_sign".equals(name)) {
                int n = ((Number) params.get("n")).intValue();
                HerraduraNl.SigmaProof pf = HerraduraNl.rnlSigmaSign(
                        unpackPoly((String) stmt.get("s_poly"), n, 3),
                        unpackPoly((String) stmt.get("m_poly"), n, 3),
                        unpackPoly((String) stmt.get("c_poly"), n, 3),
                        n, unhexBytes((String) stmt.get("msg_hex")), rng);
                if (pf == null) {
                    // The stream is exactly one buffered block and is chosen to
                    // accept on the FIRST attempt; a retry runs off its end.
                    System.out.println("FAIL op " + name + ": rejection limit reached");
                    fails++;
                    continue;
                }
                fails += replayCheck("op " + name + " w", i32Hex(pf.w), (String) expect.get("w"));
                fails += replayCheck("op " + name + " c", i32Hex(pf.c), (String) expect.get("c"));
                fails += replayCheck("op " + name + " z", i32Hex(pf.z), (String) expect.get("z"));

            } else if ("hcred_prove_kkw".equals(name)) {
                // The row TODO #303 added, and the gap TODO #302 §6 found: KKW's
                // PROVER was pinned nowhere.  hcred_kkw.json is verify-side by
                // construction (one fresh root per emulation, so a proof is not
                // a function of its statement) and KKW has no CLI surface, so
                // the 4x4 matrix does not reach it either -- leaving each port's
                // prover checked only against its OWN verifier, which is the
                // shape that let three of four ports ship a transcription bug
                // at TODO #266.  A fixed stream makes the prover a function
                // again.  `expect` is the same layout hcred_kkw.json's `proof`
                // uses, so buildKkwProofFrom reads it unchanged.
                Hcred.HcredKkwProof got = Hcred.proveKkw(
                        unpackVec((String) stmt.get("s_poly")),
                        unpackVec((String) stmt.get("m_poly")),
                        unpackVec((String) stmt.get("c_poly")),
                        new java.math.BigInteger((String) stmt.get("seed_H"), 16),
                        new java.math.BigInteger((String) stmt.get("y"), 16),
                        ((Number) params.get("N_par")).intValue(),
                        ((Number) params.get("M")).intValue(),
                        ((Number) params.get("tau")).intValue(),
                        unhexBytes((String) stmt.get("msg_hex")), rng);
                fails += compareKkwProof(name, got, buildKkwProofFrom(expect, null));

            } else if ("qcmdpc_keygen".equals(name)) {
                // What is pinned is the LOOP, not the PRF: numbered test [34]
                // pins the seed expansion (TODO #277's 3-vs-1 byte-order
                // split) and KAT/pem/'s kem_priv is verify-side, so neither
                // says anything about the order seed -> sup0 -> sup1 ->
                // screen -> inversion.  This stream REJECTS ONCE on the
                // weak-key screen and then accepts, so the reject branch is
                // pinned too -- a branch about one draw in 550 reaches.
                int qr = ((Number) params.get("r")).intValue();
                Stern.QcMdpcKeypair kp = Stern.qcmdpcKeygen(rng);
                fails += replayCheck("op " + name + " sup0", intListStr(kp.sup0),
                        jsonIntListStr(expect.get("sup0")));
                fails += replayCheck("op " + name + " sup1", intListStr(kp.sup1),
                        jsonIntListStr(expect.get("sup1")));
                fails += replayCheck("op " + name + " h_pub",
                        String.format("%0" + ((qr + 3) / 4) + "x", kp.hPub),
                        (String) expect.get("h_pub"));

            } else if ("qcmdpc_encap".equals(name)) {
                int qr = ((Number) params.get("r")).intValue();
                Stern.QcMdpcEncapResult er = Stern.qcmdpcEncap(
                        new BigInteger((String) stmt.get("h_pub"), 16), rng);
                fails += replayCheck("op " + name + " syndrome",
                        String.format("%0" + ((qr + 3) / 4) + "x", er.syn),
                        (String) expect.get("syndrome"));
                fails += replayCheck("op " + name + " k",
                        String.format("%064x", er.k), (String) expect.get("k"));

            } else if ("zkp_nl_pp_prove".equals(name)) {
                // NARROWS TODO #302 section 6: its "covered twice over" is
                // true of the CIRCUIT, which neither port carries its own
                // copy of, and does not extend to the SEED DRAW ORDER --
                // this function's own consumption order, which no row
                // pinned.  Section 2 of the same file makes the 16-byte seed
                // a security parameter.
                int n = ((Number) params.get("n")).intValue();
                int rounds = ((Number) params.get("rounds")).intValue();
                List<ZkpNl.PpRound> pp = ZkpNl.provePp(
                        new BigInteger((String) stmt.get("a"), 16),
                        new BigInteger((String) stmt.get("b"), 16),
                        new BigInteger((String) stmt.get("y"), 16),
                        n, rounds, unhexBytes((String) stmt.get("msg_hex")), rng);
                List<Object> want = (List<Object>) expect.get("rounds");
                int bad = -1;
                if (pp.size() != want.size()) {
                    System.out.println("FAIL op " + name + ": " + pp.size()
                            + " rounds, vector says " + want.size());
                    fails++;
                } else {
                    for (int j = 0; j < pp.size() && bad < 0; j++) {
                        Map<String, Object> w = (Map<String, Object>) want.get(j);
                        ZkpNl.PpRound g = pp.get(j);
                        // share2 is EMPTY exactly when e == 2, party 2's share
                        // being DERIVED rather than seeded (TODO #302 s2), so
                        // the empty case is a field value and not a gap.
                        if (g.e != ((Number) w.get("e")).intValue()
                                || !hexOf(g.comE).equals(w.get("com_e"))
                                || !hexOf(g.outE).equals(w.get("out_e"))
                                || !hexOf(g.seedP1).equals(w.get("seed_p1"))
                                || !hexOf(g.seedP2).equals(w.get("seed_p2"))
                                || !hexOf(g.gatesP2).equals(w.get("gates_p2"))
                                || !hexOf(g.share2).equals(w.get("share2"))) {
                            bad = j;
                        }
                    }
                    if (bad >= 0) {
                        System.out.println("FAIL op " + name + ": round " + bad
                                + " differs (e=" + pp.get(bad).e + ")");
                        fails++;
                    } else {
                        System.out.println("PASS op " + name + " rounds");
                    }
                }

            } else if ("hcred_prove".equals(name)) {
                // HCRED's OTHER prover, beside the KKW one above: same file,
                // same witness, and TODO #266's transcription bug was in this
                // family.  SelfTest's [31] runs this port's prover against
                // ITS OWN verifier, which is precisely the shape that lets a
                // transcription bug pass in three of four ports.
                int n = ((Number) params.get("n")).intValue();
                int rounds = ((Number) params.get("rounds")).intValue();
                int[] mPoly = unpackVec((String) stmt.get("m_poly"));
                int[] cPoly = unpackVec((String) stmt.get("c_poly"));
                BigInteger seedH = new BigInteger((String) stmt.get("seed_H"), 16);
                BigInteger ySynd = new BigInteger((String) stmt.get("y"), 16);
                byte[] hmsg = unhexBytes((String) stmt.get("msg_hex"));
                Hcred.Proof pf = Hcred.prove(unpackVec((String) stmt.get("s_poly")),
                        mPoly, cPoly, seedH, ySynd, rounds, hmsg, rng);
                fails += replayCheck("op " + name + " W", Integer.toString(pf.W),
                        Integer.toString(((Number) expect.get("W")).intValue()));
                List<Object> want = (List<Object>) expect.get("rounds");
                int bad = -1;
                String badField = "";
                if (pf.rounds.size() != want.size()) {
                    System.out.println("FAIL op " + name + ": " + pf.rounds.size()
                            + " rounds, vector says " + want.size());
                    fails++;
                } else {
                    for (int j = 0; j < pf.rounds.size() && bad < 0; j++) {
                        Map<String, Object> w = (Map<String, Object>) want.get(j);
                        Hcred.ProofRound rd = pf.rounds.get(j);
                        List<Object> cw = (List<Object>) w.get("coms");
                        for (int p = 0; p < 3 && bad < 0; p++) {
                            if (!hexOf(rd.coms[p]).equals(cw.get(p))) {
                                bad = j; badField = "coms[" + p + "]";
                            }
                        }
                        if (bad >= 0) break;
                        // `outs` travels as the suite's OWN serialisation, the
                        // one that feeds the FS hash, so this compares one hex
                        // string rather than four opinions of a nested layout.
                        String[][] pairs = {
                            {"outs", hexOf(Hcred.outputsSer(rd.outs))},
                            {"seed_c", hexOf(rd.seedC)},
                            {"seed_c1", hexOf(rd.seedC1)},
                            {"a1", packVec(rd.a1)}, {"b1", packVec(rd.b1)},
                            {"g1", packVec(rd.g1)}, {"h1", packVec(rd.h1)},
                        };
                        for (String[] pr : pairs) {
                            if (!pr[1].equals(w.get(pr[0]))) {
                                bad = j; badField = pr[0]; break;
                            }
                        }
                        if (bad >= 0) break;
                        // aux is NULL on a round where party 2 is not opened,
                        // and that nullness IS the aux-reveal condition the Go
                        // port read backwards at TODO #266 -- so a null where
                        // the vector has a vector (or the reverse) is the
                        // failure, not a skip.
                        String[] auxKeys = {"aux_s", "aux_B", "aux_D"};
                        int[][] auxVals = {rd.auxS, rd.auxB, rd.auxD};
                        for (int k = 0; k < 3; k++) {
                            Object wv = w.get(auxKeys[k]);
                            if ((auxVals[k] == null) != (wv == null)) {
                                bad = j; badField = auxKeys[k] + " (reveal condition)"; break;
                            }
                            if (auxVals[k] != null && !packVec(auxVals[k]).equals(wv)) {
                                bad = j; badField = auxKeys[k]; break;
                            }
                        }
                    }
                    if (bad >= 0) {
                        System.out.println("FAIL op " + name + ": round " + bad
                                + " differs at " + badField);
                        fails++;
                    } else {
                        System.out.println("PASS op " + name + " rounds");
                    }
                }
                if (!Hcred.verify(mPoly, cPoly, seedH, ySynd, pf, rounds, hmsg)) {
                    System.out.println("FAIL op " + name + " verifies");
                    fails++;
                } else {
                    System.out.println("PASS op " + name + " verifies");
                }

            } else {
                System.out.println("FAIL operation_replay: unknown operation \"" + name
                        + "\" -- a row was added to the vector and no Java "
                        + "consumer follows it");
                fails++;
                continue;
            }

            // A null `consumed` means the ports read at different
            // granularities and only the output is common; the row carries
            // the reason.
            Object cv = r.get("consumed");
            if (cv != null) {
                int want = ((Number) cv).intValue();
                if (rng.consumed() != want) {
                    System.out.println("FAIL op " + name + ": consumed " + rng.consumed()
                            + " stream bytes, vector says " + want);
                    fails++;
                } else {
                    System.out.println("PASS op " + name + " consumed " + want + " bytes");
                }
            }
        }
        return fails;
    }

}
