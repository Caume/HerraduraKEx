package herradurakex;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.HashMap;
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
            BigInteger seed = Herradura.rol(kAlice, keyBits / 8)
                    .xor(Hfscx256.RNL_KDF_DC_256);
            BigInteger sk = Hfscx256.nlFscxRevolveV1(seed, kAlice, keyBits / 4);
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
            BigInteger C = Herradura.hkexGfPubkey(a), C2 = Herradura.hkexGfPubkey(b);
            BigInteger sk = Herradura.hkexGfAgree(a, C2);
            BigInteger skOther = Herradura.hkexGfAgree(b, C);
            BigInteger want = hex(v, "shared_secret");
            if (!sk.equals(want) || !sk.equals(skOther)) {
                System.out.println("FAIL hkex_gf: got " + sk.toString(16) + " want " + want.toString(16));
                fails++;
            } else {
                System.out.println("PASS hkex_gf");
            }
        }

        // HSKE
        {
            Map<String, String> v = objects.get("hske");
            BigInteger key = hex(v, "key"), pt = hex(v, "plaintext");
            BigInteger ct = Herradura.hskeEncrypt(pt, key);
            BigInteger want = hex(v, "ciphertext");
            BigInteger roundTrip = Herradura.hskeDecrypt(ct, key);
            if (!ct.equals(want) || !roundTrip.equals(pt)) {
                System.out.println("FAIL hske: got " + ct.toString(16) + " want " + want.toString(16));
                fails++;
            } else {
                System.out.println("PASS hske");
            }
        }

        // HPKS
        {
            Map<String, String> v = objects.get("hpks");
            BigInteger pub = hex(v, "pub"), r = hex(v, "R"), s = hex(v, "s"), msg = hex(v, "message");
            boolean ok = Herradura.hpksVerify(msg, pub, r, s);
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
            Herradura.Ciphertext enc = Herradura.hpkeEncrypt(pt, pub, ephR);
            BigInteger wantR = hex(v, "R"), wantCt = hex(v, "ciphertext");
            BigInteger dec = Herradura.hpkeDecrypt(enc.ct, enc.r, priv);
            if (!enc.r.equals(wantR) || !enc.ct.equals(wantCt) || !dec.equals(pt)) {
                System.out.println("FAIL hpke: R(got=" + enc.r.toString(16) + " want=" + wantR.toString(16)
                        + ") ct(got=" + enc.ct.toString(16) + " want=" + wantCt.toString(16)
                        + ") decrypt_roundtrip=" + dec.equals(pt));
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

        if (fails > 0) {
            System.out.println(fails + " vector set(s) FAILED");
            System.exit(1);
        }
        System.out.println("All KAT vectors verified against the Java herradurakex package.");
    }
}
