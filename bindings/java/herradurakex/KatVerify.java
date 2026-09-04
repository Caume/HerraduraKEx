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
        BigInteger revolve = HerraduraNl.nlFscxRevolveV3(pt, key, r3);
        if (!HerraduraNl.nlChiV3(pt).equals(hex(p, "chi_of_plaintext"))
                || !HerraduraNl.nlFscxV3(pt, key).equals(hex(p, "one_round"))
                || !revolve.equals(hex(p, "revolve"))
                || !HerraduraNl.nlFscxRevolveV3Inv(revolve, key, r3).equals(pt)) {
            System.out.println("FAIL nl_fscx_v3: chi="
                    + HerraduraNl.nlChiV3(pt).equals(hex(p, "chi_of_plaintext"))
                    + " round=" + HerraduraNl.nlFscxV3(pt, key).equals(hex(p, "one_round"))
                    + " revolve=" + revolve.equals(hex(p, "revolve"))
                    + " revolve_inv="
                    + HerraduraNl.nlFscxRevolveV3Inv(revolve, key, r3).equals(pt));
            fails++;
        } else {
            System.out.println("PASS nl_fscx_v3");
        }

        Map<String, String> a = v3.get("hske_nla3");
        BigInteger got = HerraduraNl.hskeNlA3Encrypt(hex(a, "plaintext"), hex(a, "key"));
        if (!got.equals(hex(a, "ciphertext"))) {
            System.out.println("FAIL hske_nla3: got " + got.toString(16)
                    + " want " + a.get("ciphertext"));
            fails++;
        } else {
            System.out.println("PASS hske_nla3");
        }

        Map<String, String> e = v3.get("hpke_nl3");
        Herradura.Ciphertext ct = HerraduraNl.hpkeNl3Encrypt(
                hex(e, "plaintext"), hex(e, "pub"), hex(e, "ephemeral_r"));
        BigInteger dec = ct == null ? null
                : HerraduraNl.hpkeNl3Decrypt(ct.ct, ct.r, hex(e, "priv"));
        if (ct == null || !ct.r.equals(hex(e, "R")) || !ct.ct.equals(hex(e, "ciphertext"))
                || dec == null || !dec.equals(hex(e, "plaintext"))) {
            System.out.println("FAIL hpke_nl3: R="
                    + (ct != null && ct.r.equals(hex(e, "R")))
                    + " ct=" + (ct != null && ct.ct.equals(hex(e, "ciphertext")))
                    + " decrypt_roundtrip=" + (dec != null && dec.equals(hex(e, "plaintext"))));
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

        if (fails > 0) {
            System.out.println(fails + " vector set(s) FAILED");
            System.exit(1);
        }
        System.out.println("All KAT vectors verified against the Java herradurakex package.");
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
    // online proofs carry an array of path arrays), so this section brings a
    // minimal recursive-descent JSON reader rather than a dependency.

    /** Minimal recursive-descent JSON reader: enough for this file's shapes. */
    private static final class Json {
        private final String s;
        private int p;
        private Json(String s) { this.s = s; }

        static Object parse(String text) {
            Json j = new Json(text);
            j.ws();
            Object v = j.value();
            j.ws();
            if (j.p != text.length()) throw new IllegalStateException("trailing JSON at " + j.p);
            return v;
        }

        private void ws() { while (p < s.length() && Character.isWhitespace(s.charAt(p))) p++; }

        private Object value() {
            char c = s.charAt(p);
            switch (c) {
                case '{': return object();
                case '[': return array();
                case '"': return string();
                case 't': p += 4; return Boolean.TRUE;
                case 'f': p += 5; return Boolean.FALSE;
                case 'n': p += 4; return null;
                default:  return number();
            }
        }

        private Map<String, Object> object() {
            Map<String, Object> m = new java.util.LinkedHashMap<>();
            p++; ws();
            if (s.charAt(p) == '}') { p++; return m; }
            while (true) {
                ws();
                String k = string();
                ws();
                p++;              // ':'
                ws();
                m.put(k, value());
                ws();
                char c = s.charAt(p++);
                if (c == '}') return m;
                if (c != ',') throw new IllegalStateException("expected , or } at " + p);
            }
        }

        private java.util.List<Object> array() {
            java.util.List<Object> l = new java.util.ArrayList<>();
            p++; ws();
            if (s.charAt(p) == ']') { p++; return l; }
            while (true) {
                ws();
                l.add(value());
                ws();
                char c = s.charAt(p++);
                if (c == ']') return l;
                if (c != ',') throw new IllegalStateException("expected , or ] at " + p);
            }
        }

        private String string() {
            StringBuilder b = new StringBuilder();
            p++;                                  // opening quote
            while (true) {
                char c = s.charAt(p++);
                if (c == '"') return b.toString();
                if (c != '\\') { b.append(c); continue; }
                char e = s.charAt(p++);
                switch (e) {
                    case 'n': b.append('\n'); break;
                    case 't': b.append('\t'); break;
                    case 'r': b.append('\r'); break;
                    case 'b': b.append('\b'); break;
                    case 'f': b.append('\f'); break;
                    case 'u':
                        b.append((char) Integer.parseInt(s.substring(p, p + 4), 16));
                        p += 4;
                        break;
                    default:  b.append(e);        // \" \\ \/
                }
            }
        }

        private Object number() {
            int st = p;
            while (p < s.length() && "-+.eE0123456789".indexOf(s.charAt(p)) >= 0) p++;
            String tok = s.substring(st, p);
            if (tok.indexOf('.') < 0 && tok.indexOf('e') < 0 && tok.indexOf('E') < 0)
                return Long.valueOf(tok);
            return Double.valueOf(tok);
        }
    }

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
        Map<String, Object> pr = obj(set.get("proof"));
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
}
