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

        if (fails > 0) {
            System.out.println(fails + " vector set(s) FAILED");
            System.exit(1);
        }
        System.out.println("All KAT vectors verified against the Java herradurakex package.");
    }
}
