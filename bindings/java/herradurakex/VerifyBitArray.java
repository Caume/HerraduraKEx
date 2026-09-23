package herradurakex;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import java.util.Map;

/**
 * VerifyBitArray — the Java consumer for KAT/bitarray.json (TODO #314 pass 5).
 *
 * <p>BITARRAY.md is the specification; KAT/generate_bitarray_kat.py carries the
 * reference implementation and pins its output; this runs the SHIPPED Java
 * {@link BitArray} against those pinned answers.
 *
 * <p>Java is pass 5 and the FOURTH port in the gating set, which completes it:
 * all four implementations are now held to one pinned answer, and BITARRAY.md
 * §8's pass 6 — relaxing TODO #313's refusal — becomes available for the first
 * time, because "the four agree" stops being a property of four people's care
 * at one width and becomes a property of the code.
 *
 * <p>Reads the JSON through {@link Json}, whose numbers decode as {@code Long}
 * and are therefore exact: two cases here carry integers above 2^53, which the
 * Go consumer had to ask for {@code json.Number} to read correctly.
 *
 * <p>Usage: {@code java -cp bindings/java herradurakex.VerifyBitArray [path]}
 */
public final class VerifyBitArray {
    private VerifyBitArray() { }

    private static int passes = 0;
    private static int failures = 0;

    private static void ok(boolean cond, Map<String, Object> c, String detail) {
        if (cond) { passes++; return; }
        failures++;
        Object mw = c.get("mixed_with");
        System.out.printf("FAIL [%s n=%d%s] %s%n",
            c.get("op"), jint(c.get("nbits")), mw != null ? " mixed" : "", detail);
    }

    /** The outcome of one attempted operation: a value, or a BITARRAY.md §5 code. */
    private static final class Outcome {
        final BitArray value;
        final long number;
        final String code;
        Outcome(BitArray v) { value = v; number = 0; code = null; }
        Outcome(long n)     { value = null; number = n; code = null; }
        Outcome(String c)   { value = null; number = 0; code = c; }
    }

    private interface Op { Object run(); }

    private static Outcome attempt(Op op) {
        try {
            Object r = op.run();
            return (r instanceof BitArray) ? new Outcome((BitArray) r)
                                           : new Outcome(((Number) r).longValue());
        } catch (BaException e) {
            return new Outcome(e.code());
        }
    }

    private static void checkBits(Map<String, Object> c, Outcome got) {
        Map<String, Object> expect = obj(c.get("expect"));
        String wantErr = (String) expect.get("error");
        if (wantErr != null) {
            if (got.code == null) { ok(false, c, "expected " + wantErr + ", got a value"); return; }
            ok(wantErr.equals(got.code), c, "expected " + wantErr + ", got " + got.code);
            return;
        }
        if (got.code != null) { ok(false, c, "expected a value, got " + got.code); return; }
        String wantHex = (String) expect.get("hex");
        int wantNbits = jint(expect.get("nbits"));
        ok(got.value.size() == wantNbits && got.value.toHex().equals(wantHex), c,
           "got " + got.value.toHex() + "/" + got.value.size()
               + " want " + wantHex + "/" + wantNbits);
    }

    private static void checkInt(Map<String, Object> c, Outcome got) {
        Map<String, Object> expect = obj(c.get("expect"));
        String wantErr = (String) expect.get("error");
        if (wantErr != null) {
            ok(wantErr.equals(got.code), c,
               "expected " + wantErr + ", got " + (got.code == null ? "a value" : got.code));
            return;
        }
        if (got.code != null) { ok(false, c, "expected a value, got " + got.code); return; }
        long want = ((Number) expect.get("int")).longValue();
        ok(got.number == want, c, "got " + got.number + " want " + want);
    }

    public static void main(String[] args) throws Exception {
        Path path = args.length > 0 ? Paths.get(args[0])
                                    : Paths.get("KAT", "bitarray.json");
        Map<String, Object> root = obj(Json.parse(new String(
            Files.readAllBytes(path), java.nio.charset.StandardCharsets.UTF_8)));
        List<Object> cases = arr(root.get("cases"));
        int declared = jint(root.get("case_count"));
        if (declared != cases.size()) {
            System.out.printf("FAIL: case_count %d but %d cases%n", declared, cases.size());
            System.exit(1);
        }

        System.out.println("=== KAT/bitarray.json against the shipped Java BitArray (TODO #314) ===");
        System.out.printf("    %d cases, capacity BA_MAX_BITS = %d%n",
                          cases.size(), BitArray.BA_MAX_BITS);

        for (Object oc : cases) {
            final Map<String, Object> c = obj(oc);
            final String op = (String) c.get("op");
            final int n = jint(c.get("nbits"));
            final Map<String, Object> args2 = obj(c.get("args"));
            Object mw = c.get("mixed_with");
            final int bw = mw != null ? jint(mw) : n;

            // Constructors read their own operand and are scored directly.
            if (op.equals("zero"))      { checkBits(c, attempt(() -> BitArray.zero(n))); continue; }
            if (op.equals("from_hex"))  { checkBits(c, attempt(() -> BitArray.fromHex((String) args2.get("hex"), n))); continue; }
            if (op.equals("from_bytes")) {
                checkBits(c, attempt(() -> BitArray.fromBytes(unhex((String) args2.get("hex")), n)));
                continue;
            }
            if (op.equals("from_uint")) {
                final long v = ((Number) args2.get("uint")).longValue();
                checkBits(c, attempt(() -> BitArray.fromUint(v, n)));
                continue;
            }

            // Everything below needs its operands to load.  A width this port
            // cannot represent is E_WIDTH, a legitimate answer the vector pins.
            String aHex = (String) (args2.containsKey("a") ? args2.get("a") : args2.get("hex"));
            Outcome oa = aHex == null ? null : attempt(() -> BitArray.fromHex(aHex, n));
            if (oa != null && oa.code != null) { checkBits(c, oa); continue; }
            String bHex = (String) args2.get("b");
            Outcome ob = bHex == null ? null : attempt(() -> BitArray.fromHex(bHex, bw));
            if (ob != null && ob.code != null) { checkBits(c, ob); continue; }
            final BitArray a = oa == null ? null : oa.value;
            final BitArray b = ob == null ? null : ob.value;

            switch (op) {
                case "to_uint":      checkInt(c, attempt(a::toUint)); break;
                case "popcount":     checkInt(c, attempt(a::popcount)); break;
                case "is_zero":      ok(a.isZero() == (Boolean) obj(c.get("expect")).get("bool"), c, "is_zero"); break;
                case "xor":          checkBits(c, attempt(() -> a.xor(b))); break;
                case "and":          checkBits(c, attempt(() -> a.and(b))); break;
                case "or":           checkBits(c, attempt(() -> a.or(b))); break;
                case "not":          checkBits(c, attempt(a::not)); break;
                case "rot_left":     checkBits(c, attempt(() -> a.rotLeft(jint(args2.get("s"))))); break;
                case "rot_right":    checkBits(c, attempt(() -> a.rotRight(jint(args2.get("s"))))); break;
                case "shl":          checkBits(c, attempt(() -> a.shl(jint(args2.get("k"))))); break;
                case "shr":          checkBits(c, attempt(() -> a.shr(jint(args2.get("k"))))); break;
                case "truncate":     checkBits(c, attempt(() -> a.truncate(jint(args2.get("m"))))); break;
                case "extend":       checkBits(c, attempt(() -> a.extend(jint(args2.get("m"))))); break;
                case "resize_exact": checkBits(c, attempt(() -> a.resizeExact(jint(args2.get("m"))))); break;
                case "equal":        ok(a.equals(b) == (Boolean) obj(c.get("expect")).get("bool"), c, "equal"); break;
                case "compare":      checkInt(c, attempt(() -> a.compare(b))); break;
                case "bit":          checkInt(c, attempt(() -> a.bit(jint(args2.get("i"))))); break;
                case "fscx":         checkBits(c, attempt(() -> BitArray.fscx(a, b))); break;
                case "fscx_revolve": checkBits(c, attempt(() -> BitArray.fscxRevolve(a, b, jint(args2.get("i"))))); break;
                case "gf_mul":       checkBits(c, attempt(() -> BitArray.gfMul(a, b))); break;
                case "gf_pow":       checkBits(c, attempt(() -> BitArray.gfPow(a, ((Number) args2.get("e")).longValue()))); break;
                case "rnl_kdf_seed": checkBits(c, attempt(() -> BitArray.rnlKdfSeed(a))); break;
                default:
                    failures++;
                    System.out.printf("FAIL [%s] no handler in VerifyBitArray.java — a case the "
                        + "consumer does not implement must not read as a pass%n", op);
            }
        }

        System.out.printf("%nResults: %d PASS / %d FAIL (of %d cases)%n",
                          passes, failures, cases.size());
        if (passes + failures != cases.size()) {
            System.out.printf("FAIL: %d case(s) were neither passed nor failed — a case that "
                + "did not run must not be scored (TODO #291)%n",
                cases.size() - passes - failures);
            System.exit(1);
        }
        if (failures != 0) {
            System.out.println("*** FAILED: the shipped Java BitArray disagrees with BITARRAY.md ***");
            System.exit(1);
        }
        System.out.println("*** OK: the shipped Java BitArray matches KAT/bitarray.json ***");
    }

    private static byte[] unhex(String s) {
        byte[] out = new byte[s.length() / 2];
        for (int i = 0; i < out.length; i++)
            out[i] = (byte) Integer.parseInt(s.substring(2 * i, 2 * i + 2), 16);
        return out;
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> obj(Object o) { return (Map<String, Object>) o; }

    @SuppressWarnings("unchecked")
    private static List<Object> arr(Object o) { return (List<Object>) o; }

    private static int jint(Object o) { return (int) ((Number) o).longValue(); }
}
