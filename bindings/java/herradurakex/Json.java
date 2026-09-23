package herradurakex;

import java.util.Map;

/**
 * Minimal recursive-descent JSON reader, enough for the shapes KAT/ uses
 * (TODO #192; extracted from KatVerify by TODO #314 pass 5).
 *
 * <p>The shipped primitives and CLIs have no third-party dependencies in any
 * language — CLAUDE.md's standing rule — so the Java port reads its vectors
 * with this rather than a JSON library.  It lived as a private nested class
 * inside {@code KatVerify} until a SECOND consumer needed it: copying it into
 * {@code VerifyBitArray} would have been a second implementation of the one
 * thing, which is the shape TODO #314 exists to remove.
 *
 * <p>NUMBERS DECODE AS {@code Long}, EXACTLY.  That matters here and is worth
 * keeping: KAT/bitarray.json carries two integers above 2^53 — {@code to_uint}'s
 * 7025791060798414911 at n = 64, and {@code from_uint}'s 2^32 boundary — which a
 * float64 decode rounds.  The Go consumer met that and had to ask for
 * {@code json.Number}; this hand-rolled reader, written to avoid a dependency,
 * is exact by construction.
 */
final class Json {
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
