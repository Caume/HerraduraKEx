// Fuzz/der_diff/herradurakex/DerDiff.java — the Java parser's side of the DER
// parser differential (TODO #404; CliTest/test_der_reader_diff.sh drives it).
//
// stdin: one case per line, the DER bytes in hex.  stdout: one line per case,
// "OK v/w/z ..." (value in minimal hex, encoded width, lead) or
// "ERR <message hex>".  It calls what HerraduraCli calls for a DER PEM:
// Codec.derParseSeq(PemBlock) (trailing bytes, the parse, the scan; a label in
// no table, "L", skips the item count and field checks) and then derSeqScan
// for the encodings.  It is in package herradurakex for derSeqScan, which is
// package-private.  A RuntimeException other than IllegalArgumentException is
// printed as a refusal named EXC, so the test sees it.
package herradurakex;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.List;

public final class DerDiff {
    private static String hex(byte[] b) {
        StringBuilder s = new StringBuilder(b.length * 2);
        for (byte x : b) s.append(String.format("%02x", x & 0xFF));
        return s.toString();
    }

    public static void main(String[] args) throws Exception {
        BufferedReader r = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.US_ASCII));
        PrintWriter w = new PrintWriter(System.out);
        String line;
        while ((line = r.readLine()) != null) {
            byte[] d = new byte[line.length() / 2];
            for (int i = 0; i < d.length; i++)
                d[i] = (byte) Integer.parseInt(line.substring(2 * i, 2 * i + 2), 16);
            try {
                List<BigInteger> ints = Codec.derParseSeq(new Codec.PemBlock("L", d));
                Codec.DerEnc enc = Codec.derSeqScan(d, "L");
                StringBuilder s = new StringBuilder("OK");
                for (int i = 0; i < ints.size(); i++)
                    s.append(' ').append(ints.get(i).toString(16))
                     .append('/').append(enc.width[i]).append('/').append(enc.lead[i]);
                w.println(s);
            } catch (IllegalArgumentException e) {
                w.println("ERR " + hex(e.getMessage().getBytes(StandardCharsets.UTF_8)));
            } catch (RuntimeException e) {
                String m = "EXC " + e.getClass().getSimpleName() + ": " + e.getMessage();
                w.println("ERR " + hex(m.getBytes(StandardCharsets.UTF_8)));
            }
        }
        w.flush();
    }
}
