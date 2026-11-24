// Fuzz/pem_diff/PemDiff.java — the Java reader's side of the PEM reader
// differential (TODO #403; CliTest/test_pem_reader_diff.sh drives it).
//
// stdin: one case per line, the file's bytes in hex.  stdout: one line per
// case, "OK <label hex> <der hex>" or "ERR <message hex>".  The bytes go to
// Codec.pemUnwrap as HerraduraCli.readString reads them (US-ASCII, so each
// non-ASCII byte is U+FFFD), and the message is encoded as UTF-8.
import herradurakex.Codec;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;

public final class PemDiff {
    private static String h(byte[] b) {
        if (b.length == 0) return "-";
        StringBuilder s = new StringBuilder(b.length * 2);
        for (byte x : b) s.append(String.format("%02x", x & 0xFF));
        return s.toString();
    }

    public static void main(String[] args) throws Exception {
        BufferedReader r = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.US_ASCII));
        PrintWriter w = new PrintWriter(System.out);
        String line;
        while ((line = r.readLine()) != null) {
            byte[] in = new byte[line.length() / 2];
            for (int i = 0; i < in.length; i++)
                in[i] = (byte) Integer.parseInt(line.substring(2 * i, 2 * i + 2), 16);
            String text = new String(in, StandardCharsets.US_ASCII);
            try {
                Codec.PemBlock b = Codec.pemUnwrap(text);
                w.println("OK " + h(b.label.getBytes(StandardCharsets.UTF_8)) + " " + h(b.der));
            } catch (IllegalArgumentException e) {
                w.println("ERR " + h(e.getMessage().getBytes(StandardCharsets.UTF_8)));
            }
        }
        w.flush();
    }
}
