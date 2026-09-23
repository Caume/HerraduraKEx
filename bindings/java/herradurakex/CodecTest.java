package herradurakex;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.SecureRandom;

/**
 * TODO #197: round-trip test for {@link Codec}, plus (when a file path is
 * given on the command line) a fixed-vector cross-check that decodes a
 * PEM key file produced by another language's CLI and prints its fields
 * so a shell wrapper can diff them against that CLI's own report.
 *
 * Usage:
 *   java -cp bindings/java herradurakex.CodecTest                 # round-trip only
 *   java -cp bindings/java herradurakex.CodecTest decode-priv FILE # print priv,pub,nbits
 *   java -cp bindings/java herradurakex.CodecTest decode-pub  FILE # print pub,nbits
 *   java -cp bindings/java herradurakex.CodecTest encode-priv PRIV PUB FILE  # write PEM
 *   java -cp bindings/java herradurakex.CodecTest encode-session KEY NBITS FILE # write PEM
 */
public final class CodecTest {
    private CodecTest() { }

    public static void main(String[] args) throws IOException {
        if (args.length == 0) {
            roundTrip();
            return;
        }
        switch (args[0]) {
            case "decode-priv": {
                String pem = new String(Files.readAllBytes(Paths.get(args[1])), StandardCharsets.US_ASCII);
                Codec.PrivKey k = Codec.decodePrivKey(pem, Codec.PEM_HKEX_GF_PRIV);
                System.out.println(k.priv.toString(16));
                System.out.println(k.pub.toString(16));
                System.out.println(k.nbits);
                break;
            }
            case "decode-pub": {
                String pem = new String(Files.readAllBytes(Paths.get(args[1])), StandardCharsets.US_ASCII);
                Codec.PubKey k = Codec.decodePubKey(pem, Codec.PEM_HKEX_GF_PUB);
                System.out.println(k.pub.toString(16));
                System.out.println(k.nbits);
                break;
            }
            case "encode-priv": {
                BigInteger priv = new BigInteger(args[1], 16);
                BigInteger pub = new BigInteger(args[2], 16);
                String pem = Codec.encodePrivKey(Codec.PEM_HKEX_GF_PRIV, priv, pub);
                Files.write(Path.of(args[3]), pem.getBytes(StandardCharsets.US_ASCII));
                break;
            }
            case "encode-session": {
                // TODO #219: the session-key field is minimal-width, unlike the
                // fixed-width private/public key fields; this mode lets
                // CliTest/test_java_codec.sh compare the bytes against Python's.
                BigInteger key = new BigInteger(args[1], 16);
                int nbits = Integer.parseInt(args[2]);
                String pem = Codec.encodeSessionKey(key, nbits);
                Files.write(Path.of(args[3]), pem.getBytes(StandardCharsets.US_ASCII));
                break;
            }
            default:
                System.err.println("Unknown mode: " + args[0]);
                System.exit(2);
        }
    }

    private static void roundTrip() {
        SecureRandom rng = new SecureRandom();
        int fails = 0;

        // Key round-trip (priv + derived pub).
        {
            BitArray priv = BitArray.random(Herradura.N, rng);
            BitArray pub = Herradura.hkexGfPubkey(priv);
            String pem = Codec.encodePrivKey(Codec.PEM_HKEX_GF_PRIV, priv.toBigInteger(), pub.toBigInteger());
            Codec.PrivKey decoded = Codec.decodePrivKey(pem, Codec.PEM_HKEX_GF_PRIV);
            if (!decoded.priv.equals(priv.toBigInteger()) || !decoded.pub.equals(pub.toBigInteger())
                    || decoded.nbits != Herradura.N) {
                System.out.println("FAIL privkey round-trip");
                fails++;
            } else {
                System.out.println("PASS privkey round-trip");
            }

            String pubPem = Codec.encodePubKey(Codec.PEM_HKEX_GF_PUB, pub.toBigInteger());
            Codec.PubKey decodedPub = Codec.decodePubKey(pubPem, Codec.PEM_HKEX_GF_PUB);
            if (!decodedPub.pub.equals(pub.toBigInteger()) || decodedPub.nbits != Herradura.N) {
                System.out.println("FAIL pubkey round-trip");
                fails++;
            } else {
                System.out.println("PASS pubkey round-trip");
            }
        }

        // HPKE ciphertext round-trip.
        {
            BitArray priv = BitArray.random(Herradura.N, rng);
            BitArray pub = Herradura.hkexGfPubkey(priv);
            BitArray pt = BitArray.random(Herradura.N, rng);
            Herradura.Ciphertext enc = Herradura.hpkeEncrypt(pt, pub, rng);
            String pem = Codec.encodeAsymCt(enc.r.toBigInteger(), enc.ct.toBigInteger(), Herradura.N);
            Codec.AsymCt decoded = Codec.decodeAsymCt(pem);
            BitArray recovered = Herradura.hpkeDecrypt(BitArray.fromBigInteger(decoded.e, Herradura.N),
                                                       BitArray.fromBigInteger(decoded.r, Herradura.N), priv);
            if (!recovered.equals(pt)) {
                System.out.println("FAIL ciphertext round-trip");
                fails++;
            } else {
                System.out.println("PASS ciphertext round-trip");
            }
        }

        // HPKS signature round-trip.
        {
            BitArray priv = BitArray.random(Herradura.N, rng);
            BitArray pub = Herradura.hkexGfPubkey(priv);
            BitArray msg = BitArray.random(Herradura.N, rng);
            Herradura.Signature sig = Herradura.hpksSign(msg, priv, rng);
            String pem = Codec.encodeSchnorrSig(sig.s.toBigInteger(), sig.r.toBigInteger(),
                    Herradura.fscxRevolve(sig.r, msg, Herradura.I_STEPS).toBigInteger(), Herradura.N);
            Codec.SchnorrSig decoded = Codec.decodeSchnorrSig(pem);
            boolean ok = Herradura.hpksVerify(msg, pub, BitArray.fromBigInteger(decoded.r, Herradura.N),
                                              BitArray.fromBigInteger(decoded.s, Herradura.N));
            if (!ok) {
                System.out.println("FAIL signature round-trip (verify failed)");
                fails++;
            } else {
                System.out.println("PASS signature round-trip");
            }
        }

        // Session key + digest round-trip.
        {
            BigInteger key = new BigInteger(Herradura.N, rng).and(Herradura.MASK);
            String pem = Codec.encodeSessionKey(key, Herradura.N);
            Codec.PubKey decoded = Codec.decodeSessionKey(pem);
            if (!decoded.pub.equals(key) || decoded.nbits != Herradura.N) {
                System.out.println("FAIL session key round-trip");
                fails++;
            } else {
                System.out.println("PASS session key round-trip");
            }

            BigInteger digest = new BigInteger(256, rng);
            String dpem = Codec.encodeDigest(digest);
            BigInteger decodedDigest = Codec.decodeDigest(dpem);
            if (!decodedDigest.equals(digest)) {
                System.out.println("FAIL digest round-trip");
                fails++;
            } else {
                System.out.println("PASS digest round-trip");
            }
        }

        // A value with the DER sign-byte edge case (high bit set) — exercises
        // the 0x00 prepend/strip path.
        {
            BigInteger hi = BigInteger.ONE.shiftLeft(Herradura.N - 1).or(BigInteger.ONE); // top bit set
            String pem = Codec.encodePubKey(Codec.PEM_HKEX_GF_PUB, hi);
            Codec.PubKey decoded = Codec.decodePubKey(pem, Codec.PEM_HKEX_GF_PUB);
            if (!decoded.pub.equals(hi)) {
                System.out.println("FAIL sign-byte edge case round-trip");
                fails++;
            } else {
                System.out.println("PASS sign-byte edge case round-trip");
            }
        }

        if (fails > 0) {
            System.out.println(fails + " test(s) FAILED");
            System.exit(1);
        }
        System.out.println("All codec round-trip tests passed.");
    }
}
