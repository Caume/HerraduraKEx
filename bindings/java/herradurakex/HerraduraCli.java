package herradurakex;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * TODO #198/#199: Java CLI mirroring HerraduraCli/herradura.py /
 * herradura_cli.c / herradura_cli.go's subcommand interface. Covers the
 * classical quartet (algo values hkex-gf, hpks, hpke, plus hske for
 * symmetric enc/dec — {@link Herradura}) and the NL/PQC quartet (hkex-rnl,
 * hske-nla1, hske-nla2, hpks-nl, hpke-nl — {@link HerraduraNl}). dgst and
 * encfile/decfile additionally use the NL-FSCX-based HFSCX-256 hash and
 * HSKE-NL-A1 file container ({@link Hfscx256}) for wire-format parity with
 * the other CLIs.
 *
 * Out of scope (TODO #200/#201 and beyond): Stern-F code-based PQC,
 * hybrid-rnl-stern, rnl-sigma, ZKP-NL/ZKP-RNL, XMSS/WOTS, OPRF, HCRED, and
 * the {@code --kdf}/{@code --aead} CLI options.
 *
 * Subcommands: genpkey, pkey, kex, enc, dec, sign, verify, dgst, encfile,
 * decfile. PEM/DER wire format is byte-for-byte compatible with the
 * Python/C/Go CLIs (via {@link Codec}). HKEX-RNL's {@code kex} is
 * two-round: Bob responds first ({@code --our} his priv key, {@code --their}
 * Alice's pub key) with an RNL RESPONSE PEM; Alice then completes
 * ({@code --our} her priv key, {@code --their} Bob's RNL RESPONSE PEM) into
 * a plain SESSION KEY PEM — matching the Python/C/Go CLIs' convention.
 */
public final class HerraduraCli {
    private HerraduraCli() { }

    private static final SecureRandom RNG = new SecureRandom();

    public static void main(String[] args) {
        try {
            run(args);
        } catch (CliError e) {
            System.err.println(e.getMessage());
            System.exit(1);
        } catch (Exception e) {
            System.err.println("error: " + e.getMessage());
            System.exit(1);
        }
    }

    /** Thrown for expected user-facing errors (bad args, decode failures) —
     * printed without a Java stack trace, matching the other CLIs' terse
     * "subcommand: message" errors to stderr. */
    private static final class CliError extends RuntimeException {
        CliError(String msg) { super(msg); }
    }

    private static void run(String[] args) throws IOException {
        if (args.length == 0) {
            throw new CliError("usage: herradurakex <genpkey|pkey|kex|enc|dec|sign|verify|dgst|encfile|decfile> [options]");
        }
        String cmd = args[0];
        Map<String, String> opt = parseOpts(args, 1);
        switch (cmd) {
            case "genpkey": cmdGenpkey(opt); break;
            case "pkey":    cmdPkey(opt);    break;
            case "kex":     cmdKex(opt);     break;
            case "enc":     cmdEnc(opt);     break;
            case "dec":     cmdDec(opt);     break;
            case "sign":    cmdSign(opt);    break;
            case "verify":  cmdVerify(opt);  break;
            case "dgst":    cmdDgst(opt);    break;
            case "encfile": cmdEncfile(opt); break;
            case "decfile": cmdDecfile(opt); break;
            default: throw new CliError(cmd + ": unknown subcommand");
        }
    }

    // -----------------------------------------------------------------
    // Option parsing: --flag value  or  --flag (boolean)
    // -----------------------------------------------------------------

    private static Map<String, String> parseOpts(String[] args, int from) {
        Map<String, String> opt = new HashMap<>();
        int i = from;
        while (i < args.length) {
            String a = args[i];
            if (!a.startsWith("--")) throw new CliError("unexpected argument: " + a);
            String key = a.substring(2);
            if (i + 1 < args.length && !args[i + 1].startsWith("--")) {
                opt.put(key, args[i + 1]);
                i += 2;
            } else {
                opt.put(key, "true"); // boolean flag
                i += 1;
            }
        }
        return opt;
    }

    private static String req(Map<String, String> opt, String key, String cmd) {
        String v = opt.get(key);
        if (v == null) throw new CliError(cmd + ": --" + key + " required");
        return v;
    }

    // -----------------------------------------------------------------
    // PEM label <-> algo mapping (classical quartet only)
    // -----------------------------------------------------------------

    private static String privLabel(String algo) {
        switch (algo) {
            case "hkex-gf":  return Codec.PEM_HKEX_GF_PRIV;
            case "hpks":     return Codec.PEM_HPKS_PRIV;
            case "hpks-nl":  return Codec.PEM_HPKS_NL_PRIV;
            case "hpke":     return Codec.PEM_HPKE_PRIV;
            case "hpke-nl":  return Codec.PEM_HPKE_NL_PRIV;
            case "hkex-rnl": return Codec.PEM_HKEX_RNL_PRIV;
            default: throw new CliError("genpkey: unsupported --algo " + algo
                + " (this Java CLI covers the classical quartet plus hkex-rnl, "
                + "hske-nla1/nla2, hpks-nl, hpke-nl)");
        }
    }

    private static String pubLabel(String algo) {
        switch (algo) {
            case "hkex-gf":  return Codec.PEM_HKEX_GF_PUB;
            case "hpks":     return Codec.PEM_HPKS_PUB;
            case "hpks-nl":  return Codec.PEM_HPKS_NL_PUB;
            case "hpke":     return Codec.PEM_HPKE_PUB;
            case "hpke-nl":  return Codec.PEM_HPKE_NL_PUB;
            case "hkex-rnl": return Codec.PEM_HKEX_RNL_PUB;
            default: throw new CliError("unsupported --algo " + algo);
        }
    }

    private static String algoForPrivLabel(String label) {
        if (label.equals(Codec.PEM_HKEX_GF_PRIV))  return "hkex-gf";
        if (label.equals(Codec.PEM_HPKS_PRIV))     return "hpks";
        if (label.equals(Codec.PEM_HPKS_NL_PRIV))  return "hpks-nl";
        if (label.equals(Codec.PEM_HPKE_PRIV))     return "hpke";
        if (label.equals(Codec.PEM_HPKE_NL_PRIV))  return "hpke-nl";
        throw new CliError("unrecognized private-key label: " + label);
    }


    // -----------------------------------------------------------------
    // genpkey
    // -----------------------------------------------------------------

    private static void cmdGenpkey(Map<String, String> opt) throws IOException {
        String algo = req(opt, "algo", "genpkey");
        String out = opt.getOrDefault("out", "-");

        if (algo.equals("hkex-rnl")) {
            int n = Herradura.N;
            int[] mBase = HerraduraNl.rnlMPoly(n);
            int[] aRand = HerraduraNl.rnlRandPoly(n, HerraduraNl.RNLQ, RNG);
            int[] mBlind = HerraduraNl.rnlPolyAdd(mBase, aRand, HerraduraNl.RNLQ);
            HerraduraNl.RnlKeypair kp = HerraduraNl.rnlKeygen(mBlind, n, HerraduraNl.RNLQ, HerraduraNl.RNLP, RNG);
            byte[] nA = new byte[32];
            RNG.nextBytes(nA);
            writeString(out, Codec.encodeRnlPrivKey(kp.s, mBlind, n, nA));
            return;
        }

        String label = privLabel(algo); // validates algo as a side effect
        BigInteger priv = new BigInteger(Herradura.N, RNG).and(Herradura.MASK);
        BigInteger pub = Herradura.hkexGfPubkey(priv); // same keypair shape for hkex-gf/hpks(-nl)/hpke(-nl)
        String pem = Codec.encodePrivKey(label, priv, pub);
        writeString(out, pem);
    }

    // -----------------------------------------------------------------
    // pkey
    // -----------------------------------------------------------------

    private static void cmdPkey(Map<String, String> opt) throws IOException {
        String in = req(opt, "in", "pkey");
        String out = opt.getOrDefault("out", "-");
        String pemIn = readString(in);
        Codec.PemBlock block = Codec.pemUnwrap(pemIn);

        if (block.label.equals(Codec.PEM_HKEX_RNL_PRIV)) {
            Codec.RnlPrivKey pk = Codec.decodeRnlPrivKey(pemIn);
            int[] c = HerraduraNl.hkexRnlDeriveC(pk.mBlind, pk.s, pk.n);
            if (opt.containsKey("pubout")) {
                writeString(out, Codec.encodeRnlPubKey(c, pk.mBlind, pk.n, pk.nA));
            } else if (opt.containsKey("text")) {
                System.out.println("algorithm : hkex-rnl");
                System.out.println("n         : " + pk.n);
                System.out.println("s[0..4]   : " + java.util.Arrays.toString(java.util.Arrays.copyOf(pk.s, 5)));
                System.out.println("C[0..4]   : " + java.util.Arrays.toString(java.util.Arrays.copyOf(c, 5)));
            } else {
                throw new CliError("pkey: specify --pubout or --text");
            }
            return;
        }

        String algo = algoForPrivLabel(block.label);
        Codec.PrivKey pk = Codec.decodePrivKey(pemIn, block.label);

        if (opt.containsKey("pubout")) {
            String pem = Codec.encodePubKey(pubLabel(algo), pk.pub);
            writeString(out, pem);
        } else if (opt.containsKey("text")) {
            int hexWidth = pk.nbits / 4;
            System.out.println("algorithm : " + algo);
            System.out.println("bits      : " + pk.nbits);
            System.out.println("private   : " + hex(pk.priv, hexWidth));
            System.out.println("public    : " + hex(pk.pub, hexWidth));
        } else {
            throw new CliError("pkey: specify --pubout or --text");
        }
    }

    // -----------------------------------------------------------------
    // kex (hkex-gf only)
    // -----------------------------------------------------------------

    private static void cmdKex(Map<String, String> opt) throws IOException {
        String algo = req(opt, "algo", "kex");
        if (algo.equals("hkex-rnl")) {
            cmdKexRnl(opt);
            return;
        }
        if (!algo.equals("hkex-gf")) {
            throw new CliError("kex: unsupported --algo " + algo + " (this Java CLI covers hkex-gf, hkex-rnl)");
        }
        String ourPath = req(opt, "our", "kex");
        String theirPath = req(opt, "their", "kex");
        String out = req(opt, "out", "kex");

        String ourPem = readString(ourPath);
        Codec.PemBlock ourBlock = Codec.pemUnwrap(ourPem);
        Codec.PrivKey our = Codec.decodePrivKey(ourPem, ourBlock.label);

        String theirPem = readString(theirPath);
        Codec.PemBlock theirBlock = Codec.pemUnwrap(theirPem);
        Codec.PubKey their = Codec.decodePubKey(theirPem, theirBlock.label);

        if (our.nbits != their.nbits) {
            throw new CliError("kex: bit-size mismatch (ours=" + our.nbits + ", theirs=" + their.nbits + ")");
        }
        BigInteger sk = Herradura.hkexGfAgree(our.priv, their.pub);
        if (sk == null) {
            throw new CliError("kex: peer public key is degenerate (identity or zero)");
        }
        String pem = Codec.encodeSessionKey(sk, our.nbits);
        writeString(out, pem);
    }

    /** HKEX-RNL is two-round: Bob (our=Bob priv, their=Alice pub) responds
     * first with an RNL RESPONSE PEM; Alice (our=Alice priv, their=Bob's
     * RNL RESPONSE) completes the handshake into a plain SESSION KEY PEM. */
    private static void cmdKexRnl(Map<String, String> opt) throws IOException {
        String ourPath = req(opt, "our", "kex");
        String theirPath = req(opt, "their", "kex");
        String out = req(opt, "out", "kex");

        String ourPem = readString(ourPath);
        Codec.PemBlock ourBlock = Codec.pemUnwrap(ourPem);
        if (!ourBlock.label.equals(Codec.PEM_HKEX_RNL_PRIV)) {
            throw new CliError("kex hkex-rnl: --our must be an HKEX-RNL PRIVATE KEY, got " + ourBlock.label);
        }
        Codec.RnlPrivKey our = Codec.decodeRnlPrivKey(ourPem);

        String theirPem = readString(theirPath);
        Codec.PemBlock theirBlock = Codec.pemUnwrap(theirPem);

        if (theirBlock.label.equals(Codec.PEM_HKEX_RNL_PUB)) {
            // ── STEP 1: Bob responds to Alice's public key ──────────────
            Codec.RnlPubKey their = Codec.decodeRnlPubKey(theirPem);
            if (our.n != their.n) {
                throw new CliError("kex hkex-rnl: ring size mismatch (ours=" + our.n + ", theirs=" + their.n + ")");
            }
            if (!HerraduraNl.rnlValidateMBlind(their.mBlind, HerraduraNl.RNLQ)) {
                throw new CliError("kex hkex-rnl: peer m_blind failed entropy check — possible substitution attack");
            }
            int[] cB = HerraduraNl.hkexRnlDeriveC(their.mBlind, our.s, our.n);
            HerraduraNl.RnlAgreeResult agree = HerraduraNl.rnlAgree(
                our.s, their.c, HerraduraNl.RNLQ, HerraduraNl.RNLP, HerraduraNl.RNLPP, our.n, our.n);
            byte[] nB = new byte[32];
            RNG.nextBytes(nB);
            BigInteger kB = HerraduraNl.rnlContributoryKdf(agree.key, our.n, their.nA, nB);
            writeString(out, Codec.encodeRnlResponse(kB, cB, agree.hint, our.n, nB));
        } else if (theirBlock.label.equals(Codec.PEM_RNL_RESPONSE)) {
            // ── STEP 2: Alice completes the handshake ────────────────────
            Codec.RnlResponse resp = Codec.decodeRnlResponse(theirPem);
            if (our.n != resp.n) {
                throw new CliError("kex hkex-rnl: ring size mismatch (ours=" + our.n + ", response=" + resp.n + ")");
            }
            BigInteger kA = HerraduraNl.rnlAgree(
                our.s, resp.cB, HerraduraNl.RNLQ, HerraduraNl.RNLP, HerraduraNl.RNLPP, our.n, our.n, resp.hint);
            BigInteger kAInt = HerraduraNl.rnlContributoryKdf(kA, our.n, our.nA, resp.nB);
            writeString(out, Codec.encodeSessionKey(kAInt, our.n));
        } else {
            throw new CliError("kex hkex-rnl: --their must be an HKEX-RNL PUBLIC KEY or RESPONSE PEM, got "
                + theirBlock.label);
        }
    }

    // -----------------------------------------------------------------
    // enc / dec (hske symmetric, hpke asymmetric)
    // -----------------------------------------------------------------

    /** Symmetric-ciphertext DER: SEQUENCE(format_tag=0, E, nbits) — matches
     * HerraduraCli/herradura.py's _encode_sym_ct's format-tag-0 case (no
     * nonce/tag; hske-nla1/nla2's tagged variants are out of scope here). */
    private static String encodeSymCt(BigInteger e, int nbits) {
        byte[] der = Codec.derSeq(Codec.derInt(BigInteger.ZERO, -1),
                                   Codec.derInt(e, nbits / 8),
                                   Codec.derInt(BigInteger.valueOf(nbits), -1));
        return Codec.pemWrap(Codec.PEM_CIPHERTEXT, der);
    }

    /** Symmetric-ciphertext DER with a nonce, format tag 1 — matches
     * HerraduraCli/herradura.py's _encode_sym_ct's hske-nla1 (non-AEAD) case. */
    private static String encodeSymCtNonce(BigInteger e, BigInteger nonce, int nbits) {
        byte[] der = Codec.derSeq(Codec.derInt(BigInteger.ONE, -1),
                                   Codec.derInt(nonce, nbits / 8),
                                   Codec.derInt(e, nbits / 8),
                                   Codec.derInt(BigInteger.valueOf(nbits), -1));
        return Codec.pemWrap(Codec.PEM_CIPHERTEXT, der);
    }

    /** Returns {E, nbits, nonce_or_null} (format tag 0 or 1). Format tag 2
     * (hske-nla1 AEAD) is out of this Java CLI's scope. */
    private static BigInteger[] decodeSymCt(String pem) {
        Codec.PemBlock b = Codec.pemUnwrap(pem);
        if (!b.label.equals(Codec.PEM_CIPHERTEXT)) {
            throw new CliError("expected " + Codec.PEM_CIPHERTEXT + ", got " + b.label);
        }
        List<BigInteger> ints = Codec.derParseSeq(b.der);
        int formatTag = ints.get(0).intValueExact();
        if (formatTag == 0) {
            return new BigInteger[] { ints.get(1), ints.get(2), null }; // E, nbits
        } else if (formatTag == 1) {
            return new BigInteger[] { ints.get(2), ints.get(3), ints.get(1) }; // E, nbits, nonce
        } else {
            throw new CliError("hske ciphertext has format tag " + formatTag
                + " (the AEAD variant is out of this Java CLI's scope)");
        }
    }

    private static void cmdEnc(Map<String, String> opt) throws IOException {
        String algo = req(opt, "algo", "enc");
        byte[] inBytes = readBytes(req(opt, "in", "enc"));
        String out = req(opt, "out", "enc");

        if (algo.equals("hske")) {
            BigInteger[] key = loadKey(req(opt, "key", "enc"));
            int nbits = key[1].intValueExact();
            int nbytes = nbits / 8;
            BigInteger p = new BigInteger(1, padTrunc(inBytes, nbytes));
            BigInteger e = Herradura.hskeEncrypt(p, key[0]);
            writeString(out, encodeSymCt(e, nbits));
        } else if (algo.equals("hske-nla1")) {
            BigInteger[] key = loadKey(req(opt, "key", "enc"));
            int nbits = key[1].intValueExact();
            int nbytes = nbits / 8;
            BigInteger p = new BigInteger(1, padTrunc(inBytes, nbytes));
            BigInteger nonce = new BigInteger(nbits, RNG).and(Herradura.MASK);
            BigInteger e = HerraduraNl.hskeNlA1Encrypt(p, key[0], nonce);
            writeString(out, encodeSymCtNonce(e, nonce, nbits));
        } else if (algo.equals("hske-nla2")) {
            BigInteger[] key = loadKey(req(opt, "key", "enc"));
            int nbits = key[1].intValueExact();
            if (nbits != Herradura.N || !HerraduraNl.nlV2KeyIsValid(key[0])) {
                throw new CliError("enc hske-nla2: key is degenerate for NL-FSCX v2 (affine-weak class)");
            }
            int nbytes = nbits / 8;
            BigInteger p = new BigInteger(1, padTrunc(inBytes, nbytes));
            BigInteger e = HerraduraNl.hskeNlA2Encrypt(p, key[0]);
            writeString(out, encodeSymCt(e, nbits));
        } else if (algo.equals("hpke")) {
            String pubPath = req(opt, "pubkey", "enc");
            String pubPem = readString(pubPath);
            Codec.PemBlock pubBlock = Codec.pemUnwrap(pubPem);
            Codec.PubKey pub = Codec.decodePubKey(pubPem, pubBlock.label);
            int nbytes = pub.nbits / 8;
            BigInteger p = new BigInteger(1, padTrunc(inBytes, nbytes));
            Herradura.Ciphertext ct = Herradura.hpkeEncrypt(p, pub.pub, RNG);
            if (ct == null) throw new CliError("enc: recipient public key is degenerate");
            writeString(out, Codec.encodeAsymCt(ct.r, ct.ct, pub.nbits));
        } else if (algo.equals("hpke-nl")) {
            String pubPath = req(opt, "pubkey", "enc");
            String pubPem = readString(pubPath);
            Codec.PemBlock pubBlock = Codec.pemUnwrap(pubPem);
            Codec.PubKey pub = Codec.decodePubKey(pubPem, pubBlock.label);
            int nbytes = pub.nbits / 8;
            BigInteger p = new BigInteger(1, padTrunc(inBytes, nbytes));
            Herradura.Ciphertext ct = HerraduraNl.hpkeNlEncrypt(p, pub.pub, RNG);
            if (ct == null) throw new CliError("enc: could not sample a non-degenerate ephemeral key");
            writeString(out, Codec.encodeAsymCt(ct.r, ct.ct, pub.nbits));
        } else {
            throw new CliError("enc: unsupported --algo " + algo
                + " (this Java CLI covers hske, hske-nla1, hske-nla2, hpke, hpke-nl)");
        }
    }

    private static void cmdDec(Map<String, String> opt) throws IOException {
        String algo = req(opt, "algo", "dec");
        String out = req(opt, "out", "dec");

        if (algo.equals("hske")) {
            BigInteger[] key = loadKey(req(opt, "key", "dec"));
            int nbits = key[1].intValueExact();
            BigInteger[] ct = decodeSymCt(readString(req(opt, "in", "dec")));
            BigInteger d = Herradura.hskeDecrypt(ct[0], key[0]);
            writeBytes(out, toFixedBytes(d, nbits / 8));
        } else if (algo.equals("hske-nla1")) {
            BigInteger[] key = loadKey(req(opt, "key", "dec"));
            int nbits = key[1].intValueExact();
            BigInteger[] ct = decodeSymCt(readString(req(opt, "in", "dec")));
            if (ct[2] == null) throw new CliError("hske-nla1 ciphertext missing nonce");
            BigInteger d = HerraduraNl.hskeNlA1Decrypt(ct[0], key[0], ct[2]);
            writeBytes(out, toFixedBytes(d, nbits / 8));
        } else if (algo.equals("hske-nla2")) {
            BigInteger[] key = loadKey(req(opt, "key", "dec"));
            int nbits = key[1].intValueExact();
            if (nbits != Herradura.N || !HerraduraNl.nlV2KeyIsValid(key[0])) {
                throw new CliError("dec hske-nla2: key is degenerate for NL-FSCX v2 (affine-weak class)");
            }
            BigInteger[] ct = decodeSymCt(readString(req(opt, "in", "dec")));
            BigInteger d = HerraduraNl.hskeNlA2Decrypt(ct[0], key[0]);
            writeBytes(out, toFixedBytes(d, nbits / 8));
        } else if (algo.equals("hpke")) {
            BigInteger[] key = loadKey(req(opt, "key", "dec"));
            int nbits = key[1].intValueExact();
            Codec.AsymCt ct = Codec.decodeAsymCt(readString(req(opt, "in", "dec")));
            BigInteger d = Herradura.hpkeDecrypt(ct.e, ct.r, key[0]);
            if (d == null) throw new CliError("dec: ephemeral public value is degenerate");
            writeBytes(out, toFixedBytes(d, nbits / 8));
        } else if (algo.equals("hpke-nl")) {
            BigInteger[] key = loadKey(req(opt, "key", "dec"));
            int nbits = key[1].intValueExact();
            Codec.AsymCt ct = Codec.decodeAsymCt(readString(req(opt, "in", "dec")));
            BigInteger d = HerraduraNl.hpkeNlDecrypt(ct.e, ct.r, key[0]);
            if (d == null) throw new CliError("dec: ephemeral public value is degenerate or key is affine-weak");
            writeBytes(out, toFixedBytes(d, nbits / 8));
        } else {
            throw new CliError("dec: unsupported --algo " + algo
                + " (this Java CLI covers hske, hske-nla1, hske-nla2, hpke, hpke-nl)");
        }
    }

    /** Loads a private key PEM and returns {priv, BigInteger(nbits)}. */
    private static BigInteger[] loadKey(String path) throws IOException {
        String pem = readString(path);
        Codec.PemBlock block = Codec.pemUnwrap(pem);
        // A raw session-key PEM (from `kex`) has no dedicated decode helper
        // distinct from PubKey's shape (value, nbits) — reuse it.
        if (block.label.equals(Codec.PEM_SESSION_KEY)) {
            Codec.PubKey sk = Codec.decodeSessionKey(pem);
            return new BigInteger[] { sk.pub, BigInteger.valueOf(sk.nbits) };
        }
        Codec.PrivKey pk = Codec.decodePrivKey(pem, block.label);
        return new BigInteger[] { pk.priv, BigInteger.valueOf(pk.nbits) };
    }

    // -----------------------------------------------------------------
    // sign / verify (hpks only)
    // -----------------------------------------------------------------

    private static void cmdSign(Map<String, String> opt) throws IOException {
        String algo = req(opt, "algo", "sign");
        if (!algo.equals("hpks") && !algo.equals("hpks-nl")) {
            throw new CliError("sign: unsupported --algo " + algo + " (this Java CLI covers hpks, hpks-nl)");
        }
        String keyPath = req(opt, "key", "sign");
        byte[] msg = readBytes(req(opt, "in", "sign"));
        String out = req(opt, "out", "sign");

        String pem = readString(keyPath);
        Codec.PemBlock block = Codec.pemUnwrap(pem);
        Codec.PrivKey pk = Codec.decodePrivKey(pem, block.label);
        BigInteger msgInt = new BigInteger(1, padTrunc(msg, pk.nbits / 8));
        if (algo.equals("hpks")) {
            Herradura.Signature sig = Herradura.hpksSign(msgInt, pk.priv, RNG);
            writeString(out, Codec.encodeSchnorrSig(sig.s, sig.r,
                Herradura.fscxRevolve(sig.r, msgInt, Herradura.I_STEPS), pk.nbits));
        } else {
            Herradura.Signature sig = HerraduraNl.hpksNlSign(msgInt, pk.priv, RNG);
            writeString(out, Codec.encodeSchnorrSig(sig.s, sig.r,
                Hfscx256.nlFscxRevolveV1(sig.r, msgInt, Herradura.I_STEPS), pk.nbits));
        }
    }

    private static void cmdVerify(Map<String, String> opt) throws IOException {
        String algo = req(opt, "algo", "verify");
        if (!algo.equals("hpks") && !algo.equals("hpks-nl")) {
            throw new CliError("verify: unsupported --algo " + algo + " (this Java CLI covers hpks, hpks-nl)");
        }
        String pubPath = req(opt, "pubkey", "verify");
        byte[] msg = readBytes(req(opt, "in", "verify"));
        String sigPath = req(opt, "sig", "verify");

        String pubPem = readString(pubPath);
        Codec.PemBlock pubBlock = Codec.pemUnwrap(pubPem);
        Codec.PubKey pub = Codec.decodePubKey(pubPem, pubBlock.label);
        Codec.SchnorrSig sig = Codec.decodeSchnorrSig(readString(sigPath));
        BigInteger msgInt = new BigInteger(1, padTrunc(msg, pub.nbits / 8));

        boolean ok = algo.equals("hpks")
            ? Herradura.hpksVerify(msgInt, pub.pub, sig.r, sig.s)
            : HerraduraNl.hpksNlVerify(msgInt, pub.pub, sig.r, sig.s);
        if (ok) {
            System.out.println("Signature OK");
        } else {
            System.out.println("Verification FAILED");
            System.exit(1);
        }
    }

    // -----------------------------------------------------------------
    // dgst (hfscx-256 / hfscx-256-ds)
    // -----------------------------------------------------------------

    private static void cmdDgst(Map<String, String> opt) throws IOException {
        String algo = opt.getOrDefault("algo", "hfscx-256");
        byte[] inBytes = readBytes(req(opt, "in", "dgst"));
        String out = opt.getOrDefault("out", "-");

        byte[] digest;
        if (algo.equals("hfscx-256")) {
            digest = Hfscx256.hash(inBytes);
        } else if (algo.equals("hfscx-256-ds")) {
            // ds=0x01 domain separation, matching hfscx_256_ds(0x01, data) — implemented
            // as a one-byte-prefixed hash, mirroring the suite's construction.
            byte[] tagged = new byte[inBytes.length + 1];
            tagged[0] = 0x01;
            System.arraycopy(inBytes, 0, tagged, 1, inBytes.length);
            digest = Hfscx256.hash(tagged);
        } else {
            throw new CliError("dgst: unsupported --algo " + algo);
        }

        if (out.equals("-")) {
            System.out.println(hexBytes(digest));
        } else {
            byte[] der = Codec.derSeq(Codec.derInt(new BigInteger(1, digest), 32));
            writeString(out, Codec.pemWrap(Codec.PEM_DIGEST, der));
        }
    }

    // -----------------------------------------------------------------
    // encfile / decfile (hske-nla1 .hkx container)
    // -----------------------------------------------------------------

    private static void cmdEncfile(Map<String, String> opt) throws IOException {
        String algo = opt.getOrDefault("algo", "hske-nla1");
        if (!algo.equals("hske-nla1")) {
            throw new CliError("encfile: unsupported --algo " + algo + " (only hske-nla1 is supported)");
        }
        BigInteger[] key = loadKey(req(opt, "key", "encfile"));
        if (key[1].intValueExact() != 256) {
            throw new CliError("encfile: key must be 256-bit; got " + key[1] + "-bit");
        }
        byte[] pt = readBytes(req(opt, "in", "encfile"));
        byte[] out = Hfscx256.encFile(key[0], pt, RNG);
        writeBytes(req(opt, "out", "encfile"), out);
    }

    private static void cmdDecfile(Map<String, String> opt) throws IOException {
        String algo = opt.getOrDefault("algo", "hske-nla1");
        if (!algo.equals("hske-nla1")) {
            throw new CliError("decfile: unsupported --algo " + algo + " (only hske-nla1 is supported)");
        }
        BigInteger[] key = loadKey(req(opt, "key", "decfile"));
        if (key[1].intValueExact() != 256) {
            throw new CliError("decfile: key must be 256-bit; got " + key[1] + "-bit");
        }
        byte[] raw = readBytes(req(opt, "in", "decfile"));
        byte[] pt;
        try {
            pt = Hfscx256.decFile(key[0], raw);
        } catch (IllegalArgumentException e) {
            throw new CliError("decfile: " + e.getMessage());
        }
        writeBytes(req(opt, "out", "decfile"), pt);
    }

    // -----------------------------------------------------------------
    // I/O helpers ('-' means stdin/stdout, matching the other CLIs)
    // -----------------------------------------------------------------

    private static byte[] readBytes(String path) throws IOException {
        if (path.equals("-")) {
            InputStream in = System.in;
            java.io.ByteArrayOutputStream buf = new java.io.ByteArrayOutputStream();
            byte[] chunk = new byte[8192];
            int n;
            while ((n = in.read(chunk)) >= 0) buf.write(chunk, 0, n);
            return buf.toByteArray();
        }
        return Files.readAllBytes(Paths.get(path));
    }

    private static String readString(String path) throws IOException {
        return new String(readBytes(path), java.nio.charset.StandardCharsets.US_ASCII);
    }

    private static void writeBytes(String path, byte[] data) throws IOException {
        if (path.equals("-")) {
            OutputStream out = System.out;
            out.write(data);
            out.flush();
            return;
        }
        Files.write(Paths.get(path), data);
    }

    private static void writeString(String path, String data) throws IOException {
        writeBytes(path, data.getBytes(java.nio.charset.StandardCharsets.US_ASCII));
    }

    private static byte[] padTrunc(byte[] data, int nbytes) {
        byte[] out = new byte[nbytes];
        System.arraycopy(data, 0, out, 0, Math.min(nbytes, data.length));
        return out;
    }

    private static byte[] toFixedBytes(BigInteger v, int nbytes) {
        byte[] raw = v.toByteArray();
        byte[] out = new byte[nbytes];
        int rawStart = Math.max(0, raw.length - nbytes);
        int copyLen = raw.length - rawStart;
        System.arraycopy(raw, rawStart, out, nbytes - copyLen, copyLen);
        return out;
    }

    private static String hex(BigInteger v, int width) {
        String h = v.toString(16);
        if (h.length() < width) {
            StringBuilder sb = new StringBuilder();
            for (int i = h.length(); i < width; i++) sb.append('0');
            h = sb.append(h).toString();
        }
        return h;
    }

    private static String hexBytes(byte[] b) {
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte x : b) sb.append(String.format("%02x", x));
        return sb.toString();
    }
}
