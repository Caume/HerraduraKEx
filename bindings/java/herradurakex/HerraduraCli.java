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
 * hske-nla1, hske-nla2, hske-nla3, hpks-nl, hpke-nl, hpke-nl3 — {@link HerraduraNl}). dgst and
 * encfile/decfile additionally use the NL-FSCX-based HFSCX-256 hash and
 * HSKE-NL-A1 file container ({@link Hfscx256}) for wire-format parity with
 * the other CLIs.
 *
 * Also covers HPKS-Stern-F/HPKE-Stern-F (demo Stern-F code-based PQC,
 * {@code --algo hpks-stern}/{@code hpke-stern}) and HPKE-Stern-KEM (the
 * real QC-MDPC/BGF Niederreiter KEM, {@code --algo hpke-stern-kem} —
 * {@link Stern}, TODO #200), the OPRF (2HashDH over GF(2^256)*, {@code
 * oprf-blind}/{@code oprf-eval}/{@code oprf-unblind} — {@link Oprf}),
 * HPKS-WOTS-F/HPKS-XMSS-F (one-time and stateful multi-use hash-based
 * signatures, {@code --algo hpks-wots}/{@code hpks-xmss} — {@link Wots},
 * {@link Xmss}, TODO #201), HCRED (the hybrid Ring-LWR + Stern-F
 * credential, {@code --algo hcred} plus {@code cred-issue}/
 * {@code cred-prove}/{@code cred-verify} — {@link Hcred}, TODO #202), and
 * aPAKE (augmented PAKE over HKEX-RNL + OPRF + ZKBoo-NL,
 * {@code pake-register}/{@code pake-demo} — {@link Hpake}, TODO #203).
 *
 * Also covers {@code fpe}/{@code twk} (78.A/78.B, plus their {@code --v3}
 * variants, TODO #255/#260 — {@link FpeTwk}): a 32-byte-block tweak cipher
 * and a tweakable wide-block cipher, both keyed by a session key PEM (the
 * same shape {@code enc}/{@code dec} use for {@code hske}).
 *
 * Out of scope (beyond this point): the standalone HPKS-ZKP-NL/ZKP-RNL
 * signature schemes, rnl-sigma, hybrid-rnl-stern, the Stern-Ring
 * OR-composition signature, the research {@code duplex} AEAD, HPKS-T, and
 * the {@code --kdf}/{@code --aead} CLI options (TODO #260 tracks closing
 * these gaps).
 *
 * Subcommands: genpkey, pkey, kex, enc, dec, sign, verify, dgst, encfile,
 * decfile, fpe, twk. PEM/DER wire format is byte-for-byte compatible with the
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
            throw new CliError("usage: herradurakex <genpkey|pkey|kex|enc|dec|sign|verify|dgst|encfile|decfile"
                + "|fpe|twk"
                + "|oprf-blind|oprf-eval|oprf-unblind|cred-issue|cred-prove|cred-verify"
                + "|pake-register|pake-demo> [options]");
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
            case "fpe":     cmdFpe(opt);     break;
            case "twk":     cmdTwk(opt);     break;
            case "oprf-blind":   cmdOprfBlind(opt);   break;
            case "oprf-eval":    cmdOprfEval(opt);    break;
            case "oprf-unblind": cmdOprfUnblind(opt); break;
            case "cred-issue":   cmdCredIssue(opt);   break;
            case "cred-prove":   cmdCredProve(opt);   break;
            case "cred-verify":  cmdCredVerify(opt);  break;
            case "pake-register": cmdPakeRegister(opt); break;
            case "pake-demo":     cmdPakeDemo(opt);     break;
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

    /**
     * RAW reconciliation width for an HKEX-RNL ring of dimension n (TODO #223).
     * Reconciliation takes 2 bits from each of keyBits/2 coefficients, so a ring
     * of n coefficients supplies at most 2n key bits.  Since TODO #223 the ring
     * dimension (RNLN = 1024) and the key width (256) are separate; a small demo
     * ring can only supply n raw bits.
     *
     * <p>This is the width of K_raw — the contributory KDF's input — not the
     * width of the session key it returns.  See {@link #rnlSessionBits(int)}.
     */
    private static int rnlKeyBits(int n) {
        return n >= 256 ? 256 : n;
    }

    /**
     * DERIVED session-key width for HKEX-RNL: always 256, whatever the ring
     * dimension (TODO #228).  {@code rnlContributoryKdf} returns a whole
     * HFSCX-256 digest, and the ring only bounds how much raw entropy feeds
     * into it.  Labelling the session key with {@code rnlKeyBits(n)} put a
     * 256-bit key under an {@code nbits=64} label below n=256, where each CLI
     * then reconciled the mismatch differently.  At n &gt;= 256 the two
     * functions coincide, so the deployed n=1024 wire format is unchanged.
     *
     * <p>{@code n} is accepted and ignored so call sites read symmetrically
     * with {@code rnlKeyBits}.  HKEX-GF is genuinely nbits-wide and must not
     * use this.
     */
    private static int rnlSessionBits(int n) {
        return 256;
    }

    private static String privLabel(String algo) {
        switch (algo) {
            case "hkex-gf":  return Codec.PEM_HKEX_GF_PRIV;
            case "hpks":     return Codec.PEM_HPKS_PRIV;
            case "hpks-nl":  return Codec.PEM_HPKS_NL_PRIV;
            case "hpke":     return Codec.PEM_HPKE_PRIV;
            case "hpke-nl":  return Codec.PEM_HPKE_NL_PRIV;
            case "hpke-nl3": return Codec.PEM_HPKE_NL3_PRIV;
            case "hkex-rnl": return Codec.PEM_HKEX_RNL_PRIV;
            default: throw new CliError("genpkey: unsupported --algo " + algo
                + " (this Java CLI covers the classical quartet plus hkex-rnl, "
                + "hske-nla1/nla2/nla3, hpks-nl, hpke-nl, hpke-nl3)");
        }
    }

    private static String pubLabel(String algo) {
        switch (algo) {
            case "hkex-gf":  return Codec.PEM_HKEX_GF_PUB;
            case "hpks":     return Codec.PEM_HPKS_PUB;
            case "hpks-nl":  return Codec.PEM_HPKS_NL_PUB;
            case "hpke":     return Codec.PEM_HPKE_PUB;
            case "hpke-nl":  return Codec.PEM_HPKE_NL_PUB;
            case "hpke-nl3": return Codec.PEM_HPKE_NL3_PUB;
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
        if (label.equals(Codec.PEM_HPKE_NL3_PRIV)) return "hpke-nl3";
        throw new CliError("unrecognized private-key label: " + label);
    }


    // -----------------------------------------------------------------
    // genpkey
    // -----------------------------------------------------------------

    private static void cmdGenpkey(Map<String, String> opt) throws IOException {
        String algo = req(opt, "algo", "genpkey");
        String out = opt.getOrDefault("out", "-");

        if (algo.equals("hpks-stern") || algo.equals("hpke-stern")) {
            sternDemoWarning();
            Stern.SternKeypair kp = Stern.sternFKeygen(RNG);
            String label = algo.equals("hpks-stern") ? Codec.PEM_HPKS_STERN_PRIV : Codec.PEM_HPKE_STERN_PRIV;
            writeString(out, Codec.encodeSternPrivKey(label, kp.e, kp.seed));
            return;
        }
        if (algo.equals("hpke-stern-kem")) {
            Stern.QcMdpcKeypair kp = Stern.qcmdpcKeygen(RNG);
            writeString(out, Codec.encodeKemPrivKey(kp.h0, kp.h1, kp.sup0, kp.sup1));
            return;
        }
        if (algo.equals("oprf")) {
            writeString(out, Codec.encodeOprfPrivKey(Oprf.keygen(RNG)));
            return;
        }
        if (algo.equals("hpks-wots")) {
            byte[] masterSeed = new byte[32];
            RNG.nextBytes(masterSeed);
            writeString(out, Codec.encodeWotsPrivKey(masterSeed, 0));
            writeIdxState(out, 0); // 0 = unused (one-time key)
            System.err.println("HPKS-WOTS: ONE-TIME key — it may sign exactly one message.");
            return;
        }
        if (algo.equals("hcred")) {
            int[] mBase = HerraduraNl.rnlMPoly(Herradura.N);
            int[] aRand = HerraduraNl.rnlRandPoly(Herradura.N, HerraduraNl.RNLQ, RNG);
            int[] mBlind = HerraduraNl.rnlPolyAdd(mBase, aRand, HerraduraNl.RNLQ);
            Hcred.UserKeypair kp = Hcred.userKeygen(mBlind, RNG);
            BigInteger seedH = new BigInteger(Herradura.N, RNG).and(Herradura.MASK);
            BigInteger syndr = Hcred.syndrome(seedH, kp.e);
            writeString(out, Codec.encodeHcredPrivKey(kp.s, kp.c, mBlind, seedH, syndr));
            return;
        }
        if (algo.equals("hpks-xmss")) {
            int h = opt.containsKey("xmss-height") ? Integer.parseInt(opt.get("xmss-height")) : Xmss.DEFAULT_H;
            System.err.println("Generating XMSS tree (h=" + h + ", " + (1 << h) + " leaves) — may take a moment...");
            byte[] masterSeed = new byte[32];
            RNG.nextBytes(masterSeed);
            Xmss.Keypair kp = Xmss.keygen(masterSeed, h);
            writeString(out, Codec.encodeXmssPrivKey(masterSeed, h, 0, kp.leafHashes));
            writeIdxState(out, 0);
            return;
        }

        if (algo.equals("hkex-rnl")) {
            // Ring dimension is independent of the derived key width (TODO #223).
            int n = HerraduraNl.RNLN;
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

    /** Stern-F is demo/illustration-strength only at this binding's fixed
     * n=256/t=16 parameters (SecurityProofs-5.md Sec.11.8.4) — mirrors the
     * Python/C/Go CLIs' stderr warning on every stern genpkey/sign/verify/
     * enc/dec call (not printed for hpke-stern-kem, which is production-shaped). */
    private static void sternDemoWarning() {
        System.err.println("warning: HPKS-Stern-F/HPKE-Stern-F are demo-strength illustrations of a "
            + "code-based construction, not a production-hardened scheme at these parameters.");
    }

    // -----------------------------------------------------------------
    // pkey
    // -----------------------------------------------------------------

    private static void cmdPkey(Map<String, String> opt) throws IOException {
        String in = req(opt, "in", "pkey");
        String out = opt.getOrDefault("out", "-");
        String pemIn = readString(in);
        Codec.PemBlock block = Codec.pemUnwrap(pemIn);

        if (block.label.equals(Codec.PEM_HPKS_STERN_PRIV) || block.label.equals(Codec.PEM_HPKE_STERN_PRIV)) {
            sternDemoWarning();
            Codec.SternPrivKey pk = Codec.decodeSternPrivKey(pemIn, block.label);
            BigInteger syndrome = Stern.sternSyndrome(pk.seed, pk.e);
            String pubLabel = block.label.equals(Codec.PEM_HPKS_STERN_PRIV) ? Codec.PEM_HPKS_STERN_PUB : Codec.PEM_HPKE_STERN_PUB;
            if (opt.containsKey("pubout")) {
                writeString(out, Codec.encodeSternPubKey(pubLabel, syndrome, pk.seed));
            } else if (opt.containsKey("text")) {
                System.out.println("algorithm : " + (block.label.equals(Codec.PEM_HPKS_STERN_PRIV) ? "hpks-stern" : "hpke-stern"));
                System.out.println("bits      : " + pk.nbits);
                System.out.println("seed      : " + hex(pk.seed, pk.nbits / 4));
                System.out.println("syndrome  : " + hex(syndrome, pk.nbits / 8));
            } else {
                throw new CliError("pkey: specify --pubout or --text");
            }
            return;
        }

        if (block.label.equals(Codec.PEM_HPKE_STERN_KEM_PRIV)) {
            Codec.KemPrivKey pk = Codec.decodeKemPrivKey(pemIn);
            BigInteger hPub = Stern.qcmdpcPubFromPriv(pk.h0, pk.h1);
            if (opt.containsKey("pubout")) {
                writeString(out, Codec.encodeKemPubKey(hPub));
            } else if (opt.containsKey("text")) {
                System.out.println("algorithm : hpke-stern-kem");
                System.out.println("r         : " + pk.r);
                System.out.println("d         : " + pk.d);
                System.out.println("h_pub     : " + hPub.toString(16));
            } else {
                throw new CliError("pkey: specify --pubout or --text");
            }
            return;
        }

        if (block.label.equals(Codec.PEM_HPKS_XMSS_PRIV)) {
            Codec.XmssPrivKey pk = Codec.decodeXmssPrivKey(pemIn);
            if (opt.containsKey("pubout")) {
                writeString(out, Codec.encodeXmssPubKey(pk.root, pk.h));
            } else if (opt.containsKey("text")) {
                System.out.println("algorithm : hpks-xmss");
                System.out.println("h         : " + pk.h + " (" + (1 << pk.h) + " leaves)");
                System.out.println("root      : " + hexBytes(pk.root));
            } else {
                throw new CliError("pkey: specify --pubout or --text");
            }
            return;
        }

        if (block.label.equals(Codec.PEM_HPKS_WOTS_PRIV)) {
            Codec.WotsPrivKey pk = Codec.decodeWotsPrivKey(pemIn);
            if (opt.containsKey("pubout")) {
                Wots.Keypair kp = Wots.keygen(pk.masterSeed, pk.leafIdx);
                writeString(out, Codec.encodeWotsPubKey(kp.pk));
            } else if (opt.containsKey("text")) {
                System.out.println("algorithm : hpks-wots");
                System.out.println("leaf_idx  : " + pk.leafIdx);
            } else {
                throw new CliError("pkey: specify --pubout or --text");
            }
            return;
        }

        if (block.label.equals(Codec.PEM_HCRED_PRIV)) {
            Codec.HcredPrivKey pk = Codec.decodeHcredPrivKey(pemIn);
            if (opt.containsKey("pubout")) {
                writeString(out, Codec.encodeHcredPubKey(pk.c, pk.m, pk.seedH, pk.syndr));
            } else if (opt.containsKey("text")) {
                System.out.println("algorithm : hcred");
                System.out.println("n         : " + pk.n);
                System.out.println("W (weight): " + Hcred.phi(pk.s).bitCount());
            } else {
                throw new CliError("pkey: specify --pubout or --text");
            }
            return;
        }

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
                our.s, their.c, HerraduraNl.RNLQ, HerraduraNl.RNLP, HerraduraNl.RNLPP,
                our.n, rnlKeyBits(our.n));
            byte[] nB = new byte[32];
            RNG.nextBytes(nB);
            BigInteger kB = HerraduraNl.rnlContributoryKdf(agree.key, rnlKeyBits(our.n), their.nA, nB);
            writeString(out, Codec.encodeRnlResponse(kB, cB, agree.hint, our.n, nB));
        } else if (theirBlock.label.equals(Codec.PEM_RNL_RESPONSE)) {
            // ── STEP 2: Alice completes the handshake ────────────────────
            Codec.RnlResponse resp = Codec.decodeRnlResponse(theirPem);
            if (our.n != resp.n) {
                throw new CliError("kex hkex-rnl: ring size mismatch (ours=" + our.n + ", response=" + resp.n + ")");
            }
            BigInteger kA = HerraduraNl.rnlAgree(
                our.s, resp.cB, HerraduraNl.RNLQ, HerraduraNl.RNLP, HerraduraNl.RNLPP,
                our.n, rnlKeyBits(our.n), resp.hint);
            BigInteger kAInt = HerraduraNl.rnlContributoryKdf(kA, rnlKeyBits(our.n), our.nA, resp.nB);
            writeString(out, Codec.encodeSessionKey(kAInt, rnlSessionBits(our.n)));
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
        } else if (algo.equals("hske-nla3")) {
            // No key check: v3 has no weak class (TODO #255).
            BigInteger[] key = loadKey(req(opt, "key", "enc"));
            int nbits = key[1].intValueExact();
            if (nbits != Herradura.N) {
                throw new CliError("enc hske-nla3: requires a 256-bit key");
            }
            BigInteger p = new BigInteger(1, padTrunc(inBytes, nbits / 8));
            writeString(out, encodeSymCt(HerraduraNl.hskeNlA3Encrypt(p, key[0]), nbits));
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
        } else if (algo.equals("hpke-nl3")) {
            String pubPem = readString(req(opt, "pubkey", "enc"));
            Codec.PemBlock pubBlock = Codec.pemUnwrap(pubPem);
            Codec.PubKey pub = Codec.decodePubKey(pubPem, pubBlock.label);
            BigInteger p = new BigInteger(1, padTrunc(inBytes, pub.nbits / 8));
            Herradura.Ciphertext ct = HerraduraNl.hpkeNl3Encrypt(p, pub.pub, RNG);
            if (ct == null) throw new CliError("enc: recipient public key is degenerate");
            writeString(out, Codec.encodeAsymCt(ct.r, ct.ct, pub.nbits));
        } else if (algo.equals("hpke-stern")) {
            sternDemoWarning();
            String pubPem = readString(req(opt, "pubkey", "enc"));
            Codec.PemBlock pubBlock = Codec.pemUnwrap(pubPem);
            Codec.SternPubKey pub = Codec.decodeSternPubKey(pubPem, pubBlock.label);
            BigInteger p = new BigInteger(1, padTrunc(inBytes, pub.nbits / 8));
            Stern.SternEncapResult enc = Stern.hpkeSternFEncapWithE(pub.seed, RNG);
            BigInteger e = Herradura.fscxRevolve(p, enc.k, Herradura.I_STEPS);
            writeString(out, Codec.encodeSternCt(enc.ct, enc.eP, enc.k, e));
        } else if (algo.equals("hpke-stern-kem")) {
            String pubPem = readString(req(opt, "pubkey", "enc"));
            Codec.PemBlock pubBlock = Codec.pemUnwrap(pubPem);
            if (!pubBlock.label.equals(Codec.PEM_HPKE_STERN_KEM_PUB)) {
                throw new CliError("enc hpke-stern-kem: --pubkey must be an HPKE-STERN-KEM PUBLIC KEY, got " + pubBlock.label);
            }
            Codec.KemPubKey pub = Codec.decodeKemPubKey(pubPem);
            BigInteger p = new BigInteger(1, padTrunc(inBytes, Herradura.N / 8));
            Stern.QcMdpcEncapResult enc = Stern.qcmdpcEncap(pub.hPub, RNG);
            BigInteger e = Herradura.fscxRevolve(p, enc.k, Herradura.I_STEPS);
            writeString(out, Codec.encodeKemCt(enc.syn, e));
        } else {
            throw new CliError("enc: unsupported --algo " + algo
                + " (this Java CLI covers hske, hske-nla1, hske-nla2, hske-nla3, hpke, hpke-nl, hpke-nl3, hpke-stern, hpke-stern-kem)");
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
        } else if (algo.equals("hske-nla3")) {
            // No key check: v3 has no weak class (TODO #255).
            BigInteger[] key = loadKey(req(opt, "key", "dec"));
            int nbits = key[1].intValueExact();
            if (nbits != Herradura.N) {
                throw new CliError("dec hske-nla3: requires a 256-bit key");
            }
            BigInteger[] ct = decodeSymCt(readString(req(opt, "in", "dec")));
            writeBytes(out, toFixedBytes(
                HerraduraNl.hskeNlA3Decrypt(ct[0], key[0]), nbits / 8));
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
        } else if (algo.equals("hpke-nl3")) {
            BigInteger[] key = loadKey(req(opt, "key", "dec"));
            int nbits = key[1].intValueExact();
            Codec.AsymCt ct = Codec.decodeAsymCt(readString(req(opt, "in", "dec")));
            BigInteger d = HerraduraNl.hpkeNl3Decrypt(ct.e, ct.r, key[0]);
            if (d == null) throw new CliError("dec: ephemeral public value is degenerate");
            writeBytes(out, toFixedBytes(d, nbits / 8));
        } else if (algo.equals("hpke-stern")) {
            sternDemoWarning();
            String pem = readString(req(opt, "key", "dec"));
            Codec.PemBlock block = Codec.pemUnwrap(pem);
            Codec.SternPrivKey pk = Codec.decodeSternPrivKey(pem, block.label);
            Codec.SternCt ct = Codec.decodeSternCt(readString(req(opt, "in", "dec")));
            BigInteger k = Stern.hpkeSternFDecap(ct.eP, pk.seed);
            BigInteger d = Herradura.fscxRevolve(ct.e, k, Herradura.R_STEPS);
            writeBytes(out, toFixedBytes(d, pk.nbits / 8));
        } else if (algo.equals("hpke-stern-kem")) {
            String pem = readString(req(opt, "key", "dec"));
            Codec.PemBlock block = Codec.pemUnwrap(pem);
            if (!block.label.equals(Codec.PEM_HPKE_STERN_KEM_PRIV)) {
                throw new CliError("dec hpke-stern-kem: --key must be an HPKE-STERN-KEM PRIVATE KEY, got " + block.label);
            }
            Codec.KemPrivKey pk = Codec.decodeKemPrivKey(pem);
            Codec.KemCt ct = Codec.decodeKemCt(readString(req(opt, "in", "dec")));
            // Implicit rejection (TODO #235): no failure path — a DFR event
            // or a corrupt ciphertext decrypts to garbage rather than
            // reporting.
            BigInteger k = Stern.qcmdpcDecapBgf(ct.syn, pk.sup0, pk.sup1);
            BigInteger d = Herradura.fscxRevolve(ct.e, k, Herradura.R_STEPS);
            writeBytes(out, toFixedBytes(d, Herradura.N / 8));
        } else {
            throw new CliError("dec: unsupported --algo " + algo
                + " (this Java CLI covers hske, hske-nla1, hske-nla2, hske-nla3, hpke, hpke-nl, hpke-nl3, hpke-stern, hpke-stern-kem)");
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
        if (algo.equals("hpks-stern")) {
            sternDemoWarning();
            String keyPath = req(opt, "key", "sign");
            byte[] msg = readBytes(req(opt, "in", "sign"));
            String out = req(opt, "out", "sign");
            int rounds = opt.containsKey("rounds") ? Integer.parseInt(opt.get("rounds")) : Stern.SDFR;

            String pem = readString(keyPath);
            Codec.PemBlock block = Codec.pemUnwrap(pem);
            Codec.SternPrivKey pk = Codec.decodeSternPrivKey(pem, block.label);
            BigInteger msgInt = new BigInteger(1, padTrunc(msg, pk.nbits / 8));
            Stern.SternSignature sig = Stern.hpksSternFSign(msgInt, pk.e, pk.seed, rounds, RNG);
            writeString(out, Codec.encodeSternSig(sig));
            return;
        }
        if (algo.equals("hpks-xmss")) {
            String keyPath = req(opt, "key", "sign");
            byte[] msg = readBytes(req(opt, "in", "sign"));
            String out = req(opt, "out", "sign");
            Codec.XmssPrivKey pk = Codec.decodeXmssPrivKey(readString(keyPath));
            int leafIdx = readIdxState(keyPath);
            int numLeaves = 1 << pk.h;
            if (leafIdx >= numLeaves) {
                throw new CliError("sign: XMSS key exhausted (" + numLeaves + " leaves used). Generate a new key.");
            }
            Xmss.Signature sig = Xmss.sign(msg, pk.masterSeed, pk.leafHashes, leafIdx);
            writeString(out, Codec.encodeXmssSig(sig));
            writeIdxState(keyPath, leafIdx + 1);
            System.err.println("XMSS leaf " + leafIdx + " used; " + (numLeaves - leafIdx - 1) + " leaves remaining.");
            return;
        }
        if (algo.equals("hpks-wots")) {
            String keyPath = req(opt, "key", "sign");
            byte[] msg = readBytes(req(opt, "in", "sign"));
            String out = req(opt, "out", "sign");
            if (readIdxState(keyPath) != 0) {
                throw new CliError("sign: this HPKS-WOTS key was already used — WOTS keys are "
                    + "ONE-TIME. Generate a fresh key (genpkey --algo hpks-wots).");
            }
            Codec.WotsPrivKey pk = Codec.decodeWotsPrivKey(readString(keyPath));
            Wots.Signature sig = Wots.sign(msg, pk.masterSeed, pk.leafIdx);
            writeString(out, Codec.encodeWotsSig(sig.sig));
            writeIdxState(keyPath, 1);
            System.err.println("HPKS-WOTS key burned (one-time use); do not sign again with it.");
            return;
        }
        if (!algo.equals("hpks") && !algo.equals("hpks-nl")) {
            throw new CliError("sign: unsupported --algo " + algo + " (this Java CLI covers hpks, hpks-nl, hpks-stern, hpks-xmss, hpks-wots)");
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
        if (algo.equals("hpks-stern")) {
            sternDemoWarning();
            String pubPath = req(opt, "pubkey", "verify");
            byte[] msg = readBytes(req(opt, "in", "verify"));
            String sigPath = req(opt, "sig", "verify");

            String pubPem = readString(pubPath);
            Codec.PemBlock pubBlock = Codec.pemUnwrap(pubPem);
            Codec.SternPubKey pub = Codec.decodeSternPubKey(pubPem, pubBlock.label);
            Codec.SternSigDecoded sig = Codec.decodeSternSig(readString(sigPath));
            BigInteger msgInt = new BigInteger(1, padTrunc(msg, pub.nbits / 8));

            boolean ok = Stern.hpksSternFVerify(msgInt, sig.sig, pub.seed, pub.syndrome);
            if (ok) {
                System.out.println("Signature OK");
            } else {
                System.out.println("Verification FAILED");
                System.exit(1);
            }
            return;
        }
        if (algo.equals("hpks-xmss")) {
            Codec.XmssPubKey pub = Codec.decodeXmssPubKey(readString(req(opt, "pubkey", "verify")));
            byte[] msg = readBytes(req(opt, "in", "verify"));
            Xmss.Signature sig = Codec.decodeXmssSig(readString(req(opt, "sig", "verify")));
            boolean ok = Xmss.verify(msg, sig, pub.root);
            if (ok) { System.out.println("Signature OK"); } else { System.out.println("Verification FAILED"); System.exit(1); }
            return;
        }
        if (algo.equals("hpks-wots")) {
            BigInteger[] pub = Codec.decodeWotsPubKey(readString(req(opt, "pubkey", "verify")));
            byte[] msg = readBytes(req(opt, "in", "verify"));
            BigInteger[] sig = Codec.decodeWotsSig(readString(req(opt, "sig", "verify")));
            boolean ok = Wots.verify(msg, sig, pub);
            if (ok) { System.out.println("Signature OK"); } else { System.out.println("Verification FAILED"); System.exit(1); }
            return;
        }
        if (!algo.equals("hpks") && !algo.equals("hpks-nl")) {
            throw new CliError("verify: unsupported --algo " + algo + " (this Java CLI covers hpks, hpks-nl, hpks-stern, hpks-xmss, hpks-wots)");
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
    // fpe / twk (78.A / 78.B, TODO #260) — mirrors herradura.py's cmd_fpe /
    // cmd_twk and the C/Go CLIs' cmd_fpe / cmdFpe. NOT format-preserving in
    // the FF1/FF3-1 sense: 32 raw bytes in, 32 raw bytes out. --key takes a
    // HERRADURA SESSION KEY PEM (the same shape enc/dec use for hske); --v3
    // selects the NL-FSCX v3 round (TODO #255) instead of v2 — separate
    // subkey domain, so decrypt must pass --v3 too if encrypt did.
    // -----------------------------------------------------------------

    private static void cmdFpe(Map<String, String> opt) throws IOException {
        boolean doEnc = opt.containsKey("encrypt");
        boolean doDec = opt.containsKey("decrypt");
        if (doEnc == doDec) throw new CliError("fpe: exactly one of --encrypt or --decrypt required");
        BigInteger[] key = loadKey(req(opt, "key", "fpe"));
        byte[] keyBytes = toFixedBytes(key[0], key[1].intValueExact() / 8);
        byte[] ctx = opt.getOrDefault("context", "").getBytes(java.nio.charset.StandardCharsets.US_ASCII);
        byte[] inBytes = readBytes(req(opt, "in", "fpe"));
        BigInteger p = new BigInteger(1, padBlock(inBytes));
        boolean v3 = opt.containsKey("v3");
        BigInteger r = doEnc
            ? (v3 ? FpeTwk.fpeV3Encrypt(p, keyBytes, ctx) : FpeTwk.fpeEncrypt(p, keyBytes, ctx))
            : (v3 ? FpeTwk.fpeV3Decrypt(p, keyBytes, ctx) : FpeTwk.fpeDecrypt(p, keyBytes, ctx));
        writeBytes(opt.getOrDefault("out", "-"), toFixedBytes(r, Herradura.N / 8));
    }

    private static void cmdTwk(Map<String, String> opt) throws IOException {
        boolean doEnc = opt.containsKey("encrypt");
        boolean doDec = opt.containsKey("decrypt");
        if (doEnc == doDec) throw new CliError("twk: exactly one of --encrypt or --decrypt required");
        BigInteger[] key = loadKey(req(opt, "key", "twk"));
        byte[] keyBytes = toFixedBytes(key[0], key[1].intValueExact() / 8);
        long sector = opt.containsKey("sector") ? Long.parseLong(opt.get("sector")) : 0L;
        int bidx = opt.containsKey("bidx") ? Integer.parseInt(opt.get("bidx")) : 0;
        byte[] inBytes = readBytes(req(opt, "in", "twk"));
        BigInteger p = new BigInteger(1, padBlock(inBytes));
        boolean v3 = opt.containsKey("v3");
        BigInteger r = doEnc
            ? (v3 ? FpeTwk.twkV3Encrypt(p, keyBytes, sector, bidx) : FpeTwk.twkEncrypt(p, keyBytes, sector, bidx))
            : (v3 ? FpeTwk.twkV3Decrypt(p, keyBytes, sector, bidx) : FpeTwk.twkDecrypt(p, keyBytes, sector, bidx));
        writeBytes(opt.getOrDefault("out", "-"), toFixedBytes(r, Herradura.N / 8));
    }

    /** Right-pads (zero-fills) to a 32-byte block and truncates to it,
     * matching herradura.py's {@code in_bytes.ljust(32, b'\x00')[:32]}. */
    private static byte[] padBlock(byte[] in) {
        int blockLen = Herradura.N / 8;
        if (in.length == blockLen) return in;
        byte[] out = new byte[blockLen];
        System.arraycopy(in, 0, out, 0, Math.min(in.length, blockLen));
        return out;
    }

    // -----------------------------------------------------------------
    // oprf-blind / oprf-eval / oprf-unblind
    // -----------------------------------------------------------------

    private static void cmdOprfBlind(Map<String, String> opt) throws IOException {
        byte[] inBytes = readBytes(req(opt, "in", "oprf-blind"));
        String out = req(opt, "out", "oprf-blind");
        Oprf.Blinded b = Oprf.blind(inBytes, RNG);
        writeString(out, Codec.encodeOprfState(b.r, b.alpha));
    }

    private static void cmdOprfEval(Map<String, String> opt) throws IOException {
        Codec.PubKey key = Codec.decodeOprfPrivKey(readString(req(opt, "key", "oprf-eval")));
        Codec.OprfState state = Codec.decodeOprfState(readString(req(opt, "in", "oprf-eval")));
        BigInteger beta = Oprf.eval(state.alpha, key.pub);
        writeString(req(opt, "out", "oprf-eval"), Codec.encodeOprfEval(beta));
    }

    private static void cmdOprfUnblind(Map<String, String> opt) throws IOException {
        Codec.OprfState state = Codec.decodeOprfState(readString(req(opt, "state", "oprf-unblind")));
        Codec.PubKey eval = Codec.decodeOprfEval(readString(req(opt, "eval", "oprf-unblind")));
        BigInteger f = Oprf.unblind(eval.pub, state.r);
        String out = opt.getOrDefault("out", "-");
        writeString(out, hexBytes(toFixedBytes(f, state.nbits / 8)) + "\n");
    }

    // -----------------------------------------------------------------
    // cred-issue / cred-prove / cred-verify (HCRED, TODO #202)
    // -----------------------------------------------------------------

    /** Loads (c, m, seedH, syndr) from an HCRED PUBLIC or PRIVATE KEY PEM. */
    private static Codec.HcredPubKey loadHcredPubkey(String path) throws IOException {
        String pem = readString(path);
        Codec.PemBlock block = Codec.pemUnwrap(pem);
        if (block.label.equals(Codec.PEM_HCRED_PRIV)) {
            Codec.HcredPrivKey pk = Codec.decodeHcredPrivKey(pem);
            return new Codec.HcredPubKey(pk.c, pk.m, pk.seedH, pk.syndr, pk.n);
        }
        if (!block.label.equals(Codec.PEM_HCRED_PUB)) {
            throw new CliError("Expected HCRED PUBLIC KEY (or PRIVATE KEY), got " + block.label);
        }
        return Codec.decodeHcredPubKey(pem);
    }

    private static final int HCRED_SIGN_ROUNDS = 219; // production Stern-F soundness
    private static final int HCRED_CLI_ROUNDS = 219;  // production ZKBoo soundness

    private static void cmdCredIssue(Map<String, String> opt) throws IOException {
        Codec.HcredPubKey pub = loadHcredPubkey(req(opt, "in", "cred-issue"));
        String ourPem = readString(req(opt, "our", "cred-issue"));
        Codec.PemBlock ourBlock = Codec.pemUnwrap(ourPem);
        if (!ourBlock.label.equals(Codec.PEM_HPKS_STERN_PRIV) && !ourBlock.label.equals(Codec.PEM_HPKE_STERN_PRIV)) {
            throw new CliError("cred-issue: --our must be an hpks-stern private key, got " + ourBlock.label);
        }
        Codec.SternPrivKey issuer = Codec.decodeSternPrivKey(ourPem, ourBlock.label);
        BigInteger issuerSyn = Stern.sternSyndrome(issuer.seed, issuer.e);

        int rounds = opt.containsKey("rounds") ? Integer.parseInt(opt.get("rounds")) : HCRED_SIGN_ROUNDS;
        System.err.println("warning: HPKS-Stern-F/HPKE-Stern-F are demo-strength illustrations of a "
            + "code-based construction, not a production-hardened scheme at these parameters.");
        Stern.SternSignature credSig = Hcred.issue(pub.m, pub.c, pub.seedH, pub.syndr, pub.n,
            issuer.e, issuer.seed, rounds, RNG);
        writeString(opt.getOrDefault("out", "-"), Codec.encodeHcredCredential(credSig));
    }

    private static void cmdCredProve(Map<String, String> opt) throws IOException {
        String pem = readString(req(opt, "in", "cred-prove"));
        Codec.PemBlock block = Codec.pemUnwrap(pem);
        if (!block.label.equals(Codec.PEM_HCRED_PRIV)) {
            throw new CliError("cred-prove: --in must be an HCRED PRIVATE KEY PEM, got " + block.label);
        }
        Codec.HcredPrivKey pk = Codec.decodeHcredPrivKey(pem);
        byte[] msg = opt.getOrDefault("msg", "").getBytes(java.nio.charset.StandardCharsets.UTF_8);
        int rounds = opt.containsKey("rounds") ? Integer.parseInt(opt.get("rounds")) : HCRED_CLI_ROUNDS;
        Hcred.Proof proof;
        try {
            proof = Hcred.prove(pk.s, pk.m, pk.c, pk.seedH, pk.syndr, rounds, msg, RNG);
        } catch (IllegalArgumentException e) {
            throw new CliError("cred-prove: " + e.getMessage());
        }
        writeString(opt.getOrDefault("out", "-"), Codec.encodeHcredProof(proof));
    }

    private static void cmdCredVerify(Map<String, String> opt) throws IOException {
        Hcred.Proof proof = Codec.decodeHcredProof(readString(req(opt, "proof", "cred-verify")));
        Codec.HcredPubKey pub = loadHcredPubkey(req(opt, "pubkey", "cred-verify"));
        byte[] msg = opt.getOrDefault("msg", "").getBytes(java.nio.charset.StandardCharsets.UTF_8);
        int rounds = proof.rounds.size();

        boolean okProof = Hcred.verify(pub.m, pub.c, pub.seedH, pub.syndr, proof, rounds, msg);
        if (!okProof) {
            System.out.println("Verification FAILED (proof)");
            System.exit(1);
        }

        if (opt.containsKey("cred")) {
            Codec.SternSigDecoded credSig = Codec.decodeHcredCredential(readString(opt.get("cred")));
            String issuerPem = readString(req(opt, "issuer", "cred-verify"));
            Codec.PemBlock issuerBlock = Codec.pemUnwrap(issuerPem);
            if (!issuerBlock.label.equals(Codec.PEM_HPKS_STERN_PUB) && !issuerBlock.label.equals(Codec.PEM_HPKE_STERN_PUB)) {
                throw new CliError("cred-verify: --issuer must be an hpks-stern public key, got " + issuerBlock.label);
            }
            Codec.SternPubKey issuerPub = Codec.decodeSternPubKey(issuerPem, issuerBlock.label);
            boolean okCred = Hcred.credVerify(pub.m, pub.c, pub.seedH, pub.syndr, pub.n,
                credSig.sig, issuerPub.seed, issuerPub.syndrome);
            if (!okCred) {
                System.out.println("Verification FAILED (credential)");
                System.exit(1);
            }
            System.out.println("Credential OK");
        }
        System.out.println("Proof OK");
    }

    // -----------------------------------------------------------------
    // pake-register / pake-demo (aPAKE, TODO #203)
    // -----------------------------------------------------------------

    private static void cmdPakeRegister(Map<String, String> opt) throws IOException {
        Codec.PubKey key = Codec.decodeOprfPrivKey(readString(req(opt, "key", "pake-register")));
        String username = opt.getOrDefault("username", "user");
        String passwordOpt = opt.get("password");
        if (passwordOpt == null) {
            throw new CliError("pake-register: --password required (interactive prompting is not supported by this Java CLI)");
        }
        byte[] password = passwordOpt.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        Hpake.Record record = Hpake.register(username, password, key.pub, RNG);
        writeString(opt.getOrDefault("out", "-"), Codec.encodePakeRecord(record.salt, record.b, record.y));
    }

    private static void cmdPakeDemo(Map<String, String> opt) throws IOException {
        Codec.PubKey key = Codec.decodeOprfPrivKey(readString(req(opt, "key", "pake-demo")));
        String username = opt.getOrDefault("username", "demo-user");
        byte[] password = opt.getOrDefault("password", "demo-password").getBytes(java.nio.charset.StandardCharsets.UTF_8);

        Hpake.Record record = Hpake.register(username, password, key.pub, RNG);
        byte[] sk = Hpake.loginDemo(record, password, key.pub, RNG);
        if (sk != null) {
            System.out.println("- aPAKE login succeeded; session key: " + hexBytes(sk));
        } else {
            System.out.println("+ aPAKE login failed!");
            System.exit(1);
        }
        byte[] wrongSk = Hpake.loginDemo(record, "wrong-password".getBytes(java.nio.charset.StandardCharsets.UTF_8), key.pub, RNG);
        if (wrongSk == null) {
            System.out.println("- aPAKE correctly rejects wrong password");
        } else {
            System.out.println("+ aPAKE accepted wrong password! (security failure)");
            System.exit(1);
        }
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

    // -----------------------------------------------------------------
    // XMSS/WOTS state sidecar file (<keyfile>.idx), matching the Python
    // CLI's convention: XMSS stores the next-unused leaf index; WOTS
    // stores a 0/1 used flag (reusing the same file name convention).
    // -----------------------------------------------------------------

    private static void writeIdxState(String keyPath, int value) throws IOException {
        if (keyPath == null || keyPath.equals("-")) return;
        writeString(keyPath + ".idx", value + "\n");
    }

    private static int readIdxState(String keyPath) {
        try {
            String s = readString(keyPath + ".idx").trim();
            return Integer.parseInt(s);
        } catch (Exception e) {
            return 0;
        }
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
