package herradurakex;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * TODO #333: the Java port's benchmark layer, and its first row — the
 * deployed QC-MDPC KEM, {@code [36]}.
 *
 * <p>BEFORE THIS FILE, {@code bindings/java/} CONTAINED NO TIMING CODE OF ANY
 * KIND.  Not a batch helper, not a rate formatter, not one throughput row for
 * any protocol: a grep across the whole port for {@code bench},
 * {@code throughput}, {@code ops/sec} or {@code nanoTime} returned zero
 * matches.  C, Go and Python each publish {@code [32]}-{@code [43]} plus
 * {@code [54]}; Java published {@code [1]}-{@code [35]} and no cost figure at
 * all, while {@code native-java} is as REQUIRED as the other three jobs.  So
 * the gap was one LAYER wide where TODO #332's was one ROW wide, which is why
 * that item filed this one rather than smuggling a Java row in (#312).
 *
 * <h2>1. Why a third entry point rather than a section inside SelfTest</h2>
 *
 * The three roles are kept separate because their EXIT CONDITIONS differ, not
 * for tidiness.  {@link SelfTest} asserts — every check is a verdict and the
 * class exits non-zero on any failure; {@link Demo} is a walkthrough gated on
 * the same {@code [FAIL]} marker convention as C/Go/Python's demo binaries
 * (TODO #258/#259/#260).  A benchmark publishes a HOST-SPECIFIC RATE that
 * nothing asserts on, which is TODO #292's position, and it is the only one of
 * the three that needs {@code -r}/{@code -t}: neither of the others parses a
 * flag at all.  Folding it into {@code SelfTest} would have made a cost figure
 * part of what that class asserts and given {@code -t} no place to live.
 *
 * <p>It therefore gets its own {@code native-java} step, which is also the
 * only way the reduced caps CI runs it at can differ from a developer's.
 *
 * <h2>2. The batch is DERIVED, which is TODO #327's finding</h2>
 *
 * That item found Go's and Python's helpers warming 10 times and then checking
 * elapsed only AFTER a 100-call batch — a floor of 110 invocations no time cap
 * could reduce, so 66 of 138 rows overshot a 0.05 s cap in #326's own CI run,
 * the worst by 6683x.  Both now size the batch from one timed probe call, and
 * {@link #bench} does the same.  C's eight hand-picked batch constants are the
 * form NOT copied here: #327 recorded them as its own known limit, and adding
 * a ninth in a fourth place is what #294 and #296 both answered with "adopt
 * the port that is correct" rather than inventing a fourth design.
 *
 * <p>{@code -t} bounds the WARMUP as well as the timing loop, because a
 * warmup with a fixed call count is the unbounded version of exactly the
 * defect #327 fixed.
 *
 * <h2>3. JIT warmup is a correctness question for the figure</h2>
 *
 * Measured call by call on an aarch64 SBC, cold to warm: the FIRST
 * decapsulation costs 110.79 ms against a warm 19.3 (5.7x), the first keygen
 * 30.95 against 14.0 (2.2x), and both settle by about call 5-8 with occasional
 * recompilation outliers after that.  TODO #332's own hand measurements of
 * this port moved keygen 99 to 56 ms and decapsulation 36 to 24 ms between
 * runs with no code change, purely on JIT state.  So a harness reporting the
 * cold number publishes a figure up to 5.7x wrong, and the warmup count is
 * printed rather than assumed — a figure whose warmup is unstated is not a
 * figure.
 *
 * <h2>4. The rate formatter has THREE branches</h2>
 *
 * M, K and plain ops/sec at the same thresholds as C's {@code print_rate}, Go's
 * {@code fmtRate} and Python's {@code _bench}.  TODO #328's whole finding was
 * Go printing {@code 0.00 K ops/sec} for a true 4.46 ops/sec — false rather
 * than imprecise, since it reads as zero throughput — and the slowest rows
 * here are in exactly that range.  {@code tools/check_rate_format.py} holds
 * FOUR formatters against each other now rather than three, which is the gap
 * that check's own text recorded without filing.
 *
 * <h2>5. Numbering</h2>
 *
 * {@code [36]} is in JAVA'S OWN numbering space, continuing
 * {@code SelfTest.java}'s {@code [1]}-{@code [35]} as that class's doc comment
 * says new checks must.  It does NOT align with C/Go/Python's {@code [54]},
 * which is the same row in the shared space;
 * {@code spec/check_language_parity.py} checks the other three against each
 * other and nothing forces alignment, so the mapping is written down here
 * rather than inferred: <b>Java {@code [36]} is C/Go/Python {@code [54]}</b>.
 *
 * <p>The number obliges a {@code _TEST_DRAWS} cell, a
 * {@code _VERDICT_FINGERPRINTS} entry, a {@code _SAMPLED_TESTS} row and a
 * {@code _REJECTION_BASES} basis, all filled.  Unlike the 36 bare benchmark
 * rows whose fingerprint is the pinned value {@code "none"}, this one HAS a
 * verdict, for the reason in §6.
 *
 * <h2>6. The row carries a CONTROL, and that is how it earns a required job</h2>
 *
 * TODO #292's position is that a host-specific cost figure does not belong in
 * CI, and this prints in a REQUIRED job.  The grandfathered benchmarks print a
 * rate nobody asserts on; this one is a TEST as well as a figure, at no extra
 * cost, because the operations it times are the ones it checks:
 * {@code decap(encap(pk))} must reproduce the encapsulated key, and a uniform
 * syndrome must decapsulate to a DIFFERENT one, so TODO #235's
 * implicit-rejection path is reached rather than assumed.
 *
 * <p>The decoder's outcome on the uniform syndrome is REPORTED, never
 * asserted: a uniform r-bit syndrome is a decodable weight-t one with
 * probability about C(2r,t)/2^r = 2^-11193, so asserting it fails to decode
 * would be an assertion with a rate, and the key-differs check holds either
 * way (#291).
 *
 * <p>The two decapsulation paths are TIMED AND LABELLED SEPARATELY because
 * they cost different amounts — the GJS channel TODO #330 registered in
 * dudect Batch 10 — and an averaged figure would be one nobody could use.
 *
 * <h2>7. Scope: one row, not twelve</h2>
 *
 * C/Go/Python's other eleven benchmarks ({@code [32]}-{@code [43]}: FSCX, the
 * classical quartet, the NL primitives, HKEX-RNL at the ring #223 retired,
 * Stern-F and the two ZKPs) are NOT ported.  The question this item asks is
 * whether Java has a benchmark layer and what it looks like, and one row
 * settles it — the deployed KEM, which is the row {@code SECURITY.md}
 * recommends over the classical quartet and the one #332 found had no
 * published figure in any harness.  Porting the other eleven would add about
 * eleven seconds per CI run of cost figures nobody asserts on, in a REQUIRED
 * job, to answer a question already answered; the layer is here, so a twelfth
 * row is now a one-method change rather than a decision.
 *
 * <p>Usage: {@code java -cp bindings/java herradurakex.Bench [-r N] [-t S]},
 * with {@code HTEST_ROUNDS}/{@code HTEST_TIME} as env equivalents, exactly as
 * the C/Go/Python harnesses document them.
 */
public final class Bench {
    private Bench() { }

    /** Benchmark duration per row, seconds.  {@code -t} / {@code HTEST_TIME}. */
    private static double benchSec = 1.0;

    /** Hard cap on timed ops per row, 0 = none.  {@code -r} / {@code HTEST_ROUNDS}. */
    private static int roundsCap = 0;

    /**
     * Warmup calls per row before any timing, unless {@code -t} runs out
     * first.  Ten because the measurement in §3 puts the settling point at
     * about call 5-8 on this host; it is a floor against JIT state, which is
     * why it does not shrink with the batch the way Go's does.
     */
    static final int WARM_CALLS = 10;

    /** One timed row's outcome. */
    private static final class Result {
        final long ops;
        final double secs;
        final int warm;
        final int batch;
        Result(long ops, double secs, int warm, int batch) {
            this.ops = ops; this.secs = secs; this.warm = warm; this.batch = batch;
        }
    }

    /**
     * Rate as M, K or plain ops/sec (TODO #328).
     *
     * <p>All three branches, at C's, Go's and Python's thresholds.  The plain
     * one is the branch Go was MISSING: everything below 1e6 printed in K
     * units there, so a true 4.46 ops/sec rendered as {@code 0.00 K ops/sec}.
     * Every row in this file is in that range on an SBC.
     */
    static String fmtRate(long ops, double secs) {
        double rate = ops / secs;
        if (rate >= 1e6) return String.format("%.2f M ops/sec", rate / 1e6);
        if (rate >= 1e3) return String.format("%.2f K ops/sec", rate / 1e3);
        return String.format("%.2f ops/sec", rate);
    }

    /**
     * Warm, then size the batch from a WARM per-call time, then time.
     *
     * <p>Go's helper probes ONCE and cold, which under-sizes the batch by the
     * JIT factor and costs only extra polls.  Here the probe is the last
     * warmup call, so the batch is derived from the state the row is actually
     * measured in — the same derivation, fed the number it was meant to have.
     */
    private static Result bench(Runnable fn) {
        double durSec = benchSec;
        long durNs = (long) (durSec * 1e9);

        // Phase 1: warm up.  Bounded by WARM_CALLS *and* by -t, because a
        // fixed call count is the unbounded version of TODO #327's defect.
        long warmStart = System.nanoTime();
        int warm = 0;
        long perCall = 0;
        while (warm < WARM_CALLS) {
            long c0 = System.nanoTime();
            fn.run();
            perCall = System.nanoTime() - c0;
            warm++;
            if (System.nanoTime() - warmStart >= durNs) break;
        }

        // Phase 2: the batch, DERIVED.  A batch costs about a tenth of the
        // budget, so elapsed is polled ~10 times per row however slow the
        // operation is -- and an operation faster than the budget keeps the
        // historical 100, so its path is unchanged (TODO #327's criterion:
        // rates are the invariant, sample size is not).
        int batch = 100;
        if (perCall > 0 && durNs > 0) {
            batch = (int) (durNs / (10 * perCall));
            batch = Math.min(100, Math.max(1, batch));
        }
        if (roundsCap > 0 && batch > roundsCap) batch = roundsCap;

        // Phase 3: time.
        long ops = 0;
        long start = System.nanoTime();
        double secs;
        for (;;) {
            for (int i = 0; i < batch; i++) fn.run();
            ops += batch;
            secs = (System.nanoTime() - start) / 1e9;
            if (secs >= durSec) break;
            if (roundsCap > 0 && ops >= roundsCap) break;
        }
        return new Result(ops, secs, warm, batch);
    }

    private static void row(String label, Runnable fn) {
        Result r = bench(fn);
        System.out.printf("    %-42s: %s  (%d ops in %.2fs, warm=%d batch=%d)%n",
                label, fmtRate(r.ops, r.secs), r.ops, r.secs, r.warm, r.batch);
    }

    /**
     * {@code [36]}: the deployed QC-MDPC KEM, with a control.  Java's
     * counterpart of C/Go/Python's {@code [54]}.
     */
    private static boolean benchQcMdpcKem(SecureRandom rng) {
        System.out.println("[36] HPKE-Stern-KEM keygen/encap/decap throughput  [CODE-BASED PQC]");
        System.out.printf("    r=%d  d=%d  t=%d  (BIKE-128)%n",
                Stern.QCMDPC_R, Stern.QCMDPC_D, Stern.QCMDPC_T);

        final Stern.QcMdpcKeypair kp = Stern.qcmdpcKeygen(rng);
        final Stern.QcMdpcEncapResult enc = Stern.qcmdpcEncap(kp.hPub, rng);

        // A uniform r-bit syndrome, drawn through BitArray.random so this adds
        // no new spelling of "read the entropy source" to TODO #316's draw
        // census -- that one is already the seventh, found by TODO #314 pass 5.
        int rb = (Stern.QCMDPC_R + 7) / 8;
        byte[] raw = new byte[0];
        while (raw.length < rb) {
            byte[] chunk = BitArray.random(256, rng).toBytes();
            byte[] next = Arrays.copyOf(raw, raw.length + chunk.length);
            System.arraycopy(chunk, 0, next, raw.length, chunk.length);
            raw = next;
        }
        final BigInteger rnd = new BigInteger(1, Arrays.copyOf(raw, rb))
                .mod(BigInteger.ONE.shiftLeft(Stern.QCMDPC_R));

        row("keygen (incl. weak-key screen + inversion)",
                () -> Stern.qcmdpcKeygen(rng));
        row("encap", () -> Stern.qcmdpcEncap(kp.hPub, rng));
        row("decap  SUCCESS path (decoder converges)",
                () -> Stern.qcmdpcDecapBgf(enc.syn, kp.sup0, kp.sup1));
        row("decap  IMPLICIT-REJECTION path (TODO #235)",
                () -> Stern.qcmdpcDecapBgf(rnd, kp.sup0, kp.sup1));

        // The control.  Fresh key, fresh ciphertext, both paths.
        boolean okAgree = Stern.qcmdpcDecapBgf(enc.syn, kp.sup0, kp.sup1).equals(enc.k);
        boolean okDiff = !Stern.qcmdpcDecapBgf(rnd, kp.sup0, kp.sup1).equals(enc.k);
        boolean okDec = Stern.qcmdpcBgfDecode(rnd, kp.sup0, kp.sup1) != null;
        System.out.printf("    control: encap/decap agree=%s  rejection key differs=%s  "
                + "uniform syndrome decoded=%s%n", okAgree, okDiff, okDec);
        // THE SHAPE OF THESE TWO LINES IS LOAD-BEARING, and it was settled by
        // a control that did NOT fire (TODO #333).
        //
        // (a) FAIL first, PASS second.  The ninth axis slices a Java test's
        //     body from the PREVIOUS marker up to its own trailing
        //     println("PASS [N]"), so an if/else written the other way round
        //     leaves BOTH outcome lines outside the slice and #318's verdict
        //     fingerprint reads "none" -- the value pinned for a test that
        //     decides nothing at all.
        // (b) The CONJUNCTION is on the FAIL line, not on a `boolean ok =`
        //     line above it.  #318 fingerprints PASS/FAIL-BEARING lines, so a
        //     decision one line up is invisible: with `boolean ok = okAgree &&
        //     okDiff;` extracted, flipping it to `||` left every check in
        //     spec/ green.  C's [54] and Python's both put the decision inside
        //     the printf that carries the markers; Go's did not, and TODO #333
        //     fixed that in the same pass rather than shipping a fourth cell
        //     with a known-blind pin.
        if (!(okAgree && okDiff)) System.out.println("FAIL [36] "
                + "qcmdpc_kem_throughput (agree=" + okAgree + " differs=" + okDiff + ")");
        else System.out.println("PASS [36] qcmdpc_kem_throughput");
        return okAgree && okDiff;
    }

    private static void usage() {
        System.out.println("Usage: java -cp bindings/java herradurakex.Bench "
                + "[-r N | --rounds N] [-t S | --time S]");
        System.out.println("  -r/--rounds N  cap timed ops per row at N (0 = no cap)");
        System.out.println("  -t/--time S    benchmark duration per row, seconds");
        System.out.println("  Env: HTEST_ROUNDS=N  HTEST_TIME=S  (flags override)");
    }

    public static void main(String[] args) {
        String envR = System.getenv("HTEST_ROUNDS");
        String envT = System.getenv("HTEST_TIME");
        try {
            if (envR != null && !envR.isEmpty()) {
                int v = Integer.parseInt(envR.trim());
                if (v > 0) roundsCap = v;
            }
            if (envT != null && !envT.isEmpty()) {
                double v = Double.parseDouble(envT.trim());
                if (v > 0) benchSec = v;
            }
        } catch (NumberFormatException e) {
            System.out.println("Bench: bad HTEST_ROUNDS/HTEST_TIME value: " + e.getMessage());
            System.exit(2);
        }
        for (int i = 0; i < args.length; i++) {
            String a = args[i];
            if (a.equals("-h") || a.equals("--help")) { usage(); return; }
            boolean isR = a.equals("-r") || a.equals("--rounds");
            boolean isT = a.equals("-t") || a.equals("--time");
            if (!isR && !isT) {
                System.out.println("Bench: unknown argument '" + a + "'");
                usage();
                System.exit(2);
            }
            if (i + 1 >= args.length) {
                System.out.println("Bench: " + a + " needs a value");
                System.exit(2);
            }
            String v = args[++i];
            try {
                if (isR) roundsCap = Integer.parseInt(v);
                else benchSec = Double.parseDouble(v);
            } catch (NumberFormatException e) {
                System.out.println("Bench: bad value for " + a + ": " + v);
                System.exit(2);
            }
        }
        if (benchSec <= 0) benchSec = 1.0;

        System.out.println("=== Herradura cryptographic suite — Java benchmarks (TODO #333) ===");
        System.out.printf("    Config: time=%.2fs per row  rounds_cap=%s  warmup=%d call(s) per row%n",
                benchSec, roundsCap > 0 ? Integer.toString(roundsCap) : "none", WARM_CALLS);
        System.out.println("    Rates are host-specific and nothing asserts on them (TODO #292);");
        System.out.println("    [36]'s control is the assertion, and it does gate this process's exit.");
        System.out.println();

        SecureRandom rng = new SecureRandom();
        boolean ok = benchQcMdpcKem(rng);

        System.out.println();
        if (!ok) {
            System.out.println("*** FAILED: 1 check reported [FAIL] ***");
            System.exit(1);
        }
        System.out.println("*** OK: no check reported [FAIL] ***");
    }
}
