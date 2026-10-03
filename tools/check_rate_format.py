#!/usr/bin/env python3
"""TODO #328: hold the benchmark rate formatters against each other.

FOUR OF THEM SINCE TODO #333, which is the gap the KNOWN LIMIT below used to
record without filing: there were three in a four-port repo, because
bindings/java had no benchmark layer at all -- not a batch helper, not a rate
formatter, not one throughput row for any protocol.  Java's Bench.fmtRate now
exists and is in the axis.

C's print_rate, Go's fmtRate, Python's _bench and Java's Bench.fmtRate each
render a benchmark rate as
M, K or plain ops/sec.  Go's had only TWO branches -- everything below 1e6 printed
in K units -- so the harness's six slowest benchmarks published "0.00 K ops/sec"
for true rates of 0.36 to 8.57 ops/sec.  Not imprecise but FALSE: it reads as zero
throughput.  Half the rows (23 of 46) were losing precision.

Nothing caught it because NO CHECKER PARSES BENCHMARK OUTPUT -- verified,
`grep -rln 'ops/sec' spec/ tools/ CliTest/ .github/` is empty -- and this file does
not change that: running benchmarks in CI is TODO #289's runtime problem, and a cost
figure is host-specific by nature.  What it closes is the case that occurred, and it
closes it STATICALLY: every formatter must carry the same thresholds and the
same set of branches, read out of each port's own source.

That is PARAMETERS' idea (compare a value across ports) aimed at a FORMATTER'S
BRANCH STRUCTURE, which no existing axis reads.

KNOWN LIMIT, stated here rather than discovered later: this reads thresholds and
branch structure, not output, so a formatter keeping all three branches and
computing the wrong number still passes.  A SECOND LIMIT comes from the shape
rather than from the implementation, and TODO #333 is where it had to be said
out loud: the four formatters are held to EACH OTHER, so a threshold all four
agree on and that is wrong is invisible -- the standing blind spot of #277,
#294, #296 and #297, whose only exit is an assertion about ONE implementation.
WANT_M and WANT_K below are therefore this file's own numbers, read from no
port, which is the single-implementation assertion that exit requires.
"""

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# (port, file, regex locating the formatter body)
FORMATTERS = [
    ("c", "CryptosuiteTests/Herradura_tests.c",
     r"static void print_rate\s*\([^)]*\)\s*\{(.*?)\n\}"),
    ("go", "CryptosuiteTests/Herradura_tests.go",
     r"func fmtRate\s*\([^)]*\)\s*string\s*\{(.*?)\n\}"),
    ("python", "CryptosuiteTests/Herradura_tests.py",
     r"rate = ops / elapsed(.*?)print\(f\""),
    # Java's method body closes on an INDENTED brace, so the C/Go terminator
    # (a newline then `}` at column 0) does not reach it: a pattern that
    # silently ran to end of file would read every later `ops/sec` in the
    # class as part of the formatter, and over-matching is the LENIENT
    # direction for a branch census (#295).
    ("java", "bindings/java/herradurakex/Bench.java",
     r"static String fmtRate\s*\([^)]*\)\s*\{(.*?)\n    \}"),
]

# Every port must express all three, at the same thresholds.
WANT_M = 1e6
WANT_K = 1e3


def main():
    results = {}
    errors = []

    for port, rel, pat in FORMATTERS:
        p = ROOT / rel
        if not p.exists():
            errors.append(f"{rel} is missing")
            continue
        m = re.search(pat, p.read_text(), re.S)
        if not m:
            errors.append(
                f"{port}: could not locate the rate formatter in {rel} — the "
                f"pattern broke, and a formatter this check cannot read is one it "
                f"cannot hold to anything (it must fail, not skip)")
            continue
        body = m.group(1)

        # Thresholds are read from the COMPARISON, not from anywhere in the body.
        # A first version scanned every numeric literal, and its control did not
        # fire: moving Python's K branch to `>= 1e4` still left `rate/1e3` in the
        # body, so "1e3 appears" stayed true while the branch had drifted. That is
        # precisely the drift this check exists for, so the operator is required.
        # Accepts 1e6 / 1.0e6 / 1000000 / 1_000_000 spellings.
        comparisons = []
        for lit in re.findall(r">=?\s*([0-9][0-9_.eE+]*)", body):
            try:
                comparisons.append(float(lit.replace("_", "")))
            except ValueError:
                pass

        def has_threshold(want):
            return any(abs(c - want) < 1e-9 for c in comparisons)

        m_ok = has_threshold(WANT_M)
        k_ok = has_threshold(WANT_K)
        # a plain branch divides by nothing: "ops/sec" not preceded by M or K
        units = re.findall(r'"?\s*(M|K|)\s*ops/sec', body)
        plain_ok = any(u == "" for u in units)

        results[port] = (m_ok, k_ok, plain_ok, sorted(set(units)))
        if not m_ok:
            errors.append(
                f"{port}: no branch COMPARES against {WANT_M:.0e} for M ops/sec "
                f"(comparisons found: {comparisons})")
        if not k_ok:
            errors.append(
                f"{port}: no branch COMPARES against {WANT_K:.0e} for K ops/sec "
                f"(comparisons found: {comparisons})")
        if not plain_ok:
            errors.append(
                f"{port}: NO PLAIN ops/sec BRANCH — every rate below "
                f"{WANT_M:.0e} would print in K units, so a rate of 4.46 renders "
                f"as '0.00 K ops/sec' and reads as zero throughput (TODO #328)")

    # all ports must agree, which is the point of comparing them at all
    if len(results) > 1:
        shapes = {port: r[:3] for port, r in results.items()}
        if len(set(shapes.values())) > 1:
            errors.append(
                f"the ports DISAGREE on which branches exist: {shapes} — a "
                f"benchmark rate must render the same way in every port")

    # Java's formatter is IN the axis since TODO #333, so this clause is
    # INVERTED rather than deleted.  It used to assert that bindings/java had
    # no formatter at all; it now asserts that the only one there is the one
    # FORMATTERS names.  Both halves are load-bearing: a second renderer in
    # another class is unchecked, which is how the third diverged, and the
    # POSITIVE half stops a pure absence rule from passing once the thing it
    # describes is deleted (#234's vacuous pass; #326's "a string-presence
    # rule cannot tell a claim from its retraction").
    java = ROOT / "bindings/java"
    named = {ROOT / rel for _port, rel, _rx in FORMATTERS}
    if java.exists():
        hits = [f for f in java.rglob("*.java")
                if "ops/sec" in f.read_text(errors="ignore")]
        extra = sorted(h for h in hits if h not in named)
        if extra:
            errors.append(
                f"bindings/java has grown a SECOND benchmark rate formatter "
                f"({', '.join(h.name for h in extra)}) — add it to FORMATTERS, "
                f"because an unchecked renderer is how the third diverged")
        if not hits:
            errors.append(
                "bindings/java renders no rate at all — Bench.java's "
                "formatter is gone, and an absence rule that passes once the "
                "thing it describes is deleted is TODO #234's vacuous pass")

    for port in ("c", "go", "python", "java"):
        if port in results:
            mk, kk, pk, units = results[port]
            print(f"  {port:<8} M={'y' if mk else 'N'} K={'y' if kk else 'N'} "
                  f"plain={'y' if pk else 'N'}   units seen: {units}")

    if errors:
        print()
        for e in errors:
            print(f"  FAIL: {e}")
        print(f"\n*** FAILED: {len(errors)} rate-formatter problem(s) (TODO #328) ***")
        return 1
    print(f"\n*** OK: all {len(results)} ports render M / K / plain ops/sec "
          f"at the same thresholds ***")
    return 0


if __name__ == "__main__":
    sys.exit(main())
