#!/usr/bin/env python3
"""TODO #328: hold the three benchmark rate formatters against each other.

C's print_rate, Go's fmtRate and Python's _bench each render a benchmark rate as
M, K or plain ops/sec.  Go's had only TWO branches -- everything below 1e6 printed
in K units -- so the harness's six slowest benchmarks published "0.00 K ops/sec"
for true rates of 0.36 to 8.57 ops/sec.  Not imprecise but FALSE: it reads as zero
throughput.  Half the rows (23 of 46) were losing precision.

Nothing caught it because NO CHECKER PARSES BENCHMARK OUTPUT -- verified,
`grep -rln 'ops/sec' spec/ tools/ CliTest/ .github/` is empty -- and this file does
not change that: running benchmarks in CI is TODO #289's runtime problem, and a cost
figure is host-specific by nature.  What it closes is the case that occurred, and it
closes it STATICALLY: the three formatters must carry the same thresholds and the
same set of branches, read out of each port's own source.

That is PARAMETERS' idea (compare a value across ports) aimed at a FORMATTER'S
BRANCH STRUCTURE, which no existing axis reads.

KNOWN LIMIT, stated here rather than discovered later: this reads thresholds and
branch structure, not output, so a formatter keeping all three branches and
computing the wrong number still passes.  Java is not in the axis -- it has no
benchmark formatter at all, asserted below so that gaining one is an error rather
than a silence.
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

    # Java is deliberately outside the axis; gaining a formatter is an error.
    java = ROOT / "bindings/java"
    if java.exists():
        hits = [f for f in java.rglob("*.java") if "ops/sec" in f.read_text(errors="ignore")]
        if hits:
            errors.append(
                f"bindings/java has grown a benchmark rate formatter "
                f"({', '.join(h.name for h in hits)}) — add it to FORMATTERS, "
                f"because an unchecked fourth renderer is how the third diverged")

    for port in ("c", "go", "python"):
        if port in results:
            mk, kk, pk, units = results[port]
            print(f"  {port:<8} M={'y' if mk else 'N'} K={'y' if kk else 'N'} "
                  f"plain={'y' if pk else 'N'}   units seen: {units}")
    print(f"  java     no benchmark formatter (asserted)")

    if errors:
        print()
        for e in errors:
            print(f"  FAIL: {e}")
        print(f"\n*** FAILED: {len(errors)} rate-formatter problem(s) (TODO #328) ***")
        return 1
    print("\n*** OK: all three ports render M / K / plain ops/sec at the same "
          "thresholds ***")
    return 0


if __name__ == "__main__":
    sys.exit(main())
