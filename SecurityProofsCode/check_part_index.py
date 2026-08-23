#!/usr/bin/env python3
"""Consistency check for the SecurityProofs part index (TODO #231).

The seven-part split of SecurityProofs.md is described by the same table in
roughly 76 places: the index in SecurityProofs.md itself, a seven-row banner at
the top of each of the eight SecurityProofs*.md files, a "Continued in Part N"
footer at the bottom of six of them, the file map in README.md, the repository
listing in CLAUDE.md, and the split history in SecurityProofsCode/KATEX_RULES.md.

Every copy has to agree, and the section ranges have twice drifted apart (once
when TODO #224 added SecurityProofs-7.md's section 11.21, again when TODO #230
added section 11.22); the advertised math-expression counts have drifted too
(SecurityProofs.md claimed 593 spans for Part 4 against an actual 659).

This script treats the index in SecurityProofs.md as the single source of truth,
asserts that every other copy of a section range agrees with it, and asserts
that every advertised expression count matches what validate_katex.js actually
measures.  Exits non-zero on any mismatch.

Usage:
    python3 SecurityProofsCode/check_part_index.py [--require-counts]

--require-counts turns "validate_katex.js could not be run" from a skipped
check into a failure; CI passes it, since the katex job installs katex anyway.
"""

import argparse
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
INDEX = "SecurityProofs.md"
NPARTS = 7

# "- **Part 4 — §11–§11.8.2** (SecurityProofs-4.md): Non-linearity ... (659 math expressions)"
INDEX_RE = re.compile(
    r"^- \*\*Part (?P<n>[1-7]) — (?P<range>.+?)\*\* \(SecurityProofs-(?P=n)\.md\): "
    r"(?P<title>.+?) \((?P<count>\d+) math expressions\)\s*$"
)

# Banner row inside a part file; the file's own row says "(this file)".
BANNER_RE = re.compile(
    r"^> - \*\*Part (?P<n>[1-7]) — (?P<range>.+?)\*\* "
    r"\((?P<file>this file|SecurityProofs-[1-7]\.md)\): (?P<title>.+?)\s*$"
)

FOOTER_RE = re.compile(
    r"^> \*\*Continued in Part (?P<n>[1-7]) — (?P<range>.+?)\*\* "
    r"\(SecurityProofs-(?P=n)\.md\): (?P<title>.+?)\s*$"
)

# CLAUDE.md: "SecurityProofs-4.md   — §11–§11.8.2: ... (659 math expressions)"
CLAUDE_RE = re.compile(
    r"^SecurityProofs-(?P<n>[1-7])\.md\s+— (?P<range>.+?): .*?"
    r"\((?P<count>\d+) math expressions\)\s*$"
)

# KATEX_RULES.md split history: "SecurityProofs-4.md (§11–§11.8.2, 659 spans)"
KATEX_RULES_RE = re.compile(
    r"SecurityProofs-(?P<n>[1-7])\.md \((?P<range>[^()]+?), (?P<count>\d+) spans\)"
)

# README.md file map, after whitespace normalisation:
# "SecurityProofs-4.md — formal analysis §11–§11.8.2 (non-linearity ..."
README_RE = re.compile(
    r"SecurityProofs-(?P<n>[1-7])\.md — formal analysis (?P<range>.+?) \("
)


def read(path):
    with open(os.path.join(ROOT, path), encoding="utf-8") as fh:
        return fh.read()


class Checker:
    def __init__(self):
        self.errors = []

    def fail(self, where, msg):
        self.errors.append(f"{where}: {msg}")

    def expect(self, where, part, field, got, want):
        if got != want:
            self.fail(
                where,
                f"Part {part} {field} is {got!r}, but {INDEX} says {want!r}",
            )


def load_index(chk):
    """Parse the authoritative table out of SecurityProofs.md."""
    parts = {}
    for line in read(INDEX).splitlines():
        m = INDEX_RE.match(line)
        if m:
            n = int(m.group("n"))
            parts[n] = {
                "range": m.group("range"),
                "title": m.group("title"),
                "count": int(m.group("count")),
            }
    missing = [n for n in range(1, NPARTS + 1) if n not in parts]
    if missing:
        chk.fail(INDEX, f"index rows not found for part(s) {missing}")
    return parts


def measure(path):
    """Return the math-expression count validate_katex.js reports, or None."""
    script = os.path.join(ROOT, "SecurityProofsCode", "validate_katex.js")
    try:
        out = subprocess.run(
            ["node", script, path],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=300,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    m = re.search(r"(\d+) OK, \d+ FAIL, \d+ PIPE-FAIL", out.stdout)
    return int(m.group(1)) if m else None


def check_counts(chk, parts, require):
    unavailable = False
    for n in sorted(parts):
        path = f"SecurityProofs-{n}.md"
        got = measure(path)
        if got is None:
            unavailable = True
            continue
        if got != parts[n]["count"]:
            chk.fail(
                INDEX,
                f"Part {n} is advertised as {parts[n]['count']} math expressions, "
                f"but validate_katex.js measures {got} in {path}",
            )
    if unavailable:
        msg = "validate_katex.js could not be run (node or katex missing)"
        if require:
            chk.fail("counts", msg + " and --require-counts was given")
        else:
            print(f"  skipped: {msg}; counts not verified")
    return not unavailable


def check_banners(chk, parts):
    for k in range(1, NPARTS + 1):
        path = f"SecurityProofs-{k}.md"
        seen = set()
        for lineno, line in enumerate(read(path).splitlines(), 1):
            m = BANNER_RE.match(line)
            if not m:
                continue
            n = int(m.group("n"))
            seen.add(n)
            where = f"{path}:{lineno}"
            self_ref = m.group("file") == "this file"
            if self_ref != (n == k):
                chk.fail(
                    where,
                    f"Part {n} row in Part {k}'s banner "
                    f"{'claims to be' if self_ref else 'does not claim to be'} this file",
                )
            chk.expect(where, n, "range", m.group("range"), parts[n]["range"])
            chk.expect(where, n, "title", m.group("title"), parts[n]["title"])
        missing = sorted(set(range(1, NPARTS + 1)) - seen)
        if missing:
            chk.fail(path, f"banner is missing row(s) for part(s) {missing}")


def check_index_self(chk, parts):
    """SecurityProofs.md's own rows are the source of truth; only sanity-check shape."""
    text = read(INDEX)
    if "split into seven parts" not in text:
        chk.fail(INDEX, "split-into-seven-parts preamble not found")


def check_footers(chk, parts):
    for k in range(1, NPARTS):
        path = f"SecurityProofs-{k}.md"
        found = False
        for lineno, line in enumerate(read(path).splitlines(), 1):
            m = FOOTER_RE.match(line)
            if not m:
                continue
            found = True
            n = int(m.group("n"))
            where = f"{path}:{lineno}"
            if n != k + 1:
                chk.fail(where, f"Part {k} continues into Part {n}, expected Part {k + 1}")
                continue
            chk.expect(where, n, "range", m.group("range"), parts[n]["range"])
            chk.expect(where, n, "title", m.group("title"), parts[n]["title"])
        if not found:
            chk.fail(path, f"no 'Continued in Part {k + 1}' footer found")


def check_claude_md(chk, parts):
    seen = set()
    for lineno, line in enumerate(read("CLAUDE.md").splitlines(), 1):
        m = CLAUDE_RE.match(line)
        if not m:
            continue
        n = int(m.group("n"))
        seen.add(n)
        where = f"CLAUDE.md:{lineno}"
        chk.expect(where, n, "range", m.group("range"), parts[n]["range"])
        chk.expect(where, n, "count", int(m.group("count")), parts[n]["count"])
    missing = sorted(set(range(1, NPARTS + 1)) - seen)
    if missing:
        chk.fail("CLAUDE.md", f"repository listing is missing part(s) {missing}")


def check_katex_rules(chk, parts):
    path = "SecurityProofsCode/KATEX_RULES.md"
    seen = set()
    for lineno, line in enumerate(read(path).splitlines(), 1):
        for m in KATEX_RULES_RE.finditer(line):
            n = int(m.group("n"))
            seen.add(n)
            where = f"{path}:{lineno}"
            chk.expect(where, n, "range", m.group("range"), parts[n]["range"])
            chk.expect(where, n, "count", int(m.group("count")), parts[n]["count"])
    missing = sorted(set(range(1, NPARTS + 1)) - seen)
    if missing:
        chk.fail(path, f"split history is missing part(s) {missing}")


def check_readme(chk, parts):
    # The file map wraps descriptions across lines and pads with columns of
    # spaces, so normalise the whole file to a single whitespace-collapsed
    # stream before matching.
    flat = re.sub(r"\s+", " ", read("README.md"))
    seen = set()
    for m in README_RE.finditer(flat):
        n = int(m.group("n"))
        seen.add(n)
        chk.expect("README.md", n, "range", m.group("range"), parts[n]["range"])
    missing = sorted(set(range(1, NPARTS + 1)) - seen)
    if missing:
        chk.fail("README.md", f"file map is missing part(s) {missing}")


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--require-counts",
        action="store_true",
        help="fail instead of skipping when validate_katex.js cannot be run",
    )
    args = ap.parse_args()

    chk = Checker()
    parts = load_index(chk)
    if len(parts) != NPARTS:
        print("\n".join("FAIL " + e for e in chk.errors))
        return 1

    print(f"Source of truth: {INDEX}")
    for n in sorted(parts):
        print(f"  Part {n} — {parts[n]['range']} ({parts[n]['count']} math expressions)")

    print("Checking advertised expression counts against validate_katex.js ...")
    counted = check_counts(chk, parts, args.require_counts)

    print("Checking part banners, footers, README, CLAUDE.md, KATEX_RULES.md ...")
    check_index_self(chk, parts)
    check_banners(chk, parts)
    check_footers(chk, parts)
    check_readme(chk, parts)
    check_claude_md(chk, parts)
    check_katex_rules(chk, parts)

    if chk.errors:
        print()
        for e in chk.errors:
            print(f"FAIL {e}")
        print(f"\n{len(chk.errors)} mismatch(es) — the part index has drifted.")
        return 1

    tail = "" if counted else " (counts skipped)"
    print(f"\nOK — every copy of the part index agrees with {INDEX}{tail}.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
