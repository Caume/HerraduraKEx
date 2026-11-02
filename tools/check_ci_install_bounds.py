#!/usr/bin/env python3
"""TODO #353: every CI step that installs packages must carry a time bound.

The push run for v12.0.2 (run 41250281934, attempt 1) lost native-go and
native-interop to the runner: both hung in "Install dependencies" right after
`apt-get update` fetched noble-security's InRelease, printed nothing more, and
sat until GitHub's default 360-minute job limit cancelled them.  No build or
test step ran, and a rerun passed.  A step that waits on a package mirror is the
one step whose duration the repo does not control, so it is the one that gets a
bound: `timeout-minutes: 20` on each.  Over 512 successful install steps in the
40 runs before this check the median was 12 s, the 99th percentile 97 s and the
slowest 821 s (the same mirror incident, recovering); 20 minutes sits above that.

The check, over .github/workflows/ci.yml and codeql.yml:

  (a) every step whose `run:` calls apt-get / apt / npm / pip to install or
      update has a step-level `timeout-minutes`, of at most MAX_MINUTES -- a
      bound of 300 would be a bound in name only;
  (b) every line in the file that calls an installer lies inside a step the
      scanner parsed, so a layout the scanner misreads fails loudly rather than
      passing by finding nothing (the vacuous pass #291 warns of).

CONTROLS, run first and each required to fire: the real files are accepted; a
copy with one bound removed, a copy with one bound raised to 360, and a copy
with a new unbounded apt step are each refused; a copy with an installer line
the scanner cannot place in a step is refused.

KNOWN LIMIT.  It sees installer commands in `run:` text only.  An install inside
a script the step calls, or inside the Dockerfile that `docker build` runs, is
not seen; the docker job's image build is bounded by the job, not here.  No
third-party dependencies: the workflows are read with a narrow line scanner
rather than PyYAML, which is not in this repo's dependency set.
"""

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
WORKFLOWS = [ROOT / ".github/workflows/ci.yml", ROOT / ".github/workflows/codeql.yml"]
MAX_MINUTES = 30

INSTALL = re.compile(r"\bapt-get\s+(?:-\S+\s+)*(?:update|install)\b|\bapt\s+install\b|"
                     r"\bnpm\s+(?:install|ci)\b|\bpip3?\s+install\b|-m\s+pip\s+install\b")
TIMEOUT = re.compile(r"^timeout-minutes:\s*(\d+)\s*$")


def _indent(line):
    return len(line) - len(line.lstrip(" "))


def _code(line):
    """The line without a YAML comment (a '#' at the start or after a space)."""
    s = line.strip()
    return "" if s.startswith("#") else re.split(r"\s#", s, maxsplit=1)[0]


def steps(text):
    """[(first line no., name, [(line no., text)])] for each step of every job."""
    lines = text.split("\n")
    out, i = [], 0
    while i < len(lines):
        if not re.match(r"^\s+steps:\s*$", lines[i]):
            i += 1
            continue
        j = i + 1
        while j < len(lines) and not _code(lines[j]):
            j += 1
        if j >= len(lines) or not lines[j].lstrip().startswith("- "):
            i = j
            continue
        ind = _indent(lines[j])
        while j < len(lines):
            line = lines[j]
            if _code(line) and _indent(line) < ind:
                break                                   # the steps list ended
            if _code(line) and _indent(line) == ind and line.lstrip().startswith("- "):
                start, body = j + 1, [(j + 1, line)]
                j += 1
                while j < len(lines) and not (_code(lines[j]) and _indent(lines[j]) <= ind):
                    body.append((j + 1, lines[j]))
                    j += 1
                name = next((re.sub(r"^-?\s*name:\s*", "", l.strip()) for _, l in body
                             if re.match(r"^-?\s*name:", l.strip())), "(unnamed)")
                out.append((start, name, body, ind + 2))
                continue
            j += 1
        i = j
    return out


def check(path, text):
    errs, placed = [], set()
    for start, name, body, key_ind in steps(text):
        inst = [n for n, l in body if INSTALL.search(_code(l))]
        placed.update(inst)
        if not inst:
            continue
        bound = [int(m.group(1)) for _, l in body if _indent(l) == key_ind
                 for m in [TIMEOUT.match(l.strip())] if m]
        if not bound:
            errs.append("%s:%d: step '%s' installs packages (line %d) with no "
                        "timeout-minutes" % (path.name, start, name, inst[0]))
        elif bound[0] > MAX_MINUTES:
            errs.append("%s:%d: step '%s' has timeout-minutes: %d, over %d"
                        % (path.name, start, name, bound[0], MAX_MINUTES))
    for n, l in enumerate(text.split("\n"), 1):
        if INSTALL.search(_code(l)) and n not in placed:
            errs.append("%s:%d: an installer call outside any step the scanner parsed"
                        % (path.name, n))
    n_inst = sum(1 for _, _, body, _ in steps(text)
                 if any(INSTALL.search(_code(l)) for _, l in body))
    return errs, n_inst


def controls(ci_text):
    """Each mutation must be refused; returns the names of the ones that were not."""
    ci = WORKFLOWS[0]
    # A real step key, not the header comment that quotes it.
    m = re.search(r"(?m)^ +timeout-minutes: (\d+)$", ci_text)
    first, line_start, line_end = m.start(1), m.start(), m.end() + 1
    new_step = ("      - name: Control step\n        run: |\n"
                "          sudo apt-get install -y gcc\n\n")
    anchor = ci_text.index("      - name: Install")
    stray = ci_text.replace("\njobs:\n", "\n# x\nenv_note: apt-get install gcc\njobs:\n", 1)
    cases = [
        ("one bound removed", ci_text[:line_start] + ci_text[line_end:]),
        ("one bound raised to 360", ci_text[:first] + "360" + ci_text[m.end(1):]),
        ("a new unbounded apt step", ci_text[:anchor] + new_step + ci_text[anchor:]),
        ("an installer line outside every step", stray),
    ]
    missed = []
    for what, text in cases:
        errs, _ = check(ci, text)
        print("  [%s] control: %s is refused" % ("PASS" if errs else "FAIL", what))
        if not errs:
            missed.append(what)
    return missed, len(cases)


def main():
    texts = {p: p.read_text(encoding="utf-8") for p in WORKFLOWS}
    errs, total = [], 0
    for p, t in texts.items():
        e, n = check(p, t)
        print("  %s: %d install step(s), %d unbounded or over %d min"
              % (p.name, n, len(e), MAX_MINUTES))
        errs += e
        total += n
    print("  [%s] accept-control: the workflows as committed"
          % ("PASS" if not errs else "FAIL"))
    missed, n_controls = controls(texts[WORKFLOWS[0]])
    for e in errs:
        print("FAIL: " + e)
    if total == 0:
        errs.append("no install step found at all")
        print("FAIL: no install step found at all -- the scanner is reading nothing")
    if errs or missed:
        print("*** FAILED: CI install steps are not all time-bounded (TODO #353) ***")
        return 1
    print("*** OK: %d install step(s), each bounded at <= %d min; %d controls fired ***"
          % (total, MAX_MINUTES, n_controls))
    return 0


if __name__ == "__main__":
    sys.exit(main())
