#!/usr/bin/env python3
"""run_findings_gates.py -- run every findings-gating analysis script (TODO #289)

About three dozen scripts in this directory close with a sentence of the form
"exits non-zero if a finding stops reproducing", and CLAUDE.md repeats it for
each of them.  Until TODO #285 no CI job collected that status at all, so the
promise was untested; #285, #286 and #287 then added scripts to one step in
`native-python` ONE AT A TIME, excluding the rest on runtime grounds.  Twice
the excluded set turned out to contain a script that was already failing --
`qcmdpc_parameter_selection.py` (three gates, found by #286) and
`qcmdpc_bgf_variants.py` (six findings, found by #288) -- and each exclusion
had been individually defensible.  This runner is TODO #289's replacement for
that judgement call.

THE RULE, and it is the whole point of the file: the set of scripts that run is
DISCOVERED, not enumerated.  A script whose exit status is its own verdict --
`sys.exit(main())`, `raise SystemExit(main())`, or a bare `sys.exit(1)` on a
failed finding -- is run, and nothing has to be added anywhere for that to
happen.  The previous shape was a list in `ci.yml`, and a list is exactly what
lets "we did not get round to adding it" look identical to "it passes".

Skipping is still possible and is deliberately awkward: add the script to
EXCLUDED with a reason.  That table is self-invalidating the way every other
curated table in this repo is (spec/check_docs_consistency.py's anchors,
cli_surface_gaps, PARAM_DIVERGENCE): an entry naming a file that does not
exist, or that is no longer a gating script, FAILS -- so an exclusion cannot
outlive its reason.

WHAT `--quick` MEANS HERE.  A script that declares a `--quick` flag is run with
it; one that does not is run as it is.  `--quick` in this directory is a
smaller-sample mode that still reproduces every finding (the sample sizes move,
the verdicts do not), which is the property that makes it usable as a gate --
see qcmdpc_dfr_weak_keys.py's header for the canonical statement.  Pass --full
here to run everything at its default sizes instead; that is hours, not
minutes, and is a local operation rather than a CI one.

FAILURES DO NOT STOP THE RUN.  The interesting output is WHICH gates stopped
reproducing, and a `set -e` loop reports one and hides the rest -- #286 found
three failures in one script and #288 six, so partial reporting is not a
hypothetical.  Every script runs, the failures are re-listed at the end, and
the exit status is non-zero if any failed.

Run:  python3 SecurityProofsCode/run_findings_gates.py [--quick|--full] [--list]
                                                       [--timeout SECONDS]
"""

import argparse
import os
import re
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
SELF = os.path.basename(os.path.abspath(__file__))

# A script "gates" when its exit status carries its own verdict.  Three shapes
# are in use; all three are here because all three occur, not by design.
_GATING_RE = re.compile(
    r"sys\.exit\(\s*main\(\)"
    r"|raise\s+SystemExit\(\s*main\(\)\s*\)"
    r"|sys\.exit\(\s*run_tests\(\)"
    r"|sys\.exit\(\s*1\s*\)")

_QUICK_RE = re.compile(r"""add_argument\(\s*['"]--quick['"]""")

# The blind spot the three shapes above would otherwise have.  Discovery reads
# the exit CALL, so a script that gates through a fourth shape is silently not
# run -- which is the same class of hole TODO #288 found in check B'' of
# spec/check_docs_consistency.py, where a correct sentence was invisible
# because the checker looked for the wrong token.  So the CLAIM is checked
# against the discovery: a script that advertises a findings gate in its own
# header and is not discovered is an ERROR, not a silent omission.  One
# direction only -- a gating script need not advertise, and several do not.
_CLAIM_RE = re.compile(r"exits?\s+non-?zero", re.I)

# name -> reason.  EMPTY, and that is the point of TODO #289: there is no
# longer a runtime budget to spend, because this job runs beside the other
# eleven rather than inside one of them.  An entry here must say what makes its
# script unrunnable in CI -- not that it is slow -- and will fail generation
# once that stops being true.
EXCLUDED = {}


def discover():
    """Every .py here whose exit status is its own verdict, plus the claimants.

    Returns (gating, unclaimed) -- gating as (name, declares --quick) pairs,
    unclaimed as the names that advertise a findings gate without matching any
    exit shape discovery knows.
    """
    gating, claims = [], []
    for name in sorted(os.listdir(HERE)):
        if not name.endswith(".py") or name == SELF:
            continue
        with open(os.path.join(HERE, name), encoding="utf-8") as fh:
            src = fh.read()
        if _GATING_RE.search(src):
            gating.append((name, bool(_QUICK_RE.search(src))))
        elif _CLAIM_RE.search(src):
            claims.append(name)
    return gating, claims


def check_exclusions(found):
    """The orphan rule: an exclusion that describes nothing is an error."""
    names = {n for n, _ in found}
    bad = []
    for name, reason in sorted(EXCLUDED.items()):
        if not os.path.exists(os.path.join(HERE, name)):
            bad.append("%s: excluded, but no such file" % name)
        elif name not in names:
            bad.append("%s: excluded, but it is no longer a gating script -- "
                       "delete the entry (reason on file: %s)" % (name, reason))
    return bad


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--quick", action="store_true", default=True,
                    help="pass --quick to scripts that declare it (the default)")
    ap.add_argument("--full", dest="quick", action="store_false",
                    help="run every script at its default sample sizes")
    ap.add_argument("--list", action="store_true",
                    help="print what would run and exit")
    ap.add_argument("--timeout", type=int, default=3600,
                    help="per-script wall-clock limit in seconds (default 3600); "
                         "a hang must fail rather than consume the job")
    a = ap.parse_args()

    found, unclaimed = discover()
    orphans = check_exclusions(found)
    orphans += ["%s: its header advertises a findings gate, but its exit shape "
                "is not one this runner discovers -- teach _GATING_RE the shape "
                "or the script will never run in CI" % n for n in unclaimed]
    runnable = [(n, q) for n, q in found if n not in EXCLUDED]

    print("=" * 78)
    print("  findings gates: %d discovered, %d excluded, %d to run  (TODO #289)"
          % (len(found), len(EXCLUDED), len(runnable)))
    print("=" * 78)

    if orphans:
        for line in orphans:
            print("  EXCLUSION ERROR: " + line)

    if a.list:
        for name, has_quick in runnable:
            print("  %-44s %s" % (name, "--quick" if (has_quick and a.quick) else ""))
        for name, reason in sorted(EXCLUDED.items()):
            print("  %-44s EXCLUDED: %s" % (name, reason))
        return 1 if orphans else 0

    failures = []
    t_all = time.time()
    for name, has_quick in runnable:
        argv = [sys.executable, os.path.join(HERE, name)]
        if has_quick and a.quick:
            argv.append("--quick")
        t0 = time.time()
        try:
            proc = subprocess.run(argv, cwd=os.path.dirname(HERE),
                                  stdout=subprocess.PIPE,
                                  stderr=subprocess.STDOUT,
                                  timeout=a.timeout)
            rc, out = proc.returncode, proc.stdout
        except subprocess.TimeoutExpired as exc:
            rc, out = 124, (exc.output or b"") + b"\n*** TIMEOUT ***\n"
        dt = time.time() - t0

        print("  [%s] %6.0f s  %s%s"
              % ("ok  " if rc == 0 else "FAIL", dt, name,
                 " --quick" if (has_quick and a.quick) else ""))
        sys.stdout.flush()
        if rc != 0:
            failures.append((name, rc, out.decode("utf-8", "replace")))

    print("-" * 78)
    print("  total %.1f min over %d scripts" % ((time.time() - t_all) / 60.0,
                                                len(runnable)))

    for name, rc, out in failures:
        print("\n" + "=" * 78)
        print("  FAILED (exit %d): %s" % (rc, name))
        print("=" * 78)
        tail = out.rstrip().splitlines()[-40:]
        for line in tail:
            print("  | " + line)

    print()
    if orphans:
        print("*** FAILED: %d exclusion(s) describe nothing ***" % len(orphans))
    if failures:
        print("*** FAILED: %d finding gate(s) stopped reproducing: %s ***"
              % (len(failures), ", ".join(n for n, _, _ in failures)))
    if not orphans and not failures:
        print("*** OK: all %d findings gates reproduce ***" % len(runnable))
    return 1 if (orphans or failures) else 0


if __name__ == "__main__":
    sys.exit(main())
