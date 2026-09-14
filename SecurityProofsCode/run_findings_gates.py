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

EVERY .py HERE IS EITHER DISCOVERED OR DECLARED (TODO #291).  Discovery answers
"which of the gating scripts run"; until #291 nothing asked which scripts GATE.
The answer was 35 of 81 -- 46 produced output that no exit status carried, 33 of
them cited by SecurityProofs-*.md or CLAUDE.md as backing a claim, and 22 of them
computing a PASS/FAIL verdict and then discarding it, which is TODO #233's defect
one layer out.  So a script that does not gate must say why in NON_GATING, and
the runner FAILS on one that is neither discovered nor declared.  That is the
part that does not decay: adding an analysis script now forces the question.

Skipping is still possible and is deliberately awkward: add the script to
EXCLUDED with a reason.  That table is self-invalidating the way every other
curated table in this repo is (spec/check_docs_consistency.py's anchors,
cli_surface_gaps, PARAM_DIVERGENCE): an entry naming a file that does not
exist, or that is no longer a gating script, FAILS -- so an exclusion cannot
outlive its reason.

WHAT `--quick` MEANS HERE.  A script that declares a reduced-sample flag is run
with it; one that does not is run as it is.  TWO SPELLINGS are in use and both
count -- `--quick` in 20 scripts and `--fast` in three (TODO #290, which found
those three running at their DEFAULT budgets inside a job that had asked for the
reduced one: for nl_fscx_exact_trail_search.py that is 19 s against twenty-odd
minutes, with the same verdicts).  `--quick` in this directory is a
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

# A script "gates" when its exit status carries its own verdict.
#
# TODO #291 GENERALISED THIS, and the reason is the blind spot the file already
# documents below: the first version listed three exact call shapes
# (`sys.exit(main())`, `raise SystemExit(main())`, `sys.exit(run_tests())`) plus
# a bare `sys.exit(1)`, and #291 converted five scripts whose entry point is
# called `run()` -- every one of them read as "does not gate".  Naming the
# function was never the point; EXITING WITH A COMPUTED STATUS is.  So the
# pattern is now `sys.exit(<call>)` / `raise SystemExit(<call>)` for any
# function, plus an exit on a literal-or-expression 1.  `sys.exit(0)` still
# does not count, and should not: a script that always exits 0 is not a gate.
_GATING_RE = re.compile(
    r"sys\.exit\(\s*[A-Za-z_]\w*\("
    r"|raise\s+SystemExit\(\s*[A-Za-z_]\w*\("
    r"|sys\.exit\(\s*1\b"
    r"|raise\s+SystemExit\(\s*1\b")

# A reduced-sample mode, under either of the two names this directory uses.
# TODO #290: three scripts spell it `--fast` (nl_fscx_exact_trail_search.py,
# rnl_parameter_selection.py, hkex_rnl_lattice_2026.py) and looking only for
# `--quick` ran all three at their default budgets in a job that had asked for
# the reduced one.  Same shape as the _CLAIM_RE blind spot below: the runner
# reads a spelling, so a second spelling is invisible until it is named.
_QUICK_RE = re.compile(
    r"""add_argument\(\s*['"](--quick|--fast)['"]"""
    r"""|['"](--quick|--fast)['"]\s+in\s+sys\.argv""")


def _quick_flag(src):
    """The reduced-sample flag a script declares, or None.

    TODO #291 added the THIRD spelling, for the same reason #290 added the
    second: two scripts (stern_f_multiround_fs.py, hybrid_credential_phi.py)
    read the flag straight out of sys.argv rather than through argparse, so an
    argparse-only pattern ran them at full sample sizes inside a job that had
    asked for the reduced one -- and stern_f_multiround_fs.py was ALREADY a
    discovered gate, so it had been running that way since #289.
    """
    m = _QUICK_RE.search(src)
    if not m:
        return None
    return m.group(1) or m.group(2)

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


# name -> reason.  A script here is NOT a gate and does not run: it holds no
# finding whose loss would be a defect.  Self-invalidating in both directions
# like EXCLUDED -- an entry naming an absent file fails, and so does one naming
# a script that HAS since become a gate, so making one gate forces its entry
# out.  Keep the reasons this specific; "it is only a demo" is not one, since
# several demos gate (hpks_threshold_demo.py, oprf_demo.py, vdf_demo.py all
# assert something falsifiable and all run here).
NON_GATING = {
    "hkex_cfscx_blong.py":
        "DESIGN-SPACE SURVEY.  Five convolution strategies for a large-B FSCX "
        "variant, none of them shipped, none cited by any document.  Its tables "
        "are the record of why each was rejected; there is no claim about the "
        "suite for a gate to defend",
    "hkex_cfscx_compress.py":
        "DESIGN-SPACE SURVEY -- the compress-to-trapdoor construction, rejected; "
        "same reason as hkex_cfscx_blong.py",
    "hkex_cfscx_intops.py":
        "DESIGN-SPACE SURVEY -- padlock/asymmetric/hash-like schemes over the "
        "integer-op expansion, none adopted; same reason as hkex_cfscx_blong.py",
    "hkex_cfscx_preshared.py":
        "DESIGN-SPACE SURVEY -- five preshared-value constructions, none adopted; "
        "same reason as hkex_cfscx_blong.py",
    "hkex_cfscx_twostep.py":
        "DESIGN-SPACE SURVEY -- eight two-step constructions, none adopted; same "
        "reason as hkex_cfscx_blong.py",
    "nl_fscx_v2_orbit.py":
        "DISTRIBUTIONAL CHARACTERISATION.  Sampled orbit lengths of pi_K: medians, "
        "a bimodal split and a non-monotone n=24 anomaly.  Gating it would mean "
        "inventing thresholds for a sampled distribution, which TODO #291 "
        "explicitly warns against; the conclusions that mattered are in "
        "nl_fscx_v2_csp.py, which does gate",
    "stern_ct_demo.py":
        "ITS VERDICT IS THAT A LEAK IS STILL THERE.  The demo measures wall-clock "
        "timing against Hamming weight in the branchy Python _stern_apply_perm "
        "and reports [PASS] when the correlation is high -- so a gate would fail "
        "if anyone made that code constant-time, and would flake on a loaded "
        "machine.  Python is a reference implementation and this is a documented "
        "accepted risk, not a regression to defend",
}


def discover():
    """Every .py here whose exit status is its own verdict, plus the claimants.

    Returns (gating, unclaimed, undeclared) -- gating as (name, reduced-sample
    flag or None) pairs, unclaimed as the names that advertise a findings gate
    without matching any exit shape discovery knows, and undeclared as the
    scripts that neither gate nor appear in NON_GATING (TODO #291).
    """
    gating, claims, undeclared = [], [], []
    for name in sorted(os.listdir(HERE)):
        if not name.endswith(".py") or name == SELF:
            continue
        with open(os.path.join(HERE, name), encoding="utf-8") as fh:
            src = fh.read()
        if _GATING_RE.search(src):
            gating.append((name, _quick_flag(src)))
            continue
        if _CLAIM_RE.search(src):
            claims.append(name)
        if name not in NON_GATING:
            undeclared.append(name)
    return gating, claims, undeclared


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


def check_declarations(found, undeclared):
    """TODO #291's coverage rule, in both directions.

    A script that neither gates nor is declared non-gating is an error -- that
    is the 46-script hole #291 closed.  And a NON_GATING entry that describes
    nothing is an error too, exactly as an EXCLUDED one is: naming a file that
    is gone, or one that has since become a gate, fails until the entry goes.
    """
    names = {n for n, _ in found}
    bad = []
    for name in undeclared:
        bad.append("%s: neither gates nor is declared -- make its exit status "
                   "its verdict, or add it to NON_GATING with a reason" % name)
    for name, reason in sorted(NON_GATING.items()):
        if not os.path.exists(os.path.join(HERE, name)):
            bad.append("%s: declared non-gating, but no such file" % name)
        elif name in names:
            bad.append("%s: declared non-gating, but it DOES gate now -- delete "
                       "the entry (reason on file: %s)" % (name, reason))
    return bad


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--quick", action="store_true", default=True,
                    help="pass --quick/--fast to scripts that declare one "
                         "(the default)")
    ap.add_argument("--full", dest="quick", action="store_false",
                    help="run every script at its default sample sizes")
    ap.add_argument("--list", action="store_true",
                    help="print what would run and exit")
    ap.add_argument("--timeout", type=int, default=3600,
                    help="per-script wall-clock limit in seconds (default 3600); "
                         "a hang must fail rather than consume the job")
    a = ap.parse_args()

    found, unclaimed, undeclared = discover()
    orphans = check_exclusions(found) + check_declarations(found, undeclared)
    orphans += ["%s: its header advertises a findings gate, but its exit shape "
                "is not one this runner discovers -- teach _GATING_RE the shape "
                "or the script will never run in CI" % n for n in unclaimed]
    runnable = [(n, q) for n, q in found if n not in EXCLUDED]

    print("=" * 78)
    print("  findings gates: %d discovered, %d excluded, %d to run  (TODO #289); "
          "%d declared non-gating (TODO #291)"
          % (len(found), len(EXCLUDED), len(runnable), len(NON_GATING)))
    print("=" * 78)

    if orphans:
        for line in orphans:
            print("  EXCLUSION ERROR: " + line)

    if a.list:
        for name, quick_flag in runnable:
            print("  %-44s %s" % (name, quick_flag if (quick_flag and a.quick)
                                        else ""))
        for name, reason in sorted(EXCLUDED.items()):
            print("  %-44s EXCLUDED: %s" % (name, reason))
        for name, reason in sorted(NON_GATING.items()):
            print("  %-44s NON-GATING: %s" % (name, reason.split(".")[0]))
        return 1 if orphans else 0

    failures = []
    t_all = time.time()
    for name, quick_flag in runnable:
        argv = [sys.executable, os.path.join(HERE, name)]
        if quick_flag and a.quick:
            argv.append(quick_flag)
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
                 " " + quick_flag if (quick_flag and a.quick) else ""))
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
        print("*** FAILED: %d coverage error(s) -- an exclusion or non-gating "
              "declaration that describes nothing, or a script that is neither "
              "***" % len(orphans))
    if failures:
        print("*** FAILED: %d finding gate(s) stopped reproducing: %s ***"
              % (len(failures), ", ".join(n for n, _, _ in failures)))
    if not orphans and not failures:
        print("*** OK: all %d findings gates reproduce ***" % len(runnable))
    return 1 if (orphans or failures) else 0


if __name__ == "__main__":
    sys.exit(main())
