#!/usr/bin/env python3
"""TODO #326: hold docker-entrypoint.sh and .github/workflows/ci.yml against each other.

ci.yml's own header says the workflow is a "build/test matrix mirroring
docker-entrypoint.sh's smoke run ... so CI and the scripts can't silently drift
apart".  Nothing compared them, and it HAD drifted: a complete Java port shipped
at TODO #196-#203 and became a REQUIRED CI job, while the Dockerfile went on
advertising a "six-language build matrix" that names neither Java nor a reason
for leaving it out.  That is #287's withdrawn trust-model sentence and #295's
false-reason shape -- a curated claim about how two things relate, checked by
nobody.

The check runs in BOTH directions, because only one of them was ever plausible:

  (a) a target docker-entrypoint.sh runs that NO ci.yml job runs is an error --
      the quickstart drifting ahead of the matrix that is supposed to mirror it;

  (b) a ci.yml job that the entrypoint does NOT cover must carry a reason in
      EXEMPT.  Self-invalidating like every other curated table in this repo: a
      reason naming a job that IS covered fails, and a job that is neither
      covered nor exempt fails.  So Java's absence stops being a silence and
      becomes either a covered job or a written-down decision.

KNOWN LIMIT, stated here rather than discovered later.  This compares
INVOCATIONS, not work: it cannot see that two runs of the same harness use
different caps.  The entrypoint deliberately runs at reduced caps (the twelve
other jobs run every one of its targets at full size; what is unproven in the
container is the SCRIPT), so that difference is the design and not a defect.
No third-party dependencies: ci.yml is parsed with a narrow line scanner rather
than PyYAML, which is not in this repo's dependency set.
"""

import re
import sys
from pathlib import Path


# A retracted claim reads exactly like an asserted one to a string search, and
# TODO #326 hit that THREE TIMES while being written: the first version of this
# check flagged 'six-language' and then 'several minutes' inside the very comments
# added to withdraw them, and then flagged them again in CLAUDE.md's paragraph
# DESCRIBING the withdrawal.  #324's coverage guard met the mirror image of the
# problem -- its own rationale satisfied it -- and answered by stripping comments;
# that is no use here, because the claims under test ARE prose.
#
# So the rule is SCOPED rather than absolute, which is #299's prescription for a
# source check: the phrase may appear only where it is marked as retracted.  Two
# details, both found by running it and neither by reading it -- the window is TWO
# LINES, because a wrapped line puts the marker on the previous one; and comment
# markers are STRIPPED first, or a join re-inserts a '#' between "used to" and
# "say".
RETRACTED = (r"(?i)used to say|used to|until then|until TODO|was written at|"
             r"no longer|absent from|flagged|advertis|was wrong|did not build|"
             r"stopped|superseded")


def asserted_unretracted(text, phrase_re):
    """Line numbers where phrase_re appears WITHOUT a retraction marker nearby."""
    lines = [re.sub(r"^\s*(#|//)\s?", "", l) for l in text.splitlines()]
    hits = []
    for i, line in enumerate(lines, 1):
        if not re.search(phrase_re, line):
            continue
        # BACKWARD-LOOKING ONLY: the marker may share the line or be on the one
        # before, never on the one AFTER.  A centred window let a re-asserted
        # claim borrow the marker from the retraction paragraph beneath it --
        # which silently un-fired a control that had previously passed, caught
        # only by re-running every control after the refactor.  A shared code
        # path is exactly where a control regresses.
        window = " ".join(lines[max(0, i - 2):i])
        if not re.search(RETRACTED, window):
            hits.append(i)
    return hits


ROOT = Path(__file__).resolve().parent.parent
CI = ROOT / ".github/workflows/ci.yml"
ENTRY = ROOT / "docker-entrypoint.sh"
DOCKERFILE = ROOT / "Dockerfile"
README = ROOT / "README.md"
CLAUDEMD = ROOT / "CLAUDE.md"

# A ci.yml job the quickstart image does not exercise, and why.  Every entry is
# checked in both directions: naming a job that IS covered is an error, and a
# job that is neither covered nor named here is an error.
EXEMPT = {
    "native-java": (
        "The image installs no JDK.  Adding default-jdk-headless roughly doubles "
        "it for a port whose own CliTest scripts are Java-vs-Python interop, which "
        "needs no cross-toolchain and so gains nothing from the container.  This "
        "is the omission TODO #326 found UNSTATED -- the Dockerfile advertised a "
        "'six-language build matrix' and named neither Java nor this reason."
    ),
    "arduino": (
        "Needs arduino-cli plus a board target, i.e. not a host-portable build.  "
        "Excluded since TODO #139 and documented in the Dockerfile header."
    ),
    "native-interop": (
        "Its scripts drive two or more CLIs at once; the entrypoint runs "
        "CliTest/test_c_interop.sh, which is one of them, as its CLI smoke test.  "
        "Running the rest would re-run at full size what the required job already "
        "covers, which is the runtime trap TODO #289 recorded."
    ),
    "cross-lang-compat": (
        "Four-CLI matrices, so they need the Java CLI -- covered by native-java's "
        "reason above."
    ),
    "sanitizers": (
        "Needs clang plus a separate ASan/UBSan build of the whole tree, and a "
        "bounded valgrind pass.  A quickstart image is for showing the suite "
        "builds and runs, not for instrumented analysis."
    ),
    "fuzz-smoke": (
        "30 s per target of libFuzzer/go-fuzz/Hypothesis.  Needs clang and "
        "python3-hypothesis, and asserts nothing about whether the suite builds."
    ),
    "analysis-findings": (
        "~120 min of SecurityProofsCode gates, and z3-solver is a hard "
        "requirement for three of them (TODO #290).  Categorically not a "
        "quickstart concern."
    ),
    "docker": (
        "The job that RUNS docker-entrypoint.sh, so it cannot be 'covered by' it "
        "without circularity.  Listed rather than special-cased, because the rule "
        "below is exhaustive and caught this job on its first run -- which is the "
        "behaviour wanted: a new job owes a statement either way."
    ),
    "katex": (
        "Markdown math rendering, via node.  Touches no build target at all."
    ),
}

# What counts as a target the two sides can be compared on.  Keyed by the
# ci.yml job that owns it at full size.
TARGETS = {
    "native-c": [r"\./build_c\.sh", r"Herradura_tests_c"],
    "native-go": [r"\./build_go\.sh", r"Herradura_tests\.go"],
    "native-python": [r"Herradura_tests\.py"],
    "arm-i386": [r"\./build_arm\.sh", r"\./build_asm_i386\.sh",
                 r"\./run_arm\.sh", r"\./run_asm_i386\.sh"],
}


def strip_comments(text, char="#"):
    out = []
    for line in text.splitlines():
        i = line.find(char)
        out.append(line if i < 0 else line[:i])
    return "\n".join(out)


def ci_jobs(ci_text):
    """Top-level job ids: two-space-indented `key:` under `jobs:`."""
    jobs = []
    in_jobs = False
    for line in ci_text.splitlines():
        if re.match(r"^jobs:\s*$", line):
            in_jobs = True
            continue
        if in_jobs:
            if re.match(r"^\S", line):
                break
            m = re.match(r"^  ([A-Za-z0-9_-]+):\s*$", line)
            if m:
                jobs.append(m.group(1))
    return jobs


def main():
    for p in (CI, ENTRY, DOCKERFILE):
        if not p.exists():
            print(f"FAIL: {p} is missing")
            return 1

    ci_raw = CI.read_text()
    ci_code = strip_comments(ci_raw)
    entry_code = strip_comments(ENTRY.read_text())

    jobs = ci_jobs(ci_raw)
    if len(jobs) < 5:
        print(f"FAIL: parsed only {len(jobs)} ci.yml jobs — the scanner broke, "
              f"which would make every check below pass vacuously")
        return 1

    errors = []
    notes = []

    # --- direction (a): every target the entrypoint runs must be run by CI too
    covered = set()
    for job, pats in TARGETS.items():
        for pat in pats:
            in_entry = re.search(pat, entry_code) is not None
            in_ci = re.search(pat, ci_code) is not None
            if in_entry and not in_ci:
                errors.append(
                    f"(a) docker-entrypoint.sh runs {pat!r} and no ci.yml job does — "
                    f"the quickstart has drifted AHEAD of the matrix that mirrors it")
            if in_entry:
                covered.add(job)

    # a TARGETS job whose patterns appear nowhere in the entrypoint is not covered
    for job, pats in TARGETS.items():
        if job not in covered:
            if not any(re.search(p, entry_code) for p in pats):
                continue  # falls through to direction (b)

    # --- direction (b): every ci.yml job is covered or carries a reason
    for job in jobs:
        if job in covered:
            if job in EXEMPT:
                errors.append(
                    f"(b) '{job}' is EXEMPT but the entrypoint does cover it — "
                    f"delete the entry rather than leaving a stale reason")
            continue
        if job not in EXEMPT:
            errors.append(
                f"(b) ci.yml job '{job}' is neither exercised by "
                f"docker-entrypoint.sh nor listed in EXEMPT with a reason — "
                f"say which, do not leave it silent (this is how Java's "
                f"absence survived)")

    for job in EXEMPT:
        if job not in jobs:
            errors.append(
                f"(b) EXEMPT names '{job}', which is not a ci.yml job — "
                f"a reason for something that does not exist")

    # --- the claim that started the item: Java must be named or reasoned about
    if "native-java" in EXEMPT:
        df = DOCKERFILE.read_text()
        if not re.search(r"(?i)java", df):
            errors.append(
                "the Dockerfile does not mention Java at all.  Its exclusion is a "
                "DECISION (see EXEMPT['native-java']) and a decision belongs in "
                "the file a reader opens, which is exactly what TODO #326 found "
                "missing")
        for i in asserted_unretracted(df, r"(?i)six-language"):
            errors.append(
                f"Dockerfile:{i} asserts 'six-language build matrix' without "
                f"marking it retracted.  Count what it builds and say that "
                f"number, or name the languages")

    # --- the runtime claim.
    #
    # A STRING-PRESENCE RULE CANNOT TELL A CLAIM FROM ITS RETRACTION, and this
    # check learned that twice while being written: a first version flagged
    # 'six-language' and then 'several minutes' in the very comments added to
    # withdraw them.  #324's coverage guard met the mirror image of this (its own
    # rationale satisfied it) and answered by stripping comments; that is no use
    # here, because the claim under test IS a comment.  So the rule is SCOPED
    # instead, which is #299's prescription for a source check: the stale phrase
    # may appear only on a line that also marks it as retracted, so re-asserting
    # it still fails while describing its history does not.
    ent = ENTRY.read_text()
    for i in asserted_unretracted(ent, r"(?i)several minutes \(e\.g\. an ARM SBC\)"):
        errors.append(
            f"docker-entrypoint.sh:{i} asserts 'several minutes (e.g. an ARM "
            f"SBC)' without marking it retracted.  Measured at ~75-90 min on "
            f"aarch64, and that figure is the input to whether CI runs this, "
            f"so a stale one argues for the wrong answer")
    # And the positive half: the measured figure has to actually be there, or
    # deleting the sentence outright would satisfy the rule above (TODO #234's
    # vacuous pass).
    if not re.search(r"(?i)~?7[05]\s*-\s*90\s*MINUTES", ent):
        errors.append(
            "docker-entrypoint.sh does not state the MEASURED runtime.  Removing "
            "the stale claim is not the same as replacing it -- a reader still "
            "needs the number, and a rule satisfied by deletion checks nothing")

    # --- the same claim lives in three files, which is the disagreement-between-
    # documents class check_security_md.py and check_docs_consistency.py exist for.
    # TODO #326 found the language count wrong in the Dockerfile, README.md AND
    # CLAUDE.md, so fixing one would have left two.
    for doc in (README, CLAUDEMD):
        if not doc.exists():
            errors.append(f"{doc.name} is missing")
            continue
        text = doc.read_text()
        for i in asserted_unretracted(text, r"(?i)six-language"):
            errors.append(
                f"{doc.name}:{i} asserts 'six-language' of the Docker image "
                f"without marking it retracted.  The count was wrong in THREE "
                f"files at once; correcting one leaves two")
        if re.search(r"(?i)docker", text) and not re.search(r"(?i)java", text):
            errors.append(
                f"{doc.name} describes the image without mentioning Java, whose "
                f"omission is a DECISION and not an oversight")

    print(f"  ci.yml jobs           : {len(jobs)}")
    print(f"  covered by entrypoint : {len(covered)}  ({', '.join(sorted(covered))})")
    print(f"  exempt with a reason  : {len(EXEMPT)}")
    for n in notes:
        print(f"  NOTE: {n}")

    if errors:
        print()
        for e in errors:
            print(f"  FAIL: {e}")
        print(f"\n*** FAILED: {len(errors)} mirroring problem(s) (TODO #326) ***")
        return 1

    print("\n*** OK: docker-entrypoint.sh and ci.yml agree, and every job is "
          "covered or reasoned about ***")
    return 0


if __name__ == "__main__":
    sys.exit(main())
