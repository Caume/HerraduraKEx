#!/usr/bin/env python3
"""TODO #329: every shipped executable under docs/examples/ and benchmarks/ must
be built by some job, or carry a reason why not.

WHY THIS IS A DIFFERENT PREDICATE FROM ci.yml's HARNESS COVERAGE GUARD.  That
guard matches a harness by FILENAME PATTERN -- `test_*.py`, `*_test.py`,
`*_test.go` -- and TODO #325 stated the limit that leaves: "a harness named by
none of the patterns stays invisible -- a main() in a file called something
else, a shell script outside CliTest/."  #326 closed the shell-script half by
census.  This is the main() half.  `hello_herradura.go` says exactly what it is
and matches no test pattern, so no widening of that list could ever reach it;
the predicate that reaches it is the ENTRY POINT.

WHAT THE CENSUS FOUND when it was written (v9.5.18).  15 executables, 11 with no
runner at all -- and two separate five-release breakages inside them:

  * benchmarks/rnl_ring_cost.py exited 1 with `ValueError: E_WIDTH: 512`.  It
    passed the ring dimension as the session-key width too, which stopped being
    legal at v9.3.0 when TODO #314 pass 4 gave Python's BitArray BITARRAY.md
    2's width rule.  #315 found that identical defect in two
    SecurityProofsCode gates AT THE SAME COMMIT; benchmarks/ was the directory
    nobody looked at.  CLAUDE.md names this file as the HKEX-RNL cost baseline.

  * compare_hkex_x25519.py, compare_hpks_ed25519.py and compare_hske_aead.py
    import bindings/ffi/python/herradura_ffi.py, so they are consumers of the
    shim TODO #324 found with an unset `nbits`.  Against the shim that shipped
    from v9.1.0 to v9.5.12 a single hkex_gf_pubkey call aborts -- rc=134,
    "E_WIDTH in ba_nbytes".  #324's own record says it "was found by trying to
    run a benchmark": one of these three is how that item was discovered, by
    hand, and none of them had a runner.

And the coverage that DID exist was accidental: three C files are covered
because tools/poison_build.sh discovers `#include herradura.h` for a
width-guard reason, and the only two files ever given a step were given one by
an item that found them BROKEN (#287's MCP example, #324's C example).

THREE RULES, each self-invalidating, on the model of EXCLUDED / NON_GATING /
PARAM_USE_EXEMPT.

 (1) A discovered executable must be CLAIMED: named by a line of ci.yml that
     could actually execute it, or discovered by tools/poison_build.sh, or
     given an EXEMPT reason.

 (2) A LANGUAGE whose detector finds nothing is an ERROR, not a silence.  This
     is #325's per-pattern rule carried over: its guard OR-ed its patterns
     together, so a dead pattern was indistinguishable from a satisfied one,
     and the per-pattern split found a second dead pattern on its first run.

 (3) EXEMPT is exhaustive in BOTH directions.  An entry naming a file that is
     absent fails, and so does an entry for a file that has since acquired a
     runner -- so wiring something up FORCES its exemption out rather than
     leaving a stale claim behind.  It ships EMPTY, like #295's
     PARAM_USE_EXEMPT: every one of the eleven was wired up, so a future entry
     means somebody argued for an unbuilt executable, not that this was
     switched off.

KNOWN LIMIT, stated rather than discovered.  This asks whether something is
BUILT AND RUN, never whether the run asserts anything -- a benchmark that prints
numbers nobody checks satisfies it.  Two such cases were fixed in this item
because they would have made the new coverage vacuous (a build failure reading
as a skip in compare_fscx_revolve_closed_form.py, and a discarded
reconciliation verdict in rnl_ring_cost.py), but the check cannot see the class.
That is #234's vacuous pass, and the axis for it is the numbered-test one.
Scope: the two directories censused here, not every file in the repo.
"""

import os
import re
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)

ROOTS = ["docs/examples", "benchmarks"]

# An entry point per language.  Deliberately NOT a filename pattern -- see the
# module docstring.
#
# PYTHON IS PARSED, NOT MATCHED, and that correction is worth keeping.  The first
# version of this file looked for `if __name__ == "__main__"` and so MISSED BOTH
# docs/examples PYTHON EXAMPLES -- they are top-level scripts that simply execute
# statements, with no guard at all -- which would have censused 13 of 15 and
# reported OK on a corpus with two holes in it.  That is #306's sixth-spelling
# hazard, and #295's rule that getting a corpus wrong in the LENIENT direction
# makes the whole check pass vacuously: an under-matching detector cannot fail.
# ast sees both shapes because it sees what the file DOES -- a module-level call,
# or a __main__ guard -- rather than how it is spelled.
#
# Go and C stay regex: there is no parser to hand, and `func main()` / `int
# main(` are single canonical spellings in a way a Python entry point is not.
GO_MAIN = re.compile(r"^func\s+main\s*\(\s*\)", re.M)
C_MAIN = re.compile(r"^\s*(?:static\s+)?int\s+main\s*\(", re.M)


def _python_is_executable(text):
    """True if running this file as a script would DO something.

    Two accepted shapes: a `__main__` guard, or a module-level call expression.
    A file with neither is an importable library and is not an entry point.
    """
    import ast
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return False
    for node in tree.body:
        if isinstance(node, ast.If):
            # if __name__ == "__main__":
            for sub in ast.walk(node.test):
                if isinstance(sub, ast.Name) and sub.id == "__name__":
                    return True
        if isinstance(node, ast.Expr) and isinstance(node.value, ast.Call):
            return True
    return False


def _detect(ext, text):
    if ext == ".py":
        return _python_is_executable(text)
    if ext == ".go":
        return bool(GO_MAIN.search(text))
    if ext == ".c":
        return bool(C_MAIN.search(text))
    return False


LANGS = [(".py", "python"), (".go", "go"), (".c", "c")]

# Files claimed by tools/poison_build.sh, which DISCOVERS every .c including
# herradura.h, then builds it and runs it under -ftrivial-auto-var-init.  Read
# from the script's own predicate rather than restated, so a change there is not
# silently inherited here.
POISON_PREDICATE = re.compile(r"#include.*herradura\.h")

# ---------------------------------------------------------------------------
# EXEMPT: path -> reason.  Ships EMPTY (rule 3).  An entry here must name a
# file that EXISTS and that nothing else claims, or this check fails.
# ---------------------------------------------------------------------------
EXEMPT: "dict[str, str]" = {}


def discover():
    """Every file under ROOTS carrying an entry point, as {path: language}."""
    found, per_lang = {}, {name: 0 for _, name in LANGS}
    for root in ROOTS:
        abs_root = os.path.join(_ROOT, root)
        if not os.path.isdir(abs_root):
            print(f"ERROR: root {root!r} does not exist, so this census is "
                  f"reading nothing (TODO #329)")
            return None, None
        for dirpath, _dirnames, filenames in os.walk(abs_root):
            if "__pycache__" in dirpath:
                continue
            for fn in sorted(filenames):
                ext = os.path.splitext(fn)[1]
                for e, lang in LANGS:
                    if ext != e:
                        continue
                    full = os.path.join(dirpath, fn)
                    rel = os.path.relpath(full, _ROOT)
                    try:
                        text = open(full, encoding="utf-8", errors="replace").read()
                    except OSError:
                        continue
                    if _detect(ext, text):
                        found[rel] = lang
                        per_lang[lang] += 1
    return found, per_lang


def ci_claims():
    """Lines of ci.yml that could actually execute something, comments stripped.

    Comment-stripping is TODO #324's lesson, restated by #326: a guard whose own
    rationale satisfies it checks nothing, and the prose in this repo names these
    paths constantly.
    """
    p = os.path.join(_ROOT, ".github", "workflows", "ci.yml")
    out = []
    for line in open(p, encoding="utf-8").read().splitlines():
        stripped = re.sub(r"#.*$", "", line)
        if stripped.strip():
            out.append(stripped)
    return "\n".join(out)


def poison_claims():
    """The .c files tools/poison_build.sh would discover."""
    claimed = set()
    for dirpath, _d, filenames in os.walk(_ROOT):
        if os.sep + ".git" in dirpath:
            continue
        for fn in filenames:
            if not fn.endswith(".c"):
                continue
            full = os.path.join(dirpath, fn)
            try:
                text = open(full, encoding="utf-8", errors="replace").read()
            except OSError:
                continue
            if POISON_PREDICATE.search(text):
                claimed.add(os.path.relpath(full, _ROOT))
    return claimed


def main():
    found, per_lang = discover()
    if found is None:
        return 1

    problems = []

    # Rule 2: a detector that finds nothing is an error.
    for _e, lang in LANGS:
        if per_lang[lang] == 0:
            problems.append(
                f"DETECTOR DEAD: the {lang} entry-point detector matches nothing "
                f"under {' '.join(ROOTS)} -- it used to match something, so "
                f"either the pattern is wrong or the last such executable went "
                f"and the detector should go with it (TODO #329, rule 2)")

    ci = ci_claims()
    poisoned = poison_claims()

    rows = []
    for rel in sorted(found):
        if rel in poisoned:
            how = "poison_build.sh (discovers herradura.h consumers)"
        elif rel in ci:
            how = "ci.yml step"
        elif rel in EXEMPT:
            how = f"EXEMPT: {EXEMPT[rel]}"
        else:
            how = None
            problems.append(
                f"UNCLAIMED: {rel} has an entry point and no job builds it. "
                f"Add a ci.yml step that names it, or an EXEMPT reason "
                f"(TODO #329, rule 1)")
        rows.append((rel, found[rel], how))

    # Rule 3, both directions.
    for rel, reason in sorted(EXEMPT.items()):
        if not os.path.exists(os.path.join(_ROOT, rel)):
            problems.append(
                f"STALE EXEMPT: {rel} does not exist, so its reason "
                f"({reason!r}) defends nothing (TODO #329, rule 3)")
            continue
        if rel in poisoned or rel in ci:
            problems.append(
                f"OBSOLETE EXEMPT: {rel} is now claimed by a runner, so its "
                f"exemption must be DELETED rather than left standing "
                f"(TODO #329, rule 3)")

    print("Runnable-executable coverage under " + " ".join(ROOTS))
    print(f"  discovered {len(found)} executable(s): " +
          ", ".join(f"{n} {lang}" for lang, n in sorted(per_lang.items()) if n))
    print()
    width = max((len(r[0]) for r in rows), default = 10)
    for rel, lang, how in rows:
        print(f"  {rel:<{width}}  {lang:<6}  {how or '*** UNCLAIMED ***'}")
    print()
    print(f"  EXEMPT entries: {len(EXEMPT)}")

    if problems:
        print()
        for p in problems:
            print("  " + p)
        print(f"\n*** FAILED: {len(problems)} problem(s) ***")
        return 1
    print("\n*** OK: every discovered executable is built by some job ***")
    return 0


if __name__ == "__main__":
    sys.exit(main())
