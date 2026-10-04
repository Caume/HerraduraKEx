#!/usr/bin/env python3
"""Cross-language parity guard for the C/Go/Python/Java quartet (TODO #261).

WHY THIS EXISTS.  TODO #261 was filed over a concrete, silent asymmetry:
Python's HCRED shipped a second proof system (`hcred_prove_kkw`) that C, Go
and Java simply didn't have, and nothing in the repo's existing tooling could
have caught it — `spec/generate_spec.py --check` verifies the CLI `--algo`
surface, and this primitive was never CLI-exposed in any language, so it was
invisible to that check by construction.  #261 found and closed that gap by
hand (TODO_DONE.md's #261 entry).  This script is the "checked mechanically
going forward" half of that item: it turns two classes of future silent
asymmetry into a CI failure instead of a fact only a source read would find.

WHAT IT CHECKS.

  1. NUMBERED-TEST CONTIGUITY, per language.  C/Go/Python/Java each print a
     stable `[N]` marker per named test (`CryptosuiteTests/Herradura_tests.*`,
     `bindings/java/herradurakex/SelfTest.java`) — CLAUDE.md's Testing section
     and CHANGELOG.md cite these numbers as permanent IDs ("test [45] runs its
     Stern-F sub-check at rounds=32").  A stable-ID scheme with a hole in it
     (a number skipped, or reused) silently breaks every future citation of
     it, so every language's numbers must be contiguous from 1 and duplicate
     -free.

  2. NUMBERED-TEST SET ALIGNMENT across C/Go/Python specifically.  These
     three explicitly share ONE numbering (same test = same number in all
     three; CLAUDE.md's Testing section documents this).  Java's numbering is
     deliberately its OWN scheme (SelfTest.java's class doc comment explains
     why: it bundles correctness+Eve-resistance into one check per protocol
     where the other three often split those per bit-width), so Java is
     checked for internal contiguity only, never for set equality against
     the other three.

  3. SUITE-INTERNAL PRIMITIVE PRESENCE.  A manifest (below) of primitives
     that are NOT reachable through any CLI `--algo` tag — the exact class of
     thing #261's own gap was.  Each entry names a marker regex per language;
     a language missing a required marker fails unless the entry is
     explicitly `acknowledged`.  It was a SEED from v5.7.2 to v6.0.5, grown
     entry by entry; as of v6.1.0 it covers the whole internal surface,
     because check 4 makes anything less a failure.

  4. INTERNAL-SURFACE CENSUS (v6.1.0, the check that CLOSED #261).  Per
     language: enumerate the suite's own top-level functions, subtract the
     ones that language's CLI calls, subtract the ones the manifest names,
     fail on the remainder.  This is what turns check 3 from a list someone
     remembered to extend into a list that cannot be short — a new
     suite-internal primitive in any of the four languages fails CI until it
     is filed with four cells or given a CENSUS_EXEMPT rule with a reason.
     It is the mechanical form of #261's acceptance criterion, which asks for
     "never a silent absence, checked by the mechanism rather than by a
     one-time read of the source tree".

WHAT IT DELIBERATELY DOES NOT CHECK.  The CLI `--algo`/subcommand surface —
that is `spec/generate_spec.py --check`'s job, already run in CI, and
duplicating it here would just be two places that can drift apart from each
other.  Nor the CLI FLAG surface (`--passphrase`, `--kdf`, `--aead`), which is
NOT at four-way parity and has no check at all: that is TODO #267, filed when
this item closed rather than absorbed into it.

Usage:
    python3 spec/check_language_parity.py     # exit 1 on any inconsistency
"""
import glob
import json
import math
import os
import hashlib
import re
import sys
from collections import Counter

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# ── Part 1/2: numbered-test files ────────────────────────────────────────
# (path, pattern-with-one-group-capturing-the-number)
# {lang: (files holding this language's [N] markers, marker regex)}.
#
# A TUPLE OF FILES, NOT ONE FILE, since TODO #333 -- and Java is the only
# language that needs more than one.  Its benchmark layer is its own entry
# point (`Bench.java`, [36]) rather than a section inside `SelfTest.java`,
# because the two have different exit conditions: SelfTest asserts and the
# benchmark publishes a host-specific rate nothing asserts on (#292).  C, Go
# and Python keep benchmarks and security tests in ONE harness file, so their
# tuples have one element and nothing about them moves.
#
# WHY THIS IS NOT A COSMETIC GENERALISATION.  Had the Java entry stayed a
# single file, SelfTest.java's [1]-[35] would still be contiguous and
# duplicate-free, every table below would still be satisfied, and Bench.java's
# [36] would be invisible to the whole ninth axis -- no draw cell, no verdict
# fingerprint, no rejection basis, no rate.  That is #324's "a glob that
# matches nothing is indistinguishable from a glob that is satisfied" one
# directory over: a number this axis cannot see is a number it cannot hold to
# anything.
NUMBERED_TEST_FILES = {
    "c": (
        (os.path.join(REPO, "CryptosuiteTests", "Herradura_tests.c"),),
        re.compile(r'printf\("\[(\d+)\]'),
    ),
    "go": (
        (os.path.join(REPO, "CryptosuiteTests", "Herradura_tests.go"),),
        re.compile(r'fmt\.Print(?:ln|f)\("\[(\d+)\]'),
    ),
    "python": (
        (os.path.join(REPO, "CryptosuiteTests", "Herradura_tests.py"),),
        re.compile(r'print\(f?"\[(\d+)\]'),
    ),
    "java": (
        # Only the PASS branch: each check's [N] appears in both its PASS
        # and FAIL string literal (the exhaustive if/else outcome pair, both
        # always present in source regardless of runtime result), so
        # matching both would double-count every number by construction.
        # Bench.java follows the same convention for exactly this reason --
        # it prints its [36] HEADER first, as every benchmark in every port
        # does, and then a trailing PASS/FAIL [36] for its control, so the
        # header is not a second marker.
        (os.path.join(REPO, "bindings", "java", "herradurakex", "SelfTest.java"),
         os.path.join(REPO, "bindings", "java", "herradurakex", "Bench.java")),
        re.compile(r'println\("PASS \[(\d+)\]'),
    ),
}


def _marker_sources(lang):
    """[(path, text)] for the files holding this language's [N] markers.

    Read per FILE and never concatenated, because the slicing in
    `_numbered_test_bodies` is positional: Java's marker is trailing, so a
    body runs from the PREVIOUS marker, and gluing two files together would
    make Bench.java's [36] body start at SelfTest.java's [35] and swallow the
    whole tail of that file.
    """
    paths, _pattern = NUMBERED_TEST_FILES[lang]
    out = []
    for path in paths:
        with open(path, encoding="utf-8") as f:
            out.append((path, f.read()))
    return out

# C/Go/Python are documented (CLAUDE.md's Testing section) as sharing one
# numbering convention; Java's is explicitly its own (SelfTest.java's class
# doc comment). Only the first three are checked against each other.
SHARED_NUMBERING_LANGS = ("c", "go", "python")


def check_numbered_tests(errors):
    """Returns {lang: sorted distinct numbers found}."""
    numbers = {}
    for lang, (paths, pattern) in NUMBERED_TEST_FILES.items():
        found = []
        for _path, text in _marker_sources(lang):
            found.extend(int(m) for m in pattern.findall(text))
        rel = ", ".join(os.path.relpath(p, REPO) for p in paths)
        if not found:
            errors.append(
                f"{lang}: no numbered [N] tests matched in {rel} — the marker pattern is stale "
                f"(update NUMBERED_TEST_FILES), or the file genuinely lost its numbering"
            )
            numbers[lang] = []
            continue
        dupes = sorted(n for n, cnt in Counter(found).items() if cnt > 1)
        if dupes:
            errors.append(
                f"{lang}: test number(s) {dupes} appear more than once in {rel} — "
                f"stable IDs must be unique within a language"
            )
        distinct = sorted(set(found))
        expected = list(range(1, distinct[-1] + 1))
        missing = sorted(set(expected) - set(distinct))
        if missing:
            errors.append(
                f"{lang}: numbered tests in {rel} have a gap at {missing} (highest is "
                f"[{distinct[-1]}], {len(distinct)} numbers present) — a stable-ID convention "
                f"must not have holes; renumber contiguously or restore the missing test"
            )
        numbers[lang] = distinct
    return numbers


# ── Part 1/7: the numbered tests that decide a verdict from a FRESH SAMPLE ──
#
# TODO #316, the ninth axis, and the one that asks of the NUMBERED TESTS what
# TODO #300 asked of the findings gates: does this check decide a verdict from
# a fresh random sample against a FIXED threshold?  #310 found [53] doing it at
# about one run in 16 in two of four ports, fixed it, and closed by recording
# that no census existed of whether any other numbered test had the shape.
#
# WHY IT MATTERS MORE HERE THAN IT DID THERE.  The findings gates live in
# `analysis-findings`, which is continue-on-error.  These live in native-c,
# native-go, native-python and native-java, which are REQUIRED -- and since
# TODO #233 a [FAIL] marker fails the build -- so a flake here is a red
# required check on somebody else's unrelated PR.
#
# THE SHAPE OF THIS TABLE IS TODO #296's, AND THAT WAS DECIDED BY MEASURING.
# A cell per (test, port) with a reason each was the plan; about 50 of each
# language's 53 numbered tests draw fresh entropy, so that is ~200 rows whose
# great majority would read "exact: a round-trip, every trial must succeed".
# #296 met this and said why it does not work -- "there are 109, and a hundred
# prose reasons rot".  So the completeness half is a DERIVED SET, compared
# every run, and prose is spent only where a verdict departs from the default.
#
# Two things to know before extending it.
#
# (1) THE DETECTOR MUST BE VALIDATED, and it needed it.  A first Go pattern
#     matching randBA and crypto/rand found 32 of 53 tests drawing; adding
#     NewRandBitArray, mrand. and mrand.Read took it to 49 -- seventeen
#     invisible, including all of [23]-[31].  An under-matching detector makes
#     the completeness rule pass VACUOUSLY, which is #295's recorded rule that
#     getting the corpus wrong in the LENIENT direction is the dangerous one.
#     The guard is that an EMPTY per-language draw set is an error (#296's own
#     guard, and #306's sixth-spelling hazard is why both exist).
#     NB mrand is math/rand, not a CSPRNG.  It is auto-seeded since Go 1.20,
#     so it is a fresh sample every run and counts HERE even though it would
#     not count for #296's randomness census -- the two axes ask different
#     questions of the same word.
#
# (2) THE BUDGET IS A JOB-LEVEL NUMBER, NOT A PER-TEST ONE.  That is #300's
#     explicit position, arrived at after its own first draft picked 1e-6 per
#     gate and then flagged three gates at 1.2e-6 -- one run in 860 000, a
#     defect only against an arbitrary line.  So no entry carries a per-row
#     bar; each carries a RATE or an ARGUMENT, the two are counted separately
#     so the distinction cannot erode, and the SUM is checked against the
#     budget below.  If it is ever approached, replicate the largest
#     contributor (#299's pattern); raising the number is how the premise rots.
_SAMPLED_TEST_BUDGET = 1e-4

# How each language spells "read fresh randomness", inside a numbered test.
# WHERE THE MARKER SITS relative to the body, which is not the same in all
# four.  C, Go and Python print their header FIRST, so a test's body runs from
# its marker to the next one.  Java's marker is the TRAILING println("PASS
# [N]") of an if/else, so its body runs from the PREVIOUS marker to this one --
# slicing Java the other way reported [35] as drawing nothing while
# Stern.sternFKeygen(rng) sat inside it.
_TRAILING_MARKER_LANGS = ("java",)

# A test draws if it reads the CSPRNG itself OR calls a keygen that does --
# the second half matters: [22] reaches its entropy only through
# _zkp_nl_keygen, and a direct-read-only pattern reported it as drawing
# NOTHING while its verdict plainly turns on a fresh instance.  That is the
# under-matching hazard again, one level in: the first version of this table
# was rejected by its own curated row.
_TEST_DRAW_PATTERNS = {
    # C's spellings were enumerated from source, not guessed: ba_rand, rand32,
    # rand64, rand128, bn_rand_n, rnl_rand_poly_n, rnl_rand_coeff and three
    # stern_rand_error_* variants.  Guessing twice is how [15] read as drawing
    # nothing while bn_rand_n sat two lines under its header.
    "c":      re.compile(r'\burnd_fp\b|\w*rand\w*\s*\(|\w*keygen\s*\('),
    "go":     re.compile(r'\brandBA\s*\(|\bNewRandBitArray\s*\(|\bmrand\.|'
                         r'\brand\.Read\b|crypto/rand|\w*[Kk]eygen\s*\('),
    "python": re.compile(r'os\.urandom|BitArray\.random|random\.getrandbits|'
                         r'random\.randrange|random\.randint|_csprng|'
                         r'\w*keygen\s*\('),
    "java":   re.compile(r'\brng\b|\w*[Kk]eygen\s*\('),
}

# The DERIVED half, recorded so a change forces the question (#296's name set).
# A numbered test that starts or stops drawing fresh entropy moves a number
# here and fails until somebody says which it is and why.
_TEST_DRAWS = {
    "c":      [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18,
               20, 21, 22, 23, 24, 25, 26, 28, 30, 31, 32, 33, 34, 35, 36, 37,
               38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 53,
               54],
    "go":     [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18,
               20, 21, 22, 23, 24, 25, 26, 28, 30, 31, 32, 33, 34, 35, 36, 37,
               38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52,
               53, 54],
    "python": [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18,
               19, 20, 21, 22, 23, 24, 25, 26, 28, 30, 31, 32, 33, 34, 35, 36,
               37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51,
               53, 54],
    # [36] is in Bench.java, not SelfTest.java (TODO #333).  It is the only
    # cell in this table that lives outside its language's single harness
    # file, which is why NUMBERED_TEST_FILES now takes a tuple of paths.
    "java":   [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18,
               19, 20, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 35, 36],
}

# The CURATED half.  An entry only where a verdict rests on a THRESHOLD or on
# a PROBABILISTIC outcome -- the other ~40 per language are all-trials-must-
# succeed conjunctions of round-trips, where a fresh sample changes WHICH
# instance is tested and not the outcome.
#
#   (lang, test) -> (code, rate-or-None, reason)
#
# Codes are #300's, with the same meanings:
#   exact       holds with probability 1 for correct code
#   negligible  a sampled statistic against a fixed threshold, rate STATED
#   replicated  an exceedance is confirmed against a second sample first
#   follows     the threshold is computed from the statistic's own null
#
# "python" entries cover C and Go too where the three share an expression;
# a per-port row exists where they DIVERGE, which is #310's lesson stated as
# a schema -- [53] was the same code at two parameter sets, failing one run in
# 16 in Python and Go and one in 65536 in C and Java.
_SAMPLED_TESTS = {
    ("java", 36): ("negligible", 2.9387358770557188e-39,
        "JAVA'S COUNTERPART OF THE SHARED [54] ROW (TODO #333), at the same "
        "parameters and so at the same rate.  Its accept-control is the "
        "sampled half: a FRESH key and a FRESH ciphertext must decapsulate to "
        "the encapsulated secret, which fails exactly on a DECODER FAILURE, "
        "and the rejection half -- a uniform syndrome must give a DIFFERENT "
        "key -- needs two differently-domain-separated HFSCX-256 calls to "
        "collide, so it is 2^-256 and the basis names the weaker one (#322).  "
        "THE RATE IS INHERITED AND NOT MEASURED, which is #285's honest "
        "statement about BIKE-128: the DFR is not observable at any sample "
        "size, so it cannot be a function of QCMDPC_R/D/T and is read off "
        "BIKE's own analysis.  It is a SEPARATE row rather than folded into "
        "the `shared` key because `shared` means C/Go/Python by construction "
        "and Java's numbering is its own -- the same reason ('java', 30) sits "
        "beside ('shared', 21).  Exactly ONE (key, ciphertext) pair reaches "
        "the verdict; the four benchmark rungs discard theirs"),
    ("shared", 54): ("negligible", 2.9387358770557188e-39,
        "[54]'s ACCEPT-CONTROL is the sampled half, and the half that is not "
        "exact: a FRESH key and a FRESH ciphertext must decapsulate to the "
        "encapsulated secret, which fails exactly on a DECODER FAILURE.  The "
        "rejection half -- a uniform syndrome must give a DIFFERENT key -- "
        "needs HFSCX-256-DS(0x11, z||syn) to collide with "
        "HFSCX-256-DS(0x10, e0||e1||syn) and is 2^-256, so the basis names the "
        "weaker one, which is #322's rule that a cell's basis is its weakest "
        "assertion.  THE RATE IS INHERITED AND NOT MEASURED, which is the "
        "honest statement #285 made about this parameter set: at BIKE-128 the "
        "DFR is not observable at any sample size, qcmdpc_bgf_failure_rate.py "
        "reports a one-sided bound rather than a count, and the 2^-128 comes "
        "from BIKE's own analysis.  Exactly ONE (key, ciphertext) pair reaches "
        "the verdict -- the benchmark rungs discard theirs -- so the term is "
        "one DFR event per run, three ports over"),
    ("shared", 2): ("exact", None,
        "'2.9 <= mean <= 3.1' looks like the worst row in the file and is the "
        "safest: FSCX is LINEAR, so flipping one input bit moves the output by "
        "M . e_j, of weight exactly 3 at every n >= 3.  The statistic has zero "
        "variance and the window is legacy slack, not tolerance"),
    ("shared", 4): ("negligible", 1e-6,
        "bit-frequency, and the row TODO #233 fixed by making the bar follow "
        "the statistic: tol = 6 * 50/sqrt(n_run), i.e. 6 sigma of the "
        "Binomial(n_run, 1/2) per-bit percentage, reproducing the historical "
        "+/-3.00 at N=10000 and staying sound below it.  Union bound over "
        "32+64+128+256 = 480 bits puts the run-level rate near 1e-6 -- and "
        "TODO #321 is where that enumeration was CORRECTED: this row and the "
        "test's own comment both said '256+128+64', dropping the 32-bit size "
        "SIZES sweeps.  448 against 480 does not move the number (8.8e-7 vs "
        "9.5e-7), and the direction is what earns the note: a union bound over "
        "too FEW terms understates the rate, which is #295's lenient direction "
        "in an enumeration instead of in a corpus"),
    ("shared", 5): ("negligible", 1e-30,
        "'mean HD >= size//4' against a null of size/2.  The per-trial HD is "
        "Binomial(size, 1/2), so the mean over N trials sits sqrt(size*N)/2 "
        "sigma from the bar -- 28 sigma at the smallest cell (size=32, "
        "N=GF_TRIALS=100).  Recorded as a bound, not a measurement"),
    ("shared", 10): ("negligible", 2.4e-7,
        "NL-FSCX v1, and THE ROW WHOSE STATED RATE WAS WRONG IN THE UNSAFE "
        "DIRECTION -- TODO #321 found it, and it is the first on this axis that "
        "errs that way rather than conservatively.  The row described the "
        "APERIODICITY half ('no_period >= 95% of n2_run', a period inside 4n "
        "steps needing cur == A, about 4n * 2^-n = 3e-8 at n=32 against a bar "
        "of 5% of 200 trials, so P(Binom) ~ 4e-67) and published 1e-30.  The "
        "verdict is a CONJUNCTION, and its other half is "
        "'violations == n1_run' -- every one of _iters(1000) random (A, B) must "
        "break the linear prediction, so ONE coincidence fails the run.  That "
        "term is 1000 * 2^-32 = 2.3e-7 at the narrowest size, 10^23 larger "
        "than the number the row carried.  MEASURED: 1 coincidence in 100 000 "
        "at n=16 and 0 in 100 000 at n=24/32/40, i.e. the 2^-n the bound "
        "assumes.  Still 0.2% of the budget, so nothing needs fixing in the "
        "test -- what needed fixing is that a rate was read off the sub-check "
        "somebody happened to be looking at"),
    ("shared", 11): ("negligible", 1e-14,
        "NL-FSCX v2 non-linearity, 'nl_ok >= 98% of n3_run', and the null is "
        "GENUINELY NONZERO -- 4 coincidences in 20 000 at n=32 (2.0e-4), not "
        "the 2^-32 a reader assumes, so the 2% slack is load-bearing rather "
        "than generous.  P(Binom(500, 2e-4) >= 11) ~ 1e-14.  Its sibling "
        "'non_bij == 0' is EXACT: two distinct A cannot share an image of a "
        "bijection, so a collision is the defect and never the draw"),
    ("shared", 18): ("exact", None,
        "THE REFERENCE ROW.  A weight-2 code of length 32 with a 16-bit "
        "syndrome is not uniquely decodable, and this line reported [FAIL] on "
        "7.4% of runs until TODO #233 SEPARATED the ambiguous-syndrome branch "
        "from the failure branch and scored only `bad`.  That is how a "
        "probabilistic subject gets an exact verdict without slack -- prefer "
        "it to widening a threshold"),
    ("python", 19): ("negligible", 4e-75,
        "HFSCX-256 collision sanity over 500 fresh pairs, plus 6 block-boundary "
        "pairs, against a 256-bit digest"),
    ("shared", 21): ("negligible", 1.5e-29,
        "ZKP-RNL, the row #316 fixed, #321 TOOK OFF `exact`, and TODO #330 "
        "found UNDERSTATED BY EXACTLY 2x -- then took off the budget "
        "altogether.  THE RECORD PRICED ONE OF TWO IDENTICAL BRANCHES.  Both "
        "the wrong-MESSAGE case and the tampered-COMMITMENT case require the "
        "verifier's RECOMPUTED Fiat-Shamir challenge to DIFFER, so each turns "
        "on a CHALLENGE COLLISION in a space of comb(n, t)*2^t = 575 360 at "
        "n = 32, t = 4 -- 8.7e-6 each, 1.74e-5 together, which at the time was "
        "92% of the whole numbered-test budget while the row advertised half of "
        "it.  #321's reason said the OTHER cheats `really are exact`, and that "
        "is true of wrongkey and z-tamper (both caught by the residual-norm "
        "check, where the perturbation is full-range garbage in every "
        "coefficient, ~1e-93) and FALSE of the wrong-message one -- the second "
        "time this row has carried a reason exact about the wrong object, which "
        "is #310's shape and #295's.  IT FIRED: the message case failed a "
        "required `sanitizers` run at n = 32, and the verifier was RIGHT, "
        "because on a collision the proof genuinely IS valid for the second "
        "message.  REMEDY, #310's for [53] on the WIDTH axis instead of the "
        "round-count one: both FS-binding cases now run at n = 256 only, where "
        "t = 16 puts the space at 6.6e29 and the pair at 1.5e-29.  It adopts "
        "the port that was already right -- SelfTest.java's [30] runs at "
        "n = 256 only and never had the defect (#294, #296) -- and a skipped "
        "case keeps its OWN denominator and prints n/a, so `did not run` cannot "
        "read as `ran and scored zero` (#291).  The skip has a POSITIVE half: "
        "if NO width runs them the test prints [FAIL], or widening the gate "
        "everywhere would satisfy every assertion by asserting nothing (#234, "
        "#326).  Both controls were verified to fire -- dropping the verifier's "
        "FS re-derivation takes n = 256 to 0/5 on both cases, and forcing the "
        "gate off at every width trips the positive half.  MEASURED: see "
        "_ARGUED_MEASUREMENTS['sigma-challenge-collision'].  rnl_sigma_sign "
        "gives up after 1000 rejection-sampling attempts -- a legitimate signer "
        "outcome -- and all four ports scored it differently and none "
        "correctly: Python decremented its denominator and could print 0/0 "
        "[PASS]; C and Go left ok_verify == i against N == i+1, so ANY "
        "exhaustion FAILED the build; Java did fails++ directly below a comment "
        "saying it did not (#295's false-reason finding, aimed at a test).  Now "
        "one rule (#291) -- the trial leaves the denominator, N > 0 is guarded, "
        "Java retries 8 times.  Exhaustion measured at 0 in 1166 signs at n=32 "
        "and 0 in 136 at n=256, but _sigma_params records ~72% at the retired "
        "t=64, so the margin is a parameter choice and not a property"),
    ("shared", 22): ("negligible", "derived",
        "ZKP-NL tamper rejection, and the pair that makes [17] legible: the "
        "verifier hashes ALL commitments into ch_seed and checks every round's "
        "claimed challenge, so flipping a bit of round 0's com_1 is missed only "
        "if all 16 recomputed challenges still match -- (1/3)^16 per trial over "
        "10 trials.  IDENTICAL MECHANISM to [17]'s defect at 16 rounds instead "
        "of 8, so the round count is the whole distance between 2.3e-7 and "
        "1.5e-5.  No crash mode: past the challenge check it meets stale "
        "responses and returns False"),
    ("shared", 20): ("exact", None,
        "Stern ring COMPLETENESS ONLY, at rounds=4 in Python and "
        "sdfTestRounds=4 in Go -- the count CLAUDE.md's Testing section warns "
        "about.  Exact because it asserts no rejection: adding one here would "
        "carry a (2/3)^4 = 19.75% soundness error, which is that warning as a "
        "live constraint rather than as history"),
    ("shared", 45): ("negligible", "derived",
        "THE LARGEST CONTRIBUTOR, and it is already the fixed version.  A "
        "corrupted syndrome is caught only on a b = 2 round -- the ONLY branch "
        "that reads the syndrome, and this line said b = 0 until TODO #320 "
        "measured it -- so an honest signature verifies against a corrupted "
        "one with probability (2/3)^SDF_ROUNDS -- "
        "2.4e-6 at 32, over STERN_TRIALS=2.  At the rounds=8 this ran at "
        "before TODO #234 it was 3.90%, which made the whole of [45] fail "
        "38.5% of runs.  If this table's budget is ever approached, this is "
        "the row to replicate"),
    ("shared", 46): ("negligible", 3.4e-75,
        "fpe/twk domain separation: two fresh 256-bit ciphertexts must differ, "
        "and its key-boundary sibling likewise.  Coincidence terms, 200 "
        "iterations x 2 comparisons x 2^-256 = 3.4e-75 -- TODO #321 replaced a "
        "recorded 1e-70, which was the same arithmetic rounded 3e4 too high "
        "and disagreed with [19]'s 4e-75 for the identical shape one test "
        "over"),
    ("shared", 49): ("negligible", 1e-100,
        "HKEX-RNL m_blind guard, and the row TODO #321 found stating THE WRONG "
        "PARAMETER.  The ACCEPT-CONTROL is the sampled half -- a genuine "
        "uniform draw must pass -- and the guard rejects a coefficient RANGE "
        "below q/4, which n uniform draws fall inside with about "
        "n*(1/4)^(n-1).  This row said '1.5e-17 at n=32' and the literal "
        "beside it said 'at the ring dimension the test sweeps'; the test "
        "SWEEPS NOTHING -- it hardcodes n = 256 -- so the term is "
        "256*(1/4)^255 ~ 1e-152 over _iters(50) iterations, not 1e-17.  A "
        "published rate 10^134 too LARGE, which is exactly why no check and no "
        "flake could find it (#319's and #320's own finding: the conservative "
        "direction is the invisible one).  Recorded as 1e-100 rather than the "
        "arithmetic value because a bound that far below every other term is a "
        "bound, not a measurement.  Its sparsity clause is unreachable at "
        "q=65537.  The control exists because a guard that rejected everything "
        "would pass the four rejection cases perfectly"),
    ("shared", 14): ("exact", None,
        "HKEX-RNL agreement, and THE ROW TO DISTRUST -- it rests on an "
        "ARGUMENT (Peikert 1-bit reconciliation eliminates agreement failures) "
        "rather than on a derived rate, and #310's lesson is that a reason "
        "exact about the wrong object reads exactly like a correct one.  "
        "Measured here: 0 disagreements in 20 000 at n=32, which bounds the "
        "per-trial rate at 1.5e-4 (95%) and is NOT tight enough to derive a "
        "run-level number from, so it defers to "
        "SecurityProofsCode/hkex_rnl_failure_rate.py 5 and 7.  Note "
        "RNL_SIZES includes 32 while this test's own comment says the error "
        "probability is negligible 'at n >= 64'"),
    ("shared", 53): ("negligible", "derived",
        "Stern witness binding.  TODO #310's row: the forgery sub-check has "
        "its OWN round count (64 in all four) because the verifier binds wt(e) "
        "only on b = 0 rounds, and the witness is CONSTRUCTED off-weight by "
        "kernel addition rather than hoped for, which removed a 2^-t term "
        "entirely.  The ring half keeps 12 and has no soundness error"),
    ("python", 17): ("exact", None,
        "PYTHON ONLY -- C, Go and Java assert completeness only in [17], which "
        "is #310's per-port rule running the other way: a table with one cell "
        "per test would have read 'absent' and closed the row.  Until TODO "
        "#316 this was a sampled gate at (1/3)^SDF_ROUNDS = 1.5e-5 whose "
        "failure mode was an uncaught TypeError that ABORTED THE HARNESS, in a "
        "required job: the forgery claims fake_chal = [0]*8, the verifier "
        "recomputes the Fiat-Shamir challenge and rejects at the first round "
        "that disagrees, and the b = 0 branch it reached otherwise unpacked a "
        "BitArray where a real response carries an int.  Measured 0.342 / "
        "0.118 / 0.0130 / 0.0000 of 2000 attempts at rounds 1/2/4/8 against "
        "(1/3)^R.  Typed correctly the verifier RUNS that branch and rejects "
        "on the merits (c1 carries no ds=2; #298's wt(respA ^ respB) == t "
        "fails at weight 0), so the sampling is gone rather than reduced and "
        "the check now exercises the branch it used to crash through"),
    ("java", 12): ("negligible", "derived",
        "Java's Stern-F corrupt-syndrome rejection, signed at Stern.SDFR = 32. "
        "Its own comment derives why a smaller count would flake: only a b = 2 "
        "round references the syndrome, so 8 rounds skip it ~3.9% of the time"),
    ("java", 26): ("negligible", "derived",
        "Java's Stern ring forgery rejection at demoRounds = 32, and the row "
        "TODO #298 SILENTLY MADE 4.6 MILLION TIMES SAFER while three places "
        "went on quoting the old number.  TODO #260 caught it flaking at 8 "
        "rounds and wrote (2/3)^8 = 3.9% in SelfTest.java's comment, which was "
        "right AT THE TIME: only the b = 2 branch read the syndrome, so a "
        "witness matching no member's syndrome survived a challenge string "
        "with no b = 2 round.  Then #298 added wt(respA ^ respB) = t to the "
        "b = 0 branch, and a uniform 256-bit badE has weight ~128 against "
        "t = 16, so TWO of three branches now catch it and only b = 1 misses: "
        "(1/3)^rounds.  The mechanism gained a detector and every INPUT to the "
        "rate stayed put, which is why #319's machinery could not see it and "
        "#318's fingerprint did not move -- the formula was the wrong function "
        "of the right constants, one release after the fix that made it wrong.  "
        "MEASURED at rounds = 1/2/3: see _RATE_MECHANISMS['ring-forgery']"),
    ("java", 14): ("negligible", 1e-50,
        "HPKE-Stern-KEM, the only row whose subject has a DESIGNED failure "
        "rate: QC-MDPC decoding has a real DFR and TODO #235's implicit "
        "rejection makes a DFR event an output MISMATCH rather than an error, "
        "so it fails only if all 20 trials miss.  DFR^20, and at the deployed "
        "BIKE-128 the DFR is not observable at any trial count (#285 2), so "
        "the exponent is doing far less work than the base"),
    ("java", 35): ("negligible", "derived",
        "Java's copy of [53], fixed by TODO #310 in the same pass: "
        "forgeRounds = 64, off-weight witness constructed by kernel addition"),

    # ── TODO #322: the rows the DERIVED DEFAULT was carrying ─────────────
    # Eight cells whose rejection assertion turns on a fresh coin, found by
    # Part 5/6's screen.  Every one was resting on "a fresh sample changes
    # WHICH instance is tested and not the outcome" -- true of a round-trip and
    # false of all eight.
    ("java", 19): ("negligible", "derived",
        "ZKP-NL tamper rejection: ZkpNl.verify RECOMPUTES the per-round "
        "Fiat-Shamir trit and compares it, so a tampered message survives when "
        "all `rounds` coincide.  #316's [17] is this mechanism at rounds = 8, "
        "where it CRASHED; here it simply goes unrecorded"),
    ("java", 28): ("negligible", "derived",
        "the ZKBoo half of Java's pair, `rejects_msg`, same verifier and same "
        "recomputed-challenge comparison as [19]"),
    ("java", 29): ("negligible", 2.3e-8,
        "the ZKB++ half, `rejects_msg`.  #304 measured that ZKB++ kills a wrong "
        "WITNESS every round; the MESSAGE reaches this verifier only through "
        "the challenge seed, so this axis keeps the (1/3)^rounds term"),
    ("java", 30): ("negligible", 1.7e-6,
        "the Ring-LWR Sigma signer, and the JAVA COUNTERPART of the shared [21] "
        "row TODO #321 found is not `exact`: the verifier recomputes the "
        "challenge over the tampered w and on a collision the residual-norm "
        "check sees one coefficient inside a slack of 36 and accepts"),
    ("java", 31): ("negligible", 2.4e-12,
        "Java's HCRED-KKW `rejects_msg`, and the row whose rate TWO successive "
        "models got wrong: THREE bindings have to break, not one, and the "
        "dominant one is the rho PROJECTION at 1/q per opened emulation"),
    ("shared", 50): ("negligible", 2.4e-12,
        "the C/Go/Python HCRED-KKW `wrong_msg` axis: acceptance needs the "
        "opened SUBSET to coincide (1/comb(M, tau)), the rho PROJECTION "
        "residual to hold in every opened emulation (1/q each, and rho is "
        "hashed over `stmt`) and the pbar challenge to coincide "
        "(1/N_par^tau) -- 1/6 * 1/65537^2 * 1/16 at the demo triple"),
    ("shared", 8): ("negligible", 1e-77,
        "HPKS Schnorr Eve resistance: the forgery attempts are DRAWN, so "
        "`wins == 0` is a statement about a fresh sample, and a random (R, s) "
        "satisfying g^s . C^e == R is a 2^-256 event"),
    ("java", 27): ("negligible", 1e-150,
        "the accept-control is the sampled half, as in shared [49]: a genuine "
        "UNIFORM m_blind must pass a guard rejecting a coefficient range below "
        "q/4, which n = 256 uniform draws fall inside with 256*(1/4)^255"),
}

# Tests that DRAW but are out of scope because what they draw does not reach
# the verdict.  Self-invalidating like every other table here: an entry naming
# a test that has started deciding on its sample FAILS.
_SAMPLED_TEST_CONSTANT = {
    ("shared", 27): "ratchet: seeds are the literals test-seed-{i} / seed-alice "
                    "/ seed-bob, so nothing in the verdict varies run to run",
    ("shared", 29): "HDRBG: every seed is a literal (bytes(range(32)), "
                    "b'ent-monobit'), so the '0.48 <= frac <= 0.52' monobit "
                    "window is applied to a CONSTANT.  It cannot flake, and "
                    "that is the INVERSE fragility rather than a defect -- the "
                    "die is rolled once per change to the DRBG, not once per "
                    "run, so a future construction change either always passes "
                    "it or always fails it.  Java's [22] is the same shape",
    ("java", 21):   "Java's ratchet, same literal seeds as the shared [27]",
    ("java", 22):   "Java's HDRBG, same constant monobit window as [29]",
    ("java", 34):   "Java's QC-MDPC PRF seed expansion: pinned four-way vectors "
                    "(TODO #277), no draw anywhere in the verdict",
    ("c", 19):      "C's HFSCX-256 runs the pinned KAT vectors and deterministic "
                    "block-boundary inputs; only PYTHON's [19] adds the fresh "
                    "500-pair collision sanity, which is why that row is scoped "
                    "to python rather than shared",
    ("go", 19):     "Go's HFSCX-256, same as C's",
    ("c", 52):      "C's QC-MDPC PRF seed expansion: pinned vectors (TODO #277)",
    ("python", 52): "Python's, same as C's -- Go's [52] DOES draw, which is why "
                    "there is no shared row here",
}


# ── Part 2/7: where each rate COMES FROM ─────────────────────────────────
#
# TODO #319.  A rate above is a LITERAL and its formula is prose, so the
# arithmetic is checked by nobody and its inputs are checked by nobody.  Lower
# [45]'s round count and every check in this repo stays green: PARAMETERS
# compares that constant's VALUE across four languages and they all moved
# together, _VERDICT_FINGERPRINTS is a hash of the verdict LINES and not of
# what they read, and _TEST_DRAWS still sees the same draw.  The banner goes on
# printing the old sum while the true rate is 7.8% -- the pre-#234 figure that
# made [45] fail 38.5% of runs.  That is #278's recorded limit ("this axis
# reads DECLARATIONS, so it cannot see whether the bound is APPLIED") met from
# the other end: the value is read, it agrees, and it is CONSUMED BY AN
# ARITHMETIC NOBODY EVALUATES.  #318 named this as its own limit.
#
# So a rate in this table is DERIVED: the row below states the formula, each
# variable is read out of the source per port, and the result is what enters
# the budget.  The literal stops being a second source of truth rather than
# being cross-checked against one -- #304's move, which turned CLAUDE.md's
# hand-copied 6.4e-5 into a checked row for the same reason.
#
# THE CONSTANT IS NOT WHERE THE PROSE SAYS IT IS, AND IN TWO PORTS IT IS NOT A
# SUITE CONSTANT AT ALL.  This item was recommended as "move sdf-rounds-demo
# and nothing fires", which is true of two ports and false of two:
#
#     C       SDF_ROUNDS      herradura.h -- a PARAMETERS row, and
#                             -DSDF_ROUNDS=219 moves it from the command line
#     Java    Stern.SDFR      the suite -- the same PARAMETERS row
#     Python  STERN_ROUNDS    a FUNCTION-LOCAL in the harness
#     Go      sternRounds     a FUNCTION-LOCAL in the harness
#
# One rate, one test, two ports tracked and two untracked, and no table
# anywhere recorded the split.  That is #293's read-pattern split and #294's
# distribution split one axis over, with a FLAKE RATE as the object.  Hence two
# kinds of variable source, and hence the per-port derivation: one number
# cannot describe four ports, so a row takes its WORST one -- the budget is
# about a red check on somebody's PR, and any of the four native-* jobs going
# red counts.  VERIFIED, and it is the control that matters: lowering the
# constant in all four languages at once leaves PARAMETERS silent (they agree)
# and #318's fingerprints silent (the constant is in no verdict line), and this
# check alone fires, at 1.17e-1.
#
# AND ONE PUBLISHED RATE WAS ALREADY WRONG BY 10x.  [53] signs its forgery
# sub-check at forge_rounds = 64 in ONE trial, so its rate is (2/3)^64 =
# 5.4e-12; the row said 5.5e-11, and so did the comment in the test body, and
# so did Java's [35].  It is wrong in the CONSERVATIVE direction -- it
# overstates the flake rate tenfold and eats ten times its share of the budget
# -- which is exactly why nothing could catch it: a hand-computed bound that is
# too LARGE fails no check and triggers no flake.  #304 found the same shape on
# the findings-gate side ("the arithmetic is only as good as the null it is
# done against") and answered it by requiring a token; the answer here is to
# stop hand-computing.  The other two reproduced: [45] at 2 * (2/3)^32 against
# a stated 4.8e-6, and [22] at 10 * (1/3)^16 against a stated 2.3e-7, where the
# factor 10 is five iterations over the two widths and was NOWHERE in the prose.
#
# A variable is read per port as one of:
#
#     ("param", row)          the value of a PARAMETERS row in that language,
#                             through _param_eval -- so a suite constant is
#                             read exactly the way axis six reads it, with the
#                             two corrections that axis earned (non-integral
#                             results survive; an (int) cast is APPLIED)
#     ("local", rx[, slice])  capture group 1 of `rx`, searched in THAT TEST's
#                             source.  `slice` is "body" (the default, #316's
#                             forward slice) or "scope" (widened to the
#                             previous marker) -- see _numbered_test_scopes
#     ("count", rx[, slice])  capture group 1 is a comma-separated list; the
#                             value is how many items it holds.  [22]'s rate is
#                             proportional to the number of WIDTHS it sweeps,
#                             a property of a literal list and not of a constant
#
# A local/count pattern must match EXACTLY ONCE, never merely occur -- #261's
# rule for the manifest markers, for its reason: `forgeRounds` appears three
# times in Java's [35] and only one of them declares it.  A variable that
# resolves in NO port is an error and not a skip: four ports spell one constant
# four ways and C's [53] spells it a fifth (`enum { RK = 3, RND = 12, FRND = 64 }`),
# so this is #306's sixth-spelling hazard again, and an under-matching reader
# makes the whole check pass vacuously in #295's lenient direction.  #316 got
# its own detector wrong three times, every time leniently.
_SAMPLED_TEST_RATES = {
    ("shared", 45): (
        "trials * (2/3) ** rounds",
        {"rounds": {"c":      ("param", "sdf-rounds-demo"),
                    "go":     ("local", r"sternRounds,\s*sternTrials\s*=\s*(\d+)"),
                    "python": ("local", r"STERN_ROUNDS,\s*STERN_TRIALS\s*=\s*(\d+)")},
         "trials": {"c":      ("local", r"enum\s*\{\s*STERN_TRIALS\s*=\s*(\d+)", "scope"),
                    "go":     ("local", r"sternRounds,\s*sternTrials\s*=\s*\d+\s*,\s*(\d+)"),
                    "python": ("local", r"STERN_ROUNDS,\s*STERN_TRIALS\s*=\s*\d+\s*,\s*(\d+)")}},
        "A corrupted syndrome is caught only on a b = 2 round -- the only "
        "branch of the verifier that reads the syndrome at all -- so an honest "
        "signature verifies against a corrupted one with probability "
        "(2/3)^rounds, once per trial.  THIS REASON SAID b = 0, copied from "
        "the harness comment while writing the table meant to make rates "
        "trustworthy, and TODO #320 is what corrected it: see "
        "_RATE_MECHANISMS['corrupted-syndrome'], whose witness measurement is "
        "the only thing here that could tell the two apart, both predicting "
        "(2/3)^rounds.  THE ROUND COUNT IS THE SPLIT: C reads the suite's SDF_ROUNDS "
        "(so a -DSDF_ROUNDS=219 build lowers C's rate alone) while Go and "
        "Python carry their own literal, and the row's prose said SDF_ROUNDS "
        "for all three.  The trial count is harness-local in all three and is "
        "NOT the -r-capped iteration count -- #233 gave this check its own "
        "fixed budget precisely so the two could not be confused"),
    ("shared", 22): (
        "widths * iters * (1/3) ** (rounds + 1)",
        {"rounds": {"c":      ("local", r"zkp_nl_rounds\s*=\s*(\d+)", "scope"),
                    "go":     ("local", r"zkpNlRounds\s*:=\s*(\d+)"),
                    "python": ("local", r"zkp_nl_rounds\s*=\s*(\d+)")},
         "widths": {"c":      ("count", r"zkp_nl_sizes\[\]\s*=\s*\{([^}]*)\}", "scope"),
                    "go":     ("count", r"zkpNlSizes\s*:=\s*\[\]int\{([^}]*)\}"),
                    "python": ("count", r"for n in \[([^\]]*)\]")},
         "iters":  {"c":      ("local", r"g_rounds > 0 \? g_rounds : (\d+)"),
                    "go":     ("local", r"testRounds\((\d+)\)"),
                    "python": ("local", r"_iters\((\d+)\)")}},
        "ZKBoo tamper-rejection, and TWO TERMS rather than one -- which TODO "
        "#320 found by measuring and #319 got wrong: the poke reseeds "
        "Fiat-Shamir over the WHOLE commitment block, so all `rounds` stored "
        "challenges must coincidentally re-match, (1/3)^rounds, AND round 0's "
        "challenge must leave the poked com_1 unopened, a further 1/3 since "
        "com_1 is opened for e in {0, 2}.  #319's bare (1/3)^rounds overstated "
        "it 3x -- conservatively, hence invisible to every check and every "
        "flake, which is the second time that direction hid an error on this "
        "axis.  The check runs once per width per iteration, and those two "
        "multipliers were the 10x named in no comment in any of the three "
        "ports.  `iters` is the DEFAULT iteration count and -r can only lower "
        "it, so the derived rate is an upper bound rather than the rate of a "
        "particular run.  See _RATE_MECHANISMS['zkboo-poke']"),
    ("shared", 53): (
        "(2/3) ** rounds",
        {"rounds": {"c":      ("local", r"FRND\s*=\s*(\d+)", "scope"),
                    "go":     ("local", r"forgeRounds\s*:=\s*(\d+)"),
                    "python": ("local", r"forge_rounds\s*=\s*(\d+)")}},
        "TODO #310's second term: the verifier binds wt(e) only on b = 0 "
        "rounds, so a constructed off-weight witness is accepted whenever the "
        "challenge string contains none -- which is why the forgery sub-check "
        "carries its OWN round count, 64, where the ring half keeps 12 and has "
        "no soundness error.  ONE TRIAL, so there is no multiplier: this is "
        "the row whose hand-computed 5.5e-11 was (2/3)^64 = 5.4e-12 all along"),
    ("java", 12): (
        "(2/3) ** rounds",
        {"rounds": {"java": ("param", "sdf-rounds-demo")}},
        "Java's counterpart to the shared [45] corrupted-syndrome check, and "
        "the other half of the split: it signs at the SUITE's Stern.SDFR "
        "rather than at a harness literal, so this rate moves with a "
        "PARAMETERS row where Go's and Python's do not.  One trial"),
    ("java", 26): (
        "(1/3) ** rounds",
        {"rounds": {"java": ("local", r"int demoRounds\s*=\s*(\d+)")}},
        "Java's ring forgery rejection, and TODO #321 is where it STOPPED "
        "being a literal.  A witness matching no member's syndrome is caught by "
        "TWO of the verifier's three branches -- b = 0 binds "
        "wt(respA ^ respB) = t (TODO #298's fix) and b = 2 checks "
        "H(pi_seed, Hy ^ syndrome) -- so only b = 1 reads neither and the rate "
        "is (1/3)^rounds, not the (2/3)^rounds SelfTest.java's comment and both "
        "spec/ tables carried.  The old number was RIGHT WHEN WRITTEN: TODO "
        "#260 saw a real flake at 8 rounds, which (2/3)^8 = 3.9% explains and "
        "(1/3)^8 = 1.5e-4 does not, and #298 shipped the second detector a "
        "year of items later.  So this is #319's object -- a rate that moved "
        "and took nothing with it -- with a VERIFIER BRANCH in the moving role "
        "instead of a constant, which is a case #319's machinery cannot see "
        "either: every input stayed put.  See _RATE_MECHANISMS['ring-forgery']"),
    # TODO #322: the ZKP-NL message-tamper term, in the two ports whose
    # declaration a slice can reach.  See _RATE_MECHANISMS for the measurement.
    ("java", 19): (
        "(1/3) ** rounds",
        {"rounds": {"java": ("local", r"int n = 32, rounds\s*=\s*(\d+)")}},
        "Java's ZKP-NL tamper axis.  The verifier recomputes the per-round "
        "Fiat-Shamir trit and compares it, so the term is (1/3)^rounds with ONE "
        "factor -- the message reaches nothing else in that verifier"),
    ("java", 28): (
        "(1/3) ** rounds",
        {"rounds": {"java": ("local", r"int n = 8, rounds\s*=\s*(\d+)")}},
        "the ZKBoo half of Java's ZKP-NL pair, same verifier and same "
        "recomputed-challenge comparison at its own width"),
    ("java", 35): (
        "(2/3) ** rounds",
        {"rounds": {"java": ("local", r"int forgeRounds\s*=\s*(\d+)")}},
        "Java's counterpart to [53], carrying the same 10x arithmetic slip "
        "from the same hand computation -- which is the argument for deriving "
        "it rather than copying it between ports"),
}

# The other direction, and the table is exhaustive in both like every other
# curated table here: a rated row is EITHER derived above or named below with a
# reason it cannot be.  Adding a formula for one of these fails until its entry
# is deleted, so expressing a rate FORCES the row out rather than leaving a
# stale claim beside a live formula -- REPLAY_COVERAGE's rule (#305) one axis
# over.
#
# What these have in common is that none of them is a function of a round count
# or a trial budget: they are coincidence and union terms over a WIDTH, whose
# derivation would restate the same 2^-n in Python and buy no tripwire, since
# the width is already PARAMETERS' object and a numbered test that changed it
# would move its verdict fingerprint (#318) as well.  The two that are NOT of
# that shape are [4], whose input is a run-time flag, and [21], whose input is
# a module-level dict OUT OF SLICE -- and those two are the recorded limits of
# this axis, from opposite ends.
#
# EACH ENTRY CARRIES AN ANCHOR, which is TODO #321's structural addition:
#
#     row key -> (lang, regex, reason)
#
# The regex must match EXACTLY ONCE in that language's whole harness file AND
# exactly once inside THAT test's own body slice, so the reason is pinned to the
# test it describes rather than to the test somebody had in mind.  That is not
# a hypothetical: TODO #320 found ("java", 26)'s reason describing "Java's
# ZKBoo tamper-rejection", which is [28], and it found it INCIDENTALLY, while
# doing something else.  A reason is prose, so nothing cross-checked WHICH test
# it was about -- #295's false-reason finding aimed at this table instead of at
# a constant -- and one anchor per row is the cheapest thing that does.
#
# It is ONE port per row and the scope is stated rather than assumed: the defect
# the anchor closes is "this sentence is about another test", which one port
# settles; C and Go carry no independent prose here, since a `shared` row's
# reason is one sentence about one expression the three write the same way.
#
# WHAT THE TODO #321 AUDIT FOUND, because the precedent said to expect
# something and the base rate was already 1 in 9: FIVE of these nine reasons
# were wrong, in both directions.  [49] named a parameter the test does not use
# (n = 32 against a hardcoded 256) and published a rate 10^134 too large; [10]
# read its rate off the sub-check that does NOT bind, publishing 1e-30 for a
# 2.3e-7 term -- the first error on this axis in the UNSAFE direction; [4]'s
# union bound enumerated three of the four widths it sweeps; [46] rounded its
# own arithmetic 3e4 too high; and ("java", 26) left the table entirely, its
# rate having become (1/3)^rounds when TODO #298 gave the b = 0 branch a weight
# binding, 4.6 million times smaller than the (2/3)^rounds every copy quoted.
# [5], [11], [19] and ("java", 14) reproduced.
_SAMPLED_TEST_RATE_LITERAL = {
    # ── TODO #333: the same rate, in the port that had no benchmark layer ──
    ("java", 36): ("java", r"boolean okAgree = Stern\.qcmdpcDecapBgf\(",
                    "THE SAME DFR THE SHARED [54] ROW CARRIES, for the same "
                    "reason and with the same consequence: it is not a "
                    "function of the shipped constants, so an expression over "
                    "QCMDPC_R/D/T would be #320's defect with the arithmetic "
                    "wrong as well as the mechanism.  Both rows therefore "
                    "carry the literal -- deriving it in one port and "
                    "hand-computing it in the others would be two sources of "
                    "truth for one number, which is exactly the reason "
                    "('java', 31) gives for mirroring ('shared', 50)"),
    # ── TODO #332: a rate no constant in any port can express ─────────────
    ("shared", 54): ("python", r"control: encap/decap agree=\{ok_agree\}",
                    "THE DFR IS NOT A FUNCTION OF THE SHIPPED CONSTANTS, and "
                    "that is the whole reason #285 exists: r, d and t are in "
                    "PARAMETERS and the failure rate they imply is not "
                    "computable from them -- it is read off BIKE's published "
                    "analysis at the instance #276 adopted verbatim, and at "
                    "BIKE-128 no trial count reaches it, so "
                    "qcmdpc_bgf_failure_rate.py reports a one-sided upper "
                    "bound and never a measurement.  An expression over "
                    "QCMDPC_R/D/T would be a formula nobody derived, which is "
                    "#320's defect with the arithmetic coming out wrong as "
                    "well as the mechanism"),
    # ── TODO #322's six, and the reasons are three distinct limits ────────
    ("shared", 8):  ("python", r'status = "PASS" if wins == 0',
                    "a 2^-256 event, and the CONSTANT is the key width, which "
                    "is not a per-test parameter any slice can read: [8] uses "
                    "whatever _KEYBITS the harness was built for.  Deriving it "
                    "would mean reading a module-level constant through the "
                    "PARAMETERS axis, which is a different table's subject"),
    ("java", 27):   ("java", r"rnlValidateMBlind\(uniform, q\)",
                    "the accept-control term 256*(1/4)^255, whose exponent is "
                    "the RING DIMENSION -- declared `final int n = 256` in a "
                    "block that also declares n for three other cases, so no "
                    "regex reads it uniquely.  Shared [49] carries the same "
                    "number for the same reason"),
    ("java", 29):   ("java", r"boolean ppMsg = !ZkpNl\.verifyPp\(",
                    "THE THIRD RECORDED LIMIT OF THE DERIVATION AXIS, after "
                    "[4]'s run-time flag and [21]'s module-level t: [28] and "
                    "[29] share ONE `int n = 8, rounds = 16` declaration, which "
                    "sits above the PASS [28] marker -- so it is inside [28]'s "
                    "slice and outside [29]'s, and outside the WIDENED scope "
                    "slice too.  Java's trailing marker makes a shared "
                    "declaration reachable from exactly one of the two tests "
                    "that use it"),
    ("java", 30):   ("java", r"boolean rejMsg = !HerraduraNl\.rnlSigmaVerify\(",
                    "the Sigma challenge space is comb(n, t) * 2^t and t lives "
                    "in Java's own sigma parameter table, a class constant far "
                    "outside any slice -- #321 recorded exactly this for the "
                    "shared [21] row and this is its Java counterpart"),
    ("java", 31):   ("java", r"final int nPar = 4, mEmul = 4, tau = 2",
                    "1/(comb(mEmul, tau) * nPar^tau).  All three ARE local "
                    "literals here, but the shared [50] row they mirror cannot "
                    "be derived in C, and a rate derived in one port and "
                    "hand-computed in the other three is two sources of truth "
                    "for one number -- so both rows carry the literal"),
    ("shared", 50): ("python", r'rejected\["wrong_msg"\] \+= 1',
                    "1/(comb(M, tau) * N_par^tau) = 1/96, and C is why it is a "
                    "literal: Go, Python and Java each declare the triple as "
                    "named locals, and C passes `4, 4, 2` as BARE POSITIONAL "
                    "ARGUMENTS at the hcred_prove_kkw call site while printing "
                    "\"(N=4, M=4, tau=2)\" as a STRING LITERAL -- so a retune "
                    "there would print the old numbers beside new behaviour, "
                    "which is #295's diagnostic-use rule inside a numbered test"),
    ("shared", 4):  ("python", r"tol = 6\.0 \* 50\.0 / math\.sqrt\(n_run\)",
                    "THE LIMIT OF THIS AXIS, and it is a real one: the bar is "
                    "tol = 6 * 50/sqrt(n_run), so the rate is a function of "
                    "the ITERATION COUNT, which -r moves at run time.  No "
                    "static read can pin a number the command line supplies; "
                    "what makes it safe is that the bar FOLLOWS the statistic "
                    "(#233), so the rate is ~1e-6 at every n_run rather than "
                    "at one of them.  TODO #321 re-derived it and corrected "
                    "the union's enumeration in all three harnesses: 480 bits, "
                    "not the 448 every copy said"),
    ("shared", 5):  ("python", r"expected >=\{size//4\}",
                    "mean Hamming distance against a null of size/2 over "
                    "GF_TRIALS: a 2^-n coincidence term at the widths swept, "
                    "not a soundness error, so there is no round count in it.  "
                    "RE-DERIVED by TODO #321 and it reproduces: the per-trial "
                    "HD is Binomial(size, 1/2), so the mean over 100 trials "
                    "sits (16 - 8)/sqrt(32/4/100) = 28.3 sigma above the bar "
                    "at the smallest cell, which is the row's own figure"),
    ("shared", 10): ("python", r"linearity violations=\{violations\}",
                    "TWO sub-checks in one conjunction, and TODO #321 found "
                    "the published rate read off the wrong one.  The binding "
                    "term is 'violations == n1_run' -- a 2^-n linearity "
                    "coincidence over _iters(1000) draws at the narrowest "
                    "size, 2.3e-7 -- and not the aperiodicity bar, which is "
                    "4e-67.  Both are widths, not round counts, so neither is "
                    "a formula this axis can read; what a formula would have "
                    "bought is the discipline of writing down which term "
                    "dominates, which is the whole finding"),
    ("shared", 11): ("python", r"nonlinear=\{nl_ok\}",
                    "the same shape as [10]'s aperiodicity half -- a binomial "
                    "tail over a per-trial coincidence against a percentage "
                    "bar -- on a genuinely nonzero exact quantity (4 in 20 000 "
                    "at n=32).  P(Binom(500, 2e-4) >= 11) ~ 2.5e-19 against a "
                    "recorded 1e-14, so the record is the conservative side of "
                    "its own arithmetic and stays"),
    ("shared", 21): ("python", r"z_tamper=\{ok_ztamper\}",
                    "THE ROW #321 TOOK OFF `exact` AND #330 TOOK OFF THE "
                    "BUDGET, and the reason it stays a literal is unchanged and "
                    "is the same limit [4] records from the other end: the rate "
                    "is (cases * _iters(5))/(comb(n, t)*2^t), and t comes from "
                    "_sigma_params' MODULE-LEVEL dict a thousand lines above "
                    "every [N] marker, which #319's body and scope slices "
                    "cannot reach by construction.  So the second recorded "
                    "instance of that limit -- [4]'s input is a run-time flag, "
                    "this one's is out of slice -- and the answer is #320's "
                    "rather than #319's: the MECHANISM is measured instead, in "
                    "_ARGUED_MEASUREMENTS['sigma-challenge-collision'], where "
                    "the reduced parameter is t itself.  The literal moved from "
                    "8.7e-6 to 1.5e-29 when #330 gave the two FS-binding cases "
                    "their own WIDTH, and the anchor is deliberately on "
                    "z_tamper rather than on either FS case: z_tamper is exact "
                    "at BOTH widths and so is the one field of this line that "
                    "the width gate cannot turn into n/a"),
    ("shared", 46): ("python", r"key-boundary collisions=\{amb\}",
                    "fpe/twk domain separation: two fresh 256-bit ciphertexts "
                    "must differ.  Pure coincidence at 2^-256 over 200 "
                    "iterations and two comparisons, and a formula would "
                    "restate the block width PARAMETERS already holds.  TODO "
                    "#321 re-derived it as 3.4e-75 against a recorded 1e-70"),
    ("shared", 49): ("python", r'\[49\] HKEX-RNL peer-m_blind',
                    "HKEX-RNL m_blind accept-control: n * (1/4)^(n-1) at the "
                    "ring dimension the test USES, which TODO #321 found is a "
                    "hardcoded n = 256 and not the n = 32 both this entry and "
                    "the census row claimed -- the test sweeps nothing.  "
                    "Parameterised by a WIDTH, not by a round count, and the "
                    "sparsity clause is unreachable at q = 65537.  A formula "
                    "would still not have caught it: the width is a literal in "
                    "the test body, so #319's reader would have read 256 and "
                    "evaluated it correctly while the PROSE went on saying 32 "
                    "-- which is #320's finding (the number right, the stated "
                    "parameter wrong) with the two halves swapped"),
    ("python", 19): ("python", r"collision sanity, block boundaries, keyed MAC",
                    "HFSCX-256 collision sanity over 500 fresh pairs: a "
                    "birthday term at the digest width, 4e-75.  Re-derived by "
                    "TODO #321 as 500 * 2^-256 = 4.3e-75 and it reproduces -- "
                    "the one literal of the nine whose number and whose stated "
                    "mechanism were both already right"),
    ("java", 14):   ("java", r"anyMismatch = false; break;",
                    "Java's QC-MDPC decapsulation mismatch, inherited from "
                    "BIKE-128's DFR rather than derived here -- #285's finding "
                    "that no trial count reaches that rate is precisely why "
                    "there is no expression to write.  TODO #321 checked the "
                    "shape rather than the number, which is all that is "
                    "available: the gate is DFR^20 because the loop breaks on "
                    "the first SUCCESS, so it fires only if all 20 trials "
                    "miss, and 1e-50 is a bound on an inherited bound"),
}



# ── Part 3/7: whether the FORMULA is the right function ──────────────────
#
# TODO #320, and it is the limit #319 stated on itself in the same breath as
# its own result: "this closes 'the rate's INPUTS moved' and not 'the rate's
# DERIVATION was wrong' -- a formula that is the wrong function of the right
# constants still evaluates".  The limit stopped being theoretical within the
# hour.  The four ports stated CONTRADICTORY MECHANISMS for [45]'s rate:
#
#     C, Go, Python    "a bad syndrome is caught only in the b=0 round"
#     Java             "only b=2 references the syndrome"
#
# Java is right, and the VERIFIER settles it rather than an argument doing so:
# the public syndrome appears in exactly one branch, H(pi_seed, Hy ^ syndrome)
# under b == 2, while b == 0 checks wt(sr ^ sy) and two commitment hashes and
# b == 1 checks Hr.  Neither touches it.
#
# THE NUMBER WAS RIGHT AND THE DERIVATION WAS WRONG, which is the combination
# no other axis here can see.  It is (2/3)^rounds either way, because either
# way exactly one of three challenge values is the detecting one -- so #319's
# machinery evaluates it correctly, PARAMETERS agrees, #318's fingerprint is
# unmoved, the budget is unchanged, and the stated mechanism is false in three
# of four ports.  A rate that is right for the wrong reason survives every axis
# this repo has.  And it PROPAGATED: #319's own reason for [45] repeats the
# b = 0 claim, copied from the harness comment while writing the table that was
# supposed to make rates trustworthy -- #310's lesson ("a reason exact about
# the wrong object reads exactly like a correct one") landing on the item that
# restated it.
#
# So this table is #304's move at one more level of depth.  That item required
# a `follows` gate to carry a rate AND the token MEASURED, because "requiring
# the number alone would have certified §3.5 at 3.0e-4 while it ran at 6.0e-3
# -- the arithmetic is only as good as the null it is done against".  Here the
# arithmetic is only as good as the MECHANISM it is done over, and #319 shipped
# 14 rated rows with not one of them held to a measurement.
#
# WHY A FREQUENCY CHECK IS NOT THE CHECK, which is the hard part.  Both
# mechanisms predict (2/3)^rounds, so measuring the acceptance rate alone would
# have CONFIRMED the wrong one.  What separates them is #310's shape -- record
# WHICH challenge strings the failures carried -- so every entry below states
# the DETECTING event as a per-trial predicate and the ALTERNATIVE it has to
# exclude, and the instrument reports both.  A rate check validates the
# arithmetic; only a witness check validates the mechanism.
#
# WHAT THE MEASUREMENT FOUND, beyond confirming the b = 2 correction: [22]'s
# formula was ALSO wrong, by a factor of 3, and in the same conservative
# direction as #319's 10x -- so again invisible to every check and every flake.
# The stated mechanism was the poked commitment failing to be opened; the real
# one is BOTH terms, because the poke reseeds Fiat-Shamir over the whole
# commitment block (so all `rounds` stored challenges must coincidentally
# re-match, (1/3)^rounds) AND round 0's challenge must leave the poked com_1
# unopened (a further 1/3, since com_1 is opened for e in {0, 2}).  The single
# predicate matched 4 trials in 5 and the conjunction matches every one.
#
# FIVE PROPERTIES OF THIS TABLE.
#
# (1) IT IS A RECORD, NOT A CI GATE, and that is stated up front rather than
#     discovered.  Measuring a 19.75% rate usefully costs hundreds of trials
#     per rung -- ~25 minutes here -- which is #289's runtime problem in
#     miniature, and a validation that itself decides on a fresh sample is
#     #299's defect re-introduced one level up.  #304's model again: the token
#     and the numbers are recorded, the checker holds the record to the
#     expression it validates, and the runner does not re-measure.  The
#     instrument is spec/measure_sampled_rates.py and is deliberately NOT in
#     SecurityProofsCode/, so run_findings_gates.py cannot discover it and no
#     NON_GATING entry has to argue it away.
#
# (2) THE RECORD IS HELD TO THE EXPRESSION IT VALIDATES, in five ways that all
#     fail rather than drift: `term` must be a SUBSTRING of every covered row's
#     formula (check E's anchor rule, so renaming the formula fails until
#     somebody re-measures), `var` must be one of its variables, each rung's
#     recorded prediction must EQUAL the term evaluated at that rung, each
#     rung's accept count must sit inside a 6-sigma band of its own prediction,
#     and `note` must carry the token MEASURED.
#
# (3) THE INSTRUMENT MUST NOT REACH A SHIPPED DEFAULT.  [45] at rounds = 4 is
#     the 19.75% CLAUDE.md's Testing section warns about by name, used here as
#     an instrument; #310's remedy for [53] was to give the sub-check its own
#     round count, and the inverse obligation is that the reduced count stays
#     local.  Checked, not asserted: the SHIPPED value of the same variable is
#     read out of every port through #319's own readers and must be strictly
#     greater than the top of the ladder.  It compares the VARIABLE and not the
#     rate, because [45] carries a `trials` multiplier and comparing rates
#     would have compared 2 * (2/3)^4 against (2/3)^4 and passed.
#
# (4) A ROW WHOSE MECHANISM CANNOT BE MEASURED SAYS SO, in
#     _RATE_MECHANISM_UNMEASURED, exhaustive in both directions like every
#     other curated table here -- and it ships EMPTY, on PARAM_USE_EXEMPT's
#     precedent (#295): all five derived rows are measured, so a future entry
#     means a formula was argued for rather than that the check was switched
#     off.  #300's derived-versus-argued split is what that category exists for
#     and #304 is what happens when one of them contributes nothing to the
#     advertised number.
#
# (5) SCOPE, stated because #302 §6 is what an unchecked scope paragraph
#     becomes.  This validates the five rows that HAVE a formula.  The nine in
#     _SAMPLED_TEST_RATE_LITERAL have no formula to be the wrong function of --
#     their numbers are coincidence and union terms over a width, plus [4],
#     whose input is a run-time flag -- so they are out of scope by
#     construction rather than by exemption.  And a property ALL FOUR PORTS get
#     wrong is invisible here as it is everywhere: the measurement runs
#     Python's copy, and the exit from that blind spot is an assertion about
#     one implementation (#298's rule 1), which is what the witness predicate
#     is.
#
#   name -> {rows, term, var, detects, excludes, ladder, witness, note}
#
#     rows      the _SAMPLED_TEST_RATES keys this mechanism's term carries
#     term      the substring of their formula this measurement validates
#     var       the formula variable the ladder reduces
#     detects   the per-trial predicate: the outcome must equal it, exactly
#     excludes  the alternative predicate a frequency check could not rule out
#     ladder    {var value: (trials, accepts, predicted)} as measured
#     witness   the predicate's agreement, pooled, and the alternative's
#     note      prose, carrying the token MEASURED (#304's rule)
_RATE_MECHANISMS = {
    "corrupted-syndrome": {
        "rows": [("shared", 45), ("java", 12)],
        "term": "(2/3) ** rounds",
        "var":  "rounds",
        "detects":  "a round whose challenge is b = 2 -- the only branch of "
                    "hpks_stern_f_verify that reads the syndrome at all",
        "excludes": "b = 0, which C, Go and Python all stated in prose and "
                    "which predicts the SAME (2/3)^rounds, so the frequency "
                    "cannot separate the two and the witness is the check",
        "ladder": {2: (300, 138, 0.444444),
                   4: (300,  61, 0.197531),
                   6: (300,  26, 0.087791)},
        "witness":  "900/900 trials had accept == (no b = 2 round), exactly; "
                    "the b = 0 predicate matched 527/900, so the alternative "
                    "is not merely unconfirmed, it is refuted",
        "note":     "MEASURED at rounds = 2/4/6 over 900 trials at the n = 32 "
                    "[45] runs its Stern block at, with the honest "
                    "verification as an accept control on every trial (900/900 "
                    "-- a signer producing nothing verifiable would score every "
                    "trial a rejection and read as a perfect result, #234's "
                    "vacuous pass).  The rate reproduces (138/61/26 against "
                    "133.3/59.3/26.3 predicted) and the WITNESS is what settles "
                    "the mechanism: every accepting trial carried a challenge "
                    "string with no b = 2 round and every rejecting one carried "
                    "at least one, while the b = 0 predicate tracked the outcome "
                    "in 527 of 900.  Java's [12] is covered by the same "
                    "measurement on the same reading that found the defect: "
                    "hpksSternFVerify reads the syndrome in its b = 2 branch "
                    "only, as do C's Hys[k] = Hy[k] ^ syndr[k] and Go's default "
                    "case, so the four verifiers have one shape and the formula "
                    "is one formula -- which is also the limit (5) states, since "
                    "a property all four got wrong would be invisible here",
    },
    "offweight-witness": {
        "rows": [("shared", 53), ("java", 35)],
        "term": "(2/3) ** rounds",
        "var":  "rounds",
        "detects":  "a round whose challenge is b = 0 -- the only branch that "
                    "binds wt(respA ^ respB) = t, which is #298's fix and so "
                    "the only place an off-weight witness can be caught",
        "excludes": "b = 2, the MIRROR IMAGE of the row above, and the pair is "
                    "the point: the two adjacent tests have OPPOSITE detecting "
                    "rounds, which is how the true b = 0 claim came to be "
                    "written on the test where it is false",
        "ladder": {2: (150,  79, 0.444444),
                   4: (150,  36, 0.197531),
                   6: (150,  13, 0.087791)},
        "witness":  "450/450 trials had accept == (no b = 0 round), exactly; "
                    "the b = 2 predicate -- the OTHER row's detector -- matched "
                    "255/450, so the two mechanisms are measurably distinct "
                    "rather than two descriptions of one thing",
        "note":     "MEASURED at rounds = 2/4/6 over 450 trials at [53]'s "
                    "n = 64, each with the honest signature verified first as "
                    "an accept control (450/450).  Acceptance 79/36/13 against "
                    "66.7/29.6/13.2 predicted.  #310 measured this same "
                    "mechanism once, ad hoc -- 3 acceptances in 400 trials, all "
                    "3 the no-b=0 challenge strings -- and threw the harness "
                    "away, which is #296's diagnosis of #294 and the reason "
                    "this table exists rather than a second one-off.  The "
                    "PAIRING with the row above is what earns its keep: the "
                    "witness for each is the ALTERNATIVE for the other, so a "
                    "reader who conflates them (which is how the true b = 0 "
                    "claim came to be written on [45]) is contradicted by both "
                    "measurements at once",
    },
    "zkboo-poke": {
        "rows": [("shared", 22)],
        "term": "(1/3) ** (rounds + 1)",
        "var":  "rounds",
        "detects":  "the conjunction, and finding that it was one is this "
                    "item's second result: every one of the `rounds` stored "
                    "challenges must re-match the recomputation over the "
                    "TAMPERED commitment block, AND round 0's challenge must "
                    "leave the poked com_1 unopened (e == 1, since com_1 is "
                    "opened for e in {0, 2})",
        "excludes": "either term alone.  The opening term alone is flat at 1/3 "
                    "whatever the round count, so the LADDER separates it by "
                    "shape; the Fiat-Shamir term alone is #316's [17] "
                    "mechanism and is what the row's prose said, and it "
                    "overstates the rate 3x -- conservatively, hence invisible",
        "ladder": {1: (300,  29, 0.111111),
                   2: (300,  13, 0.037037),
                   3: (300,   2, 0.012346)},
        "witness":  "900/900 trials had accept == (Fiat-Shamir re-matches AND "
                    "com_1 unopened), exactly.  The Fiat-Shamir term ALONE "
                    "matched 808/900 and the opening term alone 658/900 -- both "
                    "high enough to look like an answer and neither exact, "
                    "which is what a conjunction looks like from either side",
        "note":     "MEASURED at rounds = 1/2/3 over 900 trials at n = 32, the "
                    "narrower of the two widths [22] sweeps, with the untampered "
                    "proof verified on every trial as an accept control "
                    "(900/900).  Acceptance 29/13/2 against 33.3/11.1/3.7 "
                    "predicted by the CORRECTED two-term formula; #319's "
                    "one-term version predicted 100/33/11 and the measurement "
                    "is what found it.  The ladder does more work here than a "
                    "single rung could: the opening term alone is FLAT at 1/3 "
                    "whatever the round count, so its shape separates it from "
                    "the exponential without needing the witness at all -- and "
                    "the witness then settles it exactly",
    },
    "ring-forgery": {
        "rows": [("java", 26)],
        "term": "(1/3) ** rounds",
        "var":  "rounds",
        "detects":  "any round whose challenge for the FORGING member is "
                    "b != 1, because two of the three branches catch a witness "
                    "matching no member's syndrome: b = 0 binds "
                    "wt(respA ^ respB) = t and b = 2 checks "
                    "H(pi_seed, Hy ^ syndrome)",
        "excludes": "'no b = 2 round', the PRE-#298 mechanism -- when b = 0 "
                    "bound nothing, which is what SelfTest.java's comment and "
                    "both spec/ tables still said.  It predicts (2/3)^rounds, "
                    "4.6 MILLION times larger at the shipped 32, and it was "
                    "right once: TODO #260 saw a real flake at 8 rounds, which "
                    "(2/3)^8 = 3.9% explains and (1/3)^8 = 1.5e-4 does not",
        "ladder": {1: (300, 101, 0.333333),
                   2: (300,  43, 0.111111),
                   3: (300,  12, 0.037037)},
        "witness":  "900/900 trials had accept == (every round's challenge for "
                    "the forging member is b = 1), exactly; the pre-#298 "
                    "predicate matched 619/900, so the old mechanism is not "
                    "merely superseded, it is refuted against the code as it "
                    "now stands",
        "note":     "MEASURED at rounds = 1/2/3 over 900 trials, with an honest "
                    "ring signature verified on every trial as an accept "
                    "control (900/900).  Acceptance 101/43/12 against "
                    "100.0/33.3/11.1 predicted by (1/3)^rounds, where the "
                    "superseded (2/3)^rounds predicts 200/133/89 -- so the "
                    "FREQUENCY separates these two, unusually for this table, "
                    "and the witness then settles it exactly.  Run at the "
                    "Python harness's ring width n = 32 with Java's k = 4 "
                    "rather than at Java's n = 256: the mechanism is a "
                    "statement about which verifier BRANCH reads what, and "
                    "hpks_stern_ring_verify_local and SternRing.verify are the "
                    "same three branches line for line, while one n = 256 trial "
                    "costs 6.7 s against 0.5 s -- 1.7 hours for the ladder "
                    "instead of 13 minutes.  That cross-port step is the same "
                    "one 'corrupted-syndrome' takes for Java's [12], and it is "
                    "the same limit: a property all four ports got wrong would "
                    "be invisible here",
    },
}

# The other direction, and it ships EMPTY -- see (4) above.  An entry here is a
# derived row whose MECHANISM cannot be measured, with the reason; it is not a
# way to postpone measuring one.
#
#   row key -> reason
_RATE_MECHANISMS["zkpnl-message-rematch"] = {
    "rows": [("java", 19), ("java", 28)],
    "term": "(1/3) ** rounds",
    "var":  "rounds",
    "detects":  "a message tamper surviving because EVERY round's recomputed "
                "Fiat-Shamir trit still equals the one the proof stored -- "
                "`h[0] % 3 != challenges[j]` is the only place the message "
                "reaches this verifier",
    "excludes": "the commitment-binding story, which is what the SAME words "
                "mean in HCRED: there _hcred_commit hashes the statement, so a "
                "changed message changes every recomputed commitment and no "
                "challenge coincidence can repair one.  Both stories say "
                "'the verifier rejects a tampered message' and they differ by "
                "2^-256 against (1/3)^rounds, so only a witness separates them",
    "ladder": {1: (600, 193, 0.333333),
               2: (600,  69, 0.111111),
               3: (900,  42, 0.037037)},
    "witness":  "600/600, 600/600 and 900/900 at rounds = 1/2/3 had "
                "accept == (every recomputed challenge equals the stored one), "
                "EXACTLY -- including the 193, 69 and 42 that ACCEPTED, so the "
                "witness is checked on both branches and not only the "
                "rejecting one (#296)",
    "note":     "MEASURED at rounds = 1/2/3 over 2100 trials by "
                "spec/measure_sampled_rates.py, at n = 32 rather than the Java "
                "rows' own widths because BITARRAY.md 2 admits nothing below "
                "16 in the Python instrument.  That substitution is safe for a "
                "stated reason rather than by assumption: the quantity is a "
                "property of the CHALLENGE COMPARISON, which reads neither n "
                "nor any width-dependent value, and the witness holding "
                "EXACTLY at every rung is what says the substitution did not "
                "change the mechanism.  The rate reproduces too (193/69/31 "
                "against 200.0/66.7/33.3 predicted), but per TODO #320 the "
                "rate is corroboration and the witness is the check -- here "
                "doubly so, since the alternative this excludes predicts a "
                "DIFFERENT rate and would have been caught by frequency alone; "
                "what frequency could not do is tell the reader WHICH of the "
                "two protocols they are looking at"
}
_RATE_MECHANISM_UNMEASURED = {}


# ── Part 4/7: the ARGUED half -- an `exact` verdict owes a SLACK ──────────
#
# TODO #321.  #319 made every rate an EXPRESSION over constants read from
# source and #320 held each such formula to a MEASURED mechanism.  Both act on
# the rows that HAVE a formula.  The rest of `_SAMPLED_TESTS` rested on prose
# alone -- 6 rows declared `exact` and 9 carrying a hand-computed literal -- and
# nothing checked either kind.
#
# WHY THE `exact` ROWS ARE THE EXPOSED ONES.  `exact` is the strongest claim in
# the table: the false-failure rate is ZERO.  It is also the only category that
# contributes NOTHING to the advertised budget, which is precisely the erosion
# shape #304 recorded ("an argued gate could be the job's dominant flake source
# and the advertised number would not move").  And the precedent on curated
# reasons is unanimous: #295 found 2 of 6, #304 found 3 of 3, #310 found one
# "exact about the wrong object", and #320 found a tenth reason describing the
# WRONG TEST -- incidentally, while doing something else.
#
# A SAMPLED ZERO CANNOT SHOW WHAT AN `exact` ROW ASKS IT TO SHOW, which is the
# item's central point and is not about trial counts.  [14]'s evidence was
# hkex_rnl_failure_rate.py's 0 failures in <= 2000 trials; that Wilson interval
# tops out near 1.8e-3, EIGHTEEN TIMES the whole job budget, so the measurement
# is equally consistent with `exact` and with a rate that alone would blow it --
# #285's finding in a different protocol, and #300's gate-that-cannot-go-red
# from the other side.  What the claim actually rests on is a MARGIN, and a
# margin is a different object: it is a MAXIMUM over coefficients, so one trial
# reports as many samples as the statement has terms, and its distribution has
# a visible tail where a failure count has none.  Nothing measured it.
#
# SO THE TWO TABLES BELOW.  `_EXACT_BASES` is the census -- every `exact` row
# says WHY it is exact and what happens at the parameters the suite DEPLOYS when
# the test does not run there -- and `_ARGUED_MEASUREMENTS` holds the evidence,
# on #320's model: a quantity, a bound, a ladder at a reduced parameter, an
# exact per-trial WITNESS, and the token MEASURED.
#
# SIX THINGS THAT CAME OUT OF DOING IT.
#
# (1) ONE `exact` ROW WAS NOT EXACT.  [21]'s tampered-commitment case turns on
#     a Fiat-Shamir CHALLENGE COLLISION, not on the residual-norm check, so it
#     runs at _iters(5)/(comb(32, 4) * 2^4) = 8.7e-6 -- nine percent of the
#     budget, from the category that was contributing nothing to it.
#
# (2) THE OTHER `exact` ROW'S BOUND WAS 4x WRONG, and the correction is EXACT
#     rather than sampled.  SecurityProofs-4.md 480 says HKEX-RNL reconciliation
#     needs "max per-coeff error << q/8"; over all 65537 residues the smallest
#     error that can flip a bucket is q/32 down and 3q/32 up.  Lenient by 4x, so the DOCUMENTED safety
#     factor was four times the real one -- and the real one is still 3.1x on the
#     observed maximum at the deployed ring, so the row keeps `exact` and finally
#     has evidence for it.
#
# (3) THE MARGIN HAD TO BE MEASURED AT THE DEPLOYED RING AND THE TEST IS NOT.
#     [14] sweeps RNL_SIZES = [32, 64, 128, 256], all four RETIRED by #223,
#     while the suite deploys RNLN = 1024 -- and the error accumulates as
#     O(sqrt n) through the convolution, measured at 419.6 against n = 256's
#     206.8, a factor 2.03 for 4x the dimension.  So the tested widths are the
#     FAVOURABLE ones: #295's lenient direction in a parameter instead of in a
#     corpus, and #313's "nothing ever ran the algorithm at another width"
#     pointed at a CORRECTNESS property rather than at a cost figure.
#
# (4) A MARGIN IS NOT A RATE AND THE TABLE DOES NOT PRETEND IT IS.  The two
#     `kind`s carry different ladders -- a margin rung records (trials, min,
#     mean, adverse) and a rate rung (trials, events, predicted) -- because
#     collapsing them would mean counting the margin's sign, which is the
#     0/N this item exists to stop producing.
#
# (5) THE WITNESS IS WHAT MAKES EITHER OF THEM EVIDENCE, and for the margin it
#     is not a proxy at all: the margin's SIGN and the reconciliation's answer
#     are the same fact computed two ways, so the predicate is exact by
#     construction and the instrument cannot flake on its own account (#299
#     answered one level up rather than re-introduced).  The DEPLOYED rung alone
#     could not check it -- every trial agrees there -- so the ladder's job is
#     to supply the failing branch, which is #296's "a branch a random stream
#     never enters is not covered either".
#
# (6) SCOPE, stated because #302 6 is what an unchecked scope paragraph becomes.
#     This is about the rows with NO formula.  It is NOT about widening [14] to
#     run at n = 1024 in the harness -- that is a cost decision (a deployed-ring
#     handshake is ~39 ms in Python and the test runs _iters(200) per size) --
#     and the measurement ANSWERS the question that would have justified it:
#     the deployed slack is 16 spreads clear of the cliff, so the untested
#     width is not a risk and there is nothing to file.  What the item's own
#     text said to file if the margin said otherwise is therefore not filed,
#     deliberately, rather than left as an omission.
#
#   row key -> {basis, deployed, evidence}
#
#     basis     why the rate is zero, one of:
#                 identity            a width-independent algebraic identity,
#                                     so the statistic has no variance
#                 separated           the probabilistic branch is separated from
#                                     the scored one (#233's [18])
#                 no-assertion        the test asserts no rejection, so it
#                                     carries no soundness error to begin with
#                 exhaustive-branches every branch the sample can select
#                                     rejects, so there is no detecting event
#                 margin              an inequality, with measured slack
#     deployed  what holds at the parameters the SUITE deploys, when the test
#               does not run there -- the question nobody had asked of these
#     evidence  the _ARGUED_MEASUREMENTS key, and only `margin` may have one
_EXACT_BASES = {
    ("shared", 2): {
        "basis": "identity",
        "deployed": "FSCX is LINEAR, so flipping input bit j moves the output "
                    "by M . e_j = e_j ^ ROL(e_j) ^ ROR(e_j), of weight exactly "
                    "3 at every n >= 3 because the three positions are distinct "
                    "under ROTATION.  The mean is therefore 3.000 with zero "
                    "variance at SIZES's four widths and at the deployed "
                    "KEYBITS = 256 alike -- one statement, no parameter it can "
                    "differ at, nothing to measure.  The printed min and max "
                    "are not in the verdict, which is why the 2.9/3.1 window "
                    "is legacy slack rather than tolerance",
        "evidence": None,
    },
    ("shared", 18): {
        "basis": "separated",
        "deployed": "THE REFERENCE ROW, and its parameters point the safe way.  "
                    "It runs at the harness's n = 32, t = 2 code, which is NOT "
                    "uniquely decodable -- 43% of keys admit a weight-2 "
                    "collision -- and that is exactly why #233 separated the "
                    "ambiguous-syndrome branch from the failure branch.  The "
                    "DEPLOYED Stern instance (SDF_T = 16 at n = 256) makes "
                    "ambiguity vanishingly rarer, so the test runs the ADVERSE "
                    "case and the separation makes the verdict exact at both",
        "evidence": None,
    },
    ("shared", 20): {
        "basis": "no-assertion",
        "deployed": "ring COMPLETENESS at rounds = 4, against a shipped "
                    "SDF_ROUNDS = 32 and a production 219.  A completeness "
                    "assertion has no soundness error at ANY round count, so a "
                    "reduced count is adverse to nothing here -- which is the "
                    "one direction in which CLAUDE.md's rounds = 4 warning does "
                    "not apply, and the row exists to say so.  Adding a "
                    "rejection case at 4 would carry (2/3)^4 = 19.75%, which is "
                    "that warning as a live constraint",
        "evidence": None,
    },
    ("python", 17): {
        "basis": "exhaustive-branches",
        "deployed": "the forgery claims fake_chal = [0]*8 and the verifier "
                    "recomputes the Fiat-Shamir challenge, rejecting at the "
                    "first round that disagrees.  On the (1/3)^rounds of "
                    "challenge strings where every round happens to agree it "
                    "reaches the b = 0 branch and rejects THERE, on the merits "
                    "(c1 carries no ds=2, and #298's wt(respA ^ respB) == t "
                    "fails at weight 0).  Both paths reject, at every round "
                    "count -- so the sampling TODO #316 removed cannot return "
                    "through a parameter move, which is the property that makes "
                    "this `exact` rather than negligible",
        "evidence": None,
    },
    ("shared", 14): {
        "basis": "margin",
        "deployed": "THE ROW THE TABLE NOMINATED ITSELF, and the lead held.  It "
                    "sweeps RNL_SIZES = [32, 64, 128, 256] -- every one RETIRED "
                    "by TODO #223 -- while the suite deploys RNLN = 1024, and "
                    "the per-coefficient error accumulates as O(sqrt n) through "
                    "the ring convolution: max|e| measures 206.8 mean at n = 256 "
                    "and 419.6 at n = 1024, a factor 2.03 for 4x the dimension, "
                    "which is SecurityProofs-4.md 476's mechanism quantified.  "
                    "So the TESTED widths are the favourable ones and the "
                    "untested deployed one is adverse, and the margin is "
                    "measured where the suite runs rather than where the test "
                    "does.  It is comfortable: slack 2019 mean and 1647 worst of "
                    "1000 against a bound of 2047, i.e. max|e| at 20% of the "
                    "bound, 16 spreads clear of zero",
        "evidence": "rnl-reconciliation-margin",
    },
}

# The evidence.  #320's shape, with a `kind` because the objects differ: a
# margin is an inequality with slack and a collision is a rate with a count.
#
#   name -> {kind, rows, quantity, bound, ladder, witness, note, ...}
#
#     kind == "margin": also `deployed` ({PARAMETERS row: value}, held to every
#             port's source), `var` (the ladder's parameter) and `reduces` (the
#             `deployed` key it reduces -- its deployed value IS the top rung).
#             Rungs are (trials, min_margin, mean_margin, adverse).
#     kind == "rate":   also `var`, `shipped` (the value the test runs at) and
#             `shipped_why` (why no reader can pin it, since a value this axis
#             cannot read is the whole reason the row stays a literal).
#             Rungs are (trials, events, predicted), banded at 6 sigma like
#             #320's.
_ARGUED_MEASUREMENTS = {
    "rnl-reconciliation-margin": {
        "kind": "margin",
        "rows": [("shared", 14)],
        "quantity": "the signed distance from B's per-coefficient error to the "
                    "nearest value that would move that coefficient's 2-bit "
                    "Peikert bucket, minimised over the key_bits//2 "
                    "coefficients reconciliation actually reads: with "
                    "r = (4c + (2h+1)*(q//4)) mod q, "
                    "min(e + r//4, (q-1-r)//4 - e)",
        "bound":    "zero -- and the threshold underneath it is EXACT, not "
                    "sampled: swept over all 65537 residues, the SMALLEST error "
                    "that can flip a bucket is 2048 = q//32 downward and "
                    "6145 = 3q/32 upward, so the room is 2047 down and 6144 up "
                    "and the guaranteed symmetric bound is |e| <= 2047 = "
                    "q/32 - 1, ASYMMETRIC 3:1.  SecurityProofs-4.md 480 says 'max "
                    "per-coeff error << q/8', which is 4x too generous -- in "
                    "the LENIENT direction, so the documented safety factor was "
                    "four times the real one.  Correctness is unaffected and "
                    "the sentence was not",
        "deployed": {"rnl-n": 1024, "rnl-q": 65537, "rnl-p": 4096,
                     "rnl-pp": 4, "keybits": 256},
        "var":      "p",
        "reduces":  "rnl-p",
        "ladder":   {4096: (1000,  1647,  2019.3,   0),
                     1024: (1000,   131,  1416.5,   0),
                      512: (1000, -2181,   363.5, 261),
                      256: (1000, -6404, -2057.5, 985)},
        "witness":  "4000/4000 trials had agreement == (margin >= 0), exactly "
                    "-- including the 1246 that DISAGREED, which is what makes "
                    "it evidence rather than a tautology checked on one branch.  "
                    "The margin's sign and the reconciliation's answer are the "
                    "same fact computed two ways, so the predicate is exact by "
                    "construction and the instrument cannot flake",
        "note":     "MEASURED at the DEPLOYED ring (n = 1024, key_bits = 256) "
                    "over 1000 trials per rung, with p -- the public-key "
                    "rounding modulus -- as the ladder's reduced parameter, "
                    "because the rounding error of lift() is q/(2p) and so "
                    "scales as 1/p, which puts the cliff four rungs down and "
                    "PREDICTS where rather than hunting for it.  The 1/p law "
                    "reproduces to 1.2%: max|e| means 419.6 / 1665.7 / 3353.6 / "
                    "6636.7 against 419.6 x {1, 4, 8, 16}.  The cliff arrives "
                    "at p = 512, where the mean margin is 363.5 and 261 of 1000 "
                    "trials disagree, and by p = 256 it is negative and 985 do.  "
                    "THE DEPLOYED RUNG IS THE CLAIM: 0 adverse trials, worst "
                    "margin 1647, mean 2019.3 with spread 121.6, so the shipped "
                    "parameters sit 16 spreads clear of a cliff whose position "
                    "is measured and not modelled -- which is the item's own "
                    "constraint, since a worst-case bound on the noise sum would "
                    "have certified the row from a model of a CBD(1) sampler "
                    "when it is the convolution that accumulates (#304's "
                    "finding, three gates over)",
    },
    "sigma-challenge-collision": {
        "kind": "rate",
        "rows": [("shared", 21)],
        "quantity": "whether the verifier's RECOMPUTED Fiat-Shamir challenge "
                    "equals the claimed one -- the event BOTH of [21]'s "
                    "FS-binding cases are actually a function of, where the row "
                    "said it was exact and then priced only one of the two "
                    "(TODO #330)",
        "bound":    "1/(comb(n, t) * 2^t) per trial PER CASE: the challenge is a "
                    "weight-t polynomial with a sign per position, so the space "
                    "is comb(32, 4) * 2^4 = 575 360 at t = 4 and "
                    "comb(256, 16) * 2^16 = 6.6e29 at the t = 16 the FS cases "
                    "now run at.  On a collision the WRONG-MESSAGE case accepts "
                    "with probability 1 -- the verification is then the honest "
                    "one, term for term -- while the tampered-w case needs the "
                    "residual-norm check to tolerate ONE coefficient shifted by "
                    "1 inside a slack of t*(q//(2p)+1), which it does.  Two "
                    "cases, one mechanism, and the record had one of them",
        "var":      "t",
        "shipped":  16,
        "shipped_why":
                    "t comes from _sigma_params' module-level _SIGMA_T dict, a "
                    "thousand lines above every [N] marker, so neither #319's "
                    "body slice nor its widened scope slice can reach it and "
                    "there is no PARAMETERS row for it either (the three ports "
                    "each inline the ladder in their own sigma_params).  That "
                    "is why this row's RATE stays a literal while its MECHANISM "
                    "is measured -- the second recorded limit of the reading "
                    "axis, beside [4]'s run-time flag, and the answer to it is "
                    "#320's rather than #319's",
        "ladder":   {1: (1000, 15, 0.015625),
                     2: (6000,  1, 0.00050403)},
        "witness":  "7000/7000 trials had accept == (the recomputed challenge "
                    "collides), exactly.  The ALTERNATIVE -- 'the residual-norm "
                    "check is what catches it', which is what `exact` amounted "
                    "to -- was measured against the SAME test's z-tamper case, "
                    "where the norm check genuinely is the detector, and tracked "
                    "the outcome in 985/1000 and 5999/6000: high enough to look "
                    "like an answer, and not exact.  THE WRONG-MESSAGE CASE "
                    "WAS MEASURED TOO for TODO #330, and in two independent "
                    "instruments: a C probe over the shipped herradura.h at "
                    "t = 1 gave 28 accepts in 2000 trials, 28 collisions, and "
                    "THE SAME 28 -- exactly, no exceptions -- and this "
                    "measurer, in Python, gives witness 600/600 at t = 1 (6 "
                    "accepts) and 600/600 at t = 2 (0 accepts).  So the two "
                    "cases share ONE mechanism exactly, which is why pricing "
                    "only the w case understated the row by 2x, and why the "
                    "remedy is a WIDTH rather than a tolerance",
        "note":     "MEASURED at t = 1 and t = 2 over 7000 trials at n = 32, "
                    "with the honest proof verified first as an accept control "
                    "(7000/7000) and an exhausted rejection limit excluded from "
                    "the denominator rather than scored (#291, and #316's own "
                    "fix to this very test).  Acceptance 15/1000 against 15.6 "
                    "predicted and 1/6000 against 3.0, i.e. the 31x rate ratio "
                    "between the two rungs reproduces where a single rung could "
                    "not have distinguished the mechanism from a constant.  Two "
                    "rungs and not three because the space is comb(n, t)*2^t: at "
                    "t = 3 the predicted count over 6000 trials is 0.15, and "
                    "another 0/N is what this item exists NOT to produce.  The "
                    "t = 4 the test used to run these cases at needs 5.8e5 "
                    "trials per expected event, about 14 hours here, and the "
                    "t = 16 it runs them at now needs 6.6e29 -- which is why "
                    "the rate is argued from the ladder and the space rather "
                    "than counted at the shipped parameter, and why TODO #330 "
                    "moved the cases to a width where the space is the "
                    "argument instead of tightening a threshold",
    },
}


# ── Part 5/7: the DERIVED default -- a rejection owes a BASIS ─────────────
#
# TODO #322.  #319 made every rate an expression over constants read from
# source; #320 held each such formula to a MEASURED mechanism; #321 audited the
# fifteen curated rows that have no formula.  All three act on the TWENTY rows
# that are curated.  The census counts 181 sampled cells, 20 curated and 9
# declared to draw nothing that reaches a verdict, so 126 fall through to the
# DERIVED DEFAULT -- which `_SAMPLED_TESTS`' own header states as "the other
# ~40 per language are all-trials-must-succeed conjunctions of round-trips,
# where a fresh sample changes WHICH instance is tested and not the outcome".
#
# That sentence was asserted by nothing, and the category contributes nothing
# to the advertised budget, which is #304's recorded erosion shape a third
# time: #321 found it in `exact`, #304 in `follows`, and this is the same hole
# one level out, in the category with no row at all.
#
# THE DEFAULT IS RIGHT FOR A ROUND-TRIP, and this is not 126 prose reasons.
# #296's rule stands -- "there are 109, and a hundred prose reasons rot" -- and
# a disagreement in a round-trip is a real defect, never a flake.  What the
# default cannot cover is a REJECTION assertion: a test requiring a verifier to
# say NO to a deliberately bad input, because whether that input is DETECTABLE
# can itself turn on a fresh coin.  #310 found it in [53] (the forged witness
# was sometimes the true error, one run in 16), #316 in [17] (a (1/3)^8 branch
# that CRASHED), #320 in [22] (one term where the mechanism needs two).  Three
# items found the shape in a CURATED row; nothing had asked it of the rest.
#
# THE POLARITY IS OPPOSITE TO #316's, AND THAT IS THE NOTE TO CARRY.  #316
# records why its draw census slices FORWARD from the marker: an over-wide
# slice "hides a test that stopped drawing behind a neighbour that did not", so
# over-matching is the LENIENT direction there.  Here a match means "you owe a
# statement", so over-matching is CONSERVATIVE and under-matching is the
# vacuous one.  The first screen written for this item read only the verdict
# LINES -- #318's pinned region -- and MISSED [44] and [50], whose verdict
# lines name only counters (`ok_replay`, `rejected[...]`) while the rejection
# is asserted in the body.  Both are HCRED, both are among the largest
# candidate terms, and a narrower screen would have certified them while
# looking principled.  So the screen reads the whole body with comments
# stripped, and four kinds below exist to absorb what that over-matches.
#
# WHAT IT FOUND, and the two halves are a matched pair worth reading together.
# Two protocols in this repo assert "the verifier rejects a TAMPERED MESSAGE"
# in the same words, and the mechanisms are not the same:
#
#   HCRED   the per-round commitment hashes the STATEMENT, so a changed
#           message changes every recomputed commitment.  MEASURED: over 180
#           trials at n = 32 the challenge vector coincided 41 times -- 40 of
#           120 at rounds = 1 and 1 of 60 at rounds = 4, both within noise of
#           (1/3)^rounds -- and the tampered proof was REJECTED in all 41.
#           The challenge-rematch story is not merely unconfirmed, it is
#           REFUTED, with its own confounder occurring at its predicted rate.
#   ZKP-NL  the commitments do NOT bind the message; the verifier RECOMPUTES
#           the per-round challenge and compares (`h[0] % 3 != challenges[j]`).
#           MEASURED at rounds = 1: 193 of 600 accepted against a predicted
#           0.333, and the witness -- accept IFF every recomputed challenge
#           equals the stored one -- held 600/600 EXACTLY.
#
# So one is a 2^-256 hash collision and the other is (1/3)^rounds, and no
# document here said which was which.  That is #320's finding ("the number was
# right and the derivation was wrong") with the sign flipped: here the stated
# reason was the same for both and only one of them was true of each.
#
# AND THIS ITEM'S OWN MODEL WAS REFUTED TWICE, WHICH IS THE PART TO CARRY.
# HCRED's wrong_msg was modelled at (1/3)^4 = 1.2e-2 and measured at ZERO.
# HCRED-KKW's was then modelled at 1/comb(M, tau) = 1/6, revised to
# 1/(comb(M, tau) * N_par^tau) = 1/96 -- 105x the whole job budget -- and a
# FOUR-PORT TEST CHANGE was written and BUILT against that number before the
# measurement refuted it too: the opened subset coincides at exactly its
# predicted rate, the verifier still rejects, and it never even reaches the
# pbar comparison, because `rho` is drawn from a hash over `stmt` and the
# residual check sum(rho.(zo - targets)) == sum(u) fails first at 1 - 1/q per
# opened emulation.  THREE bindings, not one; the true rate is ~2.4e-12 and the
# four-port change was REVERTED.  A test edit justified by a wrong rate is cost
# with no benefit, and #312's rule -- a refactor must not settle a question it
# happens to expose -- applies to a fix as much as to a refactor.
#
# Two things follow.  A MODEL OF A MECHANISM IS NOT A MEASUREMENT OF IT, which
# is #320's whole premise turned on the author rather than on the code: both
# wrong models were reached by reading the verifier carefully, and both looked
# finished.  And both errors were CONSERVATIVE, like #319's 10x, #320's 3x and
# #321's 10^134 -- so the direction this axis keeps failing in is the one where
# nothing red ever happens, which is why every number here owes a witness.
#
# THE SCHEMA.  A basis, a WIDTH where the claim rests on one, and prose.  The
# kinds are a closed set and fall into three groups:
#
#   RATED       the detection turns on a fresh coin, so the cell owes a
#               _SAMPLED_TESTS row WITH a rate.  `challenge-rematch`,
#               `random-forgery`, `sampled-accept-control`.
#   BY-WIDTH    acceptance needs a collision or a forgery, so the term exists
#               and is below anything the budget can represent.  Owes `bits`,
#               a NUMBER, so the claim is falsifiable: narrow the tag and the
#               row is wrong.  `hash-binding`, `mac`.
#   EXACT       no coin at all.  `equation` (the verification identity fails
#               algebraically), `structural` (a format, size, state or pinned
#               vector), `reference-count` (the counter counts MISMATCHES
#               against a reference -- a round-trip wearing a rejection's
#               name, which is what the screen over-matches on), and
#               `not-a-verdict` (the flag is a declaration, a header string,
#               or slice bleed past the last marker).
#
# `not-a-verdict` earns its place rather than hiding a miss: python [43] is a
# BENCHMARK whose slice runs to end of file, so it absorbs `main()` and the
# harness epilogue -- which is also why #318 pins that cell's "verdict" as the
# epilogue's own `*** FAILED:` line.  Recorded, because a screen artefact
# nobody wrote down is one the next reader has to rediscover.
# ONE CELL, ONE BASIS, AND IT IS THE WEAKEST OF THE CELL'S ASSERTIONS.  Most of
# these tests assert several rejections at once -- [30] rejects a tampered
# message AND a reused one-time key, [44] rejects a tamper, a corrupted
# syndrome, a wrong key and a split witness -- and a verdict is their
# CONJUNCTION, so the cell's false-failure rate is dominated by whichever
# assertion is least certain.  The basis therefore names that one and the prose
# says what the others rest on, which keeps the budget conservative: taking the
# strongest assertion would let a rate-bearing axis hide behind an exact
# neighbour, and that is #295's lenient direction inside a single row.
_REJECTION_RATED = ("challenge-rematch", "random-forgery",
                    "sampled-accept-control")
_REJECTION_BY_WIDTH = ("hash-binding", "mac")
_REJECTION_EXACT_KINDS = ("equation", "structural", "reference-count",
                          "not-a-verdict")
_REJECTION_KINDS = _REJECTION_RATED + _REJECTION_BY_WIDTH + _REJECTION_EXACT_KINDS

# How the screen recognises "this test asserts that something must be
# REFUSED".  Read over the whole body with comments stripped, for the polarity
# reason above.  Deliberately WIDE: `_bad`/`bad_` catches the mismatch
# counters of [47] and [48], which are round-trips, and they are classified
# `reference-count` rather than excluded by a cleverer pattern -- a screen
# tuned until it flags only what its author expected is a screen that agrees
# with its author.
_REJECTION_PATTERN = re.compile(
    r'reject|refus|forg|tamper|_bad\b|\bbad_|invalid|corrupt|replay|reuse|'
    r'mismatch|must_fail|split', re.I)

_REJECTION_BASES = {
    # ── RATED: a fresh coin decides whether the bad input is detectable ──
    ("java", 36): {"basis": "sampled-accept-control", "bits": None,
        "why": "Java's [36] is the shared [54] row in that port's own "
               "numbering (TODO #333), so it has the same weakest assertion: "
               "the ACCEPT-control, where a fresh key and a fresh ciphertext "
               "must agree and a decoder failure breaks it.  The rejection "
               "half is exact at 2^-256, and the row does NOT assert that the "
               "uniform syndrome fails to DECODE -- about 2^-11193, PRINTED "
               "rather than scored, since the key-differs check holds either "
               "way (#291)"},
    ("shared", 54): {"basis": "sampled-accept-control", "bits": None,
        "why": "the SAMPLED half of [54] is its accept-control: a fresh key "
               "and a fresh ciphertext must decapsulate to the encapsulated "
               "secret, which a decoder failure breaks.  The REJECTION half "
               "is exact at 2^-256 -- a uniform syndrome's implicit-rejection "
               "key collides with the success-path key only if two "
               "differently-domain-separated HFSCX-256 calls agree -- and the "
               "basis names the weaker one.  The row also does NOT assert "
               "that the uniform syndrome fails to decode: that is about "
               "2^-11193 and is PRINTED rather than scored, since the "
               "key-differs check holds either way (#291)"},
    ("java", 19): {"basis": "challenge-rematch", "bits": None,
        "why": "ZkpNl.verify RECOMPUTES the per-round Fiat-Shamir trit and "
               "compares it to the stored one, so a tampered message is "
               "undetected exactly when all `rounds` of them coincide.  "
               "Nothing else in that verifier reads the message, so the rate "
               "has ONE term -- unlike [22], where the poke also has to stay "
               "unopened (#320)"},
    ("java", 28): {"basis": "challenge-rematch", "bits": None,
        "why": "the ZKBoo half of Java's ZKP-NL pair, `rejects_msg`, on the "
               "same verifier and the same recomputed-challenge comparison as "
               "[19].  `rejects_stmt` is separate and exact: changing y breaks "
               "the output binding, which no challenge coincidence repairs"},
    ("java", 29): {"basis": "challenge-rematch", "bits": None,
        "why": "the ZKB++ half, `rejects_msg`.  #304 measured that ZKB++ "
               "rebinds out_e to the public y so a wrong WITNESS dies every "
               "round -- true, and about the witness; the MESSAGE reaches this "
               "verifier only through the challenge seed, so this axis carries "
               "the same (1/3)^rounds the ZKBoo one does"},
    ("java", 30): {"basis": "challenge-rematch", "bits": None,
        "why": "the Ring-LWR Sigma signer, and the JAVA COUNTERPART of the "
               "shared [21] row TODO #321 found was not `exact` at all: "
               "rnl_sigma_verify recomputes the challenge over the tampered w "
               "and on a collision the residual-norm check sees one "
               "coefficient inside its slack and accepts"},
    ("shared", 50): {"basis": "challenge-rematch", "bits": None,
        "why": "HCRED-KKW's `wrong_msg`, and the row this item got WRONG TWICE "
               "before measuring it.  THREE Fiat-Shamir-derived values have to "
               "re-match, not one: the opened SUBSET, the rho PROJECTION -- "
               "hashed over `stmt`, so the residual check fails at 1 - 1/q per "
               "opened emulation -- and the pbar challenge",
        "evidence": "kkw-statement-projection"},
    ("java", 31): {"basis": "challenge-rematch", "bits": None,
        "why": "Java's HCRED-KKW, `rejects_msg`, at the same (nPar, mEmul, tau) "
               "= (4, 4, 2) and the same three bindings, so it carries the same "
               "rate in a job that is required just as the other three are",
        "evidence": "kkw-statement-projection"},
    ("shared", 8): {"basis": "random-forgery", "bits": None,
        "why": "HPKS Schnorr Eve resistance: the forgery attempts are DRAWN, "
               "so `wins == 0` is a statement about a fresh sample -- a random "
               "(R, s) satisfying the verification identity is a 2^-n event "
               "and the test asserts none of them occurs"},
    ("java", 27): {"basis": "sampled-accept-control", "bits": None,
        "why": "the ACCEPT-CONTROL is the sampled half, exactly as in the "
               "shared [49] row: a genuine UNIFORM m_blind draw must pass a "
               "guard that rejects a coefficient range below q/4, which n "
               "uniform draws fall inside with about n*(1/4)^(n-1)"},

    # ── BY-WIDTH: the term exists and is a collision or a forgery ────────
    ("java", 3): {"basis": "hash-binding", "bits": 256,
        "why": "hpksVerify recomputes e = fscx_revolve(R, msg, i) from the "
               "message it is given, so accepting msg ^ 1 under a signature "
               "over msg needs the challenge function to collide on two FIXED "
               "messages at a freshly drawn R"},
    ("java", 10): {"basis": "hash-binding", "bits": 256,
        "why": "the NL-FSCX challenge variant of [3], same shape: the tampered "
               "message is rejected unless nl_fscx_revolve_v1 collides on the "
               "two messages at the drawn R"},
    ("java", 16): {"basis": "hash-binding", "bits": 256,
        "why": "WOTS verification walks the hash chains to the public key, so "
               "a tampered message is accepted only if it hashes to the same "
               "chain lengths -- a collision in the message digest"},
    ("java", 17): {"basis": "hash-binding", "bits": 256,
        "why": "XMSS is WOTS under an authentication path, so [16]'s argument "
               "carries and the path adds a second collision requirement "
               "rather than removing the first"},
    ("java", 18): {"basis": "hash-binding", "bits": 256,
        "why": "HCRED's per-round commitment hashes the STATEMENT, so a "
               "tampered message changes every commitment the verifier "
               "recomputes.  The challenge-rematch story a reader reaches for "
               "first is REFUTED by measurement -- see the evidence.  AND THIS "
               "BASIS NAMED THE WRONG ASSERTION UNTIL TODO #335: the cell's "
               "weakest axis was not its rejection at 2^-256 but its "
               "ACCEPT-control, because hcred_verify refused an HONEST proof "
               "unless 1 <= W <= W_MAX and no prover screened for it -- 6.5e-5 "
               "at n=256 and 2.6e-4 at the n=32 the shared row runs.  userKeygen "
               "screens now, so the accept-control is exact and the basis is "
               "once again the weakest thing here",
        "evidence": "hcred-statement-binding"},
    ("shared", 44): {"basis": "hash-binding", "bits": 256,
        "why": "the C/Go/Python HCRED row, `ok_replay`, identical in mechanism "
               "to Java's [18]: _hcred_commit takes stmt, so the binding is a "
               "commitment hash and not the Fiat-Shamir challenge.  THE ROW "
               "WENT RED IN CI BEFORE ANYONE CHECKED WHICH OF ITS AXES WAS "
               "WEAKEST (TODO #335): `verify=0/1` at n=32, an honest proof "
               "refused by its own verifier because W fell outside the "
               "4-sigma weight window the verifier enforces and no prover "
               "screened -- 2.6e-4, i.e. 2.6x the whole numbered-test budget, "
               "from the ACCEPT-control of a cell whose basis named its "
               "rejection.  #322's own warning, that taking the strongest "
               "assertion lets a rate-bearing axis hide behind an exact "
               "neighbour, with this row as the instance.  hcred_user_keygen "
               "screens in all four ports now, so the rate is ZERO rather than "
               "smaller and the stated basis is correct again",
        "evidence": "hcred-statement-binding"},
    ("shared", 25): {"basis": "hash-binding", "bits": 256,
        "why": "the accumulator's Merkle proof: a tampered sibling is accepted "
               "only if the recomputed root still equals the pinned one, which "
               "is a collision in the node hash"},
    ("shared", 28): {"basis": "mac", "bits": 128,
        "why": "HSKE-NL-AEAD's three tamper axes are TAG checks -- a flipped "
               "ciphertext, tag or nonce is accepted only on a tag forgery, "
               "which is the authenticator's width and not a protocol coin"},
    ("java", 25): {"basis": "mac", "bits": 128,
        "why": "the duplex AEAD's v2/v3 ct and ad rejection, on the same tag "
               "comparison: Duplex.v2Decrypt returns null unless the "
               "recomputed tag matches"},
    ("java", 33): {"basis": "mac", "bits": 128,
        "why": "Java's HSKE-NL-AEAD row, the same three axes as the shared "
               "[28] one and the same tag comparison"},
    ("shared", 48): {"basis": "mac", "bits": 128,
        "why": "among the v3 consumers' assertions, the only rejection is that "
               "the v3 duplex refuses a FLIPPED AD, which is [28]'s tag check "
               "again; everything else in that test is a round-trip"},
    ("shared", 30): {"basis": "hash-binding", "bits": 256,
        "why": "the WOTS/XMSS pair in C/Go/Python: `tamper_reject` is [16]'s "
               "chain argument, and `reuse_reject` is a STATE check on the "
               "one-time index, which is structural rather than either"},

    # ── EXACT: no coin decides detection ─────────────────────────────────
    ("java", 23): {"basis": "equation", "bits": None,
        "why": "the tamper is `s.xor(ONE)` -- the signature SCALAR, not the "
               "message -- so the threshold Schnorr identity g^s . C^e == R "
               "fails as arithmetic, with nothing drawn between the poke and "
               "the comparison"},
    ("shared", 31): {"basis": "equation", "bits": None,
        "why": "the C/Go/Python threshold Schnorr row pokes the same scalar "
               "and fails the same identity; the fresh sample chooses WHICH "
               "key the identity is checked at, not whether it holds"},
    ("java", 20): {"basis": "equation", "bits": None,
        "why": "aPAKE's wrong-login branch derives a different session key by "
               "construction, so `wrongSk == null` follows from the key "
               "schedule rather than from a comparison that could go either "
               "way on a draw"},
    ("java", 24): {"basis": "equation", "bits": None,
        "why": "`keyBoundarySeparated` asserts two fpe encryptions under "
               "DIFFERENT key/context splits DIFFER -- TODO #242's regression "
               "guard.  Equality would need the separated derivation to "
               "collide, which is the defect that guard exists to catch and "
               "not a tolerance"},
    ("java", 32): {"basis": "structural", "bits": None,
        "why": "the QC-MDPC weak-key screen runs on PINNED supports, and the "
               "only sampled part is that what keygen PRODUCES the screen "
               "ACCEPTS -- which keygen guarantees by retrying until it does, "
               "so the assertion cannot fail on a draw"},
    ("shared", 51): {"basis": "structural", "bits": None,
        "why": "the C/Go/Python weak-key screen, same pinned supports and the "
               "same keygen-output accept-control; the supports are literals "
               "chosen to sit on the threshold, so nothing here is sampled"},
    ("c", 24): {"basis": "not-a-verdict", "bits": None,
        "why": "the flag is the DECLARATION `int ok_valid = 0, ok_reject = 0` "
               "in C's tweakable wide-block round-trip; `ok_reject` is never "
               "incremented in this test and its verdict is `ok == N`, a "
               "round-trip count"},
    ("python", 43): {"basis": "not-a-verdict", "bits": None,
        "why": "a BENCHMARK, and the last marker in the file, so its slice "
               "runs to end of file and absorbs main() -- which is also why "
               "#318 pins this cell's verdict as the harness epilogue's own "
               "*** FAILED: line rather than a test's"},
    ("c", 47): {"basis": "reference-count", "bits": None,
        "why": "bad_ref / bad_inv / bad_rt COUNT MISMATCHES against a per-row "
               "chi reference and its inverse -- a round-trip wearing a "
               "rejection's name, which is what a deliberately wide screen "
               "over-matches on"},
    ("python", 47): {"basis": "reference-count", "bits": None,
        "why": "Python's copy of the same v3 primitive check, with the "
               "additional suite cross-check; every counter is a reference "
               "mismatch, so a nonzero one is a defect and never a draw"},
}


# The measurements behind the bases that rest on one -- and a rate-bearing row
# may have one too, because "what the rate is" and "which mechanism it is the
# rate OF" are different questions: [50] and [31] carry both.  A rate-bearing
# row's FORMULA still belongs to _RATE_MECHANISMS, which validates it against
# the expression; what lives here is the mechanism a reader would otherwise
# assume.  Same discipline as
# TODO #320's and #321's: an EXACT per-trial witness, a ladder that reaches the
# branch the witness has to be checked on, and the token MEASURED -- because a
# recorded rate is only as good as the mechanism it was computed over, and here
# the mechanism is which of two verifiers the reader is looking at.
#
# `refutation` is a THIRD kind, beside #321's `margin` and `rate`, and it is
# not either of them: its ladder counts the CONFOUNDER rather than the event,
# because the event is what must never happen while the confounder must.  A
# rate record demands events > 0 somewhere ("the 0/N this item exists not to
# produce"); a refutation demands CONFOUNDERS > 0 and events == 0, which is the
# same rule pointed at the object that carries the information.
_REJECTION_MEASUREMENTS = {
    "hcred-statement-binding": {
        "kind": "refutation",
        "rows": [("shared", 44), ("java", 18)],
        "quantity": "whether HCRED's verifier accepts a proof presented under a "
                    "TAMPERED message, against the confounder a reader reaches "
                    "for first -- that the per-round Fiat-Shamir challenge "
                    "vector re-derives to the same trits",
        "bound": "zero up to a 256-bit collision: _hcred_commit hashes `stmt`, "
                 "which is _hcred_stmt_hash(m, C, seed_H, y, n, MSG), so every "
                 "commitment the verifier recomputes changes with the message "
                 "and no challenge coincidence can repair one",
        "var": "rounds", "shipped": 4,
        "confounder": "the re-derived challenge vector equals the stored one",
        "ladder": {1: (120, 0, 40), 4: (60, 0, 1)},
        "witness": "0 acceptances in 180 trials at n = 32, while the confounder "
                   "occurred 41 times -- 40 of 120 at rounds = 1 and 1 of 60 at "
                   "rounds = 4, both inside noise of (1/3)^rounds -- and the "
                   "tampered proof was REJECTED in every one of the 41.  The "
                   "challenge-rematch mechanism is REFUTED, not merely "
                   "unconfirmed",
        "note": "MEASURED at n = 32 by spec/measure_sampled_rates.py over 180 "
                "trials.  The rungs reduce `rounds` BELOW the 4 that ships "
                "(#320's rule 3) for one reason: at rounds = 4 the confounder "
                "appears about once in 81, so a ladder that stayed at the "
                "shipped count would have observed it once or not at all and "
                "the refutation would rest on a single trial",
    },
    "kkw-statement-projection": {
        "kind": "refutation",
        "rows": [("shared", 50), ("java", 31)],
        "quantity": "whether HCRED-KKW's verifier accepts a proof presented "
                    "under a TAMPERED message, against the confounder TWO "
                    "successive models of this row predicted would make it "
                    "survive -- that the opened SUBSET re-derives to the same "
                    "emulations",
        "bound": "the conjunction of THREE bindings, which is why both models "
                 "were wrong: 1/comb(M, tau) for the opened subset, then 1/q "
                 "per opened emulation for the rho PROJECTION -- rho is drawn "
                 "from a hash over `stmt`, so the residual check "
                 "sum(rho.(zo - targets)) == sum(u) fails at 1 - 1/65537 -- and "
                 "only then 1/N_par^tau for the pbar challenge",
        "var": "tau", "shipped": 2,
        "confounder": "the opened SUBSET re-derives to the same emulations, "
                      "which is challenge 1 coinciding",
        "ladder": {1: (80, 0, 24), 2: (24, 0, 3)},
        "witness": "0 acceptances in 104 trials at n = 32, while the confounder "
                   "occurred 27 times -- 24 of 80 at tau = 1 against a "
                   "predicted 20.0 and 3 of 24 at the shipped tau = 2 against "
                   "4.0 -- and the tampered proof was REJECTED every time.  The "
                   "verifier does not even REACH the pbar comparison on those "
                   "27: instrumenting its own Fiat-Shamir helper shows the c2 "
                   "draw is never made, because the rho residual has already "
                   "failed, which is what puts a number on the third binding",
        "note": "MEASURED at tau = 1 and at the shipped tau = 2 over 104 trials "
                "by spec/measure_sampled_rates.py.  This record exists because "
                "the item's own arithmetic was wrong TWICE in the conservative "
                "direction -- 1/6, then 1/96, against a true ~2.4e-12 -- and a "
                "four-port test change had been written and BUILT against the "
                "second figure before the measurement refuted it.  The reduced "
                "rung raises the confounder from about one trial in six to one "
                "in four; the shipped rung is the claim, and a ladder of "
                "reduced rungs alone would refute the alternative only at "
                "parameters nobody runs",
    },
}
_REFUTATION_FIELDS = ("kind", "rows", "quantity", "bound", "var", "shipped",
                      "confounder", "ladder", "witness", "note")


def _rejection_candidates():
    """The cells this axis is responsible for, DERIVED from source.

    A cell qualifies when it (a) draws fresh entropy, (b) has a verdict line at
    all, and (c) asserts somewhere in its body that something must be REFUSED.
    Cells already carrying a curated `_SAMPLED_TESTS` row, or declared to draw
    nothing that reaches a verdict, are out of scope: they have a statement.

    C/Go/Python collapse to one `shared` key when ALL THREE flag the number,
    which is `_SAMPLED_TESTS`' own convention; a number flagged in one or two of
    them stays per-language, because that asymmetry is itself worth a row.
    """
    flagged = {}
    for lang in NUMBERED_TEST_FILES:
        bodies = _numbered_test_bodies(lang)
        prefixes = _VERDICT_COMMENT_PREFIXES[lang]
        for num in _TEST_DRAWS[lang]:
            body = bodies.get(num, "")
            code = "\n".join(
                t for t in (l.strip() for l in body.split("\n"))
                if t and not t.startswith(prefixes))
            if not _REJECTION_PATTERN.search(code):
                continue
            if _verdict_fingerprint(lang, body) == "none":
                continue        # a benchmark decides nothing to be wrong about
            flagged.setdefault(num, set()).add(lang)

    shared = set(SHARED_NUMBERING_LANGS)
    out = set()
    for num, langs in flagged.items():
        if shared <= langs:
            out.add(("shared", num))
            langs = langs - shared
        out.update((l, num) for l in sorted(langs))

    def covered(key):
        """Already carries a statement somewhere ELSE.

        A cell this axis classifies stays in scope even once it acquires the
        `_SAMPLED_TESTS` row that a rate-bearing basis REQUIRES -- otherwise
        satisfying the requirement would remove the cell from the screen and
        orphan its own entry, which the first draft of this check did.
        """
        if key in _REJECTION_BASES:
            return False
        if key in _SAMPLED_TESTS or key in _SAMPLED_TEST_CONSTANT:
            return True
        lang, num = key
        return lang in shared and (("shared", num) in _SAMPLED_TESTS
                                   or ("shared", num) in _SAMPLED_TEST_CONSTANT)

    return {k for k in out if not covered(k)}


def check_rejection_bases(errors):
    """TODO #322: the DERIVED default of `_SAMPLED_TESTS`.

    Every uncurated sampled cell that asserts a REJECTION states the BASIS on
    which that rejection holds, from a closed set of kinds -- because the
    default ("a fresh sample changes WHICH instance is tested and not the
    outcome") is true of a round-trip and is exactly what a rejection can fail.

    Returns (cells classified, rated cells, measurements)."""
    candidates = _rejection_candidates()
    for key in sorted(candidates, key=str):
        if key not in _REJECTION_BASES:
            errors.append(
                f"rejection-bases: {list(key)} draws fresh entropy, decides a "
                f"verdict and asserts that something must be REFUSED, with no "
                f"_REJECTION_BASES entry.  It is therefore resting on the "
                f"DERIVED DEFAULT, which is a statement about ROUND-TRIPS -- "
                f"say on what basis the rejection holds, and give it a "
                f"_SAMPLED_TESTS row if a fresh coin decides detection"
            )
    backed = {}
    rated = set()
    for key, ent in sorted(_REJECTION_BASES.items(), key=str):
        where = f"_REJECTION_BASES{list(key)}"
        if key not in candidates:
            errors.append(
                f"rejection-bases: {where} names a cell the screen no longer "
                f"reaches -- it stopped drawing, stopped asserting a "
                f"rejection, lost its verdict, or ACQUIRED a curated "
                f"_SAMPLED_TESTS row.  Delete the entry: a basis and a curated "
                f"verdict are two statements about one cell"
            )
            continue
        extra = set(ent) - {"basis", "bits", "why", "evidence"}
        if extra or not {"basis", "bits", "why"} <= set(ent):
            errors.append(f"rejection-bases: {where} must carry basis/bits/why "
                          f"and may carry evidence (got {sorted(ent)})")
            continue
        basis = ent["basis"]
        if basis not in _REJECTION_KINDS:
            errors.append(f"rejection-bases: {where} has unknown basis "
                          f"{basis!r} -- the kinds are a CLOSED set, so a new "
                          f"one is a claim to argue rather than a string")
            continue
        if len(ent["why"]) < 60:
            errors.append(f"rejection-bases: {where} needs a substantive reason")

        row = _SAMPLED_TESTS.get(key)
        if basis in _REJECTION_RATED:
            rated.add(key)
            if row is None:
                errors.append(
                    f"rejection-bases: {where} is {basis!r}, which means a "
                    f"FRESH COIN decides whether the bad input is detectable, "
                    f"and there is no _SAMPLED_TESTS row -- so the term is "
                    f"missing from the budget entirely"
                )
            elif row[1] is None:
                errors.append(
                    f"rejection-bases: {where} is {basis!r} and its "
                    f"_SAMPLED_TESTS row is `exact` with no rate.  A coin that "
                    f"decides detection is the definition of not exact "
                    f"(TODO #321's [21], one category out)"
                )
            if ent["bits"] is not None:
                errors.append(
                    f"rejection-bases: {where} is {basis!r} and states "
                    f"{ent['bits']} bits -- a width is how a BY-WIDTH basis is "
                    f"made falsifiable, and quoting one beside a real rate "
                    f"reads as though the rate were the collision"
                )
        else:
            if row is not None:
                errors.append(
                    f"rejection-bases: {where} is {basis!r} -- not "
                    f"rate-bearing -- and the cell ALSO carries a "
                    f"_SAMPLED_TESTS row.  One of the two is wrong about "
                    f"whether a coin decides detection"
                )
            if basis in _REJECTION_BY_WIDTH:
                bits = ent["bits"]
                if not isinstance(bits, int) or bits < 128:
                    errors.append(
                        f"rejection-bases: {where} is {basis!r} and must state "
                        f"the WIDTH acceptance would have to break, as an int "
                        f">= 128.  The number is what makes the claim "
                        f"falsifiable: narrow the tag and the row is wrong"
                    )
            elif ent["bits"] is not None:
                errors.append(
                    f"rejection-bases: {where} is {basis!r} and states a width "
                    f"-- an exact basis rests on no collision, so a width here "
                    f"is either the wrong basis or the wrong field"
                )

        ev = ent.get("evidence")
        if ev is not None:
            if ev not in _REJECTION_MEASUREMENTS:
                errors.append(f"rejection-bases: {where} names evidence "
                              f"{ev!r}, which does not exist")
            else:
                backed.setdefault(ev, set()).add(key)

    # ── the measurements ─────────────────────────────────────────────────
    try:
        with open(_RATE_MECHANISM_INSTRUMENT, encoding="utf-8") as f:
            instrument = f.read()
    except OSError:
        instrument = None       # already reported by check_rate_mechanisms

    for name, m in sorted(_REJECTION_MEASUREMENTS.items()):
        kind = m.get("kind")
        if kind != "refutation":
            errors.append(
                f"rejection-bases: {name!r} has kind {kind!r}.  A RATE-bearing "
                f"row's mechanism belongs in _RATE_MECHANISMS, which holds it "
                f"to the formula it is the mechanism OF; this table is for the "
                f"third shape only (TODO #320, #321, #322)"
            )
            continue
        want = set(_REFUTATION_FIELDS)
        if set(m) != want:
            errors.append(f"rejection-bases: {name!r} ({kind}) carries "
                          f"{sorted(set(m) ^ want)} as a field mismatch")
            continue
        if instrument is not None and f'"{name}":' not in instrument:
            errors.append(
                f"rejection-bases: {name!r} has no measurer in "
                f"spec/measure_sampled_rates.py -- a recorded measurement "
                f"whose recipe cannot be re-run is a claim, not a record"
            )
        if "MEASURED" not in m["note"]:
            errors.append(f"rejection-bases: {name!r} does not carry the token "
                          f"MEASURED (#304's rule)")
        for field in ("quantity", "bound", "witness", "note"):
            if len(m[field]) < 60:
                errors.append(f"rejection-bases: {name!r} needs a substantive "
                              f"{field!r}")
        if not m["ladder"]:
            errors.append(f"rejection-bases: {name!r} records no measurement")
            continue
        for key in (tuple(k) for k in m["rows"]):
            if kind == "refutation":
                ent = _REJECTION_BASES.get(key)
                if ent is None or ent.get("evidence") != name:
                    errors.append(
                        f"rejection-bases: {name!r} backs {list(key)}, which "
                        f"does not name it as its evidence"
                    )
            elif key not in _SAMPLED_TESTS:
                errors.append(f"rejection-bases: {name!r} backs {list(key)}, "
                              f"which is not a _SAMPLED_TESTS row")

        events_seen = confounders_seen = 0
        for val in sorted(m["ladder"]):
            rung = m["ladder"][val]
            if not (isinstance(rung, tuple) and len(rung) == 3):
                errors.append(f"rejection-bases: {name!r} rung {val} is not a "
                              f"3-tuple")
                continue
            # A refutation's shipped rung is the CLAIM -- #321's MARGIN rule,
            # not its rate rule: the statement is about the verifier the suite
            # actually runs, and the LOWER rungs exist only to make the
            # confounder frequent enough to be put to it more than once.
            if val > m["shipped"]:
                errors.append(
                    f"rejection-bases: {name!r} measures at {m['var']} = {val}, "
                    f"ABOVE the {m['shipped']} the test ships -- a rung above "
                    f"the shipped value measures a verifier nobody runs"
                )
            trials, events, confounders = rung
            if trials <= 0 or not 0 <= confounders <= trials:
                errors.append(f"rejection-bases: {name!r} rung {val} has "
                              f"{confounders} confounder(s) of {trials}")
                continue
            if events:
                errors.append(
                    f"rejection-bases: {name!r} at {m['var']}={val} records "
                    f"{events} acceptance(s) -- a refutation asserts the event "
                    f"NEVER happens, so this contradicts its own bound"
                )
            confounders_seen += confounders
            events_seen += events
        if m["shipped"] not in m["ladder"]:
            errors.append(
                f"rejection-bases: {name!r}'s ladder does not include the "
                f"shipped {m['var']} = {m['shipped']} -- the refutation has to "
                f"hold where the test RUNS, and a ladder of reduced rungs alone "
                f"refutes the alternative only at parameters nobody deploys"
            )
        if not confounders_seen:
            errors.append(
                f"rejection-bases: {name!r} never observed its CONFOUNDER "
                f"({m['confounder']!r}), so the alternative it claims to refute "
                f"was never actually put to the verifier -- #296's rule that a "
                f"branch a random stream never enters is not covered either"
            )
        if len(m["confounder"]) < 30:
            errors.append(f"rejection-bases: {name!r} needs to say what its "
                          f"confounder IS")

    for name in sorted(_REJECTION_MEASUREMENTS):
        m = _REJECTION_MEASUREMENTS[name]
        if m.get("kind") == "refutation" and name not in backed:
            errors.append(
                f"rejection-bases: {name!r} is named as evidence by no basis "
                f"-- a measurement whose subject has gone stays only as "
                f"something to re-derive later"
            )
    return len(_REJECTION_BASES), len(rated), len(_REJECTION_MEASUREMENTS)


# ── Part 6/7: the VERDICT of each numbered test, pinned ──────────────────
#
# TODO #318, and it closes a hole in TODO #316's own table.  That census
# catches a test which starts DRAWING fresh entropy; nothing caught a test
# which starts DECIDING on a threshold.  `_TEST_DRAWS` records which tests
# draw and `_SAMPLED_TESTS` is curated, so adding `if mean > 0.9:` to any of
# the ~160 already-drawing tests that carry no curated row left every check
# green.  That is the standing shape of this whole lineage -- #300 censused
# the gates and #310 asked the same of the numbered tests; #305 measured what
# the randomness pinning reached and #306 asked which code the census READS --
# arriving this time at a table I had just written.
#
# WHY A FINGERPRINT RATHER THAN A THRESHOLD DETECTOR.  A syntactic detector
# was the obvious design and is the weaker one, for two reasons found by
# trying it.  It cannot see the cases that matter most: [17]'s defect was a
# (1/3)^rounds soundness term with no numeric literal anywhere in its verdict,
# and so was [45]'s (2/3)^32 and [22]'s (1/3)^16.  And it needs to know every
# spelling of "this line decides the verdict", which is the enumeration this
# item's own detector got wrong three times running (Go's `verdict := "PASS"`
# and `status := "FAIL"`, C's [19] `puts("  FAIL: ..."); pass = 0`) -- #306's
# sixth-spelling hazard, met yet again.  Pinning the verdict REGION instead
# needs no threshold theory: any change to how a test decides fails until
# someone looks, which is what the hole actually needs.
#
# WHAT IS FINGERPRINTED is every line of a numbered test's body that carries
# a PASS or FAIL marker, comments excluded, whitespace collapsed.  So an edit
# to a test's WORK does not fire and an edit to its VERDICT does.  "none"
# means the test has no verdict line at all -- the 36 benchmark rows [32]-[43]
# and Go's [52], whose verdict lives in a helper -- and pinning that is not
# redundant: a benchmark that GROWS a verdict fires here, which is the
# direction TODO #300 found `qcmdpc_bgf_failure_rate.py` in (a gate that could
# not fail, discovered and run every CI run for eleven items).
#
# WHEN IT FIRES the question is not "is the fingerprint stale" but "does this
# test now decide on a fresh sample against a fixed threshold" -- if it does,
# it owes a `_SAMPLED_TESTS` row and the job budget owes its rate; if it does
# not, update the hash.  Re-generate with
# `python3 spec/check_language_parity.py --update-verdicts`, which prints the
# table and changes nothing on disk, so the update stays a decision.

_VERDICT_FINGERPRINTS = {
    # c
    ("c", 1): "158d13ae58", ("c", 2): "e3b7cb92dd",
    ("c", 3): "6a23f67290", ("c", 4): "44607f63e8",
    ("c", 5): "d5271af77f", ("c", 6): "d58cc9fa6c",
    ("c", 7): "158d13ae58", ("c", 8): "d58cc9fa6c",
    ("c", 9): "158d13ae58", ("c", 10): "c3f46734fb",
    ("c", 11): "71bbd22568", ("c", 12): "158d13ae58",
    ("c", 13): "158d13ae58", ("c", 14): "42037b4080",
    ("c", 15): "158d13ae58", ("c", 16): "158d13ae58",
    ("c", 17): "8965f8a720", ("c", 18): "c4ffefcf1b",
    ("c", 19): "c0593494da", ("c", 20): "83b3091774",
    ("c", 21): "de94a6f57c", ("c", 22): "e38188098b",
    ("c", 23): "6e34b5a147", ("c", 24): "6e34b5a147",
    ("c", 25): "49b930b7b4", ("c", 26): "5f0407f2d7",
    ("c", 27): "0bab6bce5d", ("c", 28): "cb3001321a",
    ("c", 29): "db48464b01", ("c", 30): "8d105328b3",
    ("c", 31): "4c02076d1c", ("c", 32): "none",
    ("c", 33): "none", ("c", 34): "none",
    ("c", 35): "none", ("c", 36): "none",
    ("c", 37): "none", ("c", 38): "none",
    ("c", 39): "none", ("c", 40): "none",
    ("c", 41): "none", ("c", 42): "none",
    ("c", 43): "none", ("c", 44): "f9063f18a0",
    ("c", 45): "f9063f18a0", ("c", 46): "9809bcaf57",
    ("c", 47): "3bed54b9b9", ("c", 48): "41b6f1ab99",
    ("c", 49): "60f6315c3a", ("c", 50): "9aa82856a7",
    ("c", 51): "1de8b648fe", ("c", 52): "71897dda69",
    ("c", 53): "d9072fd977",
    # TODO #332: the one benchmark row with a verdict, so NOT "none".
    ("c", 54): "c7edfe295a",
    # go
    ("go", 1): "10a9b5fc23", ("go", 2): "4ce634b424",
    ("go", 3): "f64d30ce54", ("go", 4): "48457c0dad",
    ("go", 5): "6df4ca9740", ("go", 6): "fe62e3e8a9",
    ("go", 7): "10a9b5fc23", ("go", 8): "408609c424",
    ("go", 9): "10a9b5fc23", ("go", 10): "f2cf35c1e8",
    ("go", 11): "73b0c3ad3c", ("go", 12): "10a9b5fc23",
    ("go", 13): "10a9b5fc23", ("go", 14): "4eddb7c1ac",
    ("go", 15): "10a9b5fc23", ("go", 16): "10a9b5fc23",
    ("go", 17): "10a9b5fc23", ("go", 18): "a72dd44d29",
    ("go", 19): "72cc1ae9d3", ("go", 20): "10a9b5fc23",
    ("go", 21): "b8cf3ad177", ("go", 22): "c8665d6d66",
    ("go", 23): "10a9b5fc23", ("go", 24): "10a9b5fc23",
    ("go", 25): "2ce2ccb1e5", ("go", 26): "5902fad95c",
    ("go", 27): "664c3c41ef", ("go", 28): "11cf42adb4",
    ("go", 29): "07513faf5c", ("go", 30): "001d15a01c",
    ("go", 31): "19ed03977c", ("go", 32): "none",
    ("go", 33): "none", ("go", 34): "none",
    ("go", 35): "none", ("go", 36): "none",
    ("go", 37): "none", ("go", 38): "none",
    ("go", 39): "none", ("go", 40): "none",
    ("go", 41): "none", ("go", 42): "none",
    ("go", 43): "none", ("go", 44): "48457c0dad",
    ("go", 45): "48457c0dad", ("go", 46): "48457c0dad",
    ("go", 47): "48457c0dad", ("go", 48): "48457c0dad",
    ("go", 49): "01eca4540f", ("go", 50): "785c8baf28",
    ("go", 51): "01eca4540f", ("go", 52): "none",
    ("go", 53): "6c1ccbfd37",
    ("go", 54): "58a2bcf2b3",   # TODO #332, re-pinned by #333
    # python
    ("python", 1): "db6ea492b7", ("python", 2): "8d558e9edf",
    ("python", 3): "4659f77207", ("python", 4): "e9725e3831",
    ("python", 5): "f679789172", ("python", 6): "a5647ecd30",
    ("python", 7): "db6ea492b7", ("python", 8): "7593ea3e82",
    ("python", 9): "db6ea492b7", ("python", 10): "4589e4143e",
    ("python", 11): "529a85a529", ("python", 12): "db6ea492b7",
    ("python", 13): "db6ea492b7", ("python", 14): "d0396ab8e6",
    ("python", 15): "db6ea492b7", ("python", 16): "db6ea492b7",
    ("python", 17): "c5f298f1d9", ("python", 18): "8be0a29714",
    ("python", 19): "63a190de9f", ("python", 20): "db6ea492b7",
    ("python", 21): "19da1c270a", ("python", 22): "d7c00b291a",
    ("python", 23): "db6ea492b7", ("python", 24): "db6ea492b7",
    ("python", 25): "e3a6e8b264", ("python", 26): "d7997e3a5d",
    ("python", 27): "16542ad09f", ("python", 28): "32e12d56dd",
    ("python", 29): "ab6e9487b2", ("python", 30): "54f1e989e6",
    ("python", 31): "fac40a296a", ("python", 32): "none",
    ("python", 33): "none", ("python", 34): "none",
    ("python", 35): "none", ("python", 36): "none",
    ("python", 37): "none", ("python", 38): "none",
    ("python", 39): "none", ("python", 40): "none",
    ("python", 41): "none", ("python", 42): "none",
    ("python", 43): "e241c66aee", ("python", 44): "8d82a4b834",
    ("python", 45): "661a73d2f2", ("python", 46): "a945af0b0a",
    ("python", 47): "a9d13b319a", ("python", 48): "9ee4fb2c2e",
    ("python", 49): "a9d13b319a", ("python", 50): "4f6ccba4ce",
    ("python", 51): "9ee4fb2c2e", ("python", 52): "dfe56e60f6",
    ("python", 53): "01a1a93925",
    ("python", 54): "255edfc9c2",   # TODO #332
    # java
    ("java", 1): "41d245afc5", ("java", 2): "2755b3f41c",
    ("java", 3): "1d765f8693", ("java", 4): "d21830647b",
    ("java", 5): "c42cc8d201", ("java", 6): "2bb016ca62",
    ("java", 7): "40932ed6ff", ("java", 8): "0cdd893ca8",
    ("java", 9): "58be83bc77", ("java", 10): "6080dac6bd",
    ("java", 11): "1a3c42a1a2", ("java", 12): "210c79f102",
    ("java", 13): "939693a3b4", ("java", 14): "9e690571c1",
    ("java", 15): "7992177842", ("java", 16): "d09b9190b4",
    ("java", 17): "2b5815300d", ("java", 18): "b149525596",
    ("java", 19): "e4fe0b33ab", ("java", 20): "55d3f2c8f3",
    ("java", 21): "5e8c9c92fb", ("java", 22): "b8f73f5742",
    ("java", 23): "cc0cbaee4b", ("java", 24): "1949de6ec3",
    ("java", 25): "d0414cd564", ("java", 26): "8f84a198e0",
    ("java", 27): "75ddafebf7", ("java", 28): "4ccb48453f",
    ("java", 29): "f64b2ee4ae", ("java", 30): "06382cbade",
    ("java", 31): "04dd85e615", ("java", 32): "b3eefc3e48",
    ("java", 33): "80c2726ac4", ("java", 34): "f548811911",
    ("java", 35): "ff38ed8c50",
    ("java", 36): "5ad1db3856",   # TODO #333 — Bench.java, not SelfTest.java
}


# Comment openers per language, so an edit to a comment mentioning FAIL does
# not read as a change to how the test decides.
_VERDICT_COMMENT_PREFIXES = {
    "c": ("//", "/*", "*"),
    "go": ("//",),
    "python": ("#",),
    "java": ("//", "/*", "*"),
}


def _verdict_lines(lang, body):
    """The PASS/FAIL-bearing lines of one numbered test, normalised."""
    out = []
    for line in body.split("\n"):
        stripped = line.strip()
        if not stripped or stripped.startswith(_VERDICT_COMMENT_PREFIXES[lang]):
            continue
        if "PASS" in stripped or "FAIL" in stripped:
            out.append(re.sub(r"\s+", " ", stripped))
    return out


def _verdict_fingerprint(lang, body):
    lines = _verdict_lines(lang, body)
    if not lines:
        return "none"
    return hashlib.sha256("\n".join(lines).encode("utf-8")).hexdigest()[:10]


def check_verdict_fingerprints(errors):
    """TODO #318: a test that changes HOW it decides must be re-examined."""
    seen = set()
    for lang in NUMBERED_TEST_FILES:
        for num, body in sorted(_numbered_test_bodies(lang).items()):
            key = (lang, num)
            seen.add(key)
            actual = _verdict_fingerprint(lang, body)
            expected = _VERDICT_FINGERPRINTS.get(key)
            if expected is None:
                errors.append(
                    f"verdicts: {lang} [{num}] has no _VERDICT_FINGERPRINTS "
                    f"entry (actual {actual}).  A new numbered test owes one: "
                    f"say whether it decides on a fresh sample against a fixed "
                    f"threshold, and give it a _SAMPLED_TESTS row if it does"
                )
            elif expected != actual:
                errors.append(
                    f"verdicts: {lang} [{num}] decides differently than when "
                    f"it was pinned ({expected} -> {actual}).  The question is "
                    f"NOT whether the hash is stale: does this test now decide "
                    f"from a FRESH SAMPLE against a FIXED THRESHOLD?  If so it "
                    f"owes a _SAMPLED_TESTS row and the job budget owes its "
                    f"rate (TODO #316); if not, re-generate with "
                    f"--update-verdicts"
                )
    for key in sorted(set(_VERDICT_FINGERPRINTS) - seen):
        errors.append(
            f"verdicts: _VERDICT_FINGERPRINTS names {key[0]} [{key[1]}], which "
            f"no longer exists — delete the row"
        )
    return len(seen)


def _numbered_test_bodies(lang):
    """{test number: source slice}, from each [N] marker to the next.

    Every one of these harnesses prints its own header as the FIRST statement
    of the test, so a slice starting at the marker holds the whole body.  A
    first version sliced [previous marker, next marker], which overlaps its
    neighbours in both directions and reported [52] -- a pinned-vector test
    that draws nothing -- as drawing, by bleed from [51]'s qcmdpc_keygen.
    Over-wide slicing is the LENIENT direction again (#295): it hides a test
    that stopped drawing behind a neighbour that did not.
    """
    _paths, marker = NUMBERED_TEST_FILES[lang]
    bodies = {}
    trailing = lang in _TRAILING_MARKER_LANGS
    for _path, text in _marker_sources(lang):
        marks = sorted((m.start(), int(m.group(1))) for m in marker.finditer(text))
        for i, (pos, num) in enumerate(marks):
            if trailing:
                start = marks[i - 1][0] if i else 0
                end = pos
            else:
                start = pos
                end = marks[i + 1][0] if i + 1 < len(marks) else len(text)
            bodies.setdefault(num, "")
            bodies[num] += text[start:end]
    return bodies


def _rate_var_count():
    """Per-port variable cells across every derived rate -- counted, not stated,
    on check E's rule that a tool-emitted number belongs to the tool."""
    return sum(len(by_lang) for _f, variables, _r in _SAMPLED_TEST_RATES.values()
               for by_lang in variables.values())


def _numbered_test_scopes(lang):
    """{test number: source slice}, WIDENED to [previous marker, next marker).

    A rate variable is a DECLARATION, and #316's slice cannot hold one in every
    port: C declares `static const int zkp_nl_rounds = 16`, `enum { STERN_TRIALS
    = 2 }` and `enum { RK = 3, RND = 12, FRND = 64 }` ABOVE the printf that
    carries its own [N] marker, where Go and Python declare theirs below.  So
    the boundary that is right for a DRAW -- which always happens after the
    header -- is wrong for the constant the draw is measured against.  #316 met
    the same asymmetry from the other side in Java's TRAILING marker.

    This is the overlapping slice #316 explicitly rejected, and it is safe HERE
    for a reason that does not transfer back: over-wide slicing is the lenient
    direction only when a match means "pass".  Every consumer requires EXACTLY
    ONE match, so bleed from a neighbour makes the count 2 and fails loudly,
    where in the draw census it made a silent test look busy.  Which is why it
    is opt-in PER VARIABLE rather than global: widening all of them turned
    [22]'s three readable variables into three ambiguous ones, in all three
    ports at once, because the neighbouring test spells its iteration count
    identically.
    """
    _paths, marker = NUMBERED_TEST_FILES[lang]
    scopes = {}
    for _path, text in _marker_sources(lang):
        marks = sorted((m.start(), int(m.group(1))) for m in marker.finditer(text))
        for i, (pos, num) in enumerate(marks):
            start = marks[i - 1][0] if i else 0
            end = marks[i + 1][0] if i + 1 < len(marks) else len(text)
            scopes.setdefault(num, "")
            scopes[num] += text[start:end]
    return scopes


def _rate_var_value(spec, lang, slices, ptables, errors, where):
    """One variable of a derived rate, read from source.  See the header above
    _SAMPLED_TEST_RATES for the three source kinds; every failure path here
    returns None and records an error, because a variable that cannot be read
    is the LENIENT direction -- a skipped term silently shrinks the rate."""
    kind, arg = spec[0], spec[1]
    if kind == "param":
        row = PARAMETERS.get(arg)
        if row is None:
            errors.append(f"sampled-rates: {where} reads PARAMETERS row {arg!r}, "
                          f"which does not exist")
            return None
        name = dict(zip(PARAM_LANGS, row[0])).get(lang)
        if name is None:
            errors.append(f"sampled-rates: {where} reads PARAMETERS row {arg!r} "
                          f"for {lang}, which that row records as absent there")
            return None
        table = ptables[lang]
        if name not in table:
            errors.append(f"sampled-rates: {where} — {lang}'s {name!r} is no "
                          f"longer a declaration in that language's suite source")
            return None
        v = _param_eval(table[name], table, lang, cls=_java_cls(lang, name))
        if v is None:
            errors.append(f"sampled-rates: {where} — {lang}'s {name!r} does not "
                          f"evaluate to a number")
        return v
    if kind in ("local", "count"):
        which = spec[2] if len(spec) > 2 else "body"
        if which not in ("body", "scope"):
            errors.append(f"sampled-rates: {where} — unknown slice {which!r}")
            return None
        hits = re.findall(arg, slices[which])
        # #261's rule: EXACTLY once, never merely present.  `forgeRounds` occurs
        # three times in Java's [35] and one of them declares it, so a pattern
        # that merely matches is one that might match the wrong occurrence next
        # release.
        if len(hits) != 1:
            errors.append(
                f"sampled-rates: {where} — pattern {arg!r} matched "
                f"{len(hits)} times in {lang}'s test source ({which} slice), "
                f"not exactly once.  Re-anchor it: a rate variable read from "
                f"the wrong occurrence is indistinguishable from one read right"
            )
            return None
        if kind == "count":
            return len([x for x in hits[0].split(",") if x.strip()])
        try:
            return int(hits[0])
        except ValueError:
            errors.append(f"sampled-rates: {where} — {hits[0]!r} is not an integer")
            return None
    errors.append(f"sampled-rates: {where} — unknown source kind {kind!r}")
    return None


def _derive_sampled_rates(errors):
    """({row key: {lang: rate}}, {(row key, lang): {var: value}}).

    Per port, because the C/Java-vs-Go/Python split in the header means one
    number cannot describe four ports; the caller takes the worst.

    The second return is TODO #320's: a mechanism measured at a REDUCED
    parameter has to be held against the SHIPPED one, and the value that must
    not be reached is a VARIABLE of the formula rather than the rate it
    produces -- [45] carries a `trials` multiplier, so comparing rates would
    have compared 2 * (2/3)^4 against (2/3)^4 and passed a build that had
    lowered SDF_ROUNDS to the instrument's own round count.
    """
    ptables = _param_tables()
    bodies = {l: _numbered_test_bodies(l) for l in NUMBERED_TEST_FILES}
    scopes = {l: _numbered_test_scopes(l) for l in NUMBERED_TEST_FILES}
    out, envs = {}, {}
    for (scope, num), (formula, variables, reason) in sorted(
            _SAMPLED_TEST_RATES.items(), key=lambda kv: str(kv[0])):
        if not reason or len(reason) < 40:
            errors.append(f"sampled-rates: [{num}] needs a reason saying where "
                          f"its formula comes from")
        langs = SHARED_NUMBERING_LANGS if scope == "shared" else (scope,)
        where0 = f"[{num}] ({scope})"
        per_lang = {}
        for lang in langs:
            body = bodies.get(lang, {}).get(num)
            if body is None:
                errors.append(f"sampled-rates: {where0} has no {lang} test body "
                              f"to read its variables from")
                continue
            sl = {"body": body, "scope": scopes.get(lang, {}).get(num, body)}
            env = {}
            for var, by_lang in sorted(variables.items()):
                if lang not in by_lang:
                    errors.append(
                        f"sampled-rates: {where0} — variable {var!r} has no "
                        f"source for {lang}, which the row's scope includes"
                    )
                    continue
                v = _rate_var_value(by_lang[lang], lang, sl, ptables, errors,
                                    f"{where0} {var}")
                if v is not None:
                    env[var] = v
            if len(env) != len(variables):
                continue
            try:
                rate = eval(formula, {"__builtins__": {}}, dict(env))
            except Exception as exc:
                errors.append(f"sampled-rates: {where0} — formula {formula!r} "
                              f"does not evaluate ({exc})")
                continue
            if not isinstance(rate, (int, float)) or not 0 <= rate <= 1:
                errors.append(f"sampled-rates: {where0} — formula gave {rate!r}, "
                              f"which is not a probability")
                continue
            per_lang[lang] = rate
            envs[((scope, num), lang)] = dict(env)
        # A variable spelled for a port the row does not cover is dead weight
        # that will rot, so it fails rather than being ignored.
        for var, by_lang in sorted(variables.items()):
            extra = sorted(set(by_lang) - set(langs))
            if extra:
                errors.append(
                    f"sampled-rates: [{num}] variable {var!r} names "
                    f"{', '.join(extra)}, which this row's scope does not cover"
                )
        if per_lang:
            out[(scope, num)] = per_lang
    return out, envs


_RATE_MECHANISM_INSTRUMENT = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                          "measure_sampled_rates.py")


def check_rate_mechanisms(errors, envs):
    """TODO #320: hold each derived formula's recorded MEASUREMENT to the
    formula it validates.  Static -- the measurement is not re-run here, for
    the reason the table's (1) states; what is checked is that the record and
    the expression cannot drift apart in silence.

    Returns (mechanisms, rows measured)."""
    try:
        with open(_RATE_MECHANISM_INSTRUMENT, encoding="utf-8") as f:
            instrument = f.read()
    except OSError:
        instrument = None
        errors.append(
            "rate-mechanisms: spec/measure_sampled_rates.py is missing — the "
            "recorded measurements name a recipe that no longer exists, which "
            "is #296's thrown-away harness exactly"
        )

    covered = {}
    for name, m in sorted(_RATE_MECHANISMS.items()):
        for field in ("rows", "term", "var", "detects", "excludes", "ladder",
                      "witness", "note"):
            if field not in m:
                errors.append(f"rate-mechanisms: {name!r} has no {field!r}")
        if set(m) - {"rows", "term", "var", "detects", "excludes", "ladder",
                     "witness", "note"}:
            errors.append(f"rate-mechanisms: {name!r} carries unknown field(s) "
                          f"{sorted(set(m) - {'rows', 'term', 'var', 'detects', 'excludes', 'ladder', 'witness', 'note'})}")
            continue
        if instrument is not None and f'"{name}":' not in instrument:
            errors.append(
                f"rate-mechanisms: {name!r} has no measurer in "
                f"spec/measure_sampled_rates.py — a recorded measurement whose "
                f"recipe cannot be re-run is a claim, not a record"
            )
        # #304's token.  Requiring the numbers alone would have certified a
        # gate at 3.0e-4 while it ran at 6.0e-3.
        if "MEASURED" not in m.get("note", ""):
            errors.append(
                f"rate-mechanisms: {name!r} does not carry the token MEASURED — "
                f"TODO #304's rule, because a rate and an argument that it is "
                f"small read identically once written down"
            )
        for field in ("detects", "excludes", "witness", "note"):
            if len(m.get(field, "")) < 40:
                errors.append(f"rate-mechanisms: {name!r} needs a substantive "
                              f"{field!r}")
        if not m.get("ladder"):
            errors.append(f"rate-mechanisms: {name!r} records no measurement")
            continue

        for key in m["rows"]:
            key = tuple(key)
            if key in covered:
                errors.append(
                    f"rate-mechanisms: {list(key)} is claimed by both "
                    f"{covered[key]!r} and {name!r} — one row, one mechanism"
                )
            covered[key] = name
            row = _SAMPLED_TEST_RATES.get(key)
            if row is None:
                errors.append(
                    f"rate-mechanisms: {name!r} names {list(key)}, which has no "
                    f"_SAMPLED_TEST_RATES formula — the row was deleted or its "
                    f"rate went back to a literal, and the measurement is stale"
                )
                continue
            formula, variables, _reason = row
            # The anchor rule, as check E uses it: the validated term must still
            # be IN the formula, so renaming the formula fails here rather than
            # leaving a measurement attached to an expression it never saw.
            if m["term"] not in formula:
                errors.append(
                    f"rate-mechanisms: {name!r} validates the term "
                    f"{m['term']!r}, which is no longer part of {list(key)}'s "
                    f"formula {formula!r} — re-measure rather than re-anchor"
                )
            if m["var"] not in variables:
                errors.append(
                    f"rate-mechanisms: {name!r} reduces {m['var']!r}, which is "
                    f"not a variable of {list(key)}'s formula"
                )
                continue
            # (3): the instrument's parameter must stay BELOW every port's
            # shipped value.  The variable, not the rate -- [45] carries a
            # trials multiplier.
            worst = max(m["ladder"])
            for (k, lang), env in sorted(envs.items(), key=str):
                if k != key or m["var"] not in env:
                    continue
                if env[m["var"]] <= worst:
                    errors.append(
                        f"rate-mechanisms: {name!r} measures at {m['var']} = "
                        f"{worst} and {lang}'s {list(key)} SHIPS "
                        f"{m['var']} = {env[m['var']]}.  The reduced parameter "
                        f"is an instrument and has reached a default: either "
                        f"the port regressed to the round count CLAUDE.md's "
                        f"Testing section warns about, or the ladder was raised "
                        f"into it"
                    )

        for rounds in sorted(m["ladder"]):
            rung = m["ladder"][rounds]
            if not (isinstance(rung, tuple) and len(rung) == 3):
                errors.append(f"rate-mechanisms: {name!r} rung {rounds} is not "
                              f"(trials, accepts, predicted)")
                continue
            trials, accepts, predicted = rung
            try:
                expect = eval(m["term"], {"__builtins__": {}},
                              {m["var"]: rounds})
            except Exception as exc:
                errors.append(f"rate-mechanisms: {name!r} term {m['term']!r} "
                              f"does not evaluate at {m['var']}={rounds} ({exc})")
                continue
            # 1e-4 relative: the recorded predictions are rounded to six
            # decimals, and a term that is the WRONG function is out by a
            # factor, never by a rounding (the two found here were 3x and 10x).
            if abs(expect - predicted) > 1e-4 * max(expect, 1e-12):
                errors.append(
                    f"rate-mechanisms: {name!r} records a prediction of "
                    f"{predicted:g} at {m['var']}={rounds} where its own term "
                    f"gives {expect:g} — the record and the expression have "
                    f"drifted, which is what this table exists to prevent"
                )
                continue
            if not 0 < trials or not 0 <= accepts <= trials:
                errors.append(f"rate-mechanisms: {name!r} rung {rounds} has "
                              f"{accepts} of {trials} trials")
                continue
            sd = math.sqrt(trials * predicted * (1 - predicted))
            if abs(accepts - trials * predicted) > 6 * sd:
                errors.append(
                    f"rate-mechanisms: {name!r} at {m['var']}={rounds} records "
                    f"{accepts}/{trials} against a prediction of "
                    f"{trials * predicted:.1f} — outside 6 sigma ({sd:.1f}), so "
                    f"the recorded measurement contradicts the recorded formula"
                )

    # Exhaustive in both directions, and the unmeasured half ships empty.
    for key in sorted(_SAMPLED_TEST_RATES, key=str):
        if key in covered and key in _RATE_MECHANISM_UNMEASURED:
            errors.append(
                f"rate-mechanisms: {list(key)} is both measured and declared "
                f"unmeasurable — measuring one is what forces its entry out"
            )
        elif key not in covered and key not in _RATE_MECHANISM_UNMEASURED:
            errors.append(
                f"rate-mechanisms: {list(key)} has a formula and neither a "
                f"measured mechanism nor a recorded reason it cannot have one.  "
                f"A formula that is the wrong function of the right constants "
                f"still evaluates (TODO #319's stated limit)"
            )
    for key, reason in sorted(_RATE_MECHANISM_UNMEASURED.items(), key=str):
        if key not in _SAMPLED_TEST_RATES:
            errors.append(
                f"rate-mechanisms: _RATE_MECHANISM_UNMEASURED{list(key)} names "
                f"a row that has no formula to validate"
            )
        if len(reason) < 60:
            errors.append(
                f"rate-mechanisms: {list(key)} needs a reason its mechanism "
                f"cannot be measured — #300's argued half, which #304 showed "
                f"decays first"
            )
    return len(_RATE_MECHANISMS), len(covered)


_MARGIN_FIELDS = ("kind", "rows", "quantity", "bound", "deployed", "var",
                  "reduces", "ladder", "witness", "note")
_RATE_FIELDS = ("kind", "rows", "quantity", "bound", "var", "shipped",
                "shipped_why", "ladder", "witness", "note")


def check_argued_evidence(errors, ptables):
    """TODO #321: the ARGUED half of `_SAMPLED_TESTS`.

    Two jobs.  (a) Every `exact` row says WHY it is exact and what holds at the
    DEPLOYED parameters, and a `margin` basis owes a measurement.  (b) Every
    hand-computed literal is ANCHORED to the test it describes, read out of
    source, because TODO #320 found one describing a different test entirely and
    found it by accident.

    Returns (exact rows with a basis, measurements, rows they back)."""
    try:
        with open(_RATE_MECHANISM_INSTRUMENT, encoding="utf-8") as f:
            instrument = f.read()
    except OSError:
        instrument = None       # already reported by check_rate_mechanisms

    # ── (a) the `exact` census, exhaustive in both directions ────────────
    exact_rows = {k for k, (c, _r, _x) in _SAMPLED_TESTS.items() if c == "exact"}
    for key in sorted(exact_rows, key=str):
        if key not in _EXACT_BASES:
            errors.append(
                f"argued-evidence: {list(key)} is declared `exact` -- the "
                f"strongest verdict here and the only one contributing nothing "
                f"to the budget -- with no _EXACT_BASES entry saying why, and "
                f"none saying what holds at the parameters the suite deploys"
            )
    claimed = {}
    for key, ent in sorted(_EXACT_BASES.items(), key=str):
        if key not in exact_rows:
            errors.append(
                f"argued-evidence: _EXACT_BASES{list(key)} names a row that is "
                f"no longer `exact` -- a row that acquired a RATE has left this "
                f"table's subject, so delete the entry with the verdict"
            )
        if set(ent) != {"basis", "deployed", "evidence"}:
            errors.append(f"argued-evidence: _EXACT_BASES{list(key)} must carry "
                          f"exactly basis/deployed/evidence")
            continue
        if ent["basis"] not in ("identity", "separated", "no-assertion",
                               "exhaustive-branches", "margin"):
            errors.append(f"argued-evidence: _EXACT_BASES{list(key)} has "
                          f"unknown basis {ent['basis']!r}")
        if len(ent["deployed"]) < 80:
            errors.append(
                f"argued-evidence: _EXACT_BASES{list(key)} needs a substantive "
                f"statement of what holds at the DEPLOYED parameters -- the "
                f"question no row here had been asked (TODO #321)"
            )
        ev = ent["evidence"]
        if ent["basis"] == "margin":
            if ev is None:
                errors.append(
                    f"argued-evidence: _EXACT_BASES{list(key)} rests on a "
                    f"MARGIN and names no measurement.  A margin with no "
                    f"measured slack is the count of zeros this item replaced"
                )
            elif ev not in _ARGUED_MEASUREMENTS:
                errors.append(f"argued-evidence: _EXACT_BASES{list(key)} names "
                              f"evidence {ev!r}, which does not exist")
        elif ev is not None:
            errors.append(
                f"argued-evidence: _EXACT_BASES{list(key)} is {ent['basis']!r} "
                f"and names evidence {ev!r} -- only a `margin` basis takes one, "
                f"or the two categories stop meaning different things"
            )

    # ── the measurements ─────────────────────────────────────────────────
    backed = {}
    for name, m in sorted(_ARGUED_MEASUREMENTS.items()):
        kind = m.get("kind")
        if kind not in ("margin", "rate"):
            errors.append(f"argued-evidence: {name!r} has unknown kind {kind!r}")
            continue
        want = set(_MARGIN_FIELDS if kind == "margin" else _RATE_FIELDS)
        if set(m) != want:
            errors.append(
                f"argued-evidence: {name!r} ({kind}) carries "
                f"{sorted(set(m) ^ want)} as a field mismatch against "
                f"{sorted(want)}"
            )
            continue
        if instrument is not None and f'"{name}":' not in instrument:
            errors.append(
                f"argued-evidence: {name!r} has no measurer in "
                f"spec/measure_sampled_rates.py -- a recorded measurement whose "
                f"recipe cannot be re-run is a claim, not a record (#296's "
                f"thrown-away harness)"
            )
        if "MEASURED" not in m["note"]:
            errors.append(
                f"argued-evidence: {name!r} does not carry the token MEASURED "
                f"-- #304's rule, extended to the category that carries no "
                f"number at all"
            )
        for field in ("quantity", "bound", "witness", "note"):
            if len(m[field]) < 60:
                errors.append(f"argued-evidence: {name!r} needs a substantive "
                              f"{field!r}")
        if not m["ladder"]:
            errors.append(f"argued-evidence: {name!r} records no measurement")
            continue
        for key in m["rows"]:
            key = tuple(key)
            if key in backed:
                errors.append(f"argued-evidence: {list(key)} is backed by both "
                              f"{backed[key]!r} and {name!r} -- one row, one "
                              f"measurement")
            backed[key] = name
            row = _SAMPLED_TESTS.get(key)
            if row is None:
                errors.append(f"argued-evidence: {name!r} backs {list(key)}, "
                              f"which is not a _SAMPLED_TESTS row")
                continue
            code, rate, _reason = row
            if code == "exact":
                ent = _EXACT_BASES.get(key)
                if ent is None or ent.get("evidence") != name:
                    errors.append(
                        f"argued-evidence: {name!r} backs the `exact` row "
                        f"{list(key)}, which does not name it as its evidence"
                    )
            elif rate == "derived":
                errors.append(
                    f"argued-evidence: {name!r} backs {list(key)}, whose rate "
                    f"is DERIVED -- a formula's mechanism belongs in "
                    f"_RATE_MECHANISMS, which validates it against the "
                    f"expression.  Two tables for two objects (TODO #320, #321)"
                )

        if kind == "margin":
            # (a) the DEPLOYED block is held to every port's source.  This is
            # #320's rule (3) INVERTED: there the reduced parameter had to stay
            # strictly below what ships, because the instrument was the
            # instrument; here the top rung IS the claim, so it must EQUAL what
            # ships -- and #223 has moved one of these constants once already.
            for prow, val in sorted(m["deployed"].items()):
                spec = PARAMETERS.get(prow)
                if spec is None:
                    errors.append(f"argued-evidence: {name!r} names PARAMETERS "
                                  f"row {prow!r}, which does not exist")
                    continue
                for lang, cname in zip(PARAM_LANGS, spec[0]):
                    if cname is None or lang not in ptables:
                        continue
                    table = ptables[lang]
                    if cname not in table:
                        continue
                    got = _param_eval(table[cname], table, lang,
                                      cls=_java_cls(lang, cname))
                    if got is not None and got != val:
                        errors.append(
                            f"argued-evidence: {name!r} was measured at "
                            f"{prow} = {val} and {lang} now SHIPS "
                            f"{cname} = {got}.  The margin was measured at "
                            f"parameters the suite no longer deploys, which is "
                            f"the defect this table exists to close -- re-run "
                            f"spec/measure_sampled_rates.py rather than "
                            f"editing the number"
                        )
            if m["reduces"] not in m["deployed"]:
                errors.append(f"argued-evidence: {name!r} reduces "
                              f"{m['reduces']!r}, which its deployed block does "
                              f"not name")
                continue
            top = m["deployed"][m["reduces"]]
            if max(m["ladder"]) != top:
                errors.append(
                    f"argued-evidence: {name!r}'s ladder tops out at "
                    f"{max(m['ladder'])} and {m['reduces']} deploys {top} -- "
                    f"the deployed rung IS the claim, so it has to be in the "
                    f"ladder and it has to be the top of it"
                )
            adverse_seen = 0
            prev = None
            for val in sorted(m["ladder"], reverse=True):
                rung = m["ladder"][val]
                if not (isinstance(rung, tuple) and len(rung) == 4):
                    errors.append(f"argued-evidence: {name!r} rung {val} is not "
                                  f"(trials, min, mean, adverse)")
                    continue
                trials, mn, mean, adverse = rung
                if trials <= 0 or not 0 <= adverse <= trials:
                    errors.append(f"argued-evidence: {name!r} rung {val} has "
                                  f"{adverse} adverse of {trials}")
                    continue
                if mn > mean:
                    errors.append(f"argued-evidence: {name!r} rung {val} has a "
                                  f"minimum above its mean")
                if val == top:
                    if adverse:
                        errors.append(
                            f"argued-evidence: {name!r}'s DEPLOYED rung records "
                            f"{adverse} adverse trial(s) of {trials}.  The row "
                            f"it backs is `exact`, which claims zero"
                        )
                    if mn <= 0:
                        errors.append(
                            f"argued-evidence: {name!r}'s deployed worst-case "
                            f"margin is {mn}, not positive -- the row it backs "
                            f"is `exact` and the measurement says it is not"
                        )
                elif val >= top:
                    errors.append(
                        f"argued-evidence: {name!r} has a non-deployed rung at "
                        f"{m['reduces']} = {val}, which is not BELOW the "
                        f"shipped {top}.  A reduced parameter is an instrument "
                        f"and must stay local (#320's rule 3)"
                    )
                if prev is not None and mean > prev:
                    errors.append(
                        f"argued-evidence: {name!r}'s mean margin RISES from "
                        f"{prev} to {mean} as {m['reduces']} falls to {val} -- "
                        f"the ladder has no cliff and so demonstrates nothing"
                    )
                prev = mean
                adverse_seen += adverse
            if not adverse_seen:
                errors.append(
                    f"argued-evidence: {name!r}'s ladder never reaches an "
                    f"adverse trial, so the witness was only ever checked on "
                    f"the agreeing branch -- #296's rule that a branch a "
                    f"random stream never enters is not covered either"
                )
        else:
            if len(m["shipped_why"]) < 60:
                errors.append(f"argued-evidence: {name!r} needs a reason its "
                              f"shipped {m['var']} cannot be read from source")
            events_seen = 0
            for val in sorted(m["ladder"]):
                rung = m["ladder"][val]
                if not (isinstance(rung, tuple) and len(rung) == 3):
                    errors.append(f"argued-evidence: {name!r} rung {val} is not "
                                  f"(trials, events, predicted)")
                    continue
                trials, events, predicted = rung
                if val >= m["shipped"]:
                    errors.append(
                        f"argued-evidence: {name!r} measures at {m['var']} = "
                        f"{val} and the test SHIPS {m['shipped']} -- the "
                        f"reduced parameter has reached a default (#320's "
                        f"rule 3)"
                    )
                if trials <= 0 or not 0 <= events <= trials:
                    errors.append(f"argued-evidence: {name!r} rung {val} has "
                                  f"{events} of {trials}")
                    continue
                sd = math.sqrt(trials * predicted * (1 - predicted))
                if abs(events - trials * predicted) > 6 * sd:
                    errors.append(
                        f"argued-evidence: {name!r} at {m['var']}={val} records "
                        f"{events}/{trials} against a prediction of "
                        f"{trials * predicted:.2f} -- outside 6 sigma "
                        f"({sd:.2f}), so the record contradicts its own bound"
                    )
                events_seen += events
            if not events_seen:
                errors.append(
                    f"argued-evidence: {name!r}'s whole ladder observed ZERO "
                    f"events, which is the 0/N this item exists not to produce "
                    f"-- lower the parameter rather than raising the trials"
                )

    for name in sorted(_ARGUED_MEASUREMENTS):
        if name not in set(backed.values()):
            errors.append(f"argued-evidence: {name!r} backs no row -- a "
                          f"measurement whose subject has gone stays only as "
                          f"something to re-derive later")

    # ── (b) the literal anchors ──────────────────────────────────────────
    bodies = {l: _numbered_test_bodies(l) for l in NUMBERED_TEST_FILES}
    # The whole-harness text, for the "exactly once in this port" half of the
    # anchor rule.  CONCATENATED across the port's files, unlike the body
    # slices: an anchor that matched one line in SelfTest.java and another in
    # Bench.java would be ambiguous about which test it describes, which is
    # the defect #320 found in ("java", 26) and found only by accident.
    texts = {lang: "\n".join(t for _p, t in _marker_sources(lang))
             for lang in NUMBERED_TEST_FILES}
    for key in sorted(_SAMPLED_TEST_RATE_LITERAL, key=str):
        scope, num = key
        ent = _SAMPLED_TEST_RATE_LITERAL[key]
        if not (isinstance(ent, tuple) and len(ent) == 3):
            errors.append(f"argued-evidence: _SAMPLED_TEST_RATE_LITERAL"
                          f"{list(key)} must be (lang, anchor, reason)")
            continue
        lang, anchor, _reason = ent
        if lang not in NUMBERED_TEST_FILES:
            errors.append(f"argued-evidence: _SAMPLED_TEST_RATE_LITERAL"
                          f"{list(key)} anchors in unknown language {lang!r}")
            continue
        if scope not in ("shared",) and scope != lang:
            errors.append(
                f"argued-evidence: _SAMPLED_TEST_RATE_LITERAL{list(key)} is "
                f"scoped to {scope!r} and anchors in {lang!r}"
            )
        n_file = len(re.findall(anchor, texts[lang]))
        body = bodies.get(lang, {}).get(num, "")
        n_body = len(re.findall(anchor, body))
        if n_file != 1 or n_body != 1:
            errors.append(
                f"argued-evidence: _SAMPLED_TEST_RATE_LITERAL{list(key)}'s "
                f"anchor {anchor!r} matched {n_file} time(s) in {lang}'s "
                f"harness and {n_body} inside [{num}]'s own body, not exactly "
                f"once each.  Re-anchor it: a reason pinned to the wrong test "
                f"reads exactly like one pinned to the right test, which is how "
                f"('java', 26)'s described [28] for two releases"
            )
    return len(_EXACT_BASES), len(_ARGUED_MEASUREMENTS), len(backed)


# ── Part 7/7: the harnesses this axis does NOT read ──────────────────────
#
# TODO #323.  Parts 1/7 through 6/7 read exactly four files -- the three in
# NUMBERED_TEST_FILES plus SelfTest.java -- and `Herradura_tests.{s,asm,ino}`
# appear nowhere in spec/.  There was no sentence anywhere saying why, which is
# not a scope decision but an unexamined boundary: TODO #306's finding, that
# WHICH CODE THE CENSUS READS is prior to everything the census says, and
# TODO #295's rule that getting the corpus wrong in the LENIENT direction makes
# the whole check pass vacuously.  `PARAM_USE_CORPUS` states its corpus forty
# lines into its own block for exactly this reason; the ninth axis did not.
#
# IT IS NOT AN EMPTY GAP, WHICH IS WHY THIS IS A PART AND NOT A COMMENT.
# ARM and NASM both reseed their LCG from /dev/urandom before test [1] (the
# SA-01 marker in each), so every verdict after that is decided on a fresh
# sample -- the property Part 1/7 censuses in the other four ports.  Both carry
# [10] "HPKS-NL Eve resistance: random forgery rejected (20 trials)", which
# draws s_fake per trial and requires all 20 to be REJECTED, and [18]
# v2_weak_key_reject.  And `arm-i386` and `arduino` carry no
# `continue-on-error`, so a flake in either is a red REQUIRED check on somebody
# else's PR -- Part 1/7's own stated reason for caring about the numbered tests
# more than about the findings gates.  Until this part the advertised budget was
# summed over four of the six gated harnesses with the omission unstated.
#
# TWO THINGS MEASURED BEFORE ANY OF IT WAS WRITTEN, AND BOTH CHANGED THE SHAPE.
#
# (1) THE SCREEN MUST READ THE TITLE, WHICH INVERTS #322's OWN REMEDY.  Part
# 5/7 found a verdict-line-only screen missing [44] and [50] and widened it to
# whole BODIES.  In assembly whole bodies are still not enough: a test's title
# lives in .rodata (`fmt_t10: .asciz "... random forgery rejected ..."`) while
# its body is ~760 lines away, and the body's only rejection wording is a
# `/* random forgery */` comment the screen strips by design.  So a body-only
# screen flags [10] in Arduino and MISSES it in both assembly harnesses -- the
# vacuous direction.  In C/Go/Python the title string IS the marker and sits
# inside the slice by construction; in assembly the marker is a symbol
# REFERENCE.  The symbol is resolved here, and a title that does not resolve is
# an ERROR rather than a skip, which is #319's rule for a variable that
# resolves nowhere: a silently missing title SHRINKS the screen.
#
# (2) ONE TEST NUMBER IS SAMPLED IN TWO HARNESSES AND DETERMINISTIC IN THE
# THIRD.  `Herradura_tests.ino` sets `prng_state = 0x12345678UL` and `setup()`
# only opens the UART -- an AVR has no entropy source -- so it is never
# reseeded and its 18 verdicts are identical on every run.  Its false-failure
# rate is exactly ZERO and it cannot contribute to the budget.  That is the
# right answer for that port and was written down nowhere.  So [10] carries a
# RATED basis in ARM and NASM and an exact one in Arduino: #319's per-port
# split with a FLAKE RATE as the object, one harness family over.  The status
# is DERIVED from each harness's source rather than curated, cross-checked
# against the record BOTH WAYS, and a harness recorded `fixed` is FORBIDDEN a
# rated basis -- so the split is checked rather than described.
#
# SCOPE, stated here rather than discovered later.  This does not port Part
# 1/7's draw detector or Part 6/7's verdict fingerprints to Thumb-2 and NASM.
# A fingerprint over "verdict-bearing lines" is a cmp/branch PAIR in assembly
# rather than a string, and a draw detector would need a fifth and sixth
# dialect after #306's sixth-spelling hazard had already been met twice.
# Folding either in converges on completeness again, which is #298's recorded
# reason for splitting an item instead of widening it.  What this closes is the
# corpus boundary and the rejection statement -- the case that exists.
#
# KNOWN LIMIT.  These harnesses run reduced parameters by design (Stern-F at
# N=32, t=2, rounds=4), so a rate derived here is a rate for the DEMO
# instance and says nothing about what ships.  That is not a defect of the
# derivation: the harness is the subject, and the flake rate of the harness is
# what the budget is about.
#
# AND WHY THESE TWO RATES CARRY NO #320-STYLE MEASUREMENT, said here rather
# than left as an omission.  Part 3/7 requires every DERIVED formula to be
# held to a measured mechanism, because a formula can be the wrong function of
# the right constants.  There is no competing mechanism to exclude here: the
# verifier accepts iff g^s_fake . C^e == R, which has exactly one solution per
# ord(g), so the rate is a THEOREM about a cyclic group and the denominator is
# computed exactly by _gf_order rather than fitted.  And a measurement could
# not settle it anyway -- at 7e-08 a confirming run needs ~10^8 trials, which
# is #321's finding that a sampled zero cannot show what an exact claim asks
# of it at any trial count.  What #320's discipline actually buys here is the
# part that IS done: the inputs are read from source and the order recomputed
# every run, so the published number moves when the harness does.  The standing warning in CLAUDE.md's Testing
# section -- that a STERN rejection test written here would carry a (2/3)^4 =
# 19.75% per-trial soundness error -- is unviolated and stays: [11]-[14] are
# completeness checks, each requiring all 3 trials to pass.

_REDUCED_HARNESSES = {
    "arm": {
        "path": os.path.join(REPO, "CryptosuiteTests", "Herradura_tests.s"),
        # Leading marker, as in C/Go/Python -- the header printf comes first,
        # so a forward slice is correct here and Java's trailing-marker hazard
        # (#322's third derivation limit) does not arise.
        "marker": re.compile(r'ldr\s+r0,\s*=fmt_t(\d+)\b'),
        "title": r'fmt_t%d:\s*\.asciz\s*"([^"]*)"',
        "line_comment": re.compile(r'@[^\n]*'),
        "job": "arm-i386",
        # The PRNG state being the DESTINATION of a read from the urandom
        # handle.  Deliberately not a bare search for "/dev/urandom", which
        # the SA-01 comment would satisfy on its own.
        "seed_probe": re.compile(r'ldr\s+r0,\s*=lcg_state\b[\s\S]{0,240}?bl\s+fread'),
        "poly": re.compile(r'ldr\s+r7,\s*=0x([0-9A-Fa-f]+)'),
        "gen_load": re.compile(r'mov\s+r0,\s*#(\d+)\b'),
        "gen_call": re.compile(r'bl\s+gf_pow_32\b'),
        "trials": re.compile(r'cmp\s+r11,\s*#(\d+)\b'),
    },
    "i386": {
        "path": os.path.join(REPO, "CryptosuiteTests", "Herradura_tests.asm"),
        "marker": re.compile(r'mov\s+eax,\s*t(\d+)_hdr\b'),
        "title": r't%d_hdr\s+db\s+"([^"]*)"',
        "line_comment": re.compile(r';[^\n]*'),
        "job": "arm-i386",
        "seed_probe": re.compile(r'mov\s+ecx,\s*prng_state\b[\s\S]{0,120}?int\s+0x80'),
        "poly": re.compile(r'%define\s+GF_POLY\s+0x([0-9A-Fa-f]+)'),
        "gen_load": re.compile(r'mov\s+eax,\s*(\d+)\b'),
        "gen_call": re.compile(r'call\s+gf_pow_32\b'),
        "trials": re.compile(r'cmp\s+ebp,\s*(\d+)\b'),
    },
    "arduino": {
        "path": os.path.join(REPO, "CryptosuiteTests", "Herradura_tests.ino"),
        "marker": re.compile(r'Serial\.println\("\[(\d+)\]'),
        # The println IS the title, so it is inside the slice already and
        # there is no symbol to resolve.
        "title": None,
        "line_comment": re.compile(r'//[^\n]*'),
        "job": "arduino",
        # A reseed would be an assignment from something that is not a literal
        # and not the LCG's own recurrence.  There is no entropy source on an
        # AVR, so this is expected NOT to match -- and it firing is the
        # interesting direction, since it would mean the harness started to
        # flake.
        "seed_probe": re.compile(
            r'randomSeed\s*\(|analogRead\s*\(|/dev/urandom|'
            r'prng_state\s*=\s*(?!prng_state\b)[A-Za-z_]'),
        "poly": re.compile(r'#define\s+GF_POLY32\s+0x([0-9A-Fa-f]+)'),
        "gen_load": re.compile(r'gf_pow_32\s*\(\s*GF_GEN\b'),
        "gen_call": None,
        "trials": None,
    },
}

# The documented range: CLAUDE.md's Testing section says these three run tests
# [1]-[18].  Held as a set rather than a count so a GAP is an error too.
_REDUCED_RANGE = tuple(range(1, 19))

# DERIVED per harness and cross-checked against this record in both
# directions.  "fresh" means the PRNG state is reseeded from an external
# entropy source, so a verdict is decided on a fresh sample; "fixed" means it
# is not, so the harness reproduces run to run and its flake rate is ZERO.
_REDUCED_ENTROPY = {
    "arm":     ("fresh",
        "SA-01 reads 4 bytes of /dev/urandom into `lcg_state` in main() before "
        "test [1], so every trial after that point is a fresh sample"),
    "i386":    ("fresh",
        "SA-01 reads 4 bytes of /dev/urandom into `prng_state` in _start "
        "before test [1], by the same convention as the ARM harness"),
    "arduino": ("fixed",
        "`prng_state = 0x12345678UL` and setup() only opens the UART -- an AVR "
        "has no entropy source and simavr supplies none -- so the LCG replays "
        "one stream and all 18 verdicts are identical on every run.  The "
        "consequence is the point: this harness CANNOT flake, so it "
        "contributes exactly 0 to the budget, and the same [10] that is rated "
        "in ARM and NASM is exact here.  What it buys in exchange is weaker: "
        "its 20 `random` forgeries are the same 20 forever"),
}

# Every cell the screen flags, classified from Part 5/7's CLOSED set of nine
# kinds -- the same vocabulary, not a second one.  `rate` is present only for
# a RATED basis in a `fresh` harness; anywhere else it must be None, which is
# what makes the ARM/Arduino split a check rather than a sentence.
_REDUCED_REJECTION_BASES = {
    ("arm", 10): {"basis": "random-forgery", "bits": None, "rate": "derived",
        "why": "s_fake = prng_next() per trial, and the verifier accepts only "
               "if g^s_fake . C^e == R -- one value of s_fake in ord(g).  All "
               "20 trials must be rejected (`cmp r11, #20`), so the rate is "
               "20/ord(g), derived from the polynomial and the generator this "
               "harness actually uses rather than assumed to be 2^-32"},
    ("i386", 10): {"basis": "random-forgery", "bits": None, "rate": "derived",
        "why": "the same construction as the ARM harness, transcribed for "
               "NASM: 20 trials, `cmp ebp, 20`, all of which must reject.  A "
               "separate row rather than a shared one because it is a separate "
               "BINARY -- the two agree today and nothing makes them agree"},
    ("arduino", 10): {"basis": "random-forgery", "bits": None, "rate": None,
        "why": "the same Eve-resistance assertion, and the reason it carries "
               "NO rate is the finding: this harness never reseeds its LCG, so "
               "the 20 forgeries are a fixed vector and the verdict is "
               "determined.  A rate here would be a claim about a coin that is "
               "not tossed"},
    ("arm", 18): {"basis": "structural", "bits": None, "rate": None,
        "why": "v2_weak_key_reject feeds the guard TWO HARDCODED keys -- 2^17, "
               "whose delta(K) is 0 at n=32 (TODO #169), which must be "
               "refused, and an ordinary key which must be accepted -- so no "
               "entropy reaches the verdict and the accept-control is built "
               "in.  #234's rule that a rejection case needs an accept "
               "control beside it, satisfied in one expression"},
    ("i386", 18): {"basis": "structural", "bits": None, "rate": None,
        "why": "the same two hardcoded keys as the ARM harness, and "
               "deterministic for the same reason: the guard is a predicate on "
               "delta(K) and neither input is drawn"},
    ("arduino", 18): {"basis": "structural", "bits": None, "rate": None,
        "why": "the same two hardcoded keys again, doubly deterministic here "
               "-- the inputs are literals AND the harness draws nothing at "
               "all -- so this cell is exact under either reading"},
    ("arduino", 17): {"basis": "not-a-verdict", "bits": None, "rate": None,
        "why": "an OVER-MATCH, kept and classified rather than dropped, which "
               "is Part 5/7's rule.  [17] is a 4-leaf Merkle proof round-trip "
               "asserting `cur == root` and rejects nothing; the screen sees "
               "`reject` because the slice runs to the next marker and the "
               "NEXT test's function declaration -- "
               "`void test_v2_weak_key_reject()` -- sits inside it.  A "
               "declaration, which is exactly what this kind exists to absorb"},
}


def _reduced_bodies(harness):
    """{test number: (body-with-comments-stripped, resolved title)}.

    Forward slice from each leading marker to the next, as Part 1/7 does for
    C/Go/Python.  The title is resolved through its symbol and appended,
    because in assembly the wording that says `this test asserts a rejection`
    is in .rodata and not in the body at all.
    """
    h = _REDUCED_HARNESSES[harness]
    with open(h["path"], encoding="utf-8", errors="replace") as f:
        text = f.read()
    hits = sorted((m.start(), int(m.group(1))) for m in h["marker"].finditer(text))
    out = {}
    for i, (off, num) in enumerate(hits):
        end = hits[i + 1][0] if i + 1 < len(hits) else len(text)
        body = re.sub(r'/\*.*?\*/', ' ', text[off:end], flags=re.S)
        body = h["line_comment"].sub(' ', body)
        title = None
        if h["title"] is not None:
            m = re.search(h["title"] % num, text)
            title = m.group(1) if m else None
        out[num] = (body, title)
    return out, text


def _gf_order(gen, poly):
    """ord(gen) in GF(2^32) under `poly`, computed exactly.

    Not sampled and not modelled: the harnesses' gf_mul_32 is a 32-step
    carryless multiply reducing on carry-out of bit 31, so this reproduces it
    directly.  #322's own model of a rejection rate was wrong twice, both
    times conservatively, which is the argument for computing rather than
    asserting -- and here the answer is not the 2^-32 the construction
    suggests, because g = 3 generates an index-15 SUBGROUP.
    """
    mask = 0xFFFFFFFF

    def mul(a, b):
        r = 0
        for _ in range(32):
            if b & 1:
                r ^= a
            carry = (a >> 31) & 1
            a = (a << 1) & mask
            if carry:
                a ^= poly
            b >>= 1
        return r

    def power(b, e):
        r = 1
        while e:
            if e & 1:
                r = mul(r, b)
            b = mul(b, b)
            e >>= 1
        return r

    n = (1 << 32) - 1
    if power(gen, n) != 1:
        return None          # not in the multiplicative group: caller errors
    order = n
    for p in (3, 5, 17, 257, 65537):     # 2^32-1 = 3.5.17.257.65537
        while order % p == 0 and power(gen, order // p) == 1:
            order //= p
    return order


def _reduced_derive(errors):
    """{(harness, test): rate} for every RATED reduced-harness rejection row.

    Every input is read from the harness's own source and the group order is
    computed, so lowering the trial count or moving the polynomial moves the
    published rate -- #319's rule, applied to the two harnesses it never read.
    The polynomial is read from the RAW text, comments included, on purpose: a
    second spelling anywhere makes the count exceed one and fail loudly, which
    is #261's exactly-once rule and the safe direction for a denominator.
    """
    rates = {}
    for (harness, num), row in sorted(_REDUCED_REJECTION_BASES.items()):
        if row.get("rate") != "derived":
            continue
        h = _REDUCED_HARNESSES[harness]
        bodies, text = _reduced_bodies(harness)
        if num not in bodies:
            errors.append(
                f"reduced-rates: [{num}] is not a test in the {harness} "
                f"harness, so its rate cannot be derived")
            continue
        body, _title = bodies[num]

        polys = h["poly"].findall(text)
        if len(polys) != 1:
            errors.append(
                f"reduced-rates: {harness} — the GF polynomial regex matched "
                f"{len(polys)} time(s), not exactly once.  A variable that "
                f"resolves nowhere is an ERROR, not a skip (TODO #319): a "
                f"skipped term silently SHRINKS the rate")
            continue
        poly = int(polys[0], 16)

        # The generator: for each gf_pow_32 call, the nearest PRECEDING
        # immediate load of the first-argument register, and all of them must
        # AGREE.  Said precisely because a reason exact about the wrong object
        # reads exactly like a correct one (#310) -- this is a proximity read,
        # not dataflow, so a call whose base is COMPUTED (the C^e term here)
        # contributes its predecessor's value rather than its own.  That is
        # sound in the direction that matters: any disagreement makes the set
        # larger than one and ERRORS, so the failure mode is a refusal to
        # publish a rate, never a wrong rate.
        gens = set()
        if h["gen_call"] is not None:
            for call in h["gen_call"].finditer(body):
                loads = h["gen_load"].findall(body[:call.start()])
                if loads:
                    gens.add(int(loads[-1]))
        if len(gens) != 1:
            errors.append(
                f"reduced-rates: {harness} [{num}] — the gf_pow_32 call sites "
                f"in this test load {sorted(gens) or 'no'} generator value(s); "
                f"exactly one is required, or the rate is a rate for a group "
                f"nobody uses")
            continue
        gen = gens.pop()

        trials = h["trials"].findall(body) if h["trials"] else []
        if len(trials) != 1:
            errors.append(
                f"reduced-rates: {harness} [{num}] — the all-must-reject "
                f"threshold matched {len(trials)} time(s), not exactly once, "
                f"so the number of trials entering the rate is ambiguous")
            continue
        n_trials = int(trials[0])

        order = _gf_order(gen, poly)
        if not order:
            errors.append(
                f"reduced-rates: {harness} [{num}] — generator {gen} is not in "
                f"the multiplicative group of GF(2^32) mod {poly:#x}, so the "
                f"forgery rate has no denominator.  Either the polynomial is "
                f"reducible or the generator moved")
            continue
        rates[(harness, num)] = n_trials / float(order)
    return rates


def check_reduced_harnesses(errors):
    """TODO #323: the three gated harnesses Parts 1/7-6/7 do not read."""
    seen = {}
    for harness, h in sorted(_REDUCED_HARNESSES.items()):
        if not os.path.exists(h["path"]):
            errors.append(f"reduced-harness: {harness} — {h['path']} is "
                          f"missing; the corpus statement names a file that "
                          f"is not there")
            continue
        bodies, text = _reduced_bodies(harness)
        found = tuple(sorted(bodies))
        seen[harness] = found
        # #296's guard: an empty census is an error, never a clean bill.
        if not found:
            errors.append(
                f"reduced-harness: {harness} — no [N] marker matched, so "
                f"either the marker pattern is stale or the harness stopped "
                f"numbering its tests.  An under-matching detector makes this "
                f"whole part pass vacuously")
            continue
        if found != _REDUCED_RANGE:
            missing = sorted(set(_REDUCED_RANGE) - set(found))
            extra = sorted(set(found) - set(_REDUCED_RANGE))
            errors.append(
                f"reduced-harness: {harness} — runs tests {list(found)}, not "
                f"the documented [1]-[18]"
                + (f"; missing {missing}" if missing else "")
                + (f"; new {extra}" if extra else "")
                + ".  A test added to a reduced harness must be screened for "
                  "a rejection assertion, so it cannot arrive unexamined")
        # Titles must RESOLVE.  A missing title shrinks the screen, which is
        # the direction this part exists to close.
        for num, (_body, title) in sorted(bodies.items()):
            if h["title"] is not None and title is None:
                errors.append(
                    f"reduced-harness: {harness} [{num}] — the title symbol "
                    f"did not resolve to a string.  In assembly the rejection "
                    f"wording lives in .rodata, so an unresolved title makes "
                    f"the screen blind to this test rather than merely quiet")

        # The entropy status, DERIVED and then compared with the record.
        recorded, why = _REDUCED_ENTROPY.get(harness, (None, ""))
        if recorded not in ("fresh", "fixed"):
            errors.append(f"reduced-harness: {harness} has no recorded entropy "
                          f"status; it is 'fresh' or 'fixed'")
            continue
        if len(why) < 60:
            errors.append(f"reduced-harness: {harness}'s entropy status needs "
                          f"a reason saying how it was read")
        probed = "fresh" if h["seed_probe"].search(text) else "fixed"
        if probed != recorded:
            errors.append(
                f"reduced-harness: {harness} is recorded {recorded!r} and its "
                f"source reads {probed!r}.  "
                + ("A harness that has STARTED drawing decides its verdicts on "
                   "a fresh sample and owes rated rows and a budget term"
                   if probed == "fresh" else
                   "A harness that has STOPPED drawing no longer flakes, so "
                   "its rated rows overstate the budget and its 'random' cases "
                   "now test one fixed vector forever")
                + " — fix the code or the record, not this check")

    # The screen: exhaustive in BOTH directions, on Part 5/7's vocabulary.
    for harness in sorted(seen):
        bodies, _text = _reduced_bodies(harness)
        for num, (body, title) in sorted(bodies.items()):
            flagged = bool(_REJECTION_PATTERN.search(body + " " + (title or "")))
            row = _REDUCED_REJECTION_BASES.get((harness, num))
            if flagged and row is None:
                errors.append(
                    f"reduced-harness: {harness} [{num}] asserts something is "
                    f"REFUSED and states no BASIS.  Add a "
                    f"_REDUCED_REJECTION_BASES entry naming one of "
                    f"{list(_REJECTION_KINDS)} — over-matching is the "
                    f"CONSERVATIVE direction here, so classify it (a counter "
                    f"or a declaration is 'reference-count' or "
                    f"'not-a-verdict'), never drop it")
            elif row is not None and not flagged:
                errors.append(
                    f"reduced-harness: _REDUCED_REJECTION_BASES[{harness!r}, "
                    f"{num}] names a test the screen does not flag — the "
                    f"assertion was removed, or the wording moved out of both "
                    f"the body and the title")

    rated = 0
    for (harness, num), row in sorted(_REDUCED_REJECTION_BASES.items()):
        if harness not in _REDUCED_HARNESSES:
            errors.append(f"reduced-harness: _REDUCED_REJECTION_BASES names "
                          f"unknown harness {harness!r}")
            continue
        basis = row.get("basis")
        if basis not in _REJECTION_KINDS:
            errors.append(
                f"reduced-harness: {harness} [{num}] has basis {basis!r}, "
                f"which is not one of Part 5/7's nine kinds.  The vocabulary "
                f"is shared on purpose — a second closed set is a second thing "
                f"to keep in step")
        if len(row.get("why", "")) < 60:
            errors.append(f"reduced-harness: {harness} [{num}] needs a reason "
                          f"saying what its basis rests on")
        status = _REDUCED_ENTROPY.get(harness, (None, ""))[0]
        has_rate = row.get("rate") is not None
        if has_rate and status != "fresh":
            errors.append(
                f"reduced-harness: {harness} [{num}] carries a rate and its "
                f"harness is {status!r}.  A harness that draws nothing cannot "
                f"flake, so a rate there is a claim about a coin that is not "
                f"tossed — this is the ARM/Arduino split, checked")
        if has_rate and basis not in _REJECTION_RATED:
            errors.append(
                f"reduced-harness: {harness} [{num}] carries a rate on basis "
                f"{basis!r}, which is not one of Part 5/7's RATED kinds "
                f"{list(_REJECTION_RATED)}")
        if basis in _REJECTION_RATED and status == "fresh" and not has_rate:
            errors.append(
                f"reduced-harness: {harness} [{num}] rests on a fresh coin in "
                f"a harness that draws, and states no rate.  That is the term "
                f"the budget was missing")
        if row.get("bits") is not None and basis not in _REJECTION_BY_WIDTH:
            errors.append(
                f"reduced-harness: {harness} [{num}] states a width on basis "
                f"{basis!r}, which does not rest on one")
        if has_rate:
            rated += 1
    fresh = sum(1 for s, _w in _REDUCED_ENTROPY.values() if s == "fresh")
    return (len(seen), fresh, len(_REDUCED_ENTROPY) - fresh,
            len(_REDUCED_REJECTION_BASES), rated)


def check_sampled_tests(errors, numbers):
    """TODO #316: which numbered tests decide a verdict from a fresh sample."""
    drawn = {}
    for lang in NUMBERED_TEST_FILES:
        pattern = _TEST_DRAW_PATTERNS[lang]
        bodies = _numbered_test_bodies(lang)
        found = sorted(n for n, body in bodies.items() if pattern.search(body))
        # #296's guard, and #306's hazard: an empty census is an error, not a
        # clean bill.  A detector that matches nothing looks exactly like a
        # harness that draws nothing.
        if not found:
            errors.append(
                f"sampled-tests: {lang} — no numbered test matched "
                f"_TEST_DRAW_PATTERNS, so either the pattern is stale or the "
                f"harness stopped drawing entropy.  An under-matching detector "
                f"makes this whole check pass vacuously (TODO #295's lenient "
                f"direction), so it fails rather than reporting zero"
            )
            drawn[lang] = []
            continue
        recorded = _TEST_DRAWS.get(lang, [])
        started = sorted(set(found) - set(recorded))
        stopped = sorted(set(recorded) - set(found))
        if started:
            errors.append(
                f"sampled-tests: {lang} — test(s) {started} now draw fresh "
                f"entropy and are not in _TEST_DRAWS.  Say what their verdict "
                f"rests on: add a _SAMPLED_TESTS entry if it turns on a "
                f"threshold or a probabilistic outcome, or record the number "
                f"here if every trial must succeed"
            )
        if stopped:
            errors.append(
                f"sampled-tests: {lang} — test(s) {stopped} are in _TEST_DRAWS "
                f"but no longer draw fresh entropy.  Delete them (or check the "
                f"detector still matches how they read the CSPRNG)"
            )
        drawn[lang] = found

    # Curated rows must name a test that exists, in a language that has it,
    # and that actually draws -- a row for a test deciding on nothing is stale.
    for (scope, num), (code, rate, reason) in sorted(_SAMPLED_TESTS.items()):
        langs = SHARED_NUMBERING_LANGS if scope == "shared" else (scope,)
        if scope != "shared" and scope not in NUMBERED_TEST_FILES:
            errors.append(f"sampled-tests: _SAMPLED_TESTS key names unknown "
                          f"scope {scope!r}")
            continue
        for lang in langs:
            if num not in numbers.get(lang, []):
                errors.append(
                    f"sampled-tests: _SAMPLED_TESTS[{scope!r}, {num}] names a "
                    f"test {lang} does not have — the row is stale, or the "
                    f"scope should be one language rather than 'shared'"
                )
            elif num not in drawn.get(lang, []):
                errors.append(
                    f"sampled-tests: _SAMPLED_TESTS[{scope!r}, {num}] is "
                    f"curated as sampled, but {lang}'s [{num}] draws no fresh "
                    f"entropy — delete the row, or the detector has gone stale"
                )
        if code not in ("exact", "negligible", "replicated", "follows"):
            errors.append(f"sampled-tests: [{num}] has unknown verdict code "
                          f"{code!r}")
        if rate is not None and not isinstance(rate, float) and rate != "derived":
            errors.append(
                f"sampled-tests: [{num}] has rate {rate!r} — a rate is a float "
                f"or the string 'derived' (TODO #319), never anything else"
            )
        if code == "exact" and rate is not None:
            errors.append(
                f"sampled-tests: [{num}] is 'exact' and carries a rate — an "
                f"exact verdict holds with probability 1, so a rate means it "
                f"is really one of the other three"
            )
        if code != "exact" and rate is None:
            errors.append(
                f"sampled-tests: [{num}] is {code!r} with no rate.  Every "
                f"non-exact entry owes a DERIVED rate or, if the rate is not "
                f"the binding consideration, an argument recorded as one"
            )
        if not reason or len(reason) < 40:
            errors.append(f"sampled-tests: [{num}] needs a reason saying what "
                          f"its verdict rests on")

    # The out-of-scope rows invalidate the same way.
    for (scope, num), reason in sorted(_SAMPLED_TEST_CONSTANT.items()):
        langs = SHARED_NUMBERING_LANGS if scope == "shared" else (scope,)
        for lang in langs:
            if num not in numbers.get(lang, []):
                errors.append(
                    f"sampled-tests: _SAMPLED_TEST_CONSTANT[{scope!r}, {num}] "
                    f"names a test {lang} does not have"
                )
        if (scope, num) in _SAMPLED_TESTS:
            errors.append(
                f"sampled-tests: [{num}] is in BOTH _SAMPLED_TESTS and "
                f"_SAMPLED_TEST_CONSTANT — it cannot both decide on a sample "
                f"and draw nothing that reaches its verdict"
            )

    # TODO #319: a row that has a formula has its rate DERIVED here, per port,
    # and takes its WORST port.  Exhaustive in both directions -- a rated row is
    # either derived or named in _SAMPLED_TEST_RATE_LITERAL with a reason -- so
    # expressing a rate FORCES its literal entry out rather than leaving a stale
    # claim beside a live formula.
    derived, envs = _derive_sampled_rates(errors)
    for key in sorted(_SAMPLED_TEST_RATES, key=str):
        if key not in _SAMPLED_TESTS:
            errors.append(
                f"sampled-rates: _SAMPLED_TEST_RATES{list(key)} names a row "
                f"that _SAMPLED_TESTS does not have — the census row was "
                f"deleted and its formula left behind"
            )
        elif _SAMPLED_TESTS[key][1] != "derived":
            errors.append(
                f"sampled-rates: {list(key)} has a formula but its "
                f"_SAMPLED_TESTS rate is still the literal "
                f"{_SAMPLED_TESTS[key][1]!r} — a derived rate and a curated one "
                f"are two sources of truth, which is the defect this closes"
            )
        if key in _SAMPLED_TEST_RATE_LITERAL:
            errors.append(
                f"sampled-rates: {list(key)} is BOTH derived and declared "
                f"un-derivable — delete the _SAMPLED_TEST_RATE_LITERAL entry, "
                f"which is what expressing the rate is supposed to force"
            )
    for key, (_c, r, _x) in sorted(_SAMPLED_TESTS.items(), key=str):
        if r is None or key in _SAMPLED_TEST_RATES:
            continue
        if key not in _SAMPLED_TEST_RATE_LITERAL:
            errors.append(
                f"sampled-rates: {list(key)} carries a rate with neither a "
                f"formula nor a recorded reason it cannot have one.  Add a "
                f"_SAMPLED_TEST_RATES entry, or say in "
                f"_SAMPLED_TEST_RATE_LITERAL why the number is hand-computed"
            )
        elif len(_SAMPLED_TEST_RATE_LITERAL[key][-1]) < 40:
            errors.append(f"sampled-rates: {list(key)} needs a reason its rate "
                          f"cannot be derived")
    for key in sorted(_SAMPLED_TEST_RATE_LITERAL, key=str):
        if key not in _SAMPLED_TESTS:
            errors.append(
                f"sampled-rates: _SAMPLED_TEST_RATE_LITERAL{list(key)} names a "
                f"row _SAMPLED_TESTS does not have"
            )
        elif _SAMPLED_TESTS[key][1] is None:
            errors.append(
                f"sampled-rates: _SAMPLED_TEST_RATE_LITERAL{list(key)} names a "
                f"row that carries NO rate — an argued row has no number to "
                f"derive, so the entry is stale"
            )

    rated = []
    for key, (_c, r, _x) in sorted(_SAMPLED_TESTS.items(), key=str):
        if r == "derived":
            per_lang = derived.get(key)
            if not per_lang:
                errors.append(
                    f"sampled-tests: {list(key)} declares its rate derived and "
                    f"nothing could be derived — its formula did not resolve, "
                    f"so the budget below is missing a term"
                )
                continue
            # The worst PORT, not the mean: any of the four native-* jobs going
            # red is a red check, so a rate that is safe in three ports and 7.8%
            # in the fourth is a 7.8% rate.
            worst_lang = max(per_lang, key=per_lang.get)
            rated.append((key, per_lang[worst_lang], worst_lang))
        elif r is not None:
            rated.append((key, r, None))
    # TODO #320: the formula's MECHANISM, not just its inputs.
    mechs, mech_rows = check_rate_mechanisms(errors, envs)
    # TODO #323: the two REDUCED harnesses this axis did not read.  Their terms
    # join the SAME sum -- the budget is a JOB-level number and `arm-i386` is
    # as blocking as `native-c`, so a rate summed over four of the six gated
    # harnesses was not the number it was advertised as.
    for key, rate in sorted(_reduced_derive(errors).items()):
        rated.append((key, rate, None))
    total = sum(r for _k, r, _l in rated)
    if total > _SAMPLED_TEST_BUDGET:
        # Resolved values only -- reading the raw table here compared the
        # 'derived' sentinel against floats and RAISED instead of reporting,
        # which the over-budget control found on its first run.
        key, rate, lang = max(rated, key=lambda kv: kv[1])
        where = f"{list(key)}" + (f" in {lang}" if lang else "")
        errors.append(
            f"sampled-tests: the summed false-failure rate is {total:.2e} per "
            f"run, over the budget of {_SAMPLED_TEST_BUDGET:.0e}.  Replicate "
            f"the largest contributor ({where} at {rate:.1e}) on TODO #299's "
            f"pattern rather than raising the budget"
        )
    return drawn, total, len(rated), mechs, mech_rows

def check_shared_numbering(errors, numbers):
    langs = [l for l in SHARED_NUMBERING_LANGS if numbers.get(l)]
    if len(langs) < 2:
        return
    union = set()
    for l in langs:
        union |= set(numbers[l])
    for l in langs:
        missing = sorted(union - set(numbers[l]))
        if missing:
            others = ", ".join(x for x in SHARED_NUMBERING_LANGS if x != l)
            errors.append(
                f"{l}: missing numbered test(s) {missing} that at least one of {others} has — "
                f"C/Go/Python share one numbering convention (CLAUDE.md's Testing section), so "
                f"a number present in one of them must be present in all three unless the test "
                f"was deliberately retired everywhere at once"
            )


# ── Part 3: suite-internal (non-CLI) primitive manifest ─────────────────
# C/Go/Python each keep their whole suite in one file, so a single path
# suffices; Java (bindings/java/herradurakex/) is split one class per
# protocol family instead, so its entry is every *.java SUITE file in that
# directory concatenated — a marker regex can then target whichever class
# actually holds it (Hcred.java, Herradura.java, Xmss.java, Ratchet.java,
# ...) without SUITE_FILES itself needing to know which one.
#
# JAVA_NON_SUITE, and why it is not just tidiness (TODO #261, v6.1.0).  The
# Java entry used to be *every* .java file in the directory, which quietly
# included HerraduraCli.java, Codec.java and the three test drivers.  That is
# the exact hole `rnl-validate-m-blind`'s comment describes from the other
# side: Python's copy of that validator lived in `HerraduraCli/herradura.py`
# and not in the suite, so the entry had to be "deliberately anchored at the
# SUITE files" to catch it — while the same manifest would have scored a
# Java primitive found ONLY in HerraduraCli.java as present.  The layers are
# now separated in both directions.  Codec.java is excluded on the same
# where-do-the-others-keep-it rule, not as a judgement about its contents:
# C and Python keep their codecs in HerraduraCli/ (`herradura_codec.h`,
# `codec.py`), so wire-format code is CLI-layer everywhere else and a
# manifest reading it here would compare unlike trees.
JAVA_NON_SUITE = {
    "HerraduraCli.java",   # CLI layer; C/Go/Python's equivalents live in HerraduraCli/
    "Codec.java",          # PEM/DER wire format; ditto (herradura_codec.h, codec.py)
    "SelfTest.java",       # test driver, counted by Part 1 instead
    "Bench.java",          # benchmark driver (TODO #333), counted by Part 1
                           # instead -- the Java counterpart of
                           # CryptosuiteTests/Herradura_tests.{c,go,py}'s
                           # [32]-[43]+[54] half, which lives outside every
                           # port's suite file for the same reason
    "Demo.java",           # suite walkthrough
    "CodecTest.java",      # test driver
    "KatVerify.java",      # KAT consumer, the Java counterpart of KAT/verify_kat.go
    "VerifyBitArray.java", # KAT/bitarray.json consumer (TODO #314 pass 5), the
                           # Java counterpart of KAT/verify_bitarray_{c.c,go.go,py.py}
    "Json.java",           # the dependency-free JSON reader those two share;
                           # extracted from KatVerify when a second one needed it
}

SUITE_FILES = {
    "c": os.path.join(REPO, "herradura.h"),
    "go": os.path.join(REPO, "herradura", "herradura.go"),
    "python": os.path.join(REPO, "Herradura cryptographic suite.py"),
    "java": sorted(
        os.path.join(REPO, "bindings", "java", "herradurakex", f)
        for f in os.listdir(os.path.join(REPO, "bindings", "java", "herradurakex"))
        if f.endswith(".java") and f not in JAVA_NON_SUITE
    ),
}

# id -> {lang: marker_regex} — a language absent from the dict, or whose
# regex doesn't match, is a finding unless the whole entry carries
# "acknowledged": "<reason>" (then the entry is documented-non-parity, not
# a silent gap, and is skipped). Regexes are matched with re.M against the
# whole file named in SUITE_FILES for that language.
#
# A Java marker may be written "File.java::<regex>" to restrict the search to
# one class.  Java's suite is many files concatenated here, so an unqualified
# short method name (`prove(`, `verify(`, `keygen(`) collides across classes;
# the uniqueness check in check_primitives() rejects such a marker outright,
# and the file prefix is the cheap way to keep the regex readable instead of
# growing it a full argument list.  It is also load-bearing on its own: it
# pins WHICH class holds the primitive, so moving a method between classes is
# a reported finding rather than a silent relocation.
PRIMITIVES = {
    "hcred-zkboo": {
        "c": r"static int hcred_prove\(",
        "go": r"func HcredProve\(",
        "python": r"^def hcred_prove\(",
        "java": r"public static Proof prove\(",
    },
    "hcred-kkw": {
        # TODO #261's seed case: Python-only until v5.5.0-v5.7.0 ported it
        # to Go, C and Java in turn. Kept here as the permanent regression
        # guard for the exact gap the item was filed over.
        "c": r"static int hcred_prove_kkw\(",
        "go": r"func HcredProveKkw\(",
        "python": r"^def hcred_prove_kkw\(",
        "java": r"public static HcredKkwProof proveKkw\(",
    },
    "hcred-stmt-hash": {
        # TODO #261 (v6.0.3), found while working #266. The statement digest
        # HCRED binds a proof to: HFSCX-256 over (m_poly, C_poly, seed_H,
        # syndrome, n, msg). BOTH hcred-zkboo and hcred-kkw call it, in all
        # four languages -- 5 to 7 call sites each, including the credential
        # issuance digest -- so the two entries above cover the two prove
        # paths while leaving the one thing they agree on unguarded.
        #
        # It is the internal-derivation class this manifest exists for: no
        # --algo tag reaches it, and a language that changed its field order,
        # its length prefixes or its domain separator would still round-trip
        # perfectly against ITSELF and fail only against the other three. That
        # is not hypothetical here -- KAT/hcred_kkw.json (TODO #266) is a
        # cross-language vector whose acceptance depends entirely on the four
        # implementations hashing the statement identically, and the one
        # divergence found while building it (C stores the syndrome in the
        # reverse byte order of Python/Go's big-endian integer, un-reversed
        # inside this very function) surfaced as C rejecting Python's
        # transcript with nothing pointing at the cause.
        #
        # Java's is package-private where the other three are file-local or
        # unexported; the regex matches the declaration as written rather
        # than requiring a visibility the port has no reason to widen.
        "c": r"static void hcred_stmt_hash\(",
        "go": r"func hcredStmtHash\(",
        "python": r"^def _hcred_stmt_hash\(",
        "java": r"static byte\[\] stmtHash\(",
    },
    # The two verify counterparts, added in the same v6.0.3 pass and for the
    # same reason the stmt-hash entry above exists: `hcred-zkboo` and
    # `hcred-kkw` each named only their PROVE entry point, so half of each
    # pair was guarded. Verify is the half that matters more -- a prover that
    # disappears is a build error in its own language, while a verifier that
    # drifts accepts or rejects the OTHER three languages' proofs, which is
    # what KAT/hcred_kkw.json (TODO #266) is a vector for. One entry per
    # direction, following hske-encrypt-masked / hske-decrypt-masked.
    "hcred-zkboo-verify": {
        "c": r"static int hcred_verify\(",
        "go": r"func HcredVerify\(",
        "python": r"^def hcred_verify\(",
        # Anchored on the signature, not just the name: bare
        # `public static boolean verify(` matches SIX classes (HpksT,
        # SternRing, Wots, Xmss, ZkpNl as well as Hcred), and SUITE_FILES
        # concatenates every *.java, so the loose form would have kept
        # passing with Hcred.verify deleted outright. See the uniqueness
        # check in check_primitives() below, which now fails on this class.
        "java": r"public static boolean verify\(int\[\] mPoly, int\[\] cPoly, "
                r"BigInteger seedH, BigInteger ySynd, Proof proof",
    },
    "hcred-kkw-verify": {
        "c": r"static int hcred_verify_kkw\(",
        "go": r"func HcredVerifyKkw\(",
        "python": r"^def hcred_verify_kkw\(",
        "java": r"public static boolean verifyKkw\(",
    },
    # The next three entries are TODO #261's first pass at extending the
    # manifest beyond its hcred-kkw seed (SecurityProofs-*.md's 78.x
    # numbering). All were already at four-language parity except
    # fscx-revolve-masked, ported to Java in this pass.
    "haccum": {
        # Merkle accumulator (78.J): checks haccum_verify, the security-
        # critical member of the leaf/node/root/prove/verify family.
        # In Java it lives inside Xmss.java (its only caller) rather than
        # a standalone module, but is public (TODO #261) like the other
        # three languages' top-level functions.
        #
        # This entry used to justify naming only verify by saying "the other
        # four move in lockstep with it in every language's history". v6.0.4
        # tested that rather than inheriting it, because the identical
        # assumption about hcred_prove/hcred_verify turned out to be wrong
        # one entry above. Here it HOLDS -- all four members are at
        # four-language parity, byte-identical in construction (leaf =
        # 0x00||data, node = 0x01||left||right, right-padded with zero
        # hashes to the next power of two, empty tree = 32 zero bytes; C
        # reaches that last case without an explicit n == 0 guard and lands
        # on the same answer) -- but they get their own entries below
        # anyway, since "verified once in 2026" is not a guard.
        "c": r"static int haccum_verify\(",
        "go": r"func HaccumVerify\(",
        "python": r"^def haccum_verify\(",
        "java": r"public static boolean haccumVerify\(",
    },
    # ── TODO #261 (v6.0.4): the haccum family's other four members ───────
    # Unlike the validators below, these ARE behaviourally covered already:
    # CliTest/test_cross_lang_matrix.sh runs a 4x4 hpks-xmss sign/verify
    # matrix, and an XMSS signature is a haccum root plus an authentication
    # path, so all 16 ordered pairs agreeing means leaf, node, root and
    # prove agree across the four languages. These entries are therefore
    # regression guards in the ordinary sense, not gap-finders -- their
    # value is that the matrix would report a haccum divergence as "hpks-xmss
    # go-sign -> java-verify FAILED", pointing at the signature scheme
    # rather than at the accumulator underneath it.
    "haccum-leaf": {
        "c": r"static inline void haccum_leaf\(",
        "go": r"func HaccumLeaf\(",
        "python": r"^def haccum_leaf\(",
        "java": r"public static byte\[\] haccumLeaf\(",
    },
    "haccum-node": {
        "c": r"static inline void haccum_node\(",
        "go": r"func HaccumNode\(",
        "python": r"^def haccum_node\(",
        "java": r"public static byte\[\] haccumNode\(",
    },
    "haccum-root": {
        "c": r"static void haccum_root\(",
        "go": r"func HaccumRoot\(",
        "python": r"^def haccum_root\(",
        "java": r"public static byte\[\] haccumRoot\(",
    },
    "haccum-prove": {
        "c": r"static uint8_t \*haccum_prove\(",
        "go": r"func HaccumProve\(",
        "python": r"^def haccum_prove\(",
        "java": r"public static List<byte\[\]> haccumProve\(",
    },
    # ── TODO #261 (v6.0.4): the three input validators ───────────────────
    # These are the manifest's sharpest case, and the reason to prefer them
    # over the rest of the unguarded sweep. A validator only ever REJECTS
    # inputs that a correct test never produces, so its absence is invisible
    # to every behavioural test in the repo: delete gf_pub_is_valid from one
    # language and `CliTest/test_cross_lang_matrix.sh`, the KAT vectors and
    # all 181 numbered tests still pass, because every artifact they exchange
    # is well-formed by construction. `spec/generate_spec.py --check` cannot
    # see them either -- no `--algo` tag reaches a validator. A manifest entry
    # is the only mechanical guard available for this class.
    #
    # All three were confirmed at four-language parity in this pass on
    # BEHAVIOUR, not just presence: same predicate, same thresholds
    # (QCMDPC_MAX_MULT = 5 in all four; delta(B) in {0, 2^(n-1)} in all four).
    "gf-pub-is-valid": {
        # Rejects the additive zero and the multiplicative identity as a peer
        # GF(2^n)* public element -- pub = 1 makes pub^e == 1 for every e, so
        # an attacker-chosen (s, R = g^s) verifies against any message under
        # HPKS, and HKEX-GF/HPKE collapse likewise.
        #
        # One representational difference, deliberately not flattened: Java
        # masks to N bits first (BigInteger is unbounded where the other three
        # hold an n-bit BitArray), which makes it strictly stricter -- an
        # over-wide value congruent to 1 is rejected there and would be
        # accepted by the others if one could ever be constructed. The regexes
        # check the function, not the arithmetic; nothing here depends on the
        # difference.
        "c": r"static int gf_pub_is_valid\(",
        "go": r"func GfPubIsValid\(",
        "python": r"^def gf_pub_is_valid\(",
        "java": r"public static boolean gfPubIsValid\(",
    },
    "nl-v2-key-is-valid": {
        # Rejects NL-FSCX v2 keys whose permutation degenerates to affine,
        # i.e. delta(B) in {0, 2^(n-1)} -- an exact characterisation of the
        # AFFINE class only, not of every differentially weak key (TODO #253
        # found a wider class this deliberately does not screen). C fixes the
        # width at 256 where Go carries b.size; that is the same
        # compile-time-vs-runtime split TODO #266 recorded for HCRED_N, and
        # is harmless here because C's whole suite is 256-bit.
        "c": r"static int nl_v2_key_is_valid\(",
        "go": r"func NlV2KeyIsValid\(",
        "python": r"^def nl_v2_key_is_valid\(",
        "java": r"public static boolean nlV2KeyIsValid\(",
    },
    "qcmdpc-key-is-strong": {
        # QC-MDPC weak-key screen (TODO #235 Part 1): rejects and redraws any
        # private polynomial whose distance spectrum exceeds multiplicity 5,
        # making the entire measured DFR tail unreachable from keygen.
        #
        # SCOPE, so nobody "completes" this by accident: it screens KEYGEN
        # only. Nothing in the PEM decode path checks an IMPORTED key's
        # spectrum, in any of the four languages, and that is a recorded
        # position rather than an oversight -- a supplied arithmetic-
        # progression key fails its own decapsulations, which is a
        # self-inflicted denial of service and not a confidentiality break
        # (SecurityProofsCode/qcmdpc_dfr_weak_keys.py §4).
        #
        # It is also the one entry in this group with NO test behind it in
        # ANY language -- a four-way absence of exactly the shape v5.8.7
        # found for rnl_validate_m_blind before it became test [49]/[27].
        # This entry guards that the function exists; nothing yet guards that
        # it still screens correctly.
        "c": r"static int qcmdpc_key_is_strong\(",
        "go": r"func QcMdpcKeyIsStrong\(",
        "python": r"^def qcmdpc_key_is_strong\(",
        "java": r"public static boolean qcmdpcKeyIsStrong\(",
    },
    "ratchet": {
        # Forward-secret ratchet (78.C): checks ratchet_advance, the
        # step that must erase superseded state (SecurityProofs-5 §11.8.3).
        "c": r"static inline void ratchet_advance\(",
        "go": r"func RatchetAdvance\(",
        "python": r"^def ratchet_advance\(",
        "java": r"static Object\[\] advance\(",
    },
    "fscx-revolve-masked": {
        # 78.H, Boolean masking via GF(2)-linearity of M. Absent from Java
        # until TODO #261 (v5.8.0) — Herradura.java now carries
        # fscxRevolveMasked/hskeEncryptMasked/hskeDecryptMasked, ported
        # from herradura.h/herradura.go/the Python suite.
        "c": r"static inline void fscx_revolve_masked\(",
        "go": r"func FscxRevolveMasked\(",
        "python": r"^def fscx_revolve_masked\(",
        "java": r"public static BitArray fscxRevolveMasked\(",
    },
    "hske-encrypt-masked": {
        "c": r"static inline void hske_encrypt_masked\(",
        "go": r"func HskeEncryptMasked\(",
        "python": r"^def hske_encrypt_masked\(",
        "java": r"public static Masked hskeEncryptMasked\(",
    },
    "hske-decrypt-masked": {
        "c": r"static inline void hske_decrypt_masked\(",
        "go": r"func HskeDecryptMasked\(",
        "python": r"^def hske_decrypt_masked\(",
        "java": r"public static Masked hskeDecryptMasked\(",
    },
    "hpkst-aggregate-pubkeys": {
        # HPKS-T (TODO #98/#106/#260) MuSig2-style key aggregation
        # (mu_j = HFSCX-256(L||C_j) mod ord; C_agg = prod C_j^mu_j) — the
        # rogue-key-binding step, not the sign/verify entry points, which
        # CLI's threshold-* subcommands already exercise in all four
        # languages (TODO #261's "lower priority than the non-CLI class"
        # note). All four already had this at parity; this entry is the
        # mechanical guard so a future change to one language's coefficient
        # derivation can't silently diverge from the other three.
        "c": r"static void _hpkst_aggregate\(",
        "go": r"func HpkstAggregatePublickeys\(",
        "python": r"^def hpkst_aggregate_pubkeys\(",
        "java": r"public static Aggregate aggregatePublicKeys\(",
    },
    "oprf-hash-to-field": {
        # OPRF (TODO #80/#201) hash-to-field: HFSCX-256(data) mapped to a
        # non-zero element of GF(2^n)*, with the 0 -> 1 remap on collision.
        # Called from both oprf_blind and oprf_direct but is not itself a
        # CLI subcommand (oprf-blind/-eval/-unblind are), so — like
        # hpkst-aggregate-pubkeys above — it's the internal-derivation class
        # TODO #261 exists to catch, not the already-CLI-reachable class.
        "c": r"static void oprf_hash_to_field\(",
        "go": r"func oprfHashToField\(",
        "python": r"^def _oprf_hash_to_field\(",
        "java": r"static BigInteger hashToField\(",
    },
    "hpake-derive-zkp-witness": {
        # aPAKE (TODO #80/#201/#203) ZKBoo witness derivation: lower bits of
        # HFSCX-256(oprf_out || "ZKP-A"), domain-separating the ZKBoo witness
        # from the raw OPRF output. Internal to hpake_register/login_demo,
        # which are reachable only via the CLI's pake-register/pake-demo
        # subcommands, not this helper directly.
        "c": r"static uint32_t _hpake_zkp_witness\(",
        "go": r"func hpakeDeriveZkpWitness\(",
        "python": r"^def _hpake_derive_zkp_witness\(",
        "java": r"static BigInteger deriveZkpWitness\(",
    },
    "hpake-rnl-kdf": {
        # aPAKE (TODO #80/#201/#203) session KDF applied to the HKEX-RNL
        # raw shared secret before it's used to authenticate/derive the
        # session key. Same internal-helper class as the two entries above.
        "c": r"static void _hpake_rnl_kdf\(",
        "go": r"func hpakeRnlKdf\(",
        "python": r"^def _hpake_rnl_kdf\(",
        "java": r"static byte\[\] rnlKdf\(",
    },
    # ── TODO #261 (v6.0.0): the tags Java was missing, now ported ────────
    # These ARE CLI-reachable, so generate_spec.py's cli_support column is the
    # primary guard and CliTest/test_zkp_hybrid_family.sh is the behavioural
    # one.  They are listed here too because cli_support checks each CLI's
    # DISPATCH source, not the suite behind it: a CLI that still parsed the tag
    # while its primitive was deleted or renamed would keep that column green.
    #
    # `hybrid-rnl-stern`'s combiner is deliberately NOT here.  It lives in the
    # CLI layer in three of the four languages (herradura_cli.c, herradura.py),
    # not in the suite files this manifest reads, so an entry for it would be
    # checking the wrong files.  The 4x4 session-key comparison in
    # test_zkp_hybrid_family.sh is what guards it.
    "zkp-nl-keygen": {
        "c": r"static void zkp_nl_keygen\(",
        "go": r"func ZkpNlKeygen\(",
        "python": r"^def zkp_nl_keygen\(",
        "java": r"public static BigInteger\[\] keygen\(",
    },
    "zkp-nl-prove": {
        # ZKBoo (nl-zkboo).
        "c": r"static ZkpNlRound \*zkp_nl_prove\(",
        "go": r"func ZkpNlProve\(",
        "python": r"^def zkp_nl_prove\(",
        "java": r"public static List<ProofRound> prove\(",
    },
    "zkp-nl-prove-pp": {
        # ZKB++ (nl-zkbpp).  Absent from Java until v6.0.0 -- ZkpNl.java's class
        # doc comment declared it, and hpks-zkp-nl, explicitly out of scope.
        "c": r"static ZkpNlPpRound \*zkp_nl_pp_prove\(",
        "go": r"func ZkpNlProvepp\(",
        "python": r"^def zkp_nl_prove_pp\(",
        "java": r"public static List<PpRound> provePp\(",
    },
    "rnl-sigma-sign": {
        # ZKP-RNL Sigma-protocol (rnl-sigma).  No Java port at any layer before
        # v6.0.0, and nothing in the Java tree recorded the omission.
        "c": r"static int rnl_sigma_sign\(",
        "go": r"func RnlSigmaSign\(",
        "python": r"^def rnl_sigma_sign\(",
        "java": r"public static SigmaProof rnlSigmaSign\(",
    },
    "rnl-validate-m-blind": {
        # TODO #261 (v5.8.7): the peer-m_blind substitution guard -- reject a
        # sparse (nz < n/4) or clustered (range < q/4) polynomial before using
        # it, since m_blind's uniformity rests entirely on the initiator's RNG
        # (TODO #89) and the responder cannot verify the draw itself.
        #
        # NOT a missing-algorithm gap but a PLACEMENT one, which is a shape this
        # manifest had not caught before: C, Go and Java all had it in the SUITE,
        # where any caller reaches it; Python had it only as a private copy inside
        # HerraduraCli/herradura.py, so the pedagogical suite path (what
        # docs/examples/hello_herradura.py shows) could not reach it, and the
        # thresholds lived in two places in that one language.  The regexes below
        # are therefore deliberately anchored at the SUITE files -- pointing
        # Python's at the CLI would have made the entry pass while the asymmetry
        # stood.
        "c": r"static int rnl_validate_m_blind\(",
        "go": r"func RnlValidateMBlind\(",
        "python": r"^def rnl_validate_m_blind\(",
        "java": r"public static boolean rnlValidateMBlind\(",
    },
    "hpake-contributory-kdf": {
        # TODO #263: aPAKE's ephemeral HKEX-RNL exchange inside
        # hpake_login_demo binds K_raw to per-session nonces from both
        # parties before it's used for the ZKBoo auth binding or the
        # session key -- the same TODO #89 RNG-hardening construction plain
        # `kex --algo hkex-rnl` applies (HFSCX-256(K_raw||n_A||n_B)).  C had
        # this from the start (reusing rnl_contributory_kdf); Go, Python and
        # Java derived the session key straight off raw K_raw until #263
        # ported it in each.
        "c": r"rnl_contributory_kdf\(K_kdf_c,",
        "go": r"func hpakeContributoryKdf\(",
        "python": r"^def _hpake_contributory_kdf\(",
        "java": r"rnlContributoryKdf\(agreeC\.key,",
    },
    # ═══ TODO #261 (v6.1.0): the manifest extended over the WHOLE internal
    #     surface, and Part 4 below made that completeness mechanical. Up to
    #     v6.0.5 every entry above was added by a one-time read of the source
    #     tree — the thing #261's acceptance criterion says not to rely on —
    #     which is why the item stayed open through eleven releases that each
    #     added to it. The entries from here down were not chosen: the census
    #     enumerated what the four suites contain, subtracted what their own
    #     CLIs call and what the manifest already named, and these are what
    #     was left. Adding a suite-internal primitive in any language now
    #     fails CI until it is filed here or given a CENSUS_EXEMPT reason.
    # ── HCRED credential circuit internals (TODO #261, v6.1.0) ────────────
    # The statement, witness, commitment and challenge steps under hcred-zkboo.
    # None is reachable through an --algo tag: `hcred-prove` names the whole proof,
    # and every step below it is a byte layout four implementations have to agree
    # on. KAT/hcred_kkw.json is a vector for the KKW path only, so these entries
    # are the ZKBoo path's mechanical guard.
    "hcred-phi": {
        "c": r"static void hcred_phi\(",
        "go": r"^func HcredPhi\(",
        "python": r"^def hcred_phi\(",
        "java": r"Hcred.java::static BigInteger phi\(",
    },
    "hcred-syndrome": {
        "c": r"static void hcred_syndrome\(",
        "go": r"^func HcredSyndrome\(",
        "python": r"^def hcred_syndrome\(",
        "java": r"Hcred.java::public static BigInteger syndrome\(",
    },
    "hcred-witness": {
        "c": r"static int _hcred_witness\(",
        "go": r"^func hcredWitness\(",
        "python": r"^def _hcred_witness\(",
        "java": r"Hcred.java::private static Witness prepareWitness\(",
    },
    "hcred-commit": {
        "c": r"static void _hcred_commit\(",
        "go": r"^func hcredCommit\(",
        "python": r"^def _hcred_commit\(",
        "java": r"Hcred.java::private static byte\[\] commit\(",
    },
    "hcred-challenges": {
        "c": r"static void _hcred_challenges\(",
        "go": r"^func hcredChallenges\(",
        "python": r"^def _hcred_challenges\(",
        "java": r"Hcred.java::private static int\[\] deriveChallenges\(",
    },
    "hcred-outputs": {
        # C names the per-party output-share computation _hcred_party_out; the
        # entry carries that name. No absence
        "c": r"static void _hcred_party_out\(",
        "go": r"^func hcredOutputs\(",
        "python": r"^def _hcred_outputs\(",
        "java": r"Hcred.java::private static Outputs computeOutputs\(",
    },
    "hcred-outputs-ser": {
        "c": r"static void _hcred_outs_ser\(",
        "go": r"^func HcredOutputsSer\(",
        "python": r"^def _hcred_outputs_ser\(",
        "java": r"Hcred.java::static byte\[\] outputsSer\(",
    },
    "hcred-ser": {
        "c": r"static void hcred_ser\(",
        "go": r"^func hcredSer\(",
        "python": r"^def _hcred_ser\(",
        "java": r"Hcred.java::private static byte\[\] ser\(",
    },
    "hcred-mpc-round": {
        "acknowledged":
            "C and Go have no separately-named MPC round: both inline the per- "
            "round share update inside hcred_prove/HcredProve. Python "
            "(_hcred_mpc_round) and Java (Hcred.mpcRound) factor it out. The "
            "round itself is covered four ways by KAT/hcred_kkw.json and the "
            "hcred-zkboo entries",
        "python": r"^def _hcred_mpc_round\(",
        "java": r"Hcred.java::private static McpRoundResult mpcRound\(",
    },
    "hcred-bind-msg": {
        "acknowledged":
            "C and Go bind the credential message in a named helper; Python and "
            "Java inline the same HFSCX-256 call inside "
            "hcred_issue/Hcred.issue. Byte-identical by KAT/hcred_kkw.json's "
            "issuance digest, which all four consume",
        "c": r"static void _hcred_bind_msg\(",
        "go": r"^func HcredBindMsg\(",
    },
    "hcred-user-keygen": {
        "c": r"static void hcred_user_keygen\(",
        "go": r"^func HcredUserKeygen\(",
        "python": r"^def hcred_user_keygen\(",
        "java": r"Hcred.java::public static UserKeypair userKeygen\(",
    },
    "hcred-issue": {
        "c": r"static void hcred_issue\(",
        "go": r"^func HcredIssue\(",
        "python": r"^def hcred_issue\(",
        "java": r"Hcred.java::public static Stern\.SternSignature issue\(",
    },
    "hcred-cred-verify": {
        "c": r"static int hcred_cred_verify\(",
        "go": r"^func HcredCredVerify\(",
        "python": r"^def hcred_cred_verify\(",
        "java": r"Hcred.java::public static boolean credVerify\(",
    },
    # ── HCRED-KKW preprocessing internals (TODO #261, v6.1.0) ─────────────
    # The cut-and-choose machinery under hcred-kkw/hcred-kkw-verify. Three of the
    # four ports carried a real transcription bug in exactly this layer (TODO #266:
    # an inverted aux-reveal condition in Go, an under-allocated commitment buffer
    # and a flipped bit convention in C), which is why the seed-tree, party and
    # commitment steps each get their own entry rather than riding on proveKkw.
    "hcred-kkw-gates": {
        "c": r"static void hcred_kkw_gates\(",
        "go": r"^func hcredKkwGates\(",
        "python": r"^def _hcred_kkw_gates\(",
        "java": r"Hcred.java::private static KkwGate\[\] kkwGates\(",
    },
    "hcred-kkw-tree": {
        "c": r"static void hcred_kkw_tree\(",
        "go": r"^func hcredKkwTree\(",
        "python": r"^def _hcred_kkw_tree\(",
        "java": r"Hcred.java::private static byte\[\]\[\] kkwTree\(",
    },
    "hcred-kkw-tree-open": {
        "c": r"static int hcred_kkw_tree_open\(",
        "go": r"^func hcredKkwTreeOpen\(",
        "python": r"^def _hcred_kkw_tree_open\(",
        "java": r"Hcred.java::private static List<KkwPathEntry> kkwTreeOpen\(",
    },
    "hcred-kkw-tree-recover": {
        "c": r"static void hcred_kkw_tree_recover\(",
        "go": r"^func hcredKkwTreeRecover\(",
        "python": r"^def _hcred_kkw_tree_recover\(",
        "java": r"Hcred.java::private static void kkwTreeRecover\(",
    },
    "hcred-kkw-party": {
        "c": r"static void hcred_kkw_party\(",
        "go": r"^func hcredKkwParty\(",
        "python": r"^def _hcred_kkw_party\(",
        "java": r"Hcred.java::private static KkwShares kkwParty\(",
    },
    "hcred-kkw-pre": {
        "c": r"static void hcred_kkw_pre\(",
        "go": r"^func hcredKkwPre\(",
        "python": r"^def _hcred_kkw_pre\(",
        "java": r"Hcred.java::private static KkwPre kkwPre\(",
    },
    "hcred-kkw-state-com": {
        "c": r"static void hcred_kkw_state_com\(",
        "go": r"^func hcredKkwStateCom\(",
        "python": r"^def _hcred_kkw_state_com\(",
        "java": r"Hcred.java::private static byte\[\] kkwStateCom\(",
    },
    "hcred-kkw-outmap": {
        "c": r"static void hcred_kkw_outmap\(",
        "go": r"^func hcredKkwOutmap\(",
        "python": r"^def _hcred_kkw_outmap\(",
        "java": r"Hcred.java::private static int\[\] kkwOutmap\(",
    },
    "hcred-kkw-targets": {
        "c": r"static void hcred_kkw_targets\(",
        "go": r"^func hcredKkwTargets\(",
        "python": r"^def _hcred_kkw_targets\(",
        "java": r"Hcred.java::private static int\[\] kkwTargets\(",
    },
    "hcred-kkw-fs-ints": {
        "c": r"static void hcred_kkw_fs_ints\(",
        "go": r"^func hcredKkwFsInts\(",
        "python": r"^def _hcred_kkw_fs_ints\(",
        "java": r"Hcred.java::private static int\[\] kkwFsInts\(",
    },
    # ── ZKBoo / ZKB++ internals (nl-zkboo, nl-zkbpp) (TODO #261, v6.1.0) ────
    # The (2,3)-decomposition steps under the two tags Java gained in v6.0.0. The
    # 4x4 matrix in CliTest/test_zkp_hybrid_family.sh is the behavioural guard;
    # these entries say WHICH function each language must still have when a future
    # refactor moves the matrix's failure somewhere less specific.
    "zkp-nl-h": {
        "acknowledged":
            "the generic ZKBoo domain hash. C has no variadic equivalent -- it "
            "builds each commitment buffer explicitly in zkp_nl_commit (see "
            "zkpp-commit) -- so there is no C function to name, not a missing "
            "step",
        "go": r"^func zkpNlH\(",
        "python": r"^def _zkp_nl_h\(",
        "java": r"ZkpNl.java::private static byte\[\] h\(",
    },
    "zkp-nl-prg-bit": {
        "c": r"static int zkp_nl_prg_bit\(",
        "go": r"^func zkpNlPrgBit\(",
        "python": r"^def _zkp_nl_prg_bit\(",
        "java": r"ZkpNl.java::private static int prgBit\(",
    },
    "zkp-nl-rol": {
        "c": r"static uint64_t zkp_nl_rol\(",
        "go": r"^func zkpNlRol\(",
        "python": r"^def _zkp_nl_rol\(",
        "java": r"ZkpNl.java::static BigInteger rol\(",
    },
    "zkp-nl-eval-circuit": {
        # C names the three-party circuit evaluation zkp_nl_eval_3p; the entry
        # carries that name. No absence
        "c": r"static void zkp_nl_eval_3p\(",
        "go": r"^func zkpNlEvalCircuit\(",
        "python": r"^def _zkp_nl_evaluate_circuit\(",
        "java": r"ZkpNl.java::private static CircuitResult evaluateCircuit\(",
    },
    "zkp-nl-pack-view": {
        "acknowledged":
            "Python's _pack_view/_unpack_view are nested inside zkp_nl_prove "
            "rather than module-level, so no top-level marker can name them; "
            "the packing is pinned four ways by "
            "CliTest/test_zkp_hybrid_family.sh's 4x4 nl-zkboo matrix",
        "c": r"static void zkp_nl_pack_view\(",
        "go": r"^func zkpNlPackView\(",
        "java": r"ZkpNl.java::private static byte\[\] packView\(",
    },
    "zkp-nl-unpack-view": {
        "acknowledged":
            "see zkp-nl-pack-view: nested inside zkp_nl_prove in Python",
        "c": r"static void zkp_nl_unpack_view\(",
        "go": r"^func zkpNlUnpackView\(",
        "java": r"ZkpNl.java::private static UnpackedView unpackView\(",
    },
    "zkp-nl-verify": {
        "c": r"static int zkp_nl_verify\(",
        "go": r"^func ZkpNlVerify\(",
        "python": r"^def zkp_nl_verify\(",
        "java": r"ZkpNl.java::public static boolean verify\(",
    },
    "zkp-nl-pp-verify": {
        "c": r"static int zkp_nl_pp_verify\(",
        "go": r"^func ZkpNlVerifypp\(",
        "python": r"^def zkp_nl_verify_pp\(",
        "java": r"ZkpNl.java::public static boolean verifyPp\(",
    },
    "zkpp-derive": {
        "c": r"static void zkpp_derive\(",
        "go": r"^func zkppDerive\(",
        "python": r"^def _zkpp_derive\(",
        "java": r"ZkpNl.java::private static Object\[\] ppDerive\(",
    },
    "zkpp-commit": {
        "c": r"static void zkpp_commit\(",
        "go": r"^func zkppCommit\(",
        "python": r"^def _zkpp_commit\(",
        "java": r"ZkpNl.java::private static byte\[\] ppCommit\(",
    },
    "zkpp-out-share": {
        "c": r"static uint64_t zkpp_out_share\(",
        "go": r"^func zkppOutShare\(",
        "python": r"^def _zkpp_out_share\(",
        "java": r"ZkpNl.java::private static BigInteger ppOutShare\(",
    },
    "zkpp-pack-bits": {
        "c": r"static void zkpp_pack_gate_bits\(",
        "go": r"^func zkppPackGateBits\(",
        "python": r"^def _zkpp_pack_bits\(",
        "java": r"ZkpNl.java::static byte\[\] ppPackBits\(",
    },
    "zkpp-unpack-bits": {
        # C and Go read one gate bit by index where Python and Java unpack the
        # whole vector; same LSB-first-within-a-byte layout either way, verified
        # by reading all four. Paired rather than acknowledged because the thing
        # that must not drift is the LAYOUT, and both shapes commit to it.
        "c": r"static int zkpp_get_gate_bit\(",
        "go": r"^func zkppGetGateBit\(",
        "python": r"^def _zkpp_unpack_bits\(",
        "java": r"ZkpNl.java::static int\[\] ppUnpackBits\(",
    },
    # ── Stern identification internals (TODO #261, v6.1.0) ────────────────
    # Commitment hashing, the H-matrix expansion, syndrome computation and the
    # permutation machinery shared by HPKS-Stern-F, the ring variant and
    # HPKE-Stern. The H-matrix expansion in particular is a wire contract: a
    # language that expanded the seed differently would produce keys the other
    # three cannot verify against, with the failure surfacing as a bad signature.
    "stern-hash": {
        "c": r"static void stern_hash\(",
        "go": r"^func SternHash\(",
        "python": r"^def _stern_hash\(",
        "java": r"Stern.java::static BigInteger sternHash\(",
    },
    "stern-matrix-row": {
        "c": r"static void stern_matrix_row\(",
        "go": r"^func SternMatrixRow\(",
        "python": r"^def _stern_matrix_row\(",
        "java": r"Stern.java::static BigInteger sternMatrixRow\(",
    },
    "stern-build-h": {
        "c": r"static void stern_build_H\(",
        "go": r"^func SternBuildH\(",
        "python": r"^def _stern_build_H\(",
        "java": r"Stern.java::static BigInteger\[\] sternBuildH\(",
    },
    "stern-syndrome-h": {
        "c": r"static void stern_syndrome_H\(",
        "go": r"^func sternSyndromeH\(",
        "python": r"^def _stern_syndrome_H\(",
        "java": r"Stern.java::static BigInteger sternSyndromeH\(",
    },
    "stern-syndrome": {
        "c": r"static void stern_syndrome\(",
        "go": r"^func SternSyndrome\(",
        "python": r"^def _stern_syndrome\(",
        "java": r"Stern.java::public static BigInteger sternSyndrome\(",
    },
    "stern-gen-perm": {
        "c": r"static void stern_gen_perm\(",
        "go": r"^func SternGenPerm\(",
        "python": r"^def _stern_gen_perm\(",
        "java": r"Stern.java::static int\[\] sternGenPerm\(",
    },
    "stern-apply-perm": {
        "c": r"static void stern_apply_perm\(",
        "go": r"^func SternApplyPerm\(",
        "python": r"^def _stern_apply_perm\(",
        "java": r"Stern.java::static BigInteger sternApplyPerm\(",
    },
    "stern-f-keygen": {
        "c": r"static void stern_f_keygen\(",
        "go": r"^func SternFKeygen\(",
        "python": r"^def stern_f_keygen\(",
        "java": r"Stern.java::public static SternKeypair sternFKeygen\(",
    },
    "stern-fs-challenges": {
        "acknowledged":
            "Python derives the Fiat-Shamir challenge string inline in "
            "hpks_stern_f_sign from _stern_hash rather than in a named helper. "
            "The derivation is a wire contract, pinned by "
            "KAT/classical_quartet.json and the 4x4 Stern matrix",
        "c": r"static void stern_fs_challenges\(",
        "go": r"^func sternFsChallenges\(",
        "java": r"Stern.java::private static int\[\] deriveChallenges\(",
    },
    "stern-ring-trit": {
        # TODO #297.  A one-line sampler that had THREE implementations across
        # the four ports while it was written inline in each -- which is the
        # case this manifest exists for, and could not see while the thing had
        # no name.  Extracted in all four at once for that reason.
        "c": r"static int stern_ring_trit\(",
        "go": r"^func sternRingTrit\(",
        "python": r"^def _stern_ring_trit\(",
        "java": r"SternRing.java::private static int ringTrit\(",
    },
    "stern-simulate-round": {
        # C names it stern_ring_simulate; the entry carries that name. No
        # absence
        "c": r"static void stern_ring_simulate\(",
        "go": r"^func sternSimulateRound\(",
        "python": r"^def _stern_simulate_round\(",
        "java": r"SternRing.java::private static Object\[\] simulateRound\(",
    },
    "stern-ring-challenges": {
        "acknowledged":
            "as stern-fs-challenges, for the ring variant: Python inlines the "
            "joint challenge derivation in hpks_stern_ring_sign",
        "c": r"static void stern_ring_challenges\(",
        "go": r"^func sternRingChallenges\(",
        "java": r"SternRing.java::private static int\[\] jointChallenges\(",
    },
    "csprng-weight-t": {
        # C and Go name the weight-t error sampler
        # stern_rand_error/SternRandError rather than after the CSPRNG; the
        # entry carries those names. No absence
        "c": r"static void stern_rand_error\(",
        "go": r"^func SternRandError\(",
        "python": r"^def _csprng_weight_t\(",
        "java": r"Stern.java::static BigInteger csprngWeightT\(",
    },
    # ── QC-MDPC KEM internals (TODO #261, v6.1.0) ─────────────────────────
    # The bit-polynomial arithmetic and BGF decoder under hpke-stern-kem. Note the
    # asymmetry these entries do NOT flag, because it is intended: since TODO #235
    # a decapsulation failure is an implicit rejection, so a divergence here is a
    # SILENT wrong session key rather than an error -- which is why
    # CliTest/lib_dfr.sh compares bytes and why qcmdpc-kem-key is listed.
    "qcp-mul": {
        "c": r"static void qcp_mul\(",
        "go": r"^func QcMdpcMul\(",
        "python": r"^def _qcp_mul\(",
        "java": r"Stern.java::static BigInteger qcpMul\(",
    },
    "qcp-mul-sparse": {
        "c": r"static void qcp_mul_sparse\(",
        "go": r"^func qcpMulSparse\(",
        "python": r"^def _qcp_mul_sparse\(",
        "java": r"Stern.java::static BigInteger qcpMulSparse\(",
    },
    "qcp-inv": {
        "c": r"static int qcp_inv\(",
        "go": r"^func QcMdpcInv\(",
        "python": r"^def _qcp_inv\(",
        "java": r"Stern.java::static BigInteger qcpInv\(",
    },
    "qcprf-refill": {
        "acknowledged":
            "Go implements the QC-MDPC PRF refill as a METHOD on QcMdpcPrf, "
            "which DECL_PATTERNS deliberately does not scan (receiver surface). "
            "Present, not reachable by a top-level marker",
        "c": r"static void qcprf_refill\(",
        "python": r"^def _qcprf_refill\(",
        "java": r"Stern.java::private static byte\[\] refill\(",
    },
    "qcprf-idx-bytes": {
        "c": r"static int qcprf_idx_bytes\(",
        "go": r"^func qcprfIdxBytes\(",
        "python": r"^def _qcprf_idx_bytes\(",
        "java": r"Stern.java::static int idxBytes\(",
    },
    "qcprf-draw": {
        "acknowledged":
            "Go alone needs a top-level entry point into the QC-MDPC index "
            "sampler: its security-test harness is a separate module, where C's "
            "static header, Python's module and Java's package-private nested "
            "class are all readable in place by their own harnesses. The "
            "primitive itself is qcprf_sparse_support / sparse_support / "
            "sparseSupport, a method in three of the four (TODO #277)",
        "go": r"^func QcMdpcPrfDraw\(",
    },
    "qcmdpc-max-multiplicity": {
        "c": r"static int qcmdpc_max_multiplicity\(",
        "go": r"^func qcMdpcMaxMultiplicity\(",
        "python": r"^def _qcmdpc_max_multiplicity\(",
        "java": r"Stern.java::static int qcmdpcMaxMultiplicity\(",
    },
    "qcmdpc-kem-key": {
        "c": r"static void qcmdpc_kem_key\(",
        "go": r"^func qcMdpcKemKey\(",
        "python": r"^def _qcmdpc_kem_key\(",
        "java": r"Stern.java::private static BigInteger qcmdpcKemKey\(",
    },
    "qcmdpc-z-seed": {
        "c": r"static void qcmdpc_z_seed\(",
        "go": r"^func qcMdpcZSeed\(",
        "python": r"^def _qcmdpc_z_seed\(",
        "java": r"Stern.java::private static byte\[\] qcmdpcZSeed\(",
    },
    "qcmdpc-counters": {
        "c": r"static void qcp_upc_planes\(",
        "go": r"^func qcmdpcCounters\(",
        "python": r"^def _qcmdpc_counters\(",
        "java": r"Stern.java::private static BigInteger\[\] qcmdpcCounters\(",
    },
    "qcmdpc-mask-ge": {
        "c": r"static void qcp_mask_ge\(",
        "go": r"^func qcmdpcMaskGe\(",
        "python": r"^def _qcmdpc_mask_ge\(",
        "java": r"Stern.java::private static BigInteger qcmdpcMaskGe\(",
    },
    "qcmdpc-bgf-decode": {
        "c": r"static int qcmdpc_bgf_decode\(",
        "go": r"^func QcMdpcBgfDecode\(",
        "python": r"^def qcmdpc_bgf_decode\(",
        "java": r"Stern.java::static BigInteger\[\] qcmdpcBgfDecode\(",
    },
    "qcmdpc-keygen": {
        "c": r"static void qcmdpc_keygen\(",
        "go": r"^func QcMdpcKeygen\(",
        "python": r"^def qcmdpc_keygen\(",
        "java": r"Stern.java::static QcMdpcKeypair qcmdpcKeygen\(BigInteger "
                r"seedInt",
    },
    "qcmdpc-encap": {
        "c": r"static void qcmdpc_encap\(",
        "go": r"^func QcMdpcEncap\(",
        "python": r"^def qcmdpc_encap\(",
        "java": r"Stern.java::static QcMdpcEncapResult qcmdpcEncap\(BigInteger "
                r"hPub, BigInteger seedInt",
    },
    "qcmdpc-decap-bgf": {
        "c": r"static void qcmdpc_decap_bgf\(",
        "go": r"^func QcMdpcDecapBgf\(",
        "python": r"^def qcmdpc_decap_bgf\(",
        "java": r"Stern.java::public static BigInteger qcmdpcDecapBgf\(",
    },
    # ── WOTS+ / XMSS internals (TODO #261, v6.1.0) ────────────────────────
    # The hash chain, digit encoding and leaf derivation under hpks-wots/hpks-xmss.
    # Behaviourally covered by test_cross_lang_matrix.sh's 4x4 xmss matrix (see the
    # haccum family above, same argument); these entries make a divergence report
    # the chain rather than the signature scheme.
    "wots-h": {
        "c": r"static inline void _wots_h_ba\(",
        "go": r"^func wotsH\(",
        "python": r"^def _wots_h\(",
        "java": r"Wots.java::static BigInteger h\(",
    },
    "wots-chain": {
        "c": r"static inline void _wots_chain_ba\(",
        "go": r"^func wotsChain\(",
        "python": r"^def _wots_chain\(",
        "java": r"Wots.java::static BigInteger chain\(",
    },
    "wots-leaf-seed": {
        "c": r"static inline void _wots_leaf_seed\(",
        "go": r"^func wotsLeafSeed\(",
        "python": r"^def _wots_leaf_seed\(",
        "java": r"Wots.java::static BigInteger leafSeed\(",
    },
    "wots-msg-to-digits": {
        "c": r"static inline void _wots_msg_to_digits\(",
        "go": r"^func wotsMsgToDigits\(",
        "python": r"^def _wots_msg_to_digits\(",
        "java": r"Wots.java::static int\[\] msgToDigits\(",
    },
    "wots-pk-bytes": {
        "c": r"static inline void _wots_pk_bytes\(",
        "go": r"^func wotsPkBytes\(",
        "python": r"^def _wots_pk_bytes\(",
        "java": r"Wots.java::public static byte\[\] pkBytes\(",
    },
    "hpks-wots-recover-pk": {
        "c": r"static inline void hpks_wots_recover_pk\(",
        "go": r"^func HpksWotsRecoverPk\(",
        "python": r"^def hpks_wots_recover_pk\(",
        "java": r"Wots.java::public static BigInteger\[\] recoverPk\(",
    },
    # ── HKEX-RNL / Ring-LWR internals (TODO #261, v6.1.0) ─────────────────
    # Sampling, rounding, lifting and reconciliation. rnl-contributory-kdf below is
    # the entry this whole census was worth writing for -- see its comment.
    "rnl-cbd-poly": {
        "c": r"static void rnl_cbd_poly_dim\(",
        "go": r"^func RnlCBDPoly\(",
        "python": r"^def _rnl_cbd_poly\(",
        "java": r"HerraduraNl.java::public static int\[\] rnlCbdPoly\(",
    },
    "rnl-round": {
        "c": r"static void rnl_round\(",
        "go": r"^func RnlRound\(",
        "python": r"^def _rnl_round\(",
        "java": r"HerraduraNl.java::public static int\[\] rnlRound\(",
    },
    "rnl-lift": {
        "c": r"static void rnl_lift\(",
        "go": r"^func RnlLift\(",
        "python": r"^def _rnl_lift\(",
        "java": r"HerraduraNl.java::public static int\[\] rnlLift\(",
    },
    "rnl-hint": {
        "c": r"static void rnl_hint\(",
        "go": r"^func RnlHint\(",
        "python": r"^def _rnl_hint\(",
        "java": r"HerraduraNl.java::public static int\[\] rnlHint\(",
    },
    "rnl-reconcile-bits": {
        "c": r"static void rnl_reconcile_bits\(",
        "go": r"^func RnlReconcileBits\(",
        "python": r"^def _rnl_reconcile_bits\(",
        "java": r"HerraduraNl.java::public static BigInteger rnlReconcileBits\(",
    },
    "rnl-m-poly": {
        "c": r"static void rnl_m_poly\(",
        "go": r"^func RnlMPoly\(",
        "python": r"^def _rnl_m_poly\(",
        "java": r"HerraduraNl.java::public static int\[\] rnlMPoly\(",
    },
    "rnl-poly-mul": {
        "c": r"static void rnl_poly_mul\(",
        "go": r"^func RnlPolyMul\(",
        "python": r"^def _rnl_poly_mul\(",
        "java": r"HerraduraNl.java::public static int\[\] rnlPolyMul\(",
    },
    "rnl-poly-add": {
        "c": r"static void rnl_poly_add\(",
        "go": r"^func RnlPolyAdd\(",
        "python": r"^def _rnl_poly_add\(",
        "java": r"HerraduraNl.java::public static int\[\] rnlPolyAdd\(",
    },
    "rnl-rand-poly": {
        "c": r"static void rnl_rand_poly\(",
        "go": r"^func RnlRandPoly\(",
        "python": r"^def _rnl_rand_poly\(",
        "java": r"HerraduraNl.java::public static int\[\] rnlRandPoly\(",
    },
    "rnl-ntt": {
        "c": r"static void rnl_ntt\(",
        "go": r"^func rnlNTT\(",
        "python": r"^def _ntt_inplace\(",
        "java": r"HerraduraNl.java::private static void nttInplace\(",
    },
    "rnl-mod-pow": {
        "acknowledged":
            "modular exponentiation over Z_q. Python uses the built-in three- "
            "argument pow(); there is nothing to port and nothing that can "
            "drift",
        "c": r"static uint32_t rnl_mod_pow\(",
        "go": r"^func rnlModPow\(",
        "java": r"HerraduraNl.java::private static long modPow\(",
    },
    "rnl-contributory-kdf": {
        # THE FINDING THIS CENSUS PAID FOR (TODO #261, v6.1.0). HFSCX-256(K_raw
        # || n_A || n_B) -- TODO #89's RNG hardening, and the step that turns the
        # raw Ring-LWR agreement into the session key. It was in the SUITE in C
        # and Java and only in the CLI in Go and Python: the same placement
        # asymmetry v5.8.7 found for rnl-validate-m-blind, one release later and
        # one step more consequential, since that one screens an input and this
        # one derives the key. A suite-only caller in two of the four languages
        # -- the path docs/examples/hello_herradura.py demonstrates -- could
        # finish an HKEX-RNL exchange and then derive the session key some other
        # way. Ported to both suites byte-identically; both CLIs now call it.
        #
        # Note what did NOT catch this: every RNL interop script passed before
        # the move and after it, because both CLIs were computing the right
        # answer. Behaviour was never wrong -- only reachability was.
        "c": r"static void rnl_contributory_kdf\(",
        "go": r"^func RnlContributoryKdf\(",
        "python": r"^def rnl_contributory_kdf\(",
        "java": r"HerraduraNl.java::public static BigInteger "
                r"rnlContributoryKdf\(",
    },
    # ── Ring-LWR Sigma protocol internals (rnl-sigma) (TODO #261, v6.1.0) ────
    # The tag with no Java port at all before v6.0.0, and no cross-language test
    # before test_zkp_hybrid_family.sh.
    "sigma-params": {
        # Go names the Sigma-protocol parameter block ZkpRnlParams; the entry
        # carries that name. No absence
        "c": r"static void sigma_params\(",
        "go": r"^func ZkpRnlParams\(",
        "python": r"^def _sigma_params\(",
        "java": r"HerraduraNl.java::public static int\[\] sigmaParams\(",
    },
    "sigma-poly-bytes": {
        "c": r"static void sigma_poly_bytes\(",
        "go": r"^func sigmaPolyBytes\(",
        "python": r"^def _sigma_poly_bytes\(",
        "java": r"HerraduraNl.java::static byte\[\] sigmaPolyBytes\(",
    },
    "sigma-challenge": {
        "c": r"static void sigma_challenge\(",
        "go": r"^func sigmaChallenge\(",
        "python": r"^def _sigma_challenge\(",
        "java": r"HerraduraNl.java::static int\[\] sigmaChallenge\(",
    },
    "rnl-sigma-verify": {
        "c": r"static int rnl_sigma_verify\(",
        "go": r"^func RnlSigmaVerify\(",
        "python": r"^def rnl_sigma_verify\(",
        "java": r"HerraduraNl.java::public static boolean rnlSigmaVerify\(",
    },
    # ── NL-FSCX v3 primitive internals (TODO #255, filed here in v6.1.0) ────
    # chi and the row partition. A 3-bit row is a complete break
    # (SecurityProofs-8.md 11.34.2), so v3-rows is a security assertion, not
    # bookkeeping -- test [47] checks the contents in all four languages and this
    # entry checks the function that produces them still exists to be checked.
    "v3-rows": {
        "acknowledged":
            "C stores the 47x5 + 3x7 row partition as a static table (_V3_ROWS) "
            "rather than computing it, so there is no function to name. The "
            "table's contents are asserted directly by test [47] in all four "
            "languages",
        "go": r"^func V3Rows\(",
        "python": r"^def v3_rows\(",
        "java": r"HerraduraNl.java::public static int\[\] v3Rows\(",
    },
    "chi-row": {
        "acknowledged":
            "C applies chi row-wise inside nl_chi_v3_ba over its limb "
            "representation rather than through a per-row callable. Bit- "
            "exactness against a per-row reference is exactly what test [47] "
            "asserts in C",
        "go": r"^func chiRow\(",
        "python": r"^def _chi_row\(",
        "java": r"HerraduraNl.java::private static int chiRow\(",
    },
    "chi-row-inv-table": {
        "acknowledged":
            "as chi-row: C inverts chi inline in nl_chi_v3_inv_ba, with no "
            "separate table-building function",
        "go": r"^func chiRowInvTable\(",
        "python": r"^def _chi_row_inv_table\(",
        "java": r"HerraduraNl.java::private static int\[\] chiRowInvTable\(",
    },
    "m-inv": {
        "c": r"static void m_inv_ba\(",
        "go": r"^func MInv\(",
        "python": r"^def _m_inv\(",
        "java": r"HerraduraNl.java::private static BitArray mInv\(",
    },
    "m-pow2-mul": {
        "acknowledged":
            "Java reaches M^(2^s) through mInvRotationsTable's precomputed "
            "rotation set rather than a squaring helper; the composed map is "
            "what the other three expose. Guarded four ways by m-inv",
        "c": r"static void ba_m_pow2_mul\(",
        "go": r"^func mPow2Mul\(",
        "python": r"^def _m_pow2_mul\(",
    },
    "one-plus-m-pow2-mul": {
        "acknowledged":
            "see m-pow2-mul",
        "c": r"static void ba_one_plus_m_pow2_mul\(",
        "go": r"^func onePlusMPow2Mul\(",
        "python": r"^def _one_plus_m_pow2_mul\(",
    },
    # ── HSKE-NL-AEAD and duplex internals (TODO #261, v6.1.0) ─────────────
    # The keystream/tag split of the counter-mode AEAD and the sponge duplex under
    # hske-duplex/hske-duplex3. Java has the duplex (TODO #260, v5.3.8) but not the
    # counter-mode AEAD; the two acknowledged cells below are that one gap, now
    # tracked as TODO #267 rather than as a Javadoc sentence.
    "hske-nl-aead-xor-ks": {
        "c": r"static void _hske_nl_aead_xor_ks\(",
        "go": r"^func hskeNlAeadXorKs\(",
        "python": r"^def _hske_nl_aead_xor_keystream\(",
        "java": r"HerraduraNl.java::static byte\[\] hskeNlAeadXorKs\(",
    },
    "hske-nl-aead-tag": {
        "c": r"static void _hske_nl_aead_tag\(",
        "go": r"^func hskeNlAeadTag\(",
        "python": r"^def _hske_nl_aead_tag\(",
        "java": r"HerraduraNl.java::static byte\[\] hskeNlAeadTag\(",
    },
    "v2dplex-init": {
        "c": r"static void _v2dplex_init\(",
        "go": r"^func v2dplexInit\(",
        "python": r"^def _v2_dplex_init\(",
        "java": r"Duplex.java::private static Object\[\] init\(",
    },
    "v2dplex-perm": {
        "c": r"static void _v2dplex_perm\(",
        "go": r"^func v2dplexPerm\(",
        "python": r"^def _v2_dplex_perm_bytes\(",
        "java": r"Duplex.java::private static byte\[\] perm\(",
    },
    "v2dplex-absorb-ad": {
        "c": r"static void _v2dplex_absorb_ad\(",
        "go": r"^func v2dplexAbsorbAD\(",
        "python": r"^def _v2_dplex_absorb_ad\(",
        "java": r"Duplex.java::private static byte\[\] absorbAd\(",
    },
    "v2dplex-finalize-tag": {
        "c": r"static void _v2dplex_squeeze_tag\(",
        "go": r"^func v2dplexFinalizeTag\(",
        "python": r"^def _v2_dplex_finalize\(",
        "java": r"Duplex.java::private static byte\[\] finalizeTag\(",
    },
    "dplex-encrypt": {
        "c": r"static void _dplex_encrypt\(",
        "go": r"^func dplexEncrypt\(",
        "python": r"^def _dplex_encrypt\(",
        "java": r"Duplex.java::private static EncResult encrypt\(",
    },
    "dplex-decrypt": {
        "c": r"static int _dplex_decrypt\(",
        "go": r"^func dplexDecrypt\(",
        "python": r"^def _dplex_decrypt\(",
        "java": r"Duplex.java::private static byte\[\] decrypt\(",
    },
    # ── fpe / twk subkey derivation (TODO #242, filed here in v6.1.0) ─────
    # TODO #241 found fpe and twk sharing ONE unseparated derivation, making them
    # literally the same function at a 12-byte context; #242 split them. Test [46]
    # is the behavioural guard in all four languages and these entries are the
    # structural one -- a re-merge would have to delete a function to pass.
    "fpe-twk-derive-b": {
        "c": r"static inline void fpe_twk_derive_b\(",
        "go": r"^func fpeTwkDeriveB\(",
        "python": r"^def _fpe_twk_derive_b\(",
        "java": r"FpeTwk.java::private static BitArray deriveB\(",
    },
    "fpe-twk-v3-derive-b": {
        "c": r"static inline void fpe_twk_v3_derive_b\(",
        "go": r"^func fpeTwkV3DeriveB\(",
        "python": r"^def _fpe_twk_v3_derive_b\(",
        "java": r"FpeTwk.java::private static BitArray deriveBv3\(",
    },
    "twk-tweak": {
        "acknowledged":
            "the (sector, bidx) -> 12-byte tweak encoding. C and Go build those "
            "12 bytes at the call site inside twk_encrypt/twk_decrypt. The "
            "encoding is pinned four ways by KAT/nl_fscx_v3.json, whose twk "
            "sector/bidx are hex strings for the float64 reason recorded there",
        "python": r"^def _twk_tweak\(",
        "java": r"FpeTwk.java::private static byte\[\] twkTweak\(",
    },
    # ── classical quartet suite entry points (TODO #261, v6.1.0) ──────────
    # These ARE reachable through --algo tags, but only in three of the four CLIs:
    # the Python CLI reimplements hpke/hpks inline from gf_pow and fscx_revolve
    # instead of calling its own suite (a duplication predating this manifest), so
    # spec/'s cli_support column does not reach the suite functions here.
    "hkex-gf-agree": {
        "c": r"static inline int hkex_gf_agree\(",
        "go": r"^func HkexGfAgree\(",
        "python": r"^def hkex_gf_agree\(",
        "java": r"Herradura.java::public static BitArray hkexGfAgree\(",
    },
    "hpks-verify": {
        "c": r"static inline int hpks_verify\(",
        "go": r"^func HpksVerify\(",
        "python": r"^def hpks_verify\(",
        "java": r"Herradura.java::public static boolean hpksVerify\(",
    },
    "hpke-encrypt": {
        "c": r"static inline int hpke_encrypt\(",
        "go": r"^func HpkeEncrypt\(",
        "python": r"^def hpke_encrypt\(",
        "java": r"Herradura.java::public static Ciphertext "
                r"hpkeEncrypt\(BitArray pt, BitArray pub, BitArray r",
    },
    "hpke-decrypt": {
        "c": r"static inline int hpke_decrypt\(",
        "go": r"^func HpkeDecrypt\(",
        "python": r"^def hpke_decrypt\(",
        "java": r"Herradura.java::public static BitArray hpkeDecrypt\(",
    },
    # ── threshold, OPRF, ratchet and hash internals (TODO #261, v6.1.0) ────
    # The remaining internal-derivation surface: MuSig2-style aggregation, the
    # OPRF's direct path, the forward-secret ratchet's initialiser and
    # HMAC-HFSCX-256.
    "hpkst-mu-coeff": {
        "c": r"static void _hpkst_mu_coeff\(",
        "go": r"^func hpkstMuCoeff\(",
        "python": r"^def _hpkst_mu_coeff\(",
        "java": r"HpksT.java::private static BigInteger muCoeff\(",
    },
    "hpkst-build-l": {
        "acknowledged":
            "Python concatenates the sorted public-key list L inline in "
            "hpkst_aggregate_pubkeys. The aggregation coefficient that consumes "
            "it is guarded four ways by hpkst-mu-coeff",
        "c": r"static uint8_t \*_hpkst_build_L\(",
        "go": r"^func hpkstBuildL\(",
        "java": r"HpksT.java::private static byte\[\] buildL\(",
    },
    "hpkst-sign": {
        "c": r"static void hpkst_sign\(",
        "go": r"^func HpkstSign\(",
        "python": r"^def hpkst_sign\(",
        "java": r"HpksT.java::public static Signature sign\(",
    },
    "oprf-direct": {
        "c": r"static void oprf_direct\(",
        "go": r"^func OprfDirect\(",
        "python": r"^def oprf_direct\(",
        "java": r"Oprf.java::public static BigInteger direct\(",
    },
    "ratchet-init": {
        "c": r"static inline void ratchet_init\(",
        "go": r"^func RatchetInit\(",
        "python": r"^def ratchet_init\(",
        "java": r"Ratchet.java::public static BitArray init\(",
    },
    "hmac-hfscx-256": {
        "c": r"static void hmac_hfscx_256\(",
        "go": r"^func HmacHfscx256\(",
        "python": r"^def hmac_hfscx_256\(",
        "java": r"Hfscx256.java::public static byte\[\] hmacHfscx256\(",
    },
    # ── the FSCX and NL-FSCX primitives themselves (TODO #261, v6.1.0) ────
    # The bottom of the stack, and the last place anyone would look for a gap --
    # which is why the census reached it and eleven hand-written passes did not.
    # C's cells are the `_ba` twins (the exempt rule above names the stems); Java
    # splits v1 into Hfscx256 and the rest into HerraduraNl.
    "fscx": {
        "c": r"static void ba_fscx\(",
        "go": r"^func Fscx\(",
        "python": r"^def fscx\(",
        "java": r"Herradura.java::public static BitArray fscx\(",
    },
    "fscx-revolve": {
        "c": r"static void ba_fscx_revolve\(",
        "go": r"^func FscxRevolve\(",
        "python": r"^def fscx_revolve\(",
        "java": r"Herradura.java::public static BitArray fscxRevolve\(",
    },
    "nl-fscx-v1": {
        "c": r"static void nl_fscx_v1_ba\(",
        "go": r"^func NlFscxV1\(",
        "python": r"^def nl_fscx_v1\(",
        "java": r"Hfscx256.java::public static BitArray nlFscxV1\(",
    },
    "nl-fscx-v2": {
        "c": r"static void nl_fscx_v2_ba\(",
        "go": r"^func NlFscxV2\(",
        "python": r"^def nl_fscx_v2\(",
        "java": r"HerraduraNl.java::public static BitArray nlFscxV2\(",
    },
    "nl-fscx-v2-inv": {
        "c": r"static void nl_fscx_v2_inv_ba\(",
        "go": r"^func NlFscxV2Inv\(",
        "python": r"^def nl_fscx_v2_inv\(",
        "java": r"HerraduraNl.java::public static BitArray nlFscxV2Inv\(",
    },
    "nl-fscx-v3": {
        "c": r"static void nl_fscx_v3_ba\(",
        "go": r"^func NlFscxV3\(",
        "python": r"^def nl_fscx_v3\(",
        "java": r"HerraduraNl.java::public static BitArray nlFscxV3\(",
    },
    "nl-fscx-v3-inv": {
        "c": r"static void nl_fscx_v3_inv_ba\(",
        "go": r"^func NlFscxV3Inv\(",
        "python": r"^def nl_fscx_v3_inv\(",
        "java": r"HerraduraNl.java::public static BitArray nlFscxV3Inv\(",
    },
    "nl-chi-v3": {
        "c": r"static void nl_chi_v3_ba\(",
        "go": r"^func NlChiV3\(",
        "python": r"^def nl_chi_v3\(",
        "java": r"HerraduraNl.java::public static BitArray nlChiV3\(",
    },
    "nl-chi-v3-inv": {
        "c": r"static void nl_chi_v3_inv_ba\(",
        "go": r"^func NlChiV3Inv\(",
        "python": r"^def nl_chi_v3_inv\(",
        "java": r"HerraduraNl.java::public static BitArray nlChiV3Inv\(",
    },
    "nl-fscx-revolve-v1": {
        "c": r"static void nl_fscx_revolve_v1_ba\(",
        "go": r"^func NlFscxRevolveV1\(",
        "python": r"^def nl_fscx_revolve_v1\(",
        "java": r"Hfscx256.java::public static BitArray nlFscxRevolveV1\(",
    },
    "nl-fscx-revolve-v2": {
        "c": r"static void nl_fscx_revolve_v2_ba\(",
        "go": r"^func NlFscxRevolveV2\(",
        "python": r"^def nl_fscx_revolve_v2\(",
        "java": r"HerraduraNl.java::public static BitArray nlFscxRevolveV2\(",
    },
    "nl-fscx-revolve-v2-inv": {
        "c": r"static void nl_fscx_revolve_v2_inv_ba\(",
        "go": r"^func NlFscxRevolveV2Inv\(",
        "python": r"^def nl_fscx_revolve_v2_inv\(",
        "java": r"HerraduraNl.java::public static BitArray "
                r"nlFscxRevolveV2Inv\(",
    },
    "nl-fscx-revolve-v3": {
        "c": r"static void nl_fscx_revolve_v3_ba\(",
        "go": r"^func NlFscxRevolveV3\(",
        "python": r"^def nl_fscx_revolve_v3\(",
        "java": r"HerraduraNl.java::public static BitArray nlFscxRevolveV3\(",
    },
    "nl-fscx-revolve-v3-inv": {
        "c": r"static void nl_fscx_revolve_v3_inv_ba\(",
        "go": r"^func NlFscxRevolveV3Inv\(",
        "python": r"^def nl_fscx_revolve_v3_inv\(",
        "java": r"HerraduraNl.java::public static BitArray "
                r"nlFscxRevolveV3Inv\(",
    },
    "nl-fscx-delta-v2": {
        "acknowledged":
            "delta(B) -- the v2 round's whole key-dependence "
            "(SecurityProofs-7.md 11.20). Python and Java compute it inline "
            "where it is used. It is a named function in C and Go only, so "
            "those two are what a rename would have to keep",
        "c": r"static void nl_fscx_delta_v2_ba\(",
        "go": r"^func nlFscxDeltaV2\(",
        "java": r"HerraduraNl.java::private static BitArray delta\(",
    },
    "nl-fscx-v2-round-const": {
        "acknowledged":
            "the per-round XOR constant TODO #245 added. C and Go apply it "
            "through a named helper; Python and Java fold it into the round "
            "body. An XOR constant leaves xdp+ exactly invariant (#245), so "
            "this is a structural entry, not a wire one",
        "c": r"static inline void nl_fscx_v2_rc_ba\(",
        "go": r"^func nlFscxV2RC\(",
    },
    "m-inv-rotations": {
        "acknowledged":
            "the rotation set realising M^-1. Go and Java precompute a table; C "
            "and Python apply the closed form per call "
            "(SecurityProofsCode/fscx_revolve_closed_form.py, TODO #213). Same "
            "map, two shapes",
        "go": r"^func computeMInvRotations\(",
        "java": r"HerraduraNl.java::private static synchronized int\[\] "
                r"mInvRotationsTable\(",
    },
    "chi-inv-for": {
        "acknowledged":
            "Java-only helper selecting the inverse-chi table for a row length; "
            "the other three index chi-row-inv-table directly",
        "java": r"HerraduraNl.java::private static int\[\] chiInvFor\(",
    },
    "nl-fscx-v1-general": {
        "acknowledged":
            "the width-parameterised v1 step used by ZKBoo and aPAKE, where the "
            "suite default is 256. ALL FOUR name it now: C (zkp_nl_f1), Go "
            "(zkpNlF1, TODO #314 pass 3), Python (zkp_nl_f1, pass 4) and Java "
            "(ZkpNl.nlFscxV1General). The reason is the item, and it arrived "
            "twice: ZKP-NL's default width is 8, BITARRAY.md 2 puts the "
            "BitArray's floor at 16 because fscx reads the octet on both sides "
            "of every position and degenerates below two octets, and "
            "KAT/bitarray.json PINS nbits = 8 as E_WIDTH -- so the 8-bit "
            "BitArray Go and Python each used to build here is exactly what the "
            "contract forbids, and the machine-word form C has always had is "
            "what replaces it. Pass 3's version of this reason said Python kept "
            "passing the width to nl-fscx-v1 'because its BitArray has no such "
            "floor'; pass 4 gave it one, so the sentence was corrected rather "
            "than left standing -- a curated reason is only as good as the pass "
            "that last read it",
        "c": r"static uint64_t zkp_nl_f1\(",
        "go": r"^func zkpNlF1\(",
        "python": r"^def zkp_nl_f1\(",
        "java": r"ZkpNl.java::public static BigInteger nlFscxV1General\(",
    },
    # ── hash, DRBG and classical entry points (TODO #261, v6.1.0) ─────────
    # The domain-separated hash and the DRBG seed step, plus the three classical
    # operations that are a named function in only two of the four languages --
    # see each acknowledged reason.
    "hfscx-256-ds": {
        "c": r"static void hfscx_256_ds\(",
        "go": r"^func Hfscx256DS\(",
        "python": r"^def hfscx_256_ds\(",
        "java": r"Hfscx256.java::public static byte\[\] hashDs\(",
    },
    "drbg-seed": {
        "c": r"static void drbg_seed\(",
        "go": r"^func DrbgSeed\(",
        "python": r"^def drbg_seed\(",
        "java": r"Hdrbg.java::public static Hdrbg seed\(byte\[\] entropy, "
                r"byte\[\] personalization",
    },
    "hske-encrypt": {
        "acknowledged":
            "classical HSKE is fscx_revolve(P, key, i) with nothing else in it, "
            "so Go and Python call fscx-revolve directly at the two call sites "
            "rather than wrapping it. C and Java name the wrapper. The "
            "construction is pinned four ways by KAT/classical_quartet.json",
        "c": r"static inline void hske_encrypt\(",
        "java": r"Herradura.java::public static BitArray hskeEncrypt\(",
    },
    "hske-decrypt": {
        "acknowledged":
            "see hske-encrypt: the inverse direction, same argument",
        "c": r"static inline void hske_decrypt\(",
        "java": r"Herradura.java::public static BitArray hskeDecrypt\(",
    },
    "hpks-sign": {
        # Four-language parity since TODO #308 (v8.1.0).  This entry carried an
        # `acknowledged` reason until then -- "Go and Python build the Schnorr
        # signature inline from gf_pow and fscx_revolve" -- which was true of
        # the SUITES and hid where those two ports' nonce was actually drawn:
        # in their CLIs, on the far side of the randomness corpus boundary
        # #306 found.  Pinned four ways by KAT/classical_quartet.json's HPKS
        # vectors, with the nonce supplied as an argument.
        "c": r"static inline void hpks_sign\(",
        "go": r"func HpksSign\(",
        "python": r"^def hpks_sign\(",
        "java": r"Herradura.java::public static Signature hpksSign\(BitArray "
                r"msg, BitArray priv, BitArray k",
    },
    "hpks-nl-sign": {
        # The NL counterpart, and the reason it is a SEPARATE entry rather than
        # a note on the one above: `sign --algo hpks-nl` is its own CLI path,
        # and in C, Go and Python the two shared ONE inline nonce draw, so
        # moving only the classical half would have left the draw exactly where
        # it was.  Java alone had both operations named before TODO #308.
        "c": r"static inline void hpks_nl_sign\(",
        "go": r"func HpksNlSign\(",
        "python": r"^def hpks_nl_sign\(",
        "java": r"HerraduraNl.java::public static Herradura.Signature "
                r"hpksNlSign\(BitArray msg, BitArray priv, BitArray k",
    },
    "hkex-gf-pubkey": {
        "acknowledged":
            "C = g^a is one gf_pow call, which Go and Python make at the call "
            "site. Note the asymmetry runs the other way from hkex-gf-agree, "
            "which all four name",
        "c": r"static inline void hkex_gf_pubkey\(",
        "java": r"Herradura.java::public static BitArray hkexGfPubkey\(",
    },
    # ── fpe / twk block operations (TODO #261, v6.1.0) ────────────────────
    # The eight enc/dec entry points across {fpe, twk} x {v2, v3}, and the three
    # per-domain derivation wrappers C and Go keep. TODO #242 separated fpe from
    # twk; test [46] guards the behaviour and these guard the shape.
    "fpe-encrypt": {
        "c": r"static inline void fpe_encrypt\(",
        "go": r"^func FpeEncrypt\(",
        "python": r"^def fpe_encrypt\(",
        "java": r"FpeTwk.java::public static BitArray fpeEncrypt\(",
    },
    "fpe-decrypt": {
        "c": r"static inline void fpe_decrypt\(",
        "go": r"^func FpeDecrypt\(",
        "python": r"^def fpe_decrypt\(",
        "java": r"FpeTwk.java::public static BitArray fpeDecrypt\(",
    },
    "fpe-v3-encrypt": {
        "c": r"static inline void fpe_v3_encrypt\(",
        "go": r"^func FpeV3Encrypt\(",
        "python": r"^def fpe_v3_encrypt\(",
        "java": r"FpeTwk.java::public static BitArray fpeV3Encrypt\(",
    },
    "fpe-v3-decrypt": {
        "c": r"static inline void fpe_v3_decrypt\(",
        "go": r"^func FpeV3Decrypt\(",
        "python": r"^def fpe_v3_decrypt\(",
        "java": r"FpeTwk.java::public static BitArray fpeV3Decrypt\(",
    },
    "twk-encrypt": {
        "c": r"static inline void twk_encrypt\(",
        "go": r"^func TwkEncrypt\(",
        "python": r"^def twk_encrypt\(",
        "java": r"FpeTwk.java::public static BitArray twkEncrypt\(",
    },
    "twk-decrypt": {
        "c": r"static inline void twk_decrypt\(",
        "go": r"^func TwkDecrypt\(",
        "python": r"^def twk_decrypt\(",
        "java": r"FpeTwk.java::public static BitArray twkDecrypt\(",
    },
    "twk-v3-encrypt": {
        "c": r"static inline void twk_v3_encrypt\(",
        "go": r"^func TwkV3Encrypt\(",
        "python": r"^def twk_v3_encrypt\(",
        "java": r"FpeTwk.java::public static BitArray twkV3Encrypt\(",
    },
    "twk-v3-decrypt": {
        "c": r"static inline void twk_v3_decrypt\(",
        "go": r"^func TwkV3Decrypt\(",
        "python": r"^def twk_v3_decrypt\(",
        "java": r"FpeTwk.java::public static BitArray twkV3Decrypt\(",
    },
    "fpe-domain-derive-b": {
        "acknowledged":
            "C and Go wrap the shared fpe/twk derivation once per domain; "
            "Python and Java pass the domain-separation string as an argument "
            "to the shared derivation instead (fpe-twk-derive-b). TODO #242 is "
            "what made the DS string load-bearing -- before it, fpe and twk "
            "WERE the same function at a 12-byte context",
        "c": r"static inline void fpe_derive_b\(",
        "go": r"^func fpeDeriveB\(",
    },
    "twk-domain-derive-b": {
        "acknowledged":
            "see fpe-domain-derive-b",
        "c": r"static inline void twk_derive_b\(",
        "go": r"^func twkDeriveB\(",
    },
    "twk-v3-domain-derive-b": {
        "acknowledged":
            "see fpe-domain-derive-b",
        "c": r"static inline void twk_v3_derive_b\(",
        "go": r"^func twkV3DeriveB\(",
    },
    # ── decomposition differences, filed rather than flattened (TODO #261, v6.1.0) ────
    # Every entry from here down is acknowledged, and each one is a place where the
    # four ports factor the SAME computation into a different number of functions.
    # They are filed rather than exempted because a reader who greps for one of
    # these names in another language deserves the reason in the same place, and
    # because an exempt rule would also cover the next thing that matched it.
    "hcred-kkw-expand": {
        "acknowledged":
            "C and Java split the seed-tree expansion into expand/levels/node- "
            "idx helpers; Go and Python compute the same tree inline in hcred- "
            "kkw-tree. The tree layout itself is consumed four ways by "
            "KAT/hcred_kkw.json",
        "c": r"static void hcred_kkw_expand\(",
        "java": r"Hcred.java::private static void kkwExpand\(",
    },
    "hcred-kkw-levels": {
        "acknowledged":
            "see hcred-kkw-expand",
        "c": r"static int hcred_kkw_levels\(",
        "java": r"Hcred.java::private static int kkwLevels\(",
    },
    "hcred-kkw-node-idx": {
        "acknowledged":
            "see hcred-kkw-expand",
        "c": r"static int hcred_kkw_node_idx\(",
        "java": r"Hcred.java::private static int kkwNodeIdx\(",
    },
    "hcred-kkw-leaf-cover": {
        "acknowledged":
            "the check that the revealed sibling path covers every leaf but the "
            "challenged one. Go and Java factor it out; C and Python assert it "
            "inline in the verifier. A tamper case in KAT/hcred_kkw.json's "
            "table covers the behaviour in all four",
        "go": r"^func kkwLeavesCoverAllExcept\(",
        "java": r"Hcred.java::private static boolean kkwLeavesCoverAllExcept\(",
    },
    "hcred-params": {
        "acknowledged":
            "HCRED's width is a RUNTIME argument in Python and Go and a "
            "COMPILE-TIME constant in C (HCRED_N) and Java (Hcred.N) -- TODO "
            "#266's finding, and the reason KAT/hcred_kkw.json ships two vector "
            "sets. Only Python needs a parameter-derivation function; there is "
            "nothing to port unless that split is closed first",
        "python": r"^def _hcred_params\(",
    },
    "hcred-issuer-msg": {
        "acknowledged":
            "Java factors the issuance message out; the other three build it "
            "inline in hcred-issue. The digest it feeds is guarded by hcred- "
            "stmt-hash",
        "java": r"Hcred.java::private static BigInteger issuerMsg\(",
    },
    "hcred-gate-round": {
        "acknowledged":
            "Java factors the per-gate MPC step out of hcred-mpc-round; the "
            "other three inline it. Same decomposition difference as hcred-mpc- "
            "round, one level down",
        "java": r"Hcred.java::private static int\[\]\[\] gateRound\(",
    },
    "hcred-outs-ser-one": {
        "acknowledged":
            "Java serialises one party's output shares through a helper that "
            "the other three inline inside hcred-outputs-ser",
        "java": r"Hcred.java::private static byte\[\] outsSerOne\(",
    },
    "zkp-nl-commit": {
        "acknowledged":
            "C builds the ZKBoo commitment buffer in a named helper; Go, Python "
            "and Java hash the same fields through their generic domain hash "
            "(zkp-nl-h), which C does not have. The two entries are the same "
            "commitment from opposite sides",
        "c": r"static void zkp_nl_commit\(",
    },
    "zkpp-tape": {
        "acknowledged":
            "Java factors ZKB++'s tape expansion out of zkpp-derive; the other "
            "three expand inline",
        "java": r"ZkpNl.java::private static byte\[\] ppTape\(",
    },
    "stern-ring-fs-seed": {
        "acknowledged":
            "Java factors the ring signature's Fiat-Shamir seed out of stern- "
            "ring-challenges; the other three derive it inline",
        "java": r"SternRing.java::private static BigInteger fiatShamirSeed\(",
    },
    "qcmdpc-planes": {
        "acknowledged":
            "the BGF counter PLANE COUNT, max(4, bit_length(d)) (TODO #330).  "
            "Go and Java compute it in a named helper; C spells it as the "
            "QCMDPC_NPLANE macro -- it sizes an array, so it must be a "
            "constant expression there -- and Python writes the expression "
            "inline at its one call site.  Four ports, one rule, two of them "
            "with a function to name",
        "go": r"^func qcmdpcPlanes\(",
        "java": r"Stern.java::private static int qcmdpcPlanes\(",
    },
    "qcmdpc-support-to-poly": {
        "acknowledged":
            "Go and Java convert a sparse support list to a dense polynomial "
            "through a helper; C writes the bits directly into a QcPoly (the "
            "exempted qcp_ family) and Python builds the integer inline",
        "go": r"^func supportToPoly\(",
        "java": r"Stern.java::private static BigInteger supToPoly\(",
    },
    "hpke-stern-f-encap": {
        "c": r"static void hpke_stern_f_encap\(",
        "go": r"^func HpkeSternFEncap\(",
        "python": r"^def hpke_stern_f_encap\(",
        "java": r"Stern.java::public static SternEncapResult "
                r"hpkeSternFEncapWithE\(",
    },
    "hske-nl-v2-duplex-decrypt": {
        "c": r"static int hske_nl_v2_duplex_decrypt\(",
        "go": r"^func HskeNlV2DuplexDecrypt\(",
        "python": r"^def hske_nl_v2_duplex_decrypt\(",
        "java": r"Duplex.java::public static byte\[\] v2Decrypt\(",
    },
    "hske-nl-v3-duplex-decrypt": {
        "c": r"static int hske_nl_v3_duplex_decrypt\(",
        "go": r"^func HskeNlV3DuplexDecrypt\(",
        "python": r"^def hske_nl_v3_duplex_decrypt\(",
        "java": r"Duplex.java::public static byte\[\] v3Decrypt\(",
    },
    "v2dplex-enc": {
        "acknowledged":
            "the duplex sponge's encrypt step. C folds it into dplex-encrypt "
            "rather than keeping a separate sponge-level function",
        "go": r"^func v2dplexEnc\(",
        "python": r"^def _v2_dplex_enc\(",
        "java": r"Duplex.java::private static Object\[\] duplexEncrypt\(",
    },
    "v2dplex-dec": {
        "acknowledged":
            "see v2dplex-enc",
        "go": r"^func v2dplexDec\(",
        "python": r"^def _v2_dplex_dec\(",
        "java": r"Duplex.java::private static Object\[\] duplexDecrypt\(",
    },
    "hske-nl-aead-streams": {
        "acknowledged":
            "Python and Java split the AEAD's keystream and MAC-key derivation "
            "into a streams helper; C and Go derive both inside "
            "hske-nl-aead-xor-ks. Java's copy arrived with the primitive in "
            "TODO #273; what remains is a FACTORING difference between two "
            "pairs of languages, not a missing capability",
        "python": r"^def _hske_nl_aead_streams\(",
        "java": r"HerraduraNl.java::static BitArray\[\] hskeNlAeadStreams\(",
    },
    "rnl-bits-to-bitarray": {
        "acknowledged":
            "packing a reconciled bit vector into the session-key "
            "representation. Java's BigInteger needs no conversion step, so "
            "there is nothing to name there",
        "c": r"static void rnl_bits_to_ba\(",
        "go": r"^func RnlBitsToBitArray\(",
        "python": r"^def _rnl_bits_to_bitarray\(",
    },
    "rnl-mul-mod-q": {
        "acknowledged":
            "multiplication mod q with the reduction written out. Python uses "
            "%, Java uses BigInteger.mod; C and Go keep a helper because both "
            "do it in fixed-width integer arithmetic where the reduction is not "
            "free",
        "c": r"static inline uint32_t rnl_mulmodq\(",
        "go": r"^func rnlMulModQ\(",
    },
    "sigma-poly-mul-n": {
        "acknowledged":
            "polynomial multiplication at an explicit width for the Sigma "
            "protocol, which runs at a different n than HKEX-RNL. Python and "
            "Java pass n to rnl-poly-mul itself",
        "c": r"static void sigma_poly_mul_n\(",
        "go": r"^func sigmaPolyMulN\(",
    },
    "syndrome-to-bitarray": {
        "acknowledged":
            "syndrome-to-session-key packing. Python and Java build the integer "
            "directly. Note herradura.h stores the syndrome in the REVERSE byte "
            "order of the big-endian integer Python and Go use -- TODO #266's "
            "finding, recorded in KAT/hcred_kkw_vector.h, and exactly why this "
            "conversion is worth naming",
        "c": r"static void syndr_to_ba\(",
        "go": r"^func SyndrToBA\(",
    },
    "ratchet-erase": {
        "acknowledged":
            "explicit zeroization of superseded ratchet state (explicit_bzero). "
            "C is the only one of the four that CAN do it: Go, Python and Java "
            "are garbage-collected and cannot guarantee the old state is gone. "
            "This is a real, unfixable asymmetry in the forward-secrecy claim "
            "of SecurityProofs-5.md 11.8.3, not a naming difference -- recorded "
            "here so it stays visible",
        "c": r"static inline void ratchet_erase\(",
    },
    "stern-f-first-preimage": {
        "acknowledged":
            "a Python-only analysis helper (first syndrome preimage by "
            "exhaustive search) used by the demo path, not part of any "
            "protocol. Nothing to port",
        "python": r"^def stern_f_first_preimage\(",
    },
}


def _suite_text():
    """{lang: whole-suite text}, plus {basename: text} for Java's per-class files."""
    file_text = {}
    java_files = {}
    for lang, paths in SUITE_FILES.items():
        paths = [paths] if isinstance(paths, str) else paths
        chunks = []
        for path in paths:
            with open(path, encoding="utf-8") as f:
                text = f.read()
            chunks.append(text)
            if lang == "java":
                java_files[os.path.basename(path)] = text
        file_text[lang] = "\n".join(chunks)
    return file_text, java_files


def _resolve_marker(pattern, lang, file_text, java_files):
    """Split an optional "File.java::regex" prefix off a marker.

    Returns (regex, haystack, where) or (None, None, error-string).
    """
    if lang == "java" and "::" in pattern:
        fname, _, regex = pattern.partition("::")
        if fname not in java_files:
            return None, None, (
                f"names class file {fname!r}, which is not a Java suite file — either it "
                f"was renamed, or it is one of JAVA_NON_SUITE (the CLI/codec/test layer, "
                f"which this manifest deliberately does not read)"
            )
        return regex, java_files[fname], fname
    return pattern, file_text[lang], None


def check_primitives(errors):
    file_text, java_files = _suite_text()

    checked = 0
    for pid, spec in PRIMITIVES.items():
        reason = spec.get("acknowledged")
        for lang in SUITE_FILES:
            pattern = spec.get(lang)
            if pattern is None:
                if reason is None:
                    errors.append(
                        f"'{pid}': PRIMITIVES has no marker for {lang}, and the entry isn't "
                        f"marked acknowledged — add a marker regex or an 'acknowledged' reason"
                    )
                continue
            checked += 1
            regex, haystack, where = _resolve_marker(pattern, lang, file_text, java_files)
            if regex is None:
                errors.append(f"'{pid}': java marker {pattern!r} {where}")
                continue
            hits = len(re.findall(regex, haystack, re.M))
            if where:
                rel = os.path.join("bindings", "java", "herradurakex", where)
            else:
                paths = SUITE_FILES[lang]
                paths = [paths] if isinstance(paths, str) else paths
                rel = ", ".join(os.path.relpath(p, REPO) for p in paths)
            if hits == 0:
                # AN `acknowledged` REASON EXCUSES AN ABSENT CELL, NEVER A DEAD
                # ANCHOR (TODO #330).  Until then `if reason: continue` sat here,
                # so a row whose ONLY cell was a port-specific helper stayed
                # green after that helper was deleted -- and the reason went on
                # describing it.  qcmdpc-upc is the case that found it: its
                # reason said "Java factors the UPC counter out of the decoder
                # loop; C, Go and Python count inline", which #330 made false in
                # all four ports at once while deleting the very function the
                # row anchored on.  That is #295's false-reason shape with the
                # manifest's own escape hatch as the carrier: a row cannot
                # describe a port's code and also decline to point at it.
                errors.append(
                    f"'{pid}': marker {pattern!r} not found in {lang}'s suite file(s) ({rel}) — "
                    f"either the function was renamed/removed (update PRIMITIVES to match) or "
                    f"this is a real cross-language gap (port it, or DROP the {lang} marker and "
                    f"let the entry's 'acknowledged' reason carry the absence; a reason excuses "
                    f"a missing cell, not a marker that points at nothing)"
                )
            elif hits > 1:
                # A marker must IDENTIFY one function, not merely occur. This
                # is not pedantry: Java's suite is many files concatenated
                # here (see SUITE_FILES), so a marker written as a bare method
                # name — `public static boolean verify(` matches six classes —
                # keeps passing after the function it was meant to guard is
                # deleted, which is precisely the silent gap this manifest
                # exists to prevent. Added in v6.0.3 after hcred-zkboo-verify
                # was written that way; every other entry was already unique.
                errors.append(
                    f"'{pid}': marker {pattern!r} matches {hits} places in {lang}'s suite "
                    f"file(s) ({rel}) — a marker must identify exactly one function, or it "
                    f"still passes once that function is gone. Anchor it on the signature "
                    f"(argument types) rather than the bare name"
                )
    return checked


# ── Part 4: internal-surface census ─────────────────────────────────────
# WHY THIS EXISTS (TODO #261, v6.1.0 — the check that CLOSES the item).
# Part 3 verifies that everything the manifest NAMES is present in four
# languages. It cannot say anything about what the manifest does not name,
# and #261's acceptance criterion is a statement about the whole internal
# surface: "never a silent absence, checked by the mechanism rather than by
# a one-time read of the source tree". Between v5.7.2 and v6.0.5 the manifest
# grew entry by entry, each addition a one-time read — exactly the thing the
# criterion says not to rely on, and the reason the item stayed open through
# eleven releases that each added to it.
#
# The census closes that loop from the other side. For each language it
# enumerates the suite's own top-level functions, subtracts the ones that
# language's CLI calls (that is the definition of "suite-internal (non-CLI)"
# this manifest has always used — made executable here rather than applied by
# hand), subtracts the ones a PRIMITIVES entry names, and FAILS on whatever
# is left. A new internal primitive is therefore a CI failure until someone
# either gives it a manifest entry (four cells) or files it below with a
# reason. Nothing can be added silently in any of the four languages.
#
# Each language is measured against ITS OWN CLI and ITS OWN markers, so the
# census needs no cross-language name matching — Go's exported CamelCase,
# C's `_ba` twins and Java's class-scoped short names never have to be
# reconciled by a normaliser that would be guessing. The cross-language claim
# stays where it belongs, in PRIMITIVES' four cells.
CLI_SOURCES = {
    "c": [os.path.join(REPO, "HerraduraCli", "herradura_cli.c")],
    "go": [os.path.join(REPO, "HerraduraCli", "herradura_cli.go")],
    "python": [os.path.join(REPO, "HerraduraCli", "herradura.py")],
    "java": [os.path.join(REPO, "bindings", "java", "herradurakex", "HerraduraCli.java")],
}

# Top-level function declarations, per language. Deliberately narrow:
#   * C   — file-scope `static` definitions (herradura.h is header-only, so
#           every suite function is one). Return types may be multi-token and
#           pointer-valued; the name is the last identifier before `(`.
#   * Go  — `func Name(` only. Methods (`func (b *BitArray) Copy()`) are the
#           BitArray/QcMdpcPrf receiver surface, which is representation, not
#           protocol, and has no counterpart in a language whose big integers
#           are built in.
#   * Py  — module-level `def`.
#   * Java— `static` methods in the suite classes; the class scopes the name.
DECL_PATTERNS = {
    "c": re.compile(r"^static\s+(?:inline\s+)?[A-Za-z_][A-Za-z0-9_ \*]*?"
                    r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(", re.M),
    "go": re.compile(r"^func ([A-Za-z][A-Za-z0-9_]*)\s*\(", re.M),
    "python": re.compile(r"^def ([A-Za-z_][A-Za-z0-9_]*)\s*\(", re.M),
    "java": re.compile(r"^\s+(?:public |private |protected )?static\s+"
                       r"[A-Za-z0-9_<>\[\],. ]+?\s+([a-zA-Z0-9_]+)\s*\(", re.M),
}

# Names excused from the census, per language, as (regex, reason) pairs. A
# rule is a CLASS of function with a stated reason, never a list of names
# someone did not want to file: the reason has to say why the thing is not a
# cross-language primitive. Every rule must still match something (see the
# dead-rule check below), so a family that disappears takes its excuse with
# it instead of quietly covering the next thing that matches.
CENSUS_EXEMPT = {
    "c": [
        (r"^_?ba(33)?_", "BitArray octet plumbing (shift/compare/popcount/print/rand, "
                         "the width check, and the fallible ba_try_* surface). NOT a "
                         "protocol step in any language. Until TODO #314 pass 3 the "
                         "reason read 'C alone needs it: Go and Python carry big "
                         "integers with these as built-ins' -- that is now false for "
                         "Go, which implements BITARRAY.md over octets and has its own "
                         "counterparts under the go rules below, and it stays true of "
                         "Python and Java only until passes 4 and 5"),
        (r"_(alloc|free)$", "manual allocation/release of a proof or signature struct. "
                            "Go, Python and Java are garbage-collected and have no "
                            "counterpart by construction"),
        (r"^_?(qcp|qcprf|qceuc)_(?!mul_sparse$|inv$|mul$|refill$|idx_bytes$)",
         "QC-MDPC bit-polynomial and PRF plumbing (get/set/copy/xor/rotate/popcount, "
         "the xorshift and degree helpers). The five members that ARE protocol steps "
         "— qcp_mul, qcp_mul_sparse, qcp_inv, qcprf_refill, qcprf_idx_bytes — are "
         "excluded from this rule and carry manifest entries"),
        (r"_be64$", "big-endian 8-byte packing helper. Go has encoding/binary and "
                    "Python has int.to_bytes; there is nothing to port"),
        (r"^ct_eq", "constant-time comparison helper. Go uses crypto/subtle, Python "
                    "uses hmac.compare_digest, Java uses MessageDigest.isEqual"),
        (r"_int_cmp$", "an int comparator passed to qsort. Go has sort.Slice, Python "
                       "has list.sort's key, Java has Arrays.sort"),
        (r"_ex$", "the explicit-parameter twin of a defaulted function (rnl_ntt_ex "
                  "beside rnl_ntt), the same split as the _dim rule below. The stem "
                  "is what the manifest names"),
        (r"^hcred_tape_", "the KKW tape as an explicit struct with init/draw/draws. "
                          "Go, Python and Java draw from a seeded PRG inline; "
                          "hcred-kkw-party is the shared step this decomposes"),
        (r"^rnl_twiddle_", "precomputed NTT twiddle table, an implementation cache for "
                           "C's fixed-width NTT. Go computes them per call, Python uses "
                           "the schoolbook or numpy path"),
        (r"_dim$", "the runtime-width twin of a fixed-width function (rnl_keygen_dim "
                   "beside rnl_keygen). C compiles one RNL_N and keeps both; the "
                   "fixed-width stem is what the manifest names"),
    ],
    "go": [
        (r"^(sternT|sternNRows|nlV3ISteps)$", "width-scaling helpers added by TODO "
         "#295 so that SdfT, SdfNRows and I3Value GOVERN the code instead of "
         "being restated as the literal ratios n/16, n/2 and 5n/16 at the call "
         "site. Go alone needs them: its Stern and v3 duplex take the width as "
         "an argument, where C compiles for a single KEYBITS and Python and "
         "Java read the constant directly. Not a protocol step in any language"),
        (r"^(New|new)", "constructors for BitArray/QcMdpcPrf — the receiver surface "
                        "the DECL_PATTERNS comment excludes, reached through a "
                        "top-level func because Go has no constructors"),
        (r"^(bitArrayMask|zkpNlMask|bitCount|CountBits|lowestSetBit|putLE|word16|"
         r"draw|draws|intSlicesEqual|qcpRotate|qcpWeight)$",
         "bit/byte/slice plumbing on Go's own representation; C's counterparts are "
         "the exempted ba_ and qcp_ families and Python's are built in.  zkpNlMask "
         "is the low-n-bit mask ZKP-NL applies: C writes (1ULL << n) - 1 inline, "
         "Python (1 << n) - 1, and Java factors it out as the exempted maskOf.  "
         "qcpWeight is big.Int's missing popcount, added by TODO #334 so that "
         "QcMdpcMul can walk the lighter operand: C has qcp_popcount in the "
         "exempted qcp_ family, Python has bin(x).count(\'1\') and Java "
         "BigInteger.bitCount"),
        (r"^(TryZero|TryFromBytes|TryFromUint|TryFromHex|MustFromHex|BaCode|"
         r"BaGfPoly|GfGenBA|baCheckWidth|baSameWidth|baErr|baFail|baHexVal)$",
         "the BitArray construction, width-check and error surface (TODO #314 pass "
         "3) -- the Go half of the family C's exempted ba_ rule covers. Not a "
         "protocol step in any language: BITARRAY.md specifies a TYPE, and these "
         "are how one port spells its constructors and its status codes"),
        (r"^Try(Fscx|GfMul|GfPow)$",
         "the FALLIBLE twin of a function the manifest names by its stem, the same "
         "split as C's exempted _ex$ and _dim$ rules. It exists because "
         "KAT/bitarray.json pins a mixed width and an unlisted width as error "
         "CODES, so a conformance consumer must be able to OBSERVE the failure "
         "where protocol code wants the panic; C's ba_try_* twins are exempted by "
         "the ba_ rule above, and Python and Java raise from the stem itself"),
        (r"^(gfMulBig|gfPowBig)$",
         "the math/big boundary for the OPRF and threshold layers, whose scalars "
         "are *big.Int by their own protocol definitions (TODO #314 pass 3). They "
         "route those layers through the ONE GF implementation rather than a "
         "second one; the other three ports have no boundary to cross because "
         "their scalar type and their bit-string type are already the same"),
        (r"^(oprfOrd|rnlTwGet)$",
         "accessors for a value the other three keep as a constant or recompute: "
         "the OPRF group order, and one twiddle from the table C's exempted "
         "rnl_twiddle_ family builds"),
    ],
    "python": [
        (r"^(_ba_check_width|ba_gf_poly|ba_gf_mul|ba_gf_pow)$",
         "the BitArray width check and the BitArray-level GF pair (TODO #314 "
         "pass 4) -- the Python half of the family C's exempted ba_ rule covers "
         "and Go's Try/Ba rules cover.  ba_gf_mul and ba_gf_pow are the "
         "BitArray-level twins of gf-mul and gf-pow, which the manifest names "
         "by their stem: this port's OPRF, threshold and Stern layers work on "
         "plain ints by their own protocol definitions, so both spellings "
         "exist and wrap ONE implementation rather than adding a second.  The "
         "width selects the polynomial, which is what BITARRAY.md 4.6 requires "
         "and what a `poly` parameter cannot enforce"),
    ],
    "java": [
        (r"^(checkWidth|hexVal|zero|fromHex|fromUint|gfPoly|rnlKdfSeed|fscx)$",
         "the BitArray width check, constructors, hex decoder and the "
         "BitArray-level statics (TODO #314 pass 5) -- the Java half of the "
         "family C's exempted ba_ rule covers, Go's Try/Ba rules cover and "
         "Python's _ba_check_width rule covers. BITARRAY.md specifies a TYPE; "
         "these are how one port spells its constructors. fscx here is the "
         "static on BitArray that Herradura.fscx -- which the manifest DOES "
         "name -- delegates to, so the cross-language cell is carried by the "
         "stem"),
        (r"^ba$",
         "the one-line BigInteger->BitArray adapter inside the threshold signer "
         "(TODO #314 pass 5). HPKS-T's aggregate keys and scalars are integers "
         "by the protocol's own definition, so that layer keeps BigInteger and "
         "crosses the boundary in one place rather than at twenty call sites; "
         "the other three ports have no boundary to cross because their scalar "
         "type and their bit-string type were never different"),
        (r"^(be2|be4|be8|be16|be32|rd4|readBe32|putS32|concat|concatAll|cat|slice|sub|"
         r"join|fixed|fixedBytes|toFixedBytes|toFixedBytesLE|fromLE|leReverseToInt|"
         r"writeBe64|readBe64|ascii|be4i|chunkToInts|bounded|boundedN)$",
         "byte-packing and array helpers. Java needs them where Go has "
         "encoding/binary and Python has int.to_bytes/slicing; C's are the "
         "exempted _be64 and ba_ families"),
        (r"^(rol|ror)$", "bit rotation. A macro in C, a one-line expression in Go and "
                         "Python; Java factors it out because BigInteger has no "
                         "rotate. ZkpNl's own rol is a DIFFERENT function at n=32 and "
                         "is manifest-named as zkp-nl-rol"),
        (r"^gateC$", "Java-only inner helper of hcred-gate-round (itself acknowledged), "
                     "one decomposition level further down"),
        (r"^(addmod|submod|mulmod|addmod3|floorMod3|maskOf|randomBig|"
         r"constantTimeEquals|toFixedBytes)$",
         "modular-arithmetic and comparison helpers that are operators or standard "
         "library calls in the other three (Python's %, Go's big.Int methods, "
         "crypto/subtle)"),
    ],
}


def _marker_names(spec_lang_pattern):
    """The function name a marker regex identifies: last identifier before `\\(`."""
    pattern = spec_lang_pattern
    if "::" in pattern:
        pattern = pattern.partition("::")[2]
    m = re.search(r"([A-Za-z_][A-Za-z0-9_]*)\s*\\\(", pattern)
    return m.group(1) if m else None


def check_census(errors):
    """Every suite-internal function must be manifest-named or exempted."""
    file_text, java_files = _suite_text()

    # Coverage is (file, name) for a file-scoped Java marker and (None, name)
    # otherwise.  Scoping matters: ZkpNl.rol and Herradura.rol are different
    # functions, and a name-only covered-set would let the entry for one
    # silently vouch for the other — the same collision the uniqueness check
    # in check_primitives() rejects on the marker side.
    covered = {lang: set() for lang in SUITE_FILES}
    for spec in PRIMITIVES.values():
        for lang in SUITE_FILES:
            if not spec.get(lang):
                continue
            name = _marker_names(spec[lang])
            if not name:
                continue
            scope = spec[lang].partition("::")[0] if "::" in spec[lang] else None
            covered[lang].add((scope, name))

    counts = {}
    for lang in SUITE_FILES:
        if lang == "java":
            declared = {
                (fname, n)
                for fname, text in java_files.items()
                for n in DECL_PATTERNS[lang].findall(text)
            }
        else:
            declared = {(None, n) for n in DECL_PATTERNS[lang].findall(file_text[lang])}
        cli_text = "\n".join(
            open(p, encoding="utf-8").read() for p in CLI_SOURCES[lang]
        )
        reachable = {
            (f, n) for (f, n) in declared
            if re.search(r"\b" + re.escape(n) + r"\s*\(", cli_text)
        }
        internal = declared - reachable
        rules = CENSUS_EXEMPT.get(lang, [])
        used = set()
        unclassified = []
        for scope, name in sorted(internal):
            if (scope, name) in covered[lang] or (None, name) in covered[lang]:
                continue
            hit = next((i for i, (rx, _) in enumerate(rules) if re.search(rx, name)), None)
            if hit is None:
                unclassified.append(f"{scope}:{name}" if scope else name)
            else:
                used.add(hit)
        for name in unclassified:
            errors.append(
                f"{lang}: suite-internal function {name!r} is named by no PRIMITIVES entry "
                f"and matched by no CENSUS_EXEMPT rule — give it a manifest entry (one "
                f"marker per language, or an 'acknowledged' reason), or add an exempt rule "
                f"saying why it is not a cross-language primitive"
            )
        for i, (rx, _) in enumerate(rules):
            if i not in used:
                errors.append(
                    f"{lang}: CENSUS_EXEMPT rule {rx!r} matched nothing — the family it "
                    f"excuses is gone or renamed, so the rule now only risks covering "
                    f"something else silently; delete or update it"
                )
        named = sum(
            1 for (scope, name) in internal
            if (scope, name) in covered[lang] or (None, name) in covered[lang]
        )
        counts[lang] = (len(declared), len(internal), named)
    return counts


# ── Parameter-value parity: the sixth axis (TODO #278) ─────────────────────
#
# The five axes above this one answer, in order: does the primitive EXIST in
# each language; does each CLI DISPATCH the --algo tag; does each CLI DEFINE
# the flag; which VALUES does it accept for that flag; and do the narrative
# documents restate the sources correctly.  NONE of them compares a numeric
# parameter's VALUE.  So `QCMDPC_MAX_MULT` can be 5 in three languages and 6
# in the fourth with every check green -- the function exists everywhere, has
# a manifest entry, dispatches its tag, takes the same flags.  TODO #276 hit
# that from one side and #277 from the other, where C's QC-MDPC PRF counter
# placement had disagreed with the other three since the protocol shipped.
#
# WHY THE ROWS ARE CURATED AND THE VALUES ARE NOT.  Names do not survive
# translation: `RNL_ETA` (C, Go) is `RNLB` (Python, Java), and Java scopes its
# constants per class, so `Stern.SDFR` and `SDF_ROUNDS` are the same parameter
# under two names in two shapes.  Only 8 of 116 normalised names appear in all
# four languages, so automatic pairing is not available.  What IS automatic is
# every number: a cell names the CONSTANT, never its value, and the checker
# reads and evaluates it from source.  A table that quoted values could go
# stale; this one cannot.
#
# EXHAUSTIVE IN BOTH DIRECTIONS, like every other table in spec/.  A suite
# constant named by no row and matched by no PARAM_CENSUS_EXEMPT rule fails.
# A PARAM_DIVERGENCE entry whose languages have CONVERGED fails until it is
# deleted, so closing a gap forces the claim out rather than leaving it stale.
# An exempt rule matching nothing is itself an error.  And a None cell -- "this
# language has no such constant" -- is checked rather than trusted, because a
# cell the EXTRACTOR dropped looks identical to one that genuinely does not
# exist, and the census cannot tell them apart: an unseen declaration is not an
# unfiled one.
#
# WHAT THIS AXIS CANNOT SEE, learned the hard way.  It reads DECLARATIONS, so it
# compares a bound's VALUE and never whether that bound is APPLIED.  XMSS_MAX_H
# is 20 in all four languages and, until TODO #278, was enforced at genpkey by
# two of them -- Python's and Java's own comments called the constant "genpkey's
# --xmss-height cap" and neither applied it there.  Nothing here could have
# found that; CliTest/test_param_bounds.sh runs the four CLIs, which can.


_PARAM_VALUE = re.compile(r"[0-9A-Za-z_+\-*/() .,]+$")


def _strip_comments(text):
    text = re.sub(r"/\*.*?\*/", " ", text, flags=re.S)
    return re.sub(r"//[^\n]*", " ", text)


def _c_params(src):
    r"""Object-like #define with an arithmetic body.

    `(?!\()` after the name is what makes it object-like -- a function-like
    macro has its parenthesis flush against the name.  The body is then taken to
    end of line and stripped, deliberately NOT matched shape-first: an earlier
    form of this required the body to be either unparenthesised or a whole
    parenthesised group anchored at "$", which silently dropped
    `#define R3_VALUE (5 * KEYBITS / 8)   /* 160 */` -- comment stripping leaves
    trailing spaces, so the closing paren was no longer at the end of the line.
    A dropped declaration is invisible to the census (an unseen constant is not
    an unfiled one), so the absent-cell cross-check below exists to catch the
    same class a second way."""
    out = {}
    src = _strip_comments(src)
    for m in re.finditer(r"^#define\s+([A-Za-z_]\w*)(?!\()\s+([^\n]*)$", src, re.M):
        v = m.group(2).strip()
        if v and _PARAM_VALUE.fullmatch(v):
            out.setdefault(m.group(1), v)
    return out


def _go_params(src):
    """Only `const (...)` blocks and `const X = ...` lines -- never a
    function-local assignment, which is not a parameter."""
    out = {}
    src = _strip_comments(src)
    for m in re.finditer(r"^const\s*\(", src, re.M):
        end = src.find("\n)", m.end())
        if end < 0:
            continue
        for line in src[m.end():end].split("\n"):
            mm = re.match(r"\s*([A-Za-z_]\w*)\s*(?:[A-Za-z_]\w*\s*)?=\s*(.+?)\s*$", line)
            if mm and _PARAM_VALUE.fullmatch(mm.group(2)):
                out.setdefault(mm.group(1), mm.group(2))
    for m in re.finditer(r"^const\s+([A-Za-z_]\w*)\s*(?:[A-Za-z_]\w*\s*)?=\s*(.+?)\s*$", src, re.M):
        if _PARAM_VALUE.fullmatch(m.group(2)):
            out.setdefault(m.group(1), m.group(2))
    return out


def _py_params(src):
    """Module scope only -- an indented assignment is a local, not a parameter."""
    out = {}
    for m in re.finditer(r"^(_?[A-Z][A-Z0-9_]*)\s*(?::\s*int)?\s*=\s*([^\n#]+)", src, re.M):
        v = m.group(2).strip()
        if _PARAM_VALUE.fullmatch(v):
            out.setdefault(m.group(1), v)
    return out


def _java_params(java_files):
    """`static final int/long/double/float`, keyed Class.NAME because Java
    scopes per class.  double/float are read for the same reason the evaluator
    keeps floats: a threshold-rule coefficient is a parameter like any other,
    and reading only integer declarations would drop it silently."""
    out = {}
    for fname, text in sorted(java_files.items()):
        cls = fname[:-5]
        for m in re.finditer(
            r"static\s+final\s+(?:int|long|double|float)\s+([A-Za-z_]\w*)\s*=\s*([^;]+);",
            _strip_comments(text),
        ):
            v = m.group(2).strip()
            if _PARAM_VALUE.fullmatch(v):
                out.setdefault(f"{cls}.{m.group(1)}", v)
    return out


def _param_eval(expr, table, lang, depth=0, cls=None):
    """Resolve an expression to a number, following references within its own
    language.  Returns None for anything that is not arithmetic -- a hash IV,
    a macro alias, a type name -- which the census then has to exempt.

    INTEGRAL RESULTS COME BACK AS int, non-integral ones as float, and the
    distinction matters: coercing everything to int read QCMDPC_TH_SLOPE
    (0.0069722) as 0 in all four languages, which is an equality no drift could
    ever break.  A threshold-rule coefficient is exactly the kind of constant
    this axis exists to compare, so it has to survive evaluation intact."""
    if depth > 12:
        return None
    e = expr.strip()
    # A C/Java `(int)` cast TRUNCATES, and the cast has to be applied rather
    # than merely removed: Hcred's W_MAX is `(int)(n/4.0 + 4*sqrt(3n/16))`,
    # which is 91.71 before the cast and 91 after.  Coercing every result to
    # int used to re-apply it by accident; once non-integral results survive,
    # dropping the cast makes C's literal 91 and Java's expression disagree.
    cast_int = re.search(r"\(int\)", e) is not None
    e = re.sub(r"\(int\)\s*", "", e)
    e = (e.replace("Math.sqrt", "__sqrt")
          .replace("Math.max", "__max")
          .replace("Math.min", "__min"))
    e = re.sub(r"(?<![0-9A-Za-z_.])max\(", "__max(", e)
    e = re.sub(r"(?<![0-9A-Za-z_.])min\(", "__min(", e)

    def resolve(m):
        name = m.group(0)
        if name in ("__sqrt", "__max", "__min"):
            return name
        for cand in (name, "_" + name):
            if cand in table:
                v = _param_eval(table[cand], table, lang, depth + 1, cls)
                return f"({v})" if v is not None else "None"
        if lang == "java":
            # own class first, then any other -- see the docstring
            order = ([f"{cls}.{name}"] if cls else []) + [
                k for k in sorted(table) if k.endswith("." + name)]
            for key in order:
                if key in table:
                    owner = key.split(".", 1)[0]
                    v = _param_eval(table[key], table, lang, depth + 1, owner)
                    return f"({v})" if v is not None else "None"
        return "None"

    e = re.sub(r"(?<![0-9A-Za-z_])(?!0[xX])[A-Za-z_]\w*(?:\.\w+)*", resolve, e)
    if "None" in e:
        return None
    if lang != "python" and not re.search(r"\d\.\d|\.\d|\d\.", e):
        # C/Go/Java `/` on ints truncates -- but only on ints.  An expression
        # carrying a float literal divides as a float in all four, so the
        # rewrite is skipped there rather than silently truncating it.
        e = re.sub(r"(?<![/])/(?![/])", "//", e)
    try:
        v = eval(e, {"__builtins__": {}},
                 {"__sqrt": math.sqrt, "__max": max, "__min": min})
    except Exception:
        return None
    try:
        if cast_int:
            return int(v)
        return int(v) if float(v).is_integer() else float(v)
    except Exception:
        return None


PARAMETERS = {
    # ── classical core (v1.4.0) ──
    "keybits": (["KEYBITS", None, "KEYBITS", "Herradura.N"], "wire",
                "the suite block width"),
    "fscx-i-steps": (["I_VALUE", None, "I_VALUE", "Herradura.I_STEPS"], "wire",
                     "i = n/4, the forward FSCX_REVOLVE step count"),
    "fscx-r-steps": (["R_VALUE", None, "R_VALUE", "Herradura.R_STEPS"], "wire",
                     "r = 3n/4, the inverse step count"),
    "block-bytes": (["KEYBYTES", None, "_QCPRF_BLOCK_BYTES", "Hfscx256.BLOCK"], "wire",
                    "n/8, one block in bytes"),
    "fscx-closed-form-min": (["FSCX_CLOSED_FORM_MIN_STEPS", None, None, None], "local",
                             "step count below which the O(log i) closed form is not "
                             "worth taking (TODO #213); C alone ships the closed form"),
    # ── BitArray capacity (TODO #314 pass 2) ──
    "ba-max-bits": (["BA_MAX_BITS", "BAMaxBits", "BA_MAX_BITS", "BitArray.BA_MAX_BITS"],
                    "local",
                    "the BitArray's per-port CAPACITY, not a width (BITARRAY.md 2/9).  "
                    "ALL FOUR PORTS ARE CONVERTED (passes 2-5) and all four carry it.  "
                    "Only C needs one -- its buffer is fixed -- while Go, Python and "
                    "Java allocate exactly nbits/8 octets and carry it anyway so that "
                    "all four answer E_WIDTH to the same inputs, which is what "
                    "KAT/bitarray.json pins.  LOCAL, and "
                    "the distinction is the point -- capacity is NOT observable, since "
                    "every operation's result depends on nbits and the active octets "
                    "only, so a port with more room cannot diverge by having it.  The "
                    "reference generator is held to the same 256 for exactly that reason, "
                    "which keeps every case in KAT/bitarray.json capacity-independent"),
    "ba-max-bytes": (["BA_MAX_BYTES", None, None, None], "local",
                     "BA_MAX_BITS/8, the capacity buffer's length (TODO #314).  Go's "
                     "cell is None and stays None: that constant is the length of C's "
                     "FIXED capacity buffer, and Go allocates exactly nbits/8 octets, "
                     "so there is nothing for it to name.  Declared anyway it would be "
                     "a constant no code reads -- the defect TODO #295's use census "
                     "exists to catch, and it fired here on the first draft of pass 3"),
    # ── NL-FSCX v3 (TODO #255) ──
    "nl-v3-i-steps": (["I3_VALUE", "I3Value", "I3_VALUE", "Duplex.I3_VALUE"], "wire",
                      "5n/16, the v3 duplex step count"),
    "nl-v3-r-steps": (["R3_VALUE", "R3Value", "R3_VALUE", "HerraduraNl.R3_VALUE"], "wire",
                      "R3_VALUE = 5n/8 = 160, derived in TODO #255"),
    "duplex-rate": (["_V2DPLEX_RATE", "v2dplexRate", "_V2DPLEX_RATE", "Duplex.RATE"],
                    "wire", "sponge rate in bytes"),
    # ── HKEX-RNL ──
    "rnl-n": (["RNL_N", "RnlN", "RNLN", "HerraduraNl.RNLN"], "wire",
              "ring dimension, moved 256 -> 1024 by TODO #223"),
    "rnl-q": (["RNL_Q", "RnlQ", "RNLQ", "HerraduraNl.RNLQ"], "wire", "ring modulus"),
    "rnl-p": (["RNL_P", "RnlP", "RNLP", "HerraduraNl.RNLP"], "wire",
              "public-key rounding modulus"),
    "rnl-pp": (["RNL_PP", "RnlPP", "RNLPP", "HerraduraNl.RNLPP"], "wire",
               "reconciliation modulus"),
    "rnl-eta": (["RNL_ETA", "RnlEta", "RNLB", "HerraduraNl.RNLB"], "wire",
                "CBD eta.  NAMED DIFFERENTLY IN EVERY PAIR -- eta in C and Go, B in "
                "Python and Java -- which is why these rows are curated"),
    "rnl-log2n": (["RNL_LOG2N", None, None, None], "local",
                  "log2 of the ring dimension, for C's fixed-width NTT twiddle tables; "
                  "the other three compute it"),
    "rnl-alt-n": (["RNL_ALT_N", None, None, None], "local",
                  "the second ring dimension C compiles, static-asserted equal to "
                  "HCRED_N; the other three take a width argument"),
    "sigma-max-attempts": (["SIGMA_MAX_ATTEMPTS", "sigmaMaxAttempts",
                            "_SIGMA_MAX_ATTEMPTS", "HerraduraNl.SIGMA_MAX_ATTEMPTS"],
                           "local", "rejection-sampling retry budget in the Ring-LWR "
                           "Sigma protocol; exceeding it is an error, not an output"),
    # ── HPKS-Stern-F ──
    "sdf-n-rows": (["SDF_N_ROWS", "SdfNRows", "SDFNR", "Stern.SDFNR"], "wire",
                   "n/2 parity-check rows"),
    "sdf-t": (["SDF_T", "SdfT", "SDFT", "Stern.SDFT"], "wire", "error weight t"),
    "sdf-rounds-demo": (["SDF_ROUNDS", "SdfRounds", "SDFR", "Stern.SDFR"], "wire",
                        "signing default; the count travels in the PEM, so a reader "
                        "accepts any count in [1, SDF_MAX_ROUNDS] (TODO #236)"),
    "sdf-rounds-prod": (["SDF_PRODUCTION_ROUNDS", "SdfProductionRounds",
                         "_STERN_F_PRODUCTION_ROUNDS", "Stern.STERN_F_PRODUCTION_ROUNDS"],
                        "wire", "219 rounds for 128-bit Fiat-Shamir soundness (#217, #222)"),
    "sdf-max-rounds": (["SDF_MAX_ROUNDS", "SdfMaxRounds", None, None], "local",
                       "bound on a round count decoded from a PEM.  Python and Java "
                       "keep it in their CLI and codec layers respectively "
                       "(HerraduraCli/herradura.py's _SDF_MAX_ROUNDS, Codec.java's "
                       "SDF_MAX_ROUNDS), both at 4096; it is a wire-decode bound, so "
                       "that is arguably its right home and C and Go are the outliers"),
    "sdf-synbytes": (["SDF_SYNBYTES", None, None, None], "local",
                     "syndrome length in bytes, for C's fixed-size buffers"),
    # ── HPKE-Stern-KEM (QC-MDPC) ──
    "qcmdpc-r": (["QCMDPC_R", "QcMdpcR", "_QCMDPC_R", "Stern.QCMDPC_R"], "wire",
                 "block size; TODO #276 recommends 12323"),
    "qcmdpc-d": (["QCMDPC_D", "QcMdpcD", "_QCMDPC_D", "Stern.QCMDPC_D"], "wire",
                 "row weight"),
    "qcmdpc-t": (["QCMDPC_T", "QcMdpcT", "_QCMDPC_T", "Stern.QCMDPC_T"], "wire",
                 "error weight"),
    "qcmdpc-nb-iter": (["QCMDPC_NB_ITER", "QcMdpcNbIter", "_QCMDPC_NB_ITER",
                        "Stern.QCMDPC_NB_ITER"], "local",
                       "BGF decoder iterations.  LOCAL and it matters: this changes the "
                       "DFR, not the ciphertext, so a language that lowered it would "
                       "fail to decapsulate slightly more often and no test would say so"),
    "qcmdpc-th-slope": (["QCMDPC_TH_SLOPE", "QcMdpcThSlope", "_QCMDPC_TH_SLOPE",
                         "Stern.QCMDPC_TH_SLOPE"], "local",
                        "BIKE L1 threshold rule, slope in the syndrome weight "
                        "(TODO #276).  LOCAL, and the reason is the same as "
                        "qcmdpc-nb-iter's only sharper: the rule changes the "
                        "DFR, not the ciphertext, so a language that mistyped a "
                        "digit here would decapsulate slightly more often and "
                        "every round-trip and interop test would still pass.  "
                        "This is also the row that made the evaluator keep "
                        "floats -- as an int it read 0 in all four"),
    "qcmdpc-th-offset": (["QCMDPC_TH_OFFSET", "QcMdpcThOffset", "_QCMDPC_TH_OFFSET",
                          "Stern.QCMDPC_TH_OFFSET"], "local",
                         "BIKE L1 threshold rule, constant term"),
    "qcmdpc-th-min": (["QCMDPC_TH_MIN", "QcMdpcThMin", "_QCMDPC_TH_MIN",
                       "Stern.QCMDPC_TH_MIN"], "local",
                      "BIKE L1 threshold floor.  At d=15 it exceeds the row "
                      "weight outright, which is why the rule and the "
                      "parameters cannot be ported separately"),
    "qcmdpc-tau": (["QCMDPC_TAU", "QcMdpcTau", "_QCMDPC_TAU", "Stern.QCMDPC_TAU"],
                   "local",
                   "gray band width; BIKE's is 3, the toy set's decoder used 2"),
    "qcmdpc-max-mult": (["QCMDPC_MAX_MULT", "qcMdpcMaxMult", "_QCMDPC_MAX_MULT",
                         "Stern.QCMDPC_MAX_MULT"], "local",
                        "weak-key screen threshold.  THE ROW TODO #276 ASKED FOR: it "
                        "gates keygen retries only, so a partial update across the four "
                        "languages changes which keys each accepts and nothing "
                        "downstream disagrees.  Test [51] pins the screen's behaviour "
                        "at this value in all four, but not the value itself"),
    "qcmdpc-rbytes": (["QCMDPC_RBYTES", "QcMdpcRBytes", None, None], "local",
                      "ceil(r/8); Python and Java size their buffers from big integers"),
    "qceuc-bytes": (["_QCEUC_BYTES", None, None, None], "local",
                    "scratch length for C's fixed-width extended-Euclid over "
                    "GF(2)[x]/(x^r - 1); the other three carry big integers"),
    "qceuc-words": (["_QCEUC_WORDS", None, None, None], "local",
                    "the same scratch length in uint64_t limbs, which is what the "
                    "extended Euclid has operated on since TODO #334; the other "
                    "three carry big integers and have no limb count to name"),
    "qcmdpc-rwords": (["QCMDPC_RWORDS", None, None, None], "local",
                      "ceil(r/64), C's limb count for the fixed-width QcPoly"),
    "qcmdpc-ds-k": (["QCMDPC_DS_K", "qcMdpcDsK", "_QCMDPC_DS_K", "Stern.QCMDPC_DS_K"],
                    "wire", "domain separator for the KEM session key"),
    "qcmdpc-ds-z": (["QCMDPC_DS_Z", "qcMdpcDsZ", "_QCMDPC_DS_Z", "Stern.QCMDPC_DS_Z"],
                    "wire", "domain separator for the implicit-rejection key"),
    "qcmdpc-ds-zseed": (["QCMDPC_DS_ZSEED", "qcMdpcDsZSeed", "_QCMDPC_DS_ZSEED",
                         "Stern.QCMDPC_DS_ZSEED"], "wire",
                        "domain separator for the z seed derived from the private key"),
    "qcprf-max-idx-bytes": (["QCPRF_MAX_IDX_BYTES", "qcprfMaxIdxBytes",
                             "_QCPRF_MAX_IDX_BYTES", "Stern.MAX_IDX_BYTES"], "wire",
                            "widest uniform index draw (TODO #277); the draw WIDTH is "
                            "derived from the modulus, so this only bounds it"),
    # ── HPKS-WOTS-F / HPKS-XMSS-F ──
    "wots-w": (["WOTS_W", "WotsW", "_WOTS_W", "Wots.W"], "wire", "Winternitz parameter"),
    "wots-log2w": (["WOTS_LOG2W", "WotsLog2W", "_WOTS_LOG2W", "Wots.LOG2W"], "wire",
                   "log2(w)"),
    "wots-l1": (["WOTS_L1", "WotsL1", "_WOTS_L1", "Wots.L1"], "wire", "message chains"),
    "wots-l2": (["WOTS_L2", "WotsL2", "_WOTS_L2", "Wots.L2"], "wire", "checksum chains"),
    "wots-l": (["WOTS_L", "WotsL", "_WOTS_L", "Wots.L"], "wire", "total chains"),
    "xmss-default-h": ([None, None, "_XMSS_H", "Xmss.DEFAULT_H"], "local",
                       "default Merkle tree height.  C and Go take h as a REQUIRED "
                       "argument and have no default; all four CLIs supply 10, so the "
                       "agreement is at the CLI layer, not this one"),
    # ── ZKP-NL ──
    "zkp-nl-default-n": (["ZKP_NL_DEFAULT_N", "ZkpNlDefaultN", "_ZKP_NL_DEFAULT_N", None],
                         "wire", "default statement width; Java takes n per call"),
    "zkp-nl-demo-rounds": (["ZKP_NL_DEMO_ROUNDS", "ZkpNlDemoRounds", "_ZKP_NL_DEMO_ROUNDS",
                            None], "wire", "demo round count; Java takes rounds per call"),
    "zkp-nl-prod-rounds": (["ZKP_NL_PROD_ROUNDS", "ZkpNlProdRounds", "_ZKP_NL_PROD_ROUNDS",
                            "Hcred.CLI_ROUNDS"], "wire",
                           "219 rounds for 128-bit soundness; Java names it for the "
                           "CLI, which is its only caller"),
    "zkp-nl-max-n": (["ZKP_NL_MAX_N", "ZkpNlMaxN", "_ZKP_NL_MAX_N", "ZkpNl.MAX_N"],
                     "wire", "largest statement width the verifier accepts"),
    "zkp-nl-max-rounds": ([None, "ZkpNlMaxRounds", "_ZKP_NL_MAX_ROUNDS", "ZkpNl.MAX_ROUNDS"],
                          "local", "bound on a round count decoded from a proof; C "
                          "bounds it in its CLI against SDF_MAX_ROUNDS instead"),
    "zkpp-seed-bytes": (["ZKPP_SEED_BYTES", "zkppSeedBytes", "_ZKPP_SEED_BYTES",
                         "ZkpNl.ZKPP_SEED_BYTES"], "wire", "per-round commitment seed"),
    # ── HCRED ──
    "hcred-n": (["HCRED_N", "HcredMaxN", "_HCRED_DEFAULT_N", "Hcred.N"], "wire",
                "the statement width"),
    "hcred-rows": (["HCRED_ROWS", None, None, "Hcred.ROWS"], "wire",
                   "n/2 rows; Go and Python derive it from the runtime width"),
    "hcred-row-bits": (["HCRED_ROW_BITS", None, None, "Hcred.ROW_BITS"], "wire",
                       "bits per row sum.  A LITERAL 9 in C and Java against Python's "
                       "n.bit_length(); the same number at n=256 by construction, and "
                       "the derived form is the one that survives a width change"),
    "hcred-eps-bits": (["HCRED_EPS_BITS", "HcredEpsBits", "_HCRED_EPS_BITS",
                        "Hcred.EPS_BITS"], "wire", "bits per epsilon share"),
    "hcred-eps-off": (["HCRED_EPS_OFF", "HcredEpsOff", "_HCRED_EPS_OFF", "Hcred.EPS_OFF"],
                      "wire", "epsilon offset"),
    "hcred-w-max": (["HCRED_W_MAX", None, None, "Hcred.W_MAX"], "wire",
                    "witness weight bound.  A LITERAL 91 in C against Java's "
                    "n/4 + 4*sqrt(3n/16); equal at n=256, and only one of them stays "
                    "right if n moves"),
    "hcred-demo-rounds": (["HCRED_DEMO_ROUNDS", None, "_HCRED_DEMO_ROUNDS",
                           "Hcred.DEMO_ROUNDS"], "wire", "demo round count"),
    "hcred-nb": (["HCRED_NB", None, None, None], "local", "bit-decomposition wire count"),
    "hcred-nd": (["HCRED_ND", None, None, None], "local", "delta-share wire count"),
    "hcred-kkw-i": (["HCRED_KKW_I", None, None, None], "local", "KKW input wires"),
    "hcred-kkw-g": (["HCRED_KKW_G", None, None, None], "local", "KKW gate count"),
    "hcred-kkw-k": (["HCRED_KKW_K", None, None, None], "local", "KKW output wires"),
    "hcred-kkw-demo-n": (["HCRED_KKW_DEMO_N", "HcredKkwDemoN", "_HCRED_KKW_DEMO_N",
                          "Hcred.KKW_DEMO_N"], "wire", "KKW parties, demo"),
    "hcred-kkw-demo-m": (["HCRED_KKW_DEMO_M", "HcredKkwDemoM", "_HCRED_KKW_DEMO_M",
                          "Hcred.KKW_DEMO_M"], "wire", "KKW preprocessing emulations, demo"),
    "hcred-kkw-demo-tau": (["HCRED_KKW_DEMO_TAU", "HcredKkwDemoTau", "_HCRED_KKW_DEMO_TAU",
                            "Hcred.KKW_DEMO_TAU"], "wire", "KKW online executions, demo"),
    "hcred-kkw-max-levels": (["HCRED_KKW_MAX_LEVELS", None, None, None], "local",
                             "Merkle depth bound on a decoded KKW proof, C only"),
    "hcred-round-outs-ser": (["HCRED_ROUND_OUTS_SER", None, None, None], "local",
                             "serialized per-round output length, C's fixed buffer"),
    "hcred-inv2": ([None, None, None, "Hcred.INV2"], "local",
                   "(q+1)/2 mod q; the other three write the expression inline"),
    # ── aPAKE ──
    "hpake-rounds": (["HPAKE_ROUNDS", "HpakeRounds", "_HPAKE_ROUNDS", "Hpake.ROUNDS"],
                     "wire", "Sigma rounds in the aPAKE transcript"),
    "hpake-zkp-n": (["HPAKE_ZKP_N", "HpakeZkpN", "_HPAKE_ZKP_N", "Hpake.ZKP_N"], "wire",
                    "statement width inside the aPAKE proof"),
    # ── fpe / twk domain separators (TODO #242, #255) ──
    "fpe-ds": (["FPE_DS", "fpeDS", "_FPE_DS", "FpeTwk.FPE_DS"], "wire",
               "fpe subkey domain separator"),
    "twk-ds": (["TWK_DS", "twkDS", "_TWK_DS", "FpeTwk.TWK_DS"], "wire",
               "twk subkey domain separator; distinct from fpe's since TODO #242"),
    "fpe-v3-ds": (["FPE_V3_DS", "fpeV3DS", "_FPE_V3_DS", "FpeTwk.FPE_V3_DS"], "wire",
                  "fpe --v3 subkey domain separator"),
    "twk-v3-ds": (["TWK_V3_DS", "twkV3DS", "_TWK_V3_DS", "FpeTwk.TWK_V3_DS"], "wire",
                  "twk --v3 subkey domain separator"),
    # ── misc ──
    "gf-generator": ([None, "GfGen", "GF_GEN", None], "wire",
                     "g = 3, the GF(2^n)* generator.  C holds it as a BitArray literal "
                     "and Java as a BigInteger, neither of which is an int declaration, "
                     "so only two of the four are readable here"),
    "hpkst-n": ([None, "hpkstN", None, "HpksT.N"], "local",
                "threshold-signature width; C and Python use the suite width directly"),
    "hybrid-combine-ds": ([None, None, None, "HerraduraNl.HYBRID_COMBINE_DS"], "local",
                          "hybrid KEX combiner domain separator; the other three write "
                          "the byte at the call site"),
    "hkx-algo-nla1": ([None, None, None, "Hfscx256.HKX_ALGO_NLA1"], "wire",
                      "HSKE-NL-A1 format tag; the other three write it at the call site"),
    "aead-ds-len": (["_AEAD_DS_LEN", None, None, None], "local",
                    "length of the AEAD domain-separation string, C's fixed buffer"),
    "v2dplex-ds-init": (["_V2DPLEX_DS_INIT_L", None, None, None], "local",
                        "duplex init DS length, C's fixed buffer"),
    "v2dplex-ds-tag": (["_V2DPLEX_DS_TAG_L", None, None, None], "local",
                       "duplex tag DS length, C's fixed buffer"),
    "v2dplex-ds-tweak": (["_V2DPLEX_DS_TWEAK_L", None, None, None], "local",
                         "duplex tweak DS length, C's fixed buffer"),
}

# Java has no header, so a class re-declares the width it needs.  These are not
# exempt from the axis -- they are CHECKED against the row they copy, because a
# re-declaration that drifted is exactly the defect this table exists to find.
PARAM_JAVA_ALIASES = {
    "keybits": ["Duplex.N", "FpeTwk.N", "Hdrbg.N", "HerraduraNl.N", "Hfscx256.N",
                "Ratchet.N", "Stern.N", "SternRing.N", "Wots.N"],
    # Hfscx256.NL_V1_SHIFT was here until TODO #314 pass 6 DELETED it: the
    # NL-FSCX v1 round's rotation is n/4 at the OPERAND's width, not a static
    # copy of N/4, and a re-declaration that can only be right at one width is
    # what kept Java's hske-nla1 keystream disagreeing with the other three
    # below 256.  The alias going away IS the fix; do not re-add it.
    "fscx-i-steps": ["Duplex.I_VALUE", "Hdrbg.I_VALUE", "HpksT.I_STEPS"],
    "fscx-r-steps": ["FpeTwk.R_VALUE"],
    "block-bytes": ["Duplex.BLOCK", "Hdrbg.BLOCK", "Hfscx256.HKX_BLOCK",
                    "HerraduraNl.AEAD_BLOCK"],
    "rnl-p": ["Hcred.RNLP"],
    "rnl-q": ["Hcred.RNLQ"],
}

# A row whose languages legitimately differ.  Values are RECORDED, so a change
# to any of them fails; and a row whose languages have CONVERGED fails until it
# is deleted -- the orphan rule, one level down from cli_flag_value_gaps.
PARAM_DIVERGENCE = {
    "hcred-n": {
        "status": "acknowledged",
        "values": {"c": 256, "go": 256, "python": 32, "java": 256},
        "reason":
            "Four cells, three MEANINGS -- which is the finding, not the numbers.  "
            "HCRED_N and Hcred.N are compile-time WIDTHS (C static-asserts its against "
            "RNL_ALT_N); HcredMaxN is a runtime MAXIMUM; _HCRED_DEFAULT_N is a runtime "
            "DEFAULT, and Python demos at 32.  So the four have never proved the same "
            "statement size, which KAT/hcred_kkw.json already records by shipping two "
            "vector sets.  Deliberate per-language scope, not a defect.",
    },
}


PARAM_LANGS = ("c", "go", "python", "java")


PARAM_CENSUS_EXEMPT = {
    "c": [(r"^QCMDPC_NPLANE$",
           "the BGF decoder's counter PLANE COUNT (TODO #330), not a protocol "
           "parameter: it is max(4, bit_length(QCMDPC_D)) -- which IS a row -- "
           "and C needs it as a macro only because it sizes an array.  Go and "
           "Java derive it at run time through qcmdpc-planes and Python writes "
           "the expression inline, so there is no second value anywhere to "
           "hold it against; a _Static_assert in herradura.h ties it to "
           "QCMDPC_D, which is the check a PARAMETERS row would otherwise be")],
    "python": [(r"^_RNL_KDF_DC_", "the HFSCX-256 KDF's initialisation constants -- a "
                                  "hash IV, not a protocol parameter.  C keeps the same "
                                  "values and Go and Java build them inline")],
}


def _param_tables():
    file_text, java_files = _suite_text()
    return {
        "c": _c_params(file_text["c"]),
        "go": _go_params(file_text["go"]),
        "python": _py_params(file_text["python"]),
        "java": _java_params(java_files),
    }


def _param_norm(name):
    """A language-independent key for a constant name: drop the Java class
    prefix and the Python underscore, then case- and underscore-fold.  Exact
    enough to pair RNL_N / RnlN / RNLN / HerraduraNl.RNLN, and deliberately not
    clever enough to pair RNL_ETA with RNLB -- that is what the curated rows are
    for.  Used only by the absent-cell cross-check, never to build a row."""
    return name.split(".")[-1].lstrip("_").replace("_", "").upper()


def _java_cls(lang, name):
    """The class an unqualified reference inside `name` resolves against."""
    return name.split(".", 1)[0] if lang == "java" else None


def check_parameters(errors):
    T = _param_tables()
    claimed = {l: set() for l in PARAM_LANGS}
    observed = {}
    for rid, (cells, observable, meaning) in sorted(PARAMETERS.items()):
        if observable not in ("wire", "local"):
            errors.append(f"parameter {rid!r}: observable must be 'wire' or 'local'")
        if not meaning:
            errors.append(f"parameter {rid!r}: no meaning recorded")
        vals = {}
        for lang, name in zip(PARAM_LANGS, cells):
            if name is None:
                continue
            claimed[lang].add(name)
            if name not in T[lang]:
                errors.append(f"parameter {rid!r}: {lang} names {name!r}, which is not a "
                              f"declaration in that language's suite source — renamed, "
                              f"moved, or deleted")
                continue
            v = _param_eval(T[lang][name], T[lang], lang, cls=_java_cls(lang, name))
            if v is None:
                errors.append(f"parameter {rid!r}: {lang}'s {name!r} does not evaluate "
                              f"to an integer ({T[lang][name]!r})")
                continue
            vals[lang] = v
        if not vals:
            errors.append(f"parameter {rid!r}: names no constant in any language")
            continue
        observed[rid] = vals
        # A None cell claims the language has no named constant for this row.
        # Check it, rather than trusting it: a cell the EXTRACTOR silently
        # dropped looks exactly like a language that genuinely lacks the
        # constant, and the census cannot tell them apart -- an unseen
        # declaration is not an unfiled one.  (This is not hypothetical: an
        # earlier C regex dropped R3_VALUE and I3_VALUE, whose bodies end in a
        # comment, and the nl-v3 rows silently compared three languages instead
        # of four.)
        wanted = {_param_norm(n) for n in cells if n}
        for lang, name in zip(PARAM_LANGS, cells):
            if name is not None:
                continue
            for cand in T[lang]:
                if _param_norm(cand) in wanted:
                    errors.append(
                        f"parameter {rid!r}: {lang} is recorded as having no named "
                        f"constant, but {cand!r} = "
                        f"{_param_eval(T[lang][cand], T[lang], lang, cls=_java_cls(lang, cand))} "
                        f"matches this row's name — fill the cell in, so the value is "
                        f"actually compared")
                    break
        # Java re-declarations must agree with the row they copy
        for alias in PARAM_JAVA_ALIASES.get(rid, []):
            claimed["java"].add(alias)
            if alias not in T["java"]:
                errors.append(f"parameter {rid!r}: java alias {alias!r} no longer exists")
                continue
            av = _param_eval(T["java"][alias], T["java"], "java",
                             cls=_java_cls("java", alias))
            if av != vals.get("java", next(iter(vals.values()))):
                errors.append(f"parameter {rid!r}: java re-declaration {alias!r} is {av}, "
                              f"not {vals.get('java')}")
        div = PARAM_DIVERGENCE.get(rid)
        if div is None:
            if len(set(vals.values())) > 1:
                errors.append(f"parameter {rid!r} ({meaning}): languages disagree — "
                              + ", ".join(f"{l}={v}" for l, v in sorted(vals.items()))
                              + " — record it in PARAM_DIVERGENCE with a reason, or fix it")
        else:
            if len(set(vals.values())) == 1:
                errors.append(f"PARAM_DIVERGENCE[{rid!r}] describes a disagreement that no "
                              f"longer exists (every language is {next(iter(vals.values()))}) "
                              f"— delete the entry")
            elif div["values"] != vals:
                errors.append(f"PARAM_DIVERGENCE[{rid!r}] records {div['values']} but the "
                              f"sources say {vals} — re-check the reason, then update it")
            if div.get("status") not in ("defect", "acknowledged"):
                errors.append(f"PARAM_DIVERGENCE[{rid!r}]: status must be 'defect' or "
                              f"'acknowledged'")
            if not div.get("reason"):
                errors.append(f"PARAM_DIVERGENCE[{rid!r}]: no reason recorded")
    for rid in PARAM_DIVERGENCE:
        if rid not in PARAMETERS:
            errors.append(f"PARAM_DIVERGENCE[{rid!r}] names no PARAMETERS row")
    for rid in PARAM_JAVA_ALIASES:
        if rid not in PARAMETERS:
            errors.append(f"PARAM_JAVA_ALIASES[{rid!r}] names no PARAMETERS row")
    # census
    counts = {}
    for lang in PARAM_LANGS:
        rules = PARAM_CENSUS_EXEMPT.get(lang, [])
        used = [False] * len(rules)
        evaluable = {k for k in T[lang]
                     if _param_eval(T[lang][k], T[lang], lang,
                                    cls=_java_cls(lang, k)) is not None}
        unfiled = []
        for name in sorted(evaluable - claimed[lang]):
            hit = False
            for i, (pat, _why) in enumerate(rules):
                if re.search(pat, name):
                    used[i] = True
                    hit = True
                    break
            if not hit:
                unfiled.append(name)
        for name in unfiled:
            errors.append(f"{lang}: suite parameter {name!r} = "
                          f"{_param_eval(T[lang][name], T[lang], lang, cls=_java_cls(lang, name))} is named by no "
                          f"PARAMETERS row and matched by no PARAM_CENSUS_EXEMPT rule")
        for i, ok in enumerate(used):
            if not ok:
                errors.append(f"{lang}: PARAM_CENSUS_EXEMPT rule {rules[i][0]!r} matches "
                              f"nothing — delete it")
        counts[lang] = (len(evaluable), len(evaluable & claimed[lang]))
    return counts, observed


# ---------------------------------------------------------------------------
# THE SEVENTH AXIS: is a declared parameter actually READ? (TODO #295)
#
# PARAMETERS above compares a constant's VALUE across the four languages and the
# parameter census asserts every suite constant is named by a row.  Both read
# DECLARATIONS.  Neither asks whether the code that constant governs ever
# consults it -- and a constant declared in all four languages and read by one
# of them passes every check in this file while the other three carry its value
# as a literal.
#
# That is not hypothetical and it is not rare.  When #295 was written this
# census flagged TEN cells across SIX rows, and every language was an offender:
#
#   rnl-eta       C, Go, Java  the CBD samplers hardcoded the eta = 1 bit-pair
#                              extraction; only Python's _rnl_cbd_poly took eta
#                              as an argument and branched on it.  Raising
#                              RNL_ETA would have moved Python's secret
#                              distribution and left three languages sampling
#                              CBD(1), with the PARAMETERS row still green
#                              because all four still DECLARED the same number
#   sdf-t         Go           six call sites wrote `n / 16`; SdfT's only two
#                              appearances were banner Printf arguments
#   sdf-n-rows    Go           `seed.size / 2` at the call site
#   nl-v3-i-steps Go           `5*n/16` at the call site
#   wots-log2w    C, Go        the literals `4` and `0xF`, four places, with the
#                              derivation written in the COMMENT beside the
#                              declaration instead of performed
#   qcmdpc-w      C            vestigial: nothing in any language computes the
#                              full row weight, so both it and its row are gone
#
# TWO OF THOSE SIX ROWS CARRIED A REASON THAT WAS FALSE, which is the part no
# other check could have caught.  qcmdpc-w's said "the other three write 2*d at
# the call site" -- no language writes it anywhere, so the row documented a call
# site that does not exist.  zkp-nl-prod-rounds' said Java "names it for the
# CLI, which is its only caller" -- the CLI declared its own literal 219 and
# never read the suite constant.  A curated reason about how a constant is USED
# cannot be validated by a checker that only reads declarations.
#
# WHY A DIAGNOSTIC USE DOES NOT COUNT, and this is what makes the check worth
# having rather than vacuous.  SdfT was not unreferenced: it appeared twice,
# both times as an argument to a banner Printf, while the code derived its own
# error weight from the width.  That is strictly worse than an unused constant
# -- the banner would have printed a retuned SdfT while Stern kept using n/16,
# in a protocol where a mismatched error weight is a total interop break.  So an
# occurrence inside a print-like call's argument list is counted separately and
# does not make a cell live.  A first pass of this census without that rule
# scored SdfT as read, which is how the rule got written.
#
# KNOWN LIMIT, found by this item's own negative control.  The census asks
# whether the constant is read ANYWHERE in the shipped path, so it cannot tell a
# live read from one in dead code.  Reverting Go's call sites to `n / 16` while
# leaving `func sternT` in place left SdfT "read" by a function nothing called,
# and the check stayed green; it fires only once the helper goes too.  That is
# the same shape as the two limits recorded above this table -- the axis reads
# what the source SAYS, never what runs -- and closing it needs a call graph,
# which is a different tool.  What the census does close is the case that
# actually occurred six times here: a constant no code mentions at all, or
# mentions only to print.
#
# CORPUS: the shipped path only -- suite, its walkthrough program, the CLI and
# the codec.  Tests, benchmarks, KAT generators and docs/examples are NOT
# consumers for this purpose: RNL_ETA's only C reference outside its #define was
# a printf label in benchmarks/rnl_deployed_ring_cost.c, and counting that would
# have scored the very cell this axis exists to find.  Getting the corpus wrong
# in the LENIENT direction makes the whole check pass vacuously, which is the
# failure mode check_docs_consistency.py's check E was built to avoid, so both
# mistakes here were made on the way in and are recorded rather than smoothed
# over.
PARAM_USE_CORPUS = {
    "c": [("herradura.h",), ("Herradura cryptographic suite.c",),
          ("HerraduraCli", "herradura_cli.c"), ("HerraduraCli", "herradura_codec.h")],
    "go": [("herradura", "herradura.go"), ("Herradura cryptographic suite.go",),
           ("herradura", "codec.go"), ("HerraduraCli", "herradura_cli.go")],
    "python": [("Herradura cryptographic suite.py",), ("HerraduraCli", "herradura.py"),
               ("HerraduraCli", "codec.py"), ("HerraduraCli", "primitives.py")],
    # java: every herradurakex/*.java, JAVA_NON_SUITE included -- HerraduraCli.java
    # and Codec.java are this language's CLI and codec layer, so they are
    # consumers here even though the parity extractor does not read them.
}

PARAM_DIAGNOSTIC_CALLS = {
    "c": r"\b(?:printf|fprintf|sprintf|snprintf|puts|fputs)\s*\(",
    "go": (r"\bfmt\.(?:Printf|Println|Print|Fprintf|Fprintln|Sprintf|Sprintln|Errorf)\s*\("
           r"|\blog\.(?:Printf|Println|Fatalf|Fatalln)\s*\("),
    "python": r"\bprint\s*\(",
    "java": r"\b(?:System\.(?:out|err)\.(?:printf|println|print)|String\.format)\s*\(",
}

PARAM_USE_DECL = {
    "c": r"#define\s+{n}\b",
    "go": r"\b{n}\s*(?:[A-Za-z_]\w*\s*)?=",
    "python": r"^\s*{n}\s*(?::\s*int\s*)?=",
    "java": r"static\s+final\s+\w+\s+{n}\s*=",
}

# Self-invalidating in both directions, like every other curated table here: an
# entry naming a cell that IS read fails (the gap closed -- delete the entry),
# and so does one naming a row or language that does not exist.  EMPTY, and that
# is the point: #295 fixed all ten cells rather than exempting any, so a future
# entry here means a genuine declaration-only parameter was argued for, not that
# the check was switched off.  Key: (row id, language) -> reason.
PARAM_USE_EXEMPT = {}


def _param_use_corpus():
    """Comment-stripped shipped-path text per language."""
    out = {}
    for lang, parts in PARAM_USE_CORPUS.items():
        chunks = []
        for rel in parts:
            with open(os.path.join(REPO, *rel), encoding="utf-8") as fh:
                text = fh.read()
            if lang == "python":
                text = re.sub(r'"""(?:.|\n)*?"""', " ", text)
                text = re.sub(r"[']{3}(?:.|\n)*?[']{3}", " ", text)
                text = re.sub(r"#[^\n]*", " ", text)
            else:
                text = _strip_comments(text)
            chunks.append(text)
        out[lang] = "\n".join(chunks)
    jdir = os.path.join(REPO, "bindings", "java", "herradurakex")
    jtexts = []
    for f in sorted(os.listdir(jdir)):
        if f.endswith(".java"):
            with open(os.path.join(jdir, f), encoding="utf-8") as fh:
                jtexts.append(_strip_comments(fh.read()))
    out["java"] = "\n".join(jtexts)
    return out


def _param_diagnostic_spans(text, lang):
    """Argument-list spans of print-like calls, located by paren depth."""
    spans = []
    for m in re.finditer(PARAM_DIAGNOSTIC_CALLS[lang], text):
        i = text.find("(", m.end() - 1)
        if i < 0:
            continue
        depth, j = 0, i
        while j < len(text):
            if text[j] == "(":
                depth += 1
            elif text[j] == ")":
                depth -= 1
                if depth == 0:
                    break
            j += 1
        spans.append((i, j))
    return spans


def check_param_use(errors):
    """Every PARAMETERS cell must name a constant that language's shipped code
    READS -- outside its own declaration, and outside a diagnostic call."""
    text = _param_use_corpus()
    spans = {lang: _param_diagnostic_spans(text[lang], lang) for lang in PARAM_LANGS}
    seen_exempt = set()
    live = 0
    for rid, (cells, _observable, _meaning) in sorted(PARAMETERS.items()):
        for lang, cell in zip(PARAM_LANGS, cells):
            if cell is None:
                continue
            bare = re.escape(cell.split(".")[-1])
            decl = PARAM_USE_DECL[lang].format(n=bare)
            body = text[lang]
            real = diag = 0
            for m in re.finditer(r"\b%s\b" % bare, body):
                ls = body.rfind("\n", 0, m.start()) + 1
                le = body.find("\n", m.end())
                le = len(body) if le < 0 else le
                if re.search(decl, body[ls:le], re.M):
                    continue
                if any(a <= m.start() <= b for a, b in spans[lang]):
                    diag += 1
                else:
                    real += 1
            key = (rid, lang)
            if real:
                if key in PARAM_USE_EXEMPT:
                    seen_exempt.add(key)
                    errors.append(
                        f"parameter {rid!r}: PARAM_USE_EXEMPT entry for {lang} describes "
                        f"a constant that IS read ({cell}) -- delete the entry")
                live += 1
                continue
            if key in PARAM_USE_EXEMPT:
                seen_exempt.add(key)
                continue
            hint = (f" -- its {diag} occurrence(s) are all inside print-like calls, so the "
                    f"code derives its own value while a banner reports this one"
                    if diag else "")
            errors.append(
                f"parameter {rid!r}: {lang} declares {cell} and never READS it{hint}. "
                f"Either make the code implementing this parameter consult the constant, "
                f"or add a PARAM_USE_EXEMPT entry saying why it is declaration-only")
    for key in sorted(PARAM_USE_EXEMPT):
        if key in seen_exempt:
            continue
        rid, lang = key
        if rid not in PARAMETERS:
            errors.append(f"PARAM_USE_EXEMPT names row {rid!r}, which no longer exists")
        elif lang not in PARAM_LANGS:
            errors.append(f"PARAM_USE_EXEMPT names language {lang!r}, which is not one of "
                          f"{PARAM_LANGS}")
        else:
            errors.append(f"PARAM_USE_EXEMPT entry {key} matches no cell -- delete it")
    return live



# ---------------------------------------------------------------------------
# TODO #296: the EIGHTH axis — the raw-entropy census, and the sampler replay
# it guards.
#
# WHERE IT SITS.  The sixth axis compares a constant's VALUE and the seventh
# asks whether that constant is ever READ.  Both are statements about code that
# is the same on every run.  This one is about the code that is NOT: a sampler's
# output is fresh per call, reaches no artifact, and is therefore invisible to
# every other check in this repo.  TODO #294 proved that the hard way --
# rnl_sigma_sign drew its ZK mask by rejection sampling in C and by raw modulo
# in the other three, a 3-vs-1 split that shipped, because no KAT pins a value
# that is random by construction and no interop pair compares two samplers.
#
# WHAT #294 PRESCRIBED AND DID NOT KEEP.  It recorded that the only check
# available for this class is a FIXED-STREAM REPLAY: replace the entropy source
# with pinned bytes, and a randomised primitive becomes deterministic and
# comparable across ports.  It verified its own fix that way and threw the
# harness away.  CLAUDE.md went on asserting, present tense, that such a check
# existed.  KAT/sampler_replay.json is that harness kept, and this axis is what
# stops it decaying.
#
# TWO THINGS ARE CHECKED, and the second is the one that does not decay.
#
# (1) VECTOR-TO-TABLE AGREEMENT.  Every sampler named in the vector must be
#     pinned in ALL FOUR languages by SAMPLER_REPLAY_PINNED, and every entry in
#     SAMPLER_REPLAY_PINNED must name a sampler the vector actually carries.
#     Self-invalidating in both directions like every other curated table here:
#     deleting a row from the vector fails until the table follows, and claiming
#     a pin the vector does not carry fails outright.
#
# (2) THE RAW-ENTROPY CENSUS.  RANDOMNESS_CENSUS records, per language, every
#     function that reads RAW ENTROPY -- as opposed to calling a higher sampler.
#     The set is DERIVED from the source on every run and compared against the
#     recorded one, so adding, removing or renaming a randomness consumer in any
#     language is a CI failure until the table is updated.  That is the point: a
#     new consumer is exactly where the next #294 will be, and the failure forces
#     someone to say whether a fixed stream reaches it.
#
# WHY A NAME SET RATHER THAN A REASON PER FUNCTION.  There are 24/24/27/30 of
# them.  A prose reason on each would be a hundred sentences that nobody reads
# and that rot; the SET is the tripwire, and the four pinned rows are where the
# argument lives.  What the census cannot do is say whether an unpinned consumer
# is CORRECT -- only that it exists and that someone looked.  Pinning the rest
# means replaying whole signing and keygen operations rather than leaf samplers,
# which is TODO #297.
#
# KNOWN LIMIT, and it is the same shape as #295's.  "Reads raw entropy" is a
# syntactic test over each language's own primitives (fread(urnd)/ba_rand,
# rand.Read/rand.Int/NewRandBitArray, os.urandom/BitArray.random,
# nextBytes/new BigInteger(bits, rng)).  A port that reached the CSPRNG by some
# fifth spelling would not be censused at all -- the blind spot #288 found in
# check_docs_consistency's check B" and #289 found in its own discovery rule.
# The guard against it is that the recorded counts are asserted to be non-zero
# per language: a regex that stopped matching fails as "the extractor broke"
# rather than passing with an empty census.
# ---------------------------------------------------------------------------

# Which sampler each language's port is called, per row of
# KAT/sampler_replay.json.  A name here is the function the replay consumer
# actually drives, so it doubles as documentation of where the sampler lives.
SAMPLER_REPLAY_PINNED = {
    "rnl_cbd_poly": {
        "c": "rnl_cbd_poly_dim", "go": "RnlCBDPoly",
        "python": "_rnl_cbd_poly", "java": "HerraduraNl.java::rnlCbdPoly",
    },
    "rnl_rand_poly": {
        "c": "rnl_rand_poly", "go": "RnlRandPoly",
        "python": "_rnl_rand_poly", "java": "HerraduraNl.java::rnlRandPoly",
    },
    "stern_weight_t": {
        "c": "stern_rand_error", "go": "SternRandError",
        "python": "_csprng_weight_t", "java": "Stern.java::csprngWeightT",
    },
    "oprf_blind_scalar": {
        "c": "oprf_blind", "go": "OprfBlind",
        "python": "oprf_blind", "java": "Oprf.java::blind",
    },
}

# The same, one level up, for KAT/operation_replay.json (TODO #297).  A row here
# is a whole randomised OPERATION rather than a leaf sampler: what it pins is the
# ORDER in which the operation visits its samplers, and any inline draw loop that
# is not a callable sampler at all.  #294's defect was of the second kind, which
# is why rnl_sigma_sign is in this table and not in the one above.
#
# The two tables are kept separate rather than merged, and that is deliberate:
# they answer different questions of an unpinned consumer.  A name absent from
# SAMPLER_REPLAY_PINNED may still be fully covered by an operation row that calls
# it; a name absent from BOTH is genuinely unpinned.
OPERATION_REPLAY_PINNED = {
    "stern_f_keygen": {
        "c": "stern_f_keygen", "go": "SternFKeygen",
        "python": "stern_f_keygen", "java": "Stern.java::sternFKeygen",
    },
    "hpks_stern_f_sign": {
        "c": "hpks_stern_f_sign", "go": "HpksSternFSign",
        "python": "hpks_stern_f_sign", "java": "Stern.java::hpksSternFSign",
    },
    "zkp_nl_prove": {
        "c": "zkp_nl_prove", "go": "ZkpNlProve",
        "python": "zkp_nl_prove", "java": "ZkpNl.java::prove",
    },
    "rnl_sigma_sign": {
        "c": "rnl_sigma_sign", "go": "RnlSigmaSign",
        "python": "rnl_sigma_sign", "java": "HerraduraNl.java::rnlSigmaSign",
    },
    # The row that found something.  Two divergences lived here: the challenge
    # trit had three schemes across four ports, and the b = 0 dummy commitment
    # was a CONSTANT in C and Go, which identified the real signer from the
    # public signature -- a ring signature with no anonymity that verified
    # perfectly, so every round-trip and interop test passed it.
    "hpks_stern_ring_sign": {
        "c": "stern_ring_sign", "go": "HpksSternRingSign",
        "python": "hpks_stern_ring_sign", "java": "SternRing.java::sign",
    },
    # The row TODO #303 added, for the gap TODO #302 §6 found by asking rather
    # than assuming: KKW's PROVER was covered NOWHERE.  KAT/hcred_kkw.json is
    # verify-side by construction -- one fresh root per emulation, so a proof is
    # not a function of its statement -- and KKW has no CLI surface, so the 4x4
    # interop matrix does not reach it either.  Each port's prover was checked
    # only against its OWN verifier, which is the shape that let three of the
    # four ports ship a transcription bug under #266.
    "hcred_prove_kkw": {
        "c": "hcred_prove_kkw", "go": "HcredProveKkw",
        "python": "hcred_prove_kkw", "java": "Hcred.java::proveKkw",
    },
    # --- TODO #307: the four rows #305's coverage census left OWED ---------
    #
    # `param_entropy` is the new cell shape and it is a finding rather than a
    # convenience.  Every one of the six rows above draws in all four ports, so
    # the four-cell rule below read as a law; the QC-MDPC pair is where it stops
    # being one.  C's qcmdpc_keygen and qcmdpc_encap take a `QcMdpcPrf *` --
    # the SEED is a parameter, drawn by herradura_cli.c's cmd_genpkey, which is
    # what CLI_DRAW_COVERAGE's qcmdpc_keygen_prf_seed row records -- so C's
    # cell is genuinely absent rather than missing, and a name there would fail
    # the rule that a pinned cell must be a CENSUSED consumer.  The cell says
    # which function it is and is cross-checked in both directions (see
    # check_randomness): the function must EXIST in that language's suite and
    # must NOT be censused.  So if C ever starts drawing there, this fails; and
    # if the function is renamed or deleted, this fails.  That is PARAMETERS'
    # `None`-cell treatment one axis over, and for its reason -- a cell the
    # extractor dropped looks identical to one that genuinely does not exist.
    "qcmdpc_keygen": {
        "c": None, "go": "QcMdpcKeygen",
        "python": "qcmdpc_keygen", "java": "Stern.java::qcmdpcKeygen",
        "param_entropy": {
            "c": ("qcmdpc_keygen",
                  "takes a QcMdpcPrf *; the 32-byte seed is drawn by "
                  "herradura_cli.c's cmd_genpkey and passed in, which is "
                  "CLI_DRAW_COVERAGE's qcmdpc_keygen_prf_seed row.  The C "
                  "consumer reads the row's stream itself and seeds the PRF "
                  "with it, so the draw ORDER inside the loop is pinned in all "
                  "four; what C does not do is read the CSPRNG here"),
        },
    },
    "qcmdpc_encap": {
        "c": None, "go": "QcMdpcEncap",
        "python": "qcmdpc_encap", "java": "Stern.java::qcmdpcEncap",
        "param_entropy": {
            "c": ("qcmdpc_encap",
                  "same shape as qcmdpc_keygen's: the PRF is a parameter and "
                  "the seed is drawn at the CLI (CLI_DRAW_COVERAGE's "
                  "qcmdpc_encap_prf_seed and hybrid_kem_prf_seed)"),
        },
    },
    # NARROWS a claim TODO #302 §6 makes.  §6 says ZKB++ is covered twice over,
    # one half being that the zkp_nl_prove row pins its masking term because
    # neither port carries its own circuit.  True OF THE CIRCUIT; it does not
    # extend to the SEED DRAW ORDER, which is this function's own consumption
    # order -- and §2 of that file makes the 16-byte seed a security parameter,
    # so the order in which seeds are drawn is not formatting.
    "zkp_nl_pp_prove": {
        "c": "zkp_nl_pp_prove", "go": "ZkpNlProvepp",
        "python": "zkp_nl_prove_pp", "java": "ZkpNl.java::provePp",
    },
    # HCRED's OTHER prover, beside the KKW one above.  The cells are not all at
    # the same FRAME and that is accurate rather than sloppy: Python and Java
    # draw inside the inner MPC round, C and Go inside the outer prove, so the
    # censused consumer differs by port while the pinned OPERATION does not.
    "hcred_prove": {
        "c": "hcred_prove", "go": "HcredProve",
        "python": "_hcred_mpc_round", "java": "Hcred.java::mpcRound",
    },
}

# ---------------------------------------------------------------------------
# TODO #305: how much of the census is actually PINNED.
#
# This is TODO #300's question one axis over.  #300 asked of the findings gates:
# the SET is the tripwire, but how many of them decide a verdict from a fresh
# sample?  RANDOMNESS_CENSUS has the identical structure and the identical
# question had never been put to it.  Its own header says what it cannot do --
# "only that it exists and that someone looked" -- and then hands the remainder
# to #297 and #303, which pinned six operations between them.  Nothing counted
# what that left, so "someone looked" was decaying into "someone looked once",
# which is exactly what #296 found had happened to #294's prescription.
#
# MEASURED: 10 consumers per language are named by a pinned row; 15 / 15 / 18 /
# 21 are not (C / Go / Python / Java).  Every one of those must appear here.
#
# THREE STATUSES, and the third is why there are three.
#
#   transitive  Covered by a pinned OPERATION that calls it.  `via` names the
#               row, and the claim is CONFIRMED by walking the call graph in
#               each language -- see _calls_reach.  It is DERIVED, not curated,
#               because #295 found two of six curated reasons about how a
#               constant is USED carrying a FALSE claim, and "covered by the
#               ring row" is the same kind of sentence.
#   unpinned    A fixed stream reaches it and pinning would still prove nothing
#               NEW, or the draw is not a cross-port object at all.  Needs a
#               reason.
#   owed        Pinning IS applicable and is not done.  Needs a reason AND an
#               item number.  This status exists so that work cannot be parked
#               inside a prose reason: the runner counts `owed` separately, on
#               #300's precedent of counting derived RATES apart from stated
#               ARGUMENTS "so the distinction cannot quietly erode".
#
# SELF-INVALIDATING IN BOTH DIRECTIONS, like every other curated table here.  A
# censused consumer that no pinned row names and no row below claims FAILS.  A
# row whose cells have ALL since been pinned FAILS until it is deleted -- so
# pinning something forces its row out rather than leaving a stale claim.  And
# a cell naming a function that is not censused in that language FAILS, which
# is what cross-checks an ABSENT cell: #278 hit that with `None` cells and had
# to check them separately, whereas here a wrongly-absent cell simply surfaces
# as an unclaimed censused name.
#
# SCOPE, stated because #302 §6 is what an unchecked scope paragraph becomes.
# Nothing here asserts that an unpinned consumer is CORRECT, and a pinned row
# sees DIVERGENCE only.  #298's rule (1) still binds: a cross-port check cannot
# see a property all four ports get wrong.
# ---------------------------------------------------------------------------
REPLAY_COVERAGE = {
    # --- covered transitively, confirmed by the call graph -----------------
    "rand_bitarray": {
        "status": "transitive", "via": "stern_f_keygen",
        "c": "ba_rand", "go": "NewRandBitArray", "python": "random",
        "java": None,   # Java inlines rng.nextBytes; it has no such helper
    },
    "stern_ring_trit": {
        "status": "transitive", "via": "hpks_stern_ring_sign",
        "c": "stern_ring_trit", "go": "sternRingTrit",
        "python": "_stern_ring_trit", "java": "SternRing.java::ringTrit",
    },
    "stern_ring_simulate": {
        "status": "transitive", "via": "hpks_stern_ring_sign",
        "c": "stern_ring_simulate", "go": "sternSimulateRound",
        "python": "_stern_simulate_round",
        "java": "SternRing.java::simulateRound",
    },
    "java_bitarray_random": {
        # TODO #314 pass 5.  Java's BitArray.random is where eleven inline
        # `new BigInteger(N, rng)` draws went when the type landed.  It is NOT
        # reached by any pinned operation in this port: its callers are the
        # classical and NL encrypt/sign entry points, none of which
        # KAT/operation_replay.json pins for Java.  UNPINNED rather than owed,
        # and the reason is TODO #311's, measured there and true verbatim here:
        # a single uniform draw of one fixed width handed straight back, with no
        # loop, no rejection and no second draw, so a fixed stream would pin the
        # identity function.  C and Go reach their equivalent helper through
        # stern_f_keygen and are covered by the rand_bitarray row; Java's
        # Stern.sternFKeygen still draws its own seed, which is why this is a
        # row of its own rather than a fourth cell there.
        "status": "unpinned",
        "reason": "a single uniform draw of one fixed width, returned unchanged "
                  "to the caller -- a fixed stream would pin the identity "
                  "function (TODO #311's finding, same shape)",
        "c": None, "go": None, "python": None,
        "java": "BitArray.java::random",
    },
    "zkp_nl_random_big": {
        "status": "transitive", "via": "zkp_nl_prove",
        "c": None, "go": None, "python": None,
        "java": "ZkpNl.java::randomBig",
    },

    # --- owed: pinning applies and is not done -----------------------------
    # EMPTY, and the emptiness is the shipped state of TODO #307 rather than a
    # table nobody filled in.  #305 measured four -- qcmdpc_keygen,
    # qcmdpc_encap, zkp_nl_pp_prove and hcred_prove -- and separated this
    # status from `unpinned` precisely so their cost would be argued in the
    # open instead of inside a prose reason.  All four are now rows in
    # KAT/operation_replay.json, which DELETED their entries here rather than
    # permitting the deletion: a row whose cells are all pinned fails until it
    # goes.  A future entry therefore means a new consumer arrived and its pin
    # was deferred with an item number, not that this check was switched off.

    # --- unpinned: a fixed stream would prove nothing new ------------------
    # The classical quartet's randomised operations.  Each draws ONE ephemeral
    # scalar and derives everything else from it, so a fixed stream pins a
    # single read of a known width -- and what the ports could disagree about
    # (the derivation) is already pinned four ways, byte for byte, by
    # KAT/classical_quartet.json, which supplies that scalar as an ARGUMENT.
    # That is the #268 property: when the random input is a parameter the
    # primitive accepts, pinning it pins the artifact.
    "hpks_sign": {
        "status": "unpinned",
        "reason":
            "One Schnorr nonce, and the signature it determines is pinned four "
            "ways by KAT/classical_quartet.json with that nonce as an "
            "argument.  Go's and Python's cells were None until TODO #308 "
            "(v8.1.0), with the note that their nonce was drawn in the CLI -- "
            "which #306 then read, and #308 moved: all four ports now name the "
            "operation, so the draw is inside this census rather than beside "
            "it",
        "c": "hpks_sign", "go": "HpksSign", "python": "hpks_sign",
        "java": "Herradura.java::hpksSign",
    },
    "hpke_encrypt": {
        "status": "unpinned",
        "reason":
            "One El Gamal ephemeral r; the ciphertext it determines is pinned "
            "four ways by KAT/classical_quartet.json with r as an argument",
        "c": "hpke_encrypt", "go": "HpkeEncrypt", "python": "hpke_encrypt",
        "java": "Herradura.java::hpkeEncrypt",
    },
    "hske_encrypt_masked": {
        "status": "unpinned",
        "reason":
            "One mask, XORed into the plaintext; the masked ciphertext is "
            "pinned by KAT/classical_quartet.json with the mask as an argument",
        "c": "hske_encrypt_masked", "go": "HskeEncryptMasked",
        "python": "hske_encrypt_masked",
        "java": "Herradura.java::hskeEncryptMasked",
    },
    "hske_decrypt_masked": {
        "status": "unpinned",
        "reason":
            "The decrypt half of hske_encrypt_masked; it draws only to keep "
            "the masked representation, and its output is checked against the "
            "same vector",
        "c": "hske_decrypt_masked", "go": "HskeDecryptMasked",
        "python": "hske_decrypt_masked",
        "java": "Herradura.java::hskeDecryptMasked",
    },
    "hpke_nl_encrypt": {
        "status": "unpinned",
        "reason":
            "The NL counterpart of hpke_encrypt, one ephemeral, pinned by "
            "KAT/nl_fscx_v3.json's consumers with the ephemeral as an "
            "argument.  Java alone names the operation; the other three take "
            "the ephemeral from the caller",
        "c": None, "go": None, "python": None,
        "java": "HerraduraNl.java::hpkeNlEncrypt",
    },
    "hpke_nl3_encrypt": {
        "status": "unpinned",
        "reason": "The v3 counterpart of hpke_nl_encrypt, same argument",
        "c": None, "go": None, "python": None,
        "java": "HerraduraNl.java::hpkeNl3Encrypt",
    },
    "hpks_nl_sign": {
        "status": "unpinned",
        "reason":
            "The NL counterpart of hpks_sign, same argument.  C, Go and Python "
            "gained the operation in TODO #308: `sign --algo hpks-nl` shared "
            "the classical path's one inline nonce draw in all three, so the "
            "classical half could not move on its own",
        "c": "hpks_nl_sign", "go": "HpksNlSign", "python": "hpks_nl_sign",
        "java": "HerraduraNl.java::hpksNlSign",
    },
    "hske_nl_aead_encrypt": {
        "status": "unpinned",
        "reason":
            "One AEAD nonce.  C and Go are absent because they take it as a "
            "parameter, which is the shape TODO #268 pinned directly: "
            "CliTest/test_aead.sh is a 4x4 matrix over the resulting "
            "ciphertext",
        "c": None, "go": None, "python": "hske_nl_aead_encrypt",
        "java": "HerraduraNl.java::hskeNlAeadEncrypt",
    },
    "duplex_encrypt": {
        "status": "unpinned",
        "reason":
            "One duplex nonce; the sponge output is pinned by "
            "KAT/nl_fscx_v3.json's hske-duplex3 consumer with the nonce as an "
            "argument",
        "c": None, "go": None, "python": "_dplex_encrypt",
        "java": "Duplex.java::encrypt",
    },
    "hfscx256_enc_file": {
        "status": "unpinned",
        "reason":
            "A file-level IV, drawn once and written to the header; the "
            "round-trip is what CliTest/test_encfile.sh checks and the "
            "construction under it is pinned by test [19]'s vectors",
        "c": None, "go": None, "python": None,
        "java": "Hfscx256.java::encFile",
    },
    "oprf_keygen": {
        "status": "unpinned",
        "reason":
            "One uniform scalar in [1, q), by the same rejection loop as "
            "oprf_blind -- which IS pinned, as a leaf sampler, by "
            "KAT/sampler_replay.json's oprf_blind_scalar row.  That row's "
            "stream is the one whose first draw is r = 1 exactly, so the "
            "rejection branch these two share is covered where it matters",
        "c": "oprf_keygen", "go": "OprfKeygen", "python": "oprf_keygen",
        "java": "Oprf.java::keygen",
    },
    "hpkst_sign": {
        "status": "unpinned",
        "reason":
            "Threshold signing draws one nonce PER SIGNER and the operation is "
            "interactive -- a replay would pin a chosen signer ordering, not a "
            "consumption order, and the aggregate it produces is checked by "
            "CliTest's threshold matrix",
        "c": "hpkst_sign", "go": "HpkstSign", "python": "hpkst_sign",
        "java": "HpksT.java::sign",
    },
    "zkp_nl_keygen": {
        "status": "unpinned",
        "reason":
            "Draws a witness, which is a STATEMENT and not a consumption "
            "order: every row of KAT/operation_replay.json states its witness "
            "in full rather than deriving it, on #297's own rule that a "
            "derived statement makes one row's failure cascade",
        "c": "zkp_nl_keygen", "go": "ZkpNlKeygen", "python": "zkp_nl_keygen",
        "java": None,
    },
    "hpake_register": {
        "status": "unpinned",
        "reason":
            "aPAKE registration draws a salt, which travels to the verifier "
            "and is therefore an argument the protocol already carries; the "
            "4x4 aPAKE block of CliTest/test_cross_lang_matrix.sh runs it",
        "c": "hpake_register", "go": "HpakeRegister",
        "python": "hpake_register", "java": "Hpake.java::register",
    },
    "hpake_login_demo": {
        "status": "unpinned",
        "reason":
            "A DEMO driver, not a primitive -- it draws to stand in for a "
            "client and is reachable from no shipped CLI path.  #291's rule "
            "that 'it is only a demo' is not a reason applies to a VERDICT; "
            "this one computes none",
        "c": "hpake_login_demo", "go": "HpakeLoginDemo",
        "python": "hpake_login_demo", "java": "Hpake.java::loginDemo",
    },
    "suite_walkthrough": {
        "status": "unpinned",
        "reason":
            "The Python suite's own main(), the walkthrough gated by TODO "
            "#233's [FAIL] convention.  Not a primitive and reached by no "
            "caller",
        "c": None, "go": None, "python": "main", "java": None,
    },
}

# Every function in the shipped suite that reads RAW ENTROPY.  Derived from the
# source on every run and compared against this list; see the header.
RANDOMNESS_CENSUS = {
    "c": [
        "ba_rand", "hcred_prove", "hcred_prove_kkw", "hpake_login_demo",
        "hpake_register", "hpke_encrypt", "hpks_nl_sign", "hpks_sign",
        "hpks_stern_f_sign",
        "hpkst_sign", "hske_decrypt_masked", "hske_encrypt_masked", "oprf_blind",
        "oprf_keygen", "rnl_cbd_poly_dim", "rnl_rand_poly",
        "rnl_sigma_sign", "stern_f_keygen", "stern_rand_error", "stern_ring_sign",
        "stern_ring_simulate", "stern_ring_trit", "zkp_nl_keygen",
        "zkp_nl_pp_prove", "zkp_nl_prove",
    ],   # 25
    "go": [
        "HcredProve", "HcredProveKkw", "HpakeLoginDemo", "HpakeRegister",
        "HpkeEncrypt", "HpksNlSign", "HpksSign",
        "HpksSternFSign", "HpksSternRingSign", "HpkstSign",
        "HskeDecryptMasked", "HskeEncryptMasked", "NewRandBitArray", "OprfBlind",
        "OprfKeygen", "QcMdpcEncap", "QcMdpcKeygen", "RnlCBDPoly", "RnlRandPoly",
        "RnlSigmaSign", "SternFKeygen", "SternRandError", "ZkpNlKeygen",
        "ZkpNlProve", "ZkpNlProvepp", "sternRingTrit", "sternSimulateRound",
    ],   # 27
    "python": [
        "_csprng_weight_t", "_dplex_encrypt", "_hcred_mpc_round", "_rnl_cbd_poly",
        "_rnl_rand_poly", "_stern_ring_trit", "_stern_simulate_round",
        "hcred_prove_kkw",
        "hpake_login_demo", "hpake_register", "hpke_encrypt", "hpks_nl_sign",
        "hpks_sign", "hpks_stern_f_sign",
        "hpks_stern_ring_sign", "hpkst_sign", "hske_decrypt_masked",
        "hske_encrypt_masked", "hske_nl_aead_encrypt", "main", "oprf_blind",
        "oprf_keygen", "qcmdpc_encap", "qcmdpc_keygen", "random",
        "rnl_sigma_sign", "stern_f_keygen", "zkp_nl_keygen", "zkp_nl_prove",
        "zkp_nl_prove_pp",
    ],   # 30
    "java": [
        "BitArray.java::random",
        "Duplex.java::encrypt", "Hcred.java::mpcRound", "Hcred.java::proveKkw",
        "Herradura.java::hpkeEncrypt", "Herradura.java::hpksSign",
        "Herradura.java::hskeDecryptMasked", "Herradura.java::hskeEncryptMasked",
        "HerraduraNl.java::hpkeNl3Encrypt", "HerraduraNl.java::hpkeNlEncrypt",
        "HerraduraNl.java::hpksNlSign", "HerraduraNl.java::hskeNlAeadEncrypt",
        "HerraduraNl.java::rnlCbdPoly", "HerraduraNl.java::rnlRandPoly",
        "HerraduraNl.java::rnlSigmaSign", "Hfscx256.java::encFile",
        "Hpake.java::loginDemo", "Hpake.java::register", "HpksT.java::sign",
        "Oprf.java::blind", "Oprf.java::keygen",
        "Stern.java::csprngWeightT", "Stern.java::hpksSternFSign",
        "Stern.java::qcmdpcEncap", "Stern.java::qcmdpcKeygen",
        "Stern.java::sternFKeygen", "SternRing.java::ringTrit",
        "SternRing.java::sign", "SternRing.java::simulateRound", "ZkpNl.java::prove",
        "ZkpNl.java::provePp", "ZkpNl.java::randomBig",
    ],   # 32
}

# Per-language raw-entropy spellings.  A new way to reach the CSPRNG must be
# added here or its callers are censused as drawing nothing.
RANDOMNESS_RAW_PATTERNS = {
    "c": r"\bfread\s*\([^;]*urnd|\bba_rand\s*\(",
    "go": r"\brand\.(?:Read|Int)\s*\(|\bNewRandBitArray\s*\(",
    # token_bytes is `secrets.token_bytes`, and it is matched UNQUALIFIED
    # because the CLI imports it as `_sec` inside the branch that uses it --
    # a module alias no pattern anchored on `secrets.` would have seen.  That
    # is the SIXTH spelling this header warns about, and TODO #306 found it
    # by widening the corpus rather than by reading the suite again: in the
    # suite it happens to sit in `main`, which draws by other means too, so
    # the census was right there BY LUCK.  Adding the pattern moves no suite
    # name, which is the check that says so rather than assuming it.
    "python": r"\bos\.urandom\s*\(|\bBitArray\.random\s*\(|\btoken_bytes\s*\(",
    # The first argument is a bit COUNT and is written as a qualified
    # constant (Herradura.N, Stern.N), so [\w.]+ rather than \w+ -- with
    # \w+ the census missed Oprf.blind and Oprf.keygen entirely, and it was
    # the pinned-sampler cross-check below that said so.  That is the
    # "fifth spelling" blind spot this header warns about, caught once.
    #
    # The SOURCE is matched case-INSENSITIVELY, and that is TODO #306's
    # second finding rather than tidiness.  Every suite port names the
    # parameter `rng`; HerraduraCli.java holds a static field `RNG`, so
    # `new BigInteger(Herradura.N, RNG)` read as not a draw at all and TWO
    # CLI functions -- one of them the threshold-nonce commit -- were
    # censused as drawing nothing once the corpus reached them.  Not a fifth
    # spelling: the SAME spelling in a different case, which is the harder
    # blind spot to predict.
    "java": r"\.nextBytes\s*\(|new\s+BigInteger\s*\(\s*[\w.]+\s*,\s*(?i:rng)\s*\)"
            r"|\bBitArray\.random\s*\(",   # TODO #314 pass 5: the SEVENTH spelling.
            # Eleven suite functions moved from an inline `new BigInteger(N, rng)`
            # to BitArray.random; without this alternative every one of them would
            # read as drawing nothing -- the blind spot the header above warns
            # about, met again and caught the same way: by the census refusing to
            # balance, not by anyone re-reading the source.
}

# ---------------------------------------------------------------------------
# TODO #306: the corpus, which is prior to the census.
#
# Everything above reads THE SUITE.  PARAM_USE_CORPUS, forty lines up in this
# same file, reads the suite AND the walkthrough AND the CLI AND the codec, and
# says why in its own header: "getting the corpus wrong in the LENIENT direction
# makes the whole check pass vacuously".  Two corpora, one file, and no sentence
# anywhere about why the randomness axis used the narrower one.
#
# It was not a considered scope.  TODO #305 found it while writing the reason
# for hpks_sign being absent in Go and Python -- at the time they did not take
# the nonce as a parameter, they DREW IT IN THE CLI -- and measured 52
# raw-entropy call sites on the far side of the boundary.  A classical Schnorr nonce is among them, and
# nonce reuse or bias recovers the private key from two signatures.
#
# WHAT WIDENING THE CORPUS FOUND, before any row was written.  The measured 52
# is 59, because the census PATTERNS had two blind spots that only a wider
# corpus could expose, both of the kind RANDOMNESS_RAW_PATTERNS' own header
# warns about and neither predictable from the suite:
#
#   * `secrets.token_bytes`, imported as `_sec` inside the branch that uses it.
#     A sixth spelling.  In the suite it sits in `main`, which draws by other
#     means as well, so the census was right there BY LUCK -- and adding the
#     pattern moves no suite name, which is what turns that from a claim into a
#     check.
#   * `new BigInteger(Herradura.N, RNG)`.  Not a new spelling at all: the same
#     one in a different CASE, because every suite port names the parameter
#     `rng` and the CLI holds a static field `RNG`.  Two Java CLI functions read
#     as drawing nothing, and one of them is the threshold-nonce commit.
#
# AND THE ONE THAT IS NOT ABOUT PATTERNS, now FIXED and recorded here because
# the finding is what the corpus was widened to see.  C's herradura.h exported
# hpks_sign, which drew its own nonce and which KAT/classical_quartet.json
# pins -- and herradura_cli.c DID NOT CALL IT.  cmd_sign transcribed the whole
# Schnorr signer inline, ba_rand through ba_sub_mod_ord, and the suite copy was
# reached only by docs/examples/c/hello_herradura.c and the FFI shim.  Go and
# Python never had the operation at all.  So THREE OF FOUR CLIs signed with an
# unpinned transcription and the fourth, Java, was the one that called the
# suite.  #305's hpks_sign coverage row was true of the FUNCTION and was
# standing in for the shipped path; that is #295's dead-code limit --
# reachability is not liveness -- aimed at a sampler instead of at a constant.
#
# TODO #308 (v8.1.0) closed it by moving the code, not by writing a vector: Go
# and Python gained HpksSign/hpks_sign, all four gained the NL counterpart --
# `sign --algo hpks-nl` shared the classical path's ONE inline draw in three
# ports, so the classical half could not move alone -- and the three CLIs now
# call what they used to copy.  The `schnorr_nonce` role is GONE from
# CLI_DRAW_COVERAGE, deleted rather than retitled `cli_only`, and the site
# counts below are what forced the deletion: those draws are no longer in a
# CLI.  56 raw-entropy CLI sites remain, down from 59.
#
# WHAT THIS AXIS CANNOT DO, stated before the table rather than after it.  A CLI
# takes no entropy source as a parameter in any of the four languages: C opens
# /dev/urandom, Go uses crypto/rand, Python os.urandom, Java a static
# SecureRandom.  So a fixed-stream replay does NOT reach this layer without a
# new shipped surface (an injection env var), and that is a change to the
# product, not to a checker -- deliberately not made here, and filed as TODO
# #309, which has to argue the hazard before it adds the seam: a CSPRNG that an
# environment variable can replace is a deterministic `genpkey` away from a
# private key nothing on disk distinguishes from a real one.  What IS available is
# the accounting, and the accounting is the thing that was missing: which draw,
# in which ports, and what -- if anything -- compares it across them.
CLI_CORPUS = {
    "c": [(("HerraduraCli", "herradura_cli.c"),
           r"^(?:static\s+)?(?:inline\s+)?[\w \*]+?\b(\w+)\s*\(", r"^\}"),
          (("HerraduraCli", "herradura_codec.h"),
           r"^(?:static\s+)?(?:inline\s+)?[\w \*]+?\b(\w+)\s*\(", r"^\}")],
    "go": [(("HerraduraCli", "herradura_cli.go"),
            r"^func\s+(?:\([^)]*\)\s*)?(\w+)\s*\(", r"^\}")],
    "python": [(("HerraduraCli", "herradura.py"), None, None),
               (("HerraduraCli", "codec.py"), None, None),
               (("HerraduraCli", "primitives.py"), None, None)],
    "java": [(("bindings", "java", "herradurakex", "HerraduraCli.java"),
              r"^    (?:public |private |protected )?static "
              r"[\w\[\]<>., ]*?\b(\w+)\s*\(", r"^    \}"),
             (("bindings", "java", "herradurakex", "Codec.java"),
              r"^    (?:public |private |protected )?static "
              r"[\w\[\]<>., ]*?\b(\w+)\s*\(", r"^    \}")],
}

# Derived from CLI_CORPUS every run and compared, exactly as RANDOMNESS_CENSUS
# is: a CLI function that starts or stops drawing fails CI until it is filed.
# Names carry their FILE, uniformly in all four languages and not only in Java
# -- a CLI spreads over a binary and a codec, and `cmd_enc` alone would not say
# which.
RANDOMNESS_CLI_CENSUS = {
    "c": [
        "herradura_cli.c::cmd_enc", "herradura_cli.c::cmd_encfile",
        "herradura_cli.c::cmd_genpkey", "herradura_cli.c::cmd_kex",
        "herradura_cli.c::cmd_threshold_commit",
        "herradura_cli.c::encrypt_pem_text_to_file",
    ],
    "go": [
        "herradura_cli.go::cmdEnc", "herradura_cli.go::cmdEncfile",
        "herradura_cli.go::cmdGenpkey", "herradura_cli.go::cmdKex",
        "herradura_cli.go::cmdThresholdCommit",
        "herradura_cli.go::encryptPEMText",
    ],
    "python": [
        "herradura.py::_encrypt_pem", "herradura.py::cmd_enc",
        "herradura.py::cmd_encfile", "herradura.py::cmd_genpkey",
        "herradura.py::cmd_kex", "herradura.py::cmd_threshold_commit",
    ],
    "java": [
        "HerraduraCli.java::cmdEnc", "HerraduraCli.java::cmdGenpkey",
        "HerraduraCli.java::cmdKexHybrid", "HerraduraCli.java::cmdKexRnl",
        "HerraduraCli.java::cmdThresholdCommit",
        "HerraduraCli.java::encryptPemText",
    ],
}

# What each CLI draw IS, and what compares it across the four ports.
#
# A ROLE, not a function: one CLI function holds several draws (cmd_genpkey
# holds six in C) and one role spans several functions (Java splits the kex
# responder nonce between cmdKexRnl and cmdKexHybrid).  So a cell is
# (function, SITE COUNT), and the site counts are checked against the source:
# per language and function, the counts of every row claiming it must SUM to the
# number of raw-entropy sites actually there.  That is the part that does not
# decay.  A name set alone would let a seventh draw be added to cmd_genpkey in
# silence -- which is precisely how 52 sites accumulated on the far side of a
# boundary nobody had stated.
#
# THREE STATUSES.
#
#   suite     At least one port draws this role inside a CENSUSED SUITE
#             consumer instead of in its CLI, and `via` names the
#             REPLAY_COVERAGE (or pinned) row that accounts for it there.  The
#             row then records the asymmetry: which ports inline the draw and
#             which delegate it.  DERIVED, not asserted -- every `via` must name
#             a real row, and a port with no CLI cell must have a cell in one of
#             them.
#   cli_only  No port draws this role in the suite: the role exists nowhere but
#             the CLI, so no suite-level pin could reach it however much pinning
#             were done.  Needs a reason.
#   owed      Pinning applies and is not done.  Needs a reason AND an item
#             number, on REPLAY_COVERAGE's rule and for its reason: a prose
#             reason is where work gets parked.
#
# `via` is REQUIRED by `suite`, FORBIDDEN to `cli_only` (which asserts no port
# draws the role in its suite, and a delegation would contradict that) and
# ALLOWED to `owed`, because the two are not exclusive: the `schnorr_nonce` row
# this rule was written for was owed in three ports and delegated in the fourth,
# and collapsing that to one status per row would have lost which was which.
# TODO #308 then closed it and the row is gone, so no `owed` row is left here --
# which is the intended steady state, not a reason to drop the rule.
#
# `absent` is the third branch of the per-language rule -- a port that ships no
# such draw at all, neither in its CLI nor in its suite.  It ships EMPTY, on
# PARAM_USE_EXEMPT's precedent: every port of every role here is accounted for
# by a cell or by a `via` row, so an entry appearing later means a genuine
# per-language absence was argued for, not that the rule was relaxed.
CLI_DRAW_COVERAGE = {
    # --- the passphrase envelope -------------------------------------------
    "pem_envelope_salt": {
        "status": "cli_only",
        "reason":
            "The PBKDF2 salt for `genpkey --passphrase`.  No suite function "
            "draws it: the envelope is assembled in the CLI in all four ports, "
            "which is why KAT/pem/enc_priv.pem exists and is the one artifact "
            "there that IS regenerate-and-diff checked -- salt and nonce are "
            "arguments the primitive accepts, so pinning them pins the file.  "
            "That pins the ARTIFACT, not the DRAW: generate_pem_kat.py supplies "
            "the salt, and no path from the CLI's own draw reaches the vector",
        "c": ("herradura_cli.c::encrypt_pem_text_to_file", 1),
        "go": ("herradura_cli.go::encryptPEMText", 1),
        "python": ("herradura.py::_encrypt_pem", 1),
        "java": ("HerraduraCli.java::encryptPemText", 1),
    },
    "pem_envelope_nonce": {
        "status": "suite", "via": ["hske_nl_aead_encrypt"],
        "reason":
            "The envelope's AEAD nonce, and the ports SPLIT on where it comes "
            "from: C, Go and Java draw it in the CLI and pass it in, while "
            "Python lets hske_nl_aead_encrypt draw its own and returns it.  "
            "Same wire format either way -- the nonce travels in the DER -- so "
            "no round-trip or interop test can see the difference, which is "
            "this axis's standing shape",
        "c": ("herradura_cli.c::encrypt_pem_text_to_file", 1),
        "go": ("herradura_cli.go::encryptPEMText", 1),
        "python": None,
        "java": ("HerraduraCli.java::encryptPemText", 1),
    },

    # --- genpkey -----------------------------------------------------------
    "classical_privkey": {
        "status": "cli_only",
        "reason":
            "The HKEX-GF/HPKS/HPKE private exponent.  ONE draw with no order "
            "to compare -- a single uniform value, used immediately -- so a "
            "fixed stream would pin the identity function.  What a divergence "
            "here would look like is a WIDTH or a masking difference, and that "
            "is the PARAMETERS axis's `bits` row, not this one",
        "c": ("herradura_cli.c::cmd_genpkey", 1),
        "go": ("herradura_cli.go::cmdGenpkey", 1),
        "python": ("herradura.py::cmd_genpkey", 1),
        "java": ("HerraduraCli.java::cmdGenpkey", 1),
    },
    "rnl_kex_nonce_a": {
        "status": "cli_only",
        "reason":
            "The HKEX-RNL initiator's contributory nonce n_A, 32 bytes, "
            "written into the public key PEM.  It reaches an artifact, so the "
            "4x4 interop matrix and KAT/pem/ both see the FORMAT -- and "
            "neither sees the draw, because a nonce is accepted as whatever "
            "the peer sent",
        "c": ("herradura_cli.c::cmd_genpkey", 1),
        "go": ("herradura_cli.go::cmdGenpkey", 1),
        "python": ("herradura.py::cmd_genpkey", 1),
        "java": ("HerraduraCli.java::cmdGenpkey", 1),
    },
    "hcred_seed_h": {
        "status": "cli_only",
        "reason":
            "HCRED's per-user seed_H, drawn at genpkey and committed to in the "
            "credential.  Java draws it as a BigInteger and the other three as "
            "a bit array, which is the CASE difference that hid two Java CLI "
            "functions from this census until the pattern was widened",
        "c": ("herradura_cli.c::cmd_genpkey", 1),
        "go": ("herradura_cli.go::cmdGenpkey", 1),
        "python": ("herradura.py::cmd_genpkey", 1),
        "java": ("HerraduraCli.java::cmdGenpkey", 1),
    },
    "hash_sig_master_seed": {
        "status": "cli_only",
        "reason":
            "Two draws per port, one for hpks-wots and one for hpks-xmss: the "
            "32-byte master seed every chain and every leaf is derived from.  "
            "The DERIVATION is deterministic in the seed and pinned four ways, "
            "so a divergence would be visible -- but only if the seed were "
            "shared, and it never is.  Python's is the `secrets.token_bytes` "
            "pair, the sixth spelling this item added to the patterns",
        "c": ("herradura_cli.c::cmd_genpkey", 2),
        "go": ("herradura_cli.go::cmdGenpkey", 2),
        "python": ("herradura.py::cmd_genpkey", 2),
        "java": ("HerraduraCli.java::cmdGenpkey", 2),
    },
    "qcmdpc_keygen_prf_seed": {
        "status": "suite", "via": ["qcmdpc_keygen"],
        "reason":
            "THE C CELL OF AN OWED PIN, and it is in the CLI.  "
            "REPLAY_COVERAGE's qcmdpc_keygen row records `c: None -- takes a "
            "QcMdpcPrf *; the seed is a parameter, not a draw`, which is true "
            "of herradura.h and stops one frame short: herradura_cli.c draws "
            "that seed itself and calls qcprf_init.  So when TODO #307 pins "
            "QC-MDPC keygen, three ports supply the stream to the suite "
            "function and C supplies it HERE",
        "c": ("herradura_cli.c::cmd_genpkey", 1),
        "go": None, "python": None, "java": None,
    },

    # --- kex ---------------------------------------------------------------
    "rnl_kex_nonce_b": {
        "status": "cli_only",
        "reason":
            "The HKEX-RNL responder's n_B, the other half of the contributory "
            "pair, drawn while answering and returned in the response PEM.  "
            "Java is the only port that splits the responder across two "
            "functions, one per algorithm, which is why this role and the "
            "hybrid one are separate rows rather than a count of two",
        "c": ("herradura_cli.c::cmd_kex", 1),
        "go": ("herradura_cli.go::cmdKex", 1),
        "python": ("herradura.py::cmd_kex", 1),
        "java": ("HerraduraCli.java::cmdKexRnl", 1),
    },
    "hybrid_kex_nonce_b": {
        "status": "cli_only",
        "reason":
            "The same responder nonce on the hybrid-rnl-stern path, where the "
            "session key is the KDF of a Ring-LWR agreement AND a Stern-KEM "
            "encapsulation.  Worth its own row because that path's failure is "
            "SILENT by construction since TODO #235 -- implicit rejection "
            "means dec always exits 0 -- so a mismatch here surfaces as two "
            "peers with different keys and no error",
        "c": ("herradura_cli.c::cmd_kex", 1),
        "go": ("herradura_cli.go::cmdKex", 1),
        "python": ("herradura.py::cmd_kex", 1),
        "java": ("HerraduraCli.java::cmdKexHybrid", 1),
    },
    "hybrid_kem_prf_seed": {
        "status": "suite", "via": ["qcmdpc_encap"],
        "reason":
            "C's PRF seed for the Stern-KEM half of the hybrid handshake, the "
            "same asymmetry as the keygen row one level down: three ports "
            "encapsulate through a suite function that draws, C's takes the "
            "PRF already seeded",
        "c": ("herradura_cli.c::cmd_kex", 1),
        "go": None, "python": None, "java": None,
    },

    # --- enc ---------------------------------------------------------------
    "hske_nla1_nonce": {
        "status": "cli_only",
        "reason":
            "HSKE-NL-A1's counter-mode nonce.  All four ports draw it in the "
            "CLI, and this is the row where that is most load-bearing: A1 is "
            "ks = nl_fscx_revolve_v1(K, K^ctr, i) with E = P ^ ks, so a "
            "repeated nonce under one key is a two-time pad outright.  Nothing "
            "compares the four draws.  Since TODO #314 pass 6 the draw is at "
            "the KEY's width rather than a fixed 256 in every port, so the "
            "four now consume the same number of entropy bytes for the same "
            "operation -- C drew 32 and kept a prefix until that pass",
        "c": ("herradura_cli.c::cmd_enc", 1),
        "go": ("herradura_cli.go::cmdEnc", 1),
        "python": ("herradura.py::cmd_enc", 1),
        "java": ("HerraduraCli.java::cmdEnc", 1),
    },
    "duplex_nonce": {
        "status": "suite", "via": ["duplex_encrypt"],
        "reason":
            "The sponge-duplex nonce for hske-duplex2/3.  C and Go draw it in "
            "the CLI; Python's suite duplex draws its own and Python ships no "
            "duplex subcommand at all, and Java's CLI hands RNG to "
            "Duplex.v2Encrypt/v3Encrypt.  Three shapes for one nonce",
        "c": ("herradura_cli.c::cmd_enc", 1),
        "go": ("herradura_cli.go::cmdEnc", 1),
        "python": None, "java": None,
    },
    "hpke_ephemeral_r": {
        "status": "suite",
        "via": ["hpke_encrypt", "hpke_nl_encrypt", "hpke_nl3_encrypt"],
        "reason":
            "The El Gamal ephemeral exponent, and the site counts are the "
            "finding: ONE draw in C and Go, which share a branch across hpke, "
            "hpke-nl and hpke-nl3; THREE in Python, one per algorithm; NONE in "
            "Java, whose CLI calls the suite for each.  Three via rows because "
            "Java splits the operation three ways -- and the other two ports "
            "have no such operation to name, so REPLAY_COVERAGE's "
            "hpke_nl_encrypt and hpke_nl3_encrypt rows are Java-only for "
            "exactly this reason",
        "c": ("herradura_cli.c::cmd_enc", 1),
        "go": ("herradura_cli.go::cmdEnc", 1),
        "python": ("herradura.py::cmd_enc", 3),
        "java": None,
    },
    "qcmdpc_encap_prf_seed": {
        "status": "suite", "via": ["qcmdpc_encap"],
        "reason":
            "C's PRF seed for `enc --algo hpke-stern-kem`, the third and last "
            "place herradura_cli.c seeds a QcMdpcPrf the other three ports "
            "seed inside the suite",
        "c": ("herradura_cli.c::cmd_enc", 1),
        "go": None, "python": None, "java": None,
    },

    # --- sign --------------------------------------------------------------
    "threshold_commit_nonce": {
        "status": "cli_only",
        "reason":
            "HPKS-T's per-signer commitment nonce k_j, and the same arithmetic "
            "as the row above applies to it -- a threshold Schnorr partial is "
            "s_j = k_j - a_j.e, so a repeat recovers that signer's share.  All "
            "four ports draw it in the CLI; the suite's hpkst_sign is the "
            "AGGREGATE path and is not what `threshold-commit` calls.  Java's "
            "is the second of the two sites the case-blind pattern missed",
        "c": ("herradura_cli.c::cmd_threshold_commit", 1),
        "go": ("herradura_cli.go::cmdThresholdCommit", 1),
        "python": ("herradura.py::cmd_threshold_commit", 1),
        "java": ("HerraduraCli.java::cmdThresholdCommit", 1),
    },

    # --- encfile -----------------------------------------------------------
    "encfile_nonce": {
        "status": "suite", "via": ["hfscx256_enc_file"],
        "reason":
            "The HFSCX-256 file-encryption nonce.  Java hands RNG to "
            "Hfscx256.encFile, which is why REPLAY_COVERAGE's "
            "hfscx256_enc_file row has a Java cell and nothing else; the other "
            "three draw it in the CLI and pass it down",
        "c": ("herradura_cli.c::cmd_encfile", 1),
        "go": ("herradura_cli.go::cmdEncfile", 1),
        "python": ("herradura.py::cmd_encfile", 1),
        "java": None,
    },
}

_CLI_DRAW_STATUSES = ("suite", "cli_only", "owed")
_CLI_BODY_CACHE = {}


def _cli_bodies(lang):
    """{file::name: body} for one language's CLI corpus, cached."""
    if lang in _CLI_BODY_CACHE:
        return _CLI_BODY_CACHE[lang]
    out = {}
    for parts, fnpat, endpat in CLI_CORPUS[lang]:
        path = os.path.join(REPO, *parts)
        base = os.path.basename(path)
        src = _slurp(path)
        pairs = _py_bodies(src) if fnpat is None else \
            _brace_bodies(src, fnpat, endpat)
        for n, b in pairs:
            out.setdefault(f"{base}::{n}", []).append(b)
    _CLI_BODY_CACHE[lang] = out
    return out


def _cli_draw_sites():
    """{lang: {file::name: number of raw-entropy sites}}, derived."""
    out = {}
    for lang in ("c", "go", "python", "java"):
        pat = RANDOMNESS_RAW_PATTERNS[lang]
        counts = {}
        for name, bodies in _cli_bodies(lang).items():
            # MATCHES, not matching lines: two draws on one line is one site
            # under a per-line count, and the two are identical across the
            # corpus today -- which is the reason to count the stricter way
            # now rather than after someone writes the line that separates
            # them.
            n = sum(len(re.findall(pat, b)) for b in bodies)
            if n:
                counts[name] = n
        out[lang] = counts
    return out


def _check_cli_draws(errors):
    """Fourth part of the eighth axis: the corpus past the suite boundary.

    See CLI_CORPUS's header.  Two tripwires and one derived claim.  The census
    is a NAME SET like RANDOMNESS_CENSUS; the site COUNTS are held by
    CLI_DRAW_COVERAGE's cells, so a new draw inside an already-censused command
    fails until a role claims it; and a `suite` row's `via` is checked against
    the real coverage tables rather than believed.
    """
    langs = ("c", "go", "python", "java")
    sites = _cli_draw_sites()

    for lang in langs:
        got = set(sites[lang])
        if not got:
            errors.append(
                f"CLI randomness census: no raw-entropy consumer found in the "
                f"{lang} CLI — the extractor broke (CLI_CORPUS's function "
                "pattern no longer matches, or RANDOMNESS_RAW_PATTERNS does), "
                "rather than the CLI having stopped drawing")
            continue
        want = set(RANDOMNESS_CLI_CENSUS[lang])
        for name in sorted(got - want):
            errors.append(
                f"CLI randomness census: {lang} CLI function '{name}' reads raw "
                "entropy and is not in RANDOMNESS_CLI_CENSUS — add it, and give "
                "it a CLI_DRAW_COVERAGE role saying what the draw IS")
        for name in sorted(want - got):
            errors.append(
                f"CLI randomness census: RANDOMNESS_CLI_CENSUS names {lang} CLI "
                f"function '{name}', which no longer reads raw entropy — delete "
                "the entry rather than leaving a census describing the old CLI")

    # Roles -> per-language claimed site counts.
    claimed = {l: {} for l in langs}
    for role, row in CLI_DRAW_COVERAGE.items():
        status = row.get("status")
        if status not in _CLI_DRAW_STATUSES:
            errors.append(
                f"CLI draw coverage: role '{role}' has status {status!r}, which "
                f"is not one of {', '.join(_CLI_DRAW_STATUSES)}")
            continue
        if not row.get("reason"):
            errors.append(
                f"CLI draw coverage: role '{role}' carries no reason — the "
                "reason is the whole content of the entry")
        if status == "owed" and not row.get("item"):
            errors.append(
                f"CLI draw coverage: role '{role}' is owed and names no TODO "
                "item — 'owed' exists so that work cannot be parked inside a "
                "prose reason, which needs somewhere to be parked instead")
        vias = row.get("via") or []
        if status == "suite" and not vias:
            errors.append(
                f"CLI draw coverage: role '{role}' is 'suite' and names no via "
                "row — the status asserts a suite consumer accounts for the "
                "ports that do not draw here, so it has to say which")
        if status == "cli_only" and vias:
            errors.append(
                f"CLI draw coverage: role '{role}' is cli_only and names via "
                f"row(s) {vias} — 'cli_only' asserts no suite consumer draws "
                "this role in any port, which a delegation contradicts")
        for v in vias:
            if v not in REPLAY_COVERAGE and v not in OPERATION_REPLAY_PINNED \
                    and v not in SAMPLER_REPLAY_PINNED:
                errors.append(
                    f"CLI draw coverage: role '{role}' delegates to '{v}', "
                    "which is named by no REPLAY_COVERAGE, "
                    "OPERATION_REPLAY_PINNED or SAMPLER_REPLAY_PINNED row — a "
                    "delegation cannot rest on a row that does not exist")

        absent = row.get("absent") or {}
        for lang in langs:
            cell = row.get(lang)
            if cell:
                fn, n = cell
                if fn not in sites[lang]:
                    errors.append(
                        f"CLI draw coverage: role '{role}' names {lang} CLI "
                        f"function '{fn}', which reads no raw entropy — delete "
                        "the cell rather than leaving a claim about a function "
                        "that no longer draws")
                    continue
                if not isinstance(n, int) or n < 1:
                    errors.append(
                        f"CLI draw coverage: role '{role}' claims {n!r} sites "
                        f"for {lang} '{fn}' — a cell claims at least one")
                    continue
                claimed[lang][fn] = claimed[lang].get(fn, 0) + n
                if lang in absent:
                    errors.append(
                        f"CLI draw coverage: role '{role}' marks {lang} absent "
                        f"and also names '{fn}' — a port cannot both draw it "
                        "and not have it")
                continue
            # No CLI cell: some other port's suite must account for it, or the
            # port must be declared absent.
            if lang in absent:
                if not absent[lang]:
                    errors.append(
                        f"CLI draw coverage: role '{role}' marks {lang} absent "
                        "with no reason")
                continue
            covered = any(
                (REPLAY_COVERAGE.get(v) or OPERATION_REPLAY_PINNED.get(v)
                 or SAMPLER_REPLAY_PINNED.get(v) or {}).get(lang)
                for v in vias)
            if not covered:
                errors.append(
                    f"CLI draw coverage: role '{role}' gives {lang} no CLI "
                    f"function, no via row naming a {lang} suite consumer, and "
                    "no `absent` reason — every port is accounted for, or the "
                    "role's shape is a guess")

    # The direction that does not decay, at SITE granularity: every raw-entropy
    # draw in the CLI corpus is claimed by exactly one role's count.
    for lang in langs:
        for fn, n in sorted(sites[lang].items()):
            c = claimed[lang].get(fn, 0)
            if c != n:
                errors.append(
                    f"CLI draw coverage: {lang} CLI function '{fn}' has {n} "
                    f"raw-entropy site(s) and CLI_DRAW_COVERAGE claims {c} — "
                    "every draw belongs to exactly one role, or the count is "
                    "not an accounting")
        for fn in sorted(set(claimed[lang]) - set(sites[lang])):
            errors.append(
                f"CLI draw coverage: {lang} CLI function '{fn}' is claimed by a "
                "role and draws nothing")


def _cli_draw_counts():
    """(roles by status, total sites per language), for the closing report."""
    by = {k: 0 for k in _CLI_DRAW_STATUSES}
    for row in CLI_DRAW_COVERAGE.values():
        if row.get("status") in by:
            by[row["status"]] += 1
    sites = _cli_draw_sites()
    return by, {l: sum(sites[l].values()) for l in ("c", "go", "python", "java")}


_REPLAY_VECTOR = os.path.join(REPO, "KAT", "sampler_replay.json")
_OPREPLAY_VECTOR = os.path.join(REPO, "KAT", "operation_replay.json")


def _slurp(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


def _brace_bodies(src, fnpat, endpat=r"^\}"):
    """(name, body) per top-level function, body ending at a column-0 '}'."""
    lines = src.split("\n")
    out, i = [], 0
    while i < len(lines):
        m = re.match(fnpat, lines[i])
        if m:
            j = i + 1
            while j < len(lines) and not re.match(endpat, lines[j]):
                j += 1
            out.append((m.group(1), "\n".join(lines[i:j + 1])))
            i = j + 1
        else:
            i += 1
    return out


def _py_bodies(src):
    """(name, body) per def, delimited by indentation."""
    lines = src.split("\n")
    out = []
    for i, ln in enumerate(lines):
        m = re.match(r"(\s*)def\s+(\w+)\s*\(", ln)
        if not m:
            continue
        ind = len(m.group(1))
        j = i + 1
        while j < len(lines):
            s = lines[j]
            if s.strip() and (len(s) - len(s.lstrip())) <= ind \
                    and not s.lstrip().startswith(("#", ")")):
                break
            j += 1
        out.append((m.group(2), "\n".join(lines[i:j])))
    return out


_BODY_CACHE = {}


def _suite_bodies(lang):
    """{name: [body, ...]} for one language's suite, cached.

    A LIST of bodies per name rather than one body, because Java OVERLOADS:
    SternRing.sign has two, and keying a dict on the bare name silently keeps
    whichever came last -- which there is a three-line wrapper that calls
    nothing, so the ring row's transitive coverage read as unreachable.  The
    census never noticed because it tests each extracted body in turn; the call
    graph TODO #305 added walks from a name, so it would have.
    """
    if lang in _BODY_CACHE:
        return _BODY_CACHE[lang]
    out = {}

    def add(name, body):
        out.setdefault(name, []).append(body)

    if lang == "c":
        for n, b in _brace_bodies(
                _slurp(os.path.join(REPO, "herradura.h")),
                r"^static\s+(?:inline\s+)?[\w \*]+?\b(\w+)\s*\("):
            add(n, b)
    elif lang == "go":
        for n, b in _brace_bodies(
                _slurp(os.path.join(REPO, "herradura", "herradura.go")),
                r"^func\s+(?:\([^)]*\)\s*)?(\w+)\s*\("):
            add(n, b)
    elif lang == "python":
        for n, b in _py_bodies(
                _slurp(os.path.join(REPO, "Herradura cryptographic suite.py"))):
            add(n, b)
    else:
        jdir = os.path.join(REPO, "bindings", "java", "herradurakex")
        for path in sorted(glob.glob(os.path.join(jdir, "*.java"))):
            base = os.path.basename(path)
            if base in JAVA_NON_SUITE:
                continue
            for n, b in _brace_bodies(
                    _slurp(path),
                    r"^    (?:public |private |protected )?static "
                    r"[\w\[\]<>., ]*?\b(\w+)\s*\(", r"^    \}"):
                add(f"{base}::{n}", b)
    _BODY_CACHE[lang] = out
    return out


def _randomness_consumers():
    """Derive, per language, the set of functions that read raw entropy."""
    found = {}
    for lang in ("c", "go", "python", "java"):
        pat = RANDOMNESS_RAW_PATTERNS[lang]
        found[lang] = {n for n, bodies in _suite_bodies(lang).items()
                       if any(re.search(pat, b) for b in bodies)}
    return found


_REACH_CACHE = {}


def _calls_reach(lang, root):
    """Every suite function reachable from `root` by static call edges.

    This is what makes a `transitive` coverage claim DERIVED rather than
    curated, which is the whole design point of TODO #305's table: #295 found
    two of six curated reasons about how a constant is USED carrying a FALSE
    claim, and "covered by the ring row" is the same kind of sentence.

    Java resolution prefers the CALLER'S OWN FILE and falls back to another
    class only when the body qualifies the call (`Stern.foo(`).  Resolving a
    bare name across every file would over-approximate, and over-approximation
    here makes a coverage claim easier to pass -- the wrong direction for a
    check whose failure is what forces someone to look.

    KNOWN LIMIT, and it is #295's: reachability is not liveness.  An edge into
    a function no live path reaches still counts, so this can confirm that a
    pinned operation COULD call a consumer, never that the shipped run does.
    """
    if (lang, root) in _REACH_CACHE:
        return _REACH_CACHE[(lang, root)]
    bodies = _suite_bodies(lang)
    by_short = {}
    for key in bodies:
        by_short.setdefault(key.split("::")[-1], set()).add(key)

    def targets(caller, body):
        for nm in set(re.findall(r"\b(\w+)\s*\(", body)):
            cands = by_short.get(nm)
            if not cands:
                continue
            if lang != "java":
                yield from cands
                continue
            same = f"{caller.split('::')[0]}::{nm}"
            if same in cands:
                yield same
                continue
            for k in cands:
                cls = k.split("::")[0][:-len(".java")]
                if re.search(r"\b%s\s*\.\s*%s\s*\(" % (re.escape(cls),
                                                        re.escape(nm)), body):
                    yield k

    seen, stack = set(), [root]
    while stack:
        cur = stack.pop()
        if cur in seen:
            continue
        seen.add(cur)
        for body in bodies.get(cur, ()):
            for nxt in targets(cur, body):
                if nxt not in seen:
                    stack.append(nxt)
    _REACH_CACHE[(lang, root)] = seen
    return seen


def _check_replay_table(errors, path, key, table, table_name, noun):
    """One replay vector against its curated table, both directions.

    Shared by the leaf vector (TODO #296) and the operation vector (#297): the
    rules are identical one level apart, and writing them twice is how the two
    would drift.
    """
    rel = os.path.join("KAT", os.path.basename(path))
    try:
        with open(path, encoding="utf-8") as f:
            vector = json.load(f)
    except (OSError, ValueError) as exc:
        errors.append(f"{noun} replay: cannot read {rel} ({exc})")
        vector = {key: []}

    names = [r["name"] for r in vector.get(key, [])]
    if not names:
        errors.append(f"{noun} replay: {rel} carries no {key} — the vector is "
                      "empty, which would make this axis vacuous")
    for name in names:
        if name not in table:
            errors.append(
                f"{noun} replay: {rel} has a row '{name}' that {table_name} does "
                "not name — add it with its four per-language functions, or the "
                "replay consumers will not follow it")
    for name, cells in table.items():
        if name not in names:
            errors.append(
                f"{noun} replay: {table_name} names '{name}' but {rel} has no such "
                "row — delete the entry, or regenerate the vector "
                "(python3 KAT/generate_kat.py)")
        # A cell may be absent ONLY where that language takes its entropy as a
        # parameter, named and cross-checked in `param_entropy` (TODO #307) --
        # see OPERATION_REPLAY_PINNED's header.  Silence is still the split
        # this rule exists to catch.
        param = cells.get("param_entropy") or {}
        missing = [l for l in ("c", "go", "python", "java")
                   if not cells.get(l) and l not in param]
        if missing:
            errors.append(
                f"{noun} replay: '{name}' has no pinned function for "
                f"{', '.join(missing)} — a {noun} pinned in three languages is "
                "exactly the split this axis exists to catch")
        for lang, spec in sorted(param.items()):
            if cells.get(lang):
                errors.append(
                    f"{noun} replay: '{name}' names a {lang} function AND "
                    "declares its entropy a parameter — the row cannot claim "
                    "both, so delete whichever is stale")
            if not (isinstance(spec, tuple) and len(spec) == 2 and all(spec)):
                errors.append(
                    f"{noun} replay: '{name}' has a param_entropy cell for "
                    f"{lang} that is not a (function, reason) pair — the reason "
                    "is what a later reader has instead of the measurement")
    return names


def check_randomness(errors):
    """Eighth axis: the raw-entropy census and the two replays it guards."""
    # --- (1) vector <-> table, both directions, for both vectors -----------
    vector_names = _check_replay_table(
        errors, _REPLAY_VECTOR, "samplers", SAMPLER_REPLAY_PINNED,
        "SAMPLER_REPLAY_PINNED", "sampler")
    op_names = _check_replay_table(
        errors, _OPREPLAY_VECTOR, "operations", OPERATION_REPLAY_PINNED,
        "OPERATION_REPLAY_PINNED", "operation")

    # --- (2) the raw-entropy census ----------------------------------------
    found = _randomness_consumers()
    for lang in ("c", "go", "python", "java"):
        got = found[lang]
        if not got:
            errors.append(
                f"randomness census: no raw-entropy consumer found in {lang} — the "
                "extractor broke (RANDOMNESS_RAW_PATTERNS no longer matches), "
                "rather than the suite having stopped using the CSPRNG")
            continue
        want = set(RANDOMNESS_CENSUS[lang])
        for name in sorted(got - want):
            errors.append(
                f"randomness census: {lang} function '{name}' reads raw entropy and "
                "is not in RANDOMNESS_CENSUS — add it, and say whether a fixed "
                "stream reaches it (KAT/sampler_replay.json) or why it cannot")
        for name in sorted(want - got):
            errors.append(
                f"randomness census: RANDOMNESS_CENSUS names {lang} function "
                f"'{name}', which no longer reads raw entropy — delete the entry "
                "rather than leaving a census that describes the old source")
        # Every pinned sampler or operation must be one of that language's
        # censused consumers.  This is the cross-check that caught the axis's
        # own blind spot at #296 -- a Java regex that missed Oprf.blind -- so it
        # applies to both tables.
        for table, noun in ((SAMPLER_REPLAY_PINNED, "sampler"),
                            (OPERATION_REPLAY_PINNED, "operation")):
            for sname, cells in table.items():
                fn = cells.get(lang)
                if fn and fn not in got:
                    errors.append(
                        f"{noun} replay: '{sname}' claims {lang} function '{fn}', "
                        "which the raw-entropy census does not find — the pin "
                        "names a function that does not draw, so the replay "
                        "proves nothing")
                # The other direction, and it is what makes an ABSENT cell a
                # claim rather than a hole (TODO #307).  A `param_entropy` cell
                # says "this language takes the source as a parameter here", so
                # the function must EXIST and must NOT be censused.  Both
                # halves fail loudly: if the port starts drawing, the pin is
                # owed after all; if the name goes, the excuse outlived what it
                # was about, which is #295's false-reason finding in miniature.
                pe = (cells.get("param_entropy") or {}).get(lang)
                if pe:
                    pfn = pe[0]
                    if pfn in got:
                        errors.append(
                            f"{noun} replay: '{sname}' says {lang} takes its "
                            f"entropy as a parameter in '{pfn}', but the census "
                            "finds that function reading raw entropy — the cell "
                            "is a pin that is now owed, not an exemption")
                    elif pfn not in _suite_bodies(lang):
                        errors.append(
                            f"{noun} replay: '{sname}' names {lang} function "
                            f"'{pfn}' as taking its entropy as a parameter, and "
                            "no such function exists in that suite — the "
                            "exemption has outlived the code it describes")
    # --- (3) coverage of the census by the two vectors (TODO #305) --------
    _check_coverage(errors, found)
    # --- (4) the corpus past the suite boundary (TODO #306) ---------------
    _check_cli_draws(errors)
    return found, vector_names, op_names


_COVERAGE_STATUSES = ("transitive", "unpinned", "owed")


def _check_coverage(errors, found):
    """Third part of the eighth axis: what the pinning actually REACHES.

    See REPLAY_COVERAGE's header.  The rules are the ones every curated table
    here follows, plus one that is not curated at all: a `transitive` claim is
    CONFIRMED against the call graph rather than believed.
    """
    langs = ("c", "go", "python", "java")
    pinned = {l: {} for l in langs}
    for table, tname in ((SAMPLER_REPLAY_PINNED, "SAMPLER_REPLAY_PINNED"),
                         (OPERATION_REPLAY_PINNED, "OPERATION_REPLAY_PINNED")):
        for row, cells in table.items():
            for l in langs:
                if cells.get(l):
                    pinned[l][cells[l]] = (row, tname)

    claimed = {l: {} for l in langs}
    for name, row in REPLAY_COVERAGE.items():
        status = row.get("status")
        if status not in _COVERAGE_STATUSES:
            errors.append(
                f"replay coverage: row '{name}' has status {status!r}, which is "
                f"not one of {', '.join(_COVERAGE_STATUSES)}")
            continue
        if status == "transitive":
            via = row.get("via")
            if via not in OPERATION_REPLAY_PINNED:
                errors.append(
                    f"replay coverage: row '{name}' is transitive via '{via}', "
                    "which OPERATION_REPLAY_PINNED does not name — a coverage "
                    "claim cannot rest on a row that does not exist")
                continue
        else:
            if not row.get("reason"):
                errors.append(
                    f"replay coverage: row '{name}' is {status} and carries no "
                    "reason — the reason is the whole content of the entry")
            if status == "owed" and not row.get("item"):
                errors.append(
                    f"replay coverage: row '{name}' is owed and names no TODO "
                    "item — 'owed' exists so that work cannot be parked inside "
                    "a prose reason, which needs somewhere to be parked instead")

        cells = [(l, row.get(l)) for l in langs]
        if not any(fn for _, fn in cells):
            errors.append(
                f"replay coverage: row '{name}' has no function in any "
                "language — delete it rather than leaving an empty claim")
        for lang, fn in cells:
            if not fn:
                continue
            if fn in pinned[lang]:
                prow, tname = pinned[lang][fn]
                errors.append(
                    f"replay coverage: row '{name}' claims {lang} function "
                    f"'{fn}', which {tname} already pins as '{prow}' — drop the "
                    "cell (and the row, if it empties), because a pinned "
                    "consumer needs no coverage claim")
                continue
            if fn not in found[lang]:
                errors.append(
                    f"replay coverage: row '{name}' names {lang} function "
                    f"'{fn}', which the raw-entropy census does not find — "
                    "delete the cell rather than leaving a claim about a "
                    "function that no longer draws")
                continue
            if fn in claimed[lang]:
                errors.append(
                    f"replay coverage: {lang} function '{fn}' is claimed by "
                    f"both '{claimed[lang][fn]}' and '{name}' — one consumer, "
                    "one row, or the count means nothing")
            claimed[lang][fn] = name
            if row["status"] == "transitive":
                op = OPERATION_REPLAY_PINNED[row["via"]].get(lang)
                if op and fn not in _calls_reach(lang, op):
                    errors.append(
                        f"replay coverage: row '{name}' says {lang} '{fn}' is "
                        f"reached by the '{row['via']}' operation row, but no "
                        f"call path runs from '{op}' to it — the claim is "
                        "false, or the call moved")

    # The direction that does not decay: every censused consumer is pinned,
    # or claimed here.  Adding one to any language fails CI until someone says
    # which.
    for lang in langs:
        for fn in sorted(found[lang] - set(pinned[lang]) - set(claimed[lang])):
            errors.append(
                f"replay coverage: {lang} function '{fn}' reads raw entropy, is "
                "pinned by neither KAT/sampler_replay.json nor "
                "KAT/operation_replay.json, and no REPLAY_COVERAGE row claims "
                "it — add a row saying whether a fixed stream reaches it, why "
                "it need not, or which item owes the pin")


def _coverage_counts():
    """(transitive, unpinned, owed) rows, for the closing report."""
    out = {k: 0 for k in _COVERAGE_STATUSES}
    for row in REPLAY_COVERAGE.values():
        if row.get("status") in out:
            out[row["status"]] += 1
    return out

def _print_verdict_table():
    """--update-verdicts: print the table, change nothing on disk."""
    print("_VERDICT_FINGERPRINTS = {")
    for lang in ("c", "go", "python", "java"):
        print(f"    # {lang}")
        row = [f'("{lang}", {num}): "{_verdict_fingerprint(lang, body)}",'
               for num, body in sorted(_numbered_test_bodies(lang).items())]
        for i in range(0, len(row), 2):
            print("    " + " ".join(row[i:i + 2]))
    print("}")


def _print_sampled_rates():
    """TODO #319: every derived rate, per port, with the constants behind it.

    The table no longer carries the numbers -- that is the point of deriving
    them -- so this is where a reader sees what the budget is made of, and it
    prints the PER-PORT spread rather than only the worst, because the
    C/Java-vs-Go/Python split is the finding and one column would hide it.
    """
    errors = []
    derived, _envs = _derive_sampled_rates(errors)
    ptables = _param_tables()
    bodies = {l: _numbered_test_bodies(l) for l in NUMBERED_TEST_FILES}
    scopes = {l: _numbered_test_scopes(l) for l in NUMBERED_TEST_FILES}
    total = 0.0
    for (scope, num), (formula, variables, _r) in sorted(
            _SAMPLED_TEST_RATES.items(), key=lambda kv: str(kv[0])):
        langs = SHARED_NUMBERING_LANGS if scope == "shared" else (scope,)
        per = derived.get((scope, num), {})
        worst = max(per.values()) if per else float("nan")
        total += worst if per else 0.0
        print(f"[{num}] ({scope})  {formula}   worst {worst:.3e}")
        # TODO #320: which MECHANISM the formula rests on, and how it was
        # settled.  A reader of this report was previously shown the arithmetic
        # and its inputs and nothing about whether the arithmetic is the right
        # function -- which is how a b = 0 claim survived in three ports.
        mech = next((n for n, m in sorted(_RATE_MECHANISMS.items())
                     if (scope, num) in [tuple(k) for k in m["rows"]]), None)
        if mech:
            m = _RATE_MECHANISMS[mech]
            rungs = ", ".join(f"{m['var']}={r}: {m['ladder'][r][1]}/{m['ladder'][r][0]}"
                              for r in sorted(m["ladder"]))
            print(f"      mechanism {mech}: detects {m['detects']}")
            print(f"      MEASURED   {rungs}   witness {m['witness']}")
        else:
            print(f"      mechanism UNMEASURED: "
                  f"{_RATE_MECHANISM_UNMEASURED.get((scope, num), '???')}")
        for lang in langs:
            cells = []
            for var, by_lang in sorted(variables.items()):
                spec = by_lang.get(lang)
                if spec is None:
                    cells.append(f"{var}=?")
                    continue
                v = _rate_var_value(
                    spec, lang,
                    {"body": bodies.get(lang, {}).get(num, ""),
                     "scope": scopes.get(lang, {}).get(num, "")},
                    ptables, [], f"[{num}] {var}")
                origin = ("suite " + spec[1] if spec[0] == "param"
                          else "harness-local")
                cells.append(f"{var}={v} ({origin})")
            got = per.get(lang)
            shown = f"{got:.3e}" if got is not None else "UNRESOLVED"
            print(f"    {lang:7} {shown}   " + ", ".join(cells))
    print()
    lit = 0.0
    for key in sorted(_SAMPLED_TEST_RATE_LITERAL, key=str):
        r = _SAMPLED_TESTS[key][1]
        lit += r
        print(f"{str(list(key)):16} {r:.1e}  hand-computed (reason recorded)")
    print(f"\nderived {total:.3e} + hand-computed {lit:.3e} = {total + lit:.3e} "
          f"against a budget of {_SAMPLED_TEST_BUDGET:.0e}")
    # TODO #321.  The rows that contribute NOTHING to that sum are the ones
    # worth printing beside it, since that is the category #304 showed decays.
    print("\nexact rows (rate zero, contributing nothing to the sum above):")
    for key, ent in sorted(_EXACT_BASES.items(), key=str):
        ev = f" -> {ent['evidence']}" if ent["evidence"] else ""
        print(f"{str(list(key)):16} {ent['basis']}{ev}")
    print("\nargued rows held to a MEASURED record:")
    for name, m in sorted(_ARGUED_MEASUREMENTS.items()):
        rows = ", ".join(f"[{n}]/{sc}" for sc, n in m["rows"])
        print(f"  {name} ({m['kind']}) for {rows}, reducing {m['var']} over "
              f"{sorted(m['ladder'], reverse=True)}")
    if errors:
        print("\nERRORS:")
        for e in errors:
            print(f"  - {e}")
    return 1 if errors else 0


def main():
    if "--update-verdicts" in sys.argv:
        _print_verdict_table()
        return 0
    if "--sampled-rates" in sys.argv:
        return _print_sampled_rates()
    errors = []
    numbers = check_numbered_tests(errors)
    check_shared_numbering(errors, numbers)
    (sampled_drawn, sampled_rate, sampled_rated,
     sampled_mechs, sampled_mech_rows) = check_sampled_tests(errors, numbers)
    argued_exact, argued_meas, argued_rows = check_argued_evidence(
        errors, _param_tables())
    rej_cells, rej_rated, rej_meas = check_rejection_bases(errors)
    (red_files, red_fresh, red_fixed, red_rows,
     red_rated) = check_reduced_harnesses(errors)
    verdicts_pinned = check_verdict_fingerprints(errors)
    checked = check_primitives(errors)
    census = check_census(errors)
    param_counts, _param_values = check_parameters(errors)
    param_used = check_param_use(errors)
    rnd_census, replay_rows, op_rows = check_randomness(errors)

    if errors:
        print("Language parity: FAILED")
        for e in errors:
            print(f"  - {e}")
        return 1

    total_numbered = sum(len(v) for v in numbers.values())
    shared_max = max(numbers[l][-1] for l in SHARED_NUMBERING_LANGS if numbers.get(l))
    print(
        f"OK: numbered-test IDs are contiguous and duplicate-free in all four languages "
        f"({total_numbered} checks total); C/Go/Python's shared [1]-[{shared_max}] set is "
        f"identical across all three; Java's own [1]-[{numbers['java'][-1]}] is internally "
        f"consistent; {checked} language-markers across {len(PRIMITIVES)} suite-internal "
        f"primitive(s) are present where required."
    )
    n_exact = sum(1 for c, _r, _x in _SAMPLED_TESTS.values() if c == "exact")
    print(
        f"OK: sampled-test census — {sum(len(v) for v in sampled_drawn.values())} "
        f"numbered test(s) across the four languages decide a verdict from a "
        f"FRESH sample (c {len(sampled_drawn['c'])}, go {len(sampled_drawn['go'])}, "
        f"python {len(sampled_drawn['python'])}, java {len(sampled_drawn['java'])}), "
        f"every one recorded; {len(_SAMPLED_TESTS)} carry a curated verdict "
        f"({n_exact} exact, {sampled_rated} with a rate — of which "
        f"{len(_SAMPLED_TEST_RATES)} are EVALUATED FROM SOURCE every run over "
        f"{_rate_var_count()} constant(s) read per port, with "
        f"{sampled_mech_rows} of those held to a MEASURED mechanism over "
        f"{sampled_mechs} validated formula(s) and "
        f"{len(_RATE_MECHANISM_UNMEASURED)} declared unmeasurable, and "
        f"{len(_SAMPLED_TEST_RATE_LITERAL)} are hand-computed with a recorded "
        f"reason they cannot be, each ANCHORED to the test it describes) and "
        f"{len(_SAMPLED_TEST_CONSTANT)} draw nothing that reaches a verdict.  "
        f"Summed false-failure rate {sampled_rate:.1e} per run against a budget "
        f"of {_SAMPLED_TEST_BUDGET:.0e} (TODO #316, #319, #320, #321, #322, #323)."
    )
    n_margin = sum(1 for m in _ARGUED_MEASUREMENTS.values()
                   if m.get("kind") == "margin")
    print(
        f"OK: the ARGUED half — all {argued_exact} `exact` row(s) record WHY "
        f"the rate is zero and what holds at the parameters the suite DEPLOYS; "
        f"{argued_rows} argued rows carry measured evidence over "
        f"{argued_meas} record(s) ({n_margin} measured MARGIN, "
        f"{argued_meas - n_margin} measured rate), each with an exact "
        f"per-trial witness; and all {len(_SAMPLED_TEST_RATE_LITERAL)} "
        f"hand-computed literal(s) are anchored to the test they describe.  An "
        f"`exact` verdict owes a SLACK, not a count of zeros (TODO #321)."
    )
    n_width = sum(1 for e in _REJECTION_BASES.values()
                  if e["basis"] in _REJECTION_BY_WIDTH)
    print(
        f"OK: the DERIVED default — {rej_cells} uncurated sampled cell(s) "
        f"assert that something must be REFUSED, and each states the BASIS on "
        f"which that rejection holds: {rej_rated} rest on a fresh coin and now "
        f"carry a rated _SAMPLED_TESTS row, {n_width} on a collision or a "
        f"forgery at a stated WIDTH, and the rest on no coin at all.  "
        f"{rej_meas} excluded mechanism(s) carry a measured REFUTATION.  The "
        f"default is a statement about ROUND-TRIPS, which is what a rejection "
        f"can fail (TODO #322)."
    )
    print(
        f"OK: the REDUCED harnesses — this axis reads {red_files} more gated "
        f"harness(es) than Parts 1/7-6/7 do, and states the corpus rather than "
        f"leaving it unexamined: {red_fresh} reseed their PRNG from "
        f"/dev/urandom and so decide verdicts on a FRESH sample, {red_fixed} "
        f"never reseed and therefore cannot flake at all — DERIVED from each "
        f"harness's source and cross-checked both ways.  {red_rows} flagged "
        f"cell(s) state a BASIS from Part 5/7's closed set, {red_rated} of them "
        f"rated and folded into the SAME budget.  The same [10] is rated in "
        f"two harnesses and exact in the third (TODO #323)."
    )
    n_none = sum(1 for v in _VERDICT_FINGERPRINTS.values() if v == "none")
    print(
        f"OK: verdict fingerprints — how all {verdicts_pinned} numbered test(s) "
        f"DECIDE is pinned, so a test that changes its verdict fails until "
        f"someone says whether it now rests on a fresh sample against a fixed "
        f"threshold; {n_none} carry no verdict line at all (the benchmarks), "
        f"which is pinned too so one that GROWS a verdict fires (TODO #318)."
    )
    print(
        "OK: internal-surface census — "
        + "; ".join(
            f"{lang} {internal} internal of {declared} declared, {named} manifest-named"
            for lang, (declared, internal, named) in census.items()
        )
        + "; every remainder carries a CENSUS_EXEMPT reason."
    )
    local_rows = sum(1 for cells, observable, _m in PARAMETERS.values()
                     if observable == "local")
    print(
        f"OK: parameter-value parity — {len(PARAMETERS)} rows over "
        + ", ".join(f"{lang} {ev}" for lang, (ev, _n) in param_counts.items())
        + f" evaluable suite parameters, all manifest-named or exempt; "
        f"{len(PARAM_DIVERGENCE)} recorded divergence(s) "
        f"({sum(1 for d in PARAM_DIVERGENCE.values() if d['status'] == 'defect')} defect, "
        f"{sum(1 for d in PARAM_DIVERGENCE.values() if d['status'] == 'acknowledged')} "
        f"acknowledged); {local_rows} rows are 'local', where a disagreement reaches no "
        f"artifact and this axis is the only check."
    )
    total_cells = sum(1 for cells, _o, _m in PARAMETERS.values() for c in cells if c)
    print(
        f"OK: parameter-use census — all {param_used} of {total_cells} declared "
        f"PARAMETERS cells are READ by that language's shipped code, outside their own "
        f"declaration and outside diagnostic calls; "
        f"{len(PARAM_USE_EXEMPT)} declaration-only exemption(s)."
    )
    print(
        f"OK: raw-entropy census — "
        + ", ".join(f"{lang} {len(rnd_census[lang])}"
                    for lang in ("c", "go", "python", "java"))
        + f" function(s) read the CSPRNG directly, all recorded; "
        f"{len(replay_rows)} sampler(s) pinned against a fixed stream in all four "
        f"languages by KAT/sampler_replay.json, and {len(op_rows)} whole "
        f"operation(s) by KAT/operation_replay.json."
    )
    cov = _coverage_counts()
    print(
        f"OK: replay coverage — every censused consumer is pinned or accounted "
        f"for: {cov['transitive']} row(s) covered transitively by a pinned "
        f"operation (confirmed against the call graph, not asserted), "
        f"{cov['unpinned']} where a fixed stream would prove nothing new, and "
        f"{cov['owed']} still OWED a pin."
    )
    cli_by, cli_sites = _cli_draw_counts()
    print(
        f"OK: CLI draw census — the corpus reaches past the suite boundary: "
        + ", ".join(f"{lang} {cli_sites[lang]}"
                    for lang in ("c", "go", "python", "java"))
        + f" raw-entropy site(s) in the four CLIs, {sum(cli_sites.values())} in "
        f"all, every one claimed by one of {len(CLI_DRAW_COVERAGE)} draw role(s) "
        f"({cli_by['suite']} delegated to a censused suite consumer, "
        f"{cli_by['cli_only']} drawn nowhere but the CLI, and {cli_by['owed']} "
        f"OWED)."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
