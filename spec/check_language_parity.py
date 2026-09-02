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

  3. SUITE-INTERNAL PRIMITIVE PRESENCE.  A small, curated manifest (below) of
     primitives that are NOT reachable through any CLI `--algo` tag — the
     exact class of thing #261's own gap was.  Each entry names a marker
     regex per language; a language missing a required marker fails unless
     the entry is explicitly `acknowledged`.  This manifest is a SEED, not a
     retroactive full audit of the whole suite (that would be the "one-time
     read of the source tree" #261's acceptance criterion says not to rely
     on) — extend it whenever a new suite-internal (non-CLI) primitive is
     added, the same way `CliTest/lib_build.sh`'s coverage guard grew script
     by script rather than being written complete on day one.

WHAT IT DELIBERATELY DOES NOT CHECK.  The CLI `--algo`/subcommand surface —
that is `spec/generate_spec.py --check`'s job, already run in CI, and
duplicating it here would just be two places that can drift apart from each
other.  A full census of every function in every suite file — see PRIMITIVES'
docstring below for why that would be mostly false positives.

Usage:
    python3 spec/check_language_parity.py     # exit 1 on any inconsistency
"""
import os
import re
import sys
from collections import Counter

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# ── Part 1/2: numbered-test files ────────────────────────────────────────
# (path, pattern-with-one-group-capturing-the-number)
NUMBERED_TEST_FILES = {
    "c": (
        os.path.join(REPO, "CryptosuiteTests", "Herradura_tests.c"),
        re.compile(r'printf\("\[(\d+)\]'),
    ),
    "go": (
        os.path.join(REPO, "CryptosuiteTests", "Herradura_tests.go"),
        re.compile(r'fmt\.Print(?:ln|f)\("\[(\d+)\]'),
    ),
    "python": (
        os.path.join(REPO, "CryptosuiteTests", "Herradura_tests.py"),
        re.compile(r'print\(f?"\[(\d+)\]'),
    ),
    "java": (
        # Only the PASS branch: each check's [N] appears in both its PASS
        # and FAIL string literal (the exhaustive if/else outcome pair, both
        # always present in source regardless of runtime result), so
        # matching both would double-count every number by construction.
        os.path.join(REPO, "bindings", "java", "herradurakex", "SelfTest.java"),
        re.compile(r'println\("PASS \[(\d+)\]'),
    ),
}

# C/Go/Python are documented (CLAUDE.md's Testing section) as sharing one
# numbering convention; Java's is explicitly its own (SelfTest.java's class
# doc comment). Only the first three are checked against each other.
SHARED_NUMBERING_LANGS = ("c", "go", "python")


def check_numbered_tests(errors):
    """Returns {lang: sorted distinct numbers found}."""
    numbers = {}
    for lang, (path, pattern) in NUMBERED_TEST_FILES.items():
        with open(path, encoding="utf-8") as f:
            text = f.read()
        found = [int(m) for m in pattern.findall(text)]
        rel = os.path.relpath(path, REPO)
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
# protocol family instead, so its entry is every *.java file in that
# directory concatenated — a marker regex can then target whichever class
# actually holds it (Hcred.java, Herradura.java, Xmss.java, Ratchet.java,
# ...) without SUITE_FILES itself needing to know which one.
SUITE_FILES = {
    "c": os.path.join(REPO, "herradura.h"),
    "go": os.path.join(REPO, "herradura", "herradura.go"),
    "python": os.path.join(REPO, "Herradura cryptographic suite.py"),
    "java": sorted(
        os.path.join(REPO, "bindings", "java", "herradurakex", f)
        for f in os.listdir(os.path.join(REPO, "bindings", "java", "herradurakex"))
        if f.endswith(".java")
    ),
}

# id -> {lang: marker_regex} — a language absent from the dict, or whose
# regex doesn't match, is a finding unless the whole entry carries
# "acknowledged": "<reason>" (then the entry is documented-non-parity, not
# a silent gap, and is skipped). Regexes are matched with re.M against the
# whole file named in SUITE_FILES for that language.
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
    # The next three entries are TODO #261's first pass at extending the
    # manifest beyond its hcred-kkw seed (SecurityProofs-*.md's 78.x
    # numbering). All were already at four-language parity except
    # fscx-revolve-masked, ported to Java in this pass.
    "haccum": {
        # Merkle accumulator (78.J): checks haccum_verify, the security-
        # critical member of the leaf/node/root/prove/verify family — the
        # other four move in lockstep with it in every language's history.
        # In Java it lives inside Xmss.java (its only caller) rather than
        # a standalone module, but is public (TODO #261) like the other
        # three languages' top-level functions.
        "c": r"static int haccum_verify\(",
        "go": r"func HaccumVerify\(",
        "python": r"^def haccum_verify\(",
        "java": r"public static boolean haccumVerify\(",
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
        "java": r"public static BigInteger fscxRevolveMasked\(",
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
}


def check_primitives(errors):
    file_text = {}
    for lang, paths in SUITE_FILES.items():
        paths = [paths] if isinstance(paths, str) else paths
        chunks = []
        for path in paths:
            with open(path, encoding="utf-8") as f:
                chunks.append(f.read())
        file_text[lang] = "\n".join(chunks)

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
            if not re.search(pattern, file_text[lang], re.M):
                if reason:
                    continue
                paths = SUITE_FILES[lang]
                paths = [paths] if isinstance(paths, str) else paths
                rel = ", ".join(os.path.relpath(p, REPO) for p in paths)
                errors.append(
                    f"'{pid}': marker {pattern!r} not found in {lang}'s suite file(s) ({rel}) — "
                    f"either the function was renamed/removed (update PRIMITIVES to match) or "
                    f"this is a real cross-language gap (port it, or add an 'acknowledged' "
                    f"reason to the PRIMITIVES entry, the same way SECURITY.md records one)"
                )
    return checked


def main():
    errors = []
    numbers = check_numbered_tests(errors)
    check_shared_numbering(errors, numbers)
    checked = check_primitives(errors)

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
    return 0


if __name__ == "__main__":
    sys.exit(main())
