#!/usr/bin/env python3
"""Cross-document consistency audit (TODO #265).

WHY THIS EXISTS.  Three mechanical cross-checks already live in this repo, and
each covers one narrow slice:

  * `spec/check_security_md.py`      — spec/ status enum  vs. SECURITY.md prose
  * `spec/check_language_parity.py`  — test/primitive sets vs. C/Go/Python/Java
  * `SecurityProofsCode/check_part_index.py` — the eight-part index, everywhere

None of them looks at the *narrative* documents.  `README.md`,
`docs/INTRODUCTION.md` and `CHANGELOG.md` describe the same protocols, the same
parameters and the same maturity verdicts as `spec/herradura-protocol-spec.json`
and `herradura.h` do — in prose, written by hand, at four different times — and
nothing has ever compared them.  TODO #265 was filed on that gap; the five
defects listed at the bottom of this docstring are what the first run found.

WHAT IT CHECKS.

  A. VERSIONS.  README's title line, `CHANGELOG.md`'s newest entry and
     `pyproject.toml` all name the same release; CHANGELOG's version list is
     strictly descending with no duplicates; every MAJOR bump has a
     `MIGRATING.md` section, as CLAUDE.md's version policy requires.

  B. PARAMETERS.  Numeric constants are read out of `herradura.h` (with their
     arithmetic evaluated, so `KEYBITS / 2` becomes 128) and compared against
     both `spec/`'s `parameters` block and a curated table of the places the
     prose repeats them.

  C. PROTOCOL COVERAGE.  Every protocol in `spec/` is accounted for in the two
     intro-level documents, and every protocol-shaped name those documents use
     resolves to something that still exists.

  D. CLAIMS.  A curated table of prose assertions that must hold, and of
     superseded assertions that must NOT come back.

THE CURATED TABLES ARE THE POINT, AND THEY ARE SELF-INVALIDATING.  Prose cannot
be derived from a spec file, so B, C and D each rest on a hand-written table --
the same bargain `check_security_md.py` struck, for the same reason.  What keeps
one honest is that it fails when either side moves: check C fails when spec/
gains or loses a protocol that DOC_COVERAGE does not mention, and every regex in
checks B and D must match at least once, so a doc edit that removes the sentence
an entry was anchored to is a failure ("anchor lost"), not a silent pass.  A
curated table nothing validates is the thing TODO #238 was filed about.

WHAT THE FIRST RUN FOUND (all six fixed in v5.8.6, and each is now pinned by an
entry below, so a regression fails this script):

  1. README.md §HPKS-Stern-F called `rounds = 32` the "production default".  It
     is the DEMO default; herradura.h emits a `#pragma message` warning below
     `SDF_PRODUCTION_ROUNDS = 219`, and README's own caveats section, 280 lines
     further down, correctly called the same 32 "a low-soundness demonstration
     configuration".  The file contradicted itself.
  2. docs/INTRODUCTION.md put Stern's per-round soundness error at `(1/3)^32`.
     It is `(2/3)` per round -- as the same document says 40 lines later -- and
     the stated `10^{-15}` matched neither.  Under `(1/3)^R`, 128-bit soundness
     would need 81 rounds rather than the 219 the whole suite is built around.
  3. docs/INTRODUCTION.md said HPKE-Stern-F ships with "no decoder implemented"
     and that production "would need a QC-MDPC or similar decoder".  The BGF
     QC-MDPC decoder has shipped since v1.9.x as `--algo hpke-stern-kem`.
  4. pyproject.toml still declared `version = "2.1.3"` at suite v5.8.5 -- 3
     major versions stale, and the number `pip` reports.
  5. README.md's caveats section said tests [4] and [18] are "FAIL-by-design"
     and "Don't treat either as a build gate".  TODO #233 (v3.0.8) fixed both
     tests and made any `[FAIL]` fail the build, with no allow-list.  The README
     was telling readers to ignore a blocking CI gate.
  6. Found by check B rather than by reading: spec/ reported
     `parameters.stern_f.rounds_demo` as the STRING
     `"32             /* ZKP rounds (demo; prod >= 219);"`.  generate_spec.py's
     comment stripper is single-line, and SDF_ROUNDS's comment runs to four, so
     the comment text leaked into the value.  Fixed in generate_spec.py; this
     script keeps it fixed, because check B compares that field to an int.

Usage:
    python3 spec/check_docs_consistency.py     # exit 1 on any inconsistency
"""
import json
import os
import re
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _p(*parts):
    return os.path.join(REPO, *parts)


SPEC_PATH = _p("spec", "herradura-protocol-spec.json")
HEADER = _p("herradura.h")
README = _p("README.md")
INTRO = _p("docs", "INTRODUCTION.md")
CHANGELOG = _p("CHANGELOG.md")
MIGRATING = _p("MIGRATING.md")
PYPROJECT = _p("pyproject.toml")

FAILURES = []


def fail(check, msg):
    FAILURES.append((check, msg))


def read(path):
    with open(path, encoding="utf-8") as fh:
        return fh.read()


# ── herradura.h constants ──────────────────────────────────────────────────
#
# The header is the authority for every protocol parameter the prose quotes.
# Values are #defines over other #defines ("(KEYBITS / 2)"), so they are
# resolved transitively and then evaluated -- integer arithmetic only, and only
# over names already resolved, so nothing here can execute header text.

_DEFINE_RE = re.compile(r"^#define\s+([A-Z][A-Z0-9_]*)\s+(\S.*?)\s*(?:/\*|//|$)", re.M)
_SAFE_EXPR = re.compile(r"^[0-9A-Z_+\-*/() ]+$")


def header_constants():
    """Every #define in herradura.h whose value evaluates to an integer."""
    raw = {}
    for name, value in _DEFINE_RE.findall(read(HEADER)):
        raw.setdefault(name, value.strip())

    resolved = {}
    for _ in range(8):                      # fixpoint; the nesting is 2 deep
        progress = False
        for name, value in raw.items():
            if name in resolved or not _SAFE_EXPR.match(value):
                continue
            expr = value
            for other in sorted(resolved, key=len, reverse=True):
                expr = re.sub(r"\b%s\b" % other, str(resolved[other]), expr)
            if re.search(r"[A-Z_]", expr):
                continue                    # still names an unresolved macro
            try:
                resolved[name] = int(eval(expr, {"__builtins__": {}}, {}))
                progress = True
            except (SyntaxError, ValueError, ZeroDivisionError, TypeError):
                pass
        if not progress:
            break
    return resolved


# ══ A. Versions ════════════════════════════════════════════════════════════

_VER = r"(\d+)\.(\d+)\.(\d+)"


def check_versions():
    changelog = read(CHANGELOG)
    versions = re.findall(r"^## \[%s\]" % _VER, changelog, re.M)
    if not versions:
        fail("A", "CHANGELOG.md: no '## [X.Y.Z]' entries found -- format changed?")
        return
    tuples = [tuple(int(x) for x in v) for v in versions]
    latest = tuples[0]
    latest_s = "%d.%d.%d" % latest

    # A1: strictly descending, no duplicates.
    for older, newer in zip(tuples[1:], tuples):
        if newer <= older:
            fail("A", "CHANGELOG.md: entry %d.%d.%d does not precede %d.%d.%d "
                      "(entries must be strictly descending, no duplicates)"
                      % (newer + older))

    # A2: README title line.
    m = re.search(r"^# Herradura Cryptographic Suite \(v%s\)" % _VER, read(README), re.M)
    if not m:
        fail("A", "README.md: title line does not match "
                  "'# Herradura Cryptographic Suite (vX.Y.Z)'")
    elif ".".join(m.groups()) != latest_s:
        fail("A", "README.md title says v%s; newest CHANGELOG.md entry is %s"
                  % (".".join(m.groups()), latest_s))

    # A3: pyproject.toml -- the version `pip` reports.
    m = re.search(r'^version\s*=\s*"%s"' % _VER, read(PYPROJECT), re.M)
    if not m:
        fail("A", "pyproject.toml: no 'version = \"X.Y.Z\"' line found")
    elif ".".join(m.groups()) != latest_s:
        fail("A", "pyproject.toml declares %s; newest CHANGELOG.md entry is %s "
                  "(this is the version `pip install` reports)"
                  % (".".join(m.groups()), latest_s))

    # A4: CLAUDE.md's policy -- every MAJOR bump gets a MIGRATING.md entry.
    migrating = read(MIGRATING)
    for major, minor, patch in tuples:
        if (minor, patch) != (0, 0) or major < 2:
            continue                        # policy applies from 2.0.0 onward
        tag = "%d.0.0" % major
        if tag not in migrating:
            fail("A", "CHANGELOG.md has a MAJOR release %s but MIGRATING.md "
                      "never mentions it (CLAUDE.md requires a MIGRATING.md "
                      "entry alongside every MAJOR bump)" % tag)


# ══ B. Parameters ══════════════════════════════════════════════════════════
#
# Each entry: (constant name, document, regex with ONE capture group holding the
# number as the prose writes it, why the sentence exists).  Both directions are
# enforced: a regex that matches nothing is an "anchor lost" failure, and every
# captured value must equal the header constant.

DOC_PARAMS = [
    ("KEYBITS", README,
     r"Parameters \(C/Go/Python\): \$N = n = (\d+)\$",
     "Stern-F code length N, README's protocol list"),
    ("SDF_T", README,
     r"Parameters \(C/Go/Python\): \$N = n = \d+\$, \$t = (\d+)\$",
     "Stern-F error weight t, README's protocol list"),
    ("SDF_ROUNDS", README,
     r"rounds \$= (\d+)\$ \(demo default",
     "Stern-F round count, README's protocol list"),
    ("SDF_PRODUCTION_ROUNDS", README,
     r"\((\d+) reaches 128-bit Fiat-Shamir soundness\)",
     "Stern-F production round count, README caveats"),
    ("SDF_PRODUCTION_ROUNDS", INTRO,
     r"reaching 128-bit soundness takes (\d+) rounds",
     "Stern-F production round count, INTRODUCTION Stern section"),
    ("SDF_ROUNDS", INTRO,
     r"After (\d+) rounds \(the suite's demo default\)",
     "Stern-F round count, INTRODUCTION soundness paragraph"),
    ("RNL_N", README,
     r"ring dimension \$n=(\d+)\$ since v2\.7\.19",
     "HKEX-RNL ring dimension, README's protocol list"),
    ("RNL_N", INTRO,
     r"\*\*Parameters:\*\* n=(\d+) \(polynomial degree\)",
     "HKEX-RNL ring dimension, INTRODUCTION"),
    ("RNL_Q", INTRO,
     r"\(polynomial degree\), q=(\d+) \(modulus\)",
     "HKEX-RNL modulus q, INTRODUCTION"),
    ("RNL_P", INTRO,
     r"q=\d+ \(modulus\), p=(\d+) \(rounding modulus\)",
     "HKEX-RNL rounding modulus p, INTRODUCTION"),
    ("I_VALUE", INTRO,
     r"iterated (\d+) steps \(= n/4\)",
     "HFSCX-256 compression step count, INTRODUCTION"),
]

# spec/'s `parameters` block quotes the same header constants.  Key path into
# the JSON -> header constant.
SPEC_PARAMS = [
    (("classical", "keybits"), "KEYBITS"),
    (("stern_f", "n_rows"), "SDF_N_ROWS"),
    (("stern_f", "t"), "SDF_T"),
    (("stern_f", "rounds_demo"), "SDF_ROUNDS"),
    (("stern_f", "rounds_production"), "SDF_PRODUCTION_ROUNDS"),
    (("stern_f", "syndrome_bytes"), "SDF_SYNBYTES"),
    (("hkex_rnl", "n"), "RNL_N"),
]


def check_parameters(consts):
    for path, name in SPEC_PARAMS:
        if name not in consts:
            fail("B", "herradura.h: constant %s not found (spec/ quotes it as %s)"
                      % (name, ".".join(path)))
            continue
        node = json.load(open(SPEC_PATH, encoding="utf-8"))["parameters"]
        for key in path:
            if not isinstance(node, dict) or key not in node:
                fail("B", "spec/: parameters.%s missing" % ".".join(path))
                node = None
                break
            node = node[key]
        if node is None:
            continue
        if node != consts[name]:
            fail("B", "spec/ parameters.%s = %r but herradura.h %s = %d"
                      % (".".join(path), node, name, consts[name]))

    for name, doc, pattern, why in DOC_PARAMS:
        rel = os.path.relpath(doc, REPO)
        if name not in consts:
            fail("B", "herradura.h: constant %s not found (%s quotes it: %s)"
                      % (name, rel, why))
            continue
        found = re.findall(pattern, read(doc))
        if not found:
            fail("B", "ANCHOR LOST -- %s: nothing matches /%s/ any more (%s). "
                      "Re-point this entry at the sentence that replaced it, or "
                      "drop it if the claim is gone." % (rel, pattern, why))
            continue
        for value in found:
            if int(value) != consts[name]:
                fail("B", "%s says %s where herradura.h %s = %d (%s)"
                          % (rel, value, name, consts[name], why))


# ══ C. Protocol coverage ═══════════════════════════════════════════════════
#
# id -> (token that must appear in README or None, token that must appear in
# INTRODUCTION or None, reason).  `None` on a side is a deliberate statement
# that the protocol is below intro-level: README and INTRODUCTION are the two
# front doors, and cataloguing all 35 protocols in either would defeat them.
# SPEC.md, SECURITY.md and docs/TUTORIAL.md are the complete listings, and they
# are covered by check_security_md.py and generate_spec.py --check.

DOC_COVERAGE = {
    # The classical quartet and the NL/PQC quartet: both front doors list these.
    "hkex-gf":          ("HKEX-GF", "HKEX-GF"),
    "hske":             ("HSKE", "HSKE"),
    "hpks":             ("HPKS", "HPKS"),
    "hpke":             ("HPKE", "HPKE"),
    "hske-nla1":        ("HSKE-NL-A1", "HSKE-NL-A1"),
    "hske-nla2":        ("HSKE-NL-A2", "HSKE-NL-A2"),
    "hkex-rnl":         ("HKEX-RNL", "HKEX-RNL"),
    "hpks-nl":          ("HPKS-NL", "HPKS-NL"),
    "hpke-nl":          ("HPKE-NL", "HPKE-NL"),
    # Code-based PQC: both front doors list these too.
    "hpks-stern":       ("HPKS-Stern-F", "HPKS-Stern-F"),
    "hpke-stern":       ("HPKE-Stern-F", "HPKE-Stern-F"),
    "hpke-stern-kem":   ("hpke-stern-kem", "hpke-stern-kem"),
    # The hash: named in both, as the construction under the signatures.
    "hfscx-256":        ("HFSCX-256", "HFSCX-256"),
    # Below intro level.  Each is a variant or a building block reached through
    # SPEC.md / TUTORIAL.md rather than the front doors.
    "hfscx-256-ds":     (None, None),   # domain-separated sibling of hfscx-256
    "hske-duplex":      (None, None),   # AEAD mode over the hash
    "hske-duplex3":     (None, None),   # its NL-FSCX v3 variant
    "hske-nla3":        (None, None),   # v3 variant of hske-nla2
    "hpke-nl3":         (None, None),   # v3 variant of hpke-nl
    "fpe":              (None, None),   # format-preserving helper, no protocol role
    "fpe-v3":           (None, None),
    "twk":              (None, None),   # tweakable wide-block helper
    "twk-v3":           (None, None),
    "hdrbg":            (None, None),   # DRBG utility subcommand
    "oprf":             (None, None),   # building block under apake
    "apake":            (None, None),   # built on oprf; demo-only, SECURITY.md row
    "hcred":            (None, "HCRED"),        # ZKP credentials; INTRODUCTION §ZKP
    "nl-zkboo":         (None, "ZKBoo"),        # ditto
    "nl-zkbpp":         (None, None),           # ZKB++ refinement of nl-zkboo
    "rnl-sigma":        (None, None),           # Sigma-protocol over HKEX-RNL
    "hpks-zkp-nl":      (None, None),           # ZKP-backed signature variant
    "hpks-ring":        (None, None),           # ring-signature variant of hpks-stern
    "hpks-t":           (None, None),           # threshold variant
    "hpks-wots":        (None, None),           # hash-based, stateful
    "hpks-xmss":        (None, None),           # hash-based, stateful
    "hybrid-rnl-stern": (None, None),           # hkex-rnl + hpke-stern-kem
}

# Protocol-shaped names the front doors may use that are not live spec ids.
HISTORICAL_NAMES = {
    "HKEX-RNL-128":  "withdrawn n=512 parameter set; never a shipped --algo tag",
    "HFSCX-256-DM":  "pre-2.0.0 name of the hash; see MIGRATING.md §2",
    "HKEX-CY":       "rejected FSCX-CY construction (SecurityProofsCode/hkex_cy_test.py)",
}

# Internal construction names: real, shipped, and deliberately not spec/ protocols,
# because they carry no --algo tag of their own.  Both of these are reached through
# a protocol that IS filed -- the .hkx file format and `enc --aead`, both under
# hske-nla1 -- so filing them again would double-count the same CLI surface.
CONSTRUCTION_NAMES = {
    "HFSCX-256-MAC":   "keyed-IV mode of the hash (SecurityProofs-6.md §11.9)",
    "HSKE-NL-A1-CTR":  "the .hkx streaming file format's construction; --algo hske-nla1",
    "HSKE-NL-AEAD":    "the `enc --aead` construction; --algo hske-nla1",
}

_PROTO_TOKEN = re.compile(r"\b(?:HKEX|HSKE|HPKS|HPKE|HFSCX)(?:-[A-Za-z0-9]+)+\b")


def check_protocol_coverage(spec):
    ids = {p["id"] for p in spec["protocols"]}

    missing = ids - set(DOC_COVERAGE)
    for pid in sorted(missing):
        fail("C", "spec/ has protocol %r with no DOC_COVERAGE entry. Add one: "
                  "either the token README/INTRODUCTION must use for it, or "
                  "(None, None) with a reason it is below intro level." % pid)
    for pid in sorted(set(DOC_COVERAGE) - ids):
        fail("C", "DOC_COVERAGE names %r, which no longer exists in spec/. "
                  "Remove the entry, or the protocol came back under a new id." % pid)

    texts = {README: read(README), INTRO: read(INTRO)}
    for pid in sorted(ids & set(DOC_COVERAGE)):
        for doc, token in zip((README, INTRO), DOC_COVERAGE[pid]):
            if token is None:
                continue
            if token not in texts[doc]:
                fail("C", "%s does not mention %r for protocol %r, but "
                          "DOC_COVERAGE says it must."
                          % (os.path.relpath(doc, REPO), token, pid))

    # Reverse direction: no front door may describe something that is gone.
    live = {t for pair in DOC_COVERAGE.values() for t in pair if t}
    live |= {p["name"].split(" (")[0] for p in spec["protocols"]}
    for doc, text in texts.items():
        for token in sorted(set(_PROTO_TOKEN.findall(text))):
            if token in live or token in HISTORICAL_NAMES:
                continue
            if token in CONSTRUCTION_NAMES:
                continue
            # A strict prefix of a live name is a family or section reference --
            # "HSKE-NL", "§HPKS-Stern" -- not a protocol claim.  A protocol that
            # really was removed is a prefix of nothing, so this stays sharp.
            if any(n.startswith(token + "-") for n in live):
                continue
            fail("C", "%s names %r, which is neither a live spec/ protocol nor "
                      "a known historical name. Either it was removed and the "
                      "prose is stale, or add it to HISTORICAL_NAMES with the "
                      "reason." % (os.path.relpath(doc, REPO), token))


# ══ D. Claims ══════════════════════════════════════════════════════════════
#
# REQUIRED: a corrected statement that must stay present, so the fix cannot be
# reverted silently.  FORBIDDEN: a superseded statement that must not come back.
# Both are keyed on TODO #265's findings and on the items that invalidated them.

REQUIRED_CLAIMS = [
    (README, r"rounds \$= 32\$ \(demo default; production needs 219",
     "#265/1: README must not call the demo round count a production default; "
     "herradura.h warns below SDF_PRODUCTION_ROUNDS = 219"),
    (INTRO, r"\(2/3\)\^32",
     "#265/2: Stern's per-round soundness error is 2/3, not 1/3"),
    (INTRO, r"`--algo hpke-stern-kem`",
     "#265/3: INTRODUCTION must record that the BGF QC-MDPC decoder ships"),
    (README, r"every `\[FAIL\]` fails the build",
     "#265/5: TODO #233 (v3.0.8) made any [FAIL] blocking, with no allow-list"),
]

FORBIDDEN_CLAIMS = [
    (README, r"production default",
     "#265/1: 32 Fiat-Shamir rounds is the DEMO default (SDF_ROUNDS); "
     "production is SDF_PRODUCTION_ROUNDS = 219"),
    (INTRO, r"\(1/3\)\^",
     "#265/2: Stern catches a cheating prover with probability 2/3 per round, "
     "so the forgery bound is (2/3)^R -- as this file says itself, 40 lines on"),
    (INTRO, r"no decoder implemented",
     "#265/3: the BGF QC-MDPC decoder has shipped since v1.9.x as "
     "`--algo hpke-stern-kem`"),
    (README, r"Two security tests are FAIL-by-design",
     "#265/5: TODO #233 (v3.0.8) fixed tests [4] and [18] and made any [FAIL] "
     "fail the build. There is no allow-list; nothing is expected to fail."),
    (README, r"[Dd]on't treat either as a build gate",
     "#265/5: [FAIL] IS a build gate since v3.0.8 (TODO #233)"),
]


def check_claims():
    for doc, pattern, why in REQUIRED_CLAIMS:
        if not re.search(pattern, read(doc)):
            fail("D", "ANCHOR LOST -- %s no longer matches /%s/. %s"
                      % (os.path.relpath(doc, REPO), pattern, why))
    for doc, pattern, why in FORBIDDEN_CLAIMS:
        m = re.search(pattern, read(doc))
        if m:
            rel = os.path.relpath(doc, REPO)
            line = read(doc)[:m.start()].count("\n") + 1
            fail("D", "%s:%d resurrects a superseded claim (%r). %s"
                      % (rel, line, m.group(0), why))


# ══ main ═══════════════════════════════════════════════════════════════════

def main():
    spec = json.load(open(SPEC_PATH, encoding="utf-8"))
    consts = header_constants()

    print("Cross-document consistency audit (TODO #265)")
    print("  authorities: herradura.h, spec/herradura-protocol-spec.json")
    print("  documents:   README.md, docs/INTRODUCTION.md, CHANGELOG.md, "
          "MIGRATING.md, pyproject.toml")
    print("  read %d integer constants from herradura.h" % len(consts))

    check_versions()
    check_parameters(consts)
    check_protocol_coverage(spec)
    check_claims()

    labels = {
        "A": "versions (README / CHANGELOG / pyproject / MIGRATING)",
        "B": "parameters (herradura.h vs. spec/ vs. prose)",
        "C": "protocol coverage (spec/ vs. README / INTRODUCTION)",
        "D": "claims (corrected statements kept, superseded ones gone)",
    }
    for key in "ABCD":
        hits = [m for k, m in FAILURES if k == key]
        print("\n%s. %s" % (key, labels[key]))
        if not hits:
            print("   OK")
        for msg in hits:
            print("   FAIL: %s" % msg)

    if FAILURES:
        print("\n*** FAILED: %d inconsistency(ies) ***" % len(FAILURES))
        return 1
    print("\n*** OK: documents agree with each other and with the sources ***")
    return 0


if __name__ == "__main__":
    sys.exit(main())
