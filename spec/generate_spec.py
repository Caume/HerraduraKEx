#!/usr/bin/env python3
"""Generates spec/herradura-protocol-spec.json from the suite's own source files
(TODO #133), so the machine-readable spec cannot silently drift from what the
CLIs actually implement.

Mechanically extracted (regex, not hand-copied) from source:
  - Algo tag -> PEM private/public key label mapping: HerraduraCli/herradura.py's
    `_PRIV_ALGOS` dict (the single most complete, most explicit definition across
    the four CLI implementations -- it covers every genpkey-producible algo).
  - Every wire-format PEM_* label: HerraduraCli/herradura_codec.h.
  - Per-subcommand --algo choices: HerraduraCli/herradura.py's argparse
    `choices=[...]` lists (enc/dec/sign/verify/kex/encfile/decfile/dgst).
  - Protocol parameter constants: herradura.h (#define), grepped by name.  ONLY
    herradura.h: this said "and herradura/herradura.go (const block)" until TODO
    #278, and it was not true -- build_parameters() read the Go source into a
    variable it never used, so every number here has always come from C alone,
    and the docstring asserted a cross-language check that did not happen.  The
    dead read is gone.  Comparing a parameter's VALUE across the four languages
    is now spec/check_language_parity.py's PARAMETERS table, which does it for
    all four rather than two, and is exhaustive in both directions.

Curated (cannot be mechanically derived, since it requires judgment about what
"production" vs "demo-only" means): the security-classification table and the
cross-implementation support matrix below. Running this script in --check mode
verifies every algo tag referenced in the curated tables still exists in the
mechanically extracted enumeration -- if a tag is renamed or removed in source,
--check fails loudly instead of silently going stale. It does NOT catch a
*newly added* algo tag missing curated data (no source signal for "this is new"
without a snapshot to diff against) -- that gap is closed by CONTRIBUTING-style
review discipline, not tooling; see spec/README.md.

Usage:
    python3 spec/generate_spec.py                # regenerate spec/herradura-protocol-spec.json
    python3 spec/generate_spec.py --check         # exit 1 if regenerating would change the file
"""
import argparse
import json
import os
import re
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HERRADURA_PY = os.path.join(REPO, "HerraduraCli", "herradura.py")
CODEC_H = os.path.join(REPO, "HerraduraCli", "herradura_codec.h")
HERRADURA_H = os.path.join(REPO, "herradura.h")
CLI_C = os.path.join(REPO, "HerraduraCli", "herradura_cli.c")
CLI_GO = os.path.join(REPO, "HerraduraCli", "herradura_cli.go")
# TODO #261: the fourth CLI.  bindings/java/ carries a complete port of the suite
# AND a herradurakex.HerraduraCli mirroring the Python CLI's subcommands and
# --algo values, but cli_support was a three-column table until v5.8.7, so
# Java's coverage -- and its five gaps -- were invisible to spec/ by construction.
CLI_JAVA = os.path.join(REPO, "bindings", "java", "herradurakex", "HerraduraCli.java")
OUT_PATH = os.path.join(REPO, "spec", "herradura-protocol-spec.json")
# TODO #274: the generated unknown-flag allow-lists.  C and Java scan argv for the
# flags they want and ignored everything else, so `enc --aead` on Java exited 0 and
# wrote an UNAUTHENTICATED ciphertext.  Both now validate against a table -- and the
# table is GENERATED from the same extractors that build `cli_flag_matrix`, so it is
# definitionally "the flags this parser actually reads".  A hand-written allow-list
# is precisely the thing that drifts, which is the failure #274 exists to close;
# --check re-emits and diffs, so adding a get_arg()/opt.get() call without
# regenerating fails rather than silently rejecting the new flag at runtime.
C_FLAG_TABLE = os.path.join(REPO, "HerraduraCli", "cli_flag_table.h")
JAVA_FLAG_TABLE = os.path.join(REPO, "bindings", "java", "herradurakex", "CliFlagTable.java")
SCHEMA_PATH = os.path.join(REPO, "spec", "herradura-protocol-spec.schema.json")
# TODO #366: the key-label acceptance table, emitted into each CLI.
C_KEY_TABLE = os.path.join(REPO, "HerraduraCli", "key_label_table.h")
JAVA_KEY_TABLE = os.path.join(REPO, "bindings", "java", "herradurakex", "KeyLabelTable.java")

SPEC_VERSION = "1.0.0"


def read(path):
    with open(path, "r") as f:
        return f.read()


# ── Mechanical extraction ─────────────────────────────────────────────────

def extract_priv_algos(py_src):
    """Parse the `_PRIV_ALGOS = {...}` dict literal: algo tag -> PRIVATE KEY label."""
    m = re.search(r"_PRIV_ALGOS\s*=\s*\{(.*?)\n\}", py_src, re.DOTALL)
    if not m:
        raise RuntimeError("could not find _PRIV_ALGOS dict in herradura.py")
    body = m.group(1)
    pairs = re.findall(r"'([a-z0-9\-]+)'\s*:\s*'([^']+)'", body)
    if not pairs:
        raise RuntimeError("_PRIV_ALGOS dict matched but no key/value pairs parsed")
    return dict(pairs)


def extract_pem_labels(codec_h_src):
    """Parse every `#define PEM_* "..."` constant."""
    pairs = re.findall(r'#define\s+(PEM_[A-Z0-9_]+)\s+"([^"]+)"', codec_h_src)
    if not pairs:
        raise RuntimeError("no PEM_* constants found in herradura_codec.h")
    return dict(pairs)


def extract_subcommands(py_src):
    """Every `sub.add_parser('name', ...)` the Python CLI defines, in order."""
    names = re.findall(r"sub\.add_parser\('([a-z0-9\-]+)'", py_src)
    if not names:
        raise RuntimeError("no sub.add_parser() calls found in herradura.py")
    return names


def extract_choices(py_src, subcommand_var, flag="--algo"):
    """Parse a `<var>.add_argument('--algo', ..., choices=[...])` call's choices list
    for a given argparse subparser variable name (e.g. 'en' for enc, 'de' for dec)."""
    pattern = (
        re.escape(subcommand_var) + r"\.add_argument\('" + re.escape(flag) + r"'.*?choices=\[(.*?)\]"
    )
    m = re.search(pattern, py_src, re.DOTALL)
    if not m:
        return None
    return re.findall(r"'([a-z0-9\-]+)'", m.group(1))


def _strip_c_comments(src):
    """Remove /* ... */ and // ... so a tag named only in a comment is not read as
    dispatch evidence."""
    src = re.sub(r"/\*.*?\*/", " ", src, flags=re.DOTALL)
    return re.sub(r"//[^\n]*", " ", src)


def extract_cli_tags(src, universe):
    """Algo tags a C, Go or Java CLI actually dispatches on.

    All three reach a tag through a quoted string literal -- `strcmp(algo, "hpks")`
    in C, a `case "hpks"` or an `algo -> PEM label` map entry in Go,
    `algo.equals("hpks")` or a `case "hpks"` in Java -- so the rule is: every
    string literal in the source, intersected with the tag universe the Python CLI
    defines.  Comments are stripped first (Java's `//` form is C's, so the same
    stripper serves).

    This replaces a hand-maintained CLI_SUPPORT table (TODO #238).  That table had
    gone stale in two places without anything noticing: it said `hpks-xmss` was
    Python-only when all three CLIs have shipped it since TODO #208, and that
    `hcred` was missing from Go when the Go CLI dispatches cred-issue/-prove/
    -verify.  A curated boolean per (tag, language) is exactly the kind of claim
    that cannot be verified by reading this file, which is why it is now derived.
    """
    literals = set(re.findall(r'"([a-z0-9\-]+)"', _strip_c_comments(src)))
    return literals & set(universe)


# ── CLI FLAG surface, per subcommand, per language (TODO #267) ────────────
#
# `cli_support` above answers "does this CLI dispatch this --algo tag", and
# TODO #261 declared that half of the CLI surface met.  It is narrower than
# "the CLI surface": a subcommand's FLAGS are capability too.  Nothing compared
# them, so `genpkey --passphrase` has been Python-only since TODO #166 (v1.9.134)
# -- recorded in that item's own text and then invisible to every check -- and
# eight further asymmetries had never been recorded anywhere at all.
#
# Same rule as extract_cli_tags: derive from each CLI's OWN argument parser, so
# a regression shows up as a changed cell rather than as silence.  The four
# parsers are four different shapes, so there are four extractors, but they
# share the same two-step: map subcommand -> handler, then collect the flag
# literals that handler (and anything it delegates to) reads.
#
# Each extractor raises when it maps no subcommands.  A regex that silently
# stopped matching would otherwise report the whole surface missing from one
# language, which is a loud failure -- but it would be the WRONG failure, and
# the message needs to say "the extractor broke", not "port 26 subcommands".


def _decl_bodies(src, decl_re, name_group=1):
    """Slice `src` at every top-level declaration matching `decl_re`, returning
    {name: body}.  Bodies run to the NEXT declaration, not to the next match of
    some narrower pattern -- slicing on `cmd*` alone gives the last command
    handler a body that swallows the rest of the file, and every flag in it."""
    decls = [(m.start(), m.group(name_group))
             for m in re.finditer(decl_re, src, re.MULTILINE)]
    bodies = {}
    for i, (pos, name) in enumerate(decls):
        end = decls[i + 1][0] if i + 1 < len(decls) else len(src)
        bodies[name] = src[pos:end]
    return bodies


def _resolve_flags(bodies, fn, flag_patterns, call_re, seen=None):
    """Flags read by `fn`, plus those read by any handler it delegates to.

    The delegation step is not decoration: C reaches `threshold-verify`'s flags
    only through `cmd_verify`, and Go's `cmdKex` splits into `cmdKexRnl` /
    `cmdKexHybrid`.  Without it those flags read as absent from the language
    that has them.

    `call_re` matches any callee handed the subcommand's own argument container
    -- `(argc, argv)`, `(args)`, `(opt, ...)` -- not only the `cmd*` handlers.
    Restricting it to `cmd*` was wrong and TODO #269 proved it: factoring three
    duplicated `--in` reads in the Java CLI into one `readMessage(opt, cmd)`
    helper made `sign --in` read as ABSENT FROM JAVA, because the helper is not
    a command handler.  A function given the parsed options is part of that
    subcommand's flag surface however it is named."""
    seen = set() if seen is None else seen
    if fn in seen or fn not in bodies:
        return set()
    seen.add(fn)
    body = bodies[fn]
    flags = set()
    for pattern in flag_patterns:
        # finditer + every non-empty group: an accessor may name TWO flags in one
        # call, as C's get_arg_multi2 / Go's multiValueFlags / Java's multiPaths do
        # for the plural and singular spelling of a list flag (TODO #270).
        for m in re.finditer(pattern, body):
            flags.update("--" + g for g in m.groups() if g)
    # finditer, not findall: `call_re` may carry alternatives, and findall on a
    # multi-group pattern yields tuples with empty slots rather than names.
    callees = {g for m in re.finditer(call_re, body) for g in m.groups() if g}
    for callee in callees:
        if callee != fn:
            flags |= _resolve_flags(bodies, callee, flag_patterns, call_re, seen)
    return flags


def extract_flags_python(py_src):
    """argparse: `xx = sub.add_parser('name')` then `xx.add_argument('--flag')`.

    Mutually-exclusive groups (`fp_mode = fp.add_mutually_exclusive_group()`)
    are followed, or `fpe`/`twk` would lose --encrypt/--decrypt."""
    flags, var_sub = {}, {}
    for line in py_src.splitlines():
        m = re.match(r"\s*(\w+)\s*=\s*sub\.add_parser\('([a-z0-9\-]+)'", line)
        if m:
            var_sub[m.group(1)] = m.group(2)
            flags.setdefault(m.group(2), set())
            continue
        m = re.match(r"\s*(\w+)\s*=\s*(\w+)\.add_mutually_exclusive_group", line)
        if m and m.group(2) in var_sub:
            var_sub[m.group(1)] = var_sub[m.group(2)]
            continue
        m = re.match(r"\s*(\w+)\.add_argument\('(--[a-z0-9\-]+)'", line)
        if m and m.group(1) in var_sub:
            flags[var_sub[m.group(1)]].add(m.group(2))
    if not flags:
        raise RuntimeError("extract_flags_python matched no sub.add_parser() calls "
                           "in herradura.py -- the extractor is stale, not the CLI.")
    return flags


def extract_flags_c(c_src):
    """C: `if (strcmp(cmd, "kex") == 0) { cmd_kex(argc, argv); ... }`, then
    get_arg/has_flag/get_arg_multi(argc, argv, "--flag") inside the handler."""
    src = _strip_c_comments(c_src)
    dispatch = dict(re.findall(
        r'strcmp\(cmd,\s*"([a-z0-9\-]+)"\)\s*==\s*0\)\s*\{\s*(cmd_[a-z_0-9]+)\(', src))
    if not dispatch:
        raise RuntimeError("extract_flags_c mapped no subcommands in herradura_cli.c "
                           "-- the extractor is stale, not the CLI.")
    bodies = _decl_bodies(src, r'^static\s+[A-Za-z_][\w \t\*]*\b(\w+)\s*\(')
    pat = [r'(?:get_arg|has_flag|get_arg_multi|rounds_arg|num_arg)\s*\(\s*argc\s*,\s*argv\s*,\s*"--([a-z0-9\-]+)"',
           # get_arg_multi2(argc, argv, "<cmd>", "--plural", "--singular", ...) — TODO #270
           r'get_arg_multi2\s*\(\s*argc\s*,\s*argv\s*,\s*"[a-z0-9\-]+"\s*,'
           r'\s*"--([a-z0-9\-]+)"\s*,\s*"--([a-z0-9\-]+)"']
    return {sub: _resolve_flags(bodies, fn, pat, r'\b(\w+)\s*\(\s*argc\b')
            for sub, fn in dispatch.items()}


def extract_valued_flags_c(c_src):
    """C's VALUE-taking flags, i.e. everything except the boolean `has_flag` ones.

    TODO #274 needs the arity, not just the name: when check_unknown_flags meets a
    token starting with "--" that is not a known flag, it has to decide whether it
    is a typo or the VALUE of the flag before it (Python and Go both accept a
    flag-shaped value such as a file literally named "--weird.pem", so C must too).
    Skipping after ANY known flag would let `enc --aead --typo` through, because
    --aead is boolean and consumes nothing."""
    src = _strip_c_comments(c_src)
    dispatch = dict(re.findall(
        r'strcmp\(cmd,\s*"([a-z0-9\-]+)"\)\s*==\s*0\)\s*\{\s*(cmd_[a-z_0-9]+)\(', src))
    if not dispatch:
        raise RuntimeError("extract_valued_flags_c mapped no subcommands in "
                           "herradura_cli.c -- the extractor is stale, not the CLI.")
    bodies = _decl_bodies(src, r'^static\s+[A-Za-z_][\w \t\*]*\b(\w+)\s*\(')
    pat = [r'(?:get_arg|get_arg_multi|rounds_arg|num_arg)\s*\(\s*argc\s*,\s*argv\s*,\s*"--([a-z0-9\-]+)"',
           r'get_arg_multi2\s*\(\s*argc\s*,\s*argv\s*,\s*"[a-z0-9\-]+"\s*,'
           r'\s*"--([a-z0-9\-]+)"\s*,\s*"--([a-z0-9\-]+)"']
    return {sub: _resolve_flags(bodies, fn, pat, r'\b(\w+)\s*\(\s*argc\b')
            for sub, fn in dispatch.items()}


def extract_flags_go(go_src):
    """Go: `case "kex":` -> `cmdKex(rest)`, then a flag.FlagSet inside.
    `fs.<Anything>("name", ...)` covers String/Bool/Int/Uint/Uint64 without
    enumerating them -- fs.Parse/fs.Visit take no string literal first, so they
    cannot match.  Repeatable flags go through stringFlags(args, "--commit")."""
    src = _strip_c_comments(go_src)
    dispatch = dict(re.findall(r'case\s+"([a-z0-9\-]+)":\s*\n\s*(cmd[A-Za-z0-9]+)\(', src))
    if not dispatch:
        raise RuntimeError("extract_flags_go mapped no subcommands in herradura_cli.go "
                           "-- the extractor is stale, not the CLI.")
    bodies = _decl_bodies(src, r'^func\s+(\w+)\s*\(')
    pat = [r'\bfs\.\w+\(\s*"([a-z0-9\-]+)"',
           r'stringFlags\(\s*\w+\s*,\s*"--([a-z0-9\-]+)"',
           # multiValueFlags(args, "<cmd>", "--plural", "--singular") — TODO #270
           r'multiValueFlags\(\s*\w+\s*,\s*"[a-z0-9\-]+"\s*,'
           r'\s*"--([a-z0-9\-]+)"\s*,\s*"--([a-z0-9\-]+)"',
           # filterMultiFlags strips the same names before flag.Parse; naming them
           # there too keeps the two lists from silently drifting apart.
           r'filterMultiFlags\(\s*\w+\s*,\s*"--([a-z0-9\-]+)"\s*,\s*"--([a-z0-9\-]+)"']
    return {sub: _resolve_flags(bodies, fn, pat, r'\b(\w+)\(\s*args\b|\b(cmd[A-Za-z0-9]+)\(')
            for sub, fn in dispatch.items()}


def extract_flags_java(java_src):
    """Java: `case "kex": cmdKex(opt);` where opt is the parsed Map, read via
    opt.get/getOrDefault/containsKey("name") or req(opt, "name", "kex")."""
    src = _strip_c_comments(java_src)
    dispatch = dict(re.findall(r'case\s+"([a-z0-9\-]+)":\s*(cmd[A-Za-z0-9]+)\(', src))
    if not dispatch:
        raise RuntimeError("extract_flags_java mapped no subcommands in "
                           "HerraduraCli.java -- the extractor is stale, not the CLI.")
    bodies = _decl_bodies(
        src, r'^    (?:private|public|protected)\s+static\s+[\w<>,\[\] ]+?\s(\w+)\s*\(')
    pat = [r'\bopt\.(?:get|getOrDefault|containsKey)\(\s*"([a-z0-9\-]+)"',
           r'\breq\(\s*opt\s*,\s*"([a-z0-9\-]+)"',
           # numArg(opt, "name", ...) -- TODO #380's numeric parser (bare name, as above)
           r'\bnumArg\(\s*opt\s*,\s*"([a-z0-9\-]+)"',
           # multiPaths(opt, "<cmd>", "plural", "singular") — TODO #270.  No "--"
           # here: Java's option map is keyed without the dashes.
           r'multiPaths\(\s*opt\s*,\s*"[a-z0-9\-]+"\s*,'
           r'\s*"([a-z0-9\-]+)"\s*,\s*"([a-z0-9\-]+)"']
    return {sub: _resolve_flags(bodies, fn, pat, r'\b(\w+)\(\s*opt\b')
            for sub, fn in dispatch.items()}


def extract_bool_flags_java(java_src, c_src):
    """Java's BOOLEAN flags: names its handlers only ever test with
    opt.containsKey, never read as a value (TODO #381).

    parseOpts needs the arity: a boolean consumes no token, so `genpkey --algo
    hpks extra` has a stray 'extra' and `--pubout=x` is refused, while a
    value-taking flag at the end of argv is missing its value (Java stored it
    as the string "true" and wrote a file of that name).  The set is checked
    against C's (every flag C reads with has_flag rather than get_arg): the
    arity of a flag is part of the shared CLI surface, so a flag boolean in one
    CLI and valued in another is refused here rather than emitted."""
    js = _strip_c_comments(java_src)
    tested = set(re.findall(r'\bopt\.containsKey\(\s*"([a-z0-9\-]+)"', js))
    valued = set()
    for pat in (r'\bopt\.(?:get|getOrDefault)\(\s*"([a-z0-9\-]+)"',
                r'\breq\(\s*opt\s*,\s*"([a-z0-9\-]+)"',
                r'\bnumArg\(\s*opt\s*,\s*"([a-z0-9\-]+)"'):
        valued |= set(re.findall(pat, js))
    java_bool = tested - valued
    flags_c, valued_c = extract_flags_c(c_src), extract_valued_flags_c(c_src)
    c_bool = set()
    for sub in flags_c:
        c_bool |= {f.lstrip("-") for f in set(flags_c[sub]) - set(valued_c.get(sub, []))}
    if java_bool != c_bool:
        raise RuntimeError("boolean flags differ between the Java and C CLIs: "
                           "Java-only %s, C-only %s (TODO #381: a flag's arity is "
                           "shared surface)" % (sorted(java_bool - c_bool),
                                                sorted(c_bool - java_bool)))
    return java_bool


def extract_const_int(src, name):
    """Grep a `#define NAME <expr>  /* comment */` (C) or `Name = <expr>  // comment`
    (Go) constant, stripping trailing line comments before capturing the expression.
    Returns an int when the expression is a bare (optionally parenthesized) integer
    literal, else the raw expression string (e.g. "KEYBITS / 2")."""
    val = None
    m = re.search(r"#define\s+" + re.escape(name) + r"[ \t]+(.+)$", src, re.MULTILINE)
    if m:
        val = m.group(1)
    else:
        m = re.search(re.escape(name) + r"\s*=\s*(.+)$", src, re.MULTILINE)
        if m:
            val = m.group(1)
    if val is None:
        return None
    val = re.sub(r"/\*.*?\*/", "", val)  # strip /* ... */ comments
    # ...and an UNTERMINATED `/*`, which opens a comment continuing onto the next
    # source line.  The rule above is single-line and non-greedy, so it does not
    # match one, and the comment text used to leak into the value: SDF_ROUNDS's
    # four-line explanatory comment made spec/ report rounds_demo as the string
    # "32             /* ZKP rounds (demo; prod >= 219);" (TODO #265).
    val = re.sub(r"/\*.*$", "", val)
    val = re.sub(r"//.*$", "", val)      # strip // comments
    val = val.strip().strip(",")
    if val.startswith("(") and val.endswith(")"):
        val = val[1:-1].strip()
    return int(val) if re.fullmatch(r"-?\d+", val) else val


# ── Curated data ──────────────────────────────────────────────────────────
# Every algo tag referenced here is validated against the mechanically
# extracted PRIV_ALGOS/PEM_LABELS/CHOICES sets in main() -- a stale or
# misspelled tag fails --check.

SECURITY = {
    "hkex-gf":   dict(status="pedagogical", quantum_resistant=False, classical_security_bits="~36.5 (n=256)",
                       notes="GF(2^n)* Diffie-Hellman. The binding classical attack is Pohlig-Hellman: the "
                             "group order 2^256-1 has a 73-bit largest prime factor, so a discrete log costs "
                             "about 2^36.5 group operations in constant memory (TODO #212, SecurityProofs-3.md "
                             "9.2.4) -- days on a single core, not the ~80-90 bits the function field sieve "
                             "would suggest. NIST SP 800-57 Rev.5 (2020) and ENISA (2022) also deprecate "
                             "GF(2^n)* groups for new designs; not suitable for production use at any deployed n.",
                       source=["TODO.md #127 (6943-6949)", "TODO_DONE.md #212"]),
    "hpks":      dict(status="pedagogical", quantum_resistant=False, classical_security_bits="~36.5 (n=256)",
                       notes="Schnorr signature over GF(2^n)*; same group-choice caveat as hkex-gf, and the "
                             "same ~2^36.5 Pohlig-Hellman key recovery, which yields arbitrary forgery. "
                             "The challenge omits the public key, so about half of all signatures (those "
                             "with gcd(e, 2^n - 1) > 1) also verify under a publicly computable second key "
                             "C*z with z^e = 1: key substitution, not forgery; accepted (TODO #415).",
                       source=["TODO.md #127", "TODO_DONE.md #212", "TODO.md #415"]),
    "hpke":      dict(status="pedagogical", quantum_resistant=False, classical_security_bits="~36.5 (n=256)",
                       notes="El Gamal encryption over GF(2^n)*; same group-choice caveat as hkex-gf, and the "
                             "same ~2^36.5 Pohlig-Hellman recovery of the decryption key. Independently, the "
                             "FSCX encryption layer leaks 126 of 256 linear functionals of the plaintext from "
                             "the ciphertext alone (TODO #210, SecurityProofs-1.md 1.3.1).",
                       source=["TODO.md #127", "TODO_DONE.md #210", "TODO_DONE.md #212"]),
    "hpks-nl":   dict(status="pedagogical", quantum_resistant=False,
                       classical_security_bits="~36.5 (n=256)",
                       notes="NL-FSCX-hardened Schnorr over the same GF(2^n)* group as hpks, so the same "
                             "~2^36.5 Pohlig-Hellman key recovery applies unchanged -- the NL-FSCX "
                             "challenge hardens the hash, not the group. NOT quantum-resistant despite the "
                             "'NL' naming suggesting a PQC upgrade; that claim is withdrawn and no "
                             "lattice-based replacement is planned. This row said `deprecated` until TODO "
                             "#238, which conflated the withdrawn PQC *claim* with the algo being "
                             "superseded: it is neither superseded nor removed -- it still ships in all "
                             "four implementations and is covered by the cross-language matrix. "
                             "`pedagogical` is what SECURITY.md has always said, and matches hpks. "
                             "Since v12.0.0 (TODO #348) the challenge is HFSCX-256-DS(0x30, R || msg) "
                             "truncated to n bits, not nl_fscx_revolve_v1(R, msg, n/4), which put the "
                             "signer's msg in v1's B. That challenge omits the public key, so hpks's "
                             "key substitution applies (about half of all signatures also verify under "
                             "a publicly computable second key); accepted (TODO #415).",
                       source=["SECURITY.md", "TODO_DONE.md #212", "SecurityProofs-4.md 11.7",
                               "TODO_DONE.md #348", "TODO.md #415"]),
    "hpke-nl":   dict(status="pedagogical", quantum_resistant=False,
                       classical_security_bits="~36.5 (n=256)",
                       notes="NL-FSCX-hardened El Gamal over the same GF(2^n)* group as hpke, with the same "
                             "~2^36.5 Pohlig-Hellman recovery of the decryption key. Same `deprecated` -> "
                             "`pedagogical` correction as hpks-nl (TODO #238).",
                       source=["SECURITY.md", "TODO_DONE.md #212", "SecurityProofs-4.md 11.7"]),
    "hkex-rnl":  dict(status="production", quantum_resistant="conjectured",
                       classical_security_bits="~206 Core-SVP at n=1024/p=4096 (~187 quantum); "
                                                 "the pre-v2.7.19 n=256 ring was worth only ~32/~29",
                       notes="Ring-LWR key exchange at ring dimension 1024 (TODO #223). Keys generated "
                             "before v2.7.19 used n=256 and are insecure — regenerate them, see "
                             "MIGRATING.md section 4. The ring dimension is separate from the derived "
                             "session key width, which stays 256 bits. Protocol caveats unrelated to the "
                             "parameters still apply: the reconciliation hint is unauthenticated, and "
                             "m_blind's uniformity rests on the initiator's RNG (TODO #89).",
                       source=["SECURITY.md", "SecurityProofs-4.md 11.4.3", "TODO #216", "TODO #223"]),
    "rnl-sigma": dict(status="production", quantum_resistant="conjectured",
                       notes="Sigma-protocol proof of knowledge of an HKEX-RNL private key. At the "
                             "pre-v2.7.19 n=256 ring the witness was recoverable in ~2^32 work, so a "
                             "proof evidenced nothing; TODO #223 moved the ring to 1024 and restored "
                             "that property. Proofs about pre-v2.7.19 keys remain meaningless.",
                       source=["CLAUDE.md", "SecurityProofs-7.md"]),
    "hpks-stern": dict(status="demo-only", quantum_resistant="conjectured",
                        classical_security_bits="~56-60 at shipped SDF_ROUNDS=32 (production requires "
                                                  "SDF_PRODUCTION_ROUNDS=219 for 128-bit soundness)",
                        notes="Fiat-Shamir signature from the Stern identification protocol (syndrome decoding). "
                              "Shipped SDF_ROUNDS=32 is a demo parameter; herradura.h emits a #pragma message "
                              "warning at compile time when SDF_ROUNDS < SDF_PRODUCTION_ROUNDS. The round "
                              "count is a per-signature wire field (item[1] of the DER SEQUENCE), not a "
                              "compile-time constant: all four CLIs accept `sign --rounds` and "
                              "any reader accepts any count in [1, SDF_MAX_ROUNDS] regardless of its own "
                              "SDF_ROUNDS, which is only the signing default (TODO #236). Before that the C "
                              "reader rejected any count != SDF_ROUNDS, so two C builds were mutually "
                              "unreadable and cross-language HCRED interop ran only at 32 rounds. Round "
                              "count and instance hardness are independent axes -- 219 rounds over the "
                              "deployed N=256 is still ~24-38 bits and still demo-only.  The 128-bit "
                              "instance is the long form, N=2304 (genpkey --level 128, TODO #382; "
                              "SPEC.md 11.1): 256-bit commitments, ~2^137 classical by BJMM.",
                        source=["herradura.h:1383-1392", "herradura/herradura.go:1108-1110",
                                "TODO.md #236"]),
    "hybrid-rnl-stern": dict(status="demo-only", quantum_resistant="conjectured",
                        classical_security_bits="~206 Core-SVP on the Ring-LWR half at n=1024; the "
                                                  "QC-MDPC half is capped by its 2^-8.6 DFR, not by a "
                                                  "work factor",
                        notes="Hybrid key exchange combining HKEX-RNL with HPKE-Stern-KEM. Shipped as a "
                              "`kex --algo` value by C, Go and Python since TODO #167 and by Java since TODO #261, but it had no entry "
                              "in this spec at all until TODO #238 added the check that caught it: "
                              "build_protocols keyed off _PRIV_ALGOS | SECURITY and hybrid-rnl-stern is "
                              "in neither, being kex-only. It inherits the hpke-stern-kem row's "
                              "properties on its KEM half -- `kex --algo hybrid-rnl-stern` used to "
                              "report decapsulation failure with its own distinct message, the same "
                              "GJS oracle, and since TODO #235 it does not report at all: the "
                              "completion always succeeds and a KEM-half failure shows up as a session "
                              "key the peer disagrees with. The hybrid stays demo-only for the KEM "
                              "half's remaining reasons even though the Ring-LWR half is unaffected. "
                              "Keys generated before v2.7.19 carry the ~32-bit n=256 ring and must be "
                              "regenerated.",
                        source=["SECURITY.md (HYBRID-RNL-STERN note)", "TODO_DONE.md #167",
                                "SecurityProofs-5.md 11.8.7"]),
    "hpke-stern": dict(status="demo-only", quantum_resistant="conjectured",
                        notes="Niederreiter KEM (Stern-based). Demo uses a known error vector e'. "
                              "NO CONFIDENTIALITY: the CLI ciphertext carried e', and K = hash(seed, e') "
                              "needs only the PUBLIC seed, so anyone holding the ciphertext and the "
                              "public key decrypted it (found by TODO #410). TODO #413 (v20.0.0) removed "
                              "enc/dec --algo hpke-stern from every CLI; hpke-stern-kem decodes with the "
                              "private key. The tag remains a genpkey key type, a Stern signing key "
                              "(the same error vector + seed as hpks-stern), and the suites keep the "
                              "library functions as a demonstration.",
                        source=["CLAUDE.md:228", "TODO.md #126 (6896-6924)", "TODO_DONE.md #413",
                                "MIGRATING.md section 55"]),
    "hpke-stern-kem": dict(status="demo-only", quantum_resistant="conjectured",
                        notes="Niederreiter/QC-MDPC KEM with a real Black-Gray-Flip (BGF) "
                              "syndrome decoder (qcmdpc_keygen/encap/decap_bgf) -- unlike "
                              "hpke-stern, decap does not need the plaintext error vector. "
                              "BIKE-128 parameters (r=12323, d=71, t=134), adopted "
                              "verbatim in TODO #276 together with BIKE's decoder -- its "
                              "syndrome-adaptive threshold rule (a FUNCTION of the syndrome "
                              "weight, not a constant in d) and NbIter=5. These replaced the "
                              "toy set r=523, d=15, t=18 that shipped through v6.7.3, whose "
                              "measured DFR was 0.264% per encapsulation (2^-8.6, n=120000, "
                              "TODO #218) against the 2^-128 IND-CCA2 needs, and whose "
                              "underlying QC syndrome-decoding instance was worth about "
                              "2^21 classical operations (TODO #276: Dumer with the "
                              "quasi-cyclic speedups, calibrated against BIKE's three "
                              "published levels; SecurityProofs-5.md 11.8.9) -- the binding "
                              "constraint, and below even the Stern-F signature at a quarter "
                              "the length, because ISD tracks the relative distance t/N. "
                              "Reclassified demo-only in TODO #218, which listed four "
                              "blockers; TODO #235 closed the two that were missing "
                              "constructions rather than parameter choices, and TODO #276 "
                              "closed the parameter one. Keygen screens weak keys "
                              "(distance-spectrum multiplicity capped at QCMDPC_MAX_MULT=6 "
                              "at these parameters -- a retry-budget choice stated in "
                              "advance rather than the measured cliff the old bound of 5 "
                              "was, though TODO #285 has since measured the cliff too and "
                              "puts it at multiplicity 31-32, leaving the bound "
                              "conservative by about 5x: what is unmeasurable at these "
                              "parameters is a DFR DIFFERENCE among ORDINARY keys, and a "
                              "weak key fails near 100% of the time), and decapsulation "
                              "applies a Fujisaki-Okamoto transform with implicit rejection: "
                              "it checks rigidity -- which at an invertible h0 reduces exactly "
                              "to wt(e)=t -- and returns HFSCX-256-DS(0x11, z || C) on any "
                              "failure instead of reporting one, so the GJS reaction attack "
                              "no longer has an oracle. STILL DEMO-ONLY, and the reason has "
                              "changed rather than gone: the DFR at these parameters is not "
                              "measurable here -- that is precisely what the change bought -- "
                              "so 2^-128 is INHERITED from BIKE's published analysis of "
                              "BIKE's decoder, and this is a reimplementation of that decoder "
                              "whose equivalence is checked by testing rather than proven, "
                              "over a suite-specific FSCX-based PRF rather than BIKE's. "
                              "Promotion is a separate decision from the parameter change and "
                              "is not made here. CliTest scripts that decapsulate still "
                              "source CliTest/lib_dfr.sh (TODO #221); at these parameters its "
                              "retries are expected never to fire, which is the desired end "
                              "state rather than evidence the policy is unneeded. "
                              "Two consequences for callers: a decoding failure is now "
                              "silent (it surfaces as a shared secret the peer disagrees "
                              "with, never an error), and the success-path session key "
                              "changed from HFSCX-256(e0||e1) to "
                              "HFSCX-256-DS(0x10, e0||e1||C), so pre-#235 builds do not "
                              "interoperate -- see MIGRATING.md. An imported private key is "
                              "still unscreened.",
                        source=["herradura.h QCMDPC_* / qcmdpc_decap_bgf",
                                "herradura/herradura.go QcMdpcDecapBgf",
                                "CliTest/test_stern_kem.sh",
                                "SecurityProofsCode/qcmdpc_bgf_failure_rate.py",
                                "SecurityProofsCode/qcmdpc_dfr_weak_keys.py",
                                "SecurityProofs-5.md 11.8.7"]),
    "hpks-zkp-nl": dict(status="demo-only", quantum_resistant="conjectured",
                        notes="Key-generation entry point for the ZKB[oo/++] proof-of-knowledge protocols. "
                              "It produces nothing but a keypair, so it has no soundness of its own -- its "
                              "status is whatever the proofs consuming it are worth, and both nl-zkboo and "
                              "nl-zkbpp ship at ZKP_NL_DEMO_ROUNDS=4 against the ZKP_NL_PROD_ROUNDS=219 "
                              "needed for 128-bit soundness. Aligned with them in TODO #238; `production` "
                              "for a keygen whose only consumers are demo-only was a classification with "
                              "nothing behind it.",
                        source=["herradura.h:2716-2721", "TODO #238"]),
    "nl-zkboo":  dict(status="demo-only", quantum_resistant="conjectured",
                       notes="ZKBoo MPC-in-the-head proof of NL-FSCX preimage knowledge. Shipped default rounds "
                             "is a demo parameter (ZKP_NL_DEMO_ROUNDS=4); production requires "
                             "ZKP_NL_PROD_ROUNDS=219 for (2/3)^R soundness at 128 bits.",
                       source=["herradura.h:2386-2392"]),
    "nl-zkbpp":  dict(status="demo-only", quantum_resistant="conjectured",
                       notes="ZKB++ variant of the same construction; same demo-rounds caveat as nl-zkboo.",
                       source=["herradura.h:2386-2392"]),
    "hpks-wots": dict(status="production", quantum_resistant="conjectured",
                       notes="RESTORED by TODO #347 (v10.0.0): NL-FSCX v1's modes now run 3n/4 = 192 rounds, where every differential characteristic costs >= 384 bits in the trail-weight model (3x the 128-bit collision bar) and every linear trail >= 191; the model is not exact for v1 and the hull is not measured (SecurityProofsCode/v1_mode_rounds.py, SecurityProofs-10.md 11.72). The chain step is 192 rounds too. Winternitz one-time signature (hash-based). Strictly one-time -- reuse of a WOTS "
                             "key is refused by the CLI. Demoted with hfscx-256 by TODO #346 (v9.5.67): its "
                             "security is that hash's, whose compression function has zero proven margin "
                             "against semi-free-start collisions; see hfscx-256.",
                       source=["herradura.h WOTS_* constants", "TODO_DONE.md #346",
                               "SecurityProofsCode/v1_mode_criterion.py"]),
    "hpks-xmss": dict(status="production", quantum_resistant="conjectured",
                       notes="RESTORED by TODO #347 (v10.0.0): NL-FSCX v1's modes now run 3n/4 = 192 rounds, where every differential characteristic costs >= 384 bits in the trail-weight model (3x the 128-bit collision bar) and every linear trail >= 191; the model is not exact for v1 and the hull is not measured (SecurityProofsCode/v1_mode_rounds.py, SecurityProofs-10.md 11.72). Earlier: demoted with hfscx-256 and hpks-wots by TODO #346 (v9.5.67); see "
                             "hfscx-256. Stateful hash-based signature (XMSS over the WOTS chains of hpks-wots), "
                              "with the next-unused leaf index kept in a <keyfile>.idx sidecar. Security "
                              "rests on HFSCX-256's collision resistance and on that state being "
                              "preserved: reusing a leaf index breaks the one-time property of the WOTS "
                              "key at that leaf, so a restored-from-backup key must not be signed with "
                              "again. Reclassified in TODO #238: this row said `pedagogical` because it "
                              "was a Python-only prototype, which stopped being true at TODO #201/#208 "
                              "-- all four implementations (C, Go, Python, Java) ship it and interoperate, "
                              "proven per-release by CliTest/test_cross_lang_matrix.sh. Nothing checked "
                              "the claim, which is what this item was filed about.",
                       source=["TODO_DONE.md #208", "TODO_DONE.md #201",
                               "CliTest/test_cross_lang_matrix.sh", "TODO_DONE.md #346"]),
    "hpks-ring": dict(status="demo-only", quantum_resistant="conjectured",
                       notes="Redesigned in v20.0.0 (TODO #415): ONE Stern proof over the ring's "
                             "block-diagonal statement diag([H_i | s_i]), proving that the signer knows one "
                             "member's weight-t error under a block and position shuffle that hides which. "
                             "Three valid openings of one round give a member's key, so a forger answers at "
                             "most two challenges in three: (2/3)^219 < 2^-128 at the CLI's 219 rounds. The "
                             "challenge binds the message, the canonical (sorted) ring and every commitment; "
                             "salted commitments keep the signer hidden even from someone holding every "
                             "member's key. The OR-composition it replaces (signatures labelled HERRADURA "
                             "HPKS-RING SIGNATURE) was forgeable with no member's key and is refused by "
                             "every CLI. Demo-only like hpks-stern: N = 256 is a ~24-38-bit instance; the "
                             "128-bit instance is the long form, N = 2304. Assembly/Arduino still carry the "
                             "old 32-bit demo (TODO #424).",
                       source=["SPEC.md section 11.2", "TODO_DONE.md #415", "CliTest/test_ring.sh"]),
    "hpks-t":    dict(status="pedagogical", quantum_resistant=False,
                       classical_security_bits="~36.5 (n=256)",
                       notes="Threshold / aggregate Schnorr over GF(2^n)* (herradura.h 4074), with signing "
                             "split across the commit/aggregate/respond/combine subcommands and only "
                             "verification behind the --algo tag. It is the same group as hpks, so it "
                             "carries the same ~2^36.5 Pohlig-Hellman recovery of a signer's share, which "
                             "yields arbitrary forgery -- thresholding distributes trust in the signing "
                             "protocol, it does not raise the hardness of the underlying group. This row "
                             "said `production` until TODO #238: hpks was reclassified pedagogical under "
                             "TODO #212 and nothing propagated that to the threshold variant, which is the "
                             "same class of drift TODO #237 found three of.",
                       source=["herradura.h:4074", "TODO_DONE.md #212", "TODO_DONE.md #98",
                               "SecurityProofs-3.md 9.2.4"]),
    "hske":      dict(status="pedagogical", quantum_resistant=False,
                       notes="Classical symmetric encryption via FSCX_REVOLVE; not quantum-resistant by design "
                             "(a symmetric primitive, not a PQC construction). Reclassified from production "
                             "under TODO #210: the key enters fscx_revolve only through the singular map "
                             "M*S_i, whose co-rank is 126 of 256 at the deployed i = n/4, so the ciphertext "
                             "alone discloses 126 linear functionals of the plaintext for every key "
                             "(SecurityProofs-1.md 1.3.1, W9). Use hske-nla1/hske-nla2 instead.",
                       source=["TODO_DONE.md #210"]),
    "hske-nla1": dict(status="production", quantum_resistant="conjectured",
                       notes="TODO #347 (v10.0.0) runs the keystream generator and MAC key at 3n/4 = 192 "
                             "rounds: every differential characteristic costs >= 384 bits in the trail-weight "
                             "model, 1.5x the full-codebook bar of 256, and every linear trail >= 191, so the "
                             "PER-KEY DATA LIMIT OF 2^64 BLOCKS set by TODO #346 IS LIFTED. CONJECTURE: v1 at "
                             "3n/4 rounds is a PRF. The record before v10.0.0 follows. NL-FSCX v1 counter-mode; supports --aead authenticated encryption. Unlike "
                             "classical hske, a known-plaintext pair does NOT break this construction: it "
                             "yields that one block's keystream and nothing else, which is inherent to "
                             "counter mode rather than a weakness. The classical 1-pair attack works by "
                             "solving E = M^i.P XOR T_i.K for T_i.K and reusing it on other ciphertexts; "
                             "the v1 carry non-linearity makes the keystream non-affine in base, so that "
                             "step has no analogue here (TODO #210, #237). Security rests on the "
                             "conjecture that NL-FSCX v1 is a PRF (SecurityProofs-4.md 11.3.1) -- an "
                             "assumption, not a proof. TODO #346 (v9.5.67) bounds it: v1's per-round "
                             "differential cost is at most 2 bits at every width (an exact 1/4-per-round "
                             "iterative characteristic), so over the n/4 = 64 rounds the full-codebook bar "
                             "of 256 bits hske-nla2 is held to cannot be met. The rating holds only under "
                             "a PER-KEY DATA LIMIT OF 2^64 BLOCKS: rekey before encrypting more under one "
                             "key. CONJECTURE (TODO #346): no differential or linear distinguisher on the "
                             "64-round keystream generator has probability or squared correlation above "
                             "2^-64; the cheapest characteristic known costs 128 bits in its core alone "
                             "(2x that bar), with no entry from a nonce difference of weight <= 22 "
                             "within 3 rounds -- the best found, not a proven least. The --aead tag is keyed hfscx-256, demo-only since #346; "
                             "the finding behind that needs a chaining difference an attacker cannot set "
                             "under an unknown key, so it does not break the tag, but the tag inherits no "
                             "production rating from this row.",
                       source=["TODO.md #237", "TODO_DONE.md #210", "TODO_DONE.md #346",
                               "SecurityProofsCode/v1_mode_criterion.py", "TODO_DONE.md #347",
                               "SecurityProofsCode/v1_mode_rounds.py"]),
    "hske-nla2": dict(status="production", quantum_resistant="conjectured",
                       notes="NL-FSCX v2 revolve-mode symmetric encryption -- a keyed bijection, not a stream "
                             "cipher. CONJECTURE (TODO #345): the key-averaged per-round trail cost of NL-FSCX"
                             " v2 at n = 256 stays at or above 1.71 differential and 0.865 linear (the share-"
                             "held bars, about 60% of its value at n = 23). Promoted from demo-only by TODO "
                             "#345 (v9.5.66), with twk, hske-nla3 and twk-v3, on the standard the other "
                             "production-track rows use: a named conjecture, cryptanalysis at the criterion "
                             "and no known attack. TODO #343 measured both trail axes exactly over real keys "
                             "to n = 23 with its methodology corrected: the key average is 1.65x / 1.71x the "
                             "bar there and rose at every width, 1.7% / 2.6% of keys sit below it, and on the "
                             "linear axis this is better covered than hske-nla1. It is NOT a bound: n = 23 to "
                             "256 is an 11x extrapolation, each width step adds less than the one before, "
                             "trails are not hulls, and v2 provably has no per-round differential floor (a "
                             "probability-1 one-round differential for every key). For security-critical use "
                             "prefer hske-nla3. Usage constraints: (1) DETERMINISTIC -- the same (P, K) gives "
                             "the same E, so embed a nonce or prefer hske-nla1 when several messages share a "
                             "key (SecurityProofs-4.md 11.3.2). (2) Keys with delta(K) in {0, 2^(n-1)} "
                             "collapse the permutation to GF(2)-affine; about 2^-129 of the key space, refused"
                             " by all four CLIs via nl_v2_key_is_valid. Since v14.0.0 (TODO #354) that check "
                             "refuses every key with arc(delta(K)) <= n/4, the short-arc weak class (about "
                             "2^-121 of keys at n = 256 with arcs of 12 bits or fewer) and the affine class "
                             "inside it; about 2^-96 of uniform keys, so it acts against hand-chosen keys "
                             "(SecurityProofs-10.md 11.81.4). The self-similarity TODO #244 "
                             "downgraded the row for was removed by TODO #245's round constants (v5.0.0).",
                       source=["TODO_DONE.md #345", "TODO_DONE.md #343", "TODO_DONE.md #244", "TODO_DONE.md #248", "SecurityProofsCode/hske_nl_a2_rating_review.py", "SecurityProofs-7.md 11.25, 11.26", "SecurityProofsCode/v2_v3_rating_review.py", "SecurityProofs-10.md 11.68", "SecurityProofs-10.md 11.81", "SECURITY.md"]),
    "hske-duplex": dict(status="research", quantum_resistant="conjectured",
                       notes="Arbitrary-length single-pass AEAD: a MonkeyDuplex-style sponge using "
                             "nl_fscx_revolve_v2 as the permutation (TODO #95 Option 2). Reclassified from "
                             "production under TODO #237 to match both the proofs and the implementation's "
                             "own banner: SecurityProofs-6.md 11.9 calls the single-pass sponge \"open "
                             "research\" requiring the differential/linear characterisation of the v2 "
                             "permutation tracked in TODO #99, and herradura.h marks it \"RESEARCH "
                             "CONSTRUCTION -- not for production use without further cryptanalysis\". "
                             "Bijectivity of v2 is proven; its standalone sponge profile is not. Use "
                             "hske-nla1 --aead, whose encrypt-then-MAC tag rests on the studied "
                             "\"v1 is a PRF\" assumption instead. Its tweak (the v2 permutation's B, "
                             "HFSCX-256 of the key and nonce) is NOT screened by nl_v2_key_is_valid "
                             "(TODO #359): about 2^-96 of tweaks fall below the screen's cut and 2^-121 "
                             "in the short-arc class measured weak, and only a chosen-nonce decrypt "
                             "querier can search for one, blind, at about 2^121 queries a hit (SecurityProofs-10.md 11.81.2, 11.81.4). Recorded "
                             "rather than fixed, since a rehash would change this research row's wire "
                             "format.",
                       source=["TODO.md #237", "herradura.h HSKE-NL-V2-Duplex banner",
                               "SecurityProofs-6.md 11.9", "TODO_DONE.md #359"]),
    "hfscx-256": dict(status="production", quantum_resistant="conjectured",
                       classical_security_bits="256-bit digest; 128-bit collision resistance in the "
                                                 "ideal-random-function model; >= 336-bit differential "
                                                 "trail floor on the 192-round Matyas-Meyer-Oseas "
                                                 "compression function (TODO #347, #351)",
                       notes="COMPRESSION MOVED TO MATYAS-MEYER-OSEAS by TODO #351 (v11.0.0): v10.0.0-v10.0.4's Davies-Meyer step let a message block choose v1's B, and for B in {0, 2^255} the round is affine-nilpotent, so at 192 rounds a zero block was the identity and H(b || 0^32) = H(0^32 || b) for every 32-byte b. The chaining value is now B; the new DeltaB = 0 shape costs >= 336 bits in the trail-weight model (SecurityProofsCode/hfscx_mmo_compression.py, SecurityProofs-10.md 11.75). RESTORED by TODO #347 (v10.0.0): NL-FSCX v1's modes now run 3n/4 = 192 rounds, where every differential characteristic costs >= 384 bits in the trail-weight model (3x the 128-bit collision bar) and every linear trail >= 191; the model is not exact for v1 and the hull is not measured (SecurityProofsCode/v1_mode_rounds.py, SecurityProofs-10.md 11.72). Earlier: DEMOTED to demo-only by TODO #346 (v9.5.67): NL-FSCX v1 has a key- and width-independent iterative differential (beta = 2^254 + 1, alpha = 2^255 + 2^254 + 1) holding with probability exactly 1/4 per round, so the compression function has a semi-free-start collision characteristic (Delta h = alpha, Delta m = beta) at 2^-128 over its 64 rounds -- exactly the birthday bound, zero margin, and a ceiling since other paths only add probability. It is not a collision of the hash, which needs Delta h = 0 (no entry into or exit from the core of weight <= 22 within 3 rounds was found). 256-bit Merkle-Damgard hash on NL-FSCX v1 with Davies-Meyer feed-forward, "
                             "re-derived in the ideal-random-function model under TODO #215. The generic "
                             "Merkle-Damgard weaknesses apply and are not defects of this construction: "
                             "Joux multicollisions and Kelsey-Schneier expandable-message second "
                             "preimages both work against it as against any MD hash without a wide pipe. "
                             "The compression function's own differential profile rests on the NL-FSCX v1 "
                             "PRF conjecture, so treat the classification as conditional on that.",
                       source=["SecurityProofs-6.md 11.9", "TODO_DONE.md #215",
                               "SecurityProofsCode/hfscx_dm_rf_model.py", "TODO_DONE.md #346",
                               "SecurityProofsCode/v1_mode_criterion.py",
                               "SecurityProofs-10.md 11.69", "TODO_DONE.md #347",
                               "SecurityProofsCode/v1_mode_rounds.py", "SecurityProofs-10.md 11.72"]),
    "hfscx-256-ds": dict(status="production", quantum_resistant="conjectured",
                       notes="hfscx-256 with an explicit domain-separation parameter; same construction, "
                             "same caveats, distinct digests per tag. Demoted with hfscx-256 by TODO #346, "
                             "restored with it by TODO #347 (v10.0.0).",
                       source=["SecurityProofs-6.md 11.9", "TODO_DONE.md #215", "TODO_DONE.md #346",
                               "TODO_DONE.md #347"]),
    "oprf":      dict(status="pedagogical", quantum_resistant=False,
                       classical_security_bits="~36.5 (n=256)",
                       notes="2HashDH OPRF over GF(2^n)*. oprf_eval is gf_pow(alpha, k), the same "
                             "exponentiation as hkex-gf/hpks/hpke, so the same Pohlig-Hellman recovery "
                             "applies to the server key k: one observed (alpha, beta) transcript pair costs "
                             "about 2^36.5 group operations at n=256 (TODO #212, #237). The base here is "
                             "the client's blinded alpha rather than the fixed g=3, and alpha is primitive "
                             "with density phi(2^n-1)/(2^n-1) = 0.4992; when it is not, k comes back modulo "
                             "ord(alpha) instead. That is not a mitigation -- ord(alpha) is publicly "
                             "computable, so an attacker watching a stream of transcripts attacks one of "
                             "the ~50% whose alpha is primitive and recovers k in full. "
                             "Obliviousness (the server not learning the client's input) is unaffected; "
                             "what breaks is k's secrecy, and with it the only property that stops anyone "
                             "who has seen one transcript from evaluating F(k, .) offline on inputs of "
                             "their choosing. That is exactly the offline-dictionary-attack resistance "
                             "the aPAKE built on this OPRF claims, so treat the aPAKE server record as "
                             "offline-guessable at the deployed n.",
                       source=["TODO.md #237", "TODO_DONE.md #212",
                               "SecurityProofsCode/hkex_gf_pohlig_hellman.py 6"]),
    "apake":     dict(status="pedagogical", quantum_resistant=False,
                       classical_security_bits="~36.5 (n=256), inherited from the OPRF",
                       notes="Asymmetric PAKE: the server record stores F(oprf_key, password) so that a "
                             "stolen database cannot be attacked offline. That property is exactly what "
                             "the oprf row breaks -- oprf_key is recoverable in ~2^36.5 group operations "
                             "from one observed transcript, so a compromised database IS offline-guessable "
                             "at the deployed n, which voids the construction's entire purpose. "
                             "Independently, the shipped ZKBoo parameters are demo-grade "
                             "(_HPAKE_ZKP_N = 32, _HPAKE_ROUNDS = 16, soundness error ~0.15%; production "
                             "needs 219 rounds). Reached through the pake-register/pake-demo subcommands "
                             "rather than an --algo tag, which is why it had no entry here at all before "
                             "TODO #238.",
                       source=["SECURITY.md", "TODO_DONE.md #237", "SecurityProofs-3.md 9.2.4"]),
    # ── TODO #241: the three formerly-unfiled subcommands ──────────────────
    "hdrbg":     dict(status="demo-only", quantum_resistant="conjectured",
                       notes="Fast-key-erasure deterministic bit generator over HFSCX-256 and "
                             "NL-FSCX v1 (TODO #96), reached through the `rand` subcommand rather "
                             "than an --algo tag. NOT an SP 800-90A DRBG and does not claim to be: "
                             "no health tests, no prediction-resistance request path, no "
                             "entropy-source assessment, and no reseed counter beyond the "
                             "output-block bound -- absent by design, not broken. DRBG_MAX_BLOCKS "
                             "= 2^20 is derived rather than arbitrary: it holds the state-walk "
                             "collision probability at 2^-179.8 against a 2^-128 requirement "
                             "(nl_fscx_v1_ratchet_collision.py section 5). Effective state entropy "
                             "is ~2^218.8 rather than 2^256, because the non-bijective walk's image "
                             "contracts. Sound as a deterministic expander for seed material that "
                             "is already full-entropy, under the block bound; not a drop-in RNG. "
                             "Backtracking resistance is best-effort in Python (immutable ints "
                             "cannot be erased); the C port erases. Classified in TODO #241.",
                       source=["Herradura cryptographic suite.py drbg_seed/generate/reseed",
                               "SecurityProofsCode/nl_fscx_v1_ratchet_collision.py",
                               "SecurityProofsCode/rand_fpe_twk_analysis.py",
                               "SECURITY.md", "SecurityProofs-7.md 11.24"]),
    "fpe":       dict(status="broken", quantum_resistant="conjectured",
                       notes="Reached through the `fpe` subcommand rather than an --algo tag. "
                             "BROKEN AS NAMED: this is not format-preserving encryption in the "
                             "SP 800-38G (FF1/FF3-1) sense. It has no radix, no length and no "
                             "domain -- it maps exactly 32 bytes to 32 bytes (any other length is refused since v16.0.0, TODO #377) and "
                             "returns raw binary, so a 16-digit card number comes back as 32 bytes "
                             "of binary. It is additionally the SAME FUNCTION as twk whenever the "
                             "context is 12 bytes: both derive their subkey as the unseparated "
                             "HFSCX-256(key || tweak), so `twk --decrypt` undoes `fpe --encrypt`, "
                             "verified byte-identical across the C, Go and Python CLIs. As a "
                             "construction it is HSKE-NL-A2's nl_fscx_revolve_v2. Do not use "
                             "where the output format must survive. TODO #242 (v4.0.0) fixed "
                             "everything about it except the name: it is now domain-separated from "
                             "twk with tag 0x20, its key/tweak boundary is length-encoded, its "
                             "derived subkey is rejection-sampled away from the degenerate affine "
                             "class, and it runs at R_VALUE=192 rather than I_VALUE=64. Renaming "
                             "it, re-scoping it, or implementing a real FF1/FF3-1 domain is a "
                             "separate decision and remains open. Wire-format breaking in v4.0.0 -- "
                             "every earlier fpe ciphertext is undecryptable, silently, since the "
                             "output is an unauthenticated permutation; see MIGRATING.md section 8.",
                       source=["Herradura cryptographic suite.py fpe_encrypt/fpe_decrypt",
                               "herradura.h fpe_encrypt", "herradura/herradura.go FpeEncrypt",
                               "SecurityProofsCode/rand_fpe_twk_analysis.py",
                               "SECURITY.md", "SecurityProofs-7.md 11.24"]),
    "twk":       dict(status="production", quantum_resistant="conjectured",
                       notes="Per-(sector, block-index) tweaked 256-bit permutation, reached through the `twk`"
                             " subcommand rather than an --algo tag; per-tweak determinism is the expected "
                             "XTS-style property. Domain-separated from fpe with tag 0x21, length-encoded "
                             "key||tweak, nl_fscx_revolve_v2 at R_VALUE=192 (TODO #242). In the random-oracle "
                             "model twk is an STPRP exactly if nl_fscx_revolve_v2 is an SPRP under a uniform "
                             "key, so it moves with hske-nla2: promoted from demo-only by TODO #345 (v9.5.66) "
                             "under the same CONJECTURE (TODO #345): the key-averaged per-round trail cost of "
                             "NL-FSCX v2 at n = 256 stays at or above 1.71 differential and 0.865 linear (the "
                             "share-held bars, about 60% of its value at n = 23). It is not a bound; see hske-"
                             "nla2. Its subkey is a hash output, so key recovery is confined to one block and "
                             "the affine class is unreachable. Prefer twk-v3 when security is critical. Wire-"
                             "format breaking in v4.0.0; see MIGRATING.md section 8.",
                       source=["Herradura cryptographic suite.py twk_encrypt/twk_decrypt", "herradura.h twk_encrypt", "herradura/herradura.go TwkEncrypt", "SecurityProofsCode/rand_fpe_twk_analysis.py", "SecurityProofsCode/twk_stprp_review.py", "SecurityProofsCode/v2_v3_rating_review.py", "SecurityProofs-10.md 11.68", "SECURITY.md"]),
    "hske-nla3": dict(status="production", quantum_resistant="conjectured",
                       notes="NL-FSCX v3 revolve-mode symmetric encryption -- hske-nla2's shape over the v3 "
                             "round: the deployed v2 round followed by a Keccak-chi layer over 47 five-bit and"
                             " 3 seven-bit rows, at R3_VALUE = 5n/8 = 160 rounds (TODO #255). Added alongside "
                             "v2, not a replacement. CONJECTURE (TODO #345): the per-round linear trail slope "
                             "of NL-FSCX v3 at n = 256 stays at or above its bar of 0.8 for every key outside "
                             "a negligible class; the differential floor 4 - log2(5) = 1.6781 >= 1.6 is "
                             "PROVEN. Promoted from demo-only by TODO #345 (v9.5.66), with hske-nla2, twk and "
                             "twk-v3. Every key measured clears 0.8 (least 1.47x at n = 10, exhaustive; 2.01x "
                             "and 1.77x in sample at n = 14 and 17) and the median key at n = 17 is above v2's"
                             " key average at n = 23, so the evidence is at least as strong as v2's on both "
                             "axes; promoting v2 alone would have recommended a demo-only variant over a "
                             "production-track one. Better-founded, not proven: the round's own linear floor "
                             "is 0.1926 bits, below 0.8 (TODO #342), and a proven LSB-row ceiling caps the "
                             "worst key's linear margin at 1.77x (SecurityProofs-10.md 11.53). The variant to "
                             "prefer when security is critical. Still DETERMINISTIC (embed a nonce or prefer "
                             "hske-nla1 when messages share a key); there is deliberately NO key check, since "
                             "both v2 weak classes dissolve under chi (SecurityProofs-8.md 11.34.4).",
                       source=["TODO_DONE.md #345", "TODO.md #255", "SecurityProofs-8.md 11.34", "SecurityProofsCode/nl_fscx_v3_weak_keys.py", "SecurityProofsCode/nl_fscx_v3_linear_width.py", "SecurityProofsCode/v2_v3_rating_review.py", "SecurityProofs-10.md 11.68"]),
    "hske-duplex3": dict(status="research", quantum_resistant="conjectured",
                       notes="hske-duplex's MonkeyDuplex sponge over the v3 permutation, with its own "
                             "domain-separation strings and its own format tag (4, against v2's 3), so "
                             "a v2 artifact is rejected by the parser rather than surfacing as an "
                             "opaque tag mismatch. The NL-FSCX v3 round is the deployed v2 round followed by a Keccak-chi layer over 47 five-bit and 3 seven-bit rows, at R3_VALUE = 5n/8 = 160 rounds (TODO #255). It is ADDED alongside v2, not a replacement: no stored artifact changes and the v2 tag keeps working. Its margin is wider than v2's and for the first time in this family it rests in part on a PROOF -- chi gives the round an unconditional per-round DIFFERENTIAL floor of 4 - log2(5) = 1.6781 bits, a bound on the round's own DDT entry, which clears v3's own bar of 1.6 (256 bits over 160 rounds) at every width, so v3 has a proven differential trail bound at n = 256 (at 1.05x) where v2 provably has none (its linear-then-add-constant round hands every key a probability-1 one-round differential). The 1-bit LINEAR floor is layer-wise only: the round's own proven linear floor is 0.1926 bits, below the 0.8 bar (TODO #342, SecurityProofs-10.md 11.52). There is deliberately NO key check: both v2 weak classes dissolve under chi and there is no chi-specific class to screen, proven exhaustively rather than sampled (SecurityProofs-8.md 11.34.4). IT ARRIVES DEMO-ONLY ANYWAY, and that is the point of the rating: v3 still has no PRP/SPRP reduction, and no LINEAR trail bound at realistic width -- its exact asymptotic linear slope clears 0.8 for every key at n = 10 (least 1.47x) and every sampled key at n = 14 and 17 (TODO #257 item 3), but those are small widths, not a bound; the margin has a proven ceiling, since the LSB row receives no carry and its cycles cost the same at every width, capping the worst key's linear slope at 1.415, at most 1.77x the bar at n = 256 (SecurityProofs-10.md §11.53) -- and differential hulls are not covered. A wider margin is not a promotion. "
                             "The sponge round count is I3_VALUE = 5n/16 = 80, and it is the FIRST "
                             "duplex round count in this suite that is derived rather than inherited: "
                             "the capacity is 128 bits, so 128 bits is the target, and the per-round "
                             "floors put the requirement at r >= 77 differential (proven) and r >= 64 "
                             "linear (layer-wise only; the same 0.8 bar as R3 once the round-level "
                             "floor is used, TODO #342). "
                             "hske-duplex's I_VALUE = 64 would have left the differential axis at 107 "
                             "bits. That does not lift the rating: what keeps the v2 duplex at "
                             "`research` is that the standalone sponge profile of the permutation has "
                             "never been characterised (TODO #99), and a per-round trail floor is not "
                             "that characterisation. Prefer hske-nla1 --aead for anything real.",
                       source=["TODO.md #255", "TODO.md #99", "SecurityProofs-8.md 11.34.8",
                               "SecurityProofs-6.md 11.9"]),
    "hpke-nl3":  dict(status="pedagogical", quantum_resistant=False,
                       classical_security_bits="~36.5 (n=256)",
                       notes="hpke-nl's shape over the v3 round, with its own PEM labels. "
                             "PEDAGOGICAL FOR THE SAME REASON hpke-nl IS, AND THE v3 ROUND DOES NOT "
                             "HELP: the break is Pohlig-Hellman against the GF(2^n)* group, which "
                             "recovers the decryption key in ~2^36.5 work without touching the "
                             "symmetric layer at all. Hardening that layer changes nothing. Shipped "
                             "for parity with the rest of the v3 family and to keep the "
                             "cross-language matrix symmetric, not because it is usable. "
                             "The NL-FSCX v3 round is the deployed v2 round followed by a Keccak-chi layer over 47 five-bit and 3 seven-bit rows, at R3_VALUE = 5n/8 = 160 rounds (TODO #255). It is ADDED alongside v2, not a replacement: no stored artifact changes and the v2 tag keeps working. Its margin is wider than v2's and for the first time in this family it rests in part on a PROOF -- chi gives the round an unconditional per-round DIFFERENTIAL floor of 4 - log2(5) = 1.6781 bits, a bound on the round's own DDT entry, which clears v3's own bar of 1.6 (256 bits over 160 rounds) at every width, so v3 has a proven differential trail bound at n = 256 (at 1.05x) where v2 provably has none (its linear-then-add-constant round hands every key a probability-1 one-round differential). The 1-bit LINEAR floor is layer-wise only: the round's own proven linear floor is 0.1926 bits, below the 0.8 bar (TODO #342, SecurityProofs-10.md 11.52). There is deliberately NO key check: both v2 weak classes dissolve under chi and there is no chi-specific class to screen, proven exhaustively rather than sampled (SecurityProofs-8.md 11.34.4). IT ARRIVES DEMO-ONLY ANYWAY, and that is the point of the rating: v3 still has no PRP/SPRP reduction, and no LINEAR trail bound at realistic width -- its exact asymptotic linear slope clears 0.8 for every key at n = 10 (least 1.47x) and every sampled key at n = 14 and 17 (TODO #257 item 3), but those are small widths, not a bound; the margin has a proven ceiling, since the LSB row receives no carry and its cycles cost the same at every width, capping the worst key's linear slope at 1.415, at most 1.77x the bar at n = 256 (SecurityProofs-10.md §11.53) -- and differential hulls are not covered. A wider margin is not a promotion. "
                             "Unlike hpke-nl, encryption does NOT resample the ephemeral scalar: "
                             "there is no affine-degenerate key class to sample past.",
                       source=["TODO.md #255", "TODO_DONE.md #212", "SecurityProofs-4.md 11.7",
                               "SecurityProofs-8.md 11.34"]),
    "fpe-v3":    dict(status="broken", quantum_resistant="conjectured",
                       notes="Reached as `fpe --v3`, a flag on the fpe subcommand rather than a new "
                             "subcommand or an --algo tag (TODO #255 recorded the choice explicitly: "
                             "fpe and twk are already filed by cli_binding rather than by tag, the "
                             "flag keeps every other option identical between the two variants, and "
                             "a new subcommand would have doubled a surface that TODO #241 found "
                             "confusing enough already). "
                             "STILL BROKEN AS NAMED, and the v3 round does not touch that: it is "
                             "still not format-preserving encryption in the SP 800-38G sense -- no "
                             "radix, no length, no domain, 32 bytes in and 32 raw bytes out. The v3 "
                             "variant does inherit TODO #242's fixes (domain separation, "
                             "length-encoded key/tweak boundary) with its own tag 0x22, so it is "
                             "separated from twk --v3 (0x23) and from both v2 variants; the same "
                             "(key, ctx) never yields the same subkey across the four. Its subkey "
                             "derivation is a single hash with NO rejection loop, unlike v2's: a "
                             "loop would reject ~2^-129 of subkeys for a degeneracy v3 does not "
                             "have, while implying the rest had been screened for one that it does. "
                             "The NL-FSCX v3 round is the deployed v2 round followed by a Keccak-chi layer over 47 five-bit and 3 seven-bit rows, at R3_VALUE = 5n/8 = 160 rounds (TODO #255). It is ADDED alongside v2, not a replacement: no stored artifact changes and the v2 tag keeps working. Its margin is wider than v2's and for the first time in this family it rests in part on a PROOF -- chi gives the round an unconditional per-round DIFFERENTIAL floor of 4 - log2(5) = 1.6781 bits, a bound on the round's own DDT entry, which clears v3's own bar of 1.6 (256 bits over 160 rounds) at every width, so v3 has a proven differential trail bound at n = 256 (at 1.05x) where v2 provably has none (its linear-then-add-constant round hands every key a probability-1 one-round differential). The 1-bit LINEAR floor is layer-wise only: the round's own proven linear floor is 0.1926 bits, below the 0.8 bar (TODO #342, SecurityProofs-10.md 11.52). There is deliberately NO key check: both v2 weak classes dissolve under chi and there is no chi-specific class to screen, proven exhaustively rather than sampled (SecurityProofs-8.md 11.34.4). IT ARRIVES DEMO-ONLY ANYWAY, and that is the point of the rating: v3 still has no PRP/SPRP reduction, and no LINEAR trail bound at realistic width -- its exact asymptotic linear slope clears 0.8 for every key at n = 10 (least 1.47x) and every sampled key at n = 14 and 17 (TODO #257 item 3), but those are small widths, not a bound; the margin has a proven ceiling, since the LSB row receives no carry and its cycles cost the same at every width, capping the worst key's linear slope at 1.415, at most 1.77x the bar at n = 256 (SecurityProofs-10.md §11.53) -- and differential hulls are not covered. A wider margin is not a promotion.",
                       source=["TODO.md #255", "SecurityProofs-8.md 11.34",
                               "SecurityProofs-7.md 11.24.2"]),
    "twk-v3":    dict(status="production", quantum_resistant="conjectured",
                       notes="Reached as `twk --v3`; see fpe-v3 for why a flag rather than a subcommand. twk's"
                             " shape over the v3 round, domain-separated with tag 0x23, at R3_VALUE = 160 "
                             "rounds (TODO #255). It moves with twk (the STPRP question is the permutation's) "
                             "and with hske-nla3 (the same round): promoted from demo-only by TODO #345 "
                             "(v9.5.66) under the same CONJECTURE (TODO #345): the per-round linear trail "
                             "slope of NL-FSCX v3 at n = 256 stays at or above its bar of 0.8 for every key "
                             "outside a negligible class; the differential floor 4 - log2(5) = 1.6781 >= 1.6 "
                             "is PROVEN. It is not a bound; see hske-nla3. It keeps twk's advantages from a "
                             "hashed subkey: key recovery confined to one block, no caller-supplied key "
                             "reaches the permutation.",
                       source=["TODO_DONE.md #345", "TODO.md #255", "TODO_DONE.md #243", "SecurityProofs-8.md 11.34", "SecurityProofsCode/v2_v3_rating_review.py", "SecurityProofs-10.md 11.68"]),
    "hcred":     dict(status="research", quantum_resistant="conjectured",
                       notes="Hybrid Ring-LWR + Stern-F credential over a unified ZKBoo-(2,3) "
                             "MPC-in-the-head circuit. All four CLIs dispatch cred-issue/cred-prove/"
                             "cred-verify -- the \"Python and C CLI only, not in Go\" note this row "
                             "used to carry was stale, and nothing checked it (TODO #238).",
                       source=["TODO_DONE.md #128", "SecurityProofs-7.md 11.10.8-11.10.10"]),
}

# (Cross-implementation CLI support is no longer curated -- see extract_cli_tags.)
# (not --help banners: those under-documented some algos in C and Go until
# TODO #339 generated their synopses from this same data).
# CLI_SUPPORT used to be a curated {tag: {c/go/python: bool}} table here.  It is
# now derived by extract_cli_tags() from each CLI's own source (TODO #238) -- see
# that function for why.  The two entries it had wrong are recorded in
# CROSS_IMPL_GAPS_CURATED below so the correction is not silent.


# ── Subcommand-bound protocols (TODO #238 Part C) ─────────────────────────
#
# `protocols` is keyed on a stable protocol id, which for most entries is also
# the `--algo` tag.  Some protocols have no `--algo` tag at all: they ship as
# their own subcommands.  aPAKE was the case that exposed this -- `pake-register`
# and `pake-demo`, no tag under which to file it, so it had no spec entry despite
# having a SECURITY.md row since TODO #237.
#
# The fix widens the key rather than adding a second parallel array: a protocol
# is filed under its id either way, and `cli_binding` records how the CLI reaches
# it.  A separate `subcommand_protocols` section would have let a protocol fall
# between the two halves, which is the failure mode being fixed.
#
# Every subcommand named here is validated against the argparse subparser list in
# herradura.py, so a renamed subcommand fails --check.
SUBCOMMAND_PROTOCOLS = {
    "threshold-commit":    "hpks-t",
    "threshold-aggregate": "hpks-t",
    "threshold-respond":   "hpks-t",
    "threshold-combine":   "hpks-t",
    "oprf-blind":          "oprf",
    "oprf-eval":           "oprf",
    "oprf-unblind":        "oprf",
    "cred-issue":          "hcred",
    "cred-prove":          "hcred",
    "cred-verify":         "hcred",
    "pake-register":       "apake",
    "pake-demo":           "apake",
    # TODO #241: classified at last. Like aPAKE these have no --algo tag and
    # ship as their own subcommands, so they are filed by id with a cli_binding.
    "rand":                "hdrbg",
    "fpe":                 "fpe",
    "twk":                 "twk",
}

# TODO #255: two protocols reached by a FLAG on an existing subcommand rather
# than by an --algo tag or a subcommand of their own.  `fpe --v3` and `twk --v3`
# are separate constructions with separate subkey domains and separate ratings,
# so they need their own entries; they are not separate subcommands, so
# SUBCOMMAND_PROTOCOLS cannot hold them without claiming a subcommand that does
# not exist.  Both halves are validated in generate(): the subcommand must be a
# real subparser, and the flag must be a real option on it.
FLAG_VARIANT_PROTOCOLS = {
    "fpe-v3": ("fpe", "--v3"),
    "twk-v3": ("twk", "--v3"),
}

# The rest of the audit #238 Part C asked for: CLI surface that reaches no
# protocol entry at all.  `pkey` is a utility.  The other three are real
# constructions that have never been classified -- they have no SECURITY entry
# here and no SECURITY.md row, so filing them means classifying them, which is
# TODO #237-shaped work rather than #238's.  Recording them here (and shipping
# them in the JSON) makes the gap enumerable instead of invisible, and the check
# in generate() fails on a *new* unfiled subcommand.
UNFILED_CLI_SURFACE = {
    "pkey": "Utility, not a protocol: derives a public key from any private-key PEM.",
    # rand/fpe/twk were here from TODO #238 until TODO #241 analysed and filed
    # them. `pkey` is the only genuine remainder: it is a key-format utility with
    # no protocol of its own, not an unanalysed construction.
}

PROTOCOL_KIND = {
    "hkex-gf": "kex", "hkex-rnl": "kex",
    "hpks": "signature", "hpks-nl": "signature", "hpks-stern": "signature",
    "hpks-wots": "signature", "hpks-xmss": "signature", "hpks-ring": "signature",
    "hpks-t": "signature", "hybrid-rnl-stern": "kex", "rnl-sigma": "zkp", "nl-zkboo": "zkp", "nl-zkbpp": "zkp",
    "hpke": "encryption", "hpke-nl": "encryption",
    "hpke-stern": "kem", "hpke-stern-kem": "kem",
    "hpks-zkp-nl": "zkp",
    "hske": "encryption", "hske-nla1": "aead", "hske-nla2": "encryption", "hske-duplex": "aead",
    "hske-nla3": "encryption", "hske-duplex3": "aead", "hpke-nl3": "encryption",
    "fpe-v3": "encryption", "twk-v3": "encryption",
    "hfscx-256": "hash", "hfscx-256-ds": "hash",
    "oprf": "oprf", "hcred": "credential", "apake": "pake",
    "hdrbg": "drbg", "fpe": "encryption", "twk": "encryption",
}

PROTOCOL_NAME = {
    "hkex-gf": "HKEX-GF (Diffie-Hellman over GF(2^n)*)",
    "hkex-rnl": "HKEX-RNL (Ring-LWR key exchange)",
    "hpks": "HPKS (Schnorr signature over GF(2^n)*)",
    "hpks-nl": "HPKS-NL (NL-FSCX-hardened Schnorr, classical only)",
    "hpke": "HPKE (El Gamal encryption over GF(2^n)*)",
    "hpke-nl": "HPKE-NL (NL-FSCX-hardened El Gamal, classical only)",
    "hpks-stern": "HPKS-Stern-F (Fiat-Shamir signature from Stern ZKID)",
    "hpke-stern": "HPKE-Stern-F (Niederreiter KEM)",
    "hpke-stern-kem": "HPKE-Stern-KEM (Niederreiter KEM, alternate encoding)",
    "hpks-zkp-nl": "HPKS-ZKP-NL (keygen for ZKBoo/ZKB++)",
    "rnl-sigma": "ZKP-RNL Sigma-protocol",
    "nl-zkboo": "ZKBoo (NL-FSCX preimage proof)",
    "nl-zkbpp": "ZKB++ (NL-FSCX preimage proof)",
    "hpks-wots": "HPKS-WOTS (Winternitz one-time signature)",
    "hpks-xmss": "HPKS-XMSS (stateful hash-based signature)",
    "hpks-ring": "HPKS-Ring (anonymous ring signature)",
    "hpks-t": "HPKS-T (threshold Schnorr signature)",
    "hske": "HSKE (classical symmetric encryption)",
    "hske-nla1": "HSKE-NL-A1 (NL-FSCX counter-mode AEAD)",
    "hske-nla2": "HSKE-NL-A2 (NL-FSCX revolve-mode encryption)",
    "hske-duplex": "HSKE-Duplex (single-pass AEAD)",
    "hske-nla3": "HSKE-NL-A3 (NL-FSCX v3 revolve-mode encryption)",
    "hske-duplex3": "HSKE-Duplex-V3 (single-pass AEAD over NL-FSCX v3)",
    "hpke-nl3": "HPKE-NL3 (NL-FSCX v3-hardened El Gamal, classical only)",
    "fpe-v3": "FPE-V3 (`fpe --v3`, NL-FSCX v3 block permutation)",
    "twk-v3": "TWK-V3 (`twk --v3`, NL-FSCX v3 tweakable block cipher)",
    "hfscx-256": "HFSCX-256 (Merkle-Damgard hash)",
    "hfscx-256-ds": "HFSCX-256-DS (domain-separated variant)",
    "oprf": "OPRF (2HashDH oblivious PRF over GF(2^n)*)",
    "hcred": "HCRED (hybrid credential)",
    "apake": "aPAKE (asymmetric password-authenticated key exchange)",
}

# TODO #261: GAP_REASONS was a table of five Java cells with a recorded reason
# each -- the "ACKNOWLEDGED rather than silent" half of #261's acceptance
# criterion.  It is now EMPTY, and deliberately kept rather than deleted: all
# five (nl-zkboo, nl-zkbpp, hpks-zkp-nl, rnl-sigma, hybrid-rnl-stern) were
# PORTED to Java in v6.0.0 instead of documented, so Java dispatches all 29 algo
# tags and there is nothing left to excuse.  Keeping the mechanism means the next
# gap gets a reason instead of silence; a gap with no entry here still appears in
# cross_implementation_gaps with note=None, which is the honest rendering of
# "nobody has written down why yet".
GAP_REASONS = {}

# Gaps in the algo-tag surface are derived (see build_cross_impl_gaps).  This
# held the one gap that was not a tag -- C's and Go's hand-written --help text
# under-documenting tags they dispatch -- until TODO #339 generated the synopsis
# from the same rows, which closed it.  Kept, empty, for the next non-tag gap.
CROSS_IMPL_GAPS_CURATED = []


# TODO #267: the ACKNOWLEDGED half of the flag matrix.
#
# The matrix itself is derived; this table is the part that cannot be -- WHY a
# language does not implement a flag.  #267's finding was not that gaps exist
# but that neither answer ("capability parity" or "deliberate scope") was
# written anywhere a check could read, so a scope note recorded once in a TODO
# (#166's "Scoped to the Python CLI only") became invisible the moment that item
# was archived.
#
# Keyed by (subcommand, flag) -> (languages that HAVE it, reason).  Both
# directions are validated in build_cli_surface_gaps, which is what keeps this
# from becoming the stale curated table TODO #238 deleted: a derived gap with no
# entry here is an error, an entry here matching no derived gap is an error, and
# an entry whose language set no longer matches what the parsers say is an error
# naming both sets.  So porting a flag fails the check until the entry is
# dropped, and deleting one fails it until the entry is too.
#
# STATUS VOCABULARY.  "acknowledged" is a deliberate per-language scope decision.
# "defect" is a gap this table does NOT bless -- it is recorded so it is visible
# and counted, and it names the follow-up.  #267 closes on the mechanism, not on
# the ports, so a defect row is an expected state here, not a failing one.
CLI_FLAG_PARITY = {
    # ── TODO #166's envelope is four-way as of v6.5.5 (TODO #268) ─────────
    # genpkey --passphrase / --kdf-iterations and pkey --passphrase / --decrypt
    # were Python-only from v1.9.134.  Closing it needed the primitive chain
    # first: hmac_hfscx_256 in Java (#261's last acknowledged hash cell), then
    # PBKDF2-HFSCX-256, and -- unrecorded by #268's own text -- HSKE-NL-AEAD
    # in Java, which was TODO #273.

    # ── Java's flag gaps under TODO #269 are all closed ───────────────────
    # `--digest` and `rand` in v6.2.0/v6.3.0, `kex --kdf` in v6.5.0, and
    # `enc --aead` in v6.5.4 (TODO #273), which needed the AEAD primitive
    # itself rather than argument-parser wiring.
    ("pake-register", "--username"): (
        ("java", "python"), "acknowledged",
        "aPAKE client identifier. It is stored in the record dict for lookup and is "
        "NOT cryptographically bound: hpake_register derives salt, B and y from the "
        "password and the OPRF key alone, and the HERRADURA PAKE RECORD PEM carries "
        "(salt, B, y) with no username field. So C and Go omitting the flag costs no "
        "interoperability -- their records are byte-comparable with Python's."),
    ("pake-demo", "--username"): (
        ("java", "python"), "acknowledged",
        "The login side of pake-register --username; unbound for the same reason."),
    ("cred-verify", "--rounds"): (
        ("c", "go"), "acknowledged",
        "An EXTRA flag rather than a missing one: C and Go let the caller override "
        "the round count a proof declares, defaulting to the proof's own. Python and "
        "Java always use the proof's. The round count travels in the PEM (TODO #236), "
        "so the default is identical in all four and the flag only widens what C and "
        "Go will attempt; it cannot make them accept a proof the others reject."),

}

# The same table one level up: a SUBCOMMAND present in some CLIs and not others.
# `cli_subcommands` above is keyed on the Python CLI's subparser list, so a
# subcommand only another CLI defines was structurally invisible to this spec.
#
# `rand` was the other entry here until TODO #269 ported it to Java (v6.3.0),
# which is the intended life-cycle of a `defect` row: it is deleted by closing the
# gap, and generation FAILS until it is.
CLI_SUBCOMMAND_PARITY = {
    "threshold-verify": (
        ("go",), "acknowledged",
        "An EXTRA subcommand rather than a missing one. All four verify a threshold "
        "signature; they differ in how it is reached. Python and Java route it through "
        "`verify --algo hpks-t`, C dispatches `verify` and delegates internally to "
        "cmd_threshold_verify, and Go additionally exposes it as its own top-level "
        "subcommand. Same operation, same PEM, one extra entry point."),
}

VALID_PARITY_STATUS = ("acknowledged", "defect")


# herradura.py's argparse subparser variable names, needed by extract_choices.
# Hoisted to module scope by TODO #269 so the --algo tag lists and the value-set
# table below read the same map rather than two copies that can drift apart.
PY_SUBPARSER_VARS = {
    "kex": "kx", "enc": "en", "dec": "de", "sign": "sg", "verify": "vf",
    "encfile": "ef", "decfile": "df", "dgst": "dg",
}


# ── TODO #269: the value-level axis, one granularity below CLI_FLAG_PARITY ────
#
# #267's matrix answers "does this CLI define this flag".  It deliberately does
# not reach the flag's accepted VALUE set, and #269 found that gap the hard way:
# porting `kex --kdf` to Java would put the flag at 4/4, DELETE its
# CLI_FLAG_PARITY row, and take with it the only written record anywhere that
# Python accepts `sp800227` and C/Go do not.  That is #267's own "anchor lost"
# failure reproduced one level down, so the axis is recorded here FIRST and the
# port comes after.
#
# Shape, and why it is a derived/curated split.  Python's sets are DERIVED from
# argparse `choices=` and must be written as None below -- so a choices list that
# changes fails this table instead of silently disagreeing with it.  C, Go and
# Java accept values through chains of string comparisons (`strcmp(v,
# "hfscx-256") == 0`, `*v == "hfscx-256"`, `v.equals(...)`), which is not
# reliably derivable, so those three are curated and carry the cost of being
# checked by hand against a probe.
#
# A flag belongs here ONLY while its value sets disagree.  Agreement makes the
# entry an orphan and generation fails until it is deleted -- the same
# life-cycle as a CLI_FLAG_PARITY row, and the reason `sign --digest` is absent:
# TODO #269 made C and Go fail closed on an unknown value, so all four now take
# exactly {none, hfscx-256} and there is nothing left to record.
CLI_FLAG_VALUES = {
    ("kex", "--kdf"): (
        {"python": None,                              # derived from choices=
         "c":      ("none", "hfscx-256"),
         "go":     ("none", "hfscx-256"),
         "java":   ("none", "hfscx-256")},
        "defect",
        "`sp800227` (TODO #165) binds the full public transcript -- both parties' "
        "public polynomials and the reconciliation hint -- into the session key per "
        "SP 800-227 Sec 4.5-4.6, and exists only in the Python CLI. It is scoped to "
        "--algo hkex-rnl, and Python rejects it on any other algo. The other three "
        "reject the VALUE, so there is no interoperability hazard in the "
        "fail-closed direction: a peer asking for sp800227 against a C/Go/Java "
        "responder gets an error, never a silently different session key. Filed as "
        "a defect rather than blessed scope because both sides must pass the same "
        "--kdf and only one CLI can pass this one."),
}


def build_cli_flag_value_gaps(flag_matrix, py_src):
    """The value-set axis of the CLI surface: derived where it can be, curated
    where it cannot, and exhaustive in both directions like every other table here.

    Four ways this raises, mirroring build_cli_surface_gaps:
      * a curated entry naming a flag no CLI defines (the flag was renamed);
      * a curated entry whose languages disagree with the derived flag matrix;
      * a Python cell that is not None, or whose argparse choices= cannot be read
        (the extractor went stale, which must fail rather than read as "no values");
      * an entry whose value sets now AGREE -- parity reached, delete the row.
    """
    langs = ("c", "go", "java", "python")
    gaps = []

    for (sub, flag), (per_lang, status, reason) in sorted(CLI_FLAG_VALUES.items()):
        if sub not in flag_matrix or flag not in flag_matrix[sub]:
            raise RuntimeError(
                f"CLI_FLAG_VALUES names `{sub} {flag}`, which no CLI's argument "
                f"parser defines. The flag was renamed or removed -- update the "
                f"entry, or delete it (TODO #269).")
        if status not in VALID_PARITY_STATUS:
            raise RuntimeError(
                f"CLI_FLAG_VALUES[({sub!r}, {flag!r})] has unknown status {status!r}.")

        # The flag matrix decides WHO must have a value set: a language that does
        # not define the flag must not carry one, and one that does must.
        present = sorted(l for l in langs if flag_matrix[sub][flag][l])
        if sorted(per_lang) != present:
            raise RuntimeError(
                f"CLI_FLAG_VALUES[({sub!r}, {flag!r})] lists value sets for "
                f"{sorted(per_lang)}, but the CLIs' own argument parsers say the "
                f"flag is defined by {present}. A language that gained or lost the "
                f"flag must gain or lose its value set with it.")

        resolved = {}
        for lang, values in per_lang.items():
            if lang == "python":
                if values is not None:
                    raise RuntimeError(
                        f"CLI_FLAG_VALUES[({sub!r}, {flag!r})]['python'] must be None: "
                        f"Python's set is derived from argparse choices=, so writing it "
                        f"out by hand is the drift this table exists to catch.")
                var = PY_SUBPARSER_VARS.get(sub)
                if var is None:
                    raise RuntimeError(
                        f"CLI_FLAG_VALUES[({sub!r}, {flag!r})] needs herradura.py's "
                        f"argparse variable for subcommand {sub!r}; add it to "
                        f"PY_SUBPARSER_VARS.")
                derived = extract_choices(py_src, var, flag)
                if not derived:
                    raise RuntimeError(
                        f"CLI_FLAG_VALUES[({sub!r}, {flag!r})]: no argparse choices= "
                        f"found for `{var}.add_argument({flag!r}, ...)` in "
                        f"herradura.py. Either the flag stopped being enumerated or "
                        f"extract_choices went stale -- both must fail here rather "
                        f"than read as an empty value set.")
                resolved[lang] = sorted(derived)
            else:
                if not values:
                    raise RuntimeError(
                        f"CLI_FLAG_VALUES[({sub!r}, {flag!r})][{lang!r}] is empty; a "
                        f"language that defines the flag accepts at least one value.")
                resolved[lang] = sorted(values)

        # Parity reached => orphan. Same direction as build_cli_surface_gaps'
        # orphan check, and the reason porting a value must delete its row.
        distinct = {tuple(v) for v in resolved.values()}
        if len(distinct) == 1:
            raise RuntimeError(
                f"CLI_FLAG_VALUES[({sub!r}, {flag!r})] records a divergence, but all "
                f"of {sorted(resolved)} now accept exactly "
                f"{list(next(iter(distinct)))}. The gap is closed -- delete the entry "
                f"(TODO #269).")

        shared = set.intersection(*(set(v) for v in resolved.values()))
        gaps.append({
            "kind": "flag_values", "subcommand": sub, "flag": flag,
            "accepted_values": {l: resolved[l] for l in sorted(resolved)},
            "accepted_by_all": sorted(shared),
            "divergent_values": sorted(set().union(*(set(v) for v in resolved.values())) - shared),
            "status": status, "reason": reason,
        })
    return gaps


def build_cli_surface_gaps(flag_matrix, subcommand_impls):
    """Every non-unanimous cell of the CLI flag/subcommand surface, derived, each
    joined to its curated reason -- and the four ways that join can fail.

    A gap with no curated entry raises: that is the check.  Adding a flag to one
    CLI and not the others fails `--check` with the flag named, and the only ways
    to make it pass are to port it or to write down why not.
    """
    langs = ("c", "go", "java", "python")
    gaps, used_flag, used_sub = [], set(), set()

    for sub in sorted(subcommand_impls):
        present = tuple(sorted(l for l in langs if l in subcommand_impls[sub]))
        if len(present) == len(langs):
            continue
        entry = CLI_SUBCOMMAND_PARITY.get(sub)
        if entry is None:
            raise RuntimeError(
                f"CLI subcommand {sub!r} is defined by {list(present)} but not by "
                f"{[l for l in langs if l not in present]}, and generate_spec.py's "
                f"CLI_SUBCOMMAND_PARITY does not account for it. Port it, or record "
                f"why it is scoped to those CLIs (TODO #267).")
        expected, status, reason = entry
        used_sub.add(sub)
        if tuple(sorted(expected)) != present:
            raise RuntimeError(
                f"CLI_SUBCOMMAND_PARITY[{sub!r}] says {sorted(expected)} implement it, "
                f"but the CLIs' own dispatch says {list(present)}. Update the entry "
                f"(or drop it if the gap is closed) -- an acknowledgement that no "
                f"longer describes the code is the drift TODO #267 exists to catch.")
        if status not in VALID_PARITY_STATUS:
            raise RuntimeError(f"CLI_SUBCOMMAND_PARITY[{sub!r}] has unknown status {status!r}.")
        gaps.append({"kind": "subcommand", "subcommand": sub, "flag": None,
                     "present_in": list(present),
                     "missing_from": [l for l in langs if l not in present],
                     "status": status, "reason": reason})

    for sub in sorted(flag_matrix):
        for flag in sorted(flag_matrix[sub]):
            cells = flag_matrix[sub][flag]
            present = tuple(sorted(l for l in langs if cells[l]))
            # A flag can only be missing from a CLI that has the subcommand at all;
            # `rand`'s seven flags are absent from Java because `rand` is, and
            # reporting them again would be the same gap counted eight times.
            scope = tuple(sorted(l for l in langs if l in subcommand_impls[sub]))
            if present == scope:
                continue
            entry = CLI_FLAG_PARITY.get((sub, flag))
            if entry is None:
                raise RuntimeError(
                    f"CLI flag `{sub} {flag}` is implemented by {list(present)} but not "
                    f"by {[l for l in scope if l not in present]}, and "
                    f"generate_spec.py's CLI_FLAG_PARITY does not account for it. Port "
                    f"it, or record why it is scoped to those CLIs (TODO #267).")
            expected, status, reason = entry
            used_flag.add((sub, flag))
            if tuple(sorted(expected)) != present:
                raise RuntimeError(
                    f"CLI_FLAG_PARITY[({sub!r}, {flag!r})] says {sorted(expected)} "
                    f"implement it, but the CLIs' own argument parsers say "
                    f"{list(present)}. Update the entry (or drop it if the gap is "
                    f"closed).")
            if status not in VALID_PARITY_STATUS:
                raise RuntimeError(
                    f"CLI_FLAG_PARITY[({sub!r}, {flag!r})] has unknown status {status!r}.")
            gaps.append({"kind": "flag", "subcommand": sub, "flag": flag,
                         "present_in": list(present),
                         "missing_from": [l for l in scope if l not in present],
                         "status": status, "reason": reason})

    # The anchor-lost direction, the half TODO #238's deleted CLI_SUPPORT table
    # never had: an acknowledgement whose gap is gone must be removed, or the
    # next reader inherits a reason for something that is no longer true.
    orphan_flags = sorted(set(CLI_FLAG_PARITY) - used_flag)
    if orphan_flags:
        raise RuntimeError(
            f"CLI_FLAG_PARITY entries matching no derived gap: {orphan_flags}. The flag "
            f"is now at parity (or was renamed/removed) -- delete the entry.")
    orphan_subs = sorted(set(CLI_SUBCOMMAND_PARITY) - used_sub)
    if orphan_subs:
        raise RuntimeError(
            f"CLI_SUBCOMMAND_PARITY entries matching no derived gap: {orphan_subs}. "
            f"Delete the entry.")
    return gaps


def build_cross_impl_gaps(cli_support):
    """Any tag not dispatched by all four CLIs, derived rather than curated.

    The curated list this replaces claimed two gaps that had both closed:
    `hpks-xmss` as Python-only (all three have shipped it since TODO #208) and
    `hcred` as missing from Go (the Go CLI dispatches cred-issue/-prove/-verify).
    Nothing checked either claim.  TODO #238.
    """
    gaps = []
    for tag in sorted(cli_support):
        impls = cli_support[tag]
        missing = sorted(i for i, ok in impls.items() if not ok)
        if not missing:
            continue
        notes = [GAP_REASONS[(tag, lang)] for lang in missing
                 if (tag, lang) in GAP_REASONS]
        gaps.append(dict(feature=f"{tag} algo tag",
                          present_in=sorted(i for i, ok in impls.items() if ok),
                          missing_from=missing,
                          note=" ".join(notes) if notes else None))
    return gaps + CROSS_IMPL_GAPS_CURATED


def build_cli_binding(pid, algo_subcommand_tags):
    """How the CLI reaches this protocol.

    `algo_flag` -- an --algo tag, plus every subcommand whose choices list carries
    it.  `subcommand` -- no tag at all; the protocol IS its subcommands (aPAKE).
    `subcommand_flag` -- a variant selected by a flag on an existing subcommand
    (`fpe --v3`, `twk --v3`; TODO #255).
    Recording this is what let aPAKE be filed under the same `protocols` array as
    everything else instead of a second parallel section (TODO #238 Part C).
    """
    if pid in FLAG_VARIANT_PROTOCOLS:
        sub, flag = FLAG_VARIANT_PROTOCOLS[pid]
        return {"kind": "subcommand_flag", "subcommands": [sub], "flag": flag}
    subs = sorted(sc for sc, tags in algo_subcommand_tags.items() if pid in tags)
    own = sorted(sc for sc, target in SUBCOMMAND_PROTOCOLS.items() if target == pid)
    if subs:
        binding = {"kind": "algo_flag", "algo_tag": pid, "subcommands": subs}
        if own:
            # e.g. hpks-t: `verify --algo hpks-t`, but signing goes through the
            # four threshold-* subcommands.
            binding["subcommands"] = sorted(set(subs) | set(own))
        return binding
    if own:
        return {"kind": "subcommand", "subcommands": own}
    return {"kind": "none", "subcommands": []}


def build_protocols(priv_algos, pem_labels, cli_support, algo_subcommand_tags):
    protocols = []
    all_ids = sorted(set(priv_algos) | set(SECURITY))
    # genpkey's one hand-appended tag (not in _PRIV_ALGOS) has PEM labels that follow
    # the same PRIVATE/PUBLIC KEY naming convention -- look them up explicitly.
    extra_priv_labels = {"hcred": "HERRADURA HCRED PRIVATE KEY"}
    for pid in all_ids:
        entry = {
            "id": pid,
            "name": PROTOCOL_NAME.get(pid, pid),
            "kind": PROTOCOL_KIND.get(pid, "encryption"),
        }
        priv_label = priv_algos.get(pid) or extra_priv_labels.get(pid)
        if priv_label:
            pub_label = priv_label.replace("PRIVATE", "PUBLIC")
            labels = {"private_key": priv_label}
            if pub_label in pem_labels.values() or pub_label != priv_label:
                labels["public_key"] = pub_label
            entry["pem_labels"] = labels
        entry["cli_binding"] = build_cli_binding(pid, algo_subcommand_tags)
        if pid in cli_support:
            entry["cli_support"] = cli_support[pid]
        if pid in SECURITY:
            entry["security"] = SECURITY[pid]
        else:
            entry["security"] = {"status": "research", "notes": "Not yet classified -- see spec/README.md."}
        protocols.append(entry)
    return protocols


def _resolve(expr, env):
    """Best-effort numeric resolution of a simple `NAME / N` style C expression
    against a dict of already-known integer constants; falls back to the raw
    expression string if it can't be resolved (e.g. unknown identifier)."""
    if isinstance(expr, int):
        return expr
    # TODO #295: the divisor may itself be a named constant.  WOTS_L1 was the
    # literal 64 with "KEYBITS / log2(W) = 256/4" in its comment; #295 made it
    # (KEYBITS / WOTS_LOG2W) so that WOTS_LOG2W governs the digit width instead
    # of being restated as `4` and `0xF` at the call sites.  Resolving only
    # NAME / <digits> turned that into the STRING "KEYBITS / WOTS_LOG2W" in
    # spec/, which --check caught as staleness.
    m = re.fullmatch(r"([A-Z_][A-Z0-9_]*)\s*/\s*([A-Z_][A-Z0-9_]*|\d+)", expr)
    if m and m.group(1) in env:
        rhs = m.group(2)
        div = env.get(rhs) if not rhs.isdigit() else int(rhs)
        if isinstance(div, int) and div:
            return env[m.group(1)] // div
    return expr


def build_parameters():
    h_src = read(HERRADURA_H)
    params = {}
    env = {}
    keybits = extract_const_int(h_src, "KEYBITS")
    if keybits:
        params["classical"] = {"keybits": keybits}
        env["KEYBITS"] = keybits
    stern = {}
    for name, key in [("SDF_N_ROWS", "n_rows"), ("SDF_T", "t"), ("SDF_ROUNDS", "rounds_demo"),
                       ("SDF_PRODUCTION_ROUNDS", "rounds_production"), ("SDF_SYNBYTES", "syndrome_bytes")]:
        v = extract_const_int(h_src, name)
        if v is not None:
            v = _resolve(v, env)
            stern[key] = v
            if isinstance(v, int):
                env[name] = v
    if stern:
        params["stern_f"] = stern
    zkp = {}
    for name, key in [("ZKP_NL_DEFAULT_N", "n_default"), ("ZKP_NL_DEMO_ROUNDS", "rounds_demo"),
                       ("ZKP_NL_PROD_ROUNDS", "rounds_production"), ("ZKP_NL_MAX_N", "n_max")]:
        v = extract_const_int(h_src, name)
        if v:
            zkp[key] = v
    if zkp:
        params["zkp_nl"] = zkp
    wots = {}
    for name, key in [("WOTS_LOG2W", "log2_w"), ("WOTS_L1", "l1"), ("WOTS_L2", "l2"), ("WOTS_L", "l_total")]:
        v = extract_const_int(h_src, name)
        if v:
            v = _resolve(v, env)          # TODO #295: WOTS_L1 is (KEYBITS / WOTS_LOG2W)
            wots[key] = v
            if isinstance(v, int):
                env[name] = v
    if wots:
        params["wots"] = wots
    rnl_n = extract_const_int(h_src, "RNL_N")
    if rnl_n:
        params["hkex_rnl"] = {"n": rnl_n}

    # TODO #272.  RING_MAX_K lives in herradura_cli.c rather than herradura.h,
    # because the ring signature is a CLI-level composition -- but it is a
    # genuine protocol constant, not one implementation's buffer size: it is on
    # the wire (the signature declares k), all four readers reject a larger k,
    # and since #272 all four writers refuse to produce one.  Recording it here
    # is what the item asked for; nothing in spec/ or SPEC.md named it before,
    # which is how three of the four CLIs came to sign rings that no verifier
    # anywhere would accept.
    ring_max_k = extract_const_int(read(CLI_C), "RING_MAX_K")
    if ring_max_k:
        params["hpks_ring"] = {"k_max": ring_max_k}
    params["_note"] = ("Assembly/Arduino targets use reduced demo parameters: Stern-F N=32 t=2 rounds=4 "
                        "(vs. the C/Go/Python values above), GF arithmetic on 32-bit operands instead of 256-bit. "
                        "See CLAUDE.md 'Protocol Stack' and TODO.md #133.")
    return params


def generate():
    py_src = read(HERRADURA_PY)
    codec_src = read(CODEC_H)

    priv_algos = extract_priv_algos(py_src)
    pem_labels_all = extract_pem_labels(codec_src)

    # Sanity check: every curated SECURITY/CLI_SUPPORT tag must exist somewhere
    # in the mechanically extracted surface (priv_algos, or any subcommand's
    # choices list) -- catches renamed/removed algo tags going stale in this file.
    subcommand_vars = ["kx", "en", "de", "sg", "vf", "ef", "df", "dg"]
    all_choice_tags = set()
    for var in subcommand_vars:
        c = extract_choices(py_src, var)
        if c:
            all_choice_tags.update(c)
    # genpkey's choices is `list(_PRIV_ALGOS) + ['hcred']` (not a literal list, so
    # extract_choices can't regex it) -- 'hcred' is genpkey's one hand-appended tag.
    genpkey_extra = {"hcred"} if "gp.add_argument('--algo', required=True, choices=list(_PRIV_ALGOS) + ['hcred'])" in py_src else set()
    known_tags = set(priv_algos) | all_choice_tags | genpkey_extra

    # Subcommands, from the argparse subparser list.  SUBCOMMAND_PROTOCOLS and
    # UNFILED_CLI_SURFACE are both validated against this, so a renamed or new
    # subcommand fails --check rather than quietly leaving the spec incomplete.
    subcommands = extract_subcommands(py_src)
    bound = set(SUBCOMMAND_PROTOCOLS) | set(UNFILED_CLI_SURFACE)
    algo_subcommands = {"genpkey", "kex", "enc", "dec", "sign", "verify",
                        "encfile", "decfile", "dgst"}
    unaccounted = set(subcommands) - bound - algo_subcommands
    if unaccounted:
        raise RuntimeError(
            f"CLI subcommand(s) this spec does not account for: {sorted(unaccounted)}. "
            f"Either bind them to a protocol in SUBCOMMAND_PROTOCOLS, or record why they "
            f"reach none in UNFILED_CLI_SURFACE (TODO #238 Part C)."
        )
    dangling = bound - set(subcommands)
    if dangling:
        raise RuntimeError(
            f"SUBCOMMAND_PROTOCOLS/UNFILED_CLI_SURFACE name subcommand(s) herradura.py no "
            f"longer defines: {sorted(dangling)}. Update generate_spec.py."
        )

    # Protocol ids reached only through a subcommand carry no --algo tag, so they
    # are legitimately absent from known_tags.
    subcommand_only_ids = (set(SUBCOMMAND_PROTOCOLS.values())
                            | set(FLAG_VARIANT_PROTOCOLS)) - known_tags
    stale = set(SECURITY) - known_tags - subcommand_only_ids
    if stale:
        raise RuntimeError(
            f"spec/generate_spec.py's curated tables reference algo tag(s) not found in "
            f"HerraduraCli/herradura.py's _PRIV_ALGOS or any --algo choices list: {sorted(stale)}. "
            f"Either the tag was renamed/removed in source (update generate_spec.py), or this is a "
            f"typo in the curated table."
        )
    # The reverse direction: a tag the CLIs dispatch but nothing in this file
    # classifies.  `hybrid-rnl-stern` sat in that hole -- a shipped `kex --algo`
    # value in all three CLIs, with a SECURITY.md paragraph of its own, and no
    # protocol entry, because build_protocols keyed off _PRIV_ALGOS | SECURITY and
    # it is in neither (TODO #238).
    unclassified = known_tags - set(SECURITY)
    if unclassified:
        raise RuntimeError(
            f"algo tag(s) the CLIs accept but generate_spec.py's SECURITY table does not "
            f"classify: {sorted(unclassified)}. Add a SECURITY entry (and a SECURITY.md row) "
            f"rather than letting the tag ship unclassified."
        )

    # TODO #255: a flag-variant protocol must name a real subparser AND a real
    # flag on it, or the binding is a claim about a CLI surface that is not there.
    for pid, (sub, flag) in sorted(FLAG_VARIANT_PROTOCOLS.items()):
        if sub not in subcommands:
            raise RuntimeError(
                f"FLAG_VARIANT_PROTOCOLS[{pid!r}] names subcommand {sub!r}, which "
                f"herradura.py does not define.")
        if f"{sub[:2]}.add_argument('{flag}'" not in py_src:
            raise RuntimeError(
                f"FLAG_VARIANT_PROTOCOLS[{pid!r}] claims `{sub} {flag}`, but "
                f"herradura.py's {sub!r} subparser does not add {flag!r}.")

    # cli_support, derived per tag from each CLI's own dispatch source.
    c_tags = extract_cli_tags(read(CLI_C), known_tags)
    go_tags = extract_cli_tags(read(CLI_GO), known_tags)
    java_tags = extract_cli_tags(read(CLI_JAVA), known_tags)
    cli_support = {tag: {"c": tag in c_tags, "go": tag in go_tags,
                          "python": True, "java": tag in java_tags}
                    for tag in sorted(known_tags)}

    # TODO #267: the same treatment one level down -- the per-subcommand FLAG
    # matrix, derived from each CLI's own argument parser exactly as cli_support
    # is derived from each CLI's own dispatch.
    flags_by_lang = {
        "python": extract_flags_python(py_src),
        "c":      extract_flags_c(read(CLI_C)),
        "go":     extract_flags_go(read(CLI_GO)),
        "java":   extract_flags_java(read(CLI_JAVA)),
    }
    langs = ("c", "go", "java", "python")
    # The union, not Python's list: `threshold-verify` is a Go-only subcommand
    # and was invisible to a spec keyed on the Python CLI's subparsers.
    all_subcommands = sorted(set().union(*(set(d) for d in flags_by_lang.values())))
    subcommand_impls = {sub: sorted(l for l in langs if sub in flags_by_lang[l])
                        for sub in all_subcommands}
    flag_matrix = {}
    for sub in all_subcommands:
        every_flag = sorted(set().union(*(flags_by_lang[l].get(sub, set()) for l in langs)))
        flag_matrix[sub] = {f: {l: f in flags_by_lang[l].get(sub, set()) for l in langs}
                            for f in every_flag}
    cli_surface_gaps = build_cli_surface_gaps(flag_matrix, subcommand_impls)
    cli_flag_value_gaps = build_cli_flag_value_gaps(flag_matrix, py_src)

    # tag lists per --algo subcommand, needed both for cli_binding and below.
    # genpkey's choices is `list(_PRIV_ALGOS) + ['hcred']`, so hcred is a real
    # --algo tag there even though it is not in _PRIV_ALGOS; without it hcred's
    # cli_binding came out as subcommand-only.
    algo_subcommand_tags = {"genpkey": sorted(set(priv_algos) | genpkey_extra)}
    for subcmd, var in sorted(PY_SUBPARSER_VARS.items()):
        choices = extract_choices(py_src, var)
        if choices is not None:
            algo_subcommand_tags[subcmd] = choices

    protocols = build_protocols(priv_algos, pem_labels_all, cli_support, algo_subcommand_tags)

    # wire_format_labels = every PEM_* label not already attached to a protocol as private/public key
    used_labels = set()
    for p in protocols:
        used_labels.update(p.get("pem_labels", {}).values())
    wire_labels = {k: v for k, v in pem_labels_all.items() if v not in used_labels}

    # Every subcommand, not only the nine that take --algo.  Sixteen of the
    # twenty-five were absent entirely before TODO #238, which is how aPAKE
    # managed to be invisible to a spec whose stated job is enumerating the CLI.
    cli_subcommands = {}
    for subcmd in subcommands:
        if subcmd in algo_subcommand_tags:
            cli_subcommands[subcmd] = {
                "implementations": subcommand_impls[subcmd],
                "has_algo_flag": True,
                "algos": {tag: sorted([impl for impl, ok in cli_support.get(tag, {}).items() if ok])
                          for tag in algo_subcommand_tags[subcmd]},
            }
        elif subcmd in SUBCOMMAND_PROTOCOLS:
            cli_subcommands[subcmd] = {
                "implementations": subcommand_impls[subcmd],
                "has_algo_flag": False,
                "protocol": SUBCOMMAND_PROTOCOLS[subcmd],
            }
        else:
            cli_subcommands[subcmd] = {
                "implementations": subcommand_impls[subcmd],
                "has_algo_flag": False,
                "protocol": None,
                "unfiled_reason": UNFILED_CLI_SURFACE[subcmd],
            }

    spec = {
        "suite": "HerraduraKEx",
        "spec_version": SPEC_VERSION,
        "generated_from": [
            "HerraduraCli/herradura.py (_PRIV_ALGOS dict, argparse choices=)",
            "HerraduraCli/herradura_codec.h (PEM_* constants)",
            "herradura.h (protocol parameter #define constants)",
            "herradura/herradura.go (Stern-F parameter const block)",
            "each CLI's own argument parser (per-subcommand --flag matrix, TODO #267)",
        ],
        "protocols": protocols,
        "wire_format_labels": dict(sorted(wire_labels.items())),
        "cli_subcommands": cli_subcommands,
        "cross_implementation_gaps": build_cross_impl_gaps(cli_support),
        "cli_flag_matrix": flag_matrix,
        "cli_surface_gaps": cli_surface_gaps,
        "cli_flag_value_gaps": cli_flag_value_gaps,
        "unfiled_cli_surface": [
            {"subcommand": sc, "reason": UNFILED_CLI_SURFACE[sc]}
            for sc in subcommands if sc in UNFILED_CLI_SURFACE
        ],
        "parameters": build_parameters(),
        "key_label_acceptance": build_key_label_acceptance(priv_algos, pem_labels_all),
        "pem_der_items": build_pem_der_items(
            list(pem_labels_all.values())
            + [l for t in key_tag_labels(priv_algos, pem_labels_all).values() for l in t]),
        "pem_der_field_caps": build_pem_der_field_caps(),
        "key_parameter_sets": build_key_param_sets(),
        "enc_integrity": build_enc_integrity(extract_choices(py_src, "en"),
                                             extract_choices(py_src, "de")),
    }
    return spec


def validate_schema(spec, required=False):
    """Validate the generated document against its own JSON Schema.

    The schema is shipped for consumers but nothing ever checked the spec against
    it, so a generator change could add a field the schema forbids
    (`additionalProperties: false` on several objects) and nobody would find out
    until a consumer's validator did.  TODO #238 added `cli_binding`,
    `unfiled_cli_surface`, and the `pake` kind, all of which needed schema edits
    to stay valid -- exactly the drift this catches.

    `jsonschema` is the suite's only third-party dependency anywhere, and it is a
    tooling one, so a bare `python3` must still be able to run the rest of the
    check: locally, an absent package is a NOTE.  In CI it is not, because a
    silently-skipped validation is the same failure this whole item is about --
    `ci.yml` installs the package and passes --require-schema, which turns the
    NOTE into an error.
    """
    try:
        import jsonschema
    except ImportError:
        if required:
            print("SCHEMA: --require-schema was passed but the `jsonschema` package is "
                  "not importable, so the generated spec was NOT validated against "
                  "spec/herradura-protocol-spec.schema.json.\n"
                  "  Install it (apt: python3-jsonschema, pip: jsonschema) or drop "
                  "--require-schema to downgrade this to a NOTE.")
            return 1
        print("NOTE: jsonschema not installed — skipped validating against "
              "spec/herradura-protocol-spec.schema.json. Pass --require-schema to "
              "make this an error (CI does).")
        return 0
    schema = json.load(open(SCHEMA_PATH))
    try:
        jsonschema.validate(spec, schema)
    except jsonschema.ValidationError as exc:
        print(f"SCHEMA: generated spec does not validate against its own schema:\n  "
              f"{exc.message}\n  at: {'/'.join(str(x) for x in exc.absolute_path)}")
        return 1
    print("OK: validates against spec/herradura-protocol-spec.schema.json.")
    return 0



_GEN_BANNER = ("GENERATED by spec/generate_spec.py (TODO #274) -- DO NOT EDIT.\n"
               "Regenerate with `python3 spec/generate_spec.py`; "
               "`--check` fails if this file is stale.")


def emit_c_flag_table(flags_c, valued_c, help_lines=()):
    """C's allow-list, as a header the dependency-free CLI can #include.

    Two arrays per subcommand: every flag, and the subset that TAKES A VALUE.
    The second is what lets check_unknown_flags tell a typo from a flag-shaped
    value without also swallowing a typo that follows a boolean flag."""
    out = ["/* " + _GEN_BANNER.replace("\n", "\n * ") + " */",
           "#ifndef HKX_CLI_FLAG_TABLE_H",
           "#define HKX_CLI_FLAG_TABLE_H", ""]
    for sub in sorted(flags_c):
        ident = sub.replace("-", "_")
        names = ", ".join('"%s"' % f for f in sorted(flags_c[sub]))
        vals = ", ".join('"%s"' % f for f in sorted(valued_c.get(sub, [])))
        out.append("static const char *const hkx_flags_%s[] = {%s};" % (ident, names or "0"))
        out.append("static const char *const hkx_valued_%s[] = {%s};" % (ident, vals or "0"))
    out += ["",
            "typedef struct { const char *cmd; const char *const *flags; int n;",
            "                 const char *const *valued; int nv; } HkxFlagSet;",
            "",
            "static const HkxFlagSet HKX_FLAG_SETS[] = {"]
    for sub in sorted(flags_c):
        ident = sub.replace("-", "_")
        out.append('    {"%s", hkx_flags_%s, %d, hkx_valued_%s, %d},'
                   % (sub, ident, len(flags_c[sub]), ident, len(valued_c.get(sub, []))))
    out += ["};",
            "static const int HKX_FLAG_SETS_N ="
            " (int)(sizeof(HKX_FLAG_SETS) / sizeof(HKX_FLAG_SETS[0]));",
            "",
            "/* usage()'s synopsis (TODO #339). */",
            "static const char HKX_HELP_SYNOPSIS[] ="]
    out += _c_string_lines(help_lines) or ['    ""']
    out[-1] += ";"
    out += ["",
            "#endif /* HKX_CLI_FLAG_TABLE_H */",
            ""]
    return "\n".join(out)


def emit_java_flag_table(flags_java, help_lines=(), bool_flags=()):
    """Java's allow-list.  Keyed WITHOUT the leading dashes, because that is how
    parseOpts keys its option map."""
    out = ["package herradurakex;", "",
           "import java.util.Arrays;",
           "import java.util.Collections;",
           "import java.util.HashMap;",
           "import java.util.HashSet;",
           "import java.util.Map;",
           "import java.util.Set;", "",
           "/** " + _GEN_BANNER.replace("\n", "\n *  ") + " */",
           "final class CliFlagTable {",
           "    private CliFlagTable() { }", "",
           "    static final Map<String, Set<String>> FLAGS;", "",
           "    static {",
           "        Map<String, Set<String>> m = new HashMap<>();"]
    for sub in sorted(flags_java):
        names = ", ".join('"%s"' % f.lstrip("-") for f in sorted(flags_java[sub]))
        out.append('        m.put("%s", new HashSet<>(Arrays.asList(%s)));' % (sub, names))
    out += ["        FLAGS = Collections.unmodifiableMap(m);",
            "    }", "",
            "    /** Flags that take no value (TODO #381); every other flag takes one. */",
            "    static final Set<String> BOOLEAN = Collections.unmodifiableSet(new HashSet<>(Arrays.asList(%s)));"
            % ", ".join('"%s"' % f for f in sorted(bool_flags)), "",
            "    /** --help's synopsis (TODO #339). */",
            "    static final String HELP_SYNOPSIS ="]
    body = ['        "%s\\n"' % l.replace("\\", "\\\\").replace('"', '\\"') for l in help_lines]
    out += [b + " +" for b in body[:-1]] + [(body[-1] if body else '        ""') + ";"]
    out += ["}",
            ""]
    return "\n".join(out)


# ── Generated --help synopses (TODO #339) ─────────────────────────────────
#
# The C, Go and Java help text was hand-written and had drifted from dispatch:
# C's genpkey line omitted oprf/hcred, Go's banner omitted hpke-stern-kem,
# nl-zkbpp, oprf, hpks-t and 13 of its 26 subcommands.  The flag tables above were
# already derived from each CLI's own parser, so the SYNOPSIS -- which flags each
# subcommand reads and which --algo tags it takes -- is generated from the same
# spec rows and printed by each CLI ahead of its hand-written notes.  Python's
# comes from argparse and needs none of this.
#
# The --algo list for a subcommand is that subcommand's Python choices filtered
# to the tags this CLI dispatches anywhere (spec `cli_subcommands`), so it is
# exactly as fine-grained as the spec's own per-subcommand view.

GO_HELP_BEGIN = "// BEGIN GENERATED help synopsis (spec/generate_spec.py, TODO #339) -- DO NOT EDIT."
GO_HELP_END = "// END GENERATED help synopsis"
_HELP_WIDTH = 79


def _wrap_words(words, first, indent):
    """Greedy word wrap: `first` prefixes line one, `indent` the rest."""
    lines, cur, prefix = [], [], first
    for w in words:
        if cur and len(prefix) + len(" ".join(cur + [w])) > _HELP_WIDTH:
            lines.append(prefix + " ".join(cur))
            prefix, cur = indent, []
        cur.append(w)
    lines.append((prefix + " ".join(cur)).rstrip())
    return lines


def build_help_synopsis(spec, lang):
    """One CLI's subcommand synopsis, as a list of lines."""
    matrix, subs_spec = spec["cli_flag_matrix"], spec["cli_subcommands"]
    subs = {sub for sub, flags in matrix.items()
            if any(cell[lang] for cell in flags.values())}
    subs |= {sub for sub, row in subs_spec.items() if lang in row["implementations"]}
    pad = max(len(s) for s in subs) + 4
    lines = ["Subcommands and the flags each one reads (generated from this CLI's",
             "own parser by spec/generate_spec.py; the notes below say which are",
             "required):"]
    for sub in sorted(subs):
        flags = sorted(f for f, cell in matrix.get(sub, {}).items() if cell[lang])
        lines += _wrap_words(flags or ["(no flags)"], ("  " + sub).ljust(pad), " " * pad)
        row = subs_spec.get(sub, {})
        if row.get("has_algo_flag"):
            tags = [t for t, impls in row["algos"].items() if lang in impls]
            lines += _wrap_words(tags, " " * pad + "--algo: ", " " * (pad + 8))
            if sub in ("enc", "dec"):   # TODO #414
                words = []
                for r in spec["enc_integrity"]:
                    if r["algo"] in tags and r["integrity"] == "none":
                        words.append(r["algo"])
                    elif r["algo"] in tags and r["integrity"] == "aead-flag":
                        words += [r["algo"], "(unless", "--aead)"]
                if words:
                    lines += _wrap_words(words, " " * pad + "NO INTEGRITY (TODO #414): ",
                                         " " * (pad + 8))
    return lines


def _c_string_lines(lines):
    return ["    \"%s\\n\"" % l.replace("\\", "\\\\").replace('"', '\\"') for l in lines]


def emit_go_help_region(go_src, lines):
    """herradura_cli.go with its generated region replaced.  In place, not a
    second file: build_go.sh compiles herradura_cli.go on its own."""
    if any("`" in l for l in lines):
        raise RuntimeError("a help line contains a backtick; Go's raw string cannot hold it")
    region = "\n".join([GO_HELP_BEGIN, "const helpSynopsis = `" + "\n".join(lines) + "\n`",
                        GO_HELP_END])
    pat = re.compile(re.escape(GO_HELP_BEGIN) + r".*?" + re.escape(GO_HELP_END), re.DOTALL)
    if not pat.search(go_src):
        raise RuntimeError("herradura_cli.go has no generated help region; restore the "
                           "BEGIN/END GENERATED help synopsis markers")
    return pat.sub(lambda _m: region, go_src, count=1)


# ── Key-label acceptance (TODO #366) ──────────────────────────────────────
#
# Until v15.0.0 no CLI compared a key's PEM label with the operation using it:
# each read whatever integers the file held, so `sign --algo hpks-stern` signed
# with an HKEX-GF private exponent, and Go signed HPKS-WOTS with one.  This table
# is the one statement of which key labels each (subcommand, --algo, key flag)
# accepts.  It is CURATED, not extracted -- it is policy -- and emitted into all
# four CLIs below, so they enforce one table rather than four.
#
# Two families are deliberately shared.  GF: hkex-gf, hpks, hpks-nl, hpke and
# hpke-nl are the same GF(2^n)* key pair (SPEC.md §7: "HPKE reuses HKEX-GF key
# pairs").  STERN: hpks-stern and hpke-stern hold the same error vector + seed
# (since TODO #413 an hpke-stern key is only a Stern signing key: enc/dec retired).
# hpke-nl3 is NOT in the GF family: it has its own labels (TUTORIAL: "an
# hpke-nl key is not an hpke-nl3 key").  Public-key slots accept PUBLIC labels
# only; a private key passed as --pubkey was mis-parsed by every CLI before.
# The exception is role "either": HCRED's public-key loaders take the private
# key too, deliberately and correctly (it carries the public fields), in all
# four CLIs and under test (test_cred.sh "proof verify (privkey)").
# `pkey` is absent on purpose: it reads any key.  The threshold rows keep the
# hpks/hpks-nl restriction all four CLIs already applied.
#
# CliTest/test_key_label_matrix.sh runs every row against every key label in
# every CLI, so a row a CLI forgets to enforce fails there.

_KF_GF = ["hkex-gf", "hpks", "hpks-nl", "hpke", "hpke-nl"]
_KF_STERN = ["hpks-stern", "hpke-stern"]
_KF_RNL = ["hkex-rnl"]
_KF_KEM = ["hpke-stern-kem"]

# (subcommand, --algo or "", key flag, "priv" | "pub" | "either", accepted key tags)
KEY_LABEL_SITES = (
    [("kex", "hkex-gf", "--our", "priv", _KF_GF),
     ("kex", "hkex-gf", "--their", "pub", _KF_GF),
     ("kex", "hkex-rnl", "--our", "priv", _KF_RNL),
     ("kex", "hkex-rnl", "--their", "pub", _KF_RNL),
     ("kex", "hybrid-rnl-stern", "--our", "priv", _KF_RNL),
     ("kex", "hybrid-rnl-stern", "--their", "pub", _KF_RNL),
     ("kex", "hybrid-rnl-stern", "--our-kem", "priv", _KF_KEM),
     ("kex", "hybrid-rnl-stern", "--their-kem", "pub", _KF_KEM)]
    + [(sub, algo, flag, role, fam)
       for algo, fam in (("hpke", _KF_GF), ("hpke-nl", _KF_GF), ("hpke-nl3", ["hpke-nl3"]),
                         ("hpke-stern-kem", _KF_KEM))
       for sub, flag, role in (("enc", "--pubkey", "pub"), ("dec", "--key", "priv"))]
    + [(sub, algo, flag, role, fam)
       for algo, fam in (("hpks", _KF_GF), ("hpks-nl", _KF_GF), ("hpks-stern", _KF_STERN),
                         ("hpks-ring", _KF_STERN), ("rnl-sigma", _KF_RNL),
                         ("nl-zkboo", ["hpks-zkp-nl"]), ("nl-zkbpp", ["hpks-zkp-nl"]),
                         ("hpks-xmss", ["hpks-xmss"]), ("hpks-wots", ["hpks-wots"]))
       for sub, flag, role in (("sign", "--key", "priv"),
                               ("verify", "--ring" if algo == "hpks-ring" else "--pubkey", "pub"))]
    # TODO #412: the group an HPKS-T signature is checked against, a comma-
    # separated list (the checkers split it, as they split --ring).
    + [("verify", "hpks-t", "--pubkey", "pub", ["hpks", "hpks-nl"])]
    + [("threshold-commit", "", "--key", "priv", ["hpks", "hpks-nl"]),
       ("threshold-respond", "", "--key", "priv", ["hpks", "hpks-nl"]),
       ("oprf-eval", "", "--key", "priv", ["oprf"]),
       ("pake-register", "", "--key", "priv", ["oprf"]),
       ("pake-demo", "", "--key", "priv", ["oprf"]),
       ("cred-issue", "", "--our", "priv", _KF_STERN),
       ("cred-issue", "", "--in", "either", ["hcred"]),
       ("cred-prove", "", "--in", "priv", ["hcred"]),
       ("cred-verify", "", "--pubkey", "either", ["hcred"]),
       ("cred-verify", "", "--issuer", "pub", _KF_STERN)])

# TODO #367: how many DER INTEGER items each DER-SEQUENCE PEM label carries, as
# (min, max).  Every CLI checks this in its one PEM-to-integers loader, before
# any decoder indexes the list, so "valid DER, wrong arity" is a one-line
# refusal everywhere instead of an index panic (Go) or a traceback (Python).
# A label used by several algorithms (CIPHERTEXT, SIGNATURE) gets the union
# here; the decoder for each algorithm then checks its exact count.  A range
# wider than one marks a documented optional trailing field (the HKEX-RNL
# contributory nonce, whose absence reads as a zero nonce).
PEM_DER_ITEMS = {
    "HERRADURA HKEX-GF PRIVATE KEY": (3, 3),
    "HERRADURA HKEX-GF PUBLIC KEY": (2, 2),
    "HERRADURA HPKS PRIVATE KEY": (3, 3),
    "HERRADURA HPKS PUBLIC KEY": (2, 2),
    "HERRADURA HPKS-NL PRIVATE KEY": (3, 3),
    "HERRADURA HPKS-NL PUBLIC KEY": (2, 2),
    "HERRADURA HPKE PRIVATE KEY": (3, 3),
    "HERRADURA HPKE PUBLIC KEY": (2, 2),
    "HERRADURA HPKE-NL PRIVATE KEY": (3, 3),
    "HERRADURA HPKE-NL PUBLIC KEY": (2, 2),
    "HERRADURA HPKE-NL3 PRIVATE KEY": (3, 3),
    "HERRADURA HPKE-NL3 PUBLIC KEY": (2, 2),
    "HERRADURA HKEX-RNL PRIVATE KEY": (3, 4),
    "HERRADURA HKEX-RNL PUBLIC KEY": (3, 4),
    "HERRADURA HKEX-RNL RESPONSE": (5, 6),
    "HERRADURA HYBRID-RNL-STERN RESPONSE": (8, 8),
    "HERRADURA HPKS-STERN PRIVATE KEY": (3, 3),
    "HERRADURA HPKS-STERN PUBLIC KEY": (3, 3),
    "HERRADURA HPKE-STERN PRIVATE KEY": (3, 3),
    "HERRADURA HPKE-STERN PUBLIC KEY": (3, 3),
    "HERRADURA HPKE-STERN-KEM PRIVATE KEY": (6, 6),
    "HERRADURA HPKE-STERN-KEM PUBLIC KEY": (2, 2),
    "HERRADURA HPKS-WOTS PRIVATE KEY": (2, 2),
    "HERRADURA HPKS-WOTS PUBLIC KEY": (2, 2),
    "HERRADURA HPKS-WOTS SIGNATURE": (2, 2),
    "HERRADURA HPKS-XMSS PRIVATE KEY": (4, 4),
    "HERRADURA HPKS-XMSS PUBLIC KEY": (2, 2),
    "HERRADURA HPKS-XMSS SIGNATURE": (5, 5),
    # TODO #415: (n, k, rounds, D, blob).  The v1 label "HERRADURA HPKS-RING
    # SIGNATURE" (the forgeable OR-composition) has no row: verify names it and
    # refuses it before this table is consulted.
    "HERRADURA HPKS-RING-V2 SIGNATURE": (5, 5),
    "HERRADURA OPRF PRIVATE KEY": (2, 2),
    "HERRADURA OPRF CLIENT STATE": (3, 3),
    "HERRADURA OPRF EVALUATION": (2, 2),
    "HERRADURA PAKE RECORD": (3, 3),
    "HERRADURA HPKST COMMITMENT": (3, 3),
    "HERRADURA HPKST NONCE": (2, 2),
    "HERRADURA HPKST AGGREGATE": (4, 4),
    "HERRADURA HPKST PARTIAL": (2, 2),
    "HERRADURA HPKST SIGNATURE": (4, 4),
    "HERRADURA HCRED CREDENTIAL": (5, 5),
    "HERRADURA SESSION KEY": (2, 2),
    "HERRADURA DIGEST": (1, 1),
    "HERRADURA HDRBG STATE": (2, 2),
    "HERRADURA ENCRYPTED PRIVATE KEY": (6, 6),
    "HERRADURA CIPHERTEXT": (3, 6),
    "HERRADURA SIGNATURE": (4, 5),
}


# ── Key parameter sets (TODO #379) ───────────────────────────────────────────
# Which key sizes `genpkey` makes, per --algo: one row per (algo, --bits value),
# chosen by `--bits` (kept for compatibility) or by `--level` (the size the
# parameters are meant to reach: `demo`, or a classical strength in bits).
# Emitted beside the key-label table into all four CLIs, each of which resolves
# genpkey's --bits / --level against it before generating anything.
#
# A row's `security` is an ESTIMATE with its source; its `status` is the
# protocol's own (SECURITY above) for a row sized to a strength level, and
# "demo" for every other row.  `ports` lists the CLIs that generate and consume
# the row today; the others refuse it by name, pointing at the TODO that closes
# the gap (TODO #379 stage 1: C and Java run only each algorithm's default).
# BITS = -1 marks a row --bits cannot name (an algorithm with no width).
PARAM_LEVELS = ("demo", "128", "192", "256")   # 192 / 256: reserved, no rows yet
PARAM_PORTS = ("py", "go", "c", "java")
PARAM_PORT_GAP_TODO = {"c": 383, "java": 384}  # narrow widths in C / Java
PARAM_FIXED_ALGOS = ("hpks-wots", "hpks-xmss")  # fixed parameters: neither flag
# --bits is validated by the algorithm's own rule, not this table (TODO #283:
# hpks-zkp-nl's n is any even value up to the wire bound 64).
PARAM_OWN_BITS_RULE = ("hpks-zkp-nl",)

_GF_ALGOS = ("hkex-gf", "hpks", "hpks-nl", "hpke", "hpke-nl", "hpke-nl3")
# sqrt(largest prime factor of 2^n - 1): Pohlig-Hellman's cost (TODO #379's pass)
_GF_PH = {32: "2^8", 64: "2^11", 128: "2^23", 256: "2^36"}
# TODO #382: SecurityProofsCode/stern_f_parameter_selection.py's BJMM / Prange
# figures (k = N/2, t = N/16); 2304 is the long form's 128-bit set.
_STERN_SEC = {256: "~2^24 by BJMM, ~2^38 by Prange (SECURITY.md)"}
_STERN_LONG = (2304, "~2^137 classical (BJMM), ~2^106 quantum (Grover-over-Prange); "
                     "SecurityProofs-5.md 11.8.3")

PARAM_LEVEL_NOTES = {a: "the GF(2^n)* family is demo-only at every width "
                        "(binary-field discrete logs fall to index calculus)"
                     for a in _GF_ALGOS + ("oprf",)}
PARAM_LEVEL_NOTES["hcred"] = ("hcred's own key (a Ring-LWR and syndrome-decoding pair "
                              "proved in ZKBoo) has no 128-bit set; the ISSUER's "
                              "hpks-stern key does: genpkey --algo hpks-stern --level 128")


def _param_rows():
    rows = []   # (algo, bits, level, default, security, ports, withdrawn)
    all4 = PARAM_PORTS
    # TODO #383 stage 1 (C) and TODO #384 (Java): every CLI runs the GF family
    # at every width.
    # TODO #385: the OPRF (2HashDH over GF(2^n)*) runs at the same four widths.
    for a in _GF_ALGOS + ("oprf",):
        for w in (32, 64, 128, 256):
            rows.append((a, w, "demo" if w == 256 else None, w == 256,
                         "at most %s (Pohlig-Hellman; index calculus is cheaper)" % _GF_PH[w],
                         all4, None))
    # TODO #383 stage 4: C runs hkex-rnl (and rnl-sigma, the hybrid) at every
    # ring; Java already did.
    for w in (32, 64, 128, 256):
        rows.append(("hkex-rnl", w, "demo" if w == 256 else None, False,
                     "far below 2^87 (not estimated)", all4, None))
    rows.append(("hkex-rnl", 512, None, False, "~2^87 classical, ~2^79 quantum", (),
                 "SECURITY.md withdraws ring dimension 512 (HKEX-RNL-128): about 87 classical "
                 "bits, short of the 128 it was claimed to give"))
    rows.append(("hkex-rnl", 1024, "128", True,
                 ">= 2^128 classical (conjectured; SECURITY.md)", all4, None))
    for a in ("hpks-stern", "hpke-stern", "hcred"):
        for w in (32, 64, 128, 256):
            sec = _STERN_SEC.get(w, "below 2^24")
            if a == "hcred":
                sec = "research construction; its Stern-F half " + sec
            # TODO #383 stages 2 and 3 (C) and TODO #384 (Java): every CLI runs
            # Stern-F (hpks-stern, hpke-stern) and hcred at every width.
            rows.append((a, w, "demo" if w == 256 else None, w == 256, sec, all4, None))
    # TODO #382 stage 2: the long form, N = 2304 (k = 1152, t = 144), in every CLI.
    for a in ("hpks-stern", "hpke-stern"):
        rows.append((a, _STERN_LONG[0], "128", False, _STERN_LONG[1], all4, None))
    rows.append(("hpke-stern-kem", -1, "128", True,
                 "2^128 classical by its parameters (BIKE-128)", all4, None))
    rows.append(("hpks-zkp-nl", 8, "demo", True,
                 "demonstration keypair; no security claim", all4, None))
    return rows


def build_key_param_sets():
    rows, seen = [], set()
    for algo, bits, level, default, sec, ports, withdrawn in _param_rows():
        if algo not in SECURITY:
            raise RuntimeError("parameter set for unknown algo %r" % algo)
        if (algo, bits) in seen:
            raise RuntimeError("duplicate parameter set %r" % ((algo, bits),))
        seen.add((algo, bits))
        if level is not None and level not in PARAM_LEVELS:
            raise RuntimeError("parameter set %r has unknown level %r" % ((algo, bits), level))
        if any(p not in PARAM_PORTS for p in ports):
            raise RuntimeError("parameter set %r names unknown ports %r" % ((algo, bits), ports))
        if withdrawn and (ports or level or default):
            raise RuntimeError("withdrawn parameter set %r must be refused everywhere"
                               % ((algo, bits),))
        rows.append({"algo": algo, "bits": bits, "level": level, "default": bool(default),
                     "status": ("withdrawn" if withdrawn else
                                SECURITY[algo]["status"] if level not in (None, "demo")
                                else "demo"),
                     "security": sec, "ports": list(ports), "withdrawn": withdrawn})
    by_algo = {}
    for r in rows:
        by_algo.setdefault(r["algo"], []).append(r)
    for algo, rs in by_algo.items():
        if sum(r["default"] for r in rs) != 1:
            raise RuntimeError("algo %r needs exactly one default parameter set" % algo)
        for lvl in PARAM_LEVELS:
            if sum(r["level"] == lvl for r in rs) > 1:
                raise RuntimeError("algo %r has two %r parameter sets" % (algo, lvl))
        if not any(r["default"] and set(r["ports"]) == set(PARAM_PORTS) for r in rs):
            raise RuntimeError("algo %r's default parameter set must run in every CLI" % algo)
    for a in PARAM_FIXED_ALGOS + PARAM_OWN_BITS_RULE + tuple(PARAM_LEVEL_NOTES):
        if a not in SECURITY:
            raise RuntimeError("parameter-set list names unknown algo %r" % a)
    return {"levels": list(PARAM_LEVELS), "fixed_algos": list(PARAM_FIXED_ALGOS),
            "own_bits_rule": list(PARAM_OWN_BITS_RULE),
            "port_gap_todo": {k: v for k, v in PARAM_PORT_GAP_TODO.items()},
            "level_notes": dict(sorted(PARAM_LEVEL_NOTES.items())), "rows": rows}


def _ps_ports(r):
    return " ".join(r["ports"])


# ── Integrity of each enc/dec --algo (TODO #414) ──────────────────────────
#
# #410's wrong-secret matrix found that `dec` under the WRONG key exits 0 and
# writes garbage for every mode without a tag, and nothing said which modes those
# are.  This table is that statement.  integrity: "tag" (dec verifies a tag and
# exits non-zero on a mismatch), "none" (no tag: a modified ciphertext or a wrong
# key decrypts to wrong bytes with exit 0), or "aead-flag" (hske-nla1: none unless
# --aead, i.e. a format-tag-2 ciphertext).  malleability is what a one-bit flip
# of the ciphertext's E field does to the plaintext, MEASURED in all four CLIs by
# CliTest/test_wrong_secret_matrix.sh: "predictable" (a fixed pattern, the same
# under every key and plaintext: the mode is linear in E), or "diffuse" (about
# half the block, varying with the key, but still undetected).  Every CLI prints
# `<sub>: warning: <warning>` to stderr on enc and dec of a mode with no tag,
# from the generated copy of this table, and the matrix holds them to it.
_SYM_ADVICE = ("for integrity use hske-duplex, hske-duplex3, hske-nla1 --aead or "
               "encfile")
_ASYM_ADVICE = ("no asymmetric mode has a tag: sign the ciphertext, or agree a key "
                "with kex and use an authenticated symmetric mode")
_LIN = "flipping ciphertext bit j flips plaintext bits j and j +/- n/4 under every key"
_LIN_E = "flipping bit j of E flips plaintext bits j and j +/- n/4 under every key"
_DIFFUSE = "a flipped bit scrambles about half the block, and nothing detects it"
ENC_INTEGRITY = {
    "hske":           ("none", "predictable", _LIN, _SYM_ADVICE),
    "hske-nla1":      ("aead-flag", "predictable",
                       "without --aead, flipping ciphertext bit j flips plaintext bit j",
                       _SYM_ADVICE),
    "hske-nla2":      ("none", "diffuse", _DIFFUSE, _SYM_ADVICE),
    "hske-nla3":      ("none", "diffuse", _DIFFUSE, _SYM_ADVICE),
    "hske-duplex":    ("tag", None, None, None),
    "hske-duplex3":   ("tag", None, None, None),
    "hpke":           ("none", "predictable", _LIN_E, _ASYM_ADVICE),
    "hpke-nl":        ("none", "diffuse", _DIFFUSE, _ASYM_ADVICE),
    "hpke-nl3":       ("none", "diffuse", _DIFFUSE, _ASYM_ADVICE),
    "hpke-stern-kem": ("none", "predictable",
                       _LIN_E + "; a corrupt syndrome decrypts to garbage by design, as "
                         "implicit rejection requires (TODO #235)", _ASYM_ADVICE),
}


def build_enc_integrity(enc_tags, dec_tags):
    if set(enc_tags) != set(dec_tags):
        raise RuntimeError("enc and dec take different --algo tags: %r"
                           % sorted(set(enc_tags) ^ set(dec_tags)))
    if set(ENC_INTEGRITY) != set(enc_tags):
        raise RuntimeError("ENC_INTEGRITY does not match enc's --algo tags: %r"
                           % sorted(set(ENC_INTEGRITY) ^ set(enc_tags)))
    rows = []
    for algo in enc_tags:
        integ, mall, detail, advice = ENC_INTEGRITY[algo]
        if integ not in ("tag", "none", "aead-flag"):
            raise RuntimeError("ENC_INTEGRITY[%r]: unknown integrity %r" % (algo, integ))
        if (integ == "tag") != (mall is None):
            raise RuntimeError("ENC_INTEGRITY[%r]: a tagged mode has no malleability "
                               "entry, an untagged one must have one" % algo)
        warning = None
        if integ != "tag":
            warning = ("--algo %s has no integrity check: a modified ciphertext or the "
                       "wrong key decrypts to wrong bytes with exit 0 (%s); %s (TODO #414)"
                       % (algo, detail, advice))
        rows.append({"algo": algo, "integrity": integ, "malleability": mall,
                     "warning": warning})
    return rows


def _c_str(s):
    return '"%s"' % s.replace("\\", "\\\\").replace('"', '\\"')


def emit_c_enc_integrity(rows):
    out = ["/* TODO #414: each enc/dec --algo's integrity: \"tag\", \"none\", or \"aead-flag\"",
           " * (none unless --aead).  warning: what enc/dec print to stderr when there is",
           " * no tag (0 for a tagged mode). */",
           "typedef struct { const char *algo, *integrity, *warning; } HkxEncIntegrity;", "",
           "static const HkxEncIntegrity HKX_ENC_INTEGRITY[] = {"]
    for r in rows:
        out.append("    {\"%s\", \"%s\",\n     %s}," % (r["algo"], r["integrity"],
                                                       _c_str(r["warning"]) if r["warning"] else "0"))
    out += ["};",
            "static const int HKX_ENC_INTEGRITY_N ="
            " (int)(sizeof(HKX_ENC_INTEGRITY) / sizeof(HKX_ENC_INTEGRITY[0]));", ""]
    return out


def emit_java_enc_integrity(rows):
    out = ["    /** TODO #414: {algo, integrity (tag | none | aead-flag), stderr warning|\"\"}. */",
           "    static final String[][] ENC_INTEGRITY = {"]
    for r in rows:
        out.append("        {\"%s\", \"%s\",\n         %s}," % (r["algo"], r["integrity"],
                                                             _c_str(r["warning"] or "")))
    out += ["    };", ""]
    return out


def emit_go_enc_integrity(rows):
    out = ["// TODO #414: each enc/dec --algo's integrity (tag | none | aead-flag) and the",
           "// warning enc/dec print to stderr when there is no tag.",
           "var encIntegrity = map[string][2]string{"]
    for r in rows:
        out.append("\t\"%s\": {\"%s\",\n\t\t%s}," % (r["algo"], r["integrity"],
                                                 _c_str(r["warning"] or "")))
    out += ["}", ""]
    return out


def emit_py_enc_integrity(rows):
    out = ["# TODO #414: each enc/dec --algo's integrity (tag | none | aead-flag) and the",
           "# warning enc/dec print to stderr when there is no tag.",
           "_ENC_INTEGRITY = {"]
    for r in rows:
        out.append("    %r: (%r,\n        %r)," % (r["algo"], r["integrity"], r["warning"]))
    out += ["}", ""]
    return out


def emit_c_param_sets(ps):
    out = ["/* TODO #379: genpkey's key parameter sets (--bits / --level). bits -1: no",
           " * --bits value names the row.  ports: the CLIs that run the row today. */",
           "typedef struct { const char *algo; int bits; const char *level; int is_default;",
           "                 const char *status, *security, *ports, *withdrawn; } HkxParamSet;", "",
           "static const HkxParamSet HKX_PARAM_SETS[] = {"]
    for r in ps["rows"]:
        out.append('    {"%s", %d, %s, %d, "%s",\n     "%s", "%s", %s},'
                   % (r["algo"], r["bits"], '"%s"' % r["level"] if r["level"] else "0",
                      int(r["default"]), r["status"], r["security"], _ps_ports(r),
                      '"%s"' % r["withdrawn"] if r["withdrawn"] else "0"))
    out += ["};",
            "static const int HKX_PARAM_SETS_N ="
            " (int)(sizeof(HKX_PARAM_SETS) / sizeof(HKX_PARAM_SETS[0]));",
            "static const char *const HKX_PARAM_LEVELS[] = {%s, 0};"
            % ", ".join('"%s"' % l for l in ps["levels"]),
            "static const char *const HKX_PARAM_FIXED[] = {%s, 0};"
            % ", ".join('"%s"' % a for a in ps["fixed_algos"]),
            "static const char *const HKX_PARAM_OWN_BITS[] = {%s, 0};"
            % ", ".join('"%s"' % a for a in ps["own_bits_rule"]),
            "static const char *const HKX_PARAM_LEVEL_NOTES[] = {"]
    for a, note in ps["level_notes"].items():
        out.append('    "%s", "%s",' % (a, note))
    out += ["    0};",
            "#define HKX_PARAM_GAP_TODO %d   /* this CLI's narrow-width TODO */"
            % ps["port_gap_todo"]["c"], ""]
    return out


def emit_java_param_sets(ps):
    out = ["    /** TODO #379: genpkey's key parameter sets: {algo, bits, level|\"\", default,",
           "     *  status, security, ports, withdrawn|\"\"}.  bits -1: no --bits value. */",
           "    static final String[][] PARAM_SETS = {"]
    for r in ps["rows"]:
        out.append('        {"%s", "%d", "%s", "%s", "%s", "%s", "%s", "%s"},'
                   % (r["algo"], r["bits"], r["level"] or "", "1" if r["default"] else "0",
                      r["status"], r["security"], _ps_ports(r), r["withdrawn"] or ""))
    out += ["    };",
            "    static final String[] PARAM_LEVELS = {%s};"
            % ", ".join('"%s"' % l for l in ps["levels"]),
            "    static final String[] PARAM_FIXED = {%s};"
            % ", ".join('"%s"' % a for a in ps["fixed_algos"]),
            "    static final String[] PARAM_OWN_BITS = {%s};"
            % ", ".join('"%s"' % a for a in ps["own_bits_rule"]),
            "    static final String[][] PARAM_LEVEL_NOTES = {"]
    for a, note in ps["level_notes"].items():
        out.append('        {"%s", "%s"},' % (a, note))
    out += ["    };",
            "    static final int PARAM_GAP_TODO = %d;" % ps["port_gap_todo"]["java"], ""]
    return out


def emit_go_param_sets(ps):
    out = ["// TODO #379: genpkey's key parameter sets (--bits / --level); bits -1: no",
           "// --bits value names the row.  ports: the CLIs that run the row today.",
           "var paramSets = []paramSet{"]
    for r in ps["rows"]:
        out.append('\t{"%s", %d, "%s", %s, "%s", "%s", "%s", "%s"},'
                   % (r["algo"], r["bits"], r["level"] or "", "true" if r["default"] else "false",
                      r["status"], r["security"], _ps_ports(r), r["withdrawn"] or ""))
    out += ["}", "",
            "var paramLevels = []string{%s}" % ", ".join('"%s"' % l for l in ps["levels"]),
            "var paramFixed = []string{%s}" % ", ".join('"%s"' % a for a in ps["fixed_algos"]),
            "var paramOwnBits = []string{%s}" % ", ".join('"%s"' % a for a in ps["own_bits_rule"]),
            "var paramLevelNotes = map[string]string{"]
    for a, note in ps["level_notes"].items():
        out.append('\t"%s": "%s",' % (a, note))
    out += ["}", ""]
    return out


def emit_py_param_sets(ps):
    out = ["# TODO #379: genpkey's key parameter sets (--bits / --level); bits -1: no",
           "# --bits value names the row.  ports: the CLIs that run the row today.",
           "_PARAM_SETS = ("]
    for r in ps["rows"]:
        out.append("    (%r, %d, %r, %r, %r,\n     %r, %r, %r),"
                   % (r["algo"], r["bits"], r["level"], r["default"], r["status"],
                      r["security"], _ps_ports(r), r["withdrawn"]))
    out += [")",
            "_PARAM_LEVELS = %r" % (tuple(ps["levels"]),),
            "_PARAM_FIXED = %r" % (tuple(ps["fixed_algos"]),),
            "_PARAM_OWN_BITS = %r" % (tuple(ps["own_bits_rule"]),),
            "_PARAM_LEVEL_NOTES = {"]
    for a, note in ps["level_notes"].items():
        out.append("    %r: %r," % (a, note))
    out += ["}", ""]
    return out


def build_pem_der_items(all_labels):
    unknown = sorted(set(PEM_DER_ITEMS) - set(all_labels))
    if unknown:
        raise RuntimeError("PEM_DER_ITEMS names labels no CLI defines: %r" % unknown)
    rows = []
    for label, (lo, hi) in sorted(PEM_DER_ITEMS.items()):
        if not 0 < lo <= hi <= 16:
            raise RuntimeError("PEM_DER_ITEMS[%r] = %r is not 1 <= min <= max <= 16" % (label, (lo, hi)))
        rows.append({"label": label, "min": lo, "max": hi})
    return rows


# TODO #372: how wide each field of each DER-SEQUENCE label may be, in
# significant bytes.  The cap is what the writer pads that field to (Python's
# der_int(v, nbytes) calls, which every CLI matches byte for byte): a value
# wider than it cannot have come from a writer, and before this table some
# CLIs truncated it, some ignored it and some refused it.  One row per (label,
# item count), optionally narrowed by `when`, a test on fields that tells two
# layouts with the same count apart (CIPHERTEXT format tags); the first row
# that matches is the one checked.  A cap is an integer expression: decimal
# constants, fK (the value of field K), + - * / (integer division),
# parentheses and min(a, b).  Every field an expression names must itself have
# a constant cap of at most 6 bytes, so the arithmetic fits a signed 64-bit
# integer in every language; the generated checks test the constant caps first.
#
# TODO #373: how each field is ENCODED.  A cap written "=E" is a fixed-width
# field: every writer emits exactly E bytes, leading zeros included, plus the
# 0x00 a set top bit needs, so the encoded width (content length less that
# sign byte) must be exactly E -- or E-1 when the content is E bytes whose
# leading 0x00 reads as a sign byte, which is the same bytes.  An exact width
# of 0 (an empty plaintext's body) is the INTEGER 0, whose one DER form is the
# single byte 00 (an INTEGER cannot be empty).  Any other cap is a scalar or a minimal value
# (the session key, a response's K): its encoding must be minimal, i.e. carry
# no 0x00 the sign does not need.  Measured on every writer in all four CLIs
# before the table was marked.  An optional fifth element lists VALUE rules,
# run once the widths hold (see _VALUE_RULE_KINDS).  Each CLI runs all of this
# in its PEM-to-integers loader, right after PEM_DER_ITEMS, and prints the
# same text:
#     <label>: field <i> is <k> bytes (expected at most <cap>)
#     <label>: field <i> is encoded in <k> bytes (expected exactly <cap>)
#     <label>: field <i> is encoded with a leading zero byte (expected minimal)
#     ... and one line per value rule, below.
_GF_N = {0: "=f2/8", 1: "=f2/8", 2: "2"}         # (priv, pub, n)
_GF_PUB = {0: "=f1/8", 1: "2"}                    # (pub, n)
_STERN_KEY = {0: "=f2/8", 1: "=f2/8", 2: "2"}     # (e or syndrome, seed, n)
# Commitments are min(n, 256) bits: 256 above N = 256, the long form (TODO #382).
_STERN_SIG = {0: "2", 1: "2", 2: "=f1*3*min(f0/8, 32)", 3: "=(f1+3)/4", 4: "=f1*2*(f0/8)"}
# (K_B, C_B, hint, n, hint length[, n_B]): K_B is minimal, like a session key.
_RNL_RESP = {0: "32", 1: "=f3*2", 2: "=f3/8", 3: "2", 4: "2", 5: "=32"}
_RNL_Q = 65537        # parameters.hkex_rnl q
_RNL_P = 4096         # parameters.hkex_rnl p
_QCMDPC_R = 12323     # "Herradura cryptographic suite.py" _QCMDPC_R
_WOTS_L = 67          # parameters.wots.l_total
# Value rules (TODO #373), each a tuple whose first element is its kind:
#   ("coef_below", K, W, COUNT, B)  field K is COUNT big-endian W-byte
#                                   coefficients, each below B
#   ("coef_cbd", K, W, COUNT, Q)    ... each 0, 1 or Q-1 (CBD(1) mod Q)
#   ("le_bits", K, R)               field K is a little-endian R-bit string
#                                   ((R+7)/8 bytes, the QC-MDPC keys and KEM
#                                   syndrome): no bit at or above R
#   ("bits", K, R)                  field K's value is below 2^R (the hybrid
#                                   response's syndrome, a plain integer)
#   ("support", K, D, R)            field K is D big-endian 2-byte indices,
#                                   each below R, no two equal (any order)
#   ("le_poly_of", K, S, D, R)      field K is the R-bit string whose set bits
#                                   are field S's D indices
#   ("equals", K, E)                field K's value is E
# COUNT, D, R and E are cap expressions.  Messages:
#     <label>: field <i> coefficient <j> is <v> (expected below <B>)
#     <label>: field <i> coefficient <j> is <v> (expected 0, 1 or <Q-1>)
#     <label>: field <i> has bits at or above r = <R>
#     <label>: field <i> index <j> is <v> (expected below r = <R>)
#     <label>: field <i> repeats index <v>
#     <label>: field <i> is not the polynomial of field <S>
#     <label>: field <i> is <v> (expected <E>)
_VALUE_RULE_KINDS = {"coef_below": 5, "coef_cbd": 5, "le_bits": 3, "bits": 3, "support": 4,
                     "le_poly_of": 5, "equals": 3}
_RNL_RESP_RULES = [("coef_below", 1, 2, "f3", _RNL_P), ("equals", 4, "f3/2")]
PEM_DER_FIELD_CAPS = [
    # label, (min items, max items), when, {field: cap}[, value rules]
    ("HERRADURA HKEX-GF PRIVATE KEY", (3, 3), None, _GF_N),
    ("HERRADURA HKEX-GF PUBLIC KEY", (2, 2), None, _GF_PUB),
    ("HERRADURA HPKS PRIVATE KEY", (3, 3), None, _GF_N),
    ("HERRADURA HPKS PUBLIC KEY", (2, 2), None, _GF_PUB),
    ("HERRADURA HPKS-NL PRIVATE KEY", (3, 3), None, _GF_N),
    ("HERRADURA HPKS-NL PUBLIC KEY", (2, 2), None, _GF_PUB),
    ("HERRADURA HPKE PRIVATE KEY", (3, 3), None, _GF_N),
    ("HERRADURA HPKE PUBLIC KEY", (2, 2), None, _GF_PUB),
    ("HERRADURA HPKE-NL PRIVATE KEY", (3, 3), None, _GF_N),
    ("HERRADURA HPKE-NL PUBLIC KEY", (2, 2), None, _GF_PUB),
    ("HERRADURA HPKE-NL3 PRIVATE KEY", (3, 3), None, _GF_N),
    ("HERRADURA HPKE-NL3 PUBLIC KEY", (2, 2), None, _GF_PUB),
    # s and m_blind are 4 bytes a coefficient, C 2; the optional nonce is 32.
    # s is CBD(1) mod q (TODO #373: Java read 2^32-1 as -1, the others as 0).
    ("HERRADURA HKEX-RNL PRIVATE KEY", (3, 4), None,
     {0: "=f2*4", 1: "=f2*4", 2: "2", 3: "=32"},
     [("coef_cbd", 0, 4, "f2", _RNL_Q), ("coef_below", 1, 4, "f2", _RNL_Q)]),
    ("HERRADURA HKEX-RNL PUBLIC KEY", (3, 4), None,
     {0: "=f2*2", 1: "=f2*4", 2: "2", 3: "=32"},
     [("coef_below", 0, 2, "f2", _RNL_P), ("coef_below", 1, 4, "f2", _RNL_Q)]),
    # (K_B, C_B, hint, n, hint length[, n_B]): 2 hint bits for each of n/2
    # coefficients, so n/8 bytes; the hint length is n/2 (Go wrote n, #373).
    ("HERRADURA HKEX-RNL RESPONSE", (5, 6), None, _RNL_RESP, _RNL_RESP_RULES),
    ("HERRADURA HYBRID-RNL-STERN RESPONSE", (8, 8), None,
     {**_RNL_RESP, 6: "=(f7+7)/8", 7: "2"},
     _RNL_RESP_RULES + [("bits", 6, "f7")]),
    ("HERRADURA HPKS-STERN PRIVATE KEY", (3, 3), None, _STERN_KEY),
    ("HERRADURA HPKS-STERN PUBLIC KEY", (3, 3), None, _STERN_KEY),
    ("HERRADURA HPKE-STERN PRIVATE KEY", (3, 3), None, _STERN_KEY),
    ("HERRADURA HPKE-STERN PUBLIC KEY", (3, 3), None, _STERN_KEY),
    # (h0, h1, support0, support1, r, d): 2 bytes a support index.  Every
    # writer sets h0 and h1 to the supports' polynomials and the decoder reads
    # only the supports, so h0 and h1 must be those polynomials.  C writes
    # the supports in draw order, the others sorted: any order is accepted.
    ("HERRADURA HPKE-STERN-KEM PRIVATE KEY", (6, 6), None,
     {0: "=(f4+7)/8", 1: "=(f4+7)/8", 2: "=f5*2", 3: "=f5*2", 4: "2", 5: "2"},
     [("support", 2, "f5", "f4"), ("support", 3, "f5", "f4"),
      ("le_poly_of", 0, 2, "f5", "f4"), ("le_poly_of", 1, 3, "f5", "f4")]),
    ("HERRADURA HPKE-STERN-KEM PUBLIC KEY", (2, 2), None, {0: "=(f1+7)/8", 1: "2"},
     [("le_bits", 0, "f1")]),
    ("HERRADURA HPKS-WOTS PRIVATE KEY", (2, 2), None, {0: "=32", 1: "4"}),
    ("HERRADURA HPKS-WOTS PUBLIC KEY", (2, 2), None, {0: "=f1*32", 1: "2"}),
    ("HERRADURA HPKS-WOTS SIGNATURE", (2, 2), None, {0: "=f1*32", 1: "2"}),
    # (seed, h, next leaf, 32 bytes a leaf); min() keeps the shift in range
    # for an h the decoder will refuse anyway.
    ("HERRADURA HPKS-XMSS PRIVATE KEY", (4, 4), None,
     {0: "=32", 1: "1", 2: "4", 3: "=32*(1<<min(f1, 32))"}),
    ("HERRADURA HPKS-XMSS PUBLIC KEY", (2, 2), None, {0: "=32", 1: "1"}),
    # (leaf, %d WOTS values of n/8 bytes, h auth-path nodes of 32, h, n)
    ("HERRADURA HPKS-XMSS SIGNATURE", (5, 5), None,
     {0: "4", 1: "=%d*(f4/8)" % _WOTS_L, 2: "=f3*32", 3: "1", 4: "2"}),
    # (n, k, rounds, D, blob): the blob's exact length follows from the
    # challenges D derives, so it is minimal DER under the all-b=0 bound
    # rounds * (96 + 2 * vector), a vector being k * n/8 + ceil(k/8) bytes.
    ("HERRADURA HPKS-RING-V2 SIGNATURE", (5, 5), None,
     {0: "2", 1: "2", 2: "2", 3: "=32", 4: "f2*(96+2*(f1*(f0/8)+(f1+7)/8))"}),
    ("HERRADURA OPRF PRIVATE KEY", (2, 2), None, _GF_PUB),
    ("HERRADURA OPRF CLIENT STATE", (3, 3), None, _GF_N),
    ("HERRADURA OPRF EVALUATION", (2, 2), None, _GF_PUB),
    ("HERRADURA PAKE RECORD", (3, 3), None, {0: "=32", 1: "=4", 2: "=4"}),
    ("HERRADURA HPKST COMMITMENT", (3, 3), None, _GF_N),
    ("HERRADURA HPKST NONCE", (2, 2), None, _GF_PUB),
    ("HERRADURA HPKST AGGREGATE", (4, 4), None, {0: "=f3/8", 1: "=f3/8", 2: "=f3/8", 3: "2"}),
    ("HERRADURA HPKST PARTIAL", (2, 2), None, _GF_PUB),
    ("HERRADURA HPKST SIGNATURE", (4, 4), None, {0: "=f3/8", 1: "=f3/8", 2: "=f3/8", 3: "2"}),
    ("HERRADURA HCRED CREDENTIAL", (5, 5), None, _STERN_SIG),
    # The session key is minimal in every writer (max(1, bit_length) bytes).
    ("HERRADURA SESSION KEY", (2, 2), None, {0: "f1/8", 1: "2"}),
    ("HERRADURA DIGEST", (1, 1), None, {0: "=32"}),
    ("HERRADURA HDRBG STATE", (2, 2), None, {0: "=32", 1: "8"}),
    # (salt, iterations, nonce, ciphertext of plaintext-length bytes, tag, length)
    ("HERRADURA ENCRYPTED PRIVATE KEY", (6, 6), None,
     {0: "=16", 1: "4", 2: "=32", 3: "=f5", 4: "=32", 5: "4"}),
    # Three items: the QC-MDPC KEM (syndrome, E, r), whose r makes (r+7)/8 the
    # syndrome width and whose E is a 32-byte key hash; hske format 0
    # (0, E, n); else HPKE (R, E, n).
    ("HERRADURA CIPHERTEXT", (3, 3), "f2 == %d" % _QCMDPC_R,
     {0: "=(f2+7)/8", 1: "=32", 2: "2"}, [("le_bits", 0, "f2")]),
    ("HERRADURA CIPHERTEXT", (3, 3), "f0 == 0", {0: "1", 1: "=(f2+7)/8", 2: "2"}),
    ("HERRADURA CIPHERTEXT", (3, 3), None, {0: "=(f2+7)/8", 1: "=(f2+7)/8", 2: "2"}),
    ("HERRADURA CIPHERTEXT", (4, 4), None, {0: "1", 1: "=(f3+7)/8", 2: "=(f3+7)/8", 3: "2"}),
    # Five: hske-nla1 format 2 (2, nonce, E, tag, n).  The HPKE-Stern demo
    # layout (ct, e', K, E, n) shared this count until TODO #413 retired it.
    ("HERRADURA CIPHERTEXT", (5, 5), None,
     {0: "1", 1: "=(f4+7)/8", 2: "=(f4+7)/8", 3: "=32", 4: "2"}),
    # Six: duplex (format 3 or 4, nonce, length, ciphertext, tag, n).
    ("HERRADURA CIPHERTEXT", (6, 6), None,
     {0: "1", 1: "=(f5+7)/8", 2: "6", 3: "=f2", 4: "=32", 5: "2"}),
    ("HERRADURA SIGNATURE", (4, 4), None, {0: "=f3/8", 1: "=f3/8", 2: "=f3/8", 3: "2"}),
    ("HERRADURA SIGNATURE", (5, 5), None, _STERN_SIG),
]

_CAP_TOKEN = re.compile(r"\s*(?:(\d+)|f(\d+)|(min)|(<<|[-+*/(),]|==))")


def _cap_refs(expr):
    """Field indices an expression reads; raises on anything outside the grammar."""
    refs, pos = set(), 0
    while pos < len(expr):
        m = _CAP_TOKEN.match(expr, pos)
        if not m or m.end() == pos:
            raise RuntimeError("PEM_DER_FIELD_CAPS: bad token in %r at %d" % (expr, pos))
        if m.group(2) is not None:
            refs.add(int(m.group(2)))
        pos = m.end()
    return refs


def _cap_parts(cap):
    """(expression, exact) for a cap: "=E" is a fixed-width field (TODO #373)."""
    cap = cap.strip()
    return (cap[1:].strip(), True) if cap.startswith("=") else (cap, False)


def build_pem_der_field_caps():
    items = dict(PEM_DER_ITEMS)
    rows, seen = [], set()
    for row in PEM_DER_FIELD_CAPS:
        label, (lo, hi), when, caps = row[:4]
        rules = row[4] if len(row) > 4 else []
        if len(row) > 5:
            raise RuntimeError("PEM_DER_FIELD_CAPS row %r has too many elements" % (label,))
        if label not in items:
            raise RuntimeError("PEM_DER_FIELD_CAPS row %r is not in PEM_DER_ITEMS" % label)
        ilo, ihi = items[label]
        if not ilo <= lo <= hi <= ihi:
            raise RuntimeError("PEM_DER_FIELD_CAPS %r: items %d..%d outside PEM_DER_ITEMS %d..%d"
                               % (label, lo, hi, ilo, ihi))
        key = (label, lo, hi, when)
        if key in seen:
            raise RuntimeError("duplicate PEM_DER_FIELD_CAPS row %r" % (key,))
        seen.add(key)
        if sorted(caps) != list(range(hi)):
            raise RuntimeError("PEM_DER_FIELD_CAPS %r: caps must name fields 0..%d" % (label, hi - 1))
        parts = {i: _cap_parts(e) for i, e in caps.items()}
        const = {i: int(e) for i, (e, _x) in parts.items() if e.isdigit()}

        def need_const(where, expr):
            for r in _cap_refs(expr):
                if r not in const or const[r] > 6:
                    raise RuntimeError("PEM_DER_FIELD_CAPS %r %s: %r reads f%d, which needs a "
                                       "constant cap of at most 6 bytes" % (label, where, expr, r))
                if parts[r][1]:
                    raise RuntimeError("PEM_DER_FIELD_CAPS %r %s: %r reads f%d, a fixed-width "
                                       "field; expressions read scalars" % (label, where, expr, r))
        for i, (e, _x) in parts.items():
            need_const("field %d" % i, e)
        if when:
            need_const("when", when)
        out_rules = []
        for rule in rules:
            kind = rule[0]
            if kind not in _VALUE_RULE_KINDS or len(rule) != _VALUE_RULE_KINDS[kind]:
                raise RuntimeError("PEM_DER_FIELD_CAPS %r: bad value rule %r" % (label, rule))
            k = rule[1]
            if not 0 <= k < lo:
                raise RuntimeError("PEM_DER_FIELD_CAPS %r: rule %r names field %d, which a "
                                   "%d-item artifact may not have" % (label, rule, k, lo))
            # A rule reads field K at its exact width, so K must be fixed-width.
            if kind != "equals" and not parts[k][1]:
                raise RuntimeError("PEM_DER_FIELD_CAPS %r: rule %r reads field %d, which is "
                                   "not fixed-width" % (label, rule, k))
            if kind == "le_poly_of" and not parts[rule[2]][1]:
                raise RuntimeError("PEM_DER_FIELD_CAPS %r: rule %r reads field %d, which is "
                                   "not fixed-width" % (label, rule, rule[2]))
            r = {"kind": kind, "field": k}
            if kind in ("coef_below", "coef_cbd"):
                r.update(width=rule[2], count=rule[3], bound=rule[4])
                need_const("rule", rule[3])
            elif kind in ("le_bits", "bits"):
                r.update(r=rule[2]); need_const("rule", rule[2])
            elif kind == "support":
                r.update(d=rule[2], r=rule[3]); need_const("rule", rule[2]); need_const("rule", rule[3])
            elif kind == "le_poly_of":
                r.update(support=rule[2], d=rule[3], r=rule[4])
                need_const("rule", rule[3]); need_const("rule", rule[4])
            else:
                r.update(value=rule[2]); need_const("rule", rule[2])
            out_rules.append(r)
        # Check order: constant caps first, so every value an expression reads
        # has already been bounded.
        order = sorted(caps, key=lambda i: (i not in const, i))
        rows.append({"label": label, "min_items": lo, "max_items": hi,
                     "when": when or "",
                     "caps": [{"field": i, "cap": parts[i][0], "exact": parts[i][1]}
                              for i in order],
                     "rules": out_rules})
    # Every label with items has rows covering each count it allows.
    for label, (ilo, ihi) in items.items():
        for k in range(ilo, ihi + 1):
            if not any(r["label"] == label and r["min_items"] <= k <= r["max_items"]
                       and not r["when"] for r in rows):
                raise RuntimeError("PEM_DER_FIELD_CAPS has no unconditional row for %r with "
                                   "%d items" % (label, k))
    return rows


def _cap_code(expr, lang):
    """Translate a cap expression; F(K) is each language's 'value of field K'."""
    out, pos = [], 0
    while pos < len(expr):
        m = _CAP_TOKEN.match(expr, pos)
        num, ref, mn, op = m.groups()
        if num is not None:
            out.append(num + ("LL" if lang == "c" else "L" if lang == "java" else ""))
        elif ref is not None:
            out.append({"py": "F[%s]", "c": "F(%s)", "go": "F(%s)", "java": "F(%s)"}[lang] % ref)
        elif mn:
            out.append({"py": "min", "c": "HKX_MIN", "go": "hkxMin", "java": "Math.min"}[lang])
        elif op == "/" and lang == "py":
            out.append("//")
        elif op == ",":
            out.append(", ")
        elif op in ("+", "-", "*", "==", "<<"):
            out.append(" %s " % op)
        else:
            out.append(op)
        pos = m.end()
    return "".join(out)


def _cap_rows_by_label(caps):
    by = {}
    for r in caps:
        by.setdefault(r["label"], []).append(r)
    return by


_MSG_WIDE = "%s: field %d is %lld bytes (expected at most %lld)"
_MSG_EXACT = "%s: field %d is encoded in %lld bytes (expected exactly %lld)"
_MSG_MINIMAL = "%s: field %d is encoded with a leading zero byte (expected minimal)"
_MSG_EQUALS = "%s: field %d is %lld (expected %lld)"


def _rule_call(rule, lang):
    """One value-rule check (TODO #373) as a call to that language's helper,
    which writes the message and returns true on a violation."""
    k, kind = rule["field"], rule["kind"]
    ex = lambda e: _cap_code(e, lang)
    if lang == "c":
        V = lambda f: "vals[%d], lens[%d]" % (f, f)
        if kind in ("coef_below", "coef_cbd"):
            return "hkx_rule_coef(m, ms, label, %d, %s, %d, %s, %dLL, %d)" % (
                k, V(k), rule["width"], ex(rule["count"]), rule["bound"], kind == "coef_cbd")
        if kind in ("le_bits", "bits"):
            return "hkx_rule_bits(m, ms, label, %d, %s, %s, %d)" % (k, V(k), ex(rule["r"]), kind == "le_bits")
        if kind == "support":
            return "hkx_rule_support(m, ms, label, %d, %s, %s, %s)" % (k, V(k), ex(rule["d"]), ex(rule["r"]))
        if kind == "le_poly_of":
            return "hkx_rule_le_poly_of(m, ms, label, %d, %s, %d, %s, %s, %s)" % (
                k, V(k), rule["support"], V(rule["support"]), ex(rule["d"]), ex(rule["r"]))
        return "hkx_rule_equals(m, ms, label, %d, F(%d), %s)" % (k, k, ex(rule["value"]))
    if lang == "go":
        if kind in ("coef_below", "coef_cbd"):
            return "hkxRuleCoef(label, %d, v[%d], %d, int64(%s), %d, %s)" % (
                k, k, rule["width"], ex(rule["count"]), rule["bound"],
                "true" if kind == "coef_cbd" else "false")
        if kind in ("le_bits", "bits"):
            return "hkxRuleBits(label, %d, v[%d], int64(%s), %s)" % (
                k, k, ex(rule["r"]), "true" if kind == "le_bits" else "false")
        if kind == "support":
            return "hkxRuleSupport(label, %d, v[%d], int64(%s), int64(%s))" % (k, k, ex(rule["d"]), ex(rule["r"]))
        if kind == "le_poly_of":
            return "hkxRuleLePolyOf(label, %d, v[%d], %d, v[%d], int64(%s), int64(%s))" % (
                k, k, rule["support"], rule["support"], ex(rule["d"]), ex(rule["r"]))
        return "hkxRuleEquals(label, %d, F(%d), int64(%s))" % (k, k, ex(rule["value"]))
    if lang == "java":
        ex = lambda e: _cap_code(e, "java").replace("F(", "F0.applyAsLong(")
        if kind in ("coef_below", "coef_cbd"):
            return "ruleCoef(label, %d, v.get(%d), %d, %s, %dL, %s)" % (
                k, k, rule["width"], ex(rule["count"]), rule["bound"],
                "true" if kind == "coef_cbd" else "false")
        if kind in ("le_bits", "bits"):
            return "ruleBits(label, %d, v.get(%d), %s, %s)" % (
                k, k, ex(rule["r"]), "true" if kind == "le_bits" else "false")
        if kind == "support":
            return "ruleSupport(label, %d, v.get(%d), %s, %s)" % (k, k, ex(rule["d"]), ex(rule["r"]))
        if kind == "le_poly_of":
            return "rulePolyOf(label, %d, v.get(%d), %d, v.get(%d), %s, %s)" % (
                k, k, rule["support"], rule["support"], ex(rule["d"]), ex(rule["r"]))
        return "ruleEquals(label, %d, F0.applyAsLong(%d), %s)" % (k, k, ex(rule["value"]))
    # py
    if kind in ("coef_below", "coef_cbd"):
        return "_rule_coef(label, %d, v[%d], %d, %s, %d, %s)" % (
            k, k, rule["width"], ex(rule["count"]), rule["bound"], kind == "coef_cbd")
    if kind in ("le_bits", "bits"):
        return "_rule_bits(label, %d, v[%d], %s, %s)" % (k, k, ex(rule["r"]), kind == "le_bits")
    if kind == "support":
        return "_rule_support(label, %d, v[%d], %s, %s)" % (k, k, ex(rule["d"]), ex(rule["r"]))
    if kind == "le_poly_of":
        return "_rule_le_poly_of(label, %d, v[%d], %d, v[%d], %s, %s)" % (
            k, k, rule["support"], rule["support"], ex(rule["d"]), ex(rule["r"]))
    return "_rule_equals(label, %d, F[%d], %s)" % (k, k, ex(rule["value"]))


def _cap_rows_by_label(caps):
    by = {}
    for r in caps:
        by.setdefault(r["label"], []).append(r)
    return by


_C_RULE_HELPERS = r"""/* TODO #373: the value rules.  Each fills m and returns 1 on a violation.  A
 * rule reads a fixed-width field, which the encoding check has already held to
 * its exact width; hkx_pad_byte reads it at that width (the parser drops one
 * leading 0x00, so a field may be one byte shorter than its width here). */
static unsigned hkx_pad_byte(const uint8_t *v, size_t n, long long w, long long i)
{
    long long off = w - (long long)n;
    return (i < off || i - off >= (long long)n) ? 0u : v[i - off];
}
static int hkx_rule_coef(char *m, size_t ms, const char *label, int k,
                         const uint8_t *v, size_t n, int w, long long cnt,
                         long long bound, int cbd)
{
    long long j, x, W = (long long)w * cnt; int b;
    for (j = 0; j < cnt; j++) {
        for (x = 0, b = 0; b < w; b++) x = (x << 8) | hkx_pad_byte(v, n, W, j * w + b);
        if (cbd ? !(x == 0 || x == 1 || x == bound - 1) : x >= bound) {
            if (cbd) snprintf(m, ms, "%s: field %d coefficient %lld is %lld (expected 0, 1 or %lld)",
                              label, k, j, x, bound - 1);
            else     snprintf(m, ms, "%s: field %d coefficient %lld is %lld (expected below %lld)",
                              label, k, j, x, bound);
            return 1;
        }
    }
    return 0;
}
/* le: an R-bit little-endian byte string (the spare bits are in the LAST
 * byte); otherwise a plain integer below 2^R (spare bits in the FIRST). */
static int hkx_rule_bits(char *m, size_t ms, const char *label, int k,
                         const uint8_t *v, size_t n, long long r, int le)
{
    long long W = (r + 7) / 8;
    if (W > 0 && r % 8 && (hkx_pad_byte(v, n, W, le ? W - 1 : 0) >> (r % 8))) {
        snprintf(m, ms, "%s: field %d has bits at or above r = %lld", label, k, r);
        return 1;
    }
    return 0;
}
static int hkx_rule_support(char *m, size_t ms, const char *label, int k,
                            const uint8_t *v, size_t n, long long d, long long r)
{
    static uint8_t seen[8192];
    long long j, x;
    memset(seen, 0, sizeof seen);
    for (j = 0; j < d; j++) {
        x = ((long long)hkx_pad_byte(v, n, 2 * d, 2 * j) << 8) | hkx_pad_byte(v, n, 2 * d, 2 * j + 1);
        if (x >= r) {
            snprintf(m, ms, "%s: field %d index %lld is %lld (expected below r = %lld)",
                     label, k, j, x, r);
            return 1;
        }
        if (seen[x >> 3] & (1u << (x & 7))) {
            snprintf(m, ms, "%s: field %d repeats index %lld", label, k, x);
            return 1;
        }
        seen[x >> 3] |= (uint8_t)(1u << (x & 7));
    }
    return 0;
}
static int hkx_rule_le_poly_of(char *m, size_t ms, const char *label, int k,
                               const uint8_t *v, size_t n, int s,
                               const uint8_t *sv, size_t sn, long long d, long long r)
{
    long long W = (r + 7) / 8, i, j, x;
    uint8_t *e = (uint8_t *)calloc((size_t)(W > 0 ? W : 1), 1);
    if (!e) { snprintf(m, ms, "out of memory"); return 1; }
    for (j = 0; j < d; j++) {
        x = ((long long)hkx_pad_byte(sv, sn, 2 * d, 2 * j) << 8) | hkx_pad_byte(sv, sn, 2 * d, 2 * j + 1);
        if (x < r) e[x >> 3] |= (uint8_t)(1u << (x & 7));
    }
    for (i = 0; i < W; i++)
        if (hkx_pad_byte(v, n, W, i) != e[i]) {
            free(e);
            snprintf(m, ms, "%s: field %d is not the polynomial of field %d", label, k, s);
            return 1;
        }
    free(e);
    return 0;
}
static int hkx_rule_equals(char *m, size_t ms, const char *label, int k, long long x, long long want)
{
    if (x == want) return 0;
    snprintf(m, ms, "%s: field %d is %lld (expected %lld)", label, k, x, want);
    return 1;
}"""


def emit_c_field_caps(caps):
    out = ["/* TODO #372 / #373: per DER-SEQUENCE label, each field's width cap",
           " * (significant bytes), its encoding (exactly its width, or minimal) and",
           " * the value rules.  ew[k] is field k's encoded width (content length less",
           " * a sign byte), lz[k] 1 when it starts with a 0x00 the sign does not need,",
           " * 2 when with a sign byte.  Returns 1 and fills m with the refusal, else 0.  F(K) is field",
           " * K's value, or -1 if it is wider than 6 bytes. */",
           "#define HKX_MIN(a, b) ((a) < (b) ? (a) : (b))",
           "static long long hkx_cap_val(const uint8_t *v, size_t n)",
           "{",
           "    long long x = 0; size_t i = 0;",
           "    while (i < n && v[i] == 0) i++;",
           "    if (n - i > 6) return -1;",
           "    for (; i < n; i++) x = (x << 8) | v[i];",
           "    return x;",
           "}",
           "static size_t hkx_cap_len(const uint8_t *v, size_t n)",
           "{",
           "    size_t i = 0;",
           "    while (i < n && v[i] == 0) i++;",
           "    return n - i;",
           "}"]
    out += _C_RULE_HELPERS.split("\n")
    out += ["#define F(k) hkx_cap_val(vals[k], lens[k])",
            "#define HKX_WIDE(k, e) do { long long c_ = (e); \\",
            "    if ((long long)hkx_cap_len(vals[k], lens[k]) > c_) { \\",
            '        snprintf(m, ms, "' + _MSG_WIDE + '", label, k, \\',
            "                 (long long)hkx_cap_len(vals[k], lens[k]), c_); return 1; } \\",
            "    } while (0)",
            "#define HKX_EXACT(k, e) do { long long c_ = (e); \\",
            "    if (!((long long)ew[k] == c_ || (lz[k] == 2 && (long long)ew[k] + 1 == c_) || \\",
            "          (c_ == 0 && ew[k] == 1 && hkx_cap_len(vals[k], lens[k]) == 0))) { \\",
            '        snprintf(m, ms, "' + _MSG_EXACT + '", label, k, (long long)ew[k], c_); \\',
            "        return 1; } \\",
            "    } while (0)",
            "#define HKX_MINIMAL(k) do { if (lz[k] == 1) { \\",
            '        snprintf(m, ms, "' + _MSG_MINIMAL + '", label, k); return 1; } \\',
            "    } while (0)",
            "static int hkx_der_field_check(const char *label, int n, const uint8_t *const *vals,",
            "                               const size_t *lens, const size_t *ew,",
            "                               const unsigned char *lz, char *m, size_t ms)",
            "{"]
    for label, rows in _cap_rows_by_label(caps).items():
        out.append('    if (strcmp(label, "%s") == 0) {' % label)
        for r in rows:
            cond = "n >= %d && n <= %d" % (r["min_items"], r["max_items"])
            if r["when"]:
                cond += " && (%s)" % _cap_code(r["when"], "c")
            out.append("        if (%s) {" % cond)
            for c in r["caps"]:
                out.append("            if (n > %d) HKX_WIDE(%d, %s);"
                           % (c["field"], c["field"], _cap_code(c["cap"], "c")))
            for c in r["caps"]:
                if c["exact"]:
                    out.append("            if (n > %d) HKX_EXACT(%d, %s);"
                               % (c["field"], c["field"], _cap_code(c["cap"], "c")))
                else:
                    out.append("            if (n > %d) HKX_MINIMAL(%d);" % (c["field"], c["field"]))
            for rule in r["rules"]:
                out.append("            if (%s) return 1;" % _rule_call(rule, "c"))
            out.append("            return 0;")
            out.append("        }")
        out.append("        return 0;")
        out.append("    }")
    out += ["    return 0;", "}", "#undef F", "#undef HKX_WIDE", "#undef HKX_EXACT",
            "#undef HKX_MINIMAL", ""]
    return out


_JAVA_RULE_HELPERS = r"""    /** TODO #373: x as exactly w bytes, big-endian (the width check has held it). */
    private static byte[] padTo(java.math.BigInteger x, long w) {
        byte[] raw = x.toByteArray();
        byte[] out = new byte[(int) w];
        int src = Math.max(0, raw.length - (int) w), dst = Math.max(0, (int) w - raw.length);
        System.arraycopy(raw, src, out, dst, raw.length - src);
        return out;
    }

    private static String ruleCoef(String label, int k, java.math.BigInteger x, int w, long cnt,
                                   long bound, boolean cbd) {
        byte[] b = padTo(x, (long) w * cnt);
        for (long j = 0; j < cnt; j++) {
            long c = 0;
            for (int i = 0; i < w; i++) c = (c << 8) | (b[(int) (j * w) + i] & 0xff);
            if (cbd ? !(c == 0 || c == 1 || c == bound - 1) : c >= bound) {
                return cbd ? String.format("%s: field %d coefficient %d is %d (expected 0, 1 or %d)",
                                           label, k, j, c, bound - 1)
                           : String.format("%s: field %d coefficient %d is %d (expected below %d)",
                                           label, k, j, c, bound);
            }
        }
        return null;
    }

    /** le: an R-bit little-endian byte string (spare bits in the LAST byte);
     *  otherwise a plain integer below 2^R (spare bits in the FIRST). */
    private static String ruleBits(String label, int k, java.math.BigInteger x, long r, boolean le) {
        long w = (r + 7) / 8;
        if (w > 0 && r % 8 != 0 && ((padTo(x, w)[le ? (int) w - 1 : 0] & 0xff) >> (r % 8)) != 0) {
            return String.format("%s: field %d has bits at or above r = %d", label, k, r);
        }
        return null;
    }

    private static String ruleSupport(String label, int k, java.math.BigInteger x, long d, long r) {
        byte[] b = padTo(x, 2 * d);
        java.util.BitSet seen = new java.util.BitSet();
        for (int j = 0; j < d; j++) {
            int idx = ((b[2 * j] & 0xff) << 8) | (b[2 * j + 1] & 0xff);
            if (idx >= r) {
                return String.format("%s: field %d index %d is %d (expected below r = %d)", label, k, j, idx, r);
            }
            if (seen.get(idx)) return String.format("%s: field %d repeats index %d", label, k, idx);
            seen.set(idx);
        }
        return null;
    }

    private static String rulePolyOf(String label, int k, java.math.BigInteger x, int s,
                                     java.math.BigInteger sup, long d, long r) {
        long w = (r + 7) / 8;
        byte[] want = new byte[(int) w];
        byte[] b = padTo(sup, 2 * d);
        for (int j = 0; j < d; j++) {
            int idx = ((b[2 * j] & 0xff) << 8) | (b[2 * j + 1] & 0xff);
            if (idx < r) want[idx >> 3] |= (byte) (1 << (idx & 7));
        }
        if (!java.util.Arrays.equals(padTo(x, w), want)) {
            return String.format("%s: field %d is not the polynomial of field %d", label, k, s);
        }
        return null;
    }

    private static String ruleEquals(String label, int k, long x, long want) {
        return x == want ? null : String.format("%s: field %d is %d (expected %d)", label, k, x, want);
    }"""


def emit_java_field_caps(caps):
    out = ["    /** TODO #372 / #373: per DER-SEQUENCE label, each field's width cap",
           "     *  (significant bytes), its encoding (exactly its width, or minimal) and",
           "     *  the value rules.  ew[k] is field k's encoded width, lz[k] 1 when it",
           "     *  starts with a 0x00 the sign does not need, 2 with a sign byte.",
           "     *  Returns the refusal, or null. */",
           "    static String fieldCheck(String label, java.util.List<java.math.BigInteger> v,",
           "                             int[] ew, int[] lz) {",
           "        int n = v.size();",
           "        java.util.function.IntToLongFunction F0 = k -> {",
           "            java.math.BigInteger x = v.get(k);",
           "            return x.bitLength() > 48 ? -1L : x.longValue();",
           "        };",
           "        java.util.function.IntUnaryOperator L = k -> (v.get(k).bitLength() + 7) / 8;",
           "        String e;",
           "        switch (label) {"]
    for label, rows in _cap_rows_by_label(caps).items():
        out.append('        case "%s":' % label)
        for r in rows:
            cond = "n >= %d && n <= %d" % (r["min_items"], r["max_items"])
            if r["when"]:
                cond += " && (%s)" % _cap_code(r["when"], "java").replace("F(", "F0.applyAsLong(")
            out.append("            if (%s) {" % cond)
            for c in r["caps"]:
                e = _cap_code(c["cap"], "java").replace("F(", "F0.applyAsLong(")
                out.append('                if (n > %d) { long c = %s; if (L.applyAsInt(%d) > c) '
                           'return String.format("%s", label, %d, (long) L.applyAsInt(%d), c); }'
                           % (c["field"], e, c["field"], _MSG_WIDE.replace("%lld", "%d"),
                              c["field"], c["field"]))
            for c in r["caps"]:
                e = _cap_code(c["cap"], "java").replace("F(", "F0.applyAsLong(")
                if c["exact"]:
                    out.append('                if (n > %d) { long c = %s; if (!(ew[%d] == c || (lz[%d] == 2 && ew[%d] + 1 == c) || (c == 0 && ew[%d] == 1 && L.applyAsInt(%d) == 0))) '
                               'return String.format("%s", label, %d, (long) ew[%d], c); }'
                               % (c["field"], e, c["field"], c["field"], c["field"], c["field"], c["field"],
                                  _MSG_EXACT.replace("%lld", "%d"), c["field"], c["field"]))
                else:
                    out.append('                if (n > %d && lz[%d] == 1) return String.format("%s", label, %d);'
                               % (c["field"], c["field"], _MSG_MINIMAL, c["field"]))
            for rule in r["rules"]:
                out.append("                if ((e = %s) != null) return e;" % _rule_call(rule, "java"))
            out.append("                return null;")
            out.append("            }")
        out.append("            return null;")
    out += ["        default:", "            return null;", "        }", "    }", ""]
    out += _JAVA_RULE_HELPERS.split("\n")
    return out


_GO_RULE_HELPERS = r"""// TODO #373: the value rules.  Each returns the refusal, or "".  A rule reads
// a fixed-width field, which the encoding check has already held to its exact
// width; hkxPad reads it at that width (DerParseSeq drops one leading 0x00).
func hkxPad(b []byte, w int64) []byte {
	out := make([]byte, w)
	if int64(len(b)) > w {
		b = b[int64(len(b))-w:]
	}
	copy(out[w-int64(len(b)):], b)
	return out
}

func hkxRuleCoef(label string, k int, x []byte, w int, cnt, bound int64, cbd bool) string {
	b := hkxPad(x, int64(w)*cnt)
	for j := int64(0); j < cnt; j++ {
		var c int64
		for i := 0; i < w; i++ {
			c = c<<8 | int64(b[j*int64(w)+int64(i)])
		}
		if cbd && !(c == 0 || c == 1 || c == bound-1) {
			return fmt.Sprintf("%s: field %d coefficient %d is %d (expected 0, 1 or %d)", label, k, j, c, bound-1)
		}
		if !cbd && c >= bound {
			return fmt.Sprintf("%s: field %d coefficient %d is %d (expected below %d)", label, k, j, c, bound)
		}
	}
	return ""
}

// le: an R-bit little-endian byte string (spare bits in the LAST byte);
// otherwise a plain integer below 2^R (spare bits in the FIRST).
func hkxRuleBits(label string, k int, x []byte, r int64, le bool) string {
	w := (r + 7) / 8
	i := int64(0)
	if le {
		i = w - 1
	}
	if w > 0 && r%8 != 0 && hkxPad(x, w)[i]>>(r%8) != 0 {
		return fmt.Sprintf("%s: field %d has bits at or above r = %d", label, k, r)
	}
	return ""
}

func hkxRuleSupport(label string, k int, x []byte, d, r int64) string {
	b := hkxPad(x, 2*d)
	seen := make(map[int64]bool, d)
	for j := int64(0); j < d; j++ {
		idx := int64(b[2*j])<<8 | int64(b[2*j+1])
		if idx >= r {
			return fmt.Sprintf("%s: field %d index %d is %d (expected below r = %d)", label, k, j, idx, r)
		}
		if seen[idx] {
			return fmt.Sprintf("%s: field %d repeats index %d", label, k, idx)
		}
		seen[idx] = true
	}
	return ""
}

func hkxRuleLePolyOf(label string, k int, x []byte, s int, sup []byte, d, r int64) string {
	w := (r + 7) / 8
	want := make([]byte, w)
	b := hkxPad(sup, 2*d)
	for j := int64(0); j < d; j++ {
		idx := int64(b[2*j])<<8 | int64(b[2*j+1])
		if idx < r {
			want[idx>>3] |= 1 << uint(idx&7)
		}
	}
	got := hkxPad(x, w)
	for i := range want {
		if got[i] != want[i] {
			return fmt.Sprintf("%s: field %d is not the polynomial of field %d", label, k, s)
		}
	}
	return ""
}

func hkxRuleEquals(label string, k int, x, want int64) string {
	if x == want {
		return ""
	}
	return fmt.Sprintf("%s: field %d is %d (expected %d)", label, k, x, want)
}"""


def emit_go_field_caps(caps):
    out = ["// TODO #372 / #373: per DER-SEQUENCE label, each field's width cap",
           "// (significant bytes), its encoding (exactly its width, or minimal) and the",
           "// value rules.  ew[k] is field k's encoded width, lz[k] 1 when it starts with",
           "// a 0x00 the sign does not need, 2 with a sign byte.  Returns the refusal, or \"\".",
           "func derFieldCheck(label string, v [][]byte, ew []int, lz []uint8) string {",
           "\tn := len(v)",
           "\tL := func(k int) int64 {",
           "\t\tb := v[k]",
           "\t\tfor len(b) > 0 && b[0] == 0 {",
           "\t\t\tb = b[1:]",
           "\t\t}",
           "\t\treturn int64(len(b))",
           "\t}",
           "\tF := func(k int) int64 {",
           "\t\tif L(k) > 6 {",
           "\t\t\treturn -1",
           "\t\t}",
           "\t\tvar x int64",
           "\t\tfor _, c := range v[k] {",
           "\t\t\tx = x<<8 | int64(c)",
           "\t\t}",
           "\t\treturn x",
           "\t}",
           "\t_ = F",
           "\tswitch label {"]
    for label, rows in _cap_rows_by_label(caps).items():
        out.append('\tcase "%s":' % label)
        for r in rows:
            cond = "n >= %d && n <= %d" % (r["min_items"], r["max_items"])
            if r["when"]:
                cond += " && (%s)" % _cap_code(r["when"], "go")
            out.append("\t\tif %s {" % cond)
            for c in r["caps"]:
                out.append("\t\t\tif c := int64(%s); n > %d && L(%d) > c {"
                           % (_cap_code(c["cap"], "go"), c["field"], c["field"]))
                out.append('\t\t\t\treturn fmt.Sprintf("%s", label, %d, L(%d), c)'
                           % (_MSG_WIDE.replace("%lld", "%d"), c["field"], c["field"]))
                out.append("\t\t\t}")
            for c in r["caps"]:
                if c["exact"]:
                    out.append("\t\t\tif c := int64(%s); n > %d && !(int64(ew[%d]) == c || (lz[%d] == 2 && int64(ew[%d])+1 == c) || (c == 0 && ew[%d] == 1 && L(%d) == 0)) {"
                               % (_cap_code(c["cap"], "go"), c["field"], c["field"], c["field"], c["field"], c["field"], c["field"]))
                    out.append('\t\t\t\treturn fmt.Sprintf("%s", label, %d, ew[%d], c)'
                               % (_MSG_EXACT.replace("%lld", "%d"), c["field"], c["field"]))
                else:
                    out.append("\t\t\tif n > %d && lz[%d] == 1 {" % (c["field"], c["field"]))
                    out.append('\t\t\t\treturn fmt.Sprintf("%s", label, %d)' % (_MSG_MINIMAL, c["field"]))
                out.append("\t\t\t}")
            for rule in r["rules"]:
                out.append("\t\t\tif e := %s; e != \"\" {" % _rule_call(rule, "go"))
                out.append("\t\t\t\treturn e")
                out.append("\t\t\t}")
            out.append('\t\t\treturn ""')
            out.append("\t\t}")
    out += ["\t}", '\treturn ""', "}", ""]
    out += _GO_RULE_HELPERS.split("\n")
    return out


_PY_RULE_HELPERS = """# TODO #373: the value rules.  Each returns the refusal, or None.  A rule reads
# a fixed-width field, which the encoding check has already held to its width.
def _rule_coef(label, k, x, w, cnt, bound, cbd):
    b = x.to_bytes(w * cnt, 'big')
    for j in range(cnt):
        c = int.from_bytes(b[j * w:(j + 1) * w], 'big')
        if cbd and c not in (0, 1, bound - 1):
            return f"{label}: field {k} coefficient {j} is {c} (expected 0, 1 or {bound - 1})"
        if not cbd and c >= bound:
            return f"{label}: field {k} coefficient {j} is {c} (expected below {bound})"
    return None


def _rule_bits(label, k, x, r, le):
    # le: an r-bit little-endian byte string (spare bits in the LAST byte);
    # otherwise a plain integer below 2^r.
    if (r % 8 and (x & 0xff) >> (r % 8)) if le else x >> r:
        return f"{label}: field {k} has bits at or above r = {r}"
    return None


def _rule_support(label, k, x, d, r):
    b, seen = x.to_bytes(2 * d, 'big'), set()
    for j in range(d):
        idx = int.from_bytes(b[2 * j:2 * j + 2], 'big')
        if idx >= r:
            return f"{label}: field {k} index {j} is {idx} (expected below r = {r})"
        if idx in seen:
            return f"{label}: field {k} repeats index {idx}"
        seen.add(idx)
    return None


def _rule_le_poly_of(label, k, x, s, sup, d, r):
    b, want = sup.to_bytes(2 * d, 'big'), bytearray((r + 7) // 8)
    for j in range(d):
        idx = int.from_bytes(b[2 * j:2 * j + 2], 'big')
        if idx < r:
            want[idx >> 3] |= 1 << (idx & 7)
    if x != int.from_bytes(want, 'big'):
        return f"{label}: field {k} is not the polynomial of field {s}"
    return None


def _rule_equals(label, k, x, want):
    return None if x == want else f"{label}: field {k} is {x} (expected {want})\""""


def emit_py_field_caps(caps):
    out = _PY_RULE_HELPERS.split("\n") + ["", "",
           "# TODO #372 / #373: per DER-SEQUENCE label, each field's width cap",
           "# (significant bytes), its encoding (exactly its width, or minimal) and the",
           "# value rules.  enc[k] is (encoded width, lead): lead 1 when it starts with a",
           "# 0x00 the sign does not need, 2 with a sign byte.",
           "def _der_field_check(label, v, enc):",
           "    \"\"\"The refusal for the first field of v that breaks its row, else None.\"\"\"",
           "    n = len(v)",
           "    F = [x if x.bit_length() <= 48 else -1 for x in v]",
           "    L = [(x.bit_length() + 7) // 8 for x in v]",
           "    e = None"]
    first = True
    py = lambda fmt: fmt.replace("%lld", "%d")
    for label, rows in _cap_rows_by_label(caps).items():
        out.append("    %s label == %r:" % ("if" if first else "elif", label))
        first = False
        for r in rows:
            cond = "%d <= n <= %d" % (r["min_items"], r["max_items"])
            if r["when"]:
                cond += " and (%s)" % _cap_code(r["when"], "py")
            out.append("        if %s:" % cond)
            for c in r["caps"]:
                out.append("            if n > %d and L[%d] > (%s):" % (c["field"], c["field"],
                                                                     _cap_code(c["cap"], "py")))
                out.append("                return %r %% (label, %d, L[%d], %s)"
                           % (py(_MSG_WIDE), c["field"], c["field"], _cap_code(c["cap"], "py")))
            for c in r["caps"]:
                if c["exact"]:
                    out.append("            if n > %d and enc[%d][0] != (%s) and not (enc[%d][1] == 2 and enc[%d][0] + 1 == (%s)) and not ((%s) == 0 and enc[%d][0] == 1 and L[%d] == 0):"
                               % (c["field"], c["field"], _cap_code(c["cap"], "py"), c["field"], c["field"],
                                  _cap_code(c["cap"], "py"), _cap_code(c["cap"], "py"), c["field"], c["field"]))
                    out.append("                return %r %% (label, %d, enc[%d][0], %s)"
                               % (py(_MSG_EXACT), c["field"], c["field"], _cap_code(c["cap"], "py")))
                else:
                    out.append("            if n > %d and enc[%d][1] == 1:" % (c["field"], c["field"]))
                    out.append("                return %r %% (label, %d)" % (_MSG_MINIMAL, c["field"]))
            for rule in r["rules"]:
                out.append("            e = %s" % _rule_call(rule, "py"))
                out.append("            if e:")
                out.append("                return e")
            out.append("            return None")
    out.append("    return None")
    return out


def key_tag_labels(priv_algos, pem_labels):
    """tag -> (PRIVATE label, PUBLIC label) for every key type a CLI can generate."""
    out = {t: (l, l.replace("PRIVATE", "PUBLIC")) for t, l in priv_algos.items()}
    out["hcred"] = (pem_labels["PEM_HCRED_PRIV"], pem_labels["PEM_HCRED_PUB"])
    return out


def build_key_label_acceptance(priv_algos, pem_labels):
    labels = key_tag_labels(priv_algos, pem_labels)
    rows, seen = [], set()
    for sub, algo, flag, role, tags in KEY_LABEL_SITES:
        key = (sub, algo, flag)
        if key in seen:
            raise RuntimeError("duplicate key-label site %r" % (key,))
        seen.add(key)
        unknown = [t for t in tags if t not in labels]
        if unknown:
            raise RuntimeError("key-label site %r names unknown key tags %r" % (key, unknown))
        rows.append({"subcommand": sub, "algo": algo, "flag": flag, "role": role,
                     "accepts": list(tags),
                     "labels": [labels[t][i] for t in tags
                                for i in ((0,) if role == "priv" else (1,) if role == "pub"
                                          else (1, 0))]})
    return rows


def emit_c_key_table(rows, items, caps, ps, integ):
    width = max(len(r["labels"]) for r in rows) + 1
    out = ["/* " + _GEN_BANNER.replace("TODO #274", "TODO #366").replace("\n", "\n * ") + " */",
           "#ifndef HKX_KEY_LABEL_TABLE_H",
           "#define HKX_KEY_LABEL_TABLE_H", "",
           "/* Which key PEM labels each (subcommand, --algo, key flag) accepts. */",
           "typedef struct { const char *cmd, *algo, *flag, *tags;",
           "                 const char *labels[%d]; } HkxKeySite;" % width, "",
           "static const HkxKeySite HKX_KEY_SITES[] = {"]
    for r in rows:
        labs = ", ".join('"%s"' % l for l in r["labels"]) + ", 0"
        out.append('    {"%s", "%s", "%s", "%s",\n     {%s}},'
                   % (r["subcommand"], r["algo"], r["flag"], ", ".join(r["accepts"]), labs))
    out += ["};",
            "static const int HKX_KEY_SITES_N ="
            " (int)(sizeof(HKX_KEY_SITES) / sizeof(HKX_KEY_SITES[0]));", "",
            "/* TODO #367: DER INTEGER items each DER-SEQUENCE label carries (min, max). */",
            "typedef struct { const char *label; int min, max; } HkxDerItems;", "",
            "static const HkxDerItems HKX_DER_ITEMS[] = {"]
    for r in items:
        out.append('    {"%s", %d, %d},' % (r["label"], r["min"], r["max"]))
    out += ["};",
            "static const int HKX_DER_ITEMS_N ="
            " (int)(sizeof(HKX_DER_ITEMS) / sizeof(HKX_DER_ITEMS[0]));", ""]
    out += emit_c_field_caps(caps)
    out += emit_c_param_sets(ps)
    out += emit_c_enc_integrity(integ)
    out += ["#endif /* HKX_KEY_LABEL_TABLE_H */", ""]
    return "\n".join(out)


def emit_java_key_table(rows, items, caps, ps, integ):
    out = ["package herradurakex;", "",
           "/** " + _GEN_BANNER.replace("TODO #274", "TODO #366").replace("\n", "\n *  ") + " */",
           "final class KeyLabelTable {",
           "    private KeyLabelTable() { }", "",
           "    /** {subcommand, algo, flag, accepted tags, label...} per key site. */",
           "    static final String[][] SITES = {"]
    for r in rows:
        cells = [r["subcommand"], r["algo"], r["flag"], ", ".join(r["accepts"])] + r["labels"]
        out.append("        {" + ", ".join('"%s"' % c for c in cells) + "},")
    out += ["    };", "",
            "    /** TODO #367: {label, min, max} DER INTEGER items per DER-SEQUENCE label. */",
            "    static final String[][] DER_ITEMS = {"]
    for r in items:
        out.append('        {"%s", "%d", "%d"},' % (r["label"], r["min"], r["max"]))
    out += ["    };", ""]
    out += emit_java_field_caps(caps)
    out += emit_java_param_sets(ps)
    out += emit_java_enc_integrity(integ)
    out += ["}", ""]
    return "\n".join(out)


GO_KEY_BEGIN = "// BEGIN GENERATED key-label table (spec/generate_spec.py, TODO #366) -- DO NOT EDIT."
GO_KEY_END = "// END GENERATED key-label table"
PY_KEY_BEGIN = "# BEGIN GENERATED key-label table (spec/generate_spec.py, TODO #366) -- DO NOT EDIT."
PY_KEY_END = "# END GENERATED key-label table"


def _replace_region(src, begin, end, body, what):
    pat = re.compile(re.escape(begin) + r".*?" + re.escape(end), re.DOTALL)
    if not pat.search(src):
        raise RuntimeError("%s has no generated key-label region; restore the "
                           "BEGIN/END GENERATED key-label table markers" % what)
    return pat.sub(lambda _m: "\n".join([begin] + body + [end]), src, count=1)


def emit_go_key_region(go_src, rows, items, caps, ps, integ):
    body = ["var keySites = []keySite{"]
    for r in rows:
        body.append('\t{"%s", "%s", "%s", "%s", []string{%s}},'
                    % (r["subcommand"], r["algo"], r["flag"], ", ".join(r["accepts"]),
                       ", ".join('"%s"' % l for l in r["labels"])))
    body.append("}")
    body.append("")
    body.append("// TODO #367: DER INTEGER items each DER-SEQUENCE label carries (min, max).")
    body.append("var derItems = map[string][2]int{")
    for r in items:
        body.append('\t"%s": {%d, %d},' % (r["label"], r["min"], r["max"]))
    body.append("}")
    body.append("")
    body += emit_go_field_caps(caps)
    body += emit_go_param_sets(ps)
    body += emit_go_enc_integrity(integ)
    return _replace_region(go_src, GO_KEY_BEGIN, GO_KEY_END, body, "herradura_cli.go")


def emit_py_key_region(py_src, rows, items, caps, ps, integ):
    body = ["_KEY_SITES = {"]
    for r in rows:
        body.append("    (%r, %r, %r): (%r, (%s)),"
                    % (r["subcommand"], r["algo"], r["flag"], ", ".join(r["accepts"]),
                       " ".join("%r," % l for l in r["labels"])))
    body.append("}")
    body.append("")
    body.append("# TODO #367: DER INTEGER items each DER-SEQUENCE label carries (min, max).")
    body.append("_DER_ITEMS = {")
    for r in items:
        body.append("    %r: (%d, %d)," % (r["label"], r["min"], r["max"]))
    body.append("}")
    body.append("")
    body.append("")
    body += emit_py_field_caps(caps)
    body.append("")
    body += emit_py_param_sets(ps)
    body += emit_py_enc_integrity(integ)
    return _replace_region(py_src, PY_KEY_BEGIN, PY_KEY_END, body, "herradura.py")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true",
                     help="exit 1 if regenerating would change spec/herradura-protocol-spec.json")
    ap.add_argument("--require-schema", action="store_true",
                     help="with --check: fail rather than skip if the `jsonschema` package "
                          "is missing, so a silently-unvalidated spec cannot pass CI")
    args = ap.parse_args()

    spec = generate()
    new_text = json.dumps(spec, indent=2, sort_keys=False) + "\n"

    # TODO #274: the generated allow-lists travel with the spec, from the same
    # extractors, so they cannot describe a parser that no longer exists.
    generated = [
        (C_FLAG_TABLE, emit_c_flag_table(extract_flags_c(read(CLI_C)),
                                         extract_valued_flags_c(read(CLI_C)),
                                         build_help_synopsis(spec, "c"))),
        (JAVA_FLAG_TABLE, emit_java_flag_table(extract_flags_java(read(CLI_JAVA)),
                                               build_help_synopsis(spec, "java"),
                                               extract_bool_flags_java(read(CLI_JAVA),
                                                                       read(CLI_C)))),
        # TODO #339: Go's synopsis lives in a marked region of the CLI itself.
        (CLI_GO, emit_go_key_region(
            emit_go_help_region(read(CLI_GO), build_help_synopsis(spec, "go")),
            spec["key_label_acceptance"], spec["pem_der_items"], spec["pem_der_field_caps"],
            spec["key_parameter_sets"], spec["enc_integrity"])),
        # TODO #366: the key-label acceptance table, in all four CLIs (with
        # #367's item counts and #372's field caps).
        (C_KEY_TABLE, emit_c_key_table(spec["key_label_acceptance"], spec["pem_der_items"],
                                       spec["pem_der_field_caps"], spec["key_parameter_sets"],
                                       spec["enc_integrity"])),
        (JAVA_KEY_TABLE, emit_java_key_table(spec["key_label_acceptance"], spec["pem_der_items"],
                                             spec["pem_der_field_caps"], spec["key_parameter_sets"],
                                             spec["enc_integrity"])),
        (HERRADURA_PY, emit_py_key_region(read(HERRADURA_PY), spec["key_label_acceptance"],
                                                     spec["pem_der_items"],
                                                     spec["pem_der_field_caps"],
                                                     spec["key_parameter_sets"],
                                                     spec["enc_integrity"])),
    ]

    if args.check:
        if not os.path.exists(OUT_PATH):
            print(f"MISSING: {OUT_PATH} does not exist; run without --check to generate it.")
            return 1
        old_text = read(OUT_PATH)
        if old_text != new_text:
            print(f"STALE: {OUT_PATH} does not match what generate_spec.py currently produces.")
            print("Run: python3 spec/generate_spec.py")
            return 1
        print("OK: spec/herradura-protocol-spec.json is up to date.")
        for path, text in generated:
            rel = os.path.relpath(path, REPO)
            if not os.path.exists(path):
                print(f"MISSING: {rel} does not exist; "
                      f"run without --check to generate it.")
                return 1
            if read(path) != text:
                print(f"STALE: {rel} does not match the flags (or the --help "
                      f"synopsis) its CLI's parser actually reads.")
                print("Run: python3 spec/generate_spec.py")
                return 1
            print(f"OK: {rel} is up to date.")
        return validate_schema(spec, required=args.require_schema)

    with open(OUT_PATH, "w") as f:
        f.write(new_text)
    for path, text in generated:
        with open(path, "w") as f:
            f.write(text)
        print(f"Wrote {os.path.relpath(path, REPO)}")
    print(f"Wrote {OUT_PATH} ({len(spec['protocols'])} protocols, "
          f"{len(spec['wire_format_labels'])} additional wire-format labels).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
