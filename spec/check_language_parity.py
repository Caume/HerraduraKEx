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
    "Demo.java",           # suite walkthrough
    "CodecTest.java",      # test driver
    "KatVerify.java",      # KAT consumer, the Java counterpart of KAT/verify_kat.go
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
        "go": r"^func hcredOutputsSer\(",
        "python": r"^def _hcred_outputs_ser\(",
        "java": r"Hcred.java::private static byte\[\] outputsSer\(",
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
        "java": r"Stern.java::private static int\[\] refill\(",
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
        "c": r"static void rnl_cbd_poly\(",
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
        "java": r"HerraduraNl.java::private static BigInteger mInv\(",
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
        "acknowledged":
            "HSKE-NL-AEAD is not in the Java port's suite -- "
            "HerraduraCli.java's class doc records --aead as out of scope, "
            "which TODO #267 now tracks as a CLI-flag asymmetry rather than a "
            "comment. The other three are byte-compatible by "
            "CliTest/test_aead.sh's 9-way matrix",
        "c": r"static void _hske_nl_aead_xor_ks\(",
        "go": r"^func hskeNlAeadXorKs\(",
        "python": r"^def _hske_nl_aead_xor_keystream\(",
    },
    "hske-nl-aead-tag": {
        "acknowledged":
            "see hske-nl-aead-xor-ks (TODO #267)",
        "c": r"static void _hske_nl_aead_tag\(",
        "go": r"^func hskeNlAeadTag\(",
        "python": r"^def _hske_nl_aead_tag\(",
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
        "java": r"FpeTwk.java::private static BigInteger deriveB\(",
    },
    "fpe-twk-v3-derive-b": {
        "c": r"static inline void fpe_twk_v3_derive_b\(",
        "go": r"^func fpeTwkV3DeriveB\(",
        "python": r"^def _fpe_twk_v3_derive_b\(",
        "java": r"FpeTwk.java::private static BigInteger deriveBv3\(",
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
        "java": r"Herradura.java::public static BigInteger hkexGfAgree\(",
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
                r"hpkeEncrypt\(BigInteger pt, BigInteger pub, BigInteger r",
    },
    "hpke-decrypt": {
        "c": r"static inline int hpke_decrypt\(",
        "go": r"^func HpkeDecrypt\(",
        "python": r"^def hpke_decrypt\(",
        "java": r"Herradura.java::public static BigInteger hpkeDecrypt\(",
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
        "java": r"Ratchet.java::public static BigInteger init\(",
    },
    "hmac-hfscx-256": {
        "acknowledged":
            "HMAC-HFSCX-256-DM (SecurityProofs-6.md 11.9.6) is absent from the "
            "Java port. Its only consumer is the Python CLI's PBKDF2 for "
            "passphrase-encrypted PEMs (TODO #166), which is itself Python-CLI- "
            "only -- the CLI-flag asymmetry TODO #267 opens over. C and Go "
            "carry the primitive with no consumer at all",
        "c": r"static void hmac_hfscx_256\(",
        "go": r"^func HmacHfscx256\(",
        "python": r"^def hmac_hfscx_256\(",
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
        "java": r"Herradura.java::public static BigInteger fscx\(",
    },
    "fscx-revolve": {
        "c": r"static void ba_fscx_revolve\(",
        "go": r"^func FscxRevolve\(",
        "python": r"^def fscx_revolve\(",
        "java": r"Herradura.java::public static BigInteger fscxRevolve\(",
    },
    "nl-fscx-v1": {
        "c": r"static void nl_fscx_v1_ba\(",
        "go": r"^func NlFscxV1\(",
        "python": r"^def nl_fscx_v1\(",
        "java": r"Hfscx256.java::public static BigInteger nlFscxV1\(",
    },
    "nl-fscx-v2": {
        "c": r"static void nl_fscx_v2_ba\(",
        "go": r"^func NlFscxV2\(",
        "python": r"^def nl_fscx_v2\(",
        "java": r"HerraduraNl.java::public static BigInteger nlFscxV2\(",
    },
    "nl-fscx-v2-inv": {
        "c": r"static void nl_fscx_v2_inv_ba\(",
        "go": r"^func NlFscxV2Inv\(",
        "python": r"^def nl_fscx_v2_inv\(",
        "java": r"HerraduraNl.java::public static BigInteger nlFscxV2Inv\(",
    },
    "nl-fscx-v3": {
        "c": r"static void nl_fscx_v3_ba\(",
        "go": r"^func NlFscxV3\(",
        "python": r"^def nl_fscx_v3\(",
        "java": r"HerraduraNl.java::public static BigInteger nlFscxV3\(",
    },
    "nl-fscx-v3-inv": {
        "c": r"static void nl_fscx_v3_inv_ba\(",
        "go": r"^func NlFscxV3Inv\(",
        "python": r"^def nl_fscx_v3_inv\(",
        "java": r"HerraduraNl.java::public static BigInteger nlFscxV3Inv\(",
    },
    "nl-chi-v3": {
        "c": r"static void nl_chi_v3_ba\(",
        "go": r"^func NlChiV3\(",
        "python": r"^def nl_chi_v3\(",
        "java": r"HerraduraNl.java::public static BigInteger nlChiV3\(",
    },
    "nl-chi-v3-inv": {
        "c": r"static void nl_chi_v3_inv_ba\(",
        "go": r"^func NlChiV3Inv\(",
        "python": r"^def nl_chi_v3_inv\(",
        "java": r"HerraduraNl.java::public static BigInteger nlChiV3Inv\(",
    },
    "nl-fscx-revolve-v1": {
        "c": r"static void nl_fscx_revolve_v1_ba\(",
        "go": r"^func NlFscxRevolveV1\(",
        "python": r"^def nl_fscx_revolve_v1\(",
        "java": r"Hfscx256.java::public static BigInteger nlFscxRevolveV1\(",
    },
    "nl-fscx-revolve-v2": {
        "c": r"static void nl_fscx_revolve_v2_ba\(",
        "go": r"^func NlFscxRevolveV2\(",
        "python": r"^def nl_fscx_revolve_v2\(",
        "java": r"HerraduraNl.java::public static BigInteger nlFscxRevolveV2\(",
    },
    "nl-fscx-revolve-v2-inv": {
        "c": r"static void nl_fscx_revolve_v2_inv_ba\(",
        "go": r"^func NlFscxRevolveV2Inv\(",
        "python": r"^def nl_fscx_revolve_v2_inv\(",
        "java": r"HerraduraNl.java::public static BigInteger "
                r"nlFscxRevolveV2Inv\(",
    },
    "nl-fscx-revolve-v3": {
        "c": r"static void nl_fscx_revolve_v3_ba\(",
        "go": r"^func NlFscxRevolveV3\(",
        "python": r"^def nl_fscx_revolve_v3\(",
        "java": r"HerraduraNl.java::public static BigInteger nlFscxRevolveV3\(",
    },
    "nl-fscx-revolve-v3-inv": {
        "c": r"static void nl_fscx_revolve_v3_inv_ba\(",
        "go": r"^func NlFscxRevolveV3Inv\(",
        "python": r"^def nl_fscx_revolve_v3_inv\(",
        "java": r"HerraduraNl.java::public static BigInteger "
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
        "java": r"HerraduraNl.java::private static BigInteger delta\(",
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
            "the width-parameterised v1 step used by ZKBoo and aPAKE at n=32, "
            "where the suite default is 256. C (zkp_nl_f1) and Java "
            "(ZkpNl.nlFscxV1General) name it; Go and Python pass the width to "
            "nl-fscx-v1 itself",
        "c": r"static uint64_t zkp_nl_f1\(",
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
        "java": r"Herradura.java::public static BigInteger hskeEncrypt\(",
    },
    "hske-decrypt": {
        "acknowledged":
            "see hske-encrypt: the inverse direction, same argument",
        "c": r"static inline void hske_decrypt\(",
        "java": r"Herradura.java::public static BigInteger hskeDecrypt\(",
    },
    "hpks-sign": {
        "acknowledged":
            "Go and Python build the Schnorr signature inline from gf_pow and "
            "fscx_revolve; C and Java name the whole operation. Pinned four "
            "ways by KAT/classical_quartet.json's HPKS vectors",
        "c": r"static inline void hpks_sign\(",
        "java": r"Herradura.java::public static Signature hpksSign\(BigInteger "
                r"msg, BigInteger priv, BigInteger k",
    },
    "hkex-gf-pubkey": {
        "acknowledged":
            "C = g^a is one gf_pow call, which Go and Python make at the call "
            "site. Note the asymmetry runs the other way from hkex-gf-agree, "
            "which all four name",
        "c": r"static inline void hkex_gf_pubkey\(",
        "java": r"Herradura.java::public static BigInteger hkexGfPubkey\(",
    },
    # ── fpe / twk block operations (TODO #261, v6.1.0) ────────────────────
    # The eight enc/dec entry points across {fpe, twk} x {v2, v3}, and the three
    # per-domain derivation wrappers C and Go keep. TODO #242 separated fpe from
    # twk; test [46] guards the behaviour and these guard the shape.
    "fpe-encrypt": {
        "c": r"static inline void fpe_encrypt\(",
        "go": r"^func FpeEncrypt\(",
        "python": r"^def fpe_encrypt\(",
        "java": r"FpeTwk.java::public static BigInteger fpeEncrypt\(",
    },
    "fpe-decrypt": {
        "c": r"static inline void fpe_decrypt\(",
        "go": r"^func FpeDecrypt\(",
        "python": r"^def fpe_decrypt\(",
        "java": r"FpeTwk.java::public static BigInteger fpeDecrypt\(",
    },
    "fpe-v3-encrypt": {
        "c": r"static inline void fpe_v3_encrypt\(",
        "go": r"^func FpeV3Encrypt\(",
        "python": r"^def fpe_v3_encrypt\(",
        "java": r"FpeTwk.java::public static BigInteger fpeV3Encrypt\(",
    },
    "fpe-v3-decrypt": {
        "c": r"static inline void fpe_v3_decrypt\(",
        "go": r"^func FpeV3Decrypt\(",
        "python": r"^def fpe_v3_decrypt\(",
        "java": r"FpeTwk.java::public static BigInteger fpeV3Decrypt\(",
    },
    "twk-encrypt": {
        "c": r"static inline void twk_encrypt\(",
        "go": r"^func TwkEncrypt\(",
        "python": r"^def twk_encrypt\(",
        "java": r"FpeTwk.java::public static BigInteger twkEncrypt\(",
    },
    "twk-decrypt": {
        "c": r"static inline void twk_decrypt\(",
        "go": r"^func TwkDecrypt\(",
        "python": r"^def twk_decrypt\(",
        "java": r"FpeTwk.java::public static BigInteger twkDecrypt\(",
    },
    "twk-v3-encrypt": {
        "c": r"static inline void twk_v3_encrypt\(",
        "go": r"^func TwkV3Encrypt\(",
        "python": r"^def twk_v3_encrypt\(",
        "java": r"FpeTwk.java::public static BigInteger twkV3Encrypt\(",
    },
    "twk-v3-decrypt": {
        "c": r"static inline void twk_v3_decrypt\(",
        "go": r"^func TwkV3Decrypt\(",
        "python": r"^def twk_v3_decrypt\(",
        "java": r"FpeTwk.java::public static BigInteger twkV3Decrypt\(",
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
    "qcmdpc-upc": {
        "acknowledged":
            "Java factors the BGF unsatisfied-parity-check counter out of the "
            "decoder loop; C, Go and Python count inline in qcmdpc-bgf-decode. "
            "The decoder is DFR-critical and covered behaviourally by "
            "CliTest/lib_dfr.sh's byte compare",
        "java": r"Stern.java::private static int\[\] computeUpc\(",
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
            "Python splits the AEAD's keystream and MAC-key derivation into a "
            "streams helper; C and Go derive both in hske-nl-aead-xor-ks, and "
            "Java has no counter-mode AEAD at all (TODO #267)",
        "python": r"^def _hske_nl_aead_streams\(",
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
                if reason:
                    continue
                errors.append(
                    f"'{pid}': marker {pattern!r} not found in {lang}'s suite file(s) ({rel}) — "
                    f"either the function was renamed/removed (update PRIMITIVES to match) or "
                    f"this is a real cross-language gap (port it, or add an 'acknowledged' "
                    f"reason to the PRIMITIVES entry, the same way SECURITY.md records one)"
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
        (r"^_?ba(33)?_", "BitArray limb plumbing (shift/compare/popcount/print/rand "
                         "over the fixed 256-bit array). C alone needs it: Go and "
                         "Python carry big integers with these as built-ins, and Java "
                         "has BigInteger. Not a protocol step in any language"),
        (r"_(alloc|free)$", "manual allocation/release of a proof or signature struct. "
                            "Go, Python and Java are garbage-collected and have no "
                            "counterpart by construction"),
        (r"^_?(qcp|qcprf|qceuc)_(?!mul_sparse$|inv$|mul$|refill$)",
         "QC-MDPC bit-polynomial and PRF plumbing (get/set/copy/xor/rotate/popcount, "
         "the xorshift and degree helpers). The four members that ARE protocol steps "
         "— qcp_mul, qcp_mul_sparse, qcp_inv, qcprf_refill — are excluded from this "
         "rule and carry manifest entries"),
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
        (r"^(New|new)", "constructors for BitArray/QcMdpcPrf — the receiver surface "
                        "the DECL_PATTERNS comment excludes, reached through a "
                        "top-level func because Go has no constructors"),
        (r"^(bitArrayMask|bitCount|CountBits|lowestSetBit|putLE|word16|draw|draws|"
         r"intSlicesEqual|qcpRotate)$",
         "bit/byte/slice plumbing on Go's own representation; C's counterparts are "
         "the exempted ba_ and qcp_ families and Python's are built in"),
        (r"^(oprfOrd|rnlTwGet)$",
         "accessors for a value the other three keep as a constant or recompute: "
         "the OPRF group order, and one twiddle from the table C's exempted "
         "rnl_twiddle_ family builds"),
    ],
    "python": [],
    "java": [
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


def main():
    errors = []
    numbers = check_numbered_tests(errors)
    check_shared_numbering(errors, numbers)
    checked = check_primitives(errors)
    census = check_census(errors)

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
    print(
        "OK: internal-surface census — "
        + "; ".join(
            f"{lang} {internal} internal of {declared} declared, {named} manifest-named"
            for lang, (declared, internal, named) in census.items()
        )
        + "; every remainder carries a CENSUS_EXEMPT reason."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
