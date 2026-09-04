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
            hits = len(re.findall(pattern, file_text[lang], re.M))
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
