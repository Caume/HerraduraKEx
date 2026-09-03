#!/usr/bin/env python3
"""Generates spec/herradura-protocol-spec.json from the suite's own source files
(TODO #133), so the machine-readable spec cannot silently drift from what the
CLIs actually implement.

Mechanically extracted (regex, not hand-copied) from source:
  - Algo tag -> PEM private/public key label mapping: HerraduraCli/herradura.py's
    `_PRIV_ALGOS` dict (the single most complete, most explicit definition across
    the three CLI implementations -- it covers every genpkey-producible algo).
  - Every wire-format PEM_* label: HerraduraCli/herradura_codec.h.
  - Per-subcommand --algo choices: HerraduraCli/herradura.py's argparse
    `choices=[...]` lists (enc/dec/sign/verify/kex/encfile/decfile/dgst).
  - Protocol parameter constants: herradura.h (#define) and herradura/herradura.go
    (const block), grepped by name.

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
HERRADURA_GO = os.path.join(REPO, "herradura", "herradura.go")
CLI_C = os.path.join(REPO, "HerraduraCli", "herradura_cli.c")
CLI_GO = os.path.join(REPO, "HerraduraCli", "herradura_cli.go")
# TODO #261: the fourth CLI.  bindings/java/ carries a complete port of the suite
# AND a herradurakex.HerraduraCli mirroring the Python CLI's subcommands and
# --algo values, but cli_support was a three-column table until v5.8.7, so
# Java's coverage -- and its five gaps -- were invisible to spec/ by construction.
CLI_JAVA = os.path.join(REPO, "bindings", "java", "herradurakex", "HerraduraCli.java")
OUT_PATH = os.path.join(REPO, "spec", "herradura-protocol-spec.json")
SCHEMA_PATH = os.path.join(REPO, "spec", "herradura-protocol-spec.schema.json")

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
                             "same ~2^36.5 Pohlig-Hellman key recovery, which yields arbitrary forgery.",
                       source=["TODO.md #127", "TODO_DONE.md #212"]),
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
                             "`pedagogical` is what SECURITY.md has always said, and matches hpks.",
                       source=["SECURITY.md", "TODO_DONE.md #212", "SecurityProofs-4.md 11.7"]),
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
                              "compile-time constant: since v3.1.0 all three CLIs accept `sign --rounds` and "
                              "any reader accepts any count in [1, SDF_MAX_ROUNDS] regardless of its own "
                              "SDF_ROUNDS, which is only the signing default (TODO #236). Before that the C "
                              "reader rejected any count != SDF_ROUNDS, so two C builds were mutually "
                              "unreadable and cross-language HCRED interop ran only at 32 rounds. Round "
                              "count and instance hardness are independent axes -- 219 rounds over the "
                              "deployed N=256 is still ~30-40 bits and still demo-only.",
                        source=["herradura.h:1383-1392", "herradura/herradura.go:1108-1110",
                                "TODO.md #236"]),
    "hybrid-rnl-stern": dict(status="demo-only", quantum_resistant="conjectured",
                        classical_security_bits="~206 Core-SVP on the Ring-LWR half at n=1024; the "
                                                  "QC-MDPC half is capped by its 2^-8.6 DFR, not by a "
                                                  "work factor",
                        notes="Hybrid key exchange combining HKEX-RNL with HPKE-Stern-KEM. Shipped as a "
                              "`kex --algo` value by all three CLIs since TODO #167, but it had no entry "
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
                        notes="Niederreiter KEM (Stern-based). Demo uses a known error vector e'; production "
                              "requires an actual QC-MDPC syndrome decoder, not yet implemented.",
                        source=["CLAUDE.md:228", "TODO.md #126 (6896-6924)"]),
    "hpke-stern-kem": dict(status="demo-only", quantum_resistant="conjectured",
                        notes="Niederreiter/QC-MDPC KEM with a real Black-Gray-Flip (BGF) "
                              "syndrome decoder (qcmdpc_keygen/encap/decap_bgf) -- unlike "
                              "hpke-stern, decap does not need the plaintext error vector. "
                              "Toy parameters (r=523, d=15, t=18); measured Decoding Failure "
                              "Rate 0.264% per encapsulation (95% CI [0.236%, 0.295%], "
                              "n=120000 trials, TODO #218; consistent with the 0.225% of "
                              "TODO #195) -- well above production security margins (BIKE "
                              "targets DFR <= 2^-128 at r=12323), so CliTest scripts that "
                              "decapsulate retry a fresh encapsulation rather than treating "
                              "a DFR event as a bug (CliTest/lib_dfr.sh, TODO #221). "
                              "Reclassified demo-only in TODO #218, which listed four "
                              "blockers; TODO #235 closed the two that were missing "
                              "constructions rather than parameter choices. Keygen now "
                              "screens weak keys (distance-spectrum multiplicity capped at "
                              "5, so the ~1-in-3400 class carrying roughly 10x the average "
                              "DFR is unreachable), and decapsulation applies a "
                              "Fujisaki-Okamoto transform with implicit rejection: it "
                              "checks rigidity -- which at an invertible h0 reduces exactly "
                              "to wt(e)=t -- and returns HFSCX-256-DS(0x11, z || C) on any "
                              "failure instead of reporting one, so the GJS reaction attack "
                              "no longer has an oracle. Still demo-only, and TODO #235 was "
                              "scoped not to change that: IND-CCA2 needs DFR <= 2^-128 and "
                              "this is 2^-8.6, and the underlying QC syndrome-decoding "
                              "instance at these parameters is far below any usable level. "
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
                       notes="Winternitz one-time signature (hash-based). Strictly one-time -- reuse of a WOTS "
                             "key is refused by the CLI.",
                       source=["herradura.h WOTS_* constants"]),
    "hpks-xmss": dict(status="production", quantum_resistant="conjectured",
                       notes="Stateful hash-based signature (XMSS over the WOTS chains of hpks-wots), "
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
                               "CliTest/test_cross_lang_matrix.sh"]),
    "hpks-ring": dict(status="demo-only", quantum_resistant="conjectured",
                       notes="Anonymous ring signature built on hpks-stern keys; inherits hpks-stern's "
                             "demo-rounds soundness caveat.",
                       source=["herradura.h SDF_* constants"]),
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
                       notes="NL-FSCX v1 counter-mode; supports --aead authenticated encryption. Unlike "
                             "classical hske, a known-plaintext pair does NOT break this construction: it "
                             "yields that one block's keystream and nothing else, which is inherent to "
                             "counter mode rather than a weakness. The classical 1-pair attack works by "
                             "solving E = M^i.P XOR T_i.K for T_i.K and reusing it on other ciphertexts; "
                             "the v1 carry non-linearity makes the keystream non-affine in base, so that "
                             "step has no analogue here (TODO #210, #237). Security rests on the "
                             "conjecture that NL-FSCX v1 is a PRF (SecurityProofs-4.md 11.3.1) -- an "
                             "assumption, not a proof.",
                       source=["TODO.md #237", "TODO_DONE.md #210"]),
    "hske-nla2": dict(status="demo-only", quantum_resistant="conjectured",
                       notes="NL-FSCX v2 revolve-mode symmetric encryption -- a keyed bijection, not a "
                             "stream cipher, so there is no keystream for a known-plaintext pair to "
                             "recover and E XOR P is not constant across messages. Two usage constraints "
                             "are load-bearing. (1) Deterministic: the same (P, K) always gives the same "
                             "E, so it is not IND-CPA in the multi-message sense unless the caller embeds "
                             "a nonce or sequence number in the plaintext; prefer hske-nla1 when several "
                             "messages share a key (SecurityProofs-4.md 11.3.2). (2) Keys with "
                             "delta(K) in {0, 2^(n-1)} collapse the permutation to GF(2)-affine and are "
                             "recoverable from a handful of known plaintexts; the class is about 2^-129 "
                             "of the key space and all three CLIs refuse it via nl_v2_key_is_valid "
                             "(SecurityProofs-7.md 11.19.2). (3) NEW in TODO #244, and the reason this "
                             "entry was DOWNGRADED FROM production in v4.0.2: the construction is "
                             "self-similar -- one unvaried round iterated 192 times, no round constant, "
                             "no key schedule -- so one slid pair very nearly determines the key and the "
                             "~2^128 birthday cost of finding one does not depend on the round count, and "
                             "it is provably not an ideal cipher, showing ~14 fixed points (tau(192); "
                             "measured 13.84 at n=16) where an ideal cipher shows 1. Neither is an attack "
                             "at n=256 and A2 is not broken -- bijectivity is proven and no attack is "
                             "known -- but the rating rested on nl_fscx_revolve_v2 being a PRP/SPRP, for "
                             "which no result exists at any round count. TODO #243 refused to promote twk "
                             "on identical evidence about the identical permutation, and A2 is the worse "
                             "of the two because its key is caller-supplied. Candidate fixes (round "
                             "constants; a prime round count, since the fixed-point excess is tau(r)) are "
                             "TODO #245, which shipped round constants in v5.0.0 -- the "
                             "structural objection is answered but the missing PRP/SPRP "
                             "reduction is not, so the rating is unchanged.",
                       source=["TODO.md #237", "TODO_DONE.md #159", "TODO_DONE.md #168",
                               "TODO_DONE.md #244",
                               "SecurityProofsCode/hske_nl_a2_rating_review.py",
                               "SecurityProofs-7.md 11.25, 11.26"]),
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
                             "\"v1 is a PRF\" assumption instead.",
                       source=["TODO.md #237", "herradura.h HSKE-NL-V2-Duplex banner",
                               "SecurityProofs-6.md 11.9"]),
    "hfscx-256": dict(status="production", quantum_resistant="conjectured",
                       classical_security_bits="256-bit digest; 128-bit collision resistance in the "
                                                 "ideal-random-function model",
                       notes="256-bit Merkle-Damgard hash on NL-FSCX v1 with Davies-Meyer feed-forward, "
                             "re-derived in the ideal-random-function model under TODO #215. The generic "
                             "Merkle-Damgard weaknesses apply and are not defects of this construction: "
                             "Joux multicollisions and Kelsey-Schneier expandable-message second "
                             "preimages both work against it as against any MD hash without a wide pipe. "
                             "The compression function's own differential profile rests on the NL-FSCX v1 "
                             "PRF conjecture, so treat the classification as conditional on that.",
                       source=["SecurityProofs-6.md 11.9", "TODO_DONE.md #215",
                               "SecurityProofsCode/hfscx_dm_rf_model.py"]),
    "hfscx-256-ds": dict(status="production", quantum_resistant="conjectured",
                       notes="hfscx-256 with an explicit domain-separation parameter; same construction, "
                             "same caveats, distinct digests per tag.",
                       source=["SecurityProofs-6.md 11.9", "TODO_DONE.md #215"]),
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
                             "domain -- it maps 32 bytes to 32 bytes, zero-pads shorter input and "
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
    "twk":       dict(status="demo-only", quantum_resistant="conjectured",
                       notes="Per-(sector, block-index) tweaked 256-bit permutation, reached "
                             "through the `twk` subcommand rather than an --algo tag. The shape is "
                             "right for disk encryption and determinism per tweak is the expected "
                             "XTS-style property, not a defect. Three things keep it below "
                             "production. TODO #242 (v4.0.0) closed all three of the blockers "
                             "TODO #241 recorded: it is now domain-separated from fpe with tag "
                             "0x21 rather than sharing an unseparated HFSCX-256(key || tweak) "
                             "derivation, the key||tweak boundary is length-encoded, and it runs "
                             "nl_fscx_revolve_v2 at R_VALUE=192 rather than I_VALUE=64, matching "
                             "HSKE-NL-A2. What keeps it demo-only is now the absence of a positive "
                             "result rather than a defect list: no reduction to a standard "
                             "tweakable-cipher security definition (no STPRP argument), and "
                             "NL-FSCX v2's security is conjectural with only key-averaged trail "
                             "bounds behind it. TODO #243 reviewed it for promotion and KEPT it "
                             "demo-only: in the random-oracle model twk is an STPRP exactly if "
                             "nl_fscx_revolve_v2 is an SPRP under a uniform key, and no such result "
                             "exists -- the permutation is one unvaried round iterated 192 times "
                             "with no round constant and no key schedule, so one slid pair "
                             "determines the key and the ~2^128 cost of finding one does not "
                             "depend on the round count. twk is nonetheless stronger than "
                             "HSKE-NL-A2 on three axes because its subkey is a hash output: key "
                             "recovery is confined to one block, the degenerate affine class is "
                             "unreachable, and per-tweak determinism is expected rather than a "
                             "constraint. That contains the blast radius of an unproven assumption "
                             "without replacing the missing proof. A2 carries the same assumption "
                             "at production-track with worse failure consequences; re-rating A2 is "
                             "TODO #244. Wire-format breaking in v4.0.0 -- every earlier twk "
                             "ciphertext is undecryptable, silently; see MIGRATING.md section 8.",
                       source=["Herradura cryptographic suite.py twk_encrypt/twk_decrypt",
                               "herradura.h twk_encrypt", "herradura/herradura.go TwkEncrypt",
                               "SecurityProofsCode/rand_fpe_twk_analysis.py",
                               "SecurityProofsCode/twk_stprp_review.py",
                               "SECURITY.md", "SecurityProofs-7.md 11.24, 11.25"]),
    "hske-nla3": dict(status="demo-only", quantum_resistant="conjectured",
                       notes="NL-FSCX v3 revolve-mode symmetric encryption -- hske-nla2's shape over "
                             "the v3 round. The NL-FSCX v3 round is the deployed v2 round followed by a Keccak-chi layer over 47 five-bit and 3 seven-bit rows, at R3_VALUE = 5n/8 = 160 rounds (TODO #255). It is ADDED alongside v2, not a replacement: no stored artifact changes and the v2 tag keeps working. Its margin is wider than v2's and for the first time in this family it rests on a PROOF -- chi gives the round an unconditional per-round trail floor of 4 - log2(5) = 1.6781 bits differential and 1 bit linear, where v2 provably has none (its linear-then-add-constant round hands every key a probability-1 one-round differential). There is deliberately NO key check: both v2 weak classes dissolve under chi and there is no chi-specific class to screen, proven exhaustively rather than sampled (SecurityProofs-8.md 11.34.4). IT ARRIVES DEMO-ONLY ANYWAY, and that is the point of the rating: v3 has the same two MISSING items as v2 -- no PRP/SPRP reduction, and no trail bound at realistic width on either axis (TODO #252, #254 are unchanged by v3 existing). A wider margin is not a promotion. "
                             "hske-nla2's two usage constraints carry over unchanged except the "
                             "weak-key one: it is still DETERMINISTIC (same (P, K) gives the same E, "
                             "so embed a nonce or prefer hske-nla1 when several messages share a "
                             "key), and self-similarity is answered by v2's round constant, which v3 "
                             "inherits verbatim -- an XOR round constant leaves xdp+ exactly "
                             "invariant (TODO #245). The affine-weak-key refusal is GONE because the "
                             "class is gone.",
                       source=["TODO.md #255", "SecurityProofs-8.md 11.34",
                               "SecurityProofsCode/nl_fscx_v3_round_count.py",
                               "SecurityProofsCode/nl_fscx_v3_weak_keys.py"]),
    "hske-duplex3": dict(status="research", quantum_resistant="conjectured",
                       notes="hske-duplex's MonkeyDuplex sponge over the v3 permutation, with its own "
                             "domain-separation strings and its own format tag (4, against v2's 3), so "
                             "a v2 artifact is rejected by the parser rather than surfacing as an "
                             "opaque tag mismatch. The NL-FSCX v3 round is the deployed v2 round followed by a Keccak-chi layer over 47 five-bit and 3 seven-bit rows, at R3_VALUE = 5n/8 = 160 rounds (TODO #255). It is ADDED alongside v2, not a replacement: no stored artifact changes and the v2 tag keeps working. Its margin is wider than v2's and for the first time in this family it rests on a PROOF -- chi gives the round an unconditional per-round trail floor of 4 - log2(5) = 1.6781 bits differential and 1 bit linear, where v2 provably has none (its linear-then-add-constant round hands every key a probability-1 one-round differential). There is deliberately NO key check: both v2 weak classes dissolve under chi and there is no chi-specific class to screen, proven exhaustively rather than sampled (SecurityProofs-8.md 11.34.4). IT ARRIVES DEMO-ONLY ANYWAY, and that is the point of the rating: v3 has the same two MISSING items as v2 -- no PRP/SPRP reduction, and no trail bound at realistic width on either axis (TODO #252, #254 are unchanged by v3 existing). A wider margin is not a promotion. "
                             "The sponge round count is I3_VALUE = 5n/16 = 80, and it is the FIRST "
                             "duplex round count in this suite that is derived rather than inherited: "
                             "the capacity is 128 bits, so 128 bits is the target, and the per-round "
                             "floors put the requirement at r >= 77 differential and r >= 64 linear. "
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
                             "The NL-FSCX v3 round is the deployed v2 round followed by a Keccak-chi layer over 47 five-bit and 3 seven-bit rows, at R3_VALUE = 5n/8 = 160 rounds (TODO #255). It is ADDED alongside v2, not a replacement: no stored artifact changes and the v2 tag keeps working. Its margin is wider than v2's and for the first time in this family it rests on a PROOF -- chi gives the round an unconditional per-round trail floor of 4 - log2(5) = 1.6781 bits differential and 1 bit linear, where v2 provably has none (its linear-then-add-constant round hands every key a probability-1 one-round differential). There is deliberately NO key check: both v2 weak classes dissolve under chi and there is no chi-specific class to screen, proven exhaustively rather than sampled (SecurityProofs-8.md 11.34.4). IT ARRIVES DEMO-ONLY ANYWAY, and that is the point of the rating: v3 has the same two MISSING items as v2 -- no PRP/SPRP reduction, and no trail bound at realistic width on either axis (TODO #252, #254 are unchanged by v3 existing). A wider margin is not a promotion. "
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
                             "The NL-FSCX v3 round is the deployed v2 round followed by a Keccak-chi layer over 47 five-bit and 3 seven-bit rows, at R3_VALUE = 5n/8 = 160 rounds (TODO #255). It is ADDED alongside v2, not a replacement: no stored artifact changes and the v2 tag keeps working. Its margin is wider than v2's and for the first time in this family it rests on a PROOF -- chi gives the round an unconditional per-round trail floor of 4 - log2(5) = 1.6781 bits differential and 1 bit linear, where v2 provably has none (its linear-then-add-constant round hands every key a probability-1 one-round differential). There is deliberately NO key check: both v2 weak classes dissolve under chi and there is no chi-specific class to screen, proven exhaustively rather than sampled (SecurityProofs-8.md 11.34.4). IT ARRIVES DEMO-ONLY ANYWAY, and that is the point of the rating: v3 has the same two MISSING items as v2 -- no PRP/SPRP reduction, and no trail bound at realistic width on either axis (TODO #252, #254 are unchanged by v3 existing). A wider margin is not a promotion.",
                       source=["TODO.md #255", "SecurityProofs-8.md 11.34",
                               "SecurityProofs-7.md 11.24.2"]),
    "twk-v3":    dict(status="demo-only", quantum_resistant="conjectured",
                       notes="Reached as `twk --v3`; see fpe-v3 for why a flag rather than a "
                             "subcommand. twk's shape over the v3 round, domain-separated with tag "
                             "0x23. The NL-FSCX v3 round is the deployed v2 round followed by a Keccak-chi layer over 47 five-bit and 3 seven-bit rows, at R3_VALUE = 5n/8 = 160 rounds (TODO #255). It is ADDED alongside v2, not a replacement: no stored artifact changes and the v2 tag keeps working. Its margin is wider than v2's and for the first time in this family it rests on a PROOF -- chi gives the round an unconditional per-round trail floor of 4 - log2(5) = 1.6781 bits differential and 1 bit linear, where v2 provably has none (its linear-then-add-constant round hands every key a probability-1 one-round differential). There is deliberately NO key check: both v2 weak classes dissolve under chi and there is no chi-specific class to screen, proven exhaustively rather than sampled (SecurityProofs-8.md 11.34.4). IT ARRIVES DEMO-ONLY ANYWAY, and that is the point of the rating: v3 has the same two MISSING items as v2 -- no PRP/SPRP reduction, and no trail bound at realistic width on either axis (TODO #252, #254 are unchanged by v3 existing). A wider margin is not a promotion. "
                             "WHAT KEEPS IT DEMO-ONLY IS EXACTLY WHAT KEEPS twk DEMO-ONLY: TODO "
                             "#243 refused to promote twk because in the ROM it is an STPRP iff the "
                             "permutation is an SPRP under a uniform key, and no such result exists. "
                             "v3 does not supply one. It removes the structural objection TODO #243 "
                             "recorded alongside it -- the round is no longer linear-then-add-constant "
                             "-- and it inherits twk's three genuine advantages over hske-nla3, all "
                             "from the subkey being a hash output: key recovery is confined to one "
                             "block, no caller-supplied key reaches the permutation, and per-tweak "
                             "determinism is the expected XTS-style property rather than a "
                             "constraint. A promotion is #248-shaped work on separate evidence.",
                       source=["TODO.md #255", "TODO_DONE.md #243", "SecurityProofs-8.md 11.34",
                               "SecurityProofs-7.md 11.24"]),
    "hcred":     dict(status="research", quantum_resistant="conjectured",
                       notes="Hybrid Ring-LWR + Stern-F credential over a unified ZKBoo-(2,3) "
                             "MPC-in-the-head circuit. All three CLIs dispatch cred-issue/cred-prove/"
                             "cred-verify -- the \"Python and C CLI only, not in Go\" note this row "
                             "used to carry was stale, and nothing checked it (TODO #238).",
                       source=["TODO_DONE.md #128", "SecurityProofs-7.md 11.10.8-11.10.10"]),
}

# (Cross-implementation CLI support is no longer curated -- see extract_cli_tags.)
# (not just --help banners, which under-document some algos in C and Go --
# see cross_implementation_gaps below).
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

# TODO #261's acceptance criterion: a four-language cell is either filled or
# ACKNOWLEDGED with a recorded reason, "never a silent absence".  Deriving Java's
# cli_support column (above) fills 24 of the 29 cells and turns the other five
# into DATA; this table is what keeps them from being data with no explanation.
# Keyed (tag, language) -> the reason that cell is empty.  A gap with no entry
# here still appears in cross_implementation_gaps, just with note=None -- which
# is the honest rendering of "nobody has written down why yet", and is what the
# five Java cells looked like before this table existed.
GAP_REASONS = {
    ("nl-zkbpp", "java"):
        "ZkpNl.java's class doc comment declares it out of scope explicitly: the "
        "Java ZKP-NL port 'exists only to give Hpake its mutual-authentication "
        "proof', so it carries the ZKBoo circuit (prove/verify) but not the ZKB++ "
        "transcript encoding. A documented per-file exclusion, the same shape "
        "Hcred.java's KKW note had before TODO #261 closed that one by porting.",
    ("hpks-zkp-nl", "java"):
        "Same ZkpNl.java doc comment: the standalone HPKS-ZKP-NL signature scheme "
        "built on the ZKBoo circuit is named out of scope alongside ZKB++.",
    ("nl-zkboo", "java"):
        "Suite-level support EXISTS (ZkpNl.prove/verify, ported under TODO #203) "
        "and is exercised through Hpake; only the CLI --algo tag is missing, so "
        "this is a CLI-surface gap rather than a missing algorithm -- the "
        "narrowest of the five, and the one to close first.",
    ("rnl-sigma", "java"):
        "No Java port at any layer: neither a CLI tag nor an RnlSigmaSign/Verify "
        "in bindings/java/. Unlike the two ZkpNl entries above, nothing in the "
        "Java tree records the omission -- TODO #261 found it, and this note is "
        "the record. Not yet triaged into port-vs-acknowledge.",
    ("hybrid-rnl-stern", "java"):
        "No Java port at any layer, and undocumented in the Java tree, same as "
        "rnl-sigma. Its C/Go/Python row is demo-only for the KEM half's DFR "
        "(see SECURITY.md), so porting it is low-value next to the other four.",
}

# Gaps in the algo-tag surface are derived (see build_cross_impl_gaps); what stays
# curated is the one gap that is not a tag at all.
CROSS_IMPL_GAPS_CURATED = [
    dict(feature="genpkey --help text completeness", present_in=["python"], missing_from=["c", "go"],
         note="C's usage() omits oprf/hcred from the genpkey line despite dispatching both; "
              "Go's banner omits hpke-stern-kem, nl-zkbpp, oprf, hpks-t despite dispatching all. "
              "This spec's algo enumeration is sourced from dispatch logic, not --help text, "
              "which is why the banners' omissions do not reach cli_support."),
]


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
    m = re.fullmatch(r"([A-Z_][A-Z0-9_]*)\s*/\s*(\d+)", expr)
    if m and m.group(1) in env:
        return env[m.group(1)] // int(m.group(2))
    return expr


def build_parameters():
    h_src = read(HERRADURA_H)
    go_src = read(HERRADURA_GO)
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
            wots[key] = v
    if wots:
        params["wots"] = wots
    rnl_n = extract_const_int(h_src, "RNL_N")
    if rnl_n:
        params["hkex_rnl"] = {"n": rnl_n}
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

    # tag lists per --algo subcommand, needed both for cli_binding and below.
    # genpkey's choices is `list(_PRIV_ALGOS) + ['hcred']`, so hcred is a real
    # --algo tag there even though it is not in _PRIV_ALGOS; without it hcred's
    # cli_binding came out as subcommand-only.
    algo_subcommand_tags = {"genpkey": sorted(set(priv_algos) | genpkey_extra)}
    for subcmd, var in [("kex", "kx"), ("enc", "en"), ("dec", "de"), ("sign", "sg"),
                         ("verify", "vf"), ("encfile", "ef"), ("decfile", "df"), ("dgst", "dg")]:
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
                "has_algo_flag": True,
                "algos": {tag: sorted([impl for impl, ok in cli_support.get(tag, {}).items() if ok])
                          for tag in algo_subcommand_tags[subcmd]},
            }
        elif subcmd in SUBCOMMAND_PROTOCOLS:
            cli_subcommands[subcmd] = {
                "has_algo_flag": False,
                "protocol": SUBCOMMAND_PROTOCOLS[subcmd],
            }
        else:
            cli_subcommands[subcmd] = {
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
        ],
        "protocols": protocols,
        "wire_format_labels": dict(sorted(wire_labels.items())),
        "cli_subcommands": cli_subcommands,
        "cross_implementation_gaps": build_cross_impl_gaps(cli_support),
        "unfiled_cli_surface": [
            {"subcommand": sc, "reason": UNFILED_CLI_SURFACE[sc]}
            for sc in subcommands if sc in UNFILED_CLI_SURFACE
        ],
        "parameters": build_parameters(),
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
        return validate_schema(spec, required=args.require_schema)

    with open(OUT_PATH, "w") as f:
        f.write(new_text)
    print(f"Wrote {OUT_PATH} ({len(spec['protocols'])} protocols, "
          f"{len(spec['wire_format_labels'])} additional wire-format labels).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
