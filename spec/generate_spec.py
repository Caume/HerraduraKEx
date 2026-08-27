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
    """Algo tags a C or Go CLI actually dispatches on.

    Both CLIs reach a tag through a quoted string literal -- `strcmp(algo, "hpks")`
    in C, a `case "hpks"` or an `algo -> PEM label` map entry in Go -- so the rule
    is: every string literal in the source, intersected with the tag universe the
    Python CLI defines.  Comments are stripped first.

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
    "hske-nla2": dict(status="production", quantum_resistant="conjectured",
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
                             "(SecurityProofs-7.md 11.19.2).",
                       source=["TODO.md #237", "TODO_DONE.md #159", "TODO_DONE.md #168"]),
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
    "rand": "HDRBG deterministic byte generator (HFSCX-256-based). No security "
            "classification exists for it in SECURITY.md or in this file.",
    "fpe":  "Format-preserving encryption of a 256-bit block (TODO #78.A). Unclassified.",
    "twk":  "Tweakable wide-block encryption of a 256-bit block (TODO #78.B). Unclassified.",
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
    "hfscx-256": "hash", "hfscx-256-ds": "hash",
    "oprf": "oprf", "hcred": "credential", "apake": "pake",
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
    "hfscx-256": "HFSCX-256 (Merkle-Damgard hash)",
    "hfscx-256-ds": "HFSCX-256-DS (domain-separated variant)",
    "oprf": "OPRF (2HashDH oblivious PRF over GF(2^n)*)",
    "hcred": "HCRED (hybrid credential)",
    "apake": "aPAKE (asymmetric password-authenticated key exchange)",
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
    """Any tag not dispatched by all three CLIs, derived rather than curated.

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
        gaps.append(dict(feature=f"{tag} algo tag",
                          present_in=sorted(i for i, ok in impls.items() if ok),
                          missing_from=missing, note=None))
    return gaps + CROSS_IMPL_GAPS_CURATED


def build_cli_binding(pid, algo_subcommand_tags):
    """How the CLI reaches this protocol.

    `algo_flag` -- an --algo tag, plus every subcommand whose choices list carries
    it.  `subcommand` -- no tag at all; the protocol IS its subcommands (aPAKE).
    Recording this is what let aPAKE be filed under the same `protocols` array as
    everything else instead of a second parallel section (TODO #238 Part C).
    """
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
    subcommand_only_ids = set(SUBCOMMAND_PROTOCOLS.values()) - known_tags
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

    # cli_support, derived per tag from each CLI's own dispatch source.
    c_tags = extract_cli_tags(read(CLI_C), known_tags)
    go_tags = extract_cli_tags(read(CLI_GO), known_tags)
    cli_support = {tag: {"c": tag in c_tags, "go": tag in go_tags, "python": True}
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
