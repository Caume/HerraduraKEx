#!/usr/bin/env python3
"""Generates spec/herradura-protocol-spec.json from the suite's own source files
(TODO #133), so the machine-readable spec cannot silently drift from what the
CLIs actually implement.

Mechanically extracted (regex, not hand-copied) from source:
  - Algo tag -> PEM private/public key label mapping: HerraduraCli/herradura.py's
    `_PRIV_ALGOS` dict (the single most complete, most explicit definition across
    the three CLI implementations -- it covers every genpkey-producible algo,
    including hpks-xmss and hcred, which the C/Go CLIs don't expose).
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
OUT_PATH = os.path.join(REPO, "spec", "herradura-protocol-spec.json")

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
    "hkex-gf":   dict(status="pedagogical", quantum_resistant=False, classical_security_bits="~80-90 (n=256)",
                       notes="GF(2^n)* Diffie-Hellman. NIST SP 800-57 Rev.5 (2020) and ENISA (2022) deprecate "
                             "GF(2^n)* groups for new designs; not suitable for production use at any deployed n.",
                       source=["TODO.md #127 (6943-6949)"]),
    "hpks":      dict(status="pedagogical", quantum_resistant=False, classical_security_bits="~80-90 (n=256)",
                       notes="Schnorr signature over GF(2^n)*; same group-choice caveat as hkex-gf.",
                       source=["TODO.md #127"]),
    "hpke":      dict(status="pedagogical", quantum_resistant=False, classical_security_bits="~80-90 (n=256)",
                       notes="El Gamal encryption over GF(2^n)*; same group-choice caveat as hkex-gf.",
                       source=["TODO.md #127"]),
    "hpks-nl":   dict(status="deprecated", quantum_resistant=False,
                       notes="NL-FSCX-hardened classical Schnorr variant; NOT quantum-resistant despite the "
                             "'NL' naming suggesting a PQC upgrade -- PQC claim deprecated, no lattice-based "
                             "replacement planned.",
                       source=["TODO.md #5 (2901)", "TODO.md (351)"]),
    "hpke-nl":   dict(status="deprecated", quantum_resistant=False,
                       notes="NL-FSCX-hardened classical El Gamal variant; NOT quantum-resistant; PQC claim "
                             "deprecated, no lattice-based replacement planned.",
                       source=["TODO.md #5 (2901)", "TODO.md (351)"]),
    "hkex-rnl":  dict(status="production", quantum_resistant="conjectured",
                       notes="Ring-LWR key exchange; conjectured quantum-resistant (lattice-based).",
                       source=["CLAUDE.md (206)"]),
    "rnl-sigma": dict(status="production", quantum_resistant="conjectured",
                       notes="Sigma-protocol proof of knowledge of an HKEX-RNL private key.",
                       source=["CLAUDE.md", "SecurityProofs-3.md"]),
    "hpks-stern": dict(status="demo-only", quantum_resistant="conjectured",
                        classical_security_bits="~56-60 at shipped SDF_ROUNDS=32 (production requires "
                                                  "SDF_PRODUCTION_ROUNDS=219 for 128-bit soundness)",
                        notes="Fiat-Shamir signature from the Stern identification protocol (syndrome decoding). "
                              "Shipped SDF_ROUNDS=32 is a demo parameter; herradura.h emits a #pragma message "
                              "warning at compile time when SDF_ROUNDS < SDF_PRODUCTION_ROUNDS.",
                        source=["herradura.h:1383-1392", "herradura/herradura.go:1108-1110"]),
    "hpke-stern": dict(status="demo-only", quantum_resistant="conjectured",
                        notes="Niederreiter KEM (Stern-based). Demo uses a known error vector e'; production "
                              "requires an actual QC-MDPC syndrome decoder, not yet implemented.",
                        source=["CLAUDE.md:228", "TODO.md #126 (6896-6924)"]),
    "hpke-stern-kem": dict(status="demo-only", quantum_resistant="conjectured",
                        notes="Same demo-decap caveat as hpke-stern.",
                        source=["TODO.md (6469)"]),
    "hpks-zkp-nl": dict(status="production", quantum_resistant="conjectured",
                        notes="Key-generation entry point for the ZKB[oo/++] proof-of-knowledge protocols "
                              "(nl-zkboo, nl-zkbpp).",
                        source=["herradura.h ZKP_NL_* constants"]),
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
    "hpks-xmss": dict(status="pedagogical", quantum_resistant="conjectured",
                       notes="Python-only prototype; not implemented in the C or Go CLI, not cross-language "
                             "wire-compatible with anything else in the suite.",
                       source=["HerraduraCli/herradura.py (Python-only)"]),
    "hpks-ring": dict(status="demo-only", quantum_resistant="conjectured",
                       notes="Anonymous ring signature built on hpks-stern keys; inherits hpks-stern's "
                             "demo-rounds soundness caveat.",
                       source=["herradura.h SDF_* constants"]),
    "hpks-t":    dict(status="production", quantum_resistant="conjectured",
                       notes="Threshold HPKS-T signing (commit/aggregate/respond/combine phases); verify-only "
                             "algo tag -- signing goes through the separate threshold-* subcommands, not `sign`."),
    "hske":      dict(status="production", quantum_resistant=False,
                       notes="Classical symmetric encryption via FSCX_REVOLVE; not quantum-resistant by design "
                             "(a symmetric primitive, not a PQC construction)."),
    "hske-nla1": dict(status="production", quantum_resistant="conjectured",
                       notes="NL-FSCX v1 counter-mode; supports --aead authenticated encryption."),
    "hske-nla2": dict(status="production", quantum_resistant="conjectured",
                       notes="NL-FSCX v2 revolve-mode symmetric encryption."),
    "hske-duplex": dict(status="production", quantum_resistant="conjectured",
                       notes="Arbitrary-length single-pass AEAD construction."),
    "hfscx-256": dict(status="production", quantum_resistant="conjectured",
                       notes="Merkle-Damgard hash built on NL-FSCX v1, with Davies-Meyer feed-forward."),
    "hfscx-256-ds": dict(status="production", quantum_resistant="conjectured",
                       notes="hfscx-256 with an explicit domain-separation parameter."),
    "oprf":      dict(status="production", quantum_resistant=False,
                       notes="2HashDH OPRF over GF(2^n)*; inherits GF(2^n)* classical-only security."),
    "hcred":     dict(status="research", quantum_resistant="conjectured",
                       notes="Hybrid credential construction (Stern-based); Python and C CLI only, not in Go."),
}

# Cross-implementation CLI support, curated from source inspection of
# herradura_cli.c, herradura_cli.go, and herradura.py dispatch/choices logic
# (not just --help banners, which under-document some algos in C and Go --
# see cross_implementation_gaps below).
CLI_SUPPORT = {
    "hkex-gf": dict(c=True, go=True, python=True),
    "hkex-rnl": dict(c=True, go=True, python=True),
    "hpks": dict(c=True, go=True, python=True),
    "hpks-nl": dict(c=True, go=True, python=True),
    "hpke": dict(c=True, go=True, python=True),
    "hpke-nl": dict(c=True, go=True, python=True),
    "hpks-stern": dict(c=True, go=True, python=True),
    "hpke-stern": dict(c=True, go=True, python=True),
    "hpke-stern-kem": dict(c=True, go=True, python=True),
    "hpks-zkp-nl": dict(c=True, go=True, python=True),
    "rnl-sigma": dict(c=True, go=True, python=True),
    "nl-zkboo": dict(c=True, go=True, python=True),
    "nl-zkbpp": dict(c=True, go=True, python=True),
    "hpks-wots": dict(c=True, go=True, python=True),
    "hpks-xmss": dict(c=False, go=False, python=True),
    "hpks-ring": dict(c=True, go=True, python=True),
    "hpks-t": dict(c=True, go=True, python=True),
    "hske": dict(c=True, go=True, python=True),
    "hske-nla1": dict(c=True, go=True, python=True),
    "hske-nla2": dict(c=True, go=True, python=True),
    "hske-duplex": dict(c=True, go=True, python=True),
    "hfscx-256": dict(c=True, go=True, python=True),
    "hfscx-256-ds": dict(c=True, go=True, python=True),
    "oprf": dict(c=True, go=True, python=True),
    "hcred": dict(c=True, go=False, python=True),
}

PROTOCOL_KIND = {
    "hkex-gf": "kex", "hkex-rnl": "kex",
    "hpks": "signature", "hpks-nl": "signature", "hpks-stern": "signature",
    "hpks-wots": "signature", "hpks-xmss": "signature", "hpks-ring": "signature",
    "hpks-t": "signature", "rnl-sigma": "zkp", "nl-zkboo": "zkp", "nl-zkbpp": "zkp",
    "hpke": "encryption", "hpke-nl": "encryption",
    "hpke-stern": "kem", "hpke-stern-kem": "kem",
    "hpks-zkp-nl": "zkp",
    "hske": "encryption", "hske-nla1": "aead", "hske-nla2": "encryption", "hske-duplex": "aead",
    "hfscx-256": "hash", "hfscx-256-ds": "hash",
    "oprf": "oprf", "hcred": "credential",
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
    "hpks-xmss": "HPKS-XMSS (hash-based, Python-only prototype)",
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
}

CROSS_IMPL_GAPS = [
    dict(feature="hpks-xmss algo tag", present_in=["python"], missing_from=["c", "go"],
         note="No C/Go equivalent; not wire-compatible with anything else in the suite."),
    dict(feature="hcred keygen + cred-issue/cred-prove/cred-verify subcommands",
         present_in=["c", "python"], missing_from=["go"], note=None),
    dict(feature="genpkey --help text completeness", present_in=["python"], missing_from=["c", "go"],
         note="C's usage() omits oprf/hcred from the genpkey line despite dispatching both; "
              "Go's banner omits hpke-stern-kem, nl-zkbpp, oprf, hpks-t despite dispatching all. "
              "This spec's algo enumeration is sourced from dispatch/choices logic, not --help text."),
]


def build_protocols(priv_algos, pem_labels):
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
        if pid in CLI_SUPPORT:
            entry["cli_support"] = CLI_SUPPORT[pid]
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
    stale = (set(SECURITY) | set(CLI_SUPPORT)) - known_tags
    if stale:
        raise RuntimeError(
            f"spec/generate_spec.py's curated tables reference algo tag(s) not found in "
            f"HerraduraCli/herradura.py's _PRIV_ALGOS or any --algo choices list: {sorted(stale)}. "
            f"Either the tag was renamed/removed in source (update generate_spec.py), or this is a "
            f"typo in the curated table."
        )

    protocols = build_protocols(priv_algos, pem_labels_all)

    # wire_format_labels = every PEM_* label not already attached to a protocol as private/public key
    used_labels = set()
    for p in protocols:
        used_labels.update(p.get("pem_labels", {}).values())
    wire_labels = {k: v for k, v in pem_labels_all.items() if v not in used_labels}

    cli_subcommands = {}
    for subcmd, var in [("kex", "kx"), ("enc", "en"), ("dec", "de"), ("sign", "sg"),
                         ("verify", "vf"), ("encfile", "ef"), ("decfile", "df"), ("dgst", "dg")]:
        choices = extract_choices(py_src, var)
        if choices is None:
            continue
        cli_subcommands[subcmd] = {
            "has_algo_flag": True,
            "algos": {tag: sorted([impl for impl, ok in CLI_SUPPORT.get(tag, {}).items() if ok])
                      for tag in choices},
        }
    cli_subcommands["genpkey"] = {
        "has_algo_flag": True,
        "algos": {tag: sorted([impl for impl, ok in CLI_SUPPORT.get(tag, {}).items() if ok])
                  for tag in sorted(priv_algos)},
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
        "cross_implementation_gaps": CROSS_IMPL_GAPS,
        "parameters": build_parameters(),
    }
    return spec


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true",
                     help="exit 1 if regenerating would change spec/herradura-protocol-spec.json")
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
        return 0

    with open(OUT_PATH, "w") as f:
        f.write(new_text)
    print(f"Wrote {OUT_PATH} ({len(spec['protocols'])} protocols, "
          f"{len(spec['wire_format_labels'])} additional wire-format labels).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
