#!/usr/bin/env python3
"""v1_remaining_sites.py — TODO #348, first pass: every NL-FSCX v1 call still at n/4.

TODO #347 (v10.0.0) raised three of NL-FSCX v1's modes to V1_MODE_STEPS = 3n/4 = 192
rounds: the HFSCX-256 compression function, HSKE-NL-A1's keystream and MAC key, and the
WOTS chain step.  Every other v1 call kept n/4 = 64 rounds (the ratchet keeps 1).  In
#347's trail-weight model a round costs >= 2 bits outside B1 (v1_mode_floor.py Lemma 1),
so 64 rounds is about 128: the collision bar with no margin, the condition #346 and
#347 treated as inadequate for HFSCX-256.  This script asks the same question of each
remaining site.

  §1  THE CENSUS.  Every nl_fscx_revolve_v1 call in the shipped code — the library,
      the suite demos, the four CLIs, the Java port, the KAT generator and consumers,
      and docs/examples — found by parsing, with its enclosing function and its step
      argument, and held to a table in BOTH directions: a new call, a vanished call
      or a changed step count fails.  Each row names the SITE it serves.  CONTROL: an
      extra call injected into a copy of one file is caught.

  §2  THE SITES, each with its bar and who controls a difference into it.  Verdicts:
        3n/4     raised by #347
        adequate no chosen difference reaches it, so a trail bound is not its bar
        owed     an attacker sets the difference, and the n/4 floor sits at the bar
        n/a      a one-way-ness question (the ratchet), not a trail question

  §3  THE CHOSEN-DIFFERENCE SITES, measured at 64 rounds in the model.
        Schnorr challenge e = v1(R, msg, n/4) (HPKS-NL, HPKS-T): a forger fixes
        m and m ^ beta, and wins when e collides for the signer's fresh R.  That is
        Delta A = 0, Delta B = beta -> 0: v1_mode_floor.py §5's shape, >= 129 outside
        the residual and absent from its class.  Bar: 128.  Margin: 1 bit.
        Stern chain hash h <- v1(h ^ v, ROL(v, n/8), n/4) (commitments, Fiat-Shamir
        and ring challenges): the first differing item enters with Delta h = 0, so
        Delta A = ROR(beta, n/8), Delta B = beta.  Lemma 1 holds for that item's 64
        rounds whatever follows, so >= 128 outside B1.  The residual's class is
        searched here.  Bar: 128 (binding / collision).  Margin: none.

  §4  WHAT IT MEANS (prose).  §5  THE DOCUMENTS.  §6  VERDICT.

Every bound is in the trail-weight model (#346 §3: it is not the exact probability for
v1).  NOT DONE: the round raise for the owed sites, which is wire-format breaking and
MAJOR, and is TODO #348's second pass.

Pure Python, deterministic.  About 35 s with --quick (D = 3), 9 min without (D = 4),
on an aarch64 SBC.  Exits non-zero if a finding stops reproducing.

Run:  python3 SecurityProofsCode/v1_remaining_sites.py [--quick]
"""

import ast
import glob
import importlib.util
import os
import re
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
QUICK = "--quick" in sys.argv
D = 3 if QUICK else 4
ROUNDS = 64
FAIL = []


def rule(t):
    print("\n" + "=" * 78)
    print(t)
    print("=" * 78)


def check(cond, what):
    print("  [%s] %s" % ("PASS" if cond else "FAIL", what))
    if not cond:
        FAIL.append(what)
    return cond


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def _src(rel):
    with open(os.path.join(ROOT, rel), encoding="utf-8") as fh:
        return fh.read()


# ═══════════════════════════════════════════════════════════════════════════
# The census
# ═══════════════════════════════════════════════════════════════════════════
FILES = (["herradura.h", "herradura/herradura.go", "Herradura cryptographic suite.py",
          "Herradura cryptographic suite.c", "Herradura cryptographic suite.go",
          "HerraduraCli/herradura_cli.c", "HerraduraCli/herradura_cli.go",
          "HerraduraCli/herradura.py", "KAT/generate_kat.py", "KAT/verify_kat.go",
          "KAT/verify_kat_c.c", "docs/examples/python/hello_herradura.py",
          "docs/examples/go/hello_herradura.go", "docs/examples/c/hello_herradura.c"] +
         sorted(os.path.relpath(p, ROOT) for p in
                glob.glob(os.path.join(ROOT, "bindings/java/herradurakex/*.java"))))

PY_NAMES = {"nl_fscx_revolve_v1"}
CALL = re.compile(r"\b(nl_fscx_revolve_v1_ba|nl_fscx_revolve_v1|NlFscxRevolveV1|"
                  r"nlFscxRevolveV1)\(")
DEFN = re.compile(r"(?:\bstatic\b[^;{]*|\bfunc |\bpublic static BitArray )$")
FN = {".h": r"^(?:static[^;(]*?\b(\w+)\s*\(|#define (\w+))",
      ".c": r"^(?:static[^;(]*?\b(\w+)\s*\(|#define (\w+)|int (main)\()",
      ".go": r"^func (?:\([^)]*\) )?(\w+)\(",
      ".java": r"^\s+(?:(?:public|private|protected|static|final) )+[\w<>\[\], .]+?\s(\w+)\s*\("}


def _blank_comments(text):
    """C-family comments and string literals replaced by spaces, newlines kept."""
    def keep_nl(m):
        return re.sub(r"[^\n]", " ", m.group(0))
    return re.sub(r'/\*.*?\*/|//[^\n]*|"(?:\\.|[^"\\\n])*"', keep_nl, text, flags=re.S)


def _top_args(s):
    parts, d, cur = [], 0, ""
    for ch in s:
        d += ch in "([{"
        d -= ch in ")]}"
        if ch == "," and d == 0:
            parts.append(cur)
            cur = ""
        else:
            cur += ch
    return parts + [cur]


def census_c_family(rel, text):
    ext = os.path.splitext(rel)[1]
    text = _blank_comments(text)
    lines = text.split("\n")
    fnre, fn, fnat = re.compile(FN[ext]), "<top>", []
    for line in lines:
        m = fnre.match(line)
        if m:
            fn = next(g for g in m.groups() if g)
        fnat.append(fn)
    rows = []
    for m in CALL.finditer(text):
        if DEFN.search(text[text.rfind("\n", 0, m.start()) + 1:m.start()]):
            continue                                   # the definition itself
        i, depth, j = m.end(), 1, m.end()
        while depth:
            depth += {"(": 1, ")": -1}.get(text[j], 0)
            j += 1
        steps = " ".join(_top_args(text[i:j - 1])[-1].split())
        rows.append((rel, fnat[text.count("\n", 0, m.start())], steps))
    return rows


def census_py(rel, text):
    rows = []

    def visit(node, fn):
        for ch in ast.iter_child_nodes(node):
            f = ch.name if isinstance(ch, (ast.FunctionDef, ast.AsyncFunctionDef)) else fn
            if isinstance(ch, ast.Call):
                name = getattr(ch.func, "id", None) or getattr(ch.func, "attr", None)
                if name in PY_NAMES:
                    rows.append((rel, fn, ast.unparse(ch.args[-1])))
            visit(ch, f)
    visit(ast.parse(text), "<top>")
    return rows


def census(override=None):
    rows = []
    for rel in FILES:
        if not os.path.exists(os.path.join(ROOT, rel)):
            continue
        text = (override or {}).get(rel) or _src(rel)
        rows += (census_py if rel.endswith(".py") else census_c_family)(rel, text)
    return rows


# (file, function, step expression) -> (count, site).  A site's verdict is in SITES.
EXPECTED = {
    # ── herradura.h: the library every C caller uses ───────────────────────
    ("herradura.h", "hfscx_256", "V1_MODE_STEPS"): (1, "hfscx"),
    ("herradura.h", "hske_nla1_ks_block", "V1_MODE_STEPS"): (1, "a1"),
    ("herradura.h", "hske_nla1_mac_key", "V1_MODE_STEPS"): (1, "a1"),
    ("herradura.h", "hske_nla1_encrypt", "3 * base.nbits / 4"): (1, "a1"),
    ("herradura.h", "_wots_h_ba", "V1_MODE_STEPS"): (1, "wots"),
    ("herradura.h", "drbg_generate", "I_VALUE"): (1, "drbg"),
    ("herradura.h", "stern_hash", "I_VALUE"): (1, "stern_chain"),
    ("herradura.h", "_SFS", "I_VALUE"): (1, "stern_chain"),
    ("herradura.h", "stern_ring_challenges", "I_VALUE"): (2, "stern_chain"),
    ("herradura.h", "stern_matrix_row", "I_VALUE"): (1, "stern_matrix"),
    ("herradura.h", "hpks_nl_sign", "I_VALUE"): (1, "schnorr_nl"),
    ("herradura.h", "hpkst_sign", "I_VALUE"): (1, "schnorr_nl"),
    ("herradura.h", "hpkst_verify", "I_VALUE"): (1, "schnorr_nl"),
    ("herradura.h", "ratchet_advance", "1"): (1, "ratchet"),
    ("herradura.h", "_hpake_rnl_kdf", "KEYBITS / 4"): (1, "rnl_kdf"),
    ("herradura.h", "qcprf_refill", "I_VALUE"): (1, "qcprf"),
    # ── herradura/herradura.go ─────────────────────────────────────────────
    ("herradura/herradura.go", "Hfscx256", "V1ModeSteps"): (1, "hfscx"),
    ("herradura/herradura.go", "HskeNla1KsBlock", "V1ModeSteps"): (1, "a1"),
    ("herradura/herradura.go", "HskeNla1MacKey", "V1ModeSteps"): (1, "a1"),
    ("herradura/herradura.go", "HskeNlA1Encrypt", "v1ModeSteps(n)"): (1, "a1"),
    ("herradura/herradura.go", "wotsH", "v1ModeSteps(n)"): (1, "wots"),
    ("herradura/herradura.go", "DrbgGenerate", "64"): (1, "drbg"),
    ("herradura/herradura.go", "SternHash", "n/4"): (1, "stern_chain"),
    ("herradura/herradura.go", "sternFsChallenges", "n/4"): (1, "stern_chain"),
    ("herradura/herradura.go", "sternRingChallenges", "n/4"): (1, "stern_chain"),
    ("herradura/herradura.go", "SternMatrixRow", "n/4"): (1, "stern_matrix"),
    ("herradura/herradura.go", "HpksNlSign", "n/4"): (1, "schnorr_nl"),
    ("herradura/herradura.go", "HpkstSign", "64"): (1, "schnorr_nl"),
    ("herradura/herradura.go", "HpkstVerify", "64"): (1, "schnorr_nl"),
    ("herradura/herradura.go", "RatchetAdvance", "1"): (1, "ratchet"),
    ("herradura/herradura.go", "hpakeRnlKdf", "kRaw.Size()/4"): (1, "rnl_kdf"),
    ("herradura/herradura.go", "word", "256/4"): (1, "qcprf"),
}


def _fill_expected():
    """Rows read off the census once and pinned; kept apart from the two library
    tables above only to keep those readable."""
    py, suite = "Herradura cryptographic suite.py", "Herradura cryptographic suite"
    rows = {
        (py, "hfscx_256", "steps"): (1, "hfscx"),
        (py, "hske_nla1_encrypt", "3 * n // 4"): (1, "a1"),
        (py, "_hske_nl_aead_streams", "V1_MODE_STEPS"): (1, "a1"),
        (py, "_hske_nl_aead_xor_keystream", "V1_MODE_STEPS"): (1, "a1"),
        (py, "_wots_h", "3 * n // 4"): (1, "wots"),
        (py, "drbg_generate", "I_VALUE"): (1, "drbg"),
        (py, "_stern_hash", "n // 4"): (1, "stern_chain"),
        (py, "_stern_matrix_row", "n // 4"): (1, "stern_matrix"),
        (py, "hpks_nl_sign", "n // 4"): (1, "schnorr_nl"),
        (py, "hpkst_sign", "I_VALUE"): (1, "schnorr_nl"),
        (py, "hpkst_verify", "I_VALUE"): (1, "schnorr_nl"),
        (py, "ratchet_advance", "1"): (1, "ratchet"),
        (py, "_hpake_rnl_kdf", "KEYBITS // 4"): (1, "rnl_kdf"),
        (py, "_qcprf_refill", "KEYBITS // 4"): (1, "qcprf"),
        (py, "main", "V1_MODE_STEPS"): (1, "a1"),
        (py, "main", "I_VALUE"): (3, "schnorr_nl"),
        (suite + ".c", "main", "V1_MODE_STEPS"): (1, "a1"),
        (suite + ".c", "main", "I_VALUE"): (3, "schnorr_nl"),
        (suite + ".go", "main", "V1ModeSteps"): (1, "a1"),
        (suite + ".go", "main", "iValue"): (3, "schnorr_nl"),
        ("HerraduraCli/herradura_cli.c", "cmd_sign", "I_VALUE"): (1, "schnorr_nl"),
        ("HerraduraCli/herradura_cli.c", "cmd_verify", "I_VALUE"): (1, "schnorr_nl"),
        ("HerraduraCli/herradura_cli.c", "cmd_threshold_aggregate", "I_VALUE"):
            (1, "schnorr_nl"),
        ("HerraduraCli/herradura_cli.go", "cmdSign", "n/4"): (1, "schnorr_nl"),
        ("HerraduraCli/herradura_cli.go", "cmdVerify", "n/4"): (1, "schnorr_nl"),
        ("HerraduraCli/herradura_cli.go", "cmdThresholdAggregate", "n/4"):
            (1, "schnorr_nl"),
        ("HerraduraCli/herradura.py", "cmd_sign", "nbits // 4"): (1, "schnorr_nl"),
        ("HerraduraCli/herradura.py", "cmd_verify", "nbits // 4"): (1, "schnorr_nl"),
        ("HerraduraCli/herradura.py", "cmd_threshold_aggregate", "nbits // 4"):
            (1, "schnorr_nl"),
        ("HerraduraCli/herradura.py", "cmd_encfile", "steps"): (2, "a1"),
        ("HerraduraCli/herradura.py", "cmd_decfile", "steps"): (2, "a1"),
        ("KAT/generate_kat.py", "rnl_kdf", "KEYBITS // 4"): (1, "rnl_kdf"),
        ("KAT/verify_kat.go", "verifyRnl", "keyBits/4"): (1, "rnl_kdf"),
        ("docs/examples/python/hello_herradura.py", "<top>", "key_n // 4"):
            (2, "rnl_kdf"),
        ("docs/examples/go/hello_herradura.go", "main", "keyN/4"): (2, "rnl_kdf"),
    }
    J = "bindings/java/herradurakex/"
    rows.update({
        (J + "Demo.java", "main", "Herradura.I_STEPS"): (2, "schnorr_nl"),
        (J + "Hdrbg.java", "generate", "I_VALUE"): (1, "drbg"),
        (J + "HerraduraCli.java", "cmdSign", "Herradura.I_STEPS"): (1, "schnorr_nl"),
        (J + "HerraduraCli.java", "cmdThresholdAggregate", "Herradura.I_STEPS"):
            (1, "schnorr_nl"),
        (J + "HerraduraNl.java", "hskeNlA1Encrypt", "3 * base.size() / 4"): (1, "a1"),
        (J + "HerraduraNl.java", "hskeNlAeadStreams", "Hfscx256.V1_MODE_STEPS"):
            (1, "a1"),
        (J + "HerraduraNl.java", "hskeNlAeadXorKs", "Hfscx256.V1_MODE_STEPS"): (1, "a1"),
        (J + "HerraduraNl.java", "hpksNlSign", "N / 4"): (1, "schnorr_nl"),
        (J + "HerraduraNl.java", "hpksNlVerify", "N / 4"): (1, "schnorr_nl"),
        (J + "Hfscx256.java", "hash", "steps"): (1, "hfscx"),
        (J + "Hfscx256.java", "encFile", "steps"): (2, "a1"),
        (J + "Hfscx256.java", "decFile", "steps"): (2, "a1"),
        (J + "Hpake.java", "rnlKdf", "Herradura.N / 4"): (1, "rnl_kdf"),
        (J + "HpksT.java", "sign", "I_STEPS"): (1, "schnorr_nl"),
        (J + "HpksT.java", "verify", "I_STEPS"): (1, "schnorr_nl"),
        (J + "KatVerify.java", "verifyRnl", "keyBits / 4"): (1, "rnl_kdf"),
        (J + "Ratchet.java", "advance", "1"): (1, "ratchet"),
        (J + "Stern.java", "sternHash", "N / 4"): (1, "stern_chain"),
        (J + "Stern.java", "sternMatrixRow", "N / 4"): (1, "stern_matrix"),
        (J + "Stern.java", "refill", "N / 4"): (1, "qcprf"),
        (J + "Wots.java", "h", "Hfscx256.V1_MODE_STEPS"): (1, "wots"),
    })
    return rows


EXPECTED.update(_fill_expected())

# site -> (verdict, rounds, bar, who sets a difference, protocols it serves)
SITES = {
    "hfscx": ("3n/4", "3n/4", "128 collision", "the message", "HFSCX-256, -DS, HDRBG output"),
    "a1": ("3n/4", "3n/4", "256 codebook", "the nonce", "HSKE-NL-A1, AEAD, encfile"),
    "wots": ("3n/4", "3n/4", "128 collision", "the chain input", "HPKS-WOTS, HPKS-XMSS"),
    "schnorr_nl": ("owed", "n/4", "128 (per signing query)",
                   "the forger (msg; R is the signer's)", "HPKS-NL, HPKS-T"),
    "stern_chain": ("owed", "n/4", "128 binding / collision",
                    "the prover (items) and the message",
                    "HPKS-Stern-F, HPKS-Ring, HPKE-Stern-F (KEM key), HCRED"),
    "drbg": ("adequate", "n/4", "one-way state walk", "nobody (secret state, fixed B)",
             "HDRBG"),
    "stern_matrix": ("adequate", "n/4", "uniform rows", "nobody (public seed, row "
                     "index; HFSCX-256 finalizer at 3n/4)", "Stern-F public matrix"),
    "qcprf": ("adequate", "n/4", "PRF, outputs never published",
              "nobody (fresh secret seed)", "HPKE-Stern-KEM keygen / encap"),
    "rnl_kdf": ("adequate", "n/4", "KDF of a secret", "nobody (K is the ring secret)",
                "HPAKE's RNL KDF, the suite-level HKEX-RNL session KDF (KAT, examples)"),
    "ratchet": ("n/a", "1", "one-way-ness (Theorem 16)", "nobody", "Ratchet"),
}

N4 = {"I_VALUE", "64", "n/4", "n // 4", "nbits // 4", "N / 4", "KEYBITS / 4",
      "KEYBITS // 4", "kRaw.Size()/4", "256/4", "iValue", "Herradura.I_STEPS",
      "I_STEPS", "Herradura.N / 4", "keyBits / 4", "keyBits/4", "key_n // 4", "keyN/4"}


def section_1():
    rule("§1  The census: every NL-FSCX v1 call in the shipped code, both directions")
    rows = census()
    got = {}
    for r in rows:
        got[r] = got.get(r, 0) + 1
    print("  %d calls in %d files" % (len(rows), len({r[0] for r in rows})))
    new = sorted(k for k in got if k not in EXPECTED)
    gone = sorted(k for k in EXPECTED if k not in got)
    moved = sorted(k for k in got if k in EXPECTED and got[k] != EXPECTED[k][0])
    check(not new, "no v1 call outside the table (%d new: %s)" % (len(new), new[:4]))
    check(not gone, "every tabled call is still there (%d gone: %s)" % (len(gone), gone[:4]))
    check(not moved, "every row's call count holds (%s)" % moved[:4])
    ports = {f.split("/")[0] if f.startswith("bindings") else f for f, _, _ in got}
    check(len(rows) >= 90 and {"herradura.h", "herradura/herradura.go",
                               "Herradura cryptographic suite.py", "bindings"} <= ports,
          "the census reaches all four ports (%d calls)" % len(rows))
    bad = [(k, v[1]) for k, v in EXPECTED.items()
           if (SITES[v[1]][1] == "n/4") != (k[2] in N4) and SITES[v[1]][1] != "1"]
    check(not bad, "every row's step expression matches its site's round count: n/4 "
          "sites take an n/4 expression, 3n/4 sites do not (%s)" % bad[:3])
    check(all(k[2] == "1" for k, v in EXPECTED.items() if v[1] == "ratchet"),
          "the ratchet's rows take 1 round")
    H = "herradura.h"
    inj = _src(H).replace("static void qcprf_refill(",
                          "static void _probe(BitArray *o, const BitArray *a)\n"
                          "{ nl_fscx_revolve_v1_ba(o, a, a, I_VALUE); }\n"
                          "static void qcprf_refill(", 1)
    probe = census({H: inj})
    check((H, "_probe", "I_VALUE") in probe and len(probe) == len(rows) + 1,
          "CONTROL: a call injected into a copy of herradura.h is caught as a new row")
    probe = census({H: _src(H).replace("&block, &rolx, &x, I_VALUE", "&block, &rolx, &x, "
                                       "V1_MODE_STEPS", 1)})
    check((H, "qcprf_refill", "V1_MODE_STEPS") in probe,
          "CONTROL: a changed step count is caught as a different row")
    return rows


def section_2(rows):
    rule("§2  The sites, their bars, and who sets a difference")
    used = {v[1] for v in EXPECTED.values()}
    check(used == set(SITES), "every site serves at least one call and every call "
          "names a site (%s)" % sorted(used ^ set(SITES)))
    print("\n  %-13s %-8s %-6s %-28s %s" % ("site", "verdict", "rounds", "bar",
                                            "who sets a difference"))
    for s, (v, r, bar, who, _) in SITES.items():
        print("  %-13s %-8s %-6s %-28s %s" % (s, v, r, bar, who))
    print("""
  adequate.  HDRBG's walk state <- v1(state, DRBG_DOMAIN, n/4) runs over a secret state
  with B fixed, and its outputs pass through HFSCX-256 at 3n/4: there is no pair of
  related inputs for a characteristic to start from, and its property is one-wayness
  and walk non-collision (nl_fscx_v1_ratchet_collision.py).  The QC-MDPC PRF expands a
  fresh secret seed whose blocks are never published, only consumed as sampling
  randomness; its counter differences enter as A1's nonce did (ROL(beta, n/8)), which
  v1_mode_floor.py §6 bounds at 128 outside the residual with no entry inside its
  class, against a bar that needs outputs the attacker never sees.  The Stern matrix
  rows are a public seed's expansion behind an HFSCX-256 finalizer; nobody benefits
  from a related row pair.  The RNL KDFs derive from the ring secret K, which no
  party can difference.

  n/a.  The ratchet's single round is a one-way-ness question (Theorem 16,
  SecurityProofs-5 §11.8.3), not a trail bound.  This item makes no claim on it.""")
    for s in ("schnorr_nl", "stern_chain"):
        check(SITES[s][0] == "owed", "%s is owed: the attacker sets the difference "
              "and the site runs n/4" % s)


def section_3():
    rule("§3  The chosen-difference sites at 64 rounds, in the model")
    FL = _load("_v1_floor", os.path.join(HERE, "v1_mode_floor.py"))
    FL.D = D
    w, t0 = FL.W(256), time.time()
    R = FL.residual(w)
    sch, ent, coll = [], [], []
    for b in R:
        adj = FL.adjacency(FL.edges(w, b, D), b)
        if b and FL.walk(adj, 0, 0, ROUNDS) is not None:
            sch.append(b)
        e = w.rol(b, w.n - 32)          # ROR(beta, n/8)
        if b and FL.walk(adj, e, None, ROUNDS) is not None:
            ent.append(b)
        if b and FL.walk(adj, e, 0, ROUNDS) is not None:
            coll.append(b)
    print("  (%d betas, class 'every round <= %d', %.0f s)" % (len(R), D, time.time() - t0))
    check(len(R) == 538, "the residual has 538 betas")
    check(not sch, "Schnorr challenge: no 64-round characteristic 0 -> 0 in the class "
          "(%d betas with one); outside the residual v1_mode_floor.py §5 gates >= 129"
          % len(sch))
    check(not ent, "Stern chain: no 64-round characteristic in the class leaves the "
          "first differing item's entry ROR(beta, n/8) (%d betas with one)" % len(ent))
    check(not coll, "Stern chain: in particular none reaches 0 (%d)" % len(coll))
    core2 = (1 << 255) | (1 << 253)
    a2 = w.M(1 << 254)
    adj = FL.adjacency(FL.edges(w, core2, D), core2)
    check(FL.walk(adj, a2, a2, ROUNDS) == 2 * ROUNDS,
          "CONTROL: the same search finds the second core's 128-bit alpha -> alpha at "
          "64 rounds, so 'no characteristic' is not a search that cannot see one")
    nb = (1 << 200) | (1 << 100) | (1 << 3)
    check(not FL.in_B1(w, nb) and len(FL.tr(w, nb)) >= 5,
          "CONTROL: Lemma 1 binds a typical beta (outside B1, |tr| = %d), so its "
          "64-round characteristics cost >= 2 * 64 = 128 from any entry"
          % len(FL.tr(w, nb)))


def section_4():
    rule("§4  What it means")
    print("""
      site           bar                         floor at n/4 (model)   margin
      Schnorr e      128 per signing query       129                    1 bit
      Stern chain    128 binding / collision     128                    none
  Both owed sites are the condition #346 called inadequate for HFSCX-256: a floor at
  the bar.  Neither moves a rating, because every protocol they serve is already
  Demo-only or Research for an independent reason -- HPKS-NL and HPKS-T fall to
  Pohlig-Hellman over GF(2^256)* (~2^36.5), Stern-F and its ring / KEM / credential
  uses sit at N = 256 (~30-40 bits).  The raise is owed so that no v1 hash in the
  suite sits at its own bar, not to repair a rating.  It is MAJOR
  (every HPKS-NL / HPKS-T / Stern-F signature, ring signature and credential changes)
  and is TODO #348's second pass.""")


def section_5():
    rule("§5  The documents")
    todo = _src("TODO.md")
    m = re.search(r"### #348:.*?(?=^### |\Z)", todo, re.S | re.M)
    check(m and "v10.0.1" in m.group(0) and "Status: **OPEN**" in m.group(0),
          "TODO #348 records this pass (v10.0.1) and stays OPEN for the raise")
    sp = _src("SecurityProofs-10.md")
    check("11.73" in sp and "v1_remaining_sites.py" in sp,
          "SecurityProofs-10.md §11.73 reports it")
    ch = _src("CHANGELOG.md")
    check("## [10.0.1]" in ch and "TODO #348" in ch, "CHANGELOG has the 10.0.1 entry")


def section_6():
    rule("§6  Verdict")
    print("""**Of the six sites NL-FSCX v1 still runs at n/4, two are owed; the other four are not
trail questions.**

  Owed: the Schnorr challenge (HPKS-NL, HPKS-T) and the Stern chain hash (commitments,
  Fiat-Shamir and ring challenges), both attacker-differenced and at the 128 bar.
  Adequate: HDRBG's walk, the QC-MDPC PRF, the Stern matrix rows and the RNL KDFs.
  Out of scope: the ratchet's one round.  No rating moves.

  NOT DONE.  The raise (MAJOR, TODO #348's second pass), the exact probability, and
  the linear hull.""")


def main():
    print(__doc__.split("Run:")[0].rstrip())
    print("\n  mode: %s (class D = %d)" % ("--quick" if QUICK else "full", D))
    rows = section_1()
    section_2(rows)
    section_3()
    section_4()
    section_5()
    section_6()
    rule("Summary")
    if FAIL:
        print("*** FAILED: %d finding(s) did not reproduce ***" % len(FAIL))
        for f in FAIL:
            print("    - " + f)
        return 1
    print("*** OK: every finding reproduced ***")
    return 0


if __name__ == "__main__":
    sys.exit(main())
