#!/usr/bin/env python3
"""v1_remaining_sites.py — TODO #348: every NL-FSCX v1 call still at n/4, and the two
that are gone.

TODO #347 (v10.0.0) raised three of NL-FSCX v1's modes to V1_MODE_STEPS = 3n/4 = 192
rounds: the HFSCX-256 compression function, HSKE-NL-A1's keystream and MAC key, and the
WOTS chain step.  Every other v1 call kept n/4 = 64 rounds (the ratchet keeps 1).  In
#347's trail-weight model a round costs >= 2 bits outside B1 (v1_mode_floor.py Lemma 1),
so 64 rounds is about 128: the collision bar with no margin.  The first pass (v10.0.1)
asked that question of each remaining site and found two OWED: the Schnorr challenge
e = v1(R, msg, n/4) (HPKS-NL, HPKS-T) and the Stern chain hash
h <- v1(h ^ v, ROL(v, n/8), n/4).  The second pass (v12.0.0) removed both from v1.

  §1  THE CENSUS.  Every nl_fscx_revolve_v1 call in the shipped code — the library,
      the suite demos, the four CLIs, the Java port, the KAT generator and consumers,
      and docs/examples — found by parsing, with its enclosing function and its step
      argument, and held to a table in BOTH directions: a new call, a vanished call
      or a changed step count fails.  Each row names the SITE it serves.  CONTROL: an
      extra call injected into a copy of one file is caught.

  §2  THE SITES, each with its bar and who controls a difference into it.  Verdicts:
        3n/4     raised by #347
        adequate no chosen difference reaches it, so a trail bound is not its bar
        n/a      a one-way-ness question (the ratchet), not a trail question
      No site is owed any more.

  §3  THE RETIRED CONSTRUCTIONS, measured at 64 rounds in the model: the record of
      why the first pass called them owed.
        Schnorr challenge: Delta A = 0, Delta B = beta -> 0, v1_mode_floor.py §5's
        shape, >= 129 outside the residual and absent from its class.  Bar 128.
        Stern chain: the first differing item enters as Delta A = ROR(beta, n/8),
        Delta B = beta; >= 128 outside B1.  Bar 128.

  §7  THE SECOND PASS.  Raising both sites to 3n/4, as first written, made them
      worse, because in both the attacker chooses v1's B (SecurityProofs-10.md
      §11.75): at msg in {0, 2^255} the challenge ignores R, and a zero item erases
      the chain.  Both now go through HFSCX-256-DS (tags 0x30 and 0x31), whose v1 B is
      the MMO chaining value.  Checked: those two degeneracies as CONTROLS against
      the retired shapes, the shipped functions against a hand-built HFSCX-256 at
      four widths, the tags in all four ports, the 32-bit targets' HFSCX-32 form,
      and that no remaining site lets a party choose its B.

  §4  WHAT IT MEANS (prose).  §5  THE DOCUMENTS.  §6  VERDICT.

Every bound is in the trail-weight model (#346 §3: it is not the exact probability for
v1).

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
    ("herradura.h", "stern_matrix_row", "I_VALUE"): (1, "stern_matrix"),
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
    ("herradura/herradura.go", "SternMatrixRow", "n/4"): (1, "stern_matrix"),
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
        (py, "_stern_matrix_row", "n // 4"): (1, "stern_matrix"),
        (py, "ratchet_advance", "1"): (1, "ratchet"),
        (py, "_hpake_rnl_kdf", "KEYBITS // 4"): (1, "rnl_kdf"),
        (py, "_qcprf_refill", "KEYBITS // 4"): (1, "qcprf"),
        (py, "main", "V1_MODE_STEPS"): (1, "a1"),
        (suite + ".c", "main", "V1_MODE_STEPS"): (1, "a1"),
        (suite + ".go", "main", "V1ModeSteps"): (1, "a1"),
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
        (J + "Hdrbg.java", "generate", "I_VALUE"): (1, "drbg"),
        (J + "HerraduraNl.java", "hskeNlA1Encrypt", "3 * base.size() / 4"): (1, "a1"),
        (J + "HerraduraNl.java", "hskeNlAeadStreams", "Hfscx256.V1_MODE_STEPS"):
            (1, "a1"),
        (J + "HerraduraNl.java", "hskeNlAeadXorKs", "Hfscx256.V1_MODE_STEPS"): (1, "a1"),
        (J + "Hfscx256.java", "hash", "steps"): (1, "hfscx"),
        (J + "Hfscx256.java", "encFile", "steps"): (2, "a1"),
        (J + "Hfscx256.java", "decFile", "steps"): (2, "a1"),
        (J + "Hpake.java", "rnlKdf", "Herradura.N / 4"): (1, "rnl_kdf"),
        (J + "KatVerify.java", "verifyRnl", "keyBits / 4"): (1, "rnl_kdf"),
        (J + "Ratchet.java", "advance", "1"): (1, "ratchet"),
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

# Who sets each remaining site's v1 B (the input #351 showed must not be chosen:
# for B in {0, 2^(n-2), 2^(n-1), 3*2^(n-2)} the round is affine, and for 0 and
# 2^(n-1) its linear part is nilpotent, so v1 forgets A after n/2 rounds).
B_SETTER = {
    "hfscx": "the chaining value (MMO since v11.0.0)",
    "a1": "the secret base K ^ nonce",
    "wots": "the secret chain value",
    "drbg": "a fixed domain constant",
    "stern_matrix": "the public seed (its owner's own key)",
    "qcprf": "the secret seed",
    "rnl_kdf": "the ring secret K",
    "ratchet": "a fixed domain constant",
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
    check(len(rows) >= 50 and {"herradura.h", "herradura/herradura.go",
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
    check("owed" not in {v[0] for v in SITES.values()},
          "no v1 site is owed: the two the first pass found (the Schnorr challenge "
          "and the Stern chain) no longer call v1 (§7)")


def section_3():
    rule("§3  The retired constructions at 64 rounds, in the model (first pass)")
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


def section_7():
    rule("§7  The second pass: the two owed sites leave v1 for HFSCX-256-DS")
    S = _load("_suite348", os.path.join(ROOT, "Herradura cryptographic suite.py"))
    BA, n = S.BitArray, 256
    W = {0, 1 << (n - 2), 1 << (n - 1), 3 << (n - 2)}
    check(set(B_SETTER) == set(SITES) and not any(
        w in B_SETTER[k] for k in B_SETTER for w in ("the forger", "the prover",
                                                     "the message", "the signer")),
          "no remaining v1 site lets a party choose its B (%d sites)" % len(SITES))
    consts = {"_DRBG_DOMAIN": S._DRBG_DOMAIN, "_RATCHET_DOMAIN": S._RATCHET_DOMAIN}
    check(all(c.uint not in W for c in consts.values()),
          "the fixed-B sites' constants are outside W (%s)" % ", ".join(consts))
    rng = __import__("random").Random(348)
    R1, R2 = (BA(n, rng.getrandbits(n)) for _ in range(2))
    for m in (0, 1 << (n - 1)):
        old = {S.nl_fscx_revolve_v1(R, BA(n, m), 3 * n // 4).uint for R in (R1, R2)}
        check(len(old) == 1, "CONTROL: the v1 challenge raised as first written, "
              "v1(R, msg, 3n/4), ignores R at msg = %s: one value for two R" %
              ("0" if m == 0 else "2^255"))
        new = {S.hpks_nl_challenge(R, BA(n, m)).uint for R in (R1, R2)}
        check(len(new) == 2, "the shipped challenge depends on R at that msg")
    x1, x2, z = BA(n, rng.getrandbits(n)), BA(n, rng.getrandbits(n)), BA(n, 0)

    def old_chain(*items):
        h = BA(n, 0)
        for v in items:
            h = S.nl_fscx_revolve_v1(h ^ v, v.rotated(n // 8), 3 * n // 4)
        return h.uint
    check(old_chain(x1, z) == old_chain(x2, z),
          "CONTROL: the Stern chain at 3n/4 with a zero item forgets every earlier "
          "item (two first items, one state)")
    check(S._stern_hash(n, x1, z, ds=1) != S._stern_hash(n, x2, z, ds=1),
          "the shipped Stern hash does not")
    ok = True
    for w in (32, 64, 128, 256):
        Rw, mw = BA(w, rng.getrandbits(w)), BA(w, rng.getrandbits(w))
        d = S.hfscx_256(bytes([0x30]) + Rw.bytes + mw.bytes)
        ok &= S.hpks_nl_challenge(Rw, mw).uint == int.from_bytes(d, "big") >> (256 - w)
    check(ok, "hpks_nl_challenge is HFSCX-256(0x30 || R || msg), high n bits, at n = "
          "32, 64, 128 and 256")
    d = S.hfscx_256(bytes([0x31, 4]) + x1.bytes + x2.bytes)
    check(S._stern_hash(n, x1, x2, ds=4).uint == int.from_bytes(d, "big"),
          "_stern_hash is HFSCX-256(0x31 || ds || items)")
    src = {k: _src(k) for k in ("herradura.h", "herradura/herradura.go",
                                "Herradura cryptographic suite.py",
                                "bindings/java/herradurakex/HerraduraNl.java",
                                "bindings/java/herradurakex/Stern.java")}
    check("hfscx_256_ds(HPKS_NL_DS_CHALLENGE," in src["herradura.h"]
          and "hfscx_256_ds(STERN_DS_HASH," in src["herradura.h"]
          and "Hfscx256DS(hpksNlDsChallenge," in src["herradura/herradura.go"]
          and "Hfscx256DS(sternDsHash," in src["herradura/herradura.go"]
          and "hfscx_256_ds(_HPKS_NL_DS_CHALLENGE," in src["Herradura cryptographic suite.py"]
          and "hfscx_256_ds(_STERN_DS_HASH," in src["Herradura cryptographic suite.py"]
          and "hashDs(HPKS_NL_DS_CHALLENGE," in src["bindings/java/herradurakex/HerraduraNl.java"]
          and "hashDs(HerraduraNl.STERN_DS_HASH," in src["bindings/java/herradurakex/Stern.java"],
          "all four ports hash both sites with HFSCX-256-DS under tags 0x30 / 0x31")
    T32 = ["Herradura cryptographic suite.s", "CryptosuiteTests/Herradura_tests.s",
           "Herradura cryptographic suite.asm", "CryptosuiteTests/Herradura_tests.asm",
           "Herradura cryptographic suite.ino", "CryptosuiteTests/Herradura_tests.ino"]
    bad = []
    for f in T32:
        t = _src(f)
        if not ("hpks_nl_challenge_32" in t and "hfscx32_absorb" in t
                and "0x31000000" in t and "0x30000000" in t):
            bad.append(f + " (helpers)")
        if re.search(r"ror\s+r1, r5, #28|rol\s+ebx, 4\n(?:\s+mov\s+ecx, 8\n)?\s+call "
                     r"nl_fscx_revolve_v1|_rol32\((?:v|a|b|msg|c[012]\w*\[[^]]*\]*), 4\), I_VALUE", t):
            bad.append(f + " (old chain)")
    check(not bad, "the six 32-bit files run both sites through HFSCX-32's MMO step "
          "and keep no v1 chain with the item as B (%s)" % bad)


def section_4():
    rule("§4  What it means")
    print("""
      site           bar                         floor at n/4 (model)   now
      Schnorr e      128 per signing query       129                    HFSCX-256-DS
      Stern chain    128 binding / collision     128                    HFSCX-256-DS
  The first pass found both sites at the condition #346 called inadequate for
  HFSCX-256: a floor at the bar.  Raising their round count was not the fix, because
  in both the attacker chooses v1's B, and #351 showed that B in {0, 2^(n-1)} makes
  v1 forget A after n/2 rounds.  So both moved onto the hash, where the attacker's
  input is v1's A and B is the MMO chaining value, reachable in W only through a
  2^254-work preimage (§11.75).  No rating moves: every protocol they serve is
  Demo-only or Research for an independent reason -- HPKS-NL and HPKS-T fall to
  Pohlig-Hellman over GF(2^256)* (~2^36.5), Stern-F and its ring / KEM / credential
  uses sit at N = 256 (~30-40 bits).  The change is MAJOR: every HPKS-NL / HPKS-T /
  Stern-F signature, ring signature, credential and HPKE-Stern-F key changes.""")


def section_5():
    rule("§5  The documents")
    done = _src("TODO_DONE.md")
    m = re.search(r"### #348:.*?(?=^### |\Z)", done, re.S | re.M)
    check(m and "v10.0.1" in m.group(0) and "Status: **DONE v12.0.0**" in m.group(0),
          "TODO #348 records both passes and is DONE v12.0.0 in TODO_DONE.md")
    check("### #348:" not in _src("TODO.md"), "and has left TODO.md")
    sp = _src("SecurityProofs-10.md")
    check("11.73" in sp and "11.76" in sp and "v1_remaining_sites.py" in sp,
          "SecurityProofs-10.md §11.73 and §11.76 report it")
    ch = _src("CHANGELOG.md")
    check("## [10.0.1]" in ch and "## [12.0.0]" in ch and "TODO #348" in ch,
          "CHANGELOG has the 10.0.1 and 12.0.0 entries")
    mg = _src("MIGRATING.md")
    check("## 26." in mg and "TODO #348" in mg, "MIGRATING.md §26 covers the MAJOR change")


def section_6():
    rule("§6  Verdict")
    print("""**No NL-FSCX v1 call left in the suite lets a party choose its B.**

  The two sites the first pass found owed -- the Schnorr challenge (HPKS-NL, HPKS-T)
  and the Stern chain hash (commitments, Fiat-Shamir and ring challenges, HPKE-Stern-F's
  key) -- now hash with HFSCX-256-DS in all four ports, and with HFSCX-32's MMO step
  on the 32-bit targets.  Adequate at n/4: HDRBG's walk, the QC-MDPC PRF, the Stern
  matrix rows and the RNL KDFs.  Out of scope: the ratchet's one round.  No rating
  moves.

  NOT DONE.  The exact probability and the linear hull of the remaining n/4 sites.""")


def main():
    print(__doc__.split("Run:")[0].rstrip())
    print("\n  mode: %s (class D = %d)" % ("--quick" if QUICK else "full", D))
    rows = section_1()
    section_2(rows)
    section_3()
    section_4()
    section_7()
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
