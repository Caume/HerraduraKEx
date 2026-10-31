#!/usr/bin/env python3
"""v2_v3_b_setter.py — TODO #352: who chooses NL-FSCX v2's and v3's B?

TODO #348 and #351 came from one question the trail model cannot ask: an input FIXED
at a degenerate value is not a trail, so a trail-weight floor says nothing about it.
v1_remaining_sites.py answers it for every v1 call (its B_SETTER table).  This gate
asks it of v2 and v3, which back four production-track rows (HSKE-NL-A2, `twk`,
HSKE-NL-A3, `twk --v3`, TODO #345).

v2's two degenerate classes are classes of B, through delta(B) = ROL(P, n/4) with
P = B * floor((B+1)/2) mod 2^n:
  * the AFFINE class, delta in {0, 2^(n-1)}, refused by nl_v2_key_is_valid;
  * the ZERO-WEIGHT-TRAIL class, tz(delta) >= 4 (SecurityProofs-7.md §11.28.3),
    accepted on purpose because "a random key loses at most 3 rounds with
    probability 1/16".  That argument is about a RANDOM key.

  §1  THE CENSUS.  Every v2/v3 call in the shipped code (the files
      v1_remaining_sites.py censuses), keyed by its enclosing function and its B
      argument, held to a table in both directions; and the 32-bit suites' call
      counts.  CONTROLS: an injected call and a changed B argument are caught.
  §2  THE SITES and who sets B, and the screens each one relies on, found in the
      source of all four ports.  CONTROL: a screen removed from a copy is caught.
  §3  v2's FREE ROUNDS, exactly, at n = 256: g(k) zero-weight (differential) and
      correlation-1 (linear) rounds for tz(delta) = k, every k.  Cross-checked
      against nl_fscx_v2_fixed_key.py and the §11.28.4 / §11.30.5 tables.
  §4  THE tz TAIL, which §11.28.4 took to be 2^-k.  It is 2^-k only to k = n/4;
      past that the low bits of P come in pairs (v2(2m^2) = 1 + 2 v2(m)) and the
      tail halves its slope.  A case-split model, checked against exhaustive
      enumeration at n = 16 and 20 (24 without --quick), gives the n = 256 tail
      for the keys the check accepts.  Witness: B = 2^95 has tz(delta) = 253,
      127 free rounds of 192, and passes nl_v2_key_is_valid.  CONTROL: B = 2^96 is
      the affine class and is refused.
  §5  QUESTION 2 — MANY TWEAKS.  `twk` and FPE derive B = HFSCX-256-DS(key || tweak)
      and the attacker chooses the tweak.  Over 2^T tweaks the best has the tz
      whose accepted tail is 2^-T, and the data to exploit it is at least
      C(T) = T + s * (192 - g).  Held, on both axes at the conjectured bars: C(T)
      never falls below the generic multi-target cost max(T, 256 - T), and stays
      above 256 throughout `twk`'s 96-bit tweak space.  CONTROL: a bar of 1.0
      fails the second check.
  §6  QUESTION 1 — HPKE-NL DECRYPT.  B = R^a with R from the ciphertext; the CLIs
      refuse the affine class with an error.  Every element of each prime-order
      subgroup of GF(2^256)* up to 65537 (274177 without --quick) is tested: none
      is in the affine class, so the refusal is no oracle on a mod d.
  §7  QUESTION 3 — v3.  Already answered by TODO #255's nl_fscx_v3_weak_keys.py
      §4(b): the zero-weight class dissolves (worst one-round probability 5/16 for
      every key).  Held here: that gate is still a gate, and chi on 5- and 7-bit
      rows has no probability-1 differential and no correlation-1 mask.
  §8  THE DOCUMENTS.  §9  VERDICT.

Every bound is in the trail-weight model (a free-round prefix plus the conjectured
per-round cost); it is not a bound on hulls.

Pure Python, deterministic.  About 30 s with --quick, 70 s without, on an
aarch64 SBC.  Exits non-zero if a finding stops reproducing.

Run:  python3 SecurityProofsCode/v2_v3_b_setter.py [--quick]
"""

import ast
import importlib.util
import math
import os
import re
import sys
from fractions import Fraction

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
QUICK = "--quick" in sys.argv
N = 256
R = 3 * N // 4                 # R_VALUE: HSKE-NL-A2, twk and FPE run 192 rounds
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


# The census machinery and file list are v1_remaining_sites.py's: reuse, do not fork.
V1 = _load("v1_remaining_sites", os.path.join(HERE, "v1_remaining_sites.py"))
FILES = V1.FILES

# ═══════════════════════════════════════════════════════════════════════════
# §1  The census
# ═══════════════════════════════════════════════════════════════════════════
CALL = re.compile(r"\b(nl_fscx_revolve_v[23](?:_inv)?(?:_ba)?|NlFscxRevolveV[23](?:Inv)?|"
                  r"nlFscxRevolveV[23](?:Inv)?|nl_fscx_v[23](?:_inv)?(?:_ba)?|"
                  r"NlFscxV[23](?:Inv)?|nlFscxV[23](?:Inv)?)\(")
PY_NAMES = {"nl_fscx_revolve_v2", "nl_fscx_revolve_v2_inv", "nl_fscx_revolve_v3",
            "nl_fscx_revolve_v3_inv", "nl_fscx_v2", "nl_fscx_v2_inv", "nl_fscx_v3",
            "nl_fscx_v3_inv"}


def _b_arg(name, args):
    """B is the argument before the step count in a revolve, the last in a round."""
    a = args[-2] if "evolve" in name else args[-1]
    return " ".join(a.split()).lstrip("&")


def _fam(name):
    return "v3" if "3" in name else "v2"


def census_c_family(rel, text):
    ext = os.path.splitext(rel)[1]
    text = V1._blank_comments(text)
    fnre, fn, fnat = re.compile(V1.FN[ext]), "<top>", []
    for line in text.split("\n"):
        m = fnre.match(line)
        if m:
            fn = next(g for g in m.groups() if g)
        fnat.append(fn)
    rows = []
    for m in CALL.finditer(text):
        if V1.DEFN.search(text[text.rfind("\n", 0, m.start()) + 1:m.start()]):
            continue                                   # the definition itself
        i, depth, j = m.end(), 1, m.end()
        while depth:
            depth += {"(": 1, ")": -1}.get(text[j], 0)
            j += 1
        rows.append((rel, fnat[text.count("\n", 0, m.start())], _fam(m.group(1)),
                     _b_arg(m.group(1), V1._top_args(text[i:j - 1]))))
    return rows


def census_py(rel, text):
    rows = []

    def visit(node, fn):
        for ch in ast.iter_child_nodes(node):
            f = ch.name if isinstance(ch, (ast.FunctionDef, ast.AsyncFunctionDef)) else fn
            if isinstance(ch, ast.Call):
                name = getattr(ch.func, "id", None) or getattr(ch.func, "attr", None)
                if name in PY_NAMES:
                    rows.append((rel, fn, _fam(name),
                                 _b_arg(name, [ast.unparse(a) for a in ch.args])))
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


H, GO, PY = "herradura.h", "herradura/herradura.go", "Herradura cryptographic suite.py"
SC, SG = "Herradura cryptographic suite.c", "Herradura cryptographic suite.go"
CC, CGO, CPY = ("HerraduraCli/herradura_cli.c", "HerraduraCli/herradura_cli.go",
                "HerraduraCli/herradura.py")
J = "bindings/java/herradurakex/"

# (file, function, round family, B argument) -> (count, site).  Read off the census
# once and pinned; a site's B setter and screen are in SITES.
EXPECTED = {
    (SC, 'main', 'v2', 'dec_nl'): (1, 'hpke_nl'),
    (SC, 'main', 'v2', 'enc_nl'): (1, 'hpke_nl'),
    (SC, 'main', 'v2', 'eve_key'): (1, 'hpke_nl'),
    (SC, 'main', 'v2', 'preshared'): (2, 'a2'),
    (SG, 'main', 'v2', 'decNl'): (1, 'hpke_nl'),
    (SG, 'main', 'v2', 'encNl'): (1, 'hpke_nl'),
    (SG, 'main', 'v2', 'eveKey'): (1, 'hpke_nl'),
    (SG, 'main', 'v2', 'preshared'): (2, 'a2'),
    (PY, '_v2_dplex_perm_bytes', 'v2', 'tweak_ba'): (1, 'duplex'),
    (PY, '_v2_dplex_perm_bytes', 'v3', 'tweak_ba'): (1, 'duplex'),
    (PY, 'fpe_decrypt', 'v2', '_fpe_twk_derive_b(_FPE_DS, key, ctx)'): (1, 'fpe_twk'),
    (PY, 'fpe_encrypt', 'v2', '_fpe_twk_derive_b(_FPE_DS, key, ctx)'): (1, 'fpe_twk'),
    (PY, 'fpe_v3_decrypt', 'v3', '_fpe_twk_v3_derive_b(_FPE_V3_DS, key, ctx)'): (1, 'fpe_twk3'),
    (PY, 'fpe_v3_encrypt', 'v3', '_fpe_twk_v3_derive_b(_FPE_V3_DS, key, ctx)'): (1, 'fpe_twk3'),
    (PY, 'main', 'v2', 'dec_nl'): (1, 'hpke_nl'),
    (PY, 'main', 'v2', 'enc_nl'): (1, 'hpke_nl'),
    (PY, 'main', 'v2', 'eve_key'): (1, 'hpke_nl'),
    (PY, 'main', 'v2', 'preshared'): (2, 'a2'),
    (PY, 'nl_fscx_v3', 'v2', 'B'): (1, 'round'),
    (PY, 'nl_fscx_v3_inv', 'v2', 'B'): (1, 'round'),
    (PY, 'twk_decrypt', 'v2', 'B'): (1, 'fpe_twk'),
    (PY, 'twk_encrypt', 'v2', 'B'): (1, 'fpe_twk'),
    (PY, 'twk_v3_decrypt', 'v3', 'B'): (1, 'fpe_twk3'),
    (PY, 'twk_v3_encrypt', 'v3', 'B'): (1, 'fpe_twk3'),
    (CPY, 'cmd_dec', 'v2', 'K'): (1, 'a2'),
    (CPY, 'cmd_dec', 'v2', 'dec_key'): (1, 'hpke_nl'),
    (CPY, 'cmd_dec', 'v3', 'K'): (1, 'a3'),
    (CPY, 'cmd_dec', 'v3', 'dec_key'): (1, 'hpke_nl3'),
    (CPY, 'cmd_enc', 'v2', 'K'): (1, 'a2'),
    (CPY, 'cmd_enc', 'v2', 'enc_key'): (1, 'hpke_nl'),
    (CPY, 'cmd_enc', 'v3', 'K'): (1, 'a3'),
    (CPY, 'cmd_enc', 'v3', 'enc_key'): (1, 'hpke_nl3'),
    (CC, 'cmd_dec', 'v2', 'K'): (1, 'a2'),
    (CC, 'cmd_dec', 'v2', 'dec_key'): (1, 'hpke_nl'),
    (CC, 'cmd_dec', 'v3', 'K'): (1, 'a3'),
    (CC, 'cmd_dec', 'v3', 'dec_key'): (1, 'hpke_nl3'),
    (CC, 'cmd_enc', 'v2', 'K'): (1, 'a2'),
    (CC, 'cmd_enc', 'v2', 'enc_key'): (1, 'hpke_nl'),
    (CC, 'cmd_enc', 'v3', 'K'): (1, 'a3'),
    (CC, 'cmd_enc', 'v3', 'enc_key'): (1, 'hpke_nl3'),
    (CGO, 'cmdDec', 'v2', 'K'): (1, 'a2'),
    (CGO, 'cmdDec', 'v2', 'decKey'): (1, 'hpke_nl'),
    (CGO, 'cmdDec', 'v3', 'K'): (1, 'a3'),
    (CGO, 'cmdDec', 'v3', 'decKey'): (1, 'hpke_nl3'),
    (CGO, 'cmdEnc', 'v2', 'K'): (1, 'a2'),
    (CGO, 'cmdEnc', 'v2', 'encKey'): (1, 'hpke_nl'),
    (CGO, 'cmdEnc', 'v3', 'K'): (1, 'a3'),
    (CGO, 'cmdEnc', 'v3', 'encKey'): (1, 'hpke_nl3'),
    ('KAT/generate_kat.py', 'gen_hpke_nl3', 'v3', 'dec_key'): (1, 'kat'),
    ('KAT/generate_kat.py', 'gen_hpke_nl3', 'v3', 'enc_key'): (1, 'kat'),
    ('KAT/generate_kat.py', 'gen_hske_nla3', 'v3', 'key'): (1, 'kat'),
    ('KAT/generate_kat.py', 'gen_nl_fscx_v3', 'v3', 'key'): (3, 'kat'),
    ('KAT/verify_kat.go', 'verifyV3', 'v3', 'encKey'): (1, 'kat'),
    ('KAT/verify_kat.go', 'verifyV3', 'v3', 'hexToBA(n, str(a, ))'): (1, 'kat'),
    ('KAT/verify_kat.go', 'verifyV3', 'v3', 'key'): (3, 'kat'),
    (J + 'Demo.java', 'main', 'v2', 'BitArray.fromBigInteger(eveKey, Herradura.N)'): (1, 'hpke_nl'),
    (J + 'Duplex.java', 'perm', 'v2', 'tweak'): (1, 'duplex'),
    (J + 'Duplex.java', 'perm', 'v3', 'tweak'): (1, 'duplex'),
    (J + 'FpeTwk.java', 'fpeDecrypt', 'v2', 'deriveB(FPE_DS, key, ctx)'): (1, 'fpe_twk'),
    (J + 'FpeTwk.java', 'fpeEncrypt', 'v2', 'deriveB(FPE_DS, key, ctx)'): (1, 'fpe_twk'),
    (J + 'FpeTwk.java', 'fpeV3Decrypt', 'v3', 'deriveBv3(FPE_V3_DS, key, ctx)'): (1, 'fpe_twk3'),
    (J + 'FpeTwk.java', 'fpeV3Encrypt', 'v3', 'deriveBv3(FPE_V3_DS, key, ctx)'): (1, 'fpe_twk3'),
    (J + 'FpeTwk.java', 'twkDecrypt', 'v2', 'b'): (1, 'fpe_twk'),
    (J + 'FpeTwk.java', 'twkEncrypt', 'v2', 'b'): (1, 'fpe_twk'),
    (J + 'FpeTwk.java', 'twkV3Decrypt', 'v3', 'b'): (1, 'fpe_twk3'),
    (J + 'FpeTwk.java', 'twkV3Encrypt', 'v3', 'b'): (1, 'fpe_twk3'),
    (J + 'HerraduraNl.java', 'hpkeNl3Decrypt', 'v3', 'Herradura.gfPow(r, priv)'): (1, 'hpke_nl3'),
    (J + 'HerraduraNl.java', 'hpkeNl3Encrypt', 'v3', 'encKey'): (1, 'hpke_nl3'),
    (J + 'HerraduraNl.java', 'hpkeNlDecrypt', 'v2', 'decKey'): (1, 'hpke_nl'),
    (J + 'HerraduraNl.java', 'hpkeNlEncrypt', 'v2', 'encKey'): (2, 'hpke_nl'),
    (J + 'HerraduraNl.java', 'hskeNlA2Decrypt', 'v2', 'key'): (1, 'a2'),
    (J + 'HerraduraNl.java', 'hskeNlA2Encrypt', 'v2', 'key'): (1, 'a2'),
    (J + 'HerraduraNl.java', 'hskeNlA3Decrypt', 'v3', 'key'): (1, 'a3'),
    (J + 'HerraduraNl.java', 'hskeNlA3Encrypt', 'v3', 'key'): (1, 'a3'),
    (J + 'HerraduraNl.java', 'nlFscxV3', 'v2', 'b'): (1, 'round'),
    (J + 'HerraduraNl.java', 'nlFscxV3Inv', 'v2', 'b'): (1, 'round'),
    (J + 'KatVerify.java', 'verifyV3', 'v3', 'BitArray.fromBigInteger(key, Herradura.N)'): (5, 'kat'),
    (J + 'SelfTest.java', 'main', 'v2', 'BitArray.fromBigInteger(key, Herradura.N)'): (1, 'test'),
    (H, '_v2dplex_perm', 'v2', 'd->tw'): (1, 'duplex'),
    (H, '_v2dplex_perm', 'v3', 'd->tw'): (1, 'duplex'),
    (H, 'fpe_decrypt', 'v2', 'B'): (1, 'fpe_twk'),
    (H, 'fpe_encrypt', 'v2', 'B'): (1, 'fpe_twk'),
    (H, 'fpe_v3_decrypt', 'v3', 'B'): (1, 'fpe_twk3'),
    (H, 'fpe_v3_encrypt', 'v3', 'B'): (1, 'fpe_twk3'),
    (H, 'nl_fscx_revolve_v2_ba', 'v2', 'b'): (1, 'round'),
    (H, 'nl_fscx_revolve_v3_ba', 'v3', 'b'): (1, 'round'),
    (H, 'nl_fscx_revolve_v3_inv_ba', 'v3', 'b'): (1, 'round'),
    (H, 'nl_fscx_v3_ba', 'v2', 'b'): (1, 'round'),
    (H, 'nl_fscx_v3_inv_ba', 'v2', 'b'): (1, 'round'),
    (H, 'twk_decrypt', 'v2', 'B'): (1, 'fpe_twk'),
    (H, 'twk_encrypt', 'v2', 'B'): (1, 'fpe_twk'),
    (H, 'twk_v3_decrypt', 'v3', 'B'): (1, 'fpe_twk3'),
    (H, 'twk_v3_encrypt', 'v3', 'B'): (1, 'fpe_twk3'),
    (GO, 'FpeDecrypt', 'v2', 'fpeDeriveB(key, ctx)'): (1, 'fpe_twk'),
    (GO, 'FpeEncrypt', 'v2', 'fpeDeriveB(key, ctx)'): (1, 'fpe_twk'),
    (GO, 'FpeV3Decrypt', 'v3', 'fpeTwkV3DeriveB(fpeV3DS, key, ctx)'): (1, 'fpe_twk3'),
    (GO, 'FpeV3Encrypt', 'v3', 'fpeTwkV3DeriveB(fpeV3DS, key, ctx)'): (1, 'fpe_twk3'),
    (GO, 'NlFscxRevolveV2', 'v2', 'b'): (1, 'round'),
    (GO, 'NlFscxRevolveV3', 'v3', 'b'): (1, 'round'),
    (GO, 'NlFscxRevolveV3Inv', 'v3', 'b'): (1, 'round'),
    (GO, 'NlFscxV3', 'v2', 'b'): (1, 'round'),
    (GO, 'NlFscxV3Inv', 'v2', 'b'): (1, 'round'),
    (GO, 'TwkDecrypt', 'v2', 'twkDeriveB(key, sector, bidx)'): (1, 'fpe_twk'),
    (GO, 'TwkEncrypt', 'v2', 'twkDeriveB(key, sector, bidx)'): (1, 'fpe_twk'),
    (GO, 'TwkV3Decrypt', 'v3', 'twkV3DeriveB(key, sector, bidx)'): (1, 'fpe_twk3'),
    (GO, 'TwkV3Encrypt', 'v3', 'twkV3DeriveB(key, sector, bidx)'): (1, 'fpe_twk3'),
    (GO, 'v2dplexPerm', 'v2', 'tw'): (1, 'duplex'),
    (GO, 'v2dplexPerm', 'v3', 'tw'): (1, 'duplex'),
}

# The 32-bit suites: fixed-width demos, B in a register, so a per-file call count.
# Their B is the demo's preshared key, the DH key, or hfscx_32 of key and tweak.
ASM_CALL = re.compile(r"^\s*(?:bl|call)\s+nl_fscx_(?:revolve_)?v[23](?:_inv)?\b", re.M)
INO_CALL = re.compile(r"\bnl_fscx_(?:revolve_)?v[23](?:_inv)?\(")
EXPECTED_32 = {"Herradura cryptographic suite.s": 10,
               "Herradura cryptographic suite.asm": 10,
               "Herradura cryptographic suite.ino": 10}


def census_32(override=None):
    out = {}
    for rel in EXPECTED_32:
        text = (override or {}).get(rel) or _src(rel)
        if rel.endswith(".ino"):
            text = re.sub(r"/\*.*?\*/|//[^\n]*", "", text, flags=re.S)
            out[rel] = sum(1 for m in INO_CALL.finditer(text)
                           if not re.search(r"uint32\s+$",
                                            text[text.rfind("\n", 0, m.start()) + 1:m.start()]))
        else:
            out[rel] = len(ASM_CALL.findall(text))
    return out


# site -> (who sets B, the screen it relies on, the question that answers it)
SITES = {
    "round": ("the caller (a round composing another: v3 = chi . v2, revolve = rounds)",
              "inherited from the caller", "-"),
    "a2": ("the key holder (the key itself)",
           "affine class refused at enc and dec in all four CLIs", "random key: §3-§4"),
    "a3": ("the key holder (the key itself)", "none, by design (v3 has no weak class)",
           "§7"),
    "hpke_nl": ("the SENDER, through R (decrypt: B = R^a)",
                "encrypt redraws r past the affine class; decrypt refuses it", "§6"),
    "hpke_nl3": ("the SENDER, through R", "none, by design", "§7"),
    "fpe_twk": ("HFSCX-256-DS(len || key || tweak): the attacker picks the tweak",
                "affine class rehashed away in the derivation", "§5"),
    "fpe_twk3": ("HFSCX-256-DS(len || key || tweak), tags 0x22/0x23",
                 "none, by design", "§5, §7"),
    "duplex": ("HFSCX-256(DS || key || nonce): the nonce is public",
               "none (research row; the affine class is about 2^-129)", "§5"),
    "kat": ("a pinned vector", "-", "-"),
    "test": ("a random key (SelfTest's v3 != v2 control)", "-", "-"),
}

# (file, pattern, count, what): the screens §2's table names, in every port.
SCREENS = [
    (CC, r'die\("(?:enc|dec) hske-nla2: " WEAK_V2_KEY_MSG\)', 2, "C CLI: A2 key refused"),
    (CGO, r"if !NlV2KeyIsValid\(K\)", 2, "Go CLI: A2 key refused"),
    (CPY, r"if not nl_v2_key_is_valid\(K\)", 2, "Python CLI: A2 key refused"),
    (J + "HerraduraCli.java", r"!HerraduraNl\.nlV2KeyIsValid\(key\)", 2,
     "Java CLI: A2 key refused"),
    (CC, r"nl_v2_key_is_valid\(&enc_key\)", 1, "C CLI: HPKE-NL r redrawn"),
    (CGO, r"NlV2KeyIsValid\(encKey\)", 1, "Go CLI: HPKE-NL r redrawn"),
    (CPY, r"nl_v2_key_is_valid\(enc_key\)", 1, "Python CLI: HPKE-NL r redrawn"),
    (J + "HerraduraNl.java", r"nlV2KeyIsValid\(encKey\)", 1, "Java: HPKE-NL r redrawn"),
    (CC, r"nl_v2_key_is_valid\(&dec_key\)", 1, "C CLI: HPKE-NL decrypt refuses"),
    (CGO, r"NlV2KeyIsValid\(decKey\)", 1, "Go CLI: HPKE-NL decrypt refuses"),
    (CPY, r"nl_v2_key_is_valid\(dec_key\)", 1, "Python CLI: HPKE-NL decrypt refuses"),
    (J + "HerraduraNl.java", r"nlV2KeyIsValid\(decKey\)", 1,
     "Java: HPKE-NL decrypt refuses"),
    (H, r"while \(!nl_v2_key_is_valid\(B\)\)", 1, "C: one rehash loop (v2 FPE/twk only)"),
    (GO, r"for !NlV2KeyIsValid\(B\)", 1, "Go: one rehash loop (v2 FPE/twk only)"),
    (PY, r"while not nl_v2_key_is_valid\(B\)", 1, "Python: one rehash loop"),
    (J + "FpeTwk.java", r"while \(!HerraduraNl\.nlV2KeyIsValid\(b\)\)", 1,
     "Java: one rehash loop"),
]


def screens(override=None):
    return [(len(re.findall(p, (override or {}).get(f) or _src(f))), c, w)
            for f, p, c, w in SCREENS]


def section_1():
    rule("§1  The census: every NL-FSCX v2/v3 call in the shipped code, both directions")
    rows = census()
    got = {}
    for r in rows:
        got[r] = got.get(r, 0) + 1
    print("  %d calls in %d files" % (len(rows), len({r[0] for r in rows})))
    new = sorted(k for k in got if k not in EXPECTED)
    gone = sorted(k for k in EXPECTED if k not in got)
    moved = sorted(k for k in got if k in EXPECTED and got[k] != EXPECTED[k][0])
    check(not new, "no v2/v3 call outside the table (%d new: %s)" % (len(new), new[:3]))
    check(not gone, "every tabled call is still there (%d gone: %s)" % (len(gone), gone[:3]))
    check(not moved, "every row's call count holds (%s)" % moved[:3])
    ports = {f.split("/")[0] if f.startswith("bindings") else f for f, _, _, _ in got}
    check(len(rows) >= 100 and {H, GO, PY, "bindings"} <= ports,
          "the census reaches all four ports (%d calls)" % len(rows))
    c32 = census_32()
    check(c32 == EXPECTED_32, "the 32-bit suites' call counts hold (%s)" % c32)
    inj = _src(H).replace("static inline void twk_encrypt(",
                          "static void _probe(BitArray *o, const BitArray *a)\n"
                          "{ nl_fscx_revolve_v2_ba(o, a, a, R_VALUE); }\n"
                          "static inline void twk_encrypt(", 1)
    probe = census({H: inj})
    check((H, "_probe", "v2", "a") in probe and len(probe) == len(rows) + 1,
          "CONTROL: a call injected into a copy of herradura.h is caught as a new row")
    probe = census({H: _src(H).replace("nl_fscx_revolve_v2_ba(ct, block, &B, R_VALUE)",
                                       "nl_fscx_revolve_v2_ba(ct, block, block, R_VALUE)", 1)})
    check((H, "twk_encrypt", "v2", "block") in probe,
          "CONTROL: a changed B argument is caught as a different row")
    s = "Herradura cryptographic suite.s"
    check(census_32({s: _src(s) + "\n    bl      nl_fscx_revolve_v2\n"})[s] == 11,
          "CONTROL: an extra 32-bit call is counted")
    return rows


def section_2():
    rule("§2  The sites, who sets B, and the screens they rely on")
    used = {v[1] for v in EXPECTED.values()}
    check(used == set(SITES), "every site serves a call and every call names a site (%s)"
          % sorted(used ^ set(SITES)))
    n_by = {}
    for v in EXPECTED.values():
        n_by[v[1]] = n_by.get(v[1], 0) + v[0]
    print("\n  %-9s %5s  %s" % ("site", "calls", "who sets B / screen / answered in"))
    for s, (who, scr, q) in SITES.items():
        print("  %-9s %5d  %s\n  %-9s %5s  screen: %s;  %s" % (s, n_by.get(s, 0), who,
                                                            "", "", scr, q))
    got = screens()
    for n_, c, w in got:
        check(n_ == c, "%s (%d of %d)" % (w, n_, c))
    cut = _src(H).replace("while (!nl_v2_key_is_valid(B)) {", "if (0) {", 1)
    check(screens({H: cut})[12][0] == 0,
          "CONTROL: the rehash loop removed from a copy of herradura.h is caught")
    print("""
  Three sites let a party other than the key holder reach B.  HPKE-NL's sender
  chooses R (§6).  `twk`/FPE's attacker chooses the tweak, and the duplex's nonce
  is public, but both reach B only through a hash of the key (§5).  v3's sites
  have no weak class to reach (§7).  The 32-bit suites are fixed-width demos
  whose B is a preshared key, a DH key or hfscx_32(key, tweak).""")


# ═══════════════════════════════════════════════════════════════════════════
# §3  Free rounds, exactly
# ═══════════════════════════════════════════════════════════════════════════
def Mv(n, x):
    m = (1 << n) - 1
    return (x ^ ((x << 1) | (x >> (n - 1))) ^ ((x >> 1) | (x << (n - 1)))) & m


def _rotl(n, x, s):
    s %= n
    return ((x << s) | (x >> (n - s))) & ((1 << n) - 1) if s else x


def free_rounds(n, allowed, cap):
    """Largest r <= cap with a nonzero gamma whose M^j gamma (j < r) all lie in the
    coordinate subspace `allowed`.  M^r is a symmetric circulant, so its row p is
    rotl(c_r, p) with c_r = M^r e_0; each banned bit p is one linear constraint."""
    banned = [p for p in range(n) if not (allowed >> p) & 1]
    piv, c = {}, 1
    for r in range(cap):
        for p in banned:
            v = _rotl(n, c, p)
            while v:
                b = v.bit_length() - 1
                if b not in piv:
                    piv[b] = v
                    break
                v ^= piv[b]
        if len(piv) == n:
            return r
        c = Mv(n, c)
    return cap


def g_diff(n, k, cap):
    """Zero-weight rounds: + delta passes V_k = span{e_0..e_(k-1), e_(n-1)} (§11.28.3)."""
    return free_rounds(n, ((1 << k) - 1) | (1 << (n - 1)), cap) if k < n else cap


def g_lin(n, k, cap):
    """Correlation-1 rounds: masks on bits 0..k pass + delta (§11.30.5)."""
    return free_rounds(n, (1 << (k + 1)) - 1, cap) if k < n else cap


def section_3():
    rule("§3  v2's free rounds at n = 256, exactly, for every tz(delta)")
    gd = [g_diff(N, k, R) for k in range(N + 1)]
    gl = [g_lin(N, k, R) for k in range(N + 1)]
    fk = _load("nl_fscx_v2_fixed_key", os.path.join(HERE, "nl_fscx_v2_fixed_key.py"))
    bad = [(n, k) for n in (8, 16) for k in range(n)
           if fk.free_rounds(n, k, 3 * n // 4) != g_diff(n, k, 3 * n // 4)]
    bad += [(N, k) for k in (0, 1, 4, 16, 64, 128) if fk.free_rounds(N, k, R) != gd[k]]
    check(not bad, "the differential count agrees with nl_fscx_v2_fixed_key.py's "
          "free_rounds at n = 8, 16 (every k) and 256 (%s)" % bad[:3])
    t_d = {0: 1, 2: 2, 4: 3, 6: 4, 8: 5, 12: 7, 16: 9, 24: 13, 40: 21}
    t_l = {0: 1, 1: 1, 2: 2, 4: 3, 8: 5, 16: 9, 32: 17, 64: 33}
    check(all(gd[k] == v for k, v in t_d.items()), "§11.28.4's table reproduces")
    check(all(gl[k] == v for k, v in t_l.items()), "§11.30.5's table reproduces")
    check(gd[253] == 127 and gd[254] == R and gl[253] == 127,
          "tz = 253 gives 127 free rounds on both axes; tz = 254 gives all 192")
    check(all(gd[k] <= k // 2 + 1 for k in range(254)) and
          all(gl[k] <= k // 2 + 1 for k in range(254)),
          "below tz = 254, g(k) <= k/2 + 1 on both axes")
    print("  k:     0  4  16  64  128  190  252  253  254\n"
          "  diff: " + " ".join("%3d" % gd[k] for k in (0, 4, 16, 64, 128, 190, 252, 253,
                                                      254)) +
          "\n  lin:  " + " ".join("%3d" % gl[k] for k in (0, 4, 16, 64, 128, 190, 252, 253,
                                                        254)))
    return gd, gl


# ═══════════════════════════════════════════════════════════════════════════
# §4  The tz tail
# ═══════════════════════════════════════════════════════════════════════════
def delta(n, B):
    m = (1 << n) - 1
    return _rotl(n, (B * ((B + 1) >> 1)) & m, n // 4)


def tz(n, v):
    return n if v == 0 else (v & -v).bit_length() - 1


def cases(n):
    """P = B * floor((B+1)/2) mod 2^n by branch and 2-adic valuation, each case a
    probability, the bits it forces and the bits taken as uniform.  Even B = 2m:
    P = 2^(1+2v) u^2 (u odd: u^2 = 1 mod 8).  Odd B = 2m+1: P = 2^w * odd, w =
    v2(m+1).  The uniformity is a MODEL, checked against enumeration in §4."""
    out = []
    for v in range(n - 1):
        e = 1 + 2 * v
        fo = {p: 0 for p in range(min(e, n))}
        if e < n:
            fo[e] = 1
        for p in (e + 1, e + 2):
            if p < n:
                fo[p] = 0
        out.append((Fraction(1, 2 ** (v + 2)), fo))
    out.append((Fraction(1, 2 ** n), {p: 0 for p in range(n)}))          # m = 0
    for w in range(n - 1):
        fo = {p: 0 for p in range(w)}
        fo[w] = 1
        out.append((Fraction(1, 2 ** (w + 2)), fo))
    out.append((Fraction(1, 2 ** n), {**{p: 0 for p in range(n - 1)}, n - 1: 1}))
    return out


def prob(n, zero, one, cs):
    tot = Fraction(0)
    for pr, fo in cs:
        x = pr
        for p in zero | one:
            want = 1 if p in one else 0
            if p in fo:
                if fo[p] != want:
                    x = 0
                    break
            else:
                x /= 2
        tot += x
    return tot


def tail(n, k, cs):
    """Pr[tz(delta) >= k]: delta bit j is P bit (j - n/4) mod n."""
    return prob(n, {(3 * n // 4 + i) % n for i in range(k)}, set(), cs)


def section_4():
    rule("§4  The tz(delta) tail: 2^-k only to k = n/4")
    errs = []
    for n in ((16, 20) if QUICK else (16, 20, 24)):
        cnt = [0] * (n + 1)
        for B in range(1 << n):
            cnt[tz(n, delta(n, B))] += 1
        cs = cases(n)
        err = max(abs(math.log2(sum(cnt[k:]) / (1 << n)) - math.log2(tail(n, k, cs)))
                  for k in range(n + 1))
        errs.append(err)
        print("  n = %d: model against all 2^%d keys, worst |log2 error| = %.4f bits"
              % (n, n, err))
    check(max(errs) < 0.06 and errs == sorted(errs, reverse=True),
          "the model is within 0.06 bits of exhaustive enumeration at every width "
          "and k, and the error shrinks with width")
    cs = cases(N)
    allp = set(range(N))
    p0 = prob(N, allp, set(), cs)
    pm = prob(N, allp - {3 * N // 4 - 1}, {3 * N // 4 - 1}, cs)
    acc = [tail(N, k, cs) - p0 - (pm if k < N else 0) for k in range(N + 1)]
    la = [(-math.log2(a) if a > 0 else math.inf) for a in acc]
    print("  n = 256, accepted keys:  k = 16: 2^-%.1f   64: 2^-%.1f   128: 2^-%.1f   "
          "190: 2^-%.1f   253: 2^-%.1f   254: 2^-%.1f"
          % tuple(la[k] for k in (16, 64, 128, 190, 253, 254)))
    check(abs(math.log2(p0) + 129) < 1e-9, "delta = 0 has density 2^-129, as "
          "nl_v2_key_is_valid's docstring says")
    check(all(abs(la[k] - k) < 1e-6 for k in range(1, 65)),
          "for k <= 64 the accepted tail is 2^-k, as §11.28.4 assumed")
    check(abs(la[128] - 97) < 0.5 and abs(la[253] - 160) < 0.5,
          "past k = 64 it is not: tz >= 128 at 2^-97 (not 2^-128), tz = 253 at 2^-160 "
          "(not 2^-253)")
    S = _load("suite", os.path.join(ROOT, PY))
    w = 1 << 95
    check(tz(N, delta(N, w)) == 253 and S.nl_v2_key_is_valid(S.BitArray(N, w)),
          "WITNESS: B = 2^95 has delta = 2^253, tz 253, and passes nl_v2_key_is_valid")
    check(delta(N, 1 << 96) == 1 << 255 and not S.nl_v2_key_is_valid(S.BitArray(N, 1 << 96)),
          "CONTROL: B = 2^96 has delta = 2^255 and is refused")
    return la


# ═══════════════════════════════════════════════════════════════════════════
# §5  Question 2: many tweaks
# ═══════════════════════════════════════════════════════════════════════════
def bars():
    row = [l for l in _src("SECURITY.md").split("\n") if l.startswith("| **HSKE-NL-A2**")][0]
    m = re.search(r"at or above (\d\.\d+) differential and (\d\.\d+) linear", row)
    return float(m.group(1)), float(m.group(2))


def many_tweak(la, g, s, slack=1):
    """For T in 0..256: the best tz among 2^T tweaks (with `slack` bits in the
    attacker's favour), its free rounds, the data C(T) and the generic G(T)."""
    out = []
    for T in range(N + 1):
        k = max(k for k in range(N + 1) if la[k] <= T + slack)
        out.append((T, k, g[k], T + s * (R - g[k]), max(T, N - T)))
    return out


def section_5(la, gd, gl):
    rule("§5  Question 2: does the attacker gain by spreading over tweaks?")
    sd, sl = bars()
    print("  bars from SECURITY.md's HSKE-NL-A2 row: %.2f differential, %.3f linear "
          "(data = 2 x weight on the linear axis)" % (sd, sl))
    res = {}
    for name, g, s in (("differential", gd, sd), ("linear", gl, 2 * sl)):
        rows = many_tweak(la, g, s)
        res[name] = rows
        print("\n  %s:   T    k    g      C(T)   generic" % name)
        for T in (0, 32, 64, 96, 128, 160, 255):
            print("  %s  %3d  %3d  %3d  %8.1f  %4d" % (" " * len(name), *rows[T]))
        check(all(c >= gen - 1e-9 for _, _, _, c, gen in rows),
              "%s: C(T) >= max(T, 256 - T) for every T: no tweak count beats the "
              "generic multi-target attack" % name)
        check(min(c for T, _, _, c, _ in rows if T <= 96) > 256,
              "%s: C(T) > 256 for every T <= 96, twk's whole tweak space" % name)
    ctrl = many_tweak(la, gd, 1.0)
    check(min(c for T, _, _, c, _ in ctrl if T <= 96) <= 256,
          "CONTROL: at a bar of 1.0 the tweak-space check fails")
    d0 = res["differential"][0][3]
    d96 = min(r[3] for r in res["differential"][:97])
    gain64 = d0 - min(c for T, _, _, c, _ in res["differential"] if T <= 64)
    tx = min(T for T, _, _, c, _ in res["differential"] if T > 64 and c < d0 - 1)
    print("""
  The tail's second slope makes spreading pay: past T = 64 each further tweak bit
  buys about one free round (two bits of tz), worth s > 1 bits, and from T = %d the
  differential C(T) is below the single-key C(0) = %.0f.  So §11.28.4's "a random
  key loses at most 3 rounds" is not the many-tweak floor.  The floor over twk's 96
  tweak bits is %.0f, and over any tweak count C(T) stays at or above the generic
  cost, meeting it only near T = 255, where both are exhaustion.  FPE's ctx and the
  duplex's nonce are unbounded, so the generic comparison is the one that applies
  to them.""" % (tx, d0, d96))
    check(gain64 < 1 and 64 < tx <= 96, "to T = 64 spreading gains under one bit "
          "(%.2f); it beats the single-key figure from T = %d" % (gain64, tx))
    return res


# ═══════════════════════════════════════════════════════════════════════════
# §6  Question 1: HPKE-NL decrypt
# ═══════════════════════════════════════════════════════════════════════════
def section_6():
    rule("§6  Question 1: is HPKE-NL's decrypt-side refusal an oracle?")
    S = _load("suite6", os.path.join(ROOT, PY))
    poly, order = S.GF_POLY[N], (1 << N) - 1
    worst = 0
    for d in ((3, 5, 17, 257, 641, 65537) if QUICK else
              (3, 5, 17, 257, 641, 65537, 274177)):
        h = S.gf_pow(S.GF_GEN, order // d, poly, N)
        x, aff, mt, seen = 1, 0, 0, set()
        for i in range(d):
            if not S.nl_v2_key_is_valid(S.BitArray(N, x)):
                aff += 1
            if i:
                mt = max(mt, tz(N, delta(N, x)))
            seen.add(x)
            x = S.gf_mul(x, h, poly, N)
        worst = max(worst, mt)
        check(order % d == 0 and x == 1 and len(seen) == d and aff == 0,
              "order-%d subgroup: %d elements, none in the affine class (largest tz "
              "off the identity: %d)" % (d, d, mt))
    print("""
  A sender who picks R of small order d already confines R^a to d values, which is
  the Pohlig-Hellman exposure SECURITY.md cites for HPKE-NL's demo-only rating.  The
  refusal would add an oracle only if some subgroup element fell in the affine
  class; none does, and outside a small subgroup the refusal fires with probability
  about 2^-129 per query.  Steering B into the zero-weight class needs the same
  small subgroup, where the key is already down to d candidates.  No change.""")
    return worst


# ═══════════════════════════════════════════════════════════════════════════
# §7  Question 3: v3
# ═══════════════════════════════════════════════════════════════════════════
def chi(L, x):
    return sum((((x >> i) & 1) ^ ((~(x >> ((i + 1) % L)) & 1) & ((x >> ((i + 2) % L)) & 1)))
               << i for i in range(L))


def section_7():
    rule("§7  Question 3: v3 — answered by TODO #255, held here")
    rg = _load("rfg", os.path.join(HERE, "run_findings_gates.py"))
    src = _src("SecurityProofsCode/nl_fscx_v3_weak_keys.py")
    check("nl_fscx_v3_weak_keys.py" not in getattr(rg, "NON_GATING", {}) and
          "nl_fscx_v3_weak_keys.py" not in getattr(rg, "EXCLUDED", {}),
          "nl_fscx_v3_weak_keys.py is a findings gate (not NON_GATING or EXCLUDED)")
    check("the zero-weight-trail class  tz(delta(B)) >= 4" in src and
          "abs(p3 - 0.3125) < 1e-12" in src,
          "its §4(b) still asserts the zero-weight class dissolves at 5/16")
    for L in (5, 7):
        tab = [chi(L, x) for x in range(1 << L)]
        p1 = [a for a in range(1, 1 << L)
              if len({tab[x] ^ tab[x ^ a] for x in range(1 << L)}) == 1]
        c1 = [(a, b) for a in range(1, 1 << L) for b in range(1, 1 << L)
              if abs(sum(1 - 2 * ((bin(a & x).count("1") + bin(b & tab[x]).count("1")) & 1)
                         for x in range(1 << L))) == 1 << L]
        check(len(set(tab)) == 1 << L and not p1 and not c1,
              "chi on %d bits: a bijection with no probability-1 differential and no "
              "correlation-1 mask" % L)
    print("""
  v2 is a bijection in A, so a nonzero input difference reaches chi nonzero and some
  row pays for it; the same for masks.  No B can make a v3 round free, so who sets
  v3's B does not matter to a trail.  #352's entry missed #255's answer; this
  section records it rather than re-deriving it.""")


# ═══════════════════════════════════════════════════════════════════════════
def section_8():
    rule("§8  The documents")
    done = _src("TODO_DONE.md")
    m = re.search(r"(?ms)^### #352:.*?(?=^### |\Z)", done)
    check(bool(m) and "Status: **DONE v12.0.2**" in m.group(0),
          "TODO_DONE.md: #352 is DONE v12.0.2")
    check("### #352:" not in _src("TODO.md"), "TODO.md no longer holds #352")
    sp = _src("SecurityProofs-10.md")
    check("## 11.77 " in sp and "TODO #352" in sp, "SecurityProofs-10.md §11.77")
    check("§11.77" in _src("SecurityProofs-7.md"),
          "SecurityProofs-7.md §11.28.4 carries the correction note")
    check("## [12.0.2]" in _src("CHANGELOG.md") and "#352" in _src("CHANGELOG.md"),
          "CHANGELOG [12.0.2]")


def main():
    section_1()
    section_2()
    gd, gl = section_3()
    la = section_4()
    section_5(la, gd, gl)
    section_6()
    section_7()
    section_8()
    rule("§9  Verdict")
    print("""
  Who sets B, for every v2/v3 call: the key holder (A2, A3), a hash of the key
  (twk, FPE, the duplex), the sender (HPKE-NL, -NL3), or a pinned vector.
    Q1  HPKE-NL: the refusal is no oracle; no small subgroup reaches the class.
    Q2  twk/FPE: spreading over tweaks never beats the generic multi-target cost,
        and stays above 256 in twk's tweak space, on both axes at the bars.
    Q3  v3: no weak class (TODO #255), held.
  Correction to §11.28.4: the tz tail is 2^-k only to k = 64, and the single-key
  "3 rounds at 1/16" is not the many-tweak floor.  No rating moves.""")
    if FAIL:
        print("\n*** FAILED: %d check(s) ***" % len(FAIL))
        for f in FAIL:
            print("  - " + f)
        return 1
    print("\n*** OK: every finding reproduces ***")
    return 0


if __name__ == "__main__":
    sys.exit(main())
