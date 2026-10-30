#!/usr/bin/env python3
"""v1_mode_rounds.py — TODO #347, closed: NL-FSCX v1's modes at 3n/4 rounds (v10.0.0).

TODO #346 found that NL-FSCX v1 costs at most 2 bits per round (an exact 1/4-per-round
core), so its n/4 = 64-round modes sat exactly at the 128-bit collision bar.  #347's
first pass (v1_mode_floor.py) proved the 2-bit floor in the trail-weight model and
sized the fix by round count; its second pass (v1_core_break.py) showed constants
cannot break the cores and a rotating key adds no proven margin.  v10.0.0 takes the
sized fix: the three modes now run V1_MODE_STEPS = 3n/4 = 192 rounds.

  §1  WHAT SHIPS.  Each port's V1_MODE_STEPS is 3n/4 = 192, and the three modes use
      it: the HFSCX-256 compression function, HSKE-NL-A1's keystream (plain and
      AEAD) and MAC key, and the WOTS chain step.  The shipped Python functions are
      recomputed by hand at 192 rounds, with a 64-round CONTROL that must differ.
      The 32-bit demo targets follow at 3n/4 = 24 (TODO #349): hfscx_32 and the A1
      keystream in the ARM / NASM / Arduino files, with a CONTROL that fires.

  §2  THE DIFFERENTIAL FLOOR AT 192 ROUNDS.  Lemma 1 (v1_mode_floor.py §2) is per
      round, so outside B1 every characteristic costs >= 2 per round, 384 over 192;
      B1 outside the residual costs more by Lemma 2.  Inside the 538-member residual,
      the class search ("every round costs <= D") is re-run at 192 rounds: the least
      characteristic is 384, met by the second core, and none starts at a zero chaining
      difference (a one-block collision) or at HSKE-NL-A1's nonce difference.

  §3  THE LINEAR FLOOR.  Every R-round linear trail weighs >= R - 1 (branch number
      5, v1_mode_floor.py §7), so 191 at 192 rounds: squared correlation <= 2^-382.

  §4  WHAT IT MEANS FOR THE RATINGS (prose).  §5  THE DOCUMENTS.  §6  VERDICT.

Every bound is in the trail-weight model; #346 §3 showed it is not the exact
probability for v1, and the linear hull is not measured.

Pure Python, deterministic.  About 3 min with --quick (D = 3), 10 min without (D = 4),
on an aarch64 SBC.  Exits non-zero if a finding stops reproducing.

Run:  python3 SecurityProofsCode/v1_mode_rounds.py [--quick]
"""

import importlib.util
import os
import re
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
QUICK = "--quick" in sys.argv
D = 3 if QUICK else 4
ROUNDS = 192
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


FL = _load("_v1_floor", os.path.join(HERE, "v1_mode_floor.py"))
H = FL.H


def _src(rel):
    with open(os.path.join(ROOT, rel), encoding="utf-8") as fh:
        return fh.read()


_ASM32 = {  # file -> (constant definition, the step operand, A1 keystream checked?)
    "Herradura cryptographic suite.s": (r"\.equ V1_MODE_STEPS, 24", "#V1_MODE_STEPS", True),
    "CryptosuiteTests/Herradura_tests.s": (r"\.equ V1_MODE_STEPS, 24", "#V1_MODE_STEPS",
                                           False),
    "Herradura cryptographic suite.asm": (r"%define V1_MODE_STEPS 24", "V1_MODE_STEPS", True),
    "CryptosuiteTests/Herradura_tests.asm": (r"%define V1_MODE_STEPS 24", "V1_MODE_STEPS",
                                             False),
    "Herradura cryptographic suite.ino": (r"#define V1_MODE_STEPS \(3 \* KEYBITS / 4\)",
                                          "V1_MODE_STEPS", True),
}


def _check_32bit(override=None):
    """TODO #349: the 32-bit demo targets (KEYBITS = 32) run v1's modes at 3n/4 = 24.
    hfscx_32 is their HFSCX-256; the A1 demo is their HSKE-NL-A1.  Their Stern and
    ZKBoo stand-ins, the HPKS-NL challenge and the RNL KDF stay at n/4 with the four
    ports (TODO #348).  Returns what is wrong; empty means all of it holds."""
    bad = []
    for f, (const, op, a1) in _ASM32.items():
        s = (override or {}).get(f) or _src(f)
        if not re.search(const, s):
            bad.append("%s: no V1_MODE_STEPS = 24" % f)
        if f.endswith(".ino"):
            body = s[s.index("static uint32 hfscx_32("):]
            body = body[:body.index("\n}")]
            ok = body.count("V1_MODE_STEPS)") == 2 and ", 8)" not in body
            a1_ok = "RNL_KDF_DC, base, V1_MODE_STEPS)" in s
        else:
            body = s[s.index("\nhfscx_32:\n"):]
            body = body[:body.index("pop     {r4, r5, pc}" if f.endswith(".s") else "ret")]
            ok = body.count(op + "\n") == 2 and not re.search(r"(#8|ecx, 8)\n", body)
            a1_ok = re.search(re.escape(op) + r"\s+[@;] 3n/4 \(TODO #349\)\n\s+"
                              r"(bl|call)\s+nl_fscx_revolve_v1\s+[@;] \w+ +=\s+ks", s)
        if not ok:
            bad.append("%s: hfscx_32 not at V1_MODE_STEPS in both blocks" % f)
        if a1 and not a1_ok:
            bad.append("%s: A1 keystream not at V1_MODE_STEPS" % f)
    return bad


# ═══════════════════════════════════════════════════════════════════════════
def section_1():
    rule("§1  What ships: V1_MODE_STEPS = 3n/4 in the three modes, all four ports")
    sites = {
        "herradura.h": [r"#define V1_MODE_STEPS \(3 \* KEYBITS / 4\)",
                        r"nl_fscx_revolve_v1_ba\(&state, &block, &state, V1_MODE_STEPS\)",
                        r"nl_fscx_revolve_v1_ba\(ks_out, seed, &base_i, V1_MODE_STEPS\)",
                        r"nl_fscx_revolve_v1_ba\(mac_key_out, &seed2, base, V1_MODE_STEPS\)",
                        r"nl_fscx_revolve_v1_ba\(&ks, &seed, &base, 3 \* base\.nbits / 4\)",
                        r"nl_fscx_revolve_v1_ba\(out, &rotx, x, V1_MODE_STEPS\)"],
        "herradura/herradura.go": [r"const V1ModeSteps = 3 \* 256 / 4",
                                   r"NlFscxRevolveV1\(block, state, V1ModeSteps\)",
                                   r"NlFscxRevolveV1\(seed, baseI, V1ModeSteps\)",
                                   r"NlFscxRevolveV1\(seed2, base, V1ModeSteps\)",
                                   r"NlFscxRevolveV1\(RnlKdfSeed\(base\), base, v1ModeSteps\(n\)\)",
                                   r"NlFscxRevolveV1\(x\.RotateLeft\(n/8\), x, v1ModeSteps\(n\)\)"],
        "Herradura cryptographic suite.py": [r"V1_MODE_STEPS = 3 \* KEYBITS // 4",
                                             r"steps = V1_MODE_STEPS",
                                             r"base, V1_MODE_STEPS\)",
                                             r"base\.uint \^ i\), V1_MODE_STEPS\)",
                                             r"rnl_kdf_seed\(base\), base, 3 \* n // 4\)",
                                             r"x\.rotated\(n // 8\), x, 3 \* n // 4\)"],
        "bindings/java/herradurakex/Hfscx256.java": [r"static final int V1_MODE_STEPS = 3 \* N / 4",
                                                     r"int steps = V1_MODE_STEPS; // 192"],
        "bindings/java/herradurakex/HerraduraNl.java": [r"nlFscxRevolveV1\(seed, base, 3 \* base\.size\(\) / 4\)",
                                                        r"base, Hfscx256\.V1_MODE_STEPS\)",
                                                        r"base\.xorUint\(i\), Hfscx256\.V1_MODE_STEPS\)"],
        "bindings/java/herradurakex/Wots.java": [r"b\.rotLeft\(N / 8\), b, Hfscx256\.V1_MODE_STEPS\)"],
    }
    missing = ["%s: %s" % (f, p) for f, pats in sites.items() for p in pats
               if not re.search(p, _src(f))]
    check(not missing, "every port defines V1_MODE_STEPS = 3n/4 and uses it in the "
          "compression function, A1's keystream and MAC key, and the WOTS chain "
          "(%d sites; missing: %s)" % (sum(map(len, sites.values())), missing[:3]))
    stale = [f for f in sites if re.search(r"NlFscxRevolveV1\(state, block, 64\)|"
                                            r"&state, &block, 64\)|steps = n // 4  # 64",
                                            _src(f))]
    check(not stale, "no port still runs the compression function at 64 rounds (%s)"
          % stale)
    check(H.V1_MODE_STEPS == ROUNDS, "the shipped Python constant is %d" % H.V1_MODE_STEPS)
    bad32 = _check_32bit()
    check(not bad32, "TODO #349: the 32-bit targets mirror it at 3n/4 = 24 -- hfscx_32's "
          "two blocks in the ARM / NASM suites and harnesses and the Arduino suite, and "
          "A1's keystream in the three suites (%s)" % bad32[:3])
    ctl = _check_32bit({"Herradura cryptographic suite.ino":
                        _src("Herradura cryptographic suite.ino").replace(
                            "nl_fscx_revolve_v1(x, 0xA3C5E7B9UL, V1_MODE_STEPS)",
                            "nl_fscx_revolve_v1(x, 0xA3C5E7B9UL, 8)")})
    check(ctl, "CONTROL: the 32-bit check FIRES on an hfscx_32 block put back at 8 rounds")

    BA, rv1 = H.BitArray, H.nl_fscx_revolve_v1
    iv = int.from_bytes(H._HFSCX256_IV_BYTES, "big")

    def mmo(msg, steps):
        """HFSCX-256 by hand: pad, length block ^ IV, Matyas-Meyer-Oseas at `steps`
        rounds (the block is v1's A, the chaining value its B; TODO #351 -- it was
        Davies-Meyer, B = the block, until v11.0.0)."""
        p = bytearray(msg) + b"\x80"
        p += b"\x00" * (-len(p) % 32)
        p += ((len(msg) * 8) ^ iv).to_bytes(32, "big")
        s = BA(256, iv)
        for o in range(0, len(p), 32):
            m = BA(256, int.from_bytes(p[o:o + 32], "big"))
            s = BA(256, rv1(m, s, steps).uint ^ m.uint)
        return s.uint.to_bytes(32, "big")
    msgs = (b"", b"a", b"HerraduraKEx v10.0.0" * 3)
    check(all(H.hfscx_256(m) == mmo(m, ROUNDS) for m in msgs),
          "hfscx_256 equals a hand-built Matyas-Meyer-Oseas chain at 192 rounds on 3 messages")
    check(all(H.hfscx_256(m) != mmo(m, 64) for m in msgs),
          "CONTROL: it differs from the same chain at 64 rounds")
    k, nn, pt = BA(256, 0x1234 << 200), BA(256, 0xabcd << 100), BA(256, 0x55)
    base = BA(256, k.uint ^ nn.uint)
    ks = rv1(H.rnl_kdf_seed(base), base, ROUNDS)
    check(H.hske_nla1_encrypt(pt, k, nn).uint == pt.uint ^ ks.uint and
          H.hske_nla1_encrypt(pt, k, nn).uint !=
          pt.uint ^ rv1(H.rnl_kdf_seed(base), base, 64).uint,
          "hske_nla1_encrypt's keystream is 192 rounds of v1 (and not 64)")
    x = BA(256, 0xfeed << 77)
    check(H._wots_h(x) == rv1(x.rotated(32), x, ROUNDS) and
          H._wots_h(x) != rv1(x.rotated(32), x, 64),
          "the WOTS chain step is 192 rounds of v1 (and not 64)")


def section_2():
    rule("§2  The differential floor at 192 rounds")
    print("""
  Lemma 1 holds round by round, so every characteristic under a beta outside B1 costs
  >= 2 bits in EVERY round: 384 over 192.  B1 betas outside the residual satisfy
  Lemma 2, 5 * total >= 11 * 191 + 5, so they cost >= 422.  That leaves the residual,
  searched exhaustively in the class 'every round costs <= %d' at 192 rounds:""" % D)
    w, t0 = FL.W(256), time.time()
    R = FL.residual(w)
    least, coll, ent = None, [], []
    for b in R:
        adj = FL.adjacency(FL.edges(w, b, D), b)
        l = FL.walk(adj, None, None, ROUNDS)
        if l is not None and (least is None or l < least[0]):
            least = (l, [b])
        elif l is not None and l == least[0]:
            least[1].append(b)
        if b and FL.walk(adj, 0, 0, ROUNDS) is not None:
            coll.append(b)
        if b and FL.walk(adj, w.rol(b, 32), None, ROUNDS) is not None:
            ent.append(b)
    print("  (%d betas, %.0f s)" % (len(R), time.time() - t0))
    core2 = (1 << 255) | (1 << 253)
    check(len(R) == 538 and least is not None and least[0] == 2 * ROUNDS and
          least[1] == [core2],
          "the least 192-round characteristic in the class is %s, under beta = 2^255 + "
          "2^253 alone (%s); TODO #346's core, beta = 2^254 + 1, lies outside the "
          "residual, where Lemma 1's 2 bits per round is the floor it meets"
          % (least and least[0], least and [hex(b) for b in least[1]]))
    w1 = FL.adjacency(FL.edges(w, (1 << 254) | 1, 2), (1 << 254) | 1)
    a1 = w.M(1 << 255)
    check(not FL.in_B1(w, (1 << 254) | 1) and FL.walk(w1, a1, a1, ROUNDS) == 2 * ROUNDS,
          "CONTROL: TODO #346's core is outside B1 and its 192-round alpha -> alpha "
          "walk costs exactly 384")
    check(not coll, "no one-block collision characteristic (0 -> 0) in the class at 192 "
          "rounds (%d betas with one)" % len(coll))
    check(not ent, "no 192-round characteristic in the class starts from HSKE-NL-A1's "
          "nonce difference ROL(beta, n/8) (%d betas with one)" % len(ent))


def section_3():
    rule("§3  The linear floor")
    print("""
  v1_mode_floor.py §7 proves 3 w_r + 2 w_(r-1) >= 3 from T's branch number of 5,
  independently of the round count: a round costs 0 only after one costing >= 2, and
  two zero-cost rounds never touch, so every R-round linear trail weighs >= R - 1.
  At 192 rounds that is 191, a squared correlation <= 2^-382.  (Gated there.)""")


def section_4():
    rule("§4  What it means for the ratings")
    print("""
      mode                    bar                  floor (model)   margin
      HFSCX-256 collision     128 (birthday)       384             3.0x
      HFSCX-256 semi-free     128                  384             3.0x
      HSKE-NL-A1 codebook     256 (full)           384             1.5x
      linear, every mode      -                    191             2^-382
  The 2^64-block per-key data limit HSKE-NL-A1 carried since #346 is no longer
  needed for the bar it was set against.  HFSCX-256 / -DS, HPKS-WOTS and
  HPKS-XMSS return to production-track (conjectured): a named conjecture,
  cryptanalysis at the criterion with room to spare, and no known attack.""")


def section_5():
    rule("§5  The documents")
    sec = _src("SECURITY.md")
    rows = {}
    for line in sec.splitlines():
        mm = re.match(r"\| \*\*(.+?)\*\*", line)
        if mm:
            rows.setdefault(mm.group(1), line)

    def restored(row):
        return "Restored by TODO #347 (v10.0.0)" in row and "Production-track" in \
            row.split("|")[2]
    for name in ("HFSCX-256 / HFSCX-256-DS", "HPKS-WOTS", "HPKS-XMSS"):
        check(restored(rows.get(name, "")), "SECURITY.md's %s row is restored to "
              "production-track by TODO #347" % name)
    a1 = rows.get("HSKE-NL-A1", "")
    check("TODO #347 (v10.0.0)" in a1 and "2^64 blocks" not in a1.split("|")[2],
          "SECURITY.md's HSKE-NL-A1 row drops the 2^64-block limit from its status")
    check(not restored(rows.get("HFSCX-256 / HFSCX-256-DS", "").replace(
        "Restored by", "Demoted by")), "CONTROL: the row check FIRES on an unrestored row")
    todo, done = _src("TODO.md"), _src("TODO_DONE.md")
    m = re.search(r"### #347:.*?(?=^### |\Z)", done, re.S | re.M)
    check("### #347:" not in todo and m and "Status: **DONE v10.0.0**" in m.group(0),
          "TODO #347 is closed as DONE v10.0.0 and moved to TODO_DONE.md")
    mig = _src("MIGRATING.md")
    check("10.0.0" in mig and "TODO #347" in mig, "MIGRATING.md has the v10.0.0 entry")


def section_6():
    rule("§6  Verdict")
    print("""**At 3n/4 = 192 rounds NL-FSCX v1's modes clear their bars with margin, in the
trail-weight model.**

  HFSCX-256: every collision characteristic costs >= 384, 3x the birthday bar, and
  the semi-free-start core that set the ceiling at 1.0x now costs 384 too.
  HSKE-NL-A1: >= 384 against the full-codebook bar of 256, so the per-key data limit
  goes.  Linear: every trail weighs >= 191.

  NOT DONE.  The exact probability (the model is not the cipher for v1), the linear
  hull, and rounds of > %d bits inside the residual.""" % D)


def main():
    print(__doc__.split("Run:")[0].rstrip())
    print("\n  mode: %s (class D = %d)" % ("--quick" if QUICK else "full", D))
    section_1()
    section_2()
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
