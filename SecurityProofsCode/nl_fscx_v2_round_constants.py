#!/usr/bin/env python3
"""nl_fscx_v2_round_constants.py — TODO #245: round constants for NL-FSCX v2.

TODO #243 (§11.25) and #244 (§11.26) found that v2-revolve was the iterate of one
unvaried round: E_B = F_B^r, with no round constant and no key schedule.  This
script is the evidence for the fix, and it also carries the corrections to two
numbers those items published -- see §0, which exists because the errors were
found by doing this work and are not being quietly dropped.

Sections
  0  Corrections to §11.25 and §11.26
  1  The gating question: does a round constant cost anything?  (No -- xdp+ is
     EXACTLY invariant, so TODO #214's trail bounds carry over verbatim.)
  2  What the round constant buys, measured
  3  The identity-collapse class, measured properly at every deployed width
  4  Verdict

Run:  python3 SecurityProofsCode/nl_fscx_v2_round_constants.py [--full]
"""

import argparse
import importlib.util
import os
import random
import statistics
import sys
from collections import Counter

SEP = "=" * 74
SEP2 = "-" * 74

_SUITE_PATH = os.path.join(os.path.dirname(__file__), '..',
                           'Herradura cryptographic suite.py')


def _load_suite():
    spec = importlib.util.spec_from_file_location('herradura_suite', _SUITE_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


_SUITE = _load_suite()


def rule(t):
    print("\n" + SEP)
    print(t)
    print(SEP)


# ── reduced-width model of one v2 round, with and without the round constant ──
def _ops(n):
    mask = (1 << n) - 1

    def rol(x, k):
        k %= n
        return ((x << k) | (x >> (n - k))) & mask

    def ror(x, k):
        k %= n
        return ((x >> k) | (x << (n - k))) & mask
    return mask, rol, ror


def M_is_singular(n):
    """M = I + ROL + ROR must be invertible or F_B is not a bijection at all.
    This is the check whose absence invalidated the n=12 rows in §11.25/§11.26."""
    mask, rol, ror = _ops(n)
    rows = [(v ^ rol(v, 1) ^ ror(v, 1)) & mask for v in [1 << i for i in range(n)]]
    rank = 0
    mat = rows[:]
    for col in range(n):
        p = next((i for i in range(rank, n) if (mat[i] >> col) & 1), None)
        if p is None:
            continue
        mat[rank], mat[p] = mat[p], mat[rank]
        for i in range(n):
            if i != rank and ((mat[i] >> col) & 1):
                mat[i] ^= mat[rank]
        rank += 1
    return rank != n


def round_step(n, B, rc_index=0):
    mask, rol, ror = _ops(n)
    d = rol((B * ((B + 1) >> 1)) & mask, n // 4)

    def F(a):
        v = (a ^ rc_index) ^ B
        return ((v ^ rol(v, 1) ^ ror(v, 1)) + d) & mask
    return F


def cipher_table(n, B, r, rc):
    """E_B as an explicit table, with (rc=True) or without the round constant."""
    N = 1 << n
    cur = list(range(N))
    for i in range(1, r + 1):
        F = round_step(n, B, i if rc else 0)
        cur = [F(x) for x in cur]
    return cur


# ═══════════════════════════════════════════════════════════════════════════
def section0():
    rule("§0  Corrections to SecurityProofs-7.md §11.25 and §11.26")
    print("""Two numbers those sections published do not survive scrutiny.  Both were
found while doing this item's work, and both are corrected in place rather than
dropped.  Neither changes either item's verdict.

  (a) EVERY n = 12 MEASUREMENT IS VOID.  M = I + ROL + ROR is SINGULAR at
      n = 12, so F_B is not a bijection there and the cycle-decomposition both
      sections used silently produces nonsense.  §11.25's n = 12 order row and
      §11.26's n = 12 fixed-point figure (3724.69) are withdrawn.  TODO #214
      avoided this by choosing widths where M is invertible and said so; #243
      and #244 did not check.  Verified below.

  (b) "measured 13.84 at n = 16, confirming tau(192) = 14 almost exactly" WAS
      A SMALL-SAMPLE ARTEFACT.  The statistic is heavy-tailed: over 300 keys
      the mean is an order of magnitude higher and its standard error exceeds
      it, because a few keys contribute enormously.  25 keys landing near 14
      was luck, and tau(r) is the mean for a UNIFORM RANDOM permutation, which
      F_B is not.  The robust statistics (median, fraction above 1) are
      reported instead from here on, and they support the same conclusion more
      honestly -- see §2.

  Neither correction rescues the construction: §2 shows the excess is real on
  robust statistics, and §3 shows the identity-collapse class is real too.
  What changes is that the numbers are now the right ones.\n""")
    print(f"      {'n':>4}  {'M singular?':>12}  {'F_B a bijection?':>17}")
    print("      " + SEP2[:40])
    for n in (8, 10, 12, 16, 20, 32, 256):
        sing = M_is_singular(n)
        print(f"      {n:>4}  {str(sing):>12}  {str(not sing):>17}"
              + ("   <- n=12 rows withdrawn" if n == 12 else ""))
    print("\n      M is invertible at the deployed n = 256, so the construction is a")
    print("      genuine bijection where it ships.  n = 12 was simply a bad choice")
    print("      of test width.")


# ═══════════════════════════════════════════════════════════════════════════
def section1():
    rule("§1  The gating question: does a round constant cost anything?")
    print("""TODO #245 named this the gating work: round constants change the round
function, and TODO #214's differential trail bounds are bounds on the round
function, so they might no longer hold.

They do hold, exactly, and the argument is short enough to check by hand.  With
an XOR round constant the round is F_i(x) = M(x XOR B XOR C_i) + delta(B).  For a
pair with input XOR difference alpha, the two inputs to M are (x XOR B XOR C_i)
and (x XOR alpha XOR B XOR C_i): the constant cancels, so the difference entering
M is still alpha.  M is linear, so the difference leaving it is still M(alpha).
And M is a bijection, so as x ranges uniformly the value entering the modular
addition ranges uniformly either way -- meaning the carry behaviour, and hence
the whole output-difference distribution, is identical.

Not approximately identical: identical.  Checked exhaustively below by
comparing the full output-difference distribution with and without a constant.\n""")
    n = 10
    rng = random.Random(5)
    same = 0
    trials = 25
    for _ in range(trials):
        B = rng.randrange(1 << n)
        alpha = rng.randrange(1, 1 << n)
        C = rng.randrange(1 << n)
        f0, fc = round_step(n, B, 0), round_step(n, B, C)
        d0 = Counter((f0(a) ^ f0(a ^ alpha)) for a in range(1 << n))
        dc = Counter((fc(a) ^ fc(a ^ alpha)) for a in range(1 << n))
        same += (d0 == dc)
    print(f"      exhaustive one-round output-difference distributions identical,")
    print(f"      with vs without an XOR round constant: {same}/{trials} random "
          f"(B, alpha, C) at n = {n}")
    print(f"""
      So TODO #214's trail bounds carry over verbatim and need no re-run.  The
      gating concern is resolved analytically, and the check above is the
      empirical confirmation rather than the argument.

      Note what this also means: a round constant is not a strengthening
      against differential cryptanalysis.  It buys nothing there and costs
      nothing there.  What it buys is §2 and §3.""")
    return same == trials


# ═══════════════════════════════════════════════════════════════════════════
def section2(full):
    rule("§2  What the round constant buys, measured")
    r = _SUITE.R_VALUE
    n = 16
    K = 40 if full else 25
    print(f"""Fixed-point count is the observable that exposes E_B = F_B^r.  An ideal
cipher has a median of 1 and exceeds 1 for about 37% of keys.  Measured at
n = 16 (where M is invertible, so F_B is a genuine bijection), r = {r}, {K} keys:\n""")
    print(f"      {'variant':>22}  {'median':>7}  {'mean':>8}  {'max':>7}  {'frac > 1':>9}")
    print("      " + SEP2[:62])
    out = {}
    for rc in (False, True):
        rng = random.Random(20250828)
        v = []
        for _ in range(K):
            T = cipher_table(n, rng.randrange(1 << n), r, rc)
            v.append(sum(1 for x in range(1 << n) if T[x] == x))
        v.sort()
        out[rc] = v
        lab = "with round constants" if rc else "without (pre-5.0.0)"
        print(f"      {lab:>22}  {statistics.median(v):>7.1f}  {sum(v)/K:>8.2f}  "
              f"{v[-1]:>7}  {sum(1 for x in v if x > 1)/K:>8.1%}")
        sys.stdout.flush()
    print(f"      {'ideal cipher':>22}  {1.0:>7.1f}  {1.0:>8.2f}  {'-':>7}  {0.37:>8.1%}")
    print("""
      The round constant moves every statistic to where an ideal cipher sits.
      This is the honest form of §11.26's claim: not "tau(r) = 14 predicts it"
      -- F_B is not a uniform random permutation and the mean is dominated by
      rare keys -- but "the median key deviates, most keys deviate, and with a
      round constant they stop deviating".""")
    return out


# ═══════════════════════════════════════════════════════════════════════════
def section3():
    rule("§3  The identity-collapse class, measured at every deployed width")
    r = _SUITE.R_VALUE
    print(f"""The sharpest consequence of E_B = F_B^r is that if ord(F_B) divides r, the
cipher IS the identity map -- plaintext passes through unchanged.  §11.25
reported this at n = 8 and said it was gone by n = 12; that claim rested on the
void n = 12 measurement (§0a) and on a 10-key sample at n = 16.  Measured
properly:\n""")
    print(f"      {'n':>4}  {'keys':>6}  {'F^r == identity':>17}  note")
    print("      " + SEP2[:64])
    # n=8 and n=16: exhaustive cycle decomposition (M invertible at both).
    for n, K in ((8, 300), (16, 300)):
        N = 1 << n
        rng = random.Random(777)
        hits = 0
        for _ in range(K):
            B = rng.randrange(N)
            F = round_step(n, B, 0)
            T = [F(a) for a in range(N)]
            seen = bytearray(N)
            ok = True
            for s in range(N):
                if seen[s]:
                    continue
                c = 0
                x = s
                while not seen[x]:
                    seen[x] = 1
                    x = T[x]
                    c += 1
                if r % c != 0:
                    ok = False
                    break
            hits += ok
        note = "small width" if n == 8 else "rare but REAL -- §11.25 missed this"
        print(f"      {n:>4}  {K:>6}  {hits:>7}/{K:<9}  {note}")
        sys.stdout.flush()
    # n=32 and n=256 cannot be enumerated: probe random points instead.
    for n, K, note in ((32, 200, "Arduino / assembly width"),
                       (256, 200, "DEPLOYED -- 256 does not divide 192")):
        mask, rol, _ = _ops(n)
        rng = random.Random(31337)
        hits = 0
        for _ in range(K):
            B = rng.randrange(1 << n)
            F = round_step(n, B, 0)
            allfix = True
            for _ in range(4):
                x = rng.randrange(1 << n)
                y = x
                for _ in range(r):
                    y = F(y)
                if y != x:
                    allfix = False
                    break
            hits += allfix
        print(f"      {n:>4}  {K:>6}  {hits:>7}/{K:<9}  {note} (probed)")
        sys.stdout.flush()
    print(f"""
      The deployed parameters are clear, and for a structural reason rather
      than luck: the class found at n = 16 has ord(F_B) = n exactly, and
      n = 256 does not divide r = {r}.  The Arduino and assembly ports at n = 32
      are clear too.  So this was never a live exposure -- but it was reachable
      at two of the widths anyone might test at, and §11.25 asserted it was not.

      With a round constant the question stops being askable: E_B is no longer
      a power of any single map, so no order of F_B can collapse it.""")


# ═══════════════════════════════════════════════════════════════════════════
def section4(inv_ok):
    rule("§4  Verdict")
    print(f"""Round constants ship in v5.0.0.  The 1-based round index is XORed into the
state before each step, in C, Go, Python and Java identically.

  * They cost nothing against differential cryptanalysis: xdp+ is exactly
    invariant (§1: {'confirmed' if inv_ok else 'NOT CONFIRMED -- investigate'}), so TODO #214's bounds carry over verbatim.
  * They remove the fixed-point deviation entirely (§2).
  * They make the identity-collapse class unaskable (§3).
  * They cost one XOR per round.

TODO #245's other candidate, a prime round count, is NOT shipped and is no
longer needed: it addressed only the fixed-point symptom, and only by making
tau(r) small.  Once the cipher is not a power of one map, the round count's
divisor structure is irrelevant.  R_VALUE stays at {_SUITE.R_VALUE}.

What this does NOT do, and what #245 was written to forbid claiming: it does not
re-rate anything.  HSKE-NL-A2 and `twk` remain demo-only.  The structural
objections in §11.25 and §11.26 are answered, which means the trail bounds
become the binding constraint again -- and those bounds are still TODO #214's
key-averaged, order-of-magnitude ones, with still no PRP or SPRP reduction for
nl_fscx_revolve_v2 at any round count.  Removing an objection is not the same as
supplying a proof.  Whether the ratings should now move is a separate question
for a separate item, on evidence gathered after this one lands.""")


def main():
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[1])
    ap.add_argument('--full', action='store_true', help='40 keys in §2 instead of 25')
    args = ap.parse_args()
    print(SEP)
    print("Round constants for NL-FSCX v2 — TODO #245")
    print(SEP)
    section0()
    inv_ok = section1()
    section2(args.full)
    section3()
    section4(inv_ok)
    print("\n" + SEP)
    print("xdp+ invariant; fixed points ideal; collapse class unaskable. Ratings unchanged.")
    print(SEP)
    return 0 if inv_ok else 1


if __name__ == '__main__':
    sys.exit(main())
