#!/usr/bin/env python3
"""v1_core_break.py — TODO #347, second pass: can NL-FSCX v1's 2-bit cores be broken
without adding rounds?

TODO #347's first pass (v1_mode_floor.py) proved, in the trail-weight model, a floor of
2 bits per round under a fixed message / key difference beta, met exactly by two cores:
    core 1: beta = 2^254 + 1,         alpha = M(2^255)
    core 2: beta = 2^255 + 2^253,     alpha = M(2^254)
Both have alpha ^ beta = 2^j and an addition output difference of 0, and both hold with
probability exactly 1/4 per round for every B.  It listed three fixes: more rounds, the
v3 round, or "breaking the core directly, with a round-dependent B or a nonzero constant
in the addition".  The first two are sized by §11.70 and §11.52.  This script measures
the third, at n = 256.

  §1  THE INSTRUMENTS.  The class-graph edge finder of v1_mode_floor.py, generalised
      to a key difference that changes between rounds (beta_r -> beta_(r+1)), agrees
      with the fixed-beta finder when beta_(r+1) = beta_r, and the layered walk built
      on it finds both cores at 128 under a fixed key.

  §2  ROUND CONSTANTS ARE TRANSPARENT.  A constant XORed into B or into A, or added
      inside the addition, cannot touch either core:
        - B ^ RC_r keeps the key difference beta, and the core holds with probability
          exactly 1/4 for EVERY B, hence for every B ^ RC_r;
        - A ^ RC_r keeps the state difference alpha, and the 1/4 is over A uniform;
        - (A + B + c_r): the core's event is A + B = A' + B', which is the same event
          with c_r added to both sides.
      The real round with random per-round constants in each place keeps both cores at
      4^-r, r = 1..5.  The linear bound of §11.70 is untouched too: a constant changes
      a trail's sign, never its weight.

  §3  A ROTATING KEY SCHEDULE, B_r = ROL(B, r s), BREAKS BOTH CORES -- for s >= 3.
      The key difference becomes beta_r = ROL(beta, r s), so a fixed-beta core no
      longer iterates.  The core FAMILY follows the rotation: alpha_r = M(2^(j_r - s)),
      beta_r = alpha_r ^ 2^(j_r), j_r = j_0 + r s, gamma = 0 maps round r to round r+1.
      But LM validity at bit j_r needs bit j_r - 1 inside alpha_r's 3-bit block
      {j_r - s - 1, j_r - s, j_r - s + 1}, so it exists only for s in {0, 1, 2}:
      checked for every s and every j.  At s = 1 it costs 3 bits per round (2 at two
      positions), 190 over 64 rounds; for s = 3 .. 255 it is invalid at every j.

  §4  WHAT THE ROTATING SCHEDULE LEAVES.  An exhaustive class search under s = 3
      ("every round costs <= 3"), over every beta that is a run of <= 4 bits, its
      complement, or two bits at any distance, at every rotation: no 64-round
      characteristic in the class exists at all, while the same search under a fixed
      key finds both 128-bit cores.  That is a sampled family, NOT a floor: Lemma 1
      still holds round by round, so the proven floor stays 2 bits per round, and the
      residual argument (Lemma 2, now on beta ^ ROL(beta, s - n/4)) is not redone.

  §5  WHAT IT MEANS FOR THE FIX (prose).  §6  THE DOCUMENTS.  §7  VERDICT.

Pure Python, deterministic.  About 5 min with --quick (every 32nd rotation in §4), 20
min without (every rotation), on an aarch64 SBC.
Exits non-zero if a finding stops reproducing.

Run:  python3 SecurityProofsCode/v1_core_break.py [--quick]
"""

import importlib.util
import itertools
import math
import os
import random
import re
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
QUICK = "--quick" in sys.argv
STEP = 32 if QUICK else 1
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


def _floor():
    spec = importlib.util.spec_from_file_location("_v1_floor",
                                                  os.path.join(HERE, "v1_mode_floor.py"))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


FL = _floor()
W, lm, p_fixed = FL.W, FL.lm, FL.p_fixed
w = W(256)
N, K, MASK = w.n, w.k, w.m
CORES = (((1 << 254) | 1, w.M(1 << 255)), ((1 << 255) | (1 << 253), w.M(1 << 254)))


def edges2(beta, beta2, Dc):
    """v1_mode_floor.edges with the key difference changing from beta (round r) to
    beta2 (round r+1): every round (alpha_r -> alpha_(r+1), weight) of weight <= Dc and
    |low bits of alpha_(r+1) ^ beta2| <= Dc.  The covered residual is
    ROL(beta, n/4) ^ beta2 = M(delta_r) ^ ROL(u_r, n/4) ^ delta_(r+1)."""
    n, k, msb = N, K, N - 1
    Mb, Rb = w.Mb, w.Rb
    c = w.rol(beta, k) ^ beta2
    out = {}
    for dm, um, em in itertools.product((0, 1), repeat=3):
        R0 = c ^ (Mb[msb] if dm else 0) ^ (Rb[msb] if um else 0) ^ (em << msb)

        def rec(R, d1, u1, nr, d2, ne):
            if R == 0:
                a1 = beta ^ d1 ^ (dm << msb)
                t = lm(w, a1, beta, beta ^ u1 ^ (um << msb))
                if t is not None and t <= Dc:
                    key = (a1, beta2 ^ d2 ^ (em << msb))
                    if out.get(key, 99) > t:
                        out[key] = t
                return
            p = (R & -R).bit_length() - 1
            if nr < Dc:
                for j in ((p - 1) % n, p, (p + 1) % n):
                    if j == msb or (d1 | u1) >> j & 1:
                        continue
                    rec(R ^ Mb[j], d1 | 1 << j, u1, nr + 1, d2, ne)
                    rec(R ^ Mb[j] ^ Rb[j], d1 | 1 << j, u1 | 1 << j, nr + 1, d2, ne)
                j = (p - k) % n
                if j != msb and not (d1 | u1) >> j & 1:
                    rec(R ^ Rb[j], d1, u1 | 1 << j, nr + 1, d2, ne)
                    rec(R ^ Rb[j] ^ Mb[j], d1 | 1 << j, u1 | 1 << j, nr + 1, d2, ne)
            if ne < Dc and p != msb and not d2 >> p & 1:
                rec(R ^ (1 << p), d1, u1, nr, d2 | 1 << p, ne + 1)
        rec(R0, 0, 0, 0, 0, 0)
    return out


def least(beta, s, Dc, R=64):
    """(least R-round walk with key difference ROL(beta, r s) in round r, every round
    <= Dc, or None; the number of rounds the class survived)."""
    d = None
    for r in range(R):
        E = edges2(w.rol(beta, r * s), w.rol(beta, (r + 1) * s), Dc)
        nd = {}
        for (a, a2), t in E.items():
            if d is None:
                da = 0
            elif a in d:
                da = d[a]
            else:
                continue
            if da + t < nd.get(a2, 1 << 30):
                nd[a2] = da + t
        d = nd
        if not d:
            return None, r
    return min(d.values()), R


def family(rot):
    """The sampled betas at one rotation: runs of 1..4 bits and their complements, and
    two bits at every distance 1..127."""
    out = []
    for L in range(1, 5):
        b = w.rol((1 << L) - 1, rot)
        out += [b, b ^ MASK]
    out += [w.rol(1 | (1 << d), rot) for d in range(1, 128)]
    return out


def _search(rot):
    return [(b, least(b, 3, 3)) for b in family(rot)]


# ═══════════════════════════════════════════════════════════════════════════
def section_1():
    rule("§1  The instruments")
    rng, bad = random.Random(11), 0
    for b in [c[0] for c in CORES] + [1 << rng.randrange(255) for _ in range(3)]:
        bad += edges2(b, b, 3) != FL.edges(w, b, 3)
    check(bad == 0, "edges2(beta, beta) equals v1_mode_floor's fixed-beta edge set on "
          "both cores' betas and 3 random single bits (D = 3)")
    got = [least(b, 0, 3) for b, _ in CORES]
    check(got == [(128, 64), (128, 64)], "CONTROL: the layered walk under a fixed key "
          "(s = 0) finds both cores at 128 over 64 rounds: %s" % got)
    bad = 0
    for _ in range(300):
        b, s = rng.getrandbits(256), rng.randrange(256)
        a, g = rng.getrandbits(256), rng.getrandbits(256)
        b2 = w.rol(b, s)
        a2 = w.M(a ^ b) ^ w.rol(g, K)
        bad += (w.rol(b, K) ^ b2) != (w.M(a ^ b) ^ w.rol(g ^ b, K) ^ (a2 ^ b2))
    check(bad == 0, "the covering identity ROL(beta_r, n/4) ^ beta_(r+1) = M(delta_r) ^ "
          "ROL(u_r, n/4) ^ delta_(r+1) holds on 300 random rounds")


def section_2():
    rule("§2  Round constants are transparent")
    rng = random.Random(7)
    Bs = [rng.getrandbits(256) for _ in range(32)]
    ok = all(p_fixed(256, B, a, b, 0) == FL.Fraction(1, 4) for B in Bs for b, a in CORES)
    check(ok, "both cores hold with probability exactly 1/4 for each of 32 random B "
          "(carry automaton), so also for every B ^ RC_r")

    def rnd(A, B, c, kind):
        if kind == "B ^ RC":
            B ^= c
        elif kind == "A ^ RC":
            A ^= c
        elif kind == "A + B + c":
            return w.M(A ^ B) ^ w.rol((A + B + c) & MASK, K)
        return w.M(A ^ B) ^ w.rol((A + B) & MASK, K)
    T = 20000 if QUICK else 100000
    for kind in ("B ^ RC", "A ^ RC", "A + B + c"):
        res = []
        for b, a in CORES:
            surv = [0] * 6
            for _ in range(T):
                RC = [rng.getrandbits(256) for _ in range(6)]
                B, A = rng.getrandbits(256), rng.getrandbits(256)
                x, y = A, A ^ a
                for r in range(1, 6):
                    x, y = rnd(x, B, RC[r], kind), rnd(y, B ^ b, RC[r], kind)
                    if x ^ y != a:
                        break
                    surv[r] += 1
            res.append(all(abs(surv[r] - T / 4 ** r) < 5 * math.sqrt(T / 4 ** r)
                           for r in range(1, 6)))
            last = surv[1:]
        check(all(res), "real round with fresh random constants in %s, %d trials: both "
              "cores hold r rounds at 4^-r, r = 1..5, each within 5 sigma (core 2: %s)"
              % (kind, T, last))
    rng2, same = random.Random(8), 0
    for _ in range(2000):
        A, B, c = rng2.getrandbits(256), rng2.getrandbits(256), rng2.getrandbits(256)
        A2 = A ^ CORES[1][1] if rng2.getrandbits(1) else rng2.getrandbits(256)
        B2 = B ^ CORES[1][0]
        same += (((A + B) & MASK) == ((A2 + B2) & MASK)) == \
            (((A + B + c) & MASK) == ((A2 + B2 + c) & MASK))
    check(same == 2000, "A + B = A' + B' exactly when A + B + c = A' + B' + c (2000 "
          "random pairs): the core's event does not see c")
    print("""
  The linear bound (§11.70) needs nothing new: a trail's masks are on A, the B-side
  mask only fixes a key-dependent sign, and a constant only flips signs.  The same
  holds for the rotating schedule below.""")


def section_3():
    rule("§3  A rotating key schedule B_r = ROL(B, r s)")
    valid = {}
    for s in range(N):
        valid[s] = {}
        for j in range(N):
            a = w.M(1 << ((j - s) % N))
            t = lm(w, a, a ^ (1 << j), 0)
            if t is not None:
                valid[s][j] = t
    big = [s for s in range(3, N) if valid[s]]
    check(not big, "the rotating core family (alpha_r = M(2^(j-s)), beta_r = alpha_r ^ "
          "2^j, gamma = 0) is invalid at every j for every s in 3..255 (%d exceptions)"
          % len(big))
    c = {s: sorted(set(valid[s].values())) for s in (0, 1, 2)}
    two = {s: [j for j, t in valid[s].items() if t == 2] for s in (0, 1, 2)}
    check(all(len(valid[s]) == 255 for s in (0, 1, 2)) and c == {0: [2, 3], 1: [2, 3],
          2: [3, 4]} and two == {0: [254, 255], 1: [1, 255], 2: []},
          "for s = 0, 1, 2 it is valid at every j but j = 0, costing %s per round; 2 bits "
          "only at j = %s" % (c, two))
    j0 = 192
    b0 = w.M(1 << (j0 - 1)) ^ (1 << j0)
    got = least(b0, 1, 3)
    check(got == (190, 64), "at s = 1 the rotating core from j_0 = 192 costs %s over 64 "
          "rounds in the class 'every round <= 3': 1.48x the collision bar" % (got,))
    dead = [least(b, 3, 3) for b, _ in CORES]
    check(all(x[0] is None and x[1] <= 2 for x in dead), "at s = 3 neither core's beta "
          "has a characteristic in the class past round %d"
          % max(x[1] for x in dead))
    rng, zero = random.Random(9), True
    for b, a in CORES:
        b1 = w.rol(b, 3)
        g = w.rol(a ^ w.M(a ^ b1), N - K)
        zero &= lm(w, a, b1, g) is None and \
            all(p_fixed(256, rng.getrandbits(256), a, b1, g) == 0 for _ in range(16))
    check(zero, "exactly: once the key difference has rotated by 3, the round maps "
          "neither core's alpha back to itself, with probability 0 for each of 16 random "
          "B (carry automaton), and LM-impossible")
    T, surv = 20000 if QUICK else 100000, [0, 0]
    b, a = CORES[1]
    for _ in range(T):
        B, A = rng.getrandbits(256), rng.getrandbits(256)
        x, y = A, A ^ a
        for r in range(2):
            x = w.F(x, w.rol(B, 3 * r))
            y = w.F(y, w.rol(B ^ b, 3 * r))
            if x ^ y != a:
                break
            surv[r] += 1
    check(abs(surv[0] - T / 4) < 5 * math.sqrt(T / 4) and surv[1] == 0,
          "on the real round with B_r = ROL(B, 3r), core 2 holds round 0 at 1/4 and never "
          "holds round 1 (%d trials: %s)" % (T, surv))


def section_4():
    rule("§4  What the rotating schedule (s = 3) leaves: a sampled class search")
    t0, rots = time.time(), list(range(0, N, STEP))
    if QUICK:
        res = [x for r in rots for x in _search(r)]
    else:
        from multiprocessing import Pool
        with Pool(max(1, (os.cpu_count() or 2) - 1)) as p:
            res = [x for o in p.map(_search, rots) for x in o]
    alive = [(v[0], hex(b)) for b, v in res if v[0] is not None]
    hist = {}
    for _, v in res:
        hist[v[1]] = hist.get(v[1], 0) + 1
    print("  (%d betas at %d rotations, %.0f s; rounds survived: %s)"
          % (len(res), len(rots), time.time() - t0, sorted(hist.items())))
    check(not alive and len(res) == 135 * len(rots), "no beta in the family (runs of "
          "1..4 bits, their complements, two bits at every distance; %s) has a 64-round "
          "characteristic whose rounds each cost <= 3 under s = 3: %s"
          % ("every %dnd rotation" % STEP if QUICK else "every rotation", alive[:3]))
    check(max(hist) <= 2, "every one of them leaves the class by round %d" % max(hist))


def section_5():
    rule("§5  What it means for the fix")
    print("""
  Constants (B ^ RC_r, A ^ RC_r, or inside the addition) do nothing: both cores keep
  their exact 1/4.  A rotating schedule with s >= 3 breaks both cores and the family
  they belong to, and nothing in the sampled family survives the class.  But Lemma 1
  is per round, so the PROVEN floor stays 2 bits per round, and nothing above it is
  proven until the residual argument is redone for beta_r = ROL(beta, r s) (Lemma 2's
  covered term becomes beta ^ ROL(beta, s - n/4); s = n/4 makes it vacuous).
      fix                         proven floor, 64 rounds     status
      more rounds (192)           384 (3.0x the bar)          sized (§11.70)
      v3 round                    1.678 per round (§11.52)    sized
      round constants             128                         ruled out
      rotating B, s >= 3          128 (Lemma 1)               cores broken; unproven
  A rotating schedule can be ADDED to more rounds without losing anything, but it does
  not replace them.""")


def section_6():
    rule("§6  The documents")
    todo = open(os.path.join(ROOT, "TODO.md")).read()
    done = open(os.path.join(ROOT, "TODO_DONE.md")).read()
    m = (re.search(r"### #347:.*?(?=^### |\Z)", todo, re.S | re.M) or
         re.search(r"### #347:.*?(?=^### |\Z)", done, re.S | re.M))
    body = m.group(0) if m else ""

    def ok(b):
        return "Second pass (v9.5.69)" in b and "v1_core_break.py" in b
    check(ok(body) and ("Status: **OPEN**" in body or "Status: **DONE v10.0.0**" in body),
          "TODO #347 records the second pass (OPEN for the choice, or closed by v10.0.0)")
    check(not ok(body.replace("Second pass", "Later pass")),
          "CONTROL: the check FIRES on an entry without the second pass")


def section_7():
    rule("§7  Verdict")
    print("""**Round constants cannot break v1's cores; a rotating key schedule can, but adds no
proven margin.  More rounds remain the only fix sized by a proof.**

  CONSTANTS.  Both cores hold with probability exactly 1/4 for every B and have a
  zero addition output difference, so a constant XORed into B or A, or added inside
  the addition, leaves them exactly where they are.  Checked on the real round.

  ROTATION.  B_r = ROL(B, r s) breaks both cores and, for s >= 3, the whole alpha ^
  beta = 2^j family.  At s = 1 the family rotates along at 3 bits per round (190).
  Under s = 3 no beta in a 135-member family per rotation keeps a characteristic of
  rounds <= 3 bits.  The proven floor is still Lemma 1's 2 bits per round.

  NOT DONE.  Lemma 2 and the residual search for the rotating schedule; any exact
  probability; the choice itself, which is a MAJOR version.""")


def main():
    print(__doc__.split("Run:")[0].rstrip())
    print("\n  mode: %s (§4 every %d rotation%s)"
          % ("--quick" if QUICK else "full", STEP, "s" if STEP > 1 else ""))
    section_1()
    section_2()
    section_3()
    section_4()
    section_5()
    section_6()
    section_7()
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
