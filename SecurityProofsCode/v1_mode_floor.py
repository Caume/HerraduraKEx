#!/usr/bin/env python3
"""v1_mode_floor.py — TODO #347, first pass: the floor under NL-FSCX v1's 2-bit cores,
before a fix is chosen.

TODO #346 (v1_mode_criterion.py) found an iterative differential at exactly 1/4 per
round and left three questions open: is anything cheaper, what does v1's linear axis
cost, and what does a real hash collision through the core cost.  This script answers
each, at n = 256, the deployed width.

The round is F_B(A) = M(A ^ B) ^ ROL(A + B, n/4), B fixed across the n/4 = 64 rounds.
A characteristic is a path over the state difference alpha under a FIXED message / key
difference beta.  Its weight is the key-averaged Lipmaa-Moriai weight; #346 §3 showed
that weight is not the exact probability for v1, so every bound below is IN THAT
MODEL, and the cheapest characteristics are checked exactly on the real round.

  §1  THE INSTRUMENTS, pinned: the integer round against the shipped nl_fscx_v1; the
      LM weight and the least-weight DP against brute force at n = 8; Wallen's linear
      weight and its input-mask enumerator against brute force at n = 4.

  §2  LEMMA 1 (transitions).  Let S be the positions i <= n-2 where alpha, beta and
      gamma are not all equal (|S| is the round's weight) and tr(beta) the positions
      where beta changes value (bit 0 counts if beta_0 = 1).  LM validity forces
      tr(beta) to lie inside S u (S+1).  So a round costs >= ceil(|tr(beta)|/2), and it
      costs <= 1 only if tr(beta) lies in {s, s+1} for one s.  Every characteristic
      under a beta outside that family B1 costs >= 2 bits in EVERY round.

  §3  LEMMA 2 (consecutive rounds).  With delta = alpha ^ beta and u = gamma ^ beta,
      both supported on S u {n-1}, two consecutive rounds satisfy
          c(beta) = beta ^ ROL(beta, n/4) = M(delta_r) ^ ROL(u_r, n/4) ^ delta_(r+1),
      so 4 w_r + w_(r+1) + 5 >= wt(c(beta)).  With wt(c) >= 16 a 64-round
      characteristic costs >= 139.  What survives both lemmas is a RESIDUAL family of
      538 betas (single bits, short runs at the top, and four special values).

  §4  THE RESIDUAL, searched exhaustively in a class.  "Every round costs <= D" is
      enumerable exactly: Lemma 1/2's structure turns a round into a covering of
      c(beta) by sparse terms, so the edges of the class graph are found completely.
      Over all 538 betas at D = 4 (D = 3 under --quick): NO cycle averages below 2
      bits per round, and the least 64-round characteristic is 128 -- a SECOND 2-bit
      core, beta = 2^255 + 2^253, alpha = M(2^254), exact 1/4 for every B.  The two
      cores are the alpha ^ beta = 2^j, gamma = 0 family at the two places where
      the MSB's free carry makes it cost 2 rather than 3.

  §5  HFSCX-256: A REAL COLLISION (Delta h = 0).  Outside the residual every round
      costs >= 2, so a one-block collision at exactly 128 needs every round to cost
      exactly 2 and |low bits of beta| <= 2.  All 64 768 such betas are searched: no
      all-2 walk 0 -> 0 exists.  So every one-block collision characteristic costs
      >= 129 outside the residual, and none exists in the residual's class.  It is
      still at the bar: one bit is not a margin.  CONTROL: the same walk finder finds
      the 128-bit semi-free-start alpha -> alpha.

  §6  HSKE-NL-A1: ENTRY FROM THE NONCE.  The seed difference is ROL(beta, n/8).
      Outside the residual the floor is 128 (>= 2 per round), 2x the 2^64-block bar;
      in the residual's class no 64-round characteristic leaves ROL(beta, n/8) at all.

  §7  THE LINEAR AXIS.  For linear trails the composition is exact (correlation
      matrices compose for any maps), so a trail's correlation is the product of its
      rounds' Wallen correlations; only the hull sum is unknown.  Wallen's carry mask z
      forces the addition's output mask lambda and input mask mu into Z u (Z+1) u {0}
      (Lemma L1), and consecutive rounds satisfy
          T(lambda_r) = M(ROL(lambda_r, n/4)) ^ lambda_r = ROL(lambda_(r-1), n/4) ^ a_r,
      a_r inside Z_r.  T's branch number is 5 (its kernel is {0, 0x55.., 0xaa.., ~0},
      weight >= 128), so 3 w_r + 2 w_(r-1) >= 3, so no round after the first costs 0
      unless the one before costs >= 2: every 64-round linear trail weighs >= 63
      (squared correlation <= 2^-126).  Least found from single-bit masks: 3 bits over
      2 rounds and 6 over 3.

  §8  WHAT IT MEANS FOR THE FIX (prose).  §9  THE DOCUMENTS.  §10  VERDICT.

Pure Python, deterministic.  About 5 min with --quick (D = 3), 15 min without (D = 4), on an aarch64 SBC.
Exits non-zero if a finding stops reproducing.

Run:  python3 SecurityProofsCode/v1_mode_floor.py [--quick]
"""

import importlib.util
import itertools
import math
import os
import random
import re
import sys
import time
from fractions import Fraction

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
FAIL = []
QUICK = "--quick" in sys.argv
D = 3 if QUICK else 4


def rule(t):
    print("\n" + "=" * 78)
    print(t)
    print("=" * 78)


def check(cond, what):
    print("  [%s] %s" % ("PASS" if cond else "FAIL", what))
    if not cond:
        FAIL.append(what)
    return cond


def _suite():
    p = os.path.join(ROOT, "Herradura cryptographic suite.py")
    spec = importlib.util.spec_from_file_location("_suite", p)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


H = _suite()


class W:
    """The v1 round at width n, as integers."""
    def __init__(self, n):
        self.n, self.m, self.k = n, (1 << n) - 1, n // 4
        self.Mb = [self.M(1 << j) for j in range(n)]
        self.Rb = [self.rol(1 << j, self.k) for j in range(n)]

    def rol(self, x, s):
        s %= self.n
        return ((x << s) | (x >> (self.n - s))) & self.m if s else x

    def M(self, x):
        return (x ^ self.rol(x, 1) ^ self.rol(x, self.n - 1)) & self.m

    def F(self, A, B):
        return self.M(A ^ B) ^ self.rol((A + B) & self.m, self.k)


def wt(x):
    return bin(x).count("1")


# ── the differential instruments ────────────────────────────────────────────
def lm(w, a, b, g):
    """Lipmaa-Moriai weight of (a, b -> g), or None if the transition is impossible."""
    m = w.m
    sa, sb, sg = (a << 1) & m, (b << 1) & m, (g << 1) & m
    if ~(sa ^ sb) & ~(sa ^ sg) & m & (a ^ b ^ g ^ sb):
        return None
    return wt(~(~(a ^ b) & ~(a ^ g) & m) & (m >> 1))


def minw(w, a, b):
    """(least LM weight over gamma, a gamma attaining it): a two-state DP over the bits."""
    n, st, bp = w.n, {True: (0, 0)}, 0
    for i in range(n):
        ai, bi = (a >> i) & 1, (b >> i) & 1
        nx = {}
        for e, (c, g) in st.items():
            for gi in ([ai ^ bi ^ bp] if e else [0, 1]):
                ne = ai == bi == gi
                cc = c + (0 if ne or i == n - 1 else 1)
                if ne not in nx or nx[ne][0] > cc:
                    nx[ne] = (cc, g | (gi << i))
        st, bp = nx, bi
    return min(st.values())


def gammas(w, a, b, wmax):
    """Every (gamma, weight) of the addition (a, b -> gamma) with LM weight <= wmax."""
    n, out, stack = w.n, [], [(1, (a ^ b) & 1, 0)]
    while stack:
        i, g, t = stack.pop()
        if i == n:
            out.append((g, t))
            continue
        p = i - 1
        if ((a >> p) & 1) == ((b >> p) & 1) == ((g >> p) & 1):
            stack.append((i + 1, g | ((((a >> i) ^ (b >> i) ^ (b >> p)) & 1) << i), t))
        else:
            t2 = t + (1 if p <= n - 2 else 0)
            if t2 <= wmax:
                stack.append((i + 1, g, t2))
                stack.append((i + 1, g | (1 << i), t2))
    return out


def tr(w, b):
    t = [0] if b & 1 else []
    return t + [i for i in range(1, w.n - 1) if ((b >> i) ^ (b >> (i - 1))) & 1]


def in_B1(w, b):
    t = tr(w, b)
    return len(t) <= 1 or (len(t) == 2 and t[1] == t[0] + 1)


def p_fixed(n, B, a, b, g):
    """Exact Pr_A[(A + B) ^ ((A ^ a) + (B ^ b)) = g], A uniform: a carry automaton."""
    st = {(0, 0): Fraction(1)}
    for i in range(n):
        ai, bi, Bi, gi = (a >> i) & 1, (b >> i) & 1, (B >> i) & 1, (g >> i) & 1
        nx = {}
        for (c1, c2), p in st.items():
            for x in (0, 1):
                y2, z2 = x ^ ai, Bi ^ bi
                if (x ^ Bi ^ c1) ^ (y2 ^ z2 ^ c2) != gi:
                    continue
                key = ((x & Bi) | (c1 & (x ^ Bi)), (y2 & z2) | (c2 & (y2 ^ z2)))
                nx[key] = nx.get(key, 0) + p / 2
        st = nx
    return sum(st.values())


def edges(w, beta, Dc):
    """Every round (alpha_r -> alpha_(r+1), weight) with weight <= Dc and
    |low bits of alpha_(r+1) ^ beta| <= Dc -- complete for the class.

    c(beta) = M(delta_r) ^ ROL(u_r) ^ delta_(r+1) is covered term by term: the lowest
    uncovered bit p of the residual must come from a round-r position j in
    {p-1, p, p+1} (through M, with u_j either way), from j = p - k (through the
    rotation), or from delta_(r+1) at p.  Every solution is reached by that branching."""
    n, k, msb = w.n, w.k, w.n - 1
    Mb, Rb = w.Mb, w.Rb
    c = beta ^ w.rol(beta, k)
    out = {}
    for dm, um, em in itertools.product((0, 1), repeat=3):
        R0 = c ^ (Mb[msb] if dm else 0) ^ (Rb[msb] if um else 0) ^ (em << msb)

        def rec(R, d1, u1, nr, d2, ne):
            if R == 0:
                a1 = beta ^ d1 ^ (dm << msb)
                t = lm(w, a1, beta, beta ^ u1 ^ (um << msb))
                if t is not None and t <= Dc:
                    key = (a1, beta ^ d2 ^ (em << msb))
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


def adjacency(E, beta):
    adj = {}
    for (a, a2), t in E.items():
        if beta == 0 and (a == 0 or a2 == 0):
            continue          # beta = 0: the zero difference is not a characteristic
        adj.setdefault(a, []).append((a2, t))
    return adj


def walk(adj, src, dst, R=64):
    """Least R-round walk in the class graph from src (every node if None) to dst
    (any node if None), or None."""
    d = {v: 0 for v in adj} if src is None else {src: 0}
    for _ in range(R):
        nd = {}
        for a, da in d.items():
            for a2, t in adj.get(a, ()):
                if da + t < nd.get(a2, 1 << 30):
                    nd[a2] = da + t
        d = nd
        if not d:
            return None
    return min(d.values()) if dst is None else d.get(dst)


def below_two(adj):
    """True if some cycle averages below 2 bits per round (Bellman-Ford on weight - 2)."""
    nodes = set(adj) | {a2 for l in adj.values() for a2, _ in l}
    pot = dict.fromkeys(nodes, 0)
    el = [(a, a2, t - 2) for a, l in adj.items() for a2, t in l]
    for _ in range(len(nodes) + 1):
        ch = False
        for a, a2, x in el:
            if pot[a] + x < pot[a2]:
                pot[a2], ch = pot[a] + x, True
        if not ch:
            return False
    return True


def residual(w):
    out = []
    for t in range(3):
        for T in itertools.combinations(range(w.n - 1), t):
            b, cur, Ts = 0, 0, set(T)
            for i in range(w.n - 1):
                cur ^= i in Ts
                b |= cur << i
            for x in (b, b | 1 << (w.n - 1)):
                if in_B1(w, x) and wt(x ^ w.rol(x, w.k)) <= 15:
                    out.append(x)
    return out


# ── the linear instruments ──────────────────────────────────────────────────
def wallen(n, u, v, x):
    """Wallen: (weight, z) of the correlation of u.(A + B) with v.A ^ x.B, or None."""
    y, z, par = u ^ v ^ x, 0, 0
    for i in range(n - 1, -1, -1):
        z |= par << i
        par ^= (y >> i) & 1
    if (u ^ v) & ~z or (u ^ x) & ~z:
        return None
    return wt(z), z


def mus(n, u, wmax):
    """{input mask v on A: least Wallen weight over the B-mask} for output mask u, weight
    <= wmax.  Top-down: where z_i = 0 the masks equal u_i; where z_i = 1 they are free."""
    out, st = {}, [(n - 1, 0, 0, 0)]
    while st:
        i, z, v, c = st.pop()
        if i < 0:
            if out.get(v, 99) > c:
                out[v] = c
            continue
        ui = (u >> i) & 1
        if z == 0:
            st.append((i - 1, ui, v | ui << i, c))
        elif c + 1 <= wmax:
            for vi, xi in itertools.product((0, 1), repeat=2):
                st.append((i - 1, 1 ^ ui ^ vi ^ xi, v | vi << i, c + 1))
    return out


# ═══════════════════════════════════════════════════════════════════════════
def section_1():
    rule("§1  The instruments, pinned")
    rng = random.Random(1)
    for n in (16, 256):
        w = W(n)
        ok = sum(w.F(A, B) == H.nl_fscx_v1(H.BitArray(n, A), H.BitArray(n, B)).uint
                 for A, B in ((rng.getrandbits(n), rng.getrandbits(n)) for _ in range(200)))
        check(ok == 200, "n = %d: the integer round agrees with nl_fscx_v1 on %d/200" % (n, ok))
    w, bad = W(8), 0
    for _ in range(120):
        a, b = rng.randrange(256), rng.randrange(256)
        cnt = [0] * 256
        for x in range(256):
            for y in range(256):
                cnt[((x + y) & 255) ^ (((x ^ a) + (y ^ b)) & 255)] += 1
        ws = [lm(w, a, b, g) for g in range(256)]
        bad += any((cnt[g] == 0) != (ws[g] is None)
                   or (ws[g] is not None and cnt[g] << ws[g] != 65536) for g in range(256))
        mw, g = minw(w, a, b)
        bad += mw != min(x for x in ws if x is not None) or lm(w, a, b, g) != mw
        bad += sorted(gammas(w, a, b, 7)) != sorted((g, x) for g, x in enumerate(ws)
                                                    if x is not None and x <= 7)
    check(bad == 0, "n = 8, 120 random (a, b), brute force over all inputs: the LM weight, "
          "the least-weight DP and the gamma enumerator are exact (%d mismatches)" % bad)
    n, N, bad, tot = 4, 16, 0, 0
    for u in range(N):
        mv = mus(n, u, n)
        for v in range(N):
            best = None
            for x in range(N):
                s = sum((-1) ** (wt(((p + q) % N) & u) + wt(p & v) + wt(q & x))
                        for p in range(N) for q in range(N))
                r = wallen(n, u, v, x)
                tot += 1
                bad += (s == 0) != (r is None) or (r is not None and abs(s) != (N * N) >> r[0])
                if r and (best is None or r[0] < best):
                    best = r[0]
                if r:      # Lemma L1: u and v live on Z u (Z+1) u {0}
                    Z = r[1] | (r[1] << 1) | 1
                    bad += bool((u | v) & ~Z & (N - 1))
            bad += best != mv.get(v)
    check(bad == 0, "n = 4, exhaustive over %d mask triples: Wallen's weight, the input-mask "
          "enumerator and Lemma L1's support are exact (%d mismatches)" % (tot, bad))


def section_2():
    rule("§2  Lemma 1: tr(beta) lies in S u (S+1), so a round costs >= ceil(|tr|/2)")
    print("""
  LM validity says: where alpha, beta, gamma agree at bit i-1 (and always at bit 0),
  alpha_i ^ beta_i ^ gamma_i = beta_(i-1).  Outside S u {n-1} all three agree, so
  beta_i = beta_(i-1) there: beta can change value only at a position in S or just
  above one.  One position of S covers at most two transitions.""")
    rng, bad, tot = random.Random(2), 0, 0
    for n, trials in ((8, 4000), (256, 300)):
        w = W(n)
        for _ in range(trials):
            b = rng.getrandbits(n)
            if n == 256:      # sparse transitions, so the low-weight rounds exist
                b = 0
                for j in rng.sample(range(n - 1), rng.randrange(0, 6)):
                    b ^= (1 << j) - 1
                b ^= rng.getrandbits(1) << (n - 1)
            a = b ^ sum(1 << j for j in rng.sample(range(n), rng.randrange(0, 4))) \
                if n == 256 else rng.getrandbits(n)
            m0 = minw(w, a, b)[0]
            for g, t in gammas(w, a, b, m0 + 2):
                S = {i for i in range(n - 1) if not ((a >> i) & 1) == ((b >> i) & 1)
                     == ((g >> i) & 1)}
                tot += 1
                bad += not set(tr(w, b)) <= S | {s + 1 for s in S}
                bad += t != len(S)
    check(bad == 0 and tot > 10000, "n = 8 and 256: tr(beta) is inside S u (S+1) on all %d "
          "valid transitions sampled (%d violations)" % (tot, bad))
    w = W(256)
    B1 = sum(1 for t in range(3) for T in itertools.combinations(range(255), t)
             if len(T) <= 1 or T[1] == T[0] + 1) * 2
    check(B1 == 2 * (1 + 255 + 254), "the betas that admit a round of weight <= 1 (B1: "
          "tr(beta) inside {s, s+1}) number %d; every other beta costs >= 2 per round" % B1)


def section_3():
    rule("§3  Lemma 2: 4 w_r + w_(r+1) + 5 >= wt(beta ^ ROL(beta, n/4))")
    print("""
  delta_r = alpha_r ^ beta and u_r = gamma_r ^ beta vanish outside S_r u {n-1}, and
  alpha_(r+1) = M(delta_r) ^ ROL(beta ^ u_r, n/4).  So c(beta) = beta ^ ROL(beta, n/4)
  = M(delta_r) ^ ROL(u_r, n/4) ^ delta_(r+1): at most 3(w_r + 1) + (w_r + 1) +
  (w_(r+1) + 1) bits.  Summed over a 64-round characteristic with wt(c) >= 16,
  5 * total >= 11 * 63 + 4 w_64 + w_1, so total >= 139.""")
    w, rng, bad, tot = W(256), random.Random(3), 0, 0
    for _ in range(400):
        b = 0
        for j in rng.sample(range(255), rng.randrange(1, 5)):
            b ^= (1 << j) - 1
        a = b ^ sum(1 << j for j in rng.sample(range(256), rng.randrange(0, 4)))
        for g, t in gammas(w, a, b, minw(w, a, b)[0] + 1)[:20]:
            a2 = w.M(a ^ b) ^ w.rol(g, w.k)
            t2 = minw(w, a2, b)[0]
            tot += 1
            bad += 4 * t + t2 + 5 < wt(b ^ w.rol(b, w.k))
            d, u = a ^ b, g ^ b
            bad += (b ^ w.rol(b, w.k)) != (w.M(d) ^ w.rol(u, w.k) ^ (a2 ^ b))
    check(bad == 0 and tot > 1000, "n = 256: the identity and the inequality hold on all %d "
          "sampled two-round characteristics" % tot)
    R = residual(w)
    kinds = {"single": 0, "top": 0, "other": 0}
    for b in R:
        lo = b & (w.m >> 1)
        kinds["single" if lo and lo & (lo - 1) == 0 else
              "top" if lo and (lo | (lo - 1)) == w.m >> 1 and lo != w.m >> 1 else "other"] += 1
    check(len(R) == 538 and kinds == {"single": 510, "top": 24, "other": 4},
          "the residual (B1 and wt(c) <= 15) is %d betas: %d single bits, %d short runs at "
          "the top (each with or without the MSB), and %d others: 0, the MSB, ~MSB and ~0"
          % (len(R), kinds["single"], kinds["top"], kinds["other"]))
    return R


def section_4(R):
    rule("§4  The residual, exhaustive in the class 'every round costs <= %d'" % D)
    w, t0 = W(256), time.time()
    sub2, least, info = [], None, {}
    for b in R:
        adj = adjacency(edges(w, b, D), b)
        if below_two(adj):
            sub2.append(b)
        l64 = walk(adj, None, None)
        if l64 is not None and (least is None or l64 < least[0]):
            least = (l64, b)
        info[b] = adj
    print("  (%d betas, %.0f s)" % (len(R), time.time() - t0))
    check(not sub2, "no characteristic in the class averages below 2 bits per round, for "
          "any of the %d residual betas (cycles of mean < 2: %d)" % (len(R), len(sub2)))
    b2 = (1 << 255) | (1 << 253)
    check(least == (128, b2), "the least 64-round characteristic in the class is 128 bits, "
          "under beta = 2^255 + 2^253: %s" % (least and (least[0], hex(least[1])),))
    a2 = w.M(1 << 254)
    check(a2 == 7 << 253 and w.M(a2 ^ b2) == a2 and lm(w, a2, b2, 0) == 2,
          "the second core: alpha = M(2^254) = 2^255 + 2^254 + 2^253, alpha ^ beta = 2^254, "
          "addition (alpha, beta -> 0) of weight 2")
    rng = random.Random(4)
    ps = {p_fixed(256, rng.getrandbits(256), a2, b2, 0) for _ in range(64)}
    check(ps == {Fraction(1, 4)}, "it holds with probability EXACTLY 1/4 for each of 64 "
          "random B at n = 256 (carry automaton): %s" % ps)
    T, surv = 100000, [0] * 6
    for _ in range(T):
        B, A = rng.getrandbits(256), rng.getrandbits(256)
        x, y = A, A ^ a2
        for r in range(1, 6):
            x, y = w.F(x, B), w.F(y, B ^ b2)
            if x ^ y != a2:
                break
            surv[r] += 1
    check(all(abs(surv[r] - T / 4 ** r) < 5 * math.sqrt(T / 4 ** r) for r in range(1, 6)),
          "on the real round, B fixed: it holds r rounds with probability 4^-r, r = 1..5 "
          "(each within 5 sigma): %s" % surv[1:])
    print("""
  Why exactly two.  alpha ^ beta = 2^j makes the linear part return M(2^j), so
  alpha = M(2^j) iterates with gamma = 0.  The addition then costs one bit for each
  of j-1, j, j+1 that is not the MSB, and is valid only if j != 0: 3 bits in general,
  2 at j = n-1 (TODO #346's core) and at j = n-2 (this one).""")
    return info


def section_5(R, info):
    rule("§5  HFSCX-256: what a real one-block collision costs (Delta h = 0)")
    w, t0 = W(256), time.time()
    cand = []
    for r in (1, 2):
        for Sx in itertools.combinations(range(255), r):
            b = sum(1 << j for j in Sx)
            cand += [x for x in (b, b | 1 << 255) if not in_B1(w, x)]
    hit = [b for b in cand if walk(adjacency(edges(w, b, 2), b), 0, 0) is not None]
    print("  (%d betas, %.0f s)" % (len(cand), time.time() - t0))
    print("""
  Outside B1 every round costs >= 2 (Lemma 1), so 128 over 64 rounds needs every round
  to cost exactly 2.  The first round starts at alpha = 0, so delta = beta and beta can
  have at most 2 bits below the MSB.  B1 betas outside the residual cost >= 139
  (Lemma 2).""")
    check(len(cand) == 64768 and not hit, "none of the %d betas outside B1 with <= 2 low bits "
          "has an all-2-bit 64-round walk 0 -> 0, so every one-block collision "
          "characteristic outside the residual costs >= 129" % len(cand))
    rc = [b for b in R if b and walk(info[b], 0, 0) is not None]
    check(not rc, "the residual: no one-block collision characteristic in the class "
          "'every round <= %d' (%d betas with one)" % (D, len(rc)))
    core = (1 << 254) | 1
    ac = (1 << 255) | (1 << 254) | 1
    adj = adjacency(edges(w, core, 2), core)
    check(walk(adj, ac, ac) == 128, "CONTROL: the same walk finder finds the 128-bit "
          "semi-free-start alpha -> alpha of TODO #346's core")


def section_6(R, info):
    rule("§6  HSKE-NL-A1: entry from the nonce difference ROL(beta, n/8)")
    w = W(256)
    ent = [b for b in R if b and walk(info[b], w.rol(b, 32), None) is not None]
    check(not ent, "the residual: no 64-round characteristic in the class 'every round <= "
          "%d' starts from the nonce difference (%d betas with one)" % (D, len(ent)))
    print("""
  Outside the residual the floor is 2 bits per round from any start, so 128 over 64
  rounds: 2x the 2^64-block data limit, now a bound in the weight model rather than
  the least a search saw.  Inside it, the class has no entry at all.""")


def section_7():
    rule("§7  The linear axis")
    w, n, k = W(256), 256, 64

    def T(x):
        return w.M(w.rol(x, k)) ^ x
    piv, ker = {}, []
    for j in range(n):
        v, p = T(1 << j), 1 << j
        while v:
            h = v.bit_length() - 1
            if h not in piv:
                piv[h] = (v, p)
                break
            v, p = v ^ piv[h][0], p ^ piv[h][1]
        if not v:
            ker.append(p)
    kw = sorted(wt(x) for x in ker)
    check(len(ker) == 2 and kw == [128, 128], "T = M o ROL^(n/4) + I has a 2-dimensional "
          "kernel {0, 0x55.., 0xaa.., ~0}: weights >= 128")
    b2 = min(1 + wt(T(1)), min(2 + wt(T(1 | 1 << j)) for j in range(1, n)))
    b3 = min(3 + wt(T(1 | 1 << i | 1 << j)) for i in range(1, n) for j in range(i + 1, n))
    check(b2 == 5 and b3 >= 5, "T's branch number is 5: weight <= 2 gives %d, weight 3 "
          "gives %d, weight 4 cannot reach the kernel (T commutes with rotation)" % (b2, b3))
    print("""
  Lemma L1: wt(lambda_r), wt(mu_r) <= 2 w_r + 1 and a_r = lambda_r ^ mu_r lies in Z_r.
  The A-mask entering round r is M(ROL(lambda_r, k)) ^ mu_r and equals ROL(lambda_(r-1),
  k), so T(lambda_r) = ROL(lambda_(r-1), k) ^ a_r and, lambda_r != 0,
      (2 w_r + 1) + (2 w_(r-1) + 1 + w_r) >= 5,  i.e.  3 w_r + 2 w_(r-1) >= 3.
  A round costing 0 needs the round before it to cost >= 2, and two zeros never touch,
  so R rounds cost >= R - 1.""")
    rng, bad, tot = random.Random(7), 0, 0
    for _ in range(300):
        G = sum(1 << j for j in rng.sample(range(n), rng.randrange(1, 4)))
        lam = w.rol(G, n - k)
        for v, c in sorted(mus(n, lam, 6).items(), key=lambda x: x[1])[:8]:
            G2 = w.M(G) ^ v
            if not G2:
                continue
            lam2 = w.rol(G2, n - k)
            tot += 1
            if c == 0:      # the only case the inequality constrains: the round before >= 2
                bad += bool(mus(n, lam2, 1))
            bad += T(lam) != (w.rol(lam2, k) ^ lam ^ v)
    check(bad == 0 and tot > 500, "n = 256: the identity holds, and a zero-cost round is never preceded by "
          "one costing <= 1, on all %d sampled two-round linear trails" % tot)
    best, R = [10], 3

    def dfs(G, r, t):
        if t >= best[0]:
            return
        if r == R:
            best[0] = t
            return
        for v, c in mus(n, w.rol(G, n - k), best[0] - 1 - t).items():
            if w.M(G) ^ v:
                dfs(w.M(G) ^ v, r + 1, t + c)
    for j in range(n):
        dfs(1 << j, 0, 0)
    check(best[0] == 6, "least found: a 3-round linear trail from a single-bit output mask "
          "costs %d bits (the floor says >= 2)" % best[0])
    print("  64 rounds: every linear trail weighs >= 63, squared correlation <= 2^-126 --\n"
          "  far past the 2^64-block limit; the full-codebook bar (128) is not reached by it.")


def section_8():
    rule("§8  What it means for the fix")
    print("""
  In the weight model v1 now has a floor of 2 bits per round that is PROVEN outside a
  538-member residual and exhaustive inside it for rounds of <= %d bits, and the two
  cores meet it exactly.  So the round count is the lever, and it can be sized:
      rounds    differential (2/round)   collision bar 128   A1 full codebook 256
        64              128                   1.00x                 0.50x
       128              256                   2.00x                 1.00x
       192 (3n/4)       384                   3.00x                 1.50x
  Linear trails cost >= R - 1 at R rounds.  The v3 round would replace this argument
  with §11.52's, and a round constant would need it redone.""" % D)


def section_9():
    rule("§9  The documents")
    sec = open(os.path.join(ROOT, "SECURITY.md")).read()
    todo = open(os.path.join(ROOT, "TODO.md")).read()
    rows = {}
    for line in sec.splitlines():
        mm = re.match(r"\| \*\*(.+?)\*\*", line)
        if mm:
            rows.setdefault(mm.group(1), line)
    a1 = rows.get("HSKE-NL-A1", "")
    hf = rows.get("HFSCX-256 / HFSCX-256-DS", "")

    def a1_ok(row):
        return "TODO #347" in row and "2^-126" in row
    check(a1_ok(a1), "SECURITY.md's HSKE-NL-A1 row cites TODO #347's differential bound "
          "and its linear floor")
    check("TODO #347" in hf and "≥ 129" in hf, "SECURITY.md's HFSCX-256 row records that a "
          "one-block collision costs >= 129 in the model: at the bar, still demo-only")
    done = open(os.path.join(ROOT, "TODO_DONE.md")).read()
    m = (re.search(r"### #347:.*?(?=^### |\Z)", todo, re.S | re.M) or
         re.search(r"### #347:.*?(?=^### |\Z)", done, re.S | re.M))
    body = m.group(0) if m else ""
    check("First pass (v9.5.68)" in body and ("Status: **OPEN**" in body or
                                              "Status: **DONE v10.0.0**" in body),
          "TODO #347 records the first pass (OPEN for the fix, or closed by v10.0.0)")
    check(not a1_ok(a1.replace("TODO #347", "TODO #346")),
          "CONTROL: the row check FIRES on a row that does not cite TODO #347")


def section_10():
    rule("§10  Verdict")
    print("""**No characteristic cheaper than 2 bits per round is known, and outside a 538-member
residual none exists in the trail-weight model.  The ratings do not move.**

  DIFFERENTIAL.  Lemma 1 makes every round cost >= 2 unless beta's transitions sit
  in one adjacent pair; Lemma 2 charges consecutive rounds for beta ^ ROL(beta, n/4).
  What both leave is 538 betas, searched exhaustively for rounds of <= %d bits: no
  cycle below 2, and a second 2-bit core (beta = 2^255 + 2^253), exact 1/4 per round.
  Both cores are the alpha ^ beta = 2^j family at j = n-1 and n-2.

  HFSCX-256.  The semi-free-start stays at exactly 128.  A real one-block collision
  costs >= 129 outside the residual and has no characteristic in its class: still at
  the bar, so the hash stays demo-only.  The finding needs an attacker-set message
  pair; its KDF / MAC / random-oracle rows are unaffected.

  HSKE-NL-A1.  Under the 2^64-block limit the differential floor is 128 (2x) as a
  bound in the model outside the residual, with no entry inside its class; every
  linear trail has squared correlation <= 2^-126.  Its conjecture now stands on a
  bound, not on a search.

  NOT DONE.  The exact probability (the model is not the cipher for v1, #346 §3),
  the linear hull, and rounds of > %d bits inside the residual.  The fix is still to
  choose: the table in §8 sizes the round count.""" % (D, D))


def main():
    print(__doc__.split("Run:")[0].rstrip())
    print("\n  mode: %s (class D = %d)" % ("--quick" if QUICK else "full", D))
    section_1()
    section_2()
    R = section_3()
    info = section_4(R)
    section_5(R, info)
    section_6(R, info)
    section_7()
    section_8()
    section_9()
    section_10()
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
