#!/usr/bin/env python3
"""lin_cycle_mean.py — TODO #254: the linear axis, measured; and the two modes.

TODO #254's first pass (`fscx_scaling_and_linear.py`, v5.0.4) left two things
open, in its own priority order:

  (1) THE TWO MODES.  §11.30.1's trail criterion is derived for a block cipher.
      It does not transfer unexamined to HSKE-NL-A1 (counter-mode PRF) or
      HFSCX-256 (Davies-Meyer), each of which runs `n/4` rounds instead of
      `3n/4`.  This is the part of #254 that reaches three production-track rows.

  (2) THE BOUND on `s_lin`, for which #254 nominated a transfer-matrix route
      after the MILP route was closed by §11.30.4.

This script settles both, and neither answer is the one the item expected.

  §1  `s_lin` IS A MINIMUM MEAN CYCLE, exactly as `s_diff` is (TODO #252
      §11.35.1), and the same machinery computes it.  A trail is a walk on the
      mask graph; its asymptotic weight per round is the least mean over the
      graph's cycles.  This supersedes the transfer-matrix route the same way
      Howard's algorithm superseded it on the differential side: the route was
      proposed to make the computation scale, and this makes it exact.

  §2  Validation.  Three methods sharing no machinery, plus the LAT itself
      checked against `fscx_scaling_and_linear.py`'s independent carry
      automaton, plus an exact structural identity for the number of nonzero
      LAT entries.

  §3  `s_lin` for NL-FSCX v2, per key, at every usable width reached.

  §4  `s_lin` for NL-FSCX v1 -- which the same machinery reaches, once the v1
      round's masks are pulled back correctly (§1.3).  #254 assumed v1 needed a
      separate treatment; it does not.

  §5  THE TWO MODES, and the answer to (1): a trail bound cannot reach either
      of them, and not because the bar is sharper.  In both modes the input the
      attacker varies is the *B* input -- the counter in A1, the message block
      in Davies-Meyer -- and B is the round CONSTANT, entering all `r` rounds at
      once.  There is no per-round propagation graph in B, so there is no trail
      and no cycle mean.  §11.30.1 is inapplicable to A1 and HFSCX-256 in either
      direction, and the `s_lin` of §3-§4 says nothing about them.  Direct
      exhaustive measurement of both modes' actual axis is reported instead.

  §6  What remains.

Exits non-zero if a finding stops reproducing.

Run:  python3 SecurityProofsCode/lin_cycle_mean.py [--quick] [--wide]
      --quick  smaller samples, n <= 11
      --wide   adds n = 13 to §3 (slow: a few minutes per key)
"""

import argparse
import importlib.util
import math
import os
import random
import sys

SEP = "=" * 74
SEP2 = "-" * 74
FAIL = []
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EPS = 1e-12

# §11.30.1's block-cipher criterion, carried by #252 §11.31.1 and #254 §11.30.
CRIT_LIN = 2.0 / 3.0


def rule(t):
    print("\n" + SEP)
    print(t)
    print(SEP)


def check(cond, what):
    if not cond:
        FAIL.append(what)
        print(f"      *** REGRESSION: {what} ***")


def _load(name, fn):
    p = os.path.join(ROOT, 'SecurityProofsCode', fn)
    spec = importlib.util.spec_from_file_location(name, p)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


# The differential pass owns the cycle-mean machinery; reusing it rather than
# reimplementing is the point -- if the two axes disagree it must be about the
# cipher, not about two copies of Howard's algorithm.
DC = _load('_dc', 'diff_cycle_mean.py')
SL = _load('_sl', 'fscx_scaling_and_linear.py')
FK = DC.FK
SINGULAR = DC.SINGULAR


# ═══════════════════════════════════════════════════════════════════════════
# The LAT of addition with a constant, and the two mask graphs
# ═══════════════════════════════════════════════════════════════════════════

def signs(n, v):
    """The +-1 vector s[y] = (-1)^(v.y), built by doubling in O(2^n)."""
    s = [1]
    for i in range(n):
        f = -1 if (v >> i) & 1 else 1
        s = s + [f * t for t in s]
    return s


def lat_row(n, d, v):
    """One row of the LAT of x -> (x+d) mod 2^n: g[w] = 2^n * C(v <- w).

    The trick that makes this affordable is that the row is a rotation, not a
    new function: (-1)^(v.(x+d)) = s[(x+d) mod 2^n] with s fixed by v, so the
    row is one list rotation followed by a Walsh-Hadamard transform.  Cost is
    (n+1)*2^n per row and (n+1)*4^n for the whole table, which reaches n = 13.
    """
    N = 1 << n
    s = signs(n, v)
    g = s[d:] + s[:d]
    h = 1
    while h < N:
        for i in range(0, N, h << 1):
            for j in range(i, i + h):
                a = g[j]
                b = g[j + h]
                g[j] = a + b
                g[j + h] = a - b
        h <<= 1
    return g


def build_v2(n, d, K=None):
    """v2's mask graph.  One round is F(x) = M(x ^ B ^ C_i) + d.

    Masks travel backwards.  A mask `beta` on the round output pulls through the
    addition to a mask `w` on M's output with correlation C(beta <- w), then
    through M -- which is symmetric, so the mask on the round input is M(w) --
    and through the XOR with a constant, which changes only a sign.  So the edge
    is beta -> M(w), weighted -log2 |C(beta <- w)|.  Node 0 is excluded: the
    zero mask is the trivial approximation, not a trail.
    """
    N = 1 << n
    Ma = FK.m_tab(n)
    adj = [[] for _ in range(N)]
    for beta in range(1, N):
        g = lat_row(n, d, beta)
        e = [(Ma[w], -math.log2(abs(g[w]) / N)) for w in range(1, N) if g[w]]
        if K and len(e) > K:
            e.sort(key=lambda t: t[1])
            e = e[:K]
        adj[beta] = e
    return adj


def build_v1(n, B, K=None):
    """v1's mask graph -- the same LAT, which is #254's surprise.

    The v1 round is F_B(A) = M(A) ^ M(B) ^ ROL((A+B) mod 2^n, n/4), and its
    nonlinear term takes A, not a constant.  It looks like a different object.
    It is not.  Split a mask `beta` on the output:

        beta . F_B(A) = M(beta) . A  ^  gamma . (A + B)  ^  const,
        gamma = ROR(beta, n/4),

    using M = M^T.  B is held constant for the whole revolve, so `gamma.(A+B)`
    is again addition of a CONSTANT, and its correlation with a mask `w` on A is
    the same C(gamma <- w) the v2 graph uses -- with B itself as the constant
    rather than delta(B).  The round input mask is M(beta) ^ w.

    Two consequences.  v1 needs no new machinery.  And v1's key-dependence does
    NOT collapse to a derived constant the way v2's collapses to delta(B): the
    graph depends on all 2^n values of B, so v1 is swept over keys, not deltas.
    """
    N = 1 << n
    Ma = FK.m_tab(n)
    k = n // 4
    adj = [[] for _ in range(N)]
    for beta in range(1, N):
        gamma = ((beta >> k) | (beta << (n - k))) & (N - 1) if k else beta
        g = lat_row(n, B, gamma)
        mb = Ma[beta]
        e = [(mb ^ w, -math.log2(abs(g[w]) / N))
             for w in range(N) if g[w] and (mb ^ w)]
        if K and len(e) > K:
            e.sort(key=lambda t: t[1])
            e = e[:K]
        adj[beta] = e
    return adj


def mu(adj):
    alive = DC.prune(adj)
    return DC.howard(adj, alive)


def s_lin_v2(n, d, K=None):
    return mu(build_v2(n, d, K))


def s_lin_v1(n, B, K=None):
    return mu(build_v1(n, B, K))


def rol(x, k, n):
    k %= n
    m = (1 << n) - 1
    return ((x << k) | (x >> (n - k))) & m if k else x


def tz(d, n):
    return n if d == 0 else (d & -d).bit_length() - 1


def stats(v):
    v = sorted(v)
    L = len(v)
    return dict(n=L, p10=v[L // 10], med=v[L // 2], mean=sum(v) / L,
                lo=v[0], hi=v[-1],
                below=sum(1 for x in v if x < CRIT_LIN) / L)


# ═══════════════════════════════════════════════════════════════════════════
def section_1():
    rule("§1  The linear slope is a minimum mean cycle")
    print("""TODO #254 asks for `s_lin`, the asymptotic per-round weight of the best linear
trail, and nominated a TRANSFER MATRIX for it after §11.30.4 closed the MILP
route.  The transfer-matrix idea was right about the shape of the object and
wrong about what to do with it, in exactly the way #252's route 3 was.

Write the round as three layers.  XOR with the key and the round constant moves
a mask unchanged and contributes a sign.  M is linear and symmetric, so a mask
`w` after it is the mask M(w) before it -- deterministic, weight zero.  Only the
addition is probabilistic.  So a linear trail is nothing but a WALK on a graph:

    nodes  = the 2^n - 1 nonzero masks
    edges  = beta -> M(w), weight -log2 |C_add(beta <- w)|

and the weight of the best r-round trail is the least weight over r-edge walks:

    W(r) = c + s_lin * r + o(1).

That is the standard min-plus asymptotic, and it identifies `s_lin` exactly:

    ******  s_lin  =  the MINIMUM MEAN CYCLE of the mask graph  ******

`c` is the cost of walking into the cheapest cycle and cancels in a cycle mean,
because a cycle has no beginning.  So the transient that #252 §11.31.2 diagnosed
on the differential side, and that #254 §11.30.3 diagnosed here as SATURATION,
are both properties of reading a slope off a finite series -- and a cycle mean
is not read off a series.  It is computed, in seconds, by Howard's policy
iteration, at every width the LAT reaches.

This retires #254's item (2).  The transfer-matrix route existed to make the
computation scale; the computation does not need to scale, because the answer is
a cycle mean and cycles are small.""")
    print(SEP2)
    print("""§1.2  The LAT is affordable because each row is a ROTATION.

  (-1)^(v.(x+d))  =  s_v[(x+d) mod 2^n],  s_v fixed by v alone,

so the row for output mask v is one rotation of s_v followed by a
Walsh-Hadamard transform: (n+1)*2^n per row, (n+1)*4^n for the table.  There is
no need for a per-pair carry automaton, which is what made the first pass
measure at n <= 10.""")
    print(SEP2)
    print("""§1.3  v1 rides the same LAT.  See build_v1's docstring: pulling a mask through
M(A) ^ M(B) ^ ROL(A+B, n/4) leaves `gamma . (A+B)` with B constant, which is the
same add-a-constant correlation with B itself in the role delta(B) plays for v2.
#254 budgeted a separate treatment for v1 and does not need one.

One asymmetry survives and matters for §4: v2's round depends on the key only
through delta(B), so a sweep over keys is a sweep over deltas -- 554 of them at
n = 10, for 1024 keys.  v1's round depends on B directly, so every key is its
own graph and there is no collapse.""")


# ═══════════════════════════════════════════════════════════════════════════
def section_2(quick):
    rule("§2  Validation")

    print("\n  (a) The LAT against fscx_scaling_and_linear.py's carry automaton")
    print("      -- an independent implementation, per-pair rather than per-row.")
    n = 6
    N = 1 << n
    bad = 0
    for d in range(N):
        for v in range(N):
            g = lat_row(n, d, v)
            for w in range(N):
                if abs(g[w] / N - SL.corr_add_const(n, d, w, v)) > 1e-12:
                    bad += 1
    print(f"      n = {n}, all {N} constants, all {N * N} mask pairs: "
          f"{bad} mismatches")
    check(bad == 0, "LAT disagrees with corr_add_const")

    print("\n  (b) An exact structural identity for the LAT's support.")
    print("      The number of nonzero entries depends on d ONLY through")
    print("      k = tz(d), and equals 2^k * (4^(n-k) - 4)/3 for k <= n-2,")
    print("      and 2^n for k >= n-1.  Not previously recorded; it is what")
    print("      makes the graph's edge count predictable.")
    bad = 0
    for n in (5, 6, 7):
        N = 1 << n
        for d in range(N):
            k = tz(d, n)
            want = (1 << n) if k >= n - 1 else (1 << k) * ((4 ** (n - k) - 4) // 3)
            got = sum(1 for v in range(N) for x in lat_row(n, d, v) if x)
            if got != want:
                bad += 1
    print(f"      n = 5, 6, 7, every constant: {bad} deviations")
    check(bad == 0, "LAT support identity failed")

    print("\n  (c) The v1 mask pull-back against a brute-force LAT of the real")
    print("      v1 round, evaluated as the suite evaluates it.")
    n = 6
    N = 1 << n
    Ma = FK.m_tab(n)
    k = n // 4
    bad = 0
    for B in (0, 1, 27, N - 1):
        F = [Ma[A] ^ Ma[B] ^ rol((A + B) & (N - 1), k, n) for A in range(N)]
        for beta in range(1, N):
            gamma = ((beta >> k) | (beta << (n - k))) & (N - 1) if k else beta
            g = lat_row(n, B, gamma)
            for w in range(N):
                alpha = Ma[beta] ^ w
                act = abs(sum(1 if (bin(beta & F[A]).count('1')
                                    ^ bin(alpha & A).count('1')) % 2 == 0 else -1
                              for A in range(N))) / N
                if abs(abs(g[w]) / N - act) > 1e-12:
                    bad += 1
    print(f"      n = {n}, four keys, all mask pairs: {bad} mismatches")
    check(bad == 0, "v1 mask pull-back is wrong")

    print("\n  (d) Howard's policy iteration against Karp's theorem, and against")
    print("      the exact r-round trail weight computed by dynamic programming")
    print("      -- three methods, no shared machinery below the graph.")
    cases = [(7, 13, 'v2'), (7, 44, 'v2'), (8, 37, 'v2'), (8, 150, 'v2'),
             (7, 25, 'v1'), (8, 91, 'v1')]
    if not quick:
        cases += [(10, 201, 'v2'), (10, 333, 'v1')]
    print(f"      {'n':>3} {'key/delta':>10} {'ver':>4} {'Howard':>10} "
          f"{'Karp':>10} {'DP r=40..59':>12}")
    INF = float('inf')
    for n, d, ver in cases:
        adj = build_v1(n, d) if ver == 'v1' else build_v2(n, d)
        alive = DC.prune(adj)
        h = DC.howard(adj, alive)
        kp = DC.karp(adj, alive)
        N = 1 << n
        W = [0.0] * N
        prev = None
        incs = []
        for r in range(1, 60):
            nw = [INF] * N
            for b in range(1, N):
                if W[b] == INF:
                    continue
                base = W[b]
                for a, w in adj[b]:
                    if base + w < nw[a]:
                        nw[a] = base + w
            W = nw
            m = min(x for x in W if x < INF)
            if prev is not None:
                incs.append(m - prev)
            prev = m
        dp = sum(incs[-20:]) / 20
        print(f"      {n:3d} {d:10d} {ver:>4} {h:10.6f} {kp:10.6f} {dp:12.6f}")
        check(abs(h - kp) < 1e-9, f"Howard != Karp at n={n} {ver} key={d}")
        check(abs(h - dp) < 0.02, f"Howard != DP window at n={n} {ver} key={d}")
    print("\n  (e) Edge pruning.  §3's widest row keeps only the K cheapest")
    print("      out-edges per node, because the full graph at n = 13 is 22M")
    print("      edges.  Pruning is only sound if the answer does not depend on")
    print("      K, which is checked here at a width where the full graph fits.")
    n = 10 if quick else 11
    d = sorted(x for x in DC.deltas_with_multiplicity(n)
               if not DC.screened(n, x))[7]
    full = s_lin_v2(n, d, None)
    for K in (64, 32, 16):
        got = s_lin_v2(n, d, K)
        print(f"      n = {n}, delta = {d}: K = {K:3d} gives {got:.9f}   "
              f"(full graph {full:.9f})")
        check(abs(got - full) < 1e-9, f"K = {K} pruning changed mu at n={n}")

    print("""
      The DP column is a 20-round window average and is only approximate: the
      min-plus series is eventually PERIODIC, so a window that is not a whole
      number of periods carries an O(1/window) error.  #252 §11.35.2 recorded
      that trap on the differential side; it is present here too, and it is the
      reason the window is averaged rather than differenced.""")


# ═══════════════════════════════════════════════════════════════════════════
def section_3(quick, wide):
    rule("§3  s_lin for NL-FSCX v2, per key, exactly")
    print("""One graph per distinct delta(B), weighted by how many keys produce it.  The
deployed key check `nl_v2_key_is_valid` rejects delta = 0 and delta = 2^(n-1);
those two are excluded here, as #252 §11.35.3 excludes them.

Criterion (§11.30.1, block-cipher mode -- HSKE-NL-A2, `twk`, `fpe`):
""" + f"      s_lin >= {CRIT_LIN:.4f}")
    plan = [(7, None, None), (8, None, None), (10, 60 if quick else None, None)]
    if not quick:
        plan.append((11, 90, None))
    if wide:
        plan.append((13, 12, 32))
    rows = []
    print(f"\n  {'n':>3} {'keys':>6} {'p10':>8} {'median':>8} {'mean':>8} "
          f"{'min':>8} {'max':>8} {'below':>7}")
    print("  " + SEP2)
    for n, cap, K in plan:
        mult = DC.deltas_with_multiplicity(n)
        ds = sorted(d for d in mult if not DC.screened(n, d))
        if cap and len(ds) > cap:
            random.seed(20260831)
            ds = sorted(random.sample(ds, cap))
        vals = []
        for d in ds:
            m = s_lin_v2(n, d, K)
            if m is not None:
                vals += [m] * mult[d]
        st = stats(vals)
        rows.append((n, len(ds), st))
        print(f"  {n:3d} {len(ds):6d} {st['p10']:8.4f} {st['med']:8.4f} "
              f"{st['mean']:8.4f} {st['lo']:8.4f} {st['hi']:8.4f} "
              f"{st['below']:6.1%}")
    print("""
  `below` is the key-weighted fraction under the 2/3 criterion.  Every column is
  exact per key: there is no sampling error inside a row, only in which deltas
  the row sampled.""")
    return rows


# ═══════════════════════════════════════════════════════════════════════════
def section_4(quick):
    rule("§4  s_lin for NL-FSCX v1, per key, exactly")
    print("""By §1.3 the same machinery reaches v1.  There is no delta collapse, so this
sweeps keys directly.  A key whose graph has NO cycle at all is reported
separately: it means no infinite trail exists, which is the best possible
outcome and must not be averaged in as a number.""")
    plan = [(7, None), (8, None), (10, 60 if quick else 200)]
    if not quick:
        plan.append((11, 60))
    rows = []
    print(f"\n  {'n':>3} {'keys':>6} {'acyc':>5} {'p10':>8} {'median':>8} "
          f"{'mean':>8} {'min':>8} {'max':>8} {'below':>7}")
    print("  " + SEP2)
    for n, cap in plan:
        N = 1 << n
        Bs = list(range(N))
        if cap and N > cap:
            random.seed(20260831)
            Bs = sorted(random.sample(Bs, cap))
        vals = []
        acyc = 0
        for B in Bs:
            m = s_lin_v1(n, B)
            if m is None:
                acyc += 1
            else:
                vals.append(m)
        st = stats(vals)
        rows.append((n, len(Bs), acyc, st))
        print(f"  {n:3d} {len(Bs):6d} {acyc:5d} {st['p10']:8.4f} "
              f"{st['med']:8.4f} {st['mean']:8.4f} {st['lo']:8.4f} "
              f"{st['hi']:8.4f} {st['below']:6.1%}")

    print("""
  §4.2  The degenerate class, characterised exactly.  A few keys admit a
  correlation-1 trail of unbounded length (mean weight 0) or no cycle at all.
  Exhaustively, at both widths where an exhaustive scan is instant, the class is
  the same four keys and nothing else:""")
    for n in (7, 8):
        N = 1 << n
        bad = []
        for B in range(N):
            m = s_lin_v1(n, B)
            if m is None or m < 1e-9:
                bad.append((B, tz(B, n), 'acyclic' if m is None else 'zero'))
        want = sorted({0, 1 << (n - 2), 1 << (n - 1), 3 << (n - 2)})
        got = sorted(b for b, _, _ in bad)
        print(f"      n = {n}:  {len(bad)}/{N} keys  ->  "
              + ", ".join(f"B={b} (tz={t}, {k})" for b, t, k in bad))
        check(got == want, f"v1 degenerate key class changed at n={n}")
    print("""
      That is exactly the keys supported on the top two bits -- tz(B) >= n-2 --
      which is four keys at every width, one of them the all-zero key the suite
      already treats as degenerate.  At n = 256 the class has density 2^-254.
      Contrast #253's differential class for v2, which is every B with
      tz(delta(B)) >= 4 and covers about 6% of keys: this one is not a weak-key
      class in any operational sense and needs no screening.  It is recorded
      because it is the linear analogue and because §11.30.5's correlation-1
      subspace predicted something in this shape.""")
    return rows


# ═══════════════════════════════════════════════════════════════════════════
def section_5(quick):
    rule("§5  The two modes -- #254's item (1)")
    print("""§11.30's scope note says the block-cipher criterion "does not transfer
unexamined" to HSKE-NL-A1 or HFSCX-256, and guesses that a naive transfer would
give "a sharper bar", since both run n/4 rounds instead of 3n/4.  Sharper is the
wrong word.  The transfer does not fail by a factor of three.  It fails.

  A1.     ks_i = F1^(n/4)(seed, base ^ i).  `seed` and `base` are secret; the
          attacker varies the block counter i.  So the varying input is the
          SECOND argument -- the B input.  The first argument never varies at
          all across a keystream.

  DM.     state' = F1^(n/4)(state, block) ^ state.  The message block is again
          the B input, and it is the input the attacker controls.

A trail -- differential or linear -- propagates a difference or a mask in the
FIRST argument through r rounds.  That is what §11.30.1's `s` measures and what
§3 and §4 above compute.  In both of these modes that input is a constant, and
the attacked input is the round constant, which enters ALL r rounds
simultaneously.  There is no round-by-round propagation in B, hence no trail,
hence no cycle, hence no cycle mean.  The tool this item built does not reach
these two modes, and neither does the criterion.

  CONSEQUENCE.  The three production-track rows #254 hoped this item would move
  -- HSKE-NL-A1, HFSCX-256, and everything inheriting the hash -- are NOT
  reachable by a trail bound, in either direction.  §3's and §4's numbers speak
  to HSKE-NL-A2, `twk` and `fpe` only.  That retires the part of #254 that
  expected `s_lin` to re-rate them, and replaces it with a different question:
  what does the family look like under variation of B?""")
    print(SEP2)
    print("""§5.2  What can be measured on the actual axis, and what it says.

Below is the exhaustive maximum differential probability of the A1 keystream map
B -> F1^r(A0, B), over the counter differences A1 can actually reach (a block
index XOR, so small), as a function of r.  The floor is the same statistic for a
random function of the same size -- #254 §11.30.3's saturation, and it binds
after three or four rounds, which is why this is a diagnosis and not a bound.""")
    ns = (11, 13) if quick else (11, 13, 14)
    DMAX = 15
    random.seed(11)

    def maxdp(G, N):
        best = 0
        for dB in range(1, min(DMAX + 1, N)):
            cnt = {}
            for B in range(N):
                o = G[B] ^ G[B ^ dB]
                cnt[o] = cnt.get(o, 0) + 1
            m = max(cnt.values())
            if m > best:
                best = m
        return best / N

    sat_ok = True
    for n in ns:
        N = 1 << n
        Ma = FK.m_tab(n)
        k = n // 4
        floor = math.log2(maxdp([random.randrange(N) for _ in range(N)], N))
        print(f"\n      n = {n}   deployed r = n/4 = {n // 4}   "
              f"random-function floor {floor:6.2f}")
        prev = None
        reached = None
        for r in range(1, 9):
            vals = []
            for _ in range(2):
                A0 = random.randrange(N)
                cur = [A0] * N
                for _ in range(r):
                    cur = [Ma[cur[B]] ^ Ma[B] ^ rol((cur[B] + B) & (N - 1), k, n)
                           for B in range(N)]
                vals.append(math.log2(maxdp(cur, N)))
            m = sum(vals) / len(vals)
            inc = f"{m - prev:+6.2f}" if prev is not None else "      "
            at = "   <-- at the floor" if m <= floor + 0.35 else ""
            print(f"        r = {r}:  log2 maxDP = {m:6.2f}   inc {inc}{at}")
            prev = m
            if m <= floor + 0.35:
                reached = r
                break
        if reached is None or reached > 6:
            sat_ok = False
    check(sat_ok, "A1 B-axis did not saturate by r = 6 at n <= 14")
    print("""
      Read it as a floor, not a slope.  The pre-saturation increments run to
      3.5 bits per round -- healthy -- but they are read at r <= 4, and #252
      §11.35.5 is the standing warning about exactly that: a slope read inside
      the transient missed the true asymptote by -7 to +17 percent with no
      consistent sign, on an axis where the asymptote could be computed.  Here
      it cannot be, so there is nothing to correct the read against.  A1's
      deployed r = 64 at n = 256 is far outside anything measurable.""")
    print(SEP2)
    print("""§5.3  Davies-Meyer, message input.  A necessary condition for HFSCX-256's
collision resistance is that the compression function not collapse in the
message: C(s,B) = F1^(n/4)(s,B) ^ s should behave like a random function of B.
This is exhaustively checkable, and the round count is the deployed n/4.""")
    print(f"\n      {'n':>3} {'r':>3} {'image fraction':>16} "
          f"{'max preimages':>15}")
    print("      " + "-" * 42)
    random.seed(3)
    dm_ok = True
    for n in (10, 11, 12, 13) if quick else (10, 11, 12, 13, 14):
        N = 1 << n
        Ma = FK.m_tab(n) if n not in SINGULAR else [
            (x ^ rol(x, 1, n) ^ rol(x, n - 1, n)) for x in range(N)]
        r = n // 4
        fr = []
        mc = 0
        for _ in range(3):
            s = random.randrange(N)
            cur = [s] * N
            for _ in range(r):
                cur = [Ma[cur[B]] ^ Ma[B] ^ rol((cur[B] + B) & (N - 1), n // 4, n)
                       for B in range(N)]
            cnt = {}
            for B in range(N):
                o = cur[B] ^ s
                cnt[o] = cnt.get(o, 0) + 1
            fr.append(len(cnt) / N)
            mc = max(mc, max(cnt.values()))
        f = sum(fr) / len(fr)
        print(f"      {n:3d} {r:3d} {f:16.4f} {mc:15d}")
        if n >= 12 and abs(f - (1 - 1 / math.e)) > 0.02:
            dm_ok = False
    print(f"\n      A random function gives image fraction "
          f"{1 - 1 / math.e:.4f}.")
    check(dm_ok, "DM message-input image fraction departs from a random function")
    print("""
      No anomaly.  At the widths where n/4 is more than two rounds the message
      input behaves like a random function to within the measurement, which
      corroborates §11.9's ideal-random-function treatment (TODO #215) on the
      one point a trail argument could have contradicted.  Note the singular
      widths are usable HERE and only here: n = 12 makes M non-invertible, which
      voids §3 and §4 -- F_B must be a bijection for a mask graph to mean
      anything -- but Davies-Meyer does not need F_B invertible, so the row is
      kept and labelled.""")


# ═══════════════════════════════════════════════════════════════════════════
def section_6(rows2, rows1):
    rule("§6  Where this leaves #254")

    def trend(label, seq):
        print(f"\n  {label}")
        for n, m, b in seq:
            v = "clears" if m >= CRIT_LIN else "BELOW "
            print(f"      n = {n:2d}:  median s_lin = {m:.4f}  {v}   "
                  f"{b:5.1%} of keys below 2/3")
        rise = all(seq[i][1] <= seq[i + 1][1] + 1e-9 for i in range(len(seq) - 1))
        fall = all(seq[i][2] >= seq[i + 1][2] - 1e-9 for i in range(len(seq) - 1))
        print(f"      monotone rising: {rise}    failing fraction "
              f"monotone falling: {fall}")
        return rise, fall

    m2 = [(n, st['med'], st['below']) for n, _, st in rows2]
    m1 = [(n, st['med'], st['below']) for n, _, _, st in rows1]
    r2, f2 = trend("NL-FSCX v2 (delta-indexed, key-weighted):", m2)
    r1, f1 = trend("NL-FSCX v1 (key-indexed):", m1)
    check(r2 and f2, "v2 s_lin is no longer monotone in width")
    check(r1 and f1, "v1 s_lin is no longer monotone in width")
    check(m2[-1][1] >= CRIT_LIN, "v2 widest median no longer clears 2/3")
    check(m1[-1][1] >= CRIT_LIN, "v1 widest median no longer clears 2/3")

    print("""
  THE SHAPE MATCHES THE DIFFERENTIAL AXIS.  #252 §11.35.4 found the differential
  median monotone rising, clearing its 4/3 criterion from n = 8 on, with the
  failing fraction thinning.  The linear axis does the same thing against 2/3:
  below the criterion at the two narrowest widths, above it from n = 10 on, and
  still rising at the widest width measured, with the failing fraction falling by
  roughly a factor of two to three across the range.  Both primitives, measured
  independently, do it.  This is the reassuring direction, and it is the first
  time the quantity has been computed rather than read off a slope.

  IT IS ALSO A CORRECTION.  §11.30.6 settled the linear slope at
  0.59 / 0.75 / 0.93 / 0.95 for n = 7 / 8 / 10 / 11, read as a finite-round
  increment after removing saturation and the transient, and concluded that "the
  slope rises with width" was WEAKENED -- flattening, +0.03 between the two
  widest against +0.16 between the two narrowest.  Computed exactly, the
  flattening is not there.  The medians keep climbing at the same pace to the
  widest width reached, and #252 §11.35.5's diagnosis applies verbatim: a
  finite-round read is a window average over a series that has not reached its
  slope, and its errors have no consistent sign.

  WHAT THIS DOES NOT DO.  It does not promote anything.  HSKE-NL-A2, `twk` and
  `fpe` are demo-only for reasons (#243, #244, #248) that this measurement does
  not touch -- the SPRP assumption, the tau(192) fixed-point theorem, the single
  unvaried round.  Clearing a trail criterion at four or five small widths is not
  a substitute for any of them.  And the criterion is sufficient, not necessary:
  what an attacker gets is the linear HULL, the sum over all trails sharing
  endpoints, which a per-trail weight bounds in only one direction.

  WHAT IS NOW CLOSED.
    * Item (2), the bound.  `s_lin` is a minimum mean cycle and is computed
      exactly, per key, at every width the LAT reaches.  The transfer-matrix
      route is superseded exactly as #252's route 3 was, and for the same
      reason: it was proposed to make the computation scale, and the computation
      does not need to.  §11.35.7 predicted this transfer would work "more
      cleanly still" on the linear axis.  It does -- and it reaches n = 13,
      two widths further than the differential axis got, because the LAT's rows
      are rotations (§1.2) while the DDT has no such structure.
    * Item (1), the two modes.  Answered, negatively and structurally: a trail
      bound cannot reach HSKE-NL-A1 or HFSCX-256, because in both the attacked
      input is the round constant B, which enters all r rounds at once.  #254
      can no longer be the item that re-rates the three production-track rows,
      and §11.30's scope note is corrected -- the naive transfer does not give
      "a sharper bar", it gives nothing.

  WHAT REMAINS.
    * THE WIDTH EXTRAPOLATION, and it is now the only thing #252 and #254 have
      left, jointly.  Five exact points that rise do not bound n = 256.  The
      two items reduce to one question and should be filed as one.
    * The linear hull, which no trail method reaches and which is the gap
      between everything measured here and a security claim.
    * The B-axis, newly named by §5 and belonging to whoever re-examines A1 and
      HFSCX-256.  Nothing in this repository measures it beyond §5.2's four
      rounds, and the round count there is n/4 rather than 3n/4, so it has less
      margin to spend, not more.""")
    return r2


# ═══════════════════════════════════════════════════════════════════════════
def main():
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[1])
    ap.add_argument('--quick', action='store_true',
                    help='smaller samples, n <= 11')
    ap.add_argument('--wide', action='store_true',
                    help='add n = 13 to §3 (minutes per key)')
    args = ap.parse_args()
    section_1()
    section_2(args.quick)
    rows2 = section_3(args.quick, args.wide)
    rows1 = section_4(args.quick)
    section_5(args.quick)
    section_6(rows2, rows1)
    print("\n" + SEP)
    if FAIL:
        print(f"*** FAILED: {len(FAIL)} finding(s) stopped reproducing ***")
        for f in FAIL:
            print(f"  - {f}")
        print(SEP)
        sys.exit(1)
    print("*** OK: every finding reproduced ***")
    print(SEP)


if __name__ == '__main__':
    main()
