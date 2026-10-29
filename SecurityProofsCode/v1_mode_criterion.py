#!/usr/bin/env python3
"""v1_mode_criterion.py — TODO #346: the trail criterion for NL-FSCX v1's two n/4-round
modes, HSKE-NL-A1 (counter-mode PRF) and HFSCX-256 (Davies-Meyer compression).

The round is F_B(A) = M(A ^ B) ^ ROL(A + B, n/4), iterated n/4 times with B held
constant and NO round constant (nl_fscx_revolve_v1).  §11.30.1's criterion was derived
for a block cipher at 3n/4 rounds; this script derives the two modes' own bars and
holds v1 to them.

  §1  THE MODEL, PINNED against the shipped nl_fscx_v1 at n = 16, 24 and 256.

  §2  THE TWO CRITERIA.  A difference beta in B enters EVERY round, so a trail is a
      path over the state difference alpha with beta fixed.
      HFSCX-256: a collision needs Delta(E) = Delta(h) (the feed-forward cancels it);
      the attacker chooses the message, works offline, and the generic cost is the
      birthday bound, so a characteristic is an attack below weight n/2 = 128.
      HSKE-NL-A1: ks = F_base^(n/4)(seed(base)), base = K ^ nonce.  A differential
      distinguisher needs about 2^w pairs with a fixed nonce difference, so its bar
      is the DATA available per key: n = 256 at the full codebook (the bar
      HSKE-NL-A2 is held to), or log2 of a stated per-key data limit.

  §3  THE MARKOV MODEL FAILS FOR v1.  The usual trail model treats each round's B as
      fresh and uniform; in v1 the SAME B enters every round.  One-round transition
      probabilities for a fixed B are exact (carry automaton = brute force), but at
      n = 8 a two-round "trail" with finite weight has probability ZERO on many
      (B, beta) pairs.  So trail weights are not the measurement for v1; exact
      probabilities on the real cipher are.

  §4  A WIDTH-INDEPENDENT ITERATIVE CHARACTERISTIC.  With
          beta  = 2^(n-2) + 1,   alpha = M(2^(n-1)) = 2^(n-1) + 2^(n-2) + 1,
      alpha ^ beta = 2^(n-1), so M(alpha ^ beta) = alpha, and the addition's output
      difference is 0 -- the rotation never sees a difference.  The round maps
      alpha back to alpha with probability EXACTLY 1/4 for every B (carry automaton
      at n = 256, 256 keys), at every width and rotation.  Exhaustive at n = 16:
      rounds 1 and 2 hold for exactly 1/4 and 1/16 of all states, for every B tried.
      On the shipped round at n = 256 the characteristic holds r rounds with
      probability 4^-r to r = 9.  CONTROL: moving beta's low bit kills it.

  §5  WHAT IT CAPS.
      - v1's per-round differential cost is at most 2 bits at EVERY width, so the
        width-growth that carried v2 past its bar cannot carry v1 past 2.
      - HFSCX-256: Delta(h) = alpha, Delta(m) = beta gives Delta(E) = alpha and a
        compression-function collision (semi-free-start) with probability 2^-128
        over 64 rounds -- EXACTLY the birthday bound.  Zero margin, proven; any
        other path alpha -> alpha only adds probability.  Not a collision of the
        hash: that needs Delta(h) = 0, and no entry into or exit from the
        characteristic of weight <= 14 within 4 rounds exists at n = 256.
      - HSKE-NL-A1: the core costs 128 bits over 64 rounds, so a full-codebook bar
        of 256 cannot be met unless entry from the nonce difference costs over 128.

  §6  THE RATINGS, and the documents held to them.  HFSCX-256 / -DS, HPKS-WOTS and
      HPKS-XMSS are demo-only; HSKE-NL-A1 stays production-track ONLY under a per-key
      data limit of 2^64 blocks, under a named conjecture; HKEX-RNL and ZKP-RNL keep
      their ratings and record their HFSCX-256 dependency.  SECURITY.md and spec/
      must say so.  CONTROL: the row check FIRES on the pre-#346 HFSCX-256 status.

Pure Python, seeded, about 10 s.  Exits non-zero if a finding stops reproducing.

Run:  python3 SecurityProofsCode/v1_mode_criterion.py
"""

import heapq
import json
import re
import importlib.util
import math
import os
import random
import sys
from fractions import Fraction

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
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

    def rol(self, x, s):
        s %= self.n
        return ((x << s) | (x >> (self.n - s))) & self.m if s else x

    def M(self, x):
        return (x ^ self.rol(x, 1) ^ self.rol(x, self.n - 1)) & self.m

    def F(self, A, B):
        return self.M(A ^ B) ^ self.rol((A + B) & self.m, self.k)

    def alpha(self):
        return (1 << (self.n - 1)) | (1 << (self.n - 2)) | 1

    def beta(self):
        return (1 << (self.n - 2)) | 1


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


def gammas(w, a, b, wmax):
    """Every (g, weight) of the addition (a, b -> g) with Lipmaa-Moriai weight <= wmax."""
    n, out, stack = w.n, [], [(1, (a ^ b) & 1, 0)]
    while stack:
        i, g, wt = stack.pop()
        if i == n:
            out.append((g, wt))
            continue
        p = i - 1
        if ((a >> p) & 1) == ((b >> p) & 1) == ((g >> p) & 1):
            bit = ((a >> i) ^ (b >> i) ^ (b >> p)) & 1
            stack.append((i + 1, g | (bit << i), wt))
        else:
            w2 = wt + (1 if p <= n - 2 else 0)
            if w2 <= wmax:
                stack.append((i + 1, g, w2))
                stack.append((i + 1, g | (1 << i), w2))
    return out


def least(w, src, dst, beta, wmax, rmax):
    """Least key-averaged weight src -> dst within rmax rounds, or None if none <= wmax."""
    best, pq = {(src, 0): 0}, [(0, 0, src)]
    while pq:
        wt, r, s = heapq.heappop(pq)
        if best.get((s, r), 1 << 30) < wt:
            continue
        if s == dst and r > 0:
            return wt, r
        if r == rmax:
            continue
        x = w.M(s ^ beta)
        for g, t in gammas(w, s, beta, wmax - wt):
            s2, v = x ^ w.rol(g, w.k), wt + t
            if v < best.get((s2, r + 1), 1 << 30):
                best[(s2, r + 1)] = v
                heapq.heappush(pq, (v, r + 1, s2))
    return None


# ═══════════════════════════════════════════════════════════════════════════
def section_1():
    rule("§1  The model, pinned against the shipped nl_fscx_v1")
    rng = random.Random(1)
    for n in (16, 24, 256):
        w = W(n)
        ok = sum(w.F(A, B) == H.nl_fscx_v1(H.BitArray(n, A), H.BitArray(n, B)).uint
                 for A, B in ((rng.getrandbits(n), rng.getrandbits(n)) for _ in range(200)))
        check(ok == 200, "n = %d: the integer round agrees with nl_fscx_v1 on %d/200" % (n, ok))
    w, B, P = W(256), rng.getrandbits(256), rng.getrandbits(256)
    rev = H.nl_fscx_revolve_v1(H.BitArray(256, P), H.BitArray(256, B), 64).uint
    x = P
    for _ in range(64):
        x = w.F(x, B)
    check(x == rev, "nl_fscx_revolve_v1 is F_B iterated 64 times, B fixed, no round constant")


def section_2():
    rule("§2  The two criteria")
    n, r = 256, 256 // 4
    print("""
  A difference beta in B enters every round, so a characteristic is a path over the
  state difference alpha with beta held fixed; its weight over the deployed
  r = n/4 = %d rounds is what each mode's bar is read against.

  HFSCX-256 (Davies-Meyer, h' = E_m(h) ^ h).  A collision of the compression function
  needs Delta(E) = Delta(h).  The attacker chooses m, works offline, and has no data
  limit, so the bar is the generic birthday cost:  weight >= n/2 = %d, i.e. %.1f bits
  per round at r = n/4.  (Semi-free-start if Delta(h) != 0; a collision of the hash
  itself needs Delta(h) = 0.)

  HSKE-NL-A1 (ks = F_base^(n/4)(seed(base)), base = K ^ nonce).  ks is a PUBLIC function
  of base, so the PRF question is a related-input one under the unknown offset K.  A
  differential distinguisher needs about 2^w pairs with a fixed nonce difference, so
  the bar is the data available per key:  weight >= n = %d at the full codebook (the
  bar HSKE-NL-A2 is held to, %.1f bits per round here), or >= log2(D) for a stated
  per-key limit of D blocks.  The suite states no such limit today."""
          % (r, n // 2, (n / 2) / r, n, n / r))


def section_3():
    rule("§3  The Markov trail model fails for v1: the same B enters every round")
    w = W(8)
    rng = random.Random(3)
    one = zero = finite = 0
    for _ in range(40):
        B, beta = rng.randrange(256), rng.randrange(1, 256)
        cnt = {}
        for A in range(256):
            d = w.F(A, B) ^ w.F(A, B ^ beta)
            cnt[d] = cnt.get(d, 0) + 1
        # one round, exact: the automaton's table against brute force
        tab = {}
        for g in range(256):
            p = p_fixed(8, B, 0, beta, g)
            if p:
                d = w.M(beta) ^ w.rol(g, w.k)
                tab[d] = tab.get(d, 0) + p
        one += all(abs(tab.get(d, 0) - c / 256) < 1e-12 for d, c in cnt.items()) \
            and len(tab) == len(cnt)
        # two rounds to a zero difference: the Markov product against the real cipher
        prod = 0
        for g1 in range(256):
            p1 = p_fixed(8, B, 0, beta, g1)
            if not p1:
                continue
            a1 = w.M(beta) ^ w.rol(g1, w.k)
            for g2 in range(256):
                if w.M(a1 ^ beta) ^ w.rol(g2, w.k) == 0:
                    prod = max(prod, p1 * p_fixed(8, B, a1, beta, g2))
        real = sum(w.F(w.F(A, B), B) == w.F(w.F(A, B ^ beta), B ^ beta) for A in range(256))
        if prod:
            finite += 1
            zero += real == 0
    check(one == 40, "one round with B fixed: the carry automaton's table equals brute "
          "force on %d/40 (B, beta)" % one)
    check(zero >= 5, "two rounds: %d of %d (B, beta) with a finite-weight Markov trail to "
          "a zero difference have NO real two-round collision" % (zero, finite))
    print("""
  So v1 is measured below by exact probabilities on the real cipher, and the trail
  model is used only to FIND candidates.  The small-width trail runs also mislead in
  a second way: at n = 8-11 the rotation is n/4 = 2, which lines up with M's
  three-bit spread and gives a 1-bit-per-round trail that exists at no wider width.""")
    w10 = W(10)
    art = least(w10, w10.m ^ 3, w10.m ^ 3, w10.m ^ 1, 6, 1)
    w256 = W(256)
    gone = least(w256, w256.m ^ 3, w256.m ^ 3, w256.m ^ 1, 6, 1)
    check(art == (1, 1) and gone is None, "the n = 10 one-bit iterate (alpha = ~3, beta = "
          "~1) costs %s there and does not exist at n = 256" % (art,))


def section_4():
    rule("§4  A width-independent iterative characteristic, probability 1/4 per round")
    w = W(256)
    a, b = w.alpha(), w.beta()
    check(w.M(a ^ b) == a, "alpha ^ beta = 2^(n-1), and M(2^(n-1)) = alpha: the linear "
          "part returns alpha")
    rng = random.Random(4)
    ps = {p_fixed(256, rng.getrandbits(256), a, b, 0) for _ in range(256)}
    check(ps == {Fraction(1, 4)}, "the addition (alpha, beta -> 0) holds with probability "
          "EXACTLY 1/4 for each of 256 random B at n = 256 (carry automaton): %s" % ps)
    # exhaustive at n = 16
    w16 = W(16)
    a16, b16 = w16.alpha(), w16.beta()
    ex = []
    for B in [rng.getrandbits(16) for _ in range(4)]:
        S = [(A, A ^ a16) for A in range(1 << 16)]
        c = []
        for _ in range(2):
            S = [(w16.F(x, B), w16.F(y, B ^ b16)) for x, y in S]
            S = [(x, y) for x, y in S if x ^ y == a16]
            c.append(len(S))
        ex.append(tuple(c))
    check(set(ex) == {(16384, 4096)}, "n = 16, exhaustive over all 2^16 states: rounds 1 "
          "and 2 hold for exactly 1/4 and 1/16, for every B tried %s" % ex)
    # the real cipher at n = 256, B held fixed across rounds
    T, R = 400000, 6
    surv = [T] + [0] * R
    for _ in range(T):
        B, A = rng.getrandbits(256), rng.getrandbits(256)
        x, y = A, A ^ a
        for r in range(1, R + 1):
            x, y = w.F(x, B), w.F(y, B ^ b)
            if x ^ y != a:
                break
            surv[r] += 1
    print("\n     r   held      log2(held/T)   4^-r")
    for r in range(1, R + 1):
        print("  %4d   %6d   %8.2f       %4d" % (r, surv[r], math.log2(surv[r] / T), -2 * r))
    tol = all(abs(surv[r] - T / 4 ** r) < 5 * math.sqrt(T / 4 ** r) for r in range(1, R + 1))
    check(tol, "n = 256, B fixed every round: the characteristic holds r rounds with "
          "probability 4^-r, r = 1..%d (each within 5 sigma)" % R)
    # control
    c = 0
    for _ in range(20000):
        B, A = rng.getrandbits(256), rng.getrandbits(256)
        c += (w.F(A, B) ^ w.F(A ^ a, B ^ b ^ 2)) == a
    check(c < 20, "CONTROL: beta ^ 2 does not iterate (%d/20000)" % c)
    return a, b


def section_5(a, b):
    rule("§5  What it caps")
    n, r = 256, 64
    print("""
  - Per round: v1's differential cost is at most 2 bits at every width.  v2's margin
    came from its per-round cost GROWING with the width (§11.67); v1's cannot grow
    past 2.  v1's linear axis is not measured here.
  - HFSCX-256, semi-free-start: Delta(h) = alpha, Delta(m) = beta keeps Delta(E) = alpha
    for all %d rounds with probability 2^-%d, and the feed-forward cancels it.  Bar:
    2^-%d.  Margin: 1.00x, a CEILING -- other paths alpha -> alpha only add
    probability.  It is not a collision of the hash, which needs Delta(h) = 0.
  - HSKE-NL-A1: the core costs %d bits over %d rounds, so the full-codebook bar of %d
    holds only if entry from the nonce difference costs more than %d bits.""" %
          (r, 2 * r, n // 2, 2 * r, r, n, n - 2 * r))
    check(2 * r == n // 2, "the semi-free-start characteristic's weight over n/4 rounds "
          "is exactly the birthday bar n/2 = %d" % (n // 2))
    w = W(256)
    entry = least(w, 0, a, b, 14, 4)
    exit_ = least(w, a, 0, b, 14, 4)
    nonce = least(w, w.rol(b, n // 8), a, b, 14, 4)
    check(entry is None and exit_ is None and nonce is None,
          "n = 256: no entry from 0, no exit to 0, and no entry from the nonce difference "
          "ROL(beta, n/8) of key-averaged weight <= 14 within 4 rounds")
    print("  (lower bounds only: a hash collision via this core costs 128 + entry + exit.\n"
          "   The same search at weight <= 22 within 3 rounds -- about 4 min, not run\n"
          "   here -- also finds none: SecurityProofs-10.md §11.69)")


def security_rows():
    rows, on = {}, False
    for line in open(os.path.join(ROOT, "SECURITY.md")):
        if line.startswith("## "):
            on = line.strip() == "## Protocol Status"
            continue
        if on and line.startswith("| **"):
            cells = [c.strip() for c in line.strip().strip("|").split("|")]
            mm = re.match(r"\*\*(.+?)\*\*", cells[0])
            if mm:
                rows.setdefault(mm.group(1).strip(), (cells[1], line))
    return rows


DEMOTED = {"HFSCX-256 / HFSCX-256-DS": ("hfscx-256", "hfscx-256-ds"),
           "HPKS-WOTS": ("hpks-wots",), "HPKS-XMSS": ("hpks-xmss",)}


def demoted_ok(status, row):
    """Demo-only naming TODO #346 -- or, since v10.0.0, restored by TODO #347's 3n/4
    rounds with #346's demotion kept in the row's record.  This gate's FINDING (the
    64-round core) still reproduces; the rating it set is superseded, not withdrawn."""
    if status.startswith("Demo-only"):
        return "TODO #346" in row
    return (status.startswith("Production-track") and "Restored by TODO #347 (v10.0.0)"
            in row and "Demoted by TODO #346" in row)


def section_6():
    rule("§6  The ratings, and the documents held to them")
    rows = security_rows()
    spec = json.load(open(os.path.join(ROOT, "spec", "herradura-protocol-spec.json")))
    st = {p["id"]: p["security"]["status"] for p in spec["protocols"]}
    for h, pids in DEMOTED.items():
        status, row = rows.get(h, ("(missing)", ""))
        check(demoted_ok(status, row), "SECURITY.md '%s' is demo-only and names TODO #346 "
              "('%s...')" % (h, status[:40]))
        want = "demo-only" if status.startswith("Demo-only") else "production"
        check(all(st.get(p) == want for p in pids), "spec/ %s: %s, matching SECURITY.md (%s)"
              % ("/".join(pids), want, [st.get(p) for p in pids]))
    status, row = rows.get("HSKE-NL-A1", ("(missing)", ""))
    check(status.startswith("Production-track") and
          ("2^64" in status or "lifted by TODO #347 (v10.0.0)" in status)
          and "Conjecture (TODO #346)" in row and st.get("hske-nla1") == "production",
          "HSKE-NL-A1 stays production-track, under the stated 2^64-block data limit or "
          "with it lifted by TODO #347's 3n/4 rounds, naming its conjecture, and spec/ agrees")
    for h in ("HKEX-RNL", "ZKP-RNL Σ-protocol"):
        status, row = rows.get(h, ("(missing)", ""))
        check(status.startswith("Production-track") and "HFSCX-256 dependency (TODO #346)"
              in row, "%s keeps its rating and records its HFSCX-256 dependency" % h)
    status, row = rows["HFSCX-256 / HFSCX-256-DS"]
    old = "Production-track (conjectured)"
    check(not demoted_ok(old, row.replace(status, old).replace("Restored by TODO #347", "")),
          "CONTROL: the row check FIRES on the pre-#346 HFSCX-256 status")


def section_7():
    rule("§7  Verdict")
    print("""**HFSCX-256 / -DS, HPKS-WOTS and HPKS-XMSS move to demo-only.  HSKE-NL-A1 stays
production-track only under a per-key data limit of 2^64 blocks.**

  THE FINDING.  NL-FSCX v1 has a key- and width-independent iterative differential
  at exactly 1/4 per round (§4).  It caps v1's per-round differential cost at 2 bits
  at every width, so v1 cannot follow v2, whose margin came from width growth.

  HFSCX-256.  Its compression function's semi-free-start collision characteristic
  sits at 2^-128 over 64 rounds -- exactly the birthday bound, a ceiling.  No hash
  collision below 2^128 is known, but zero margin is not cryptanalysis AT the
  criterion with room to spare, which is the bar #345 applied, and no measurement
  can raise a proven ceiling.  WOTS and XMSS ARE this hash's security, so they go
  with it.  Its KDF, MAC and random-oracle uses under a secret or fresh input
  (HKEX-RNL, ZKP-RNL, the --aead and .hkx tags) are not reached by a finding that
  needs an attacker-set chaining difference; those rows keep their ratings and say
  what they rest on.

  HSKE-NL-A1.  A counter-mode PRF's bar is the data it hands out per key.  At the
  full codebook (256 bits over 64 rounds) v1 provably cannot pass; at 2^64 blocks
  per key the cheapest characteristic known (128 bits in its core alone, no entry
  from a nonce difference of weight <= 22 within 3 rounds) clears it 2x -- the best
  found, not a proven least.  So the rating now carries a usage limit, named in the row.

  NOT DONE HERE.  v1's linear axis in these modes; a full search for cheaper
  characteristics (the one found is the least the bounded searches saw, not proven
  least).  The fix -- more rounds, or a stronger round under the hash -- is a
  wire-format break and is TODO #347.""")


def main():
    print(__doc__.split("Run:")[0].rstrip())
    section_1()
    section_2()
    section_3()
    a, b = section_4()
    section_5(a, b)
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
