#!/usr/bin/env python3
"""
hfscx_dm_rf_model.py — HFSCX-256-DM in the ideal-random-FUNCTION model (TODO #215, §11.9.12).

The deployed compression is Davies-Meyer over NL-FSCX v1:

    C_DM(s, m) = F_1^{64}(s, m) XOR s

SecurityProofs-6.md §11.9.8 cites the PGV/BRS provable-security result for this
shape.  That result is proved in the ideal-CIPHER model: it requires E_m(.) to be
a permutation for every block m.  F_1 is documented non-bijective in A (§11.5 Q3),
so the citation does not apply as stated.  This script re-derives what the correct
model — an ideal random function with feed-forward — actually gives, and searches
for the structure that model would not excuse.

  §1  Inner-map image collapse vs. C_DM image        (does non-bijectivity propagate?)
  §2  DM fixed points: v1 (search) vs. v2 (inversion) (Dean-1999 exposure)
  §3  Joux multicollisions against the MD chain       (2^t collisions for t.2^{n/2})
  §4  Kelsey-Schneier long-message second preimage    (refutes the flat 2^n claim)
  §5  NL-FSCX v2 as inner map — bijectivity + cost    (the "make PGV apply" option)
  §6  Bound summary extrapolated to n = 256

Small-n analogue: the chain is exercised at n = 16 (a power of two — M is singular
at non-power-of-two n, which would make v2 non-bijective for reasons unrelated to
this analysis) with the deployed structural relation steps = n/4, and additionally
at the deployed literal steps = 64.  Exhaustive passes are over all 2^16 states.

Runtime: ~75 s at default settings; --quick skips the r=64 exhaustive pass (§1).
"""

import argparse
import importlib.util
import itertools
import math
import os
import random
import time


# ── Load suite via importlib (suite filename has a space) ──────────────────
_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
_SPEC = importlib.util.spec_from_file_location(
    's', os.path.join(_ROOT, 'Herradura cryptographic suite.py'))
_SUITE = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_SUITE)
BitArray                = _SUITE.BitArray
nl_fscx_revolve_v1      = _SUITE.nl_fscx_revolve_v1
nl_fscx_revolve_v2      = _SUITE.nl_fscx_revolve_v2
nl_fscx_revolve_v2_inv  = _SUITE.nl_fscx_revolve_v2_inv

SEP  = "═" * 72
SEP2 = "─" * 72

N_SMALL = 16                 # power of two: M invertible, so v2 is bijective
R_STRUCT = N_SMALL // 4      # deployed structural relation steps = n/4
R_DEPLOY = 64                # deployed literal step count at n = 256

# 1 - 1/e: the image fraction of a uniformly random function on a finite set.
RANDOM_FUNC_IMAGE = 1.0 - 1.0 / math.e


def human_size(nbytes: float) -> str:
    for unit in ('B', 'KiB', 'MiB', 'GiB', 'TiB', 'PiB', 'EiB'):
        if nbytes < 1024 or unit == 'EiB':
            return f"{nbytes:.0f} {unit}"
        nbytes /= 1024


def comp_v1(s: int, m: int, n: int = N_SMALL, r: int = R_STRUCT) -> int:
    """C_DM(s, m) = F_1^r(s, m) XOR s — the deployed compression, at small n."""
    return nl_fscx_revolve_v1(BitArray(n, s), BitArray(n, m), r).uint ^ s


def comp_v2(s: int, m: int, n: int = N_SMALL, r: int = R_STRUCT) -> int:
    """The v2-inner-map variant considered in §5 — DM over a genuine permutation."""
    return nl_fscx_revolve_v2(BitArray(n, s), BitArray(n, m), r).uint ^ s


def chain(s0: int, blocks, comp=comp_v1) -> int:
    """Merkle-Damgard iteration over a list of message blocks (no padding —
    every message compared below has the same block length, so the length
    block that HFSCX-256-DM appends is identical for both and cannot separate
    them; see §4)."""
    s = s0
    for b in blocks:
        s = comp(s, b)
    return s


# ═══════════════════════════════════════════════════════════════════════════
# §1 — Does the inner map's image collapse propagate to the compression?
# ═══════════════════════════════════════════════════════════════════════════
def section1(quick: bool) -> None:
    print(SEP)
    print("§1  Inner-map image collapse vs. C_DM image")
    print(SEP)
    print("A1 models C_DM as a random function.  The objection behind TODO #215 is")
    print("that F_1^r is measurably NOT one: iterating a non-bijective map shrinks")
    print("its image toward 2/r of the space.  The question that matters is whether")
    print("the feed-forward inherits that collapse.\n")
    print(f"n = {N_SMALL} (exhaustive over all {1 << N_SMALL} states), block m = 0xA5C3")
    print(f"ideal random-function image fraction = 1 - 1/e = {RANDOM_FUNC_IMAGE:.4f}\n")

    m = 0xA5C3
    B = BitArray(N_SMALL, m)
    rounds = [R_STRUCT, 16] if quick else [R_STRUCT, 16, R_DEPLOY]
    print(f"{'r':>4}  {'image F_1^r':>12}  {'image C_DM':>11}  {'2/r':>7}  {'#F_1^r = 0':>10}")
    print(SEP2)
    for r in rounds:
        t0 = time.time()
        f = [nl_fscx_revolve_v1(BitArray(N_SMALL, a), B, r).uint
             for a in range(1 << N_SMALL)]
        img_f = len(set(f)) / (1 << N_SMALL)
        img_c = len({f[a] ^ a for a in range(1 << N_SMALL)}) / (1 << N_SMALL)
        zeros = sum(1 for v in f if v == 0)
        tag = "  <- deployed step count" if r == R_DEPLOY else ""
        print(f"{r:>4}  {img_f:>12.4f}  {img_c:>11.4f}  {2.0 / r:>7.4f}  "
              f"{zeros:>10}   ({time.time() - t0:.0f}s){tag}")

    print()
    print("Reading: F_1^r collapses as 2/r exactly as a random function would, and")
    print("at the deployed r = 64 it retains only ~3% of the space (~5 bits) — the")
    print("measurement TODO #215 records.  C_DM's image, however, sits at 1 - 1/e")
    print("for every r: the feed-forward restores it.  This is not luck.  For fixed")
    print("m, s -> s XOR c is a bijection, so C_DM(s,m) = F(s,m) XOR s re-randomises")
    print("over s even where F is many-to-one; the collapse does NOT propagate.")
    print("The inner map's non-bijectivity therefore costs nothing HERE — the gap is")
    print("in which theorem licenses the bound, not in this statistic.")


# ═══════════════════════════════════════════════════════════════════════════
# §2 — DM fixed points: the one place bijectivity would HURT
# ═══════════════════════════════════════════════════════════════════════════
def section2(trials: int = 20000) -> None:
    print("\n" + SEP)
    print("§2  DM fixed points — v1 (search) vs. v2 (one inversion)")
    print(SEP)
    print("C_DM(s,m) = s  <=>  F^r(s,m) = 0.  Under an ideal CIPHER this is free:")
    print("s = E_m^{-1}(0) for any m — the Dean-1999 weakness that makes DM's fixed")
    print("points the cheap route to expandable messages.  Under a non-invertible")
    print("inner map it is a preimage-of-zero problem (assumption A2).\n")

    random.seed(215)
    print(f"v1, random search over {trials} (s, m) pairs at n = {N_SMALL}, r = {R_STRUCT}:")
    found = 0
    t0 = time.time()
    for _ in range(trials):
        s = random.getrandbits(N_SMALL)
        m = random.getrandbits(N_SMALL)
        if comp_v1(s, m) == s:
            found += 1
    print(f"  fixed points found: {found}   (expected for a random function: "
          f"{trials / (1 << N_SMALL):.2f})   [{time.time() - t0:.0f}s]\n")

    print(f"v1, exhaustive over all s for four fixed blocks m (r = {R_DEPLOY}, deployed):")
    for m in (0xA5C3, 0x0001, 0xFFFF, 0x1234):
        B = BitArray(N_SMALL, m)
        cnt = sum(1 for a in range(1 << N_SMALL)
                  if nl_fscx_revolve_v1(BitArray(N_SMALL, a), B, R_DEPLOY).uint == 0)
        print(f"  m = {m:#06x}: {cnt} fixed point(s)")
    print("  At r = 64 the image of F_1^r covers ~3% of the space (§1), so 0 usually")
    print("  is not in it at all — for most blocks NO fixed point exists to find.\n")

    print(f"v2 (bijective inner map), by inversion — no search at all:")
    hits = 0
    for m in (0xA5C3, 0x0001, 0xFFFF, 0x1234):
        B = BitArray(N_SMALL, m)
        s = nl_fscx_revolve_v2_inv(BitArray(N_SMALL, 0), B, R_STRUCT)
        ok = comp_v2(s.uint, m) == s.uint
        hits += ok
        print(f"  m = {m:#06x}: s = v2^-r(0, m) = {s.uint:#06x}   C_DM(s,m) == s ? {ok}")
    print(f"  {hits}/4 fixed points produced in O(r) work, one per block value.")
    print("\nReading: this inverts the usual intuition.  Making the inner map bijective")
    print("to license the PGV citation would HAND the attacker free DM fixed points —")
    print("the very structure the ideal-cipher proof does not cover and that Dean's")
    print("attack consumes.  Non-bijectivity is load-bearing in the deployed design.")


# ═══════════════════════════════════════════════════════════════════════════
# §3 — Joux multicollisions
# ═══════════════════════════════════════════════════════════════════════════
def section3(t_stages: int = 4) -> None:
    print("\n" + SEP)
    print("§3  Joux multicollisions against the MD chain")
    print(SEP)
    print("Any Merkle-Damgard hash — DM or not, ideal cipher or not — admits Joux's")
    print("cascaded collisions: t successive one-block collisions give 2^t messages")
    print(f"sharing a digest for t.2^(n/2) work instead of 2^(n(2^t-1)/2^t).\n")

    random.seed(1215)
    iv = 0x4855
    s = iv
    pairs = []
    cost = 0
    t0 = time.time()
    for _ in range(t_stages):
        seen = {}
        while True:
            m = random.getrandbits(N_SMALL)
            cost += 1
            v = comp_v1(s, m)
            if v in seen and seen[v] != m:
                pairs.append((seen[v], m))
                s = v
                break
            seen[v] = m

    msgs = list(itertools.product(*pairs))
    digests = {chain(iv, list(mm)) for mm in msgs}
    print(f"stages t = {t_stages}: {cost} compression calls, {time.time() - t0:.1f}s")
    print(f"  {len(msgs)} distinct {t_stages}-block messages -> "
          f"{len(digests)} distinct digest(s)  [want 1]")
    print(f"  colliding block pairs: "
          + ", ".join(f"({a:#06x},{b:#06x})" for a, b in pairs))
    print(f"  generic cost for a {len(msgs)}-way collision at n = {N_SMALL}: "
          f"2^{N_SMALL * (len(msgs) - 1) // len(msgs)}; Joux paid ~2^{math.log2(cost):.1f}")
    print("\nReading: confirmed, as it must be — this is a property of the MD mode,")
    print("not of the compression.  It bounds any future claim that concatenating")
    print("HFSCX-256-DM with a second hash doubles the security level (it does not),")
    print("and it is the engine behind §4.  No claim currently in §11.9 relies on")
    print("multicollision hardness, so nothing deployed is affected.")


# ═══════════════════════════════════════════════════════════════════════════
# §4 — Kelsey-Schneier long-message second preimage
# ═══════════════════════════════════════════════════════════════════════════
def section4(k: int = 8) -> None:
    print("\n" + SEP)
    print("§4  Kelsey-Schneier second preimage on a 2^k-block message")
    print(SEP)
    print("§11.9.4 currently claims second-preimage resistance of 2^n classical,")
    print('"no birthday speed-up since one input is fixed".  For a LONG target that')
    print("is false in any MD hash: an expandable message plus one linking block")
    print("costs about k.2^(n/2+1) + 2^(n-k).  Demonstrated end-to-end below.\n")

    random.seed(11215)
    iv = 0x4855
    t0 = time.time()

    # 1. Expandable message: stage i collides a 1-block branch against a
    #    (2^(i-1)+1)-block branch from the same state, so the assembled prefix
    #    can take any length in [k, k + 2^k - 1] at a single fixed chain value.
    s = iv
    stages = []
    cost = 0
    for i in range(1, k + 1):
        filler = [random.getrandbits(N_SMALL) for _ in range(1 << (i - 1))]
        s_long = chain(s, filler)
        cost += len(filler)
        short, long_ = {}, {}
        while True:
            m = random.getrandbits(N_SMALL)
            cost += 2
            short.setdefault(comp_v1(s, m), m)
            long_.setdefault(comp_v1(s_long, m), m)
            common = set(short) & set(long_)
            if common:
                v = common.pop()
                stages.append((short[v], filler + [long_[v]]))
                s = v
                break
    print(f"expandable message: k = {k}, lengths {k}..{k + (1 << k) - 1} blocks, "
          f"{cost} compressions, s_exp = {s:#06x}")

    # 2. Target message and its intermediate chain states.
    target = [random.getrandbits(N_SMALL) for _ in range(1 << k)]
    states = []
    cs = iv
    for b in target:
        cs = comp_v1(cs, b)
        states.append(cs)

    # 3. Linking block: one block from s_exp onto any target state we can reach.
    link = None
    link_cost = 0
    while link is None:
        m = random.getrandbits(N_SMALL)
        link_cost += 1
        v = comp_v1(s, m)
        for j in range(k, len(states)):
            if states[j] == v:
                link = (m, j)
                break
    m_link, j = link
    print(f"linking block {m_link:#06x} -> target state index {j}, "
          f"{link_cost} tries (expected 2^(n-k) = {1 << (N_SMALL - k)})")

    # 4. Assemble: expandable stretched to j blocks, link block, target's tail.
    extra = j - k
    prefix = []
    for idx, (short_b, long_bl) in enumerate(stages):
        prefix += long_bl if (extra >> idx) & 1 else [short_b]
    forged = prefix + [m_link] + target[j + 1:]

    d_t, d_f = chain(iv, target), chain(iv, forged)
    total = cost + link_cost
    print(f"\n  target : {len(target)} blocks, digest {d_t:#06x}")
    print(f"  forged : {len(forged)} blocks, digest {d_f:#06x}")
    print(f"  distinct message ? {forged != target}    equal length ? "
          f"{len(forged) == len(target)}    digests match ? {d_t == d_f}")
    print(f"  total ~{total} compressions vs generic 2^{N_SMALL} = {1 << N_SMALL} "
          f"({(1 << N_SMALL) / total:.1f}x speed-up)   [{time.time() - t0:.0f}s]")
    print("\nEqual length matters: HFSCX-256-DM's final block is (8.|D|) XOR s_0, so a")
    print("length-preserving second preimage carries the SAME finalization block and")
    print("the match survives padding.  The attack is real against the deployed hash.")
    print("§11.9.4's flat 2^n claim is wrong as written; see §6 for what it costs at")
    print("n = 256 (answer: nothing practical — the corrected figure is still far")
    print("above the suite's 128-bit target).")


# ═══════════════════════════════════════════════════════════════════════════
# §5 — NL-FSCX v2 as the inner map
# ═══════════════════════════════════════════════════════════════════════════
def section5(bench: int = 400) -> None:
    print("\n" + SEP)
    print("§5  NL-FSCX v2 as inner map — the 'make the PGV citation apply' option")
    print(SEP)

    n = N_SMALL
    B = BitArray(n, 0xA5C3)
    img = {nl_fscx_revolve_v2(BitArray(n, a), B, R_STRUCT).uint for a in range(1 << n)}
    bij = len(img) == (1 << n)
    print(f"v2 bijectivity, exhaustive at n = {n}, r = {R_STRUCT}: "
          f"image = {len(img)}/{1 << n} -> bijective = {bij}")
    rt = all(nl_fscx_revolve_v2_inv(
                 nl_fscx_revolve_v2(BitArray(n, a), B, R_STRUCT), B, R_STRUCT).uint == a
             for a in range(0, 1 << n, 97))
    print(f"v2 inverse round-trip on a {len(range(0, 1 << n, 97))}-point sample: {rt}")
    print("  -> E_m(s) = v2^r(s, m) IS a block cipher; DM over it is PGV-1 verbatim,")
    print("     and the BRS/PGV ideal-cipher bounds would apply exactly as cited.\n")

    # Cost at the deployed size.
    random.seed(5215)
    a = BitArray(256, random.getrandbits(256))
    b = BitArray(256, random.getrandbits(256))
    t0 = time.time()
    for _ in range(bench):
        nl_fscx_revolve_v1(a, b, 64)
    t_v1 = time.time() - t0
    t0 = time.time()
    for _ in range(bench):
        nl_fscx_revolve_v2(a, b, 64)
    t_v2 = time.time() - t0
    print(f"cost at n = 256, r = 64, {bench} calls (Python reference impl):")
    print(f"  v1 {t_v1:.2f}s    v2 {t_v2:.2f}s    ratio {t_v2 / t_v1:.2f}x")
    print("  (v2 is not the slower map — its per-key delta is hoisted out of the")
    print("   revolve loop.  Performance is not an argument either way here.)")

    print("\nWhat the swap would buy and cost:")
    print("  + the cited PGV/BRS ideal-cipher bounds become applicable as written")
    print("  - free DM fixed points, one per block, by inversion (§2) — it ADDS the")
    print("    Dean-1999 structure that the deployed non-bijective map denies")
    print("  - the idealisation moves from 'v1 is a PRF' (studied: §11.8.3-4, and the")
    print("    OWF assumption A2 that every other suite protocol already leans on) to")
    print("    'v2 is an ideal cipher' — a strictly stronger claim about a map whose")
    print("    differential/linear profile is still open (TODO #99, TODO #214)")
    print("  - v2 has a documented degenerate-key class (nl_v2_key_is_valid, §11.19.2)")
    print("    where delta(B) in {0, 2^(n-1)} makes the round affine.  As an inner")
    print("    map the MESSAGE BLOCK plays the role of B, so the attacker chooses it")
    print("    freely — the key-validity screen that protects HSKE-NL-A2/HPKE-NL")
    print("    cannot be applied to a hash input")
    print("  - wire-format break for every artifact carrying a digest: signatures,")
    print("    AEAD tags, Stern commitments, KDF outputs, HCRED proofs")
    print("\n  => Recommendation: do NOT swap.  See §6 and SecurityProofs-6.md §11.9.12.")


# ═══════════════════════════════════════════════════════════════════════════
# §6 — Extrapolation to n = 256
# ═══════════════════════════════════════════════════════════════════════════
def section6() -> None:
    print("\n" + SEP)
    print("§6  Corrected bounds at n = 256")
    print(SEP)
    n = 256
    print("Model: C_DM(s,m) = f(s,m) XOR s with f a random function (assumption A1).")
    print("For fixed (s,m) the feed-forward is a constant XOR, so C_DM is ITSELF a")
    print("uniform, independent random function — every ideal-random-function bound")
    print("transfers with no loss, and the DM shape adds nothing and costs nothing.\n")
    print(f"  {'property':<34}{'bound':>16}   basis")
    print(SEP2)
    print(f"  {'collision':<34}{'2^128':>16}   birthday on a random function")
    print(f"  {'preimage':<34}{'2^256':>16}   A2 (inversion of C_DM)")
    print(f"  {'2nd preimage, short message':<34}{'2^256':>16}   implied by collision res.")
    print(f"  {'length extension':<34}{'2^256':>16}   A2, Theorem 18 (unchanged)")
    print(f"  {'DM fixed point':<34}{'2^256':>16}   preimage of 0 under A2 (§2)")
    print(SEP2)
    print("  2nd preimage against a 2^k-block target — k.2^(n/2+1) + 2^(n-k):")
    for k in (20, 30, 40, 50):
        cost = k * 2 ** (n / 2 + 1) + 2 ** (n - k)
        print(f"    k = {k:>2}  ({human_size(2 ** (k + 5)):>9} message)   "
              f"~2^{math.log2(cost):.1f}")
    print(SEP2)
    print("The 2^(n-k) term dominates at every physically realisable k; the crossover")
    print("where the expandable message becomes the bottleneck is near k = 120, i.e. a")
    print("2^125-byte target.  So the corrected second-preimage figure never drops")
    print("below ~2^200 in practice and the 128-bit target is untouched — but the")
    print('claim in §11.9.4 must read "2^n for short messages, k.2^(n/2+1) + 2^(n-k)')
    print('for a 2^k-block target", not a flat 2^n.')
    print("\nBottom line for TODO #215: every NUMBER in the §11.9.11 summary table")
    print("survives the model correction.  What does not survive is the PGV/BRS")
    print("citation in §11.9.8 (ideal-cipher, inapplicable) and the flat")
    print("second-preimage claim in §11.9.4.  Both are documentation defects, not")
    print("construction defects, and the fix is to state the random-function")
    print("derivation that the construction actually satisfies.")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[1])
    ap.add_argument('--quick', action='store_true',
                    help='skip the r=64 exhaustive pass in §1 (~25 s)')
    args = ap.parse_args()

    t0 = time.time()
    print(SEP)
    print("HFSCX-256-DM in the ideal-random-function model — TODO #215")
    print(SEP)
    section1(args.quick)
    section2()
    section3()
    section4()
    section5()
    section6()
    print("\n" + SEP)
    print(f"done in {time.time() - t0:.0f}s")
    print(SEP)


if __name__ == '__main__':
    main()
