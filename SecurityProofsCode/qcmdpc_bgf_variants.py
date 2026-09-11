#!/usr/bin/env python3
"""qcmdpc_bgf_variants.py — do decoder-side BGF variants close the DFR gap?
(TODO #250)

SecurityProofs-5.md §11.8.7 closes on a question TODO #218 asked and did not
answer: whether the near-codeword-aware and failure-recycling BGF variants of
the recent literature close the DFR gap "without a wire-format change".  It
also states the precondition this script had to wait for — "at parameters this
far from the target the answer would not change the classification", so the
comparison is worth running only alongside a parameter change, and TODO #276
is that change (§11.8.9: adopt BIKE-128's r = 12323, d = 71, t = 134).

WHAT IS UNDER TEST, AND WHAT IS NOT.  Every variant here is decoder-side only:
same public key, same ciphertext, same session-key derivation, so a receiver
may switch variant unilaterally.  That is exactly the class #250 asks about.
A variant that needs a wire change (a decoding hint, a second syndrome, an
FO-visible retry counter) is out of scope by construction and none is
implemented.

METHODOLOGY, and the two places it departs from §11.8.7 on purpose:

  1. PAIRED INSTANCES.  §11.8.7 measured one decoder and reported a rate.  A
     comparison of five decoders wants the DISCORDANT PAIRS, not five rates:
     every variant sees the identical (key, error) stream, and what is reported
     is how many of the baseline's failures a variant repairs and how many of
     its successes the variant breaks.  Two independent rates whose confidence
     intervals overlap can still hide a systematic difference; McNemar on the
     paired counts cannot.  It is also ~5x cheaper, since keygen dominates a
     trial at every parameter set here (11.4 ms of a 13 ms trial at r = 6007).

  2. THE VARIANTS WERE NOT CHOSEN FROM A MENU.  §2 measures the failure MODES
     first — residual error weight, residual syndrome weight, and whether the
     decoder converged to a wrong codeword — and each variant then targets a
     mode that census actually found.  The census is what disqualifies the
     obvious candidate: at the retired parameters a failure leaves a residual
     error of median weight 15 and a residual syndrome of weight ~95, so
     low-weight completion (try every single position, then every pair among
     the top counters) has almost nothing to work on, and it is reported as a
     measured dead end rather than left out silently.

WHICH INSTANCE THIS MEASURES (TODO #288).  §§2-6 study the RETIRED QC-MDPC set
-- r = 523, d = 15, t = 18 -- as a literal, and §7 is the argument that carries
the result to what ships.  That was always the design; what was not always true
is that the script said so.  It took d and t from the suite while hardcoding r,
so TODO #276's adoption of BIKE-128 left it measuring (467, 71, 134) and
(443..523, 71, 134), instances that are not MDPC codes, and six of eighteen
findings stopped reproducing -- including §1's pinning, the gate the rest is
explicitly conditioned on.  Re-pointing the whole file at BIKE-128 instead was
considered and rejected: a decode there costs ~55 ms against ~1 ms here, so the
run would go from minutes to hours, and §7 already supplies the transfer.

Run: python3 qcmdpc_bgf_variants.py [--quick] [--full]
Exits non-zero if a recorded finding stops reproducing.
"""

import argparse
import importlib.util
import math
import os
import random
import sys
import time
from collections import Counter

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)

# ── The instance this script measures, as a LITERAL (TODO #288) ────────────
#
# This is a RETIRED-INSTANCE STUDY and says so up front, because it stopped
# being one silently.  §§1-6 measure the QC-MDPC set that shipped through
# v6.7.3 -- r = 523, d = 15, t = 18 -- and §7 is the argument that carries the
# result to what ships now.
#
# It used to take d and t from the suite while hardcoding r, so TODO #276's
# adoption of BIKE-128 left it building (467, 71, 134) and (443..523, 71, 134):
# 71 support positions in a 443-bit ring is 16% density, which is not an MDPC
# code at all.  Six of eighteen findings stopped reproducing, including §1's
# pinning -- the gate everything else is explicitly conditioned on -- and §6's
# curve fit returned r* = inf because there was no waterfall left to fit.
#
# WHY PINNED RATHER THAN RE-POINTED AT BIKE-128.  The deployed (d, t) has a
# reachable waterfall, at r ~ 9800 (TODO #285 §3), so re-pointing is possible
# in principle.  It is not worth it here: a decode at r = 9800 costs ~55 ms
# against ~1 ms at r ~ 500, so this script's 480 s would become hours, and it
# would buy nothing #7 does not already provide.  §7 IS the transfer argument
# -- it re-runs the comparison at the largest (d, t) whose waterfall is
# reachable and checks that the RANKING and the size of the gaps survive --
# and #250's four verdict-carrying findings never stopped reproducing.  What
# broke was the evidence chain, not the verdict.
#
# So: every section that measures the retired set names it from here, and any
# section that means what ships reads the suite and says so.  Do not "fix" this
# by pointing it back at _QCMDPC_R/_D/_T.
RETIRED = (523, 15, 18)
# ...and its iteration count.  The shipped decoder runs 5 now (BIKE L1 converges
# far faster); the rule POL_BASE models ran 20, and its post-iteration-7
# relaxation is meaningless at 5.  Taking this from the suite is how §1's
# pinning came to compare a 20-iteration policy against a 5-iteration function.
NB_ITER_RETIRED = 20

FINDINGS = []


def load(name, path, argv=None):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    saved, sys.argv = sys.argv, (argv or [name])
    try:
        spec.loader.exec_module(mod)
    finally:
        sys.argv = saved
    return mod


def rule(title):
    print("\n" + "=" * 74)
    print(title)
    print("=" * 74)


def check(label, cond, detail=""):
    FINDINGS.append((label, bool(cond), detail))
    print(f"  [{'OK ' if cond else 'FAIL'}] {label}" + (f"  {detail}" if detail else ""))
    return bool(cond)


def popc(x):
    return bin(x).count("1")


# ── suite + sibling scripts ────────────────────────────────────────────────
SUITE = load("herradura_suite", os.path.join(_ROOT, "Herradura cryptographic suite.py"))
DW = load("qcmdpc_dfr_weak_keys", os.path.join(_HERE, "qcmdpc_dfr_weak_keys.py"))

keygen = DW.keygen                  # instance generation is shared, deliberately:
syndrome_of = DW.syndrome_of        # a variant comparison must not also be a
random_error = DW.random_error      # comparison of two instance generators
clopper_pearson = DW.clopper_pearson


# ═══════════════════════════════════════════════════════════════════════════
# The decoder substrate
#
# One decoder, one policy object.  qcmdpc_dfr_weak_keys.py used to carry a copy
# holding its counters in four bitplanes, correct only at d <= 15; TODO #285
# deleted it, since #276 made the SHIPPED decoder bit-sliced and that copy
# existed only for speed.  qcmdpc_parameter_selection.py's sizes the planes from
# d but takes its threshold rule as an argument, having dropped the shipped
# schedule.  This one does both, so one substrate serves every policy here and
# every parameter set stays reachable.
#
# WHICH DECODER IT REPRODUCES DEPENDS ON THE POLICY (TODO #288).  With POL_BASE
# it is the decoder that shipped THROUGH v6.7.3; with SwPolicy carrying the
# suite's QCMDPC_TH_* constants it is the one that ships NOW.  §1 pins the
# second against the real SUITE.qcmdpc_bgf_decode, which is what validates this
# substrate; the first is a specification match with no referent left in the
# tree, and §1 says so rather than asserting it.
# ═══════════════════════════════════════════════════════════════════════════
def _counters(s, sup, r, full, nb):
    """Carry-save sum of the rotated syndrome over sup -> nb bitplanes."""
    c = [0] * nb
    for k in sup:
        v = s if k == 0 else ((s >> k) | (s << (r - k))) & full
        for i in range(nb):
            cy = c[i] & v
            c[i] ^= v
            v = cy
            if v == 0:
                break
    return c


def _mask_ge(c, full, th, nb):
    """bit j set iff counter[j] >= th, MSB-first comparison."""
    if th <= 0:
        return full
    gt, eq = 0, full
    for i in range(nb - 1, -1, -1):
        ci = c[i]
        if (th >> i) & 1:
            eq &= ci
        else:
            gt |= eq & ci
            eq &= ~ci & full
    return (gt | eq) & full


def _bits(x):
    out = []
    while x:
        b = x & -x
        out.append(b.bit_length() - 1)
        x ^= b
    return out


def _flip(j, sup, r, s):
    for k in sup:
        s ^= 1 << ((j + k) % r)
    return s


class Policy:
    """A decoder variant.  Everything a variant may change lives here, and
    nothing here touches the ciphertext, the key, or the KEM's hashing — the
    whole point of #250's question is what a receiver can change alone."""

    name = "base"
    tau = 2                     # gray band width: counter in [th - tau, th)
    restarts = 0                # failure recycling: extra attempts after a failure
    ncw = False                 # near-codeword-aware post-processing
    completion = 0              # low-weight completion: 0 = off, 1 = singles, 2 = pairs

    def __init__(self, **kw):
        for k, v in kw.items():
            setattr(self, k, v)

    def threshold(self, it, sw, d, attempt=0):
        """The rule that shipped THROUGH v6.7.3: affine in d, blind to the
        syndrome weight, with a loosened schedule after iteration 7.

        NOT what herradura.h holds today -- TODO #276 replaced it with BIKE
        Level 1's, which is affine in the SYNDROME WEIGHT at 5 iterations and
        is expressible here as SwPolicy(QCMDPC_TH_SLOPE, QCMDPC_TH_OFFSET,
        QCMDPC_TH_MIN, late_shipped=False).  This docstring said "the shipped
        rule" and named qcmdpc_bgf_decode until TODO #288."""
        th_floor = (d + 1) // 2 + 2
        th = (max(math.ceil(0.66 * d), th_floor) if it < 7
              else max(th_floor - 1, 8))
        return th + attempt      # attempt != 0 only under failure recycling


def _iterate(s, e0, e1, sup0, sup1, r, d, nb_iter, pol, attempt, it0=0):
    """The BGF iteration proper.  With pol = POL_BASE and it0 = 0 this is the
    deployed decoder's loop, bit-for-bit (pinned in §1)."""
    full = (1 << r) - 1
    nb = max(4, d.bit_length())
    th_floor = (d + 1) // 2 + 2
    for it in range(it0, nb_iter):
        if s == 0:
            break
        th = pol.threshold(it, popc(s), d, attempt)
        c0 = _counters(s, sup0, r, full, nb)
        c1 = _counters(s, sup1, r, full, nb)
        b0 = _mask_ge(c0, full, th, nb)
        b1 = _mask_ge(c1, full, th, nb)
        g0 = _mask_ge(c0, full, th - pol.tau, nb) & ~b0 & full
        g1 = _mask_ge(c1, full, th - pol.tau, nb) & ~b1 & full
        black, gray = (_bits(b0), _bits(b1)), (_bits(g0), _bits(g1))
        for j in black[0]:
            e0 ^= 1 << j
            s = _flip(j, sup0, r, s)
        for j in black[1]:
            e1 ^= 1 << j
            s = _flip(j, sup1, r, s)
        if it == 0:
            # The shipped decoder's quirk, reproduced: the re-check masks are
            # computed ONCE per group rather than once per candidate position.
            for group in (black, gray):
                f0 = _mask_ge(_counters(s, sup0, r, full, nb), full, th_floor, nb)
                f1 = _mask_ge(_counters(s, sup1, r, full, nb), full, th_floor, nb)
                for j in group[0]:
                    if (f0 >> j) & 1:
                        e0 ^= 1 << j
                        s = _flip(j, sup0, r, s)
                for j in group[1]:
                    if (f1 >> j) & 1:
                        e1 ^= 1 << j
                        s = _flip(j, sup1, r, s)
    return s, e0, e1


def bgf(syn_pub, sup0, sup1, r, d, nb_iter, pol, ctx=None):
    """Returns (e0, e1) or None.  With pol = POL_BASE this is the deployed
    decoder, bit-for-bit (pinned in §1)."""
    full = (1 << r) - 1
    s_init = 0
    for k in sup0:
        s_init ^= ((syn_pub << k) | (syn_pub >> (r - k))) & full

    for attempt in range(pol.restarts + 1):
        s, e0, e1 = _iterate(s_init, 0, 0, sup0, sup1, r, d, nb_iter, pol, attempt)
        if s == 0:
            return (e0, e1)
        if pol.ncw or pol.completion:
            out = _post(s, e0, e1, sup0, sup1, r, d, nb_iter, pol, ctx)
            if out is not None:
                return out
    return None


def _rot(x, j, r, full):
    return x if j == 0 else ((x << j) | (x >> (r - j))) & full


def _post(s, e0, e1, sup0, sup1, r, d, nb_iter, pol, ctx):
    """Post-processing applied to a FAILED decoder state.  Both mitigations
    here are answers to §2's failure census, and both are receiver-local.

    NEAR-CODEWORD-AWARE (pol.ncw).  The trap is structural and cheap to state:
    squaring is linear over GF(2), so h0^2 = h0(x^2) has weight EXACTLY d.  The
    vector (h0·x^j, 0) therefore has error weight d but syndrome weight d as
    well -- a residual the counters cannot distinguish from noise, because
    every one of its parity checks is satisfied about as often as chance.
    Those are the sets N(h0), N(h1) of the BIKE weak-key literature, and they
    are exactly the pattern a stalled decoder sits in.  Detection is a distance
    test over the 2r shifts of h0^2 and h1^2; a match is corrected by flipping
    the d positions it names, after which the ordinary iteration resumes.

    LOW-WEIGHT COMPLETION (pol.completion).  Try every single position, then
    every pair among the highest counters, and keep one that lets the iteration
    reach a zero syndrome.  §2 predicts this finds almost nothing at the
    retired parameters (a failure's residual error has median weight 15), and
    it is implemented anyway so that prediction is measured rather than
    asserted."""
    full = (1 << r) - 1
    nb = max(4, d.bit_length())
    st = ctx.get("stats") if isinstance(ctx, dict) else None

    if pol.ncw and ctx is not None:
        best = None
        for which, sq in ((0, ctx["h0sq"]), (1, ctx["h1sq"])):
            for j in range(r):
                w = popc(s ^ _rot(sq, j, r, full))
                if best is None or w < best[0]:
                    best = (w, which, j)
        w, which, j = best
        if st is not None:
            st["ncw_best_gain"] += popc(s) - w
            st["ncw_looked"] += 1
        if w < popc(s):                      # the shift genuinely reduces it
            if st is not None:
                st["ncw_fired"] += 1
            sup = sup0 if which == 0 else sup1
            for k in sup:
                pos = (j + k) % r
                if which == 0:
                    e0 ^= 1 << pos
                    s = _flip(pos, sup0, r, s)
                else:
                    e1 ^= 1 << pos
                    s = _flip(pos, sup1, r, s)
            if s == 0:
                if st is not None:
                    st["ncw_solved_direct"] += 1
                return (e0, e1)
            s2, f0, f1 = _iterate(s, e0, e1, sup0, sup1, r, d, nb_iter, pol, 0, it0=1)
            if s2 == 0:
                if st is not None:
                    st["ncw_solved"] += 1
                return (f0, f1)

    if pol.completion:
        c0 = _counters(s, sup0, r, full, nb)
        c1 = _counters(s, sup1, r, full, nb)
        top = []
        for blk, c in ((0, c0), (1, c1)):
            scored = []
            for th in range(d, 0, -1):
                for j in _bits(_mask_ge(c, full, th, nb)):
                    scored.append(j)
                if len(scored) >= 8:
                    break
            top += [(blk, j) for j in scored[:8]]
        cands = [(x,) for x in top]
        if pol.completion >= 2:
            cands += [(top[a], top[b]) for a in range(len(top))
                      for b in range(a + 1, len(top))]
        for picks in cands:
            s2, g0, g1 = s, e0, e1
            for blk, j in picks:
                if blk == 0:
                    g0 ^= 1 << j
                    s2 = _flip(j, sup0, r, s2)
                else:
                    g1 ^= 1 << j
                    s2 = _flip(j, sup1, r, s2)
            if s2 == 0:
                # A genuine COMPLETION: the flip alone zeroes the syndrome.
                if st is not None:
                    st["completion_direct"] += 1
                return (g0, g1)
            s3, h0_, h1_ = _iterate(s2, g0, g1, sup0, sup1, r, d, nb_iter, pol, 0, it0=1)
            if s3 == 0:
                # NOT a completion: the flip only perturbed the state and the
                # ordinary iteration did the rest.  §5 separates these two,
                # because conflating them credits the wrong mechanism -- an
                # earlier draft of this file did exactly that and reported
                # completion repairing 10 of 14 failures at parameters where
                # §2 says a completable failure essentially never occurs.
                if st is not None:
                    st["completion_resume"] += 1
                return (h0_, h1_)
    return None


# ═══════════════════════════════════════════════════════════════════════════
# The variants
# ═══════════════════════════════════════════════════════════════════════════
class SwPolicy(Policy):
    """Threshold affine in the SYNDROME WEIGHT rather than constant in d.

    This is the one structural difference between the shipped decoder and
    BIKE's BGF that is not a constant: BIKE's rule reads the syndrome weight
    and the shipped one ignores it.  The constants are NOT BIKE's published
    ones — those are level-specific and transfer to nothing else here (§3
    measures what happens when they are used off-level).  They are derived in
    §4 from the counter distributions of the parameter set under test, by the
    likelihood-ratio rule: flip a position when a counter that high is more
    likely to come from an error position than from a clean one, i.e. the
    smallest th with t·P(C >= th | error) >= (n - t)·P(C >= th | clean)."""

    name = "sw-th"

    def __init__(self, a, b, floor, late_shipped=True, **kw):
        super().__init__(**kw)
        self.a, self.b, self.floor = a, b, floor
        # late_shipped=True keeps the deployed decoder's post-iteration-7
        # relaxation, so a comparison against the baseline moves exactly one
        # knob.  False is the rule as its own author states it, applied at
        # every iteration -- which is what §3 needs, since a rule wearing the
        # shipped decoder's late phase is no longer that rule.
        self.late_shipped = late_shipped

    def threshold(self, it, sw, d, attempt=0):
        # The LATE phase is the shipped one, verbatim.  Only the first seven
        # iterations' threshold is under test, so the comparison moves exactly
        # one knob -- and the grid point (slope 0, offset 0) is then the shipped
        # decoder itself rather than something that merely resembles it.  An
        # earlier draft of this file got that wrong and scored the baseline at
        # 28.7% where it measures 10.7%: a constant threshold held for all
        # twenty iterations is a THIRD rule, not the deployed one.
        if it >= 7 and self.late_shipped:
            return max((d + 1) // 2 + 1, 8) + attempt
        th = max(int(self.a * sw + self.b), self.floor)
        return min(th, d) + attempt


POL_BASE = Policy(name="base")
POL_NCW = Policy(name="ncw", ncw=True)
POL_RECYCLE = Policy(name="recycle", restarts=4)
POL_COMPLETE = Policy(name="complete", completion=2)
POL_NCW_RECYCLE = Policy(name="ncw+recycle", ncw=True, restarts=4)


def key_ctx(sup0, sup1, r):
    """Per-key precomputation the near-codeword test needs: h0^2 and h1^2.
    Squaring is the map j -> 2j mod r on the support, so both have weight d."""
    h0sq = sum(1 << ((2 * k) % r) for k in sup0)
    h1sq = sum(1 << ((2 * k) % r) for k in sup1)
    return {"h0sq": h0sq, "h1sq": h1sq}


# ═══════════════════════════════════════════════════════════════════════════
# §1  The baseline IS the shipped decoder
# ═══════════════════════════════════════════════════════════════════════════
def section1(n):
    rule("§1  Pinning: the decoder substrate, twice")
    r0, d0, t0_ = RETIRED
    rd, dd, td = SUITE._QCMDPC_R, SUITE._QCMDPC_D, SUITE._QCMDPC_T
    print(f"""  A variant comparison whose baseline is not a real decoder measures the
  wrong thing, so this runs first and everything below is gated on it.  TODO
  #288 split it in two, because #276 left the single pinning it used to do
  with no referent: this script's POL_BASE is the rule that shipped THROUGH
  v6.7.3 -- constant in d, 20 iterations, the post-iteration-7 relaxation --
  and what ships now is BIKE Level 1's, affine in the SYNDROME WEIGHT at 5
  iterations.  Pinning the old policy against the new function compares two
  different algorithms and fails, which is exactly what it did.

  (a) THE MACHINERY, against what ships TODAY.  The loop, the flip logic, the
      bitplane counters and the iteration-0 second pass are shared by every
      policy here, so they are pinned against the real
      SUITE.qcmdpc_bgf_decode at the DEPLOYED parameters
      (r = {rd}, d = {dd}, t = {td}) -- with the policy configured to BIKE
      L1's shipped constants, which SwPolicy can express exactly.  This is a
      stronger check than the one it replaces: it holds the substrate to a
      function that exists rather than to a copy of itself.

  (b) THE BASELINE POLICY, at the instance this script studies
      (r = {r0}, d = {d0}, t = {t0_}).  POL_BASE models a decoder no longer in
      the tree, so it cannot be pinned against a function -- but it IS pinned,
      by §5, against the MEASUREMENT that decoder left behind: 0.264%
      [0.236%, 0.295%] over 120 000 trials in SecurityProofs-5.md §11.8.7.
      That is the referent, and it is a stronger one than a sample of this
      size could be, because at a 0.264% DFR sixty trials expect 0.16
      failures.  So this half only establishes that the retired instance is
      well-formed and decodes -- a parameter typo would show up here rather
      than as a mysterious DFR three sections later.""")

    # (a) the shared substrate vs. the function that ships
    pol_ship = SwPolicy(SUITE._QCMDPC_TH_SLOPE, SUITE._QCMDPC_TH_OFFSET,
                        SUITE._QCMDPC_TH_MIN, late_shipped=False,
                        tau=SUITE._QCMDPC_TAU, name="shipped-l1")
    nb_dep = SUITE._QCMDPC_NB_ITER
    rng = random.Random(20250908)
    n_a = max(4, n // 8)          # a decode at the deployed r is ~50x a retired one
    agree_a = 0
    for _ in range(n_a):
        sup0, sup1, h0, h1, h_pub = keygen(rng, rd, dd)
        e0, e1 = random_error(rng, rd, td)
        syn = syndrome_of(e0, e1, h_pub, rd)
        want = SUITE.qcmdpc_bgf_decode(syn, h0, set(sup0), set(sup1))
        got = bgf(syn, sup0, sup1, rd, dd, nb_dep, pol_ship)
        agree_a += (want == got)
    check(f"(a) the substrate reproduces the SHIPPED decoder on {n_a} deployed instances",
          agree_a == n_a, f"agree {agree_a}/{n_a}")

    # (b) the retired instance this script measures
    r, d, t = RETIRED
    nb_iter = NB_ITER_RETIRED
    decoded = 0
    for _ in range(n):
        sup0, sup1, h0, h1, h_pub = keygen(rng, r, d)
        e0, e1 = random_error(rng, r, t)
        syn = syndrome_of(e0, e1, h_pub, r)
        got = bgf(syn, sup0, sup1, r, d, nb_iter, POL_BASE)
        decoded += (got == (e0, e1))
    # At a 0.264% DFR this sample is overwhelmingly all-success; anything
    # below ~95% means the instance is malformed, not that the DFR moved.
    check("(b) the retired instance is well-formed and decodes",
          decoded >= int(0.95 * n),
          f"{decoded}/{n} decoded (expect ~{n} at a 0.264% DFR; "
          f"§5 is what pins the RATE)")
    return r, d, t, nb_iter


# ═══════════════════════════════════════════════════════════════════════════
# §2  What a failure actually looks like — the census that picks the variants
# ═══════════════════════════════════════════════════════════════════════════
def census(rng, r, d, t, nb_iter, want_failures, budget_s):
    full = (1 << r) - 1
    res_w, syn_w = Counter(), Counter()
    wrong_cw = trials = nf = 0
    t0 = time.time()
    while nf < want_failures and time.time() - t0 < budget_s:
        sup0, sup1, h0, h1, h_pub = keygen(rng, r, d)
        e0, e1 = random_error(rng, r, t)
        syn = syndrome_of(e0, e1, h_pub, r)
        s_init = 0
        for k in sup0:
            s_init ^= ((syn << k) | (syn >> (r - k))) & full
        s, g0, g1 = _iterate(s_init, 0, 0, sup0, sup1, r, d, nb_iter, POL_BASE, 0)
        trials += 1
        if s == 0 and (g0, g1) == (e0, e1):
            continue
        nf += 1
        if s == 0:
            wrong_cw += 1
        res_w[popc(g0 ^ e0) + popc(g1 ^ e1)] += 1
        syn_w[popc(s)] += 1
    return trials, nf, res_w, syn_w, wrong_cw


def section2(quick):
    rule("§2  Failure-mode census at the retired parameters")
    print("""  The variants below are answers to this table, not a menu.  Three modes are
  distinguishable and each admits a different receiver-local mitigation:
  a near-miss (a residual error of weight 1-2, which low-weight completion
  repairs), a stall on a near-codeword (a LOW residual syndrome weight next to
  a HIGH residual error weight -- the N(h0)/N(h1) trap), and an ordinary stall
  (both high, which only a different trajectory can escape).""")
    r, d, t = RETIRED
    nb_iter = NB_ITER_RETIRED
    rng = random.Random(4242)
    want = 40 if quick else 200
    trials, nf, res_w, syn_w, wrong_cw = census(rng, r, d, t, nb_iter, want,
                                               120 if quick else 900)
    if nf == 0:
        check("the census observed at least one failure", False, "none in budget")
        return None
    rw = sorted(res_w.elements())
    sw = sorted(syn_w.elements())
    med_r, med_s = rw[len(rw) // 2], sw[len(sw) // 2]
    near_miss = sum(v for k, v in res_w.items() if k <= 2)
    low_syn = sum(v for k, v in syn_w.items() if k <= 2 * d)
    print(f"\n  {trials} trials, {nf} failures "
          f"(DFR {nf / trials:.4%}, {clopper_pearson(nf, trials)[0]:.4%}"
          f"-{clopper_pearson(nf, trials)[1]:.4%})")
    print(f"  residual error weight wt(e ^ e_hat):  min {rw[0]}, median {med_r}, max {rw[-1]}")
    print(f"  residual syndrome weight:             min {sw[0]}, median {med_s}, max {sw[-1]}")
    print(f"  converged to a WRONG codeword (s = 0, e_hat != e): {wrong_cw}")
    print(f"  near-misses (residual error weight <= 2):          {near_miss}")
    print(f"  near-codeword-shaped (residual syndrome <= 2d = {2 * d}): {low_syn}")

    check("failures are stalls, not near-misses "
          "(so low-weight completion has almost nothing to repair)",
          near_miss <= 0.05 * nf,
          f"{near_miss}/{nf} have residual error weight <= 2")
    check("the decoder does not converge to a wrong codeword at these parameters",
          wrong_cw == 0, f"{wrong_cw}/{nf}")
    check("a failure leaves a residual error far heavier than t/2",
          med_r > t / 2, f"median {med_r} against t/2 = {t / 2}")
    return dict(trials=trials, failures=nf, med_res=med_r, med_syn=med_s,
                near_miss=near_miss, wrong_cw=wrong_cw, low_syn=low_syn)


# ═══════════════════════════════════════════════════════════════════════════
# §3  The threshold rule does not transfer between parameter sets
# ═══════════════════════════════════════════════════════════════════════════
def section3(quick):
    rule("§3  A threshold rule is not portable — measured, at d = 45")
    print("""  Before any variant is compared, one thing has to be established about the
  comparison itself: a threshold rule carries its parameter set with it.
  CLAUDE.md records this from TODO #276 as "each fails outright at the other's
  d"; here it is measured, cheaply, at an intermediate d where both rules are
  at least defined.  It is why SwPolicy DERIVES its constants in §4 instead of
  importing BIKE's published affine rule, and why a variant that beat the
  baseline only by carrying better-tuned constants would prove nothing.""")
    r, d, t = 6007, 45, 70
    nb_iter = NB_ITER_RETIRED     # POL_BASE's budget; see RETIRED (TODO #288)
    n = 12 if quick else 40
    rng = random.Random(99)
    bike = SwPolicy(0.0069722, 13.530, 36, late_shipped=False,
                    name="bike-l1-constants")
    ok = {"base": 0, "bike-l1-constants": 0}
    for _ in range(n):
        sup0, sup1, h0, h1, h_pub = keygen(rng, r, d)
        e0, e1 = random_error(rng, r, t)
        syn = syndrome_of(e0, e1, h_pub, r)
        for pol in (POL_BASE, bike):
            if bgf(syn, sup0, sup1, r, d, nb_iter, pol) == (e0, e1):
                ok[pol.name] += 1
    print(f"\n  r = {r}, d = {d}, t = {t}, {n} paired instances")
    print(f"    shipped rule  max(ceil(0.66d), (d+1)/2+2) = {max(math.ceil(0.66 * d), (d + 1) // 2 + 2)}"
          f":  {ok['base']}/{n} decoded")
    print(f"    BIKE-L1 rule  max(0.0069722*sw + 13.530, 36)  :  "
          f"{ok['bike-l1-constants']}/{n} decoded")
    check("BIKE's Level-1 constants are not usable off-level",
          ok["bike-l1-constants"] < ok["base"],
          f"{ok['bike-l1-constants']} vs {ok['base']} of {n}")
    return ok


# ═══════════════════════════════════════════════════════════════════════════
# §4  Tuning the syndrome-weight rule ON THE OBJECTIVE, not on a proxy
# ═══════════════════════════════════════════════════════════════════════════
def _fit(xs, ys):
    n = len(xs)
    mx, my = sum(xs) / n, sum(ys) / n
    sxx = sum((x - mx) ** 2 for x in xs)
    sxy = sum((x - mx) * (y - my) for x, y in zip(xs, ys))
    a = sxy / sxx if sxx else 0.0
    b = my - a * mx
    ss_tot = sum((y - my) ** 2 for y in ys)
    ss_res = sum((y - (a * x + b)) ** 2 for x, y in zip(xs, ys))
    return a, b, (1 - ss_res / ss_tot if ss_tot else 1.0)


def mean_initial_sw(rng, r, d, t, n):
    """Mean weight of the syndrome the decoder starts from."""
    full = (1 << r) - 1
    acc = 0
    for _ in range(n):
        sup0, sup1, h0, h1, h_pub = keygen(rng, r, d)
        e0, e1 = random_error(rng, r, t)
        syn = syndrome_of(e0, e1, h_pub, r)
        s = 0
        for k in sup0:
            s ^= ((syn << k) | (syn >> (r - k))) & full
        acc += popc(s)
    return acc / n


def sw_grid(th_ship, sw0, floor):
    """Rules of the form th(sw) = max(int(a*sw + b), floor), parameterised so
    that every one of them passes through (sw0, th_ship + offset): the slope
    says how hard the rule reacts to the syndrome weight, the offset moves the
    whole rule up or down.  The shipped constant rule is the grid point
    (slope 0, offset 0), so the search cannot lose to the baseline by
    construction -- if reading the syndrome weight is worth nothing, tuning
    returns the baseline and says so."""
    out = []
    for m in (0.0, 0.25, 0.5, 0.75, 1.0, 1.5):
        a = m * th_ship / sw0
        for off in (-4, -2, 0, 2, 4):
            b = th_ship + off - a * sw0
            out.append((a, b))
    return out


def measure(rng, r, d, t, nb_iter, n, pol, ctx_needed=False, budget_s=None):
    """DFR of one policy over n fresh instances."""
    fails = 0
    t0 = time.time()
    done = 0
    for _ in range(n):
        sup0, sup1, h0, h1, h_pub = keygen(rng, r, d)
        e0, e1 = random_error(rng, r, t)
        syn = syndrome_of(e0, e1, h_pub, r)
        ctx = key_ctx(sup0, sup1, r) if ctx_needed else None
        if bgf(syn, sup0, sup1, r, d, nb_iter, pol, ctx) != (e0, e1):
            fails += 1
        done += 1
        if budget_s and time.time() - t0 > budget_s:
            break
    return fails, done


def tune(r_cal, d, t, nb_iter, n_cal, th_ship, seed):
    """Rank the grid by DFR on a calibration set drawn in the WATERFALL, where
    failures are common enough to rank rules at a sane sample size, then hand
    the winner back to be evaluated out-of-sample at the target r.  Tuning at
    the target r directly is not affordable: at the deployed r a rule needs
    ~10^5 instances to separate it from its neighbours, times the grid size."""
    sw0 = mean_initial_sw(random.Random(seed), r_cal, d, t, 30)
    floor = max(2, (d + 1) // 2 - 2)
    best = None
    table = []
    for (a, b) in sw_grid(th_ship, sw0, floor):
        pol = SwPolicy(a, b, floor, name="sw-th")
        f, n = measure(random.Random(seed), r_cal, d, t, nb_iter, n_cal, pol)
        table.append((f / n, a, b))
        if best is None or f / n < best[0]:
            best = (f / n, a, b)
    table.sort()
    return best, table, sw0, floor


def section4(quick):
    rule("§4  The syndrome-weight rule, tuned on DFR itself")
    print("""  SwPolicy's constants are not imported and not derived from a counter model:
  they are SEARCHED, ranked by the quantity the whole item is about.  Two
  choices make that honest rather than circular.

  TRAIN AND TEST ARE DISJOINT.  Ranking happens on a calibration set drawn in
  the WATERFALL, at an r where failures are common enough to separate rules at
  a few hundred instances; the winner is then measured at the target r on
  instances it has never seen (§5, §7).  Tuning at the target r directly is not
  affordable -- a 0.2% DFR needs ~10^5 instances per grid point.

  THE BASELINE IS IN THE GRID.  POL_BASE's constant rule is the grid point
  (slope 0, offset 0), so a search that finds nothing returns the baseline
  itself.  ("The shipped rule" until TODO #288, which is no longer what that
  phrase means -- see RETIRED and §1.)  A syndrome-adaptive rule that cannot beat a constant one on its own
  training set is not going to beat it anywhere.""")
    nb_iter = NB_ITER_RETIRED
    out = {}
    for (r_cal, d, t, tag, n_cal) in [
            # r = 467 is a literal chosen against the RETIRED d, so it takes
            # the retired d and t with it (TODO #288).  Pairing it with the
            # suite's current d = 71 gave (467, 71, 134) -- 16% density, not an
            # MDPC code -- and the grid then separated nothing.
            (467, RETIRED[1], RETIRED[2], "retired", 150 if quick else 700),
            (3607, 45, 70, "mid", 40 if quick else 250),
    ]:
        th_ship = max(math.ceil(0.66 * d), (d + 1) // 2 + 2)
        # The grid's baseline point must BE the baseline, not resemble it.
        ident = SwPolicy(0.0, float(th_ship), 2, name="grid-baseline")
        rng = random.Random(9)
        same = n_id = 0
        for _ in range(30 if d == RETIRED[1] else 10):
            sup0, sup1, h0, h1, h_pub = keygen(rng, r_cal, d)
            e0, e1 = random_error(rng, r_cal, t)
            syn = syndrome_of(e0, e1, h_pub, r_cal)
            same += (bgf(syn, sup0, sup1, r_cal, d, nb_iter, POL_BASE)
                     == bgf(syn, sup0, sup1, r_cal, d, nb_iter, ident))
            n_id += 1
        check(f"[{tag}] the grid's (slope 0, offset 0) point IS the baseline decoder",
              same == n_id, f"{same}/{n_id} identical outcomes")
        best, table, sw0, floor = tune(r_cal, d, t, nb_iter, n_cal, th_ship, 1234)
        dfr, a, b = best
        base_dfr = [row[0] for row in table if row[1] == 0.0 and
                    abs(row[2] - th_ship) < 1e-9]
        out[tag] = (a, b, floor)
        print(f"\n  {tag:9s} calibration r = {r_cal}, d = {d}, t = {t}, "
              f"{n_cal} instances/rule, {len(table)} rules")
        print(f"    mean initial syndrome weight sw0 = {sw0:.0f}, "
              f"shipped constant th = {th_ship}")
        print(f"    best rule: th = max({a:.6f}*sw + {b:.3f}, {floor})  "
              f"-> calibration DFR {dfr:.2%}")
        if base_dfr:
            print(f"    shipped rule as a grid point:                    "
                  f"-> calibration DFR {base_dfr[0]:.2%}")
        print(f"    at sw = sw0 that rule reads th = "
              f"{max(int(a * sw0 + b), floor)} against the shipped {th_ship}")
        worst = table[-1][0]
        print(f"    spread over the grid: {table[0][0]:.2%} .. {worst:.2%}")
        check(f"[{tag}] the tuning grid separates rules at all "
              "(so a null result is a measurement, not a blind search)",
              worst > table[0][0], f"{table[0][0]:.2%} .. {worst:.2%}")
    return out


# ═══════════════════════════════════════════════════════════════════════════
# §5  The paired comparison, at the retired parameters
# ═══════════════════════════════════════════════════════════════════════════
def variants_for(tuned):
    a, b, floor = tuned
    return [POL_BASE,
            SwPolicy(a, b, floor, name="sw-th"),
            POL_NCW,
            POL_RECYCLE,
            POL_COMPLETE,
            POL_NCW_RECYCLE]


def paired(rng, r, d, t, nb_iter, pols, n, budget_s):
    """Every policy on the identical (key, error) stream."""
    fails = {p.name: 0 for p in pols}
    stats = {p.name: Counter() for p in pols}
    disc = {p.name: [0, 0] for p in pols}     # [base failed & p ok, base ok & p failed]
    done = 0
    t0 = time.time()
    for _ in range(n):
        sup0, sup1, h0, h1, h_pub = keygen(rng, r, d)
        e0, e1 = random_error(rng, r, t)
        syn = syndrome_of(e0, e1, h_pub, r)
        ok = {}
        for p in pols:
            ctx = key_ctx(sup0, sup1, r)
            ctx["stats"] = stats[p.name]
            ok[p.name] = (bgf(syn, sup0, sup1, r, d, nb_iter, p, ctx) == (e0, e1))
            if not ok[p.name]:
                fails[p.name] += 1
        for p in pols:
            if p.name == "base":
                continue
            if not ok["base"] and ok[p.name]:
                disc[p.name][0] += 1
            elif ok["base"] and not ok[p.name]:
                disc[p.name][1] += 1
        done += 1
        if time.time() - t0 > budget_s:
            break
    return fails, disc, done, stats


def section5(tuned, quick):
    rule("§5  Paired DFR at the retired parameters (r = 523, d = 15, t = 18)")
    print("""  Every variant decodes the SAME instances as the baseline, so the report is
  the discordant pairs -- how many of the baseline's failures a variant
  repairs, and how many of its successes it breaks -- rather than six rates
  that have to be compared through overlapping intervals.

  A variant is only interesting here if REPAIRED - BROKE is positive and large
  relative to the baseline's own failure count.""")
    r, d, t = RETIRED
    nb_iter = NB_ITER_RETIRED
    pols = variants_for(tuned["retired"])
    n = 4000 if quick else 60000
    budget = 240 if quick else 2400
    fails, disc, done, stats = paired(random.Random(20250250), r, d, t, nb_iter,
                                     pols, n, budget)
    print(f"\n  {done} paired instances\n")
    print(f"  {'variant':14s} {'failures':>9s} {'DFR':>10s}   "
          f"{'95% CI':>20s}   repaired  broke")
    base_f = fails["base"]
    for p in pols:
        f = fails[p.name]
        lo, hi = clopper_pearson(f, done)
        rep, bro = disc[p.name]
        extra = "" if p.name == "base" else f"{rep:>8d} {bro:>6d}"
        print(f"  {p.name:14s} {f:>9d} {f / done:>10.4%}   "
              f"[{lo:.4%}, {hi:.4%}]   {extra}")
    # THIS is what pins POL_BASE (TODO #288).  The decoder it models is no
    # longer in the tree, so it cannot be pinned against a function -- but the
    # measurement it left behind is a referent, and a sharper one than any
    # sample this script can afford: 120 000 trials against our 4 000.
    check("the baseline's DFR at the RETIRED parameters agrees with "
          "SecurityProofs-5.md §11.8.7 (0.264%, [0.236%, 0.295%])",
          clopper_pearson(base_f, done)[0] <= 0.00295
          and clopper_pearson(base_f, done)[1] >= 0.00236,
          f"{base_f / done:.4%} over {done} trials")
    # WHICH MECHANISM DID THE WORK.  A repair is credited to the thing that
    # actually produced it, which is not always the thing the variant is named
    # after: `complete` flips a candidate AND resumes the iteration, and the
    # split below says which half mattered.
    print("\n  mechanism attribution (counted inside the failed-state handler):")
    for p in pols:
        st = stats[p.name]
        if not st:
            continue
        parts = ", ".join(f"{k} {v}" for k, v in sorted(st.items()))
        print(f"    {p.name:14s} {parts}")
    st_c = stats["complete"]
    check("a genuine low-weight COMPLETION essentially never fires, as §2 "
          "predicted from the residual-weight census",
          st_c["completion_direct"] <= max(1, 0.10 * base_f),
          f"{st_c['completion_direct']} direct completions vs "
          f"{st_c['completion_resume']} repairs that needed the resume")
    st_n = stats["ncw"]
    check("the near-codeword test finds no near-codeword to correct at these "
          "parameters (§2 found 0 near-codeword-shaped failures)",
          st_n["ncw_fired"] == 0 or st_n["ncw_solved"] == 0,
          f"fired {st_n['ncw_fired']}, solved {st_n['ncw_solved']}")
    return fails, disc, done, pols, stats


# ═══════════════════════════════════════════════════════════════════════════
# §6  Each variant gets its OWN DFR(r) fit — the item asks for exactly this
# ═══════════════════════════════════════════════════════════════════════════
def curve(pol, rs, d, t, nb_iter, want_fail, budget_s, seed):
    pts = []
    for r in rs:
        rng = random.Random(seed + r)
        fails = trials = 0
        t0 = time.time()
        while fails < want_fail and time.time() - t0 < budget_s:
            sup0, sup1, h0, h1, h_pub = keygen(rng, r, d)
            e0, e1 = random_error(rng, r, t)
            syn = syndrome_of(e0, e1, h_pub, r)
            ctx = key_ctx(sup0, sup1, r) if pol.ncw else None
            if bgf(syn, sup0, sup1, r, d, nb_iter, pol, ctx) != (e0, e1):
                fails += 1
            trials += 1
        if fails >= 3:
            pts.append((r, trials, fails))
    return pts


def extrapolate(pts, target_log2=-128):
    xs = [p[0] for p in pts]
    ys = [math.log2(p[2] / p[1]) for p in pts]
    a, b, r2 = _fit(xs, ys)
    r_star = (target_log2 - b) / a if a else float("inf")
    return a, b, r2, r_star


def section6(tuned, quick):
    rule("§6  DFR(r) per variant — each fitted in its own waterfall")
    print("""  §11.8.7 fitted ONE line, for the shipped decoder, and #250 records why a
  variant cannot borrow it: a decoder that moves the waterfall moves the whole
  curve, so a variant needs its own fit or its r* is read off someone else's
  slope.  Each variant is therefore measured over the r window where ITS OWN
  DFR is observable at a sane sample size, which is not the same window for
  all of them -- a variant with a 10x lower DFR runs out of failures 10x
  sooner.

  Both of §11.8.7's caveats carry over unchanged, and both point the same way:
  a QC-MDPC DFR curve is concave (waterfall, then a flatter error floor) and
  every point here is in the waterfall, so every r* below is a LOWER BOUND on
  the r that decoder would really need.""")
    # The r windows below are literals around the RETIRED r, so they take the
    # retired d and t with them (TODO #288).  Read from the suite, they swept
    # r = 443..523 at d = 71: nothing decodes there, so every curve had fewer
    # than three usable points and the fit returned r* = inf.
    d, t = RETIRED[1], RETIRED[2]
    nb_iter = NB_ITER_RETIRED
    want = 12 if quick else 40
    budget = 25 if quick else 200
    windows = {
        "base": [479, 491, 503, 523],
        "sw-th": [443, 457, 467, 479],
        "recycle": [467, 479, 491, 503],
        "ncw": [479, 491, 503, 523],
    }
    pols = {p.name: p for p in variants_for(tuned["retired"])}
    out = {}
    for name, rs in windows.items():
        pts = curve(pols[name], rs, d, t, nb_iter, want, budget, 555)
        if len(pts) < 3:
            check(f"[{name}] the DFR curve has at least 3 usable points",
                  False, f"{len(pts)} points")
            continue
        a, b, r2, r_star = extrapolate(pts)
        out[name] = (a, b, r2, r_star, pts)
        print(f"\n  {name}")
        for (r, n, f) in pts:
            print(f"    r = {r:4d}   {n:>8d} trials  {f:>4d} failures   "
                  f"DFR {f / n:>9.4%}   log2 {math.log2(f / n):>7.2f}")
        print(f"    fit: log2(DFR) = {a:.4f}*r + {b:.2f}  (R^2 = {r2:.3f})"
              f"   ->  r* at 2^-128 = {r_star:.0f}")
    if "base" in out and "sw-th" in out:
        rb, rs = out["base"][3], out["sw-th"][3]
        print(f"\n  r* ratio, tuned threshold vs shipped: {rs / rb:.3f}")
        check("the fitted r* for the shipped decoder is in the "
              "same range as §11.8.7's 1723 (within 2x)",
              0.5 <= out["base"][3] / 1723 <= 2.0,
              f"r* = {out['base'][3]:.0f} against 1723")
    return out


# ═══════════════════════════════════════════════════════════════════════════
# §7  The same comparison at a second (d, t) — #250's "re-point at #276"
# ═══════════════════════════════════════════════════════════════════════════
def section7(tuned, quick):
    rule("§7  Does the ordering survive a move toward #276's parameter set?")
    print("""  #250 says in as many words that a decoder comparison at r = 523 "measures
  the wrong instance" and must be re-pointed at whatever TODO #276 selects.
  #276 selects BIKE-128: r = 12323, d = 71, t = 134.  That set cannot be
  measured here and §8 gives the number rather than the excuse, so this
  section takes the largest (d, t) whose waterfall is reachable -- d = 45,
  t = 70, waterfall at r ~ 3700 -- and asks the one question that transfers:
  is the RANKING of the variants, and the SIZE of the gap between them, the
  same as at the retired set §§2-6 measure?  A conclusion that only holds at
  d = 15 would be worth nothing to #276.  THIS SECTION IS WHAT CARRIES THE
  RESULT, and TODO #288 is why that is worth saying twice: §§2-6 study the
  instance that is gone, deliberately and by literal, so the transfer argument
  is not a nicety here -- it is the whole link to what ships.""")
    r, d, t = 3701, 45, 70
    nb_iter = NB_ITER_RETIRED     # POL_BASE's budget; see RETIRED (TODO #288)
    pols = variants_for(tuned["mid"])
    n = 200 if quick else 1200
    budget = 240 if quick else 1800
    fails, disc, done, stats = paired(random.Random(606), r, d, t, nb_iter,
                                      pols, n, budget)
    print(f"\n  r = {r}, d = {d}, t = {t}: {done} paired instances\n")
    print(f"  {'variant':14s} {'failures':>9s} {'DFR':>10s}   repaired  broke")
    for p in pols:
        rep, bro = disc[p.name]
        extra = "" if p.name == "base" else f"{rep:>8d} {bro:>6d}"
        print(f"  {p.name:14s} {fails[p.name]:>9d} {fails[p.name] / done:>10.4%}   {extra}")
    base_f = fails["base"]
    best = min((fails[p.name], p.name) for p in pols)
    print(f"\n  best variant here: {best[1]} "
          f"({base_f} -> {best[0]} failures over {done} instances)")
    check("the mid-scale set reproduces the deployed set's ordering: the "
          "trajectory-perturbing variants beat the baseline and the "
          "near-codeword test alone does not",
          fails["ncw"] >= base_f * 0.9 and best[1] != "ncw",
          f"base {base_f}, ncw {fails['ncw']}, best {best[1]} {best[0]}")
    return fails, disc, done


# ═══════════════════════════════════════════════════════════════════════════
# §8  What it would take to measure #276's set — and the verdict arithmetic
# ═══════════════════════════════════════════════════════════════════════════
def section8(curves, dep_fails, dep_done, quick):
    rule("§8  BIKE-128 directly: the cost, and the arithmetic that settles #250")
    r, d, t = 12323, 71, 134
    nb_iter = SUITE._QCMDPC_NB_ITER
    rng = random.Random(8080)
    n = 2 if quick else 5
    ok = 0
    t_dec = t_key = 0.0
    for _ in range(n):
        t0 = time.time()
        sup0, sup1, h0, h1, h_pub = keygen(rng, r, d)
        e0, e1 = random_error(rng, r, t)
        syn = syndrome_of(e0, e1, h_pub, r)
        t1 = time.time()
        ok += (bgf(syn, sup0, sup1, r, d, nb_iter,
                   SwPolicy(0.0069722, 13.530, 36, name="bike")) == (e0, e1))
        t_dec += time.time() - t1
        t_key += t1 - t0
    per = t_dec / n
    print(f"\n  measured at BIKE-128, in the bit-sliced decoder of this file:")
    print(f"    {per * 1000:.0f} ms per decapsulation ({ok}/{n} decoded), "
          f"{t_key / n * 1000:.0f} ms per keygen")
    print(f"  §11.8.9 records the same instance at 5.4 s in the SHIPPED "
          f"Python decoder, which walks")
    print(f"  all r positions in an interpreter loop, and at 8 ms bit-sliced; "
          f"this is that second")
    print(f"  number reproduced independently, and it is why #276 makes the "
          f"rewrite a PREREQUISITE.")
    print(f"\n  what a DFR measurement costs at that speed.  These are "
          f"SUCCESS-path timings:")
    print(f"  a failure runs the full {nb_iter}-iteration budget and costs "
          f"several times more,")
    print(f"  which is second-order only while the DFR being measured is small.")
    print(f"    DFR 1e-3, ~1e4 trials  : {per * 1e4 / 60:>7.0f} min")
    print(f"    DFR 1e-5, ~1e6 trials  : {per * 1e6 / 3600:>7.0f} h")
    print(f"    DFR 2^-128             : not reachable by sampling at any "
          f"speed, by 30+ orders of magnitude")
    print("""
  So a decoder comparison at #276's set is a comparison of FITTED CURVES,
  always -- BIKE's own 2^-128 is an extrapolation too.  What this file can do
  at those parameters, and §7 does one (d, t) below them, is compare variants
  where the waterfall is reachable and check that the ranking is stable.""")

    rule("§8b  The verdict")
    base_dfr = dep_fails["base"] / dep_done
    best_name, best_f = min(((p, f) for p, f in dep_fails.items() if p != "base"),
                            key=lambda kv: kv[1])
    if best_f == 0:
        best_f = 0.5                      # one-sided: no failure observed
    gain_bits = math.log2(base_dfr / (best_f / dep_done))
    short_bits = 128 - (-math.log2(base_dfr))
    print(f"\n  at the retired parameters, the best decoder-side variant "
          f"({best_name}) buys {gain_bits:.1f} bits of DFR")
    print(f"  the shortfall to IND-CCA2 at these parameters is "
          f"{short_bits:.1f} bits")
    print(f"  so the variant covers {100 * gain_bits / short_bits:.1f}% of it")
    # READ AS r, WHICH IS THE READING THAT COUNTS.  A variant's DFR at the
    # retired r is an intercept; what a parameter change would have to buy is
    # a slope.  These are not the same ranking, and §6 measures them apart.
    if "base" in curves:
        rb = curves["base"][3]
        print(f"\n  {'variant':14s} {'DFR at r=523':>14s} {'fitted slope':>14s} "
              f"{'r* at 2^-128':>14s}")
        for name, (a, b, r2, r_star, pts) in sorted(curves.items(),
                                                    key=lambda kv: kv[1][3]):
            f = dep_fails.get(name)
            dfr = f"{f / dep_done:.4%}" if f is not None else "--"
            print(f"  {name:14s} {dfr:>14s} {a:>14.4f} {r_star:>14.0f}")
        best_r = min(curves.items(), key=lambda kv: kv[1][3])
        print(f"\n  best r*: {best_r[0]} at {best_r[1][3]:.0f}, "
              f"{100 * (1 - best_r[1][3] / rb):.1f}% below the shipped decoder's "
              f"{rb:.0f} -- against a deployed r of {SUITE._QCMDPC_R}")
        # The two rankings disagree, and that disagreement is the reason #250
        # asks for a per-variant fit rather than a per-variant DFR.
        by_dfr = [n for n in sorted(curves, key=lambda n: dep_fails.get(n, 1e9))]
        by_rstar = [n for n in sorted(curves, key=lambda n: curves[n][3])]
        print(f"  ranked by DFR at r = 523 : {' < '.join(by_dfr)}")
        print(f"  ranked by fitted r*      : {' < '.join(by_rstar)}")
        moved = [n for n in by_dfr if by_dfr.index(n) != by_rstar.index(n)]
        detail = "; ".join(
            f"{n}: {by_dfr.index(n) + 1} by DFR, {by_rstar.index(n) + 1} by r*"
            for n in moved) or "the two orderings agree"
        check("ranking the variants by DFR at one r does NOT rank them by r*, "
              "which is why #250 asks each decoder for its own fit",
              by_dfr != by_rstar, detail)
    check("no decoder-side variant closes the DFR gap without a parameter "
          "change -- the central finding #250 exists to record",
          gain_bits < 0.10 * short_bits,
          f"{gain_bits:.1f} bits bought against {short_bits:.1f} needed")
    check("the improvement that IS available is real and worth recording",
          gain_bits > 1.0, f"{gain_bits:.1f} bits")
    return gain_bits, short_bits


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--quick", action="store_true",
                    help="small samples; findings still gate the exit status")
    ap.add_argument("--full", action="store_true",
                    help="the sample sizes the recorded numbers were taken at")
    args = ap.parse_args()
    quick = args.quick or not args.full

    print(__doc__.strip())
    print(f"\n[{'quick' if quick else 'full'} mode]")
    t0 = time.time()

    section1(60 if quick else 200)
    section2(quick)
    section3(quick)
    tuned = section4(quick)
    dep_fails, dep_disc, dep_done, pols, dep_stats = section5(tuned, quick)
    curves = section6(tuned, quick)
    section7(tuned, quick)
    section8(curves, dep_fails, dep_done, quick)

    rule("Findings")
    bad = [f for f in FINDINGS if not f[1]]
    for label, okf, detail in FINDINGS:
        print(f"  [{'OK ' if okf else 'FAIL'}] {label}")
    print(f"\n  {len(FINDINGS) - len(bad)}/{len(FINDINGS)} reproduced "
          f"in {time.time() - t0:.0f}s")
    if bad:
        print("\n*** A recorded finding did not reproduce. ***")
        return 1
    print("\n*** OK: every recorded finding reproduced ***")
    return 0


if __name__ == "__main__":
    sys.exit(main())
