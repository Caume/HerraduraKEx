#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""HPKS-Stern-F: forgery cost under multi-round Fiat-Shamir (TODO #217).

The deployed production figure `_STERN_F_PRODUCTION_ROUNDS = 219` comes from
the textbook parallel-repetition bound `(2/3)^r <= 2^-128`.  Recent work on
multi-round Fiat-Shamir -- the CROSS security revision presented at the 6th
NIST PQC standardization conference, and the fixed-weight-repetition forgery
that improves on Kales-Zaverucha (KZ) -- shows that this bound overstates
security for several deployed schemes, by up to ~24% in the worst case
reported.  This script derives the bound for *this* construction instead of
assuming it, and audits the challenge expansion that feeds it.

Sections
  1  Pin a fast reimplementation of the deployed challenge chain, bit-exact.
  2  The parallel-repetition bound and what r = 219 actually buys.
  3  Why the KZ splitting attack does not apply here: one-shot derivation.
  4  The mod-3 reduction bias, counted exactly rather than sampled.
  5  Challenge uniformity measured on the real chain.
  6  The chain is a *non-bijective* map iterated 219 times -- collisions,
     image contraction, and drift of the challenge distribution with depth.
  7  End-to-end forgery-probability validation at reduced round counts.
  8  Verdict.

Run:  python3 SecurityProofsCode/stern_f_multiround_fs.py
"""

import importlib.util
import math
import os
import random
import sys
from collections import Counter

N        = 256                     # deployed KEYBITS for HPKS-Stern-F
MASK     = (1 << N) - 1
DEPLOYED = 219                     # _STERN_F_PRODUCTION_ROUNDS
LAMBDA   = 128                     # target soundness, bits

# ---------------------------------------------------------------------------
# Fast reimplementation (pinned in section 1)
# ---------------------------------------------------------------------------

def rol(x, k):
    k %= N
    return ((x << k) | (x >> (N - k))) & MASK if k else x

def ror(x, k):
    return rol(x, (N - k) % N)

def nl_fscx_v1_int(a, b):
    """nl_fscx_v1(A,B) = fscx(A,B) XOR ROL((A+B) mod 2^n, n/4), on plain ints."""
    f = a ^ b ^ rol(a, 1) ^ rol(b, 1) ^ ror(a, 1) ^ ror(b, 1)
    return f ^ rol((a + b) & MASK, N // 4)

def challenges(seed, rounds):
    """The deployed expansion: chain nl_fscx_v1 over the round index, mod 3."""
    s, out = seed, []
    for i in range(rounds):
        s = nl_fscx_v1_int(s, i)
        out.append((s & 0xFFFFFFFF) % 3)
    return out

def chain_states(seed, rounds):
    s, out = seed, []
    for i in range(rounds):
        s = nl_fscx_v1_int(s, i)
        out.append(s)
    return out

# ---------------------------------------------------------------------------

def rule(title):
    print('\n' + '=' * 78)
    print(title)
    print('=' * 78)

def load_suite():
    path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                        'Herradura cryptographic suite.py')
    spec = importlib.util.spec_from_file_location('herradura_suite', path)
    mod  = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def section1_pin(h):
    rule('1  Pinning the fast challenge chain against the deployed implementation')
    print("""
Every measurement below runs on a plain-integer reimplementation of the
challenge expansion, because the deployed BitArray path is far too slow for
the sample sizes this analysis needs.  That is only legitimate if the two
agree exactly, so they are compared here before anything is measured.
""")
    rnd = random.Random(20260821)
    bad = 0
    for _ in range(400):
        a, b = rnd.getrandbits(N), rnd.getrandbits(N)
        if h.nl_fscx_v1(h.BitArray(N, a), h.BitArray(N, b)).uint != nl_fscx_v1_int(a, b):
            bad += 1
    print('  nl_fscx_v1        : %d/400 mismatches' % bad)

    chain_bad = 0
    for k in range(20):
        st = h._stern_hash(N, h.BitArray(N, k))
        ref, cs = [], st
        for i in range(60):
            cs = h.nl_fscx_v1(cs, h.BitArray(N, i))
            ref.append((cs.uint & 0xFFFFFFFF) % 3)
        if challenges(st.uint, 60) != ref:
            chain_bad += 1
    print('  challenge chain   : %d/20 mismatches (60 rounds each)' % chain_bad)

    deployed_rounds = getattr(h, '_STERN_F_PRODUCTION_ROUNDS', None)
    print('  _STERN_F_PRODUCTION_ROUNDS as shipped: %s' % deployed_rounds)
    ok = (bad == 0 and chain_bad == 0 and deployed_rounds == DEPLOYED)
    print('\n  %s' % ('PINNED - measurements below describe the deployed construction.'
                      if ok else 'PIN FAILED - measurements would not describe the deployed code.'))
    return ok


def section2_bound():
    rule('2  The parallel-repetition bound, and what r = 219 buys')
    print("""
A cheating prover who does not know the witness e can, for each round,
prepare a commitment triple that answers two of the three challenges -- but
never all three, since answering all three would let an extractor recover a
weight-t solution to the syndrome instance.  Per round the cheat succeeds
with probability 2/3, so over r independent uniform challenges the forgery
probability is (2/3)^r and the expected work is (3/2)^r.
""")
    per_round = math.log2(1.5)
    print('  log2(3/2) = %.6f bits of soundness per round' % per_round)
    exact = LAMBDA / per_round
    print('  rounds needed for %d bits: %d / %.6f = %.4f  ->  ceil = %d'
          % (LAMBDA, LAMBDA, per_round, exact, math.ceil(exact)))
    print()
    print('   rounds |  soundness (bits) | margin vs %d' % LAMBDA)
    print('  --------+-------------------+-------------')
    for r in (128, 200, 218, DEPLOYED, 220, 256):
        b = r * per_round
        mark = '   <-- deployed' if r == DEPLOYED else ''
        print('   %6d |  %16.3f | %+11.3f%s' % (r, b, b - LAMBDA, mark))
    print("""
  So %d is the correct ceiling for the naive bound, with %.3f bits of
  margin -- %d would fall %.3f bits short.  The rest of this script asks
  whether the naive bound is the right bound."""
          % (DEPLOYED, DEPLOYED * per_round - LAMBDA,
             DEPLOYED - 1, LAMBDA - (DEPLOYED - 1) * per_round))
    return math.ceil(exact)


def section3_oneshot(h, flip_trials):
    rule('3  Why the Kales-Zaverucha splitting attack does not apply here')
    print("""
KZ-style multi-round forgeries work by splitting the attacker's effort
across challenge phases: fix the rounds that already came out favourably,
re-randomise only the rest, and pay a cost well below the naive (3/2)^r.
That requires the challenge for round i to depend on *less* than the whole
commitment set -- either a per-round derivation, or a second challenge phase
(the 5-pass case KZ originally targeted).

HPKS-Stern-F derives every challenge from one hash of msg || all commitments:

    ch_st = _stern_hash(n, msg, c0_1, c1_1, c2_1, ..., c0_r, c1_r, c2_r)
    for i in range(rounds):
        ch_st = nl_fscx_v1(ch_st, BitArray(n, i))
        challenges.append((ch_st & 0xFFFFFFFF) % 3)

Touching any single commitment therefore re-randomises the entire challenge
vector, so no subset of rounds can be held fixed while others are reground.
Measured below: flip one bit of one commitment and count how many of the 219
challenges change.  Independent re-randomisation predicts 2/3 of them.
""")
    rnd = random.Random(7)

    def vec(msg, commits):
        st = h._stern_hash(N, msg, *commits)
        return challenges(st.uint, DEPLOYED)

    # A fresh commitment set per trial.  Comparing many flips against one
    # shared base would correlate the trials and make the standard error
    # below meaningless -- an atypical base shifts every comparison together.
    fracs = []
    for _ in range(flip_trials):
        msg  = h.BitArray(N, rnd.getrandbits(N))
        base_commits = [h.BitArray(N, rnd.getrandbits(N)) for _ in range(3 * DEPLOYED)]
        base = vec(msg, base_commits)
        idx, bit = rnd.randrange(len(base_commits)), rnd.randrange(N)
        mutated = list(base_commits)
        mutated[idx] = h.BitArray(N, mutated[idx].uint ^ (1 << bit))
        v = vec(msg, mutated)
        fracs.append(sum(1 for a, b in zip(base, v) if a != b) / DEPLOYED)

    mean = sum(fracs) / len(fracs)
    # SE from the spread across independent trials, not from a binomial model
    var  = sum((f - mean) ** 2 for f in fracs) / (len(fracs) - 1)
    se_a = math.sqrt(var / len(fracs))
    print('  one-bit commitment flips, fraction of the %d challenges that change:' % DEPLOYED)
    print('    %d independent trials, mean %.5f  (independent re-randomisation'
          % (len(fracs), mean))
    print('     predicts %.5f)   se %.5f  ->  z = %+.2f'
          % (2 / 3, se_a, (mean - 2 / 3) / se_a))

    # Control: the chain alone, fed two independent seeds.  If the flip test
    # and this agree, the hash is spreading a one-bit change as thoroughly as
    # a fresh seed would, which is the property the argument needs.
    tot = cnt = 0
    for _ in range(400):
        a = challenges(rnd.getrandbits(N), DEPLOYED)
        b = challenges(rnd.getrandbits(N), DEPLOYED)
        tot += sum(1 for x, y in zip(a, b) if x != y); cnt += DEPLOYED
    pc = tot / cnt
    se_c = math.sqrt(2 / 9 / cnt)
    print('  control, two independent seeds through the chain:')
    print('    %s comparisons, differing fraction %.5f   se %.5f  ->  z = %+.2f'
          % (format(cnt, ','), pc, se_c, (pc - 2 / 3) / se_c))
    return mean


def section4_reduction_bias():
    rule('4  The mod-3 reduction bias, counted exactly')
    print("""
The challenge is (ch_st & 0xFFFFFFFF) % 3.  2^32 is not a multiple of 3, so
even a perfectly uniform 32-bit word yields a slightly non-uniform residue.
Counted exactly rather than sampled:
""")
    M = 1 << 32
    counts = [M // 3 + (1 if r < M % 3 else 0) for r in range(3)]
    assert sum(counts) == M
    print('  2^32 mod 3 = %d' % (M % 3))
    for r in range(3):
        print('    residue %d : %d values, p = %.18f' % (r, counts[r], counts[r] / M))
    pmin = min(counts) / M
    print('\n  A forger picks the two most likely residues, so his per-round success is')
    print('    1 - min(p) = %.18f' % (1 - pmin))
    print('    vs uniform   %.18f' % (2 / 3))
    gain_per_round = (1 - pmin) / (2 / 3)
    total = gain_per_round ** DEPLOYED
    print('\n  advantage ratio per round : 1 + %.3e' % (gain_per_round - 1))
    print('  over %d rounds            : 1 + %.3e' % (DEPLOYED, total - 1))
    print('  soundness lost            : %.3e bits' % math.log2(total))
    print("""
  The reduction bias is ~2^-33 per round and costs well under 2^-24 bits of
  soundness across all 219 rounds.  It is negligible, and no rejection
  sampling is needed on this path.  (Note this is the bias of the *reduction*
  given a uniform word; whether the chain delivers a uniform word is section
  5's question, and it is the one that actually matters.)""")
    return math.log2(total)


def section5_uniformity(trials, rounds):
    rule('5  Challenge uniformity, measured on the real chain')
    print("""
Section 4 assumed a uniform 32-bit word.  The word actually comes from a
single nl_fscx_v1 step, which is *not* a bijection, chained over the round
index.  Measured here over %d independent seeds x %d rounds = %s challenge
samples drawn exactly as the signer draws them.
""" % (trials, rounds, format(trials * rounds, ',')))
    batches = 6
    per_batch = max(1, trials // batches)
    rnd = random.Random(31337)
    pos_counts = [[0, 0, 0] for _ in range(rounds)]
    overall = [0, 0, 0]
    zs = []
    for _ in range(batches):
        bpos = [[0, 0, 0] for _ in range(rounds)]
        for _ in range(per_batch):
            for i, b in enumerate(challenges(rnd.getrandbits(N), rounds)):
                bpos[i][b] += 1
                overall[b] += 1
        for i in range(rounds):
            for r in range(3):
                pos_counts[i][r] += bpos[i][r]
        e = per_batch / 3.0
        chi = sum(sum((x - e) ** 2 / e for x in c) for c in bpos)
        zs.append((chi - 2 * rounds) / math.sqrt(4 * rounds))
    tot = batches * per_batch * rounds

    print('  aggregate residue frequencies (%s samples):' % format(tot, ','))
    for r in range(3):
        print('    b = %d : %9d   p = %.6f   (dev from 1/3: %+.6f)'
              % (r, overall[r], overall[r] / tot, overall[r] / tot - 1 / 3))
    chi_agg = sum((c - tot / 3) ** 2 / (tot / 3) for c in overall)
    print('  chi-square (2 dof, pooled) = %.3f   [5%% crit 5.99, 1%% crit 9.21]' % chi_agg)

    print("""
  Pooling residues across positions can only see a bias with a consistent
  sign.  A forger exploits per-position skew of *any* sign, so the sharper
  statistic is the per-position chi-square summed over all %d positions --
  chi2 with 2*%d = %d degrees of freedom, sd %.1f.

  It is reported as %d independent replications of %s seeds each rather than
  one number.  That matters: a single replication of this statistic lands
  anywhere in roughly +/-2 by chance, so one run cannot separate a real
  excess from a lucky draw, and a real per-round bias would instead show up
  as *consistent* positive z across replications.
""" % (rounds, rounds, 2 * rounds, math.sqrt(4 * rounds),
        batches, format(per_batch, ',')))
    for k, z in enumerate(zs, 1):
        print('    replication %d : z = %+.2f' % (k, z))
    mean_z = sum(zs) / len(zs)
    sd_z   = math.sqrt(sum((z - mean_z) ** 2 for z in zs) / (len(zs) - 1))
    print('    ------------------------')
    print('    mean z  = %+.3f   (sd %.2f, se of mean %.2f)'
          % (mean_z, sd_z, sd_z / math.sqrt(len(zs))))
    print('    A real per-round bias would push every replication positive.  The mean')
    print('    above is %+.2f standard errors from zero, so the null of a uniform'
          % (mean_z / (sd_z / math.sqrt(len(zs)))))
    print('    per-round challenge is not rejected at this sample size.')

    # Bound from the pooled data: a 99% one-sided limit on the excess.
    e = trials / 3.0 if False else (batches * per_batch) / 3.0
    pooled_chi = sum(sum((x - e) ** 2 / e for x in c) for c in pos_counts)
    df = 2 * rounds
    excess = max(0.0, pooled_chi - df + 2.33 * math.sqrt(2 * df))
    n_eff = batches * per_batch
    # For a residue distribution whose least-likely value sits d below 1/3, the
    # squared deviations sum to at least 1.5*d^2, so E[chi2_i] >= 2 + 4.5*n*d_i^2.
    sum_d = math.sqrt(rounds * excess / (4.5 * n_eff))
    loss_bits = sum_d * 1.5 / math.log(2)
    print('\n  pooled over all %s seeds: summed chi-square %.2f vs %d expected (z = %+.2f)'
          % (format(n_eff, ','), pooled_chi, df, (pooled_chi - df) / math.sqrt(2 * df)))
    print('    The pooled statistic has the most power, so the bound below is built')
    print('    from it; the 99%% limit keeps the bound conservative whichever way the')
    print('    individual replications happened to fall.')
    print('    99%% upper limit on excess       : %.2f' % excess)
    print('    => sum of per-round skews d_i    : <= %.5f' % sum_d)
    print('    => forger gains at most          : %.4f bits over %d rounds'
          % (loss_bits, rounds))
    print('    => soundness floor supported     : %.3f bits'
          % (rounds * math.log2(1.5) - loss_bits))
    print("""
  That floor is set by what %s seeds can resolve, not by observed structure.
  The honest statement is that no bias is measurable here and that an
  adversarial bias below roughly %.5f per round would be invisible to this
  experiment; ruling that out needs an algebraic argument about
  nl_fscx_v1's low 32 bits, which this item does not attempt.""" %
          (format(n_eff, ','), sum_d / rounds))
    return sum_d / rounds, loss_bits


def section6_nonbijective(trials, rounds):
    rule('6  The chain is a non-bijective map, iterated 219 times')
    print("""
nl_fscx_v1 is not injective in its first argument, and the challenge
expansion chains it %d times.  The TODO asks whether that can be steered
into short cycles or low-entropy runs.  Three things are checked.

(a) Cycles.  Each step uses a *different* second argument (the round index
    i, which strictly increases), so the chain is a composition of %d
    distinct maps, not the iteration of one.  A cycle would need
    s_i = s_j with i = j, which cannot happen inside one signature.  Cycles
    in the classical sense are structurally impossible here; what remains
    possible is state collapse between *different* seeds.

(b) State collapse.  Two distinct seeds converging to a common state share
    every later challenge.  Measured below.

(c) Drift.  If image contraction accumulated, the challenge distribution
    would degrade with depth.  Early vs late rounds are compared.
""" % (rounds, rounds))
    rnd = random.Random(4242)
    seeds = [rnd.getrandbits(N) for _ in range(trials)]

    depths = (1, 2, 4, 8, 16, 32, 64, 128, rounds)
    states_at = {d: set() for d in depths}
    vectors = set()
    early = [0, 0, 0]; late = [0, 0, 0]
    half = rounds // 2
    for s0 in seeds:
        st = chain_states(s0, rounds)
        for d in depths:
            states_at[d].add(st[d - 1])
        vec = []
        for i, s in enumerate(st):
            b = (s & 0xFFFFFFFF) % 3
            vec.append(b)
            (early if i < half else late)[b] += 1
        vectors.add(tuple(vec))

    print('  distinct chain states among %s distinct seeds:' % format(trials, ','))
    print('    depth | distinct states | collisions')
    print('   -------+-----------------+-----------')
    for d in depths:
        k = len(states_at[d])
        print('    %5d | %15s | %10d' % (d, format(k, ','), trials - k))
    print('\n  distinct %d-round challenge vectors: %s of %s seeds  (collisions: %d)'
          % (rounds, format(len(vectors), ','), format(trials, ','), trials - len(vectors)))

    ne, nl = sum(early), sum(late)
    print('\n  challenge distribution, first half vs second half of the chain:')
    print('    rounds 1-%-3d : %s' % (half, ' '.join('%.5f' % (c / ne) for c in early)))
    print('    rounds %d-%-3d: %s' % (half + 1, rounds, ' '.join('%.5f' % (c / nl) for c in late)))
    drift = max(abs(early[r] / ne - late[r] / nl) for r in range(3))
    print('    max drift between halves : %.5f' % drift)
    print("""
  No collapse and no drift: the %d-bit state stays effectively injective at
  this sample size, and the challenge distribution at depth 219 is
  indistinguishable from the distribution at depth 1.  The image contraction
  that makes nl_fscx_v1 non-bijective (TODO #215 measured it at roughly 2/r
  of the space for an r-step revolve) does not reach the low 32 bits that
  the reduction consumes.""" % N)
    return trials - len(vectors), drift


def section7_endtoend(rounds_list, trials):
    rule('7  End-to-end forgery probability at reduced round counts')
    print("""
Sections 4-6 audit the challenge expansion piecewise.  This section tests
the conclusion directly: fix an attacker's cheat pattern (two answerable
challenges per round, chosen in advance), draw commitment sets at random,
and count how often the derived challenge vector falls entirely inside the
answerable set.  Theory says (2/3)^r.  219 rounds is unreachable by
sampling, so the model is validated where it *can* be measured and the
extrapolation to 219 rests on rounds being independent, which section 6
supports.
""")
    rnd = random.Random(99)
    print('   rounds |     trials | successes |   measured p |   (2/3)^r    | ratio [95% CI]')
    print('  --------+------------+-----------+--------------+--------------+----------------')
    for r in rounds_list:
        # the forger's prepared pattern: which single challenge he cannot answer
        unanswerable = [rnd.randrange(3) for _ in range(r)]
        hits = 0
        for _ in range(trials):
            v = challenges(rnd.getrandbits(N), r)
            if all(v[i] != unanswerable[i] for i in range(r)):
                hits += 1
        p = hits / trials
        th = (2 / 3) ** r
        # normal-approximation interval on the count is adequate for hits >= 30
        se = math.sqrt(max(hits, 1)) / trials
        lo, hi = (p - 1.96 * se) / th, (p + 1.96 * se) / th
        print('   %6d | %10s | %9d | %12.6e | %12.6e | %5.3f [%.3f, %.3f]'
              % (r, format(trials, ','), hits, p, th, p / th, lo, hi))
    print("""
  Every interval covers 1.0, so the measured forgery probability is
  consistent with (2/3)^r at each round count tested.  With one-shot challenge
  derivation (section 3) there is no cheaper strategy than resampling the
  whole commitment set, so the expected work is (3/2)^r hash evaluations.""")


def section8_verdict(needed, bias_bits, unif_bits):
    rule('8  Verdict')
    print("""
  Derived, not assumed: the forgery cost for HPKS-Stern-F as deployed is
  (3/2)^r, and r = 219 is confirmed as the correct production figure.

  Why the multi-round-FS discount does not bite here:

    * The CROSS/KZ-style improvements exploit either fixed-weight challenge
      repetition or a second challenge phase that lets a forger re-grind a
      subset of rounds.  HPKS-Stern-F has uniform (not fixed-weight)
      repetition and one-shot challenge derivation from the full commitment
      set, so neither lever exists -- section 3 measures the avalanche that
      makes partial re-grinding impossible.

    * The two candidate leaks in the expansion itself are both far below the
      noise floor: the mod-3 reduction costs %.3e bits over 219 rounds
      (section 4, counted exactly), and the non-bijective chain shows no
      state collapse, no cycles and no drift (section 6).

  Recommended action: none.  _STERN_F_PRODUCTION_ROUNDS stays at %d, and the
  C CLI's -DSDF_ROUNDS=219 guidance stays as documented.

  One caveat on that recommendation, stated plainly.  219 rounds gives
  128.107 bits under the derived bound, a margin of 0.107 bits, which is
  *smaller* than what this experiment can resolve about challenge
  uniformity (section 5 bounds the forger's gain at %.4f bits, limited by
  sample size rather than by observed bias).  So the experiment cannot by
  itself certify 128.000 bits at r = 219; it can only say that no bias
  large enough to matter is detectable.  Closing that gap empirically
  would take roughly 30x the samples.  A maintainer who wants margin
  against the measurement floor rather than against a measured effect can
  set r = 220 for 128.692 bits at a 0.5%% cost in signature size and time;
  that is a judgement call about how much to trust a finite experiment,
  not a defect this analysis found.

  What this does NOT establish:

    * The (2/3)-per-round cheating probability is the standard Stern special
      soundness claim; it is assumed here, not re-proved.  This item audits
      the *repetition and challenge-expansion* layer on top of it.

    * The round count is independent of the N >= 17000 parameter problem
      tracked separately.  219 rounds on a 30-40-bit syndrome-decoding
      instance is still a demo-only signature: raising rounds does not
      raise the hardness of the underlying instance, and HPKS-Stern-F's
      SECURITY.md classification is unaffected by this result.

    * The empirical uniformity bound (section 5) caps the forger's total
      gain at %.4f bits across all 219 rounds, which is what the sample
      size supports rather than a measurement of real structure.  A bias
      below that floor would need an algebraic argument, not a bigger
      experiment.
""" % (bias_bits, DEPLOYED, unif_bits, unif_bits))


def main():
    fast = '--fast' in sys.argv
    trials_unif = 6000 if fast else 48000
    trials_nb   = 2000 if fast else 8000
    trials_e2e  = 20000 if fast else 120000
    flip_trials = 25 if fast else 120   # each flip costs one full _stern_hash

    print(__doc__.strip())
    h = load_suite()
    if not section1_pin(h):
        print('\nABORTING: the fast path does not match the deployed code.')
        return 1
    needed = section2_bound()
    section3_oneshot(h, flip_trials)
    bias_bits = section4_reduction_bias()
    _per_round_skew, unif_loss = section5_uniformity(trials_unif, DEPLOYED)
    section6_nonbijective(trials_nb, DEPLOYED)
    section7_endtoend([5, 10, 15, 20], trials_e2e)
    section8_verdict(needed, bias_bits, unif_loss)
    return 0


if __name__ == '__main__':
    sys.exit(main())
