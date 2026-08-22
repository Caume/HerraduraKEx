#!/usr/bin/env python3
"""
stern_f_round_count_resolution.py — closing TODO #217's resolution gap on the
HPKS-Stern-F round count (TODO #222, §11.8.8).

TODO #217 confirmed r = 219 = ceil(128 / log2(3/2)) and found no measurable bias
in the Fiat-Shamir challenge expansion, but left a gap it could not close from
the inside:

    (3/2)^219 gives 128.107 bits  -- a margin of 0.107 bits over target
    that analysis could only resolve biases above 0.4418 bits

So it could not certify 128.000 bits at r = 219, and TODO #222 was opened to
decide between moving the production figure to 220 or documenting the margin as
an accepted assumption.

Both options take the 0.44-bit floor as given.  It is not: that floor is a
*sample-size* limit, not observed structure.  The bound is

    sum_d  <=  sqrt(rounds * excess / (4.5 * n))          [n = seeds]
    loss   =   sum_d * 1.5 / ln 2

so it shrinks as 1/sqrt(n).  TODO #217 used 48,000 seeds.  Resolving 0.107 bits
needs about 1.4 million, which is minutes of compute -- so the honest third
option is to measure harder rather than to move a deployed security parameter to
accommodate an experiment's limitations.

  §1  The resolution model, and how many seeds the margin actually needs
  §2  The measurement at scale, replicated
  §3  Verdict

Methodology is TODO #217's, unchanged: the per-position chi-square summed over
all 219 positions (df = 2*219), reported as independent replications so a real
per-round bias shows as consistently positive z rather than one lucky draw, with
a 99% one-sided limit on the excess turned into a bound on the forger's gain.
The challenge expansion is imported from stern_f_multiround_fs.py rather than
reimplemented, so the two cannot drift.

Runtime: ~25 min at the default 3,000,000 seeds across 8 workers; --quick runs
200,000 (~20 s) and reproduces the shape but not the verdict.
"""

import argparse
import importlib.util
import math
import os
import random
import sys
from concurrent.futures import ProcessPoolExecutor

_HERE = os.path.dirname(os.path.abspath(__file__))


def _load_217():
    """Import TODO #217's script so the challenge expansion is shared, not copied."""
    path = os.path.join(_HERE, 'stern_f_multiround_fs.py')
    spec = importlib.util.spec_from_file_location('stern_f_multiround_fs', path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


S = _load_217()
ROUNDS = S.DEPLOYED
TARGET_BITS = 128.0
MARGIN = ROUNDS * math.log2(1.5) - TARGET_BITS


def rule(title):
    print()
    print('=' * 78)
    print(title)
    print('=' * 78)


def _batch(args):
    """Tally per-position residue counts for one batch of seeds."""
    seed, count = args
    rnd = random.Random(seed)
    pos = [[0, 0, 0] for _ in range(ROUNDS)]
    for _ in range(count):
        for i, b in enumerate(S.challenges(rnd.getrandbits(S.N), ROUNDS)):
            pos[i][b] += 1
    return pos


def loss_bits_for(n_eff, excess):
    """TODO #217's bound: excess chi-square -> summed per-round skew -> bits."""
    sum_d = math.sqrt(ROUNDS * excess / (4.5 * n_eff))
    return sum_d, sum_d * 1.5 / math.log(2)


def section1():
    rule('1  The resolution model')
    df = 2 * ROUNDS
    null_excess = 2.33 * math.sqrt(2 * df)
    print(f"""
  r = {ROUNDS} gives {ROUNDS * math.log2(1.5):.3f} bits, a margin of {MARGIN:.3f} over {TARGET_BITS:.0f}.

  The bound TODO #217 reports is built from the summed per-position chi-square
  (df = 2*{ROUNDS} = {df}).  Under the null its 99% one-sided excess is
  2.33*sqrt(2*df) = {null_excess:.1f}, and that converts to a bound on the forger's gain
  which falls as 1/sqrt(seeds):
""")
    print(f"    {'seeds':>12} {'resolution floor':>18}   {'vs the 0.107-bit margin':>24}")
    print('    ' + '-' * 60)
    for n in (48_000, 200_000, 500_000, 1_000_000, 1_400_000, 3_000_000):
        _, lb = loss_bits_for(n, null_excess)
        verdict = 'resolves it' if lb < MARGIN else 'cannot resolve it'
        tag = '   <-- TODO #217' if n == 48_000 else ''
        print(f"    {n:>12,} {lb:>17.4f}b   {verdict:>24}{tag}")
    n_need = ROUNDS * null_excess / (4.5 * (MARGIN * math.log(2) / 1.5) ** 2)
    print(f"""
  Seeds needed to bring the floor under the margin: {n_need:,.0f}.

  Those are *expected* floors: they assume the chi-square lands at its 99% null
  limit.  §2's bound uses the excess actually observed, so it comes out lower
  when the statistic falls below expectation and higher when it runs hot.  The
  table says how many seeds to budget, not what §2 will print.

  That is the whole of TODO #222's difficulty — not a property of the round
  count, but of how long TODO #217 ran.  §2 runs it longer.
""")
    return null_excess


def section2(total, workers, quick):
    rule('2  The measurement at scale')
    reps = 6
    per_rep = total // reps
    per_worker = max(1, per_rep // workers)
    print(f"""
  {total:,} seeds x {ROUNDS} rounds = {total * ROUNDS:,} challenge samples, drawn
  exactly as the signer draws them, in {reps} independent replications of
  {per_rep:,} seeds each.  A real per-round bias pushes every replication
  positive; noise scatters them around zero.
""")
    df = 2 * ROUNDS
    sd = math.sqrt(2 * df)
    pooled = [[0, 0, 0] for _ in range(ROUNDS)]
    zs = []
    with ProcessPoolExecutor(max_workers=workers) as ex:
        for k in range(reps):
            jobs = [(1_000_000 * (k + 1) + w, per_worker) for w in range(workers)]
            rep = [[0, 0, 0] for _ in range(ROUNDS)]
            for part in ex.map(_batch, jobs):
                for i in range(ROUNDS):
                    for r in range(3):
                        rep[i][r] += part[i][r]
                        pooled[i][r] += part[i][r]
            n_rep = per_worker * workers
            e = n_rep / 3.0
            chi = sum(sum((x - e) ** 2 / e for x in c) for c in rep)
            z = (chi - df) / sd
            zs.append(z)
            print(f'    replication {k + 1} : {n_rep:>9,} seeds   chi2 = {chi:9.1f}   z = {z:+.2f}',
                  flush=True)

    n_eff = per_worker * workers * reps
    mean_z = sum(zs) / len(zs)
    sd_z = math.sqrt(sum((z - mean_z) ** 2 for z in zs) / (len(zs) - 1))
    se = sd_z / math.sqrt(len(zs))
    e = n_eff / 3.0
    pooled_chi = sum(sum((x - e) ** 2 / e for x in c) for c in pooled)
    z_pooled = (pooled_chi - df) / sd
    excess = max(0.0, pooled_chi - df + 2.33 * math.sqrt(2 * df))
    sum_d, loss = loss_bits_for(n_eff, excess)
    floor = ROUNDS * math.log2(1.5) - loss

    print(f"""
    ------------------------------------------------------------
    mean z over replications : {mean_z:+.3f}   (sd {sd_z:.2f}, se {se:.2f}, {mean_z / se if se else 0:+.2f} se from zero)
    pooled over {n_eff:,} seeds : chi2 = {pooled_chi:.1f} vs {df} expected, z = {z_pooled:+.2f}

    99% upper limit on excess     : {excess:.2f}
    => summed per-round skew d_i  : <= {sum_d:.6f}   ({sum_d / ROUNDS:.3e} per round)
    => forger gains at most       : {loss:.4f} bits over {ROUNDS} rounds
    => soundness floor supported  : {floor:.3f} bits
""")
    return loss, floor, mean_z, se


def section3(loss, floor, mean_z, se, quick):
    rule('3  Verdict')
    resolves = loss < MARGIN
    print(f"""
  margin at r = {ROUNDS}          : {MARGIN:.3f} bits over {TARGET_BITS:.0f}
  resolution floor now        : {loss:.4f} bits   (TODO #217: 0.4418)
  soundness floor supported   : {floor:.3f} bits
""")
    if quick:
        print("  --quick was used: this run is a shape check, not the verdict.\n"
              "  Re-run at the default seed count before citing anything here.")
        return
    if not resolves:
        print(f"""  The floor is still above the {MARGIN:.3f}-bit margin, so this run does NOT
  settle TODO #222.  Increase the seed count and re-run.""")
        return
    print(f"""  The experiment now resolves biases well below the margin it needs to clear,
  and finds none: the replications scatter around zero ({mean_z:+.2f} se from it),
  and the pooled 99% limit supports a soundness floor of {floor:.3f} bits — above
  {TARGET_BITS:.0f}.

  **Keep r = {ROUNDS}.**  The case for moving to 220 rested entirely on TODO #217
  being unable to resolve the margin; at this sample size it can, and there is
  nothing there.  Moving a deployed parameter to compensate for an experiment's
  sample size would have been the wrong response, and 220 buys nothing measurable
  for its ~0.5% cost in signature size and verification time.

  What this does NOT establish: that no bias exists, only that none above
  {loss:.4f} bits does.  An adversarial bias engineered below that is still
  invisible here, and ruling it out needs an algebraic argument about
  nl_fscx_v1's low 32 bits rather than more samples.  TODO #217 said the same
  about its own floor; the floor is simply {0.4418 / loss:.0f}x lower now.
""")


def main():
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[1])
    ap.add_argument('--seeds', type=int, default=3_000_000,
                    help='total seeds (default 3,000,000)')
    ap.add_argument('--quick', action='store_true',
                    help='200,000 seeds, ~20 s — shape only, not the verdict')
    ap.add_argument('--workers', type=int, default=min(8, os.cpu_count() or 1))
    args = ap.parse_args()
    total = 200_000 if args.quick else args.seeds

    print(__doc__.split('\n', 1)[1].split('  §1')[0].strip())
    section1()
    loss, floor, mean_z, se = section2(total, args.workers, args.quick)
    section3(loss, floor, mean_z, se, args.quick)
    return 0


if __name__ == '__main__':
    sys.exit(main())
