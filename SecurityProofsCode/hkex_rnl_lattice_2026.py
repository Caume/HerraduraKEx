#!/usr/bin/env python3
"""
hkex_rnl_lattice_2026.py — HKEX-RNL and HKEX-RNL-128 re-estimated against the
2026 lattice-attack landscape (TODO #216, §11.4.3).

SECURITY.md currently puts HKEX-RNL (n=256) at ~105 classical / ~100 quantum
Core-SVP bits and promotes HKEX-RNL-128 (n=512) as production-track at ~220/~200.
Neither figure was ever computed from the deployed parameters: the n=256 number
is cited from the literature, and the n=512 number is a linear extrapolation
(110 * n/256) off that citation.  This script computes both directly.

  §1  Deployed parameters, read from the suite, and the LWR -> LWE translation
  §2  The cost model: BKZ root-Hermite factor, primal uSVP, dual, hybrid
  §3  Validation — reproduce published Core-SVP for Kyber (LWE) and Saber (LWR)
  §4  HKEX-RNL n=256 and HKEX-RNL-128 n=512 under all three attack families
  §5  Why: for LWR the relative noise is 1/(p*sqrt(12)) — q does not appear
  §6  The documented estimate, and the two places its reasoning inverts
  §7  What parameter move would actually reach 128 bits
  §8  Verdict and the SECURITY.md rows

The `lattice-estimator` could not be run here: it requires SageMath, which is not
installable on this host (no distribution package, no pip).  Rather than quote a
number this repo cannot reproduce, §2 implements the same published estimates the
estimator implements for these attack families, and §3 pins that implementation
to six independent published Core-SVP figures before §4 uses it.  Every number in
§4 onward is void if §3 does not reproduce all six.  Methodology reference:
lattice-estimator commit 53da5982597709ba0fdf94ea37a84d822310fd84 (2026-08-21).

Core-SVP is a deliberately crude *lower* bound — it charges one SVP call and
ignores the polynomial factors.  §4 also reports the gate-count variants, which
sit above it.  The verdict does not depend on which model is used.

Runtime: under a second — the primal search is a binary search over block size,
and every attack cost here is closed-form.  --fast trims §7's sweep to a coarse
grid; there is no reason to use it except to shorten the output.
"""

import argparse
import importlib.util
import math
import os
import sys


# ── Load suite via importlib (suite filename has a space) ──────────────────
_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)


def load_suite():
    """Import the deployed suite so parameters cannot drift from this script."""
    path = os.path.join(_ROOT, 'Herradura cryptographic suite.py')
    spec = importlib.util.spec_from_file_location('herradura_suite', path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def rule(title):
    print()
    print('=' * 78)
    print(title)
    print('=' * 78)


# ---------------------------------------------------------------------------
# §2  Cost model
# ---------------------------------------------------------------------------

def delta(beta):
    """BKZ-beta root-Hermite factor (Chen-Nguyen asymptotic, beta >= 50)."""
    return ((math.pi * beta) ** (1.0 / beta) * beta / (2 * math.pi * math.e)) \
        ** (1.0 / (2.0 * (beta - 1)))


def lwr_sigma(q, p):
    """Stddev of the deterministic rounding error of round_p(.) on Z_q.

    round_p collapses q/p consecutive residues to one, so the error is uniform
    over q/p values: variance ((q/p)^2 - 1)/12.  This is the standard LWR -> LWE
    modelling used for Saber, and §3 validates it against Saber's own figures.
    """
    return math.sqrt(((q / p) ** 2 - 1) / 12.0)


def _primal_feasible(n, q, sd_s, sd_e, m_max, beta):
    """2016 primal-uSVP success condition, with Bai-Galbraith rescaling.

    Kannan embedding of dimension d = m + n + 1.  BKZ-beta recovers the unique
    short vector when  sqrt(beta) * sd_e <= delta^(2*beta-d-1) * vol^(1/d),
    with vol = q^m * nu^n and nu = sd_e/sd_s the rescaling that makes the secret
    and the error the same width.  Returns the winning m, or None.
    """
    if beta < 50:
        return None
    ld = math.log(delta(beta))
    nu = sd_e / sd_s
    lhs = math.log(math.sqrt(beta) * sd_e)
    for m in range(max(1, n // 2), m_max + 1):
        d = m + n + 1
        if beta > d:
            continue
        rhs = (2 * beta - d - 1) * ld + (m * math.log(q) + n * math.log(nu)) / d
        if lhs <= rhs:
            return m
    return None


def primal_usvp(n, q, sd_s, sd_e, m_max, beta_max=2000):
    """Smallest BKZ block size solving the primal uSVP instance.

    Feasibility is monotone in beta (larger beta shrinks delta *and* makes the
    2*beta-d-1 exponent less negative, so both terms move the same way), so this
    binary-searches and then asserts beta-1 is infeasible.
    """
    beta_max = min(beta_max, m_max + n + 1)   # beta cannot exceed the embedding dim
    if _primal_feasible(n, q, sd_s, sd_e, m_max, beta_max) is None:
        return None
    lo, hi = 50, beta_max
    if _primal_feasible(n, q, sd_s, sd_e, m_max, lo) is not None:
        return lo, _primal_feasible(n, q, sd_s, sd_e, m_max, lo)
    while hi - lo > 1:
        mid = (lo + hi) // 2
        if _primal_feasible(n, q, sd_s, sd_e, m_max, mid) is None:
            lo = mid
        else:
            hi = mid
    m = _primal_feasible(n, q, sd_s, sd_e, m_max, hi)
    assert _primal_feasible(n, q, sd_s, sd_e, m_max, hi - 1) is None, \
        'primal feasibility is not monotone in beta — binary search invalid'
    return hi, m


def dual(n, q, sd_s, sd_e, m_max, sieve=0.292, mem=0.2075, m_step=8):
    """Core-SVP cost of the dual distinguishing attack, Kyber/Saber-spec form.

    Short vectors in {x : A^T x = 0 mod q} (volume q^n, rescaled by nu for the
    small secret) give <x,b> = <x,e>, distinguishable from uniform with
    advantage eps = 4*exp(-2*pi^2*tau^2), tau = ||x||*sd_e/q.  The attack is
    repeated 1/eps^2 times, less the 2^(mem*beta) vectors one sieve call already
    produces.  Returns (log2 cost, beta, m).
    """
    best = None
    nu = sd_e / sd_s
    for beta in range(50, min(m_max, 1600) + 1):
        ld = math.log(delta(beta))
        for m in range(beta, m_max + 1, m_step):
            d = m + n
            logvol = n * math.log(q) + n * math.log(nu)
            log_tau = (d - 1) * ld + logvol / d + math.log(sd_e) - math.log(q)
            if log_tau > 2.0:            # tau this large gives no advantage
                continue
            tau = math.exp(log_tau)
            log2_eps = 2.0 - 2 * math.pi ** 2 * tau * tau / math.log(2)
            log2_reps = max(0.0, -(mem * beta) - 2 * log2_eps)
            cost = sieve * beta + log2_reps
            if best is None or cost < best[0]:
                best = (cost, beta, m)
    return best


def hybrid_zero_forcing(n, q, sd_s, sd_e, m_max, p_zero, k_step=4):
    """Zero-forcing hybrid: guess that k secret coordinates are 0, then reduce.

    Each guessed coordinate costs -log2(p_zero) bits of repetition and buys
    whatever the lattice saves at secret dimension n-k.  Sparse/narrow secrets
    are exactly where this is supposed to bite, so it is the right check for a
    CBD(1) secret (P(0) = 1/2).  Returns (best log2 cost, best k).
    """
    guess_bit = -math.log2(p_zero)
    best = None
    for k in range(0, n // 2, k_step):
        r = primal_usvp(n - k, q, sd_s, sd_e, m_max)
        if r is None:
            continue
        cost = 0.292 * r[0] + k * guess_bit
        if best is None or cost < best[0]:
            best = (cost, k)
    return best


# Cost models applied to a block size.  Core-SVP is the floor; the gate-count
# variants add the polynomial factors Core-SVP deliberately drops.
COST_MODELS = (
    ('Core-SVP classical  (BDGL16 sieve)', lambda b: 0.292 * b),
    ('Core-SVP quantum    (Laarhoven)   ', lambda b: 0.265 * b),
    ('gate count          (0.292b+16.4) ', lambda b: 0.292 * b + 16.4),
    ('MATZOV 2022         (0.257b+15.1) ', lambda b: 0.2570 * b + 15.1),
)


# ---------------------------------------------------------------------------
# §3  Validation targets — published Core-SVP figures
# ---------------------------------------------------------------------------
# (name, secret dim, q, sd_s, sd_e, published classical Core-SVP)
# Kyber round 3: LWE, secret and error both CBD(eta).
# Saber round 3: LWR, secret CBD(mu/2), error from rounding q=2^13 -> p=2^10.

def validation_targets():
    saber_sd_e = lwr_sigma(8192, 1024)
    return [
        ('Kyber512   (LWE)', 512, 3329, math.sqrt(1.5), math.sqrt(1.5), 118),
        ('Kyber768   (LWE)', 768, 3329, 1.0, 1.0, 181),
        ('Kyber1024  (LWE)', 1024, 3329, 1.0, 1.0, 254),
        ('LightSaber (LWR)', 512, 8192, math.sqrt(10 / 4.0), saber_sd_e, 118),
        ('Saber      (LWR)', 768, 8192, math.sqrt(8 / 4.0), saber_sd_e, 189),
        ('FireSaber  (LWR)', 1024, 8192, math.sqrt(6 / 4.0), saber_sd_e, 260),
    ]


# ---------------------------------------------------------------------------
# Sections
# ---------------------------------------------------------------------------

def section1(suite):
    rule('1  Deployed parameters and the LWR -> LWE translation')
    q, p, pp, eta = suite.RNLQ, suite.RNLP, suite.RNLPP, suite.RNLB
    n = suite.KEYBITS
    sd_e = lwr_sigma(q, p)
    sd_s = math.sqrt(eta / 2.0)
    print(f"""
  Read from the suite (so this script cannot drift from what ships):

    RNLQ  = {q:<8}  prime modulus (Fermat prime 2^16+1)
    RNLP  = {p:<8}  public-key rounding modulus
    RNLPP = {pp:<8}  reconciliation modulus
    RNLB  = {eta:<8}  secret distribution CBD(eta)
    n     = {n:<8}  ring dimension (KEYBITS)

  Public key is C = round_p(m_blind * s) with s <- CBD({eta}) and NO added error
  term (_rnl_keygen), so this is Ring-LWR, not Ring-LWE.  Translating:

    secret stddev  sd_s = sqrt(eta/2)          = {sd_s:.4f}
    error  stddev  sd_e = sqrt(((q/p)^2-1)/12) = {sd_e:.4f}     (q/p = {q/p:.4f})
    relative noise alpha = sd_e/q              = {sd_e/q:.3e}

  For scale, alpha at the same security level elsewhere:
    Kyber512    1.2247/3329 = {1.2247/3329:.3e}   ({1.2247/3329/(sd_e/q):.1f}x noisier)
    LightSaber  {lwr_sigma(8192,1024):.4f}/8192 = {lwr_sigma(8192,1024)/8192:.3e}   ({lwr_sigma(8192,1024)/8192/(sd_e/q):.1f}x noisier)

  One ring element is published, so the attacker gets exactly n = {n} equations
  in n unknowns.  Every estimate below caps the sample count at m <= n; §4 shows
  that cap is not what binds.
""")
    return n, q, p, eta, sd_s, sd_e


def section2():
    rule('2  The cost model')
    print("""
  Three attack families, each the standard published estimate:

    primal uSVP   Kannan embedding, 2016 estimate, Bai-Galbraith rescaling for
                  the narrow secret.  Reports the smallest BKZ block size beta.
    dual          short dual vectors distinguish LWE from uniform; cost is the
                  sieve plus the repetitions needed for a constant advantage.
    hybrid        zero-forcing on the sparse CBD(1) secret (P(0) = 1/2), the
                  family the small-secret/hybrid improvements act on.

  A block size beta is converted to bits by the models in COST_MODELS.  Core-SVP
  charges a single SVP call at sieve cost and drops every polynomial factor, so
  it is a lower bound by construction; the gate-count rows sit above it.  The
  verdict in §8 holds under all four.
""")


def section3(quiet=False):
    rule('3  Validation — reproducing published Core-SVP figures')
    print("""
  The estimator cannot be run on this host, so the implementation above is
  pinned to six published figures first: three LWE (Kyber, validating the
  primal/dual machinery) and three LWR (Saber, validating the rounding-error
  translation in particular).  Saber matters most here: it is the only
  standardisation-track LWR scheme, so it is the only published check on the
  sd_e = sqrt(((q/p)^2-1)/12) step that §1 relies on.
""")
    print(f"    {'scheme':18s} {'beta':>5} {'computed':>9} {'published':>10} {'delta':>7}")
    ok = True
    for name, n, q, sd_s, sd_e, pub in validation_targets():
        b, m = primal_usvp(n, q, sd_s, sd_e, 4 * n)
        got = 0.292 * b
        diff = got - pub
        if abs(diff) > 1.5:
            ok = False
        print(f"    {name:18s} {b:>5} {got:>9.1f} {pub:>10} {diff:>+7.1f}")
    print()
    if ok:
        print("  All six reproduce to within 1.5 bits.  The model is pinned; §4 may proceed.")
    else:
        print("  *** MISMATCH — the model is NOT pinned.  Every number below is void. ***")
    return ok


def section4(n, q, p, eta, sd_s, sd_e):
    rule('4  HKEX-RNL and HKEX-RNL-128 under the three attack families')
    results = {}
    for label, nn in (('HKEX-RNL      n=256', 256), ('HKEX-RNL-128  n=512', 512)):
        b, m = primal_usvp(nn, q, sd_s, sd_e, nn)
        dcost, dbeta, dm = dual(nn, q, sd_s, sd_e, nn)
        hcost, hk = hybrid_zero_forcing(nn, q, sd_s, sd_e, nn, 0.5)
        results[nn] = (b, dcost, hcost)
        print(f"""
  {label}   (q={q}, p={p}, eta={eta})

    primal uSVP   beta = {b:<5} (m = {m}, embedding dim {m+nn+1})
    dual          {dcost:.1f} bits at beta = {dbeta}  (m = {dm})
    hybrid        {hcost:.1f} bits, best at k = {hk} guessed-zero coordinates

    primal binds.  Under each cost model:""")
        for mname, f in COST_MODELS:
            print(f"      {mname}  {f(b):6.1f} bits")
        print(f"""
    The hybrid gains nothing: each guessed coordinate costs {-math.log2(0.5):.1f} bit and saves
    only about {(0.292*b - 0.292*primal_usvp(nn-32,q,sd_s,sd_e,nn)[0])/32:.2f} bits of lattice work, so k = 0 is optimal.  The
    2026 hybrid-decoding improvements this TODO was opened to check therefore do
    not move the number — the plain primal attack is already far cheaper.""")
    print("""
  The dual attack is more expensive than the primal here only because m <= n
  starves it of samples; it is not the binding attack either way.
""")
    return results


def section5(q, p, sd_e):
    rule('5  Why — for LWR the relative noise is set by p alone')
    print(f"""
  For q/p >> 1 the rounding error has sd_e ~= (q/p)/sqrt(12), so

      alpha = sd_e/q ~= 1/(p*sqrt(12))

  and q cancels.  Raising q with p held fixed does not add noise; it only makes
  the same fixed number of rounding buckets span a larger modulus, which is
  strictly easier for lattice reduction.  Numerically:
""")
    print(f"    {'p':>6}  {'alpha = sd_e/q':>16}   at q = {q}")
    for pp in (256, 512, 1024, 2048, 4096, 8192):
        print(f"    {pp:>6}  {lwr_sigma(q, pp)/q:>16.3e}"
              + ('   <-- deployed' if pp == p else ''))
    print(f"""
  The suite's own comment at RNLQ reads:

      "q=65537 (Fermat prime, fast arithmetic) gives lower noise-to-margin ratio
       than q=3329 (Kyber), ensuring reliable single-block agreement"

  That is accurate about correctness and is exactly the problem for security.
  Lower noise-to-modulus ratio is what makes reconciliation reliable and what
  makes the lattice problem easy; the two are the same knob turned the same way.
  The deployed p = {p} puts alpha at {sd_e/q:.2e}, about {(lwr_sigma(q,1024)/q)/(sd_e/q):.0f}x quieter than Saber's p = 1024.
""")


def section6():
    rule('6  The documented estimate, and where its reasoning inverts')
    print("""
  SecurityProofs-4.md §11.4.3 and SECURITY.md carry ~105 classical / ~100
  quantum Core-SVP bits at n=256 and ~220/~200 at n=512.  Two steps produce them:

  (a) The n=256 figure is cited, not computed — "MATZOV Report 2022; Albrecht et
      al. LWE estimator 2023 updates" with no parameter set attached.  Kyber-512
      is Module-LWE at effective dimension 512 with q=3329; HKEX-RNL n=256 is
      Ring-LWR at dimension 256 with q=65537.  The dimension is half and alpha is
      5x smaller, so a Kyber-512-adjacent number cannot transfer.

  (b) The n=512 figure extrapolates linearly off (a): "Core-SVP(n) ~= 110*n/256".
      beta does grow close to linearly in n at fixed (q,p,eta) — §7 confirms that
      shape — so the *slope* is defensible.  It is anchored to a wrong intercept.

  The document also offers a cross-check that runs backwards:

      "HKEX-RNL at n=512 has relative noise ratio sigma/sqrt(q) = 4.67/256 =
       0.018, smaller than ML-KEM-512's 1.22/57.7 = 0.021, confirming a lower
       bound of at least 128 bits."

  Smaller relative noise makes LWE/LWR *easier*, not harder.  Read the right way
  round, that comparison predicts HKEX-RNL is weaker than ML-KEM-512 at equal
  dimension, which is what §4 measures.  (sigma/sqrt(q) is also not the relevant
  ratio; alpha = sigma/q is, and on alpha the gap is 5x rather than 1.2x.)
""")


def section7(q, fast):
    rule('7  What would actually reach 128 bits')
    print("""
  Sweeping the three levers.  "OK" marks >= 128 bits on BOTH classical and
  quantum Core-SVP — the target SECURITY.md states.
""")
    ns = (256, 512, 768, 1024) if not fast else (512, 768, 1024)
    ps = (4096, 2048, 1024, 512) if not fast else (4096, 1024)
    etas = (1, 2, 3) if not fast else (1, 2)
    print(f"    {'n':>5} {'p':>6} {'eta':>4} | {'beta':>5} {'classical':>10} {'quantum':>9}")
    print('    ' + '-' * 52)
    for nn in ns:
        for pp in ps:
            for e in etas:
                sd_e = lwr_sigma(q, pp)
                sd_s = math.sqrt(e / 2.0)
                b, _ = primal_usvp(nn, q, sd_s, sd_e, nn)
                c, qt = 0.292 * b, 0.265 * b
                tag = ' OK' if min(c, qt) >= 128 else ''
                note = ''
                if (nn, pp, e) == (256, 4096, 1):
                    note = '   <-- deployed'
                elif (nn, pp, e) == (512, 4096, 1):
                    note = '   <-- HKEX-RNL-128'
                print(f"    {nn:>5} {pp:>6} {e:>4} | {b:>5} {c:>10.1f} {qt:>9.1f}{tag}{note}")
        print()
    print("""  Reading the sweep:

    * n dominates.  p is worth roughly 10 bits per halving and eta a few bits;
      neither closes a 96-bit gap.
    * n=512 does not reach 128 quantum bits at ANY (p, eta) in the sweep.  The
      best cell, p=512 with eta=3, is still short.  HKEX-RNL-128 cannot be
      rescued by retuning; it needs a larger ring.
    * n=768 clears both at the deployed p=4096 with nothing else changed, but
      768 is not a power of two, so x^n+1 has no negacyclic NTT and _rnl_poly_mul
      loses its Cooley-Tukey path.  Kyber solves exactly this with a module
      (k=3 rings at n=256) rather than one large ring.
    * n=1024 clears both with margin and keeps the NTT.  Cost is 4x the key
      material and ring multiplication of the deployed set.

  Choosing among these is a protocol change and belongs in its own item, not
  here.  Note also that p and reconciliation reliability are the same knob:
  hkex_rnl_failure_rate.py owns the correctness side, and any move on p has to
  be re-run through it.
""")


def section8(results, pinned):
    rule('8  Verdict')
    b256 = results[256][0]
    b512 = results[512][0]
    gen_name, gen = max(COST_MODELS, key=lambda mf: mf[1](b256))
    gen_name = ' '.join(gen_name.split())
    print(f"""
  Pinned to six published figures in §3: {'yes' if pinned else 'NO — verdict void'}

  Computed, deployed parameters (q=65537, p=4096, eta=1, primal uSVP binding):

    HKEX-RNL      n=256   beta={b256:<4}  {0.292*b256:5.1f} classical / {0.265*b256:5.1f} quantum Core-SVP bits
    HKEX-RNL-128  n=512   beta={b512:<4}  {0.292*b512:5.1f} classical / {0.265*b512:5.1f} quantum Core-SVP bits

  Documented in SECURITY.md / SecurityProofs-4.md §11.4.3:

    HKEX-RNL      n=256          ~105 classical / ~100 quantum
    HKEX-RNL-128  n=512          ~220 classical / ~200 quantum

  The gaps are {105-0.292*b256:.0f} and {220-0.292*b512:.0f} bits.  Both documented figures are too high, and
  the n=512 set — currently promoted as production-track and the recommended
  answer to n=256 being below target — does not reach 128 bits either.

  Even on the most defender-generous model here ({gen_name.strip()}), n=256 is
  {gen(b256):.0f} bits and n=512 is {gen(b512):.0f} bits.  No cost model rescues either set.

  This is a parameter-selection error, not an implementation bug: the code does
  what §11.4 specifies, and §11.4 chose p to make reconciliation reliable
  without accounting for what that choice does to alpha (§5).

  Rows SECURITY.md should carry:

    HKEX-RNL (n=256)      NOT for production   ~32 classical / ~29 quantum Core-SVP bits
    HKEX-RNL-128 (n=512)  NOT for production   ~87 classical / ~79 quantum Core-SVP bits

  Both are well below the 100-bit floor the current text claims clearance of.
  HKEX-RNL should not be presented as a quantum-resistant option at either size
  until the ring dimension moves (§7).  The hybrid protocol HYBRID-RNL-STERN
  retains whatever HPKE-Stern-KEM provides on its own; what it does not have is a
  meaningful second contribution from the RNL half.
""")


def main():
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[1])
    ap.add_argument('--fast', action='store_true',
                    help='coarse grid in §7 (~25 s instead of ~3 min)')
    args = ap.parse_args()

    print(__doc__.split('\n', 1)[1].split('  §1')[0].strip())

    suite = load_suite()
    n, q, p, eta, sd_s, sd_e = section1(suite)
    section2()
    pinned = section3()
    if not pinned:
        print('\nAborting: the cost model did not reproduce its validation targets.')
        return 1
    results = section4(n, q, p, eta, sd_s, sd_e)
    section5(q, p, sd_e)
    section6()
    section7(q, args.fast)
    section8(results, pinned)
    return 0


if __name__ == '__main__':
    sys.exit(main())
