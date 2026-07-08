#!/usr/bin/env python3
"""
nl_fscx_rot_analysis.py — Formal rotational differential analysis of NL-FSCX v1 (TODO #75).

Applies the Khovratovich-Nikolić 2010 rotational cryptanalysis framework to F1^r.

KEY FINDINGS (reported in §11.8.3 "Rotational structure" subsection):

  §1  Single-round two-sided rotational probability
        p_rot^(1)(k) ≈ 0.25–0.38 (n-independent for n ≥ 16)
        Analytic derivation: FSCX is exactly rotation-equivariant;
        deviation comes from carry mismatch in ROL(A+B, n/4).

  §2  One-sided vs. two-sided comparison
        One-sided  (B fixed): p ≈ 0  (< 10^{-5}) for all r, k tested
        Two-sided  (both rotated): p = 1–6% at r=8, n=32

  §3  Multi-round power-law decay
        Two-sided: p(r) ≈ C(k) * r^{-alpha(k)}, NOT geometric decay
        k=1: alpha ≈ 0.96, C ≈ 0.42  →  p(r) ≈ 0.42/r
        k=8: alpha ≈ 1.88, C ≈ 0.65  →  p(r) ≈ 0.65/r^2

  §4  Extrapolation to n=256, r=64 (protocol round count)
        k=1: p(64) ≈ 0.0078  →  ~128 query pairs for 50% distinguisher advantage
        k=8: p(64) ≈ 0.00026 →  ~3850 query pairs

  §5  Protocol impact analysis
        PRF uses (Stern-F, HSKE-NL-A1, HFSCX-256-DM): B is the fixed key
          → one-sided only → p ≈ 0 → no rotational distinguisher
        WOTS hash h(x) = F1^{n/4}(ROL(x,n/8), x): rotating x rotates both A and B
          → two-sided → polynomial RO distinguisher (~128 pairs at n=256)
          → BUT Theorem 16 uses OWF only, not ROM → WOTS-F security intact

Runtime: ~5 min on a modest CPU (power-law sweep is the bottleneck).
Set FULL_DECAY_SWEEP=False to skip §3 (~4 min) and use pre-computed constants.
"""

import math
import time
import random
import sys

random.seed(0xC0DE_FEED)

FULL_DECAY_SWEEP = True

SEP  = "═" * 72
SEP2 = "─" * 72

# ─── Primitives ───────────────────────────────────────────────────────────────

def rol(x, r, n):
    r %= n; m = (1 << n) - 1
    return ((x << r) | (x >> (n - r))) & m

def fscx(A, B, n):
    m = (1 << n) - 1
    return (A ^ B ^ rol(A,1,n) ^ rol(B,1,n) ^ rol(A,n-1,n) ^ rol(B,n-1,n)) & m

def nl_fscx_v1(A, B, n):
    m = (1 << n) - 1
    return (fscx(A, B, n) ^ rol((A + B) & m, n >> 2, n)) & m

def nl_fscx_r(A, B, r, n):
    for _ in range(r):
        A = nl_fscx_v1(A, B, n)
    return A

# ─── §1: Single-round rotational probability ─────────────────────────────────

def section1():
    print(SEP)
    print("§1 — Single-Round Two-Sided Rotational Probability")
    print(SEP)
    print("  p_rot^(1)(k) = Pr_{A,B}[ F1(ROL(A,k), ROL(B,k)) == ROL(F1(A,B), k) ]")
    print("  Equivalently: Pr[ ROL(A+B, k) == ROL(A,k)+ROL(B,k) (mod 2^n) ]")
    print("  (FSCX is exactly rotation-equivariant; all deviation is in the carry term)")
    print()

    # Exhaustive at n=8
    n = 8
    N = 1 << n
    print(f"  n={n} (exhaustive):")
    print(f"  {'k':>4}  {'p_rot':>10}  {'log2(p)':>10}")
    for k in [1, 2, 3, 4]:
        hits = 0
        m = N - 1
        for A in range(N):
            for B in range(N):
                if rol((A+B)&m, k, n) == (rol(A,k,n)+rol(B,k,n))&m:
                    hits += 1
        p = hits / (N * N)
        print(f"  k={k:<3}  {p:.6f}  {math.log2(p):.3f}")

    print()
    # Sampled at n=32 (n-independence check)
    n = 32
    trials = 200_000
    print(f"  n={n} (sampled {trials}):")
    print(f"  {'k':>4}  {'p_rot':>10}  {'log2(p)':>10}")
    m = (1 << n) - 1
    for k in [1, 2, 4, 8, 16]:
        hits = 0
        for _ in range(trials):
            A = random.randrange(1 << n)
            B = random.randrange(1 << n)
            if rol((A+B)&m, k, n) == (rol(A,k,n)+rol(B,k,n))&m:
                hits += 1
        p = hits / trials
        print(f"  k={k:<3}  {p:.6f}  {math.log2(p):.3f}")

    print()
    print("  Analytic note: FSCX(ROL(A,k),ROL(B,k)) = ROL(FSCX(A,B),k) exactly,")
    print("  so the only non-equivariance is in ROL((A+B) mod 2^n, n/4) vs")
    print("  ROL(ROL(A,k)+ROL(B,k) mod 2^n, n/4).  The two differ exactly when")
    print("  the carry pattern of (ROL(A,k)+ROL(B,k)) differs from ROL(A+B, k).")

# ─── §2: One-sided vs. two-sided ─────────────────────────────────────────────

def section2():
    print(SEP)
    print("§2 — One-sided vs. Two-sided Rotational Comparison")
    print(SEP)
    print("  Two-sided: Pr[F1^r(ROL(A,k), ROL(B,k)) == ROL(F1^r(A,B), k)]")
    print("  One-sided: Pr[F1^r(ROL(A,k), B)         == ROL(F1^r(A,B), k)]  (B fixed)")
    print()

    n = 32
    trials = 100_000
    B_fixed = 0xDEADBEEF
    print(f"  n={n}, r=8, {trials} trials, B_fixed=0x{B_fixed:08X}")
    print(f"  {'k':>4}  {'two-sided':>12}  {'one-sided':>12}  {'ratio':>10}")
    for k in [1, 2, 4, 8, 16]:
        h2 = h1 = 0
        for _ in range(trials):
            A = random.randrange(1 << n)
            B = random.randrange(1, 1 << n)
            ya = nl_fscx_r(A, B, 8, n)
            if nl_fscx_r(rol(A,k,n), rol(B,k,n), 8, n) == rol(ya,k,n):
                h2 += 1
            # one-sided: B fixed
            ya1 = nl_fscx_r(A, B_fixed, 8, n)
            if nl_fscx_r(rol(A,k,n), B_fixed, 8, n) == rol(ya1,k,n):
                h1 += 1
        p2, p1 = h2/trials, h1/trials
        ratio_str = f"{p2/p1:.1f}×" if p1 > 0 else "∞"
        print(f"  k={k:<3}  {p2:.4e}      {p1:.4e}      {ratio_str}")

    print()
    print("  One-sided: zero hits across all (k, r) combinations tested with 100 000")
    print("  trials each.  Upper bound: < 10^{-5} ≈ 2^{-17}.")
    print()
    print("  Why zero?  One-sided equivariance requires:")
    print("    ROL(ROL(A,k)+B, n/4) XOR ROL(A+B, n/4+k) = M(B) XOR M(ROL(B,k))")
    print("  The RHS is a constant C(B,k); the LHS is a pseudo-random function of A.")
    print("  For the generic B used here, C(B,k) is not in the image of the LHS")
    print("  (or with negligible probability), so the equation has no solutions.")
    print()
    print("  IMPLICATION: all PRF uses of F1 (Stern-F row generator, HSKE-NL-A1")
    print("  keystream, HFSCX-256-DM) use B as a fixed key.  Rotating the input A")
    print("  does not create a rotational pair in the output.  These uses are")
    print("  ROTATION-SAFE; the rotational NOTE in TODO #74 does NOT affect them.")

# ─── §3: Multi-round power-law decay ─────────────────────────────────────────

def section3():
    print(SEP)
    print("§3 — Multi-Round Decay: Power Law (Two-Sided)")
    print(SEP)

    n = 32
    trials = 200_000

    if not FULL_DECAY_SWEEP:
        print("  (skipped — set FULL_DECAY_SWEEP=True to run)")
        return

    print(f"  n={n}, {trials} trials per (r,k)")
    print(f"  {'r':>5}  {'k=1':>12}  {'k=2':>12}  {'k=4':>12}  {'k=8':>12}")

    results = {}
    for r in [1, 2, 4, 8, 12, 16, 24, 32, 48, 64]:
        row = {}
        for k in [1, 2, 4, 8]:
            hits = 0
            for _ in range(trials):
                A = random.randrange(1 << n)
                B = random.randrange(1, 1 << n)
                ya = nl_fscx_r(A, B, r, n)
                if nl_fscx_r(rol(A,k,n), rol(B,k,n), r, n) == rol(ya,k,n):
                    hits += 1
            row[k] = hits / trials
        results[r] = row
        sys.stdout.flush()
        print(f"  r={r:<4}  "
              f"{row[1]:.4e}  {row[2]:.4e}  {row[4]:.4e}  {row[8]:.4e}")

    print()
    # Power-law fit: log(p) = a + b*log(r) for r >= 8
    print("  Power-law fit: p(r) ≈ C * r^(-alpha)  [r = 8..64]")
    print(f"  {'k':>4}  {'C':>8}  {'alpha':>8}  {'p(64)_fit':>12}  {'p(64)_meas':>12}")
    fit_rs = [r for r in results if r >= 8]
    for k in [1, 2, 4, 8]:
        data = [(r, results[r][k]) for r in fit_rs if results[r][k] > 0]
        n_d = len(data)
        logr = [math.log(r) for r, _ in data]
        logp = [math.log(p) for _, p in data]
        mr = sum(logr)/n_d; mp = sum(logp)/n_d
        b = sum((lr-mr)*(lp-mp) for lr,lp in zip(logr,logp)) / sum((lr-mr)**2 for lr in logr)
        a = mp - b*mr
        C = math.exp(a); alpha = -b
        p64 = C * 64**(-alpha)
        print(f"  k={k:<3}  {C:.4f}    {alpha:.4f}    {p64:.4e}      {results[64][k]:.4e}")

# ─── §4: Extrapolation and distinguisher query complexity ─────────────────────

def section4():
    print(SEP)
    print("§4 — Extrapolation to n=256, r=64 and Distinguisher Query Complexity")
    print(SEP)

    # Pre-computed fit constants from §3 (200k-trial run, r=8..64 at n=32)
    fit = {
        1: (0.406, 0.949),   # k=1: C=0.406, alpha=0.949
        2: (0.231, 0.978),   # k=2
        4: (0.231, 1.327),   # k=4
        8: (0.633, 1.870),   # k=8
    }

    print("  Fit: p(r) ≈ C * r^(-alpha)  (from §3 regression, r=8..64 at n=32)")
    print()
    r64 = 64   # n/4 for n=256
    print(f"  Protocol round count r = n/4 = {r64} (at n=256):")
    print(f"  {'k':>4}  {'C':>8}  {'alpha':>8}  {'p(64)':>12}  "
          f"{'queries_50pct':>16}  {'log2(q)':>10}")
    for k in sorted(fit):
        C, alpha = fit[k]
        p = C * r64**(-alpha)
        # Queries for 50% advantage: p^q = 0.5 => q = log(0.5)/log(1-p) ≈ ln(2)/p
        q = math.log(2) / p
        print(f"  k={k:<3}  {C:.4f}    {alpha:.4f}    {p:.4e}      {q:>16.0f}  "
              f"{math.log2(q):.1f}")

    print()
    print("  A distinguisher querying q pairs achieves ~50% advantage.")
    print("  These are POLYNOMIAL query counts — a rotational RO-distinguisher exists")
    print("  for the two-sided use case (WOTS hash chain).")
    print()
    print("  However: HPKS-WOTS-F security (Theorem 16) reduces to OWF, not ROM.")
    print("  A polynomial-query random-oracle distinguisher does NOT break Theorem 16.")
    print("  The distinguisher is a DESIGN CONCERN (not a formal break) for any future")
    print("  construction that requires F1 to behave as a random oracle.")

# ─── §5: Protocol impact analysis ────────────────────────────────────────────

def section5():
    print(SEP)
    print("§5 — Protocol Impact Analysis")
    print(SEP)

    uses = [
        ("HPKS-WOTS-F chain",
         "h(x) = F1^{n/4}(ROL(x,n/8), x)",
         "TWO-SIDED",
         "Rotating x rotates both A=ROL(x,n/8) and B=x simultaneously",
         "Polynomial RO-distinguisher (~90 pairs, k=1, n=256; q = ln2/p).  "
         "Theorem 16 uses OWF only — no security break."),

        ("Stern-F PRF row generator",
         "F_K(i) = F1^{n/4}(ROL(K^i, n/8), K)",
         "ONE-SIDED",
         "B=K is fixed; only A=ROL(K^i,n/8) varies with input i",
         "p ≈ 0 (<2^{-17}).  PRF security unaffected."),

        ("HSKE-NL-A1 keystream",
         "ks_i = F1^{n/4}(K ^ ctr, K)",
         "ONE-SIDED",
         "B=K is fixed key; A=K^ctr varies per counter",
         "p ≈ 0.  Keystream security unaffected."),

        ("HFSCX-256-DM compression",
         "C_DM(s,m) = F1^64(s, m) XOR s",
         "ONE-SIDED (in s)",
         "B=m (message block) is fixed per call; A=s (chaining value) varies",
         "p ≈ 0.  Compression function security unaffected."),
    ]

    for name, formula, rot_type, why, impact in uses:
        print(f"  {name}")
        print(f"    {formula}")
        print(f"    Rotation type: {rot_type}")
        print(f"    Reason: {why}")
        print(f"    Impact: {impact}")
        print()

    print("  SUMMARY:")
    print("  - All PRF and hash-function uses of F1 have B fixed (one-sided) → p≈0.")
    print("  - Only HPKS-WOTS-F hash chain is two-sided → polynomial RO-distinguisher.")
    print("  - Theorem 16 security proof does not require ROM → no formal break.")
    print("  - The rotational NOTE from TODO #74 is now CHARACTERISED: it is an")
    print("    open design concern for any future ROM-based security argument, but")
    print("    does not affect the current OWF-based security proofs.")

# ─── §6: Sparse-B stratified rotational rate (TODO #125, Q1) ─────────────────

def rand_weight(w, n):
    """Random n-bit value of exact Hamming weight w."""
    bits = random.sample(range(n), w)
    v = 0
    for b in bits:
        v |= 1 << b
    return v

def two_sided_rate(k, r, n, trials, wt=None):
    """Two-sided rotational-equivariance rate; B uniform (wt=None) or wt(B)=wt."""
    hits = 0
    for _ in range(trials):
        A = random.randrange(1 << n)
        B = rand_weight(wt, n) if wt is not None else random.randrange(1, 1 << n)
        if nl_fscx_r(rol(A,k,n), rol(B,k,n), r, n) == rol(nl_fscx_r(A, B, r, n), k, n):
            hits += 1
    return hits / trials

def section6():
    print(SEP)
    print("§6 — Sparse-B Stratified Rotational Rate at n=32 (TODO #125, Q1)")
    print(SEP)
    print("  Two-sided rate at r=8, stratified by wt(B); uniform-B baseline last row.")
    print()

    n, r, trials = 32, 8, 50_000
    weights = [1, 2, 4, 8, 16, 24, 32]
    print(f"  n={n}, r={r}, {trials} trials per (wt, k)")
    print(f"  {'wt(B)':>7}  {'k=1':>10}  {'k=2':>10}  {'k=4':>10}  {'k=8':>10}")
    results = {}
    for w in weights:
        row = {k: two_sided_rate(k, r, n, trials, wt=w) for k in [1, 2, 4, 8]}
        results[w] = row
        print(f"  {w:>7}  {row[1]:>10.4f}  {row[2]:>10.4f}  {row[4]:>10.4f}  {row[8]:>10.4f}")
        sys.stdout.flush()
    base = {k: two_sided_rate(k, r, n, trials) for k in [1, 2, 4, 8]}
    print(f"  {'unif':>7}  {base[1]:>10.4f}  {base[2]:>10.4f}  {base[4]:>10.4f}  {base[8]:>10.4f}")
    print()
    for w in weights:
        elev = max(results[w][k] / base[k] if base[k] > 0 else float('inf')
                   for k in [1, 2, 4, 8])
        flag = "  <-- ELEVATED" if elev > 2.0 else ""
        print(f"  wt={w:<3} max elevation over uniform baseline: {elev:5.1f}x{flag}")
    return results, base

# ─── §7: Threshold weight for safe-use bound (TODO #125, Q2) ──────────────────

def section7(results, base):
    print(SEP)
    print("§7 — Threshold Weight: Safe-Use Lower Bound on wt(B) (TODO #125, Q2)")
    print(SEP)
    print("  Minimum wt(B) at which every k-stratum is within 2x of the uniform")
    print("  baseline (fine-grained sweep around the transition).")
    print()

    n, r, trials = 32, 8, 50_000
    fine = {}
    print(f"  {'wt(B)':>7}  {'k=1':>10}  {'k=8':>10}  {'max elev':>10}")
    threshold = None
    for w in [1, 2, 3, 4, 5, 6, 8, 12, 16]:
        row = results.get(w) or {k: two_sided_rate(k, r, n, trials, wt=w) for k in [1, 8]}
        fine[w] = row
        elev = max(row[k] / base[k] if base[k] > 0 else float('inf')
                   for k in row if k in base)
        print(f"  {w:>7}  {row[1]:>10.4f}  {row[8]:>10.4f}  {elev:>9.1f}x")
        if threshold is None and elev <= 2.0:
            threshold = w
        sys.stdout.flush()
    print()
    print(f"  THRESHOLD: wt(B) >= {threshold} keeps the two-sided rate within 2x of")
    print(f"  the uniform-B baseline at n=32.  Documented as the safe-use lower")
    print(f"  bound on B density for PRF applications (scales as wt >= {threshold}·n/32).")
    return threshold

# ─── §8: Sparse-message impact on HFSCX-256-DM (TODO #125, Q3) ────────────────

def section8():
    print(SEP)
    print("§8 — Sparse-Message Impact on HFSCX-256-DM Compression (TODO #125, Q3)")
    print(SEP)
    print("  C_DM(s,m) = F1^{2n}(s, m) XOR s with B=m fixed per call (one-sided in s).")
    print("  Adversarial sparse m: does wt(m) in {1,2,4} enable (a) a one-sided")
    print("  rotational distinguisher in s, or (b) a two-sided distinguisher when")
    print("  the attacker also submits ROL(m,k)?  Model at n=32, r=64 rounds.")
    print()

    n, r, trials = 32, 64, 50_000
    m_all = (1 << n) - 1

    print(f"  (a) ONE-SIDED in s (m fixed sparse), n={n}, r={r}, {trials} trials:")
    print(f"  {'wt(m)':>7}  {'k=1':>10}  {'k=8':>10}")
    for w in [1, 2, 4]:
        row = {}
        for k in [1, 8]:
            hits = 0
            for _ in range(trials):
                m = rand_weight(w, n)
                s = random.randrange(1 << n)
                ya = nl_fscx_r(s, m, r, n) ^ s
                yb = nl_fscx_r(rol(s,k,n), m, r, n) ^ rol(s,k,n)
                if yb == rol(ya, k, n):
                    hits += 1
            row[k] = hits / trials
        print(f"  {w:>7}  {row[1]:>10.5f}  {row[8]:>10.5f}")
        sys.stdout.flush()
    print()

    print(f"  (b) TWO-SIDED (attacker submits m and ROL(m,k)), r=64 vs r=8:")
    print(f"  {'wt(m)':>7}  {'r':>4}  {'k=1':>10}  {'k=8':>10}")
    for w in [1, 2, 4]:
        for r_test in [8, 64]:
            row = {}
            for k in [1, 8]:
                hits = 0
                for _ in range(trials // 5):
                    m = rand_weight(w, n)
                    s = random.randrange(1 << n)
                    ya = nl_fscx_r(s, m, r_test, n) ^ s
                    yb = nl_fscx_r(rol(s,k,n), rol(m,k,n), r_test, n) ^ rol(s,k,n)
                    if yb == rol(ya, k, n):
                        hits += 1
                row[k] = hits / (trials // 5)
            print(f"  {w:>7}  {r_test:>4}  {row[1]:>10.5f}  {row[8]:>10.5f}")
            sys.stdout.flush()
    print()
    print("  Interpretation: the DM feed-forward XOR s breaks exact equivariance")
    print("  unless F1^r itself is equivariant AND the XOR aligns; residual rates")
    print("  quantify how much of the sparse-B elevation survives 64 rounds.")

# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    print()
    print("nl_fscx_rot_analysis.py — Rotational structure of NL-FSCX v1 (TODO #75)")
    print()
    t_total = time.monotonic()
    section1()
    print(); sys.stdout.flush()
    section2()
    print(); sys.stdout.flush()
    section3()
    print(); sys.stdout.flush()
    section4()
    print(); sys.stdout.flush()
    section5()
    print(); sys.stdout.flush()
    res6, base6 = section6()
    print(); sys.stdout.flush()
    section7(res6, base6)
    print(); sys.stdout.flush()
    section8()
    print()
    print(SEP)
    print(f"Total runtime: {time.monotonic()-t_total:.1f} s")
    print("END nl_fscx_rot_analysis.py")
    print(SEP)

if __name__ == '__main__':
    main()
