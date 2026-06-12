#!/usr/bin/env python3
"""
nl_fscx_v1_ratchet_collision.py — Collision-probability analysis for the
NL-FSCX v1 forward-secret ratchet (TODO #78.C).

The ratchet advances state via:
    state_{i+1} = nl_fscx_revolve_v1(state_i, DOMAIN, 1)

Because nl_fscx_v1 is non-bijective (onto but not one-to-one over {0,1}^n), two
distinct states can map to the same next state — a "collision".  If any two ratchet
positions share a state the secrecy guarantee breaks from that point onward.

KEY FINDINGS (§11.X of SecurityProofs-2.md):

  §1  Empirical output collision rate of a single nl_fscx_v1 step
        Measured fraction of inputs that share their output with another input.
        Gives the per-step "birthday" probability.

  §2  Birthday-bound collision distance
        Expected number of steps before two independently-initialized ratchets
        collide, or before a single ratchet re-enters a prior state.
        Modelled as birthday problem in image size |Im(F1)|.

  §3  Image-size estimation
        |Im(F1)| / 2^n  measured for n ∈ {8, 16, 32}.
        Extrapolated to n=256 via linear regression on log-scale.

  §4  Practical ratchet lifetime bound
        Maximum safe number of steps before re-keying is required,
        at collision probability ≤ 2^{-k} for k ∈ {64, 80, 128}.

  §5  HDRBG walk characterisation (TODO #96)
        The DRBG advances via a full revolve F^(n/4) per output block.
        (a) composed-image contraction: |Im(F^64)| extrapolates to ≈ 2^218.8
            at n=256 (vs 2^243.8 for a single step).
        (b) Brent rho+cycle of the revolve walk tracks sqrt-of-image scaling
            (n=16: median 64; n=20: median 785; n=24: median 2,873).
        (c) With DRBG_MAX_BLOCKS = 2^20: E[walk collision] ≈ 2^109.7 blocks;
            P(collision within the limit) ≈ 2^-180  →  SAFE (≤ 2^-128 target).

Runtime: minutes-to-hours with the n=32 sweep on slow hosts.
Set env FULL_SWEEP=0 to skip n=32 and use extrapolated values only.
"""

import math
import os
import random
import time

# ---------------------------------------------------------------------------
# Minimal self-contained NL-FSCX v1 (mirrors suite, integer-only)
# ---------------------------------------------------------------------------

def _rol(x: int, k: int, n: int) -> int:
    mask = (1 << n) - 1
    k %= n
    return ((x << k) | (x >> (n - k))) & mask

def nl_fscx_v1(a: int, b: int, n: int) -> int:
    mask = (1 << n) - 1
    rol_a = _rol(a, 1, n)
    ror_a = _rol(a, n - 1, n)
    rol_b = _rol(b, 1, n)
    ror_b = _rol(b, n - 1, n)
    fscx  = (a ^ b ^ rol_a ^ rol_b ^ ror_a ^ ror_b) & mask
    add   = (a + b) & mask
    rol_add = _rol(add, n // 4, n)
    return (fscx ^ rol_add) & mask

# ---------------------------------------------------------------------------
# §1  Per-step collision rate
# ---------------------------------------------------------------------------

def measure_collision_rate(n: int, domain: int) -> tuple[float, int, int]:
    """Return (collision_rate, image_size, input_count).
    For small n only (exhaustive scan)."""
    size = 1 << n
    outputs: dict[int, int] = {}
    for x in range(size):
        y = nl_fscx_v1(x, domain, n)
        outputs[y] = outputs.get(y, 0) + 1
    image_size = len(outputs)
    colliding = sum(c for c in outputs.values() if c > 1)
    return colliding / size, image_size, size

# ---------------------------------------------------------------------------
# §2  Birthday-bound collision distance
# ---------------------------------------------------------------------------

def collision_distance(image_size: int) -> float:
    """Expected number of steps before two states collide (birthday paradox).
    E[collision] ≈ sqrt(pi/2 * image_size) for uniform distribution."""
    return math.sqrt(math.pi / 2 * image_size)

def safe_steps(image_size: int, prob: float) -> int:
    """Maximum steps such that P(collision) <= prob (birthday approximation).
    P(no collision after k steps) ≈ e^{-k^2 / (2 * image_size)}
    => k <= sqrt(-2 * image_size * ln(1 - prob))"""
    if prob >= 1.0:
        return image_size
    if prob < 1e-12:
        # ln(1-p) underflows to 0 in float64 for tiny p; use ln(1-p) ≈ -p
        return int(math.sqrt(2.0 * image_size * prob))
    return int(math.sqrt(-2.0 * image_size * math.log(1.0 - prob)))

# ---------------------------------------------------------------------------
# §3  Image-size estimation and extrapolation
# ---------------------------------------------------------------------------

def estimate_image_fraction(n: int, domain: int, samples: int = 50000) -> float:
    """Monte Carlo estimate of |Im(F1)| / 2^n for larger n."""
    seen: set[int] = set()
    mask = (1 << n) - 1
    for _ in range(samples):
        x = random.getrandbits(n)
        seen.add(nl_fscx_v1(x, domain, n))
    # Good-Turing correction: estimate coverage
    coverage = len(seen) / samples
    return coverage  # lower bound; true fraction ~ coverage / (1 - e^{-samples/image})

def extrapolate_image_size(fractions: list[tuple[int, float]]) -> float:
    """Log-linear fit: log(image_fraction) = a + b*n.
    Returns extrapolated fraction at n=256."""
    xs = [n for n, _ in fractions]
    ys = [math.log(f) for _, f in fractions]
    # Least-squares
    xm = sum(xs) / len(xs)
    ym = sum(ys) / len(ys)
    b  = sum((x - xm) * (y - ym) for x, y in zip(xs, ys)) / \
         sum((x - xm) ** 2 for x in xs)
    a  = ym - b * xm
    log_frac_256 = a + b * 256
    return math.exp(log_frac_256)

# ---------------------------------------------------------------------------
# §5  HDRBG walk characterisation (TODO #96)
# ---------------------------------------------------------------------------
# The HDRBG (suite drbg_seed/drbg_generate, TODO #96) advances state once per
# 32-byte output block via a full revolve, not a single step:
#     state_{i+1} = nl_fscx_revolve_v1(state_i, DRBG_DOMAIN, n/4)
# At reduced width n we use steps = n/4 (the same I_VALUE scaling the suite
# applies).  Two questions:
#   (a) how much does composing n/4 steps shrink the image beyond one step?
#   (b) what are the rho (tail) and cycle lengths of the walk x -> F^(n/4)(x)?
# The DRBG output limit DRBG_MAX_BLOCKS = 2^20 must sit far below the walk's
# expected collision distance at n=256.

def revolve_v1(a: int, b: int, steps: int, n: int) -> int:
    for _ in range(steps):
        a = nl_fscx_v1(a, b, n)
    return a

def revolve_image_fraction(n: int, domain: int) -> float:
    """Exhaustive |Im(F^(n/4))| / 2^n for small n."""
    steps = n // 4
    seen = set()
    for x in range(1 << n):
        seen.add(revolve_v1(x, domain, steps, n))
    return len(seen) / (1 << n)

def brent_rho_cycle(n: int, domain: int, start: int, cap: int) -> tuple[int, int]:
    """Brent's algorithm on x -> F^(n/4)(x).  Returns (tail_len, cycle_len);
    (-1, -1) if no cycle found within cap evaluations."""
    steps = n // 4
    power = lam = 1
    tortoise = start
    hare = revolve_v1(start, domain, steps, n)
    evals = 1
    while tortoise != hare:
        if power == lam:
            tortoise = hare
            power *= 2
            lam = 0
        hare = revolve_v1(hare, domain, steps, n)
        lam += 1
        evals += 1
        if evals > cap:
            return -1, -1
    # find tail length mu
    tortoise = hare = start
    for _ in range(lam):
        hare = revolve_v1(hare, domain, steps, n)
    mu = 0
    while tortoise != hare:
        tortoise = revolve_v1(tortoise, domain, steps, n)
        hare = revolve_v1(hare, domain, steps, n)
        mu += 1
        if mu > cap:
            return -1, lam
    return mu, lam

def section5_drbg_walk():
    print("§5  HDRBG walk characterisation (TODO #96): x -> F^(n/4)(x)")
    DRBG_DOMAIN_BYTES = b'NL-FSCX-DRBG-V1\x00' + b'\x00' * 16
    drbg_domains = {n: int.from_bytes(DRBG_DOMAIN_BYTES[:n // 8], 'big')
                    for n in (8, 16, 24)}
    # 20-bit domain: truncate the 32-bit prefix bitwise
    drbg_domains[20] = int.from_bytes(DRBG_DOMAIN_BYTES[:4], 'big') >> 12

    # (a) composed-image contraction, exhaustive at n=8,16
    print("    (a) image fraction after one revolve (n/4 composed steps):")
    rev_fractions = []
    for n in (8, 16):
        t0 = time.perf_counter()
        frac = revolve_image_fraction(n, drbg_domains[n])
        rev_fractions.append((n, frac))
        print(f"        n={n:>2}  |Im(F^{n//4})|/2^{n} = {frac:.6f}"
              f"  ({time.perf_counter() - t0:.2f}s)")
    frac256 = extrapolate_image_size(rev_fractions)
    print(f"        extrapolated to n=256: |Im(F^64)| ≈ 2^{256 + math.log2(frac256):.2f}")

    # (b) rho/cycle lengths via Brent
    print("    (b) Brent rho/cycle lengths of the revolve walk (random starts):")
    rng = random.Random(0xD2B6)
    for n, starts, cap in ((16, 100, 1 << 18), (20, 60, 1 << 19), (24, 30, 1 << 20)):
        mus, lams, censored = [], [], 0
        t0 = time.perf_counter()
        for _ in range(starts):
            mu, lam = brent_rho_cycle(n, drbg_domains[n], rng.getrandbits(n), cap)
            if mu < 0 or lam < 0:
                censored += 1
            else:
                mus.append(mu)
                lams.append(lam)
        if mus:
            mus.sort(); lams.sort()
            tot = [m + l for m, l in zip(mus, lams)]; tot.sort()
            print(f"        n={n:>2}  rho+cycle: min={tot[0]:>7,}  "
                  f"median={tot[len(tot)//2]:>7,}  max={tot[-1]:>7,}  "
                  f"(censored>{cap:,}: {censored}/{starts}; "
                  f"sqrt(2^n)={int(math.sqrt(1 << n)):,})  "
                  f"({time.perf_counter() - t0:.1f}s)")
        else:
            print(f"        n={n:>2}  all {starts} walks exceeded cap={cap:,} "
                  f"(rho+cycle > cap; sqrt(2^n)={int(math.sqrt(1 << n)):,})")

    # (c) DRBG_MAX_BLOCKS check against birthday bound at n=256
    print("    (c) DRBG_MAX_BLOCKS=2^20 vs extrapolated collision distance at n=256:")
    im256 = frac256 * (2.0 ** 256)
    exp_collision = collision_distance(im256)
    p_at_limit = (2.0 ** 20) ** 2 / (2.0 * im256)
    print(f"        E[walk collision] ≈ 2^{math.log2(exp_collision):.1f} blocks")
    print(f"        P(collision within 2^20 blocks) ≈ 2^{math.log2(p_at_limit):.1f}")
    verdict = "SAFE" if p_at_limit < 2.0 ** -128 else "REVIEW"
    print(f"        verdict: {verdict} (limit must keep probability ≤ 2^-128)")
    print()

# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

# Set env FULL_SWEEP=0 to skip the n=32 exhaustive scan (slow on small hosts).
FULL_SWEEP = os.environ.get('FULL_SWEEP', '1') != '0'

def main():
    print("=" * 68)
    print("NL-FSCX v1 Ratchet Collision Analysis — SecurityProofsCode")
    print("=" * 68)
    print()

    # Domain constant: first 32/16/8 bits of b'NL-FSCX-RATCHET-V1\x00' repeated
    DOMAIN_BYTES = b'NL-FSCX-RATCHET-V1\x00' * 2   # 40 bytes
    domains = {
        8:  int.from_bytes(DOMAIN_BYTES[:1],  'big'),
        16: int.from_bytes(DOMAIN_BYTES[:2],  'big'),
        32: int.from_bytes(DOMAIN_BYTES[:4],  'big'),
    }

    # ── §1  Per-step collision rate ──────────────────────────────────────────
    print("§1  Per-step collision rate (exhaustive scan)")
    print(f"    {'n':>4}  {'domain':>12}  {'image |Im|':>12}  "
          f"{'|Im|/2^n':>10}  {'colliding':>10}")
    fractions: list[tuple[int, float]] = []
    for n in [8, 16] + ([32] if FULL_SWEEP else []):
        domain = domains.get(n, int.from_bytes(DOMAIN_BYTES[:n // 8], 'big'))
        t0 = time.perf_counter()
        crate, imsize, total = measure_collision_rate(n, domain)
        elapsed = time.perf_counter() - t0
        frac = imsize / total
        fractions.append((n, frac))
        print(f"    {n:>4}  {domain:>12}  {imsize:>12,}  {frac:>10.6f}"
              f"  {crate * 100:>9.3f}%  ({elapsed:.2f}s)")

    print()

    # ── §2  Birthday-bound collision distance ────────────────────────────────
    print("§2  Birthday-bound collision distance at n=32 (if measured)")
    if FULL_SWEEP and any(n == 32 for n, _ in fractions):
        frac32  = next(f for n, f in fractions if n == 32)
        imsize32 = int(frac32 * (1 << 32))
        exp_steps = collision_distance(imsize32)
        print(f"    |Im(F1)| at n=32 ≈ {imsize32:,}  ({frac32:.6f} × 2^32)")
        print(f"    E[collision] ≈ {exp_steps:.2e} steps")
        for prob_label, prob in [("2^-128", 2**-128), ("2^-80", 2**-80),
                                  ("2^-64", 2**-64),  ("10^-6", 1e-6)]:
            k = safe_steps(imsize32, prob)
            print(f"    Safe steps for P(collision) ≤ {prob_label}: {k:,}")
    else:
        print("    (FULL_SWEEP=False — set True to run n=32 exhaustive scan)")
    print()

    # ── §3  Image-size extrapolation ─────────────────────────────────────────
    print("§3  Image-size extrapolation to n=256")
    if len(fractions) >= 2:
        frac256 = extrapolate_image_size(fractions)
        imsize256 = frac256 * (2 ** 256)
        print(f"    Extrapolated |Im(F1)| / 2^256 ≈ {frac256:.6f}")
        print(f"    Extrapolated |Im(F1)| ≈ 2^{math.log2(imsize256):.2f}")
        print()

        # ── §4  Practical ratchet lifetime bound at n=256 ───────────────────
        print("§4  Practical ratchet lifetime bound at n=256 (extrapolated)")
        for prob_label, prob in [("2^-128", 2**-128), ("2^-80", 2**-80),
                                  ("2^-64", 2**-64)]:
            k = safe_steps(imsize256, prob)
            bits = math.log2(k) if k > 0 else 0
            print(f"    P(collision) ≤ {prob_label}: safe for ≤ 2^{bits:.1f} steps")
    else:
        print("    Insufficient data points for extrapolation (need n=8 and n=16).")
    print()

    # ── Monte Carlo verification for n=64 ───────────────────────────────────
    print("§3b Monte Carlo estimate for n=64 (50k samples)")
    domain64 = int.from_bytes(DOMAIN_BYTES[:8], 'big')
    t0 = time.perf_counter()
    frac64 = estimate_image_fraction(64, domain64, samples=50000)
    elapsed = time.perf_counter() - t0
    print(f"    n=64  coverage estimate: {frac64:.6f}  ({elapsed:.2f}s)")
    print()

    # ── §5  HDRBG walk (TODO #96) ────────────────────────────────────────────
    section5_drbg_walk()

    # ── Summary ──────────────────────────────────────────────────────────────
    print("SUMMARY")
    print("  • nl_fscx_v1 is non-bijective: |Im| < 2^n (onto but not 1-to-1).")
    print("  • Collision probability scales as k^2 / (2 * |Im|) for k steps")
    print("    (birthday bound).")
    if len(fractions) >= 2 and FULL_SWEEP:
        imsize256 = extrapolate_image_size(fractions) * (2 ** 256)
        k128 = safe_steps(imsize256, 2**-128)
        print(f"  • At n=256, safe ratchet lifetime ≈ 2^{math.log2(k128):.1f} steps")
        print(f"    at 2^-128 collision probability (extrapolated).")
    print("  • RECOMMENDATION: re-key (call ratchet_init with a fresh seed) before")
    print("    the safe-step bound.  For typical use (< 2^40 messages) with n=256,")
    print("    the extrapolated collision probability is negligible.")
    print()


if __name__ == '__main__':
    main()
