#!/usr/bin/env python3
"""
nl_fscx_rx_differential_2025.py — TODO #158: applying the automated RX-differential
search methodology of "An Automatic Search Framework for Rotational-XOR Differential
Characteristics of ARX Ciphers" (2025, https://doi.org/10.1007/s10623-025-01571-6) to
FSCX / NL-FSCX v1.

BACKGROUND

TODO #75/#125 (`nl_fscx_rot_analysis.py`) already characterise the *pure rotational*
case: the RX-difference with a zero XOR component (da = db = 0), tracked as
    p_rot(r,k) = Pr[F1^r(ROL(A,k), ROL(B,k)) == ROL(F1^r(A,B), k)]
and found a power-law decay p_rot(r,k) ~ C(k) r^-alpha(k), not geometric.

The 2025 paper's real contribution is an *automated search* over the full RX-difference
space (nonzero da, db as well as rotation k) to find the highest-probability multi-round
trail — the pure-rotational case (da=db=0) is only one point in that space, and it need
not be the optimum. Its own propagation rules are specific to modular addition in ARX
ciphers (SPECK/CHAM/SPARX/Ballet); FSCX's linear component M = I xor ROL xor ROR is pure
XOR-rotation and commutes exactly with both rotation and XOR, so it contributes
probability 1 to every trail regardless of (da, db) — all probability mass in an
NL-FSCX v1 round comes from the ROL((A+B) mod 2^n, n/4) modular-addition term. That
restriction is exactly the addition-only object the paper's propagation rules describe,
so the *methodology* (search over (da, db, k) for the best single-round transition, then
chain rounds under the Markov assumption) transfers even though this repo has no
SAT/SMT solver dependency to reproduce the paper's own CNF encoding.

THIS SCRIPT

Implements a bounded, empirical stand-in for that search (hill-climbing over (da, db)
at fixed k, evaluated by Monte Carlo rather than exact CNF/SAT enumeration): it is not
a full reproduction of the paper's automated SAT search, and does not claim to find a
provably-optimal trail. It is scoped to answer the open question TODO #158 poses:
does *any* nonzero-XOR RX-difference (da, db) give a materially higher single-round
transition probability than the already-measured da=db=0 case?

Usage: python3 SecurityProofsCode/nl_fscx_rx_differential_2025.py
"""
import random

random.seed(0xC0DE_2025)

SEP = "=" * 72


def rol(x, r, n):
    r %= n
    m = (1 << n) - 1
    return ((x << r) | (x >> (n - r))) & m


def fscx(a, b, n):
    m = (1 << n) - 1
    return (a ^ b ^ rol(a, 1, n) ^ rol(b, 1, n) ^ rol(a, n - 1, n) ^ rol(b, n - 1, n)) & m


def nl_fscx_v1(a, b, n):
    m = (1 << n) - 1
    return (fscx(a, b, n) ^ rol((a + b) & m, n >> 2, n)) & m


def best_output_diff_prob(n, k, da, db, trials, rng):
    """Empirical Pr[max over dc] of a single-round RX-difference transition
    (da, db) -> dc under rotation k, for nl_fscx_v1. Returns (best_dc, prob)."""
    m = (1 << n) - 1
    counts = {}
    for _ in range(trials):
        a = rng.getrandbits(n)
        b = rng.getrandbits(n)
        out0 = nl_fscx_v1(a, b, n)
        a2 = rol(a, k, n) ^ da
        b2 = rol(b, k, n) ^ db
        out1 = nl_fscx_v1(a2, b2, n)
        dc = (out1 ^ rol(out0, k, n)) & m
        counts[dc] = counts.get(dc, 0) + 1
    dc_best, hits = max(counts.items(), key=lambda kv: kv[1])
    return dc_best, hits / trials


def hill_climb(n, k, trials, rng, iters=200):
    """Local search over (da, db) maximizing best single-round transition prob."""
    da, db = 0, 0
    _, best_p = best_output_diff_prob(n, k, da, db, trials, rng)
    for _ in range(iters):
        bit = rng.randrange(2 * n)
        cda, cdb = da, db
        if bit < n:
            cda ^= 1 << bit
        else:
            cdb ^= 1 << (bit - n)
        _, p = best_output_diff_prob(n, k, cda, cdb, trials, rng)
        if p > best_p:
            da, db, best_p = cda, cdb, p
    return da, db, best_p


def main():
    rng = random.Random(0xC0DE_2025)
    print(SEP)
    print("TODO #158 — RX-differential local search over NL-FSCX v1's addition step")
    print(SEP)
    print("Comparing best-found nonzero-(da,db) single-round transition probability")
    print("against the already-measured da=db=0 (pure rotational) baseline.\n")

    trials = 20000
    for n in (16, 32):
        for k in (1, n // 4):
            _, p_zero = best_output_diff_prob(n, k, 0, 0, trials, rng)
            da, db, p_best = hill_climb(n, k, trials, rng, iters=150)
            improved = "YES" if p_best > p_zero * 1.15 else "no"
            print(f"n={n:3d} k={k:2d}: da=db=0 best-dc prob={p_zero:.4f}  |  "
                  f"hill-climb best prob={p_best:.4f} at da={da:#x},db={db:#x}  "
                  f"materially-improved={improved}")
    print()
    print(SEP)
    print("CONCLUSION")
    print(SEP)
    print("If no configuration above shows a materially higher probability than the")
    print("da=db=0 baseline, this local (non-exhaustive) search finds no evidence that")
    print("introducing an XOR component to the RX-difference beats the pure-rotational")
    print("trail already characterised by TODO #75/#125 for NL-FSCX v1's addition step.")
    print("This does NOT rule out a better trail outside hill-climbing's reach; a full")
    print("SAT/SMT reproduction of the paper's exhaustive search is needed to close that")
    print("gap (see SecurityProofs-2.md's TODO #158 note for scope/caveats).")


if __name__ == "__main__":
    main()
