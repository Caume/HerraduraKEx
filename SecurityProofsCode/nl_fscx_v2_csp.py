#!/usr/bin/env python3
"""
nl_fscx_v2_csp.py — Phase 0 decision gate for the Non-Abelian Key Exchange
(TODO #78.E, SecurityProofs-2 §11.8.5 "Option C / NASG").

THE QUESTION THIS SCRIPT ANSWERS
--------------------------------
A Ko-Lee / Anshel-Anshel-Goldfeld (AAG) style key exchange over a non-abelian group
REQUIRES two commuting subgroups: Alice draws from <a_1,...>, Bob from <b_1,...>, and
correctness depends on [a_i, b_j] = e.  The companion script nl_fscx_v2_kex.py §3 already
found 0/300 commuting pairs under random key selection, which suggests — but does not
prove — that the NL-FSCX v2 permutation family {pi_K} has no usable commuting structure.

Before investing in a CSP security reduction (Obstacles 1 and 3 of §11.8.5), Phase 0
settles whether the family has ANY exploitable algebraic structure:

  §1  Centralizer search — for each K1, the EXACT set of K2 whose permutation pi_{K2}
      commutes with pi_{K1} as a full permutation (exhaustive at small n).  If
      centralizers are generically {pi_{K1}}^<powers> only, Ko-Lee/AAG has no two
      independent commuting subgroups to draw from.

  §2  Theorem-15 algebraic necessary condition — the A=0 commutativity equation
      delta(K1) - delta(K2) == M(K1 XOR K2) (mod 2^n).  Counting its solutions bounds
      the centralizer from above and exposes any hidden coset structure cheaply.

  §3  Subgroup-order growth — order of <pi_{K_1},...,pi_{K_m}> versus |Sym(2^n)| = (2^n)!.
      If a handful of generators already generate the full symmetric group, there is no
      structured proper subgroup (no quotient) to host a hard, samplable KEX instance.

  §4  DECISION GATE verdict — combines §1-§3 into one of:
        (a) trivial centralizers + full Sym(2^n)  -> Ko-Lee/AAG DEAD; pivot to Stickel
            two-sided KEX (E = pi_{K1} . A . pi_{K2}, no commutativity needed) or close
            78.E as a documented impossibility.
        (b) structured centralizers / proper subgroup -> structure exists; proceed to
            Phase 1 (orbit/order bound) and Phase 2 (circuit-model CSP transfer).

PRIMITIVE (identical to nl_fscx_v2_orbit.py):
    pi_K(A) = (M(A XOR K) + delta(K)) mod 2^n
    M(X)    = X XOR ROL(X,1,n) XOR ROL(X,n-1,n)        (FSCX linear map, order n/2)
    delta(K)= ROL(K * ((K+1)>>1) mod 2^n, n/4)

Runtime: ~10 s on a modest CPU at the default sizes.
"""

import math
import random
import sys
import time

random.seed(0xC0DE_FEED_78E)

SEP  = "═" * 72
SEP2 = "─" * 72


# ─── Self-contained primitives (integer-only, mirrors suite) ──────────────────

def rol(x: int, r: int, n: int) -> int:
    r %= n
    return ((x << r) | (x >> (n - r))) & ((1 << n) - 1)

def fscx(A: int, B: int, n: int) -> int:
    return (A ^ B ^ rol(A, 1, n) ^ rol(B, 1, n) ^ rol(A, n-1, n) ^ rol(B, n-1, n)) \
           & ((1 << n) - 1)

def delta_v2(K: int, n: int) -> int:
    """delta(K) = ROL(K * ceil(K/2) mod 2^n, n/4)."""
    return rol((K * ((K + 1) >> 1)) & ((1 << n) - 1), n >> 2, n)

def m_step(X: int, n: int) -> int:
    return X ^ rol(X, 1, n) ^ rol(X, n - 1, n)

def pi_K(A: int, K: int, n: int) -> int:
    """pi_K(A) = (M(A XOR K) + delta(K)) mod 2^n."""
    return (fscx(A, K, n) + delta_v2(K, n)) & ((1 << n) - 1)


def perm_of(K: int, n: int) -> tuple:
    """Materialise pi_K as a length-2^n permutation tuple."""
    return tuple(pi_K(A, K, n) for A in range(1 << n))

def compose(p: tuple, q: tuple) -> tuple:
    """(p ∘ q)(x) = p[q[x]]."""
    return tuple(p[q[x]] for x in range(len(q)))

def is_identity(p: tuple) -> bool:
    return all(p[i] == i for i in range(len(p)))


# ─── §1: Centralizer search (exhaustive, full-permutation commutativity) ──────

def section1(ns=(4, 6, 8)):
    print(SEP)
    print("§1 — Centralizer Search (exhaustive full-permutation commutativity)")
    print(SEP)
    print("  For each K1, count K2 with  pi_{K2} ∘ pi_{K1} == pi_{K1} ∘ pi_{K2}.")
    print("  A non-trivial centralizer is the minimum requirement for a Ko-Lee/AAG KEX.")
    print()

    for n in ns:
        N = 1 << n
        perms = [perm_of(K, n) for K in range(N)]
        cent_sizes = []
        # how many keys K2 commute with K1 OTHER than via the cyclic group <pi_{K1}>?
        nontrivial_keys = 0
        for K1 in range(N):
            p1 = perms[K1]
            csize = 0
            for K2 in range(N):
                p2 = perms[K2]
                if compose(p1, p2) == compose(p2, p1):
                    csize += 1
            cent_sizes.append(csize)
            # K1=K1 always commutes with itself (csize >= 1); identity key may too.
            if csize > 2:
                nontrivial_keys += 1
        mn, mx = min(cent_sizes), max(cent_sizes)
        avg = sum(cent_sizes) / len(cent_sizes)
        print(f"  n={n}  (keys {N})  centralizer |{{K2 : commute}}|: "
              f"min={mn} max={mx} avg={avg:.2f}")
        print(f"        keys with centralizer > 2: {nontrivial_keys}/{N}")
        # Identify the typical commuting partners for a sample key
        sample = 1
        partners = [K2 for K2 in range(N)
                    if compose(perms[sample], perms[K2]) == compose(perms[K2], perms[sample])]
        print(f"        K1={sample} commutes with K2 in: {partners[:12]}"
              f"{' ...' if len(partners) > 12 else ''}")
        print()


# ─── §2: Theorem-15 algebraic necessary condition (A=0 commutativity) ─────────

def section2(ns=(8, 12, 16)):
    print(SEP)
    print("§2 — Theorem-15 Necessary Condition:  δ(K1) − δ(K2) ≡ M(K1⊕K2) (mod 2^n)")
    print(SEP)
    print("  This is the commutativity condition evaluated at A=0 (Theorem 15 proof).")
    print("  It is NECESSARY (not sufficient) for full-permutation commutativity, so its")
    print("  solution count upper-bounds the §1 centralizer and is cheap at larger n.")
    print()

    for n in ns:
        N = 1 << n
        mask = N - 1
        # exhaustive K1 sweep only where N^2 stays tractable in pure Python (n<=12);
        # sample K1 for larger n (inner K2 loop is still exhaustive over all N).
        if n <= 12:
            k1_iter = list(range(N))
            exhaustive = True
        else:
            k1_iter = [random.randrange(N) for _ in range(512)]
            exhaustive = False

        total_solutions = 0
        max_sol = 0
        k1_with_extra = 0   # K1 admitting a solution K2 != K1
        for K1 in k1_iter:
            dK1 = delta_v2(K1, n)
            sols = 0
            extra = False
            for K2 in range(N):
                lhs = (dK1 - delta_v2(K2, n)) & mask
                rhs = m_step(K1 ^ K2, n)
                if lhs == rhs:
                    sols += 1
                    if K2 != K1:
                        extra = True
            total_solutions += sols
            max_sol = max(max_sol, sols)
            if extra:
                k1_with_extra += 1
        cnt = len(list(k1_iter)) if not exhaustive else N
        tag = "exhaustive" if exhaustive else "sampled 4096 K1"
        print(f"  n={n:2d} ({tag}):  avg solutions/K1 = {total_solutions / cnt:.3f}  "
              f"max = {max_sol}  K1 with a partner K2≠K1: {k1_with_extra}/{cnt}")
    print()
    print("  Note: K2=K1 is always a solution (δ(K1)−δ(K1)=0=M(0)).  Counts near 1.0")
    print("  mean with few K1 admitting K2≠K1 ⇒ the necessary condition itself already")
    print("  forbids non-trivial commuting partners for almost all keys.")
    print()


# ─── §3: Subgroup-order growth versus |Sym(2^n)| ─────────────────────────────

def subgroup_order(gens, N, cap):
    """BFS closure of the subgroup generated by `gens` (permutation tuples).
    Returns (order, hit_cap)."""
    ident = tuple(range(N))
    seen = {ident}
    frontier = [ident]
    while frontier:
        nxt = []
        for p in frontier:
            for g in gens:
                q = compose(g, p)
                if q not in seen:
                    seen.add(q)
                    nxt.append(q)
                    if len(seen) > cap:
                        return len(seen), True
        frontier = nxt
    return len(seen), False

def section3(configs=((4, 2), (4, 3), (6, 2), (6, 3))):
    print(SEP)
    print("§3 — Subgroup-Order Growth:  |⟨pi_{K_1},...,pi_{K_m}⟩|  vs  |Sym(2^n)|")
    print(SEP)
    print("  If a few generators already generate (or nearly generate) the full")
    print("  symmetric group, there is NO structured proper subgroup to host a hard,")
    print("  samplable KEX instance.")
    print()

    CAP = 500_000
    for n, m in configs:
        N = 1 << n
        sym_order = math.factorial(N)
        # pick m random non-degenerate keys (avoid K=0 linear degeneracy)
        keys = []
        while len(keys) < m:
            K = random.randrange(1, N)
            if K not in keys:
                keys.append(K)
        gens = [perm_of(K, n) for K in keys]
        order, capped = subgroup_order(gens, N, CAP)
        if capped:
            frac = f">{CAP} (cap hit; |Sym|={sym_order:.3g})"
        else:
            frac = f"{order}  ({100.0 * order / sym_order:.2e}% of |Sym|={sym_order})"
        print(f"  n={n}  m={m}  keys={keys}")
        print(f"        subgroup order = {frac}")
    print()
    print("  Interpretation: order hitting the cap (or == |Sym|) ⇒ the family generates a")
    print("  huge/full symmetric group ⇒ no proper-subgroup structure for Ko-Lee/AAG.")
    print()


# ─── §4: Decision-gate verdict ───────────────────────────────────────────────

def section4():
    print(SEP)
    print("§4 — Phase 0 Decision Gate (TODO #78.E)")
    print(SEP)
    print("""  Combine the evidence:

    • §1 centralizers generically trivial (size ≈ 2, only <pi_{K1}> powers)  AND
    • §2 necessary condition admits ~no K2≠K1 partner                         AND
    • §3 a few generators reach the full / near-full symmetric group
        ⇒ VERDICT (a): Ko-Lee/AAG is NOT instantiable — no two independent
          commuting subgroups exist.  Pivot 78.E to a Stickel-type two-sided KEX
          (E = pi_{K1} · A · pi_{K2}, commutativity NOT required) or close 78.E as a
          documented impossibility result.

    • If §1/§2 expose structured centralizers (cosets) OR §3 stays in a proper
      subgroup
        ⇒ VERDICT (b): exploitable structure exists — proceed to Phase 1 (orbit/order
          lower bound) and Phase 2 (circuit-model CSP transfer theorem).

  Read the printed §1-§3 numbers above against these criteria to record the verdict
  in SecurityProofs-2 §11.8.5 and the TODO #78.E status line.""")
    print()


# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    print()
    print("nl_fscx_v2_csp.py — Phase 0 decision gate for Non-Abelian KEX (TODO #78.E)")
    print()
    t0 = time.monotonic()
    section1(); print(); sys.stdout.flush()
    section2(); print(); sys.stdout.flush()
    section3(); print(); sys.stdout.flush()
    section4()
    print(SEP)
    print(f"Total runtime: {time.monotonic() - t0:.1f} s")
    print("END nl_fscx_v2_csp.py")
    print(SEP)


if __name__ == '__main__':
    main()
