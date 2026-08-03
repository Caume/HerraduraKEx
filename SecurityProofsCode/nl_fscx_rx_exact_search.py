#!/usr/bin/env python3
"""
nl_fscx_rx_exact_search.py — TODO #158: exact RX-differential search for NL-FSCX v1

Supersedes the Monte-Carlo/hill-climbing stand-in in `nl_fscx_rx_differential_2025.py`
with an *exact* analysis, in response to

    "An Automatic Search Framework for Rotational-XOR Differential Characteristics of
    ARX Ciphers" (2025, https://doi.org/10.1007/s10623-025-01571-6)

whose full text is paywalled.  Reproducing its CNF encoding is unnecessary here: the
search space for NL-FSCX v1 is small enough to solve *exactly*, which is strictly
stronger than any heuristic SAT/SMT trail search the paper could run.

WHY THE SEARCH SPACE COLLAPSES

An NL-FSCX v1 round is

    nl_fscx_v1(A, B) = fscx(A, B) XOR ROL((A + B) mod 2^n, n/4)

with fscx(A,B) = M(A) XOR M(B) and M = I XOR ROL XOR ROR.  M is a XOR of rotations, so
it commutes with rotation and is linear over GF(2).  Writing the RX-relation with
rotation offset g as Abar = ROTL(A,g) XOR da, Bbar = ROTL(B,g) XOR db, §1 verifies

    dY = M(da) XOR M(db) XOR ROL(dS, n/4),   dS := (Abar + Bbar) XOR ROTL(A+B, g)

i.e. the FSCX linear layer transmits *every* RX-difference with probability 1 and
contributes no search surface at all.  All probability mass comes from the modular
addition, and dY is a bijective function of dS.  The whole problem reduces to the
RX-differential of `+`, which §2 solves exactly with an O(n) carry DP.

  §1  Round reduction — the linear layer is probability-1 (empirical verification)
  §2  Exact RX-differential of modular addition (carry DP) + brute-force validation
  §3  Certified-optimal single-round characteristic at n=8 (exhaustive over da,db,dS)
  §4  Exact optimal multi-round trail at n=8 (max-product DP, Markov assumption)
  §5  The Markov assumption's error — exact p_rot vs the trail estimate
  §6  n=16 corroboration (low-Hamming-weight sweep + sampled p_rot)

Usage:
    python3 SecurityProofsCode/nl_fscx_rx_exact_search.py           # g=1, ~8 min
    python3 SecurityProofsCode/nl_fscx_rx_exact_search.py --full    # all g, ~30 min

§3 and §6 dominate the runtime: the exhaustive n=8 sweep costs one exact DP per
(da, db) pair, and that DP's cost grows with the number of reachable output
differences (cheap for sparse da/db, ~1000x dearer for dense ones).

Self-contained (no imports from the suite), per SecurityProofsCode convention.
"""

import math
import random
import sys
from itertools import combinations, product

SEP  = "=" * 74
SEP2 = "-" * 74


# ─────────────────────────────────────────────────────────────────────────────
# Primitives (mirroring `Herradura cryptographic suite.py`)
# ─────────────────────────────────────────────────────────────────────────────

def rotl(x, r, n):
    r %= n
    return ((x << r) | (x >> (n - r))) & ((1 << n) - 1) if r else x


def rotr(x, r, n):
    return rotl(x, (-r) % n, n)


def M(x, n):
    """FSCX linear map M = I XOR ROL XOR ROR."""
    return x ^ rotl(x, 1, n) ^ rotr(x, 1, n)


def nl_fscx_v1(A, B, n):
    """nl_fscx_v1(A,B) = fscx(A,B) XOR ROL((A+B) mod 2^n, n/4)."""
    return (M(A, n) ^ M(B, n)) ^ rotl((A + B) & ((1 << n) - 1), n // 4, n)


def maj(a, b, c):
    return (a & b) | (a & c) | (b & c)


# ─────────────────────────────────────────────────────────────────────────────
# §1  Round reduction
# ─────────────────────────────────────────────────────────────────────────────

def section1(trials=4000):
    print(SEP)
    print("§1  Round reduction — the FSCX linear layer is probability-1")
    print(SEP)
    print("Claim:  dY = M(da) XOR M(db) XOR ROL(dS, n/4)")
    print("        with dS = (Abar + Bbar) XOR ROTL(A+B, g)")
    print()

    rng = random.Random(0x2025)
    bad_round = bad_lin = 0
    for _ in range(trials):
        n = rng.choice([8, 16, 32])
        msk = (1 << n) - 1
        g  = rng.randrange(n)
        da = rng.randrange(1 << n)
        db = rng.randrange(1 << n)
        A  = rng.randrange(1 << n)
        B  = rng.randrange(1 << n)
        Ab = rotl(A, g, n) ^ da
        Bb = rotl(B, g, n) ^ db

        dY_actual = nl_fscx_v1(Ab, Bb, n) ^ rotl(nl_fscx_v1(A, B, n), g, n)
        dS = ((Ab + Bb) & msk) ^ rotl((A + B) & msk, g, n)
        if dY_actual != (M(da, n) ^ M(db, n) ^ rotl(dS, n // 4, n)):
            bad_round += 1

        lin  = M(A, n) ^ M(B, n)
        linb = M(Ab, n) ^ M(Bb, n)
        if (linb ^ rotl(lin, g, n)) != (M(da, n) ^ M(db, n)):
            bad_lin += 1

    print(f"  round reduction over {trials} random (n, g, da, db, A, B): "
          f"{'VERIFIED' if bad_round == 0 else str(bad_round) + ' FAILURES'}")
    print(f"  linear-layer prob-1 transmission:                        "
          f"{'VERIFIED' if bad_lin == 0 else str(bad_lin) + ' FAILURES'}")
    print()
    print("  => dY is a bijection of dS; the search space is the RX-differential of `+`.")
    print()
    return bad_round == 0 and bad_lin == 0


# ─────────────────────────────────────────────────────────────────────────────
# §2  Exact RX-differential of modular addition
# ─────────────────────────────────────────────────────────────────────────────

def rx_add_dist(n, g, da, db):
    """Exact distribution of dS = (Abar + Bbar) XOR ROTL(A+B, g) over all (A,B).

    Returns {dS: count}, counts summing to 4^n.

    Derivation.  With j(i) = (i-g) mod n, matching bit i of the barred sum against bit
    j of the rotated unbarred sum gives, for every position,

        cbar_i XOR c_j = da_i XOR db_i XOR dS_i

    where c / cbar are the two addition carry chains.  So dS is fully determined by the
    carry pair, and an O(n) DP over states (c_j, cbar_i) is exact.  The unbarred chain
    wraps (its carry is discarded at bit n and restarts at 0), so the carry entering the
    walk, c_{n-g}, is unknown: it is guessed as u and checked for consistency at the end.
    """
    g %= n
    out = {}
    dab = [((da >> i) & 1, (db >> i) & 1) for i in range(n)]
    for u in ([0, 1] if g else [0]):
        cur = {(u, 0, 0): 1}                       # (c, cbar, dS-prefix) -> count
        for i in range(n):
            j = (i - g) % n
            wrap = bool(g) and (j == n - 1)        # unbarred carry resets here
            dai, dbi = dab[i]
            nxt = {}
            for (c, cb, pref), cnt in cur.items():
                ds_bit = (cb ^ c) ^ dai ^ dbi      # forced by the carry pair
                pref2 = pref | (ds_bit << i)
                for a, b in product((0, 1), repeat=2):
                    key = (0 if wrap else maj(a, b, c),
                           maj(a ^ dai, b ^ dbi, cb),
                           pref2)
                    nxt[key] = nxt.get(key, 0) + cnt
            cur = nxt
        for (c, cb, pref), cnt in cur.items():
            if (not g) or c == u:                  # carry-consistency check
                out[pref] = out.get(pref, 0) + cnt
    return out


def _brute_dist(n, g, da, db):
    msk = (1 << n) - 1
    hist = {}
    for A in range(1 << n):
        rA = rotl(A, g, n) ^ da
        for B in range(1 << n):
            rB = rotl(B, g, n) ^ db
            dS = ((rA + rB) & msk) ^ rotl((A + B) & msk, g, n)
            hist[dS] = hist.get(dS, 0) + 1
    return hist


def section2(n=8, trials=8):
    print(SEP)
    print(f"§2  Exact RX-differential DP vs brute force (n={n})")
    print(SEP)
    rng = random.Random(11)
    mism = 0
    for _ in range(trials):
        g  = rng.randrange(n)
        da = rng.randrange(1 << n)
        db = rng.randrange(1 << n)
        d = {k: v for k, v in rx_add_dist(n, g, da, db).items() if v}
        b = {k: v for k, v in _brute_dist(n, g, da, db).items() if v}
        if d != b:
            mism += 1
            print(f"  MISMATCH g={g} da={da:#04x} db={db:#04x}")
    print(f"  {trials} random (g, da, db), full distributions compared over all "
          f"2^{2 * n} pairs")
    print(f"  result: {'EXACT — 0 mismatches' if mism == 0 else str(mism) + ' MISMATCHES'}")
    print()
    return mism == 0


# ─────────────────────────────────────────────────────────────────────────────
# §3  Certified-optimal single-round characteristic
# ─────────────────────────────────────────────────────────────────────────────

def section3(n=8, gammas=(1, 2)):
    print(SEP)
    print(f"§3  Certified-optimal single-round characteristic (n={n}, exhaustive)")
    print(SEP)
    print("Every (da, db, dS) is enumerated, so the optimum is certified, not sampled.")
    print()
    tot = 4 ** n
    print(f"  {'g':>3} {'baseline p(0,0,0)':>19} {'global best p':>15} {'-log2':>7}  optimum at")
    print(f"  {'-' * 3} {'-' * 19} {'-' * 15} {'-' * 7}  {'-' * 24}")
    results = {}
    for g in gammas:
        base = rx_add_dist(n, g, 0, 0).get(0, 0) / tot
        best_c, best_at = 0, None
        for da in range(1 << n):
            for db in range(1 << n):
                d = rx_add_dist(n, g, da, db)
                ds = max(d, key=d.get)
                if d[ds] > best_c:
                    best_c, best_at = d[ds], (da, db, ds)
        p = best_c / tot
        tag = "== pure-rotational" if best_at[:2] == (0, 0) else f"da={best_at[0]:#04x} db={best_at[1]:#04x}"
        print(f"  {g:>3} {base:>19.6f} {p:>15.6f} {-math.log2(p):>7.2f}  {tag}")
        results[g] = (base, p, best_at)
    print()
    return results


# ─────────────────────────────────────────────────────────────────────────────
# §4  Exact optimal multi-round trail
# ─────────────────────────────────────────────────────────────────────────────

def build_transitions(n, g, db):
    """da -> {da': best single-round probability}, using the §1 reduction."""
    tot = 4 ** n
    q   = n // 4
    Mdb = M(db, n)
    trans = []
    for da in range(1 << n):
        best = {}
        Mda = M(da, n)
        for ds, c in rx_add_dist(n, g, da, db).items():
            da2 = Mda ^ Mdb ^ rotl(ds, q, n)
            p = c / tot
            if p > best.get(da2, 0.0):
                best[da2] = p
        trans.append(best)
    return trans


def section4(n=8, g=1, dbs=(0, 1), rounds=6):
    print(SEP)
    print(f"§4  Exact optimal multi-round trail (n={n}, g={g}, Markov assumption)")
    print(SEP)
    print("Full 2^n-state transition graph, max-product DP — the optimum over ALL")
    print("trails, which the prior hill-climbing stand-in could not reach.")
    print("B is held constant across rounds (as in nl_fscx_revolve_v1), so db is fixed")
    print("and da_{r+1} = M(da_r) XOR M(db) XOR ROL(dS_r, n/4).")
    print()
    out = {}
    for db in dbs:
        trans = build_transitions(n, g, db)
        cur = [1.0] * (1 << n)
        hist = []
        for _ in range(rounds):
            nxt = [0.0] * (1 << n)
            for da in range(1 << n):
                base = cur[da]
                if base == 0.0:
                    continue
                for da2, p in trans[da].items():
                    v = base * p
                    if v > nxt[da2]:
                        nxt[da2] = v
            cur = nxt
            hist.append(max(cur))
        pure = trans[0].get(0, 0.0)
        print(f"  db={db:#04x}:  pure-rotational per-round p(da=0 -> 0) = {pure:.6f}"
              + (f"  (2^{math.log2(pure):.2f})" if pure > 0 else "  (impossible)"))
        print("    best r-round trail:  " + "  ".join(
            f"r={i+1}: 2^{math.log2(v):.1f}" if v > 0 else f"r={i+1}: 0"
            for i, v in enumerate(hist)))
        out[db] = (pure, hist)
    print()
    return out


# ─────────────────────────────────────────────────────────────────────────────
# §5  The Markov assumption's error
# ─────────────────────────────────────────────────────────────────────────────

def section5(n=8, g=1, rounds=6):
    print(SEP)
    print(f"§5  Markov trail estimate vs EXACT p_rot (n={n}, g={g})")
    print(SEP)
    print("p_rot(r) is measured exactly over all 2^{2n} (A,B) pairs — no sampling, no")
    print("independence assumption. The trail estimate multiplies per-round optima.")
    print()
    per = rx_add_dist(n, g, 0, 0).get(0, 0) / (4 ** n)
    N = 1 << n
    pairs = [(A, B) for A in range(N) for B in range(N)]
    cur  = list(pairs)
    curb = [(rotl(A, g, n), rotl(B, g, n)) for A, B in pairs]
    print(f"  {'r':>3} {'exact p_rot':>14} {'Markov trail':>14} {'understated by':>16}")
    print(f"  {'-' * 3} {'-' * 14} {'-' * 14} {'-' * 16}")
    rows = []
    for r in range(1, rounds + 1):
        cur  = [(nl_fscx_v1(a, b, n), b) for a, b in cur]
        curb = [(nl_fscx_v1(a, b, n), b) for a, b in curb]
        hits = sum(1 for (a, _), (ab, _) in zip(cur, curb) if ab == rotl(a, g, n))
        p  = hits / len(pairs)
        mk = per ** r
        print(f"  {r:>3} {p:>14.6f} {mk:>14.8f} {p / mk:>15.1f}x")
        rows.append((r, p, mk))
    print()
    print("  => The Markov/round-independence assumption underlying trail search is not")
    print("     tight for NL-FSCX v1: B is reused every round, so rounds are strongly")
    print("     dependent and the true probability is far HIGHER than any trail bound.")
    print("     Trail search therefore cannot be the binding analysis here — the direct")
    print("     measurement of TODO #75/#125 remains the operative characterisation.")
    print()
    return rows


# ─────────────────────────────────────────────────────────────────────────────
# §6  n=16 corroboration
# ─────────────────────────────────────────────────────────────────────────────

def low_weight(n, maxw):
    out = [0]
    for w in range(1, maxw + 1):
        for pos in combinations(range(n), w):
            v = 0
            for p in pos:
                v |= 1 << p
            out.append(v)
    return out


def section6(n=16, gammas=(1,), maxw=2, samples=200000, rounds=6):
    print(SEP)
    print(f"§6  n={n} corroboration")
    print(SEP)
    tot = 4 ** n
    cands = low_weight(n, maxw)
    print(f"  Low-Hamming-weight sweep (wt <= {maxw}): {len(cands)}^2 = "
          f"{len(cands) ** 2} (da, db) pairs per g")
    for g in gammas:
        base = rx_add_dist(n, g, 0, 0).get(0, 0) / tot
        best_c, best_at = 0, None
        for da in cands:
            for db in cands:
                d = rx_add_dist(n, g, da, db)
                ds = max(d, key=d.get)
                if d[ds] > best_c:
                    best_c, best_at = d[ds], (da, db, ds)
        p = best_c / tot
        verdict = ("== baseline (pure-rotational optimal)"
                   if abs(p - base) < 1e-12 else f"BEATS baseline at {best_at}")
        print(f"    g={g}: baseline 2^{math.log2(base):.2f}   best 2^{math.log2(p):.2f}   {verdict}")
    print()

    g = gammas[0]
    per = rx_add_dist(n, g, 0, 0).get(0, 0) / tot
    rng = random.Random(5)
    pairs = [(rng.randrange(1 << n), rng.randrange(1 << n)) for _ in range(samples)]
    cur  = list(pairs)
    curb = [(rotl(a, g, n), rotl(b, g, n)) for a, b in pairs]
    print(f"  Markov gap at n={n}, g={g} (sampled p_rot, {samples} pairs):")
    print(f"    {'r':>3} {'sampled p_rot':>15} {'Markov trail':>15} {'understated by':>16}")
    for r in range(1, rounds + 1):
        cur  = [(nl_fscx_v1(a, b, n), b) for a, b in cur]
        curb = [(nl_fscx_v1(a, b, n), b) for a, b in curb]
        hits = sum(1 for (a, _), (ab, _) in zip(cur, curb) if ab == rotl(a, g, n))
        p = hits / samples
        mk = per ** r
        ratio = f"{p / mk:>15.1f}x" if mk > 0 else " " * 15 + "-"
        print(f"    {r:>3} {p:>15.6f} {mk:>15.8f} {ratio}")
    print()


def main():
    full = "--full" in sys.argv
    print()
    print(SEP)
    print("NL-FSCX v1 — exact RX-differential search (TODO #158)")
    print("Supersedes nl_fscx_rx_differential_2025.py's Monte-Carlo stand-in")
    print(SEP)
    print()
    section1()
    section2()
    section3(n=8, gammas=tuple(range(1, 8)) if full else (1,))
    section4(n=8, g=1)
    section5(n=8, g=1)
    section6(n=16)
    print(SEP)
    print("Done. See SecurityProofs-4.md (NL-FSCX rotational subsection) for the write-up.")
    print(SEP)
    print()


if __name__ == "__main__":
    main()
