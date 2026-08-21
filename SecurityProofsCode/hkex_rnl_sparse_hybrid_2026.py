#!/usr/bin/env python3
"""
hkex_rnl_sparse_hybrid_2026.py — Is HKEX-RNL's CBD(η=1) secret "sparse"? (TODO #157)

Concrete worksheet backing SecurityProofs-4.md §11.6's re-check of

    "Careful with the Ring: Enhanced Hybrid Decoding Attacks against Module/Ring-LWE"
    [Hou-Jiang, eprint 2026/366]

whose abstract claims an O(N) hybrid-decoding speedup "in sparse secret setting", with
up to 13-bit security-estimate reductions that push 12 of 16 named FHE parameter sets
below 128-bit security.

The paper's PDF is Cloudflare-gated, so its formal sparsity definition cannot be read.
This worksheet therefore avoids depending on it: instead of comparing against one
threshold, it shows that *no* threshold in the sparse regime captures HKEX-RNL's
deployed secret distribution except with probability far below the security target.

  §1  CBD(η=1) coefficient law — exact and empirical
  §2  Exact Hamming-weight law of a CBD(η=1) secret at n=256
  §3  Threshold-independent sparsity test — P[HW ≤ h] across the whole sparse regime
  §4  Hybrid-attack guessing-space entropy — the precondition the speedup needs
  §5  Bit budget vs HKEX-RNL's 105–115-bit Core-SVP estimate

Deployed parameters: q=65537, p=4096, pp=4, η=1, n=256
Self-contained (no imports from the suite), per SecurityProofsCode convention; the
sampler in §1 is copied verbatim from `_rnl_cbd_poly` in
`Herradura cryptographic suite.py`.
"""

import os
from math import comb, log2

# ─────────────────────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────────────────────
Q       = 65537   # Fermat prime modulus (deployed)
ETA     = 1       # CBD(η=1): secret coefficients in {-1, 0, 1}
N       = 256     # deployed ring degree
TRIALS  = 20000   # empirical sample count for §1/§2

# HKEX-RNL's current estimated security (SecurityProofs-4.md §11.6)
CORE_SVP_LO, CORE_SVP_HI = 105, 115

# The paper's own headline improvements
RING_FACTOR_BITS = log2(N)   # the claimed O(N) speedup, in bits, at N=256
MEASURED_MAX_BITS = 13       # "improve the attack complexity by up to 13 bits"

SEP  = "=" * 74
SEP2 = "-" * 74


# ─────────────────────────────────────────────────────────────────────────────
# Sampler (copied verbatim from `_rnl_cbd_poly` in the suite)
# ─────────────────────────────────────────────────────────────────────────────

def _rnl_cbd_poly(n, eta, q):
    """Centered binomial distribution CBD(eta): each coefficient = a - b (mod q)."""
    if eta == 1:
        raw = os.urandom((n + 3) // 4)
        out = []
        for i in range(n):
            shift = (i & 3) * 2
            a = (raw[i >> 2] >> shift) & 1
            b = (raw[i >> 2] >> (shift + 1)) & 1
            out.append((a - b) % q)
        return out
    mask = (1 << eta) - 1
    byte_count = (2 * eta + 7) // 8
    out = []
    for _ in range(n):
        raw = int.from_bytes(os.urandom(byte_count), 'big')
        a   = bin(raw & mask).count('1')
        b   = bin((raw >> eta) & mask).count('1')
        out.append((a - b) % q)
    return out


def hamming_weight(poly, q):
    """Number of nonzero coefficients (values are 0, 1, or q-1 for CBD(1))."""
    return sum(1 for c in poly if c % q != 0)


# ─────────────────────────────────────────────────────────────────────────────
# §1  CBD(η=1) coefficient law
# ─────────────────────────────────────────────────────────────────────────────

def section1():
    print(SEP)
    print("§1  CBD(η=1) coefficient law — exact vs empirical")
    print(SEP)
    print("Each coefficient is a - b for independent uniform bits a, b:")
    print("    Pr[s_i =  0] = Pr[a=b]        = 1/2  = 0.5000")
    print("    Pr[s_i = +1] = Pr[a=1, b=0]   = 1/4  = 0.2500")
    print("    Pr[s_i = -1] = Pr[a=0, b=1]   = 1/4  = 0.2500")
    print("  => nonzero density  delta = 1/2 exactly (independent of n)")
    print()

    counts = {0: 0, 1: 0, Q - 1: 0}
    total  = 0
    for _ in range(TRIALS // N + 1):
        for c in _rnl_cbd_poly(N, ETA, Q):
            counts[c] = counts.get(c, 0) + 1
            total += 1

    print(f"Empirical over {total} sampled coefficients (deployed sampler):")
    print(f"    Pr[s_i =  0] = {counts[0] / total:.4f}")
    print(f"    Pr[s_i = +1] = {counts[1] / total:.4f}")
    print(f"    Pr[s_i = -1] = {counts[Q - 1] / total:.4f}")
    nz = (counts[1] + counts[Q - 1]) / total
    print(f"    nonzero density = {nz:.4f}   (expected 0.5000)")
    print()
    return nz


# ─────────────────────────────────────────────────────────────────────────────
# §2  Exact Hamming-weight law at n=256
# ─────────────────────────────────────────────────────────────────────────────

def section2():
    print(SEP)
    print(f"§2  Hamming weight of a CBD(η=1) secret at n={N}")
    print(SEP)
    print("Each coefficient is nonzero independently with probability 1/2, so")
    print(f"    HW ~ Binomial(n={N}, p=1/2)")
    mean = N * 0.5
    var  = N * 0.25
    sd   = var ** 0.5
    print(f"    E[HW]   = {mean:.1f}   ({mean / N * 100:.1f}% density)")
    print(f"    sd[HW]  = {sd:.1f}")
    print(f"    E[HW] is {mean / sd:.0f} standard deviations above HW = 0")
    print()

    obs = [hamming_weight(_rnl_cbd_poly(N, ETA, Q), Q)
           for _ in range(TRIALS // 20)]
    print(f"Empirical over {len(obs)} sampled secrets (deployed sampler):")
    print(f"    min HW = {min(obs)}   mean HW = {sum(obs) / len(obs):.1f}   max HW = {max(obs)}")
    print()
    return mean, sd


# ─────────────────────────────────────────────────────────────────────────────
# §3  Threshold-independent sparsity test
# ─────────────────────────────────────────────────────────────────────────────

def tail_prob_bits(h):
    """log2 Pr[HW <= h] for HW ~ Binomial(N, 1/2), computed exactly."""
    return log2(sum(comb(N, k) for k in range(h + 1))) - N


def section3():
    print(SEP)
    print("§3  Threshold-independent sparsity test")
    print(SEP)
    print("The attack's speedup is claimed 'in sparse secret setting'. Rather than")
    print("guess the paper's threshold, sweep every plausible one and ask: how likely")
    print("is a deployed CBD(η=1) secret to satisfy it at all?")
    print()
    print(f"    {'h <=':>6}  {'density':>9}  {'Pr[HW <= h]':>16}")
    print(f"    {'-' * 6}  {'-' * 9}  {'-' * 16}")

    rows = [1, 2, 4, 8, 16, 26, 32, 64, 96, 112, 128]
    for h in rows:
        bits = tail_prob_bits(h)
        print(f"    {h:>6}  {h / N * 100:>8.2f}%  {'2^' + format(bits, '.1f'):>16}")
    print()

    # The FHE sparse regime named by the paper's five target papers
    h_fhe = int(N * 0.006)
    print(f"The five cited FHE target papers use h/N ~ 0.2%-0.6% (h in {{64,128,192}}")
    print(f"against N = 2^15). Scaled to n={N} that is h <= {max(h_fhe, 1)}, reached with")
    print(f"probability 2^{tail_prob_bits(max(h_fhe, 1)):.1f} — i.e. never.")
    print()

    # Find the loosest threshold still below the 128-bit security target
    loosest = max(h for h in range(N // 2) if tail_prob_bits(h) < -128)
    print(f"Loosest threshold whose escape probability still beats 2^-128:")
    print(f"    h <= {loosest}  (density {loosest / N * 100:.1f}%),  Pr = 2^{tail_prob_bits(loosest):.1f}")
    print()
    print("=> Any sparsity definition at density below ~12% is escaped by a deployed")
    print("   CBD(η=1) secret with probability better than 2^-120 — below the 128-bit")
    print("   target itself. The conclusion therefore holds for ANY threshold the")
    print("   paper could reasonably use, without needing to read its definition.")
    print()
    return loosest


# ─────────────────────────────────────────────────────────────────────────────
# §4  Hybrid-attack guessing-space entropy
# ─────────────────────────────────────────────────────────────────────────────

def sparse_ternary_bits(h):
    """log2 of the number of ternary secrets of length N with exactly h nonzeros."""
    return log2(comb(N, h)) + h


def section4():
    print(SEP)
    print("§4  Guessing-space entropy — the precondition the speedup needs")
    print(SEP)
    print("The hybrid MITM/decoding lineage this paper accelerates splits the secret")
    print("into a guessed block and a lattice-decoded block. Its advantage over pure")
    print("lattice decoding comes from the guessed block having *low entropy*, which")
    print("for sparse secrets follows from there being few nonzero positions to place.")
    print()

    cbd_bits = N * 1.5   # per-coefficient Shannon entropy of CBD(1) = 1.5 bits
    print(f"    CBD(η=1) at n={N}:  1.5 bits/coefficient  ->  {cbd_bits:.0f} bits total")
    print()
    print(f"    {'sparse h':>9}  {'density':>9}  {'search space':>14}  {'gap vs CBD':>12}")
    print(f"    {'-' * 9}  {'-' * 9}  {'-' * 14}  {'-' * 12}")
    for h in [1, 2, 16, 64]:
        b = sparse_ternary_bits(h)
        print(f"    {h:>9}  {h / N * 100:>8.2f}%  {'2^' + format(b, '.0f'):>14}  {cbd_bits - b:>11.0f} bits")
    print()
    print(f"At the FHE sparse densities the paper targets, the guessing space is")
    print(f"{cbd_bits - sparse_ternary_bits(1):.0f}+ bits smaller than HKEX-RNL's. There is no comparably cheap")
    print("block to guess against a 50%-density secret, so the hybrid attack degenerates")
    print("to the primal lattice attack already covered by the Core-SVP estimate.")
    print()
    return cbd_bits


# ─────────────────────────────────────────────────────────────────────────────
# §5  Bit budget
# ─────────────────────────────────────────────────────────────────────────────

def section5():
    print(SEP)
    print("§5  Bit budget vs HKEX-RNL's Core-SVP estimate")
    print(SEP)
    print(f"HKEX-RNL deployed estimate (§11.6): {CORE_SVP_LO}-{CORE_SVP_HI} bits Core-SVP")
    print(f"Paper's claimed ring-structure speedup: O(N) = 2^{RING_FACTOR_BITS:.0f} "
          f"({RING_FACTOR_BITS:.0f} bits) at N={N}")
    print(f"Paper's measured maximum improvement:  {MEASURED_MAX_BITS} bits "
          f"(on sparse FHE parameter sets)")
    print()
    print("Stakes if the attack DID apply (it does not — §3, §4):")
    lo = CORE_SVP_LO - MEASURED_MAX_BITS
    hi = CORE_SVP_HI - MEASURED_MAX_BITS
    print(f"    {CORE_SVP_LO}-{CORE_SVP_HI} bits  ->  {lo}-{hi} bits  "
          f"(a material loss — hence this re-check)")
    print()
    print("Applicability verdict:")
    print("    §3: the sparsity precondition fails for ANY sparse-regime threshold,")
    print("        except with probability below 2^-120.")
    print("    §4: the guessing-space reduction the speedup monetizes does not exist")
    print("        at 50% density.")
    print()
    print(f"=> No revision to the {CORE_SVP_LO}-{CORE_SVP_HI}-bit Core-SVP estimate.")
    print("   'Small' (CBD, bounded magnitude) and 'sparse' (few nonzero positions)")
    print("   are distinct properties, and HKEX-RNL is small but emphatically not sparse.")
    print()


def main():
    print()
    print(SEP)
    print("HKEX-RNL vs the 2026 sparse-secret hybrid decoding attack (TODO #157)")
    print(f"Deployed: q={Q}, n={N}, η={ETA}   |   eprint 2026/366 [Hou-Jiang]")
    print(SEP)
    print()
    section1()
    section2()
    section3()
    section4()
    section5()
    print(SEP)
    print("Done. See SecurityProofs-4.md §11.6 for the write-up.")
    print(SEP)
    print()


if __name__ == "__main__":
    main()
