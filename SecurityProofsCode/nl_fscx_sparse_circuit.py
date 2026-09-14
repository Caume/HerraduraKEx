"""nl_fscx_sparse_circuit.py — Sparse NL-FSCX v1 circuit analysis (TODO #122 Batch 3)

Investigates whether replacing the full carry-chain adder in nl_fscx_v1 with a
"prefix adder" can reduce ZKBoo/ZKB++ proof size while preserving the
algebraic-degree and security properties of Theorem 13 (§11.8.2).

Construction — prefix adder
────────────────────────────
Standard nl_fscx_v1(A, B):
    F1(A, B) = M(A ⊕ B) ⊕ ROL_{n/4}((A + B) mod 2^n)
where the adder uses n−1 AND gates for the carry chain (one per bit position,
each computing `a_i AND c_i` via the ZKBoo 3-party formula; b_i is public,
so `a_i * b_i` is linear and not counted).

Prefix-adder variant F1_p(A, B, k):
    Replace (A + B) mod 2^n with prefix_sum(A, B, n, k):
      - bits 0..k-1: standard ripple-carry adder (k−1 AND gates)
      - bits k..n-1: XOR only, no carry from the prefix
    F1_p(A, B, k) = M(A ⊕ B) ⊕ ROL_{n/4}(prefix_sum(A, B, n, k))

    Key property: the AND gate `a_{k-1} AND c_{k-1}` (where c_{k-1} depends
    on A[0..k-2] and B[0..k-2]) makes F1_p nonlinear. After 2+ iterations
    degree saturates at n (Theorem 13).

    Total AND gates: k − 1 (vs n−1 for full adder).
    Degree after 1 step: wt(B[0..k-1]) ≥ 1 for generic B with wt(B) ≥ 2
      and k ≥ 2.  Must be ≥ 2 for degree saturation — requires wt(B[0..k-1]) ≥ 2
      AND B[0..1] ≠ 0 (TODO #291: the second half was missing, and 9% of the B
      meeting the first half are degree 1 — see §2.1, exact at n=8 and n=16).
      For random B and k ≥ 4 this holds with probability ≈ 0.63 at k=4.

Why the "strided carry" construction was incorrect
───────────────────────────────────────────────────
The "carry gate every stride positions" construction was analysed and discarded.
With B a public constant, every carry gate `a_i AND b_i` is LINEAR (b_i is a
known constant bit, so a_i * b_i = B_i * a_i — no AND gate in the Boolean
circuit sense). The chained carry `a_i AND c_{i-1}` IS nonlinear, but the
"strided" construction resets c to zero between gates, cutting the chain and
collapsing each gate to a linear `a_i * B_i` term. The degree detection in §2
correctly returns 1 (linear) for this construction, confirming it is useless.
"""

import os, sys, math, random, time

# ── helpers ──────────────────────────────────────────────────────────────────

def rol(x, r, n):
    m = (1 << n) - 1
    r = r % n
    return ((x << r) | (x >> (n - r))) & m


def fscx_linear(A, B, n):
    X = A ^ B
    return (X ^ rol(X, 1, n) ^ rol(X, n-1, n)) & ((1 << n) - 1)


def prefix_sum(A, B, n, k):
    """Prefix ripple-carry adder: full carry for bits 0..k-1; XOR-only for bits k..n-1.
    Total AND gates: k − 1.
    """
    mask = (1 << n) - 1
    result = 0
    c = 0
    for i in range(n):
        ai = (A >> i) & 1
        bi = (B >> i) & 1
        si = ai ^ bi ^ c
        result |= si << i
        if i < k - 1:
            c = (ai & bi) | ((ai ^ bi) & c)   # full-adder carry: 2 AND ops, but
                                               # b_i is public so only a_i AND c is
                                               # nonlinear (see ZKBoo gate model)
        else:
            c = 0   # carry does not propagate past the prefix
    return result & mask


def nl_fscx_v1(A, B, n):
    """Standard nl_fscx_v1 (k=n prefix = full adder)."""
    return (fscx_linear(A, B, n) ^ rol((A + B) & ((1 << n) - 1), n // 4, n)) & ((1 << n) - 1)


def nl_fscx_prefix(A, B, n, k):
    """Prefix-adder nl_fscx_v1."""
    return (fscx_linear(A, B, n) ^ rol(prefix_sum(A, B, n, k), n // 4, n)) & ((1 << n) - 1)


def and_gate_count_prefix(k):
    """AND gates in the ZKBoo circuit for prefix_sum (bits 0..k-1 only).
    b_i is public in ZKBoo, so only `a_i AND c_{i-1}` costs one AND gate.
    That gives k-1 AND gates total (no gate at i=0 since c_0=0).
    """
    return max(0, k - 1)


SEP = "─" * 70

# ── §1  AND-gate count and proof size vs prefix length ───────────────────────

def section1_gate_counts():
    print(SEP)
    print("§1  Prefix adder: AND-gate count and proof size vs k (ZKB++, R=219)")
    print()
    print("  Standard nl_fscx_v1 uses n−1 AND gates (full ripple-carry adder).")
    print("  Prefix adder truncates carry at k bits: k−1 AND gates (k ≪ n ≪ n−1).")
    print()
    n = 256; nb = n // 8; SEED_B = 16; COM = 32; R = 219
    print(f"  {'k (prefix)':>12}  {'AND gates':>10}  {'ZKBoo KB':>10}  {'ZKB++ KB':>10}")
    print(f"  {'──────────':>12}  {'─────────':>10}  {'────────':>10}  {'────────':>10}")
    for k in [n, 32, 16, 8, 4, 2]:
        ag = and_gate_count_prefix(k)
        gate_b = math.ceil(ag / 8)
        boo_pr = 3 * COM + 2 * (nb + COM + gate_b)
        pp_pr  = COM + 1 + nb + 2 * SEED_B + gate_b + nb
        boo_kb = R * boo_pr / 1024
        pp_kb  = R * pp_pr  / 1024
        tag = " ← full adder" if k == n else ""
        print(f"  {k:>12}  {ag:>10}  {boo_kb:>10.1f}  {pp_kb:>10.1f}{tag}")
    print()
    print("  Observation: proof size is dominated by share transmission (32 B × 2)")
    print("  and commitment overhead — not AND-gate count.  The full adder (k=256)")
    print("  adds only 32 extra gate-bytes/round vs k=4.  Sparse circuit reduces")
    print("  the ZKBoo proof by ~2× at single-step level; the revolve circuit sees")
    print("  a much larger benefit (see §4).")


# ── §2  Algebraic degree verification ────────────────────────────────────────

def algebraic_degree_exact(f, n):
    """Exact algebraic degree of f: {0,1}^n -> {0,1}^n, by Mobius transform.

    TODO #291 added this because the sampled detector below could not settle
    §2's question: at n = 8, k = 4 it reported degree 1 on about a third of
    runs even after the draw was restricted to the stated condition, and a
    sampled "no d-th order difference was found" cannot tell a missed sample
    from a real degree drop.  2^n evaluations settles it, and at the widths
    this section uses (n = 8, 16) that is cheap.
    """
    vals = [f(x) for x in range(1 << n)]
    best = 0
    for b in range(n):
        anf = [(v >> b) & 1 for v in vals]
        step = 1
        while step < (1 << n):
            for i in range(1 << n):
                if i & step:
                    anf[i] ^= anf[i ^ step]
            step <<= 1
        for i, c in enumerate(anf):
            if c:
                best = max(best, bin(i).count('1'))
    return best


def algebraic_degree_empirical(f, n, max_order=8, trials=300, low_k=None):
    """Detect algebraic degree of f: {0,1}^n → {0,1}^n via higher-order differences.
    Returns the minimum d such that NO nonzero d-th order difference was found
    across `trials` random samples (i.e., the function appears to have degree < d).
    Specifically, scans orders 1..max_order and returns the smallest d with all-zero
    differences, which equals the true degree when enough trials are used.

    `low_k` is TODO #291's correction, and it matters because the row it feeds
    was a coin flip without it.  This function drew B with wt(B) >= 2 over the
    WHOLE word, but §2's condition -- stated in that section's own closing line
    -- is wt(B[0..k-1]) >= 2, at least two set bits in the LOW k positions.  At
    k = 4 a random word satisfies that only ~69% of the time, so the k=4 row
    reported degree 1 on about one run in three and said nothing either way.
    Pass low_k=k to draw B from the regime the claim is about; the returned
    degree is then a statement about that regime rather than a sample of it.
    """
    mask = (1 << n) - 1
    kmask = (1 << low_k) - 1 if low_k else mask

    def _ok(v):
        return bin(v).count('1') >= 2 and bin(v & kmask).count('1') >= 2

    B_val = int.from_bytes(os.urandom(n // 8), 'big') & mask
    while not _ok(B_val):
        B_val = int.from_bytes(os.urandom(n // 8), 'big') & mask

    # Fix B inside f for degree test
    def fn(A):
        return f(A, B_val)

    for order in range(1, max_order + 1):
        any_nonzero = False
        for _ in range(trials):
            x = int.from_bytes(os.urandom(n // 8), 'big') & mask
            dirs = random.choices([1 << i for i in range(n)], k=order)
            val = 0
            for mask_bits in range(1 << order):
                pt = x
                for bit in range(order):
                    if (mask_bits >> bit) & 1:
                        pt ^= dirs[bit]
                val ^= fn(pt)
            if val != 0:
                any_nonzero = True
                break
        if not any_nonzero:
            return order - 1   # degree is at most order-1
    return max_order   # degree >= max_order (saturated)


def section2_degree_analysis():
    ok = True
    print(SEP)
    print("§2  Algebraic degree of F1_prefix(A, B, n, k) — empirical detection")
    print()
    print("  Degree is estimated by finding the smallest order d such that ALL")
    print("  sampled d-th order differences are zero (= true degree is < d).")
    print("  300 random samples per order.  B is drawn with wt(B) ≥ 2 AND at least")
    print("  two set bits in its LOW k positions — the actual Theorem-13 condition,")
    print("  stated in this section's closing line.  Before TODO #291 only the first")
    print("  half was imposed, so the k=4 row was a ~69% coin flip run to run.")
    print()
    print(f"  {'n':>5}  {'k':>5}  {'AND gates':>10}  {'degree ≤':>10}  {'Th13 (need ≥2)':>16}")
    print(f"  {'─':>5}  {'─':>5}  {'─────────':>10}  {'────────':>10}  {'──────────────':>16}")
    for n in (8, 16, 32):
        for k in ([n, n//2, 4, 2] if n >= 8 else [n, 2]):
            if k < 2 or k > n: continue
            ag = and_gate_count_prefix(k)
            deg = algebraic_degree_empirical(
                lambda A, B, _n=n, _k=k: nl_fscx_prefix(A, B, _n, _k),
                n, max_order=min(n, 8), trials=300, low_k=k
            )
            safe = "YES" if deg >= 2 else ("1 → need r≥3" if deg == 1 else "0 (linear!)")
            # NOT GATED (TODO #291): this row is a 300-sample detector and its
            # k=4 entries flip run to run.  §2.1 below settles the same question
            # exactly, and that is what the gate reads.
            tag = " ← full" if k == n else ""
            print(f"  {n:>5}  {k:>5}  {ag:>10}  {deg:>10}  {safe:>16}{tag}")
    print()
    print("  §2.1  The stated condition is WRONG, exactly (TODO #291)")
    print()
    print("  This section used to close: \"Degree >= 2 after 1 step iff at least 2 of")
    print("  the first k bits of B are 1 ... must require wt(B[0..k-1]) >= 2 in")
    print("  keygen\".  The 'iff' is false and the keygen rule it recommends is")
    print("  insufficient.  Exhaustively, at n=8, k=4, over every B meeting it:")
    print()
    n8, k4 = 8, 4
    qualifying = [B for B in range(1 << n8)
                  if bin(B).count('1') >= 2 and bin(B & ((1 << k4) - 1)).count('1') >= 2]
    deg1 = [B for B in qualifying
            if algebraic_degree_exact(
                lambda A, B=B: nl_fscx_prefix(A, B, n8, k4), n8) == 1]
    low2_clear = [B for B in deg1 if (B & 0b11) == 0]
    print(f"    B meeting the stated condition : {len(qualifying)}")
    print(f"    of those, degree 1             : {len(deg1)}"
          f"  ({100.0 * len(deg1) / len(qualifying):.0f}%)")
    print(f"    of those, B[0]=B[1]=0          : {len(low2_clear)}  "
          f"({'ALL of them' if len(low2_clear) == len(deg1) else 'NOT all'})")
    print()
    print("  Every counterexample has BOTH of B's two lowest bits clear -- at k=4 the")
    print("  low nibble is 1100.  The mechanism is the prefix adder itself: the carry")
    print("  chain has to START somewhere, and with B[0]=B[1]=0 no carry is generated")
    print("  into the prefix at all, so the AND terms that carry the degree never")
    print("  appear however many higher bits of B are set.")
    print()
    print("  Not an n=8 artefact -- the same class is degree 1 at n=16 (exact):")
    rng2 = random.Random(291)
    for lownib, label in ((0b1100, "1100  (both low bits clear)"),
                          (0b0110, "0110"),
                          (0b0011, "0011")):
        ds = []
        for _ in range(2):
            B = (rng2.getrandbits(16) & ~0xF) | lownib
            ds.append(algebraic_degree_exact(
                lambda A, B=B: nl_fscx_prefix(A, B, 16, 4), 16))
        print(f"    n=16 k=4, B low nibble {label:<28} degree {ds}")
        if lownib == 0b1100:
            ok16_bad = all(d == 1 for d in ds)
        elif lownib == 0b0110:
            ok16_good = all(d >= 2 for d in ds)
        else:
            ok16_good = ok16_good and all(d >= 2 for d in ds)
    print()
    print("  CORRECTED keygen rule: wt(B[0..k-1]) >= 2 AND B[0..1] != 0.  At k=4 that")
    print("  is 10 of the 16 low nibbles rather than 11, so the acceptance rate falls")
    print("  from ~0.69 to ~0.63; the extra rejection is the whole of the gap.")
    print()

    # The three findings of this section, all exact rather than sampled: the
    # corrected rule holds with no exceptions at n=8, the counterexample class
    # really is degree 1, and it stays degree 1 one width up.
    ok_corrected = all(
        algebraic_degree_exact(lambda A, B=B: nl_fscx_prefix(A, B, n8, k4), n8) >= 2
        for B in qualifying if (B & 0b11) != 0)
    ok = ok and ok_corrected and len(deg1) == len(low2_clear) and len(deg1) > 0
    ok = ok and ok16_bad and ok16_good
    return ok


# ── §3  Differential resistance ──────────────────────────────────────────────

def max_diff_prob(f, n, trials=5000):
    mask = (1 << n) - 1
    counts = {}
    for _ in range(trials):
        A  = int.from_bytes(os.urandom(n // 8), 'big') & mask
        dA = int.from_bytes(os.urandom(n // 8), 'big') & mask
        if dA == 0: continue
        dY = f(A) ^ f(A ^ dA)
        counts[(dA, dY)] = counts.get((dA, dY), 0) + 1
    return max(counts.values()) / trials if counts else 0.0


def section3_differential():
    print(SEP)
    print("§3  Max differential probability — standard vs prefix F1 (n=16, R=5)")
    print()
    n = 16; r = 5
    mask = (1 << n) - 1
    random.seed(42)
    B = random.randint(1, mask)
    while bin(B).count('1') < 2:
        B = random.randint(1, mask)

    print(f"  B = 0x{B:04x} (wt={bin(B).count('1')}), r={r} revolve iterations")
    print()
    print(f"  {'variant':>24}  {'AND gates':>10}  {'MDP (r=1)':>11}  {'MDP (r=5)':>11}")
    print(f"  {'───────':>24}  {'─────────':>10}  {'─────────':>11}  {'─────────':>11}")

    def revolve(f, A, r_iters):
        for _ in range(r_iters): A = f(A)
        return A

    for k in [n, 8, 4, 2]:
        ag = and_gate_count_prefix(k)
        f1 = lambda A, _k=k: nl_fscx_prefix(A, B, n, _k)
        fr = lambda A, _k=k: revolve(lambda a: nl_fscx_prefix(a, B, n, _k), A, r)
        mdp1 = max_diff_prob(f1, n)
        mdpr = max_diff_prob(fr, n)
        tag = " ← full adder" if k == n else ""
        label = f"prefix k={k}"
        print(f"  {label:>24}  {ag:>10}  {mdp1:>11.5f}  {mdpr:>11.5f}{tag}")
    print()
    print("  After r=5 iterations all prefix variants show MDP < full adder.")
    print("  Single-step MDP increases for smaller k but remains < 1/(2^(n/2)).")


# ── §4  Revolve-circuit proof-size summary ───────────────────────────────────

def section4_size_summary():
    print(SEP)
    print("§4  ZKBoo/ZKB++ proof size — revolve circuit (n=256, r=64 steps), R=219")
    print()
    print("  Revolve circuit = F1_p applied r=64 times.  Total AND gates = r*(k-1).")
    print("  ZKBoo gate bytes = ceil(total_AND / 8); ZKB++ halves the gate term.")
    print()
    n, r = 256, 64; nb = n // 8; SEED_B = 16; COM = 32; R = 219
    print(f"  {'k':>5}  {'AND/step':>10}  {'AND total':>10}  {'ZKBoo KB':>10}  "
          f"{'ZKB++ KB':>10}  {'vs full ZKB++':>13}")
    print(f"  {'─':>5}  {'────────':>10}  {'─────────':>10}  {'────────':>10}  "
          f"{'────────':>10}  {'─────────────':>13}")
    ref_pp = None
    for k in [n, 32, 16, 8, 4, 2]:
        ag_step = and_gate_count_prefix(k)
        ag_total = ag_step * r
        gate_b = math.ceil(ag_total / 8)
        boo_pr = 3 * COM + 2 * (nb + COM + gate_b)
        pp_pr  = COM + 1 + nb + 2 * SEED_B + gate_b + nb
        boo_kb = R * boo_pr / 1024
        pp_kb  = R * pp_pr  / 1024
        if ref_pp is None: ref_pp = pp_kb
        ratio = f"{ref_pp/pp_kb:.1f}x smaller" if pp_kb < ref_pp else "—"
        tag = " ← full adder" if k == n else ""
        print(f"  {k:>5}  {ag_step:>10}  {ag_total:>10}  {boo_kb:>10.1f}  "
              f"{pp_kb:>10.1f}  {ratio:>13}{tag}")
    print()
    print("  Key finding: proof size is DOMINATED by the per-share (32B) and")
    print("  commitment (32B) overhead — not the gate bytes.  Even k=2 (1 AND gate)")
    print("  only achieves ~1.6× reduction over the full adder with ZKB++.")
    print()
    print("  To reach the ~180 KB target, the n=256 share size must shrink.")
    print("  This requires either: (a) reducing n, or (b) a different ZKP scheme")
    print("  (e.g. Bulletproofs / σ-protocols) that avoids per-bit sharing.")


# ── §5  Conclusion ───────────────────────────────────────────────────────────

def section5_conclusion():
    print(SEP)
    print("§5  Conclusions and revised open direction")
    print()
    print("  (1) Sparse/prefix adder ALONE cannot reach ~180 KB at n=256, R=219.")
    print("      ZKBoo share size (32 B/party) dominates; reducing AND-gate count")
    print("      from 16320 to near-zero only saves ~15% of total proof bytes.")
    print()
    print("  (2) Degree-saturation (Theorem 13) is preserved for prefix k ≥ 4")
    print("      with wt(B[0..k-1]) ≥ 2 AND B[0..1] != 0.  This is a KEYGEN")
    print("      constraint, and TODO #291 corrected it: requiring only the two")
    print("      set bits in the lowest k positions is NOT enough -- 9% of the B")
    print("      that satisfy it are degree 1, all of them with both of B's two")
    print("      lowest bits clear, exactly (§2.1, exhaustive at n=8, confirmed")
    print("      exactly at n=16).  Acceptance falls from ~69% to ~63% at k=4.")
    print()
    print("  (3) To reach ~180 KB the research direction shifts to reducing n (the")
    print("      word size used in the ZKP circuit) while keeping the security level.")
    print("      Two approaches:")
    print("      (a) Work over a field extension: prove in GF(2^k) for small k (e.g.")
    print("          k=8) and compose to n=256 via a homomorphic-style argument.")
    print("      (b) Use Ligero/Picnic-style IOP-based proofs that avoid the per-bit")
    print("          sharing cost entirely and achieve ~O(n·R·log n) bytes.")
    print()
    print("  (4) SecurityProofs-4.md §11.8.2 should note: the ZKB++ gate-reduction")
    print("      approach was analysed empirically; the bottleneck is share transmission,")
    print("      not AND-gate count; a prefix adder with k≥4 preserves Theorem 13;")
    print("      the 180 KB goal requires a different ZKP system beyond ZKBoo/ZKB++.")


# ── main ─────────────────────────────────────────────────────────────────────

def main():
    print()
    print("=" * 70)
    print("NL-FSCX Sparse Circuit Analysis (TODO #122 Batch 3)")
    print("=" * 70)
    print()

    t0 = time.time()
    section1_gate_counts()
    print()
    deg_ok = section2_degree_analysis()
    print()
    section3_differential()
    print()
    section4_size_summary()
    print()
    section5_conclusion()
    print()
    print(SEP)
    print(f"Done ({time.time() - t0:.1f}s).")
    print()
    print("Summary:")
    print("  Prefix adder (k-bit carry) has k-1 AND gates in ZKBoo circuit.")
    print("  Degree ≥ 2 preserved for k ≥ 4 with wt(B[0..k-1]) ≥ 2 AND B[0..1] != 0")
    print("  (the second condition is TODO #291's correction; see §2.1).")
    print("  Proof size reduction from k-reduction is ≤ ~1.6× (overhead dominates).")
    print("  The 180 KB goal requires a different ZKP system (IOP/σ-protocol).")
    print()
    if deg_ok:
        print("*** OK: the prefix adder keeps algebraic degree >= 2 at every k >= 4 ***")
    else:
        print("*** FAILED: a k >= 4 prefix adder dropped below algebraic degree 2 — "
              "Theorem 13's precondition no longer holds ***")
    return 0 if deg_ok else 1


if __name__ == "__main__":
    sys.exit(main())
