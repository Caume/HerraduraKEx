# Formal Cryptographic Analysis of the Herradura Cryptographic Suite — Part 10

**Status:** See Part 1 (SecurityProofs-1.md) for full status header.

> **This is Part 10 of a split document.**
>
> - **Part 1 — §1** (SecurityProofs-1.md): Algebraic Foundations
> - **Part 2 — §2–§8** (SecurityProofs-2.md): Protocol Analysis · Security Analysis · Summary Tables · Quantum Attack Analysis · Experimental Code Index
> - **Part 3 — §9–§10** (SecurityProofs-3.md): Non-Linear Proposals · v1.4.0 Migration
> - **Part 4 — §11–§11.8.2** (SecurityProofs-4.md): Non-linearity and Post-quantum Extensions · NL-FSCX v1/v2 · HKEX-RNL
> - **Part 5 — §11.8.3–§11.8.10** (SecurityProofs-5.md): PQ Signature Options · HPKE-Stern-KEM
> - **Part 6 — §11.9** (SecurityProofs-6.md): HFSCX-256-DM
> - **Part 7 — §11.10–§11.13, §11.15–§11.33** (SecurityProofs-7.md): Zero-Knowledge Proof Extensions · Research-Review Sections
> - **Part 8 — §11.34–§11.36** (SecurityProofs-8.md): NL-FSCX v3 — Exact Row Analysis · Asymptotic Trail Slopes
> - **Part 9 — §11.37–§11.42** (SecurityProofs-9.md): The Width Residue · The Annealed Threshold at n = 256 · The Pair Correlation · The Quenched Check · The Certified Ladder · The Exact Slope
> - **Part 10 — §11.43** (this file): The Local Certificate

---

## 11.43 The local certificate — TODO #257, sixth pass

`SecurityProofsCode/local_potential_certificate.py` reproduces everything in this section.

§11.42 left TODO #257 owing one thing on the differential axis: that exact $\mu$, the minimum mean cycle of the fixed-key NL-FSCX v2 difference graph, does not decrease between n = 23 and n = 256. §11.37 had already closed two kinds of route. Comparing two graphs fails because there is no embedding between widths. Guessing a potential fails because Howard's bias correlates with no natural node statistic.

This pass tries the route those two leave open. It does not guess the potential; it optimises it. But it restricts the optimisation to potentials that a bit-position DP can evaluate at any width. If that worked it would be a proof at n = 256, the first in this line of work. It does not work, and the measured reason is specific.

### 11.43.1 The certificate

For any function $\varphi$ on differences, every cycle has mean at least

$$\min_{a \to b} \bigl( w(a,b) + \varphi(a) - \varphi(b) \bigr),$$

because $\varphi$ telescopes around a cycle. With $\varphi$ unrestricted the best such bound IS $\mu$: this is LP duality for the minimum mean cycle.

Now restrict $\varphi$ to be LOCAL: a sum over bit positions s of a table $G_s$ indexed by the w-bit window of the difference starting at s. The minimum above then becomes a shortest path along the bit positions. Its state is the carry-pair automaton of §11.38.1 plus the window bits of a and b, and its cost is linear in n. So the bound is evaluable at n = 256 for any window w that fits the state, and the best $G$ for a given w is a linear program.

### 11.43.2 The relaxation, and why the carry slot stays in

The edge weight is $-\log_2$ of a path COUNT, a sum over carry sequences, so it is not additive along the bit positions.

**Dropping the carry slot does not work.** The obvious additive relaxation charges each bit by the better of its two carry slots. It is sound, but the relaxed graph has $\mu = 0$ on every key tried, at n = 7, 8 and 10, whose true $\mu$ ranges from about 0.4 to 1.8. Every edge can find a free slot somewhere. This is the gate's negative control.

**Keeping the slot works.** The DP carries the 2-vector over the carry slot and merges states by the componentwise maximum. That can only over-count the path count, so the bound can only be too low. Measured against an exhaustive scan of every edge at n = 7, 8 and 10, it never exceeds the true minimum reduced cost, for the LP-optimal $G$ and for random ones. At the optimal $G$ it recovers most of the LP's value.

### 11.43.3 The window must grow with n

Write $w^*$ for the smallest window at which the optimised local bound equals $\mu$.

| n | 7 | 8 | 10 |
|---|---|---|---|
| median $w^*$ | 6 | 6 | 7 |
| $w^*$ range | 4–6 | 4–6 | 6–8 |

The median $w^*$ is n−1, n−2 and n−3: about 0.7n, and growing. A certificate that reaches $\mu$ has to see most of the word.

### 11.43.4 At a fixed window the bound does not grow

With the window fixed at 5 bits:

| n | 8 | 10 | 11 | 13 | 14 |
|---|---|---|---|---|---|
| keys | 12 | 12 | 12 | 6 | 6 |
| median bound / exact mu | 0.94 | 0.87 | 0.81 | 0.71 | 0.70 |
| median bound | 1.21 | 1.43 | 1.50 | 1.27 | 1.32 |
| median exact mu | 1.30 | 1.63 | 1.83 | 1.79 | 1.87 |

The certified share of $\mu$ falls at every width step. The bound itself is lower at n = 13–14 than at n = 10–11, while exact $\mu$ is not. A recorded, ungated run at n = 16 with w = 4 gives about 1.0–1.4 on three keys.

### 11.43.5 Why: the dual is not a cycle

The LP dual of the local bound is a probability distribution over edges whose source and target have the same window statistics at every position. A cycle is one such distribution, but most are not cycles.

The optimal dual sits on LIGHT differences. Its dual-weighted popcount is about 0.42n at n = 8, 0.37n at n = 10 and 0.34n at n = 11, falling with n. The optimal cycles are dense, 0.6n to 0.86n (§11.37). The dual can stitch together cheap, sparse edges because it never sees the support of a difference beyond w bits, while $M$ grows that support every round. A wider word only offers more cheap places to stitch, so the bound is set by the cheapest LOCAL neighbourhoods of $\delta$. Exact $\mu$ is a global quantity.

### 11.43.6 What this changes

**Closed by measurement, and recorded so it is not re-derived: a local potential certificate.** It is sound at every width and exact when the window covers the word. Its value at n = 256 is computable by a DP whose relaxation is measured to be close. It fails on the one quantity that matters: the window it needs grows with n, and the DP costs about $4^w$ per bit.

**The quenched effect, again.** §11.40 found the annealed model blind to where the RUNS of $\delta$ sit. This certificate is blind to how $M$ GROWS THE SUPPORT of a difference. Both are global properties of one fixed constant and one linear map, and a bound assembled from local pieces cannot carry either. The next route has to carry non-local information, and support growth under $M$ is the obvious candidate.

**Unchanged.** Exact $\mu$, measured to n = 23 in §11.42, grows at every width step, and the criterion holds at n = 256 if it keeps not decreasing. That monotonicity residue and the linear hull are still owed.

**No rating moves, and none could**, for the reasons §11.38.7 gives.
