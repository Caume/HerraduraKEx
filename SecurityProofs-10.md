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
> - **Part 10 — §11.43–§11.47** (this file): The Local Certificate · The Local Certificate at n = 256 · The Linear Hull, Measured · Where the Cycles Pay · Two Routes Without a Potential

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

---

## 11.44 The local certificate at n = 256 — TODO #257, seventh pass

`SecurityProofsCode/local_certificate_n256.py` reproduces everything in this section. It drives `local_certificate_dp.c` and re-verifies the pinned tables in `local_certificate_n256.json`.

§11.43 measured, at n ≤ 14, that a certificate built from w-bit windows needs a window that grows with n. It concluded that what is left has to carry non-local information. This pass tries that first. Then it stops extrapolating and solves the certificate at the deployed width.

### 11.44.1 Non-local information, added at small n

There are three ways to give the certificate something a window cannot see. Each is measured as a median share of exact $\mu$:

| n | 8 | 10 | 11 |
|---|---|---|---|
| a global statistic alone (popcount, run count) | 0.32 | 0.29 | 0.37 |
| w = 5 windows | 0.94 | 0.88 | 0.83 |
| w = 5 windows + the global statistic | 0.97 | 0.91 | 0.88 |
| w = 5 windows on the two-round graph | 0.99 | 0.93 | 0.90 |

A global statistic alone admits a self-loop at its lightest same-class edge. Added to the windows it buys 0.03–0.04, and two-round paths buy 0.05–0.07. In every row the share still falls with n. A k-round certificate sees k rounds of support growth, a fixed amount, while what it has to capture grows with n.

### 11.44.2 Solving the LP without enumerating the graph

The LP of §11.43 has one row per edge, and the graph at n = 256 cannot be listed. Constraint generation avoids listing it. Each round, the sound DP's back-pointer traces and an exact single-carry-path Viterbi propose edges. Every proposed edge gets its exact weight, and a row is added only if the current potential violates it. Three things make this work.

**Both separators are needed.** The Viterbi alone overstates the LP at n = 10: it gives 1.48, 1.03 and 1.44 where the optimum is 1.22, 0.84 and 1.38. Checked against every edge, its potential certifies only 0.28, 0.00 and 0.50. A single carry path under-counts exactly the edges that carry the most paths.

**The box on the potential grows in stages.** An unconstrained potential runs to the edge of its box in the first rounds. A DP over such a potential merges so many unrelated prefixes that its traces stop naming violated edges.

**One shared table.** Let $\varphi$ be a sum over positions of one 16 × 16 table $F$, indexed by the 4-bit window of the difference and the 4-bit window of $\delta$ at that position, and used at every position. It costs 2–7% of the LP against a table per position, at n = 16 and 20. It also keeps the LP the same size at every width.

The DP is the sixth pass's, renormalised per bit position. At n = 256 the old one overflows a double for a large potential. The new one never exceeds the exhaustive minimum reduced cost on 36 (key, potential) pairs.

### 11.44.3 Solved at each width, the bound does not grow

Through n = 48 the potential comes from the LP; from n = 64 on, from a supergradient ascent. By constraint generation, n = 64 takes about 30 minutes per key and the rows grow faster than n. Where both ran (16 keys, n = 16 to 64), the ascent's bound is 0.78–1.11 of the LP route's, median 0.96. Every figure below is the sound DP's bound at the potential found, so it is a theorem about that key's graph: every cycle has mean at least this much.

| n | 16 | 20 | 24 | 32 | 48 | 64 | 96 | 128 | 192 | 256 |
|---|---|---|---|---|---|---|---|---|---|---|
| keys | 3 | 3 | 3 | 3 | 3 | 3 | 3 | 3 | 3 | 4 |
| median certified bound | 0.81 | 1.50 | 1.36 | 0.98 | 1.03 | 0.72 | 0.76 | 0.67 | 0.77 | 0.66 |
| median exact mu | 1.82 | 2.93 | | | | | | | | |

The figures through n = 48 are by LP and the rest by ascent. The LP's own value, which bounds any shared-table certificate on that key's exact minimum, is 0.97 at n = 16, 1.81 at n = 20 and 1.35–1.46 at n = 64. Exact $\mu$ grows about 0.14 per bit (§11.42).

So the certified bound peaks near n = 20 and then sits at about 0.6–0.8 per round, while $\mu$ keeps rising. The certified share falls roughly as 1/n. The sixth pass read that trend off n ≤ 14; here it is measured to n = 256.

### 11.44.4 What it certifies at n = 256

The four pinned keys at n = 256 get $\mu$ at least 0.54, 0.58, 0.74 and 0.90 per round. These are the first nonzero lower bounds on $\mu$ at the deployed width. The trivial one is 0, because every key has a probability-1 one-round differential. Each table is 256 numbers, and the gate re-verifies all sixteen pinned certificates from scratch. Every one is below the 4/3 criterion, so this class proves the criterion at no key measured. A 10,000-step ascent on the first of them returns the same 0.58 as 3,000 steps: the ascent has stopped improving, not run out of steps.

The finite-round corollary is weak. An r-round trail weighs at least $r t - (\max\varphi - \min\varphi)$, and $\varphi$ spans 77–98 bits at n = 256. So 192 rounds are certified at only 13–95 bits, against the 256 the criterion asks. The per-round statement is the useful one.

**Transfer control.** Solve one table jointly over six keys at n = 24 and carry it to n = 256. It certifies 0.50–0.70 on its own keys and is negative on all six n = 256 keys. Local configurations it never saw are unconstrained, and the potential exploits them. The certificate has to be solved per key, at the width.

### 11.44.5 What this changes

**Closed by measurement: local certificates, at every width.** §11.43 closed them by extrapolation from n ≤ 14. Solving them to n = 256 confirms it, and adds that the bound is positive at the deployed width. It is the first rigorous lower bound on the asymptotic per-round weight at n = 256, but it is roughly half the criterion and a small fraction of $\mu$.

**What a window misses** is not density, which buys 0.03–0.04, and not a few rounds of support growth, which buy 0.05–0.07. It is that a LIGHT difference cannot stay light around a whole cycle. The LP dual stitches cheap, sparse, locally balanced edges together, while every real cheap cycle is dense. The next route has to bound, globally, how much weight a sparse difference sheds under $M$ per round. That is a statement about the support, not about windows of it.

**Unchanged.** Exact $\mu$, measured to n = 23, grows at every width step. Still owed: monotonicity from n = 23 to 256, and the linear hull. No rating moves (§11.38.7).

---

## 11.45 The linear hull, measured — TODO #257, eighth pass

`SecurityProofsCode/hull_exact.py` reproduces everything in this section. It drives `hull_exact.c`.

#257 has carried two obligations since it merged #252 and #254. The second has been carried forward unchanged by all seven passes, since §11.36.9. Every number in this line of work is a TRAIL weight. What an attacker gets is the HULL: the signed sum over every trail that shares the endpoints. A trail weight bounds it in one direction only. This pass measures the hull exactly, at the widths where that is possible.

### 11.45.1 The object, and why it is not a model

Fix a key B. Build the r-round map of the shipped round as a table, r = 1 up to three rounds past 3n/4. That round is x ↦ M(x ⊕ i ⊕ B) + δ(B) mod 2^n, including the round constants i of TODO #245. Then scan the map's whole correlation table and whole difference table for the largest nontrivial entry. Write H_lin(r) and H_diff(r) for those, in bits. Nothing here assumes independence, key averaging or a Markov chain. The figures are what the cipher has at that width.

The round constants matter here and nowhere earlier. An XOR constant leaves every trail weight unchanged, which is why TODO #245 could add them without touching a single trail bound. It does change the sign of each trail's contribution, and the hull is a signed sum. Every earlier measurement was blind to them; this one is not.

Beside the hull, three more measurements:

- the best r-round trail on each axis, T_lin(r) and T_diff(r): the least weight of any r-step walk on the mask or difference graph;
- the same table scan over uniformly random permutations, which gives the ideal-cipher floor;
- the point at which a hull counts as at the floor: when it is no worse than the worst of 32 random permutations (12 at n = 14).

A fixed tolerance around the median floor does not work. At small n the tables are coarsely quantised, and a first draft with a 0.25-bit band flagged nine keys that were merely inside the random spread.

The cost is n · 4^n per round, so the method reaches n = 14 by default and n = 16 under `--full`. It does not reach n = 23, the widest exact trail measurement (§11.42), let alone 256.

**Soundness.** The helper reproduces the shipped `nl_fscx_revolve_v2` on all 65,536 inputs at n = 16, for two keys and r = 1 and 3. Its hulls and trails agree with a pure-Python brute force at n = 7 for r = 1–4: the brute force takes every (u, v) and every input difference, and the trails come from Bellman iteration on the graph builders of §11.35–§11.36. One round has a correlation-1 and a probability-1 approximation on every key, the MSB freebie. **Negative control:** with + replaced by ⊕, the round is affine, and the scan reads 0 bits at every round on both axes, so it can report a failure.

### 11.45.2 Hull against trail

The table gives three quantities, as min / median / max over keys:

- **H/T:** the hull's weight divided by the best trail's, at the last round before saturation;
- **gain:** the trail weight minus the hull weight, in bits, at the same round;
- **lag:** how many rounds after the best trail the hull reaches the floor, as median (maximum).

A round counts as before saturation while the trail weight is at least 1 bit and at least 0.5 bits below the median floor. The n = 16 row is `--full` only.

| n | keys | linear H/T | linear gain (bits) | linear lag | differential H/T | differential gain (bits) | differential lag |
|---|---|---|---|---|---|---|---|
| 8 | 16 | 0.72 / 0.75 / 0.93 | 0.09 / 0.25 / 0.39 | 0 (2) | 0.76 / 0.97 / 1.12 | −0.26 / 0.07 / 0.86 | 0 (2) |
| 10 | 16 | 0.71 / 0.91 / 1.23 | −0.42 / 0.16 / 0.57 | 1 (2) | 0.90 / 0.97 / 1.06 | −0.29 / 0.15 / 0.52 | 1 (2) |
| 11 | 16 | 0.75 / 0.86 / 1.03 | −0.08 / 0.27 / 0.60 | 1 (2) | 0.74 / 0.95 / 1.02 | −0.13 / 0.30 / 1.11 | 1 (1) |
| 13 | 8 | 0.71 / 0.89 / 0.99 | 0.01 / 0.30 / 0.75 | 1 (2) | 0.85 / 0.95 / 0.97 | 0.20 / 0.45 / 1.04 | 0 (1) |
| 14 | 6 | 0.77 / 0.87 / 0.89 | 0.40 / 0.49 / 0.89 | 1 (1) | 0.79 / 0.90 / 1.00 | −0.03 / 0.85 / 1.96 | 1 (1) |
| 16 | 8 | 0.73 / 0.82 / 0.92 | 0.38 / 0.76 / 1.06 | 1 (1) | 0.80 / 0.90 / 1.02 | −0.14 / 1.08 / 2.18 | 1 (1) |

At n = 7 the linear floor (1.5 bits) leaves no round between the 1-bit minimum and saturation, so that row is omitted. One n = 16 key, with tz(δ) = 5, is in #253's weak class and is slow on the trail already. Its linear lag is 3, and it is left out of the lag column.

**Clustering is real.** Before saturation the hull usually runs below the best trail. The median gain is positive at every width, and the maximum reaches 1.1 bits linear and 2.2 bits differential at n = 16. Sometimes the hull is above the trail instead (negative gain), where trails with opposite signs cancel.

**It is a share, and the share falls.** The gain in bits grows with n partly because the trail weight at the last pre-saturation round does. As a share of that weight, the median is:

| n | 10 | 11 | 13 | 14 | 16 |
|---|---|---|---|---|---|
| linear | 0.91 | 0.86 | 0.89 | 0.87 | 0.82 |
| differential | 0.97 | 0.95 | 0.95 | 0.90 | 0.90 |

A least-squares line falls about 0.011 per bit on both axes. The linear medians are noisy; the differential ones fall almost monotonically. No key at any width keeps less than 0.71. A draft of this section read n = 10–14 alone, saw "no downward trend", and called the hull a fixed factor. The n = 16 row withdrew that before it was published.

**In rounds it costs about one, at every width.** The hull reaches the ideal floor at most two rounds after the best trail, and typically one, outside #253's class. At n ≥ 13 every key's hull is at the floor by r = 3n/4 + 1.

### 11.45.3 Late, not stuck

Seven (key, axis) cells have a trail that clears the floor by r = 3n/4 and a hull that does not. Six are at n ≤ 11 and one is at n = 16. The clearest is n = 8, B = 21 on the linear axis: the trail weighs 2.31 bits at r = 6, while the hull weighs 1.36 against a worst random permutation of 1.61.

The count is not the finding. An ideal cipher lands below the worst of 32 random permutations about once in 33 tries, which is about 3.4 of the 113 such cells at n ≤ 13. What matters is that every one reaches the floor within two more rounds: the one-round lag of §11.45.2, crossing 3n/4 at widths where 3n/4 leaves no slack. The n = 16 cell is a quantised maximum one count above what every random permutation showed, and it is at the floor one round later.

### 11.45.4 What this changes

**Item (2) of #257 is no longer unreached.** The linear hull has been measured exactly, for the shipped round with its round constants, to n = 14 (n = 16 under `--full`). It is a proportional correction to the trail. At n = 16 it is worth a median 18% of the trail weight on the linear axis and 10% on the differential, at most 29% on any key. The share grows slowly with width.

**It cannot be carried to n = 256 as a fixed factor.** Exact $\mu$ at n = 23 is 2.4× the linear criterion and 2.2× the differential one (§11.42). The hull eats that margin only if its share falls below 0.42 on the linear axis or 0.45 on the differential. At n ≤ 16 no key comes close; the worst is 0.71. A straight line through the medians would reach 0.42 near n = 50. That is an extrapolation of exactly the kind #257 has withdrawn four times. It is recorded here as the question it raises, not as an answer.

**Still owed.** Monotonicity of exact $\mu$ in n, from n = 23 to 256, unchanged from §11.44.5. And now the hull share above n = 16, which no exact method reaches: the cost is n · 4^n per round. No rating moves (§11.38.7).

---

## 11.46 Where the cycles pay — TODO #257, ninth pass

`SecurityProofsCode/live_region_certificate.py` reproduces everything in this section.

§11.44.5 said what the window certificate misses: a light difference cannot stay light around a whole cycle, so the next route had to carry non-local information about how a difference moves. This pass finds such a fact, and it is exact. It then measures where the optimal cycles actually pay, and gives the certificate that information. The certificate does not improve, and a control says why.

### 11.46.1 The live region

Three facts, each checked exhaustively:

- **Addition with a constant keeps the lowest active bit of a difference.** Below that bit the two inputs agree, so their carries agree, so the output difference is zero there and one at that bit. There were 0 violations over every difference and every input, at n = 10, for six keys.
- **M moves the lowest active bit down by exactly one.** The exception is a difference whose most significant bit is set: ROL wraps that bit to position 0, and the lowest active bit resets to 0. There were 0 violations over every difference at n = 10 and n = 16.
- **XOR round constants do not touch a difference.**

So in every round the lowest active bit either descends one position for free or resets at the wrap, and every cycle must reset. The bits below it are dead: no carry difference exists there. Everything above it is the **live region**. The linear axis is the mirror image. Addition with a constant has a nonzero correlation only when the input and output masks share their highest bit (0 violations over every mask pair at n = 8), so a mask's live region is everything below its highest bit.

Every step of every optimal cycle measured in §11.46.2 obeys this.

### 11.46.2 Where the optimal cycles pay

For each key, the exact solver of §11.42 returns an optimal cycle. Each edge's weight is split bit by bit by the chain rule along the carry automaton, from the least significant bit up. The split is exact: it sums to the solver's edge weight on every edge, to within 5e-13. On the linear axis the split uses the sign-free norm of the carry vector, and the last position absorbs the final cancellation.

| axis | n | keys | weight on or one above a run boundary of δ | share of positions that are | cost per position one above a boundary ÷ elsewhere | $\mu$ per boundary |
|---|---|---|---|---|---|---|
| differential | 13 | 16 | 0.93 | 0.65 | 4.2 | 0.31 |
| differential | 14 | 16 | 0.90 | 0.61 | 4.1 | 0.34 |
| differential | 16 | 12 | 0.89 | 0.62 | 4.1 | 0.31 |
| differential | 17 | 12 | 0.88 | 0.62 | 3.1 | 0.32 |
| linear | 13 | 16 | 0.90 | 0.65 | 2.2 | 0.15 |
| linear | 14 | 16 | 0.79 | 0.61 | 1.8 | 0.16 |
| linear | 16 | 12 | 0.79 | 0.62 | 1.8 | 0.15 |
| linear | 17 | 12 | 0.83 | 0.62 | 1.3 | 0.16 |

A run boundary is a position where δ's bit differs from the one below it. The weight columns are medians over keys.

**The cost is at δ's run boundaries.** Inside a run of δ the carry is nearly determined, because it tends to the run's value. Just above a boundary it is a fresh random bit. Uncertainty costs weight; determinism does not. That is why a position one bit above a boundary costs three to four times an ordinary one on the differential axis. It is the mechanism under §11.42's finding that exact $\mu$ rises with the run count of δ, which until now was only a regression.

**δ's trailing zeros are free.** With no carry in and a 0 addend, no carry can form, so a difference there passes at no cost. In all 28 keys whose lowest run is zeros, no optimal cycle pays anything inside that run. A lowest run of ones is paid for in 8 of 28. This is #253's weak class, keys with at least four trailing zeros in δ, seen from the cycle side.

**It is not a figure for n = 256.** $\mu$ per boundary is steady at about 0.31 (differential) and 0.15 (linear) over these widths, but it is not a constant. Across keys it falls as boundaries crowd: the correlation with boundary density is −0.56 differential and −0.60 linear. Boundaries share cost. A typical 256-bit δ has about 128 of them, and how much each would then cost is exactly the open question.

**No per-round bound of this shape exists.** In 61 rounds of optimal cycles, three or more boundaries are live and the round costs under 0.05 bits. Any argument has to amortise cost across rounds, which is what a potential does.

**Cycles are not pinned at the wrap.** The share of rounds whose lowest active bit has left the bottom three positions grows from 0.25 to 0.64 over n = 13–17 on the differential axis. So the cycles are not a finite problem at the wrap boundary either.

### 11.46.3 The certificate, told where the live region is

The window LP of §11.43 and §11.44 gets one extra table, a value per class of some feature of the live region. Five features are tried: the position of the lowest active bit; the number of δ boundaries in the live region (§11.46.2's quantity); the lowest and highest active bits together; and a 3-bit or 5-bit window anchored at the lowest active bit. Each runs against the exhaustive graph, as a share of exact $\mu$, at windows of 3 and 5 bits.

Beside each feature is a **control**: a random labelling of the nodes into the same number of classes.

| feature | classes | w = 3, n = 8 → 10 | random, same classes | w = 5, n = 8 → 10 | random, same classes |
|---|---|---|---|---|---|
| windows only | – | 0.737 → 0.598 | – | 0.940 → 0.878 | – |
| lowest active bit | n | 0.750 → 0.644 | 0.769 → 0.639 | 0.946 → 0.884 | 0.954 → 0.888 |
| boundaries in the live region | n | 0.741 → 0.635 | 0.770 → 0.638 | 0.940 → 0.881 | 0.948 → 0.886 |
| lowest and highest bits | n² | 0.791 → 0.712 | 0.878 → 0.791 | 0.957 → 0.904 | 1.000 → 0.946 |
| anchored 3-bit window | 8n | 0.789 → 0.685 | 0.896 → 0.779 | 0.962 → 0.897 | 1.000 → 0.940 |
| anchored 5-bit window | 32n | 0.836 → 0.715 | 0.998 → 0.905 | 0.989 → 0.916 | 1.000 → 0.988 |

**Every feature leaves the share falling.** That was the stop rule set before the run.

**None clears the control.** The random labelling ties the two n-class features, within 0.005, and beats every richer one, by 0.011 to 0.19. So what a feature buys is its class count, not its content. At these sizes extra classes let the LP approach a separate value per node, and per-node values give exactly $\mu$. Without the control, an anchored feature paired with the highest bit reaches 1.000 at n = 8, which reads as progress; it has 4096 classes for 256 nodes. At n = 256 a random labelling has no structure for the bit-position DP to evaluate, so it is not a candidate. It is the bar a usable feature had to clear.

### 11.46.4 What this changes

**A structural fact, exact at every width.** The live region of a difference, or of a mask, moves one bit per round or resets at the wrap. It is the non-local information §11.44.5 asked for, and it is true.

**Where $\mu$ is paid.** At δ's run boundaries, about one bit above each, with δ's trailing zeros free. This explains the run-count dependence of §11.42. It is a description, not a figure for n = 256, because the cost per boundary falls as boundaries crowd.

**The local-potential route is closed.** Three passes have now given the window certificate non-local information: windows alone (§11.43), global statistics and two-round paths (§11.44), and the live region (here). Each leaves the certified share falling. This pass adds the control the others lacked: a random labelling of equal size does as well. A potential whose class count stays small against the graph carries nothing a DP at n = 256 could use. A bound at the deployed width needs an argument about cycles, not about edge-local potentials, and §11.46.2 is what such an argument would have to account for.

**Still owed.** Monotonicity of exact $\mu$ in n, and the hull share above n = 16, both unchanged from §11.45.4. No rating moves (§11.38.7).

---

## 11.47 Two routes without a potential — TODO #257, tenth pass

`SecurityProofsCode/width_lift_closure.py` reproduces everything in this section. It drives the C solver of §11.42.

§11.46.4 closed the local-potential route and said that a bound at n = 256 needs an argument about cycles. Two cycle-level routes need no certificate at all. This pass walks both, and neither reaches n = 256. Each fails in a way that says something about the question.

### 11.47.1 An upper bound by construction

Every bound in #257 so far has been a lower bound. §11.42 left two readings of n = 256 standing, about 13 from a power law and about 33 from a levelled per-bit median, and no lower bound can separate them. An upper bound can. One explicit cycle at n = 256 with mean below 33 would refute the levelled reading for that key.

The search is the simplest one available. Map each difference to its cheapest out-edge. Best-first search over the carry-pair automaton finds that edge exactly, because the partial weight never decreases along a branch. The map is a function on $2^n$ differences, so iterating it must close a cycle, and every edge on that cycle is a real edge. Its mean is a sound upper bound on $\mu$. On 441 nodes at n = 10 the enumerator returns the same least edge weight as the certified solver's row.

**Where it closes, the cycle is loose.** Against exact $\mu$ at n = 13 and 14 the greedy cycle's mean is 1.27 to 2.03 times as large, with a median of 1.47. At n = 20–26 it is 0.21–0.30 per bit, against exact $\mu$'s 0.13–0.15.

**It closes after exponentially many steps.** The rho length (tail plus cycle), median over 16 walks per width:

| n | 14 | 16 | 20 | 22 | 24 | 26 |
|---|---|---|---|---|---|---|
| log2 median rho | 7.21 | 8.98 | 9.86 | 10.21 | 11.13 | 14.45 |
| greedy cycle mean per bit | 0.174 | 0.216 | 0.302 | 0.285 | 0.267 | 0.207 |

A least-squares line gives 0.48 bits of rho per bit of width. A random mapping gives 0.5. Over n = 14–22 alone the slope is 0.34, so the exact rate is not pinned. Either rate puts closure at n = 256 beyond $2^{80}$ steps. Breadth-first exploration does no better: 20,000 nodes at n = 32 or 64, expanding four cheapest edges each, contained no cycle at all.

**So there is no constructive upper bound on $\mu$ at n = 256.** Even a walk that did close would be about 1.5 times loose. It could confirm a low value near the power law's 13, never establish a high one. The two readings of §11.42 stay unseparated.

### 11.47.2 The lift between widths

§11.37 recorded that there is no embedding between widths, because M and δ both depend on n. That is true of the graphs. It is not true of the keys. Insert one bit inside a run of δ, equal to the run: that is a natural map from width n to n + 1 that keeps δ's boundary sequence. The strongest form of what #257 owes would be that exact $\mu$ never decreases along it. With a second local operation, adding boundaries, that would carry $\mu \geq 4/3$ from a width where it is exact to n = 256 one step at a time.

It does not hold. Every run of every key is stretched in turn and exact $\mu$ compared before and after (n + 1 = 15 is skipped by stretching two bits, since M is singular there). "Flip" is the second operation at fixed width: one interior bit of a run of length at least 3 is flipped, adding two boundaries.

| axis | n → n + 1 | lifts | lifts that lower $\mu$ | largest drop | run length 1 | run length ≥ 3 | lowest run of zeros | flip: median, keys lowered |
|---|---|---|---|---|---|---|---|---|
| differential | 13 → 14 | 165 | 41 (25%) | −0.245 | +0.169 | +0.030 | +0.004 | +0.267, 1 of 23 |
| differential | 16 → 17 | 121 | 30 (25%) | −0.203 | +0.190 | +0.016 | +0.029 | +0.329, 0 of 16 |
| linear | 13 → 14 | 165 | 49 (30%) | −0.229 | +0.058 | −0.012 | −0.020 | +0.134, 3 of 23 |
| linear | 16 → 17 | 121 | 28 (23%) | −0.098 | +0.083 | +0.005 | −0.014 | +0.164, 1 of 16 |

The three middle columns are the mean change in $\mu$ when a run of that kind is stretched.

**The lift is not monotone.** It lowers exact $\mu$ on a quarter of all lifts, on both axes and at both widths, by up to a quarter of a bit.

**What decides the sign is the run length.** Stretching a run of length 1 turns a one-bit run into a two-bit one and moves the boundary above it one position further from the one below. That adds 0.17–0.19 on the differential axis and 0.06–0.08 on the linear. Stretching a run of length 3 or more moves $\mu$ by between −0.012 and +0.030 on average. Width that adds no boundary adds no cost. That is §11.46.2's finding, that the cost sits at δ's run boundaries, stated as a fact about n.

**The lowest run of zeros moves $\mu$ by about nothing.** Those bits are never paid for (§11.46.2), so one more is neither a cost nor a saving. A first draft said stretching it lowers $\mu$ "most often". That was true at n = 13 (8 of 12 keys) and false at n = 16 (3 of 7), and it was withdrawn before publication.

**Adding boundaries raises $\mu$ on almost every key, but not every one.** Every key at n = 16 rose on the differential axis; 1 to 3 keys fell in each of the other three cells.

### 11.47.3 What this changes

**Closed: an upper bound by search.** The cheapest-edge map closes after exponentially many steps, and its cycles are about 1.5 times loose where they do close. No cycle can be exhibited at the deployed width, so the two readings of §11.42 stay unseparated.

**Closed: monotonicity along a lift.** There is a natural map between widths, on keys rather than graphs, and exact $\mu$ is not monotone along it. The fixed-width boundary insertion is not monotone either. So the monotonicity #257 owes cannot be proved pointwise along any chain of these operations. If it holds, it is a statement about typical keys, in distribution.

**Measured: width without boundaries adds nothing.** Exact $\mu$ grows with n through the number of boundaries in δ, about n/2 for a typical key, and not through n itself. That moves the question without answering it. What #257 owes is how $\mu$ behaves as boundaries are added at density 1/2, and §11.46.2 found that the cost per boundary falls as boundaries crowd.

**Still owed.** Monotonicity of exact $\mu$ in n, now as a distributional statement about the boundary count at density 1/2; and the hull share above n = 16, unchanged from §11.45.4. No rating moves (§11.38.7).
