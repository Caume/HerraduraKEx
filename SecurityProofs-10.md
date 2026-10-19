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
> - **Part 10 — §11.43–§11.65** (this file): The Local Certificate · The Local Certificate at n = 256 · The Linear Hull, Measured · Where the Cycles Pay · Two Routes Without a Potential · The Coupled Ladder · The Period Exponent · The Period Series to n = 19 · The Period Series to n = 20 · The v3 Trail Criterion · The v3 Linear Slope · The v2 Measurement Audit · The Period Series Over Keys · The Implicit Solver · The Transient Over Keys · The Quantiles Over Keys · The Short-Window Class · The Discount as a Share · The Long-Window Keys · The Series at n = 22 · The Tail and the Arc · The Arc Curve · The Gap Curve

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

## 11.48 The coupled ladder — TODO #257, eleventh pass

§11.47 left #257 owing a distributional statement: that $\mu$ rises with n for typical keys, since no pointwise chain of local operations on δ is monotone. Every earlier ladder compared that expectation across widths with independent samples of keys, and §11.42 could not tell "levelling" from "still falling" that way. This pass couples the widths instead. Reproduced by `SecurityProofsCode/coupled_width_increment.py`, which drives §11.42's certified C solver.

### 11.48.1 The coupling is exact

Insert one uniform bit at a uniform position (0 to n) of a uniform n-bit δ. For a fixed output and a fixed position, exactly one pair (δ, bit) produces it, so the output is uniform at width n + 1. Hence

E[$\mu$ at n + 1] − E[$\mu$ at n] = E[$\mu$(inserted δ) − $\mu$(δ)]

exactly, and the right side is a mean of paired differences. Two insertions step over a singular width (3 divides n, where M is not invertible). Both statements are checked exhaustively at small n rather than argued.

The deployed key map, δ(B) over odd B, is injective onto a pseudo-random half of δ-space. Its run-count law is within 1% (total variation) of uniform δ's at n = 13, 14 and 16, checked exhaustively. Since §11.46.2 found that $\mu$ is paid at run boundaries, uniform δ is the right ensemble for a statement about deployed keys.

### 11.48.2 Every step rises in expectation

Exact $\mu$ on both sides of every pair, at every valid step from n = 4 to 17. "Increment" is per step (one or two bits), "se" is its paired standard error clustered by key (corrected in §11.49.1; the first release divided by the number of pairs and understated every error by 1.4–1.6 times), and "falls" is the share of single pairs where $\mu$ went down.

| step | differential increment | se | falls | linear increment | se | falls |
|---|---|---|---|---|---|---|
| 4 → 5 | 0.287 | 0.013 | 1% | 0.162 | 0.013 | 15% |
| 5 → 7 | 0.443 | 0.025 | 12% | 0.182 | 0.011 | 8% |
| 7 → 8 | 0.094 | 0.018 | 49% | 0.063 | 0.011 | 36% |
| 8 → 10 | 0.365 | 0.021 | 16% | 0.139 | 0.010 | 19% |
| 10 → 11 | 0.174 | 0.018 | 21% | 0.095 | 0.012 | 20% |
| 11 → 13 | 0.190 | 0.025 | 25% | 0.111 | 0.013 | 25% |
| 13 → 14 | 0.185 | 0.018 | 21% | 0.087 | 0.013 | 21% |
| 14 → 16 | 0.185 | 0.024 | 23% | 0.122 | 0.008 | 11% |
| 16 → 17 | 0.089 | 0.027 | 32% | 0.060 | 0.011 | 22% |

**Expected $\mu$ rises at every step, on both axes.** The smallest lower 3σ bound on any step is +0.009 on the differential axis (16 → 17, the one marginal step) and +0.027 on the linear, while single pairs fall on up to 49% (differential) and 36% (linear) of draws. This is the distributional monotonicity #257 owes, measured over a range of widths. It is not a proof for every n: nothing here keeps the increment away from zero as n grows.

**Pairing is what makes it measurable.** The paired standard error is a median 3.6–4.0 times smaller than independent samples with as many keys would carry. That is why §11.42's independent samples could not resolve the per-bit trend.

**The mechanism survives the coupling.** An insertion that adds two boundaries raises $\mu$ more than one that adds none, at every step on both axes.

### 11.48.3 Single steps are not stationary; periods of three widths are (partly withdrawn, §11.49)

A density-1/2 argument predicts that the increment settles, because boundary density does not change with n. Single steps do not settle. Neighbouring steps disagree per bit by about 4 standard errors on the differential axis (7 → 8 at 0.094 against 8 → 10 at 0.183). The first release also claimed 4.6 on the linear axis (10 → 11 at 0.095 against 11 → 13 at 0.056). With errors clustered by key that is about 3, and §11.49's independent 3000-pair runs resolve no such term on the linear axis, so that half is withdrawn. So the expected $\mu$ carries a width-specific term that no run statistic sees.

Summed over a period of three widths, the term cancels. A period is a one-bit step plus the two-bit step over the next singular width, which is the period of M's singularity.

| period | differential | linear |
|---|---|---|
| 4 → 7 | 0.730 ± 0.018 | 0.344 ± 0.009 |
| 7 → 10 | 0.459 ± 0.020 | 0.202 ± 0.009 |
| 10 → 13 | 0.364 ± 0.022 | 0.206 ± 0.012 |
| 13 → 16 | 0.370 ± 0.022 | 0.209 ± 0.011 |

**Withdrawn (§11.49).** This paragraph read both series as flat from n = 10 on, at 0.122 and 0.069 per bit, within 5% of §11.42's levelled per-bit medians. Two periods inside understated errors could not see a 9% decline. Resolved with thousands of keys per period, both series fall, 3.5–4 standard errors from a levelled rate.

### 11.48.4 What this changes

**Measured: monotonicity in expectation.** The obligation §11.47 re-stated holds at every step from n = 4 to 17, on both axes, by an exact coupling. It holds in expectation and not pointwise.

**Withdrawn (§11.49): a flat per-period rate.** The first release read the per-period increment as flat from n = 10 to 16. §11.49 resolves it and finds it falling on both axes.

**Not decided here; §11.49 removes one: §11.42's two readings.** The first release compared two periods and found them 1.2 and 0.6 standard errors from the power law, with understated errors. It carried the "flat" series to n = 256 as about 32 and 18. Those readings are withdrawn with the flatness they rested on.

**Fixed on the way: a hang in the certified solver.** SPFA in `certified_cycle_mean.c`, and in its Python twin, ran on w − $\mu'$, where Howard's $\mu'$ is a cycle's sum divided by its length. At n = 17, δ = 0x1f6ef the two roundings disagree by less than 1e-11. The optimal cycle is then a negative cycle to SPFA, which never terminates. Every fixed seed before this pass missed such a key; uniform sampling met one. Both solvers now run SPFA at $\mu'$ − 1e-9 and certify $\mu$ to within 2e-9. A relaxation budget turns a genuine negative cycle into an error instead of a hang. All five earlier gates that use the solver reproduce unchanged.

**Still owed.** A reason the per-period increment stays bounded away from zero, or enough further periods to separate §11.42's readings; and the hull share above n = 16, unchanged from §11.45.4. No rating moves (§11.38.7).

## 11.49 The period exponent — TODO #257, twelfth pass

§11.48 read the per-period increment as flat from n = 10 and found it agreeing with §11.42's levelled reading. Two things were wrong with that, and this pass is both corrections. Reproduced by `SecurityProofsCode/period_exponent.py`, which drives §11.42's certified C solver.

### 11.49.1 The errors were understated, and a better estimator exists

**Clustered errors.** §11.48 drew several insertions per base δ and divided by the square root of the number of pairs. Insertions into one δ share $\mu$(δ), so they are not independent. Clustered by key, every error is 1.4–1.6 times larger. `coupled_width_increment.py` now prints both, and §11.48 is corrected in place. With the corrected errors, every step still rises at 3σ. The weakest is differential 16 → 17, at 0.089 ± 0.027.

**One pair per period.** The coupling is exact for any number of inserted bits. Three uniform bits inserted into a uniform δ at n give a uniform δ at n + 3, checked exhaustively. So a whole period is one paired draw: one solver call at n + 3, and no error from adding two separately estimated steps. No valid δ can produce a degenerate output, also checked exhaustively, so the sampler's rejection loop never changes the coupling.

**A control variate with an exact mean.** The change in δ's run count has a known mean: k/2 for k inserted bits over all strings, corrected exactly for the two degenerate δ the sampler excludes (checked against brute force). It correlates with the increment because $\mu$ is paid at run boundaries (§11.46.2), and cuts the error by 10–20%.

### 11.49.2 The period series, resolved (partly withdrawn, §11.50)

P(n) is the expected increase in $\mu$ from n to n + 3. These figures come from an independent replication with about 8000 pairs per period; the gate reproduces them on its own seeds.

| period | differential P | linear P |
|---|---|---|
| 7 → 10 | 0.451 ± 0.004 | 0.227 ± 0.002 |
| 10 → 13 | 0.382 ± 0.004 | 0.207 ± 0.002 |
| 13 → 16 | 0.362 ± 0.003 | 0.199 ± 0.002 |

The local exponent compares two adjacent periods (d log P / d log n). A levelled per-bit rate predicts 0. §11.42's power law (exponent 0.63 differential, 0.84 linear) predicts −0.37 and −0.16.

| interval | differential exponent | linear exponent |
|---|---|---|
| 7 → 10 vs 10 → 13 | −0.55 ± 0.05 | −0.31 ± 0.04 |
| 10 → 13 vs 13 → 16 | −0.23 ± 0.06 | −0.18 ± 0.05 |

**P falls on both axes.** Between the periods at 10 and 13, the exponent is 4.0 standard errors below a levelled rate on the differential axis and 3.5 on the linear. The gate's own smaller sample gives −0.40 ± 0.08 (5.3σ) and −0.14 ± 0.07 (1.9σ), so it scores the differential rejection only. Combined, the linear one is about 4σ. §11.48's 0.364 and 0.370 sat inside understated errors and could not see a decline of 5–9% per period.

**Neither of §11.42's readings describes it.** A power law has one exponent. The differential exponent moves from −0.55 to −0.23 across two adjacent intervals, about 3.6 standard errors once the period at 10, shared by both, is accounted for. So the decline is itself slowing. The gate's own seeds do not resolve this drift (−0.53 to −0.40); it rests on the replication. The linear value at 10 → 13 sits on the power law's −0.16, but its value at 7 → 10 does not.

**Withdrawn (§11.50): the decline is slowing.** One period further, to n = 19, the differential exponent is −2.02 ± 0.23 and the linear −1.26 ± 0.19. The fall steepens rather than slows.

### 11.49.3 What this changes

**Withdrawn: a flat per-period rate**, on both axes, and with it §11.48's agreement with the levelled reading.

**Removed: the premise of §11.42's higher reading.** The levelled per-bit median (about 33 differential and 17 linear at n = 256) assumed a constant increment. That is rejected on the differential axis in both samples, and on the linear axis in the larger one. The power law (about 13 and 11) is not confirmed either, since no fixed exponent fits the differential decline. So the n = 256 value lies between the two readings, and nothing here pins it.

**Unaffected: monotonicity and the criteria.** Every step still rises in expectation (§11.48.2, corrected errors). The lower reading is still about 10 times the 4/3 and 2/3 criteria, so nothing here threatens them.

**Still owed.** A reason the per-period increment stays bounded away from zero as it declines; and the hull share above n = 16, unchanged from §11.45.4. No rating moves (§11.38.7).

## 11.50 The period series to n = 19 — TODO #257, thirteenth pass

§11.49 read the decline of the per-period increment as slowing. This pass measures the next period, which reaches n = 19, and the second residue class beside it. Reproduced by `SecurityProofsCode/period_series_n19.py`, from the pinned sample `period_series_n19.json`.

### 11.50.1 The sample

A period cannot start at a singular width. Where 3 divides n, M is not invertible and $\mu$ is identically 0, so P(15) = 0 − 0. The periods therefore form two series: starts 7, 10, 13 and 16, which is the series §11.49 measured, and starts 8, 11 and 14.

Each pair is one three-bit insertion into one key, the exact coupling of §11.49.1, with the run-count control variate at its exact mean. There are 11 700 pairs per axis. The 500 pairs at n = 19 each take about 30 s to solve exactly, so the whole sample is pinned and the gate re-solves a prefix of every cell.

Two consistency checks pass. P(13) on this seed reproduces §11.49.2's independent replication, at 0.9σ differential and 0.1σ linear. E[$\mu_{16}$] from the end of P(13) and from the start of P(16), two independent samples, agree within 0.8σ.

### 11.50.2 The series

| period | differential P | linear P |
|---|---|---|
| 7 → 10 | 0.447 ± 0.007 | 0.225 ± 0.003 |
| 10 → 13 | 0.384 ± 0.006 | 0.210 ± 0.003 |
| 13 → 16 | 0.357 ± 0.006 | 0.199 ± 0.003 |
| 16 → 19 | 0.244 ± 0.010 | 0.157 ± 0.005 |
| 8 → 11 | 0.505 ± 0.007 | 0.211 ± 0.003 |
| 11 → 14 | 0.365 ± 0.006 | 0.206 ± 0.003 |
| 14 → 17 | 0.308 ± 0.007 | 0.176 ± 0.003 |

**E[$\mu$] still rises over every period.** The smallest increment, P(16), is 24 standard errors above zero on the differential axis and 31 on the linear. E[$\mu_{19}$] is 2.61 differential and 1.31 linear, which is 1.95 and 1.96 times the 4/3 and 2/3 criteria.

**The fall steepens.** In the series §11.49 measured, the local exponent moves from −0.32 over 10 → 13 to −2.02 over 13 → 16 on the differential axis, 6.2 standard errors with the shared period counted once. On the linear axis it moves from −0.23 to −1.26, 4.5 standard errors. P falls over the last step of both series on both axes, by 6.7 to 9.8 standard errors. In the second series the exponent steepens on the linear axis (−0.09 to −0.72) and not on the differential one (−1.18 to −0.80). The gate prints that series and does not score it.

### 11.50.3 A Howard non-termination, fixed

The sample hit one key, n = 14 with δ = 0x1500 on the linear axis, on which Howard's policy iteration never terminated. That happened in `certified_cycle_mean.c` and in the Python solvers it transcribes. Every node already held the optimal mean. What kept moving was the bias h, which each evaluation rooted at whichever cycle node the scan reached first. With several cycles of equal mean, the h values of two cycles are then not comparable, so one "strict improvement" can be undone by the next.

The fix roots h at each cycle's smallest node, in all four Howard implementations. $\mu$ does not depend on the root, and the certificate (SPFA on the full graph at $\mu'$ − 1e-9) is what makes the answer exact. On 744 random keys at n = 7 to 16, both axes, the fixed and old solvers give identical $\mu$, edges kept and certificate rounds. The gate's negative control runs the old root inside the certified solver and shows it failing to terminate in certificate round 2 of this key.

### 11.50.4 What this changes

**Withdrawn: the decline is slowing** (§11.49.2). One period further, it steepens on both axes.

**Removed: the premise of both n = 256 readings.** §11.42's power law (about 13 differential and 11 linear) assumed a fixed exponent. The levelled reading (about 33 and 17) was already rejected in §11.49. A decline that accelerates fits neither.

**Unaffected: monotonicity to n = 19.** Every period measured still rises in expectation.

**Re-aimed: what #257 owes.** The question is no longer which growth curve holds at n = 256. It is whether E[$\mu$] stays above the criteria at all. At the last period the increment is 0.081 per bit differential and 0.052 linear. If it reaches zero within a few more periods, E[$\mu$] levels at about twice the criteria. If it turns negative, nothing measured so far says where it stops. The margin at the widest measured width is about 2x, not 10x.

**Still owed.** Further periods, starting with P(17) to n = 20 at about 60–100 s per solve (measured in §11.51), or an argument that bounds the increment below. The hull share above n = 16 is unchanged from §11.45.4. No rating moves (§11.38.7).

## 11.51 The period series to n = 20 — TODO #257, fourteenth pass

§11.50 left the n = 2 (mod 3) series one period short of the n = 1 series. This pass measures the period that starts at n = 17, so that both classes reach the same depth. Reproduced by `SecurityProofsCode/period_series_n20.py`, from the pinned sample `period_series_n20.json`.

### 11.51.1 The sample

There are 500 pairs per axis, drawn by §11.50's own sampler with the same seed and the same three-bit coupling. Each pair needs one exact solve at n = 20. That takes 1 to 2 minutes, and up to 4.1 GB on the differential axis against 0.83 GB at n = 19. The whole cell is about 26 CPU hours, so it is pinned and the gate re-solves a prefix.

E[$\mu_{17}$] from the end of P(14) and from the start of P(17), two independent samples, agree within 0.3σ differential and 1.1σ linear.

### 11.51.2 The series

| period | differential P | linear P |
|---|---|---|
| 13 → 16 | 0.357 ± 0.006 | 0.199 ± 0.003 |
| 16 → 19 | 0.244 ± 0.010 | 0.157 ± 0.005 |
| 14 → 17 | 0.308 ± 0.007 | 0.176 ± 0.003 |
| 17 → 20 | 0.210 ± 0.008 | 0.147 ± 0.004 |

**E[$\mu$] still rises.** P(17) is 27 standard errors above zero differential and 33 linear. E[$\mu_{20}$] is 2.67 differential and 1.35 linear, 2.00 and 2.03 times the 4/3 and 2/3 criteria: the same margin as at n = 19.

**P falls again.** From P(14) to P(17) it drops by 9.6 standard errors differential and 5.2 linear.

**The two classes fall by the same factor.** Over their latest period, P(16)/P(13) and P(17)/P(14) are 0.684 ± 0.030 and 0.682 ± 0.029 on the differential axis, and 0.789 ± 0.028 and 0.835 ± 0.030 on the linear axis, 0.1σ and 1.1σ apart. So §11.50's steeper fall was not one cell's fluctuation.

**The second series now steepens too.** Its differential exponent moves from −0.80 over 11 → 14 to −2.17 over 14 → 17, 4.4 standard errors. §11.50 had printed that series' earlier step as not steepening. On the linear axis the change, −0.72 to −1.02, is 1.1 standard errors and is printed, not scored.

### 11.51.3 What a constant ratio would mean

If every later period kept the pooled ratio (0.683 differential, 0.810 linear), the remaining increments would form a geometric series and E[$\mu$] would level near 3.12 and 1.98, which is 2.3 and 3.0 times the criteria. The gate prints this and does not score it. A constant ratio is the optimistic end, not a floor: in the n = 1 series the ratio already fell once, from 0.93 (P(13)/P(10)) to 0.68.

### 11.51.4 What this changes

**Confirmed: the steeper fall.** Both residue classes now show it, by the same factor.

**Unaffected: monotonicity to n = 20,** and a margin of about 2x over both criteria at the widest measured width.

**Narrowed: what #257 owes.** If the ratio holds, E[$\mu$] levels comfortably above the criteria. If it keeps falling, E[$\mu$] levels near the present 2x or lower, and a negative increment is not excluded. The next period, P(19), needs n = 22 solves. Peak memory grew about 5x from n = 19 to n = 20, so it is out of reach of this solver on this host. A lower-memory solver, or an argument that bounds the ratio, is the way forward. The hull share above n = 16 is unchanged from §11.45.4. No rating moves (§11.38.7).

## 11.52 What v3's trail floors prove against v3's own criterion — TODO #342

SECURITY.md's five v3 rows, and spec/'s notes for them, said two things that cannot both hold. They said χ gives the v3 round "an unconditional per-round trail floor of 1.6781 bits differential and 1 bit linear", and that v3 has "no trail bound at realistic width on either axis". This section settles which is true, axis by axis. Reproduced by `SecurityProofsCode/nl_fscx_v3_trail_criterion.py`.

### 11.52.1 v3's own bars

§11.30.1's criterion is that a differential trail dies once s_diff · r ≥ n, and a linear one once s_lin · r ≥ n/2. For v2 the round count is tied to n, so the bars collapse to 4/3 and 2/3. For v3 the round count is free. At R3 = 160 against a 256-bit block, and at the duplex's I3 = 80 against its 128-bit capacity, the bars are the same two numbers: **s_diff ≥ 1.6 and s_lin ≥ 0.8**.

### 11.52.2 Differential: a proven trail bound at every width

§11.34.3's lowest-active-row lemma bounds the round's own DDT entry, which sums over every intermediate difference and so includes clustering across the carry. That bound is 5/16 for every key at every width. Every r-round characteristic therefore has weight at least 1.6781 · r. Since 1.6781 ≥ 1.6, **v3 has a proven differential trail bound at n = 256**: 268.5 bits over 160 rounds against 256 needed, which is 1.049× with no room to trim R3. The gate checks the bound against the exhaustive full-round DDT at n = 10: no entry exceeds 5/16, and 5/16 is attained.

Differential hulls, which sum over characteristics, are not covered.

### 11.52.3 Linear: the 1-bit floor is layer-wise

§11.33.2's linear floor of 1 bit charges χ alone, with the mask between the addition and χ held fixed. The round's own LAT entry sums over that mask. The proven round-level floor is §11.34.2's single-row bound, 0.1926 bits, which gives 30.8 bits over 160 rounds against 128 needed. The negative control: the full round at n = 10 attains |corr| = 0.875 in a single round, below both the layer-wise 1 bit and the 0.8 bar. So the 1-bit figure is not a bound on the round, and **v3 has no proven linear trail bound at n = 256**.

The rows had placed a round-level floor and a layer-wise one side by side as if they were the same kind.

### 11.52.4 The exact asymptotic slopes at n = 10

The asymptotic slope is the minimum mean cycle of the round-level DDT or LAT graph: 1023 nodes and every edge. It is computed by Howard's iteration and certified by a potential: every edge u → v satisfies h(u) ≤ w − μ + h(v), so no cycle is cheaper than μ, and the policy cycle attains it. Over **all 1024 keys** (the gate's `--full`):

| axis | least | median | most | bar | least / bar |
|---|---|---|---|---|---|
| differential | 2.500 | 3.000 | 3.667 | 1.6 | 1.56× |
| linear | 1.178 | 1.524 | 1.766 | 0.8 | 1.47× |

No key's differential slope falls below the proven floor, so the measurement agrees with the proof. Every key's linear slope clears 0.8. The least is at key 0x095, and the gate pins that key and a least-differential key into every run.

This is one width. §11.42 to §11.51 show for v2 how far small-width figures can sit from n = 256, so it is evidence, not a bound.

### 11.52.5 What this changes

**Corrected:** all five v3 rows of SECURITY.md and spec/'s notes. The differential axis has a proven trail bound at every width. The linear axis does not, and the 1-bit figure is now labelled layer-wise. HSKE-NL-A3's status line reads "narrower gap than HSKE-NL-A2 (linear axis only)". The duplex's r ≥ 64 linear requirement is labelled layer-wise too.

**Corrected in §11.34:** §11.34.6 compared v3's multi-round linear slope with v2's 2/3 rather than v3's 0.8. The slope clears either bar, and `nl_fscx_v3_weak_keys.py` now checks 0.8. §11.34.8 had cited the 1-bit linear floor to §11.34.2, which gives 0.1926; its source is §11.33.2.

**Filed:** v3's linear slope at realistic width, against 0.8, as TODO #257's item (3) beside v2's two axes.

**Unchanged:** every v3 rating. None of the five rows is demo-only for want of a trail bound alone. The missing PRP/SPRP reduction stands, and so, for the duplex, does the uncharacterised sponge profile (TODO #99).

## 11.53 v3's linear slope at n = 14 and 17, and the LSB-row ceiling — TODO #257, item (3)

§11.52 left v3's linear axis open: the round-level floor is 0.1926 bits, and the exact asymptotic slope had been measured at n = 10 only. This section takes it to n = 14 (rows 7, 7) and n = 17 (rows 5, 5, 7), the next two widths with an all-5-or-7 partition and an invertible M. It also proves a width-independent **ceiling** on the worst key's slope. The gate is `SecurityProofsCode/nl_fscx_v3_linear_width.py`, with the C helper `v3_round_mmc.c`.

### 11.53.1 The solver

At n = 17 the round-level LAT has 2^34 entries, too many to store. `v3_round_mmc.c` keeps the graph implicit: a full pass recomputes the LAT one column at a time, with one Walsh–Hadamard transform per output mask, and the DDT one row at a time. Howard's iteration runs on a subgraph G′ of the cheap edges, plus each node's cheapest edge. The answer is then **certified** against the whole graph. Shortest paths of w − (μ − 10⁻⁹) on G′ give a potential p, and one full pass checks p(u) ≤ w − μ + p(v) on every edge. If any edge violates it, that edge joins G′ and the solve repeats. So every figure below is the exact minimum mean cycle of the full graph, to 10⁻⁹. It is not the minimum over a subgraph.

The gate holds the solver to the Python one of §11.52 on four keys and both axes. Before relying on it here, it was also checked against the exhaustive n = 10 run, all 1024 keys on both axes, with no disagreement. A negative control shows the certificate firing: with the cap at 1 bit, the first subgraph's optimum is wrong (1.6270 against 1.5982 for key 0x009). The certificate finds 72 violating edges, and the loop ends at the true value.

### 11.53.2 The measurements

The samples are uniform keys: 2048 of the 16384 at n = 14, and 24 at n = 17. Every answer is certified.

| n | rows | keys | differential least / median | linear least / 1st pct / median / most | least / 0.8 |
|---|---|---|---|---|---|
| 10 | 5, 5 | all 1024 (§11.52) | 2.500 / 3.000 | 1.178 / 1.238 / 1.524 / 1.766 | 1.47× |
| 14 | 7, 7 | 2048 | 3.000 / 3.000 | 1.607 / 1.678 / 1.869 / 2.000 | 2.01× |
| 17 | 5, 5, 7 | 24 | 3.000 / 3.000 | 1.415 / 1.415 / 1.667 / 2.000 | 1.77× |

Every sampled key clears 0.8 at both widths. No differential slope falls below §11.34.3's proven 1.6781, so the measurement and the proof agree again.

The partitions differ, and the figures follow them. n = 14 has no 5-row, and 7-rows are the stronger row (§11.34.2: worst one-round grade 0.719 against 0.875). n = 10 and n = 17 have a 5-row at the LSB, as the deployed 47 × 5 + 3 × 7 does. These are the comparable pair: from n = 10 (exhaustive) to n = 17 (sampled), the least linear slope rose from 1.178 to 1.415 and the median from 1.524 to 1.667.

### 11.53.3 The LSB-row ceiling

Of the 24 optimal cycles at n = 17, 15 lie on masks inside the lowest 5-bit row. The least-linear key's is one of them, a single self-loop on mask 0x1c. The other nine sit in the second 5-row or in the 7-row, rows that receive a carry. The LSB row is special because the addition's carry starts at bit 0.

**Lemma.** Let the partition have a row of length L at the LSB, and let n ≥ L + 2. For masks u and v confined to that row, the LAT entry |corr(u·x, v·T(x))| depends on δ(B) mod 2^L and on nothing else. In particular it does not depend on n.

*Proof.* v·T(x) reads only the row's L output bits. Those are χ_L applied to the low L bits of M(x ⊕ B) + δ(B). No carry enters bit 0, so the low L bits of the sum are a function of the low L bits of M(x ⊕ B) and of δ(B) mod 2^L. Bit i of M(y) is y_{i−1} ⊕ y_i ⊕ y_{i+1}, so those L bits read y at positions n − 1 and 0..L, and these are L + 2 distinct positions when n ≥ L + 2. u·x reads positions 0..L−1. So the correlation is an average over L + 2 uniform bits of a fixed function of δ(B) mod 2^L. The XOR with B only flips signs. ∎

So every cycle through LSB-row masks is a cycle of the full round-level graph, with the same mean at every width. The minimum mean cycle of the LSB-row graph is an **upper** bound on the key's linear slope at every width, n = 256 included. Computed exactly over all classes and certified:

- **L = 5:** the least is **1.4150** = −log2(3/8), at δ(B) ≡ 5 (mod 8), which is 4 of the 32 classes. The most is 2.000.
- **L = 7:** the least is 1.6781.

The deployed partition has a 5-row at the LSB, and δ(B) mod 32 takes every value over the keys; about one key in eight is ≡ 5 (mod 8), and the gate checks both on 4096 random 256-bit keys. So **at n = 256, every key with δ(B) ≡ 5 (mod 8) has linear slope at most 1.4150. v3's worst-key linear margin over the 0.8 bar is therefore at most 1.77×, at every width.** This is a ceiling, not a floor: it says how good the linear axis can be, not that it is good.

The gate checks the lemma directly. The full-width LAT entries between LSB-row masks equal the local ones exactly at n = 10 (three keys) and at n = 14. Against the table of the wrong δ class, the same comparison fails. The gate also checks that no solved key exceeds its LSB-row value. Over every key measured, 1024 + 2048 + 24 of them, none does. The share whose slope *equals* the LSB-row value is 22% at n = 10, 77% at n = 14 and 67% at n = 17. The n = 17 least sits exactly on the 5-row ceiling.

### 11.53.4 What it changes

**Established:** a proven, width-independent ceiling of 1.4150 on the worst key's linear slope, from the LSB row alone. The linear margin at n = 256 cannot exceed 1.77×. There are also exact certified slopes at two more widths, all clearing 0.8 in sample.

**Still open, and now sharper:** a lower bound. The question is whether some cycle cheaper than the LSB row's appears as n grows. Such a cycle must use rows that do receive a carry. On the comparable widths, the share of keys sitting at their LSB-row value grew and the least slope rose, which is the direction a ceiling-tight answer would take. But that rests on one exhaustive width and one sampled one, and §11.42–§11.51 show for v2 how far small-width figures can sit from n = 256. TODO #257's item (3) stays open, narrowed to the cycles below the LSB-row value.

**Unchanged:** every v3 rating. HSKE-NL-A3's status already reads "linear axis only". The ceiling does not move that.

---

## 11.54 An audit of the v2 measurement methodology — TODO #343

§11.42–§11.51 estimate E[μ], the per-round slope of NL-FSCX v2's best trail, by sampling the additive constant δ uniformly over n-bit strings, and hold it to μ · 3n/4 ≥ n (n/2 on the linear axis). This section checks both choices against what they stand for. Two of them are errors, and both make the n = 256 margin look larger than it is. A third finding is a gap in the weak-key screen that turns out to be harmless at the deployed width. The gate is `SecurityProofsCode/v2_measurement_audit.py`, with the C helper `v2_round_transient.c`.

### 11.54.1 The key-induced distribution of δ

A key B gives δ(B) = ROL(p, n/4) with p = B · ⌊(B+1)/2⌋ mod 2^n. Write tz for the number of trailing zeros.

- **Even B = 2^j · u, u odd:** p = 2^(2j−1) · u², so tz(p) = 2j − 1 is odd.
- **Odd B:** p = B · (B+1)/2, so tz(p) = tz(B+1) − 1.

This gives an exact preimage count for every δ. Let k = tz(p), w = p / 2^k and m = n − k. The even branch needs k odd and u² ≡ w (mod 2^m); each square root lifts to 2^(j−1) odd u. The odd branch writes B + 1 = 2^(k+1) · v, and v ↦ v · (2^(k+1) · v − 1) is a bijection on odd residues mod 2^m, so exactly one v₀ solves it; it counts when v₀ ≤ 2^(n−k−1). The gate checks this count against brute force for every nonzero δ at every n ≤ 16, 131 043 values in all.

Three consequences:

- **About half the δ values are reachable** by any key: 54% at n = 16.
- **Some are reached by many keys:** up to 2^(n/2), 256 at n = 16.
- **The zero run is heavy-tailed:** P(tz(p) = t) = 2^−(t+2) + [t odd] · 2^−((t+3)/2), exactly, at every t well below n. That is about 2^(−t/2), against 2^−(t+1) for a uniform string. The rotation puts that run at δ's bits n/4 and up.

### 11.54.2 The wrong population

μ depends on δ alone, so the slope over real keys is the slope over δ weighted by preimage count. Exhaustively, over every δ and every key:

| n | differential, uniform δ | differential, keys | linear, uniform δ | linear, keys |
|---|---|---|---|---|
| 7 | 1.164 | 1.119 (−3.8%) | 0.529 | 0.516 (−2.5%) |
| 8 | 1.270 | 1.198 (−5.7%) | 0.609 | 0.576 (−5.5%) |
| 10 | 1.602 | 1.503 (−6.1%) | 0.749 | 0.706 (−5.7%) |
| 11 | 1.777 | 1.654 (−7.0%) | 0.823 | 0.770 (−6.4%) |
| 13 | 1.988 | 1.892 (−4.8%) | 0.955 | 0.908 (−4.9%) |

The 5th percentile falls further: at n = 11 (differential) it is 1.065 over uniform δ and 0.648 over keys. The cause is the zero run of §11.54.1. At n = 13 the differential mean is about 2.0 for keys with t ≤ 2, 1.44 at t = 5, 1.15 at t = 7 and about 0.55 at t = 9 and 11.

**Correction to the published series.** Reweighting the pinned samples of §11.50 and §11.51 by preimage count lowers E[μ] at all 20 (axis, width) points, by 0.8% to 7.3%. The reweighted figures are noisy, because the ~46% of pinned draws that no key reaches get weight zero. §11.55 replaces them with a series drawn over keys.

### 11.54.3 The affine class has four members

δ ∈ {0, 2^(n−1), 2^(n−2), 3 · 2^(n−2)} makes the round GF(2)-affine. Adding 2^(n−2) flips bit n − 2 and carries that bit into the top bit, which is linear. Exhaustively at n = 7, 8 and 10, these four are the only affine values. The CLIs reject the first two. Keys reach 2^(n−2) at n = 11, 14, 17, 19, 20 and 22; this review first met one as a μ = 0 key at n = 17, B = 0x40.

**At the deployed width the screen is complete.** At n ≡ 0 (mod 8) the target p is 2^k or 3 · 2^k with k = 3n/4 − 2 even. An even B gives p an odd valuation, so it cannot reach either. An odd B needs v ≡ −1 or −3 (mod 2^(n/4+2)) with v ≤ 2^(n/4+1), which is impossible. The gate evaluates §11.54.1's count at n = 8, 16, 24, 32, 64, 128 and 256 and gets zero for both values at each.

### 11.54.4 The criterion is on W(r), not on μ · r

μ is the slope a trail pays in the limit. A trail of r rounds pays W(r) = μ · r + c, and the deployed criterion is W(3n/4) ≥ n (n/2 linear). `v2_round_transient.c` computes W(r) exactly from the full DDT or LAT by a min-plus recursion. Its slope over rounds 4n to 8n reproduces the certified μ within 4% for every key, which checks the two tools against each other. Over keys B drawn uniformly, eight per width:

| n | r | differential mean c/n (worst) | linear mean c/n (worst) |
|---|---|---|---|
| 10 | 7 | −0.30 (−0.40) | −0.14 (−0.18) |
| 11 | 8 | −0.25 (−0.32) | −0.15 (−0.17) |
| 13 | 9 | −0.30 (−0.38) | −0.17 (−0.22) |
| 14 | 10 | −0.37 (−0.42) | −0.20 (−0.24) |

The n = 14 row has six keys and runs under `--full` only. c is negative for every key measured, and c/n does not shrink with n; at n = 14 it is the largest yet. This fits M's local diffusion: a sparse difference spreads by one bit each way per round, so a trail can spend a fixed fraction of its rounds in a cheap ramp. If c/n holds at 192 rounds, the criterion on μ becomes (1 − c/n) / (3/4) instead of 1 / (3/4): about **1.71** instead of 4/3 differential, and **0.87** instead of 2/3 linear. §11.57 re-measures c/n over keys to n = 19: it does not hold, it deepens with width, and the bars at n = 19 are 1.89 and 0.94.

### 11.54.5 What it changes

At n = 20, the widest exact width, the published averages are 2.00× and 2.03× the old bars. Weighted to keys and held to the corrected bars, they are about **1.5×** on both axes. That figure applies c/n measured at n ≤ 13 to n = 20, so it is an extrapolation. The levelling scenario of §11.51.3 (E[μ] near 3.1 and 2.0) becomes about 1.8× and 2.3× rather than 2.3× and 3×.

**Established:** the population error and its size; the transient at the deployed round count, at three widths; the affine class, and its unreachability at n = 256.

**Still open (TODO #343):** whether c/n holds, grows or shrinks at larger r, which the corrected bars depend on; the period series drawn over keys rather than δ; and an implicit-edge v2 solver to take both past n = 20.

**Unchanged:** every rating. HSKE-NL-A2 and `twk` were demo-only already; their outlook is weaker again. The CLIs' affine screen needs no change for the deployed width.

---

## 11.55 The period series over keys — TODO #343, second pass

§11.54.2 showed that the series of §11.42–§11.51 sampled the wrong population, uniform δ instead of real keys, and could only correct it by reweighting, which gave ~46% of the pinned draws weight zero. This section measures the series over keys directly. The gate is `SecurityProofsCode/key_series.py`, and the sample is pinned in `key_series.json`.

### 11.55.1 The sampler

Keys are split into strata by the length t of p's trailing zero run (§11.54.1): t = 0 to 7 each on its own, and t ≥ 8 together. Each stratum's weight is its exact share of the key space, by enumeration. Every stratum gets at least eight keys, so the long-run tail is resolved rather than merely present. The estimate is the stratum-weighted mean, with the stratified standard error.

Keys whose δ makes the round affine (§11.54.3) are left out. The CLIs refuse two of those values, and no key reaches the other two at n = 256, so keeping them would weigh in a class the deployed width does not have. At n = 11 this alone moves the exhaustive key average from 1.654 to 1.680.

**Check:** at n = 10 and 11 (and 13 by default) a stratified sample of about 300 keys, drawn by the same code, agrees with the exhaustive key average on both axes, with z between 0.2 and 1.7.

### 11.55.2 The series

Exhaustive over every key to n = 13. Sampled above that: 1207, 809, 610, 313 and 113 keys at n = 14, 16, 17, 19 and 20, both axes solved on every key with the certified solver.

| n | differential, keys | differential, uniform δ | linear, keys | linear, uniform δ | keys below the corrected bars (diff / lin) |
|---|---|---|---|---|---|
| 7 | 1.119 | 1.149 | 0.516 | 0.531 | 97% / 100% |
| 8 | 1.198 | 1.274 | 0.576 | 0.613 | 82% / 94% |
| 10 | 1.503 | 1.604 | 0.706 | 0.754 | 58% / 72% |
| 11 | 1.680 | 1.784 | 0.783 | 0.823 | 43% / 61% |
| 13 | 1.892 | 1.989 | 0.908 | 0.958 | 30% / 39% |
| 14 | 2.067 ± 0.012 | 2.149 | 0.996 ± 0.006 | 1.031 | 21% / 27% |
| 16 | 2.233 ± 0.015 | 2.342 | 1.096 ± 0.007 | 1.155 | 15% / 17% |
| 17 | 2.368 ± 0.015 | 2.461 | 1.169 ± 0.008 | 1.205 | 10% / 11% |
| 19 | 2.507 ± 0.019 | 2.605 | 1.250 ± 0.011 | 1.308 | 6.5% / 7.4% |
| 20 | 2.564 ± 0.032 | 2.666 | 1.313 ± 0.019 | 1.353 | 4.6% / 5.0% |

The corrected bars are §11.54.4's 1.71 and 0.87.

- **The rise continues over keys:** at every step of both residue classes, on both axes, by 5.6 standard errors or more.
- **Over keys E[μ] is lower** than the uniform-δ record at every pinned width, by 3–5%.
- **The weak share thins.** The share of keys below the corrected bar falls at every step of both classes from n = 10, to about 5% at n = 20.
- **The increments keep shrinking.** Over keys, in the n ≡ 1 (mod 3) class that n = 256 belongs to, P = 0.384, 0.388, 0.342 and 0.273 (differential), with ratios 1.01, 0.88 and 0.80. Linear: 0.190, 0.203, 0.188 and 0.154, ratios 1.07, 0.93 and 0.82. In the n ≡ 2 class the differential ratios are 0.80, 0.78 and 0.65.

### 11.55.3 What it changes

At n = 19, the widest width of n = 256's residue class, E[μ] over keys is 2.507 differential and 1.250 linear. That is 1.88× and 1.87× the old bars, but **1.47× and 1.44×** the corrected ones. The corrected bars themselves rest on §11.54.4's c/n, measured to n = 14 only; §11.57 re-measures them to n = 19, where they are 1.89 and 0.94, and the margins become 1.32× on both axes.

**Established:** the series over the population that ships, to n = 20, with exhaustive values to n = 13. It replaces §11.54.2's reweighted figures, and the uniform-δ levels of §11.50–§11.51 should no longer be quoted.

**Still open (TODO #343):** c/n at more rounds; an implicit-edge solver for n = 22–23 (§11.56); and, inherited from TODO #257, whether the rise continues to n = 256 at all. The increments are shrinking faster each period, so the levelling question is unchanged in kind. Over keys, it starts from a lower level.

**Unchanged:** every rating.

## 11.56 The certified solver with its graph held implicitly — TODO #343, third pass

The series of §11.50–§11.55 stops at n = 20 because of memory, not time. `certified_cycle_mean.c` keeps every edge of weight at most $W_u$ out of each node u, and raises $W_u$ until $W_u \ge \mu' - p(u)$. Because every potential is at most zero, a heavier edge cannot violate p, so the kept graph is certified without looking at the rest. But that bound charges every edge's target the least potential there is, so the solver keeps far more edges than the certificate uses: 76 million on the heaviest pinned n = 20 key and 225 million on an n = 22 key. The gate is `SecurityProofsCode/v2_implicit_solver.py`.

### 11.56.1 The implicit mode

The same program has a second mode, selected by a sixth header field, and it reuses the same row walks. It holds a subgraph G′ and checks the rest of the graph by regenerating it:

- G′ starts as the stored solver's first graph, the edges of weight at most $W_0$.
- Howard's policy iteration and the potential run on G′ exactly as before.
- A certify pass then walks every row again, to the same bound $\mu' - p(u)$, so no edge the stored solver would keep is skipped. It tests each edge against the potential at its own target: $p(v) \le p(u) + w - \mu' + \text{TOL}$.
- The edges that fail join G′, and the solve repeats. When a pass finds at most $2^n$ violators it adds all of them; otherwise it adds the four worst of each row, which keeps the first, poorly informed passes from filling G′.

A pass that finds no violator certifies $\mu(G) \ge \mu' - \text{TOL}$ on the whole graph. That is the stored solver's certificate, with the same tolerances, and nothing outside G′ is ever stored.

### 11.56.2 The checks

- **The same μ:** on 64 fixed-seed solves at n = 7–17, both axes, the two modes agree exactly. **Control:** at every width from n = 10, some key's G′ before the first certify pass overstates μ, so the certify passes do change the answer. (At n = 7 and 8 the starting graph is already exact.)
- **The pinned slopes:** 50 pinned keys of `key_series.json`, including the heaviest n = 20 key on each axis, re-solve to the recorded μ.
- **The graph held:** on the ten heaviest pinned keys, G′ holds 0.30 of the stored edges in all, and between 0.10 and 0.57 on any one key.

| key | stored: edges / peak / time | implicit: edges / peak / time |
|---|---|---|
| n = 20, differential (heaviest pinned) | 76 M / 964 MB / 208 s | 19 M / 316 MB / 363 s |
| n = 20, linear (heaviest pinned) | 35 M / 486 MB / 129 s | 16 M / 272 MB / 95 s |
| n = 22, differential | 225 M / 2.9 GB / 880 s | 26 M / 716 MB / 649 s |
| n = 22, linear | 54 M / 940 MB / 221 s | 38 M / 778 MB / 215 s |
| n = 23, differential | — (about 8 GB, not run) | 37 M / 1.2 GB / 23 min |
| n = 23, linear | — | 60 M / 1.4 GB / 8 min |

The n = 22 and 23 rows use the first fixed-seed key of `exact_slope_ladder.py` and are reproduced under `--full`.

### 11.56.3 What it changes

**Established:** a certified v2 solver whose memory is G′ plus about 100 bytes per node, at the stored solver's tolerances and with its answers. On the differential axis it holds a quarter to an eighth of the stored graph at n = 20–22, with no loss of speed. That removes the memory cap on the series: an n = 23 key now takes 1.2–1.4 GB, so several solve side by side on a 16 GB host.

**A limit, measured:** the linear gain shrinks with width. G′ holds 0.25–0.57 of the stored linear graph at n = 17, 0.45 at n = 20 and 0.70 at n = 22. On that axis most of the stored graph is edges the certificate does need, and the per-node arrays are a growing share of the peak.

**Still open (TODO #343):** the key-sampled series of §11.55 carried to n = 22–23 with this solver, and c/n at more rounds (§11.57).

**Unchanged:** every rating, and every pinned figure.

## 11.57 The r-round transient over keys, to n = 20 — TODO #343, fourth and fifth passes

§11.54.4 found that the deployed criterion is on the exact best trail over the deployed rounds, W(3n/4) ≥ n (n/2 linear). That trail is cheaper than μ · 3n/4 by a start-up discount c = W(r) − μ · r. It measured c/n on eight keys per width at n = 10–14, because `v2_round_transient.c` holds the round's whole $2^{2n}$ table. The corrected bars on μ, 1.71 and 0.87, and the margins of §11.55 rest on that measurement. The gate is `SecurityProofsCode/v2_transient_series.py`, and the sample is pinned in `v2_transient_series.json`.

### 11.57.1 W(r) without the table

`certified_cycle_mean.c` gains a third mode, which computes W(r) for r = 1 to R. It first runs §11.56's implicit solve, for two things:

- **A lower bound.** The certified potential satisfies $p(v) \le p(u) + w - \mu_{lb}$ on every edge of the graph, so any k-round path out of u weighs at least $k \mu_{lb} + p_{min} - p(u)$.
- **An upper bound.** The same min-plus recursion over G′ alone gives U(r) ≥ W(r), since G′'s paths are paths of the graph.

With S(k) the largest U(r) − r · $\mu_{lb}$ over r = k to R, a node reached after k rounds at cost x can lie on an optimal trail only if $x \le k \mu_{lb} + S(k) - p_{min} + p(u)$. An edge out of it is needed only if its weight is at most $(k+1) \mu_{lb} + S(k+1) - p_{min} - x$. The exact recursion walks only those rows, to that bound. Every prefix of an optimal trail passes both tests, so W(r) is exact.

**Check:** W(r) for r = 1 to 2n equals the dense recursion's at every round, on 36 solves at n = 7–14, both axes, within 1e-12. **Control:** from n = 10, U(r) from G′ alone overstates some W(r) on some key of every width, so the walk over the whole graph is needed. An n = 19 key takes about a minute per axis.

### 11.57.2 The transient over keys

The keys are drawn by §11.55's stratified sampler, with R = 2n rounds and both axes per key: 216, 223, 183, 145, 128, 128, 113 and 107 keys at n = 10, 11, 13, 14, 16, 17, 19 and 20. Here r = ⌊3n/4⌋, and the bar on μ is (1 − c/n) / (3/4), or (1/2 − c/n) / (3/4) on the linear axis.

| n | diff. E[c/n] | diff. bar on μ | diff. keys failing W(r) ≥ n | lin. E[c/n] | lin. bar on μ | lin. keys failing W(r) ≥ n/2 |
|---|---|---|---|---|---|---|
| 10 | −0.283 | 1.71 | 71% | −0.160 | 0.88 | 84% |
| 11 | −0.300 | 1.73 | 53% | −0.162 | 0.88 | 70% |
| 13 | −0.314 | 1.75 | 47% | −0.168 | 0.89 | 59% |
| 14 | −0.330 | 1.77 | 33% | −0.184 | 0.91 | 35% |
| 16 | −0.374 | 1.83 | 16% | −0.201 | 0.94 | 19% |
| 17 | −0.397 | 1.86 | 13% | −0.198 | 0.93 | 17% |
| 19 | −0.419 | 1.89 | 8.3% | −0.208 | 0.94 | 12% |
| 20 | −0.434 | 1.91 | 3.8% | −0.225 | 0.97 | 5.2% |

Standard errors on E[c/n] are 0.003–0.007.

- **A discount on every key:** c < 0 on every key of every width, on both axes.
- **Settled in rounds:** E[c(2n)]/n is within 0.018 (differential) and 0.011 (linear) of E[c(⌊3n/4⌋)]/n at every width. The average discount is taken within a few rounds of the start, so the deployed round count is already past it.
- **Not settled in width:** E[c/n] goes from −0.283 to −0.434 differential and from −0.160 to −0.225 linear between n = 10 and 20. That is 19.6 and 17.6 standard errors. The differential discount deepens at every step.
- **The true criterion:** it fails on more keys than μ · ⌊3n/4⌋ ≥ n does at every width. The share it fails on falls with n: from 71% to 3.8% differential and from 84% to 5.2% linear.

### 11.57.3 What it changes

At n = 19, the widest width of n = 256's residue class, the bars on μ are **1.89 and 0.94**, not §11.54.4's 1.71 and 0.87; those lie 19–22 standard errors below. §11.55's E[μ] over keys at n = 19, 2.507 and 1.250, is **1.32×** both bars, not 1.47× and 1.44×. Read directly, E[W(⌊3n/4⌋)] is 1.42 n differential and 1.40 · (n/2) linear.

At n = 20 the bars are **1.91 and 0.97**, and §11.55's E[μ] there, 2.564 and 1.313, is 1.34× and 1.36× them. E[W(⌊3n/4⌋)] is 1.51 n and 1.54 · (n/2).

### 11.57.4 The pace at n = 20 — fifth pass

n = 20 is the costliest width of the sample: about 15 minutes per key with eight solves sharing memory bandwidth, 107 keys in about 4 hours. The default gate re-solves none of them, and `--full` re-solves them all. They answer the question §11.57.3 left open, which was whether the discount's growth slows. A weighted least-squares slope of E[c/n] against n, fitted over two ranges that share n = 14:

| | d E[c/n] / dn, n = 10–14 | d E[c/n] / dn, n = 14–20 | d E[W(⌊3n/4⌋)/n] / dn, n = 14–20 |
|---|---|---|---|
| differential | −0.0104 ± 0.0016 | −0.0167 ± 0.0013 | +0.056 ± 0.005 |
| linear | −0.0052 ± 0.0008 | −0.0060 ± 0.0006 | +0.037 ± 0.003 |

- **The discount does not slow.** Over n = 14–20 it deepens at least as fast as over n = 10–14: about 3 standard errors faster differential, and level within error linear. Over this range c grows like n², not like n, so the sample fixes no constant c/n that could be carried to n = 256.
- **The criterion still gains.** E[W(⌊3n/4⌋)]/n rises 11 and 13 standard errors over n = 14–20, so μ's growth outpaces the discount. The keys failing the true criterion fall from 8.3% to 3.8% differential and from 12% to 5.2% linear between n = 19 and 20.

**Established:** the transient over keys to n = 20 at the deployed round count. It is a discount on every key and is spent early. It deepens with width and has not slowed by n = 20, while W(⌊3n/4⌋)/n keeps rising.

**Open (TODO #343):** both trends past n = 20. Neither the discount nor the gain on W(⌊3n/4⌋)/n is bounded at n = 256 by anything here, so the bars on μ quoted at n = 19–20 are read at those widths only. §11.58 reads the same keys by quantile, and §11.60 reads the discount as a share of μ.

**Unchanged:** every rating. The margins quoted against the deployed criterion fall from about 1.45× to about 1.3×.

## 11.58 The criterion over keys by quantile — TODO #343, sixth pass

§11.55 and §11.57 report means over keys. A mean can rise while its weak tail stays put, and the weak tail is what a fixed key meets. This section reads the per-key margin y = W(⌊3n/4⌋) / (bar · n), with bar = 1 differential and 1/2 linear, so y ≥ 1 means that key's exact best trail over the deployed rounds meets the deployed criterion. It uses the 1243 keys pinned for §11.57 and solves nothing. The gate is `SecurityProofsCode/v2_key_quantiles.py`.

### 11.58.1 The tail weight, exactly

δ is p rotated by n/4, with p = B · ((B + 1) >> 1) mod 2^n, so δ's nonzero bits lie in a cyclic window of w = n − tz(p) bits. An even key with tz(B) = s gives tz(p) = 2s − 1; an odd key gives tz(p) = tz(B + 1) − 1. So away from the edges P(tz(p) ≥ 2k − 1) = 2^−k + 4^−k, and the exact share, edge keys included, is a short sum.

**Check:** the sum equals enumeration over every key at n = 8–16, for every t.

### 11.58.2 The quantiles

These are stratified quantiles of y. The standard errors come from a seeded bootstrap within strata.

| n | diff. q5 | diff. q10 | diff. q25 | diff. q50 | lin. q5 | lin. q10 | lin. q25 | lin. q50 |
|---|---|---|---|---|---|---|---|---|
| 10 | 0.22 | 0.36 | 0.57 | 0.88 | 0.13 | 0.23 | 0.49 | 0.76 |
| 11 | 0.25 | 0.49 | 0.66 | 0.99 | 0.18 | 0.40 | 0.61 | 0.88 |
| 13 | 0.39 | 0.57 | 0.79 | 1.01 | 0.34 | 0.53 | 0.72 | 0.93 |
| 14 | 0.49 | 0.65 | 0.93 | 1.22 | 0.43 | 0.54 | 0.84 | 1.13 |
| 16 | 0.88 | 0.93 | 1.22 | 1.36 | 0.77 | 0.85 | 1.12 | 1.30 |
| 17 | 0.82 | 0.90 | 1.17 | 1.42 | 0.75 | 0.85 | 1.17 | 1.39 |
| 19 | 0.73 | 1.05 | 1.31 | 1.51 | 0.77 | 0.94 | 1.23 | 1.49 |
| 20 | 1.03 | 1.11 | 1.45 | 1.59 | 1.00 | 1.09 | 1.37 | 1.61 |

Standard errors are 0.02–0.04 on the median and 0.03–0.13 on q5 and q10.

- **Every quantile rises.** q5, q10, q25 and q50 all rise from n = 10 to 20, by 6.7 standard errors or more on both axes.
- **The median key meets the criterion** at every width from n = 14.
- **The tail keeps pace.** Over n = 14–20, q5, q10 and q25 rise at least as fast per bit as the median, within two standard errors. q5 gains +0.061 per bit against the median's +0.059 (differential), and +0.076 against +0.076 (linear). The distribution moves up as a whole, and at n = 20 even q5 is at the bar: 1.03 and 1.00.

### 11.58.3 The bottom does not move

The weakest keys are short-window keys.

- **Where the minimum sits:** at every width, the weakest sampled key has w ≤ 9.
- **No improvement:** keys with w ≤ 9 reach y < 0.25 at every width from n = 10 to 20.
- **Everyone else rises:** from n = 16, every sampled key with w ≥ 10 has y > 0.25; the lowest is 0.42 differential and 0.29 linear.

These findings only bite from n = 16. Below that, w ≤ 9 covers most keys: 75% of them at n = 10. At n = 16–20 the class holds 16, 8, 6 and 4 sampled keys, all from the oversampled t ≥ 8 stratum, so the minima rest on few keys.

The bottom of the distribution is therefore a class set by the window, not by n. §11.58.1 gives its weight: P(w ≤ 9) is 1.6% at n = 20 and $2^{-124}$ at n = 256, comparable to the $2^{-129}$ affine class the CLIs already screen.

**Established:** the deployed criterion over keys by quantile to n = 20. Every quantile from q5 up rises, the 5–25% tail at the median's pace, and q5 reaches the bar at n = 20. The keys that stay weak are a short-window class whose exact weight falls as $2^{-(n-w)/2}$.

**Open (TODO #343):** reading the short-window class at n = 256 assumes the window, not the width, is what makes a key weak. That holds on the sample to n = 20 but is not proved; §11.59 measures it on constructed keys. The quantile trends, like the means, are not bounded at n = 256 by anything here.

**Unchanged:** every rating.

## 11.59 The short-window class — TODO #343, seventh pass

§11.58 found the bottom of the key distribution among short-window keys, whose δ has its nonzero bits in a cyclic window of w = n − tz(p) bits. It put their weight at n = 256 near $2^{-124}$, provided the window rather than the width is what keeps a key weak. The random sample could not test that, because it held only 16, 8, 6 and 4 such keys at n = 16–20. This pass constructs them. The gate is `SecurityProofsCode/v2_short_window.py`, and the keys are pinned in `v2_short_window.json`.

### 11.59.1 The construction

The two branches of tz(p) give keys directly. An even key B = odd · 2^s has tz(p) = 2s − 1, and an odd key B = odd · 2^(t+1) − 1 has tz(p) = t. For each width n = 10, 11, 13, 14, 16, 17, 19 and 20, and each window w = 1 to min(12, n − 2), the gate builds up to six keys with distinct δ. Affine δ are left out, which gives 409 keys. Both axes are solved exactly with §11.57.1's trail mode.

**Check:** every row is the seeded construction and has the window it claims. A prefix re-solves to the recorded values.

### 11.59.2 The window, not the width

With the window held fixed, μ does not grow with n. The slope comes from a fixed-effects fit of μ on n over n = 10–20, with one intercept per window:

| | fixed window, w ≤ 12 | random keys (§11.57) |
|---|---|---|
| differential, per bit | −0.006 ± 0.006 | +0.107 ± 0.003 |
| linear, per bit | +0.001 ± 0.003 | +0.061 ± 0.002 |

The random keys' slope is computed from their own pinned file, as a control: if both slopes were flat, the comparison would fail. Here they differ by 16 and 19 standard errors.

So a key's per-round cost is capped by its window, whatever the width. At n = 20, windows of 1–6 bits give μ of 0.3–1.4 differential, against a key average of 2.59.

### 11.59.3 The class stays weak

For every window w ≤ 6 and every width, the mean margin y = W(⌊3n/4⌋) / (bar · n) is below 0.75: at most 0.70 differential and 0.65 linear. At every width, some key with w ≤ 6 has y < 0.25. Windows of 9–12 bits sit near the bar: their mean y is mostly between 0.8 and 1.25, and lowest (0.50) at n = 11, w = 9.

**Established:** over n = 10–20 and windows up to 12 bits, the window and not the width sets a key's per-round cost. §11.58's reading of the bottom of the distribution is therefore measured, not assumed, within that range. At n = 256, keys with w ≤ 6 weigh P(tz(p) ≥ 250) = $2^{-126}$, and keys with w ≤ 12 weigh $2^{-123}$. That is next to the $2^{-129}$ affine class the CLIs already screen. A screen on tz(p) ≥ n − 12 would remove them at that cost, but no CLI does this today.

**Open (TODO #343):** windows of 13 bits or more are not measured here. Whether a 40-bit window is weak at n = 256 is the width question in another form, since generic keys at n = 20 are windows of about 20 bits. §11.61 measures windows of 13–20 bits from the pinned random sample.

**Unchanged:** every rating.

## 11.60 The discount as a share of the trail — TODO #343, eighth pass

§11.57.4 found that E[c/n] keeps deepening through n = 20, so that c grows like n² and no constant c/n can be carried to n = 256. The bar on μ that §11.57 derives from it climbs with width too. This pass asks what the deepening is made of, and what is left of an extrapolation in n = 256's residue class. It reads the 1243 keys pinned for §11.57 and solves nothing. The gate is `SecurityProofsCode/v2_discount_share.py`.

### 11.60.1 c ≤ 0 is a theorem

The round graph does not change from round to round, because δ(B) is fixed for a key, and a trail's state stays nonzero. So the best trail weight is superadditive: W(a + b) ≥ W(a) + W(b). By Fekete's lemma, μ = lim W(r)/r = sup W(r)/r, so W(r) ≤ μ · r at every r. §11.57.3's finding that c is negative on every key is that lemma, not an empirical result.

**Check:** superadditivity holds on all 505,033 pairs a + b ≤ 2n of every pinned key, on both axes, and c(r) ≤ 0 at every r = 1 to 2n. **Controls:** the first check fires on 162 of 216 n = 10 keys once W is shifted up by one bit, and the second fires on all 216 against a μ understated by 20%.

### 11.60.2 The share holds while c/n deepens

The discount's share is λ(n) = −E[c(⌊3n/4⌋)/n] / E[μ], a ratio of stratified means.

| n | 10 | 11 | 13 | 14 | 16 | 17 | 19 | 20 |
|---|---|---|---|---|---|---|---|---|
| λ, differential | 0.180 | 0.178 | 0.168 | 0.161 | 0.165 | 0.163 | 0.168 | 0.167 |
| λ, linear | 0.217 | 0.207 | 0.189 | 0.184 | 0.181 | 0.165 | 0.169 | 0.169 |

Standard errors are 0.002–0.004. Over n = 14–20, E[c/n] deepens by 0.0167 per bit differential and 0.0060 linear. If that deepening were independent of μ, λ would rise by about 0.0071 and 0.0051 per bit. It does not:

- **Differential:** λ moves +0.0011 ± 0.0006 per bit.
- **Linear:** λ falls, −0.0024 ± 0.0007 per bit.

So most of the deepening is μ's own growth. The trail saves about the same share, roughly one sixth, of a dearer round. In §11.57's terms the discount does not slow, but it is not a separate trend competing with μ.

### 11.60.3 Not a law for each key

Within a width, c/n is not proportional to μ. A least-squares line c/n = a + b · μ over a width's keys has b near −0.085 differential and −0.06 linear, well short of −λ. Its intercept is below zero by 6 standard errors or more differential, and 9 or more linear, at every width from n = 14. So λ describes the key average, and a single key's margin still has to be read from its own W.

### 11.60.4 The class n ≡ 1 (mod 3)

n = 256 is in this class, and its measured widths are 10, 13, 16 and 19. n = 7 is left out because its five rounds are all transient. With the share held, the margin at 3n/4 rounds, which is exact at n = 256, is y\* = E[μ] · (3/4 − λ) / bar. This also removes the wobble of ⌊3n/4⌋/n, which is 0.700, 0.692, 0.750 and 0.737 across the class.

| n | 10 | 13 | 16 | 19 |
|---|---|---|---|---|
| y\*, differential | 0.917 | 1.091 | 1.329 | 1.457 |
| y\*, linear | 0.850 | 1.030 | 1.288 | 1.428 |

- **y\* rises at every step** of the class, by 4.4 standard errors or more.
- **The bar on μ becomes fixed in n.** With λ pooled over n = 14–20, it is bar / (3/4 − λ) = **1.71 and 0.865**, against §11.57's 1.89 and 0.94 at n = 19, which climb with E[c/n]. E[μ] at n = 19 is **1.46× and 1.43×** it, 22 and 18 standard errors above.

The gate prints three readings at n = 256 and scores none of them:

- If E[μ] froze at its n = 19 value, y\*(256) would be 1.46 and 1.43.
- The criterion fails at n = 256 only if E[μ] falls 31% (30% linear) below its n = 19 value, or if λ rises to about 0.35, double any value measured from n = 14.
- If the class's increments of y\* kept their last ratio, 0.54, y\* would level at 1.61 and 1.59.

Each of these spans 79 periods, and assumes the share holds over 237 bits more than were measured.

**Established:** c ≤ 0 is a theorem. Over n = 14–20, the discount is a roughly constant share of μ on average over keys, so the deepening of c/n does not compete with μ's growth. With the share held, the n = 256 question narrows to whether E[μ] stays within 30% of its n = 19 value.

**Open (TODO #343):** whether λ stays near 0.17 past n = 20. Nothing here bounds it, and §11.60.3 shows it is not a per-key law. Whether E[μ] keeps rising remains #257's question.

**Unchanged:** every rating. The margin against the deployed criterion reads about 1.45× with the share held, against about 1.3× with c/n held at its n = 19–20 value. The share-held figure is a reading, not a bound.

## 11.61 The long-window keys — TODO #343, ninth pass

§11.59 constructed keys with windows w = n − tz(p) of at most 12 bits, and left longer windows unmeasured. Those need no construction. §11.55's sampler stratifies on t = tz(p) exactly, so each stratum t < 8 of the pinned random sample is a uniform sample of the keys with window w = n − t. The 1243 keys pinned for §11.57 hold at least 8 keys in every (w, n) cell with w = 13–20 that the plan reaches. This pass reads them together with §11.59's 409 constructed keys and solves nothing. The gate is `SecurityProofsCode/v2_long_window.py`.

### 11.61.1 Mostly the window, not quite only

A fixed-effects slope of μ on n, with one intercept per window, over the 498 random keys with w = 13–20:

| | fixed window, w = 13–20 | random keys (§11.57) |
|---|---|---|
| differential, per bit | +0.023 ± 0.010 | +0.107 ± 0.003 |
| linear, per bit | +0.016 ± 0.005 | +0.061 ± 0.002 |

- **Most of the width trend is the window.** The fixed-window slope is 8 standard errors below the random keys' on both axes. A random key's window is within six bits of n for 93% of keys, so E[μ] rising with n is mostly the window growing.
- **What is left only helps.** The residual width effect is positive, at 2.2 and 3.0 standard errors. For windows up to 12 bits, §11.59's constructed keys showed none.

### 11.61.2 The window curve

The window curve f(w) is the mean over widths of the cell means, taken over both pinned files.

| w | 1–4 | 5–8 | 9–12 | 13–16 | 17–20 |
|---|---|---|---|---|---|
| f, differential | 0.76 | 1.28 | 1.90 | 2.36 | 2.60 |
| f, linear | 0.39 | 0.62 | 0.92 | 1.16 | 1.32 |

- **f rises block by block** on both axes.
- **Every window from 13 bits meets the criterion on average.** The mean margin y = W(⌊3n/4⌋) / (bar · n) is at least 1.21 differential and 1.15 linear.
- **Long-window keys still fail, and less often as the window grows.** 23% and 26% of keys are below the bar at w = 13–14, and 4% and 7% at w = 17–20.

The block increments shrink from +0.46 to +0.24 differential and from +0.24 to +0.16 linear. The gate prints this and does not score it. It is #257's levelling question, asked of the window instead of the width.

### 11.61.3 What it changes

At n = 256, every window measured here is negligible. P(w ≤ 20) is about 2^-119, and 93% of keys have windows of 250 bits or more.

**Established:** keys with windows of 13–20 bits behave like ordinary keys of that many bits. Most of E[μ]'s growth with n is the window growing, and the width adds a small positive residual. Under the deployed criterion the weak class is the windows of about 12 bits or fewer, as in §11.59.

**Closed as far as n ≤ 20 can close it:** windows of 13 bits or more. Above 20 bits a w-bit window is the width question at w. Because the residual width effect is not negative, a key at n = 256 is read as no weaker than a key with the same window measured at width w. That is a reading of n ≤ 20, not a bound. §11.64.1 withdraws it: with the arc held fixed instead of the window, μ falls with n.

**Unchanged:** every rating.

## 11.62 The series at n = 22 — TODO #343, tenth pass

Every item §11.60 and §11.61 left open needs a width past 20. n = 22 is the next width of n = 256's residue class n ≡ 1 (mod 3), and §11.53's implicit solver reaches it: one key costs about 32 minutes differential and 12 minutes linear, at about 0.87 GB. So this is a sample, not a census. 43 keys are drawn by key_series' rule, at least 3 per stratum of t = tz(p) and otherwise 30 keys in proportion, with seed 3431. Each is solved for W(1..16) on both axes, and 16 = ⌊3n/4⌋. The run took 6 h 17 min at seven solves in parallel on an aarch64 SBC. The gate is `SecurityProofsCode/v2_series_n22.py`. It reads the pinned file, so its verdicts cannot flake.

### 11.62.1 The sample and Fekete

The nine strata hold all 2^22 keys except key_series' 1536 affine-delta keys, and the pinned rows are exactly the seeded draw. W is superadditive and c(r) ≤ 0 at every round of every key, on both axes. That is §11.60.1's theorem, checked at a width where it had not been looked at. The control fires on W(r) + 1 at 40 of the 43 keys.

### 11.62.2 The class one step on

| n | 10 | 13 | 16 | 19 | 22 |
|---|---|---|---|---|---|
| E[μ], differential | 1.569 | 1.866 | 2.272 | 2.492 | 2.757 ± 0.038 |
| y\*, differential | 0.917 | 1.091 | 1.329 | 1.457 | 1.613 |
| below the bar, differential | 70.9% | 46.5% | 16.2% | 8.3% | 2.3% |
| E[μ], linear | 0.735 | 0.891 | 1.114 | 1.235 | 1.430 ± 0.025 |
| y\*, linear | 0.850 | 1.030 | 1.288 | 1.428 | 1.653 |
| below the bar, linear | 83.7% | 58.7% | 18.8% | 11.7% | 2.3% |

y\* uses §11.60.4's λ, pooled over n = 14–20.

- **E[μ] keeps rising**, by 5.1 standard errors differential and 6.1 linear from n = 19, and y\* rises with it.
- **The share holds at a fifth width.** λ(22) is 0.172 differential and 0.161 linear, within 0.015 of the pooled 0.165 and 0.172. The two axes move in opposite directions, by +2.0 and −2.8 standard errors. Both are under half the break-even λ at n = 22, 0.387 and 0.400.
- **E[μ] at n = 22 is 1.61× and 1.65× the share-held bar** of 1.71 and 0.865.
- **The keys below the bar fall to 2.3%** on each axis. Every sampled key below the bar has tz(p) ≥ 6, which means a window of 16 bits or less. In this sample the failures that remain are §11.61's short windows. §11.63.1 corrects that reading: a larger sample has a failing key whose window is 18 bits.

The gate prints the class increments of E[μ] and does not score them. They are +0.30, +0.41, +0.22, +0.27 differential and +0.16, +0.22, +0.12, +0.20 linear. §11.60.4's levelling reading took the 16 → 19 step's ratio, 0.54, and levelled y\* at 1.61 and 1.59. n = 22 alone reaches that, and its step is larger than the one before. The increments alternate instead of shrinking, so four steps show no level.

### 11.62.3 What it changes

**Established:** at n = 22, over a 43-key stratified sample, E[μ] still rises and λ still sits near 0.17. The deployed criterion's margin with the share held reads about 1.6× on both axes, up from about 1.45× at n = 19.

**Caveats:** 43 keys is a thin sample. The 2.3% below the bar is three keys, and the strata t ≥ 2 hold 3–5 keys each. The SEs above are the stratified ones and are honest for E[μ] and λ, but not for the tail share. This is a measurement at n = 22, not a bound at n = 256.

**Open (TODO #343, #257):** whether λ stays near 0.17 and E[μ] keeps rising past n = 22. The next width of the class is n = 25. If memory scales with 2^n, as it has so far, a solve there needs about 7 GB, so this 16 GB host could run only two at a time. That cost has not been measured.

**Unchanged:** every rating.

## 11.63 The tail at n = 22, and the arc the window misses — TODO #343, eleventh pass

§11.62's tail was thin. The strata t ≥ 2 held 3–5 keys each, and the share below the bar was three keys. This pass draws 33 more keys in a second seeded draw that does not overlap the first, bringing every stratum from t = 2 to t = 8 up to 8 keys. The union of two disjoint simple random samples of a stratum is itself one, so the stratified estimators carry over. The run took 4 h 04 min at seven solves in parallel. The gate is `SecurityProofsCode/v2_tail_n22.py`. It reads the two pinned files and counts five widths exhaustively, so its verdicts cannot flake.

### 11.63.1 The tail at n = 22

| 76 keys at n = 22 | differential | linear |
|---|---|---|
| E[μ] (43 keys: 2.757, 1.430) | 2.754 ± 0.030 | 1.429 ± 0.022 |
| λ (43 keys: 0.172, 0.161) | 0.172 ± 0.003 | 0.162 ± 0.003 |
| below the bar | 1.9% ± 0.8% | 1.9% ± 0.8% |
| below the bar at n = 19 | 8.3% ± 2.4% | 11.7% ± 2.8% |

- **The top-up leaves E[μ] and λ in place**, within one of §11.62's standard errors.
- **The share below the bar falls from n = 19**, by 2.6 standard errors differential and 3.4 linear. It now has a standard error, but it still rests on six keys.
- **Correction to §11.62.2.** One of the failing keys has t = 4, which is a window n − tz(p) of 18 bits. Its p is `0000000000100010010000`, with ten leading zeros as well as four trailing zeros, so the nonzero bits of its round constant fit in an 8-bit arc.
- **§11.61's fixed-window slope** with the 48 n = 22 keys of windows 15–20 added is +0.016 ± 0.008 differential and +0.012 ± 0.004 linear per bit. That is still 10 standard errors below random keys'.

### 11.63.2 The arc, not n − tz(p)

The nonzero bits of δ lie in a cyclic arc of length n minus δ's longest cyclic run of zeros. tz(p) is only one of those zero runs, so the window n − tz(p) bounds the arc from above. Over all 1319 pinned random keys, n = 10–22:

- **Within a width, the arc explains the margin far better than the window does.** R² is 0.62 and 0.63 for the arc, against 0.37 and 0.38 for the window. The control, with the arcs shuffled among the keys of each width, gives 0.001.
- **Long arcs rarely fail.** From n = 19 on, keys with an arc over 12 bits fall below the bar 3 times out of 237 on each axis, against 15 and 20 out of 268 for a window over 12 bits. Most of §11.61's long-window failures are short arcs.

### 11.63.3 What it changes

Counted exhaustively at n = 16, 17, 19, 20 and 22, the short-arc class (arc ≤ 12) is 2.25–3.63 times the short-window class (w ≤ 12), with no trend in n. The gate prints and does not score the reading at n = 256: at that ratio the class would weigh about 2^-121, against 2^-123 for w ≤ 12. That is an extrapolation, not a count.

**Established:** the weak class of v2 keys is the keys whose round constant's nonzero bits fit in a short cyclic arc. n − tz(p) is an upper bound on that arc, so §11.59–§11.61 read the class through a coarse proxy. The class stays negligible at n = 256.

**Corrected:** §11.59's suggested screen on tz(p) ≥ n − 12 misses most of the class. A screen should test the arc. None ships.

**Caveats:** §11.63.2's counts are unweighted, because the sample is stratified on t and not on the arc.

**Unchanged:** every rating.

## 11.64 The arc curve — TODO #343, twelfth pass

§11.63 found that the cyclic arc of δ, not the window n − tz(p), sets a key's margin. It left the arc curve open, because every pinned sample was stratified on t and not on the arc. This pass draws by the arc. For arcs 4, 8, 12 and 16 and every width n = 10–22 not divisible by 3, it draws 6 keys uniformly from the keys with exactly that arc, with distinct round constants. That is 162 keys in 27 cells, with μ and W(⌊3n/4⌋) solved on both axes. Widths divisible by 3 are left out because M is not invertible there and μ is 0 on every key; the gate checks this at n = 12. The gate is `SecurityProofsCode/v2_arc_curve.py`, and it reads the pinned file.

### 11.64.1 At a fixed arc, μ falls with the width

| differential μ | n = 10 | 11 | 13 | 14 | 16 | 17 | 19 | 20 | 22 |
|---|---|---|---|---|---|---|---|---|---|
| arc 4 | 0.81 | 1.15 | 0.90 | 1.00 | 0.84 | 0.95 | 0.68 | 0.95 | 0.80 |
| arc 8 | 1.90 | 2.03 | 1.71 | 1.66 | 1.59 | 1.77 | 1.48 | 1.50 | 1.33 |
| arc 12 | | | | 2.15 | 2.36 | 2.27 | 2.25 | 2.26 | 2.00 |
| arc 16 | | | | | | | 2.80 | 2.76 | 2.71 |

- **The fixed-arc slope is negative.** With one intercept per arc it is −0.030 ± 0.007 per bit differential and −0.013 ± 0.003 linear, at 4.4 and 4.0 standard errors. Random keys gain +0.107 and +0.061 per bit, so their growth with n is the arc growing with n, which more than offsets the fall.
- **It is not a residue-class mix.** At arc 8 it falls in both classes, n ≡ 1 and n ≡ 2 (mod 3).
- **It replicates** on the 1368 earlier pinned keys with an arc of at most 12, random and constructed: −0.025 ± 0.003 and −0.007 ± 0.001 per bit.
- At arc 8, differential μ falls 30% from n = 10 to n = 22, and no levelling is visible.

**This withdraws §11.61.3's reading** that a key at n = 256 is no weaker than a key with the same window measured at width w. That reading rested on a positive fixed-window slope, and a fixed window mixes arcs.

### 11.64.2 At a fixed width, μ rises with the arc

At every width the cell means rise from arc 4 to 8 to 12 to 16, on both axes. Every arc-4 key fails the deployed criterion at every width, and no arc-16 key does. The share failing is 43 and 46 of 54 at arc 8, and 6 of 36 at arc 12.

### 11.64.3 Where typical keys sit

| n | 13 | 14 | 16 | 17 | 19 | 20 |
|---|---|---|---|---|---|---|
| mean n − arc | 3.99 | 4.13 | 4.28 | 4.35 | 4.47 | 4.54 |
| P(n − arc ≤ 3) | 0.50 | 0.48 | 0.45 | 0.43 | 0.40 | 0.38 |

Counted over every key, a random key's arc falls a few bits short of n, and the gap grows the way the longest zero run of a random string does, about 0.9 bits per doubling of n. The gate prints and does not score the reading at n = 256, which is about 8 bits.

**Established:** μ is set by the arc, and at a fixed arc it falls slowly with the width over n = 10–22. Random keys gain with width only because their arc grows with it.

**For typical keys:** they sit near the diagonal, with an arc close to n, so §11.64.1's fall reaches them only through a gap of a few bits that grows like log n. Their n = 256 question is still the width question; §11.65 reads it at a fixed gap.

**For short-arc keys:** they get weaker as the width grows at a fixed arc, so at n = 256 they are weaker than the same arc measured here. They are already the class that fails, and it weighs about 2^-121 (§11.63.3, extrapolated).

**Caveats:** six keys per cell; arc 16 is measured only at n = 19, 20 and 22. The fall is a slope measured over n = 10–22, not a law.

**Unchanged:** every rating.

## 11.65 The gap curve — TODO #343, thirteenth pass

§11.64 found that at a fixed arc μ falls with the width, and that a typical key's arc sits a few bits short of n. It left open the question that matters for those keys: μ at a fixed gap n − arc as n grows, and whether the cost of a gap bit stays bounded. This pass needs no solves. It reads the gap off every pinned random key: the 1243 keys of the transient series at n = 10–20 and the 76 keys at n = 22 (§11.62, §11.63), 1319 in all. The 162 arc-drawn keys of §11.64 serve as an independent replicate. The gate is `SecurityProofsCode/v2_gap_curve.py`.

### 11.65.1 At a fixed gap, μ rises with the width

| differential μ | n = 10 | 11 | 13 | 14 | 16 | 17 | 19 | 20 | 22 |
|---|---|---|---|---|---|---|---|---|---|
| gap 2 | 1.94 | 2.10 | 2.18 | 2.45 | 2.49 | 2.60 | 2.79 | 2.69 | 2.99 |
| gap 3 | 1.73 | 1.81 | 2.12 | 2.36 | 2.45 | 2.63 | 2.75 | 2.83 | 2.95 |
| gap 4 | 1.38 | 1.78 | 1.89 | 2.08 | 2.44 | 2.53 | 2.71 | 2.70 | 2.84 |
| gap 6 | 0.94 | 1.30 | 1.51 | 1.66 | 2.12 | 2.26 | 2.20 | 2.34 | 2.63 |

- **The fixed-gap slope is the random-key slope.** With one intercept per gap, over the 770 keys with a gap of at most 4, it is +0.111 ± 0.003 per bit differential and +0.065 ± 0.002 linear. Random keys gain +0.107 and +0.061. So E[μ]'s growth with n is growth at a fixed gap, and none of it is carried by the gap moving.
- **It is not the stratification.** With one intercept per (gap, t) cell it is +0.125 and +0.069. On the t = 0 stratum alone it is +0.102 and +0.061, above 15 standard errors on both axes.
- **It replicates** on the independent arc-drawn keys with a gap of at most 10: +0.135 ± 0.008 and +0.069 ± 0.004.

This and §11.64.1 read one surface along two lines. At a fixed gap the arc grows one-for-one with n, and a bit of arc is worth more than the fixed-arc fall takes away.

### 11.65.2 The cost of a gap bit falls with the width

At each width the gate fits the slope of μ on the gap over gaps 2–10. Gaps 0 and 1 are rare, with at most 13 keys per width, and are not monotone.

| n | 10 | 11 | 13 | 14 | 16 | 17 | 19 | 20 | 22 |
|---|---|---|---|---|---|---|---|---|---|
| differential, per gap bit | −0.22 | −0.20 | −0.20 | −0.21 | −0.14 | −0.15 | −0.16 | −0.12 | −0.11 |
| as a share of mean μ | 15% | 12% | 11% | 11% | 7% | 6% | 7% | 5% | 4% |
| linear, per gap bit | −0.10 | −0.09 | −0.09 | −0.11 | −0.07 | −0.08 | −0.09 | −0.07 | −0.07 |

- **A gap bit always costs.** Every slope is below −5 standard errors.
- **The cost shrinks with the width.** Differential, it is −0.21 per bit at n = 10–11 and −0.11 at n = 20–22 (8.3 SE apart); linear, −0.094 and −0.072 (3.5 SE). As a share of the width's mean μ it falls by more than half on both axes, from about 13% to about 5%.
- The gate prints and does not score one reading: at n = 22, moving a key from gap 4 to the roughly 8 bits that §11.64.3 extrapolates for n = 256 costs about 0.45 of a mean μ of 2.56 differential.

**Established:** over n = 10–22, typical keys gain with width at a fixed gap at the full random-key rate. §11.64's fall at a fixed arc is the cost of a gap bit, and that cost is bounded and shrinking.

**For typical keys:** this is the most direct reading of the n = 256 question these widths allow, and every part of it says the width helps. Their gap grows like log n (§11.64.3) while the cost of each gap bit falls.

**Caveats:** keys are stratified on t, not on the gap, so cell means are unweighted. The mean μ in the share row is the sample's, not E[μ]. Every trend is measured over n = 10–22, not proved, and nothing says how it continues.

**Unchanged:** every rating.
