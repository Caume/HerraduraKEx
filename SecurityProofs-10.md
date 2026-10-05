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
> - **Part 10 — §11.43–§11.45** (this file): The Local Certificate · The Local Certificate at n = 256 · The Linear Hull, Measured

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
