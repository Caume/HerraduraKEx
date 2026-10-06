# Formal Cryptographic Analysis of the Herradura Cryptographic Suite — Part 9

**Status:** See Part 1 (SecurityProofs-1.md) for full status header.

> **This is Part 9 of a split document.**
>
> - **Part 1 — §1** (SecurityProofs-1.md): Algebraic Foundations
> - **Part 2 — §2–§8** (SecurityProofs-2.md): Protocol Analysis · Security Analysis · Summary Tables · Quantum Attack Analysis · Experimental Code Index
> - **Part 3 — §9–§10** (SecurityProofs-3.md): Non-Linear Proposals · v1.4.0 Migration
> - **Part 4 — §11–§11.8.2** (SecurityProofs-4.md): Non-linearity and Post-quantum Extensions · NL-FSCX v1/v2 · HKEX-RNL
> - **Part 5 — §11.8.3–§11.8.10** (SecurityProofs-5.md): PQ Signature Options · HPKE-Stern-KEM
> - **Part 6 — §11.9** (SecurityProofs-6.md): HFSCX-256-DM
> - **Part 7 — §11.10–§11.13, §11.15–§11.33** (SecurityProofs-7.md): Zero-Knowledge Proof Extensions · Research-Review Sections
> - **Part 8 — §11.34–§11.36** (SecurityProofs-8.md): NL-FSCX v3 — Exact Row Analysis · Asymptotic Trail Slopes
> - **Part 9 — §11.37–§11.42** (this file): The Width Residue · The Annealed Threshold at n = 256 · The Pair Correlation · The Quenched Check · The Certified Ladder · The Exact Slope
> - **Part 10 — §11.43–§11.46** (SecurityProofs-10.md): The Local Certificate · The Local Certificate at n = 256 · The Linear Hull, Measured · Where the Cycles Pay

---

## 11.37 The width extrapolation — the one question TODO #252 and TODO #254 share

`SecurityProofsCode/width_residue.py` reproduces everything in this section.  §11.35 computed the asymptotic *differential* slope exactly as a minimum mean cycle; §11.36 did the same for the *linear* slope, on both NL-FSCX v1 and v2.  Each ends owing the width extrapolation and nothing else, and it is the same extrapolation about the same kind of object.  This section is that shared residue, worked.

It does not close it.  It changes what is being asked, three times over.

### 11.37.1 The residue is monotonicity, not the limit

Both criteria are already met at the widest width either item reached, and every measured value is exact — a minimum mean cycle, not a slope read off a finite series.

| axis | widest exact value | criterion | margin |
|---|---|---|---|
| differential | $s_{\text{diff}} = 1.903$ at $n = 11$ | $4/3 = 1.3333$ | $1.43\times$ |
| linear | $s_{\text{lin}} = 1.154$ at $n = 13$ | $2/3 = 0.6667$ | $1.73\times$ |

Both sequences rise monotonely over every width measured, on both primitives, and the fraction of keys below the criterion falls to zero for v2's linear slope by $n = 13$.  So the extrapolation does not have to produce a limit.  It has to rule out a turning point:

$$\text{if } \mu(n) \text{ is non-decreasing for } n \geq 13, \text{ both criteria hold at } n = 256.$$

That is a strictly weaker obligation than the one #252 and #254 were filed with, and it is worth stating because both items have been carrying the harder version of the question for four passes.

### 11.37.2 There is no embedding between widths, which resolves §11.35.7's caution

§11.35.7 warned that the obvious tool points the wrong way: exhibit a cycle at width $n$ that survives at width $n+1$ and one proves $\mu$ **non-increasing**, the opposite of what is measured.  The warning turns out to be unnecessary, and the reason is worth having.

Both of the round's width-dependent objects change with $n$.  $M = I \oplus \mathrm{ROL} \oplus \mathrm{ROR}$ is built from rotations by one position, so $M_n$ and $M_{n+1}$ disagree on almost every argument; and $\delta(B) = \mathrm{ROL}(B \lfloor (B+1)/2 \rfloor \bmod 2^n, n/4)$ changes in its modulus *and* in its rotation amount.  Measured, of the nodes lying on an optimal cycle at width $n$, the fraction whose image under $M$ is unchanged at width $n+1$ is $33$% at both $n = 7$ and $n = 10$.  A cycle of length $L$ therefore survives with probability about $0.33^{L}$, and §11.37.3 measures $L \geq 10$ everywhere — so in practice none survives, and the same key's $\delta$ is a different constant besides.

**The graph at width $n+1$ is not an extension of the graph at width $n$; it is an unrelated graph on a different vertex set.**  The obvious tool does not point the wrong way.  It does not apply.  The consequence is clarifying rather than comfortable: a monotonicity proof cannot come from comparing two graphs, so it has to come from a statement about the *ensemble*, which is §11.37.4.

### 11.37.3 Two routes closed by measurement

**The sparse-subgraph route.**  The natural first idea for reaching $n = 256$ is to search only low-Hamming-weight differences or masks.  That subgraph is small enough to enumerate at any width, and because a subgraph has fewer cycles its minimum mean is an *upper* bound on the true one — so a cheap cycle found there would be a real result at the deployed width.  It fails on the input: the optimal cycle is dense.

| axis | $n$ | median cycle length | median max Hamming weight | as a fraction of $n$ |
|---|---|---|---|---|
| differential | 7 / 8 / 10 / 11 | 12 / 10 / 22 / 13 | 6 / 6 / 7 / 8 | $0.86 / 0.75 / 0.70 / 0.73$ |
| linear | 7 / 8 / 10 / 11 | 10 / 10 / 11 / 10 | 4 / 5 / 6 / 7 | $0.57 / 0.62 / 0.60 / 0.64$ |

No downward trend at any width.  At $n = 256$ that is a difference or mask of weight between 150 and 220, while the subgraph of weight at most $w$ has $\binom{256}{\leq w}$ nodes — enumerable only for single-digit $w$.  The optimal cycle is not in any subgraph anyone can build, and it is not close.

**The LP-dual route**, which is the only one that could give a *theorem* rather than an estimate.  Minimum mean cycle is a linear program, and its dual says that if a potential $h$ on the nodes satisfies

$$w(a \to b) + h(b) - h(a) \geq \lambda \quad \text{for every edge},$$

then $\mu \geq \lambda$ unconditionally, at any width.  Howard's algorithm already produces the optimal $h$ as its bias, so the question is whether that $h$ has a closed form one could write down at $n = 256$ and verify combinatorially.  Measured against every natural statistic of a node — Hamming weight, trailing zeros, NAF weight, the value itself — the largest correlation anywhere is $0.371$ (Hamming weight, linear axis, $n = 8$), accounting for about a seventh of the variance; every differential-axis entry is under $0.11$.  A potential must still exist, but it cannot be guessed from these, and a potential computed node by node is a $2^{256}$-sized object.

### 11.37.4 The route that is open: an annealed first-moment model

§11.37.2 says a monotonicity proof cannot come from relating two graphs, so it has to come from treating the graph as a member of an ensemble.  That can be tested directly.

In a digraph on $N$ nodes where each node has $D$ out-edges to arbitrary targets, with weights drawn from a distribution $F$, the expected number of cycles of length $L$ whose mean weight is at most $\lambda$ is about

$$\frac{D^{L}}{L} \Pr[W_1 + \dots + W_L \leq \lambda L] \ \approx\ \frac{1}{L}\exp\bigl(L(\ln D - I(\lambda))\bigr)$$

with $I$ the large-deviation rate function of $F$.  The exponent changes sign at the $\lambda$ solving $I(\lambda) = \ln D$, so that $\lambda$ is the model's prediction for the minimum mean cycle — depending on nothing but the weight distribution and the out-degree, both of which are available at any width.

| axis | $n$ | exact $\mu$ | annealed | ratio | out-degree |
|---|---|---|---|---|---|
| differential | 7 | $1.4958$ | $1.2644$ | $0.846$ | 9 |
| differential | 8 | $1.7483$ | $1.5644$ | $0.892$ | 13 |
| differential | 10 | $1.7385$ | $1.6352$ | $0.972$ | 19 |
| differential | 11 | $1.8943$ | $1.8975$ | $0.967$ | 30 |
| linear | 7 | $0.6851$ | $0.5876$ | $0.851$ | 43 |
| linear | 8 | $0.8180$ | $0.7159$ | $0.880$ | 86 |
| linear | 10 | $0.8058$ | $0.7562$ | $0.997$ | 256 |
| linear | 11 | $0.8951$ | $0.8846$ | $1.004$ | 341 |

Per-key median ratios $0.846 \to 0.892 \to 0.972 \to 0.967$ and $0.851 \to 0.880 \to 0.997 \to 1.004$: the model under-predicts at the narrow widths — the direction that matters, since under-predicting $\mu$ over-states the attacker's advantage — and the gap closes to a few percent by the widest width, on both axes independently.  That is the expected behaviour of a first-moment threshold on a graph becoming locally tree-like: asymptotically tight, pulled low at small sizes by correlations a tree does not have.

Two cautions before this is leaned on.  The convergence is to within a few percent, not to zero, and on a small sample of keys the ratio overshoots one by about a tenth — so **this is an estimator, not a bound**, and a claim resting on it would need the sign of the finite-size correction established rather than observed.  What it does establish is that $\mu$ is not an algebraic accident of this cipher: it is close to what the weight distribution alone predicts.

### 11.37.5 What the model needs, and the third closed route

The annealed threshold solves $I(\lambda) = \ln D$.  With $D$ of order $2^n/3$ on the linear axis, $\ln D$ is about $n \ln 2$, and the $\lambda$ achieving a rate that large is the quantile of $F$ at roughly $3 \cdot 2^{-n}$.  The threshold is set by the *cheapest* edges a node has, not by typical ones — and indeed $\mu$ sits between the tenth percentile and the median of the per-node minimum out-edge weight at every width measured:

| axis | $n$ | $\mu$ | p10 min out-edge | median min out-edge |
|---|---|---|---|---|
| differential | 7 / 8 / 10 / 11 | $1.496 / 1.748 / 1.739 / 1.894$ | $1.000 / 1.356 / 1.415 / 1.708$ | $2.000 / 2.415 / 2.415 / 2.915$ |
| linear | 10 / 11 | $0.806 / 0.895$ | $0.516 / 0.677$ | $1.206 / 1.317$ |

The median minimum out-edge weight rises with $n$ at about the rate $\mu$ does.  So the width dependence of the whole construction is inherited from one quantity: **the largest correlation of $x \mapsto x + d$ for a fixed output mask, and its differential twin, the largest $\mathrm{xdp}^{+}$ for a fixed input difference.**  That is the residue stated with no FSCX in it — a question about modular addition with a constant.

It is also why the third route fails.  *Estimate $F$ at $n = 256$ by sampling mask pairs, then evaluate the model* reaches the bulk of $F$ and not a tail of measure $2^{-n}$.  Run at $n = 256$ that procedure returns about $157$; run at $n = 13$, where the answer is known, it returns $0.48$ against an exact $1.154$.  The control is what identifies the $157$ as an artefact of the sampler, and it is recorded here so that nobody quotes it.

### 11.37.6 A decomposition that shortens the sequence to extrapolate

The slope depends on the key almost entirely through $\mathrm{tz}(\delta)$ — the same statistic #253's differential weak class is defined by and §11.30.5's correlation-1 mask subspace is indexed by.  Within a width, $\mu$ falls by a roughly constant amount per trailing zero:

| $n$ | $\mathrm{tz} = 0$ | $1$ | $2$ | $3$ | $4$ | per-$\mathrm{tz}$ slope |
|---|---|---|---|---|---|---|
| 8 | $0.797$ | $0.664$ | $0.564$ | $0.417$ | $0.321$ | $0.119$ |
| 10 | $0.882$ | $0.832$ | $0.611$ | $0.491$ | — | $0.130$ |
| 11 | $0.939$ | $0.862$ | $0.715$ | $0.611$ | $0.539$ | $0.100$ |

The per-trailing-zero cost is $0.100$ to $0.130$ — flat to within the sample.  If that offset is width-independent, and it looks it, the whole per-key distribution at $n = 256$ follows from **one** sequence, the $\mathrm{tz} = 0$ class, plus a constant — because the distribution of $\mathrm{tz}(\delta)$ does not itself depend on the width.  That halves the extrapolation's surface without assuming anything about its limit.

### 11.37.7 Where this leaves the two items

**Their remaining scope is identical**: the width behaviour of a minimum mean cycle over an add-constant transition graph, on two axes sharing their machinery, their obstacle and their reduction.  Carrying two items whose open text would be the same paragraph is how the disagreement-between-documents class of defect (#237, #238) begins, and merging them is recommended.

**The obligation is smaller than either item states.**  By §11.37.1 what is owed is monotonicity, not a limit.

Routes, ranked, with three now closed:

1. **Open, and the only one with a path to $n = 256$.**  Bound the largest correlation and the largest $\mathrm{xdp}^{+}$ of addition with a *constant* as a function of $n$ (§11.37.5).  Self-contained, and it feeds a model already validated to within a few percent at $n = 11$.  Note that Wallén's characterisation does **not** apply — §11.30.4 closed that for the constant-addend case — so this needs its own argument.
2. **Open, weaker.**  Extend the exact sequence.  The linear axis reaches $n = 13$ for the cost of an $(n+1)4^{n}$ table and $n = 14$ is a factor of four away; the differential axis is stuck at $n = 11$ on its $2^{2n}$ DDT.  More points would not prove monotonicity but would make a turning point harder to hide.
3. **Closed.**  Sparse-subgraph search at $n = 256$: the optimal cycle is dense (§11.37.3).
4. **Closed.**  Guessing the LP-dual potential: it correlates with nothing (§11.37.3).
5. **Closed.**  Sampling the weight distribution at $n = 256$: the threshold is a $2^{-n}$ quantile, and the sampler misses it by more than a factor of two at $n = 13$, where the answer is known (§11.37.5).

**No rating moves, and none could.**  Every row this touches is already demo-only for reasons on other axes (#243, #244, #248), and the production-track rows #254 hoped to reach were removed from its scope by §11.36.8, which showed a trail bound cannot describe those modes at all.

---

## 11.38 The width extrapolation, evaluated: the annealed threshold at $n = 256$ (TODO #257)

TODO #252 and TODO #254 were merged into **TODO #257** in v5.2.4, because three passes each had reduced them to the same obligation over the same kind of object.  This section is that merged item's first pass.

§11.37 opened one route and, in the same breath, closed the only way anyone had of walking it.  The route is the annealed first-moment model of §11.37.4, which predicts the slope from two inputs — the edge-weight distribution and the out-degree — and tracks the exact $\mu$ to within a few percent by $n = 11$ on both axes.  The closure is §11.37.5: at $n = 256$ the model's threshold sits in a $2^{-n}$ quantile of that distribution, so a *sampler* cannot find it, and the control run recorded there returns $0.48$ at $n = 13$ where the exact answer is $1.154$.

The obstacle is real and it is not the one that matters.  **The model needs the distribution only through its moments, and the moments are a linear dynamic program.**  Nothing is sampled below; nothing is extrapolated from a narrow width.

Reproduce with `python3 SecurityProofsCode/annealed_moment_ladder.py`; it exits non-zero if any finding below stops reproducing.

### 11.38.1 A differential is a constraint sequence, not a pair

The v2 round is $F(x) = M(x \oplus B \oplus C_i) + \delta(B) \bmod 2^{n}$, and two of its three layers move a difference deterministically.  All of the probability is addition of the **constant** $\delta$.

Write $c_i$ and $c'_i$ for the carries into bit $i$ of $x + \delta$ and $(x \oplus \alpha) + \delta$.  Then the output difference satisfies

$$\beta_i = \alpha_i \oplus c_i \oplus c'_i, \qquad c_0 = c'_0 = 0 .$$

So $\beta$ is not a free variable.  Given $\alpha$, the differential is exactly the sequence $e_i = \alpha_i \oplus \beta_i$ of carry-pair *parities*, forced to start at $e_0 = 0$, and

$$\mathrm{xdp}^{+}(\alpha \to \beta) = 2^{-(n-1)} \cdot \lvert \lbrace x : \text{the carry pair follows } e \rbrace \rvert .$$

The carry pair $(c, c')$ takes four values, split by $e$ into two **classes** of two **slots** each; bit $n - 1$ produces only the discarded carry-out, so a differential constrains $n - 1$ steps.  Every transfer is a $2 \times 2$ matrix with entries in $\lbrace 0, 1, 2 \rbrace$, indexed by $(\delta_i, \alpha_i, e_i, e_{i+1})$.

Validated bit-exactly against the exhaustive DDT at $n = 6$ and $n = 7$ — every addend, every $(\alpha, \beta)$ pair, $2^{18}$ and $2^{21}$ entries.  The linear analogue is §11.30.4's `corr_add_const`, one carry with a signed transfer, and is reproduced here so that both ladders share a code path.

### 11.38.2 The moments are linear where the distribution is not

The weight of an edge is $(n-1) - \log_2 N(\alpha, e)$ with $N$ the path count above.  A *histogram* of those weights needs $N$ itself, and the reachable count-vectors proliferate: measured at about $1.5\times$ per bit, $3980$ distinct states by $n = 20$.  That is the wall §11.37.5 hit.

The **moment**

$$A_t = \sum_{\alpha, e} N(\alpha, e)^{t}$$

does not hit it.  For integer $t$, $N^{t}$ counts $t$-tuples of consistent $x$-paths, and a tuple is a walk in the $t$-fold tensor power of the same automaton.  Tensor powers are linear, so the sum over all $(\alpha, e)$ commutes with the transfer: carry **one** running vector of length $2^{t}$ per state, apply $\sum_{\alpha_i, e_{i+1}} T^{\otimes t}$ at each bit, and read $A_t$ off the end.  The cost is $O(n \cdot t \cdot 2^{t})$ — with no dependence on the number of differentials at all.

The edge *count* is the same DP over slot-supports rather than counts, and the two exclusions the graph needs ($\alpha = 0$, $\beta = 0$) are carried as one extra bit of state.  On the linear axis the support needs no DP: §11.36.3's identity gives it in closed form, and the mask pairs excluded contain exactly one nonzero entry, $(0,0)$.

Both are validated against exhaustive enumeration at every addend for $n \le 8$ (differential, $t \le 4$) and $n \le 7$ (linear, $t = 2, 4, 6$).

### 11.38.3 Integer moments are enough — a lemma, not an approximation

The annealed threshold is a supremum over a continuous parameter,

$$\lambda^{*} = \sup_{t > 0} \frac{-\log_2 D - \log_2 M(t)}{t}, \qquad M(t) = \mathbb{E}\left[p^{t}\right],$$

with $D$ the out-degree and $p$ the edge probability.  Only integer $t$ is computable, and restricting a supremum to a lattice gives a lower bound for free.  What makes it *exact* is concavity.

Write $g(t) = -\log_2 D - \log_2 M(t)$.  By Hölder, $\log_2 M$ is convex in $t$, so $g$ is concave; on any interval $[u, v]$ it therefore lies above its chord and below either flanking secant.  Every such bound has the form $(A + Bt)/t$, which is monotone in $t$ and hence extremal at an endpoint.  **Both bounds reduce to lattice values, so the integer lattice brackets $\lambda^{*}$** — and the bracket is observed to close, to $10^{-12}$, at every width and every key tried.

Two graph facts the model consumes are also exact rather than sampled.  The live-node count is $2^{n} - 1$ on both axes: on the differential side because addition is a bijection, so no nonzero input difference is annihilated with probability one; on the linear side by Parseval, since each LAT row has squared entries summing to $1$ while $C(0 \to v) = 0$ for $v \neq 0$.

### 11.38.4 The linear axis reaches only even moments

$\lvert C \rvert^{t}$ is a tensor power only for even $t$; for odd $t$ the DP would need the **sign** of the finished sum, which is not a per-bit quantity.  It is not an affine one either: fitted over $\mathrm{GF}(2)$ in the $2n$ mask bits plus a constant and rejected at every addend tried, with exactly half of the nonzero entries negative in every case.

So the linear ladder runs on $\lbrace 2, 4, \ldots \rbrace$ and brackets rather than closing.  Measured against §11.37.4's histogram routine on the exact mask graph, the lower end is conservative in every case, at most $2.7$% below it, and the bracket is at most $7.7$% wide.  The differential ladder agrees with the same routine to $0.0029$ bits, and is the more accurate of the two — the residual is that routine's $\theta$ grid.

### 11.38.5 The curve, to $n = 256$ — and $\mu$ does not converge

Per-key medians from the exact moment ladder, seven keys per width, both axes.  The criteria are the fixed numbers §11.30.1 derived and do not move with $n$.

| $n$ | $\lambda^{*}_{\mathrm{diff}}$ | $\lambda^{*}_{\mathrm{diff}}/n$ | $\lambda^{*}_{\mathrm{lin}}$ | $\lambda^{*}_{\mathrm{lin}}/n$ | vs $4/3$ | vs $2/3$ |
|---|---|---|---|---|---|---|
| 8 | $1.159$ | $0.145$ | $0.521$ | $0.065$ | $0.9\times$ | $0.8\times$ |
| 11 | $1.692$ | $0.154$ | $0.778$ | $0.071$ | $1.3\times$ | $1.2\times$ |
| 13 | $2.020$ | $0.155$ | $0.923$ | $0.071$ | $1.5\times$ | $1.4\times$ |
| 16 | $2.722$ | $0.170$ | $1.247$ | $0.078$ | $2.0\times$ | $1.9\times$ |
| 32 | $5.463$ | $0.171$ | $2.518$ | $0.079$ | $4.1\times$ | $3.8\times$ |
| 64 | $11.798$ | $0.184$ | $5.444$ | $0.085$ | $8.8\times$ | $8.2\times$ |
| 128 | $23.814$ | $0.186$ | $11.002$ | $0.086$ | $17.9\times$ | $16.5\times$ |
| **256** | $\mathbf{48.44}$ | $0.189$ | $\mathbf{22.40}$ | $0.088$ | $\mathbf{36.3\times}$ | $\mathbf{33.6\times}$ |

**The sequence does not converge.  It is linear in $n$.**  Four passes of this analysis — #247, #252's two, #254's two — asked what the per-round slope converges to.  The premise is wrong: what settles down is $\lambda^{*}/n$, at about $0.19$ on the differential axis and $0.088$ on the linear one.  The criteria are constants.  So the margin *grows* with width, and $n = 256$ is the easiest row in the table rather than the hardest.

The residual variation in $\lambda^{*}/n$ is sampling spread rather than drift, and it **concentrates**: the per-key range of $\lambda^{*}/n$ narrows from $0.0345$ at $n = 32$ to $0.0093$ at $n = 256$ on the differential axis, and from $0.0158$ to $0.0043$ on the linear one.

Two earlier statements need adjusting, one of them mine from §11.35.

* **§11.30.2's scale-invariance theorem stands, but not one of its corollaries.**  That the *criterion* does not depend on $n$ is unaffected.  That "no key size moves it" was read as *widening buys nothing on this axis*, and that reading is wrong: widening faces the same criterion with proportionally more margin.  Nothing here recommends widening — the margin at $n = 256$ is already $36\times$ — but the reason not to is cost, not futility.
* **§11.35.6 and §11.36.5 are retro-explained.**  Both reported $\mu$ rising monotonely over $n = 7$ to $13$ and neither could say why a bounded-looking quantity kept climbing.  It is not bounded.  Those sections' *exact* medians $1.279, 1.349, 1.717, 1.903$ at $n = 7, 8, 10, 11$ are $0.183, 0.169, 0.172, 0.173$ of $n$ — the same constant this table approaches from below, measured on $\mu$ itself rather than on the model.

### 11.38.6 The $\mathrm{tz}$ decomposition at $n = 256$, corrected

§11.37.6 measured $\mu$ falling by $0.100$ to $0.130$ per trailing zero of $\delta$ at $n \le 11$, conjectured that offset to be width-independent, and concluded that only the $\mathrm{tz} = 0$ sequence needs extrapolating.  At $n = 256$ the conjecture is checkable rather than inferred, and it fails in both directions at once.

| $\mathrm{tz}(\delta)$ | $0$ | $1$ | $2$ | $3$ | $4$ | $6$ | $8$ |
|---|---|---|---|---|---|---|---|
| $\lambda^{*}_{\mathrm{diff}}$ | $49.96$ | $49.96$ | $48.36$ | $47.83$ | $47.34$ | $48.05$ | $47.14$ |
| $\lambda^{*}_{\mathrm{lin}}$ | $23.11$ | $23.13$ | $22.39$ | $22.13$ | $21.90$ | $22.22$ | $21.80$ |

The trend survives — least-squares slopes $-0.337$ and $-0.159$ per zero on the two axes.  The *ordering within the table* does not: at this sample size it moves between runs, and adjacent classes are not separated.  Only the trend and the span are stable, and only those are used.

What fails is the conjecture.  The per-zero offset is **not** width-independent: about $0.40$ (differential) and $0.19$ (linear) per zero here, against $0.100$ to $0.130$ at $n \le 11$.  It has instead shrunk sharply *relative* to $\lambda^{*}$ — the whole span across $\mathrm{tz} = 0$ to $8$ is under $6$% of the largest class, where at $n \le 11$ a single trailing zero cost $5$ to $7$%.

§11.37.6's **conclusion** survives *a fortiori*, for a better reason than the one given: the $\mathrm{tz}$ correction at realistic width is negligible rather than merely constant.  The worst class in the table clears both criteria by more than $32\times$.

Over twenty keys at $n = 256$ the per-key range is $43.91$ to $50.86$ (differential) and $20.36$ to $23.53$ (linear).  The closest approach to either bar is $33\times$ on the differential axis and $31\times$ on the linear one.

### 11.38.7 What TODO #257 owes now

**Settled, at the level the model supports.**

1. **The annealed threshold is exactly computable at $n = 256$, on both axes.**  §11.37.5's closure of this route was right about the sampler and wrong about the obstacle.  The $157$ that section recorded as an artefact — with the instruction not to quote it — is replaced by $48.44$.
2. **$\mu$ is not asymptotically constant; it is linear in $n$.**  The monotonicity #257 inherited is not a delicate property of a converging sequence but the leading behaviour of a linear one, which is why every pass since #247 found it and none could explain it.
3. **Both criteria are cleared at $n = 256$ by $36\times$ and $34\times$**, in the model, at every key and every $\mathrm{tz}$ class sampled.

**Not settled, and neither part is small.**

1. **The model is an estimator.**  It is annealed — a first-moment count of cheap cycles — and a first moment bounds nothing on its own, since it can be carried by rare graphs.  It is validated against exact $\mu$ only at $n \le 13$, where it runs $3$ to $15$% *below* the truth and converging upward.  Nothing here promotes it to a bound.  *(§11.40: past $n = 13$ the convergence did not hold — the model crosses the exact value and runs about $7$% **above** it, so it is an estimator of unknown sign.)*
2. **The linear hull.**  Unchanged from §11.36.9: a trail statement is not a hull statement, and no method in this line of work reaches the hull.

The cheapest thing that would upgrade the first item is now stated precisely, and is the whole of what #257 has left.  The annealed count over-counts cycles sharing edges, so the gap between the model and $\mu$ is a **second-moment** question about the same two inputs — the edge-weight distribution and the out-degree — and both are exactly computable here at any width.  It needs no new machinery, only the pair correlation.

**No rating moves, and none could.**  Every row this touches is demo-only for reasons on other axes (#243, #244, #248), and the three production-track rows left the scope of a trail bound entirely in §11.36.8.

---

## 11.39 The pair correlation: #257's second moment, evaluated

**Reproduced by `SecurityProofsCode/pair_correlation_second_moment.py`, which exits non-zero if any finding here stops holding.**

§11.38.7 closed TODO #257 with two outstanding items and named the cheaper one precisely: the annealed count over-counts cycles that share edges, so the gap between the model and $\mu$ is a *second-moment* question about the same two inputs, and "needs no new machinery, only the pair correlation." That is correct, and this section walks it. The conclusion is that the correction is not merely small at $n = 256$ but **exponentially small in $n$**, and that it is $O(1)$ over exactly the range where exact $\mu$ is computable — which is a quantitative account of §11.38's own validation gap.

### 11.39.1 The entire correlation is one ratio

$E[N]$ counts closed walks whose mean weight falls below a threshold, and bounds the tail by Chernoff: for $L$ **independent** edges, $E[2^{-t \Sigma}] = M(t)^L$. Two walks sharing $j$ edges break that independence in exactly one place. A shared edge's weight appears in *both* walks, so its factor enters the joint expectation as $M(2t)$ where independence would give $M(t)^2$. Hence

$$\frac{E[N^2]}{E[N]^2} = E_{\text{pairs}}\left[R(t)^{ j}\right], \qquad R(t) = \frac{M(2t)}{M(t)^2} \ge 1,$$

with $R \ge 1$ by Cauchy–Schwarz and equality iff the edge weight is almost surely constant. **Nothing else about the weight distribution enters the pair correlation.** Since $M(t) = A_t / (E \cdot 2^{st})$ with $A_t$ the linear DP of §11.38.2 and $s$ the scale, $R$ is one higher rung of the ladder that was already built:

$$\log_2 R(t) = \log_2 A_{2t} + \log_2 E - 2\log_2 A_t .$$

The optimum sits at $t^{*} = 3$ on the differential axis and $t^{*} = 4$ to $6$ on the linear one, so the rungs required are $A_6$ and $A_8$ through $A_{12}$ — all inside the $T_D = 8$ and $T_L = 12$ that §11.38 already computes. #257's estimate of the cost was right.

**Validation.** The edge count, each moment, and their combination into $R$ are checked against a brute-force enumeration of the whole edge set at $n = 6, 7, 8, 9$ for four addends each: the edge count matches exactly and every ratio to $2.5 \times 10^{-15}$.

### 11.39.2 The ratio that matters is $R/E$, and it is linear in $n$

$R$ alone is enormous and grows with width — $2^{234}$ at $n = 256$ — which invites the conclusion that pair correlation dominates. It does not, because the number of *opportunities* to share an edge grows faster. For two walks of length $L$ in a graph with $E$ edges the expected overlap is $O(L^2/E)$, so the correction is governed by $L^2 R / E$, and the measured behaviour of the ratio is

$$\log_2\big(R/E\big) \approx -0.653 n \quad \text{(differential)}, \qquad -0.917 n \quad \text{(linear)},$$

over $n = 10$ to $256$ on both axes. $L$ enters only as $2\log_2 L$, so **any polynomial cycle length is swamped by a linear-in-$n$ exponent.** Taking $L = 0.86n$, the pessimistic end of the dense-cycle range §11.37.4 measured:

| $n$ | 12 | 16 | 32 | 64 | 128 | 256 |
|---|---|---|---|---|---|---|
| $\log_2(L^2R/E)$, differential | $-0.62$ | $-1.85$ | $-7.96$ | $-30.5$ | $-68.4$ | $-151.2$ |
| $\log_2(L^2R/E)$, linear | $-4.15$ | $-6.84$ | $-19.6$ | $-46.8$ | $-103.8$ | $-219.1$ |

(worst case over the sampled odd addends at each width; the script prints the same table)

so at $n = 256$

$$\frac{E[N^2]}{E[N]^2} = 1 + 2^{-151} \text{ (differential)}, \qquad 1 + 2^{-219} \text{ (linear)}.$$

Within the annealed ensemble the first moment is **not** carried by rare graphs, which is the objection §11.38.7's item 1 raised against it.

**$L$ is the one input taken from elsewhere, and it is the one that cannot matter.** Even the absurd choice $L = n^2$ shifts the curve by a constant and delays the crossover to $n \approx 40$; it does not change the sign of the slope, because $\log_2(R/E)$ is linear in $n$ while $2\log_2 L$ is logarithmic.

### 11.39.3 It explains the validation gap it was asked about

§11.38 reported the model running $3$ to $15$% *below* exact $\mu$ at $n \le 13$ "and converging upward", and gave no account of why. This is the account, and it is not a coincidence of the range:

- The correction crosses $1$ at $n \approx 11$ to $12$ and is $O(1)$ across $n = 10$ to $13$ — **exactly the widths where exact $\mu$ exists**, and nowhere above them.
- Its **sign** matches. An over-count inflates $E[N]$, which moves the crossing of $E[N] = 1$ to a cheaper threshold, so the model *under-states* $\mu$ — and the model runs low.

So the discrepancy visible in the validation range is a property of that range rather than of the model, and the "converging upward" that §11.38 could only observe is the over-count dying at $2^{-0.65n}$.

> **Withdrawn as an account (§11.40).** The arithmetic above stands; the conclusion drawn from it does not. Exact $\mu$ computed past $n = 13$ shows the gap crossing zero between $n = 11$ and $n = 13$ and opening the other way: the model over-states $\mu$ for every sampled key at $n = 14$, $16$ and $17$. An over-count that dies cannot produce that.

### 11.39.4 What this settles, and what it does not

**Settled — §11.38.7's item 1 as posed.** The edge-sharing over-count is quantified exactly, at any width, on both axes, from the existing ladder; it is negligible wherever the answer is not already exact; and it accounts for the validation gap in both magnitude and sign.

**Not settled.**

1. **This is not a bound on the deterministic object.** Concentration of an annealed ensemble says that ensemble's typical member is representative. It does not say that one fixed round function is a typical member of it. Closing that is a *quenched* argument and none is attempted here, so the status of §11.38's $n = 256$ figures is unchanged: an exactly-evaluated **estimator**, now with its internal consistency established rather than assumed.  *(§11.40 then compared it with the exact answer past $n = 13$, and the estimator's error turns out not to be conservative.)*
2. **The linear hull.** Untouched, and out of reach of this line of work — unchanged from §11.36.9 and §11.38.7.

**No rating moves, and none could**, for the reasons §11.38.7 gives: every row this analysis touches is demo-only on other axes (#243, #244, #248), and the production-track rows left the scope of a trail bound in §11.36.8.

---

## 11.40 The quenched check: exact $\mu$ past $n = 13$, and the model crosses it (TODO #257)

**Reproduced by `SecurityProofsCode/quenched_exact_ladder.py`, which exits non-zero if any finding here stops holding.**

§11.39.4 left #257 owing a *quenched* statement: the annealed ensemble concentrates, but nothing said that one fixed round function is a typical member of it. A proof of that is not attempted here either. What is attempted is the cheaper thing that had never been done: compare the model with the exact answer over more widths than the five where both had been computed. §11.39.3 had made a prediction that this comparison can test. It said the model's error was an edge-sharing over-count, $O(1)$ on $n = 10$ to $13$ and dying as $2^{-0.65n}$ above, so the model should converge to the exact $\mu$ from the safe side.

**It does not.** The error changes sign between $n = 11$ and $n = 13$. At every width computed above that, the model over-states the exact minimum mean cycle of the fixed round.

### 11.40.1 The exact graph was limited by how it was built, not by its size

`diff_cycle_mean.py` built each difference graph from an exhaustive DDT of $x \mapsto x + \delta$, which is $2^{2n}$ work and stops at $n = 11$. The graph itself is much smaller than that, because the out-degree is small — about 30 to 150 at these widths. §11.38.1's carry-pair automaton gives the out-edges of one node directly: they are the class sequences with a nonzero path count, enumerated by depth-first search. That costs (out-degree $\times$ $n$) per node. Exact $\mu$ then follows from Howard's algorithm on compact arrays, in about 30 s per key at $n = 16$ and a few minutes at $n = 17$. ($n = 12$ and $n = 15$ are skipped, since $M$ is singular there.)

The automaton-built graph is checked edge for edge and weight for weight against the DDT-built one at $n = 8, 10, 11$. The compact Howard is checked against `diff_cycle_mean.py`'s own Howard at $n = 11$ and $13$, to $10^{-9}$.

### 11.40.2 Exact against annealed, same key, both axes

Each row uses a fixed key stream (seeded, so the table reproduces) with the deployed key screen applied. The ratio is exact $\mu$ divided by the lower end of the annealed bracket of §11.38.3, which closes to $10^{-12}$ on this axis.

| $n$ | keys | median exact $\mu$ | $\mu/n$ | median ratio | min ratio | max ratio | keys with ratio $< 1$ |
|---|---|---|---|---|---|---|---|
| 7 | 12 | $1.279$ | $0.183$ | $1.177$ | $1.087$ | $1.239$ | $0$% |
| 8 | 12 | $1.361$ | $0.170$ | $1.097$ | $0.626$ | $1.190$ | $25$% |
| 10 | 12 | $1.701$ | $0.170$ | $1.067$ | $0.692$ | $1.113$ | $17$% |
| 11 | 12 | $1.860$ | $0.169$ | $1.043$ | $0.968$ | $1.095$ | $8$% |
| 13 | 12 | $1.858$ | $0.143$ | $0.983$ | $0.753$ | $1.023$ | $83$% |
| 14 | 12 | $2.201$ | $0.157$ | $0.936$ | $0.750$ | $0.999$ | $100$% |
| 16 | 12 | $2.280$ | $0.143$ | $0.927$ | $0.804$ | $0.970$ | $100$% |
| 17 | 6 | $2.605$ | $0.153$ | $0.923$ | $0.804$ | $0.951$ | $100$% |

The median ratio falls at every step from $n = 7$ to $n = 14$, from $1.18$ to $0.94$. After that the fall slows: $0.93$ at $n = 16$ and at $n = 17$. *(§11.41: it does not slow. With eight keys $n = 17$ is at $0.90$, and the certified solver takes the ladder on to $0.81$ at $n = 19$ and $0.75$ at $n = 20$. The linear axis crosses too, between $n = 13$ and $14$.)* Every sampled key is below $1$ from $n = 14$ on. The linear axis can be checked only to $n = 11$ here, because exact linear $\mu$ needs a LAT row per mask. Its ratio falls the same way, from $1.23$ at $n = 7$ to $1.08$ at $n = 11$. It is still above $1$ at the median, with one key in eight already below.

### 11.40.3 Which keys the model over-states

The keys with the lowest ratios are the ones whose additive constant has long runs of equal bits and many trailing zeros. Pooled over $n \ge 10$, the lowest-ratio quarter has a mean longest run of $4.5$ and a mean $\mathrm{tz}(\delta)$ of $2.4$. The highest-ratio quarter has $3.4$ and $0.9$.

A run of ones below bit $i$ pushes $\Pr[c_i = 1] = (\delta \bmod 2^i)/2^i$ toward $1$, and a run of zeros pushes it toward $0$. Either way, the carry into the top of a run is nearly deterministic, so a difference sitting there passes the addition for about $2^{-\text{run}}$ bits rather than one. A cheap *cycle* is then a set of differences that keeps returning to the same runs. Where those runs are is a property of one fixed constant. An annealed ensemble with independent edges reproduces the weight distribution but not where the cheap edges sit relative to each other, so it cannot see such a cycle.

This is the quenched effect itself, observed. It is a correlation over a few dozen keys, offered as the measured lead and not as a derivation.

The same structure is visible at $n = 256$ directly, where no exact $\mu$ exists. Take six fixed deployed keys, and for each find the cheapest two-round trail whose input difference is one bit and which passes each addition unchanged ($\beta = \alpha$). Computed exactly from the automaton, every one weighs under half a bit: $0.028$ to $0.46$. The cheapest belongs to the key with the longest run, $11$ equal bits. That says nothing about $\mu$, which is a cycle statement — a cheap transient is §11.35's old news. What it shows is where the cheap edges sit at the deployed width: on the runs of one fixed constant.

### 11.40.4 What this changes

**Withdrawn: §11.39.3's account of the validation gap.** The over-count arithmetic of §11.39.1 and §11.39.2 stands. The conclusion drawn from it, that the gap closes from the safe side, does not: the gap crosses zero and opens the other way, which an over-count that dies cannot produce.

**Downgraded: §11.38's $n = 256$ figures** ($48.44$ differential, $22.40$ linear). They were presented as an exactly evaluated estimator whose finite-size error had been observed to be conservative. It is not conservative: above $n = 11$ the error is about $7$% at the median on the unsafe side, and where it settles is not measured. An estimator whose bias has changed sign and whose limit is unknown cannot be extrapolated across 240 widths with a sign attached. So the $36\times$ margin is no longer supported by anything measured. It is not *lost* either: losing the $4/3$ criterion would need the ratio to fall to about $1/36$, against $0.93$ at the widest width computed. What is lost is the claim that the margin is measured. *(§11.41 withdraws the model as the basis for these figures. The ratio keeps falling, so no constant-factor correction is available. The exact $\mu/n$ is flat over eight widths and gives about $27\times$ instead, as a reading and not a bound.)*

**Unchanged: every exact number.** Per-width medians clear $4/3$ from $n = 8$ on, through $n = 17$. Every width also has keys below it, as §11.37.1 recorded for narrower widths. The median is not monotone at this sample size, since $n = 13$ does not clear $n = 11$. $\mu/n$ stays between $0.14$ and $0.16$ from $n = 13$ on, which is consistent with linear growth. But the slope that would carry it to $n = 256$ is exactly what the model no longer supplies.

**Still owed.** A quenched argument, now with a measured reason why the annealed one cannot stand in for it and a measured lead (§11.40.3) on what such an argument would have to control: the run structure of $\delta$. The linear hull remains owed too.

**No rating moves, and none could**, for the reasons §11.38.7 gives.

## 11.41 Exact $\mu$ to n = 20 on both axes: the ratio does not settle, the exact slope does (TODO #257)

**Reproduced by `SecurityProofsCode/certified_cycle_ladder.py`, which exits non-zero if any finding here stops holding.**

§11.40 left two limits, and both were limits of construction. The linear axis stopped at n = 11, because exact linear $\mu$ built every LAT row, which is $(n+1)4^n$ work. The differential axis stopped at n = 17, because the automaton builder enumerated *every* out-edge, and one n = 19 key passed 4.6 GB without finishing. So whether the falling ratio settles was not measured on either axis.

### 11.41.1 A certificate makes a pruned graph exact

A minimum mean cycle is decided by cheap edges. So keep, out of each node $u$, only the edges of weight at most $W_u$, giving a subgraph $G'$ in which every node keeps at least one edge. Its minimum mean cycle $\mu'$ satisfies $\mu' \ge \mu(G)$. Let $p$ be the shortest-path potential of the reduced weights $w - \mu'$ from a zero-weight virtual source. It is well defined because $G'$ has no negative cycle, and it satisfies $p \le 0$ and $p(v) \le p(u) + w(u,v) - \mu'$ on $G'$. An omitted edge has $w(u,v) > W_u$. So if $W_u \ge \mu' - p(u)$ at every node, then $p(u) + w - \mu' > 0 \ge p(v)$, which makes $p$ feasible on all of $G$. Every cycle of $G$ then has mean at least $\mu'$, so $\mu(G) = \mu'$.

Where a node fails the test, its threshold is raised to $\mu' - p(u)$ and the subgraph is solved again. The loop ends only when every node passes, so a returned value is exact rather than an estimate.

The pruning inside a row is sound because a partial edge's weight only grows as bits are added. On the linear axis, the correlation of $x \mapsto x + \delta$ is a product of $2 \times 2$ carry matrices whose columns have $\ell_1$ norm at most 1, so the $\ell_1$ norm of the partial vector bounds $|C|$. On the differential axis, the carry-pair automaton has two choices of $x$ per bit, so the partial path count at most doubles per remaining bit. A row then costs (edges kept) $\times$ $n$ rather than $2^n$. The pruned graph keeps about 3 to 25 edges per node, against roughly $2^n/3$ in the full linear graph. Exact $\mu$ costs about two minutes per key per axis at n = 17 and under an hour at n = 20.

The solver returns the full-graph value to $10^{-9}$ on both axes at n = 7, 8, 10, 11, and on the differential axis at n = 13, 14. A negative control shows the raising loop is what makes it exact. Without the loop, at a fixed $W = 1$ bit, 13 of 18 keys get a $\mu$ that is too large, and the certificate test flags all 13.

### 11.41.2 The ladders

Same fixed key stream as §11.40.2, so the rows to n = 16 reproduce that table. n = 17 now has eight keys rather than six. The rows for n = 19 and 20 run under `--full` only. The ratio is exact $\mu$ over the lower end of the annealed bracket; "ann$/n$" is that lower end's median over $n$.

**Differential:**

| $n$ | keys | median exact $\mu$ | exact $\mu/n$ | ann$/n$ | median ratio | min ratio | max ratio | min exact $\mu$ | ratio $< 1$ |
|---|---|---|---|---|---|---|---|---|---|
| 13 | 12 | 1.858 | 0.143 | 0.144 | 0.983 | 0.753 | 1.023 | 0.833 | 83% |
| 14 | 12 | 2.201 | 0.157 | 0.163 | 0.936 | 0.750 | 0.999 | 0.977 | 100% |
| 16 | 12 | 2.280 | 0.143 | 0.154 | 0.927 | 0.804 | 0.970 | 1.193 | 100% |
| 17 | 8 | 2.790 | 0.164 | 0.182 | 0.901 | 0.804 | 0.951 | 2.057 | 100% |
| 19 | 6 | 2.707 | 0.142 | 0.177 | 0.809 | 0.773 | 0.869 | 2.201 | 100% |
| 20 | 4 | 2.933 | 0.147 | 0.205 | 0.749 | 0.691 | 0.756 | 2.857 | 100% |

**Linear:**

| $n$ | keys | median exact $\mu$ | exact $\mu/n$ | ann$/n$ | median ratio | min ratio | max ratio | min exact $\mu$ | ratio $< 1$ |
|---|---|---|---|---|---|---|---|---|---|
| 11 | 12 | 0.860 | 0.078 | 0.072 | 1.082 | 0.932 | 1.172 | 0.514 | 17% |
| 13 | 12 | 0.898 | 0.069 | 0.066 | 1.020 | 0.857 | 1.064 | 0.422 | 25% |
| 14 | 12 | 0.986 | 0.070 | 0.075 | 0.984 | 0.834 | 1.073 | 0.497 | 75% |
| 16 | 12 | 1.108 | 0.069 | 0.071 | 0.975 | 0.879 | 1.055 | 0.598 | 83% |
| 17 | 8 | 1.316 | 0.077 | 0.084 | 0.929 | 0.865 | 1.015 | 1.009 | 75% |
| 19 | 6 | 1.347 | 0.071 | 0.082 | 0.873 | 0.854 | 0.941 | 1.108 | 100% |
| 20 | 4 | 1.557 | 0.078 | 0.095 | 0.823 | 0.814 | 0.835 | 1.412 | 100% |

### 11.41.3 What the ladders say

**The ratio does not settle.** §11.40.2 read the differential median as slowing near 0.93. With eight keys it is 0.90 at n = 17, then 0.81 at n = 19 and 0.75 at n = 20. The linear axis crosses between n = 13 and 14 and falls the same way, at about half the rate. The samples at n = 19 and 20 are small, six and four keys. But every key there is below 1 on both axes, and the trend agrees with the eight-key row at n = 17.

**The exact slope does settle.** Exact median $\mu/n$ stays between 0.14 and 0.16 on the differential axis from n = 13 to 20, and between 0.07 and 0.08 on the linear axis. Over the same widths the model's median $\lambda^*/n$ climbs from 0.14 to about 0.2 and from 0.07 to about 0.09. So the exact minimum mean cycle is still growing linearly in $n$. What the model gets wrong is the slope. *(§11.42: partly a sampling artefact. The n = 20 sample here was run-heavy, and at a typical run count the differential median steps down to about 0.13.)*

**The model's error is largest where it predicts most.** Within one width, the least-squares slope of exact $\mu$ on $\lambda^*$ across keys is about 1 at n = 13, and 0.61 (differential) and 0.68 (linear) at n = 17. The keys the model rates strongest are the ones it over-states most. That is consistent with §11.40.3: the run structure of one fixed constant caps the exact value, and the independent-edge ensemble does not see the cap.

### 11.41.4 What this changes

**Withdrawn: §11.38 as the basis for the n = 256 figures.** §11.40 left them as an estimator of unknown sign whose error might at least be a constant factor. It is not a constant factor: the ratio falls at every width measured, by 0.25 on the differential axis by n = 20. So 48.44 and 22.40, and the $36\times$ and $34\times$ margins, have no measured support, and no correction of them is available.

**Replacing it, as a reading:** the exact slope. A median $\mu/n$ that has stayed at 0.14 to 0.16 over eight widths puts n = 256 near $0.14 \times 256 \approx 36$ differential. On the linear axis, $0.07 \times 256 \approx 18$. Both are about $27\times$ the $4/3$ and $2/3$ criteria. This is a reading of eight widths and not a bound, the same status §11.38's figures had. The difference is that it extrapolates the exact object rather than a model now measured to drift away from it. *(§11.42 withdraws this reading. With 32–96 keys per width, and adjusted for the run count of $\delta$, the differential per-bit median is about 0.13 at n = 19–23, not 0.145. Forms that fit n = 13–23 read anywhere from about 10 to 26 times the criteria at n = 256.)*

**Unchanged: every exact number.** The medians clear both criteria at every width from n = 10 on. From n = 17 on, every sampled key clears both.

**Still owed.** A quenched argument for n = 256. Its target has moved: it is the exact slope, flat for eight widths, rather than the model's error, which is not converging. The linear hull is owed too.

**No rating moves, and none could**, for the reasons §11.38.7 gives.

## 11.42 The exact slope, with enough keys: not flat, still growing (TODO #257)

**Reproduced by `SecurityProofsCode/exact_slope_ladder.py`, which exits non-zero if any finding here stops holding.**

§11.41 replaced §11.38's model figures with a reading of the exact slope: median $\mu/n$ looked flat at 0.14–0.16 (differential) and 0.07–0.08 (linear) from n = 13 to 20, which put n = 256 near 36 and 18. That reading rested on 12 keys per width at n ≤ 16, 8 at n = 17, 6 at n = 19 and 4 at n = 20. That is too few to call a distribution flat. The Python solver was why it was so few.

### 11.42.1 The same solver, faster

`certified_cycle_mean.c` is §11.41.1's certified solver transcribed to C. It takes the automaton tables from the Python sources on its input, so the two cannot disagree about what an edge is. On n = 7, 8, 10, 11, 13 and 14, three keys each, both axes, it returns the same $\mu$ (to $10^{-12}$), the same number of edges kept and the same number of certificate rounds. It is about 40 times faster and compacts its edge pool in place. An n = 20 key takes about two minutes and an n = 22 key about half an hour, at up to 5 GB.

### 11.42.2 The ladder

Fixed key stream as before, so earlier tables' keys are a prefix of these. "Run-adjusted" moves each key to a typical run count of $\delta$ (n/2 runs) along the pooled within-width slope of exact $\mu$ on the run count: 0.132 per run differential, 0.075 linear. "Slope on $\lambda^*$" is the least-squares slope of exact $\mu$ on the model's value across one width's keys.

**Differential:**

| n | keys | median exact μ/n | runs/n | run-adjusted μ/n | run-adjusted μ | model λ*/n | median ratio | IQR/median | slope on λ* |
|---|---|---|---|---|---|---|---|---|---|
| 13 | 32 | 0.1476 | 0.54 | 0.1507 | 1.959 | 0.1580 | 0.958 | 0.303 | 1.00 |
| 14 | 32 | 0.1559 | 0.50 | 0.1528 | 2.140 | 0.1645 | 0.940 | 0.291 | 0.90 |
| 16 | 32 | 0.1448 | 0.50 | 0.1413 | 2.261 | 0.1622 | 0.882 | 0.274 | 0.80 |
| 17 | 96 | 0.1486 | 0.53 | 0.1424 | 2.420 | 0.1692 | 0.873 | 0.206 | 0.67 |
| 19 | 48 | 0.1394 | 0.53 | 0.1316 | 2.500 | 0.1665 | 0.807 | 0.172 | 0.60 |
| 20 | 16 | 0.1448 | 0.60 | 0.1295 | 2.590 | 0.1953 | 0.740 | 0.026 | 0.32 |
| 22 | 8 | 0.1274 | 0.55 | 0.1228 | 2.703 | 0.1658 | 0.757 | 0.023 | 0.23 |
| 23 | 3 | 0.1310 | 0.52 | 0.1281 | 2.947 | 0.1963 | 0.667 | 0.046 | 0.13 |

**Linear:**

| n | keys | median exact μ/n | runs/n | run-adjusted μ/n | run-adjusted μ | model λ*/n | median ratio | IQR/median | slope on λ* |
|---|---|---|---|---|---|---|---|---|---|
| 13 | 32 | 0.0712 | 0.54 | 0.0727 | 0.946 | 0.0726 | 1.020 | 0.278 | 1.02 |
| 14 | 32 | 0.0735 | 0.50 | 0.0735 | 1.029 | 0.0755 | 0.998 | 0.303 | 0.97 |
| 16 | 32 | 0.0705 | 0.50 | 0.0685 | 1.097 | 0.0745 | 0.951 | 0.302 | 0.86 |
| 17 | 96 | 0.0722 | 0.53 | 0.0702 | 1.193 | 0.0775 | 0.928 | 0.259 | 0.83 |
| 19 | 48 | 0.0692 | 0.53 | 0.0660 | 1.253 | 0.0766 | 0.873 | 0.194 | 0.81 |
| 20 | 16 | 0.0749 | 0.60 | 0.0657 | 1.314 | 0.0900 | 0.825 | 0.083 | 0.60 |
| 22 | 8 | 0.0644 | 0.55 | 0.0644 | 1.417 | 0.0760 | 0.840 | 0.066 | 0.43 |
| 23 | 3 | 0.0724 | 0.52 | 0.0708 | 1.629 | 0.0899 | 0.805 | 0.142 | 0.50 |

### 11.42.3 What the ladder says

The rows at n = 17 and 19 carry 96 and 48 keys (the gate's default runs 32 and 24); n = 22 and 23 run under `--full` only.

**The slope is not flat at the level §11.41 read.** Exact $\mu$ rises with the number of runs in $\delta$, and the n = 20 sample in §11.41 happened to carry 0.60 n runs against about 0.5 n elsewhere, which raised its median. Moved to a typical run count, the differential per-bit median is about 0.15 at n = 13–14 and about 0.13 at n = 19–23: 0.132, 0.130, 0.123, 0.128. Keys already within one run of n/2 show the same step with no regression involved. Whether the median keeps falling or has levelled is not resolved. The linear median moves within 0.064–0.074 with no decline established beyond the scatter; it is 0.071 at n = 23, on three keys.

**Exact $\mu$ still grows.** Run-adjusted, the median rises at every width step on both axes: 1.96 to 2.95 differential and 0.95 to 1.63 linear, over n = 13 to 23. At n = 23 it is 2.2 and 2.4 times the criteria.

**The model's error is a scale error.** Within one width the model ranks keys almost exactly; the correlation of $\lambda^*$ with exact $\mu$ is 0.98 at n = 13. But at n ≥ 17 it credits each run of $\delta$ with about 0.21 on the differential axis where exact $\mu$ gains about 0.12, and about 0.095 against 0.074 on the linear axis. So the keys it rates strongest are the ones it over-states most. The slope of exact $\mu$ on $\lambda^*$ across keys falls from 1.0 at n = 13 to 0.1–0.6 at n = 20–23.

**The keys agree more as n grows.** The interquartile range of exact $\mu/n$, over its median, falls from about 0.3 at n = 13 to 0.02–0.05 differential and 0.07–0.14 linear at n = 20–23.

### 11.42.4 What this changes

**Withdrawn: §11.41.4's reading of the exact slope as flat at 0.14–0.16**, and its n = 256 figures of about 36 and 18, about $27\times$ both criteria. At a typical run count the differential per-bit median is about 0.13 from n = 19 to 23, and it got there by falling from about 0.15.

**Not fixed by the data: any single n = 256 figure.** Forms that fit n = 13 to 23 differ by a factor of 2.5 at n = 256. A power law ($\mu \sim n^{0.63}$ differential, $n^{0.84}$ linear) reads about 13 and 11, roughly 10 and 17 times the criteria. A per-bit median that has levelled at its last four widths (0.128 and 0.067) reads about 33 and 17, roughly 25 times. Both are readings and not bounds, and the data do not choose between them.

**What is measured: §11.37's monotonicity residue**, now with ten widths behind it. The run-adjusted median exact $\mu$ grows at every step from n = 13 to 23 on both axes, and is more than twice both criteria at n = 23. So the criterion holds at n = 256 if exact $\mu$ is non-decreasing in n. That, and not a slope, is what an argument has to show. There is still no embedding between widths (§11.37), so it cannot be shown by comparing two graphs.

**Still owed.** That quenched argument, and the linear hull.

**No rating moves, and none could**, for the reasons §11.38.7 gives.

---

> **Continued in Part 10 — §11.43–§11.46** (SecurityProofs-10.md): The Local Certificate · The Local Certificate at n = 256 · The Linear Hull, Measured · Where the Cycles Pay
