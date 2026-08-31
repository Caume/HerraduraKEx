# Formal Cryptographic Analysis of the Herradura Cryptographic Suite — Part 9

**Status:** See Part 1 (SecurityProofs-1.md) for full status header.

> **This is Part 9 of a split document.**
>
> - **Part 1 — §1** (SecurityProofs-1.md): Algebraic Foundations
> - **Part 2 — §2–§8** (SecurityProofs-2.md): Protocol Analysis · Security Analysis · Summary Tables · Quantum Attack Analysis · Experimental Code Index
> - **Part 3 — §9–§10** (SecurityProofs-3.md): Non-Linear Proposals · v1.4.0 Migration
> - **Part 4 — §11–§11.8.2** (SecurityProofs-4.md): Non-linearity and Post-quantum Extensions · NL-FSCX v1/v2 · HKEX-RNL
> - **Part 5 — §11.8.3–§11.8.8** (SecurityProofs-5.md): PQ Signature Options · HPKE-Stern-KEM
> - **Part 6 — §11.9** (SecurityProofs-6.md): HFSCX-256-DM
> - **Part 7 — §11.10–§11.13, §11.15–§11.33** (SecurityProofs-7.md): Zero-Knowledge Proof Extensions · Research-Review Sections
> - **Part 8 — §11.34–§11.36** (SecurityProofs-8.md): NL-FSCX v3 — Exact Row Analysis · Asymptotic Trail Slopes
> - **Part 9 — §11.37–§11.38** (this file): The Width Residue · The Annealed Threshold at n = 256

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

1. **The model is an estimator.**  It is annealed — a first-moment count of cheap cycles — and a first moment bounds nothing on its own, since it can be carried by rare graphs.  It is validated against exact $\mu$ only at $n \le 13$, where it runs $3$ to $15$% *below* the truth and converging upward.  Nothing here promotes it to a bound.
2. **The linear hull.**  Unchanged from §11.36.9: a trail statement is not a hull statement, and no method in this line of work reaches the hull.

The cheapest thing that would upgrade the first item is now stated precisely, and is the whole of what #257 has left.  The annealed count over-counts cycles sharing edges, so the gap between the model and $\mu$ is a **second-moment** question about the same two inputs — the edge-weight distribution and the out-degree — and both are exactly computable here at any width.  It needs no new machinery, only the pair correlation.

**No rating moves, and none could.**  Every row this touches is demo-only for reasons on other axes (#243, #244, #248), and the three production-track rows left the scope of a trail bound entirely in §11.36.8.
