# Formal Cryptographic Analysis of the Herradura Cryptographic Suite — Part 8

**Status:** See Part 1 (SecurityProofs-1.md) for full status header.

> **This is Part 8 of a split document.**
>
> - **Part 1 — §1** (SecurityProofs-1.md): Algebraic Foundations
> - **Part 2 — §2–§8** (SecurityProofs-2.md): Protocol Analysis · Security Analysis · Summary Tables · Quantum Attack Analysis · Experimental Code Index
> - **Part 3 — §9–§10** (SecurityProofs-3.md): Non-Linear Proposals · v1.4.0 Migration
> - **Part 4 — §11–§11.8.2** (SecurityProofs-4.md): Non-linearity and Post-quantum Extensions · NL-FSCX v1/v2 · HKEX-RNL
> - **Part 5 — §11.8.3–§11.8.8** (SecurityProofs-5.md): PQ Signature Options · HPKE-Stern-KEM
> - **Part 6 — §11.9** (SecurityProofs-6.md): HFSCX-256-DM
> - **Part 7 — §11.10–§11.13, §11.15–§11.33** (SecurityProofs-7.md): Zero-Knowledge Proof Extensions · Research-Review Sections
> - **Part 8 — §11.34–§11.37** (this file): NL-FSCX v3 — Exact Row Analysis · Asymptotic Trail Slopes · The Width Residue

---

## 11.34 NL-FSCX v3: exact row analysis, weak keys, and a correction to §11.33 (TODO #255)

§11.33 derived NL-FSCX v3's round count, $R_3 = 5n/8 = 160$, from a *layer-wise* trail floor charged to $\chi$ alone, and stated plainly that the floor bounds a trail rather than the round's own DDT entry — within-round clustering can beat it.  This section closes that caveat with a number, and in doing so answers the question TODO #255 could not begin implementation without: **does v3 need a key check?**

It does not.  The reasoning is unusually clean for this family, because v3 admits a reduction that v2 never did.

Reproduce with `python3 SecurityProofsCode/nl_fscx_v3_weak_keys.py`; it exits non-zero if any finding below stops reproducing.

### 11.34.1 The reduction: a 256-bit question that is a $2^5$ computation

The v3 round is

$$x \longmapsto \chi\bigl( M(x \oplus i \oplus B) + \delta(B) \bmod 2^n \bigr).$$

Two structural facts collapse it.

**(a) The key enters only as $\delta(B)$.** $M$ is invertible and $y \mapsto y + \delta$ is a bijection, so substituting $y = M(x \oplus i \oplus B)$ is measure-preserving.  Every differential and linear property of the round is therefore a property of

$$g_\delta(y) = \chi(y + \delta)$$

alone: $B$, the round index $i$ and $M$ all drop out.

**(b) $\chi$ is row-local, and so is carry propagation.** The low $L$ bits of $y + \delta$ depend only on the low $L$ bits of $y$ and $\delta$ plus a one-bit carry-in.  So the profile of the row at offset $o$ is an exhaustive computation over $2^L$ inputs, $2^L$ row-deltas and two carries — **independent of $n$**.

Together, an exhaustive statement about every one of the $2^{256}$ keys is a sweep over $L = 5$ and $L = 7$.  This is the lever the v2 analysis never had: v2's round has no row structure, which is exactly why TODO #253 had to extrapolate from $n \le 11$ and why its factor-of-two gap could only be measured, never closed.

Carry bookkeeping is charged conservatively throughout.  For a linear mask the carry-in $c$ is a function of $y$, so $|\mathrm{corr}| \le \max_c |\mathrm{corr}(c)|$; for a differential the pair's two carry-ins may differ, so $p \le \max_{c,c'} p(c,c')$.  Both bound the true quantity in the safe direction — weight can only be *higher* than reported — so every floor below is sound.

### 11.34.2 The linear axis, exhaustively

Maximum single-row correlation over all row-deltas, both carry-ins and all nonzero output masks:

| $L$ | $\max\|\mathrm{corr}\|$ | weight | correlation-1 cases | status |
|---|---|---|---|---|
| 3 | $1.000000$ | $0$ | 8 | **degenerate** |
| 5 | $0.875000$ | $0.1926$ | 0 | ok |
| 7 | $0.718750$ | $0.4764$ | 0 | ok |

$L = 3$ is §11.33.4's break, and the reduction now supplies its mechanism: bit 0 of a sum has no carry-in, so the low bit entering $\chi$ is affine in $y$, and a 3-bit row has no room to destroy the resulting correlation.  It is a property of the **row length**, not of the key — which is why the fix is the minimum-row-5 constraint and not a key check.

$L = 5$ and $L = 7$ admit none.  Note that $-\log_2 0.875 = 0.1926$ is exactly the "worst single round $0.193$" §11.33.4 reported from 150 sampled keys.  **That figure was never a weak-key artefact.** It is the universal single-row bound, and it is attained.

Sweeping past the deployed row lengths (`--long`) says something the deployed ones cannot: the weight **saturates** — $0.1926$ at $L = 5$, $0.4764$ at $L = 7$, $0.5243$ at $L = 9$ — and never approaches $\chi$'s own isolated floor of $1$.  ($L = 11$ is some $16\times$ $L = 9$'s work in pure Python and is left out of the reproducible sweep; measured once by the same code it gives $0.5282$, another $0.004$ bits.)  **It is the carry, not the row length, that caps this axis.**  The gain from 5 to 7 is real and is why the partition spends its remainder on 7-rows; past 7 there is essentially nothing left to buy, for rows that no longer divide $256$ conveniently.  "Use longer rows" is therefore not available as a future fix for the linear bound.

The full $L = 5$ distribution over the 32 row-deltas is three-valued and identical for both carry-ins:

| $\|\mathrm{corr}\|$ | weight | row-deltas |
|---|---|---|
| $0.875$ | $0.1926$ | 8 of 32 |
| $0.625$ | $0.6781$ | 8 of 32 |
| $0.500$ | $1.0000$ | 16 of 32 |

§11.33.4 also reported a sampled *median* of $0.678$, which is not the median of this distribution (that is $1.000$).  It is the median of the induced **per-key** statistic — the worst row a key actually has, i.e. the minimum weight over its rows — at the two-row width §11.33.4 measured at.  Deriving that from the exact row distribution gives $\Pr[\min = 0.1926] = 7/16$, $\Pr[\min = 0.6781] = 5/16$, $\Pr[\min = 1] = 1/4$, whose median is $0.6781$. §11.33.4's 150-key sample was measuring this three-point row distribution all along, through one width's worth of row structure.

### 11.34.3 The differential axis, and the lowest-active-row lemma

The same sweep on the differential axis, split by whether the two members of the pair share a carry-in:

| $L$ | same-carry $\max p$ | weight | differing-carry $\max p$ | weight |
|---|---|---|---|---|
| 5 | $5/16$ | $1.6781$ | $1/2$ | $1.0000$ |
| 7 | $1/4$ | $2.0000$ | $1/2$ | $1.0000$ |

Taken flat, the differing-carry column would give a floor of only $1$ bit — below §11.33.2's layer-wise $2$ — and at $s_{\mathrm{diff}} = 1$ the §11.30.1 criterion $s_{\mathrm{diff}} \cdot r \ge n$ would demand $r \ge 256$, which $R_3 = 160$ fails.  It does not apply.

> **Lemma (lowest active row).** Let $\beta = M(\alpha) \ne 0$ be the difference entering the addition, and let $j$ be the lowest row on which $\beta$ is nonzero.  Then the two inputs $y$ and $y \oplus \beta$ agree on every bit below row $j$, hence produce the **same** carry into row $j$.  The lowest active row is therefore always in the same-carry column — and at least one active row always exists, because $M$ is invertible and $\alpha \ne 0$.

So the per-round differential floor is the worst same-carry entry over the deployed row lengths.  The 5-rows are weaker than the 7-rows and are 47 of the 50, giving

$$s_{\mathrm{diff}} = -\log_2 \tfrac{5}{16} = 4 - \log_2 5 = 1.6781 \text{ bits},$$

exactly, for every key at every width.  It is also **key-independent**: all 32 (resp. 128) row-deltas give the same same-carry maximum.

### 11.34.4 The two inherited v2 weak classes both dissolve

Measured at $n = 10$ with partition $(5,5)$ — the smallest width whose partition satisfies the minimum-row-5 constraint.

**(a) The affine class $\delta(B) \in \{0, 2^{n-1}\}$ (§11.19.2).** 48 of the 1024 keys are in it.  The v2 round is affine for all 48; the v3 round is affine for none.  This is provable rather than merely measured: v3's round is $\chi$ composed with the v2 round, $\chi$ is a fixed key-independent **non-linear** bijection, and $\chi \circ (\text{affine})$ is non-affine whenever $\chi$ is.  No key can make the v3 round affine, at any width.

**(b) The zero-weight-trail class $\mathrm{tz}(\delta(B)) \ge 4$ (§11.28.3).** 127 of the 1024 keys are in it. v2 hands this class a probability-1 one-round differential — the MSB freebie. v3's worst one-round DDT entry over the same class is $5/16$, which is precisely §11.34.3's universal same-carry bound: **the class does not merely improve, it lands on the floor every key already sits on, and so is not a class at all.**

### 11.34.5 Is there a new $\chi$-specific class?

**Differential: no.** §11.34.3's same-carry maximum is identical for every row-delta, so the differential profile does not depend on the key.  A class needs a distinguished subset and there is none.

**Linear: graded, but not screenable.** 8 of 32 row-deltas reach the worst grade $|\mathrm{corr}| = 0.875$, so one row is "bad" with probability $1/4$.  The deployed partition has 47 five-rows reading essentially unrelated slices of $\delta(B)$, so

$$\Pr[\text{a key has no worst-grade row}] \approx (3/4)^{47} = 1.34 \times 10^{-6}.$$

The worst grade is attained by all but about one key in $750{,}000$.  A "weak class" containing everybody is a property of the design, not a key defect, and screening for it is not available — there is nothing to reject.  This is the exact opposite of v2's situation, where the classes were sparse (density $\approx 2^{-129}$ for the affine class) and screening cost one comparison.

The $\chi$-specific class §11.33.4 *did* find — the $\delta(B)$-odd keys — exists only for partitions containing a 3-row, and is closed by the minimum-row-5 constraint rather than by a key check.

### 11.34.6 Correction to §11.33: the round count stands, the headroom does not

§11.33.2 states the floor as a layer-wise trail bound — 2 bits differential, 1 bit linear — charged to $\chi$ alone, with the caveat that a trail *fixes* the intermediate difference while the round's own DDT entry *sums over* it. §11.34.3 closes that caveat: the round-level differential floor is $4 - \log_2 5 = 1.6781$, not $2.000$, the gap being clustering across the carry.

Evaluated on the round-level figure, §11.30.1's differential criterion needs

$$r \ge \frac{n}{s_{\mathrm{diff}}} = \frac{256}{1.6781} = 152.6,$$

so $R_3 = 160$ clears it — at $1.049\times$, not the $1.25\times$ §11.33.6 recorded against an $r \ge 128$ requirement.

> **$R_3 = 160$ is the right number, for a reason narrower than the one on record, and there is no room to reduce it.** A future item that wants to trim the round count must first widen this floor, not merely re-measure it.

The linear axis is unchanged in both findings and logic.  The round-level figure $0.1926$ would demand $r \ge 664$ if it were a slope, and §11.33.5 declined to price it that way because it is not chainable. §11.34's exact multi-round trail search — maximum over *all* mask paths, not a sample — re-confirms that at $n = 10$: the slope rises from $0.79$ at $r = 1$ to about $1.4$ bits/round by $r = 6$, comfortably above the $s_{\mathrm{lin}} \ge 2/3$ bar and roughly seven times the single-round figure.  $0.1926$ is a transient, not a slope.

### 11.34.7 Consequence for the implementation

**v3 ships with no key check.** There is deliberately no `nl_v3_key_is_valid` in any of the four language ports, and no rejection-sampling loop in any v3 key generation path:

| class | status under v3 |
|---|---|
| affine, $\delta(B) \in \{0, 2^{n-1}\}$ | dissolved, provably, at every width (§11.34.4a) |
| zero-weight, $\mathrm{tz}(\delta(B)) \ge 4$ | dissolved; no zero-weight round for any key (§11.34.3, §11.34.4b) |
| new $\chi$-specific | differential profile key-independent; linear profile graded but universal (§11.34.5) |
| $\delta(B)$-odd | real, but a property of 3-rows; closed by the minimum-row-5 constraint (§11.34.2) |

Carrying v2's check across anyway would be worse than useless: it would reject a $\approx 2^{-129}$ fraction of keys for a degeneracy v3 does not have, while implying to a reader that the remaining keys had been screened for one that it does.

**The minimum-row-5 constraint is a security assertion and is enforced in code.** All four ports derive the partition from a rule that emits only 5s and 7s, and the test harnesses assert that every row is odd and at least 5 (test [47] in C, Go and Python).

### 11.34.8 The duplex sponge round count, derived (TODO #255)

`hske-duplex3` is `hske-duplex`'s MonkeyDuplex construction with the v3 permutation in place of the v2 one. Its round count is **not** $R_3$: a sponge permutation is not a block cipher and is not held to the codebook-sized target §11.30.1 sets. It is

$$I_3 = \frac{5n}{16} = 80 \quad (n = 256),$$

and it is the first duplex round count in this suite that is derived rather than inherited.

**The target.** The state is 256 bits split rate $128$ / capacity $c = 128$. A sponge's security against the generic attacks is governed by the capacity, so the quantity to clear is $c = 128$ bits, not $n = 256$.

**The requirement.** §11.34.3 gives the v3 round an unconditional differential floor of $4 - \log_2 5 = 1.6781$ bits and §11.34.2 a linear floor of $1$ bit, both per round and both independent of the key. Applying §11.30.1's two criteria at the capacity rather than the block size:

$$r \ \ge\ \frac{c}{1.6781} = 76.3 \quad\text{(differential)}, \qquad r \ \ge\ \frac{c}{2} = 64 \quad\text{(linear)}.$$

So $r \ge 77$ binds, and $I_3 = 80$ clears it on both axes with a small margin. That $I_3 = R_3 / 2$ exactly — half the round count for a half-width target — is a consequence of both being $5n/2^k$, not an independent choice.

**Why not reuse $I = n/4 = 64$.** `hske-duplex` runs the v2 permutation at $I = 64$, a count inherited from the classical FSCX step parameter rather than derived from anything. At the v3 floor, $64$ rounds would give $64 \times 1.6781 = 107.4$ bits against a $128$-bit capacity — short, and short in the one direction that matters. v2 has no per-round floor at all, so the same arithmetic cannot even be attempted for `hske-duplex`; its $64$ is not defensible or indefensible, it is unquantified.

> **This does not lift `hske-duplex3`'s rating.** What holds the v2 duplex at *research* is that the permutation's standalone **sponge** profile — the differential/linear characterisation TODO #99 tracks — has never been produced. A per-round trail floor is a statement about the round, not that characterisation, and the gap between the two is exactly the thing a sponge's security argument needs and this family does not have. `hske-duplex3` ships at *research* for the same reason, with a floor its predecessor lacks and the same missing analysis.

**Cost.** $80$ v3 rounds against $64$ v2 rounds is $1.25\times$ the rounds on top of the per-round ratio. Measured end to end against the shipped `herradura.h` (`benchmarks/v3_consumer_cost.c`), that is $1.45\times$ per 4 KiB message, and $1.38\times$ at 64 bytes where the fixed cost of init, associated-data absorption and finalisation — about five permutation calls regardless of length — dominates.

---

## 11.35 The asymptotic differential slope, measured exactly (TODO #252)

§11.31 posed TODO #252's target correctly — the criterion is width-independent, so what is wanted is the asymptotic per-round increment `s_diff` against a bar of `4/3` — and then concluded that this quantity "is **not measurable by exhaustive search at any reachable width** — not slowly, but at all", because the cheap transient and the $0.6n$ ceiling overlap at every width an exhaustive DDT reaches.

**That conclusion is withdrawn here.**  It is a correct statement about the *method* every previous pass used, and a false one about the asymptote.  Reproduce with `python3 SecurityProofsCode/diff_cycle_mean.py`; it exits non-zero if any finding below stops reproducing.

### 11.35.1 The asymptote is a minimum mean cycle

The XOR with the key and the round constant, and the linear map $M$, are deterministic on differences; only the addition of $\delta(B)$ is probabilistic.  A trail is therefore a **walk on a finite directed graph**: nodes are the $2^n$ differences, and the edge $a \to b$ carries weight

$$w(a \to b) = -\log_2 \text{xdp}(M(a) \to b).$$

For any finite weighted digraph the minimum weight over walks of $r$ edges obeys $W(r) = c + \mu r + o(1)$, where $\mu$ is the **minimum mean cycle** — the least average edge weight over all directed cycles.  Hence

$$s_{\text{diff}} = \mu, \qquad\text{exactly, for that width and that key.}$$

Both of §11.31.2's brackets dissolve against this object rather than being defeated by it.  The **transient** is precisely the constant $c$, the cost of walking into the best cycle; it is what contaminates a slope read at small $r$, and it cancels in a mean taken over a cycle, which has no beginning.  The **ceiling** is a statement about interpreting a finite trail against a codebook of size $2^n$; a cycle is not compared to a codebook, so nothing caps it.  And $\mu$ is computable in near-linear time by Howard's policy iteration, so the widths that were out of reach for a solver are not out of reach for this.

### 11.35.2 Validation — three independent methods

Howard's algorithm is iterative, so it is checked against two methods sharing none of its machinery: **Karp's theorem**, which reads the answer off a table of exact $k$-edge distances and never forms a policy, and **value iteration** run far past the ceiling.  Seven cases at $n = 7$ and $n = 8$ agree to $10^{-9}$.

The third column carries the methodological point.  Value iteration *is* §11.31's own series.  Run to $r = 400$ its cumulative weight is far beyond $0.6n$, deep inside the region §11.31.2 called ceiling-limited — and it converges on the same $\mu$ the two exact methods return.  The series was never flattening.  What flattens is a slope read at $r = 3$–$5$, which is inside the transient: the diagnosis was right and the conclusion drawn from it was not.

One implementation note worth recording, because it is a trap.  Reading $\mu$ off the tail of a value-iteration series by averaging over a fixed window is only approximate — the series is eventually **periodic**, and a window that is not a whole number of periods leaves an $O(1/\text{window})$ error that shows up in the fourth decimal.  Detecting the period makes the read exact.  A short period must be confirmed over a long tail rather than over one repetition: at $n = 7$, $\delta = 44$ satisfies the periodicity test at $P = 3$ by coincidence and reports a $\mu$ one percent low if that is believed.

### 11.35.3 The per-key slope at every usable width

$\mu$ for every distinct additive constant $\delta(B)$ a key can produce, weighted by how many keys produce it.  Widths 7 and 8 are exhaustive over all keys; 10 and 11 are sampled over distinct constants.  $n = 9$ and $n = 12$ are absent throughout — $M$ is singular there, so $F_B$ is not a bijection and a trail through it is not a trail (§11.25, TODO #245).

| $n$ | deltas | keys | min | median | mean | max | p10 | % keys below `4/3` |
|---|---|---|---|---|---|---|---|---|
| 7 | 69 | 112 | 0.500 | 1.279 | 1.188 | 1.778 | 0.718 | 63.4% |
| 8 | 138 | 232 | 0.250 | 1.349 | 1.275 | 2.014 | 0.425 | 50.0% |
| 10 | 120 | 197 | 0.340 | 1.717 | 1.615 | 2.320 | 1.087 | 35.5% |
| 11 | 60 | 110 | 0.650 | 1.903 | 1.813 | 2.523 | 1.165 | 27.3% |

Every constant in the table **already passes the deployed check**: `nl_v2_key_is_valid` rejects $\delta = 0$ and $\delta = 2^{n-1}$ and nothing else, and both are excluded.  These are the slopes of keys the shipped code accepts.

### 11.35.4 Against the `4/3` criterion

The median is **monotone rising** across every width tested, it clears the criterion from $n = 8$ on, and the fraction of accepted keys below the criterion is **monotone falling**, more than halving between the narrowest and widest width measured.  Both trends point the same way and neither is subtle.  This is the reassuring direction, and it is the first time the quantity has been measured rather than projected.

Three things keep it from being a bound.

1. **The narrow widths do not really bear on the criterion.**  At $n = 7$ the deployed round count would be $r = 3n/4 = 5$, and an asymptotic slope is not what governs a five-round cipher — the transient is.  $n = 7$ and $n = 8$ are present to establish a trend and to be cross-checkable by Karp, not because a 63% failure rate at $n = 7$ says anything about $n = 256$.
2. **A tail remains, and the deployed check does not screen it.**  The p10 column is the relevant one: a tenth of accepted keys sit below the criterion at every width, and that tail is thinning more slowly than the median is rising.  This is the same shape §11.28 found on the fixed-key side, and it receives the same disposition — documented, not screened, since screening it would reject a substantial fraction of keys for a property that is not an attack.
3. **Four points are a trend, not a limit.**  The usable sequence is $n = 7, 8, 10, 11$ and the next rung is $n = 13$.

**Effect on ratings: none, deliberately.**  The NL-FSCX v2 rows are demo-only already (§11.26, §11.29), and nothing here promotes or demotes them.  What has changed is that the quantity gating any future move is now measurable.

### 11.35.5 A correction to #247's "3.0 bits per round"

#247 §(d) reported key-averaged optima $4.0 / 7.0 / 10.0$ at $r = 3/4/5$, read them as "exactly linear at 3.0 bits per round", and projected $256/3 \approx 86$ rounds.  Solved for the minimum mean cycle in the same key-averaged model:

| $n$ | exact $\mu$ | slope read at $r = 3$–$5$ | ratio |
|---|---|---|---|
| 7 | 2.1555 | 1.9960 | 0.93 |
| 8 | 2.0107 | 2.0466 | 1.02 |
| 10 | 2.7512 | 3.2109 | 1.17 |

The read misses the exact asymptote by between $-7$ and $+17$ percent, and **the sign is not consistent**.  It is not a slope that happens to be biased; it is a window average over a series that has not reached its slope, and which way it lands depends on where the transient sits.  So the correction is not "3.0 should be 2.6" — it is that 3.0 is not a per-round increment at all, and neither its value nor its direction of error is recoverable without solving for the cycle mean at that width.  The 86-round projection has no support.  A second symptom from the MILP itself: extending #247's own series to $r = 6$ (§11.35.6) gives $2.0 / 4.0 / 7.0 / 10.0 / 14.0$, whose increments are $2 / 3 / 3 / 4$ — rising, not the constant $3.0$ the series was described as.

**§11.28.6's ratio survives and is now measured directly.**  That section put the per-key figure at "about half" the key-averaged one, inferred from §11.28's spread.  Comparing exact asymptotes at $n = 10$ gives $1.717 / 2.751 = 0.62$, consistent with §11.28's measured $0.50$–$0.61$ and no longer resting on two transient-contaminated series.

### 11.35.6 Route 1 quantified, and closed

§11.31.3 made route 1 — a stronger MILP backend — first choice, with the target $r = 10$–$14$ at $n = 32$–$64$.  HiGHS was put against CBC on the identical model, on one machine, so the comparison is not against a recorded timing.

| $n = 32$ | CBC | HiGHS |
|---|---|---|
| $r = 4$ | 68 s, proven | 47 s, proven |
| $r = 5$ | 635 s, **unproven** | 171 s, proven, weight 10.0 |
| $r = 6$ | not attempted | 676 s, proven, weight 14.0 |

HiGHS is genuinely better and bought two results CBC could not: $r = 5$ and $r = 6$ at $n = 32$ are now proven, so the width-agreement table of #247 §(d) extends by two rows.  That is a real if small addition to the one-sided statement #247 owns.

It does not reach the target, and the growth rate says it cannot.  HiGHS costs $1.6 / 10.1 / 47.0 / 171.1 / 676.3$ seconds at $r = 2/3/4/5/6$ — a factor of $3.6$–$4.0$ per added round with no sign of flattening, and $r = 6$ was predicted at about 620 s before it was run.  Extrapolated, $r = 10$ is roughly a day and a half and $r = 14$ roughly eight months, four to seven orders of magnitude past where a better LP backend lands.

**The target was unnecessary.**  $r = 10$–$14$ was needed only to open a window to read a slope in.  §11.35.1 removes the need for a window, and §11.35.3 delivers the same quantity exactly, in seconds, at widths both solvers reach trivially.  Route 1 is closed not because it failed but because the question it was aimed at no longer has to be asked that way.  **Route 3** (a transfer matrix over difference classes) was proposed to make the computation scale; Howard's policy iteration on the difference graph already does, so route 3 is superseded rather than pending.  **Route 2** remains demoted for the reason §11.31.3 gave.

### 11.35.7 What TODO #252 still owes

One thing: **the width extrapolation, and nothing else.**  $\mu$ is exact at the width measured, and reading it at $n = 256$ is not possible by this method — the graph has $2^n$ nodes, so the exhaustive-DDT bound that stopped every previous pass stops this one too.  What has changed is that the residual question is the limit of a monotone sequence of *exact* values, rather than a slope read through two sources of contamination at widths where no clean read exists.

A caution for whoever attacks it, because the obvious tool points the wrong way.  Embedding is how one usually relates widths: exhibit a cycle at width $n$ that survives at width $n+1$, and conclude $\mu(n+1) \leq \mu(n)$.  That argument, if it worked, would prove $\mu$ **non-increasing** — the opposite of what §11.35.3 measures.  Widening also adds nodes and therefore adds candidate cycles, so the naive counting argument points down as well.  $\mu$ rises anyway, which means the rise is driven by width *destroying* cheap cycles rather than by anything an embedding captures, and a structural proof has to explain that first.

The other two openings are cheaper: extend the sequence to $n = 13$ and $n = 14$, where the cost is the DDT's $2^{2n}$ and not the cycle computation, which stays cheap; and carry the same reformulation to the **linear** axis, where §11.30 has the identical problem and where mask propagation through $M$ is deterministic, so the cycle argument should transfer more cleanly still.

---

## 11.36 The linear slope, measured exactly — and why the two modes are out of reach (TODO #254)

`SecurityProofsCode/lin_cycle_mean.py` reproduces everything in this section.  It is TODO #254's second pass, and it closes both of the items the first pass left, in the first pass's own priority order.  Neither answer is the one the item expected.

§11.35.7 ended by predicting that #252's cycle reformulation "should transfer more cleanly still" to the linear axis.  It does, and it reaches two widths further.

### 11.36.1 The linear slope is a minimum mean cycle

The NL-FSCX v2 round is $F_i(x) = M(x \oplus B \oplus C_i) + \delta(B)$.  Two of its three layers move a mask deterministically: XOR with a constant changes only a sign, and $M$ is linear and symmetric, so a mask $w$ after it is the mask $M(w)$ before it.  Only the addition is probabilistic.  A linear trail is therefore a walk on a graph,

$$\text{nodes} = \{1, \dots, 2^n-1\}, \qquad \beta \longrightarrow M(w) \ \text{ with weight } -\log_2 |C_{+\delta}(\beta \leftarrow w)|$$

and the best $r$-round trail weight obeys the standard min-plus asymptotic $W(r) = c + s_{\text{lin}} r + o(1)$.  That identifies the slope exactly:

$$s_{\text{lin}} = \text{the minimum mean cycle of the mask graph}.$$

The constant $c$ is the cost of walking into the cheapest cycle, and it cancels in a cycle mean because a cycle has no beginning.  So **saturation** — the contamination §11.30.3 found in almost every slope figure in this repository — is a property of reading a slope off a finite series, and a cycle mean is not read off a series.  It is computed, by Howard's policy iteration, in seconds.

This retires #254's item (2).  The **transfer-matrix route** was nominated to make the computation scale after §11.30.4 closed the MILP route; it is superseded exactly as #252's route 3 was, and for the same reason — the computation does not need to scale, because the answer is a cycle mean and cycles are small.

### 11.36.2 Why the LAT is affordable, and an exact identity for its support

The obstacle to this measurement was always the linear approximation table of $x \mapsto x + d \bmod 2^n$: $4^n$ entries, and §11.30's first pass computed them one pair at a time through a carry automaton, which is why it stopped at $n = 10$.  Each row is a **rotation**, not a new function:

$$(-1)^{v \cdot (x+d)} = s_v[(x+d) \bmod 2^n], \qquad s_v[y] = (-1)^{v \cdot y}$$

so the row for output mask $v$ is one list rotation of $s_v$ followed by a Walsh–Hadamard transform — $(n+1)2^n$ per row and $(n+1)4^n$ for the table.  That reaches $n = 13$ in pure Python.

The table's support turns out to have an exact closed form, not previously recorded here.  Writing $k = \mathrm{tz}(d)$ for the number of trailing zeros of the addend, the number of nonzero entries depends on $d$ **only** through $k$:

$$\lvert \lbrace (v,w) : C(v \leftarrow w) \neq 0 \rbrace \rvert = \begin{cases} 2^k \cdot \dfrac{4^{n-k} - 4}{3}, & k \leq n-2 \\ 2^n, & k \geq n-1 \end{cases}$$

verified exhaustively over every addend at $n = 5, 6, 7$.  At $k = 0$ that is $(4^n-4)/3$, one third of the table; each trailing zero halves it.  It is what makes the graph's edge count predictable in advance, and it is the check that would catch a broken LAT before any slope is read off it.

### 11.36.3 v1 rides the same table

The v1 round is $F_B(A) = M(A) \oplus M(B) \oplus \mathrm{ROL}(A + B \bmod 2^n, n/4)$, and its nonlinear term takes $A$ rather than a constant.  It looks like a different object and #254 budgeted a separate treatment for it.  It is not different.  Splitting a mask $\beta$ on the output, and using $M = M^{T}$,

$$\beta \cdot F_B(A) = M(\beta) \cdot A \ \oplus \ \gamma \cdot (A + B) \ \oplus \ \text{const}, \qquad \gamma = \mathrm{ROR}(\beta, n/4).$$

$B$ is held constant for the whole revolve, so $\gamma \cdot (A+B)$ is again addition of a **constant**, and its correlation with a mask $w$ on $A$ is the same $C(\gamma \leftarrow w)$ the v2 graph uses — with $B$ itself in the role $\delta(B)$ plays for v2.  The round input mask is $M(\beta) \oplus w$.

One asymmetry survives and shapes the sweep.  v2's round depends on the key only through $\delta(B)$, so a sweep over keys collapses to a sweep over deltas — 554 of them for 1024 keys at $n = 10$.  v1's round depends on $B$ directly, with no collapse, so every key is its own graph.

### 11.36.4 Validation

Four checks, and the script fails if any stops reproducing.

- The LAT against `fscx_scaling_and_linear.py`'s carry automaton — an independent implementation, per-pair rather than per-row: $0$ mismatches over every constant and every mask pair at $n = 6$.
- The support identity of §11.36.2: $0$ deviations at $n = 5, 6, 7$.
- The v1 pull-back of §11.36.3 against a brute-force LAT of the round as the suite evaluates it: $0$ mismatches, four keys, every mask pair, $n = 6$.
- Edge pruning.  The widest row keeps only the $K$ cheapest out-edges per node, because the full graph at $n = 13$ has 22M edges; at $n = 11$, where the full graph fits, $K = 64, 32, 16$ all reproduce the full-graph answer to $10^{-9}$.
- Howard's policy iteration against **Karp's theorem** and against the exact $r$-round trail weight from a min-plus dynamic program: agreement to $10^{-9}$ between the first two, and to better than $0.02$ against a 20-round window of the third.

The dynamic-programming column is deliberately a window *average* rather than a difference.  The min-plus series is eventually periodic here as it is on the differential side, so a window that is not a whole number of periods carries an $O(1/\text{window})$ error — §11.35.2's trap, present on this axis too.

### 11.36.5 The measured slope

Per key, exact.  `below` is the key-weighted fraction under §11.30.1's criterion $s_{\text{lin}} \geq 2/3$.

**NL-FSCX v2**, indexed by $\delta(B)$, excluding the two constants `nl_v2_key_is_valid` already rejects:

| $n$ | deltas | p10 | median | mean | min | max | below $2/3$ |
|---|---|---|---|---|---|---|---|
| 7 | 69 (all) | $0.3240$ | $0.5931$ | $0.5156$ | $0.1429$ | $0.8113$ | 77.7% |
| 8 | 138 (all) | $0.2557$ | $0.6304$ | $0.5755$ | $0.2000$ | $0.9715$ | 57.8% |
| 10 | 554 (all) | $0.3260$ | $0.7341$ | $0.7055$ | $0.1667$ | $1.1136$ | 45.3% |
| 11 | 90 | $0.3180$ | $0.8313$ | $0.7642$ | $0.3180$ | $1.1245$ | 33.2% |
| 13 | 12 | $0.7539$ | $1.1541$ | $1.0631$ | $0.7539$ | $1.2211$ | 0.0% |

The $n = 13$ row needs `--wide` and takes minutes per key; every one of its twelve keys clears the criterion, and its *minimum* is above the median at $n = 11$.  Weighting by delta rather than by key gives medians $0.5931 / 0.6515 / 0.7983 / 0.8699 / 1.0350$ over the same widths — the same trend, so neither the sampling nor the weighting is driving it.

**NL-FSCX v1**, indexed by the key itself:

| $n$ | keys | p10 | median | mean | min | max | below $2/3$ |
|---|---|---|---|---|---|---|---|
| 7 | 128 (all) | $0.2721$ | $0.6048$ | $0.5280$ | $0.0000$ | $0.8080$ | 78.1% |
| 8 | 256 (all) | $0.2996$ | $0.6157$ | $0.5847$ | $0.1667$ | $0.8515$ | 66.7% |
| 10 | 200 | $0.4150$ | $0.7535$ | $0.6972$ | $0.0000$ | $1.0150$ | 37.5% |
| 11 | 60 | $0.4716$ | $0.8516$ | $0.7797$ | $0.2767$ | $1.0869$ | 33.3% |

A supplementary eight-key run at $n = 13$ gives median $1.0709$, minimum $0.4975$ and 25.0% below the criterion, continuing the same climb; it is reported here rather than in the table because the shipped script does not sweep v1 that wide by default.

**The shape matches the differential axis.**  §11.35.4 found the differential median monotone rising, clearing $4/3$ from $n = 8$ on, with the failing fraction thinning.  The linear median does the same against $2/3$: below at the two narrowest widths, above from $n = 10$ on, still rising at the widest width reached, with the failing fraction falling monotonely across the range — from 77.7% to zero for v2 by $n = 13$, and from 78.1% to 33.3% for v1 by $n = 11$.  Both primitives do it independently.  This is the reassuring direction, and it is the first time the quantity has been computed rather than read off a slope.

**It does not promote anything.**  HSKE-NL-A2, `twk` and `fpe` are demo-only for reasons this measurement does not touch — the SPRP assumption (#243), the $\tau(192) = 14$ fixed-point theorem (#244), the single unvaried round.  Clearing a trail criterion at four small widths substitutes for none of them.  And the criterion is sufficient, not necessary: what an attacker gets is the linear **hull**, the sum over all trails sharing endpoints, which a per-trail weight bounds in one direction only.

### 11.36.6 A correction to §11.30.6: the flattening is an artefact

§11.30.6 settled the linear slope at $0.59 / 0.75 / 0.93 / 0.95$ for $n = 7/8/10/11$ after removing saturation and the transient, and concluded that "the slope rises with width" was **weakened** — flattening, $+0.03$ between the two widest against $+0.16$ between the two narrowest.

Computed exactly, the flattening is not there — the sequence accelerates instead.  The v2 medians climb $+0.04 / +0.10 / +0.10 / +0.32$ per step across $n = 7, 8, 10, 11, 13$, against the first pass's $+0.16 / +0.18 / +0.02$; the v1 medians climb without a flat step over the same range.  §11.35.5's diagnosis applies verbatim: a finite-round read is a window average over a series that has not reached its slope, and its errors have no consistent sign.  Nothing in §11.30.6's *conclusion* changes — every width above $n = 7$ still clears $2/3$ — but the deceleration it reported should not be carried forward.

### 11.36.7 The v1 degenerate class, characterised exactly

A few v1 keys admit a correlation-1 trail of unbounded length — mean weight $0$ — or no cycle at all.  Exhaustively, at both widths where an exhaustive scan is instant, the class is the same four keys and nothing else:

$$B \in \{0,\ 2^{n-2},\ 2^{n-1},\ 3 \cdot 2^{n-2}\} \quad\Longleftrightarrow\quad \mathrm{tz}(B) \geq n-2.$$

At $n = 7$ the four give a zero-weight cycle; at $n = 8$ their graphs are acyclic, which is strictly better for the defender.  Four keys at every width, one of them the all-zero key the suite already treats as degenerate, is density $2^{-254}$ at $n = 256$.  Contrast #253's differential class for v2 — every $B$ with $\mathrm{tz}(\delta(B)) \geq 4$, about 6% of keys.  This one is not a weak-key class in any operational sense and needs no screening; it is recorded because §11.30.5's correlation-1 subspace predicted something in this shape.

### 11.36.8 The two modes — TODO #254's item (1), answered negatively

§11.30's scope note says the block-cipher criterion "does not transfer unexamined" to HSKE-NL-A1 or HFSCX-256, and guesses that a naive transfer would give "a sharper bar", both running $n/4$ rounds instead of $3n/4$.  *Sharper* is the wrong word.  The transfer does not fail by a factor of three.  It fails.

$$\text{A1:} \quad ks_i = F_1^{n/4}(\text{seed},\ \text{base} \oplus i), \qquad \text{DM:} \quad h' = F_1^{n/4}(h,\ m) \oplus h$$

In A1 the seed and base are secret and the attacker varies the block counter $i$, so the varying input is the **second** argument; the first never varies at all across a keystream.  In Davies–Meyer the message block is again the second argument, and it is the input the attacker controls.  A trail — differential or linear — propagates a difference or a mask in the *first* argument through $r$ rounds.  That is what §11.30.1's $s$ measures and what §11.36.5 computes.  In both of these modes the attacked input is the round **constant**, which enters all $r$ rounds simultaneously: there is no round-by-round propagation in $B$, hence no trail, hence no cycle, hence no cycle mean.

**Consequence.**  The three production-track rows #254 hoped to reach — HSKE-NL-A1, HFSCX-256, and everything inheriting the hash (HPKS-WOTS, HPKS-XMSS, every Fiat–Shamir transform in the suite) — are **not reachable by a trail bound in either direction**.  §11.36.5's numbers speak to HSKE-NL-A2, `twk` and `fpe` only.  #254 can no longer be the item that re-rates them, and the naive transfer §11.30 anticipated gives nothing rather than a sharper bar.

What can be measured on the actual axis is the exhaustive maximum differential probability of the A1 keystream map $B \mapsto F_1^{r}(A_0, B)$, over the counter differences A1 can actually reach.  Against a random-function floor of $-7.68$ at $n = 11$ and $-9.42$ at $n = 13$, $\log_2$ of that maximum runs $-0.10 / -1.90 / -4.42 / -5.80 / -7.68$ and $-0.34 / -2.95 / -5.88 / -7.80 / -9.19$ at $r = 1 \dots 5$: healthy pre-saturation increments running to $3.5$ bits per round, and the floor reached by $r = 5$.  Read it as a floor, not a slope.  Those increments are read at $r \leq 4$, and §11.35.5 is the standing warning about exactly that — on an axis where the asymptote *could* be computed, a read inside the transient missed it by between $-7$ and $+17$ percent with no consistent sign.  Here it cannot be computed, so there is nothing to correct the read against, and A1's deployed $r = 64$ at $n = 256$ is far outside anything measurable.

The Davies–Meyer message input is better news and is exhaustively checkable.  A necessary condition for collision resistance is that $m \mapsto F_1^{n/4}(h, m) \oplus h$ not collapse; measured, its image fraction is $0.6465 / 0.6442 / 0.6231 / 0.6246 / 0.6314$ at $n = 10/11/12/13/14$ against the $1 - 1/e = 0.6321$ a random function gives, with maximum preimage counts of $5$ to $8$.  No anomaly, which corroborates §11.9's ideal-random-function treatment (TODO #215) on the one point a trail argument could have contradicted.  Note that the singular widths are usable here and only here: $n = 12$ makes $M$ non-invertible, which voids §11.36.5 — $F_B$ must be a bijection for a mask graph to mean anything — but Davies–Meyer does not need $F_B$ invertible.

### 11.36.9 What TODO #254 still owes

Item (2) is closed by §11.36.1 and item (1) by §11.36.8.  Three things remain, and the first is not #254's alone.

**The width extrapolation.**  Five exact points that rise do not bound $n = 256$.  This is now the *only* thing #252 and #254 have left, jointly and identically — both items reduce to the same question about the same kind of object, and §11.35.7's caution transfers with it: an embedding argument would prove the slope non-increasing, the opposite of what is measured, so the rise must come from width destroying cheap cycles rather than from anything an embedding captures.  It should be filed once, not twice.

**The linear hull.**  Every number in §11.36.5 is a trail weight.  While the criterion is being cleared by a comfortable factor this is a technicality; the two narrowest widths do not clear it, and if a wider measurement ever lands near the bar the gap between the best trail and the hull stops being one.

**The B-axis.**  Newly named by §11.36.8 and belonging to whoever re-examines A1 and HFSCX-256.  Nothing in this repository measures it beyond four rounds, and those two modes run $n/4$ rounds rather than $3n/4$ — less margin to spend, not more.

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
