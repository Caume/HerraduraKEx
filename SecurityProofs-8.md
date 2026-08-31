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
> - **Part 8 — §11.34–§11.35** (this file): NL-FSCX v3 — Exact Row Analysis · Asymptotic Differential Slope

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
