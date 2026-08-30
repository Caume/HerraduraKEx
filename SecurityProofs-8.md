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
> - **Part 8 — §11.34** (this file): NL-FSCX v3 — Exact Row Analysis

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
