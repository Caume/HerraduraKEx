# HerraduraKEx — Open TODO Items

> **Completed, deprecated, and acknowledged items have moved to [`TODO_DONE.md`](TODO_DONE.md) (TODO #154).** This file holds only entries with `Status: **OPEN**`. Item numbers are global and preserved across both files — when an item here is completed, move its whole entry to the end of `TODO_DONE.md` and update its Status line, per CLAUDE.md's TODO policy.

---

## Open items

### #224: Explore a masked-step / hash-based HKEX PQC variant (MFSCX-KEX)

Every HKEX variant shipped so far derives its hardness from one of two places:
GF(2^n)* discrete log (HKEX-GF — classically broken by Shor, and the FSCX layer
around it is affine) or Ring-LWR (HKEX-RNL — which TODO #216/#223 showed is far
below its claimed level at the deployed parameters). This item is the exploratory
track for a third construction that leans on symmetric/hash-style hardness
instead, using FSCX itself as the mixing function.

**Proposed construction (MFSCX_REVOLVE).** Add a per-step, non-uniform seed
injection to the revolve loop. With `M = I ⊕ ROL ⊕ ROR` as today:

```
MFSCX_REVOLVE(A, B, i; S):
    for j = 0 .. i-1:
        A <- FSCX(A, B) ⊕ (S_j & mask_j)
```

where `S_j` is a seed-derived subkey for step `j` and `mask_j` selects *which*
bits of `S_j` actually get XORed in. Two mask regimes to evaluate:

- **static P-box** — `mask_j` fixed at compile time (a published permutation/
  selection box, same for all sessions);
- **dynamic P-box** — `mask_j` derived from the seed itself, or from the current
  state `A`, so the injection pattern is session- (or state-) dependent.

**The central tension, to be settled before any implementation.** The two-party
agreement in every FSCX-based construction rests on the XOR homomorphism of the
affine map, and that same affinity is exactly what `hkex_classical_break.py`
exploits (`sk = S_{r+1}·(C ⊕ C2)`, computable from the wire values alone).

- A **static** mask keeps the whole map affine over GF(2): it only changes the
  constant term, `MFSCX(A,B) = M^i·A ⊕ T_i·B ⊕ c(S)`, and `c(S)` cancels in
  `C ⊕ C2` whenever both parties use the same public S. First task is therefore
  to check whether the existing break generalizes verbatim — the expectation is
  that it does, and that finding alone would close the static branch.
- A **dynamic** (state-dependent) mask does destroy affinity, but it also
  destroys the homomorphism that makes `C_A ⊕ C_B` a shared value at all. The
  open question is whether there is any middle ground: a mask schedule that is
  non-linear in the seed while remaining commutative in the two parties'
  contributions. `hkex_nonce_impossibility.py` already proves no *nonce* choice
  rescues HKEX; the argument there is algebraic and may extend to any
  seed-injection schedule. Extending it (or finding the gap) is the real work.

**Hash-based hardness — state the ceiling up front.** "Hash-based key exchange"
is not a free substitution for a trapdoor. Hash-based *signatures* (already here
as HPKS-WOTS-F / HPKS-XMSS-F) work because signing needs no trapdoor; key
exchange does. Against a random-oracle-only adversary the Impagliazzo–Rudich
separation caps black-box key agreement at Merkle-puzzle quadratic security —
2^128 target means ~2^64 honest work, which is not shippable. So the plan must
pick its honest goal early:

1. **Interactive/authenticated setting** — MFSCX as a KDF or ratchet over an
   already-shared secret (this is HSKE territory, and works, but is not a KEX);
2. **Merkle-puzzle-style KEX** — real, provable, and quantifiably too slow;
   worth a cost table so the number is on the record rather than assumed;
3. **MFSCX as the symmetric layer inside a structured PQC KEM** — e.g. as the
   hash/KDF/error-sampler inside the QC-MDPC or Ring-LWR path, where hardness
   comes from the code/lattice and MFSCX only has to be a good PRF. This is the
   only branch with a plausible production endpoint.

**Plan.**

1. Add `SecurityProofsCode/mfscx_kex_analysis.py`, self-contained like its
   neighbours. Sections: (a) formalize MFSCX_REVOLVE for both mask regimes;
   (b) re-run the `hkex_classical_break.py` recovery against the static-mask
   variant across widths, expecting success — i.e. a disproof; (c) measure
   algebraic degree / branch number of the dynamic-mask variant, reusing the
   method in `fscx_branch_number.py` and `nl_fscx_owf_analysis.py`;
   (d) test whether two-party agreement survives dynamic masking at all
   (it likely does not — record the failure rate); (e) the Merkle-puzzle cost
   table for option 2.
2. Reuse `fscx_revolve_corank.py`'s machinery to compute the co-rank of the
   masked key map `T_i` under a static P-box, at the deployed `i = n/4`,
   `r = 3n/4` — if the mask shrinks the image, that is a second independent
   reason to reject the static branch.
3. Check the dynamic-mask permutation for orbit collapse the way
   `nl_fscx_v2_orbit.py` does: a seed-derived mask that lands in a short cycle
   silently degrades to a static one.
4. Only if steps 1–3 leave a branch alive, write it up as a new SecurityProofs
   subsection (§11.21, in `SecurityProofs-7.md` — mind the ~750-expression
   KaTeX budget per TODO #220) and open a separate implementation TODO. Do not
   add an `--algo` tag, PEM label, or `spec/` entry from this item.
5. If all branches close, the deliverable is still worth having: land the script
   plus a short negative-result section, the same way `hkex_cy_test.py` and
   `hkex_cfscx_*.py` record constructions that were tried and rejected. A
   documented dead end is the point of this item, not a failure of it.

**Success criterion.** Either a construction with a written hardness assumption
that is not restatable as "FSCX is affine", or a clear negative result saying
why seed-masked FSCX cannot give key agreement. Anything that only *looks*
non-linear while `C ⊕ C2` still determines `sk` does not count.

Status: **OPEN**

### #225: `native-python` — measure what the n=1024 ring actually costs, and where it goes

*Premise rewritten (2026-08-23). The original entry framed this as timeout risk.
That framing does not survive contact with the workflow file: `.github/workflows/`
contains **no `timeout-minutes` key at all**, so every job inherits GitHub's
360-minute default. Five recent `native-python` runs took 18.3, 22.4, 23.5, 24.6
and 24.7 minutes — a ~15x margin. There is no timeout to cross, and "raise the job
timeout" was never one of the options because no timeout was ever set. The real
question is a different one, below.*

TODO #223 moved HKEX-RNL's ring from 256 to 1024. The NTT is O(n log n), so the
Python reference's ring multiply went from 1.7 ms to 8.9 ms — 5.2x — measured on a
host without numpy (`_NUMPY = False`, the pure-Python `_ntt_inplace` path).

**Where that 5.2x actually lands.** The suite runs under `-t 2.0`, a per-test
wall-clock cap. A capped test does not get slower when its inner operation gets
slower — it performs **fewer iterations in the same two seconds**. So the ring
move did not buy 5.2x more job time; it bought roughly 5.2x less RNL coverage,
silently, with no signal in the log. That is the concern worth tracking, and it
is a correctness-confidence concern, not a scheduling one.

Step timings from run 32617685487 locate the time precisely:

| Step | Time | Share |
|---|---|---|
| Python test suite (`-t 2.0`) | 1091 s | 82% |
| CliTest — Python CLI (15 scripts) | 243 s | 18% |
| everything else | 9 s | <1% |

So the job is dominated by the capped suite, whose duration is set by the *number*
of tests and benchmarks, not by how fast any one of them runs. Adding a test costs
up to 2 s; making RNL 5x slower costs nothing in time.

**Work.**

1. Instrument iteration counts, not wall time. For each RNL-touching test, record
   how many iterations completed inside the cap at n=256 vs n=1024. That number is
   the coverage that was lost, and it is the figure this item exists to put on the
   record. Land it in `benchmarks/` so the next ring-parameter change has a
   baseline.
2. Decide per test whether the surviving iteration count is still adequate. These
   are correctness checks, not benchmarks — a handful of iterations may be entirely
   sufficient for some and plainly too few for others. Where it is too few, raise
   that test's cap specifically rather than the job's; there is ample headroom.
3. Settle the numpy question, which the original entry raised and which is still
   open. `_rnl_poly_mul` takes a vectorised path when numpy imports. The
   `native-python` job installs `python3` and nothing else, so whether numpy is
   present depends on the `ubuntu-latest` image rather than on anything this repo
   controls — and **the suite prints no indication either way**, so the CI logs
   cannot answer it retrospectively (grepping them for `numpy` returns nothing).
   Add a one-line banner reporting `_NUMPY` at startup. That is a two-line change
   that makes every future run self-documenting, and it should land first, since
   steps 1 and 2 are measuring a path whose identity is currently unknown.

**A second-order detail worth checking while instrumenting.** The cap is polled
every 64 iterations (`(i & 63) == 63`, `Herradura_tests.py:1175`), not every
iteration. Overshoot is therefore bounded by 64 iterations' worth of work, which
scales with per-iteration cost — the same 5.2x applies to it. At n=1024 this is
probably still small against a 2 s cap, but it is unmeasured, and it is the one
mechanism by which a slower ring *could* lengthen the job rather than shorten
coverage. Confirm it is negligible, or tighten the poll for the RNL tests.

**Explicitly not in scope.** Splitting `native-python` the way TODO #205 split the
combined `native` job. That was listed as an option under the timeout framing; with
a 15x margin it addresses nothing, and it would cost a second full checkout and
dependency install for no benefit.

Status: **OPEN**
