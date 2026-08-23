# HerraduraKEx — Open TODO Items

> **Completed, deprecated, and acknowledged items have moved to [`TODO_DONE.md`](TODO_DONE.md) (TODO #154).** This file holds only entries with `Status: **OPEN**`. Item numbers are global and preserved across both files — when an item here is completed, move its whole entry to the end of `TODO_DONE.md` and update its Status line, per CLAUDE.md's TODO policy.

---

## Open items

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

### #230: Does TODO #224's negative result extend to an S-box layer?

TODO #224 closed the seed-masked revolve (MFSCX) as a key exchange, but the
argument that closed it has a stated scope, and an S-box is outside it.  The
impossibility theorem in `mfscx_kex_analysis.py` §5 quantifies over *additive*
injections: values `u_j` that enter the step by XOR and reach the session key
only through the accumulator `L = xor_j M^(r-1-j).u_j`.  That linear factoring is
what let correctness force `L` to be a public function of `(C, C2)`.  A
substitution layer does not factor out of the iteration at all:

```
SFSCX_REVOLVE(A, B, i):
    for j = 0 .. i-1:
        A <- S(FSCX(A, B))          # or FSCX(S(A), B), or a B-keyed S_B(.)
```

so #224's theorem says nothing about it, in either direction.  The expectation is
still failure — but by a different mechanism, and "we expect it for the same
reason" is exactly the kind of claim this repo has been wrong about before
(TODO #216 vs. the cited Core-SVP figures).  This item settles it.

**The real question underneath.** Agreement in every HKEX variant rests on one
identity — that the two parties' step maps commute up to the XOR corrections:

```
revolve(revolve(A2, B2, i), B,  r) xor A   ==
revolve(revolve(A,  B,  i), B2, r) xor A2
```

which holds because `M` is linear and `M.S_n = 0`.  An S-box breaks commutation.
So the honest formulation is not "does an S-box fail" but:

> Characterize *every* step function `G(A, B)` for which HKEX-style two-party
> agreement holds.  Conjecture: `G` must be affine over some abelian group, i.e.
> any such construction is a disguised XOR/DH homomorphism — and therefore
> already covered by one of the existing breaks.

If that conjecture is provable, it subsumes TODO #210, the nonce impossibility
theorem, and TODO #224 as corollaries, and it retires a whole class of future
proposals in one place instead of one script at a time.  The repo currently holds
five separate one-off failures of this shape — `hkex_cy_test.py` (FSCX-CY, carry
non-linearity), `nl_fscx_v2_kex.py` (non-abelian `pi_K` family, Ko-Lee),
`hkex_cfscx_*.py` (four preshared/two-step/int-op/compress constructions),
`hkex_nonce_impossibility.py`, and now `mfscx_kex_analysis.py` — none of which
knows about the others.  Deciding whether they are instances of one theorem is
the substance of this item; the S-box is the concrete case that motivates it.

**Sub-cases, cheapest first.  They do not all have the same answer.**

1. **GF(2)-linear S-box** (a bit permutation, an MDS-style matrix, any linear
   `L`).  This is *not* a new construction: the step becomes `L.M.(A xor B)`, so
   every result carries over verbatim with `M` replaced by `L.M`.  Predictions to
   confirm rather than assume: agreement survives iff `(L.M)` has the same
   order/annihilation structure that gives `S_n = 0`; the break formula becomes
   `S_(r+1)` over the new operator; and the TODO #210 co-rank changes — a
   well-chosen `L` may well make the key map *invertible*, which would be a real
   (if non-KEX) result worth having, in the same way TODO #211's odd-`i` finding was.
2. **Affine S-box** (`L.x xor c`).  Reduces to case 1 plus a constant, and the
   constant is exactly TODO #224's `kappa` — expected to be closed by #224's own
   argument.  Confirm that the reduction is exact rather than merely plausible.
3. **Genuinely non-linear S-box, unkeyed** — AES-style bytewise inversion over
   `GF(2^8)`, or a 4-bit box applied nibblewise.  This is the case the item is
   named for.  Measure the agreement rate, and — the discriminator that matters —
   the *distribution* of `sk_A xor sk_B`, not just the pass/fail count.  #224
   measured `n/2` mean Hamming distance for the dynamic mask, i.e. the two values
   are unrelated and no reconciliation can help.  If an S-box instead leaves a
   *small* distance, the construction is not dead: it is noisy, and Peikert-style
   reconciliation is already deployed in this suite (HKEX-RNL, §11.4.2).  That
   would be a live branch, and it is the one outcome that would make this item
   more than a fourth negative result.
4. **B-keyed S-box** (`S_B(.)`, box selected by the revolve parameter).  Destroys
   even the shared-box symmetry; expected to be the worst case, included to bound
   the space rather than because it is promising.

**Plan.**

1. Add `SecurityProofsCode/sbox_kex_extension.py`, self-contained like its
   neighbours.  Sections: (a) restate #224's theorem with its scope condition made
   explicit, and show by construction that an S-box violates the condition — the
   point being that #224 is *silent* here, not that it applies; (b) case 1, with
   the co-rank of `L.M` measured against `fscx_revolve_corank.py`'s closed form and
   an explicit search for an `L` making the key map invertible; (c) case 2's
   reduction; (d) cases 3 and 4, reporting agreement rate *and* the Hamming-distance
   distribution of `sk_A xor sk_B` against the `n/2` random-function baseline;
   (e) the reconciliation test from sub-case 3, run only if (d) shows small distances.
2. Attempt the characterization theorem.  Start at small width where the space is
   enumerable: for `n = 4` and `n = 6`, search over step functions `G` in a
   restricted but non-trivial family and record which admit agreement.  A clean
   empirical statement ("every agreeing `G` found at `n = 4/6` is affine over an
   abelian group") is a publishable-grade result for this repo even without the
   general proof, provided the family searched is described honestly and the
   search is exhaustive over it rather than sampled.
3. If the theorem lands, write it up as §11.22 in `SecurityProofs-7.md` and add
   back-references from §11.21 and §1.3.1, so the five scattered failures point at
   one statement.  Mind the KaTeX budget — Part 7 is at 649 of ~750 after TODO
   #224, so a theorem-heavy section may need Part 7 split (cf. TODO #220) rather
   than squeezed in.  Budget the split as part of this item, not as a surprise.
4. If sub-case 3 leaves a reconciliation-based branch alive, do **not** implement
   it here.  Open a separate implementation TODO, and note that a noisy-agreement
   KEX whose hardness is "inverting an S-box layer" still needs a written hardness
   assumption before it is worth any code — the failure mode TODO #224 warned
   about, where a construction looks non-linear but the wire still determines the key.

**Explicitly out of scope.** No `--algo` tag, PEM boundary label, or `spec/` entry
from this item, and no change to any shipped protocol.  A linear S-box that makes
the key map invertible (sub-case 1) is a finding about HSKE/HPKE, not a licence to
change them; that would be its own TODO with its own wire-format and MIGRATING.md
analysis.

**Success criterion.** Either the characterization theorem (with the S-box case
falling out as a corollary), or — failing the general proof — a measured answer for
all four sub-cases in which the distance distribution, not just the pass/fail rate,
is reported, so that a future reader can tell "unrelated" from "noisy but
reconcilable".  A result that only says "agreement failed 0/2000" repeats TODO #224
without extending it and does not close this item.

Status: **OPEN**
