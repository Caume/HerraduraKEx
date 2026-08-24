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

---

### #232: Decide whether to act on §11.22.2's co-rank improvement (126 -> 64) in HSKE/HPKE

TODO #230 produced an unshipped side-result. §11.22.2 of `SecurityProofs-7.md` shows
that TODO #210's plaintext leak is not intrinsic to the FSCX construction: with a
linear box `L` the step becomes FSCX with `M` replaced by `M' = L.M`, and writing
`Y = M' + I`,

    co-rank(T_i) = dim ker Y^(2^v2(i) - 1)

so #210's closed form `2(2^v2(i) - 1)` is the special case `v(M + I) = 2`. **The factor
2 is a property of this particular `M`, not of the construction.** A box with Jordan
type `(n-1, 1)` takes the leak from **126 to 64 of 256** at `n = 256, i = 64`, and 64
is a proved floor, not a search result: `dim ker Y^(i-1) = sum_j min(lambda_j, i-1)` is
minimized by the fewest and largest blocks, and the unconstrained optimum (regular
nilpotent, co-rank 63) has `Y^(n-1) != 0` and therefore **fails agreement**.

**This item is the decision, not the change.** Nothing here authorises editing HSKE or
HPKE; §11.22.2 says as much in its own last line.

**Why the answer is probably "no", and what would have to be true for it to be "yes".**
Three routes to the same leak are already on the table, and the linear box is the worst
of them on every axis:

| route | co-rank at n=256 | cost | source |
|---|---|---|---|
| odd `i` (e.g. 65) | **0** — `T_i` invertible, Shannon-perfect at one-time use | a parameter | #210/#211, `hske_perfect_secrecy.py` |
| secret per-step injection | **0** — `sigma_i` is surjective since `m(1) = 1` | a subkey schedule | #224, §11.21.3 |
| linear box `L` (this item) | **64** — and never 0, since `Y` is nilpotent so `Y^(i-1)` is singular for every even `i` | a new primitive **and** a MAJOR wire-format break | #230, §11.22.2 |

Two further points argue against shipping it:

1. **None of the three fixes the affine two-time break.** `E1 xor E2 = M^i.(P1 xor P2)`
   under a reused key holds regardless of `L`, `i`, or any additive injection, because
   all of them preserve affinity. The real fix for multi-use is the NL quartet, which
   already ships.
2. **It cannot change a `SECURITY.md` rating.** HSKE (key-only) is already "Not
   suitable for production" and HPKE "Demo-only", and each is disqualified by something
   the co-rank does not touch — a single known-plaintext pair recovers the HSKE
   keystream, and HPKE falls to ~2^36.5 Pohlig-Hellman. A MAJOR break that moves 126 to
   64 buys a rating change of exactly zero.

So the plausible outcomes are `DEPRECATED` (documented, deliberately not shipped) or an
opt-in that touches no default. Shipping it as the default would need an argument that
survives all four objections above, and per CLAUDE.md's MAJOR rules that argument must
appear in this item's own text before any code moves.

**Work to do.**

1. Decide among: (a) close as `DEPRECATED` with the reasoning recorded in
   `SecurityProofs-7.md`; (b) expose the `(n-1, 1)` box as an opt-in that leaves every
   default and every existing artifact readable; (c) make it the default, which is a
   MAJOR bump plus a `MIGRATING.md` entry, since it changes what existing `--algo hske`
   and `--algo hpke` ciphertexts decrypt to.
2. If (b) or (c): exhibit the concrete `L` — §11.22.2 measured a Jordan type, not a
   shipped matrix. It must be stated as a bit-matrix or a closed form, verified to give
   `Y^(n-1) = 0` and co-rank 64 at n=256, and be cheap enough for the AVR and Thumb-2
   targets, which is a real constraint: FSCX is currently three shifts and five XORs.
3. Either way, check the knock-on to HPKS. #210 notes the Schnorr challenge
   `e = fscx_revolve(R, msg, i)` lives in a 130-dimensional affine subspace; a box that
   moves the co-rank to 64 moves that to 192, which is a *signature* parameter and a
   separate wire-format question from HSKE/HPKE.
4. Whatever is decided, add the comparison table above to §11.22.2 so a future reader
   does not rediscover the 126 -> 64 result and mistake it for the best available fix.

Related: [[#210]] (the leak), [[#211]] (odd `i`, co-rank 0), [[#224]] (secret injection,
co-rank 0), [[#230]] (this result's origin).

Status: **OPEN**
