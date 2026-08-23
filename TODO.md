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
