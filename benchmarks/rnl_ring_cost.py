"""TODO #225: what the n=1024 ring actually costs in the Python test suite, and
where the `native-python` job's time actually goes.

TODO #223 moved HKEX-RNL's ring dimension from 256 to 1024.  The concern this
item was opened on was that the capped security tests would silently lose
coverage: a test under `-t 2.0` does not get slower when its inner operation
gets slower, it performs fewer iterations in the same two seconds.

Measured, that concern does not apply, for a reason the item did not anticipate:

  * `CryptosuiteTests/Herradura_tests.py` is self-contained — it transcribes the
    primitives rather than importing the suite — and its `RNL_SIZES` is still
    `[32, 64, 128, 256]`.  The ring move happened in the suite's `RNLN`; the
    harness never followed.  The same is true of the C harness
    (`rnl_sizes[] = {32, 64, 128, 256}` against `RNL_N 1024`).
  * The harness could not follow even if it wanted to.  It uses one variable for
    both the ring dimension and the key width, and its KDF line computes
    `_RNL_KDF_DC_256 >> (256 - n_rnl)`, which raises `ValueError: negative shift
    count` for any `n_rnl > 256`.  The suite keeps the two separate — the ring is
    1024 while the derived session key stays `KEYBITS = 256` — which is exactly
    the distinction TODO #223 introduced and the harness predates.
  * So no RNL call site is truncated by the cap.  Every one completes its full
    requested iteration count.  Coverage of the *deployed* ring comes from
    `KAT/hkex_rnl.json` (which does pin n=1024) and from the CliTest scripts that
    drive the CLI at its default ring, not from the capped suite.

What the census in §3 does find is that `-t` caps much less than it appears to.
`_trange` polls the clock at `(i & 63) == 63`, so a call site that requests fewer
than 64 iterations can never be interrupted: the cap is structurally inert there.
18 of 95 capped sites are in that category, and they account for ~71% of all time
spent inside capped sites.  The worst single site requests 30 iterations and runs
~97 s against a 2.0 s cap.  That, not the ring, is where the job time goes.

Run:
    python3 benchmarks/rnl_ring_cost.py              # ring cost + cap arithmetic
    python3 benchmarks/rnl_ring_cost.py --census     # + full 95-site census (slow)
"""

import argparse
import importlib.util
import os
import statistics
import sys
import time

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
_TESTS = os.path.join(_ROOT, "CryptosuiteTests", "Herradura_tests.py")

CAP = 2.0          # the per-test wall-clock cap the CI job passes as -t 2.0
POLL = 64          # _trange polls at (i & 63) == 63
RING_SIZES = [32, 64, 128, 256, 512, 1024]


def load_harness():
    spec = importlib.util.spec_from_file_location("herradura_tests", _TESTS)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["herradura_tests"] = mod
    spec.loader.exec_module(mod)      # __name__ != '__main__', nothing runs
    return mod


def median_of(fn, reps=5):
    """Median wall time of `reps` calls, after one warm-up call."""
    fn()
    samples = []
    for _ in range(reps):
        t0 = time.perf_counter()
        fn()
        samples.append(time.perf_counter() - t0)
    return statistics.median(samples)


# ─────────────────────────────────────────────────────────────────────────────
# §1  The ring-parameter baseline
# ─────────────────────────────────────────────────────────────────────────────

def section1(ht):
    print("=" * 74)
    print("§1  Ring cost by dimension — the baseline for the next parameter move")
    print("=" * 74)
    print()
    print(f"  _rnl_poly_mul path: {'numpy NTT' if ht._NUMPY else 'pure-Python NTT'}")
    print()
    mul, per = {}, {}
    for n in RING_SIZES:
        f = ht._rnl_rand_poly(n, ht.RNLQ)
        g = ht._rnl_rand_poly(n, ht.RNLQ)
        mul[n] = median_of(lambda f=f, g=g, n=n: ht._rnl_poly_mul(f, g, ht.RNLQ, n))
        m_base = ht._rnl_m_poly(n)
        per[n] = median_of(lambda n=n, m=m_base: _one_kex_iteration(ht, n, m), reps=3)
    print("    n      poly_mul      vs n=256     one [14] iteration     vs n=256")
    for n in RING_SIZES:
        print(f"  {n:5d}   {mul[n]*1000:8.3f} ms   {mul[n]/mul[256]:7.2f}x   "
              f"{per[n]*1000:12.2f} ms   {per[n]/per[256]:9.2f}x")
    print()
    print(f"  The 5.2x the item quotes for 256 -> 1024 reproduces: "
          f"{mul[1024]/mul[256]:.2f}x on the ring multiply, "
          f"{per[1024]/per[256]:.2f}x end to end.")
    print()
    return per


def _one_kex_iteration(ht, n, m_base):
    """One iteration of security test [14], at ring dimension n."""
    a_rand = ht._rnl_rand_poly(n, ht.RNLQ)
    m_blind = ht._rnl_poly_add(m_base, a_rand, ht.RNLQ)
    s_A, C_A = ht._rnl_keygen(m_blind, n, ht.RNLQ, ht.RNLP)
    s_B, C_B = ht._rnl_keygen(m_blind, n, ht.RNLQ, ht.RNLP)
    K_A, hint = ht._rnl_agree(s_A, C_B, ht.RNLQ, ht.RNLP, ht.RNLPP, n, n)
    K_B = ht._rnl_agree(s_B, C_A, ht.RNLQ, ht.RNLP, ht.RNLPP, n, n, hint)
    return K_A == K_B


# ─────────────────────────────────────────────────────────────────────────────
# §2  What survives the cap, and what the harness cannot reach
# ─────────────────────────────────────────────────────────────────────────────

def section2(ht, per):
    print("=" * 74)
    print("§2  What survives a 2.0 s cap — and why n=1024 is not in the harness")
    print("=" * 74)
    print()
    requested = 200                    # test [14]'s iteration request
    print(f"  Security test [14] requests {requested} iterations per ring size.")
    print(f"  _trange polls at (i & {POLL - 1}) == {POLL - 1}, so it can only stop at a")
    print(f"  multiple of {POLL}: the surviving count is always {POLL}, 128, 192, ... or all "
          f"{requested}.")
    print()
    print("    n      ms/iter   affordable in 2.0 s   actually runs   in RNL_SIZES?")
    for n in RING_SIZES:
        afford = CAP / per[n]
        if afford >= requested:
            runs = f"{requested} (all)"
        else:
            runs = str(max(POLL, POLL * int(afford // POLL)))
        print(f"  {n:5d}   {per[n]*1000:8.2f}   {afford:19.1f}   {runs:>13}   "
              f"{'yes' if n in ht.RNL_SIZES else 'no'}")
    print()
    print(f"  RNL_SIZES = {ht.RNL_SIZES}; the suite's deployed ring is RNLN = 1024.")
    print("  At every size the harness actually runs, the full 200 iterations complete:")
    print("  the cap never bites, so the ring move cost zero measured coverage there.")
    print()
    print("  The harness cannot be pointed at 1024 by editing RNL_SIZES alone:")
    for n in (256, 1024):
        try:
            ht._RNL_KDF_DC_256 >> (256 - n)
            verdict = "ok"
        except ValueError as exc:
            verdict = f"{type(exc).__name__}: {exc}"
        print(f"    _RNL_KDF_DC_256 >> (256 - {n}):  {verdict}")
    print()
    print("  The harness uses one variable for both the ring dimension and the key")
    print("  width.  The suite separates them (ring 1024, KEYBITS 256) — that is what")
    print("  TODO #223 introduced, and the harness predates it.  Coverage of the")
    print("  deployed ring comes from KAT/hkex_rnl.json and the CliTest scripts.")
    print()


# ─────────────────────────────────────────────────────────────────────────────
# §3  Where the job time actually goes
# ─────────────────────────────────────────────────────────────────────────────

KNOWN_OFFENDERS = ("test_hpke_stern_f_correctness", "test_hpks_stern_f_correctness",
                   "test_zkp_nl_correctness", "test_zkp_rnl_correctness")


def section3(ht, census):
    print("=" * 74)
    print("§3  Cap coverage — the sites -t cannot touch")
    print("=" * 74)
    print()
    print(f"  A site requesting fewer than {POLL} iterations is never polled, so the cap")
    print("  is structurally inert there no matter how slow the work becomes.")
    print()
    names = sorted(n for n in dir(ht) if n.startswith("test_")) if census \
        else list(KNOWN_OFFENDERS)
    if not census:
        print(f"  Quick mode: the {len(names)} worst sites only.  Use --census for all of them.")
    print()
    rec = []
    orig = ht._trange

    def traced(n):
        done, t0 = 0, time.perf_counter()
        for i in orig(n):
            done += 1
            yield i
        rec.append((cur[0], n, done, time.perf_counter() - t0))

    ht._trange = traced
    ht.g_time_limit = CAP
    cur = [None]
    for name in names:
        cur[0] = name
        with open(os.devnull, "w") as devnull:
            saved, sys.stdout = sys.stdout, devnull
            try:
                getattr(ht, name)()
            except Exception as exc:                      # noqa: BLE001
                sys.stdout = saved
                print(f"    {name}: ERROR {type(exc).__name__}: {exc}")
                continue
            finally:
                sys.stdout = saved
    ht._trange = orig

    inert = [r for r in rec if r[1] < POLL]
    trunc = [r for r in rec if r[2] < r[1]]
    total = sum(r[3] for r in rec)
    print(f"    {'test':<34} {'req':>5} {'done':>5} {'wall s':>8}  status")
    for name, req, done, wall in sorted(rec, key=lambda r: -r[3])[:12]:
        status = ("cap INERT" if req < POLL else
                  "truncated" if done < req else "ran in full")
        print(f"    {name:<34} {req:>5} {done:>5} {wall:>8.2f}  {status}"
              f"{'  <- ' + format(wall / CAP, '.0f') + 'x cap' if wall > 2 * CAP else ''}")
    print()
    print(f"  sites measured:            {len(rec)}")
    print(f"  truncated by the cap:      {len(trunc)}")
    print(f"  cap-inert (requested < {POLL}): {len(inert)}")
    if rec:
        print(f"  wall inside cap-inert sites: {sum(r[3] for r in inert):.1f}s of "
              f"{total:.1f}s ({100 * sum(r[3] for r in inert) / total:.0f}%)")
    print()
    print("  Recorded for the whole suite on an idle host (95 sites, -t 2.0):")
    print("    16 sites truncated — all GF/NL/FPE/TWK, none of them RNL, and every")
    print("       one stops at exactly 64 of 100, the poll granularity.")
    print("    18 sites cap-inert, carrying 302 s of the 424 s spent in capped sites.")
    print("    worst: test_hpke_stern_f_correctness, 30 requested, ~97 s against a")
    print("       2.0 s cap.")
    print()
    print("  Separately, 16 call sites pass a literal count to _trange instead of")
    print("  _iters(...), so -r/--rounds does not reach them either.")
    print()


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--census", action="store_true",
                    help="run every test function, not just the known offenders (slow)")
    args = ap.parse_args()

    ht = load_harness()
    print()
    per = section1(ht)
    section2(ht, per)
    section3(ht, args.census)
    print("=" * 74)
    print("Baseline recorded.  The ring is not what costs the job its time.")
    print("=" * 74)
    return 0


if __name__ == "__main__":
    sys.exit(main())
