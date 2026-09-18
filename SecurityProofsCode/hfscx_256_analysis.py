#!/usr/bin/env python3
"""
hfscx_256_analysis.py — Empirical security tests for HFSCX-256-DM (TODO #34/#72, §11.9).

  §1  Avalanche on input bit flips                    (ideal mean = 128 / 256)
  §2  Avalanche on key bit flips (keyed MAC mode)     (ideal mean = 128 / 256)
  §3  Output Hamming weight + byte uniformity         (chi-square)
  §4  Collision sanity vs birthday bound              (run with --full for 2^17)
  §5  Length-extension resistance — naive forgery     (expected: 0 successes)
  §6  Domain separation: unkeyed vs keyed             (expected: all differ)
  §7  Fixed-point search                              (best-effort: orbit lengths > 1)

These tests rule out trivial weaknesses but do NOT constitute a formal proof.
Collision and preimage hardness rest on the NL-FSCX v1 PRF/OWF assumptions
(SecurityProofs.md §11.8.4 A1, §11.8.3 A2).

Runtime: ~60 s on a modest CPU at default trial counts; --full adds ~120 s for §4.
"""

import importlib.util
import math
import os
import sys
import time
from collections import Counter


# ── Load suite via importlib (suite filename has a space) ──────────────────
_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
_SPEC = importlib.util.spec_from_file_location(
    's', os.path.join(_ROOT, 'Herradura cryptographic suite.py'))
_SUITE = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_SUITE)
hfscx_256          = _SUITE.hfscx_256
BitArray           = _SUITE.BitArray
nl_fscx_revolve_v1 = _SUITE.nl_fscx_revolve_v1
nl_fscx_v1         = _SUITE.nl_fscx_v1
_HFSCX256_IV_BYTES = _SUITE._HFSCX256_IV_BYTES


SEP  = "═" * 72
SEP2 = "─" * 72


def popcount_bytes(b: bytes) -> int:
    return sum(bin(byte).count('1') for byte in b)


# ═══════════════════════════════════════════════════════════════════════════
# The SAC gate, as a REPLICATION (TODO #300)
#
# §1 and §2 both gated on |mean - 128| < 3.SE against a FRESH os.urandom sample
# every run.  That is a two-sided 3-sigma test, so a perfectly good hash fails
# it about one run in 370 BY CONSTRUCTION -- #299's defect, in the same file,
# one section over, left behind because §3 was the one that happened to fire.
#
# The null is well behaved: 24 independent blocks of 5 000 trials measured z in
# [-1.50, +1.84], median 0.33, none past 2 sigma.  So an exceedance here is a
# tail event rather than a bias, and the right response is #299's -- confirm it
# against a SECOND independent sample at a stricter level.  4.5 sigma takes the
# per-section false-failure rate from 2.7e-3 to about 1.9e-8, and costs the
# extra sample on only 0.27% of runs.
#
# Power is untouched, and that is the point: an avalanche bias worth the name
# misses 128 by many standard errors in EVERY sample.  The flip count is
# Binomial(256, 1/2), so sigma = 8 and SE = 8/sqrt(5000) = 0.113 -- a hash whose
# avalanche mean is off by a single bit sits at z = 8.8, comfortably past the
# 4.5 confirmation level in both samples, while the nominal tail does not.
# ═══════════════════════════════════════════════════════════════════════════
_SAC_TRIGGER = 3.0      # first-sample threshold, in standard errors
_SAC_CONFIRM = 4.5      # second-sample threshold; 1.9e-8 combined


def _sac_z(mean: float, std: float, trials: int) -> float:
    """Standardised distance of the avalanche mean from the ideal 128."""
    se = std / math.sqrt(trials) if std > 0 else float('inf')
    return abs(mean - 128.0) / se


def _sac_replicated(label: str, mean: float, std: float, trials: int,
                    resample) -> bool:
    """Gate on |mean-128|, confirming any exceedance against a fresh sample."""
    z = _sac_z(mean, std, trials)
    if z < _SAC_TRIGGER:
        print(f"  {label:<13}: PASS  (|mean−128| = {z:.2f}·SE < "
              f"{_SAC_TRIGGER}·SE)")
        return True
    print(f"  {label:<13}: {z:.2f}·SE from ideal — over {_SAC_TRIGGER}·SE, "
          f"confirming against a second independent sample")
    mean2, std2, _ = resample(trials)
    z2 = _sac_z(mean2, std2, trials)
    ok = z2 < _SAC_CONFIRM
    print(f"  {label:<13}: second sample mean {mean2:.3f} "
          f"({z2:.2f}·SE)  {'below' if ok else 'ABOVE'} {_SAC_CONFIRM}·SE")
    print(f"  {label:<13}: {'PASS' if ok else 'FAIL — off-ideal in two '
          'independent samples'}")
    return ok


# ═══════════════════════════════════════════════════════════════════════════
# §1 — Avalanche on input bit flips
# ═══════════════════════════════════════════════════════════════════════════
def section1_sample(trials: int):
    """One independent input-bit avalanche sample: (mean, std, elapsed)."""
    flips = []
    t0 = time.monotonic()
    for _ in range(trials):
        msg = os.urandom(16)
        h0 = hfscx_256(msg)
        bit = int.from_bytes(os.urandom(2), 'big') % (8 * 16)
        msg_arr = bytearray(msg)
        msg_arr[bit // 8] ^= 1 << (bit % 8)
        h1 = hfscx_256(bytes(msg_arr))
        flips.append(popcount_bytes(bytes(a ^ b for a, b in zip(h0, h1))))
    elapsed = time.monotonic() - t0
    mean = sum(flips) / trials
    std  = math.sqrt(sum((f - mean) ** 2 for f in flips) / trials)
    return mean, std, elapsed, flips


def section1(trials: int = 5_000) -> bool:
    print(SEP)
    print(f"§1 — Avalanche on input bit flips  ({trials} trials, msg=16 B)")
    print(SEP)
    mean, std, elapsed, flips = section1_sample(trials)
    print(f"  Ideal mean   : 128.0")
    print(f"  Mean         : {mean:.3f}")
    print(f"  Std dev      : {std:.3f}")
    print(f"  Min / Max    : {min(flips)} / {max(flips)}")
    sac_ok = _sac_replicated("SAC", mean, std, trials,
                             lambda t: section1_sample(t)[:3])
    print(f"  Time         : {elapsed:.1f} s")
    return sac_ok


# ═══════════════════════════════════════════════════════════════════════════
# §2 — Avalanche on key bit flips (keyed MAC mode)
# ═══════════════════════════════════════════════════════════════════════════
def section2_sample(trials: int):
    """One independent key-bit avalanche sample: (mean, std, elapsed)."""
    iv_const = int.from_bytes(_HFSCX256_IV_BYTES, 'big')
    flips = []
    t0 = time.monotonic()
    for _ in range(trials):
        msg = os.urandom(16)
        K = int.from_bytes(os.urandom(32), 'big')
        h0 = hfscx_256(msg, iv=BitArray(256, K ^ iv_const))
        bit = int.from_bytes(os.urandom(1), 'big') % 256
        h1 = hfscx_256(msg, iv=BitArray(256, (K ^ (1 << bit)) ^ iv_const))
        flips.append(popcount_bytes(bytes(a ^ b for a, b in zip(h0, h1))))
    elapsed = time.monotonic() - t0
    mean = sum(flips) / trials
    std  = math.sqrt(sum((f - mean) ** 2 for f in flips) / trials)
    return mean, std, elapsed, flips


def section2(trials: int = 5_000) -> bool:
    print(SEP)
    print(f"§2 — Avalanche on key bit flips  ({trials} trials, keyed MAC)")
    print(SEP)
    mean, std, elapsed, flips = section2_sample(trials)
    print(f"  Ideal mean   : 128.0")
    print(f"  Mean         : {mean:.3f}")
    print(f"  Std dev      : {std:.3f}")
    print(f"  Min / Max    : {min(flips)} / {max(flips)}")
    sac_ok = _sac_replicated("Key-SAC", mean, std, trials,
                             lambda t: section2_sample(t)[:3])
    print(f"  Time         : {elapsed:.1f} s")
    return sac_ok


# ═══════════════════════════════════════════════════════════════════════════
# §3 — Output Hamming weight + byte uniformity (chi-square)
# ═══════════════════════════════════════════════════════════════════════════
def _byte_chi2(trials: int):
    """One independent sample: (chi2, mean weight, std, elapsed)."""
    weights = []
    byte_counts = Counter()
    t0 = time.monotonic()
    for _ in range(trials):
        h = hfscx_256(os.urandom(16))
        weights.append(popcount_bytes(h))
        for b in h:
            byte_counts[b] += 1
    elapsed = time.monotonic() - t0
    mean = sum(weights) / trials
    std = math.sqrt(sum((w - mean) ** 2 for w in weights) / trials)
    # Byte distribution: 32 bytes/digest x trials, 256 buckets
    expected = trials * 32 / 256
    chi2 = sum((byte_counts.get(v, 0) - expected) ** 2 / expected
               for v in range(256))
    return chi2, mean, std, elapsed


def section3(trials: int = 5_000) -> bool:
    print(SEP)
    print(f"§3 — Output Hamming weight + byte uniformity  ({trials} trials)")
    print(SEP)
    # chi2(0.001, 255) ~ 330.5; chi2(0.05, 255) ~ 293.2; chi2(0.95, 255) ~ 219.0
    P05, P001 = 293.2, 330.5
    chi2, mean, std, elapsed = _byte_chi2(trials)
    print(f"  Mean weight    : {mean:.3f}  (ideal 128.0)")
    print(f"  Weight std dev : {std:.3f}  (ideal ≈ 8.0 = √(256/4))")
    print(f"  Byte chi²      : {chi2:.1f}  (df=255, expected ≈ 255)")
    print(f"  Critical χ²    : 0.05→{P05},  0.001→{P001}")

    # THE GATE IS A REPLICATION, NOT A SINGLE TEST, and the reason is that this
    # script's exit status is a CI gate (TODO #291).  `chi2 < 293.2` is the
    # p = 0.05 critical value applied to a FRESH os.urandom sample every run, so
    # a perfectly uniform hash fails it one run in twenty BY CONSTRUCTION -- and
    # it did, on the PR for TODO #297, with 338.7 against a measured null of
    # median 251.1 and 2/40 samples over 293.2, i.e. exactly the nominal rate.
    # That is the defect class CLAUDE.md's Testing section names: a
    # probabilistic property asserted as a deterministic one.  A flaky gate is
    # worse than no gate, because the first response to a known-flaky failure is
    # to re-run it, and that is also the response to a real one.
    #
    # So an exceedance is CONFIRMED against a second independent sample at the
    # 0.001 level before it counts: false-failure rate 0.05 x 0.001 = 5e-5
    # rather than 1 in 20, and the extra ~4 s is paid only on the 5% of runs
    # that need it.  Power is essentially untouched -- a hash biased enough to
    # matter puts chi2 in the thousands over 160,000 byte samples, not at 300.
    ok = chi2 < P05
    if not ok:
        print(f"  Uniformity     : over the 0.05 critical value — "
              f"confirming against a second independent sample")
        chi2b, _, _, elapsed_b = _byte_chi2(trials)
        elapsed += elapsed_b
        ok = chi2b < P001
        print(f"  Byte chi² (#2) : {chi2b:.1f}  "
              f"({'below' if ok else 'ABOVE'} the 0.001 critical value)")
    print(f"  Uniformity     : {'PASS' if ok else 'FAIL — non-uniform in two independent samples'}")
    print(f"  Time           : {elapsed:.1f} s")
    return ok


# §4 — Collision sanity (no accidental collisions far below birthday bound)
# ═══════════════════════════════════════════════════════════════════════════
def section4(full: bool) -> bool:
    print(SEP)
    if not full:
        print("§4 — Collision sanity  (run with --full for 2^17 trials)")
        print(SEP)
        return True   # not run is not a failed finding
    trials = 1 << 17  # 131 072 — birthday at n=256 is 2^128; expected: 0
    print(f"§4 — Collision sanity  ({trials} trials, expected 0 collisions)")
    print(SEP)
    seen = set()
    collisions = 0
    t0 = time.monotonic()
    for i in range(trials):
        h = hfscx_256(i.to_bytes(8, 'big'))
        if h in seen:
            collisions += 1
        seen.add(h)
        if (i + 1) % 20_000 == 0:
            print(f"  ... {i+1:>8d} / {trials}  collisions={collisions}  "
                  f"({time.monotonic()-t0:.0f}s)")
    elapsed = time.monotonic() - t0
    print(f"  Collisions   : {collisions}")
    print(f"  Result       : {'PASS' if collisions == 0 else 'FAIL'}")
    print(f"  Time         : {elapsed:.1f} s")
    return collisions == 0


# ═══════════════════════════════════════════════════════════════════════════
# §5 — Length-extension resistance: naive forgery from published digest fails
# ═══════════════════════════════════════════════════════════════════════════
def section5(trials: int = 200) -> None:
    print(SEP)
    print(f"§5 — Length-extension resistance  ({trials} naive forgery trials)")
    print(SEP)
    print("    A length-extension attack treats the published digest H(M) as")
    print("    the chain state and continues compression with attacker-chosen")
    print("    blocks. With finalization, this should never produce H(M||X).")
    successes = 0
    t0 = time.monotonic()
    for _ in range(trials):
        msg = os.urandom(32)
        ext = os.urandom(32)
        h_msg = hfscx_256(msg)
        # Naive forgery: forged_state = compression(h_msg as state, ext as block)
        st = BitArray(256, int.from_bytes(h_msg, 'big'))
        blk = BitArray(256, int.from_bytes(ext, 'big'))
        forged = nl_fscx_revolve_v1(st, blk, 64).uint.to_bytes(32, 'big')
        # Real digest of msg || ext
        real = hfscx_256(msg + ext)
        if forged == real:
            successes += 1
    elapsed = time.monotonic() - t0
    print(f"  Successful naive extensions : {successes}/{trials}  "
          f"(expected 0)")
    print(f"  Result                      : {'PASS' if successes == 0 else 'FAIL'}")
    print(f"  Time                        : {elapsed:.1f} s")
    return successes == 0


# ═══════════════════════════════════════════════════════════════════════════
# §6 — Domain separation: unkeyed vs keyed yield different outputs
# ═══════════════════════════════════════════════════════════════════════════
def section6(trials: int = 1_000) -> None:
    print(SEP)
    print(f"§6 — Domain separation: unkeyed vs keyed  ({trials} trials)")
    print(SEP)
    iv_const = int.from_bytes(_HFSCX256_IV_BYTES, 'big')
    differ = 0
    examined = 0
    t0 = time.monotonic()
    for _ in range(trials):
        msg = os.urandom(16)
        K = int.from_bytes(os.urandom(32), 'big')
        if K == 0:
            continue  # by construction: keyed(K=0) == unkeyed
        examined += 1
        h_un  = hfscx_256(msg)
        h_key = hfscx_256(msg, iv=BitArray(256, K ^ iv_const))
        if h_key != h_un:
            differ += 1
    elapsed = time.monotonic() - t0
    print(f"  Domains differ : {differ}/{examined}")
    print(f"  Result         : {'PASS' if differ == examined else 'FAIL'}")
    print(f"  Time           : {elapsed:.1f} s")
    return differ == examined


# ═══════════════════════════════════════════════════════════════════════════
# §7 — Fixed-point search on the compression function (best-effort)
# ═══════════════════════════════════════════════════════════════════════════
def section7(trials: int = 200) -> None:
    print(SEP)
    print(f"§7 — Fixed-point search on C_DM(s, m) = F1^64(s, m) ⊕ s  "
          f"({trials} (s, m) pairs)")
    print(SEP)
    print("    With Davies-Meyer compression (deployed v1.9.0), a fixed point")
    print("    requires F1^64(s, m) = 0 — a preimage of zero under A2, costing")
    print("    Ω(2^128) work.  We search for this condition directly.")
    fps = 0
    near_fps = 0  # within 1 bit (F1^64(s,m) has ≤1 bit set)
    t0 = time.monotonic()
    for _ in range(trials):
        s = BitArray(256, int.from_bytes(os.urandom(32), 'big'))
        m = BitArray(256, int.from_bytes(os.urandom(32), 'big'))
        out = nl_fscx_revolve_v1(s, m, 64)
        if out.uint == 0:
            fps += 1
        elif bin(out.uint).count('1') <= 1:
            near_fps += 1
    elapsed = time.monotonic() - t0
    print(f"  F1^64(s,m)==0 (fixed pts): {fps}/{trials}    (expected: 0)")
    print(f"  Near-zero (≤1 bit set)   : {near_fps}/{trials}  (expected ≈ 0)")
    print(f"  Time                     : {elapsed:.1f} s")
    return fps == 0


# ═══════════════════════════════════════════════════════════════════════════
# Main
# ═══════════════════════════════════════════════════════════════════════════
def main() -> int:
    full = '--full' in sys.argv
    print()
    print("hfscx_256_analysis.py — HFSCX-256-DM empirical security tests")
    print(f"  Backs SecurityProofs.md §11.9 (TODO #34)")
    print()
    findings = [("§1 input-bit SAC", section1()),
                ("§2 key-bit SAC", section2()),
                ("§3 byte uniformity", section3()),
                ("§4 no collisions far below the birthday bound", section4(full)),
                ("§5 length-extension resistance", section5()),
                ("§6 keyed/unkeyed domain separation", section6()),
                ("§7 no DM fixed points", section7())]
    print()
    print(SEP)
    bad = [name for name, ok in findings if not ok]
    if bad:
        print("*** FAILED: %d finding(s) stopped reproducing: %s ***"
              % (len(bad), ", ".join(bad)))
    else:
        print("*** OK: all %d findings reproduce ***" % len(findings))
    print("END hfscx_256_analysis.py")
    print(SEP)
    return 1 if bad else 0


if __name__ == '__main__':
    sys.exit(main())
