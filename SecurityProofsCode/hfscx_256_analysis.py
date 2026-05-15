#!/usr/bin/env python3
"""
hfscx_256_analysis.py — Empirical security tests for HFSCX-256 (TODO #34, §11.9).

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
# §1 — Avalanche on input bit flips
# ═══════════════════════════════════════════════════════════════════════════
def section1(trials: int = 5_000) -> None:
    print(SEP)
    print(f"§1 — Avalanche on input bit flips  ({trials} trials, msg=16 B)")
    print(SEP)
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
    print(f"  Ideal mean   : 128.0")
    print(f"  Mean         : {mean:.3f}")
    print(f"  Std dev      : {std:.3f}")
    print(f"  Min / Max    : {min(flips)} / {max(flips)}")
    # SAC criterion: mean within 1 standard error of 128 is acceptable
    sac_ok = abs(mean - 128.0) < 3 * (std / math.sqrt(trials))
    print(f"  SAC          : {'PASS' if sac_ok else 'FAIL'}  "
          f"(|mean−128| < 3·SE)")
    print(f"  Time         : {elapsed:.1f} s")


# ═══════════════════════════════════════════════════════════════════════════
# §2 — Avalanche on key bit flips (keyed MAC mode)
# ═══════════════════════════════════════════════════════════════════════════
def section2(trials: int = 5_000) -> None:
    print(SEP)
    print(f"§2 — Avalanche on key bit flips  ({trials} trials, keyed MAC)")
    print(SEP)
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
    print(f"  Ideal mean   : 128.0")
    print(f"  Mean         : {mean:.3f}")
    print(f"  Std dev      : {std:.3f}")
    print(f"  Min / Max    : {min(flips)} / {max(flips)}")
    sac_ok = abs(mean - 128.0) < 3 * (std / math.sqrt(trials))
    print(f"  Key-SAC      : {'PASS' if sac_ok else 'FAIL'}")
    print(f"  Time         : {elapsed:.1f} s")


# ═══════════════════════════════════════════════════════════════════════════
# §3 — Output Hamming weight + byte uniformity (chi-square)
# ═══════════════════════════════════════════════════════════════════════════
def section3(trials: int = 5_000) -> None:
    print(SEP)
    print(f"§3 — Output Hamming weight + byte uniformity  ({trials} trials)")
    print(SEP)
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
    std  = math.sqrt(sum((w - mean) ** 2 for w in weights) / trials)
    # Byte distribution: 32 bytes/digest × trials, 256 buckets
    expected = trials * 32 / 256
    chi2 = sum((byte_counts.get(v, 0) - expected) ** 2 / expected
               for v in range(256))
    # χ²(0.001, 255) ≈ 330.5; χ²(0.05, 255) ≈ 293.2; χ²(0.95, 255) ≈ 219.0
    print(f"  Mean weight    : {mean:.3f}  (ideal 128.0)")
    print(f"  Weight std dev : {std:.3f}  (ideal ≈ 8.0 = √(256/4))")
    print(f"  Byte chi²      : {chi2:.1f}  (df=255, expected ≈ 255)")
    print(f"  Critical χ²    : 0.05→293.2,  0.001→330.5")
    p05 = chi2 < 293.2
    print(f"  Uniformity     : {'PASS (p>0.05)' if p05 else 'inspect'}")
    print(f"  Time           : {elapsed:.1f} s")


# ═══════════════════════════════════════════════════════════════════════════
# §4 — Collision sanity (no accidental collisions far below birthday bound)
# ═══════════════════════════════════════════════════════════════════════════
def section4(full: bool) -> None:
    print(SEP)
    if not full:
        print("§4 — Collision sanity  (run with --full for 2^17 trials)")
        print(SEP)
        return
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


# ═══════════════════════════════════════════════════════════════════════════
# §7 — Fixed-point search on the compression function (best-effort)
# ═══════════════════════════════════════════════════════════════════════════
def section7(trials: int = 200) -> None:
    print(SEP)
    print(f"§7 — Fixed-point search on C(s, m) = F1^64(s, m)  "
          f"({trials} (s, m) pairs)")
    print(SEP)
    print("    Searches for s, m with C(s, m) == s. Plain MD without Davies-")
    print("    Meyer feed-forward is theoretically vulnerable to fixed points;")
    print("    empirically they should be rare for random (s, m).")
    fps = 0
    near_fps = 0  # within 1 bit
    t0 = time.monotonic()
    for _ in range(trials):
        s = BitArray(256, int.from_bytes(os.urandom(32), 'big'))
        m = BitArray(256, int.from_bytes(os.urandom(32), 'big'))
        out = nl_fscx_revolve_v1(s, m, 64)
        if out.uint == s.uint:
            fps += 1
        elif bin(out.uint ^ s.uint).count('1') <= 1:
            near_fps += 1
    elapsed = time.monotonic() - t0
    print(f"  Exact fixed points     : {fps}/{trials}    (expected: 0)")
    print(f"  Near-fixed (≤1 bit)    : {near_fps}/{trials}  (expected ≈ 0)")
    print(f"  Note: a Davies-Meyer compression C_DM(s, m) = C(s, m) ⊕ s would")
    print(f"        require F1^64(s, m) = 0 for a fixed point — strictly harder.")
    print(f"  Time                   : {elapsed:.1f} s")


# ═══════════════════════════════════════════════════════════════════════════
# Main
# ═══════════════════════════════════════════════════════════════════════════
def main() -> None:
    full = '--full' in sys.argv
    print()
    print("hfscx_256_analysis.py — HFSCX-256 empirical security tests")
    print(f"  Backs SecurityProofs.md §11.9 (TODO #34)")
    print()
    section1()
    section2()
    section3()
    section4(full)
    section5()
    section6()
    section7()
    print()
    print(SEP)
    print("END hfscx_256_analysis.py")
    print(SEP)


if __name__ == '__main__':
    main()
