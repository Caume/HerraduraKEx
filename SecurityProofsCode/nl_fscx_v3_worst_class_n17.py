#!/usr/bin/env python3
"""nl_fscx_v3_worst_class_n17.py — TODO #257 item (3), fifteenth pass: does any key of
v3's worst LSB class fall BELOW the 5-row ceiling at n = 17?

nl_fscx_v3_linear_width.py (§11.53) proved a CEILING on v3's linear slope: the LSB row
of the addition gets no carry in, so every cycle through LSB-row masks is a function of
delta(B) mod 32 alone, and the least such cycle mean -- 1.4150, at delta(B) = 5 mod 8 --
bounds the worst key's slope from above at every width, n = 256 included.  What it left
open is the FLOOR: whether a cycle through carry-receiving rows undercuts that value.
Its n = 17 evidence was a 24-key UNIFORM sample, whose least key sits exactly on the
ceiling; only a few of those 24 keys are in the worst class at all.

This pass samples the worst class itself.  If a carry-receiving cycle can beat the
ceiling, it beats it on a key whose ceiling is already the lowest, so this is where a
floor below 1.4150 would show first.

  §1  THE DRAW.  NKEYS keys B < 2^17, seeded, uniform over delta(B) mod 8 = 5, disjoint
      from §11.53's 24.  CONTROL: delta mod 8 = 5 holds for every drawn key, and for
      about one key in eight of the full key space.
  §2  THE SOLVES.  Every key's certified exact linear slope (v3_round_mmc.c, rows
      5/5/7), from the pinned file.  Each must be CERTIFIED, and none may exceed its
      LSB-row value (the ceiling is a proof; a key above it is a solver bug).
  §3  THE FINDING.  How many keys sit exactly ON the ceiling, how many below, and the
      least.  None below means floor = ceiling on the worst class at n = 17; one below
      means the ceiling is not the floor, and v3's worst-key linear margin is not
      1.77x.
  §4  RE-SOLVE (not in --quick).  The least key is solved again and must reproduce.

  CAVEATS.  One width; a sample, not the class.  A floor at n = 17 is not a floor at
  n = 256: a carry-receiving cycle needs rows that wider widths have more of.

Exits non-zero if a finding stops reproducing.

Run:  python3 SecurityProofsCode/nl_fscx_v3_worst_class_n17.py [--quick | --regenerate]
      --quick      : §1-§3 from the pinned file (seconds)
      default      : also §4, one n = 17 solve (~5 min, 8 threads)
      --regenerate : solve the sample, resumable (~4.5 min per key at 8 threads)
"""

import argparse
import importlib.util
import json
import os
import random
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
PINNED = os.path.join(HERE, "nl_fscx_v3_worst_class_n17.json")
FAIL = []
N = 17
NKEYS = 96
SEED = 25703 * 100 + 17


def _load(name):
    path = os.path.join(HERE, name)
    spec = importlib.util.spec_from_file_location(name[:-3], path)
    mod = importlib.util.module_from_spec(spec)
    argv, sys.argv = sys.argv, [name]
    try:
        spec.loader.exec_module(mod)
    finally:
        sys.argv = argv
    return mod


LW = _load("nl_fscx_v3_linear_width.py")     # build(), solve(), d_low(), CEIL5, SAMPLE


def rule(title):
    print("\n" + "=" * 78 + "\n" + title + "\n" + "=" * 78)


def check(ok, msg):
    print("  [%s] %s" % ("PASS" if ok else "FAIL", msg))
    if not ok:
        FAIL.append(msg)


def worst(B):
    return LW.d_low(N, B, 5) % 8 == 5


def draw():
    old = set(LW.sample_keys(N))
    pool = [B for B in range(1 << N) if worst(B) and B not in old]
    return random.Random(SEED).sample(pool, NKEYS)


def regenerate():
    LW.build()
    ck = PINNED + ".partial"
    done = {}
    if os.path.exists(ck):
        with open(ck) as fh:
            done = {int(k): v for k, v in json.load(fh).items()}
    keys = draw()
    for i, B in enumerate(keys):
        if B in done:
            continue
        t0 = time.time()
        mu, rounds, cert, clen, _mu1, _v1 = LW.solve(N, B, 1)
        done[B] = [mu, rounds, cert, clen, round(time.time() - t0, 1)]
        with open(ck, "w") as fh:
            json.dump({str(k): v for k, v in done.items()}, fh)
        print("  %3d/%d  B = 0x%05x  mu = %.10f  certified %s  (%.0f s)"
              % (len(done), len(keys), B, mu, cert, done[B][4]), flush=True)
    with open(PINNED, "w") as fh:
        json.dump({"what": "v3 linear slope, n = 17, rows 5/5/7, keys with "
                           "delta(B) = 5 mod 8 (TODO #257 item 3)",
                   "seed": SEED, "n": N, "rows": [5, 5, 7],
                   "rows_per_key": "B -> [mu, howard rounds, certified, cycle length, seconds]",
                   "keys": {"%x" % B: done[B] for B in keys}}, fh, indent=1)
    os.remove(ck)
    print("pinned", PINNED)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--quick", action="store_true")
    ap.add_argument("--regenerate", action="store_true")
    a = ap.parse_args()
    if a.regenerate:
        regenerate()
        return
    print(__doc__.split("\n\n")[0])
    with open(PINNED) as fh:
        P = json.load(fh)
    rows = {int(k, 16): v for k, v in P["keys"].items()}
    keys = draw()

    rule("§1  The draw")
    check(sorted(rows) == sorted(keys) and len(keys) == NKEYS,
          "the pinned keys are exactly draw()'s %d, seeded" % NKEYS)
    check(all(worst(B) for B in keys) and not set(keys) & set(LW.sample_keys(N)),
          "every drawn key has delta(B) = 5 mod 8, and none is in §11.53's 24")
    frac = sum(1 for B in range(1 << N) if worst(B)) / float(1 << N)
    check(0.10 < frac < 0.15,
          "CONTROL: delta(B) = 5 mod 8 holds for %.1f%% of all 2^17 keys (about one "
          "in eight), so the class is not a handful of keys" % (100 * frac))

    rule("§2  The solves")
    mus = [rows[B][0] for B in keys]
    check(all(rows[B][2] for B in keys), "every solve is CERTIFIED")
    above = [B for B in keys if rows[B][0] > LW.CEIL5 + 1e-9]
    check(not above, "no key's slope exceeds its LSB-row value %.4f (%d above)"
          % (LW.CEIL5, len(above)))

    rule("§3  The finding")
    def split(r):
        return ([B for B in keys if abs(r[B][0] - LW.CEIL5) < 1e-9],
                [B for B in keys if r[B][0] < LW.CEIL5 - 1e-9])
    on, below = split(rows)
    least = min(keys, key=lambda B: rows[B][0])
    print("  %d keys: %d ON the ceiling, %d below; least %.10f (B = 0x%05x)"
          % (len(keys), len(on), len(below), rows[least][0], least))
    RECORD_ON, RECORD_BELOW = 96, 0               # the --regenerate run of the pinned file
    check(len(on) == RECORD_ON and len(below) == RECORD_BELOW,
          "the record: %d on the ceiling, %d below -- floor = ceiling on every sampled "
          "worst-class key" % (RECORD_ON, RECORD_BELOW))
    fake = dict(rows)
    fake[keys[0]] = [LW.CEIL5 - 1e-6] + rows[keys[0]][1:]
    fake[keys[1]] = [LW.CEIL5 + 1e-6] + rows[keys[1]][1:]
    f_on, f_below = split(fake)
    f_above = [B for B in keys if fake[B][0] > LW.CEIL5 + 1e-9]
    check(f_below == [keys[0]] and f_above == [keys[1]] and len(f_on) == NKEYS - 2,
          "CONTROL: one slope moved 1e-6 below the ceiling and one 1e-6 above are "
          "counted below and above, so a key under the ceiling would show")
    check(min(mus) >= LW.BAR_LIN, "every key clears v3's 0.8 bar (least %.4fx)"
          % (min(mus) / LW.BAR_LIN))

    if not a.quick:
        rule("§4  Re-solve the least key")
        LW.build()
        mu = LW.solve(N, least, 1)[0]
        check(abs(mu - rows[least][0]) < 1e-9, "B = 0x%05x reproduces: %.10f" % (least, mu))
    else:
        print("\n  §4 n/a under --quick")

    print()
    if FAIL:
        print("*** FAILED: %d finding(s) did not reproduce ***" % len(FAIL))
        sys.exit(1)
    print("*** OK: every finding reproduced ***")


if __name__ == "__main__":
    main()
