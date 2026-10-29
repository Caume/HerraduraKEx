#!/usr/bin/env python3
"""v2_v3_rating_review.py — TODO #345: re-review the NL-FSCX v2 and v3 block-cipher rows.

TODO #248 (v2_family_rating_review.py) kept HSKE-NL-A2 and `twk` demo-only.  It
replaced their rationale -- the absent PRP/SPRP reduction is not the standard the
rest of SECURITY.md uses -- and named what would earn the promotion: the linear
axis measured at realistic width, where the trend pointed.  TODO #343 (closed
v9.5.65) has since corrected two methodology errors in that measurement and
re-measured both axes over real keys to n = 23.  This is the review #248 asked for,
and it covers four rows, not two: HSKE-NL-A3 and `twk --v3` were demo-only for
exactly A2's stated reasons, on evidence at least as strong, so promoting v2 alone
would leave SECURITY.md recommending a demo-only variant over a production-track one.

  §1  THE STANDARD.  #248 §2 named six production-track rows resting on a named
      conjecture with no reduction.  TODO #346 demoted three of them (HFSCX-256,
      HPKS-WOTS, HPKS-XMSS) for a FINDING -- zero proven margin on NL-FSCX v1's
      compression function -- not for a change of standard; the other three are
      still production-track on it.  If either stops holding, the premise is gone
      and this gate FAILS.

  §2  v2, FROM THE PINNED n = 23 RECORD (v2_series_n23.json), not from prose.
      E[mu] = 2.813 / 1.482 is 1.65x / 1.71x the share-held bar 1.710 / 0.865, more
      than 5 SE above it, risen from n = 20, with 1.7% / 2.6% of keys below it.

  §3  v3, FROM ITS GATES' RECORDS.  The differential floor 4 - log2(5) = 1.6781 is
      PROVEN and clears v3's bar of 1.6 at every width.  The linear slope clears 0.8
      for every key measured at n = 10 (exhaustive), 14 and 17 (sampled), least
      1.47x; its median at n = 17 (2.08x) is above v2's key AVERAGE at n = 23.

  §4  THE EVIDENCE AGAINST, CARRIED.  v2's one-round probability-1 differential is
      CONSTRUCTED against the shipped round (CONTROL: a random difference fails);
      the margins the conjectures rest on are printed with what erodes them.

  §5  THE CONSTRAINTS, RE-DERIVED against the shipped code: both versions are
      deterministic; v2's affine screen still rejects; v3 has no key check.

  §6  THE DOCUMENTS AGREE WITH THE VERDICT.  The four SECURITY.md rows read
      "Production-track (conjectured)", each names its conjecture and TODO #345,
      the A2 row still says to prefer HSKE-NL-A3, and spec/ says `production` for
      all four.  CONTROL: the row check FIRES on the pre-#345 status.

  §7  VERDICT.  Prose.

Reads pinned records only, so it cannot flake.  About 20 s.

Exits non-zero if a finding stops reproducing.

Run:  python3 SecurityProofsCode/v2_v3_rating_review.py
"""

import importlib.util
import json
import math
import os
import random
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
FAIL = []
NAME = {0: "differential", 1: "linear"}

# The six rows #248 §2 named as production-track on a named conjecture alone: three
# still are, and three were demoted by TODO #346 for a finding against NL-FSCX v1.
STANDARD = ("HSKE-NL-A1", "HKEX-RNL", "ZKP-RNL Σ-protocol")
DEMOTED_346 = ("HFSCX-256 / HFSCX-256-DS", "HPKS-WOTS", "HPKS-XMSS")

# The four rows this review moves: SECURITY.md heading -> (spec/ id, version, the
# numbers its conjecture must name).
REVIEWED = {
    "HSKE-NL-A2":              ("hske-nla2", 2, ("1.71", "0.865")),
    "Tweakable wide-block":    ("twk",       2, ("1.71", "0.865")),
    "HSKE-NL-A3":              ("hske-nla3", 3, ("0.8",)),
    "Tweakable wide-block V3": ("twk-v3",    3, ("0.8",)),
}
STATUS = "Production-track (conjectured)"


def rule(t):
    print("\n" + "=" * 78)
    print(t)
    print("=" * 78)


def check(cond, what):
    print("  [%s] %s" % ("PASS" if cond else "FAIL", what))
    if not cond:
        FAIL.append(what)
    return cond


def _load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    argv, sys.argv = sys.argv, [os.path.basename(path)]
    try:
        spec.loader.exec_module(mod)
    finally:
        sys.argv = argv
    return mod


H = _load(os.path.join(ROOT, "Herradura cryptographic suite.py"), "_suite")
S23 = _load(os.path.join(HERE, "v2_series_n23.py"), "v2_series_n23")
LW = _load(os.path.join(HERE, "nl_fscx_v3_linear_width.py"), "nl_fscx_v3_linear_width")
TS, KS = S23.TS, S23.KS


def security_rows(text):
    """{heading: (status cell, whole row)} for SECURITY.md's protocol table."""
    rows, on = {}, False
    for line in text.splitlines():
        if line.startswith("## "):
            on = line.strip() == "## Protocol Status"
            continue
        if not on or not line.startswith("| **"):
            continue
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        m = re.match(r"\*\*(.+?)\*\*", cells[0])
        if m:
            rows.setdefault(m.group(1).strip(), (cells[1], line))
    return rows


def row_ok(status, row, nums):
    """The four conditions §6 holds each reviewed row to."""
    return (status.startswith(STATUS) and "TODO #345" in row
            and "Conjecture" in row and all(x in row for x in nums))


# ═══════════════════════════════════════════════════════════════════════════
def section_1(rows):
    rule("§1  The standard: production-track on a named conjecture")
    for h in STANDARD + DEMOTED_346:
        st = rows.get(h, ("(missing)", ""))[0]
        print("    %-26s %s" % (h, st[:60]))
    check(all(rows.get(h, ("",))[0].startswith("Production-track") for h in STANDARD),
          "the three of #248 §2's six not reached by TODO #346 are still production-track, "
          "none on a reduction")
    def _346(h):
        st, row = rows.get(h, ("", ""))
        if st.startswith("Demo-only"):
            return "TODO #346" in row
        # v10.0.0: TODO #347's 3n/4 rounds restored them, on this same standard.
        return (st.startswith("Production-track") and "Demoted by TODO #346" in row
                and "Restored by TODO #347 (v10.0.0)" in row)
    check(all(_346(h) for h in DEMOTED_346),
          "the other three were demoted for TODO #346's finding, which the row names -- "
          "a finding against NL-FSCX v1, not a change of standard -- and are demo-only "
          "or, since v10.0.0, restored by TODO #347 on the same standard")
    print("""
  So the bar is a NAMED CONJECTURE + quantitative cryptanalysis at the criterion
  + no known attack.  HSKE-NL-A1 meets it only under a per-key data limit since
  TODO #346 derived its criterion; HFSCX-256 met it at zero margin, which #346
  judged not enough.  The question for the four rows below is whether they meet the same bar,
  not whether they meet a higher one.""")


def section_2():
    rule("§2  v2: the pinned key sample at n = 23 against the share-held bar")
    rec = json.load(open(S23.PINNED))
    rec_old = json.load(open(TS.PINNED))
    S = KS.strata(S23.N)
    M23 = S23.measures23(rec["rows"], S)
    M = TS.measures(rec_old)
    out = {}
    for axis in (0, 1):
        e = M23[axis]
        # the share-held bar of §11.60: bar / (3/4 - lambda), lambda the pooled share
        pts = [S23.DS.share(rec_old, n, axis) for n in S23.DS.WIDTHS if n >= S23.DS.LATE]
        wt = [1 / p[1] ** 2 for p in pts]
        lam = sum(w * p[0] for w, p in zip(wt, pts)) / sum(wt)
        barmu = TS.BAR[axis] / (0.75 - lam)
        m, s = e["mu"]
        m20, s20 = M[(20, axis)]["mu"]
        z = (m - m20) / math.hypot(s, s20)
        out[axis] = (m, s, barmu, lam, e["lam"][0], e["fail"])
        print("\n  %s: E[mu](23) = %.3f +/- %.3f, bar %.3f (lambda %.4f): %.2fx, %.0f SE"
              % (NAME[axis], m, s, barmu, lam, m / barmu, (m - barmu) / s))
        check(m / barmu > 1.5 and (m - barmu) / s > 5,
              "%s: E[mu] at n = 23 is %.2fx the share-held bar, more than 5 SE above it"
              % (NAME[axis], m / barmu))
        check(z > 3, "%s: and it rose from n = 20 (%.3f -> %.3f, %.1f SE)"
              % (NAME[axis], m20, m, z))
        check(e["fail"] < 0.03, "%s: %.1f%% of keys sit below the deployed criterion"
              % (NAME[axis], 100 * e["fail"]))
        print("    the conjecture this rests on: E[mu] at n = 256 >= %.3f, i.e. it may "
              "fall to %.0f%% of its n = 23 value" % (barmu, 100 * barmu / m))
    return out


def section_3(v2):
    rule("§3  v3: a proven differential floor, and the linear slope by key")
    bar_d = 256 / H.R3_VALUE
    bar_l = 128 / H.R3_VALUE
    check(abs(LW.FLOOR_DIFF - (4 - math.log2(5))) < 1e-12 and LW.FLOOR_DIFF >= bar_d,
          "differential: the proven round-level floor 4 - log2(5) = %.4f clears v3's "
          "bar 256/%d = %.2f at every width (%.3fx)"
          % (LW.FLOOR_DIFF, H.R3_VALUE, bar_d, LW.FLOOR_DIFF / bar_d))
    check(abs(LW.BAR_LIN - bar_l) < 1e-12, "linear: v3's bar is 128/%d = %.2f"
          % (H.R3_VALUE, bar_l))
    print("\n     n   keys    least   median   least/0.8")
    for n, (k, _, lin, _) in sorted(LW.RECORD.items()):
        print("  %4d   %4d   %.4f   %.4f   %.2fx" % (n, k, lin[0], lin[2], lin[0] / bar_l))
    check(all(lin[0] / bar_l > 1.4 for _, _, lin, _ in LW.RECORD.values()),
          "linear: every key measured at n = %s clears 0.8, the least at %.2fx"
          % ("/".join(str(n) for n in sorted(LW.RECORD)),
             min(lin[0] for _, _, lin, _ in LW.RECORD.values()) / bar_l))
    med17 = LW.RECORD[17][2][2] / bar_l
    v2l = v2[1][0] / v2[1][2]
    check(med17 > v2l, "linear: v3's MEDIAN key at n = 17 (%.2fx) is above v2's key "
          "AVERAGE at n = 23 (%.2fx), and v3's differential is proven where v2's is "
          "measured" % (med17, v2l))
    print("  ceiling, proven (§11.53.3): the worst key's linear slope at n = 256 is at "
          "most %.4f, %.2fx the bar" % (LW.CEIL5, LW.CEIL5 / bar_l))


def section_4(v2):
    rule("§4  The evidence against, carried rather than argued away")
    n = 16
    msb = H.BitArray(n, 1 << (n - 1))
    a = H._m_inv(msb)
    rng = random.Random(345)
    hit = ctrl = 0
    T = 200
    for _ in range(T):
        B = H.BitArray(n, rng.randrange(1 << n))
        x = H.BitArray(n, rng.randrange(1 << n))
        d = (H.nl_fscx_v2(x, B) ^ H.nl_fscx_v2(x ^ a, B)).uint
        hit += d == msb.uint
        r = H.BitArray(n, rng.randrange(1, 1 << n))
        ctrl += (H.nl_fscx_v2(x, B) ^ H.nl_fscx_v2(x ^ r, B)).uint == H.fscx(r, H.BitArray(n, 0)).uint
    check(hit == T, "v2: input difference M^-1(2^(n-1)) = 0x%04x passes one shipped round "
          "as 2^(n-1) with probability 1 (%d/%d, n = %d): no per-round differential floor"
          % (a.uint, hit, T, n))
    check(ctrl < T // 2, "CONTROL: a random difference does not pass linearly (%d/%d)"
          % (ctrl, T))
    print("""
  What erodes the v2 margin, none of it scored here:
    - n = 23 -> 256 is an 11x extrapolation; the share lambda ~ 1/6 is a reading
      of eight widths, and the linear one passes its 0.015 tolerance by 0.001
      (v2_series_n23.py) -- in the favourable direction;
    - each class step adds less than the one before (+0.37 +0.38 +0.16 +0.22
      differential), so a level -- or a later turn-down -- is not excluded;
    - trails are not hulls: clustering cost 10-20%% of the margin at n = 16 and
      grows slowly with width (§11.44);
    - the figures are key AVERAGES; the short-arc class (arcs of about 12 bits or
      fewer, ~2^-123 of keys at n = 256) stays weak at any width and is not
      screened, by design (§11.61-§11.63).
  So v2's margin is about %.2fx / %.2fx, measured and extrapolated, not proven.
  v3's is proven on the differential axis (1.05x) and measured on the linear one,
  under a proven 1.77x ceiling: wider where it is measured, but also capped."""
          % (v2[0][0] / v2[0][2], v2[1][0] / v2[1][2]))


def section_5():
    rule("§5  The usage constraints, re-derived against the shipped code")
    rng = random.Random(7)
    K = H.BitArray(256, rng.getrandbits(256))
    P = H.BitArray(256, rng.getrandbits(256))
    d2 = H.nl_fscx_revolve_v2(P, K, H.R_VALUE) == H.nl_fscx_revolve_v2(P, K, H.R_VALUE)
    d3 = H.nl_fscx_revolve_v3(P, K, H.R3_VALUE) == H.nl_fscx_revolve_v3(P, K, H.R3_VALUE)
    check(d2 and d3, "DETERMINISTIC, both versions: identical (P, K) gives identical E -- "
          "embed a nonce, or prefer HSKE-NL-A1 when messages share a key")
    check(not H.nl_v2_key_is_valid(H.BitArray(256, 0)) and H.nl_v2_key_is_valid(K),
          "v2's affine screen still rejects delta = 0 and accepts a random key")
    check(not hasattr(H, "nl_v3_key_is_valid"),
          "v3 has no key check: both weak classes dissolve under chi (§11.34.4)")


def section_6(rows):
    rule("§6  The documents agree with the verdict")
    spec = json.load(open(os.path.join(ROOT, "spec", "herradura-protocol-spec.json")))
    st = {p["id"]: p["security"]["status"] for p in spec["protocols"]}
    for h, (pid, ver, nums) in REVIEWED.items():
        status, row = rows.get(h, ("(missing)", ""))
        check(row_ok(status, row, nums), "SECURITY.md '%s' reads '%s...', names its "
              "conjecture (%s) and TODO #345" % (h, status[:30], ", ".join(nums)))
        check(st.get(pid) == "production", "spec/ '%s' is 'production' (is '%s')"
              % (pid, st.get(pid)))
    a2 = rows.get("HSKE-NL-A2", ("", ""))[1]
    check(re.search(r"prefer[^|]{0,40}HSKE-NL-A3", a2) is not None,
          "the HSKE-NL-A2 row still says to prefer HSKE-NL-A3")
    status, row = rows["HSKE-NL-A2"]
    old = "Demo-only — reviewed twice; the gap is one specific measurement"
    check(not row_ok(old, row.replace(status, old), REVIEWED["HSKE-NL-A2"][2]),
          "CONTROL: the row check FIRES on the pre-#345 status")
    for h in ("HPKE-NL3", "HSKE-Duplex-V3", "FPE-V3"):
        print("    out of scope, unchanged: %-16s %s" % (h, rows.get(h, ("?",))[0][:50]))


def section_7():
    rule("§7  Verdict")
    print("""**HSKE-NL-A2, `twk`, HSKE-NL-A3 and `twk --v3` move to Production-track
(conjectured).  The four rows move together.**

  WHY NOW.  #248 withheld the promotion because the binding axis had one
  small-width measurement and an unresolved width trend.  The axis is now
  measured exactly, over keys, on both axes, to n = 23 (§2); the methodology
  errors that flattered it are corrected; the margin rose at every width.  That
  is the bar the six rows of §1 are held to, and on the linear axis A2 is better
  covered than HSKE-NL-A1, which sits at production-track today.

  THE CONJECTURES, NAMED.  v2: the key-averaged per-round trail cost at n = 256
  stays at or above 1.71 differential and 0.865 linear -- about 60% of its
  n = 23 value.  v3: the per-round linear trail slope at n = 256 stays at or
  above 0.8 for every key outside a negligible class; the differential axis is
  proven.  Each row states its conjecture.  Neither is a bound.

  WHAT DOES NOT CHANGE.  No reduction exists; trails are not hulls; the margins
  are modest (§4).  Both versions stay deterministic.  v2 keeps its affine
  screen and leaves the short-arc class documented rather than screened (a new
  refusal would make an existing --algo accept less).  HSKE-NL-A3 stays the
  variant to prefer when security is critical: a proven differential floor
  rather than a measured one.  Better-founded, not proven -- its linear floor is
  0.19 against 0.8.  No wire format, key or ciphertext changes.

  OUT OF SCOPE.  HPKE-NL and HPKE-NL3 are demo-only for Pohlig-Hellman, which no
  NL-FSCX result reaches; HSKE-Duplex(-V3) is research (a sponge needs a
  different argument); FPE / FPE-V3 are broken as named.

  WHAT WOULD UNDO IT.  A v2 measurement past n = 23 below the bar, the linear
  share failing in the UNFAVOURABLE direction, a v3 key below 0.8 outside a
  negligible class, or any attack.  TODO #257 carries the measurements.""")


def main():
    print(__doc__.split("Run:")[0].rstrip())
    rows = security_rows(open(os.path.join(ROOT, "SECURITY.md")).read())
    section_1(rows)
    v2 = section_2()
    section_3(v2)
    section_4(v2)
    section_5()
    section_6(rows)
    section_7()
    rule("Summary")
    if FAIL:
        print("*** FAILED: %d finding(s) did not reproduce ***" % len(FAIL))
        for f in FAIL:
            print("    - " + f)
        return 1
    print("*** OK: every finding reproduced ***")
    return 0


if __name__ == "__main__":
    sys.exit(main())
