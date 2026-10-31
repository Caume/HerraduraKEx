#!/usr/bin/env python3
"""hfscx_mmo_compression.py — TODO #351: HFSCX-256's Davies-Meyer compression let a
zero block erase itself; v11.0.0 moves it to Matyas-Meyer-Oseas.

The round is F_B(A) = M(A ^ B) ^ ROL(A + B, n/4), iterated on A with B fixed.  The
trail-weight model of TODO #346/#347 prices DIFFERENCES.  It cannot see a FIXED input
that switches the round's non-linearity off, and v10.0.0's raise to 3n/4 rounds made one
such input fatal.  This script pins the finding, the fix, and what the fix leaves.

  §1  THE AFFINE B VALUES.  A + B is GF(2)-affine in A exactly when B has no set bit
      below n-2: B in W = {0, 2^(n-2), 2^(n-1), 3*2^(n-2)}.  Every carry is then a
      product with a constant, except the top one, which falls off the word.
      Exhaustive at n = 8, 10, 12.  For B in {0, 2^(n-1)} the round's linear part is
      L = M ^ ROL^(n/4) = (1 + X + X^(n-1) + X^(n/4)) over GF(2)[X]/(X^n + 1).  Since
      X^n + 1 = (X+1)^n, L = (X+1)^2 * u with u a unit, so L is NILPOTENT: rank L^k is
      n - 2k and L^(n/2) = 0.  Checked at n = 32 and 256.  So v1(A, B, s) for those two B
      does not depend on A once s >= n/2.  For B = 0 it is identically 0.

  §2  THE FINDING, ON v10.x's CONSTRUCTION.  Davies-Meyer: C(s, m) = F_m^r(s) ^ s, with
      the BLOCK as B.  At r = 3n/4 = 192 (v10.0.0-v10.0.4) a zero block gives
      C(s, 0) = s, the identity, so H(b || 0^32) = H(0^32 || b) for every 32-byte b: a
      free collision between two different messages of the same length.  Reproduced on
      a transcription of v10.x's chain.  CONTROL: at r = 64 (before v10.0.0), L^64 has
      rank 128 and C(s, 0) = L^64(s) ^ s is a bijection (TODO #159's §1).  The collision
      is absent there.  The block 2^255 also turns C(., m) into s ^ const at 192 rounds.

  §3  THE FIX, AS SHIPPED.  Matyas-Meyer-Oseas: C(s, m) = F_s^r(m) ^ m.  The CHAINING
      VALUE is B and the block is A, so no message chooses B.  The shipped Python
      hfscx_256 equals a hand-built MMO chain on three messages, and differs from the
      DM chain (CONTROL).  None of the four W blocks commutes with a random block or
      erases itself.  The four ports agree with each other through test [19]'s vectors
      and the KAT and PEM files.  This script checks the Python reference only.

  §4  WHAT MMO LEAVES.  A chaining value in W is reachable only through a compression
      output, by solving F_s(m) ^ m = w for one of four targets.  That is a 2^254-work
      preimage.  Neither IV is in W: _HFSCX256_IV, and HFSCX-32's 0xA3C5E7B9 at n = 32.
      The keyed form sets the initial chaining value to key ^ IV, so four keys out of
      2^256 are weak.  Nobody picks an HFSCX key: the AEAD and .hkx MAC keys come out of
      v1 at 3n/4, and HMAC puts the key in a BLOCK.

  §5  THE NEW DIFFERENTIAL SHAPE.  A one-block MMO collision under one chaining value
      is DeltaB = 0, DeltaA = Delta_m, and v1's output difference must equal Delta_m, so
      the feed-forward cancels it.  A path that reaches the zero difference stays there
      and cannot end on Delta_m.  So it is a 192-round characteristic over nonzero
      alphas under beta = 0.  beta = 0 is in TODO #347's residual, so Lemmas 1-2 give
      nothing there.  This section measures it with v1_mode_floor.py's own complete
      class edges: in the class "every round costs <= D", the longest walk avoiding 0
      is 2 edges, at every D tried.  So a run of rounds each costing <= D is at most 3
      long, any 4 consecutive rounds of such a characteristic include one costing
      >= D + 1, and 192 rounds cost >= (D + 1) * floor(192 / 4).  That is 288 at D = 5
      (--quick) and 336 at D = 6: 2.25x and 2.6x the 128-bit birthday bar.  A differing chaining value is beta != 0,
      the case TODO #347 already bounds (§11.72: >= 384 outside the residual).  Which
      input is the message does not enter that bound.

  §6  THE OTHER v1 SITES AT >= n/2 ROUNDS.  W only matters where someone CHOOSES B and
      the step count is at least n/2.  The four ports' other 3n/4 sites are HSKE-NL-A1's
      keystream (B = K ^ nonce ^ ctr) and MAC key (B = K ^ nonce), which are behind
      the secret key, and the WOTS chain step (B = x, a secret or a chain output).
      Pinned from herradura.h.  TODO #348's owed sites stay at n/4, where L^(n/4) still
      has a 2^(n/2) kernel.  That is recorded in #348 for its second pass, and this
      script makes no claim on it.

  §7  THE DOCUMENTS.  §8  VERDICT.

Pure Python, deterministic.  About 10 s with --quick (D = 5), 2 min without (D = 6),
on an aarch64 SBC.  Exits non-zero if a finding stops reproducing.

Run:  python3 SecurityProofsCode/hfscx_mmo_compression.py [--quick]
"""

import importlib.util
import os
import random
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
QUICK = "--quick" in sys.argv
D = 5 if QUICK else 6
FAIL = []


def rule(t):
    print("\n" + "=" * 78)
    print(t)
    print("=" * 78)


def check(cond, what):
    print("  [%s] %s" % ("PASS" if cond else "FAIL", what))
    if not cond:
        FAIL.append(what)
    return cond


def _load(name, rel):
    spec = importlib.util.spec_from_file_location(name, os.path.join(ROOT, rel))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def _src(rel):
    with open(os.path.join(ROOT, rel), encoding="utf-8") as f:
        return f.read()


H = _load("_suite", "Herradura cryptographic suite.py")
BA, rv1 = H.BitArray, H.nl_fscx_revolve_v1
IV = int.from_bytes(H._HFSCX256_IV_BYTES, "big")


def rol(x, s, n):
    s %= n
    m = (1 << n) - 1
    return ((x << s) | (x >> (n - s))) & m if s else x


def M(x, n):
    return x ^ rol(x, 1, n) ^ rol(x, n - 1, n)


def gf2_rank(rows):
    rank, rows = 0, list(rows)
    while rows:
        p = rows.pop()
        if not p:
            continue
        rank += 1
        hb = p.bit_length() - 1
        rows = [r ^ p if r >> hb & 1 else r for r in rows]
    return rank


def pad(msg, init):
    p = bytearray(msg) + b"\x80"
    p += b"\x00" * (-len(p) % 32)
    p += ((len(msg) * 8) ^ init).to_bytes(32, "big")
    return [int.from_bytes(p[o:o + 32], "big") for o in range(0, len(p), 32)]


def dm(msg, r):
    """v10.x's HFSCX-256 by hand: Davies-Meyer, the block is v1's B."""
    s = IV
    for m in pad(msg, IV):
        s = rv1(BA(256, s), BA(256, m), r).uint ^ s
    return s


def mmo(msg, r):
    """v11.0.0's HFSCX-256 by hand: Matyas-Meyer-Oseas, the chaining value is B."""
    s = IV
    for m in pad(msg, IV):
        s = rv1(BA(256, m), BA(256, s), r).uint ^ m
    return s


def W_set(n):
    return {0, 1 << (n - 2), 1 << (n - 1), 3 << (n - 2)}


# ═══════════════════════════════════════════════════════════════════════════
def section_1():
    rule("§1  The affine B values, and the nilpotent linear part")
    ok = True
    for n in (8, 10, 12):
        m = (1 << n) - 1
        aff = [B for B in range(1 << n)
               if all(((x ^ (1 << j)) + B) & m ^ (x + B) & m == ((1 << j) + B) & m ^ B
                      for x in range(1 << n) for j in range(n))]
        good = set(aff) == W_set(n)
        ok = ok and good
        print("  n = %2d: A + B affine in A for B in %s" % (n, [hex(b) for b in aff]))
    check(ok, "A + B is GF(2)-affine in A exactly for B in {0, 2^(n-2), 2^(n-1), "
          "3*2^(n-2)}, exhaustive at n = 8, 10, 12")

    for n in (32, 256):
        k = n // 4
        cols = [1 << j for j in range(n)]
        ranks = {}
        for step in range(1, n // 2 + 1):
            cols = [M(c, n) ^ rol(c, k, n) for c in cols]
            if step in (1, n // 8, n // 4, 3 * n // 8, n // 2 - 1, n // 2):
                ranks[step] = gf2_rank(cols)
        good = all(rk == n - 2 * s for s, rk in ranks.items())
        print("  n = %3d: rank L^k = %s" % (n, ", ".join("k=%d:%d" % kv for kv in sorted(ranks.items()))))
        check(good and ranks[n // 2] == 0,
              "n = %d: rank L^k = n - 2k, and L^(n/2) = 0 -- L is nilpotent" % n)

    A1, A2 = random.Random(351).getrandbits(256), random.Random(352).getrandbits(256)
    for B in (0, 1 << 255):
        c1, c2 = rv1(BA(256, A1), BA(256, B), 128).uint, rv1(BA(256, A2), BA(256, B), 128).uint
        c3 = rv1(BA(256, A1), BA(256, B), 127).uint ^ rv1(BA(256, A2), BA(256, B), 127).uint
        check(c1 == c2 and c3 != 0 and (B or c1 == 0),
              "B = %s: v1(A, B, 128) is the same for two random A (%s), and 127 rounds "
              "still separate them" % ("0" if not B else "2^255", "0" if not c1 else "a constant"))
    for B in (1 << 254, 3 << 254, 1):
        c1 = rv1(BA(256, A1), BA(256, B), 192).uint
        c2 = rv1(BA(256, A2), BA(256, B), 192).uint
        check(c1 != c2, "CONTROL: B = %s does not collapse at 192 rounds" % hex(B))


# ═══════════════════════════════════════════════════════════════════════════
def section_2():
    rule("§2  The finding on v10.x's Davies-Meyer chain")
    rng = random.Random(3510)
    z = bytes(32)
    blocks = [rng.getrandbits(256).to_bytes(32, "big") for _ in range(3)]
    check(all(dm(b + z, 192) == dm(z + b, 192) for b in blocks),
          "DM at 192 rounds (v10.0.0-v10.0.4): H(b || 0^32) == H(0^32 || b) for 3 random b")
    check(all(dm(b + z, 192) != dm(b, 192) for b in blocks),
          "... and the two messages are distinct from b itself (the padding still binds length)")
    check(all(dm(b + z, 64) != dm(z + b, 64) for b in blocks),
          "CONTROL: DM at 64 rounds (before v10.0.0) has no such collision")
    s = rng.getrandbits(256)
    check(rv1(BA(256, s), BA(256, 0), 192).uint ^ s == s,
          "the mechanism: C_DM(s, 0) = F_0^192(s) ^ s = s, the identity")
    c = rv1(BA(256, s), BA(256, 1 << 255), 192).uint
    check(c == rv1(BA(256, s ^ 0xabc), BA(256, 1 << 255), 192).uint,
          "and the block 2^255 makes C_DM(s, 2^255) = s ^ const")


# ═══════════════════════════════════════════════════════════════════════════
def section_3():
    rule("§3  The fix as shipped: Matyas-Meyer-Oseas")
    msgs = (b"", b"a", b"HerraduraKEx v11.0.0" * 3)
    check(all(H.hfscx_256(m) == mmo(m, H.V1_MODE_STEPS).to_bytes(32, "big") for m in msgs),
          "the shipped hfscx_256 equals a hand-built MMO chain at %d rounds on 3 messages"
          % H.V1_MODE_STEPS)
    check(all(H.hfscx_256(m) != dm(m, H.V1_MODE_STEPS).to_bytes(32, "big") for m in msgs),
          "CONTROL: it differs from v10.x's DM chain")
    rng = random.Random(3511)
    b = rng.getrandbits(256).to_bytes(32, "big")
    bad = [hex(w) for w in sorted(W_set(256))
           if H.hfscx_256(b + w.to_bytes(32, "big")) == H.hfscx_256(w.to_bytes(32, "big") + b)
           or H.hfscx_256(b + w.to_bytes(32, "big")) == H.hfscx_256(b)]
    check(not bad, "no W block commutes with a random block or erases itself (%s)" % bad)
    hdr = _src("herradura.h")
    body = hdr[hdr.index("static void hfscx_256("):]
    body = body[:body.index("\n}\n")]
    check("nl_fscx_revolve_v1_ba(&state, &block, &state, V1_MODE_STEPS);" in body
          and "ba_xor(&state, &state, &block);" in body and "BitArray prev" not in body,
          "herradura.h's hfscx_256 passes the block as A and the state as B, and feeds "
          "the block forward")
    ok32 = []
    for f in ("Herradura cryptographic suite.ino",):
        s = _src(f)
        ok32.append("nl_fscx_revolve_v1(x, 0xA3C5E7B9UL, V1_MODE_STEPS) ^ x" in s and
                    "nl_fscx_revolve_v1(0xA3C5E799UL, s, V1_MODE_STEPS) ^ 0xA3C5E799UL" in s)
    for f in ("Herradura cryptographic suite.s", "CryptosuiteTests/Herradura_tests.s",
              "Herradura cryptographic suite.asm", "CryptosuiteTests/Herradura_tests.asm"):
        s = _src(f)
        ok32.append("(MMO, v11.0.0, TODO #351)" in s and "(DM block" not in s)
    check(all(ok32), "HFSCX-32 is MMO in the five 32-bit files (%d of 5)" % sum(ok32))


# ═══════════════════════════════════════════════════════════════════════════
def section_4():
    rule("§4  What MMO leaves: W as a chaining value")
    check(IV not in W_set(256), "_HFSCX256_IV is not in W (top byte 0x%02x)" % (IV >> 248))
    check(0xA3C5E7B9 not in W_set(32), "HFSCX-32's IV 0xA3C5E7B9 is not in W at n = 32")
    k = IV  # a key equal to the IV gives an initial chaining value of 0
    m = random.Random(3512).getrandbits(256)
    check(rv1(BA(256, m), BA(256, k ^ IV), 192).uint ^ m == m,
          "the keyed form's four weak keys exist: key = IV gives C(0, m) = m.  They are "
          "4 of 2^256, and no shipped caller lets anyone pick an HFSCX key")
    print("""
  Reaching W from a non-weak chaining value means solving F_s(m) ^ m = w for one of
  four w: a 2^254-work preimage.  HMAC puts its key in a BLOCK (A), the AEAD and .hkx
  MAC keys are outputs of v1 at 3n/4 under a secret, and the bare hash starts at the IV.""")


# ═══════════════════════════════════════════════════════════════════════════
def section_5():
    rule("§5  The new shape: DeltaB = 0, in the class 'every round <= %d'" % D)
    sys_argv = sys.argv
    sys.argv = [sys.argv[0]]
    try:
        f = _load("_floor", "SecurityProofsCode/v1_mode_floor.py")
    finally:
        sys.argv = sys_argv
    w = f.W(256)

    def longest(adj):
        memo, onstack = {}, set()

        def lp(a):
            if a in onstack:
                return float("inf")
            if a in memo:
                return memo[a]
            onstack.add(a)
            r = max((1 + lp(a2) for a2, _ in adj.get(a, ())), default=0)
            onstack.discard(a)
            memo[a] = r
            return r
        return max((lp(a) for a in adj), default=0)

    res = {}
    for d in sorted({3, 4, D}):
        E = f.edges(w, 0, d)
        adj = f.adjacency(E, 0)
        res[d] = longest(adj)
        print("  D = %d: %6d class edges, longest walk avoiding 0 = %s rounds"
              % (d, len(E), res[d]))
    L = res[D]
    check(all(v == 2 for v in res.values()),
          "the longest walk is 2 edges at every D tried (%s)" % sorted(res.items()))
    bound = (D + 1) * (192 // (L + 2))
    check(bound >= 2 * 128,
          "so a cheap run is <= %d rounds and every 192-round DeltaB = 0 characteristic "
          "costs >= (D+1)*floor(192/%d) = %d, %.2fx the 128-bit bar"
          % (L + 1, L + 2, bound, bound / 128))
    ctl = f.walk(f.adjacency(f.edges(w, 1 << 255 | 1 << 253, 4), 1 << 255 | 1 << 253),
                 None, None, R=64)
    check(ctl == 128, "CONTROL: the same instrument finds #347's 128-bit core over 64 rounds "
          "at beta = 2^255 + 2^253 (got %s)" % ctl)
    print("""
  Why 4 rounds: a round costing <= D needs its input alpha to have <= D low bits, so in
  a run of m cheap rounds the first m - 1 are a walk of class edges, and m <= 3.  The
  bound counts the expensive rounds only; the cheap ones are not credited.  The edge sets are
  v1_mode_floor.py's, complete for the class.  A differing chaining value is beta != 0,
  bounded by §11.72 (>= 384 outside the residual) whichever input carries the message.""")


# ═══════════════════════════════════════════════════════════════════════════
def section_6():
    rule("§6  The other v1 sites at >= n/2 rounds")
    hdr = _src("herradura.h")
    calls = re.findall(r"nl_fscx_revolve_v1_ba\(([^;]*?),\s*V1_MODE_STEPS\)", hdr)
    sites = sorted(c.split(",")[-1].strip() for c in calls)
    want = sorted(["&state", "&base_i", "base", "x"])
    check(sites == want,
          "herradura.h has exactly four V1_MODE_STEPS calls, with B = %s" % sites)
    print("""
    site                 B                     who can set B to a W value
    HFSCX-256            the chaining value    nobody (§4)
    A1 keystream         K ^ nonce ^ ctr       only someone who knows K
    A1 MAC key           K ^ nonce             only someone who knows K
    WOTS chain step      x                     a secret key or a chain output

  TODO #348's owed sites (the Schnorr challenge, B = msg, and the Stern chain hash,
  B = ROL(item, n/8)) stay at n/4, where L^(n/4) has a 2^(n/2) kernel rather than none.
  That is recorded in #348 for its second pass; this script makes no claim on it.""")


# ═══════════════════════════════════════════════════════════════════════════
def section_7():
    rule("§7  The documents")
    done = _src("TODO_DONE.md")
    m = re.search(r"^### #351:.*?(?=^### |\Z)", done, re.S | re.M)
    check(bool(m) and "Status: **DONE v11.0.0**" in m.group(0),
          "TODO_DONE.md has #351 as DONE v11.0.0")
    sp = _src("SecurityProofs-10.md")
    check("## 11.75 " in sp and "hfscx_mmo_compression.py" in sp,
          "SecurityProofs-10.md §11.75 names this gate")
    check("## [11.0.0]" in _src("CHANGELOG.md"), "CHANGELOG.md has [11.0.0]")
    check(re.search(r"^## \d+\. .*\(v11\.0\.0\)", _src("MIGRATING.md"), re.M) is not None,
          "MIGRATING.md has a v11.0.0 section")
    todo = _src("TODO.md")
    m = re.search(r"^### #348:.*?(?=^### |\Z)", todo, re.S | re.M)
    check(bool(m) and "#351" in m.group(0), "TODO.md's #348 records #351's constraint")


def main():
    random.seed(351)
    section_1()
    section_2()
    section_3()
    section_4()
    section_5()
    section_6()
    section_7()
    rule("§8  Verdict")
    print("""
  v10.0.0-v10.0.4's HFSCX-256 had a free collision, H(b || 0^32) = H(0^32 || b), that
  the trail-weight model could not see.  v11.0.0's MMO compression takes B from the
  chaining value, where W is a 2^254-work preimage away.  In the trail model its new
  DeltaB = 0 shape costs >= %d over 192 rounds.""" % ((D + 1) * 48))
    if FAIL:
        print("\n%d check(s) FAILED:" % len(FAIL))
        for x in FAIL:
            print("  - " + x)
        return 1
    print("\nAll checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
