#!/usr/bin/env python3
# hybrid_credential_phi.py — Resolving the binding map φ for the hybrid
# Ring-LWR + Stern-F credential (TODO #123, SecurityProofs-3.md §11.10.8/§11.10.9)
#
# The §11.10.8 design sketch left one open problem: a map φ from the ternary
# Ring-LWR secret s ∈ {-1,0,1}^n to a low-weight binary Stern witness
# e ∈ F_2^N, together with a cheap zero-knowledge gadget proving e = φ(s)
# for committed s and e.  The sketch assumed the gadget required either an
# expensive bit-decomposition circuit or a restrictive common-ring linearity.
#
# This script shows a third path: choose φ(s)_i = [s_i = +1] (the positive-
# support bitmap).  For ternary s the binding relation is then *algebraic of
# degree ≤ 3 over Z_q* — no bit decomposition at all:
#
#     ternary check      :  s_i^3 - s_i           = 0
#     support extraction :  (s_i^2 + s_i)·inv(2)  = e_i
#
# i.e. exactly 2 multiplications per coefficient (a_i = s_i·s_i, b_i = a_i·s_i),
# 2n = 512 multiplication gates total at n = 256.  Both constraints are native
# Z_q arithmetic, so any MPC-in-the-head or lattice product argument applies
# directly.
#
# Sections:
#   §1  Survey of binding-map candidates (A/B/C/D)
#   §2  φ_A weight distribution and leakage at n=256 (CBD(1) secrets)
#   §3  SDP hardness regimes at w=16 vs w≈64 — the many-solutions forgery
#       finding and the issuer-binding requirement
#   §4  Gadget cost models (ZKBoo-Z_q / KKW / BDLOP / boolean-PRF comparison)
#   §5  MPC-in-the-head prototype of the φ_A gadget over Z_q
#       (completeness, three cheat classes, measured proof sizes)
#   §6  Summary and recommendation
#
# Self-contained (no imports from the suite); reproduces the analysis cited in
# SecurityProofs-3.md §11.10.9.
#
# Usage:  python3 hybrid_credential_phi.py [--fast]

import hashlib
import math
import os
import sys

Q     = 65537                 # HKEX-RNL modulus (Fermat prime 2^16+1)
INV2  = (Q + 1) // 2          # 2^{-1} mod q
SEP   = "=" * 78
SEP2  = "-" * 78

_FAST = '--fast' in sys.argv
TRIALS_COMPLETE = 10 if _FAST else 30
TRIALS_CHEAT    = 100 if _FAST else 500
WEIGHT_SAMPLES  = 20_000 if _FAST else 100_000


def _shake(data: bytes, outlen: int) -> bytes:
    return hashlib.shake_256(data).digest(outlen)


def lg_choose(n: int, k: int) -> float:
    """log2 of the binomial coefficient C(n, k)."""
    if k < 0 or k > n:
        return float('-inf')
    return (math.lgamma(n + 1) - math.lgamma(k + 1)
            - math.lgamma(n - k + 1)) / math.log(2)


# =============================================================================
# §1  Survey of binding-map candidates
# =============================================================================

def section1():
    print(SEP)
    print("§1  Binding-map candidates φ : {-1,0,1}^n → F_2^N  (n = N = 256)")
    print(SEP)
    print("""
  A. Positive-support bitmap        φ(s)_i = 1  iff  s_i = +1
       Weight   : w = wt_+(s) ~ Binomial(256, 1/4) — variable, revealed
       Gadget   : PURELY ALGEBRAIC over Z_q, degree ≤ 3:
                    s_i^3 = s_i          (ternary membership)
                    e_i   = (s_i^2+s_i)/2  (support extraction)
                  → 2 multiplications/coefficient, 512 gates at n=256.
                  No bit decomposition.  This falsifies the §11.10.8
                  assumption that route (a) is necessarily expensive.
       Caveat   : Stern must run at revealed weight w ≈ 64 (see §3).

  B. Common-seed derivation         s = CBD(PRF_κ(1)), e = FixedWeight(PRF_κ(2))
       Gadget   : ZK proof of two NL-FSCX PRF evaluations — a boolean
                  circuit with ≈ 2 × 16,320 AND gates (F1^64 at n=256).
                  ZKBoo cost ≈ 1.8 MB at R=219 (§4).  Sound but heavy.

  C. F_2-linear projection          e = L·bits(s), public L
       The Ring-LWR relation is Z_q-linear in s; the Stern relation is
       F_2-linear in e.  No common ring: relating them still requires a
       decomposition gadget, so C degenerates into route (a).  Rejected.

  D. First-t_S-positives selection  φ(s) = indicator of the first 16
                                    positions with s_i = +1
       Weight   : fixed t_S = 16 — keeps the deployed Stern parameters and
                  the unique-solution SDP regime (§3).
       Gadget   : candidate A's 512 Z_q gates PLUS a prefix-sum selection
                  circuit ≈ 256 × (9-bit counter increment + threshold
                  compare) ≈ 2,800 boolean AND gates → ≈ 5.5× candidate A.
""")


# =============================================================================
# §2  φ_A weight distribution and leakage (n = 256, CBD(1))
# =============================================================================

def section2():
    print(SEP)
    print("§2  φ_A weight distribution and leakage  (CBD(1), n = 256, "
          f"{WEIGHT_SAMPLES:,} samples)")
    print(SEP)
    n = 256

    # Empirical: s_i = a_i - b_i with a,b uniform bits → s_i=+1 iff (a=1,b=0).
    counts = {}
    for _ in range(WEIGHT_SAMPLES):
        a = int.from_bytes(os.urandom(n // 8), 'big')
        b = int.from_bytes(os.urandom(n // 8), 'big')
        w = bin(a & ~b & ((1 << n) - 1)).count('1')
        counts[w] = counts.get(w, 0) + 1
    ws     = sorted(counts)
    mean_e = sum(w * c for w, c in counts.items()) / WEIGHT_SAMPLES
    var_e  = sum((w - mean_e) ** 2 * c for w, c in counts.items()) / WEIGHT_SAMPLES

    # Exact Binomial(256, 1/4) reference.
    p = 0.25
    mean_x = n * p
    sd_x   = math.sqrt(n * p * (1 - p))

    # Exact Shannon entropy of the weight (the leakage of revealing w).
    ent = 0.0
    for k in range(n + 1):
        lp = lg_choose(n, k) + k * math.log2(p) + (n - k) * math.log2(1 - p)
        ent -= (2.0 ** lp) * lp
    # Exact left tail P[w < 16] (φ_D feasibility: needs ≥ 16 positives).
    lg_tail = float('-inf')
    for k in range(16):
        lp = lg_choose(n, k) + k * math.log2(p) + (n - k) * math.log2(1 - p)
        lg_tail = max(lg_tail, lp) + math.log2(1 + 2 ** (min(lg_tail, lp)
                                                         - max(lg_tail, lp)))

    s_entropy = n * (0.5 * 1 + 2 * 0.25 * 2)   # H(1/2,1/4,1/4)=1.5 bits/coeff

    print(f"  empirical mean wt_+(s)  : {mean_e:7.2f}   "
          f"(exact {mean_x:.0f})")
    print(f"  empirical std dev       : {math.sqrt(var_e):7.2f}   "
          f"(exact {sd_x:.2f})")
    print(f"  observed range          : [{ws[0]}, {ws[-1]}]")
    print(f"  H(wt_+)  — leakage from revealing the Stern weight w:")
    print(f"      exact entropy       : {ent:.3f} bits")
    print(f"      secret entropy H(s) : {s_entropy:.0f} bits "
          f"(256 coeff × 1.5 bits)")
    print(f"      relative leak       : {100 * ent / s_entropy:.2f}%   → negligible")
    print(f"  P[wt_+(s) < 16]         : 2^{lg_tail:.1f}   "
          f"(φ_D always has 16 positives to select)")
    print()


# =============================================================================
# §3  SDP hardness regimes — the many-solutions forgery finding
# =============================================================================

def section3():
    print(SEP)
    print("§3  SDP hardness at the φ_A weight — many-solutions regime analysis")
    print(SEP)
    N, k = 256, 128            # Stern-F demo code: length N, dimension k
    rows = N - k               # 128 parity rows → syndrome space 2^128
    print(f"  Code: (N={N}, k={k}) — syndrome space 2^{rows}\n")
    print(f"  {'w':>4} {'lg #wt-w words':>15} {'lg #solutions':>14} "
          f"{'Prange lg iters':>16} {'effective lg':>13}")
    for w in (16, 64):
        lg_words = lg_choose(N, w)
        lg_sols  = lg_words - rows            # E[#solutions per syndrome]
        lg_pr    = lg_choose(N, w) - lg_choose(N - k, w)
        lg_eff   = lg_pr - max(lg_sols, 0.0)  # multiplicity speedup
        print(f"  {w:>4} {lg_words:>15.1f} {lg_sols:>14.1f} "
              f"{lg_pr:>16.1f} {lg_eff:>13.1f}")
    print("""
  Finding (new, material to the credential design):

  * w = 16 (deployed Stern-F): E[#solutions] = 2^-44.9 — unique-solution
    regime; Prange ≈ 2^17 iterations (the documented ~30-40 bit demo level
    once the per-iteration Gaussian-elimination cost is included).

  * w ≈ 64 (φ_A weight): E[#solutions] ≈ 2^75.6.  Prange's per-iteration
    success probability is multiplied by the solution count, collapsing the
    effective work to ≈ 2^3.8 iterations — finding SOME weight-64 solution
    of H·e^T = y is EASY.

  Consequence — self-registered-key forgery: an attacker finds any weight-64
  solution e' to the issued syndrome y (cheap, above), sets s' = e'
  (+1 on the support, 0 elsewhere — valid ternary with φ_A(s') = e'),
  registers the Ring-LWR public key C' = round_p(m·s'), and proves the
  compound statement honestly.  The binding gadget does NOT prevent this:
  every sub-relation is genuinely satisfied.

  Mitigations (either suffices):
    1. Issuer-bound pair: the credential is an issuer SIGNATURE over
       (C, y) — the verifier checks the pair's provenance, so a forger
       must match an EXISTING issued pair: find s' with BOTH
       round_p(m·s') = C and H·φ_A(s')^T = y — a 128-bit targeted
       preimage condition on top of Ring-LWR key recovery.
    2. φ_D (first-16-positives): keeps w = t_S = 16 and the
       unique-solution regime at ≈ 5.5× gadget cost (§1.D).

  Recommendation: mitigation 1 (issuer-bound (C, y)) — credentials are
  issuer-signed in any deployment of §11.10.8, so this costs nothing.
""")


# =============================================================================
# §4  Gadget cost models
# =============================================================================

def section4():
    print(SEP)
    print("§4  Gadget cost models at n = 256 (512 Z_q multiplication gates)")
    print(SEP)
    n      = 256
    gates  = 2 * n            # a = s∘s, b = a∘s
    CB     = 3                # bytes per Z_q coefficient (17 bits → 3 B)
    COM    = 32
    SEED   = 16

    # (i) ZKBoo-(2,3) over Z_q — the §5 prototype's accounting, optimised
    # transcript (ship only party e+1's gate vectors and party e+2's outputs;
    # opened parties' outputs recomputed).
    per_round = 3 * COM + 2 * SEED + n * CB + 2 * n * CB * 2
    for R, lbl in ((69, "2^-40 soundness"), (219, "2^-128 soundness")):
        tot = R * per_round
        print(f"  ZKBoo-Z_q  R={R:<4} ({lbl:<16}): "
              f"{tot:>9,} B  ({tot / 1024:6.1f} KB)")

    # (ii) KKW (MPC-in-the-head with preprocessing), 64 parties, τ = 22
    # executions for 2^-128: per execution ≈ one broadcast element per
    # multiplication + log2(64)-deep seed tree + commitment.
    n_par, tau = 64, 22
    per_exec = gates * CB + int(math.log2(n_par)) * SEED + COM + 200
    kkw = tau * per_exec
    print(f"  KKW  64-party, τ=22 (2^-128)       : "
          f"{kkw:>9,} B  ({kkw / 1024:6.1f} KB)   [hash-only]")

    # (iii) BDLOP-based lattice product argument (cited estimate).
    print(f"  BDLOP product argument (2^-128)    : "
          f"{2048:>9,} B  (   2.0 KB)   [needs lattice commitment]")

    # (iv) Boolean-PRF route (candidate B) for comparison, from the ZKBoo
    # model of zkp_pqc_exploration.py §3.6: F1^64 at n=256 has 16,320 AND
    # gates; two PRF evaluations.
    and_total = 2 * 64 * (n - 1)
    view      = math.ceil(n / 8) + COM + math.ceil(and_total / 8)
    prf_route = 219 * (3 * COM + 2 * view)
    print(f"  Boolean-PRF route (candidate B)    : "
          f"{prf_route:>9,} B  ({prf_route / 1024:6.1f} KB)   [2 × F1^64 circuits]")

    print(f"""
  Hybrid credential totals (Stern-F 78 KB + Ring-LWR 1 KB + gadget):
     φ_A + BDLOP gadget : ≈  81 KB   (matches the §11.10.8 estimate)
     φ_A + KKW gadget   : ≈ {79 + kkw // 1024:d} KB   (hash-only — no new assumptions)
     φ_A + ZKBoo-Z_q    : ≈ {79 + 219 * per_round // 1024:d} KB
     candidate B        : ≈ {79 + prf_route // 1024:,d} KB   (rejected)
""")


# =============================================================================
# §5  MPC-in-the-head prototype of the φ_A gadget (ZKBoo-(2,3) over Z_q)
# =============================================================================
#
# Statement : (e_pub)  — claimed positive-support bitmap, n public bits
# Witness   : s ∈ {-1,0,1}^n (coefficients stored mod q; -1 ≡ q-1)
# Relations : for every i:  s_i^3 - s_i = 0   and   (s_i^2 + s_i)·inv2 = e_i
#
# 3-party additive sharing over Z_q; ZKBoo (2,3)-decomposition:
#   party j's multiplication share
#     z_j = x_j·y_j + x_{j+1}·y_j + x_j·y_{j+1} + R_j - R_{j+1}   (mod q)
#   Σ_j z_j = x·y.
# Two gate layers:  a = s ∘ s,  b = a ∘ s.
# Output shares  :  o1_j = b_j - s_j        (Σ must be 0)
#                   o2_j = (a_j + s_j)·inv2 (Σ must be e_i)
# Fiat-Shamir    :  challenge byte stream from SHAKE-256 over
#                   (e_pub ‖ commitments ‖ cleartext output shares).
# Per round the verifier opens parties (c, c+1), fully recomputes party c,
# and checks party c+1's commitment binding — cheating detection 2/3/round.

class _Tape:
    """Deterministic Z_q sampler from a 16-byte seed (17-bit rejection)."""
    def __init__(self, seed: bytes, need: int):
        # 3 bytes/draw; over-provision 2x for rejections.
        self.buf = _shake(b'tape' + seed, 6 * need + 64)
        self.pos = 0

    def draw(self) -> int:
        while True:
            v = int.from_bytes(self.buf[self.pos:self.pos + 3], 'big') & 0x1FFFF
            self.pos += 3
            if v < Q:
                return v


def _ser(vec) -> bytes:
    return b''.join(v.to_bytes(3, 'big') for v in vec)


def _phi(s_vec):
    """φ_A: positive-support bitmap of a ternary vector (coeffs mod q)."""
    return [1 if v == 1 else 0 for v in s_vec]


def _mpc_views(s_vec, n):
    """One MPC-in-the-head execution: returns (seeds, aux, a, b, o1, o2)."""
    seeds = [os.urandom(16) for _ in range(3)]
    tapes = [_Tape(sd, 3 * n) for sd in seeds]
    sh = [[tapes[0].draw() for _ in range(n)],
          [tapes[1].draw() for _ in range(n)],
          None]
    sh[2] = [(s_vec[i] - sh[0][i] - sh[1][i]) % Q for i in range(n)]
    R1 = [[t.draw() for _ in range(n)] for t in tapes]
    R2 = [[t.draw() for _ in range(n)] for t in tapes]

    a = [[0] * n for _ in range(3)]
    b = [[0] * n for _ in range(3)]
    for j in range(3):
        k = (j + 1) % 3
        for i in range(n):
            a[j][i] = (sh[j][i] * sh[j][i] + sh[k][i] * sh[j][i]
                       + sh[j][i] * sh[k][i] + R1[j][i] - R1[k][i]) % Q
    for j in range(3):
        k = (j + 1) % 3
        for i in range(n):
            b[j][i] = (a[j][i] * sh[j][i] + a[k][i] * sh[j][i]
                       + a[j][i] * sh[k][i] + R2[j][i] - R2[k][i]) % Q
    o1 = [[(b[j][i] - sh[j][i]) % Q for i in range(n)] for j in range(3)]
    o2 = [[((a[j][i] + sh[j][i]) * INV2) % Q for i in range(n)] for j in range(3)]
    return seeds, sh, a, b, o1, o2


def _commit(j, seeds, sh, a, b, o1, o2) -> bytes:
    aux = _ser(sh[2]) if j == 2 else b''
    return _shake(b'com' + bytes([j]) + seeds[j] + aux
                  + _ser(a[j]) + _ser(b[j]) + _ser(o1[j]) + _ser(o2[j]), 32)


def _fs_challenges(e_pub, rounds_data, R):
    """Fiat-Shamir round challenges in {0,1,2} (rejection-sampled bytes)."""
    h = hashlib.shake_256()
    h.update(bytes(e_pub))
    for (coms, o1, o2) in rounds_data:
        for c in coms:
            h.update(c)
        for j in range(3):
            h.update(_ser(o1[j]) + _ser(o2[j]))
    stream = h.digest(4 * R + 64)
    out, pos = [], 0
    while len(out) < R:
        v = stream[pos]; pos += 1
        if v < 252:
            out.append(v % 3)
    return out


def gadget_prove(s_vec, e_pub, n, R):
    execs, rounds_data = [], []
    for _ in range(R):
        seeds, sh, a, b, o1, o2 = _mpc_views(s_vec, n)
        coms = [_commit(j, seeds, sh, a, b, o1, o2) for j in range(3)]
        execs.append((seeds, sh, a, b, o1, o2))
        rounds_data.append((coms, o1, o2))
    chals = _fs_challenges(e_pub, rounds_data, R)
    proof = []
    for r in range(R):
        seeds, sh, a, b, o1, o2 = execs[r]
        coms, _, _ = rounds_data[r]
        c = chals[r]
        cp1 = (c + 1) % 3
        aux = sh[2] if 2 in (c, cp1) else None
        proof.append(dict(coms=coms, o1=o1, o2=o2,
                          seed_c=seeds[c], seed_c1=seeds[cp1], aux=aux,
                          a1=a[cp1], b1=b[cp1]))
    return proof, chals


def gadget_verify(e_pub, proof, n, R):
    rounds_data = [(rd['coms'], rd['o1'], rd['o2']) for rd in proof]
    chals = _fs_challenges(e_pub, rounds_data, R)
    for r, rd in enumerate(proof):
        c   = chals[r]
        cp1 = (c + 1) % 3
        o1, o2 = rd['o1'], rd['o2']
        # 1. Output sums match the public statement.
        for i in range(n):
            if (o1[0][i] + o1[1][i] + o1[2][i]) % Q != 0:
                return False
            if (o2[0][i] + o2[1][i] + o2[2][i]) % Q != e_pub[i]:
                return False
        # 2. Rebuild the two opened parties' tapes and input shares.
        t_c  = _Tape(rd['seed_c'], 3 * n)
        t_c1 = _Tape(rd['seed_c1'], 3 * n)
        sh_c  = ([t_c.draw() for _ in range(n)] if c != 2
                 else list(rd['aux'] or []))
        if c == 2:
            pass                       # aux is the input share itself
        sh_c1 = ([t_c1.draw() for _ in range(n)] if cp1 != 2
                 else list(rd['aux'] or []))
        if c == 2 and (rd['aux'] is None or len(rd['aux']) != n):
            return False
        if cp1 == 2 and (rd['aux'] is None or len(rd['aux']) != n):
            return False
        R1_c  = [t_c.draw() for _ in range(n)]
        R2_c  = [t_c.draw() for _ in range(n)]
        R1_c1 = [t_c1.draw() for _ in range(n)]
        R2_c1 = [t_c1.draw() for _ in range(n)]
        # 3. Fully recompute party c's gates using party c+1's wires.
        a_c = [(sh_c[i] * sh_c[i] + sh_c1[i] * sh_c[i]
                + sh_c[i] * sh_c1[i] + R1_c[i] - R1_c1[i]) % Q
               for i in range(n)]
        b_c = [(a_c[i] * sh_c[i] + rd['a1'][i] * sh_c[i]
                + a_c[i] * sh_c1[i] + R2_c[i] - R2_c1[i]) % Q
               for i in range(n)]
        o1_c = [(b_c[i] - sh_c[i]) % Q for i in range(n)]
        o2_c = [((a_c[i] + sh_c[i]) * INV2) % Q for i in range(n)]
        if o1_c != o1[c] or o2_c != o2[c]:
            return False
        # 4. Commitment bindings for both opened parties.
        seeds3 = [b''] * 3
        seeds3[c], seeds3[cp1] = rd['seed_c'], rd['seed_c1']
        sh3 = [[0] * n] * 3
        sh3 = list(sh3)
        sh3[c], sh3[cp1] = sh_c, sh_c1
        if 2 in (c, cp1):
            sh3[2] = list(rd['aux'])
        a3 = [rd['a1']] * 3; a3 = list(a3); a3[c] = a_c; a3[cp1] = rd['a1']
        b3 = list([rd['b1']] * 3); b3[c] = b_c; b3[cp1] = rd['b1']
        # party c+1's outputs recomputed from its shipped gate vectors:
        o1_c1 = [(rd['b1'][i] - sh_c1[i]) % Q for i in range(n)]
        o2_c1 = [((rd['a1'][i] + sh_c1[i]) * INV2) % Q for i in range(n)]
        if o1_c1 != o1[cp1] or o2_c1 != o2[cp1]:
            return False
        o13 = list([None] * 3); o23 = list([None] * 3)
        o13[c], o13[cp1] = o1_c, o1_c1
        o23[c], o23[cp1] = o2_c, o2_c1
        for j in (c, cp1):
            aux_b = _ser(sh3[2]) if j == 2 else b''
            com = _shake(b'com' + bytes([j]) + seeds3[j] + aux_b
                         + _ser(a3[j]) + _ser(b3[j])
                         + _ser(o13[j]) + _ser(o23[j]), 32)
            if com != rd['coms'][j]:
                return False
    return True


def _proof_bytes(proof, n) -> int:
    tot = 0
    for rd in proof:
        tot += 3 * 32 + 2 * 16                    # commitments + 2 seeds
        tot += 6 * n * 3                          # cleartext o1,o2 × 3 parties
        tot += 2 * n * 3                          # a1, b1 gate vectors
        if rd['aux'] is not None:
            tot += n * 3
    return tot


def _rand_ternary(n):
    out = []
    while len(out) < n:
        byte = os.urandom(1)[0]
        for shift in (0, 2, 4, 6):
            aa, bb = (byte >> shift) & 1, (byte >> (shift + 1)) & 1
            out.append((aa - bb) % Q)
            if len(out) == n:
                break
    return out


def section5():
    print(SEP)
    print("§5  MPC-in-the-head φ_A gadget prototype (ZKBoo-(2,3) over Z_q)")
    print(SEP)

    # -- 5.1 completeness ------------------------------------------------------
    n, R = 32, 8
    fails = 0
    for _ in range(TRIALS_COMPLETE):
        s = _rand_ternary(n)
        e = _phi(s)
        proof, _ = gadget_prove(s, e, n, R)
        if not gadget_verify(e, proof, n, R):
            fails += 1
    print(f"  §5.1 completeness  (n={n}, R={R}, {TRIALS_COMPLETE} trials): "
          f"{TRIALS_COMPLETE - fails}/{TRIALS_COMPLETE} accepted"
          f"{'   [FAIL]' if fails else '   [PASS]'}")

    # one full-size run to confirm n=256 works end to end
    n2 = 256
    s = _rand_ternary(n2)
    e = _phi(s)
    proof256, _ = gadget_prove(s, e, n2, R)
    ok256 = gadget_verify(e, proof256, n2, R)
    print(f"       full-size check (n=256, R={R}): "
          f"{'accepted   [PASS]' if ok256 else 'REJECTED   [FAIL]'}")

    # -- 5.2 cheat class 1: e is not φ(s) (honest MPC, false statement) --------
    n = 32
    caught = 0
    for _ in range(TRIALS_CHEAT):
        s = _rand_ternary(n)
        e = _phi(s)
        e[os.urandom(1)[0] % n] ^= 1              # flip one claimed bit
        proof, _ = gadget_prove(s, e, n, R)
        if not gadget_verify(e, proof, n, R):
            caught += 1
    print(f"  §5.2 cheat: e ≠ φ(s)      ({TRIALS_CHEAT} trials): "
          f"{caught}/{TRIALS_CHEAT} rejected (expected 100% — output-sum check)"
          f"{'   [PASS]' if caught == TRIALS_CHEAT else '   [FAIL]'}")

    # -- 5.3 cheat class 2: s not ternary --------------------------------------
    caught = 0
    for _ in range(TRIALS_CHEAT):
        s = _rand_ternary(n)
        s[os.urandom(1)[0] % n] = 2               # inject a non-ternary coeff
        e = _phi(s)
        proof, _ = gadget_prove(s, e, n, R)
        if not gadget_verify(e, proof, n, R):
            caught += 1
    print(f"  §5.3 cheat: s not ternary ({TRIALS_CHEAT} trials): "
          f"{caught}/{TRIALS_CHEAT} rejected (expected 100% — ternary check)"
          f"{'   [PASS]' if caught == TRIALS_CHEAT else '   [FAIL]'}")

    # -- 5.4 cheat class 3: corrupted view (soundness-error measurement) -------
    # The prover claims a flipped e-bit and patches party 0's cleartext o2
    # share so the sums match; detection only when a challenge opens party 0's
    # computation (c = 0 recompute, or c = 2 via commitment binding) → the
    # per-round soundness error is 1/3 and survival is (1/3)^R.
    R3 = 3
    passed = 0
    for _ in range(TRIALS_CHEAT):
        s = _rand_ternary(n)
        e = _phi(s)
        flip = os.urandom(1)[0] % n
        e[flip] ^= 1
        execs, rounds_data = [], []
        for _r in range(R3):
            seeds, sh, a, b, o1, o2 = _mpc_views(s, n)
            delta = (e[flip] - _phi(s)[flip]) % Q
            o2[0][flip] = (o2[0][flip] + delta) % Q          # patch the sum
            coms = [_commit(j, seeds, sh, a, b, o1, o2) for j in range(3)]
            execs.append((seeds, sh, a, b, o1, o2))
            rounds_data.append((coms, o1, o2))
        chals = _fs_challenges(e, rounds_data, R3)
        proof = []
        for r in range(R3):
            seeds, sh, a, b, o1, o2 = execs[r]
            coms, _, _ = rounds_data[r]
            c = chals[r]; cp1 = (c + 1) % 3
            aux = sh[2] if 2 in (c, cp1) else None
            proof.append(dict(coms=coms, o1=o1, o2=o2,
                              seed_c=seeds[c], seed_c1=seeds[cp1], aux=aux,
                              a1=a[cp1], b1=b[cp1]))
        if gadget_verify(e, proof, n, R3):
            passed += 1
    exp = TRIALS_CHEAT * (1 / 3) ** R3
    print(f"  §5.4 cheat: corrupted view (R={R3}, {TRIALS_CHEAT} trials): "
          f"{passed} passed — expected ≈ {exp:.1f}  [(1/3)^R soundness error]")

    # -- 5.5 measured proof sizes ----------------------------------------------
    sz32  = _proof_bytes(gadget_prove(_rand_ternary(32), _phi(_rand_ternary(32)),
                                      32, 1)[0], 32)
    sz256 = _proof_bytes(proof256, 256) // R
    print(f"\n  §5.5 measured prototype sizes (per round, cleartext-output "
          f"format):")
    print(f"       n=32  : {sz32:6,} B/round   "
          f"→ R=219: {219 * sz32 / 1024:7.1f} KB")
    print(f"       n=256 : {sz256:6,} B/round   "
          f"→ R=219: {219 * sz256 / 1024:7.1f} KB")
    print(f"       (the optimised accounting in §4 ships only party c+2's")
    print(f"        outputs — production should use the §4 KKW or BDLOP path)")
    print()


# =============================================================================
# §6  Summary
# =============================================================================

def section6():
    print(SEP)
    print("§6  Summary and recommendation (TODO #123 resolution)")
    print(SEP)
    print("""
  1. The binding map: φ_A(s)_i = [s_i = +1].  For ternary s the relation
     e = φ_A(s) is algebraic of degree ≤ 3 over Z_q — 2 multiplication
     gates per coefficient (512 at n=256).  No bit decomposition.  The
     §11.10.8 dichotomy (expensive circuit vs restrictive linear map) was
     a false choice: the polynomial identity route is both cheap and exact.

  2. Leakage: revealing the Stern weight w = wt_+(s) leaks ≈ 4.8 bits of
     the ≈ 384-bit secret (≈ 1.3%) — negligible.

  3. New finding: at w ≈ 64 the SDP instance has ≈ 2^76 solutions and
     finding one is easy (≈ 2^3.8 Prange iterations) → the credential MUST
     bind (C, y) via an issuer signature (standard practice, zero cost),
     or use φ_D (fixed weight 16, ≈ 5.5× gadget) to stay in the
     unique-solution regime.

  4. Gadget cost at n=256, 2^-128 soundness:
       BDLOP product argument   ≈   2 KB  (lattice commitment required)
       KKW 64-party MPCitH      ≈  40 KB  (hash-only, RECOMMENDED)
       ZKBoo-Z_q (this script)  ≈ 850 KB  (prototype accounting)
       boolean-PRF route (B)    ≈ 1.8 MB  (rejected)

  5. Hybrid credential totals: ≈ 81 KB (BDLOP) / ≈ 120 KB (KKW) —
     Stern-F-dominated either way, consistent with §11.10.8's estimate.

  Status: the φ gadget question posed as the open problem in §11.10.8 is
  RESOLVED (φ_A + issuer-bound (C, y) + KKW or BDLOP gadget).  Promotion to
  a suite implementation is tracked separately (TODO #128).
""")


if __name__ == '__main__':
    print(SEP)
    print("hybrid_credential_phi.py — binding map φ for the hybrid credential "
          "(TODO #123)")
    print(SEP)
    print(f"Flags: --fast={_FAST}")
    section1()
    section2()
    section3()
    section4()
    section5()
    section6()
    print(SEP)
    print("Done.")
    print(SEP)
