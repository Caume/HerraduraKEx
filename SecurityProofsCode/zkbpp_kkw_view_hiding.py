#!/usr/bin/env python3
"""TODO #302 — the same hiding assertion for ZKB++ and KKW.

TODO #298 scoped three hiding assertions.  #301 wrote the ZKBoo one and stopped
there on purpose; these are the other two.  They are a separate item, and not a
widening of #301, because THE EXPOSURE SURFACE IS DIFFERENT IN EACH -- which is
#298's scoping note, and is the thing this file measures rather than assumes.

WHAT #301 ESTABLISHED AND THIS REUSES: the count-the-survivors shape, and above
all the control discipline.  A control that fires by EXCLUDING THE TRUE WITNESS
is measuring the checker disagreeing with the prover, not a leak; #301 threw
away two drafts on exactly that.  Both controls here assert that the true
witness is what survives.

ZKB++ (§1-§3) OPENS SEEDS, NOT VIEWS, and that changes the answer rather than
just the plumbing.  Only party e+2's AND-gate outputs are revealed -- party
e+1's are RECOMPUTED by the verifier -- so the single revealed gate vector is
exactly the one whose mask r_e is a tape bit of the party that was never opened.
Under an ideal seed expansion that leaves the witness completely free (§1).  But
the hidden party's seed is 16 BYTES and determines BOTH its share and its tape,
so the freedom is not unconditional the way ZKBoo's independent draws are: a
candidate survives only if SOME seed produces both.  That is a counting
question, and §2 answers it exactly --

    a round with hidden party e in {0, 1} constrains its seed by 2n-1 bits
      (n bits of share, n-1 of tape), and a round with e = 2 by only n-1,
      because party 2's share is DERIVED (s2 = A ^ s0 ^ s1) rather than seeded

-- measured against 2^(k-c) at three widths and in both regimes.  THE
CONSEQUENCE IS NOT ACADEMIC: with k = 128 the seeded regime has 129-2n bits of
slack, so the margin collapses at n = 64, which is _ZKP_NL_MAX_N exactly.  The
construction stays COMPUTATIONALLY hiding there (finding the excluded candidates
means searching 2^128 seeds) but it is not STATISTICALLY hiding, and the repo
did not draw that line anywhere.  At the CLI default n = 8 the slack is 113
bits.

KKW (§4-§5) OPENS A PRE-PROCESSING EMULATION PLUS AN ONLINE EXECUTION, and the
witness lives in Z_q^288, so counting survivors by enumeration is not available.
It does not need to be: the observer's system is SOLVABLE IN CLOSED FORM.  Every
unknown of the hidden party -- lambda_in from z_in, lambda_xy from the
sum-to-product relation, lambda_z from the revealed t -- is determined in one
pass for ANY candidate witness, leaving exactly ONE residual equation, the u
check.  §4 measures what that equation is, and the answer is an exact identity:

    u' - u  ==  -rho . (circuit(w') - targets)     (mod q)

i.e. the transcript's only constraint on a candidate is the VERIFIER'S OWN
STATEMENT PROJECTION, which is a function of public data alone.  Identical in
every online emulation, so the tau of them are not tau independent constraints.
§4 then does the constructive half: it solves for a SECOND witness the public
statement cannot separate from the true one and shows the transcript cannot
separate it either.

Exits non-zero if a finding stops reproducing.
"""

import argparse
import importlib.util
import math
import os
import re
import sys
import time
import warnings

warnings.filterwarnings("ignore", category=RuntimeWarning)

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
SEP = "=" * 74


def _load_suite():
    path = os.path.join(_ROOT, "Herradura cryptographic suite.py")
    spec = importlib.util.spec_from_file_location("hsuite", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


H = _load_suite()
Q = H.RNLQ


# ---------------------------------------------------------------------------
# §1-§3 — ZKB++
# ---------------------------------------------------------------------------

def _cached_prg():
    memo = {}

    def f(tape, i):
        k = (bytes(tape), i)
        if k not in memo:
            memo[k] = H._zkp_nl_prg_bit(tape, i)
        return memo[k]
    return f


def _open_party(p, seed, share2_b, nb, mask):
    """What the verifier reconstructs for one opened party.  Party 2's share is
    sent explicitly (it is derived, not seeded); the others come from the seed."""
    if p == 2:
        return int.from_bytes(share2_b, 'big') & mask, H._zkp_nl_h(seed, b'tape')
    return H._zkpp_derive(seed, nb, mask)


def _required_tape(A_cand, e, sp1, tp1, sp2, tp2, gp2, B, n, prg):
    """The hidden party's tape bits that this candidate would force.

    Party e+2's revealed AND output is the only per-round equation, and its
    `+1` neighbour IS the hidden party -- so r_e is the single mask, and the
    equation is SOLVED rather than checked.  Returned packed, because §2 and §3
    then ask whether any seed can supply that exact pattern.
    """
    p1, p2 = (e + 1) % 3, (e + 2) % 3
    mask = (1 << n) - 1
    sh = {e: (A_cand ^ sp1 ^ sp2) & mask, p1: sp1, p2: sp2}
    c = {e: 0, p1: 0, p2: 0}
    pat = 0
    for i in range(n - 1):
        a = {p: (sh[p] >> i) & 1 for p in (e, p1, p2)}
        r1, r2 = prg(tp1, i), prg(tp2, i)
        base2 = (a[p2] & c[p2]) ^ (a[p2] & c[e]) ^ (a[e] & c[p2])
        re = gp2[i] ^ base2 ^ r2
        pat |= re << i
        ao = {p2: gp2[i],
              p1: (a[p1] & c[p1]) ^ (a[p1] & c[p2]) ^ (a[p2] & c[p1]) ^ r1 ^ r2,
              e:  (a[e] & c[e]) ^ (a[e] & c[p1]) ^ (a[p1] & c[e]) ^ re ^ r1}
        Bi = (B >> i) & 1
        c = {p: (Bi * a[p]) ^ ao[p] ^ (Bi * c[p]) for p in (e, p1, p2)}
    return pat


def _zkbpp_proof(n, rounds, seed_bytes=None):
    orig = H._ZKPP_SEED_BYTES
    if seed_bytes:
        H._ZKPP_SEED_BYTES = seed_bytes
    try:
        A, B, y = H.zkp_nl_keygen(n)
        proof = H.zkp_nl_prove_pp(A, B, y, n, rounds, b"TODO-302")
        good = H.zkp_nl_verify_pp(B, y, n, rounds, b"TODO-302", proof)
    finally:
        H._ZKPP_SEED_BYTES = orig
    return A, B, proof, good


def _seed_supply(e, seed_bytes, sp1, sp2, nb, mask, n):
    """What a seed space of 2^(8*seed_bytes) can actually produce this round:
    share -> the tape patterns reachable alongside it (or, when the hidden
    party is party 2, the tape patterns alone -- its share is not seeded)."""
    supply, free = {}, {}
    for k in range(1 << (8 * seed_bytes)):
        sd = k.to_bytes(seed_bytes, 'big')
        te = H._zkp_nl_h(sd, b'tape')
        pat = 0
        for i in range(n - 1):
            pat |= H._zkp_nl_prg_bit(te, i) << i
        if e == 2:
            free[pat] = free.get(pat, 0) + 1
        else:
            se = int.from_bytes(H._zkp_nl_h(sd, b'share')[:nb], 'big') & mask
            supply.setdefault((se ^ sp1 ^ sp2) & mask, {}).setdefault(pat, 0)
            supply[(se ^ sp1 ^ sp2) & mask][pat] += 1
    return supply, free


def _zkbpp_survivors(n, rounds, seed_bytes=None):
    """(survivors, total, true-A-kept, per-regime seed-hit tallies)."""
    A, B, proof, good = _zkbpp_proof(n, rounds, seed_bytes)
    nb, mask = (n + 7) // 8, (1 << n) - 1
    prg = _cached_prg()
    surv = set(range(1 << n))
    # One OBSERVATION PER ROUND, not per candidate.  The 2^n candidates of a
    # round are scored against the same enumerated seed multiset, so a
    # fluctuation in that multiset moves all of them together: they are one
    # measurement, not 2^n.  A first pass banded them as independent cells and
    # got a band roughly an order of magnitude too tight, which showed up as
    # ratios wandering 0.84-1.28 between runs with no defect behind them.
    obs = {'seeded': [], 'derived': []}
    for rd in proof:
        e = rd['e']
        p1, p2 = (e + 1) % 3, (e + 2) % 3
        sp1, tp1 = _open_party(p1, rd['seed_p1'], rd['share2'], nb, mask)
        sp2, tp2 = _open_party(p2, rd['seed_p2'], rd['share2'], nb, mask)
        gp2 = H._zkpp_unpack_bits(rd['gates_p2'], n - 1)
        if seed_bytes is None:
            continue                 # ideal expansion: the seed constrains nothing
        supply, free = _seed_supply(e, seed_bytes, sp1, sp2, nb, mask, n)
        key = 'derived' if e == 2 else 'seeded'
        keep = set()
        pats = {}
        hits = cells = 0
        for a in range(1 << n):
            pat = _required_tape(a, e, sp1, tp1, sp2, tp2, gp2, B, n, prg)
            pats[a] = pat
            h = free.get(pat, 0) if e == 2 else supply.get(a, {}).get(pat, 0)
            # The true witness is NOT a random cell: the prover's own seed is
            # inside the enumerated space, so that cell always scores at least
            # one hit by construction.  Scoring it biases the mean upward by one
            # per round, so §2 measures the other candidates; §1 and §3 keep the
            # survivor count, which is where the true witness has to be counted.
            if a != A:
                hits += h
                cells += 1
            if h and a in surv:
                keep.add(a)
        # A SECOND certain hit, and it exists only in the derived regime: there
        # a seed is keyed by the tape pattern ALONE -- party 2's share is not
        # seeded -- so a candidate colliding with the true seed's pattern
        # inherits that seed.  In the seeded regime the key carries the share
        # too and a != A cannot collide.  Arithmetic, so it belongs in the
        # prediction rather than in a wider band.
        sure = (sum(1 for a in pats if a != A and pats[a] == pats[A])
                if e == 2 else 0)
        c = (n - 1) if e == 2 else (2 * n - 1)
        # (2^k - 1), not 2^k: the true seed is accounted for by `sure`.
        expect = cells * (2.0 ** (8 * seed_bytes) - 1) / 2.0 ** c + sure
        obs[key].append(hits / expect if expect else float('nan'))
        surv = keep
    return len(surv), 1 << n, A in surv, obs, good


def section1(n=8, rounds=8):
    print(SEP)
    print(f"§1 — ZKB++: the two opened seeds vs. the witness  (n={n}, "
          f"rounds={rounds})")
    print(SEP)
    print("  ZKB++ reveals FEWER per-round fields than ZKBoo: party e+1's gate")
    print("  outputs are recomputed by the verifier, so `gates_p2` is the only")
    print("  revealed gate vector -- and its mask r_e is a tape bit of the party")
    print("  that was never opened.  Under an ideal seed expansion that leaves")
    print("  every candidate consistent.  §2 is where the seed stops being ideal.")
    surv, total, kept, _o, good = _zkbpp_survivors(n, rounds, None)
    print(f"  proof verifies   : {good}")
    print(f"  candidates for A : {total}")
    print(f"  surviving        : {surv}")
    print(f"  true A kept      : {kept}")
    print(f"  narrowed by      : {0 if surv == total else '>0'} bits")
    ok = good and surv == total and kept
    print(f"  Hiding           : {'PASS' if ok else 'FAIL — the seeds narrow A'}")
    return ok


def section2(widths=(4, 6, 8), rounds=6, trials=4, seed_bytes=1):
    print(SEP)
    print("§2 — ZKB++: the seed budget, and where it runs out")
    print(SEP)
    k = 8 * seed_bytes
    print("  A hidden party's seed must supply BOTH its share and its tape, so a")
    print("  candidate survives only if some seed produces both.  Constraint per")
    print("  round: c = 2n-1 when the hidden party is 0 or 1, and c = n-1 when it")
    print("  is party 2 -- whose share is derived, not seeded.  Expected number of")
    print(f"  consistent seeds is then 2^(k-c), here with k = {k}.")
    print()
    print("  ONE OBSERVATION PER ROUND.  A round's candidates all meet the same")
    print("  enumerated seed multiset, so they move together and are one")
    print("  measurement, not 2^n of them; a first pass banded them as")
    print("  independent cells and got a band an order of magnitude too tight.")
    print()
    print("  THE GATE IS ON THE EXPONENT, and that is a deliberate limit.  The")
    print("  CONSTANT carries small-width combinatorics this file does not model")
    print("  in full -- the certain-hit term below is one piece of it, and the")
    print("  residue is worth 0.2-0.6 bits at n = 4 -- so gating it would be")
    print("  gating an artifact.  The exponent is what the claim rests on, and")
    print("  the two candidate exponents (2n-1 against n-1) differ by n BITS, so")
    print("  a 1-bit band separates them with room to spare.")
    print()
    print(f"  {'n':>3}  {'regime':<8} {'c':>3}  {'rounds':>6}  {'ratio':>7}"
          f"  {'bits off':>9}  verdict")
    ok = True
    for n in widths:
        agg = {'seeded': [], 'derived': []}
        for _ in range(trials):
            _s, _t, _kept, obs, _g = _zkbpp_survivors(n, rounds, seed_bytes)
            for key in agg:
                agg[key].extend(obs[key])
        for key, c in (('seeded', 2 * n - 1), ('derived', n - 1)):
            r = [x for x in agg[key] if x == x and x > 0]
            if len(r) < 5:
                print(f"  {n:>3}  {key:<8} {c:>3}  {len(r):>6}  {'—':>7}"
                      f"  {'—':>9}  thin")
                continue
            mean = sum(r) / len(r)
            bits = abs(math.log2(mean))
            good = bits <= 1.0
            ok &= good
            print(f"  {n:>3}  {key:<8} {c:>3}  {len(r):>6}  {mean:>7.3f}"
                  f"  {bits:>9.2f}  {'PASS' if good else 'FAIL'}")
    print()
    K_SHIPPED = 8 * H._ZKPP_SEED_BYTES
    print(f"  CONSEQUENCE at the shipped seed length (k = {K_SHIPPED}):")
    for n, label in ((8, "CLI default"), (32, ""), (62, ""),
                     (64, "_ZKP_NL_MAX_N")):
        c = 2 * n - 1
        print(f"    n = {n:>3}  c = {c:>3}  slack = {K_SHIPPED - c:>4} bits"
              f"   {label}")
    print("  So the seeded regime keeps 113 bits of slack at the default width and")
    print("  ONE bit at the wire maximum.  At n = 64 an unbounded observer can")
    print("  exclude candidates; a bounded one cannot, since reaching them means")
    print("  searching 2^128 seeds.  Computationally hiding, not statistically so,")
    print("  and only at that one width.")
    print(f"  §2               : {'PASS' if ok else 'FAIL — the counting law moved'}")
    return ok


def section3(n=8, rounds=6, seed_bytes=1):
    print(SEP)
    print("§3 — ZKB++ NEGATIVE CONTROL: the seed budget taken away")
    print(SEP)
    print(f"  A {seed_bytes}-byte seed is {8*seed_bytes} bits against a {2*n-1}-bit")
    print("  constraint, so almost no candidate has a consistent seed and the set")
    print("  collapses.  If this does not FIRE, §1 is asserting nothing.  The true")
    print("  witness MUST survive -- a control that fires by excluding it is")
    print("  measuring the checker, which is how two of #301's drafts died.")
    surv, total, kept, _o, good = _zkbpp_survivors(n, rounds, seed_bytes)
    fired = surv < total
    print(f"  proof still verifies : {good}")
    print(f"  surviving            : {surv} / {total}   true A kept: {kept}")
    print(f"  Control              : {'FIRES' if fired else 'DID NOT FIRE'}")
    ok = fired and kept and good
    print(f"  §3                   : {'PASS' if ok else 'FAIL'}")
    return ok


# ---------------------------------------------------------------------------
# §4-§5 — KKW
# ---------------------------------------------------------------------------

def _kkw_setup(n=32, N_par=4, M=8, tau=4, msg=b"TODO-302"):
    m = H._rnl_poly_add(H._rnl_m_poly(n), H._rnl_rand_poly(n, Q), Q)
    seed_H = H.BitArray.random(n)
    s, C, e_int = H.hcred_user_keygen(m, n)
    y = H.hcred_syndrome(seed_H, e_int, n)
    p = H.hcred_prove_kkw(s, m, C, seed_H, y, n, N_par=N_par, M=M, tau=tau,
                          msg_bytes=msg)
    good = H.hcred_verify_kkw(m, C, seed_H, y, p, n, msg)
    return dict(n=n, m=m, C=C, seed_H=seed_H, y=y, s=s, proof=p, msg=msg,
                good=good)


def _kkw_public(ctx):
    """Everything an observer recomputes from the proof alone -- the same walk
    hcred_verify_kkw does, kept here so the observer uses no prover state."""
    n = ctx['n']
    p = ctx['proof']
    N_par, M, tau = p['params']
    rows, row_bits, _w = H._hcred_params(n)
    nb = rows * row_bits
    nd = n * H._HCRED_EPS_BITS
    I, G = n + nb + nd, 2 * n + nb + nd
    gates = H._hcred_kkw_gates(n, nb, nd)
    H_rows = H._stern_build_H(ctx['seed_H'].uint, n, rows)
    stmt = H._hcred_stmt_hash(ctx['m'], ctx['C'], ctx['seed_H'], ctx['y'], n,
                              ctx['msg'])
    lvl = N_par.bit_length() - 1
    h_es = [None] * M
    for e, root in p['pre'].items():
        nodes, li, lz, lxy, aux = H._hcred_kkw_pre(root, N_par, I, G, gates)
        coms = [H._hcred_kkw_state_com(e, j, nodes[(lvl, j)],
                                       aux if j == N_par - 1 else None)
                for j in range(N_par)]
        h_es[e] = H.hfscx_256(b'HCRED-kkwem' + e.to_bytes(2, 'big')
                              + b''.join(coms))
    on = {}
    for e, od in p['online'].items():
        pb = od['pbar']
        leaves = H._hcred_kkw_tree_recover(od['path'], N_par)
        coms = [od['com_h'] if j == pb else
                H._hcred_kkw_state_com(e, j, leaves[j],
                                       od['aux'] if j == N_par - 1 else None)
                for j in range(N_par)]
        h_es[e] = H.hfscx_256(b'HCRED-kkwem' + e.to_bytes(2, 'big')
                              + b''.join(coms))
        shares = {}
        for j, seed in leaves.items():
            li, lz, lxy = H._hcred_kkw_party(seed, I, G)
            if j == N_par - 1:
                lxy = [(lxy[g] + od['aux'][g]) % Q for g in range(G)]
            shares[j] = (li, lz, lxy)
        on[e] = dict(shares=shares, pb=pb, od=od)
    h_pre = H.hfscx_256(b'HCRED-kkwpre' + stmt + b''.join(h_es))
    subset = sorted(p['online'])
    for e in subset:
        od = on[e]['od']
        zin = od['zin']
        zz = [0] * G
        tvec = {j: [0] * len(gates) for j in on[e]['shares']}
        for gidx, (xk, xi, yk, yi, zi) in enumerate(gates):
            zx = zin[xi] if xk == 'in' else zz[xi]
            zy = zin[yi] if yk == 'in' else zz[yi]
            acc = od['t'][gidx]
            for j, (li, lz, lxy) in on[e]['shares'].items():
                lx = li[xi] if xk == 'in' else lz[xi]
                ly = li[yi] if yk == 'in' else lz[yi]
                t = (-zx * ly - zy * lx + lxy[gidx] + lz[zi]) % Q
                if j == 0:
                    t = (t + zx * zy) % Q
                tvec[j][gidx] = t
                acc += t
            zz[zi] = acc % Q
        on[e]['zz'] = zz
        on[e]['tvec'] = tvec
    msk = []
    for e in subset:
        od = on[e]['od']
        msk.append(H._hcred_ser(od['zin']))
        for j in range(N_par):
            msk.append(H._hcred_ser(od['t'] if j == on[e]['pb']
                                    else on[e]['tvec'][j]))
    h_msk = H.hfscx_256(b'HCRED-kkwmsk' + b''.join(msk))
    K = I + 1 + 2 * rows + n
    rho = H._HcredTape(H.hfscx_256(b'HCRED-kkwrho' + stmt + h_pre
                                   + h_msk)).draws(K)
    targets = H._hcred_kkw_targets(p['W'], ctx['y'], ctx['C'], n, rows,
                                   row_bits)
    return dict(I=I, G=G, gates=gates, H_rows=H_rows, rho=rho, K=K,
                targets=targets, on=on, subset=subset, N_par=N_par, rows=rows,
                row_bits=row_bits, n=n, nb=nb, m=ctx['m'])


def _kkw_witness(ctx, R):
    rows, rb = R['rows'], R['row_bits']
    W, beta, delta = H._hcred_witness(ctx['s'], ctx['m'], ctx['C'], R['H_rows'],
                                      ctx['y'], ctx['n'], rows, rb)
    return [x % Q for x in ctx['s']] + beta + delta


def _kkw_circuit(R, w):
    zz = [0] * R['G']
    for _g, (xk, xi, yk, yi, zi) in enumerate(R['gates']):
        x = w[xi] if xk == 'in' else zz[xi]
        y = w[yi] if yk == 'in' else zz[yi]
        zz[zi] = (x * y) % Q
    return zz


def _kkw_projection(R, w):
    """rho . (the circuit's own output relation), a function of PUBLIC data and
    the candidate -- the verifier's statement check, with no transcript in it."""
    z = _kkw_circuit(R, w)
    out = H._hcred_kkw_outmap(w, z, R['m'], R['H_rows'], R['n'], R['rows'],
                              R['row_bits'])
    return sum(R['rho'][k] * ((out[k] - R['targets'][k]) % Q)
               for k in range(R['K'])) % Q


def _kkw_solve(R, e, w_cand):
    """Solve the hidden party's masks for a candidate, and return the u it
    forces.  Every unknown is determined in one pass; u is the one residual."""
    info = R['on'][e]
    od, pb, sh = info['od'], info['pb'], info['shares']
    zin, zz = od['zin'], info['zz']
    I, G = R['I'], R['G']
    lam_in = [(zin[w] - w_cand[w] - sum(sh[j][0][w] for j in sh)) % Q
              for w in range(I)]
    lam_z = [0] * G
    tin = [(zin[w] - w_cand[w]) % Q for w in range(I)]
    tz = [0] * G
    for gidx, (xk, xi, yk, yi, zi) in enumerate(R['gates']):
        zx = zin[xi] if xk == 'in' else zz[xi]
        zy = zin[yi] if yk == 'in' else zz[yi]
        lx_pb = lam_in[xi] if xk == 'in' else lam_z[xi]
        ly_pb = lam_in[yi] if yk == 'in' else lam_z[yi]
        lx_tot = tin[xi] if xk == 'in' else tz[xi]
        ly_tot = tin[yi] if yk == 'in' else tz[yi]
        # Sum over ALL parties of the corrected lambda_xy is lx*ly by
        # construction, so the hidden share is determined whether or not aux
        # was revealed -- pbar == N-1 buys no extra freedom.
        lxy_pb = (lx_tot * ly_tot - sum(sh[j][2][gidx] for j in sh)) % Q
        base = (-zx * ly_pb - zy * lx_pb + lxy_pb) % Q
        if pb == 0:
            base = (base + zx * zy) % Q
        lam_z[zi] = (od['t'][gidx] - base) % Q
        tz[zi] = (sum(sh[j][1][zi] for j in sh) + lam_z[zi]) % Q
    lo = H._hcred_kkw_outmap(lam_in, lam_z, R['m'], R['H_rows'], R['n'],
                             R['rows'], R['row_bits'])
    return sum(R['rho'][k] * lo[k] for k in range(R['K'])) % Q, lam_in


def _kkw_alt_witness(R, w_true, idx):
    """A SECOND witness the public statement cannot separate from the true one.

    The residual is quadratic in a delta-block coefficient (that wire enters the
    circuit only as h = delta^2 and the output map only as h - delta), and the
    true value is one root, so the other root is an explicit indistinguishable
    twin.  Degree 2 is asserted, not assumed.
    """
    x0 = w_true[idx]

    def f(d):
        w = list(w_true)
        w[idx] = (x0 + d) % Q
        return _kkw_projection(R, w)

    y0, y1, y2, y3 = f(0), f(1), f(2), f(3)
    a = ((y2 - 2 * y1 + y0) * pow(2, Q - 2, Q)) % Q
    b = (y1 - y0 - a) % Q
    if y0 % Q != 0 or (9 * a + 3 * b + y0) % Q != y3 % Q or a == 0:
        return None
    d = ((-b) * pow(a, Q - 2, Q)) % Q
    if d == 0:
        return None
    w = list(w_true)
    w[idx] = (x0 + d) % Q
    return w


def section4(perturbations=4):
    print(SEP)
    print("§4 — KKW: what the online view constrains, beyond the masks")
    print(SEP)
    t0 = time.time()
    ctx = _kkw_setup()
    R = _kkw_public(ctx)
    w_true = _kkw_witness(ctx, R)
    print(f"  proof verifies   : {ctx['good']}   (built in {time.time()-t0:.0f} s)")
    print(f"  witness lives in : Z_{Q}^{R['I']}  — not enumerable, and it does")
    print("                     not need to be: the observer's system is solvable.")
    print()
    print("  (a) the solver reproduces the hidden party's u for the TRUE witness")
    base_ok = True
    for e in R['subset']:
        u, _ = _kkw_solve(R, e, w_true)
        hit = u == R['on'][e]['od']['u'] % Q
        base_ok &= hit
        print(f"      emu {e:>2}  pbar={R['on'][e]['pb']}  u matches: {hit}")
    print()
    print("  (b) for a WRONG candidate the one residual equation is exactly the")
    print("      verifier's own statement projection:  u' - u == -rho.(residual)")
    import random
    random.seed(302)
    ident_ok = True
    same_across = True
    for _ in range(perturbations):
        w = list(w_true)
        i = random.randrange(R['I'])
        w[i] = (w[i] + random.randrange(1, Q)) % Q
        res = _kkw_projection(R, w)
        diffs = []
        for e in R['subset']:
            u, _ = _kkw_solve(R, e, w)
            diffs.append((u - R['on'][e]['od']['u']) % Q)
        ident_ok &= all(d == (-res) % Q for d in diffs)
        same_across &= len(set(diffs)) == 1
        print(f"      coefficient {i:>3} moved: rho.residual={res:>6}  "
              f"u'-u={diffs[0]:>6} in all {len(diffs)} emulations  "
              f"identity: {all(d == (-res) % Q for d in diffs)}")
    print()
    print("      The tau emulations give the SAME equation, not tau independent")
    print("      ones — and that equation contains no per-emulation secret.")
    print()
    print("  (c) the constructive half: a SECOND witness the public statement")
    print("      cannot separate, which the transcript cannot separate either")
    alt = None
    for off in range(6):
        alt = _kkw_alt_witness(R, w_true, R['n'] + R['nb'] + off)
        if alt is not None:
            idx = R['n'] + R['nb'] + off
            break
    twin_ok = False
    if alt is None:
        print("      could not construct one (no quadratic root) — see §4 notes")
    else:
        pub = _kkw_projection(R, alt)
        hits = []
        for e in R['subset']:
            u, _ = _kkw_solve(R, e, alt)
            hits.append(u == R['on'][e]['od']['u'] % Q)
        print(f"      differs in coefficient {idx}: {w_true[idx]} -> {alt[idx]}")
        print(f"      public statement projection : {pub}  (0 = indistinguishable)")
        print(f"      transcript-consistent in    : {sum(hits)}/{len(hits)} emulations")
        twin_ok = pub == 0 and all(hits)
    ok = base_ok and ident_ok and same_across and twin_ok
    print(f"  §4               : {'PASS' if ok else 'FAIL'}")
    return ok


def section5():
    print(SEP)
    print("§5 — KKW NEGATIVE CONTROL: the one-time pad made public")
    print(SEP)
    print("  z_in = w + sum_j lambda_in[j] hides the witness because the hidden")
    print("  party's share of that sum is unknown.  Derive every party's masks")
    print("  from a CONSTANT seed and the pad becomes public arithmetic, so z_in")
    print("  names the witness outright.  The true witness must be what comes")
    print("  back — a control that returned anything else would be a solver bug.")
    orig = H._hcred_kkw_party
    H._hcred_kkw_party = lambda seed, I, G: orig(b'\x00' * 32, I, G)
    try:
        ctx = _kkw_setup()
        R = _kkw_public(ctx)
    finally:
        H._hcred_kkw_party = orig
    w_true = _kkw_witness(ctx, R)
    known = orig(b'\x00' * 32, R['I'], R['G'])[0]
    N_par = R['N_par']
    e = R['subset'][0]
    zin = R['on'][e]['od']['zin']
    rec = [(zin[w] - N_par * known[w]) % Q for w in range(R['I'])]
    fired = rec == w_true
    print(f"  control proof still verifies : {ctx['good']}")
    print(f"  witness read straight off z_in: {fired}")
    print(f"  surviving candidates          : 1 of {Q}^{R['I']}")
    ok = fired and ctx['good']
    print(f"  Control                       : {'FIRES' if fired else 'DID NOT FIRE'}")
    print(f"  §5                            : {'PASS' if ok else 'FAIL'}")
    return ok


def section6():
    print(SEP)
    print("§6 — SCOPE: what pins these properties across the four ports")
    print(SEP)
    print("  #301's cheap answer was that KAT/operation_replay.json already")
    print("  pinned ZKBoo's masking term byte-exactly, so no per-port test was")
    print("  needed.  #302's note said to ask the same question here rather than")
    print("  assume it.  The answers differ -- and both are CHECKED below rather")
    print("  than asserted, because a scope paragraph nobody re-reads is exactly")
    print("  how #287's withdrawn trust-model sentence survived.")
    print()
    import json as _json

    def _body(text, start_pat, end_pat):
        m = re.search(start_pat, text)
        if not m:
            return None
        rest = text[m.end():]
        e = re.search(end_pat, rest)
        return rest[:e.start()] if e else rest

    checks = []

    # (a) ZKB++ does not carry its own circuit in C or Go, so ZKBoo's pinned
    #     row covers its masking term too.  Scoped to the prover's BODY:
    #     an unscoped grep would match the ZKBoo prover further up the file.
    c_src = open(os.path.join(_ROOT, "herradura.h")).read()
    c_body = _body(c_src, r"static ZkpNlPpRound \*zkp_nl_pp_prove\(",
                   r"\n(static|/\*\*|[A-Za-z_].*\n\{)")
    checks.append(("C   zkp_nl_pp_prove calls the shared zkp_nl_eval_3p",
                   bool(c_body) and "zkp_nl_eval_3p" in c_body))
    go_src = open(os.path.join(_ROOT, "herradura", "herradura.go")).read()
    go_body = _body(go_src, r"func ZkpNlProvepp\(", r"\nfunc ")
    checks.append(("Go  ZkpNlProvepp calls the shared zkpNlEvalCircuit",
                   bool(go_body) and "zkpNlEvalCircuit" in go_body))

    # (b) the seed length is a security parameter (§2), so it must be on the
    #     axis that compares a constant's VALUE across the four languages.
    par = open(os.path.join(_ROOT, "spec", "check_language_parity.py")).read()
    checks.append(("    zkpp-seed-bytes is a PARAMETERS row",
                   '"zkpp-seed-bytes"' in par))

    # (c) KKW's prover is pinned NOWHERE, and this must self-invalidate: if a
    #     replay row is ever added, this fires and the prose above is wrong.
    ops = _json.load(open(os.path.join(_ROOT, "KAT",
                                       "operation_replay.json")))
    names = {o["name"] for o in ops["operations"]}
    checks.append(("    no KKW prover row in operation_replay.json "
                   "(self-invalidating)", "hcred_prove_kkw" not in names))
    kkw = _json.load(open(os.path.join(_ROOT, "KAT", "hcred_kkw.json")))
    checks.append(("    hcred_kkw.json still declares itself VERIFY-SIDE",
                   "VERIFY-SIDE" in kkw.get("note", "")))

    for label, good in checks:
        print(f"  [{'ok' if good else 'XX'}] {label}")
    print()
    print("  ZKB++ — COVERED: the masking term by operation_replay.json's")
    print("    zkp_nl_prove row (same evaluator, checked above) and the seed")
    print("    length by check_language_parity.py's zkpp-seed-bytes row.  So this")
    print("    file is Python-only for #301's reason, reached differently.")
    print("  KKW — NOT COVERED, and not by oversight: hcred_kkw.json is")
    print("    VERIFY-SIDE by construction, so it exercises no port's PROVER; and")
    print("    KKW has no CLI surface in any language, so the 4x4 interop matrix")
    print("    covering HCRED's sigma variant does not reach it.  §4-§5 are the")
    print("    only check of this property in the repo, which is #298's rule (1).")
    print("    Pinning KKW's prover across ports is a replay-vector job, filed.")
    ok = all(g for _l, g in checks)
    print(f"  §6               : {'PASS' if ok else 'FAIL'}")
    return ok


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--quick", action="store_true",
                    help="narrower §2 ladder and fewer §4 perturbations; "
                         "the findings still gate")
    args = ap.parse_args()

    print()
    print("zkbpp_kkw_view_hiding.py — TODO #302: ZKB++ opens seeds, KKW opens "
          "an emulation")
    print()
    widths = (4, 8) if args.quick else (4, 6, 8)
    rounds2 = 6 if args.quick else 6
    trials = 3 if args.quick else 5
    perts = 2 if args.quick else 4
    findings = [
        ("§1 ZKB++ seeds do not determine A", section1()),
        ("§2 the seed-budget law holds", section2(widths=widths, rounds=rounds2, trials=trials)),
        ("§3 ZKB++ control fires", section3()),
        ("§4 KKW adds only the statement check", section4(perturbations=perts)),
        ("§5 KKW control fires", section5()),
        ("§6 cross-port scope is stated", section6()),
    ]

    print()
    print(SEP)
    bad = [name for name, ok in findings if not ok]
    for name, ok in findings:
        print(f"  {name:<42} {'PASS' if ok else 'FAIL'}")
    if bad:
        print("\n*** FAILED: %d finding(s) stopped reproducing: %s ***"
              % (len(bad), ", ".join(bad)))
    else:
        print("\n*** OK: all %d findings reproduce ***" % len(findings))
    print(SEP)
    return 1 if bad else 0


if __name__ == '__main__':
    sys.exit(main())
