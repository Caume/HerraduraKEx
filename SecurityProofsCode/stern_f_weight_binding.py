#!/usr/bin/env python3
"""TODO #298 — the two properties no Stern test in this repo asserted.

Every existing check on HPKS-Stern-F and HPKS-Stern-Ring asserts COMPLETENESS
(an honest transcript verifies) or SOUNDNESS-BY-TAMPER (a poked transcript does
not).  Neither of those can see the two defects below, and both shipped for the
life of all seven ports.

  §1  WITNESS-WEIGHT BINDING.  The b = 0 response must bind wt(e) = t.  Until
      v8.0.0 the prover drew r weight-t and the verifier checked wt(sigma(r))
      for b = 0 and wt(r) for b = 1 -- both of them the PROVER'S OWN BLINDING
      VALUE.  Nothing bound wt(e), so the statement proved was "I know some
      preimage of s under H", and H is n/2 x n: a preimage is one Gaussian
      elimination away from the PUBLIC key.  Universal forgery, no secret.
      This section builds that forgery and asserts the shipped verifier rejects
      it -- and, as a control, that the RETIRED rule accepts it.

  §2  RING ANONYMITY, structurally.  A ring signature must not carry a marker
      that separates the signer's rounds from the simulated ones.  Two markers
      are checked: a repeated commitment value (TODO #297's defect, the constant
      b = 0 dummy c0), and a response statistic that identifies the signer
      (this item's: the simulated b = 0 pair had wt(respA ^ respB) ~ n/2 where a
      real signer's is exactly t, so ONE b = 0 round named the signer).

  §3  NEGATIVE CONTROLS.  Both sections are re-run against the RETIRED
      constructions and must FAIL there.  A hiding test that cannot fail is the
      vacuous pass TODO #234 found in the Arduino harness, one layer out.

Exits non-zero if a finding stops reproducing.
"""

import argparse
import importlib.util
import os
import sys
import warnings

# The sections run at demo round counts on purpose -- soundness per round is
# not what is under test here, and 219 rounds x 20 trials x 2 blocks is hours.
warnings.filterwarnings("ignore", category=RuntimeWarning)

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)


def _load_suite():
    path = os.path.join(_ROOT, "Herradura cryptographic suite.py")
    spec = importlib.util.spec_from_file_location("hsuite", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


H = _load_suite()
N = H.KEYBITS
NROWS = N // 2
T = max(2, N // 16)
MASK = (1 << N) - 1


def _uniform(n=N):
    return int.from_bytes(os.urandom(n // 8), "big") & ((1 << n) - 1)


# ---------------------------------------------------------------------------
# §1 — witness-weight binding
# ---------------------------------------------------------------------------

def _solve_syndrome(H_rows, syndrome):
    """Any e' with H.e'^T == syndrome, by Gaussian elimination over GF(2).

    Uses ONLY public data (the matrix seed and the syndrome).  The free
    variables are all set to zero, which is why the result has weight ~n/4
    rather than t -- any other setting would do.
    """
    aug = [[H_rows[i], (syndrome >> i) & 1] for i in range(len(H_rows))]
    pivots = []
    row = 0
    for col in range(N - 1, -1, -1):
        sel = next((k for k in range(row, len(aug)) if (aug[k][0] >> col) & 1),
                   None)
        if sel is None:
            continue
        aug[row], aug[sel] = aug[sel], aug[row]
        for k in range(len(aug)):
            if k != row and ((aug[k][0] >> col) & 1):
                aug[k][0] ^= aug[row][0]
                aug[k][1] ^= aug[row][1]
        pivots.append((col, row))
        row += 1
    e = 0
    for col, k in pivots:
        if aug[k][1]:
            e |= 1 << col
    return e


def _verify_retired_rule(msg, sig, seed, syndrome):
    """The verifier as it stood until v8.0.0: wt(respA) = t for b = 0 and
    wt(respB) = t for b = 1, with nothing checking wt(e).  Kept here as §1's
    control -- the forgery must be ACCEPTED by this and REJECTED by the shipped
    one, or the section is measuring something other than the rule that moved.
    """
    commits, challenges, responses = sig
    flat = [msg]
    for c0, c1, c2 in commits:
        flat += [c0, c1, c2]
    ch_st = H._stern_hash(N, *flat)
    for i, b in enumerate(challenges):
        ch_st = H.nl_fscx_v1(ch_st, H.BitArray(N, i))
        if (ch_st.uint & 0xFFFFFFFF) % 3 != b:
            return False
    H_rows = H._stern_build_H(seed.uint, N, NROWS)
    for i, b in enumerate(challenges):
        c0, c1, c2 = commits[i]
        resp = responses[i]
        if b == 0:
            sr, sy = resp
            if H._stern_hash(N, H.BitArray(N, sr), ds=2) != c1:
                return False
            if H._stern_hash(N, H.BitArray(N, sy), ds=3) != c2:
                return False
            if bin(sr).count("1") != T:            # the RETIRED check
                return False
        elif b == 1:
            pi_seed, r_int = resp
            if bin(r_int).count("1") != T:         # the RETIRED check
                return False
            perm = H._stern_gen_perm(pi_seed, N)
            Hr = H._stern_syndrome_H(H_rows, r_int)
            if H._stern_hash(N, pi_seed, H.BitArray(N, Hr), ds=1) != c0:
                return False
            sr = H._stern_apply_perm(perm, r_int, N)
            if H._stern_hash(N, H.BitArray(N, sr), ds=2) != c1:
                return False
        else:
            pi_seed, y_int = resp
            perm = H._stern_gen_perm(pi_seed, N)
            Hy = H._stern_syndrome_H(H_rows, y_int)
            if H._stern_hash(N, pi_seed,
                             H.BitArray(N, Hy ^ syndrome), ds=1) != c0:
                return False
            sy = H._stern_apply_perm(perm, y_int, N)
            if H._stern_hash(N, H.BitArray(N, sy), ds=3) != c2:
                return False
    return True


def _sign_retired(msg, e_int, seed, rounds):
    """The prover as it stood until v8.0.0: weight-t blinding.  Only the r draw
    differs from the shipped one; everything else is the suite's own helpers."""
    H_rows = H._stern_build_H(seed.uint, N, NROWS)
    commits, data = [], []
    for _ in range(rounds):
        r_int = H._csprng_weight_t(N, T)           # the RETIRED draw
        y_int = (e_int ^ r_int) & MASK
        pi_seed = H.BitArray.random(N)
        perm = H._stern_gen_perm(pi_seed, N)
        Hr = H._stern_syndrome_H(H_rows, r_int)
        sr = H._stern_apply_perm(perm, r_int, N)
        sy = H._stern_apply_perm(perm, y_int, N)
        commits.append((H._stern_hash(N, pi_seed, H.BitArray(N, Hr), ds=1),
                        H._stern_hash(N, H.BitArray(N, sr), ds=2),
                        H._stern_hash(N, H.BitArray(N, sy), ds=3)))
        data.append((r_int, y_int, pi_seed, sr, sy))
    flat = [msg]
    for c0, c1, c2 in commits:
        flat += [c0, c1, c2]
    ch_st = H._stern_hash(N, *flat)
    chals = []
    for i in range(rounds):
        ch_st = H.nl_fscx_v1(ch_st, H.BitArray(N, i))
        chals.append((ch_st.uint & 0xFFFFFFFF) % 3)
    resps = []
    for i, (r_int, y_int, pi_seed, sr, sy) in enumerate(data):
        b = chals[i]
        resps.append((sr, sy) if b == 0 else
                     (pi_seed, r_int) if b == 1 else (pi_seed, y_int))
    return (commits, chals, resps)


def section1(rounds=32):
    print("\n§1  Witness-weight binding — is wt(e) = t bound by the verifier?")
    seed, e, syn = H.stern_f_keygen()
    H_rows = H._stern_build_H(seed.uint, N, NROWS)

    e_forged = _solve_syndrome(H_rows, syn)
    same_syn = H._stern_syndrome_H(H_rows, e_forged) == syn
    w = bin(e_forged).count("1")
    print(f"  Forged witness : weight {w} (honest key is {T}), "
          f"syndrome matches: {same_syn}")
    if not same_syn or w == T:
        print("  §1 INCONCLUSIVE: the linear solve did not produce an "
              "off-weight preimage")
        return False

    msg = H.BitArray.random(N)

    # The honest control has to pass, or a verifier that rejects everything
    # would score the forgery check perfectly (the accept-control rule this
    # repo applies to every rejection test).
    honest = H.hpks_stern_f_sign(msg, e, seed, syn, rounds=rounds)
    honest_ok = H.hpks_stern_f_verify(msg, honest, seed, syn)
    print(f"  Accept control : honest signature verifies: {honest_ok}")

    forged = H.hpks_stern_f_sign(msg, e_forged, seed, syn, rounds=rounds)
    shipped_ok = H.hpks_stern_f_verify(msg, forged, seed, syn)
    print(f"  Shipped rule   : forgery accepted: {shipped_ok}  "
          f"({'FAIL — universal forgery' if shipped_ok else 'rejected'})")

    forged_retired = _sign_retired(msg, e_forged, seed, rounds)
    retired_ok = _verify_retired_rule(msg, forged_retired, seed, syn)
    print(f"  Retired rule   : forgery accepted: {retired_ok}  "
          f"({'as recorded' if retired_ok else 'CONTROL DID NOT FIRE'})")

    ok = honest_ok and (not shipped_ok) and retired_ok
    print(f"  Binding        : {'PASS' if ok else 'FAIL'}")
    return ok


# ---------------------------------------------------------------------------
# §2 — ring anonymity, structurally
# ---------------------------------------------------------------------------

def _ring_keys(k):
    keys, secrets = [], []
    for _ in range(k):
        seed, e, syn = H.stern_f_keygen()
        keys.append((seed, syn))
        secrets.append(e)
    return keys, secrets


def _commit_collisions(commits, k, rounds):
    seen, dups = set(), 0
    for i in range(k):
        for r in range(rounds):
            for c in commits[i][r]:
                v = c.uint if hasattr(c, "uint") else int(c)
                if v in seen:
                    dups += 1
                seen.add(v)
    return dups


def _as_int(v):
    return v.uint if hasattr(v, "uint") else int(v)


def _signer_score(chals, resps, k, rounds):
    """Rank members by the b = 0 marker: the mean wt(respA ^ respB) over that
    member's b = 0 rounds.  A real signer's is exactly t; the pre-fix simulator
    produced ~n/2.  Returns the member index the statistic points at (the
    minimum), or None if no member had a b = 0 round."""
    best, best_i = None, None
    for i in range(k):
        ws = [bin(_as_int(resps[i][r][0]) ^ _as_int(resps[i][r][1])).count("1")
              for r in range(rounds) if chals[i][r] == 0]
        if not ws:
            continue
        m = sum(ws) / len(ws)
        if best is None or m < best:
            best, best_i = m, i
    return best_i


def _retired_sim_b0():
    """The b = 0 simulated response pair as it stood until v8.0.0: respA a
    weight-t vector, respB uniform and INDEPENDENT of it."""
    return H._csprng_weight_t(N, T), _uniform()


def _identification_rate(trials, k, rounds, retired):
    """How often does the b = 0 marker name the true signer?  Under a correct
    construction this is 1/k; the pre-fix one scored 1.0."""
    hits = 0
    for _ in range(trials):
        keys, secrets = _ring_keys(k)
        j = int.from_bytes(os.urandom(1), "big") % k
        msg = H.BitArray.random(N)
        commits, chals, resps = H.hpks_stern_ring_sign(
            msg, secrets[j], j, keys, rounds=rounds)
        if retired:
            # Replace every SIMULATED b = 0 pair with the retired form.  The
            # statistic is what is under test, so rebuilding the transcript
            # around it is enough -- and it keeps the control to one function
            # rather than a second copy of the whole ring signer.
            resps = [list(m) for m in resps]
            for i in range(k):
                if i == j:
                    continue
                for r in range(rounds):
                    if chals[i][r] == 0:
                        resps[i][r] = _retired_sim_b0()
        if _signer_score(chals, resps, k, rounds) == j:
            hits += 1
    return hits


def section2(k=4, rounds=32, trials=20):
    print("\n§2  Ring anonymity — does any structural marker name the signer?")
    keys, secrets = _ring_keys(k)
    j = 1
    msg = H.BitArray.random(N)
    commits, chals, resps = H.hpks_stern_ring_sign(
        msg, secrets[j], j, keys, rounds=rounds)

    verified = H.hpks_stern_ring_verify(msg, (commits, chals, resps), keys)
    print(f"  Accept control : ring signature verifies: {verified}")

    dups = _commit_collisions(commits, k, rounds)
    print(f"  Commitments    : repeated values across {3 * k * rounds} "
          f"member-rounds: {dups}  ({'PASS' if dups == 0 else 'FAIL'})")

    # Identification rate.  Under a correct construction the marker is pure
    # chance (1/k); a real marker scores 1.0.  Gating a RATE against a fixed
    # threshold is the shape TODO #299 found failing one run in twenty, so the
    # threshold is set where the binomial tail is negligible and an exceedance
    # is CONFIRMED against a second independent block before it fails.
    thresh = (trials * 3) // 4
    hits = _identification_rate(trials, k, rounds, retired=False)
    print(f"  Identification : signer named {hits}/{trials} times "
          f"(chance is ~{trials // k})")
    ok_id = hits < thresh
    if not ok_id:
        print(f"  Identification : over {thresh}/{trials} — confirming "
              f"against a second independent block")
        hits2 = _identification_rate(trials, k, rounds, retired=False)
        print(f"  Identification : second block {hits2}/{trials}")
        ok_id = hits2 < thresh

    ok = verified and dups == 0 and ok_id
    print(f"  Anonymity      : {'PASS' if ok else 'FAIL'}")
    return ok


# ---------------------------------------------------------------------------
# §3 — negative controls
# ---------------------------------------------------------------------------

def section3(k=4, rounds=32, trials=20):
    print("\n§3  Negative controls — both markers must FIRE on the retired form")
    thresh = (trials * 3) // 4

    hits = _identification_rate(trials, k, rounds, retired=True)
    fired_resp = hits >= thresh
    print(f"  Retired b=0 pair : signer named {hits}/{trials} "
          f"({'control FIRES' if fired_resp else 'DID NOT FIRE'})")

    # TODO #297's marker: a constant dummy c0 on every simulated b = 0 round.
    keys, secrets = _ring_keys(k)
    j = 0
    msg = H.BitArray.random(N)
    commits, chals, _ = H.hpks_stern_ring_sign(
        msg, secrets[j], j, keys, rounds=rounds)
    const_c0 = H._stern_hash(N, H.BitArray(N, 0), H.BitArray(N, 0), ds=1)
    commits = [list(m) for m in commits]
    n_planted = 0
    for i in range(k):
        if i == j:
            continue
        for r in range(rounds):
            if chals[i][r] == 0:
                c0, c1, c2 = commits[i][r]
                commits[i][r] = (const_c0, c1, c2)
                n_planted += 1
    dups = _commit_collisions(commits, k, rounds)
    fired_c0 = dups > 0
    print(f"  Retired c0 dummy : {n_planted} constants planted, "
          f"{dups} repeats seen ({'control FIRES' if fired_c0 else 'DID NOT FIRE'})")

    ok = fired_resp and fired_c0
    print(f"  Controls         : {'PASS' if ok else 'FAIL'}")
    return ok


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--quick", action="store_true",
                    help="smaller samples; the findings still gate the exit status")
    args = ap.parse_args()
    trials = 8 if args.quick else 20
    rounds = 16 if args.quick else 32

    print("=" * 74)
    print("TODO #298 — Stern-F witness binding and Stern-Ring anonymity")
    print(f"  n = {N}, t = {T}, rounds = {rounds}, trials = {trials}")
    print("=" * 74)

    results = [
        ("§1 witness-weight binding", section1(rounds)),
        ("§2 ring anonymity", section2(rounds=rounds, trials=trials)),
        ("§3 negative controls", section3(rounds=rounds, trials=trials)),
    ]
    print("\n" + "=" * 74)
    bad = [name for name, ok in results if not ok]
    for name, ok in results:
        print(f"  {name:<28} {'PASS' if ok else 'FAIL'}")
    if bad:
        print("\nFINDINGS NO LONGER REPRODUCE: " + ", ".join(bad))
        sys.exit(1)
    print("\nAll findings reproduce.")
    sys.exit(0)


if __name__ == "__main__":
    main()
