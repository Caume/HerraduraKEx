#!/usr/bin/env python3
"""TODO #320: MEASURE the mechanism behind each derived false-failure rate.

THE INSTRUMENT, AND IT IS NOT A CI GATE.  TODO #319 made every derived rate in
`check_language_parity.py`'s `_SAMPLED_TEST_RATES` an EXPRESSION over constants
read out of the four ports' source, so the rate's INPUTS can no longer move
unseen.  It stated its own limit in the same breath -- "a formula that is the
wrong function of the right constants still evaluates" -- and the limit stopped
being theoretical within the hour:

    C, Go and Python all said [45]'s corrupted syndrome is "caught only in the
    b = 0 round".  Java said b = 2.  Java is right: `hpks_stern_f_verify`
    references the syndrome in exactly one branch, `H(pi_seed, Hy ^ syndrome)`
    under b == 2, while b == 0 checks wt(sr ^ sy) and two commitment hashes and
    b == 1 checks Hr.  Neither touches it.

The NUMBER is (2/3)^rounds either way, because either way exactly one of three
challenge values is the detecting one -- so #319's machinery evaluates it
correctly, PARAMETERS agrees, #318's fingerprint is unmoved and the budget is
unchanged, while the stated mechanism is false in three of four ports.  A rate
that is right for the wrong reason survives every axis this repo has.

WHY A FREQUENCY CHECK IS NOT ENOUGH, which is the whole design of this file.
Both mechanisms predict (2/3)^rounds, so measuring the acceptance rate would
have CONFIRMED the wrong one.  What separates them is TODO #310's shape --
record WHICH challenge strings the failures carried.  So every measurement here
reports two things:

    a RATE, observed against the formula the table ships, which validates the
    arithmetic; and

    a WITNESS, an exact per-trial predicate (accept == "the challenge string
    contains no detecting round"), which validates the MECHANISM -- together
    with the ALTERNATIVE predicate the rate alone could not exclude, which is
    reported beside it and must NOT track the outcome.

A rate check validates the arithmetic; only a witness check validates the
mechanism.

FOUR THINGS TO KNOW BEFORE EXTENDING IT.

(1) IT IS DELIBERATELY NOT RUN BY CI, and the reason is two-sided.  Measuring a
    19.75% rate usefully costs hundreds of trials per row -- ~15 minutes here --
    which is #289's runtime problem in miniature; and a validation that itself
    decides on a fresh sample is #299's defect re-introduced one level up.
    #304's model is the one followed: the TOKEN and the numbers are recorded in
    the table, the checker holds the record to the expression it validates, and
    the runner does not re-measure.  Nothing in SecurityProofsCode/ either, so
    `run_findings_gates.py` cannot discover it and no NON_GATING entry has to
    argue it away.

(2) THE EXIT STATUS RESTS ON THE WITNESS, NOT ON THE FREQUENCY.  The predicate
    is exact -- zero mismatches over every trial, or the mechanism stated in the
    table is not the mechanism the code implements -- so this script cannot
    flake on its own account.  The frequency is corroboration and is banded at
    6 sigma (a false alarm near 1e-9), which is also why it needs no
    replication: #299's remedy exists for a bar that fires one run in twenty,
    and a bar that fires one run in a billion is not that bar.

(3) THE REDUCED PARAMETER IS AN INSTRUMENT AND MUST STAY LOCAL.  [45] at
    rounds = 4 is the 19.75% CLAUDE.md's Testing section warns about by name;
    it is used here on purpose and must never reach a shipped default, which
    `check_language_parity.py` enforces by reading the SHIPPED value of the
    same variable out of every port and refusing a ladder that touches it.

(4) THE MEASUREMENT RUNS THE HARNESS'S OWN CODE, loaded through importlib the
    way SecurityProofsCode/ loads the suite.  `Herradura_tests.py` keeps LOCAL
    copies of the Stern signer, verifier and the ZKBoo prover (they are what
    [45], [53] and [22] actually call), so measuring the suite's copies would
    measure a different function -- #306's "the pinned function and the shipped
    path were different code" as a measurement error rather than as a defect.

Usage:
    python3 spec/measure_sampled_rates.py                 # every mechanism
    python3 spec/measure_sampled_rates.py -m corrupted-syndrome
    python3 spec/measure_sampled_rates.py --trials 100    # a quicker sketch
    python3 spec/measure_sampled_rates.py --only argued   # TODO #321's half
"""

import argparse
import importlib.util
import math
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

sys.path.insert(0, HERE)
from check_language_parity import (_RATE_MECHANISMS,        # noqa: E402
                                   _ARGUED_MEASUREMENTS)


def _harness():
    """The numbered-test harness as a module, without running it.

    Its __main__ guard means an import runs no test; what we want is its local
    Stern and ZKBoo code, which is the code under measurement.
    """
    path = os.path.join(ROOT, "CryptosuiteTests", "Herradura_tests.py")
    spec = importlib.util.spec_from_file_location("_h320_tests", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# ── the three mechanisms ─────────────────────────────────────────────────
#
# Each returns (accepts, witness_agreements, alternative_agreements,
# control_ok) over `trials` independent trials at the reduced parameter.
# `witness_agreements` counts trials where the outcome EQUALS the stated
# predicate; anything less than `trials` falsifies the stated mechanism.

def _measure_corrupted_syndrome(H, rounds, trials):
    """[45] / java [12]: an honest signature verified against a corrupted
    syndrome.  Detecting round: b = 2, the only branch that reads the syndrome.
    Alternative under test: b = 0, which three ports' comments claimed."""
    n = 32                          # the width [45] runs its Stern block at
    acc = wit = alt = ctrl = 0
    for _ in range(trials):
        seed, e_int, syndrome = H.stern_f_keygen(n)
        msg = H.BitArray.random(n)
        sig = H.hpks_stern_f_sign(msg, e_int, seed, syndrome, n, rounds)
        # The accept control: [45] requires the honest verification FIRST, so a
        # signer that produced nothing verifiable would score every trial as a
        # rejection and read as a perfect result (#234's vacuous pass).
        if H.hpks_stern_f_verify(msg, sig, seed, syndrome, n):
            ctrl += 1
        out = H.hpks_stern_f_verify(msg, sig, seed, syndrome ^ 1, n)
        ch = sig[1]
        acc += bool(out)
        wit += (bool(out) == (2 not in ch))
        alt += (bool(out) == (0 not in ch))
    return acc, wit, alt, ctrl


def _measure_offweight_witness(H, rounds, trials):
    """[53] / java [35]: a CONSTRUCTED off-weight witness, signed and verified.
    Detecting round: b = 0, the only branch that binds wt(respA ^ respB) = t.
    Alternative under test: b = 2 -- the mirror image of the row above, and the
    pair is the point: the two adjacent tests have OPPOSITE detecting rounds,
    which is how the b = 0 claim came to be written on the wrong one."""
    n = 64                          # the width [53] runs at
    t = max(2, n // 16)
    n_rows = n // 2
    acc = wit = alt = ctrl = 0
    for _ in range(trials):
        seed, e_int, syn = H.stern_f_keygen(n)
        rows = [H._stern_matrix_row(seed.uint, i, n).uint for i in range(n_rows)]
        msg = H.BitArray.random(n)
        honest = H.hpks_stern_f_sign(msg, e_int, seed, syn, n, rounds)
        if H.hpks_stern_f_verify(msg, honest, seed, syn, n):
            ctrl += 1
        forged_e = H._stern_solve_syndrome(rows, syn, n, avoid_weight=t)
        sig = H.hpks_stern_f_sign(msg, forged_e, seed, syn, n, rounds)
        out = H.hpks_stern_f_verify(msg, sig, seed, syn, n)
        ch = sig[1]
        acc += bool(out)
        wit += (bool(out) == (0 not in ch))
        alt += (bool(out) == (2 not in ch))
    return acc, wit, alt, ctrl


def _measure_zkboo_poke(H, rounds, trials):
    """[22]: one bit flipped in round 0's com_1.  Detecting event is NOT the
    opening of the poked commitment -- it is the Fiat-Shamir recomputation,
    which reseeds off the whole commitment block, so EVERY stored challenge has
    to re-match: (1/3)^rounds.  Alternative under test: "the poked round's
    challenge does not open com_1", which is #316's [17] mechanism misapplied
    one test over and predicts a FLAT 1/3 at every round count -- so the ladder
    separates them by shape, not only by value."""
    n = 32                          # the narrower of the two widths [22] sweeps
    nb = (n + 7) // 8
    acc = wit = alt = ctrl = 0
    for _ in range(trials):
        A, B, y = H._zkp_nl_keygen(n)
        proof = H._zkp_nl_prove(A, B, y, n, rounds, H.ZKP_MSG)
        if H._zkp_nl_verify(B, y, n, rounds, H.ZKP_MSG, proof):
            ctrl += 1
        tam = [dict(r) for r in proof]
        c1 = bytearray(tam[0]["com_1"])
        c1[0] ^= 1
        tam[0] = dict(tam[0])
        tam[0]["com_1"] = bytes(c1)
        out = H._zkp_nl_verify(B, y, n, rounds, H.ZKP_MSG, tam)
        # The witness: recompute the challenges over the TAMPERED commitments,
        # exactly as the verifier's first loop does.
        coms = [[r["com_0"], r["com_1"], r["com_2"]] for r in tam]
        block = b"".join(b"".join(c) for c in coms)
        seed = H._zkp_nl_h(block, B.to_bytes(nb, "big"),
                           y.to_bytes(nb, "big"), H.ZKP_MSG)
        fs_ok = all(H._zkp_nl_h(seed, j.to_bytes(4, "big"))[0] % 3 == tam[j]["e"]
                    for j in range(rounds))
        # The second term: com_1 is opened iff p1 == 1 or p2 == 1, i.e. iff
        # e in {0, 2}; so it goes UNOPENED exactly when the round's e is 1.
        unopened = tam[0]["e"] == 1
        acc += bool(out)
        # The CONJUNCTION is the mechanism.  Either term alone tracks about
        # four trials in five, which is what an authoring pass that had not yet
        # measured the thing wrote here first -- and the shipped instrument
        # then FAILED against its own record, at 158/180, which is the record
        # doing its job on the code rather than the other way round.
        wit += (bool(out) == (fs_ok and unopened))
        # The alternative reported beside it is the Fiat-Shamir term ALONE --
        # #319's claim, and #316's [17] mechanism one test over.
        alt += (bool(out) == fs_ok)
    return acc, wit, alt, ctrl


def _measure_ring_forgery(H, rounds, trials):
    """java [26] (TODO #321): a ring signature produced with a witness that
    matches NO member's syndrome.  Detecting event: any round whose challenge
    for the forging member is b != 1, because TWO branches catch it -- b = 0
    binds wt(respA ^ respB) = t (TODO #298's fix, which did not exist when this
    test's rate was written down) and b = 2 checks H(pi_seed, Hy ^ syndrome).
    Only b = 1 reads neither, so the rate is (1/3)^rounds.

    Alternative under test: "no b = 2 round" -- the PRE-#298 mechanism, when
    b = 0 bound nothing, and still what SelfTest.java's comment and both spec/
    tables said.  It predicts (2/3)^rounds, 4.6 million times larger at the
    shipped 32 rounds, and it is what made TODO #260 see a real flake at 8.

    Run at the harness's own ring width n = 32 rather than at Java's 256: the
    mechanism is a statement about which verifier BRANCH reads what, identical
    in the two ports' source, and one n = 256 trial costs 6.7 s against 0.5 s
    here -- 1.7 hours for the ladder instead of 13 minutes."""
    n = 32
    k = 4                           # Java's ring size, not the harness's 3
    acc = wit = alt = ctrl = 0
    for _ in range(trials):
        keys, errs = [], []
        for _ in range(k):
            seed_i, e_i, syn_i = H.stern_f_keygen(n)
            keys.append((seed_i, syn_i))
            errs.append(e_i)
        msg = H.BitArray.random(n)
        # The accept control, as everywhere here: an honest ring signature must
        # verify, or a signer producing nothing verifiable scores every trial a
        # rejection and reads as a perfect result (#234's vacuous pass).
        honest = H.hpks_stern_ring_sign_local(msg, errs[0], 0, keys, n, rounds)
        if H.hpks_stern_ring_verify_local(msg, honest, keys, n):
            ctrl += 1
        bad = H.BitArray.random(n).uint      # matches no member's syndrome
        sig = H.hpks_stern_ring_sign_local(msg, bad, 0, keys, n, rounds)
        out = H.hpks_stern_ring_verify_local(msg, sig, keys, n)
        ch = sig[1][0]                       # the forging member's challenges
        acc += bool(out)
        wit += (bool(out) == all(b == 1 for b in ch))
        alt += (bool(out) == (2 not in ch))
    return acc, wit, alt, ctrl


_MEASURERS = {
    "corrupted-syndrome": _measure_corrupted_syndrome,
    "offweight-witness":  _measure_offweight_witness,
    "zkboo-poke":         _measure_zkboo_poke,
    "ring-forgery":       _measure_ring_forgery,
}


# ── the ARGUED half: TODO #321 ────────────────────────────────────────────
#
# #320's three measurers above validate a FORMULA.  These two validate a row
# that has no formula: an `exact` verdict, whose claim is that the rate is
# ZERO, and a literal whose mechanism nobody had measured.  The shapes differ
# because the objects do -- a MARGIN is not a rate, which is the whole point:
# a rate has to be counted and an inequality can be read off one trial with as
# many samples in it as the statement has coefficients.

def _measure_rnl_margin(H, p, trials):
    """[14] (TODO #321): HKEX-RNL Peikert reconciliation, at the DEPLOYED ring.

    The quantity is the signed distance from each reconciled coefficient to the
    nearest value of B's error that would move its 2-bit bucket, minimised over
    the key_bits//2 coefficients reconciliation actually reads.  Its SIGN is not
    a proxy for agreement -- it IS agreement, which is what makes the witness
    exact rather than statistical.

    The per-coefficient room is residue-dependent and ASYMMETRIC, which is the
    finding: with r = (4c + (2h+1)*(q//4)) mod q, B may run down by r//4 and up
    by (q-1-r)//4, and over all 65537 residues the smallest error that can flip
    a bucket is exactly q//32 = 2048 downward and 3q/32 = 6145 upward, i.e. the
    room bottoms out at 2047 down and 6144 up.  SecurityProofs-4.md 480's
    "max per-coeff error << q/8" is therefore 4x too generous -- in the LENIENT
    direction, so it overstates the safety factor rather than the risk.

    `p` is the public-key rounding modulus and the ladder's reduced parameter;
    lowering it scales the rounding error of lift() as q/(2p), i.e. as 1/p, so
    the cliff is reachable in four rungs and its position is predicted rather
    than hunted for.  The DEPLOYED rung is the top one and is the claim.
    """
    q, pp, qq, hq = H.RNLQ, H.RNLPP, H.RNLQ // 4, H.RNLQ // 2
    # The DEPLOYED ring and key width come from the table's own `deployed`
    # block, which check_language_parity.py holds to every port's source -- so
    # there is one place that says 1024, and it is a place that fails if the
    # suite moves (#223 moved this very constant once already).
    dep = _ARGUED_MEASUREMENTS["rnl-reconciliation-margin"]["deployed"]
    n, key_bits = dep["rnl-n"], dep["keybits"]
    margins = []
    adverse = wit = 0
    maxerr = 0
    for _ in range(trials):
        m = H._rnl_poly_add(H._rnl_m_poly(n), H._rnl_rand_poly(n, q), q)
        sA, CA = H._rnl_keygen(m, n, q, p)
        sB, CB = H._rnl_keygen(m, n, q, p)
        KA = H._rnl_poly_mul(sA, H._rnl_lift(CB, p, q), q, n)
        KB = H._rnl_poly_mul(sB, H._rnl_lift(CA, p, q), q, n)
        hint = H._rnl_hint(KA, q)
        agree = (H._rnl_reconcile_bits(KA, hint, q, pp, key_bits)
                 == H._rnl_reconcile_bits(KB, hint, q, pp, key_bits))
        worst = None
        for i in range(key_bits // 2):
            c, h = KA[i], hint[i]
            d = (KB[i] - c) % q
            e = d - q if d > hq else d
            maxerr = max(maxerr, abs(e))
            r = (4 * c + (2 * h + 1) * qq) % q
            mg = min(e + r // 4, (q - 1 - r) // 4 - e)
            worst = mg if worst is None else min(worst, mg)
        margins.append(worst)
        adverse += (not agree)
        # THE WITNESS.  Nothing statistical about it: the margin's sign and the
        # reconciliation's answer are the same fact computed two ways, so one
        # mismatch means the quantity recorded in the table is not the quantity
        # the code decides on.
        wit += (agree == (worst >= 0))
    return (min(margins), sum(margins) / len(margins), adverse, wit, maxerr)


def _measure_sigma_collision(H, t, trials):
    """[21] (TODO #321): ZKP-RNL's tampered-commitment case, which is NOT exact.

    [21] increments w[0] and requires the verifier to reject.  The verifier
    recomputes the Fiat-Shamir challenge over the tampered w and rejects when it
    disagrees with the claimed one -- so the case turns on a CHALLENGE
    COLLISION, and the challenge is a weight-t signed sparse polynomial, i.e. a
    space of comb(n, t) * 2^t.  On a collision the residual-norm check sees one
    coefficient shifted by 1 inside a slack of t*(q//(2p)+1) and accepts, so the
    row's `exact` verdict is wrong at about 1 trial in 575 360 at n = 32.

    `t` is the ladder's reduced parameter because it is the only one that moves
    the space by orders of magnitude without changing the mechanism; the shipped
    value at n = 32 is 4, and it comes from _sigma_params' module-level dict
    rather than from anything inside the test, which is why this row's rate
    stays a literal (see _SAMPLED_TEST_RATE_LITERAL)."""
    q = H.RNLQ
    n = 32
    H._SIGMA_T[n] = t                      # instrument-local, never shipped
    m_base = H._rnl_m_poly(n)
    acc = wit = alt = ctrl = ran = 0
    for _ in range(trials):
        m = H._rnl_poly_add(m_base, H._rnl_rand_poly(n, q), q)
        s_poly, C = H._rnl_keygen(m, n, q, H.RNLP)
        try:
            w, c, z = H._rnl_sigma_sign(s_poly, m, C, n, H.ZKP_MSG)
        except RuntimeError:
            continue                        # #291: a trial that did not run
        ran += 1
        if H._rnl_sigma_verify(m, C, n, H.ZKP_MSG, w, c, z):
            ctrl += 1
        wt = list(w)
        wt[0] += 1
        out = H._rnl_sigma_verify(m, C, n, H.ZKP_MSG, wt, c, z)
        coll = (c == H._sigma_challenge(m, C, wt, n, q, t, H.ZKP_MSG))
        acc += bool(out)
        wit += (bool(out) == coll)
        # The ALTERNATIVE: "the residual-norm check is what catches it", which
        # is what an `exact` verdict on this case amounts to.  Measured against
        # the z-tamper case in the same test, where the norm check genuinely IS
        # the detector -- so the two cases are shown to be different mechanisms
        # rather than two descriptions of one.
        zt = list(z)
        zt[0] += 1
        alt += (bool(out) == bool(H._rnl_sigma_verify(m, C, n, H.ZKP_MSG,
                                                     w, c, zt)))
    return acc, wit, alt, ctrl, ran


_ARGUED_MEASURERS = {
    "rnl-reconciliation-margin": _measure_rnl_margin,
    "sigma-challenge-collision": _measure_sigma_collision,
}


def _run_argued(want, override):
    """The TODO #321 half.  Same contract as the mechanisms above: the exit
    status rests on the WITNESS, which is exact, and the numbers are
    corroboration."""
    failures = []
    H = _harness()
    for name in want:
        spec = _ARGUED_MEASUREMENTS[name]
        rows = ", ".join(f"[{n}]/{s}" for s, n in spec["rows"])
        print(f"── {name}  ({rows})  [{spec['kind']}]")
        print(f"   quantity  {spec['quantity']}")
        print(f"   bound     {spec['bound']}")
        tot = totwit = 0
        for key in sorted(spec["ladder"], reverse=True):
            rung = spec["ladder"][key]
            flags = []
            if spec["kind"] == "margin":
                rec_trials = rung[0]
                trials = override or rec_trials
                mn, mean, adverse, wit, maxe = _ARGUED_MEASURERS[name](
                    H, key, trials)
                tot += trials
                totwit += wit
                if wit != trials:
                    flags.append(f"WITNESS {wit}/{trials}")
                if key == max(spec["ladder"]) and adverse:
                    flags.append(f"DEPLOYED RUNG HAS {adverse} ADVERSE TRIAL(S)")
                verdict = "PASS" if not flags else "FAIL: " + "; ".join(flags)
                print(f"   {spec['var']}={key:<5} trials={trials:<5} "
                      f"min={mn:<7} mean={mean:<9.1f} adverse={adverse:<5} "
                      f"max|e|={maxe:<6} witness={wit}/{trials}  [{verdict}]")
            else:
                rec_trials, _rec_ev, predicted = rung
                trials = override or rec_trials
                acc, wit, alt, ctrl, ran = _ARGUED_MEASURERS[name](H, key, trials)
                tot += ran
                totwit += wit
                sd = math.sqrt(max(ran, 1) * predicted * (1 - predicted))
                lo, hi = ran * predicted - 6 * sd, ran * predicted + 6 * sd
                if wit != ran:
                    flags.append(f"WITNESS {wit}/{ran}")
                if ctrl != ran:
                    flags.append(f"ACCEPT-CONTROL {ctrl}/{ran}")
                if not lo <= acc <= hi:
                    flags.append(f"RATE outside 6 sigma [{lo:.1f}, {hi:.1f}]")
                verdict = "PASS" if not flags else "FAIL: " + "; ".join(flags)
                print(f"   {spec['var']}={key:<5} trials={ran:<5} "
                      f"events={acc:<5} predicted={ran * predicted:<9.2f} "
                      f"witness={wit}/{ran} alternative={alt}/{ran}  [{verdict}]")
            if flags:
                failures.append(f"{name} at {spec['var']}={key}: "
                                + "; ".join(flags))
        print(f"   TOTAL     witness {totwit}/{tot} exact")
        print()
    return failures


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("-m", "--mechanism", action="append",
                    help="measure only this mechanism (repeatable)")
    ap.add_argument("--trials", type=int, default=None,
                    help="override the recorded trial count per rung")
    ap.add_argument("--only", choices=("mechanisms", "argued"), default=None,
                    help="run only TODO #320's formula mechanisms, or only "
                         "TODO #321's argued-row evidence")
    args = ap.parse_args(argv)

    # Exhaustive in both directions, like every curated table in spec/: a
    # mechanism recorded with no measurer here, or a measurer for a mechanism
    # the table does not record, is an error rather than a silent skip.
    missing = sorted(set(_RATE_MECHANISMS) - set(_MEASURERS))
    extra = sorted(set(_MEASURERS) - set(_RATE_MECHANISMS))
    if missing or extra:
        for k in missing:
            print(f"FAIL: _RATE_MECHANISMS records {k!r} and this file has no "
                  f"measurer for it")
        for k in extra:
            print(f"FAIL: this file measures {k!r}, which _RATE_MECHANISMS "
                  f"does not record")
        return 1

    missing = sorted(set(_ARGUED_MEASUREMENTS) - set(_ARGUED_MEASURERS))
    extra = sorted(set(_ARGUED_MEASURERS) - set(_ARGUED_MEASUREMENTS))
    if missing or extra:
        for k in missing:
            print(f"FAIL: _ARGUED_MEASUREMENTS records {k!r} and this file has "
                  f"no measurer for it")
        for k in extra:
            print(f"FAIL: this file measures {k!r}, which "
                  f"_ARGUED_MEASUREMENTS does not record")
        return 1

    known = set(_RATE_MECHANISMS) | set(_ARGUED_MEASUREMENTS)
    if args.mechanism:
        bad = [m for m in args.mechanism if m not in known]
        if bad:
            print(f"FAIL: unknown mechanism(s): {', '.join(bad)}")
            return 1
        want = [m for m in args.mechanism if m in _RATE_MECHANISMS]
        want_argued = [m for m in args.mechanism if m in _ARGUED_MEASUREMENTS]
    else:
        want = sorted(_RATE_MECHANISMS)
        want_argued = sorted(_ARGUED_MEASUREMENTS)
    if args.only == "mechanisms":
        want_argued = []
    elif args.only == "argued":
        want = []

    if want:
        print("TODO #320: mechanism validation for the derived false-failure "
              "rates")
        print("(a rate check validates the arithmetic; only a witness check "
              "validates the mechanism)\n")
    failures = []
    H = _harness() if want else None
    for name in want:
        spec = _RATE_MECHANISMS[name]
        rows = ", ".join(f"[{n}]/{s}" for s, n in spec["rows"])
        print(f"── {name}  ({rows})")
        print(f"   term      {spec['term']}  over {spec['var']}")
        print(f"   detects   {spec['detects']}")
        print(f"   excludes  {spec['excludes']}")
        tot_trials = tot_wit = tot_alt = 0
        for rounds in sorted(spec["ladder"]):
            rec_trials, _rec_acc, predicted = spec["ladder"][rounds]
            trials = args.trials or rec_trials
            acc, wit, alt, ctrl = _MEASURERS[name](H, rounds, trials)
            sd = math.sqrt(trials * predicted * (1 - predicted))
            lo = trials * predicted - 6 * sd
            hi = trials * predicted + 6 * sd
            obs = acc / trials
            tot_trials += trials
            tot_wit += wit
            tot_alt += alt
            flags = []
            if ctrl != trials:
                flags.append(f"ACCEPT-CONTROL {ctrl}/{trials}")
            if wit != trials:
                flags.append(f"WITNESS {wit}/{trials}")
            if not lo <= acc <= hi:
                flags.append(f"RATE outside 6 sigma [{lo:.1f}, {hi:.1f}]")
            verdict = "PASS" if not flags else "FAIL: " + "; ".join(flags)
            print(f"   {spec['var']}={rounds:<3} trials={trials:<5} "
                  f"accepted={acc:<5} observed={obs:.5f} "
                  f"predicted={predicted:.5f}  witness={wit}/{trials} "
                  f"alternative={alt}/{trials}  [{verdict}]")
            if flags:
                failures.append(f"{name} at {spec['var']}={rounds}: "
                                + "; ".join(flags))
        print(f"   TOTAL     witness {tot_wit}/{tot_trials} exact, "
              f"alternative {tot_alt}/{tot_trials}")
        # The alternative must NOT track the outcome.  A mechanism whose
        # alternative also matched every trial would be indistinguishable from
        # it by this instrument, and recording it as validated would be the
        # b = 0 / b = 2 error with a measurement wrapped round it.
        if tot_alt == tot_trials:
            msg = (f"{name}: the ALTERNATIVE predicate also matched every "
                   f"trial, so this measurement does not discriminate")
            print(f"   [FAIL] {msg}")
            failures.append(msg)
        print()

    if want_argued:
        print("TODO #321: the ARGUED half -- an `exact` verdict owes a SLACK, "
              "not a count of zeros\n")
        failures += _run_argued(want_argued, args.trials)

    if failures:
        print("*** FAILED: the recorded mechanism does not match what the code "
              "does ***")
        for f in failures:
            print(f"  - {f}")
        return 1
    print("*** OK: every measured mechanism reproduces, witness-exact ***")
    return 0


if __name__ == "__main__":
    sys.exit(main())
