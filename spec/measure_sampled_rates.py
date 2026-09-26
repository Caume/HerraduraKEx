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
"""

import argparse
import importlib.util
import math
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

sys.path.insert(0, HERE)
from check_language_parity import _RATE_MECHANISMS   # noqa: E402


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


_MEASURERS = {
    "corrupted-syndrome": _measure_corrupted_syndrome,
    "offweight-witness":  _measure_offweight_witness,
    "zkboo-poke":         _measure_zkboo_poke,
}


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("-m", "--mechanism", action="append",
                    help="measure only this mechanism (repeatable)")
    ap.add_argument("--trials", type=int, default=None,
                    help="override the recorded trial count per rung")
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

    want = args.mechanism or sorted(_RATE_MECHANISMS)
    bad = [m for m in want if m not in _RATE_MECHANISMS]
    if bad:
        print(f"FAIL: unknown mechanism(s): {', '.join(bad)}")
        return 1

    print("TODO #320: mechanism validation for the derived false-failure rates")
    print("(a rate check validates the arithmetic; only a witness check "
          "validates the mechanism)\n")
    H = _harness()
    failures = []
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
