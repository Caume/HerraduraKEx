#!/usr/bin/env python3
"""TODO #301 — does a ZKBoo transcript carry more than the protocol says it may?

TODO #298 scoped three hiding assertions and wrote two of them.  This is the
third, at the protocol #301 said to start with: for ZKBoo, THE TWO REVEALED
PARTY VIEWS MUST NOT DETERMINE THE THIRD.

Why that is testable at all, where "the simulator's output is computationally
indistinguishable" is not: it is a statement about the SIZE OF A SET.  The
witness A is n bits; the question is how many values of A are consistent with
what the proof reveals.  At the demo width that set is small enough to
ENUMERATE, so the answer is a count rather than an argument.

WHERE THE HIDING ACTUALLY LIVES, which is the part worth knowing before editing
`_zkp_nl_evaluate_circuit`.  The (2,3) decomposition has party p computing

    and_out[p] = (a_p & c_p) ^ (a_p & c_{p+1}) ^ (a_{p+1} & c_p) ^ r_p ^ r_{p+1}

and the proof opens parties e+1 and e+2 for a hidden e.  Party e+1's gate is
then fully determined by revealed data -- both its operands are open -- and is
what the verifier CHECKS.  Party e+2's is not: its `+1` neighbour IS the hidden
party, so its revealed `and_out` carries a_e and c_e.  The only thing standing
between an observer and those bits is `r_{p+1}` = r_e, a tape bit of the party
that was never opened.  ONE TERM.  Delete it and the transcript starts naming
the witness.

So the assertion is: enumerate every candidate A, solve for the hidden party's
tape bits, and count how many candidates survive.  A correct construction leaves
ALL of them -- the revealed views narrow A by exactly zero bits, however many
rounds are opened.

§3 is the negative control and it is not optional: a hiding test that cannot
fail is TODO #234's vacuous pass one layer out, which is the rule TODO #298
established and `stern_f_weight_binding.py` §3 is the model for.  The control
here is a PRG stuck at a constant -- the mask bits become known to the observer,
the freedom disappears, and the candidate set collapses.

§4 is a SCOPE check rather than a hiding one, and it is why this script is
Python-only where #298 needed a test in four ports.  The masking term is pinned
BYTE-EXACTLY by KAT/operation_replay.json's zkp_nl_prove row, whose expected
`view_p1`/`view_p2` contain the packed gate outputs -- so a port that drops it
fails that vector in C, Go, Java and Python alike.  §4 demonstrates that rather
than asserting it: it re-derives the row with the term removed and checks the
bytes move.  The cross-port axis is therefore already covered, and what was
missing was only the PROPERTY, which is §1-§3.

NOT IN THIS ITEM, deliberately.  ZKB++ opens SEEDS rather than views (a
different exposure surface, with its own `aux` field) and KKW opens a
pre-processing emulation; each wants its own dozen lines against its own
protocol, which is #298's scoping note and the reason #301 exists as a separate
item at all.  Widening this script to all three is how it converges on
completeness again.

Exits non-zero if a finding stops reproducing.
"""

import argparse
import importlib.util
import json
import os
import sys
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


# ---------------------------------------------------------------------------
# The enumeration
# ---------------------------------------------------------------------------

def _unpack(view, nb):
    """(share, tape, out_share, [(a, c, and_out), ...]) from a packed view."""
    return (int.from_bytes(view[:nb], 'big'),
            view[nb:nb + 32],
            int.from_bytes(view[nb + 32:nb + 32 + nb], 'big'),
            [(b & 1, (b >> 1) & 1, (b >> 2) & 1) for b in view[nb + 32 + nb:]])


def _cached(prg):
    """The PRG is a full HFSCX-256 call and does not depend on the candidate."""
    memo = {}

    def f(tape, gate):
        key = (bytes(tape), gate)
        if key not in memo:
            memo[key] = prg(tape, gate)
        return memo[key]
    return f


def _consistent(A_cand, e, vp1, vp2, B, n, prg):
    """Does some hidden-party tape reproduce BOTH revealed views exactly?

    The hidden party's tape bits are free when the PRG actually depends on its
    tape, so party e+2's gate equation is solved rather than checked.  When the
    PRG ignores the tape (§3's control) those bits are known instead, the
    equation has no free variable, and most candidates fail here.
    """
    p1, p2 = (e + 1) % 3, (e + 2) % 3
    s1, t1, _o1, gv1 = vp1
    s2, t2, _o2, gv2 = vp2
    se = (A_cand ^ s1 ^ s2) & ((1 << n) - 1)
    sh = {e: se, p1: s1, p2: s2}
    # Does the hidden party's tape still buy any freedom?  Asked of the PRG
    # itself rather than assumed, so the control needs no separate flag.
    free_re = prg(b"\x00" * 32, 0) != prg(b"\x11" * 32, 0)
    carry = {0: {e: 0, p1: 0, p2: 0}}
    for i in range(n - 1):
        ai = {p: (sh[p] >> i) & 1 for p in (e, p1, p2)}
        ci = dict(carry[i])
        r1, r2 = prg(t1, i), prg(t2, i)
        # party e+1: both operands revealed, so this is a CHECK
        ao1 = ((ai[p1] & ci[p1]) ^ (ai[p1] & ci[p2])
               ^ (ai[p2] & ci[p1])) ^ r1 ^ r2
        if (ai[p1], ci[p1], ao1) != gv1[i]:
            return False
        if (ai[p2], ci[p2]) != gv2[i][:2]:
            return False
        # party e+2: its `+1` neighbour is the HIDDEN party, so this is where
        # a_e and c_e appear and where r_e is the only mask
        base2 = ((ai[p2] & ci[p2]) ^ (ai[p2] & ci[e]) ^ (ai[e] & ci[p2]))
        if free_re:
            r_e = gv2[i][2] ^ base2 ^ r2          # solve; always possible
        else:
            r_e = prg(b"", i)                     # known -> the equation bites
            if base2 ^ r2 ^ r_e != gv2[i][2]:
                return False
        base_e = ((ai[e] & ci[e]) ^ (ai[e] & ci[p1]) ^ (ai[p1] & ci[e]))
        ao = {p1: ao1, p2: gv2[i][2], e: base_e ^ r_e ^ r1}
        Bi = (B >> i) & 1
        carry[i + 1] = {p: (Bi * ai[p]) ^ ao[p] ^ (Bi * ci[p])
                        for p in (e, p1, p2)}
    return True


def _count_survivors(n, rounds, prg, patch=None):
    """(survivors, total, true-A-kept) for one fresh proof."""
    orig = H._zkp_nl_prg_bit
    if patch:
        H._zkp_nl_prg_bit = patch
    try:
        A, B, y = H.zkp_nl_keygen(n)
        proof = H.zkp_nl_prove(A, B, y, n, rounds, b"TODO-301")
    finally:
        H._zkp_nl_prg_bit = orig
    prg = _cached(prg)
    nb = (n + 7) // 8
    surv = set(range(1 << n))
    for rd in proof:
        e = rd['e']
        vp1 = _unpack(rd['view_p1'], nb)
        vp2 = _unpack(rd['view_p2'], nb)
        surv = {a for a in surv if _consistent(a, e, vp1, vp2, B, n, prg)}
    return len(surv), 1 << n, A in surv


def section1(n=8, rounds=8):
    print(SEP)
    print(f"§1 — The revealed pair of views vs. the witness  (n={n}, "
          f"rounds={rounds})")
    print(SEP)
    surv, total, kept = _count_survivors(n, rounds, H._zkp_nl_prg_bit)
    print(f"  candidates for A : {total}")
    print(f"  surviving        : {surv}")
    print(f"  true A kept      : {kept}")
    bits = 0.0 if surv == total else (total.bit_length() - 1) - (surv.bit_length() - 1)
    print(f"  narrowed by      : {bits:.0f} bits")
    ok = surv == total and kept
    print(f"  Hiding           : {'PASS' if ok else 'FAIL — the views narrow A'}")
    return ok


def section2(n=12, rounds=16):
    print(SEP)
    print(f"§2 — The same, wider and with more rounds opened  (n={n}, "
          f"rounds={rounds})")
    print(SEP)
    print("  More rounds means more revealed view pairs.  If any of them leaked,")
    print("  the intersection over rounds would shrink; it does not.")
    surv, total, kept = _count_survivors(n, rounds, H._zkp_nl_prg_bit)
    print(f"  surviving        : {surv} / {total}   true A kept: {kept}")
    ok = surv == total and kept
    print(f"  Hiding           : {'PASS' if ok else 'FAIL — the views narrow A'}")
    return ok


def section3(n=8, rounds=8):
    print(SEP)
    print("§3 — NEGATIVE CONTROL: the mask bits become known")
    print(SEP)
    print("  A PRG stuck at a constant leaves party e+2's gate equation with no")
    print("  free variable, so the transcript starts naming the witness.  If this")
    print("  section does not FIRE, §1 and §2 are asserting nothing.")
    zero = lambda tape, gate: 0                                    # noqa: E731
    surv, total, kept = _count_survivors(n, rounds, zero, patch=zero)
    fired = surv < total
    narrowed = (total.bit_length() - 1) - (surv.bit_length() - 1) if surv else total.bit_length()
    print(f"  surviving        : {surv} / {total}   true A kept: {kept}")
    print(f"  narrowed by      : {narrowed} bits")
    print(f"  Control          : {'FIRES' if fired else 'DID NOT FIRE'}")
    # The true A must survive too, or the control is firing because the checker
    # disagrees with the prover rather than because anything leaked.
    ok = fired and kept
    print(f"  §3               : {'PASS' if ok else 'FAIL'}")
    return ok


def section4():
    print(SEP)
    print("§4 — SCOPE: the masking term is already pinned across the four ports")
    print(SEP)
    print("  KAT/operation_replay.json's zkp_nl_prove row pins view_p1/view_p2")
    print("  byte-exactly, and those bytes carry the packed gate outputs — so a")
    print("  port that drops r_{p+1} fails that vector rather than needing a test")
    print("  here.  Demonstrated, not asserted: re-derive the row without the")
    print("  term and check the bytes move.")
    sys.path.insert(0, os.path.join(_ROOT, "KAT"))
    import generate_kat as G                                        # noqa: E402
    suite = G.suite
    path = os.path.join(_ROOT, "KAT", "operation_replay.json")
    row = [r for r in json.load(open(path))["operations"]
           if r["name"] == "zkp_nl_prove"][0]
    st, pa = row["statement"], row["params"]
    n, rounds = pa["n"], pa["rounds"]
    A, B, y = int(st["a"], 16), int(st["b"], 16), int(st["y"], 16)
    msg = bytes.fromhex(st["msg_hex"])
    stream = bytes.fromhex(row["stream"])

    def nomask(shares, tapes, Bv, nn):
        mask = (1 << nn) - 1
        carry = [[0, 0, 0]] * nn
        gvs = [[], [], []]
        for i in range(nn - 1):
            ai = [(shares[p] >> i) & 1 for p in range(3)]
            ci = [carry[i][p] for p in range(3)]
            Bi = (Bv >> i) & 1
            ri = [suite._zkp_nl_prg_bit(tapes[p], i) for p in range(3)]
            ao = [0, 0, 0]
            for p in range(3):
                p1 = (p + 1) % 3
                ao[p] = ((ai[p] & ci[p]) ^ (ai[p] & ci[p1])
                         ^ (ai[p1] & ci[p]) ^ ri[p])        # no ^ ri[p1]
                gvs[p].append((ai[p], ci[p], ao[p]))
            carry[i + 1] = [(Bi * ai[p]) ^ ao[p] ^ (Bi * ci[p])
                            for p in range(3)]
        ss = [0, 0, 0]
        for i in range(nn):
            for p in range(3):
                ss[p] ^= ((((shares[p] >> i) & 1) ^ ((Bv >> i) & 1)
                           ^ carry[i][p]) << i)
        rot = [suite._zkp_nl_rol(ss[p], nn // 4, nn) for p in range(3)]
        Bc = (Bv ^ suite._zkp_nl_rol(Bv, 1, nn)
              ^ suite._zkp_nl_rol(Bv, nn - 1, nn)) & mask
        lin = [(shares[p] ^ suite._zkp_nl_rol(shares[p], 1, nn)
                ^ suite._zkp_nl_rol(shares[p], nn - 1, nn)) & mask
               for p in range(3)]
        lin[0] ^= Bc
        return [(lin[p] ^ rot[p]) & mask for p in range(3)], gvs

    def views(patch):
        orig = suite._zkp_nl_evaluate_circuit
        if patch:
            suite._zkp_nl_evaluate_circuit = patch
        try:
            with G._replay(stream):
                pr = suite.zkp_nl_prove(A, B, y, n, rounds, msg)
        finally:
            suite._zkp_nl_evaluate_circuit = orig
        return [r['view_p1'].hex() for r in pr]

    pinned = [r["view_p1"] for r in row["expect"]["rounds"]]
    shipped_ok = views(None) == pinned
    broken_moves = views(nomask) != pinned
    print(f"  shipped reproduces the pinned views : {shipped_ok}")
    print(f"  dropping the term moves those bytes : {broken_moves}")
    ok = shipped_ok and broken_moves
    print(f"  §4               : {'PASS' if ok else 'FAIL'}")
    return ok


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--quick", action="store_true",
                    help="skip §2's wider enumeration; the findings still gate")
    args = ap.parse_args()

    print()
    print("zkboo_view_hiding.py — TODO #301: what a revealed view carries")
    print()
    findings = [("§1 two views do not determine the third", section1()),
                ("§3 negative control fires", section3()),
                ("§4 the cross-port axis is pinned", section4())]
    if not args.quick:
        findings.insert(1, ("§2 the same at n=12, 16 rounds", section2()))

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
