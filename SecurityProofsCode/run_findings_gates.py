#!/usr/bin/env python3
"""run_findings_gates.py -- run every findings-gating analysis script (TODO #289)

About three dozen scripts in this directory close with a sentence of the form
"exits non-zero if a finding stops reproducing", and CLAUDE.md repeats it for
each of them.  Until TODO #285 no CI job collected that status at all, so the
promise was untested; #285, #286 and #287 then added scripts to one step in
`native-python` ONE AT A TIME, excluding the rest on runtime grounds.  Twice
the excluded set turned out to contain a script that was already failing --
`qcmdpc_parameter_selection.py` (three gates, found by #286) and
`qcmdpc_bgf_variants.py` (six findings, found by #288) -- and each exclusion
had been individually defensible.  This runner is TODO #289's replacement for
that judgement call.

THE RULE, and it is the whole point of the file: the set of scripts that run is
DISCOVERED, not enumerated.  A script whose exit status is its own verdict --
`sys.exit(main())`, `raise SystemExit(main())`, or a bare `sys.exit(1)` on a
failed finding -- is run, and nothing has to be added anywhere for that to
happen.  The previous shape was a list in `ci.yml`, and a list is exactly what
lets "we did not get round to adding it" look identical to "it passes".

EVERY .py HERE IS EITHER DISCOVERED OR DECLARED (TODO #291).  Discovery answers
"which of the gating scripts run"; until #291 nothing asked which scripts GATE.
The answer was 35 of 81 -- 46 produced output that no exit status carried, 33 of
them cited by SecurityProofs-*.md or CLAUDE.md as backing a claim, and 22 of them
computing a PASS/FAIL verdict and then discarding it, which is TODO #233's defect
one layer out.  So a script that does not gate must say why in NON_GATING, and
the runner FAILS on one that is neither discovered nor declared.  That is the
part that does not decay: adding an analysis script now forces the question.

Skipping is still possible and is deliberately awkward: add the script to
EXCLUDED with a reason.  That table is self-invalidating the way every other
curated table in this repo is (spec/check_docs_consistency.py's anchors,
cli_surface_gaps, PARAM_DIVERGENCE): an entry naming a file that does not
exist, or that is no longer a gating script, FAILS -- so an exclusion cannot
outlive its reason.

WHAT `--quick` MEANS HERE.  A script that declares a reduced-sample flag is run
with it; one that does not is run as it is.  TWO SPELLINGS are in use and both
count -- `--quick` in 20 scripts and `--fast` in three (TODO #290, which found
those three running at their DEFAULT budgets inside a job that had asked for the
reduced one: for nl_fscx_exact_trail_search.py that is 19 s against twenty-odd
minutes, with the same verdicts).  `--quick` in this directory is a
smaller-sample mode that still reproduces every finding (the sample sizes move,
the verdicts do not), which is the property that makes it usable as a gate --
see qcmdpc_dfr_weak_keys.py's header for the canonical statement.  Pass --full
here to run everything at its default sizes instead; that is hours, not
minutes, and is a local operation rather than a CI one.

FAILURES DO NOT STOP THE RUN.  The interesting output is WHICH gates stopped
reproducing, and a `set -e` loop reports one and hides the rest -- #286 found
three failures in one script and #288 six, so partial reporting is not a
hypothetical.  Every script runs, the failures are re-listed at the end, and
the exit status is non-zero if any failed.

Run:  python3 SecurityProofsCode/run_findings_gates.py [--quick|--full] [--list]
                                                       [--timeout SECONDS]
"""

import argparse
import ast
import os
import re
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
SELF = os.path.basename(os.path.abspath(__file__))

# A script "gates" when its exit status carries its own verdict.
#
# TODO #291 GENERALISED THIS, and the reason is the blind spot the file already
# documents below: the first version listed three exact call shapes
# (`sys.exit(main())`, `raise SystemExit(main())`, `sys.exit(run_tests())`) plus
# a bare `sys.exit(1)`, and #291 converted five scripts whose entry point is
# called `run()` -- every one of them read as "does not gate".  Naming the
# function was never the point; EXITING WITH A COMPUTED STATUS is.  So the
# pattern is now `sys.exit(<call>)` / `raise SystemExit(<call>)` for any
# function, plus an exit on a literal-or-expression 1.  `sys.exit(0)` still
# does not count, and should not: a script that always exits 0 is not a gate.
_GATING_RE = re.compile(
    r"sys\.exit\(\s*[A-Za-z_]\w*\("
    r"|raise\s+SystemExit\(\s*[A-Za-z_]\w*\("
    r"|sys\.exit\(\s*1\b"
    r"|raise\s+SystemExit\(\s*1\b")

# A reduced-sample mode, under either of the two names this directory uses.
# TODO #290: three scripts spell it `--fast` (nl_fscx_exact_trail_search.py,
# rnl_parameter_selection.py, hkex_rnl_lattice_2026.py) and looking only for
# `--quick` ran all three at their default budgets in a job that had asked for
# the reduced one.  Same shape as the _CLAIM_RE blind spot below: the runner
# reads a spelling, so a second spelling is invisible until it is named.
_QUICK_RE = re.compile(
    r"""add_argument\(\s*['"](--quick|--fast)['"]"""
    r"""|['"](--quick|--fast)['"]\s+in\s+sys\.argv""")


def _quick_flag(src):
    """The reduced-sample flag a script declares, or None.

    TODO #291 added the THIRD spelling, for the same reason #290 added the
    second: two scripts (stern_f_multiround_fs.py, hybrid_credential_phi.py)
    read the flag straight out of sys.argv rather than through argparse, so an
    argparse-only pattern ran them at full sample sizes inside a job that had
    asked for the reduced one -- and stern_f_multiround_fs.py was ALREADY a
    discovered gate, so it had been running that way since #289.
    """
    m = _QUICK_RE.search(src)
    if not m:
        return None
    return m.group(1) or m.group(2)

# The blind spot the three shapes above would otherwise have.  Discovery reads
# the exit CALL, so a script that gates through a fourth shape is silently not
# run -- which is the same class of hole TODO #288 found in check B'' of
# spec/check_docs_consistency.py, where a correct sentence was invisible
# because the checker looked for the wrong token.  So the CLAIM is checked
# against the discovery: a script that advertises a findings gate in its own
# header and is not discovered is an ERROR, not a silent omission.  One
# direction only -- a gating script need not advertise, and several do not.
_CLAIM_RE = re.compile(r"exits?\s+non-?zero", re.I)

# name -> reason.  EMPTY, and that is the point of TODO #289: there is no
# longer a runtime budget to spend, because this job runs beside the other
# eleven rather than inside one of them.  An entry here must say what makes its
# script unrunnable in CI -- not that it is slow -- and will fail generation
# once that stops being true.
# TODO #300's fresh-entropy detection.  Kept beside discovery because the two
# have to agree about what the gate set is.
_OS_ENTROPY_RE  = re.compile(r"\bos\.urandom\b|\bsecrets\.\w+|\bSystemRandom\b")
_UNSEEDED_RE    = re.compile(r"random\.Random\(\s*\)")
_MODRAND_SEED_RE = re.compile(r"random\.seed\(\s*[^)\s]")
_MODRAND_USE_RE = re.compile(r"\brandom\.(?!Random\b|seed\b)\w+\(")

EXCLUDED = {}


# name -> reason.  A script here is NOT a gate and does not run: it holds no
# finding whose loss would be a defect.  Self-invalidating in both directions
# like EXCLUDED -- an entry naming an absent file fails, and so does one naming
# a script that HAS since become a gate, so making one gate forces its entry
# out.  Keep the reasons this specific; "it is only a demo" is not one, since
# several demos gate (hpks_threshold_demo.py, oprf_demo.py, vdf_demo.py all
# assert something falsifiable and all run here).
NON_GATING = {
    "hkex_cfscx_blong.py":
        "DESIGN-SPACE SURVEY.  Five convolution strategies for a large-B FSCX "
        "variant, none of them shipped, none cited by any document.  Its tables "
        "are the record of why each was rejected; there is no claim about the "
        "suite for a gate to defend",
    "hkex_cfscx_compress.py":
        "DESIGN-SPACE SURVEY -- the compress-to-trapdoor construction, rejected; "
        "same reason as hkex_cfscx_blong.py",
    "hkex_cfscx_intops.py":
        "DESIGN-SPACE SURVEY -- padlock/asymmetric/hash-like schemes over the "
        "integer-op expansion, none adopted; same reason as hkex_cfscx_blong.py",
    "hkex_cfscx_preshared.py":
        "DESIGN-SPACE SURVEY -- five preshared-value constructions, none adopted; "
        "same reason as hkex_cfscx_blong.py",
    "hkex_cfscx_twostep.py":
        "DESIGN-SPACE SURVEY -- eight two-step constructions, none adopted; same "
        "reason as hkex_cfscx_blong.py",
    "nl_fscx_v2_orbit.py":
        "DISTRIBUTIONAL CHARACTERISATION.  Sampled orbit lengths of pi_K: medians, "
        "a bimodal split and a non-monotone n=24 anomaly.  Gating it would mean "
        "inventing thresholds for a sampled distribution, which TODO #291 "
        "explicitly warns against; the conclusions that mattered are in "
        "nl_fscx_v2_csp.py, which does gate",
    "stern_ct_demo.py":
        "ITS VERDICT IS THAT A LEAK IS STILL THERE.  The demo measures wall-clock "
        "timing against Hamming weight in the branchy Python _stern_apply_perm "
        "and reports [PASS] when the correlation is high -- so a gate would fail "
        "if anyone made that code constant-time, and would flake on a loaded "
        "machine.  Python is a reference implementation and this is a documented "
        "accepted risk, not a regression to defend",
}


# ── TODO #300: which gates decide a verdict from a FRESH random sample? ──────
#
# #289 built this job on the premise that a red run means something, and #299
# found that premise failing two ways at once on one PR.  Nothing then asked how
# many of the gates have the same shape.  This is that census.
#
# THE DERIVED HALF, which cannot go stale: a gating script that draws fresh
# entropy -- os.urandom, secrets, random.Random() with no seed, or module-level
# random.* without random.seed(<literal>) -- must carry an entry below.  Of the
# 74, 43 draw only from a LITERAL seed and 6 draw no randomness at all, so their
# verdicts reproduce run to run and cannot flake; the 25 that do are the
# population this table covers.
#
# THE CURATED HALF, which is the actual work: what does the EXIT STATUS depend
# on?  #300's first rule is that sampling is not the defect -- deciding on a
# fresh sample against a fixed threshold is.  stern_ring_challenge_bias.py draws
# from os.urandom and gates on `counts == [86, 85, 85]`, which is arithmetic;
# nl_fscx_sparse_circuit.py samples 300 differences per order and gates on an
# EXHAUSTIVE degree computation, with the sampled row explicitly left ungated by
# #291.  Both are `exact` here.
#
# The four verdict codes, and the rule for each:
#
#   exact       the gate holds with probability 1 for correct code.  A fresh
#               sample changes WHICH instance is tested, not the outcome.
#   negligible  a sampled statistic against a fixed threshold, with the nominal
#               per-run false-failure rate STATED.  Must be < 1e-6.
#   replicated  #299's shape: an exceedance is confirmed against a second
#               independent sample at a stricter level before it fails.
#   follows     the threshold is computed FROM the statistic's own null rather
#               than fixed -- hybrid_credential_phi.py's 4-sigma Poisson band
#               around the expected (1/3)^R survivors is the model.
#
# Every entry carries a RATE or an ARGUMENT.  A rate is a number someone
# derived; an argument is a reason the rate is not the binding consideration,
# and entries resting on one are counted separately in the census line so the
# distinction cannot quietly erode.  #300's third rule is why: slack wide enough
# never to fire is TODO #234's vacuous pass, so "the threshold is generous" is
# not on its own a safe answer.
#
# WHAT THE CENSUS FOUND, all three fixed here.  (a) hfscx_256_analysis.py §1 and
# §2 gated |mean-128| < 3.SE on a fresh sample -- #299's own defect, in #299's
# own file, one section over, left because §3 was the one that fired.  (b)
# qc_mdpc_bgf_prototype.py §3 gated abs(z) < 3 on a fresh chi-square, and was
# wrong twice: flaky at ~1 run in 200 measured, and TWO-SIDED on a one-sided
# claim -- its single observed failure in 200 samples was z = -3.66, the sampler
# looking TOO uniform.  (c) qcmdpc_bgf_failure_rate.py was the inverse error and
# the worse one: main() had a single `return 0`, so it was discovered, run every
# CI run, and could not go red.  A gate that cannot fail is not a gate.
#
# name -> (code, rate-or-None, reason).  rate is the nominal per-run
# false-failure probability; None means the entry rests on its argument.
# A red run must be worth believing.  At 1e-3 a failure is 99.9% likely to be
# real, which is the standard the rest of this job is built to; the measured
# total is currently 6.4e-5 (5.4e-5 before TODO #304 derived the three `follows`
# rates this sum had been missing), and it is dominated by two gates -- #299's
# replicated chi-square in hfscx_256_analysis.py §3 at 5e-5 and #302's
# seed-budget gate at 1e-5.  Everything else in the table sums to about 4e-6.
# If this budget is ever approached, replicate the largest contributor; raising
# the number is how the premise rots.
_FLAKE_BUDGET = 1e-3

SAMPLED_GATES = {
    # ── replicated ──────────────────────────────────────────────────────────
    "hfscx_256_analysis.py": ("replicated", 5e-5,
        "§3's byte-uniformity chi-square is #299's replication (0.05 trigger, "
        "0.001 confirmation, 5e-5).  §1 and §2 were 3.SE one-shot SAC gates at "
        "2.7e-3 each until #300 and are now the same shape at 1.9e-8, so §3 "
        "dominates.  The null was measured over 24 blocks: z in [-1.50, +1.84], "
        "median 0.33, none past 2 sigma"),
    "qc_mdpc_bgf_prototype.py": ("replicated", 4.6e-9,
        "§3's PRF support uniformity, made ONE-SIDED and replicated by #300.  "
        "Only an over-large chi-square is evidence against uniformity, and the "
        "measured null (200 samples) fired once, at z = -3.66 -- the left tail, "
        "i.e. the sampler looking too good.  Negative control: a sampler missing "
        "10% of positions scores z = +20.85 in both samples"),
    "stern_f_weight_binding.py": ("replicated", 1e-10,
        "§2's signer-identification rate over k signatures, built on #299's "
        "pattern from the start (TODO #298).  §1 and §3 are exact, and §1 only "
        "BECAME so in TODO #310: this reason used to argue it from 'a "
        "Gaussian-elimination witness either verifies or does not', which is "
        "true of the VERIFIER and was not true of the WITNESS.  The "
        "free-variables-zero solve returns the TRUE error whenever all t of "
        "its positions fall in pivot columns -- rate 2^-t, i.e. 1.5e-5 here -- "
        "and the shipped verifier then correctly ACCEPTS it, which §1 scored "
        "as INCONCLUSIVE and returned as a failure.  The witness is now "
        "CONSTRUCTED off-weight by kernel addition, so the branch is "
        "unreachable.  §1 carried a SECOND term of the same kind, also argued "
        "away by that sentence: the verifier binds wt(e) only on b = 0 "
        "rounds, so the forgery survives a challenge string with none -- "
        "(2/3)^rounds, 7.4e-6 at the rounds = 32 it used.  Now 64, i.e. "
        "5.5e-11, so the section is exact to well past this table's "
        "resolution rather than usually right.  The negative controls "
        "score 20/20 and 32/33"),
    # ── follows ─────────────────────────────────────────────────────────────
    "hybrid_credential_phi.py": ("follows", 2.2e-7,
        "§5.4 gates a SOUNDNESS ERROR, so the bar follows the statistic: "
        "expected (1/3)^R of TRIALS_CHEAT survive and the band is 4-sigma "
        "Poisson around that, not zero.  MEASURED null, 60 samples: mean 3.77 "
        "against the expected 3.704, variance 3.57 against Poisson's 3.70, "
        "0/60 exceedances -- the one entry of the three whose model needed no "
        "correction.  A correct 4-sigma band on a mean of 3.7 nevertheless "
        "fires at P(X >= 12) = 4.7e-4, which is what it did in TODO #302's "
        "gate run and is 8.8x what the whole job then advertised; #299's "
        "replication takes it to 2.2e-7 for one extra second"),
    "zkp_pqc_exploration.py": ("follows", 6.6e-8,
        "§3.5 gates ZKBoo soundness the same way -- `passed <= "
        "int(expected*4)+2` around the expected (1/3)^R survivors -- and TODO "
        "#304 found the MODEL wrong, not the bar.  MEASURED null, 1500 "
        "samples: mean 2.028 against a modelled 1.235, variance 2.093, 9 "
        "exceedances, i.e. 6.0e-3 per run and 111x the 5.4e-5 then advertised. "
        "The missing term is that the 'cheat' is built as a fixed function of "
        "the instance, so about 1 trial in 131 hands it a GENUINE preimage and "
        "completeness passes it: conditioned on the trial being a real cheat, "
        "survival is 518/39695 = 0.01305 against (1/3)^4 = 0.01235 and the "
        "model is intact.  Those trials are now discarded, restoring 2.6e-4, "
        "and replicated to 6.6e-8.  §3.7 became EXACT in the same pass -- its "
        "claim that ZKB++ soundness is also (1/3)^R is FALSE (0 survivors in "
        "39 708 genuine cheats; ZKB++ rebinds out_e to y, so a wrong witness "
        "dies every round), and its old bar of 6 was slack enough to absorb a "
        "real regression.  §3/§3.7 completeness is exact (`fail == 0`)"),
    # ── negligible, with the rate derived ───────────────────────────────────
    "hkex_gf_test.py": ("negligible", 1.2e-6,
        "Test 3 gates `hits == 0` where Eve's linear attack succeeds only by "
        "collision, at 2^-n over TRIALS = 5000 at n = 32: 5000 * 2^-32.  Its "
        "other gates (`errors == 0`, `passed == TRIALS`) are exact"),
    "hkex_cy_test.py": ("negligible", 1.2e-6,
        "Same shape and the same 5000 * 2^-32 at n = 32: `hits == 0` for the "
        "linear attack, and `matched <= 2` for HKEX-CY agreement, where the "
        "accidental rate is 2^-n so three hits is far past astronomical"),
    "hkex_nl_proposal.py": ("negligible", 1.2e-6,
        "`hits == 0` for the classical attack at 5000 * 2^-32, as hkex_gf_test; "
        "its `passed == TRIALS`, `errors == 0` and `matched < TRIALS` gates are "
        "exact"),
    "hkex_rnl_sparse_hybrid_2026.py": ("negligible", 5.7e-7,
        "`abs(nz - 0.5) < 5 * SE` on the CBD(eta=1) density -- a two-sided "
        "5-sigma test, 5.7e-7.  The weight-law gate beside it compares the mean "
        "to 5 sample STANDARD DEVIATIONS rather than standard errors, which is "
        "slack rather than flaky and is why this entry is not `exact`"),
    "qcmdpc_bgf_failure_rate.py": ("negligible", 1e-36,
        "`failures == 0` over 400 trials, the gate #300 added to a main() that "
        "previously had a single `return 0`.  At BIKE-128 the DFR is ~2^-128 "
        "(#285 §2), so 400 * 2^-128 is zero for every purpose -- and a failure "
        "at this sample size is a DECODER REGRESSION, not a DFR event"),
    "hkex_rnl_failure_rate.py": ("negligible", 1e-40,
        "`f1 > 0` over 10 000 un-reconciled trials at n = 32, where the failure "
        "rate is percent-scale by construction -- P(f1 == 0) is (1-p)^10000.  "
        "`f7 == 0 and t7 >= 200` at the deployed ring is the reconciled DFR, "
        "which no sample of 200 can make fire"),
    "nl_fscx_v1_ratchet_collision.py": ("negligible", 1e-12,
        "The image fraction is a 50 000-sample coverage estimate with SE ~ 0.002 "
        "against a band of [0.55, 0.72] centred on 1 - 1/e -- about 40 SE of "
        "headroom.  n = 8 is excluded from the band by the entry's own comment "
        "because the asymptotic figure does not apply at 256 points"),
    "nl_fscx_v2_kex.py": ("negligible", 1e-9,
        "`comm_ex is None` fails only if a randomly drawn key pair happens to "
        "commute, which is the property the script exists to refute; the "
        "non-abelian gate beside it is a constructive witness and exact"),
    "nl_fscx_ligero.py": ("negligible", 1e-9,
        "§3's soundness asserts are rejections of a wrong statement, which can "
        "pass only at the protocol's own soundness error (2^-lambda per "
        "repetition); completeness (`assert ok`) is exact"),
    # ── found by TODO #301's widening: sampling through the SUITE ───────────
    "zkbpp_kkw_view_hiding.py": ("follows", 1e-5,
        "MEASURED null (TODO #304), and the one `follows` entry that turned out "
        "sound: 200 000 bootstrap replications of §2's statistic over 60 pooled "
        "runs gave ZERO exceedances of the shipped 1-bit band, so the rate is "
        "an upper bound rather than an estimate.  Two things the measurement "
        "settled that the argument could not.  The unit of observation really "
        "is the ROUND -- rounds inside one call share the witness, and the "
        "between-call to within-call variance ratio is 0.88 (seeded) and 1.27 "
        "(derived), i.e. no detectable correlation -- and the n = 8 seeded cell "
        "sits at a mean of 1.126, a 0.17-bit bias that eats a sixth of the band "
        "and is the thing to watch if the ladder ever moves.  An analytic "
        "estimate said this cell ran at ~7e-3 and a wider band was drafted on "
        "the strength of it; the bootstrap refuted that and the change was "
        "dropped, which is the same discipline the other two entries got.  "
        "Five of its six sections are exact for zkboo_view_hiding.py's reason "
        "(TODO #302): §1 and §3 enumerate every candidate against a fresh "
        "transcript, §4's u' - u == -rho.(residual) is an identity mod q, §5 "
        "is an equality, §6 reads source.  §2 is the one sampled section, and "
        "the bar FOLLOWS the statistic rather than sitting at a fixed level: "
        "it gates the EXPONENT of the seed-budget law to within 1 bit, where "
        "the two candidate exponents (2n-1 against n-1) differ by n bits, so "
        "the band is ~n-1 bits clear of the alternative at every width it "
        "measures.  The CONSTANT is deliberately not gated -- small-width "
        "combinatorics move it by 0.2-0.6 bits and gating that would be "
        "gating an artifact.  Observations are per ROUND, not per candidate: "
        "a round's candidates meet one enumerated seed multiset and move "
        "together, and a draft that banded them as independent cells was an "
        "order of magnitude too tight and flaked at 1 run in 3.  A cell with "
        "fewer than 5 rounds is reported and NOT scored, because a threshold "
        "a thin statistic always clears is #234's vacuous pass"),
    "zkboo_view_hiding.py": ("exact", None,
        "Draws a fresh ZKBoo keypair and proof every run, and the verdict is a "
        "COUNT over that proof: all 2^n candidates for the witness survive the "
        "revealed views, for any proof.  A fresh sample changes which transcript "
        "is enumerated, not the answer -- §3's control is what makes the count "
        "able to move at all.  This entry is the one that found #300's blind "
        "spot: its own script samples only through the suite"),
    "rnl_parameter_selection.py": ("exact", None,
        "Calls the suite's _rnl_keygen in §3 and §4, but the GATE is `worst is "
        "None` from §2's lattice estimate, which is a deterministic computation.  "
        "#300's first rule exactly: the script samples, the verdict does not"),
    "qcmdpc_dfr_weak_keys.py": ("negligible", None,
        "RESTS ON AN ARGUMENT.  §1 pins the shipped decoder against a "
        "per-position reference (exact per drawn instance) and §6's oracle check "
        "is exact; the sampled one is §4's multiplicity cliff against the "
        "deployed screen bound, measured at 31-32 against a bound of 6, so the "
        "margin is ~5x and not a few sigma.  Tighten the bound and derive the "
        "rate"),
    # ── exact: the verdict does not depend on the draw ──────────────────────
    "stern_ring_challenge_bias.py": ("exact", None,
        "Samples, but gates on `counts == [86, 85, 85]` (arithmetic: 256 = "
        "3*85+1) and on a SOURCE check that the rejection fix is still present.  "
        "The cleanest illustration of #300's first rule"),
    "nl_fscx_sparse_circuit.py": ("exact", None,
        "Gates on `algebraic_degree_exact`, an exhaustive computation.  Its "
        "300-sample degree detector is deliberately NOT gated -- #291 found the "
        "k=4 row flipping run to run and left it ungated with a comment saying "
        "so, which is this census's rule arrived at one item early"),
    "hkex_classical_break.py": ("exact", None,
        "`sk_alice == sk_bob == sk_eve` -- the break either works on a drawn "
        "instance or the algebra is wrong"),
    "hkex_fscxn_analysis.py": ("exact", None,
        "`c == t and e == t`: correctness and Eve's recovery both hold on every "
        "instance, being GF(2)-linear identities"),
    "hkex_multinonce_analysis.py": ("exact", None,
        "`ok == T` on both halves -- an identity that holds for every draw"),
    "hkex_nonce_impossibility.py": ("exact", None,
        "Four protocol identities (HSKE round trip, HPKE session key, the nonce "
        "impossibility, S_r.n_A constant), each exact per instance"),
    "hkex_pake_demo.py": ("exact", None,
        "The correct password yields one shared key (exact) and the wrong one "
        "does not (fails only on a 2^-n key collision)"),
    "oprf_demo.py": ("exact", None,
        "Blind/evaluate/unblind round trips and the verifiable-OPRF proof, all "
        "exact per instance"),
    "hpks_threshold_demo.py": ("exact", None,
        "Five protocol outcomes -- single-party verify, the rogue-key attack "
        "succeeding, 2-of-2 and 3-of-3 verifying, and coefficient binding "
        "blocking the attack -- each exact on the instance drawn"),
    "hpks_schnorr_z3.py": ("exact", None,
        "z3 decides each drawn instance outright; a random width-n instance is "
        "proved or refuted, never estimated"),
    "qcmdpc_parameter_selection.py": ("negligible", None,
        "RESTS ON AN ARGUMENT, not a derived rate.  Its sampled gates are "
        "BEFORE/AFTER comparisons whose two sides differ by orders of magnitude "
        "-- t = 134 decoding without failure, the BIKE rule beating the deployed "
        "one, rejection rates straddling 1%, the retired d failing at >= 90% of "
        "trials.  A margin that wide is not a few sigma apart, so the binding "
        "consideration is the separation and not a tail probability.  If any of "
        "these is ever tightened, derive the rate"),
}


def _suite_fresh_functions():
    """Suite functions that draw fresh entropy, TRANSITIVELY (TODO #301).

    #300's detector read each script's OWN source, which misses the script that
    calls `suite.zkp_nl_keygen()` and samples through it -- and #301's own gate
    was the first of those, so the census was blind to the script that exposed
    it.  Derived rather than listed: parse the suite, find the functions that
    touch os.urandom/secrets directly, then close over the suite's internal call
    graph.  28 of 222 at the time of writing.

    A NAME SET is deliberately coarse -- it cannot tell a call whose result
    reaches the verdict from one that does not -- but coarse in the SAFE
    direction: a false positive costs an entry with a reason, where a false
    negative is a gate nobody classified.  Three of the four scripts a crude
    "calls something called keygen" regex flagged were locally-defined helpers
    taking a seeded rng; this finds exactly the three that are real.
    """
    path = os.path.join(os.path.dirname(HERE), "Herradura cryptographic suite.py")
    try:
        with open(path, encoding="utf-8") as fh:
            src = fh.read()
        tree = ast.parse(src)
    except (OSError, SyntaxError):
        return set()
    direct, calls = set(), {}
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            body = ast.get_source_segment(src, node) or ""
            if _OS_ENTROPY_RE.search(body):
                direct.add(node.name)
            calls[node.name] = {c.func.id for c in ast.walk(node)
                                if isinstance(c, ast.Call)
                                and isinstance(c.func, ast.Name)}
    fresh, changed = set(direct), True
    while changed:
        changed = False
        for fn, cs in calls.items():
            if fn not in fresh and (cs & fresh):
                fresh.add(fn)
                changed = True
    return fresh


_SUITE_FRESH = None


def _fresh_entropy(src):
    """Which fresh-entropy sources a script draws from, if any (TODO #300).

    Fresh means "different every run", which is what makes a verdict able to
    flake.  A literal seed is not fresh -- `random.Random(1234)` reproduces --
    so the test for module-level `random.*` is use WITHOUT a literal seed call.
    """
    why = []
    if _OS_ENTROPY_RE.search(src):
        why.append("os.urandom/secrets")
    if _UNSEEDED_RE.search(src):
        why.append("random.Random()")
    if _MODRAND_USE_RE.search(src) and not _MODRAND_SEED_RE.search(src):
        why.append("module random.* unseeded")
    if not why:
        # Indirect: sampling through the suite (TODO #301).  Only asked when
        # nothing direct was found, since it is the more expensive test.
        global _SUITE_FRESH
        if _SUITE_FRESH is None:
            _SUITE_FRESH = _suite_fresh_functions()
        via = sorted(fn for fn in _SUITE_FRESH
                     if re.search(r"\.\s*" + re.escape(fn) + r"\s*\(", src))
        if via:
            why.append("suite: " + ", ".join(via[:3]))
    return why


def check_sampling(found):
    """TODO #300's census rule, in both directions.

    A gating script that draws fresh entropy must say what its verdict rests
    on; an entry naming a script that no longer gates, or that no longer draws
    fresh entropy, must go.  Same self-invalidating shape as EXCLUDED and
    NON_GATING -- a curated reason cannot outlive the thing it describes.
    """
    bad = []
    fresh = {}
    for name, _ in found:
        with open(os.path.join(HERE, name), encoding="utf-8") as fh:
            why = _fresh_entropy(fh.read())
        if why:
            fresh[name] = why
    for name in sorted(fresh):
        if name not in SAMPLED_GATES:
            bad.append("%s: draws fresh entropy (%s) and gates, but has no "
                       "SAMPLED_GATES entry -- say what its verdict rests on"
                       % (name, ", ".join(fresh[name])))
    names = {n for n, _ in found}
    for name, (code, rate, reason) in sorted(SAMPLED_GATES.items()):
        if not os.path.exists(os.path.join(HERE, name)):
            bad.append("%s: in SAMPLED_GATES, but no such file" % name)
        elif name not in names:
            bad.append("%s: in SAMPLED_GATES, but it is no longer a gating "
                       "script -- delete the entry" % name)
        elif name not in fresh:
            bad.append("%s: in SAMPLED_GATES, but it no longer draws fresh "
                       "entropy -- delete the entry (it reproduces now)" % name)
        if code not in ("exact", "negligible", "replicated", "follows"):
            bad.append("%s: unknown verdict code %r" % (name, code))
        if code == "negligible" and rate is None and "ARGUMENT" not in reason:
            bad.append("%s: declared negligible with no rate and no stated "
                       "argument -- derive the rate or say why it is not the "
                       "binding consideration" % name)
        # TODO #304.  `follows` was the one code exempt from the rate-or-
        # argument rule, on the ground that a bar computed from the statistic's
        # own null needs no number.  All three entries that used it were then
        # found flaking above the whole job's budget, because the NULL IS A
        # MODEL and nothing had checked the model: zkp_pqc_exploration.py §3.5
        # ran at 1.64x its modelled mean and 6.0e-3 per run, and §3.7's claim
        # was false outright.  A `follows` entry now owes the same rate, plus
        # the token MEASURED, because the arithmetic is only as good as the
        # null it is done against and the way to know is to sample it.
        if code == "follows":
            if rate is None and "ARGUMENT" not in reason:
                bad.append("%s: declared follows with no rate -- a bar that "
                           "follows the statistic still fires at some rate "
                           "against the true null; derive it" % name)
            if "MEASURED" not in reason:
                bad.append("%s: declared follows without a MEASURED null -- "
                           "the bar is computed from a MODEL of the null, so "
                           "say what the null actually measured" % name)
    # THE BUDGET, and it is deliberately a JOB-level number rather than a
    # per-gate one.  A per-gate bound is a constant somebody picks, and the
    # first draft of this check picked 1e-6 and then flagged three gates at
    # 1.2e-6 -- a rate of one run in 860 000, which is not a defect and was
    # only "too high" against an arbitrary line.  What #289's premise actually
    # rests on is the rate of the WHOLE job: if the gates together flake more
    # often than this, a red run stops meaning something and everyone starts
    # re-running, which is also the response to a real failure.
    total = sum(r for _, r, _ in SAMPLED_GATES.values() if r is not None)
    if total >= _FLAKE_BUDGET:
        bad.append("the job's nominal false-failure rate is %.1e per run, over "
                   "the %.0e budget -- replicate the largest contributor rather "
                   "than raising the budget" % (total, _FLAKE_BUDGET))
    return bad, fresh

def discover():
    """Every .py here whose exit status is its own verdict, plus the claimants.

    Returns (gating, unclaimed, undeclared) -- gating as (name, reduced-sample
    flag or None) pairs, unclaimed as the names that advertise a findings gate
    without matching any exit shape discovery knows, and undeclared as the
    scripts that neither gate nor appear in NON_GATING (TODO #291).
    """
    gating, claims, undeclared = [], [], []
    for name in sorted(os.listdir(HERE)):
        if not name.endswith(".py") or name == SELF:
            continue
        with open(os.path.join(HERE, name), encoding="utf-8") as fh:
            src = fh.read()
        if _GATING_RE.search(src):
            gating.append((name, _quick_flag(src)))
            continue
        if _CLAIM_RE.search(src):
            claims.append(name)
        if name not in NON_GATING:
            undeclared.append(name)
    return gating, claims, undeclared


def check_exclusions(found):
    """The orphan rule: an exclusion that describes nothing is an error."""
    names = {n for n, _ in found}
    bad = []
    for name, reason in sorted(EXCLUDED.items()):
        if not os.path.exists(os.path.join(HERE, name)):
            bad.append("%s: excluded, but no such file" % name)
        elif name not in names:
            bad.append("%s: excluded, but it is no longer a gating script -- "
                       "delete the entry (reason on file: %s)" % (name, reason))
    return bad


def check_declarations(found, undeclared):
    """TODO #291's coverage rule, in both directions.

    A script that neither gates nor is declared non-gating is an error -- that
    is the 46-script hole #291 closed.  And a NON_GATING entry that describes
    nothing is an error too, exactly as an EXCLUDED one is: naming a file that
    is gone, or one that has since become a gate, fails until the entry goes.
    """
    names = {n for n, _ in found}
    bad = []
    for name in undeclared:
        bad.append("%s: neither gates nor is declared -- make its exit status "
                   "its verdict, or add it to NON_GATING with a reason" % name)
    for name, reason in sorted(NON_GATING.items()):
        if not os.path.exists(os.path.join(HERE, name)):
            bad.append("%s: declared non-gating, but no such file" % name)
        elif name in names:
            bad.append("%s: declared non-gating, but it DOES gate now -- delete "
                       "the entry (reason on file: %s)" % (name, reason))
    return bad


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--quick", action="store_true", default=True,
                    help="pass --quick/--fast to scripts that declare one "
                         "(the default)")
    ap.add_argument("--full", dest="quick", action="store_false",
                    help="run every script at its default sample sizes")
    ap.add_argument("--list", action="store_true",
                    help="print what would run and exit")
    ap.add_argument("--timeout", type=int, default=3600,
                    help="per-script wall-clock limit in seconds (default 3600); "
                         "a hang must fail rather than consume the job")
    a = ap.parse_args()

    found, unclaimed, undeclared = discover()
    orphans = check_exclusions(found) + check_declarations(found, undeclared)
    sampling_bad, fresh = check_sampling(found)
    orphans += sampling_bad
    orphans += ["%s: its header advertises a findings gate, but its exit shape "
                "is not one this runner discovers -- teach _GATING_RE the shape "
                "or the script will never run in CI" % n for n in unclaimed]
    runnable = [(n, q) for n, q in found if n not in EXCLUDED]

    print("=" * 78)
    print("  findings gates: %d discovered, %d excluded, %d to run  (TODO #289); "
          "%d declared non-gating (TODO #291)"
          % (len(found), len(EXCLUDED), len(runnable), len(NON_GATING)))
    # TODO #300: what a red run is worth, as a number rather than a premise.
    rates = [r for c, r, _ in SAMPLED_GATES.values() if r is not None]
    argued = sum(1 for c, r, _ in SAMPLED_GATES.values() if r is None)
    by_code = {}
    for code, _, _ in SAMPLED_GATES.values():
        by_code[code] = by_code.get(code, 0) + 1
    print("  fresh-sampling gates: %d of %d classified (TODO #300) -- %s; "
          "%d rest on an argument"
          % (len(fresh), len(found),
             ", ".join("%d %s" % (n, c) for c, n in sorted(by_code.items())),
             argued))
    print("  nominal false-failure rate of the whole job: %.1e per run "
          "(sum over the %d gates with a derived rate; the other %d are "
          "argued; the remaining %d gates draw no fresh entropy and cannot flake)"
          % (sum(rates), len(rates), argued, len(found) - len(fresh)))
    print("=" * 78)

    if orphans:
        for line in orphans:
            print("  EXCLUSION ERROR: " + line)

    if a.list:
        for name, quick_flag in runnable:
            print("  %-44s %s" % (name, quick_flag if (quick_flag and a.quick)
                                        else ""))
        for name, reason in sorted(EXCLUDED.items()):
            print("  %-44s EXCLUDED: %s" % (name, reason))
        for name, reason in sorted(NON_GATING.items()):
            print("  %-44s NON-GATING: %s" % (name, reason.split(".")[0]))
        return 1 if orphans else 0

    failures = []
    t_all = time.time()
    for name, quick_flag in runnable:
        argv = [sys.executable, os.path.join(HERE, name)]
        if quick_flag and a.quick:
            argv.append(quick_flag)
        t0 = time.time()
        try:
            proc = subprocess.run(argv, cwd=os.path.dirname(HERE),
                                  stdout=subprocess.PIPE,
                                  stderr=subprocess.STDOUT,
                                  timeout=a.timeout)
            rc, out = proc.returncode, proc.stdout
        except subprocess.TimeoutExpired as exc:
            rc, out = 124, (exc.output or b"") + b"\n*** TIMEOUT ***\n"
        dt = time.time() - t0

        print("  [%s] %6.0f s  %s%s"
              % ("ok  " if rc == 0 else "FAIL", dt, name,
                 " " + quick_flag if (quick_flag and a.quick) else ""))
        sys.stdout.flush()
        if rc != 0:
            failures.append((name, rc, out.decode("utf-8", "replace")))

    print("-" * 78)
    print("  total %.1f min over %d scripts" % ((time.time() - t_all) / 60.0,
                                                len(runnable)))

    for name, rc, out in failures:
        print("\n" + "=" * 78)
        print("  FAILED (exit %d): %s" % (rc, name))
        print("=" * 78)
        tail = out.rstrip().splitlines()[-40:]
        for line in tail:
            print("  | " + line)

    print()
    if orphans:
        print("*** FAILED: %d coverage error(s) -- an exclusion or non-gating "
              "declaration that describes nothing, or a script that is neither "
              "***" % len(orphans))
    if failures:
        print("*** FAILED: %d finding gate(s) stopped reproducing: %s ***"
              % (len(failures), ", ".join(n for n, _, _ in failures)))
    if not orphans and not failures:
        print("*** OK: all %d findings gates reproduce ***" % len(runnable))
    return 1 if (orphans or failures) else 0


if __name__ == "__main__":
    sys.exit(main())
