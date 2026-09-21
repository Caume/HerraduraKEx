# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

HerraduraKEx is a cryptographic suite implementing four protocols — HKEX-GF (key exchange), HSKE (symmetric encryption), HPKS (Schnorr signature), and HPKE (El Gamal encryption) — built on the FSCX (Full Surroundings Cyclic XOR) primitive and Diffie-Hellman arithmetic over GF(2^n)*. Implementations exist in C, Go, Python, ARM Thumb-2 assembly, NASM i386 assembly, and Arduino.

## Repository Structure

```
Herradura cryptographic suite.{c,go,py,s,asm,ino}  — protocol suite, one file per language
herradura.h                                         — header-only C library (shared by CLI and external code)
CryptosuiteTests/
  Herradura_tests.{c,go,py,s,asm,ino}              — security tests & benchmarks
  go.mod                                            — module herradurakex/tests
HerraduraCli/
  herradura.py / herradura_cli.c / herradura_cli.go — OpenSSL-style CLI (Python, C, Go)
  herradura_codec.h / codec.py                      — PEM/DER encode-decode helpers
  primitives.py                                     — suite import shim for Python CLI
  go.mod                                            — module herradurakex/cli (replaces ../go.mod)
CliTest/                                             — CLI integration + cross-language interop
                                                      scripts.  Not indexed here: ci.yml's
                                                      native-interop coverage-guard step is the
                                                      real index, and fails if a script isn't
                                                      claimed by exactly one native-* job
  lib_dfr.sh                                        — shared QC-MDPC DFR retry policy; every
                                                       script that decapsulates must source it
                                                       (TODO #221), enforced by ci.yml's DFR guard.
                                                       Since TODO #235 a DFR event is an output
                                                       MISMATCH, not an error — implicit rejection
                                                       means `dec --algo hpke-stern-kem` always
                                                       exits 0 — so the retry is keyed on comparing
                                                       bytes, `dfr_is_event` is gone (the guard
                                                       fails on a resurrected copy), and a script
                                                       that only checks dec's exit status is no
                                                       longer testing the KEM
  lib_build.sh                                      — shared "is the CLI binary built?" policy
                                                       (TODO #229).  The compiled CLIs are not
                                                       tracked in git, so run ./build_c.sh and
                                                       ./build_go.sh before the C/Go CliTest
                                                       scripts; a run that asserts nothing now
                                                       exits 2 instead of 0
  test_v3_family.sh                                 — the five NL-FSCX v3 consumers at the
                                                       CLI (TODO #255): hske-nla3 and
                                                       hpke-nl3 across all four CLIs,
                                                       hske-duplex3 / fpe --v3 / twk --v3
                                                       across all four as well — TODO #260
                                                       added Java's fpe/twk in v5.3.6 and
                                                       its duplex in v5.3.8, and this line
                                                       said "Java ships no duplex, fpe or
                                                       twk" until TODO #261 caught it
                                                       contradicting the script's own
                                                       header.  Claimed by
                                                       native-interop; degrades to a NOTE
                                                       if bindings/java is not compiled.
                                                       Asserts the FLAG actually changes
                                                       the output — a --v3 that parsed and
                                                       was then ignored would pass every
                                                       round-trip
  test_zkp_hybrid_family.sh                         — the five algo tags Java lacked
                                                       until TODO #261 (v6.0.0), as a
                                                       full 4x4 matrix: every
                                                       (signer, verifier) pair for
                                                       nl-zkboo / nl-zkbpp / rnl-sigma
                                                       and every (responder, completer)
                                                       pair for hybrid-rnl-stern, the
                                                       latter compared on SESSION-KEY
                                                       BYTES since #235's implicit
                                                       rejection makes a mismatch
                                                       silent.  Claimed by
                                                       native-interop.  The matrix
                                                       shape is the point: every other
                                                       cross-language test checked each
                                                       implementation against PYTHON,
                                                       which reports Python-vs-Python
                                                       for the very pair that was
                                                       broken — nl-zkboo and rnl-sigma
                                                       had never interoperated between
                                                       {C, Go} and Python, and that is
                                                       why it shipped
  test_param_bounds.sh                              — the enforcement axis (TODO #278).
                                                       spec/'s PARAMETERS table compares a
                                                       bound's VALUE across the four
                                                       languages; it reads DECLARATIONS, so
                                                       it cannot see whether the bound is
                                                       APPLIED.  XMSS_MAX_H was 20 in all
                                                       four and enforced at genpkey by two:
                                                       Python's and Java's own comments
                                                       called the constant "genpkey's
                                                       --xmss-height cap" and neither applied
                                                       it there.  Java WRAPPED (1 << 32
                                                       shifts by 32 & 31 = 0, so it wrote a
                                                       ONE-leaf tree labelled h = 32 and
                                                       exited 0); Python did not wrap and so
                                                       never returned.  Only running the CLIs
                                                       can see that class.  Claimed by
                                                       cross-lang-compat.  Its rejections run
                                                       BEFORE the accept-control on purpose:
                                                       an in-range XMSS keygen costs minutes
                                                       in Python and Java, and a rejection
                                                       must be fast by definition
  lib_malformed.sh                                  — shared malformed-PEM case table (TODO
                                                       #239, #240): every field that sizes an
                                                       allocation, rewritten to a hostile value.
                                                       Sourced by test_weak_key_rejection.sh
                                                       (C only, so it also runs under the
                                                       sanitizers job) and by
                                                       test_malformed_pem_matrix.sh (all four
                                                       CLIs, claimed by cross-lang-compat).
                                                       Each section asserts the genuine artifact
                                                       first and skips its rejection cases if
                                                       that control fails — a CLI that cannot
                                                       start also exits non-zero, which a
                                                       rejection test would otherwise score as
                                                       a pass
KAT/                                                 — fixed Known-Answer-Test vectors (TODO #190, #226):
  classical_quartet.json    — HKEX-GF/HSKE/HPKS/HPKE vectors at n=256, NIST-CAVP-.rsp-style
  hkex_rnl.json              — HKEX-RNL two-party handshakes at the deployed n=1024
                               and at n=64: m_blind, both (s,C) pairs, the transmitted
                               hint, K_raw and the session key (TODO #226).  Pins the
                               suite layer only — the CLI/PEM layer is TODO #227
  pem/                       — byte-exact wire-format artifacts: keys, a kex response,
                               a session key and an HSKE ciphertext, which each CLI must
                               CONSUME and reproduce (TODO #227).  Pins the CLI layer that
                               hkex_rnl.json does not, at n=1024 and n=64 (TODO #228
                               settled the small-ring session-key width at 256 bits,
                               so all four CLIs now agree there; the C CLI is skipped
                               at n=64, being compiled for a single RNL_N).
                               Since TODO #268 it also holds enc_priv.pem, the
                               passphrase envelope over n1024_alice_priv.pem:
                               unlike hcred_kkw.json that one IS
                               regenerate-and-diff checked, because its two
                               random inputs (the PBKDF2 salt and the AEAD
                               nonce) are arguments the primitive accepts, so
                               pinning them pins the artifact.  Since TODO #280
                               it also holds enc_priv_zero_{ct,tag}.pem, whose
                               salt, nonce and (respectively) ciphertext or tag
                               START WITH 0x00 -- the case a minimal DER INTEGER
                               cannot carry, which C and Go rejected on about
                               one key in 64 while Python and Java read it back.
                               enc_priv.pem could not have caught that (its salt
                               starts 0x10, its nonce 0x60) and neither could the
                               random writer x reader matrix, which passes 63
                               times in 64.  Its expected
                               plaintext is a file this directory already
                               contains, so the CONSUME direction is checked
                               against a byte-exact target rather than a
                               re-derivation.  Since TODO #284 it also holds the
                               HPKE-Stern-KEM set -- kem_priv/kem_pub/kem_ct plus
                               message_kem.bin -- at the deployed BIKE-128, ONE
                               WIDTH ONLY because C compiles for a single
                               QCMDPC_R.  Before #284 no Stern-KEM artifact was
                               pinned ANYWHERE, and #276 had just moved every
                               field width.  The half that earns it is
                               kem_reject_ct.pem + message_kem_reject.bin, the
                               IMPLICIT-REJECTION output: since #235 a decoding
                               failure is silent by design, so test_stern_kem.sh
                               can only check the four CLIs against EACH OTHER --
                               that catches a divergence but NOT a drift, and a
                               four-way drift is invisible to every round-trip
                               test by construction.  Demonstrated, not argued:
                               moving QCMDPC_DS_Z in all four leaves
                               test_stern_kem.sh at 18/0 and fails this vector.
                               Its expected bytes are garbage BY DESIGN -- pinned
                               garbage is the point.  test_kat_pem.sh is the one
                               script EXEMPT from ci.yml's DFR guard, and the
                               exemption is the reasoned kind: a pinned key and a
                               pinned ciphertext have no randomness to retry
                               with, and if that pair ever stops decoding it is a
                               decoder regression, never a DFR event, so a retry
                               would mask the signal the vector exists to produce
  nl_fscx_v3.json            — the NL-FSCX v3 primitive (chi, one round, the
                               R3_VALUE revolve and its inverse) and all five
                               consumers (TODO #255).  The only KAT coverage of
                               the NL side of the suite.  twk's sector/bidx are
                               hex STRINGS, not JSON numbers: a 64-bit sector
                               does not survive the float64 a JSON parser
                               defaults to, and the loss is silent
  hcred_kkw.json             — HCRED-KKW, and the ONLY PINNED vector here
                               (TODO #266).  hcred_prove_kkw draws one
                               os.urandom root per emulation, so a proof is not
                               a function of its statement and regenerate-and-
                               diff cannot work: it is a VERIFY-SIDE vector that
                               every language must CONSUME and accept, like
                               pem/.  That is also the shape that catches the
                               bugs KKW actually had -- an inverted aux-reveal
                               condition (Go), an under-allocated commitment
                               buffer and a flipped bit convention (C) are all
                               READER disagreements about a byte layout.  TWO
                               SETS, and the reason is a finding: HCRED's width
                               is a runtime argument in Python and Go (both demo
                               at n=32) but a COMPILE-TIME constant of 256 in C
                               (HCRED_N) and Java (Hcred.N), so the four have
                               never proved the same statement size and only
                               n256 is consumable by all four.  n32 is kept
                               because one n=256 verification is ~70 s in
                               Python: the full accept-plus-six-rejections
                               matrix runs there on n32 and in the compiled
                               consumers on n256 -- split by COST, not coverage.
                               Z_q vectors are hex of the protocol's own
                               3-bytes-per-coefficient encoding, never JSON
                               numbers, for nl_fscx_v3.json's float64 reason
  hcred_kkw_vector.h         — GENERATED: hcred_kkw.json[n256] transposed into C
                               arrays (TODO #266), so the dependency-free C tree
                               needs no JSON parser.  A pure deterministic
                               transform of the JSON, so unlike the JSON it IS
                               regenerate-and-diff checked -- editing one
                               without re-emitting the other fails rather than
                               drifting.  The syndrome is emitted in
                               herradura.h's INTERNAL byte order (the reverse of
                               the big-endian integer Python/Go use); feeding
                               Python's order makes every proof reject with
                               nothing pointing at byte order
  generate_kat.py            — deterministic reference generator (Python) for the three
                               regenerable JSON files; --check verifies currency.
                               --capture-kkw re-captures the pinned KKW vector (the one
                               output here that legitimately differs run to run) and
                               re-emits its C header; --emit-kkw-header rebuilds the
                               header alone.  --check does not diff the KKW vector: it
                               VERIFIES it and asserts each tamper case rejects, which
                               is stronger — a byte-identical file whose verifier has
                               drifted still fails
  generate_pem_kat.py        — generator for pem/; --check verifies currency
  verify_kat.go               — independent cross-check against the Go herradura package
                               (bindings/java KatVerify does the same for Java)
  verify_kat_c.c              — the C consumer for hcred_kkw.json[n256] (TODO #266),
                               compiled on demand by CliTest/test_kat_vectors.sh.
                               C had no KAT verifier of any kind before this, in the
                               language where two of the three KKW port bugs were
SecurityProofsCode/                                 — standalone Python proof/analysis scripts:
  hkex_gf_test.py          — HKEX-GF DH correctness + BSGS DLP illustration
  hkex_nl_verification.py  — NL-FSCX period analysis, Ring-LWR invertibility/noise, v2 bijectivity
  hkex_cy_test.py          — FSCX-CY exhaustive non-linearity & HKEX-CY failure proof
  hkex_cfscx_*.py          — preshared-value, two-step, integer-op, compress/blong constructions
  hkex_classical_break.py  — classical algebraic break proofs
  fscx_revolve_corank.py   — co-rank of the classical FSCX_REVOLVE key map (TODO #210)
  fscx_revolve_closed_form.py — closed-form O(log i) FSCX_REVOLVE: the telescoping
                             identity, the Frobenius argument that keeps every
                             factor sparse, bit-exactness against the loop, and
                             why the NL variants cannot use it (TODO #213)
  hkex_gf_pohlig_hellman.py — Pohlig-Hellman cost/recovery vs. HKEX-GF/HPKS/HPKE (TODO #212)
  hske_perfect_secrecy.py  — Shannon-perfect one-time HSKE at odd step counts (TODO #211)
  hfscx_dm_rf_model.py     — HFSCX-256-DM re-derived in the ideal-random-function
                             model; Joux/Kelsey-Schneier demos (TODO #215)
  qcmdpc_dfr_weak_keys.py  — QC-MDPC BGF DFR extrapolation, weak keys, and the
                             GJS reaction attack (TODO #218), RE-POINTED at
                             BIKE-128 by #285 -- it had exited 1 in its own §1
                             since #276 moved the parameters, and it is the
                             recorded acceptance oracle for both #218 and #235.
                             It no longer carries its own decoder: #276 made the
                             SHIPPED one bit-sliced, which was the twin's whole
                             reason to exist, and the twin had by then diverged
                             twice (four bitplanes, valid only at d <= 15, plus
                             the pre-#276 threshold rule).  §1 now pins the
                             shipped decoder against a PER-POSITION reference,
                             at the deployed instance and at §3's waterfall --
                             both at d = 71, because BIKE's threshold floor of
                             36 unsatisfied checks is unreachable by a row of
                             weight 15, so the retired parameters are not a
                             usable cross-check instance for this decoder.
                             The re-pointing SPLITS the sections by what they
                             measure, and that split is the finding: §2 and §3
                             are about the SIZE of the failure rate, which at
                             BIKE-128 is not observable at any sample size (§2
                             reports a bound and says the 2^-128 is INHERITED
                             from BIKE; §3 inverts to come DOWN from r until the
                             waterfall appears, at ~80% of the deployed r, and
                             measures the CURVATURE to sign its extrapolation).
                             §4 and §5 are about its SHAPE and survive intact --
                             a weak key fails near 100% of the time, so §4
                             measures the multiplicity cliff at the deployed
                             parameters directly.  That last one RE-DERIVES the
                             constant #276 recorded on a retry budget: the cliff
                             has moved from 6-7 to 31-32, so QCMDPC_MAX_MULT = 6
                             is conservative by ~5x rather than tuned to an edge,
                             and §11.8.9's "cannot be re-derived" is true of the
                             METHOD (resolving DFR differences) and not of the
                             constant.  Exits non-zero if a finding stops
                             reproducing
  qcmdpc_bgf_variants.py   — do DECODER-SIDE BGF variants close the DFR gap?
                             (TODO #250).  READ THIS FIRST if you touch it: it
                             is a RETIRED-INSTANCE STUDY -- §§2-6 measure
                             r = 523, d = 15, t = 18 from the RETIRED literal
                             and §7 is the argument that carries the result to
                             what ships.  That was always the design; TODO #288
                             is where it started SAYING so, after #276's
                             adoption of BIKE-128 left it hardcoding r while
                             reading d and t from the suite -- building
                             (467, 71, 134) and sweeping r = 443..523 at d = 71,
                             instances that are not MDPC codes at 16% density --
                             and six of eighteen findings stopped reproducing,
                             §1's pinning among them, which is the gate the rest
                             is explicitly conditioned on.  §6's fit returned
                             r* = inf because there was no waterfall left.
                             Re-pointing the whole file at BIKE-128 was
                             considered and REJECTED: a decode at r = 9800
                             (#285 §3's reachable waterfall) costs ~55 ms
                             against ~1 ms here, minutes would become hours, and
                             §7 already supplies the transfer.  §1 now pins
                             TWICE, and the split is the useful part: (a) the
                             shared substrate against the REAL shipped
                             qcmdpc_bgf_decode, with SwPolicy carrying the
                             suite's QCMDPC_TH_* constants -- BIKE L1 is
                             expressible in this file's policy object, so the
                             substrate is held to a function that exists rather
                             than to a copy of itself; and (b) POL_BASE, which
                             models a decoder no longer in the tree and is
                             pinned by §5 against the MEASUREMENT that decoder
                             left behind (§11.8.7's 0.264%, 120 000 trials) --
                             a sharper referent than a 4 000-trial sample.
                             NB_ITER_RETIRED = 20 exists for the same reason the
                             literal does: the shipped decoder runs 5 now, and
                             pinning a 20-iteration policy against a
                             5-iteration function was half of why §1 failed.
                             NO, and the number is the point: the
                             best variant buys ~4 bits of DFR against a
                             ~120-bit shortfall, i.e. 3% of it, and moves the
                             fitted r* by ~4%.  #250 was gated on #276 for a
                             reason -- a comparison at r = 523 measures the
                             wrong instance -- so §7 re-runs it at the largest
                             (d, t) whose waterfall is reachable and checks the
                             RANKING transfers.  Three things worth knowing
                             before extending it.  (1) The variants are
                             answers to a measured FAILURE CENSUS (§2), not a
                             menu: at these parameters a failure is a STALL
                             (residual error weight ~16, residual syndrome ~96),
                             never a near-miss, so low-weight completion has
                             nothing to complete and the near-codeword test
                             fires but never solves.  (2) Everything that helps
                             helps for ONE reason -- it perturbs the trajectory
                             out of the stall -- which is why a tuned threshold,
                             a restart and a flip-then-resume all land within a
                             bit of each other, and why an early draft of the
                             script credited "completion" for repairs the
                             RESUME had made.  The mechanism attribution in §5
                             exists to keep that honest.  (3) The threshold grid
                             CONTAINS the shipped rule as its (slope 0,
                             offset 0) point, asserted by an identity check --
                             a first draft did not, because it dropped the
                             deployed decoder's post-iteration-7 relaxation, and
                             scored the baseline at 28.7% where it measures
                             10.7%.  A tuning grid whose null point is not the
                             baseline measures a third decoder
  qcmdpc_parameter_selection.py — HPKE-Stern-KEM's replacement parameters.
                             READ THIS FIRST if you touch it: the script is a
                             BEFORE/AFTER argument, and TODO #286 found it
                             failing its own findings gate three ways because
                             it read "before" from the present tense.  §1's
                             cost, §5's converse control and §6's rejection-rate
                             comparison all took the set-under-criticism from
                             _QCMDPC_R/_D/_T, which worked until #276's
                             recommendation was ADOPTED -- after which §1
                             printed that BIKE-128 is worth 2^136 and that "a
                             desktop reaches it" in one breath, §5's control ran
                             at d=71 where the rule it was meant to break works
                             fine, and §6 compared one instance against itself
                             (0.0200/0.0200).  There is now a RETIRED = (523,
                             15, 18) literal for the "before" side and a §0
                             frame guard that says so if the suite ever carries
                             something that is neither set.  #286 also withdrew
                             §7's "one blocker" (v6.7.3 shipped the bit-sliced
                             decoder it demanded) and reconciled §6 with #285's
                             measured cliff -- §6's premise that no cliff could
                             be measured at these parameters was wrong, and the
                             sentence is withdrawn rather than left standing,
                             though the retry-budget route it describes selects
                             the same constant
                             (TODO #276), on the model of #223's job for
                             HKEX-RNL.  Supplies the number §11.8.7 and
                             SECURITY.md were standing in for with "far below
                             any usable security level": the deployed instance
                             is worth ~2^21 classical, BELOW §11.8.3's
                             2^56-2^60 for the Stern-F SIGNATURE despite four
                             times the length, because ISD tracks the relative
                             distance t/N and 18/1046 vs 16/256 is 3.6x the
                             wrong way.  Dumer is calibrated against BIKE's
                             three published levels (+8.0 bits, spread 0.9
                             over a 3.3x range of r), not modelled.  CENTRAL
                             FINDING: t and d are set by ISD essentially
                             INDEPENDENTLY of r (min t moves by 6 and min d by
                             2 over a 12.3x range), and r is then set by DFR
                             alone -- so #218's fitted r = 1723 buys FOUR BITS
                             with d and t unchanged, and is separately
                             inadmissible because ord_2(1723) = 574 != 1722,
                             the same class of structural defect that made
                             #223 reject n = 768.  At r = 12323 the frontier
                             lands on exactly BIKE-128's (t, d) = (134, 71),
                             so the recommendation is to adopt BIKE-128
                             verbatim rather than invent a set.  Two things
                             that move with it and are easy to miss: the
                             threshold rule is a FUNCTION, not a constant
                             (BIKE's is affine in the SYNDROME WEIGHT; the
                             deployed one ignores it, and each fails outright
                             at the other's d), and the shipped PYTHON decoder
                             takes 5.4 s per decapsulation at r = 12323
                             against 16 ms today, so a bit-sliced rewrite is a
                             PREREQUISITE, not a follow-up.  QCMDPC_MAX_MULT
                             cannot be re-derived the way #218 derived it --
                             that needed a measurable DFR, which is what the
                             change exists to remove -- so 6 is recorded on a
                             stated retry budget and the cliff passes to #250.
                             ALSO CHECKS THE FSCX LAYER, which §11.8.5 had only
                             ARGUED about (its claim is about the INSTANCE, not
                             the sampler): qcprf_uniform_idx draws 16-BIT words,
                             and ENCAPSULATION samples modulo 2r, so BIKE-128
                             fits at 75% acceptance, BIKE-192 sits on the last
                             usable multiple, and BIKE-256 gives lim = 0 and a
                             NON-TERMINATING rejection loop -- a hard ceiling one
                             level above the recommendation, invisible from the
                             parameters.  The shipped sampler's supports are
                             indistinguishable from the ideal ones the MAX_MULT
                             figure was read off, so that constant transfers
                             rather than needing re-derivation.
                             Exits non-zero if a finding stops reproducing
  nl_fscx_v3_round_count.py — NL-FSCX v3's round count, DERIVED (TODO #255):
                             R3_VALUE = 5n/8 = 160 at n=256.  Rests on the
                             family's FIRST per-round trail bound — chi gives
                             the v3 round an unconditional floor of 2 bits
                             differential / 1 bit linear at every odd row
                             length, where v2 provably has none (its
                             linear-then-add-constant round hands every key a
                             probability-1 one-round differential).  So
                             §11.30.1's criteria are met at r >= n/2 = 128
                             outright, without #252 or #254; 160 adds a stated
                             1.25x margin for linear clustering.  Also finds
                             MINIMUM ROW LENGTH 5 is a hard constraint —
                             oddness alone is NOT sufficient: a 3-bit row on
                             the LSB gives a correlation-1 one-round linear
                             approximation to exactly the delta(B)-odd keys
                             (112/256 at n=8, exhaustive).  47x5+3x7 is
                             unaffected, but odd_partition(8) = (3,5) is not,
                             so §11.32's n=8 column is void.  Exits non-zero
                             if a finding stops reproducing
  nl_fscx_v3_weak_keys.py  — does NL-FSCX v3 need a key check?  NO, and it is a
                             proof rather than a sample (TODO #255).  The v3
                             round's key-dependence collapses to delta(B), and
                             chi's ROW-LOCALITY makes the per-row profile exact
                             at ANY width -- so an exhaustive statement about
                             every 256-bit key is a sweep over L=5 and L=7.
                             Both v2 weak classes dissolve; the differential
                             profile is key-INDEPENDENT, and the linear one is
                             graded but attains its worst grade for all but
                             ~1 key in 750,000, so there is nothing to screen.
                             Also CORRECTS #255's own round-count derivation:
                             the LOWEST-ACTIVE-ROW LEMMA (a pair always shares
                             the carry into its lowest active row) puts the
                             round-level differential floor at exactly
                             4 - log2(5) = 1.6781, not the layer-wise 2.000, so
                             the criterion needs r >= 153 and R3_VALUE = 160
                             clears it at 1.05x, not the 1.25x §11.33.6 recorded.
                             Exits non-zero if a finding stops reproducing
  and_layer_recheck.py     — TODO #246's candidate comparison, re-run after
                             #252 invalidated its methodology.  #246's ordering
                             SURVIVES and is better founded: B's advantage lives
                             in the TRANSIENT, which #252 showed is the
                             width-independent part, so it is the half of a
                             small-width comparison that carries to n=256.
                             Mechanism: any linear-then-add-constant round has a
                             probability-1 one-round differential (the MSB
                             freebie) and chi removes it -- B's round-1 weight is
                             2.00/1.81/2.00 where v2 and A are 0.00 on both axes.
                             Disqualifies candidate A (correlation-1 linear trail
                             through 8 rounds at n=8).  Records a reporting bug
                             of its own that had scored "no measurement window"
                             as "below criterion", penalising the stronger
                             candidates.  Leaves #251 a decision, not a blocker
  diff_bound_window.py     — why the differential bound has not closed
                             (TODO #252, first pass; still open).  The stall is
                             NOT solver time: an increment series has a cheap
                             transient (every key has a probability-1 one-round
                             differential) and a ceiling at ~0.6n, and the
                             asymptote lives between them -- a window that is
                             zero or one round wide at every width an exhaustive
                             DDT reaches.  So #247's 2.0/4.0/7.0, identical at
                             n=16/32/64, was measuring the TRANSIENT, not the
                             quantity the s_diff >= 4/3 criterion needs.  Demotes
                             #252's route 2 (yields >= 1 against a 4/3 bar) and
                             re-aims route 1 at higher ROUND COUNTS at n=32-64
                             rather than at wider n.  Re-checks and corrects
                             #254's linear numbers (settled 0.59/0.75/0.93/0.95;
                             conclusion holds, the "rises with width" trend is
                             weakened).  NAF-weight weak-key lead filed, not
                             concluded -- samples are too thin.  ITS CENTRAL
                             CONCLUSION IS WITHDRAWN by diff_cycle_mean.py: the
                             window argument is right about reading a slope off
                             a finite series and wrong about the asymptote
  diff_cycle_mean.py       — the asymptotic differential slope, MEASURED
                             (TODO #252, second pass; only the width
                             extrapolation is still open).  s_diff is the
                             MINIMUM MEAN CYCLE of the difference graph, so the
                             transient (the constant cost of walking into the
                             cycle) and the 0.6n ceiling (a codebook statement;
                             a cycle is not a codebook) both cancel -- and it is
                             exactly computable per key by Howard's policy
                             iteration, cross-checked against Karp and against
                             value iteration run far past the ceiling.  Per-key
                             median mu = 1.279/1.349/1.717/1.903 at n=7/8/10/11,
                             MONOTONE RISING, clearing the 4/3 criterion from
                             n=8 on, with the failing fraction falling
                             63%->27%.  Every key measured already passes the
                             deployed nl_v2_key_is_valid.  Corrects #247's "3.0
                             bits per round" -- the r=3..5 read misses the exact
                             asymptote by -7% to +17% with NO consistent sign,
                             so the 86-round projection has no support.  Closes
                             route 1 (HiGHS beats CBC 1.4-3.7x and proves
                             n=32 r=5,6, but growth is 3.6-4.0x per round, so
                             r=10-14 is 4-7 orders of magnitude away) and
                             supersedes route 3.  Exits non-zero if a finding
                             stops reproducing
  width_residue.py         — the ONE question #252 and #254 still share, worked
                             (both items still OPEN).  Does not close it;
                             changes it three times.  (1) THE RESIDUE IS
                             MONOTONICITY, NOT THE LIMIT: both criteria are
                             already met at the widest EXACT width (1.903 vs
                             4/3 at n=11; 1.154 vs 2/3 at n=13), so any
                             non-decreasing continuation clears n=256.  (2)
                             THERE IS NO EMBEDDING between widths -- M and
                             delta both depend on n, and only a third of
                             optimal-cycle nodes keep their image at n+1 -- so
                             §11.35.7's caution does not apply, and no proof
                             can come from comparing two graphs.  (3) An
                             ANNEALED FIRST-MOMENT MODEL predicts mu from the
                             edge-weight distribution and out-degree alone,
                             within a few percent by n=11 on BOTH axes, which
                             reduces the whole width question to the max
                             correlation / max xdp+ of addition with a
                             CONSTANT -- a statement with no FSCX in it.
                             Closes three routes by measurement: sparse
                             subgraphs (optimal cycles are dense, 0.6-0.86n),
                             a guessed LP-dual potential (Howard's bias
                             correlates with nothing, max 0.37), and sampling
                             the weight distribution at n=256 (the threshold
                             is a 2^-n quantile; the sampler returns 157 at
                             n=256 and 0.48 at n=13 where the exact answer is
                             1.154 -- DO NOT QUOTE THE 157).  Recommends
                             merging #252 and #254.  Exits non-zero if a
                             finding stops reproducing
  annealed_moment_ladder.py — the width extrapolation, EVALUATED (TODO #257,
                             which MERGES #252 and #254).  #255-era passes
                             closed the sampling route because the annealed
                             threshold sits in a 2^-n quantile; that is true
                             and is not the obstacle.  The model needs the
                             edge-weight distribution only through its
                             MOMENTS, and A_t = sum of (path count)^t is a
                             count of t-TUPLES of paths, hence one linear DP
                             over a tensor power -- O(n*t*2^t), no dependence
                             on the number of edges, exact at n=256.  Rests
                             on a carry-pair automaton for xdp+ with a
                             CONSTANT (the output difference is not free:
                             beta_i = alpha_i xor c_i xor c'_i, so a
                             differential is a constraint sequence), and on a
                             concavity lemma making the INTEGER lattice
                             exact rather than a lower bound.  FINDING: mu is
                             not asymptotically constant, it is LINEAR IN n
                             (~0.19n differential, ~0.088n linear), so the
                             fixed 4/3 and 2/3 criteria are cleared at n=256
                             by 36x and 34x and n=256 is the EASIEST width,
                             not the hardest.  Replaces #252's warned-against
                             157 with 48.4.  Retro-explains why every pass
                             since #247 saw mu rise and none could say why,
                             and corrects §11.30.2's reading that no key size
                             would help (the criterion is width-independent;
                             the achieved slope is not).  The linear axis
                             reaches only EVEN t -- a correlation's sign is
                             not affine in the masks, checked -- so it
                             brackets to 1-7% instead of closing.  Still an
                             ESTIMATOR: annealed, validated against exact mu
                             only at n<=13.  Exits non-zero if a finding
                             stops reproducing
  pair_correlation_second_moment.py — TODO #257's SECOND MOMENT, evaluated; closes
                             that item's part (1).  The whole pair correlation is
                             ONE RATIO, R(t) = M(2t)/M(t)^2, because a shared edge
                             contributes M(2t) to the joint exponential moment where
                             independence gives M(t)^2 -- and M(2t) is a higher rung
                             of the SAME A_t ladder #257 already built, which is why
                             it needed no new machinery.  FINDING: R alone is
                             enormous (2^226 at n=256) but the EDGE COUNT grows
                             faster, and log2(R/E) is LINEAR IN n (-0.653n
                             differential, -0.917n linear), so the correction is
                             2^-151 / 2^-219 at n=256 -- the first moment is not
                             carried by rare graphs.  Also EXPLAINS the 3-15%
                             validation gap §11.38 could only report: the correction
                             is O(1) across n=10..13, exactly the range where exact
                             mu exists, and its sign matches (an over-count
                             under-states the threshold).  Still NOT a bound on the
                             deterministic object -- an annealed ensemble
                             concentrating is not a fixed round function being
                             typical of it, which is why #257 stays open
  lin_cycle_mean.py        — the asymptotic LINEAR slope, measured, and the two
                             modes (TODO #254, second pass; only the width
                             extrapolation is still open).  s_lin is the
                             MINIMUM MEAN CYCLE of the mask graph, the same
                             reformulation #252 used on differences, and it
                             reaches n = 13 -- two widths further -- because
                             each LAT row is a ROTATION plus one
                             Walsh-Hadamard, not a per-pair carry automaton.
                             Records an exact identity for the LAT's support
                             (it depends on the addend only through tz).
                             v1 needs no separate machinery: pulling a mask
                             through M(A) xor M(B) xor ROL(A+B, n/4) leaves
                             addition of a CONSTANT again, with B itself in
                             delta(B)'s role.  Per-key medians rise monotonely
                             and clear the 2/3 criterion from n = 10 on, for
                             BOTH v1 and v2 -- so #11.30.6's reported
                             "flattening" was a finite-round artefact, and
                             nothing is promoted, since the v2 rows are
                             demo-only for reasons (#243, #244) this does not
                             touch.  ANSWERS #254's item (1) NEGATIVELY: a
                             trail bound cannot reach HSKE-NL-A1 or
                             HFSCX-256 at all, because in both the attacked
                             input is the round CONSTANT B, which enters every
                             round at once -- so there is no trail, and the
                             three production-track rows are not #254's to
                             move.  Exits non-zero if a finding stops
                             reproducing
  fscx_scaling_and_linear.py — the linear axis and what key size buys
                             (TODO #254, first pass; the bound is still open).
                             SCALE-INVARIANCE THEOREM: because r = 3n/4 is tied
                             to the block size, the trail criterion does not
                             depend on n -- s_lin >= 2/3, s_diff >= 4/3 at every
                             width -- so the open question is a scalar, and NO
                             KEY SIZE MOVES IT (n=512 is the same criterion at
                             4x cost).  Derived for a block cipher; does NOT
                             transfer unexamined to A1/HFSCX-256, which run n/4
                             rounds.  Closes the MILP route structurally: a
                             constant addend has non-power-of-two correlations,
                             so Wallen and every ARX encoding on it are
                             inapplicable.  Finds saturation had invalidated
                             most slope figures in the repo, #248's included
  v2_family_rating_review.py — re-review of the NL-FSCX v2 family ratings
                             (TODO #248).  Both rows stay demo-only and BOTH
                             RATIONALES ARE REPLACED: "no PRP/SPRP reduction"
                             is not the standard the rest of SECURITY.md uses
                             (six production-track rows rest on named
                             conjectures, as does AES), and the self-similarity
                             reason was already false -- #245 removed it and
                             both rows still asserted it while also saying it
                             was fixed.  Proves invariant-subspace resistance
                             at n=256 (BCLR criterion, the family's first
                             unconditional result).  Finds LINEAR, not
                             differential, is the binding axis -- and that it
                             does not distinguish A2 from the v1-backed
                             production-track rows, so it is filed as #254
                             rather than used to demote three more.  Exits
                             non-zero if a finding stops reproducing
  nl_fscx_v2_fixed_key.py  — the fixed-key trail gap (TODO #253).  #247's
                             factor of two between a real key and the
                             key-averaged bound does NOT dissolve with width
                             (0.50-0.61 at n=7,8,10,11) and is generic, not
                             tail-driven.  Finds a weak-key class the deployed
                             nl_v2_key_is_valid misses -- every B with
                             tz(delta(B)) >= 4 admits a zero-weight trail, at
                             every width including 256, proven by GF(2)
                             nullspace rather than extrapolated -- and shows it
                             costs at most ~3 of 192 rounds on 6% of keys, so
                             it is documented rather than screened.  Corrects
                             §11.20.5, which called the affine class a passing
                             cross-check when it is a proper subset.  Exits
                             non-zero if a finding stops reproducing.  Ungates
                             #248.  n=9/n=12 are excluded throughout: M is
                             singular there
  nl_fscx_v2_round_constants.py — round constants for NL-FSCX v2 (TODO #245).
                             Ships the fix and carries the corrections to #243
                             and #244: every n=12 measurement in §11.25/§11.26
                             was void (M is SINGULAR at n=12, so F_B is not a
                             bijection -- always check before picking a test
                             width), and the tau(192)=14 "confirmation" was a
                             25-key sample of a heavy-tailed statistic.  Proves
                             an XOR round constant leaves xdp+ exactly invariant,
                             so #214's trail bounds carry over verbatim
  hske_nl_a2_rating_review.py — is HSKE-NL-A2 production-track? (TODO #244).
                             No, and this is the suite's first downgrade of a
                             production-track row.  Adds the result #243 lacked:
                             a THEOREM, not a conjecture -- since E_B = F_B^r,
                             E[fixed points] = tau(r) = tau(192) = 14 against an
                             ideal cipher's 1 (measured 13.84 at n=16).  Not an
                             attack; provably not an ideal cipher.  Corollary:
                             192 = 2^6*3 is among the worst round counts
                             available, a prime gives ~1.04 (TODO #245)
  twk_stprp_review.py      — should `twk` move off demo-only? (TODO #243).
                             No: in the ROM it is an STPRP iff nl_fscx_revolve_v2
                             is an SPRP, and no such result exists.  Records the
                             structural finding neither #241 nor #242 caught --
                             v2-revolve is ONE unvaried round iterated 192 times,
                             no round constant, no key schedule -- so one slid
                             pair determines the key and the round count does
                             nothing against that class.  Also finds HSKE-NL-A2
                             carries the same assumption at production-track with
                             worse failure consequences (TODO #244)
  rand_fpe_twk_analysis.py — the three formerly-unclassified CLI subcommands
                             (TODO #241).  `fpe` and `twk` turn out to be the
                             same function -- one unseparated
                             HFSCX-256(key||tweak) subkey derivation, so a
                             12-byte ctx makes them identical -- and `fpe` is
                             not FPE in the SP 800-38G sense at all.  Exits
                             non-zero if a finding stops reproducing, so it
                             cannot print a stale verdict.  The fix is TODO #242
  hkex_rnl_lattice_2026.py — HKEX-RNL/HKEX-RNL-128 Core-SVP re-estimated directly
                             (primal/dual/hybrid), pinned to published Kyber and
                             Saber figures; supersedes the cited ~105/~220 bit
                             numbers with ~32/~87 (TODO #216)
  rnl_parameter_selection.py — picks HKEX-RNL's replacement parameters: rejects
                             n=768 (x^768+1 CRT-splits over Z, so it projects to
                             ~39 bits), measures the DFR floor, and lands on
                             n=1024 with p unchanged (TODO #223)
  sbox_kex_extension.py    — does #224 extend to an S-box?  It does not
                             extend — it is replaced: a characterization
                             theorem showing every step function admitting
                             HKEX agreement forces the i-fold iterate into a
                             coset of the translation group, after which the
                             session key is two evaluations of the public
                             step function away from the wire.  Subsumes
                             #210/#224/nonce-impossibility (TODO #230)
  corank_linear_box_decision.py — should the suite act on §11.22.2's
                             126 -> 64 co-rank improvement?  No: the classical
                             M is already optimal among rotation-based steps,
                             the cheap realisation puts 64 raw plaintext bits
                             in the clear, the sound one costs ~128x and does
                             not fit AVR, and odd i reaches co-rank 0 for free.
                             Also pins the leak's weight-4 functional
                             (TODO #232)
  mfscx_kex_analysis.py    — seed-masked FSCX revolve (MFSCX) as a key
                             exchange: static mask stays affine and the
                             classical break generalizes verbatim, dynamic
                             mask destroys two-party agreement, and the
                             generalized injection-schedule impossibility
                             theorem closes the middle ground.  Negative
                             result (TODO #224)
  stern_f_multiround_fs.py — HPKS-Stern-F round count vs. multi-round
                             Fiat-Shamir forgery; challenge-expansion audit
                             (TODO #217)
  stern_f_round_count_resolution.py — reruns #217's uniformity statistic at
                             3M seeds, dropping the resolution floor 0.4418 ->
                             0.0588 bits and settling r=219 vs 220 (TODO #222)
  stern_f_weight_binding.py — the two properties no Stern test asserted
                             (TODO #298), and the item that found a UNIVERSAL
                             FORGERY.  READ §1 FIRST if you touch the Stern
                             verifier: the b = 0 check must be on
                             respA XOR respB, which is wt(sigma(e)) = wt(e).
                             Until v8.0.0 it was on respA alone -- wt(sigma(r)),
                             the prover's own BLINDING value -- and b = 1
                             checked wt(r), so no branch bound the witness at
                             all.  The statement proved was "I know some
                             preimage of s under H", and H is n/2 x n, so a
                             preimage is one Gaussian elimination away from the
                             PUBLIC key: a weight-67 e' signs anything, in
                             milliseconds, with no secret.  §2 is the RING
                             ANONYMITY half and the same root cause: with r
                             weight-t the real y = e XOR r had weight ~2t where
                             a simulator's dummy was uniform, so ONE b = 0 round
                             named the signer (measured: wt(respA XOR respB)
                             exactly t for the signer, 117-143 for every other
                             member, k = 4, rounds = 32).  It gates an
                             IDENTIFICATION RATE, with #299's replication rather
                             than a fixed threshold on one sample.  §3 is the
                             part that keeps the rest honest: both markers are
                             re-run against the RETIRED constructions and must
                             FIRE -- a hiding test that cannot fail is #234's
                             vacuous pass one layer out, and the §2 control is a
                             transcript rebuild rather than a second copy of the
                             whole ring signer, because the STATISTIC is what is
                             under test.  What #298 could NOT have found by
                             comparison, and the reason it exists: all four
                             ports drew the uniform dummy, so the operation
                             replay pinned it green.  Exits non-zero if a
                             finding stops reproducing
  nl_fscx_exact_trail_search.py — exact xdp+ trail bounds for NL-FSCX v1/v2
                             via SMT; rotation table; key-averaging gap
                             (TODO #214)
  hkex_rnl_failure_rate.py — HKEX-RNL reconciliation failure rate, plus §6,
                             which until TODO #286 printed a SECURITY TABLE in
                             which every row was wrong in the unsafe direction:
                             it labelled the retired n=256 "Current (deployed)"
                             at 110 bits, starred n=512 as ">=128 classical+
                             quantum" at 220, and called the actually deployed
                             n=1024 a "(reference)" at 440 -- against the
                             ~32/~87/~206 TODO #216 computed DIRECTLY.  The
                             anchor was a live constant, not a comment
                             (cl = _BASELINE_CL * n/256), and chosen_n = 512 fed
                             §7.  #286 WITHDREW the projection rather than
                             re-anchoring it, and the reason is worth keeping:
                             re-pointing the same model at ~32 would still
                             assert bits proportional to n, which #216's own
                             figures refute (32 -> 206 over 256 -> 1024 is 6.4x
                             for 4x), and #223 separately rejected n=768 on a
                             ring-structure ground -- x^768+1 CRT-splits over Z
                             -- that no scaling model can see.  §7 now verifies
                             reconciliation at the DEPLOYED ring instead of at
                             the declined candidate
  qcmdpc_bgf_failure_rate.py — a direct end-to-end DFR count over the shipped
                             keygen/encap/decode path.  Its claim to close the
                             "DFR never measured" gap of #183/#186 is WITHDRAWN
                             by TODO #286, not repaired: at BIKE-128 no trial
                             count reaches the rate (#285 §2), so the script
                             reports a one-sided upper bound and never prints
                             "Measured DFR: 0.000000", which reads as a result
                             and is not one.  The 2000-trial default -- sized
                             when the DFR was 0.26% -- is now 400
  hkex_*_analysis.py       — FSCX_N, multi-nonce, and nonce-impossibility analyses
  validate_katex.js         — pipeline simulator for GitHub KaTeX rendering
  check_part_index.py       — asserts every copy of the eight-part index (banners,
                              footers, README, CLAUDE.md, KATEX_RULES.md) agrees with
                              SecurityProofs.md, and that the advertised expression
                              counts match what validate_katex.js measures (TODO #231)
  zkboo_view_hiding.py      — what a ZKBoo transcript carries, and the last
                             of TODO #298's three hiding assertions (TODO
                             #301).  The two revealed party views must not
                             determine the third, and that is testable because
                             it is a claim about the SIZE OF A SET: at the demo
                             width every candidate witness can be ENUMERATED.
                             Measured: the revealed pair narrows the witness by
                             EXACTLY ZERO bits (256/256 at n=8, 4096/4096 at
                             n=12, unchanged at 32 rounds opened).  READ THIS
                             BEFORE TOUCHING _zkp_nl_evaluate_circuit: the
                             hiding rests on ONE TERM.  Party e+1's AND gate has
                             both operands open and is what the verifier checks;
                             party e+2's `+1` neighbour IS the hidden party, so
                             its revealed and_out carries a_e and c_e, and the
                             only mask is r_{p+1}, a tape bit of the party never
                             opened.  §3's control makes those bits known (a PRG
                             stuck at a constant) and the candidate set collapses
                             to 4/256, six bits, with the true witness still
                             inside -- that last part is what separates a real
                             leak from a checker disagreeing with its prover, and
                             two earlier drafts of the control failed exactly
                             there.  PYTHON-ONLY ON PURPOSE: the masking term is
                             pinned byte-exactly by KAT/operation_replay.json's
                             zkp_nl_prove row, so a port that drops it fails that
                             vector in all four languages, and §4 demonstrates
                             that rather than asserting it.  ZKB++ and KKW are
                             deliberately out of scope -- #298's note that a
                             shared harness converges on completeness again.
                             Exits non-zero if a finding stops reproducing
  zkbpp_kkw_view_hiding.py  — the other two of TODO #298's three hiding
                             assertions (TODO #302).  #301 did ZKBoo and
                             stopped; these are separate because THE EXPOSURE
                             SURFACE DIFFERS, which is the thing the file
                             measures rather than assumes.  ZKB++ OPENS SEEDS:
                             only party e+2's gate outputs are revealed (e+1's
                             are recomputed by the verifier), so the one
                             revealed gate vector is exactly the one masked by
                             the unopened party's tape, and under an ideal
                             expansion the witness is completely free.  But the
                             hidden party's 16-BYTE SEED determines its share
                             AND its tape, so the freedom is a COUNTING
                             question, and §2 answers it: a round constrains
                             that seed by 2n-1 bits when the hidden party is 0
                             or 1, and by only n-1 when it is party 2, whose
                             share is DERIVED (s2 = A ^ s0 ^ s1) rather than
                             seeded.  Validated against 2^(k-c) at three widths
                             in both regimes -- on the EXPONENT, where the
                             alternative is n bits away, and NOT on the constant,
                             which small-width combinatorics move by 0.2-0.6
                             bits.  Two corrections went into the PREDICTION
                             rather than into a wider band (the true witness's
                             cell is not a random draw, since the prover's own
                             seed is in the enumerated space; and a party-2
                             pattern collision inherits that seed, worth 1.28x
                             at 15 sigma when left out), and the unit of
                             observation is the ROUND: a round's 2^n candidates
                             meet ONE seed multiset and move together, so
                             banding them as independent cells was an order of
                             magnitude too tight and flaked at 1 run in 3.
                             TODO #304 audited this entry -- it was filed
                             `follows` with NO rate, which is precisely the hole
                             that item closes -- and it came back SOUND: 200 000
                             bootstrap replications over 60 pooled runs, ZERO
                             exceedances of the 1-bit band, so <= 1e-5 as an
                             upper bound.  Two things the measurement settled
                             that the argument could not.  The unit of
                             observation really is the ROUND: rounds inside one
                             call share the witness, yet between-call over
                             within-call variance is 0.88 seeded and 1.27
                             derived, i.e. no detectable correlation.  And the
                             n = 8 seeded cell runs at a mean of 1.126, a
                             0.17-bit bias eating a sixth of the band, which is
                             what to watch if the ladder ever moves.  NO code
                             change: an analytic estimate put that cell at ~7e-3
                             and a wider max(1 bit, 5 SE) band was drafted
                             against it, then dropped when the bootstrap refuted
                             the estimate.
                             THE CONSEQUENCE IS THE FINDING:
                             with k = 128 the slack is 129-2n, so it is 113 bits
                             at the CLI default n = 8 and ONE BIT at n = 64,
                             which is _ZKP_NL_MAX_N exactly.  ZKB++ stays
                             COMPUTATIONALLY hiding there -- reaching the
                             excluded candidates means searching 2^128 seeds --
                             but it is not STATISTICALLY hiding, and no document
                             here drew that line.  KKW needs no enumeration and
                             could not have one (the witness is in Z_q^288): the
                             observer's system is SOLVABLE IN CLOSED FORM, every
                             hidden-party unknown determined in one pass for ANY
                             candidate, leaving exactly one residual equation --
                             and §4 measures what it is:
                             u' - u == -rho.(circuit(w') - targets) mod q, the
                             VERIFIER'S OWN STATEMENT PROJECTION, identical in
                             every online emulation, so the tau of them are not
                             tau independent constraints.  §4 then CONSTRUCTS a
                             second witness the statement cannot separate (the
                             residual is quadratic in a delta-block coefficient,
                             degree asserted not assumed, and the true value is
                             one root) and shows the transcript cannot separate
                             it either.  Both controls follow #301's discipline
                             -- a 1-byte ZKB++ seed collapses 256 candidates to
                             the true one, a constant KKW pad makes z_in name
                             the witness -- and BOTH ASSERT THE TRUE WITNESS
                             SURVIVES, which is what separates a leak from a
                             checker disagreeing with its prover.  §6 CHECKS the
                             cross-port scope instead of asserting it: ZKB++ is
                             covered twice over (C's zkp_nl_pp_prove calls the
                             shared zkp_nl_eval_3p and Go's ZkpNlProvepp calls
                             zkpNlEvalCircuit, so the zkp_nl_prove replay row
                             pins its masking term; and the seed length, which
                             §2 makes a security parameter, is the
                             zkpp-seed-bytes PARAMETERS row), while KKW is
                             covered NOWHERE -- hcred_kkw.json is VERIFY-SIDE by
                             construction so it exercises no port's PROVER, and
                             KKW has no CLI surface so the 4x4 matrix does not
                             reach it.  That check is self-invalidating: adding
                             a KKW prover row FAILS §6 until the prose is
                             corrected.  Exits non-zero if a finding stops
                             reproducing
  run_findings_gates.py     — runs every findings-gating script here, and is what
                              CI's `analysis-findings` job invokes (TODO #289).
                              DISCOVERS its set rather than reading a list: a
                              script whose exit status is its own verdict is run,
                              with nothing to add anywhere.  That is the fix for
                              a three-item pattern -- #285, #286 and #287 each
                              added ONE script to a native-python step and
                              excluded the rest as too slow, and the excluded set
                              twice held a script that was already failing.
                              Skipping one needs a reason in EXCLUDED, which is
                              self-invalidating: an entry naming an absent or
                              no-longer-gating file FAILS.  A script that
                              ADVERTISES a findings gate and is not discovered is
                              an error too -- discovery reads the exit CALL, so a
                              fourth exit shape would otherwise be invisible.
                              Runs everything even after a failure and re-lists
                              the failures at the end, because #286 found three
                              broken gates in one script and #288 six.
                              `--list` prints the set without running it
SecurityProofs.md                                   — split index (redirects to Parts 1–9; quantum analysis is in SecurityProofs-2.md §6)
SecurityProofs-1.md                                 — §1: Algebraic Foundations (300 math expressions)
SecurityProofs-2.md                                 — §2–§8: Protocol Analysis · Security Analysis · Summary Tables · Quantum Attack Analysis · Experimental Code Index (409 math expressions)
SecurityProofs-3.md                                 — §9–§10: Non-Linear Proposals · v1.4.0 Migration (409 math expressions)
SecurityProofs-4.md                                 — §11–§11.8.2: Non-linearity/PQC extensions · NL-FSCX v1/v2 · HKEX-RNL (693 math expressions)
SecurityProofs-5.md                                 — §11.8.3–§11.8.10: PQ signature options · HPKE-Stern-KEM (672 math expressions)
SecurityProofs-6.md                                 — §11.9: HFSCX-256-DM (131 math expressions)
SecurityProofs-7.md                                 — §11.10–§11.13, §11.15–§11.33: ZKP extensions · Ring-LWR Σ-protocol · NL-FSCX ZKBoo · research-review sections (698 math expressions)
SecurityProofs-8.md                                 — §11.34–§11.36: NL-FSCX v3 exact row analysis · the asymptotic differential and linear slopes, measured (435 math expressions)
SecurityProofs-9.md                                 — §11.37–§11.39: the width residue #252 and #254 shared · the annealed threshold, evaluated exactly at n = 256 · the pair correlation, which closes #257's second-moment item (485 math expressions)
docs/
  TUTORIAL.md               — API usage guide per protocol and language
  INTRODUCTION.md           — lay-audience primer for all core concepts
  examples/{python,c,go}/   — hello_herradura.* integration examples
Mcp/                                                 — MCP server exposing the CLI (genpkey/pkey/kex/
                                                      enc/dec/sign/verify/dgst) as agent-callable tools
                                                      over stdio; see Mcp/README.md for the trust model.
                                                      Mcp/test_server.py and
                                                      docs/examples/mcp/hello_herradura_mcp.py both run
                                                      in native-python since TODO #287 -- they existed,
                                                      passed, were listed in Mcp/README.md under
                                                      "Testing", and NO job ran either, which mattered
                                                      because claim 3 of the trust model ("private-key
                                                      file contents are never echoed back") names
                                                      test_server.py as its own enforcement.  #287 also
                                                      found the harness exercising five of eight tools
                                                      end to end -- enc/dec/dgst were named in the
                                                      tools/list assertion and never CALLED, so the one
                                                      tool that turns a private key plus a ciphertext
                                                      into plaintext was untested -- and applying the
                                                      key-echo check to `sign` alone, the tool where a
                                                      leak matters least.  THE DEFECT IT FOUND: every
                                                      input_schema declares additionalProperties: false
                                                      and travels to the agent in tools/list, and the
                                                      server never validated against it, so an unknown
                                                      argument was dropped in silence -- exit 0,
                                                      artifact written, no mention in the response.
                                                      That is TODO #274's fail-open shape one boundary
                                                      further out: misspell `aead` and the caller asked
                                                      for authenticated encryption and got
                                                      confidentiality only, except the caller here is an
                                                      LLM that generated its JSON from a schema
                                                      promising violations are reported.  The server now
                                                      enforces required keys, unknown keys, declared
                                                      types and enums, and returns an isError result
                                                      naming the offender.  One trust-model sentence was
                                                      also WITHDRAWN as an overstatement: responses do
                                                      not carry "never file bytes" -- `out: "-"` sends a
                                                      tool's output to stdout and responses carry
                                                      stdout, so dgst returns a hex digest that way by
                                                      design and dec returns PLAINTEXT into the agent's
                                                      context.  The caller chose it; a test pins it so
                                                      it stays a choice
spec/                                                — machine-readable protocol spec (JSON Schema):
                                                      parameters, PEM wire-format labels, CLI --algo
                                                      tags, and security-level classification per
                                                      protocol; generate_spec.py regenerates it and
                                                      `--check` gates it (stale-vs-generator, schema
                                                      validity, and that every tag the CLIs accept is
                                                      classified).  Schema validation needs the
                                                      `jsonschema` package — tooling-only: a bare
                                                      python3 gets a NOTE, while CI installs it and
                                                      passes `--require-schema` so a skipped
                                                      validation cannot pass.  (It is no longer the
                                                      repo's only third-party package: see the
                                                      optional-dependency note below.)  check_security_md.py
                                                      cross-checks
                                                      every protocol's status against SECURITY.md's
                                                      prose table — the disagreement-between-documents
                                                      class TODO #237 found three of and #238 two more.
                                                      check_language_parity.py (TODO #261) is a
                                                      different axis: numbered-test [N] contiguity in
                                                      each of C/Go/Python/Java, set-alignment of
                                                      C/Go/Python's shared [1]-[51] numbering, a
                                                      manifest of suite-internal (non-CLI)
                                                      primitives -- 200 entries, four cells each --
                                                      so a primitive with no `--algo` tag can still
                                                      be caught missing in a language, and since
                                                      v6.1.0 an INTERNAL-SURFACE CENSUS that closed
                                                      TODO #261.  The census is what keeps the
                                                      manifest complete: per language it lists the
                                                      suite's own top-level functions, subtracts the
                                                      ones that language's CLI calls, subtracts the
                                                      ones the manifest names, and FAILS on the rest.
                                                      So adding a suite-internal primitive in any
                                                      language is a CI failure until it is filed with
                                                      four cells or given a CENSUS_EXEMPT rule with a
                                                      reason -- and an exempt rule matching nothing is
                                                      itself an error, so a family cannot leave its
                                                      excuse behind for the next thing that matches.
                                                      A marker regex must match EXACTLY
                                                      ONCE, not merely occur (TODO #261, v6.0.3):
                                                      Java's entry is every SUITE herradurakex/*.java
                                                      concatenated, so a bare method name like
                                                      `public static boolean verify(` matches six
                                                      classes and keeps passing after the one it
                                                      guards is deleted.  Anchor new Java markers on
                                                      the signature, or scope them with the
                                                      `File.java::<regex>` form (v6.1.0), which also
                                                      pins WHICH class holds the primitive.  Note
                                                      JAVA_NON_SUITE: HerraduraCli.java, Codec.java
                                                      and the test drivers are NOT read, because a
                                                      primitive living only in a CLI is the very
                                                      asymmetry this manifest catches (it found one
                                                      in Python at v5.8.7 and another in Go and
                                                      Python at v6.1.0).
                                                      check_docs_consistency.py (TODO #265)
                                                      is the third axis, and the only one that reads
                                                      the NARRATIVE documents: README.md,
                                                      docs/INTRODUCTION.md and CHANGELOG.md restate
                                                      spec/'s and herradura.h's protocols, parameters
                                                      and verdicts in hand-written prose, and nothing
                                                      compared them before.  SIX checks now -- it was
                                                      four until TODO #286 and #287 added two, and this
                                                      line said "four" until #288 caught it.  A:
                                                      versions (README title / CHANGELOG head /
                                                      pyproject.toml agree; MAJOR bumps have a
                                                      MIGRATING.md entry).  B: parameters (herradura.h
                                                      #defines, resolved transitively, vs. spec/ and
                                                      vs. the sentences quoting them), plus a CENSUS
                                                      that fails on a parameter assignment no DOC_PARAMS
                                                      row captures -- the direction that was open, and
                                                      how #276 moved QCMDPC_R/D/T under four documents
                                                      for two releases.  B'' (TODO #286): currency
                                                      claims in SecurityProofsCode/ -- a phrase
                                                      asserting CURRENCY ("current", "deployed",
                                                      "ships") next to a number that must equal the
                                                      header constant.  The protocol FAMILY has to be
                                                      identifiable and comes from the sentence OR, since
                                                      TODO #288, from the FILENAME: a file entirely
                                                      about one family never names it in a sentence,
                                                      which is exactly where the defect hid --
                                                      qcmdpc_bgf_variants.py titled a section "the
                                                      deployed parameters (r = 523, d = 15, t = 18)"
                                                      over code measuring BIKE-128 and B'' could not
                                                      see it.  Requiring the token is still right (it
                                                      took that check from 35 findings, 33 of them on
                                                      CORRECT sentences, to one); the filename default
                                                      is how it keeps being right without the blind
                                                      spot, at the price of four exemptions that are
                                                      all correct sentences and all carry a reason --
                                                      if that list grows without reasons that specific,
                                                      revisit the widening rather than the exemptions.
                                                      C: protocol coverage (both directions).  D: a
                                                      claims table of corrected statements that must
                                                      stay plus superseded ones that must not return.
                                                      E (TODO #287): CLAUDE.md's own tool-emitted
                                                      counts, held to the tool that prints them rather
                                                      than to a hand count, so a wording change in the
                                                      tool fails as "cannot read" instead of passing
                                                      vacuously.  Its curated tables are
                                                      self-invalidating the way check_security_md.py's
                                                      mapping is: a spec/ protocol with no
                                                      DOC_COVERAGE entry fails, and every regex must
                                                      match at least once, so deleting the sentence an
                                                      entry anchors to is an "anchor lost" FAILURE,
                                                      not a silent pass.  All four run in CI's
                                                      native-python job (TODO #238, #261, #265).
                                                      `protocols` is keyed on a protocol id, not an
                                                      --algo tag: aPAKE, and since TODO #241 also
                                                      hdrbg/fpe/twk, have no tag and are filed under
                                                      their subcommands via `cli_binding`.
                                                      `unfiled_cli_surface` now names only `pkey`, a
                                                      key-format utility with no protocol of its own.
                                                      cli_flag_matrix / cli_surface_gaps (TODO #267)
                                                      are the FOURTH axis, one level below
                                                      cli_support: that column answers "does this CLI
                                                      dispatch this --algo tag", and #261 met it at
                                                      v6.0.0, but a subcommand's FLAGS are capability
                                                      too and nothing compared them.  Derived from
                                                      each CLI's OWN argument parser -- argparse
                                                      add_argument, C's get_arg/has_flag, Go's
                                                      flag.FlagSet + stringFlags, Java's
                                                      opt.get/req -- mapping subcommand to handler
                                                      and then FOLLOWING DELEGATION, or C's
                                                      threshold-verify flags (reached only via
                                                      cmd_verify) read as absent from a CLI that has
                                                      them.  Every extractor RAISES when it maps no
                                                      subcommands, so a stale regex fails as "the
                                                      extractor broke" rather than as "port 26
                                                      subcommands".  cli_surface_gaps is exhaustive
                                                      in both directions like check_docs_
                                                      consistency's anchors: a gap with no reason
                                                      fails, and so does a reason with no gap -- so
                                                      PORTING a flag fails --check until its
                                                      CLI_FLAG_PARITY entry is deleted.  Two limits
                                                      to know before extending it: it is at FLAG
                                                      granularity, so a flag's VALUE set can still
                                                      differ (kex --kdf takes sp800227 in Python
                                                      only) and that lives in the gap's reason, not
                                                      in the matrix; and a flag gap is scoped to CLIs
                                                      that define the subcommand, so Java's missing
                                                      `rand` is ONE subcommand row, not eight flag
                                                      rows.  `status` is acknowledged (deliberate
                                                      per-language scope) vs defect (a real
                                                      asymmetry, recorded and counted) -- #267 closed
                                                      on the MECHANISM, so defect rows are the
                                                      expected steady state, not a failing one.
                                                      Read the counts from cli_surface_gaps, not
                                                      from prose: #269 and #270 have already deleted
                                                      ten of the original sixteen, each deletion
                                                      FORCED because the generator refuses to emit a
                                                      spec while an acknowledgement describes a gap
                                                      that no longer exists.  #273 (v6.5.4) and
                                                      #268 (v6.5.5) deleted the last five, so every
                                                      remaining row is `acknowledged` -- a deliberate
                                                      per-language scope decision -- and a NEW
                                                      `defect` row now means a fresh asymmetry rather
                                                      than an inherited one.  #268 also showed the
                                                      table catching a gap being CREATED: a Java-only
                                                      `dec --aead` was refused before it shipped.
                                                      NOTE for anyone adding a new way to
                                                      READ a flag: the matrix is derived from
                                                      per-language accessor patterns, so a new
                                                      accessor must be taught to the extractor or
                                                      its flags read as ABSENT -- #269's
                                                      readMessage and #270's get_arg_multi2 /
                                                      multiValueFlags / multiPaths each needed that.
                                                      cli_flag_value_gaps (TODO #269) is the FIFTH
                                                      axis and sits one level below cli_flag_matrix
                                                      again: that matrix answers "does this CLI
                                                      DEFINE this flag", never "which VALUES does it
                                                      accept".  Two divergences lived under that
                                                      floor and neither was visible anywhere -- C and
                                                      Go REJECTED `kex --kdf none`, which is Python's
                                                      own default value, and both SILENTLY accepted
                                                      any unrecognised `--digest` as `none`, the
                                                      weaker branch, so one missing hyphen signed the
                                                      raw message and reported success.  Shape is a
                                                      derived/curated split, because it has to be:
                                                      Python's value sets come from argparse
                                                      `choices=` and MUST be written as None in
                                                      CLI_FLAG_VALUES, while C/Go/Java accept values
                                                      through chains of string comparisons that no
                                                      regex reads reliably.  Exhaustive in both
                                                      directions like every other table here, with
                                                      the orphan rule doing the same work one level
                                                      down: an entry whose value sets have CONVERGED
                                                      fails generation until it is deleted, so
                                                      reaching value parity forces the row out rather
                                                      than leaving a stale claim.  The axis is
                                                      SPARSE by design -- a flag belongs in it only
                                                      while the four disagree, which is why
                                                      `--digest` is absent (all four now take exactly
                                                      {none, hfscx-256}) and `kex --kdf` is present
                                                      (Python alone takes sp800227).  Its executable
                                                      half is CliTest/test_kdf_matrix.sh and
                                                      test_digest_matrix.sh's value-set block.
                                                      PARAMETERS / PARAM_DIVERGENCE (TODO #278),
                                                      in check_language_parity.py, are the SIXTH
                                                      axis and the first to compare a numeric
                                                      parameter's VALUE: 82 rows, four cells each,
                                                      naming the CONSTANT and never its number, so
                                                      the checker reads and evaluates it from each
                                                      language's source and the table cannot go
                                                      stale.  Curated rows because names do not
                                                      survive translation -- RNL_ETA in C and Go is
                                                      RNLB in Python and Java, and only 8 of 116
                                                      normalised names appear in all four, so
                                                      automatic pairing is not available.
                                                      Exhaustive in both directions like every
                                                      other table here: a suite constant named by
                                                      no row fails the parameter census, and a
                                                      PARAM_DIVERGENCE row whose languages have
                                                      CONVERGED fails until deleted.  Java's
                                                      per-class re-declarations (Duplex.N,
                                                      Stern.N, ...) are NOT exempt but CHECKED
                                                      against the row they copy, via
                                                      PARAM_JAVA_ALIASES -- Java has no header, so
                                                      a drifted copy is exactly the defect this
                                                      looks for, and the evaluator resolves an
                                                      unqualified name in its OWN class first or
                                                      one class's constant answers for another's.
                                                      A `None` cell -- "this language has no
                                                      such constant" -- is cross-checked
                                                      against that language's declarations,
                                                      because a cell the EXTRACTOR dropped
                                                      looks identical to one that genuinely
                                                      does not exist and the census cannot
                                                      tell them apart; the first C regex
                                                      dropped R3_VALUE and I3_VALUE, whose
                                                      bodies end in a comment.
                                                      Each row carries `wire` or `local`: 28 are
                                                      `local`, meaning a disagreement there reaches
                                                      no artifact and no round-trip or interop test
                                                      can see it, so this axis is their only check
                                                      -- QCMDPC_MAX_MULT (the row #276 asked for,
                                                      a keygen-retry gate) and QCMDPC_NB_ITER (it
                                                      changes the DFR, not the ciphertext) are the
                                                      two worth knowing.  KNOWN LIMIT, and #278
                                                      found it the hard way: this axis reads
                                                      DECLARATIONS, so it cannot see whether a
                                                      bound is ENFORCED.  XMSS_MAX_H = 20 in all
                                                      four and only C and Go applied it at genpkey;
                                                      Python's and Java's own comments called the
                                                      constant "genpkey's --xmss-height cap".  That
                                                      class needs CliTest/test_param_bounds.sh,
                                                      which runs the four CLIs, and is claimed by
                                                      cross-lang-compat.  A SECOND KNOWN LIMIT,
                                                      found by TODO #294: the axis compares a
                                                      constant's VALUE and the census compares a
                                                      primitive's PRESENCE, so neither can see HOW
                                                      a primitive uses its constants -- a sampling
                                                      STRATEGY is invisible here.  rnl_sigma_sign
                                                      drew its ZK mask y by REJECTION SAMPLING in C
                                                      and by raw modulo in the other three, a
                                                      3-vs-1 split with C the correct one, and
                                                      nothing in the repo could see it: y is local
                                                      randomness reaching no artifact, so no KAT
                                                      pins it and none could (a proof is randomised
                                                      per signature), and no round-trip or interop
                                                      pair compares two samplers.  That is #293's
                                                      invisibility property one axis over -- #293's
                                                      split was in READ PATTERN, #294's in
                                                      DISTRIBUTION.  The only check available for
                                                      this class is a FIXED-STREAM REPLAY, which
                                                      pins the four consumption orders against each
                                                      other; it works only because #294 adopted C's
                                                      scheme verbatim in the other three rather
                                                      than inventing a fourth correct sampler
                                                      PARAM_USE_CORPUS / PARAM_USE_EXEMPT (TODO
                                                      #295), in check_language_parity.py, are the
                                                      SEVENTH axis and the one BELOW the sixth:
                                                      PARAMETERS compares a constant's VALUE and
                                                      the parameter census asserts every constant
                                                      is named by a row, but both read
                                                      DECLARATIONS, so neither asks whether the
                                                      code that constant governs ever CONSULTS it.
                                                      A constant could be declared in all four
                                                      languages, agree in all four, be named by a
                                                      row, and be READ BY ONE -- the other three
                                                      carrying its value as a literal, every check
                                                      green.  Ten such cells across six rows when
                                                      #295 ran the census, and EVERY LANGUAGE was
                                                      an offender somewhere: rnl-eta in C, Go and
                                                      Java (the CBD samplers hardcode the eta=1
                                                      bit-pair extraction; only Python's
                                                      _rnl_cbd_poly takes eta and branches, and C's
                                                      RNL_ETA appeared nowhere outside its #define
                                                      but a benchmark printf), sdf-t / sdf-n-rows /
                                                      nl-v3-i-steps in Go (the ratios n/16,
                                                      seed.size/2, 5n/16 written out at the call
                                                      site), wots-log2w in C and Go (the literals 4
                                                      and 0xF, with the derivation in the COMMENT
                                                      beside the declaration instead of performed),
                                                      qcmdpc-w in C (vestigial everywhere; the
                                                      constant and its row are now deleted).  This
                                                      is the THIRD direction on the axis -- #278's
                                                      limit is declared-but-not-ENFORCED, #294's is
                                                      used-DIFFERENTLY, #295's is declared and not
                                                      used AT ALL.  TWO OF THE SIX ROWS CARRIED A
                                                      FALSE REASON, which is what no other check
                                                      could catch: qcmdpc-w's cited a 2*d call site
                                                      existing in no language, and
                                                      zkp-nl-prod-rounds' said Java "names it for
                                                      the CLI, which is its only caller" while the
                                                      CLI declared its own literal 219 twice.  A
                                                      curated reason about how a constant is USED
                                                      cannot be validated by a checker that only
                                                      reads declarations.  A DIAGNOSTIC USE DOES
                                                      NOT COUNT, and that rule is what keeps this
                                                      from being vacuous: SdfT was not
                                                      unreferenced, it appeared twice as banner
                                                      Printf arguments while Stern derived its own
                                                      error weight from the width -- strictly worse
                                                      than an unused constant, since the banner
                                                      would have printed a retuned SdfT while the
                                                      code kept using n/16.  A first pass without
                                                      the rule scored it as read.  CORPUS is the
                                                      shipped path only (suite, walkthrough, CLI,
                                                      codec): counting benchmarks would have scored
                                                      RNL_ETA live off a printf label, and getting
                                                      the corpus wrong in the LENIENT direction
                                                      makes the whole check pass vacuously.
                                                      PARAM_USE_EXEMPT is self-invalidating in both
                                                      directions and ships EMPTY -- all ten cells
                                                      were FIXED, so a future entry means a
                                                      declaration-only parameter was argued for,
                                                      not that the check was switched off.  KNOWN
                                                      LIMIT, found by #295's own negative control:
                                                      the census asks whether a constant is read
                                                      ANYWHERE in the shipped path, so it cannot
                                                      tell a live read from one in DEAD CODE --
                                                      reverting Go's call sites while leaving func
                                                      sternT in place kept SdfT "read" and the
                                                      check green.  Closing that needs a call
                                                      graph; what the census does close is the case
                                                      that occurred six times here, a constant no
                                                      code mentions at all or mentions only to
                                                      print
                                                      RANDOMNESS_CENSUS /
                                                      SAMPLER_REPLAY_PINNED (TODO #296),
                                                      in check_language_parity.py, are the
                                                      EIGHTH axis, and they are about the
                                                      code the other seven cannot reach.
                                                      Axes six and seven ask what a
                                                      constant's VALUE is and whether it is
                                                      READ -- both statements about code
                                                      that is the same on every run.  A
                                                      SAMPLER's output is not: it is fresh
                                                      per call, reaches no artifact, and so
                                                      no KAT pins it and NONE COULD.  #294
                                                      proved that the hard way and recorded
                                                      the only check available for the
                                                      class -- a FIXED-STREAM REPLAY, which
                                                      replaces the entropy source with
                                                      pinned bytes, makes a randomised
                                                      primitive deterministic, and then
                                                      holds the four consumption orders
                                                      against each other.  IT THEN THREW
                                                      THE HARNESS AWAY, and this file went
                                                      on asserting in the present tense
                                                      that the check existed; a grep for it
                                                      across every .sh, .py, .c and .go
                                                      returned THIS FILE ALONE.  That is
                                                      #287's withdrawn trust-model sentence
                                                      and #291's 22 discarded verdicts one
                                                      layer out.  KAT/sampler_replay.json
                                                      is the harness kept: 4 leaf
                                                      samplers, each with a fixed stream,
                                                      the value the SHIPPED sampler
                                                      produces, and -- where all four ports
                                                      read at the same granularity -- the
                                                      bytes consumed.  It needed NO new
                                                      test script and NO CI wiring, because
                                                      four ports against one pinned vector
                                                      is four ports against each other, and
                                                      every consumer already existed:
                                                      generate_kat.py --check (the
                                                      regenerate-and-diff IS Python's
                                                      replay), verify_kat_c via fmemopen,
                                                      verify_kat.go via a swapped
                                                      rand.Reader, KatVerify via a
                                                      SecureRandom subclass.  C and Java
                                                      needed no injection machinery at all
                                                      -- their samplers take the source as
                                                      a parameter -- and Go's package-
                                                      variable swap is the one fragile
                                                      hook, loud rather than silent if a
                                                      future Go bypasses it.  WHAT THE
                                                      CENSUS FOUND: three of the four
                                                      samplers disagreed across ports with
                                                      every implementation individually
                                                      CORRECT -- the weight-t error vector
                                                      had THREE schemes (C Fisher-Yates on
                                                      a 1-byte draw, Go Fisher-Yates over
                                                      crypto/rand.Int, Python/Java
                                                      rejection into a set on 4 bytes) and
                                                      the OPRF blinding scalar another
                                                      three.  No distribution was wrong; a
                                                      primitive with three consumption
                                                      orders simply cannot be pinned
                                                      against itself.  Both converge on
                                                      Python/Java's scheme, adopted
                                                      VERBATIM rather than a fifth correct
                                                      one invented (#294's precedent),
                                                      which also lifts C's uint8_t index
                                                      cap of n <= 256.  AND ONE REAL
                                                      DEFECT: C's oprf_blind rejected a
                                                      degenerate scalar with `continue`
                                                      inside a do/while, which jumps to the
                                                      CONDITION -- so a rejected draw
                                                      re-tested the previous iteration's
                                                      verdict, uninitialised on the first,
                                                      and had it compared equal to 1 the
                                                      function would have returned r = 1,
                                                      i.e. alpha = H(x) with the blinding
                                                      GONE.  Reachability against
                                                      /dev/urandom is 2^-255, so it is UB
                                                      and a logic error rather than a
                                                      practical vulnerability -- and that
                                                      is exactly why the sanitizers job
                                                      never saw it and a chosen stream
                                                      found it at once.  THE AXIS CAUGHT
                                                      ITS OWN BLIND SPOT on the way in: the
                                                      Java census regex matched a bare \w+
                                                      first argument to
                                                      new BigInteger(bits, rng), so
                                                      Oprf.blind and Oprf.keygen were not
                                                      censused AT ALL, and what noticed was
                                                      the rule that a pinned sampler must
                                                      appear among that language's
                                                      censused consumers.  The census is a
                                                      NAME SET, derived from source every
                                                      run and compared -- 25/25/28/31 in
                                                      C/Go/Python/Java -- so adding,
                                                      removing or renaming a randomness
                                                      consumer anywhere fails CI until
                                                      someone says whether a fixed stream
                                                      reaches it.  A set rather than a
                                                      reason per function is deliberate:
                                                      there are 109, and a hundred prose
                                                      reasons rot.  TWO LIMITS, recorded
                                                      rather than asserted away.
                                                      rnl_rand_poly pins OUTPUT but not
                                                      byte count -- it is block-buffered in
                                                      Go, Python and Java (#293) and
                                                      unbuffered in C, so the byte-to-draw
                                                      mapping is common and the total is
                                                      not; the generated header emits no
                                                      RPL_RAND_CONSUMED so the C consumer
                                                      cannot assert it by mistake.  And the
                                                      census is SYNTACTIC, so a sixth
                                                      spelling of "read the CSPRNG" would
                                                      go unseen; the guard is that an empty
                                                      per-language census is an error, not
                                                      a pass.  A branch a random stream
                                                      never enters is not covered either,
                                                      which is why the OPRF stream's first
                                                      draw is r = 1 EXACTLY and the
                                                      weight-t stream is the first label
                                                      whose draws collide twice -- without
                                                      those the repaired code and the
                                                      duplicate-skip path are unguarded,
                                                      and in the negative control they
                                                      were.  Pinning the remaining
                                                      consumers means replaying whole
                                                      operations rather than leaf samplers,
                                                      which TODO #297 did.
                                                      OPERATION_REPLAY_PINNED (TODO #297)
                                                      sits BESIDE the sampler table and is
                                                      checked by the same generalised code:
                                                      KAT/operation_replay.json pins 10
                                                      whole randomised OPERATIONS -- Stern-F
                                                      keygen and signing, Stern-F RING
                                                      signing, the ZKBoo prover, the
                                                      Ring-LWR Sigma signer, since
                                                      TODO #303 the HCRED-KKW prover, and
                                                      since TODO #307 the four #305 had
                                                      filed as OWED (QC-MDPC keygen and
                                                      encapsulation, the ZKB++ prover and
                                                      HCRED's sigma prover) -- each against a
                                                      fixed STATEMENT as well as a fixed
                                                      stream.  A cell may be ABSENT since
                                                      #307, and only one way: `param_entropy`
                                                      names the function and says that
                                                      language takes its entropy as a
                                                      PARAMETER there.  C's qcmdpc_keygen
                                                      takes a QcMdpcPrf *, so the seed is
                                                      drawn in the CLI, and naming the
                                                      function in the table would fail the
                                                      rule that a pinned cell must be a
                                                      CENSUSED consumer.  Cross-checked both
                                                      ways -- the function must EXIST and
                                                      must NOT be censused -- so C starting
                                                      to draw there fails, and the function
                                                      being renamed fails: PARAMETERS'
                                                      None-cell treatment one axis over.  That is the new part: a leaf
                                                      row is one call with scalar arguments,
                                                      while an operation is a function of its
                                                      key and message too, so every row states
                                                      its inputs in full rather than deriving
                                                      them from another row (a derived
                                                      statement makes one row's failure
                                                      cascade and hides which diverged).  It
                                                      needed no new script, no CI wiring and
                                                      no injection machinery -- every
                                                      operation already takes its entropy as a
                                                      parameter in C (FILE *) and Java
                                                      (SecureRandom), and the four consumers
                                                      #296 built follow the second vector as
                                                      they do the first.  The two tables are
                                                      SEPARATE on purpose: a consumer absent
                                                      from the sampler table may be covered by
                                                      an operation row that calls it, and one
                                                      absent from both is genuinely unpinned.
                                                      WHAT IT FOUND is not a consumption-order
                                                      divergence but an ANONYMITY BREAK.
                                                      hpks_stern_ring_sign simulates the
                                                      non-signer members; for a simulated
                                                      member's b = 0 round the dummy
                                                      commitment c0 was hash(ZERO, ZERO) in C
                                                      and Go -- one fixed constant -- while
                                                      the real signer's c0 uses a freshly
                                                      drawn pi_seed and never takes it.  At
                                                      the default rounds = 32 every
                                                      non-signer shows the constant with
                                                      probability 1 - (2/3)^32 and the signer
                                                      never does, so the signer is the member
                                                      with none of them, read off the public
                                                      signature.  Measured, k=4: the signer
                                                      scored 0 where the other three scored
                                                      9, 13 and 9.  It survived because the
                                                      signature VERIFIES -- c0 is unchecked
                                                      for b = 0 by construction -- so every
                                                      round-trip, 4x4 interop matrix and
                                                      tamper test passed it, and no KAT could
                                                      pin a ring signature that is randomised
                                                      per call.  Python and Java always drew a
                                                      dummy; their form is adopted verbatim.
                                                      UNDERNEATH IT, the per-round challenge
                                                      trit had THREE schemes while it was
                                                      written INLINE in all four: a byte with
                                                      255 rejected (C, Python), a whole n-bit
                                                      draw reduced modulo 3 (Go, biased 2^-32
                                                      and 32 bytes per trit), and
                                                      Random.nextInt(3) (Java).  It is now one
                                                      NAMED sampler in each port with a
                                                      PRIMITIVES entry, because a sampler
                                                      written inline in four places is one the
                                                      manifest cannot see -- and C's 8-try
                                                      bound and its fail-open (i ^ r) fallback
                                                      on a short /dev/urandom read went with
                                                      the extraction.  KNOWN LIMIT: the
                                                      rnl_sigma_sign row is pinned on the
                                                      SINGLE-ATTEMPT path, which is the
                                                      MINORITY path -- the operation retries
                                                      and accepts about one attempt in three
                                                      or four, and at an attempt boundary the
                                                      buffered ports (#293) discard a block
                                                      tail that unbuffered C goes on to use,
                                                      so the byte-to-draw mapping is common
                                                      only until the first retry.  The row's
                                                      stream is chosen to accept first time,
                                                      is exactly one block long so a retry
                                                      exhausts it rather than passing quietly,
                                                      and the generator asserts it.  What the
                                                      cross-port design CANNOT do is see a
                                                      property all four ports get wrong: the
                                                      constant was found by reading four
                                                      implementations side by side, and had
                                                      all four hashed zeros the vector would
                                                      have pinned the agreed constant forever.
                                                      That class -- no test anywhere asserts a
                                                      HIDING property, only completeness and
                                                      soundness -- is TODO #298.
                                                      REPLAY_COVERAGE (TODO #305) is the
                                                      THIRD part of this axis and asks what
                                                      the other two never did: how much of
                                                      the census the pinning actually
                                                      REACHES.  10 consumers per language
                                                      were named by a pinned row and
                                                      15/15/18/21 were not, so "someone
                                                      looked" was decaying into "someone
                                                      looked once" -- #296's own diagnosis
                                                      of #294, one turn later.  Every
                                                      censused consumer is now pinned or
                                                      carries a row, self-invalidating in
                                                      both directions, and a row's cell
                                                      naming a function that is ALREADY
                                                      pinned fails too, so pinning something
                                                      forces its row out.  THREE statuses,
                                                      and the third is the point:
                                                      `transitive` (covered by a pinned
                                                      operation that calls it), `unpinned`
                                                      (a fixed stream would prove nothing
                                                      new) and `owed` (pinning applies and
                                                      is not done, so it needs an ITEM
                                                      NUMBER as well as a reason).  `owed`
                                                      exists because a prose reason is
                                                      exactly where work gets parked, which
                                                      is #295's false-reason finding pointed
                                                      at a table rather than at a constant;
                                                      the count is printed and is a check-E
                                                      row.  The `transitive` half is DERIVED,
                                                      not curated -- the checker walks a
                                                      per-language CALL GRAPH from the pinned
                                                      operation and fails a claim no call
                                                      path supports -- which also touches
                                                      #295's "closing that needs a call
                                                      graph" from the other side without
                                                      closing it, since reachability is not
                                                      liveness.  Building it found Java
                                                      OVERLOADS breaking a name-keyed body
                                                      map (SternRing.sign has two, and the
                                                      three-line one calls nothing), and it
                                                      found C's rnl_cbd_poly: a second copy
                                                      of the CBD sampler, specialised to
                                                      RNL_N, with its own fread, called by
                                                      NOTHING -- and not inert, because the
                                                      rnl-cbd-poly manifest row anchored C's
                                                      cell on the dead one while the protocol
                                                      ran the live rnl_cbd_poly_dim.  Deleted
                                                      in v8.0.6.  What it did NOT fold in is
                                                      filed: the census corpus is the SUITE
                                                      ALONE while #295's is suite + CLI, so
                                                      52 raw-entropy call sites in the four
                                                      CLIs are uncensused and one of them is
                                                      Python's classical Schnorr NONCE (TODO
                                                      #306), and the four owed pins are TODO
                                                      #307 -- which closed them in v8.2.0,
                                                      so this table reports 0 OWED and the
                                                      four rows were DELETED rather than
                                                      retitled, the pinning forcing the
                                                      deletion
                                                      CLI_CORPUS /
                                                      RANDOMNESS_CLI_CENSUS /
                                                      CLI_DRAW_COVERAGE (TODO #306) are
                                                      the FOURTH part of this axis and
                                                      the one that is not about the
                                                      census at all -- it is about which
                                                      code the census READS.
                                                      PARAM_USE_CORPUS forty lines up in
                                                      the same file reads suite +
                                                      walkthrough + CLI + codec and says
                                                      why; the randomness axis read the
                                                      SUITE ALONE, with no sentence
                                                      anywhere about the difference, and
                                                      that was never a considered scope.
                                                      56 raw-entropy sites sit in the
                                                      four CLIs (c 17, go 14, python 14,
                                                      java 11), every one now claimed by
                                                      one of 16 named draw ROLES -- 59
                                                      sites and 17 roles until TODO #308
                                                      moved the Schnorr nonce into the
                                                      suite and the `schnorr_nonce` row
                                                      was DELETED, which is the site-count
                                                      check doing what it was built for.  A
                                                      role, not a function: one command
                                                      holds six draws and one role spans
                                                      two functions (Java splits the kex
                                                      responder by algorithm), so a cell
                                                      is (function, SITE COUNT) and the
                                                      counts must SUM to what the source
                                                      holds -- a name set alone would let
                                                      a seventh draw be added to
                                                      cmd_genpkey in silence, which is
                                                      how 52 sites accumulated on the far
                                                      side of an unstated boundary.
                                                      THREE STATUSES: `suite` (some port
                                                      draws this role inside a censused
                                                      suite consumer instead, and `via`
                                                      names the REPLAY_COVERAGE row, so
                                                      the row records WHICH ports inline
                                                      the draw and which delegate),
                                                      `cli_only` (no port draws it in a
                                                      suite, so no pin could ever reach
                                                      it) and `owed`.  `via` is required
                                                      by `suite`, FORBIDDEN to `cli_only`
                                                      -- a delegation contradicts that
                                                      status -- and allowed to `owed`,
                                                      because schnorr_nonce is owed in
                                                      three ports and delegated in the
                                                      fourth.  WIDENING THE CORPUS FOUND
                                                      THE PATTERNS WRONG, which is why
                                                      the filed figure was 52:
                                                      secrets.token_bytes imported as
                                                      `_sec` inside its own branch (a
                                                      sixth spelling; in the suite it
                                                      sits in `main`, which draws by
                                                      other means, so the census was
                                                      right there BY LUCK), and
                                                      new BigInteger(Herradura.N, RNG) --
                                                      not a new spelling but the SAME one
                                                      in a different CASE, since every
                                                      suite port names the parameter
                                                      `rng` and the CLI holds a static
                                                      field `RNG`, which hid two Java CLI
                                                      functions including the
                                                      threshold-nonce commit.  Adding
                                                      both moves NO suite name, and that
                                                      non-move is what turns "the suite
                                                      census was right" from a claim into
                                                      a check.  AND THE FINDING UNDER THE
                                                      HEADLINE: C's herradura.h exported
                                                      hpks_sign, it drew its own nonce,
                                                      KAT/classical_quartet.json pinned
                                                      it, and herradura_cli.c DID NOT
                                                      CALL IT -- cmd_sign transcribed the
                                                      whole Schnorr signer inline and the
                                                      suite copy was reached only by
                                                      docs/examples and the FFI shim.  Go
                                                      and Python never had the operation.
                                                      So three of four CLIs signed with
                                                      an unpinned transcription and Java
                                                      was the one that called the suite:
                                                      the pinned function and the shipped
                                                      path were different code in the
                                                      port that had both, #295's
                                                      dead-code limit aimed at a sampler.
                                                      TODO #308 (v8.1.0) closed it by
                                                      moving the code -- the three CLIs
                                                      now call what they copied, the NL
                                                      half moved with the classical one
                                                      because they shared ONE draw, and
                                                      the schnorr_nonce role was DELETED
                                                      rather than retitled.  KNOWN LIMIT, stated
                                                      before the table rather than after
                                                      it: no CLI takes an entropy source
                                                      as a parameter in any language, so
                                                      a fixed-stream replay does NOT
                                                      reach this layer without a new
                                                      shipped surface (TODO #309, which
                                                      owes the hazard argument before the
                                                      seam), and what was missing was
                                                      never the replay -- it was knowing
                                                      which draws exist, in which ports,
                                                      and what compares them
SPEC.md                                              — human-readable prose companion to
                                                      spec/herradura-protocol-spec.json
SECURITY.md                                          — security policy: protocol maturity levels,
                                                      vulnerability reporting process
Dockerfile / docker-entrypoint.sh                    — quickstart image building/smoke-testing the
                                                      C/Go/Python/ARM/i386 targets (TODO #139); see
                                                      Build Commands
pyproject.toml                                       — packaging metadata for the Python CLI/suite
                                                      (setuptools build backend, no runtime deps)
bindings/ffi/                                        — opt-in ctypes/cgo FFI bindings around
                                                      herradura.h's classical v1.4.0 quartet, for
                                                      performance-sensitive Python/Go callers
bindings/java/                                       — complete pure-Java port of the whole suite
                                                      (TODO #196-#203, closed), incl. a
                                                      herradurakex.HerraduraCli mirroring the
                                                      Python CLI's subcommands and --algo values —
                                                      all 29 tags since TODO #261 (v6.0.0) ported
                                                      the last five: hpks-zkp-nl, nl-zkboo,
                                                      nl-zkbpp, rnl-sigma and hybrid-rnl-stern.
                                                      spec/'s cli_support column is derived from
                                                      this CLI's dispatch source as it is for the
                                                      other three, so a regression shows up as an
                                                      empty cell rather than as silence;
                                                      cross-checked against KAT/.  hpks-wots /
                                                      hpks-xmss keep one-time-use/leaf-index state
                                                      in a <keyfile>.idx sidecar, as Python does.
                                                      HSKE-NL-AEAD (`enc --aead`) landed in TODO #273:
                                                      the port had no AEAD primitive at all, so it was
                                                      the last Java capability gap that was not merely
                                                      argument-parser wiring.  CliTest/test_aead.sh is
                                                      now a 4x4 matrix rather than 9-way
herradura/                                            — root-level Go package (herradura.go, codec.go)
                                                      used by the FFI Go binding and its fuzz tests
benchmarks/                                          — recorded benchmark output/history;
                                                      v3_round_cost.c measures the NL-FSCX v2
                                                      vs v3 per-round cost in one shared 4x64
                                                      limb representation, so only chi is
                                                      timed (TODO #255): 2.12-2.17x per round,
                                                      ~1.77x per block at v3's 160 rounds vs
                                                      v2's 192.  Its fast chi is validated
                                                      bit-exactly against a per-row reference
                                                      before timing.  That projection does
                                                      NOT hold for the shipped C path:
                                                      v3_consumer_cost.c links herradura.h
                                                      itself and measures 1.16x per round —
                                                      the byte-per-limb BitArray makes the v2
                                                      round expensive enough that chi is a
                                                      smaller relative addition — so
                                                      hske-nla3 / fpe --v3 / twk --v3 come
                                                      out at ~0.97x, hske-duplex3 at ~1.45x
                                                      (80 sponge rounds vs 64) and hpke-nl3
                                                      at ~2.92x (160 vs hpke-nl's deployed
                                                      I_VALUE=64).  Both figures are right;
                                                      the packed one is what an optimised
                                                      port would see;
                                                      rnl_ring_cost.py measures the HKEX-RNL
                                                      ring-cost curve (n=32..1024) and audits
                                                      what the `-t` cap actually caps (TODO #225);
                                                      rnl_deployed_ring_cost.{c,go,py} is the
                                                      DEPLOYED ring in the three languages that
                                                      ship it (TODO #292).  READ THIS FIRST if
                                                      you quote an HKEX-RNL cost figure:
                                                      benchmark [40]'s four rows are n=32..256,
                                                      i.e. the ring TODO #223 RETIRED, because
                                                      both harnesses transcribe the primitives
                                                      and use ONE variable for the ring
                                                      dimension and the key width, so they
                                                      raise above 256 (#225) -- until #292 the
                                                      only published figure for the protocol
                                                      this suite recommends was an interpreted-
                                                      Python one.  Full handshake at n=1024:
                                                      C 0.505 ms, Go 1.088 ms, Python 39.36 ms
                                                      (pure-Python NTT; the .py prints which
                                                      path is live, and a Python RNL figure
                                                      without that label is not a figure).
                                                      Three things worth knowing.  (1) The C
                                                      handshake is FOUR NTTs and ~7 us of
                                                      everything else, so cost work there is
                                                      NTT work and nothing else.  (2) Scaling
                                                      is 4.6x for 4x the dimension against
                                                      [40]'s n=256 row, so #223 bought
                                                      ~32 -> ~206 Core-SVP bits for 4.6x the
                                                      time -- and HKEX-RNL is 32x FASTER than
                                                      [34]'s HKEX-GF handshake, so no cost
                                                      argument favours the classical quartet.
                                                      (3) The three languages DISAGREED about
                                                      where the time goes, which is why there
                                                      are three files and is what the table
                                                      found: in Go the m_blind derivation was
                                                      40% of a handshake and 21x C's, a CSPRNG
                                                      read pattern fixed in TODO #293
                                                      (v7.0.11), which buffered Go, Python and
                                                      Java -- C had always amortised through a
                                                      buffered FILE *, so it is UNCHANGED and
                                                      is the control proving the host did not
                                                      move between the two releases.  Go's
                                                      m_blind is now 0.048 ms, 4.4% of a
                                                      handshake, and Go is 2.15x C rather than
                                                      3.0x.  #293 also corrected two of #292's
                                                      own numbers: the 50x was reads with no
                                                      sampler around them (the shipped fix is
                                                      19.9x), and Java escapes by NativePRNG
                                                      buffering /dev/urandom, not by being a
                                                      userspace DRBG.  They GATE on a
                                                      both-sides-agree control but are NOT in
                                                      run_findings_gates.py's set (it scans
                                                      SecurityProofsCode/ only) -- host-specific
                                                      cost figures do not belong in CI;
                                                      compare_*.py drivers, incl.
                                                      compare_fscx_revolve_closed_form.py
                                                      (TODO #213, C/Go/Python)
Fuzz/                                                — fuzzing harnesses (see TODO #130)
```

## Changelog, README, and TODO Policy

All notable changes are documented in `CHANGELOG.md` only.  Do **not** add version notes, release blurbs, or change summaries to `README.md`.  The README describes the current state of the project; the CHANGELOG tracks its history.  When a feature or fix is completed, add a new versioned entry to `CHANGELOG.md` and update the version number in the `README.md` title line — nothing else.

Work items are tracked as numbered entries (#1–#N) with a `Status:` line, split across two files (TODO #154): **`TODO.md`** holds only currently-`OPEN` entries; **`TODO_DONE.md`** archives everything else (`DONE`/`DEPRECATED`/`ACKNOWLEDGED`), in original numeric/chronological order. Numbering is global and never reused across the two files — an item keeps its `#N` forever, whichever file it currently lives in. When completing a TODO, update its `Status:` line to `**DONE vX.Y.Z**` with the release version, move the whole entry from `TODO.md` to the end of `TODO_DONE.md`, then add the corresponding `CHANGELOG.md` entry. Version numbers follow `MAJOR.MINOR.PATCH`; each TODO completion is typically one PATCH bump. When creating a new item, add it to `TODO.md` with `Status: **OPEN**`.

**MINOR vs. PATCH (post-2.0.0):** bump MINOR, not PATCH, for a TODO that adds a new
protocol, CLI subcommand, or public API surface without breaking any existing one (e.g.
a new `--algo` variant, a new language-target port of an existing protocol). Bump PATCH
for everything else — bug fixes, documentation, internal refactors, parameter tuning,
new tests. This mirrors ordinary semver practice; `TODO_DONE.md`'s pre-2.0.0 history
used PATCH almost everywhere (matching this project's fast, incremental TODO cadence)
and that history is not being renumbered retroactively.

**MAJOR (post-2.0.0):** reserved for changes that break the stable CLI/PEM/wire-format
surface 2.0.0 establishes — a PEM boundary label change, a CLI flag rename or removal,
a change to what an existing `--algo` value produces or accepts, or any change that
makes an existing key/ciphertext/signature file unreadable by a newer build. Any TODO
that would require one of these must call it out explicitly in its own text (not just
in the `Status:` line) and get a `MIGRATING.md` entry alongside the version bump —
follow the format already used there. Internal changes with no effect on stored
artifacts or the CLI surface (e.g. an internal hash construction upgrade that also
changes wire format, like the HFSCX-256-DM and Stern H-matrix changes predating 2.0.0)
are wire-format breaking but not necessarily MAJOR-worthy on their own; use judgment
and err toward documenting in `MIGRATING.md` regardless of which version-component
changes.

The `Status:` line format for `TODO.md` / `TODO_DONE.md` sections, and the list of
grandfathered pre-#154 entries, live in the `todo-status` skill
(`.claude/skills/todo-status/SKILL.md`) — load it when opening or closing a TODO.

## Third-party dependencies

The shipped primitives and CLIs have **none**, in any language, and that is a property
worth preserving — `./build_c.sh`, `./build_go.sh` and every `HerraduraCli/` entry point
run against a bare toolchain.  Four optional packages exist, all analysis- or
tooling-only.  Most consumers degrade to a printed NOTE rather than failing; `z3-solver`
is the documented exception, for the reason in its row (TODO #290).

| package | used by | absent ⇒ | install |
|---|---|---|---|
| `jsonschema` | `spec/generate_spec.py` schema validation | NOTE, but CI passes `--require-schema` so a skipped validation cannot pass | `pip install jsonschema` |
| `z3-solver` | `SecurityProofsCode/nl_fscx_exact_trail_search.py` (TODO #214), `fscx_periodicity_z3.py`, `hpks_schnorr_z3.py` | **the gate FAILS** — those last two are z3 from top to bottom, so there is no section left to skip and a printed NOTE plus exit 0 would report a finding as reproducing that was never checked.  All three print the install line and exit non-zero; CI's `analysis-findings` job installs the package for exactly this reason (TODO #290) | `pip install z3-solver` |
| `pulp` (CBC) | `SecurityProofsCode/nl_fscx_v2_bounds.py` §(d) MILP bounds (TODO #247) | section skipped | `sudo apt-get install -y python3-pulp`, or a venv: `python3 -m venv ~/.venvs/herradura-milp && ~/.venvs/herradura-milp/bin/pip install pulp` |
| `highspy` | the same §(d) model under a stronger backend (TODO #252 §11.35.6) | CBC is used instead, and reaches one round fewer | `~/.venvs/herradura-milp/bin/pip install highspy` (PuLP finds it as the `HiGHS` solver) |

Never add one to a shipped primitive.  If an analysis script needs a solver, it imports it
inside a `try`/`except ImportError` and prints what to install — and then decides its exit
status by what is left: non-zero if the solver WAS the gate, zero with a NOTE if the gate
survives without it.

## Build Commands

Use the build scripts when building everything; they apply the correct flags, output names, and dependency checks.

```bash
./build_c.sh          # compiles suite, tests, and HerraduraCli/herradura_cli
./build_go.sh         # compiles suite, tests, and HerraduraCli/herradura_cli_go
./build_arm.sh        # ARM Thumb-2 suite + tests (requires arm-linux-gnueabi-gcc)
./build_asm_i386.sh   # NASM i386 suite + tests (auto-detects elf_i386-capable linker)
./build_arduino.sh    # Arduino/AVR suite + tests; run_arduino.sh runs them under simulation
./build_c_sanitize.sh # C suite/tests/CLI under ASan+UBSan (requires clang); see Testing
```

### Docker

`docker build -t herradurakex .` builds a quickstart image (TODO #139) covering the
C/Go/Python/ARM Thumb-2/NASM i386 targets (Arduino is excluded — needs `arduino-cli`
and a board target). `docker-entrypoint.sh` builds every host-portable target and runs
a smoke test (the C/Go/Python security test suites plus a CLI interop test) on
container start.

### C

Use `build_c.sh`. Manual equivalent: `gcc -O2 -o <output> <source.c>` per target (suite, tests, CLI).

> **Build collision hazard:** `go build file.go` (without `-o`) names its output
> after the source filename stem — identical to the old unsuffixed C binary path.
> The `_c` suffix makes all six target binaries distinct: `_c`, `_go`, `_arm`,
> `_i386`, `_avr.elf`. Always use `build_go.sh` or pass `-o name_go` explicitly
> when invoking `go build` directly. Never run bare `go build file.go`.

### Go and Python

Use `build_go.sh`.  The Python targets need no build step, and neither language
target has external dependencies.  Never run bare `go build file.go` — see the
build-collision hazard above.

### Assembly

Use `build_arm.sh` / `build_asm_i386.sh`. To run: `qemu-arm -L /usr/arm-linux-gnueabi "./Herradura cryptographic suite_arm"` or `qemu-i386 "./Herradura cryptographic suite_i386"`.

> **i386 linker portability:** `x86_64-linux-gnu-ld -m elf_i386` fails on ARM64 hosts
> (e.g. Raspberry Pi 5 / Ubuntu) with "unrecognized emulation mode: elf_i386" because the
> native `ld` (aarch64) has no i386 emulation.  `build_asm_i386.sh` auto-detects the first
> available linker with `elf_i386` support.  If none is found, install one:
> - `sudo apt-get install -y binutils-x86-64-linux-gnu`  (provides `x86_64-linux-gnu-ld`)
> - `sudo apt-get install -y binutils-i686-linux-gnu`    (provides `i686-linux-gnu-ld`)

## Testing

No unit-test framework in the traditional sense — tests are pass/fail assertions printed
to the console by the suite/CLI binaries themselves.

**A failing test now fails the build (TODO #233).** Until v3.0.8 the C/Go/Python harnesses
printed `[PASS]`/`[FAIL]` and exited 0 regardless, so `native-c`, `native-go` and
`native-python` went green whenever a security test failed. Each harness now aggregates
the `[FAIL]` markers passing through its own output — `#define printf hprintf` in C, a
module-level `print` shadow in Python, an `os.Stdout` scanning pipe in Go — and exits
non-zero, closing with `*** OK: no check reported [FAIL] ***` or
`*** FAILED: n check(s) reported [FAIL] ***` plus the offending lines. There is no
allow-list: no test is expected to fail. If you add a test, you do not need to register it
anywhere — the wrapper sees any line carrying `[FAIL]`, which is exactly why it was built
that way.

**The ARM, NASM i386 and Arduino harnesses are gated too (TODO #234)**, at their own
output layers and for the same reason. ARM routes every `bl printf` through `bl hprintf`
(a `strstr` on the format string, then a tail call to the real `printf`); NASM i386 scans
inside `print_str`, the single `write`-syscall path; Arduino routes all 18 verdicts
through one `verdict(bool)` helper — output scanning cannot work there, because the marker
is split across two `Serial` calls (`"  ["` then `"FAIL]"`) and the literal `[FAIL]` never
appears in a single write. `build_arm.sh` and `build_asm_i386.sh` **fail the build** on a
call site that bypasses the wrapper without a `GATE-EXEMPT` marker, so use `bl hprintf` /
`call print_str` in new assembly.

The AVR target cannot return an exit status at all — the firmware loops forever, so
simavr runs under `timeout` and the status is discarded. Its verdict travels over the UART
instead, and `run_arduino.sh` fails on a `*** FAILED:` line **and on the OK line never
arriving**; a hang, a reset, or a `TIMEOUT` shorter than one pass (2-4 s; the default is
90) is a failure, not a pass.

One hazard to know before adding an assembly test: those harnesses assert *correctness*
only, never *soundness*, and their Stern-F runs at `rounds=4`. A rejection test written
there would carry a `(2/3)^4` = 19.75% soundness error per trial — five times worse than
the `rounds=8` that made C's [45] fail 38.5% of runs. Give it its own round count.

Three tests had to be fixed before the gate could be enabled, all the same class — a
probabilistic property asserted as a deterministic one. If you write a test whose subject
has a soundness error, a birthday bound, or a sample-size-dependent statistic, make the
threshold follow it: [4] now scales its tolerance as `6 × 50/sqrt(N)`, [18] distinguishes
an ambiguous syndrome from a decoder failure (the n=32/t=2 code is not uniquely decodable
— 43% of keys admit a weight-2 collision), and [45] runs its Stern-F sub-check at
`rounds=32` so `(2/3)^rounds` is negligible. TODO #234 found the same class pointing the
other way in the Arduino harness: [7] passed at 80% agreement and never asserted the
`ok_sk` statistic it printed, so it now requires `ok_raw == trials && ok_sk == trials` —
1,000,000 measured trials of that n=32 Ring-LWR construction produced no disagreement at
all (DFR ≤ 3e-6 at 95%), so the slack was masking a silent check, not absorbing noise.

`.github/workflows/ci.yml` runs twelve
jobs on every push/PR, eleven of them required/blocking (the twelfth,
`analysis-findings`, is on probation — see below): `native-c`, `native-go`, `native-python`
(one job per language — build/no-build + suite tests + that language's own `CliTest/*.sh`
scripts, split from a single combined `native` job in TODO #205), `native-interop`
(the `CliTest/*.sh` scripts that exercise two or more CLIs at once — builds both C and Go —
plus a coverage-guard step that fails if any non-Java, non-cross-lang-matrix `CliTest/*.sh`
script isn't claimed by exactly one of these four `native-*` jobs, and a DFR-guard step that
fails if a script which decapsulates `hpke-stern-kem` doesn't source `CliTest/lib_dfr.sh`,
TODO #221), `native-java` (builds/
runs the `bindings/java/` port, its `Demo.java` suite walkthrough — gated on the same
`[FAIL]`-marker convention as C/Go/Python's demo binaries, TODO #258/#259/#260 — and all
`CliTest/test_java_*.sh` scripts — Java-vs-Python interop and KAT cross-checks
per-protocol-family, TODO #206), `cross-lang-compat` (builds
all four CLIs and runs two 4-way scripts: `CliTest/test_cross_lang_matrix.sh`, a genuine
C/Go/Python/Java compatibility matrix across the classical quartet, the NL/PQC quartet,
the Stern family, HCRED, OPRF, and aPAKE, proving every pair of languages interoperates
directly rather than only each against Python (TODO #207); and
`CliTest/test_malformed_pem_matrix.sh`, the same four CLIs against deliberately malformed
PEMs, because the bounds on the fields that size an allocation are a wire contract — an
artifact one CLI refuses must not be one another accepts (TODO #240). Both run after the
four `native-*` jobs),
`arm-i386` (ARM Thumb-2/NASM i386 under qemu), `katex` (math-rendering validation, TODO
#179, plus the part-index consistency check of TODO #231), `arduino` (Arduino/AVR under
simavr — ran `continue-on-error: true` until TODO #185
promoted it after confirming 100% pass history since its one known failure mode, an SRAM
overflow, was fixed in TODO #155), `fuzz-smoke` (30s/target libFuzzer/go-fuzz/Hypothesis/
CLI-argv run, TODO #187), `sanitizers` (C suite/tests/CLI under ASan+UBSan plus a
bounded valgrind memcheck pass, TODO #188), and `analysis-findings` (TODO #289 — every
findings-gating `SecurityProofsCode/` script, via `run_findings_gates.py`; `continue-on-
error: true` for now, on the `arduino` job's TODO #185 route). Locally, run the same
scripts by hand as described below.

**The findings gates, and why they are a job rather than a step (TODO #289).** 76
findings-gating scripts in `SecurityProofsCode/` close with "exits non-zero if a finding
stops reproducing" — a count read from the runner rather than by hand, and checked by
`check_docs_consistency.py`'s check E. TODO #285 found that NO job collected that status, and the three items
after it each added ONE script to a step in `native-python` and excluded the rest on
runtime grounds — **twice leaving a script that was already failing inside the excluded
set** (#286 found `qcmdpc_parameter_selection.py` broken three ways, #288 found
`qcmdpc_bgf_variants.py` broken six). Every exclusion was individually defensible; the
pattern was not. `SecurityProofsCode/run_findings_gates.py` is the replacement and its
one structural idea is that **the set is DISCOVERED, not enumerated** — a script whose
exit status is its own verdict is run, with nothing to add anywhere, because a list is
exactly what makes "nobody got round to it" look identical to "it passes". Three things
to know before touching it. (1) Excluding a script needs a reason in `EXCLUDED`, which
is self-invalidating like every other curated table here: an entry naming a file that is
absent, or that is no longer gating, FAILS. (2) Discovery reads the exit CALL, so a
fourth exit shape would be silently skipped — the same blind spot #288 found in check
B″ — and the guard against it is that a script ADVERTISING a findings gate in its own
header and not discovered is an error, checked in both negative controls. (3) Failures
do not stop the run: #286 hit three and #288 six, so a `set -e` loop reporting the first
and hiding the rest is not hypothetical. The two QC-MDPC scripts stay in `native-python`
as well, deliberately, because that job is required and this one is not yet.

**And which scripts GATE, which is the prior question (TODO #291).** #289 and #290 both
answer "which of the gating scripts run"; nothing asked how many scripts gate at all.
The answer was **35 of 81**: 46 produced output no exit status carried, 33 of them cited
by `SecurityProofs-*.md` or `CLAUDE.md` as backing a claim, and **22 computed a PASS/FAIL
verdict and discarded it** — TODO #233's defect class one layer out, in the layer that
backs the security documents rather than the one that tests the code. It is now **76
gating and 7 declared non-gating**, and every `SecurityProofsCode/*.py` is one or the
other: the runner FAILS on a script that is neither, which is the part that does not
decay, since adding an analysis script now forces the question. Four things worth knowing.
(1) `NON_GATING` is self-invalidating in both directions like `EXCLUDED` — an entry naming
an absent file fails, and so does one naming a script that has since become a gate. (2)
"It is only a demo" is not a reason: `hpks_threshold_demo.py`, `oprf_demo.py`,
`vdf_demo.py` and `hkex_pake_demo.py` all assert something falsifiable and all gate. The
seven that do not are five `hkex_cfscx_*.py` design-space surveys of rejected
constructions, `nl_fscx_v2_orbit.py` (a sampled distribution, where a gate would mean
inventing a threshold), and `stern_ct_demo.py`, whose verdict is that a timing leak is
STILL THERE — a gate would fail if anyone fixed it. (3) The conversion turned up a
FOURTH exit shape and a THIRD `--quick` spelling, both the blind spot the runner already
documents: five scripts name their entry point `run()` rather than `main()` and read as
non-gating, and two declare `--fast` through `sys.argv` rather than argparse — one of
them (`stern_f_multiround_fs.py`) already a gate, so it had been running at full sample
size since #289. (4) A section that did not run must not be scored: `--full`-only and
`--skip2/--skip3` sections return "no finding", never a passing one, or a skipped section
becomes a vacuous pass — the inverse of what TODO #234 found in the Arduino harness.

**And whether a red run means anything, which is the question under all of that (TODO
#299).** A gate that fails at random trains everyone to re-run it, and re-running is also
the response to a real failure — so one flaky gate degrades the whole job. #299 found
both shapes on one PR. `hfscx_256_analysis.py` §3 gated on `chi2 < 293.2`, the p = 0.05
critical value, against a FRESH `os.urandom` sample every run: a correct hash fails that
one run in twenty by construction, and the measured null (median 251.1, 2/40 over the
threshold across 40 local samples) is the nominal rate exactly. It is now a REPLICATION —
an exceedance is confirmed against a second independent sample at the 0.001 level — so
the false-failure rate is 5e-5 and power is untouched, since a hash biased enough to
matter puts chi2 in the thousands over 160,000 byte samples, not at 300. That is
`CLAUDE.md`'s own Testing class (a probabilistic property asserted as a deterministic
one, the thing TODO #233 fixed in three tests) surfacing in the ANALYSIS layer, where
nobody had looked because until #289 and #291 nothing collected these exit statuses at
all. The other shape is the opposite and is not a flake: `stern_ring_challenge_bias.py`
§4 is a SOURCE check on a shipped fix, anchored on a literal spelling, and TODO #297
moved that spelling when it extracted the challenge trit into a named sampler in all four
ports. The fix was still there; the gate was RIGHT to fire, because the sentence it
defended had become unverifiable. Re-anchor a source check on the named helper, scope it
to that helper's body (every one of these files carries an unrelated 255), and know its
inherent limit — it reads syntax, so it cannot see whether the helper is still CALLED,
which is #295's dead-code limit one axis over and is covered here only by
`KAT/operation_replay.json`'s ring row. The census of which other gates compare a fresh
sample to a fixed threshold is TODO #300, still OPEN.

**And what a test asserts, which is prior to whether it runs (TODO #298).** #289,
#290, #291 and #299 all answer questions about the gating MACHINERY. #298 asked what the
gates and the numbered tests actually SAY, and the answer for the whole zero-knowledge
family was: completeness (an honest transcript verifies) or soundness-by-tamper (a poked
one does not), and nothing else. Neither can see a HIDING failure, so a ring signature
with zero anonymity passed every round-trip, every 4x4 interop matrix and every KAT by
construction -- which is how #297's constant dummy shipped. Writing the first hiding
assertion found a second anonymity break **in all four ports at once** (the b = 0 and
b = 2 simulated responses were uniform where a real signer's have weight ~2t, so ONE
b = 0 round named the signer) and, underneath it, that **nothing bound the witness
weight**: HPKS-Stern-F was universally forgeable from the public key by Gaussian
elimination. Three things to carry forward. (1) A cross-port check cannot see a property
all four ports get wrong -- that is the standing blind spot of #277, #294, #296 and #297,
and the only exit from it is an assertion about ONE implementation. (2) A hiding test
needs a negative control that FIRES, checked in `stern_f_weight_binding.py` §3, or it is
#234's vacuous pass. (3) Where the property can be made an invariant the VERIFIER
enforces, prefer that and then do NOT also assert it in a test: #298's anonymity half is
now self-enforcing (`wt(respA ^ respB) = t` is checked on every b = 0 round of every
member), so a simulator regression fails the existing round-trip tests, and a case
asserting it would pass vacuously. The remaining hiding assertion -- a revealed view
carries no more than the protocol allows -- is TODO #301, still OPEN.

**And how often a green run is green by luck, which is what makes the rest of it
worth anything (TODO #300).** #299 fixed one gate that failed one CI run in twenty and
filed the obvious next question: how many of the others decide a verdict the same way?
The census is in `run_findings_gates.py`'s `SAMPLED_GATES`, beside `EXCLUDED` and
`NON_GATING` and self-invalidating like both. **29 of the 76** decide a verdict from a
fresh random sample; the rest draw only from a literal seed or draw nothing at all, so
they reproduce run to run and cannot flake. Four things worth knowing. (1) SAMPLING IS NOT THE
DEFECT -- deciding on a fresh sample against a FIXED threshold is.
`stern_ring_challenge_bias.py` draws from `os.urandom` and gates on
`counts == [86, 85, 85]`, which is arithmetic; `nl_fscx_sparse_circuit.py` samples 300
differences per order and gates on an EXHAUSTIVE degree computation, having had its
sampled row left ungated by #291 for this exact reason. Both are `exact`. (2) The budget
is a JOB-level number, not a per-gate one. A per-gate bound is a constant somebody picks,
and the first draft of this check picked 1e-6 and then flagged three gates at 1.2e-6 --
one run in 860 000, a defect only against an arbitrary line. What #289's premise rests on
is the rate of the whole job: **6.4e-5 per run** (5.4e-5 until TODO #304 derived the
three `follows` rates that had been missing from the sum), dominated by #299's own
replicated chi-square at 5e-5 and #302's seed-budget gate at 1e-5, with everything else
together at about 4e-6. (3) Every
entry carries a derived RATE or a stated ARGUMENT, and the two are counted separately in
the runner's banner so the distinction cannot quietly erode -- because #300's own third
rule is that slack wide enough never to fire is TODO #234's vacuous pass, so "the
threshold is generous" is not by itself an answer. (4) THE CENSUS FOUND THREE, all fixed
in v8.0.1, and the third is the one to remember. `hfscx_256_analysis.py` §1 and §2 gated
`|mean-128| < 3.SE` on a fresh sample -- #299's defect, in #299's own file, one section
over, left because §3 was the one that happened to fire. `qc_mdpc_bgf_prototype.py` §3
gated `abs(z) < 3` on a fresh chi-square and was wrong TWICE: flaky at about 1 run in 200
measured, and two-sided on a one-sided claim -- its single observed failure across 200
samples was z = -3.66, the sampler looking TOO uniform, so the gate's one real failure
mode was evidence FOR the finding it defends. And `qcmdpc_bgf_failure_rate.py` was the
inverse error and the worst of the three: `main()` had a single `return 0`, so the runner
discovered it, ran it every CI run, and it could not go red. A gate that cannot fail is
not a gate, and that one sat inside this job from #289 until #300 looked.

**And what a revealed view carries, which is the last of #298's three (TODO #301).**
#298 scoped three hiding assertions and wrote two; this is the third, at the protocol it
said to start with. For ZKBoo the statement is that THE TWO REVEALED PARTY VIEWS MUST NOT
DETERMINE THE THIRD, and it is testable because it is a claim about the SIZE OF A SET: the
witness is n bits, so at the demo width every candidate can be ENUMERATED and counted.
`SecurityProofsCode/zkboo_view_hiding.py` does that. Result: the revealed pair narrows the
witness by **exactly zero bits** -- 256/256 at n = 8 and 4096/4096 at n = 12, unchanged at
32 rounds opened. Three things to know before touching `_zkp_nl_evaluate_circuit`. (1)
WHERE THE HIDING LIVES is one term. Party e+1's AND gate has both operands open and is what
the verifier checks; party e+2's `+1` neighbour IS the hidden party, so its revealed
`and_out` carries a_e and c_e, and the only thing between an observer and those bits is
`r_{p+1}` = a tape bit of the party that was never opened. Delete that one term and the
transcript starts naming the witness. (2) THE CONTROL IS THE TEST. A PRG stuck at a
constant makes those mask bits known, and the candidate set collapses to 4/256 -- six bits
-- with the true witness still inside, which is what distinguishes a real leak from a
checker that simply disagrees with the prover. Two earlier drafts of that control fired for
the wrong reason and were thrown away; a hiding test whose control fires by excluding the
true witness is measuring its own bug. (3) IT IS PYTHON-ONLY ON PURPOSE, where #298 needed
four ports: the masking term is pinned BYTE-EXACTLY by `KAT/operation_replay.json`'s
`zkp_nl_prove` row, whose expected `view_p1`/`view_p2` carry the packed gate outputs, so a
port that drops it fails that vector in all four languages. §4 demonstrates that rather
than asserting it. ZKB++ (which opens SEEDS, a different exposure surface) and KKW are NOT
in this item, for #298's reason: a harness spanning all three converges on completeness
again.

**And the other two of #298's three, where the surface is not the same (TODO #302).**
#301 wrote the ZKBoo hiding assertion and said why ZKB++ and KKW were not folded in: a
harness spanning all three converges on completeness again. `zkbpp_kkw_view_hiding.py`
is those two, and the scoping note was right -- neither reduces to #301's dozen lines.
Four things to carry forward. (1) **ZKB++ reveals LESS per round than ZKBoo and is
therefore harder to reason about, not easier.** Party e+1's gate outputs are recomputed
by the verifier, so `gates_p2` is the only revealed gate vector -- and it is exactly the
one whose mask is a tape bit of the unopened party. Under an ideal seed expansion that
leaves every candidate consistent, which makes #301's enumeration nearly vacuous here;
the content is one level down. (2) **The seed is the surface.** A 16-byte seed
determines the hidden party's share AND its tape, so a candidate survives only if some
seed supplies both, and that is a counting question with an exact answer: 2n-1 bits of
constraint when the hidden party is 0 or 1, n-1 when it is party 2, whose share is
derived rather than seeded. Measured against 2^(k-c) at three widths in both regimes -- on the
EXPONENT, which is where the claim lives and where the alternative is n bits
away, not on the constant, which small-width combinatorics move by 0.2-0.6 bits.
And the unit of observation is the ROUND: a round's candidates meet one seed
multiset and move together, so banding them as independent cells was an order of
magnitude too tight and flaked at about 1 run in 3 before it was fixed.
With k = 128 the slack is 129-2n, which is 113 bits at the CLI default and **ONE BIT at
n = 64 = `_ZKP_NL_MAX_N`** -- so at that one width ZKB++ is computationally but not
statistically hiding, a line no document here had drawn. Not a defect and not a fix:
seed-based schemes are computationally ZK by construction, and reaching the excluded
candidates means searching 2^128 seeds. It is a property, now recorded with its
threshold. (3) **KKW's answer is an identity, not a count**, and that is better.
Enumeration is unavailable (the witness is in Z_q^288) and unnecessary: every
hidden-party unknown is determined in one pass for ANY candidate -- lambda_in from
z_in, lambda_xy from the sum-to-product relation (so `aux` buys no extra freedom either
way), lambda_z from the revealed t -- leaving exactly one residual equation, and it is
`u' - u == -rho.(circuit(w') - targets)`, the verifier's own statement projection.
Identical in every online emulation, so tau emulations are ONE constraint, not tau. The
constructive half is the part to keep: a second witness the public statement cannot
separate, built by solving the residual's quadratic in a delta-block coefficient, which
the transcript cannot separate either. (4) **The cross-port answer differs between the
two, and §6 CHECKS it rather than asserting it** -- #287's withdrawn trust-model
sentence is what an unchecked scope paragraph becomes. ZKB++ is covered twice (neither
port carries its own circuit, so ZKBoo's replay row pins its masking term; and the seed
length is a `PARAMETERS` row, which §2 promotes from formatting to security). KKW is
covered nowhere: `hcred_kkw.json` is VERIFY-SIDE by construction so no port's PROVER is
exercised, and KKW has no CLI surface so the 4x4 interop matrix does not reach it. That
gap is filed as TODO #303, not folded in here, and §6 self-invalidates -- adding the row
fails the section until the prose is corrected. It fired: #303 added the row, and §6's
check is now inverted, so DELETING it fails the section rather than quietly restoring
the gap.

**And KKW's PROVER, which #302 §6 found covered nowhere (TODO #303).** #302 asked
#301's cheap question -- what already holds this property across the four ports? -- and
got two answers. ZKB++ was covered twice; KKW was covered by nothing, because the two
gaps compound: `KAT/hcred_kkw.json` is VERIFY-SIDE by construction (one fresh root per
emulation, so a proof is not a function of its statement and regenerate-and-diff cannot
work) and KKW has no CLI surface, so the 4x4 interop matrix does not reach it either.
Numbered test [50] runs each port's prover against ITS OWN verifier, which is precisely
the shape that let three of four ports ship a transcription bug at #266. **A fixed
stream makes the prover a function again**, so this needed no new mechanism at all --
`KAT/operation_replay.json` gained a sixth row and the four consumers #296 and #297
built follow it as they follow the other five. Four things to know. (1) **The width is
not a choice**: HCRED's `n` is a runtime argument in Python and Go but a compile-time
constant of 256 in C (`HCRED_N`) and Java (`Hcred.N`), so 256 is the only width all four
can prove. (2) **`(N_par, M, tau)` IS a choice and was made on measured cost** -- an
n=256 prove is 80.1 s in Python at `hcred_kkw.json`'s (4, 8, 4) and 40.8 s at this row's
(4, 4, 2), and `generate_kat.py --check` pays it every run -- with what the smaller
triple must still exercise ASSERTED in the generator rather than assumed: `M > tau`
leaves emulations unopened, and the two opened ones must straddle the aux-reveal
condition, which is the condition the Go port read backwards. (3) **`consumed` is exact
here**, at `M x 32` = 128 bytes, where the `rnl_sigma_sign` row's is null: all four read
one 32-byte root per emulation with no rejection anywhere. Measuring that cost answered
a question nobody had asked: the same prove is **C 0.7 s, Java 8.6 s, Go 38.5 s, Python
40.8 s**, so **Go's KKW sits at interpreted-Python speed, ~55x C's**. Pre-existing and
out of #303's scope -- it is also why `CliTest/test_kat_vectors.sh` has always spent
minutes in its Go step, since the `hcred_kkw[n256]` block there is seven n=256
verifications at ~33 s each -- and the reason the row is affordable is that it adds
about a sixth to that, not that it is cheap. (4) **The four ports agree**,
and that is the result, not a disappointment -- C, Go and Java each reproduced Python's
proof field for field on the first attempt, where #296 found three of four samplers
diverging and #297 found an anonymity break. What the row buys is that they cannot stop
agreeing quietly. Scope, because #302 §6 is what an unchecked scope paragraph becomes:
the row pins **divergence, not hiding** -- a pad predictable in all four ports passes a
cross-port vector by construction -- so `zkbpp_kkw_view_hiding.py` §4-§5 stay the only
check of the hiding property, which is #298's rule (1).

**And what the bar is measured against, which is what "the bar follows the statistic"
was standing in for (TODO #304).** #300's census gave every sampled gate either a derived
RATE or a stated ARGUMENT and counted the two separately "so the distinction cannot
quietly erode". It eroded the other way: `follows` entries -- the ones whose threshold is
computed FROM the statistic's own null -- contribute nothing to the banner's sum, so an
argued gate could be the job's dominant flake source and the advertised number would not
move. **All three `follows` entries were defective, and the common root is that the null
was a MODEL and nothing had checked the model.** (1) `zkp_pqc_exploration.py` §3.5 ran at
**6.0e-3 per run -- one CI run in 167, and 111x the 5.4e-5 the job then advertised** -- on a
measured null of 2.028 against a modelled 1.235 (1500 samples). The missing term is that
the cheating prover's wrong witness is a FIXED function of the instance, so about one
trial in 131 hands it a genuine preimage and COMPLETENESS passes it: that trial is not a
cheat, and conditioned on the trial being one the model is intact (0.01305 vs 0.01235).
The correction went into the EXPERIMENT, not the band -- TODO #302 §2's lesson a second
time. (2) §3.7 of the same file was the inverse and worse: its finding claimed ZKB++
soundness "stays at (1/3)^R" and **a genuine cheat survives 0 times in 39,708**, because
ZKB++ rebinds `out_e` to the public y so a wrong witness dies every round. Its bar of 6
was slack enough to absorb a real regression while reading PASS -- a false claim and a
vacuous pass are the same defect from two sides, which is #300's own third rule. It is
EXACT now. (3) `hybrid_credential_phi.py` §5.4 is the one whose model was RIGHT (measured
3.77 against 3.704 over 60 samples) and which flaked anyway at 4.7e-4, because a correctly
calibrated 4-sigma band on a mean of 3.7 simply does fire that often; it fired in #302's
own gate run. Both are replicated per #299 now. Two things to carry forward. **A `follows`
entry now owes a rate AND the token `MEASURED`**, the second because requiring the number
alone would have certified §3.5 at 3.0e-4 while it ran at 6.0e-3 -- the arithmetic is only
as good as the null it is done against. And **#302's own entry was audited in the same
pass, as #304 said it must be** -- and it came back SOUND, at <=1e-5 with zero exceedances
in 200,000 bootstrap replications. A wider band was drafted for it on an analytic estimate
of ~7e-3 and dropped when the bootstrap refuted the estimate, which is the same discipline
the other two got: retuning a gate that measures fine is widening a band under another
name. **The job's honest rate is 6.4e-5, not 5.4e-5**, and CLAUDE.md's copy of it is now a
check-E row rather than a hand-copied number -- the same reporting gap one layer out.

**And how much of that pinning actually REACHES the census, which is the question the
census could not ask of itself (TODO #305).** #300 asked of the findings gates: the SET is
the tripwire, but how many of them decide a verdict from a fresh sample? `RANDOMNESS_CENSUS`
has the identical structure -- a name set, derived from source every run, whose whole job is
to force a question when it changes -- and nobody had put the identical question to it. Its
own header says what it cannot do ("only that it exists and that someone looked") and then
hands the remainder to #297 and #303, which pinned six operations between them. **Nothing
counted what that left: 10 consumers per language were named by a pinned row and 15 / 15 /
18 / 21 were not.** `REPLAY_COVERAGE` is the answer, and of the four it filed as owed,
**0 consumers are still OWED a pin** — TODO #307 pinned all four in v8.2.0, which
deleted their rows. Four things to carry forward. (1) **`owed` is a status, not a reason.** A row
is `transitive`, `unpinned` or `owed`, and the third needs an ITEM NUMBER as well as a
sentence -- because a prose reason is exactly where work gets parked, which is #295's
false-reason finding aimed at a table instead of a constant. The count is printed and held
by a check-E row, so retitling an `owed` row `unpinned` to retire work moves a number
CLAUDE.md is checked against. (2) **The `transitive` half is DERIVED.** "Covered by the ring
row" is the same kind of curated sentence #295 found two of six of carrying a false claim,
so the checker walks a per-language CALL GRAPH from the pinned operation and fails a claim
no call path supports. That touches #295's recorded "closing that needs a call graph" from
the other side and does not close it: reachability is not liveness. (3) **It found a
DUPLICATE, which is worse than dead code.** C's `rnl_cbd_poly` specialised
`rnl_cbd_poly_dim` to `RNL_N` with its own `fread` and its own loop, and nothing anywhere
called it -- but it was load-bearing for the wrong thing, because the `rnl-cbd-poly`
manifest row anchored C's cell on the DEAD copy while the protocol ran the live one. Every
syntactic checker read the duplicate as the real sampler. Deleted. (4) **The corpus stops at
the suite boundary and a Schnorr nonce is on the other side.** Writing the reason for
`hpks_sign` being absent in Go and Python turned up that they do not take the nonce as a
parameter -- they draw it in the CLI, which this census does not read. 52 raw-entropy call
sites sit outside the corpus across the four CLIs, and `PARAM_USE_CORPUS` in the same file
already includes CLIs for #295's stated reason. That is TODO #306, filed rather than folded
in.

**And which code the census READS, which is prior to everything the census says (TODO
#306).** #305 asked how much of `RANDOMNESS_CENSUS` is pinned and hit a wall that was not
about pinning: writing the reason for `hpks_sign` being absent in Go and Python turned up
that they draw the Schnorr nonce **in the CLI**, which that census does not read. The
inconsistency was inside one file — `PARAM_USE_CORPUS` forty lines up reads suite +
walkthrough + CLI + codec and says why ("getting the corpus wrong in the LENIENT direction
makes the whole check pass vacuously"), while the randomness axis read the suite alone with
no sentence anywhere about the difference. `CLI_CORPUS`, `RANDOMNESS_CLI_CENSUS` and
`CLI_DRAW_COVERAGE` close it: **56 raw-entropy draws sit in the four CLIs**, every one
claimed by one of 16 named roles — 59 and 17 when the item ran, until TODO #308 moved the
Schnorr nonce into the suite and the `schnorr_nonce` role was deleted. Four things to carry forward. (1) **Widening the corpus
found the PATTERNS wrong**, which is why the filed figure was 52 — `secrets.token_bytes`
imported as `_sec` inside its own branch (a sixth spelling, and in the suite it sits in
`main`, which draws by other means, so the census was right there **by luck**), and
`new BigInteger(Herradura.N, RNG)`, which is not a new spelling at all but the same one in a
different CASE, because every suite port names the parameter `rng` and the CLI holds a static
field `RNG`. Two Java CLI functions read as drawing nothing, one of them the threshold-nonce
commit. Adding both patterns moves NO suite name, and that non-move is the check that the
suite census was correct rather than the claim that it was. (2) **The accounting is at SITE
granularity, not function.** A cell is (function, count) and the counts must sum to what the
source holds, because one command holds six draws and a name set would let a seventh be added
in silence — which is precisely how 52 sites accumulated on the far side of an unstated
boundary. (3) **The headline is a Schnorr nonce and the finding under it is worse than its
absence.** C's `herradura.h` exports `hpks_sign`, it draws its own nonce, and
`KAT/classical_quartet.json` pins it — and `herradura_cli.c` DOES NOT CALL IT, transcribing
the whole signer inline instead; the suite copy is reached only by `docs/examples` and the FFI
shim. Go and Python never had the operation. So three of four CLIs sign with an unpinned
transcription and Java is the one that calls the suite. The pinned function and the shipped
path are different code in the port that has both, which is #295's dead-code limit
(reachability is not liveness) aimed at a sampler instead of a constant. Filed as TODO #308,
because the fix is not a vector — it is to make the three CLIs call the operation they copy.
(4) **A fixed-stream replay does not reach this layer and the item does not pretend
otherwise.** No CLI takes an entropy source as a parameter in any of the four languages, so
pinning here needs a new shipped surface (an injection env var), which is a change to the
product and is deliberately not made — filed as TODO #309, which owes the hazard argument
before the seam: an env var that replaces the CSPRNG is one accidental export away from a
deterministic `genpkey` whose output is indistinguishable on disk from a real key. What was missing was never the replay; it was knowing
which draws exist, in which ports, and what compares them.

**And moving the draw instead of pinning it, which is what a `cli_only` row would have
argued was impossible (TODO #308).** #306 censused 59 CLI draws and found one that was not
a census problem at all: `herradura.h` exported `hpks_sign`, it drew its own nonce,
`KAT/classical_quartet.json` pinned it four ways — and `herradura_cli.c` did not call it,
transcribing the whole signer inline while the suite copy was reached only by
`docs/examples` and the FFI shim. Go and Python never had the operation. **The pinned
function and the shipped path were different code in the only port that had both**, which
is #295's dead-code limit (reachability is not liveness) aimed at a sampler instead of a
constant. Four things to carry forward. (1) **The fix was not a vector, and that is the
transferable part.** A fixed stream cannot reach a CLI in any of the four languages, so
pinning the draw WHERE IT WAS needed a new shipped surface — which is #309 and is
deliberately still unbuilt. Making the three CLIs CALL the operation they copied moves the
draw to a suite function the existing replay machinery already reaches, and for C that
function was already pinned. **When a draw cannot be pinned where it is, ask whether it is
in the right place before building a seam to reach it.** (2) **The NL half could not stay
behind**, and the site counts are what said so: `sign --algo hpks-nl` shared the classical
path's ONE inline `ba_rand` / `NewRandBitArray` / `BitArray.random` in C, Go and Python, so
moving only `hpks` would have left the draw exactly where it was with every table
unchanged. A cell here is (function, SITE COUNT) for precisely this reason. Java alone had
named both operations all along, and its shape — the suite draws the nonce and returns
`(R, s)`, the caller recomputes `e` for the PEM — is what the other three adopted verbatim,
on #294's and #296's precedent that adopting an existing correct port beats inventing a
fourth API. (3) **`schnorr_nonce` was DELETED, not retitled `cli_only`**, which the item
named in advance as the thing that must not happen: `cli_only` is true of a draw's CURRENT
LOCATION, and the location was the question. The site-count check forced the deletion
rather than permitting it — 56 sites over 16 roles with **0 owed**, down from 59 over 17 —
and `RANDOMNESS_CLI_CENSUS` stopped naming `cmd_sign` in three ports because it stopped
drawing there. (4) **Byte-identity is not what a round-trip shows.** The item asked whether
the signature was the same before and after, and a randomised nonce makes that
unanswerable by signing twice; it is answerable at a FIXED nonce, and the retired
transcription and the suite operation agree on `(R, s, e)` over 50 trials × 2 algorithms in
each of the three ports — C through `fmemopen`, Go through a `crypto/rand.Reader` swap,
Python through a `BitArray.random` substitution. The 4×4 CLI matrix (32/32 on `hpks` and
`hpks-nl`) proves interoperability, which is a weaker statement and was never the one in
doubt. One correction the item earned on the way out: it said the asymmetry was filed as
`CLI_FLAG_PARITY`'s `hpks-sign` row, and `REPLAY_COVERAGE`'s own reason said so too. There
is no such row — `CLI_FLAG_PARITY` is about CLI FLAGS and lives in a different file. The
acknowledgement was `PRIMITIVES`' `hpks-sign` entry, the right thing to re-examine under
the wrong name in two places.

**And the four pins that were still OWED, where the item's own prescription was the
thing that had to be corrected (TODO #307).** #305 built the coverage table, measured
that 10 consumers per language were pinned and 15 / 15 / 18 / 21 were not, and separated
`owed` from `unpinned` so that cost would be argued in the open rather than inside a
prose reason. This is that column: `qcmdpc_keygen`, `qcmdpc_encap`, `zkp_nl_pp_prove` and
`hcred_prove`, now rows in `KAT/operation_replay.json` consumed by all four ports through
the drivers #296 and #297 already built — no new script, no CI wiring, no injection
machinery. The count is **0 owed**, and the four coverage rows were DELETED rather than
retitled because a row whose cells are all pinned fails until it goes. Four things to
carry forward. (1) **The item told the next person to do the wrong thing, and measuring
is what caught it.** It prescribed a QC-MDPC stream "chosen to clear the weak-key screen
and the invertibility retry first time, on the `rnl_sigma_sign` row's precedent". That
precedent exists because a retry there desynchronises unbuffered C from the three
buffered ports (#293) — the attempt boundary falls inside a block. **No such boundary
exists here**: the CSPRNG is read exactly once for a 32-byte seed and every retry redraws
from the PRF, which is deterministic and unbuffered in all four. So the shipped stream
REJECTS ONCE on the screen and then accepts, pinning a branch a random stream reaches
about one draw in 550 (37 in 20 219, measured), and the generator asserts the rejection
rather than hoping for it. **A precedent cited by name is not the same as a precedent
that applies.** (2) **The costs it flagged were backwards, which is the argument for
measuring them before writing the row rather than after.** The QC-MDPC pair it called
expensive are the two CHEAPEST here (0.05 s and 0.10 s in Python at BIKE-128 — the
inversion is one extended Euclid, not a decode); `hcred_prove` at n = 256 is the one that
costs, ~10.5 s per prove, which is why it runs at `rounds = 2` — the smallest count that
can still open rounds on both sides of the aux-reveal condition, the condition the Go
port read backwards at #266. (3) **The four-cell rule was a law only because every row so
far obeyed it.** C's `qcmdpc_keygen` takes a `QcMdpcPrf *`, so the seed is a PARAMETER
there and a draw in the other three, and naming the function would fail the standing rule
that a pinned cell must be a CENSUSED consumer. `param_entropy` is the cell for that, and
it is cross-checked both ways — the function must EXIST and must NOT be censused — so C
starting to draw there fails and the function being renamed fails. The C consumer still
replays the operation: it reads the row's 32 bytes itself and seeds the PRF. (4) **A
self-invalidating check fired, in the file that wrote it.** `zkbpp_kkw_view_hiding.py` §6
asserted, as an ABSENCE, that the ZKB++ prover's seed order was unpinned, and said so
that "the day #307 pins the prover, this fires and forces the prose below to be
corrected". It did. §6 is inverted now and its "covered in two places and not a third"
paragraph says three — #302 §6's handoff to #303 happening a second time, same file,
other protocol. And the result is the one #303 got rather than #296's or #297's: **C,
Java and Go each reproduced Python's transcript field for field on the first attempt.**
What the rows buy is that the four cannot stop agreeing quietly.

**And whether a NUMBERED TEST decides on a fresh sample, which #300 asked only of the
findings gates (TODO #310).** #299 fixed one gate that failed about one CI run in twenty,
and #300 censused all 76 of them for the same shape — a verdict decided from a fresh random
sample against a FIXED threshold. That census stopped at `SecurityProofsCode/`. The numbered
tests are the other place a verdict is computed, and `[53]` had the defect at **one run in
16**. `[53]` is #298's universal-forgery guard: build a syndrome-matching witness of the
WRONG weight from public data, assert the verifier rejects it. `_stern_solve_syndrome`
leaves free variables at zero, so it returns the solution supported on the PIVOT columns —
and when all `t` of the true error's positions fall in those columns it returns **the true
error itself**, weight exactly `t`. The test then asserts the verifier rejects a perfectly
genuine witness, so **the one branch where it goes red is the branch where HPKS-Stern-F
behaved correctly**. Four things worth carrying. (1) **The rate is exactly 2^-t and the
histogram proves it is not a tail**: 191 hits in 3000 trials (6.4% against a predicted
6.25%) at the harness's n = 64, t = 4, with a clean bulk centred at 16, NOTHING at weights
5 or 6, and 39 of 39 sampled hits satisfying `e_forged == e_true`. A binomial tail would put
~0.00003 there. (2) **All four ports carried it and two were merely luckier** — Python and Go
run `[53]` at n = 64, t = 4, C and Java at n = 256, t = 16, so the same code failed one run
in 16 in two ports and one in 65536 in the other two; the fix goes into all four, because
2^-16 is a smaller number and not a different property. (3) **The fix is to CONSTRUCT the
off-weight witness, not to hope for one**: XOR kernel basis vectors into the solution until
its weight differs. `H.v^T == 0`, so the syndrome-matches control still holds exactly, and
the result is deterministic given the key — no threshold, no retry loop, no sample. It makes
the assertion STRONGER, since the old one tested a wrong-weight witness only when the draw
happened to supply one. (4) **Retrying until the weight differs was considered and rejected**:
that is the same sampled gate with the sampling hidden in a loop, and making the assertion
conditional on `wt != t` is worse still — TODO #234's vacuous pass, passing 6% of runs
without testing anything. The remaining question this one opens and does not answer is
whether any OTHER numbered test decides a verdict from a fresh sample against a fixed
threshold; `[4]`, `[18]` and `[45]` were fixed by #233 and #234 by making the threshold
follow the statistic, but no census exists.

**And the same hole in the gate that FOUND the forgery (TODO #310, second half).**
`stern_f_weight_binding.py` builds the same Gaussian-elimination witness and carried the
same 2^-t defect at 1.5e-5 — and two things made it worse than the harness copy. It scored
the case as `§1 INCONCLUSIVE` **and returned False**, so a section that could not conclude
was reported as a finding that stopped reproducing, which is #291's "a section that did not
run must not be scored" inverted. And `run_findings_gates.py`'s `SAMPLED_GATES` reason
argued it away: "§1 and §3 are exact: a Gaussian-elimination witness either verifies or does
not" — true of the VERIFIER, false of the WITNESS. That is #300's own derived-RATE versus
stated-ARGUMENT split failing on the argued side, the same shape #304 found in all three
`follows` entries ("the null was a MODEL and nothing had checked the model"). The lesson to
carry: **a reason that is exact about the wrong object reads exactly like a correct one**,
and the only thing that separated them here was running the construction 3000 times. Note
what the fix protects: correcting the reason alone would have moved the job's advertised
false-failure rate from 6.4e-5 to 7.9e-5, and that figure is a check-E row — fixing the
script instead makes the published number true.

**And the second one hiding behind it (TODO #310, third part).** Closing the witness-weight
hole made `[53]` go red again, differently: an off-weight witness the verifier ACCEPTED. The
verifier binds `wt(e)` only on `b = 0` rounds — that is the shape of #298's own fix, since
`wt(respA ^ respB)` is checkable only where both responses exist — so a wrong-weight witness
survives a challenge string containing no `b = 0` round at all: **(2/3)^rounds**, 0.77% at
`[53]`'s rounds = 12, one run in 130, in all four ports, and 7.4e-6 at
`stern_f_weight_binding.py` §1's rounds = 32. Measured: 3 acceptances in 400 trials, 3
no-`b=0` strings, the same 3. The remedy is the one this section already prescribes — **give
it its own round count** — which is what #234 did to `[45]` at 38.5% and what the standing
warning about a rounds = 4 Stern-F rejection test is about; `[53]`'s forgery sub-check now
signs at 64 rounds and the ring half keeps 12, having no soundness error. **The lesson is
that the two hid each other**: at a combined ~7.0% per run nobody asks which of the two
coins landed badly, and the second only became visible once the first was gone. When a test
turns out to be a sampled gate, the question is not "what is its rate" but "how many terms
does its rate have".

**And whether a draw is worth reaching before building something to reach it with (TODO
#311).** #306 censused 56 CLI entropy draws over 16 roles and #309 proposed a seam to pin
the 9 that no suite-level pin reaches — an env var that replaces the CSPRNG in a shipped
binary, which #309's own text calls "the sharpest footgun this repo could add". It also
filed the prior question against itself and did not answer it: are those 9 draws in the
right PLACE? #308 had just shown one that was not. **The nine split 7 / 2 and the split is
adverse to the seam.** Seven are a single uniform draw of one fixed width handed straight
to a function that already accepts it as an argument, with no loop, no rejection and no
second draw — so a fixed stream pins the identity function and the seam would teach
nothing about any of them. The remaining two are `hske_nla1_nonce` and
`threshold_commit_nonce`, which are exactly the two #309 nominates as worth pinning, and
are also the only two where the CLI transcribes a multi-step OPERATION rather than drawing
a parameter. Four things to carry forward. (1) **The cheap question came first and it was
decisive**, which is #302's discipline (ask what already holds this property) pointed at a
proposal instead of at a protocol: the triage cost an afternoon of reading and removed the
need for a new shipped surface. (2) **The curated reason was not evidence.** Three of the
seven rows already said "a fixed stream would pin the identity function" and four did not;
all seven were re-read against source in four ports, because #295 found two of six reasons
carrying a false claim and this table came after it. The classical exponent was checked
specifically for #294's rejection-sampling split and has none. (3) **A considered no is
recorded as one.** `threshold_commit_nonce` transcribes two steps, `hpkst_sign` is the
AGGREGATE path and no port has a function to call, so inventing one to host two lines
would add a public surface to make a table tidier — written down in #311 so it is not
re-derived as an oversight. (4) **The triage did not perform the move it recommends**, on
#306's precedent of filing #308 rather than folding it in: a triage that also does the
work cannot report that the work was the right call. What it found is TODO #312 — HSKE-NL-
A1's plain mode is a suite function in Java alone, and C, Go and Python transcribe it
twice each while calling the suite for its AEAD sibling in the same branch. #309 stays
OPEN with nothing withdrawn, and is no longer next.

`.github/workflows/codeql.yml` runs a separate, non-blocking CodeQL static-analysis
matrix (C/C++, Go, Python) on every push/PR plus a weekly schedule (TODO #189); alerts
surface under the repo's Security tab rather than as a required check.

Whenever a TODO adds or removes a test number or CLI subcommand, re-check this section (and `llms.txt`'s CLI section) for drift rather than waiting for the next major-version doc audit — see TODO #145.

```bash
# C/Go/Python — security tests [1]–[29] + benchmarks [30]–[41]
# ([44] HCRED, [45] weak-key/malformed-input rejection, [46] fpe/twk domain
#  separation, [47] the NL-FSCX v3 primitive appended after the benchmarks to
#  avoid renumbering; all four
#  languages also run test [19] "HFSCX-256-DM known-answer vectors" out of
#  strict numeric sequence.  [46] is TODO #242's regression guard: fpe and twk
#  shared one unseparated subkey derivation until v4.0.0 and were literally the
#  same function at a 12-byte context.  Python's copy of the derivation is
#  cross-checked against the shipped suite there, since that harness alone
#  re-implements it — C and Go call herradura.h / the herradura package.
#  [48] is TODO #255's guard for the five v3 CONSUMERS, which [47] does not
#  cover: round-trips, each v3 variant differing from its v2 counterpart on the
#  same inputs (a reused DS string or tag would still round-trip), fpe --v3 vs
#  twk --v3 at a 12-byte context -- #241's bug in new code -- and, in C/Go, that
#  the v3 duplex rejects a flipped AD.  Python's copy of fpe/twk v3 is
#  cross-checked against the suite as [46]'s is; Python has no duplex in either
#  version, so hske-duplex3 is covered only by C and Go.
#  [47] is TODO #255's guard for the v3 primitive: chi against a per-row
#  reference, chi^-1 . chi == id, the revolve round-trip at R3_VALUE = 160, and
#  that every row of the 47x5 + 3x7 partition is odd and >= 5 -- a 3-row is a
#  complete break (SecurityProofs-8.md 11.34.2), so that last one is a security
#  assertion.  Python's copy is cross-checked against the shipped suite there,
#  as [46] does, since that harness alone re-implements the primitive.
#  [49] is TODO #261's guard for the HKEX-RNL peer-m_blind substitution check
#  (reject a sparse or clustered m_blind before using it).  All four languages
#  ship it and NONE tested it until #261 -- and Python's suite did not have the
#  function at all, only a private copy inside HerraduraCli/herradura.py, so
#  #261 moved it into the suite and the CLI now imports it.  Case (a) is an
#  accept-control: a guard that rejected everything would otherwise pass the
#  four rejection cases perfectly.  Python's copy is cross-checked against the
#  suite as [46]'s and [47]'s are.  Java's counterpart is SelfTest.java's [27]
#  [50] is TODO #266's guard for HCRED-KKW's PROVE side, which KAT/hcred_kkw.json
#  cannot reach by construction (that vector is verify-only).  KKW shipped in all
#  four languages under #261 verified only structurally -- round-trips and
#  rejection checks written by hand during each port, then thrown away -- and
#  three of the four ports carried a real transcription bug found exactly that
#  way.  Accept-control plus the same six rejection axes the vector's tamper
#  table applies, so a divergence between test and vector is visible rather than
#  two independent opinions about what to check.  Unlike [46]-[49] it calls the
#  suite rather than keeping a local copy: KKW is ~113 lines of interlocking
#  cut-and-choose machinery and a second copy would be a new place for the very
#  divergence it guards.  Java's counterpart is SelfTest.java's [31], where the
#  tamper is a REBUILD rather than a poke because that port's proof fields are
#  final.
#  [51] is TODO #261's guard for the QC-MDPC weak-key screen
#  (qcmdpc_key_is_strong), the TODO #235 Part 1 check that makes the measured
#  DFR tail unreachable from keygen.  Another FOUR-WAY absence, the same shape
#  as [49]'s: it is called only from qcmdpc_keygen, so nothing anywhere
#  exercised it and a screen that accepted everything passed the whole repo.
#  Its supports are PINNED rather than sampled, all at QCMDPC_D = 15 because
#  C's qcmdpc_key_is_strong takes a fixed-width QcMdpcPriv, and the accept
#  case sits exactly ON the threshold so it is both control and lower
#  boundary.  The case that earns its keep is the CYCLIC-FOLD discriminator:
#  a support whose run straddles zero has true multiplicity 6 but only 5 if
#  min(d, r-d) is dropped, so an implementation that lost the fold passes
#  every other case and fails just that one.  SCOPE, before anyone extends
#  it: the screen covers KEYGEN only -- no PEM decode path checks an imported
#  key's spectrum in any language, and that is a recorded position, not an
#  oversight (an arithmetic-progression key fails its own decapsulations: a
#  self-inflicted DoS, not a confidentiality break).  Python keeps a local
#  copy cross-checked against the suite as [46]-[49] do; C/Go/Java call
#  theirs directly.  All four also assert that what keygen PRODUCES the
#  screen ACCEPTS, which no pinned vector can.  Java's counterpart is
#  SelfTest.java's [32]
#  [53] is TODO #298's guard for the two properties no Stern test asserted.
#  Every other check on Stern-F and Stern-Ring asserts COMPLETENESS or
#  SOUNDNESS-BY-TAMPER, and neither can see (a) that the verifier binds
#  wt(e) = t, or (b) that no commitment value repeats across the member-rounds
#  of one ring signature.  (a) builds the GAUSSIAN-ELIMINATION forgery from the
#  PUBLIC key -- which every build before v8.0.0 accepted -- and asserts the
#  verifier rejects it, with the honest signature checked FIRST as an accept
#  control.  (b) is #297's constant-dummy marker stated as an INVARIANT, so it
#  is catchable in ONE port rather than by reading four implementations side by
#  side; it caught #297's fix having never reached this harness's own copy of
#  the ring simulator.  Calls the SUITE rather than a local transcription, as
#  [50] does.  NOT asserted here, deliberately: that a simulated b = 0 pair
#  carries the same wt(respA ^ respB) as a real one -- the VERIFIER checks that
#  since v8.0.0, so a simulator regression fails the existing round-trips and a
#  case asserting it would pass vacuously.  Java's counterpart is
#  SelfTest.java's [35].  Runs BEFORE fclose(urnd_fp) in the C harness, since
#  unlike [51] and [52] it draws keys
#  [52] is TODO #277's guard for the QC-MDPC PRF's SEED EXPANSION, and it is a
#  four-way PINNED vector because the four languages did not agree.  C XORed
#  the counter into the TOP four bytes of the seed where Python, Go and Java
#  XOR it into the LOW bits, so block 0 agreed -- ctr is 0 there -- and every
#  block after it did not.  A 3-1 split survived the life of the protocol
#  because the seed is freshly random at every keygen, only the resulting KEY
#  travels on the wire, and nothing ever asked one language to reproduce
#  another's expansion; hence a vector, not a round-trip.  Case (b) is
#  deliberately the SECOND support drawn from one PRF -- the first is one
#  block and would have passed throughout.  It also pins the modulus-sized
#  draw width #277 introduced and exercises a modulus past 65536, which the
#  16-bit-only sampler could not serve and did not refuse either: its
#  acceptance limit was zero, so it spun forever.  Python and Go reach the
#  sampler through the suite rather than keeping a local copy -- a second
#  opinion about the byte order in dispute would prove nothing -- which is
#  why the Go package exports QcMdpcPrfDraw at all.  Java's counterpart is
#  SelfTest.java's [34])
./CryptosuiteTests/Herradura_tests_c
./CryptosuiteTests/Herradura_tests_c -r 500        # cap each test at 500 iterations
./CryptosuiteTests/Herradura_tests_c -t 2.0        # cap wall-clock per test/bench at 2 s
HTEST_ROUNDS=200 HTEST_TIME=1.5 ./CryptosuiteTests/Herradura_tests_c  # env-var equivalents

cd CryptosuiteTests && go run Herradura_tests.go
cd CryptosuiteTests && go run Herradura_tests.go -r 500 -t 2.0

python3 CryptosuiteTests/Herradura_tests.py
python3 CryptosuiteTests/Herradura_tests.py -r 500 -t 2.0

# Assembly — build first (see Build Commands), then run:
# ARM/NASM/Arduino: tests [1]–[18]
qemu-arm -L /usr/arm-linux-gnueabi ./CryptosuiteTests/Herradura_tests_arm
qemu-i386 ./CryptosuiteTests/Herradura_tests_i386
./run_arduino.sh tests    # simavr; TIMEOUT env var, default 90s

# C sanitizers (TODO #188) — build first with build_c_sanitize.sh, then run:
./build_c_sanitize.sh
./CryptosuiteTests/Herradura_tests_asan -t 2.0   # ASan+UBSan; aborts on first issue found
./HerraduraCli/herradura_cli_asan --help         # CLI under the same instrumentation

# Valgrind memcheck (slow — use small -r/-t; a plain, non-sanitized debug build,
# since ASan and valgrind's own instrumentation conflict):
gcc -O0 -g -o /tmp/herr_tests_valgrind CryptosuiteTests/Herradura_tests.c
valgrind --leak-check=full --show-leak-kinds=definite,indirect \
  /tmp/herr_tests_valgrind -r 3 -t 0.2
```

The `-r`/`--rounds` flag caps iterations per security test; `-t`/`--time` sets the wall-clock limit for both tests and benchmarks. CLI flags override `HTEST_ROUNDS`/`HTEST_TIME` env vars.

**What `-t` actually bounds (TODO #225).** It caps iteration *count*, not wall time, and only at the granularity of `_trange`'s poll — `(i & 63) == 63`. A call site requesting fewer than 64 iterations is never polled, so the cap cannot reach it however slow its work becomes: 18 of the Python suite's 95 capped sites are in that category and carry ~71% of the time spent inside capped sites (worst: `test_hpke_stern_f_correctness`, 30 iterations requested, ~97 s against a 2.0 s cap). A truncated site always stops at a multiple of 64, never in between. Separately, 16 sites pass a literal count to `_trange` instead of `_iters(...)`, so `-r` does not reach them either. Every run now prints a closing `--- Time cap: ... ---` line reporting sites entered, truncated, and unpollable. The startup banner reports whether `_rnl_poly_mul` took the numpy or pure-Python path, and the `RNL_SIZES` the tests exercise — which is **not** the suite's deployed `RNLN`. Baseline: `benchmarks/rnl_ring_cost.py`; for what the deployed ring costs in each language, `benchmarks/rnl_deployed_ring_cost.{c,go,py}` (TODO #292) — benchmark [40]'s own HKEX-RNL rows stop at the retired n = 256.

The suite files run EVE (eavesdropper) bypass tests inline on every execution.

### CLI integration tests (CliTest/)

```bash
# Python CLI — build not required (python3 used directly)
bash CliTest/test_keygen.sh
bash CliTest/test_vectors.sh   # key-agreement correctness: Alice+Bob derive same secret
bash CliTest/test_sign.sh
bash CliTest/test_encrypt.sh
bash CliTest/test_encfile.sh
bash CliTest/test_signfile.sh
bash CliTest/test_aead.sh      # HSKE-NL-AEAD enc/dec --aead, 16-way cross-CLI interop (needs C+Go built; Java joined in TODO #273)

# C CLI — requires HerraduraCli/herradura_cli (build_c.sh)
bash CliTest/test_c_keygen.sh
bash CliTest/test_c_interop.sh # Python-generated keys consumed by C CLI and vice versa

# Go CLI — requires HerraduraCli/herradura_cli_go (build_go.sh)
bash CliTest/test_go_keygen.sh
bash CliTest/test_go_interop.sh
```

### SecurityProofsCode scripts

Each script in `SecurityProofsCode/` is standalone — runnable on its own with no third-party dependencies.  Many (about 20, including `fscx_revolve_corank.py` and `fscx_revolve_closed_form.py`) do load the suite via `importlib`, deliberately: a script that verifies a claim about the shipped implementation has to test the shipped implementation.  Run them to reproduce the analysis results cited in `SecurityProofs-*.md`:

```bash
python3 SecurityProofsCode/hkex_gf_test.py          # DH correctness + DLP
python3 SecurityProofsCode/hkex_rnl_failure_rate.py  # HKEX-RNL failure-rate analysis
python3 SecurityProofsCode/nl_fscx_owf_analysis.py   # NL-FSCX OWF cryptanalysis
python3 SecurityProofsCode/nl_fscx_rot_analysis.py   # rotational differential analysis

# The two QC-MDPC scripts take minutes to over an hour at full sample sizes and
# both accept --quick (smaller samples; the findings still gate the exit status):
python3 SecurityProofsCode/qcmdpc_bgf_variants.py --quick   # ~11 min; --full is ~72 min

# All of them at once, which is what CI's analysis-findings job runs (TODO #289).
# --quick is the default here and is applied to scripts declaring --quick or
# --fast, in argparse OR straight out of sys.argv -- three spellings of one
# reduced-sample mode (TODO #290, #291);
# --full runs everything at its default sample sizes (hours, not minutes).
# --list also prints the 7 scripts DECLARED non-gating and why (TODO #291).
python3 SecurityProofsCode/run_findings_gates.py --list   # what would run, and how
python3 SecurityProofsCode/run_findings_gates.py         # ~120 min on an aarch64 SBC
```

## Core Cryptographic Architecture

### Primitives

**FSCX(A, B):**
```
C = A ⊕ B ⊕ ROL(A) ⊕ ROL(B) ⊕ ROR(A) ⊕ ROR(B)
```
Linear map M = I ⊕ ROL ⊕ ROR; order of M is n/2. Iterating FSCX creates periodic orbits of length P or P/2 (P = bit size).

**FSCX_REVOLVE(A, B, n):** Iterates FSCX n times, keeping B constant.

**GF(2^n) arithmetic:** `gf_mul` (carryless multiply mod irreducible polynomial), `gf_pow` (square-and-multiply). Generator g = 3.

### Protocol Stack

**Classical (v1.4.0):**
```
FSCX_REVOLVE + GF(2^n)* arithmetic
├── HKEX-GF  — C = g^a; C2 = g^b; sk = C2^a = C^b = g^{ab}
├── HSKE     — E = fscx_revolve(P, key, i); D = fscx_revolve(E, key, r) = P
├── HPKS     — Schnorr: R = g^k; e = fscx_revolve(R, msg, i);
│              s = (k - a·e) mod (2^n-1); verify: g^s · C^e == R
└── HPKE     — El Gamal: enc_key = C^r = g^{ar};
               E = fscx_revolve(P, enc_key, i);
               dec_key = R^a = g^{ra};
               D = fscx_revolve(E, dec_key, r) = P
```

**NL/PQC (v1.5.0):**
```
NL-FSCX primitives + Ring-LWR
├── HSKE-NL-A1 — counter-mode: ks = nl_fscx_revolve_v1(K, K⊕ctr, i); E = P ⊕ ks
├── HSKE-NL-A2 — revolve-mode: E = nl_fscx_revolve_v2(P, K, r); D = inverse
├── HKEX-RNL   — Ring-LWR key exchange (conjectured quantum-resistant)
├── HPKS-NL    — Schnorr with NL-FSCX v1 challenge: e = nl_fscx_revolve_v1(R, msg, i)
└── HPKE-NL    — El Gamal with NL-FSCX v2: E = nl_fscx_revolve_v2(P, enc_key, i)
```

**Code-Based PQC (v1.5.18):**
```
Stern identification protocol (ZKP for syndrome decoding)
├── HPKS-Stern-F — Fiat-Shamir signature (C/Go/Python: N=n=256, t=16, rounds=32 demo
│                  default, 219 for 128-bit Fiat-Shamir soundness — all three CLIs
│                  take `sign --rounds 219` and `cred-issue --rounds 219` since
│                  v3.1.0 (TODO #236); the round count travels in the PEM, so a
│                  reader accepts any count in [1, SDF_MAX_ROUNDS] regardless of
│                  its own SDF_ROUNDS, which remains only the signing default.
│                  assembly/Arduino: N=32, t=2, rounds=4)
│                  commit: c0=hash(π,H·r^T), c1=hash(σ(r)), c2=hash(σ(y))
│                  challenge b∈{0,1,2} via NL-FSCX hash of msg+commitments
│                  response reveals permuted r, y=e⊕r, or permutation π
└── HPKE-Stern-F — Niederreiter KEM: ct=H·e'^T; K=hash(seed,e')
                   (`--algo hpke-stern`: demo, decap uses known e'; `--algo hpke-stern-kem`:
                   real BGF QC-MDPC decoder, qcmdpc_keygen/encap/decap_bgf in C/Go/Python)
```

Parameters: i = n/4, r = 3n/4. GF arithmetic uses 32-bit operands in assembly/Arduino; 256-bit in C/Go/Python suite. HSKE and FSCX tests always use 256-bit.

### herradura.h — header-only C library

`herradura.h` exposes the entire suite as a single-include header.  External C code (including `HerraduraCli/herradura_cli.c`) includes it directly; there is no separate compilation step.  All exported symbols are prefixed `ba_`, `gf_`, `nl_`, `rnl_`, `hkex_`, `hske_`, `hpks_`, `hpke_`, `stern_`, or `hpks_stern_`/`hpke_stern_`.

### HerraduraCli — OpenSSL-style CLI

Three parallel implementations (`herradura.py`, `herradura_cli.c`, `herradura_cli_go`) share the same PEM wire format and subcommand interface: `genpkey`, `pkey`, `kex`, `enc`, `dec`, `sign`, `verify`, `dgst`, `encfile`, `decfile`.  PEM files produced by any implementation are byte-for-byte compatible with the others.

- Python CLI (`herradura.py`) imports the suite via `primitives.py`, which uses `importlib` to load the space-named suite file.
- C CLI (`herradura_cli.c`) `#include`s `../herradura.h` and `herradura_codec.h` for PEM/DER encode-decode.
- HKEX-RNL key exchange is two-round: Bob responds first (`kex --algo hkex-rnl --our bob.pem --their alice_pub.pem`), then Alice completes using Bob's response PEM.
- `docs/examples/` contains minimal `hello_herradura.{py,c,go}` integration samples.  The Python example shows the `importlib` pattern required because the suite filename contains spaces.

## KaTeX Rendering Rules for Markdown Files

GitHub renders math in `README.md`, `SecurityProofs.md`, and similar files via KaTeX, and the rendering pipeline (markdown/CommonMark first, then KaTeX) has ~11 sharp edges around `_`, `$`, `*`, spacing commands, and a ~750-expression per-page limit that silently breaks math past that threshold.

Before editing any `$...$`/`$$...$$` math span in this repo, read `SecurityProofsCode/KATEX_RULES.md` in full — it documents every rule, the correct-pattern table, and the local validation script (`SecurityProofsCode/validate_katex.js`). Do not guess at KaTeX-safe syntax from general LaTeX knowledge; GitHub's pipeline rejects several constructs that are valid in standalone KaTeX.

## License

Dual-licensed under GPL v3.0 and MIT. Users may choose either.
