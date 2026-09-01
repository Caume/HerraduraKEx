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
                                                       across C/Go/Python (Java ships no
                                                       duplex, fpe or twk).  Claimed by
                                                       native-interop; degrades to a NOTE
                                                       if bindings/java is not compiled.
                                                       Asserts the FLAG actually changes
                                                       the output — a --v3 that parsed and
                                                       was then ignored would pass every
                                                       round-trip
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
                               at n=64, being compiled for a single RNL_N)
  nl_fscx_v3.json            — the NL-FSCX v3 primitive (chi, one round, the
                               R3_VALUE revolve and its inverse) and all five
                               consumers (TODO #255).  The only KAT coverage of
                               the NL side of the suite.  twk's sector/bidx are
                               hex STRINGS, not JSON numbers: a 64-bit sector
                               does not survive the float64 a JSON parser
                               defaults to, and the loss is silent
  generate_kat.py            — deterministic reference generator (Python) for all three
                               JSON files; --check verifies currency
  generate_pem_kat.py        — generator for pem/; --check verifies currency
  verify_kat.go               — independent cross-check against the Go herradura package
                               (bindings/java KatVerify does the same for Java)
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
                             GJS reaction attack (TODO #218)
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
  nl_fscx_exact_trail_search.py — exact xdp+ trail bounds for NL-FSCX v1/v2
                             via SMT; rotation table; key-averaging gap
                             (TODO #214)
  hkex_*_analysis.py       — FSCX_N, multi-nonce, and nonce-impossibility analyses
  validate_katex.js         — pipeline simulator for GitHub KaTeX rendering
  check_part_index.py       — asserts every copy of the eight-part index (banners,
                              footers, README, CLAUDE.md, KATEX_RULES.md) agrees with
                              SecurityProofs.md, and that the advertised expression
                              counts match what validate_katex.js measures (TODO #231)
SecurityProofs.md                                   — split index (redirects to Parts 1–9; quantum analysis is in SecurityProofs-2.md §6)
SecurityProofs-1.md                                 — §1: Algebraic Foundations (300 math expressions)
SecurityProofs-2.md                                 — §2–§8: Protocol Analysis · Security Analysis · Summary Tables · Quantum Attack Analysis · Experimental Code Index (409 math expressions)
SecurityProofs-3.md                                 — §9–§10: Non-Linear Proposals · v1.4.0 Migration (409 math expressions)
SecurityProofs-4.md                                 — §11–§11.8.2: Non-linearity/PQC extensions · NL-FSCX v1/v2 · HKEX-RNL (685 math expressions)
SecurityProofs-5.md                                 — §11.8.3–§11.8.8: PQ signature options · HPKE-Stern-KEM (587 math expressions)
SecurityProofs-6.md                                 — §11.9: HFSCX-256-DM (131 math expressions)
SecurityProofs-7.md                                 — §11.10–§11.13, §11.15–§11.33: ZKP extensions · Ring-LWR Σ-protocol · NL-FSCX ZKBoo · research-review sections (698 math expressions)
SecurityProofs-8.md                                 — §11.34–§11.36: NL-FSCX v3 exact row analysis · the asymptotic differential and linear slopes, measured (435 math expressions)
SecurityProofs-9.md                                 — §11.37–§11.38: the width residue #252 and #254 shared · the annealed threshold, evaluated exactly at n = 256 (401 math expressions)
docs/
  TUTORIAL.md               — API usage guide per protocol and language
  INTRODUCTION.md           — lay-audience primer for all core concepts
  examples/{python,c,go}/   — hello_herradura.* integration examples
Mcp/                                                 — MCP server exposing the CLI (genpkey/pkey/kex/
                                                      enc/dec/sign/verify/dgst) as agent-callable tools
                                                      over stdio; see Mcp/README.md for the trust model
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
                                                      C/Go/Python's shared [1]-[48] numbering, and a
                                                      curated manifest of suite-internal (non-CLI)
                                                      primitives -- seeded with the HCRED-KKW gap the
                                                      item was filed over -- so a primitive with no
                                                      `--algo` tag can still be caught missing in a
                                                      language.  All three run in CI's native-python
                                                      job (TODO #238, #261).
                                                      `protocols` is keyed on a protocol id, not an
                                                      --algo tag: aPAKE, and since TODO #241 also
                                                      hdrbg/fpe/twk, have no tag and are filed under
                                                      their subcommands via `cli_binding`.
                                                      `unfiled_cli_surface` now names only `pkey`, a
                                                      key-format utility with no protocol of its own
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
                                                      Python CLI's subcommands and --algo values;
                                                      cross-checked against KAT/.  hpks-wots /
                                                      hpks-xmss keep one-time-use/leaf-index state
                                                      in a <keyfile>.idx sidecar, as Python does
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
run against a bare toolchain.  Three optional packages exist, all analysis- or
tooling-only, and every consumer of them degrades to a printed NOTE rather than failing:

| package | used by | absent ⇒ | install |
|---|---|---|---|
| `jsonschema` | `spec/generate_spec.py` schema validation | NOTE, but CI passes `--require-schema` so a skipped validation cannot pass | `pip install jsonschema` |
| `z3-solver` | `SecurityProofsCode/nl_fscx_exact_trail_search.py` (TODO #214) | section skipped | `pip install z3-solver` |
| `pulp` (CBC) | `SecurityProofsCode/nl_fscx_v2_bounds.py` §(d) MILP bounds (TODO #247) | section skipped | `sudo apt-get install -y python3-pulp`, or a venv: `python3 -m venv ~/.venvs/herradura-milp && ~/.venvs/herradura-milp/bin/pip install pulp` |
| `highspy` | the same §(d) model under a stronger backend (TODO #252 §11.35.6) | CBC is used instead, and reaches one round fewer | `~/.venvs/herradura-milp/bin/pip install highspy` (PuLP finds it as the `HiGHS` solver) |

Never add one to a shipped primitive.  If an analysis script needs a solver, it imports it
inside a `try`/`except ImportError` and prints what to install.

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

`.github/workflows/ci.yml` runs eleven
jobs on every push/PR, all required/blocking: `native-c`, `native-go`, `native-python`
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
CLI-argv run, TODO #187), and `sanitizers` (C suite/tests/CLI under ASan+UBSan plus a
bounded valgrind memcheck pass, TODO #188). Locally, run the same scripts by hand as
described below.

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
#  as [46] does, since that harness alone re-implements the primitive)
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

**What `-t` actually bounds (TODO #225).** It caps iteration *count*, not wall time, and only at the granularity of `_trange`'s poll — `(i & 63) == 63`. A call site requesting fewer than 64 iterations is never polled, so the cap cannot reach it however slow its work becomes: 18 of the Python suite's 95 capped sites are in that category and carry ~71% of the time spent inside capped sites (worst: `test_hpke_stern_f_correctness`, 30 iterations requested, ~97 s against a 2.0 s cap). A truncated site always stops at a multiple of 64, never in between. Separately, 16 sites pass a literal count to `_trange` instead of `_iters(...)`, so `-r` does not reach them either. Every run now prints a closing `--- Time cap: ... ---` line reporting sites entered, truncated, and unpollable. The startup banner reports whether `_rnl_poly_mul` took the numpy or pure-Python path, and the `RNL_SIZES` the tests exercise — which is **not** the suite's deployed `RNLN`. Baseline: `benchmarks/rnl_ring_cost.py`.

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
bash CliTest/test_aead.sh      # HSKE-NL-AEAD enc/dec --aead, 9-way cross-CLI interop (needs C+Go CLIs built)

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
