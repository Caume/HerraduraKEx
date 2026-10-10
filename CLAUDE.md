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
  test_narrow_width_matrix.sh                       — the WIDTH axis (TODO #313, #314).
                                                       Every other CliTest script feeds
                                                       `enc` from a DEFAULT-width session
                                                       key, so a four-way divergence in
                                                       `hske-nla1` below 256 bits sat under a
                                                       green 518-assertion
                                                       test_cross_lang_matrix.sh.  REWRITTEN
                                                       TWICE, each time on the previous
                                                       header's own instruction: it PINNED
                                                       THE DEFECT at v8.3.1 while #313 was
                                                       undecided, asserted route 2's "all
                                                       four REFUSE" at v9.0.0, and asserts
                                                       "ALL FOUR AGREE" since v9.5.0, when
                                                       TODO #314 pass 6 converged the ports
                                                       and lifted the refusal.  Now: the full
                                                       4x4 (writer x reader) matrix at 256,
                                                       128, 64 and 32 bits -- 48 narrow cells
                                                       -- plus the refusals that remain,
                                                       which are about FORMATS rather than
                                                       about ports disagreeing: a declared
                                                       width no BitArray can have
                                                       (BITARRAY.md 2), a ciphertext whose
                                                       declared width disagrees with the
                                                       key's (3, a mixed width is never
                                                       coerced -- and this layer used to
                                                       RESOLVE that by preferring one side,
                                                       Go the ciphertext's width and C the
                                                       fixed 256 it stamped on everything),
                                                       and encfile/decfile, whose .hkx
                                                       container has no width field at all.
                                                       FOUR CONTROLS.  The matrix is now its
                                                       own accept-control, so it acquires the
                                                       one that lets it FAIL: a genuine
                                                       artifact decrypted under a DIFFERENT
                                                       key must NOT recover the plaintext, or
                                                       an hske-nla1 that ignored its key
                                                       entirely would score 64/64 -- #234's
                                                       vacuous pass inverted.  The two
                                                       length-preserving relabel cases each
                                                       have their own un-rewritten control
                                                       (DER INTEGER 256 is 02 02 01 00, 128
                                                       is 02 02 00 80 and 260 is 02 02 01 04,
                                                       all four bytes, so no SEQUENCE length
                                                       moves and the artifact stays
                                                       well-formed: the point is to change
                                                       what it CLAIMS).  The SCOPE control
                                                       survives the relaxation and points the
                                                       other way -- #313 scoped its guard to
                                                       hske-nla1, so `--algo hske` at a
                                                       narrow width must still behave as it
                                                       did, a relaxation that quietly widened
                                                       being as much a scope error as a guard
                                                       that did.  And BOTH COUNTS are
                                                       asserted independently, narrow
                                                       round-trips and refusals, so a loop
                                                       that stopped iterating or one port
                                                       losing a check cannot pass quietly.
                                                       Claimed by cross-lang-compat
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
  bitarray.json              — the BitArray conformance vectors (TODO #314 pass 1),
                               376 cases at widths 32/64/128/256 against BITARRAY.md.
                               ALL FOUR PORTS CONSUME THEM, 376/376 each: C
                               (pass 2, v9.1.0), Go (pass 3), Python (pass 4) and
                               JAVA (pass 5, v9.4.0), via
                               KAT/verify_bitarray_{c.c,go.go,py.py} and
                               herradurakex.VerifyBitArray -- the first three run
                               by CliTest/test_kat_vectors.sh, the fourth by
                               CliTest/test_java_bindings.sh, where the Java
                               toolchain is already built.  THIS IS NO LONGER A
                               CURRENCY CHECK: four
                               INDEPENDENT implementations against ONE pinned answer
                               is the cross-implementation check BITARRAY.md 7
                               describes, and it is what no round-trip or interop
                               test can supply -- those compare a port against
                               another port's OPINION.  C reads the generated header
                               while Go and Python read the JSON, so the three do not
                               share one input file; and the Python consumer's header
                               answers the obvious objection -- a Python consumer
                               checking a Python-generated vector is not circular,
                               because the reference is a SEPARATE class in the
                               generator written against the document, and the
                               consumer loads the SHIPPED suite through importlib and
                               never touches it.  While it
                               was one port, both BITARRAY.md 7 and
                               test_kat_vectors.sh said so out loud rather than
                               letting 376/376 read as more than it was -- #234's
                               vacuous pass is what a regenerate-and-diff of a
                               deterministic function against itself becomes if
                               nobody says what it does not prove.  TWO CASES CARRY
                               INTEGERS ABOVE 2^53 (to_uint's 7025791060798414911 at
                               n=64 and from_uint's 2^32 boundary), so a consumer
                               that decodes JSON numbers as float64 rounds one of
                               them -- nl_fscx_v3.json's hazard, met for the first
                               time by the Go consumer, which is why that one decodes
                               with json.Number.  It is NOT silent: the pinned answer
                               disagrees and the case fails.  Error cases pin an expected error CODE,
                               not a value (BITARRAY.md 5 makes the set closed and
                               identical in every port), so a port failing for the right
                               reason is distinguishable from one failing for the wrong
                               one.  Operands are STRUCTURED, not pseudo-random: a
                               rotation or a truncation that loses an octet is invisible
                               against a uniform operand and obvious against a patterned
                               one
  generate_bitarray_kat.py   — the reference implementation of BITARRAY.md, and the
                               generator for bitarray.json.  The reference lives in a
                               GENERATOR and not in a fifth shipped library on purpose:
                               #314's "what must NOT happen" is a fifth implementation
                               standing beside the four, and a generator is not shipped
                               and is linked by nothing -- the same standing
                               generate_kat.py already has.  Verified BEHAVIOUR-
                               PRESERVING before anything was built on it: it reproduces
                               the shipped C suite at n=256, the shipped Go package at
                               n=256, and the shipped Python suite at 32/64/128/256, on
                               xor/rol/ror/fscx/fscx_revolve/gf_mul/rnl_kdf_seed/
                               popcount, with zero mismatches -- so the contract is the
                               existing agreed behaviour with the width rules made
                               explicit, not a redesign.  --check (currency) GATES;
                               --report (per-port conformance) deliberately does NOT,
                               because an unconverted port is expected to diverge and
                               the Testing section below allows no failing test.  Both
                               controls verified to FIRE: a one-field edit to
                               bitarray.json makes --check exit 1, and flipping the
                               reference's truncation to LOW bits flips the report's
                               rnl_kdf_seed row from conforms to DIVERGES
  bitarray_vector.h          — GENERATED: bitarray.json transposed into C arrays, so
                               the dependency-free C tree needs no JSON parser
                               (hcred_kkw_vector.h's precedent, TODO #266).  A pure
                               deterministic transform, so --check verifies the header
                               and the JSON agree -- editing one without re-emitting
                               the other FAILS rather than drifting
  verify_bitarray_c.c        — the C conformance consumer for bitarray.json (TODO
                               #314 pass 2), compiled on demand by
                               CliTest/test_kat_vectors.sh.  Scores every case as pass
                               or fail and FAILS if the two do not sum to the case
                               count -- a case with no handler must not read as a pass
                               (#291's "a section that did not run must not be
                               scored", applied to a vector consumer)
  verify_bitarray_go.go      — the Go conformance consumer (TODO #314 pass 3), and
                               the SECOND independent implementation against the
                               pinned answer, which is the point at which the vector
                               becomes decisive.  Reads bitarray.json DIRECTLY --
                               encoding/json is in the standard library, so the
                               generated C view exists for the dependency-free C tree
                               alone -- with json.Number, for the >2^53 reason above.
                               Same not-scored-is-not-passed rule as the C consumer
  verify_bitarray_py.py      — the Python conformance consumer (TODO #314 pass 4),
                               the THIRD.  Loads the SHIPPED suite through importlib
                               as the SecurityProofsCode scripts do and never touches
                               the generator's reference class, which is why it is
                               not circular -- its header says so, because that is
                               the first thing to ask of it.  Same
                               not-scored-is-not-passed rule as the other two
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
                             typical of it, which is why #257 stays open.
                             ITS §4 ACCOUNT OF THE VALIDATION GAP IS WITHDRAWN
                             by quenched_exact_ladder.py: the arithmetic
                             stands, the "gap closes from the safe side" does not
  quenched_exact_ladder.py  — TODO #257's QUENCHED CHECK, by measurement rather
                             than proof (v9.5.24).  Exact mu was stuck at n = 11
                             on the differential axis because each graph was built
                             from a 2^(2n) DDT; enumerating each node's out-edges
                             from §11.38.1's carry-pair automaton costs (out-degree
                             x n) instead, so the FIXED round's exact minimum mean
                             cycle reaches n = 13, 14, 16, 17 (n = 19 is under
                             --full but no key completed: > 4.6 GB, > 30 min).  FINDING: the model's error is NOT
                             conservative.  exact/annealed falls 1.18 -> 1.04 over
                             n = 7..11, crosses 1 between 11 and 13, and is below 1
                             for EVERY sampled key at n = 14, 16 and 17 (~0.93 at
                             the median, the fall slowing).  So §11.38's n = 256
                             figures are an estimator of UNKNOWN sign, not a
                             conservative one -- the 36x margin is unsupported, not
                             lost (losing 4/3 needs a ratio near 1/36).  The keys
                             it over-states most have long RUNS of equal bits in
                             delta, where carries are near-deterministic and a
                             difference passes addition almost free: a property of
                             one fixed constant that an independent-edge ensemble
                             cannot see, i.e. the quenched effect itself.  At
                             n = 256 the same keys carry explicit two-round trails
                             under half a bit.  Fixed seeds throughout, so it
                             cannot flake.  Exits non-zero if a finding stops
                             reproducing.  ITS "FALL SLOWING" READING IS WITHDRAWN
                             by certified_cycle_ladder.py: at 8 keys n = 17 is 0.90
                             and the ratio goes on to 0.75 by n = 20
  certified_cycle_ladder.py — TODO #257's fourth pass (v9.5.25): exact mu on BOTH
                             axes to n = 20.  READ ITS CERTIFICATE BEFORE REUSING
                             THE SOLVER: it builds only the edges below a per-node
                             threshold W_u, solves that subgraph, then takes the
                             shortest-path potential p of w - mu' and raises W_u
                             wherever W_u < mu' - p(u).  When no node fails, p is
                             feasible on the FULL graph and the subgraph's mu is
                             EXACT, not an estimate; a negative control shows a
                             fixed small W with the loop off over-states mu on 13
                             of 18 keys and the test flags all 13.  Pruning inside
                             a row is sound because partial weight only grows (l1
                             norm of the linear carry vector; at most doubling of
                             the differential path count).  ~3-25 edges per node
                             where the full linear graph has ~2^n/3, so the linear
                             axis goes from n = 11 to n = 20.  FINDINGS: the ratio
                             to the annealed model does NOT settle -- differential
                             0.90 / 0.81 / 0.75 at n = 17 / 19 / 20, linear crosses
                             1 between 13 and 14 and reaches 0.82 -- but the EXACT
                             median mu/n is flat for eight widths (0.14-0.16 and
                             0.07-0.08), and within a width exact mu rises only
                             ~0.6 per unit of the model's lambda*.  So the model's
                             SLOPE is wrong, §11.38's n = 256 figures lose their
                             basis, and the reading that replaces them is the exact
                             slope: ~36 and ~18 at n = 256, ~27x both criteria --
                             a reading, not a bound.  n = 19 and 20 run under
                             --full only (~6 h, ~1 GB per n = 20 key).  Fixed
                             seeds, so it cannot flake.  Exits non-zero if a
                             finding stops reproducing.  ITS FLAT-SLOPE READING (and
                             the ~36 / ~18 / 27x it gave n = 256) IS WITHDRAWN by
                             exact_slope_ladder.py: it rested partly on a run-heavy
                             n = 20 sample
  exact_slope_ladder.py    — TODO #257's fifth pass (v9.5.26), and the reason the
                             previous one's reading did not survive.  Drives
                             certified_cycle_mean.c, the same certified solver in C
                             (~40x faster, in-place edge compaction), which §1
                             checks against the Python one on mu, edges kept AND
                             certificate rounds before any number is used; the C
                             reads the automaton tables from the Python sources on
                             stdin, so the two cannot disagree about what an edge
                             is.  The C IS the gate above n = 14, so no compiler is
                             a FAILURE, not a skip.  With 32-96 keys per width:
                             (a) exact mu rises with the RUN COUNT of delta (~0.13
                             per run differential, ~0.074 linear) and §11.41's n = 20
                             sample was run-heavy, so its "flat at 0.14-0.16" was
                             partly a sampling artefact -- at a typical run count the
                             differential per-bit median is ~0.15 at n = 13-14 and
                             ~0.13 at n = 19-23 (levelling or still falling: not
                             resolved); the linear one shows no trend beyond scatter;
                             (b) exact mu itself GROWS at every width step to n = 23,
                             ending at 2.2x / 2.4x the criteria; (c) the model ranks
                             keys right (corr 0.98) but credits each run ~0.21 where
                             exact mu gains ~0.12; (d) the keys converge (IQR/median
                             0.3 -> ~0.03-0.1).  So NO single n = 256 figure is
                             supported -- a power law reads ~13 / ~11 (10x / 17x), a
                             levelled per-bit median ~33 / ~17 (25x) -- and what is
                             measured is §11.37's monotonicity residue with ten
                             widths behind it.  --full reaches n = 22 and 23 (~5 and
                             ~8 GB per key; do not run two at once on a 16 GB host).
                             Fixed seeds, so it cannot flake.  Exits non-zero if a
                             finding stops reproducing
  certified_cycle_mean.c   — the C solver exact_slope_ladder.py compiles and drives;
                             standalone (no herradura.h), so tools/poison_build.sh
                             does not discover it and need not
  local_potential_certificate.py — TODO #257's sixth pass (v9.5.27): the first
                             route in #257 that would have been a PROOF at n = 256,
                             built and measured, and why it does not get there.  For
                             any phi, mu >= min over edges of w + phi(a) - phi(b);
                             with phi a sum of w-bit WINDOW functions that minimum is
                             a bit-position DP (the carry-pair automaton plus window
                             bits), linear in n, and the optimal phi is an LP (HiGHS).
                             READ §1 BEFORE REUSING THE DP: the weight is -log2 of a
                             path COUNT, so the DP keeps the carry SLOT and merges by
                             componentwise max (sound, measured close); dropping the
                             slot gives mu = 0 on every key, the negative control.
                             FINDING: the window it needs to reach mu GROWS with n
                             (median w* = n-1, n-2, n-3 at n = 7, 8, 10, ~0.7n), and
                             at a fixed window the certified share of mu FALLS
                             (0.94 -> 0.70 over n = 8..14 at w = 5), the bound itself
                             lower at n = 13-14 than at 10-11 while mu is not.
                             The LP dual says why: a distribution of LIGHT edges
                             whose local window statistics balance stands in for a
                             cycle, and it never sees M grow the support.  Needs
                             highspy, which IS the gate, so absent means FAIL.
                             Fixed keys and a deterministic LP, so it cannot flake.
                             ITS "AT A FIXED WINDOW IT DOES NOT GROW" IS NOW MEASURED
                             TO n = 256 by local_certificate_n256.py
  local_certificate_n256.py — TODO #257's seventh pass (v9.5.28): the sixth pass's
                             certificate SOLVED at the deployed width instead of
                             extrapolated.  READ §1(d) AND THE solve() DOCSTRING
                             BEFORE REUSING THE SOLVER: the LP is built by
                             constraint generation from exact edges (no graph is
                             listed), and it needs BOTH separators -- the sound DP's
                             back-pointer traces and an exact single-carry-path
                             Viterbi -- because the Viterbi alone under-counts the
                             edges with many carry paths and OVERSTATES the LP (its
                             potential certifies ~0.1 where the optimum is ~1); the
                             potential's box must grow in stages or the DP's traces
                             stop naming violated edges.  One SHARED table
                             F[a-window][delta window] costs 2-7% of the LP against
                             a table per position and keeps it one size at every
                             width; above n = 48 the LP is too slow (rows grow faster
                             than n) and a supergradient ascent finds F.  Whatever F
                             is, the DP's bound is a theorem, so the 16 tables are
                             PINNED in local_certificate_n256.json (16 x 16 numbers
                             each) and §4 re-verifies them from scratch.  FINDINGS:
                             non-local additions at small n (popcount/run-count
                             tables, two-round paths) buy 0.03-0.07 and the share
                             still falls; solved per width the bound peaks near
                             n = 20 (~1.5) and sits at ~0.6-0.8 from n = 64 to 256
                             while exact mu grows ~0.14 per bit; at n = 256 four keys
                             get mu >= 0.54 / 0.58 / 0.74 / 0.90 -- the first NONZERO
                             lower bound at the deployed width, every one BELOW 4/3.
                             A table solved at n = 24 and carried to n = 256 is
                             negative on every unseen key: solve per key, at the
                             width.  Needs highspy and a C compiler (both FAIL when
                             absent).  --regenerate rebuilds the pins (~1 h)
  local_certificate_dp.c   — the C helper local_certificate_n256.py compiles and
                             drives over a pipe: the sound DP with traces and the
                             Viterbi.  Standalone (no herradura.h), like
                             certified_cycle_mean.c
  local_certificate_n256.json — the pinned certificates: one 16 x 16 table per key at
                             n = 64, 96, 128, 192 and 256, and the bound each gives
  hull_exact.py            — TODO #257's eighth pass (v9.5.29): the LINEAR HULL, which
                             all seven earlier passes carried forward as "unreached",
                             MEASURED -- exactly, for the shipped round WITH #245's round
                             constants (they only flip a trail's sign, so every trail
                             measurement was blind to them and the hull is not).  For a
                             fixed key the r-round map is built as a table and its whole
                             correlation and difference tables are scanned: no trail, no
                             independence, no key averaging.  Beside it the best r-round
                             trail and the same scan over random permutations (the
                             floor).  READ THE NOTE ABOVE `PRE` before changing what "at the
                             floor" means: a fixed band around the median floor flagged
                             nine keys that were inside the random spread, because small
                             tables are coarsely quantised -- "at the floor" is "no worse
                             than the worst of 32 random permutations".  FINDINGS:
                             clustering is real and it is a SHARE of the trail weight
                             that FALLS -- median 0.91 -> 0.82 (linear) and 0.97 -> 0.90
                             (differential) over n = 10..16, ~-0.011 per bit, worst key
                             0.71 -- and it costs about ONE ROUND to the ideal floor at
                             every width.  Seven cells are LATE, not stuck (each at the
                             floor by 3n/4 + 2).  A first draft read n = 10-14 as "no
                             trend" and carried a FIXED factor to n = 256; --full's n = 16
                             withdrew that, so the hull is NOT carried to 256 -- a line
                             through the medians eats the n = 23 exact-mu margin near
                             n = 50, recorded as a question.  Cost is n * 4^n per round:
                             n = 14 by default, 16 under --full (~80 min).  Needs a C
                             compiler (absent means FAIL)
  hull_exact.c             — the C helper hull_exact.py compiles and drives: the r-round
                             table, both hull scans and both trail DPs.  Standalone (no
                             herradura.h), like certified_cycle_mean.c
  live_region_certificate.py — TODO #257's ninth pass (v9.5.30): where the optimal cycles
                             PAY, and why telling the local certificate does not help.
                             A LIVE-REGION LEMMA, exhaustive: addition with a constant
                             keeps a difference's LOWEST active bit (a mask's HIGHEST,
                             on the linear axis) and M moves it one bit per round or
                             resets it at the wrap, so every cycle must reset.  Every
                             optimal-cycle edge split bit by bit (an exact chain-rule
                             decomposition): the cost sits at delta's RUN BOUNDARIES,
                             about one bit above each, delta's trailing zeros are never
                             paid for, and mu per boundary (~0.31 / ~0.15) FALLS as
                             boundaries crowd -- a description, not a figure for 256.
                             Then the window LP is given features of the live region,
                             and READ ITS CONTROL BEFORE TRUSTING A FEATURE: a RANDOM
                             labelling with the same number of classes ties the two
                             n-class features and beats every richer one, because at
                             small n extra classes let the LP approach a value per node,
                             which IS mu -- an anchored feature reached 1.000 at n = 8
                             with 4096 classes for 256 nodes.  So the local-potential
                             route (sixth, seventh, ninth passes) is CLOSED.  Needs a C
                             compiler and highspy (both FAIL when absent)
  width_lift_closure.py    — TODO #257's tenth pass (v9.5.33): two cycle-level routes that
                             need no potential, both CLOSED.  (1) An UPPER bound by
                             construction -- the only kind that could refute one of
                             §11.42's two n = 256 readings (~13, ~33): iterate the
                             cheapest-edge map (best-first over the carry automaton,
                             checked against the certified solver's rows) until it
                             closes.  Sound, but it closes like a random mapping (rho
                             grows ~0.48 bits per bit over n = 14..26, so ~2^120 steps
                             at 256), and where it closes it is ~1.5x loose.  (2) The
                             LIFT between widths that §11.37's "no embedding" missed:
                             it is true of graphs, not keys -- stretching a run of delta
                             by one bit is a natural map n -> n + 1.  Exact mu is NOT
                             monotone along it (falls on ~25% of lifts, both axes,
                             n = 13 and 16), and what sets the sign is the RUN LENGTH:
                             a length-1 run adds 0.17-0.19 (differential), a run of
                             length >= 3 ~0.  Width without a boundary adds no cost, so
                             what #257 owes is a DISTRIBUTIONAL statement about boundary
                             count at density 1/2, not a pointwise one.  Drives
                             exact_slope_ladder.py's C solver (no compiler means FAIL)
  coupled_width_increment.py — TODO #257's eleventh pass (v9.5.34): the distributional
                             monotonicity the tenth pass re-stated #257 as owing, MEASURED
                             by an EXACT COUPLING.  A uniform bit inserted at a uniform
                             position of a uniform delta is uniform one width up, so
                             E[mu_{n+1}] - E[mu_n] is a mean of PAIRED differences --
                             checked exhaustively, not argued -- and pairing cuts the
                             standard error ~4x against the independent ladders every
                             earlier pass used.  FINDINGS: E[mu] rises at EVERY step from
                             n = 4 to 17 on both axes while single pairs fall on up to
                             half of all draws; single steps are NOT stationary on the
                             differential axis (a period-3 term, M's singular widths).
                             TWO CLAIMS OF ITS FIRST RELEASE ARE WITHDRAWN by
                             period_exponent.py: "flat from n = 10" per period (with
                             the ~32 / ~18 it read for n = 256) and the linear
                             non-stationarity -- both rested on errors that ignored the
                             clustering of insertions by key, now corrected (1.4-1.6x
                             larger; the weakest step, differential 16 -> 17, clears 0 at
                             3 sigma by +0.009).  ALSO FIXED A HANG in the solver it drives: SPFA in
                             certified_cycle_mean.c and certified_cycle_ladder.py ran on
                             w - mu' with Howard's mu' rounded as sum / length, so on
                             n = 17, delta = 0x1f6ef the optimal cycle was a NEGATIVE cycle
                             to SPFA (< 1e-11) and it never terminated; every fixed seed
                             before had missed such a key.  Both run SPFA at mu' - 1e-9
                             now, with a relaxation budget that turns a real negative
                             cycle into an error.  Needs a C compiler (absent means FAIL)
  period_exponent.py       — TODO #257's twelfth pass (v9.5.35): the per-period increment
                             of E[mu] RESOLVED, and the eleventh pass's "flat from n = 10"
                             WITHDRAWN.  Two corrections: errors CLUSTERED BY KEY (the m
                             insertions into one delta share mu(delta)), and one THREE-BIT
                             insertion per pair, since the coupling is exact for any k --
                             a whole period is one paired draw, checked exhaustively -- plus
                             a CONTROL VARIATE (change in run count) whose mean is EXACT,
                             the two excluded degenerate deltas corrected for and checked
                             against brute force.  FINDINGS: P(n) = E[mu_{n+3}] - E[mu_n]
                             FALLS on both axes, the 10 -> 13 local exponent 3.5-4 sigma
                             below a levelled rate in a ~8000-pair replication (~-0.23
                             differential, ~-0.18 linear; only the differential one is
                             SCORED, the gate's own sample putting linear at 1.9 sigma),
                             so §11.42's higher n = 256 reading (~33 / ~17) loses its
                             premise -- and the power law is NOT confirmed either: the
                             differential exponent drifts from -0.55 to -0.23 across two
                             adjacent intervals, so the decline is slowing.  The scored
                             check is the levelled rejection; the power-law distance is
                             printed, not scored.  Drives exact_slope_ladder.py's C solver
                             (no compiler means FAIL)
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
SecurityProofs.md                                   — split index (redirects to Parts 1–10; quantum analysis is in SecurityProofs-2.md §6)
SecurityProofs-1.md                                 — §1: Algebraic Foundations (300 math expressions)
SecurityProofs-2.md                                 — §2–§8: Protocol Analysis · Security Analysis · Summary Tables · Quantum Attack Analysis · Experimental Code Index (409 math expressions)
SecurityProofs-3.md                                 — §9–§10: Non-Linear Proposals · v1.4.0 Migration (409 math expressions)
SecurityProofs-4.md                                 — §11–§11.8.2: Non-linearity/PQC extensions · NL-FSCX v1/v2 · HKEX-RNL (693 math expressions)
SecurityProofs-5.md                                 — §11.8.3–§11.8.10: PQ signature options · HPKE-Stern-KEM (672 math expressions)
SecurityProofs-6.md                                 — §11.9: HFSCX-256-DM (131 math expressions)
SecurityProofs-7.md                                 — §11.10–§11.13, §11.15–§11.33: ZKP extensions · Ring-LWR Σ-protocol · NL-FSCX ZKBoo · research-review sections (698 math expressions)
SecurityProofs-8.md                                 — §11.34–§11.36: NL-FSCX v3 exact row analysis · the asymptotic differential and linear slopes, measured (435 math expressions)
SecurityProofs-9.md                                 — §11.37–§11.42: the width residue #252 and #254 shared · the annealed threshold, evaluated exactly at n = 256 · the pair correlation, which closes #257's second-moment item · the quenched check, where exact mu to n = 17 crosses below the model · the certified ladder, exact mu to n = 20 on both axes, where the ratio keeps falling · the exact slope with 32-96 keys per width, not flat but still growing to n = 23 (726 math expressions)
SecurityProofs-10.md                                — §11.43–§11.49: the local certificate, a sound lower bound on mu at any width whose window must grow with n · the certificate SOLVED at n = 256, positive (0.54-0.90) and below 4/3 · the linear hull MEASURED exactly to n = 16, a share of the trail weight (0.91 -> 0.82 linear) that falls slowly with width and costs about one round · where the optimal cycles PAY, at delta's run boundaries, and the local-potential route closed by a random-labelling control · two routes without a potential, both closed: no upper bound on mu(256) by search, and no monotone lift between widths · the coupled ladder, an exact pairing between widths under which E[mu] rises at every step from n = 4 to 17 on both axes, and the period exponent, which resolves the per-period increment FALLING on both axes and so rejects the levelled n = 256 reading without confirming the power law (90 math expressions)
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
                                                      primitives -- 202 entries, four cells each --
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
                                                      parameter's VALUE: 85 rows, four cells each,
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
                                                      and what compares them.
                                                           measure_sampled_rates.py is the
                                                      INSTRUMENT for the ninth axis's
                                                      derived rates (TODO #320), and the
                                                      one file here that CI does NOT run.
                                                      check_language_parity.py's
                                                      _RATE_MECHANISMS records, per derived
                                                      formula, the MECHANISM it rests on as
                                                      a per-trial witness predicate plus the
                                                      ALTERNATIVE a frequency check could
                                                      not exclude, and the measurement that
                                                      settled it; this script re-runs that
                                                      measurement.  It is separate and
                                                      unwired on purpose: hundreds of trials
                                                      per rung is #289's runtime problem in
                                                      miniature, and a validation that
                                                      itself decides on a fresh sample is
                                                      #299's defect one level up -- so
                                                      #304's model applies, the token and
                                                      the numbers recorded and the runner
                                                      not re-measuring.  It is NOT in
                                                      SecurityProofsCode/, so
                                                      run_findings_gates.py cannot discover
                                                      it and no NON_GATING entry has to
                                                      argue it away.  Its own exit status
                                                      rests on the WITNESS, which is exact,
                                                      so it cannot flake on its own account;
                                                      the frequency is corroboration, banded
                                                      at 6 sigma.  What the checker enforces
                                                      statically is that the record and the
                                                      expression cannot drift apart: the
                                                      validated term must still be a
                                                      SUBSTRING of every covered row's
                                                      formula, each rung's prediction must
                                                      EQUAL that term evaluated there, and
                                                      the reduced parameter must stay
                                                      STRICTLY BELOW every port's shipped
                                                      value of the same variable -- the
                                                      variable and not the rate, since [45]
                                                      carries a trials multiplier.
                                                      SINCE TODO #321 IT ALSO MEASURES THE
                                                      ARGUED HALF, the rows with no formula
                                                      to be the wrong function of:
                                                      _EXACT_BASES makes every `exact` row
                                                      state why its rate is ZERO and what
                                                      holds at the parameters the suite
                                                      DEPLOYS when the test does not run
                                                      there, and _ARGUED_MEASUREMENTS backs
                                                      the one that rests on an inequality
                                                      with a measured SLACK.  Two shapes,
                                                      because a margin is not a rate: a
                                                      margin rung records (trials, min,
                                                      mean, adverse) and a rate rung
                                                      (trials, events, predicted), and
                                                      collapsing them would mean counting
                                                      the margin's sign -- the 0/N that
                                                      item exists not to produce.  The
                                                      DEPLOYED block is held to every port's
                                                      source, which is rule (3) INVERTED:
                                                      there the reduced parameter had to
                                                      stay strictly below what ships, here
                                                      the top rung IS the claim and must
                                                      EQUAL it, so #223 moving RNL_N or
                                                      RNL_P again fails the record rather
                                                      than aging it.  SINCE TODO #322 IT
                                                      ALSO MEASURES REFUTATIONS -- a THIRD
                                                      kind, because a refutation is not a
                                                      rate either: its ladder counts the
                                                      CONFOUNDER rather than the event,
                                                      since the event is what must never
                                                      happen while the confounder must, and
                                                      a rate rung demanding events > 0
                                                      would reject exactly the shape this
                                                      records.  Its shipped rung is the
                                                      CLAIM, as a margin's deployed rung is;
                                                      the reduced rungs exist only to make
                                                      the confounder frequent enough to be
                                                      put to the verifier more than once.
                                                      `--only rejection` runs that half
                                                           The ninth axis's CORPUS is stated
                                                      in the file since TODO #323, and it is
                                                      six harnesses rather than four.  Parts
                                                      1/7-6/7 read
                                                      Herradura_tests.{c,go,py} plus
                                                      SelfTest.java; Part 7/7 adds the three
                                                      REDUCED harnesses --
                                                      Herradura_tests.{s,asm,ino} -- which
                                                      appeared nowhere in spec/ with no
                                                      sentence saying why.  They are not
                                                      inert: ARM and NASM reseed their LCG
                                                      from /dev/urandom before test [1], both
                                                      carry [10] (a drawn random forgery, all
                                                      20 of which must be REFUSED) and [18]
                                                      (the v2 weak-key guard), and `arm-i386`
                                                      and `arduino` are as BLOCKING as
                                                      `native-c`.  Two things to know before
                                                      extending it.  The screen reads each
                                                      test's TITLE as well as its body, which
                                                      inverts #322's remedy: in assembly the
                                                      title is in .rodata ~760 lines from the
                                                      body and the body's only rejection
                                                      wording is a comment the screen strips,
                                                      so a body-only screen MISSES [10] in
                                                      both assembly ports -- demonstrated by
                                                      reverting the screen, not argued.  And
                                                      the entropy status is DERIVED per
                                                      harness and cross-checked both ways,
                                                      because Arduino never reseeds (an AVR
                                                      has no source and simavr supplies none),
                                                      so its flake rate is exactly ZERO and
                                                      the same [10] is rated in two harnesses
                                                      and exact in the third -- a harness
                                                      recorded `fixed` is FORBIDDEN a rated
                                                      basis.  The basis vocabulary is Part
                                                      5/7's nine kinds, shared rather than
                                                      duplicated, and [10]'s rate is computed
                                                      rather than assumed: g = 3 generates an
                                                      index-15 SUBGROUP of GF(2^32)*, so the
                                                      rate is 20/286331153 and not 20.2^-32.
                                                      Deliberately NOT ported here: the draw
                                                      detector and #318's verdict
                                                      fingerprints, a fingerprint over
                                                      verdict-bearing LINES being a cmp/branch
                                                      pair in assembly rather than a string
SPEC.md                                              — human-readable prose companion to
                                                      spec/herradura-protocol-spec.json
BITARRAY.md                                          — the NORMATIVE BitArray specification
                                                      (TODO #314).  One variable-width
                                                      bit-string type — big-endian octet
                                                      string with the width carried WITH the
                                                      value — to replace the three embedded
                                                      bignum types (math/big, Python int,
                                                      java.math.BigInteger) three of the four
                                                      ports delegate to.  READ 3 FIRST if you
                                                      touch any width-taking code: every
                                                      binary operation REQUIRES equal widths
                                                      and a mismatch is E_MIXED_WIDTH, never
                                                      a coercion.  That clause is the one all
                                                      four ports got wrong when the item was
                                                      filed, and in four different ways — Go
                                                      silently returned ALL ZEROS (Xor did
                                                      not mask, so an over-wide Val made
                                                      Bytes() copy nothing), Python silently
                                                      DISCARDS the other operand, and C and
                                                      Java could not pose the question at
                                                      all.  C and Go report it now; 6 keeps
                                                      the measured defects because a fixed
                                                      defect nobody can still read about is
                                                      one nobody learns from.  4.4 settles
                                                      TODO #313's split: truncation takes the
                                                      HIGH bits, the big-endian PREFIX, which
                                                      is the representation-natural rule and
                                                      is what Python and C's own declared
                                                      narrow constants already say — Go's
                                                      low-octet slice is the outlier, and its
                                                      rule was MEASURED rather than read.
                                                      Status: ALL SIX PASSES ARE DONE --
                                                      C (pass 2, v9.1.0), Go (pass 3), Python
                                                      (pass 4), Java (pass 5, v9.4.0), and
                                                      PASS 6 (v9.5.0), which RELAXED TODO
                                                      #313's refusal: `hske-nla1` is accepted
                                                      at every width 2 permits and all four
                                                      CLIs agree octet for octet at 32, 64,
                                                      128 and 256.  8
                                                      tabulates the six passes, 8.1 records
                                                      what pass 3 cost OUTSIDE the type, 8.2
                                                      what pass 4 measured that the others
                                                      could not, 8.3 what pass 5 bought
                                                      that they could not and 8.4 WHAT PASS 6
                                                      FOUND -- two ports that passed the
                                                      376-case vector and still produced the
                                                      wrong keystream below 256, because
                                                      conforming to the TYPE is not the same
                                                      as CONSUMING it at the value's width; 9
                                                      records the C
                                                      type decision the item demanded be made
                                                      in the item rather than in review — it
                                                      is source-compatible, because the FFI
                                                      ABI is flat byte buffers that never
                                                      name BitArray and herradura.h is
                                                      header-only, so no ABI boundary for the
                                                      type exists.  GO's is NOT: Val was an
                                                      exported field and GfMul/GfPow/GfPoly
                                                      took a poly and a width the type now
                                                      carries, so the package API moves and
                                                      all six in-tree consumers move with it
                                                      — a Go PACKAGE change, not a CLI/PEM/
                                                      wire one, hence MINOR.  Assembly and Arduino are
                                                      OUT OF SCOPE by design and stay fixed-
                                                      width
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
                                                      now a 4x4 matrix rather than 9-way.
                                                      FOUR ENTRY POINTS, and the fourth is new
                                                      (TODO #333): SelfTest (asserts, [1]-[35]),
                                                      Demo (walkthrough, [FAIL]-gated),
                                                      KatVerify/VerifyBitArray (vector
                                                      consumers) and BENCH -- the port's first
                                                      timing code of any kind.  Before v9.5.23 a
                                                      grep across the whole port for `bench`,
                                                      `throughput`, `ops/sec` or `nanoTime`
                                                      returned ZERO matches, in a port that
                                                      ships the deployed KEM and whose job is
                                                      REQUIRED, so check_rate_format.py held
                                                      three formatters in a four-port repo.
                                                      Bench carries [36] (the deployed QC-MDPC
                                                      KEM, Java's counterpart of C/Go/Python's
                                                      [54]) with a CONTROL that gates its exit,
                                                      `-r`/`-t` + HTEST_ROUNDS/HTEST_TIME, a
                                                      batch DERIVED from a warm per-call probe
                                                      rather than C's eight hand-picked
                                                      constants (#327), and a printed warmup
                                                      count, because the first decapsulation on
                                                      an SBC costs 5.7x the warm one and a
                                                      figure whose warmup is unstated is not a
                                                      figure.  Java's [1]-[36] therefore spans
                                                      TWO files and
                                                      spec/check_language_parity.py's
                                                      NUMBERED_TEST_FILES reads both
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
                                                      cost figures do not belong in CI.  THAT
                                                      SENTENCE WAS EXACT ABOUT THE WRONG OBJECT
                                                      until TODO #329: it is right about the
                                                      NUMBERS and was silent about whether these
                                                      files still COMPILE, and nine of the
                                                      eleven executables in this directory had
                                                      no runner at all -- rnl_ring_cost.py had
                                                      been exiting 1 on E_WIDTH since v9.3.0 and
                                                      the three FFI-consuming compare_*.py
                                                      aborted with rc=134 against the shim #324
                                                      fixed.  So the .go is BUILD-ONLY in CI
                                                      (building asserts nothing about a rate,
                                                      which is why #292's position survives),
                                                      rnl_ring_cost.py runs --quick (1 alone;
                                                      2/3 are #225's cap audit and exceed
                                                      600 s), and tools/check_runnable_coverage.py
                                                      fails if a new executable here is
                                                      unclaimed;
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
and `highspy` are the documented exceptions, for the reasons in their rows (TODO #290,
TODO #257's sixth pass).

| package | used by | absent ⇒ | install |
|---|---|---|---|
| `jsonschema` | `spec/generate_spec.py` schema validation | NOTE, but CI passes `--require-schema` so a skipped validation cannot pass | `pip install jsonschema` |
| `z3-solver` | `SecurityProofsCode/nl_fscx_exact_trail_search.py` (TODO #214), `fscx_periodicity_z3.py`, `hpks_schnorr_z3.py` | **the gate FAILS** — those last two are z3 from top to bottom, so there is no section left to skip and a printed NOTE plus exit 0 would report a finding as reproducing that was never checked.  All three print the install line and exit non-zero; CI's `analysis-findings` job installs the package for exactly this reason (TODO #290) | `pip install z3-solver` |
| `pulp` (CBC) | `SecurityProofsCode/nl_fscx_v2_bounds.py` §(d) MILP bounds (TODO #247) | section skipped | `sudo apt-get install -y python3-pulp`, or a venv: `python3 -m venv ~/.venvs/herradura-milp && ~/.venvs/herradura-milp/bin/pip install pulp` |
| `highspy` | the same §(d) model under a stronger backend (TODO #252 §11.35.6); and `SecurityProofsCode/local_potential_certificate.py` / `local_certificate_n256.py` / `live_region_certificate.py` (TODO #257, sixth, seventh and ninth passes), where every bound is an LP optimum | in `nl_fscx_v2_bounds.py`, CBC is used instead and reaches one round fewer; in `local_potential_certificate.py`, `local_certificate_n256.py` and `live_region_certificate.py` **the gate FAILS**, on z3's reasoning -- the solver is the whole gate, so there is nothing left to skip.  CI's `analysis-findings` job installs it beside z3-solver | `pip install highspy` (pulls in numpy), or `~/.venvs/herradura-milp/bin/pip install highspy` (PuLP finds it as the `HiGHS` solver) |

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

`docker build -t herradurakex .` builds a quickstart image (TODO #139) covering
FIVE of the suite's seven language targets — C/Go/Python/ARM Thumb-2/NASM i386.
**Two are excluded on purpose and both reasons are now CHECKED** rather than merely
written (TODO #326): Arduino needs `arduino-cli` plus a board target, so it is not a
host-portable build; and JAVA is omitted because the image installs no JDK, which
this sentence did not say for 437 commits while the Dockerfile advertised a language
count it did not build. `docker-entrypoint.sh` builds every included target and runs
a smoke test (the C/Go/Python/ARM/NASM security test suites plus a CLI interop test)
on container start — **~75–90 min on an ARM SBC**, measured, where its own header used
to say "several minutes". `HERRADURA_SMOKE_ROUNDS` / `HERRADURA_SMOKE_TIME` cap it
without changing the shipped defaults. The `docker` CI job builds the image and runs
the entrypoint at reduced caps, and `tools/check_docker_mirror.py` holds the script
and `ci.yml` against each other in both directions.

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

One hazard to know before adding an assembly test: their Stern-F runs at `rounds=4`, so a
*Stern* rejection test written there would carry a `(2/3)^4` = 19.75% soundness error per
trial — five times worse than the `rounds=8` that made C's [45] fail 38.5% of runs. Give it
its own round count. That warning stands and is unviolated: `[11]`–`[14]` are completeness
checks, each requiring all 3 trials to pass. **This paragraph used to open by saying those
harnesses "assert *correctness* only, never *soundness*", and TODO #323 withdrew that half
as false** — `[10] HPKS-NL Eve resistance: random forgery rejected (20 trials)` requires all
20 of a drawn `s_fake` to be refused, and `[18] v2_weak_key_reject` is a weak-key guard, in
all three harnesses, today. A sentence about what a body of code asserts, contradicted by
that code, is #295's false-reason shape aimed at this section; the rejection assertions are
now screened and rated rather than described.

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
jobs on every push/PR, **all twelve required/blocking** since TODO #317 promoted
`analysis-findings` (the last one on probation — see below): `native-c`, `native-go`, `native-python`
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
findings-gating `SecurityProofsCode/` script, via `run_findings_gates.py`; ran
`continue-on-error: true` on the `arduino` job's TODO #185 route until TODO #317
promoted it). Locally, run the same scripts by hand as described below.

**The findings gates, and why they are a job rather than a step (TODO #289).** 86
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
as well, deliberately. That was first justified by this job not yet being required; TODO
#317 made it blocking, so the reason now is defense in depth (TODO #336): they are the two
gates #285 and #286 found broken and the ones the deployed KEM's parameters rest on, so they
fail the language job a QC-MDPC change most directly touches, not only this one.

**And which scripts GATE, which is the prior question (TODO #291).** #289 and #290 both
answer "which of the gating scripts run"; nothing asked how many scripts gate at all.
The answer was **35 of 81**: 46 produced output no exit status carried, 33 of them cited
by `SecurityProofs-*.md` or `CLAUDE.md` as backing a claim, and **22 computed a PASS/FAIL
verdict and discarded it** — TODO #233's defect class one layer out, in the layer that
backs the security documents rather than the one that tests the code. It is now **86
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
follow the statistic, and no census existed — TODO #316 is that census.

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
`[53]`'s rounds = 12, one run in 130, in all four ports, and 2.3e-6 at
`stern_f_weight_binding.py` §1's rounds = 32 — and **1.5e-3 at the rounds = 16 CI actually
ran**, because §1's new 64-round default was never reached: `main()` passed the `--quick`
round count straight into it, and that fired in CI before TODO #337 fixed the call site. Measured: 3 acceptances in 400 trials, 3
no-`b=0` strings, the same 3. The remedy is the one this section already prescribes — **give
it its own round count** — which is what #234 did to `[45]` at 38.5% and what the standing
warning about a rounds = 4 Stern-F rejection test is about; `[53]`'s forgery sub-check now
signs at 64 rounds and the ring half keeps 12, having no soundness error. **The lesson is
that the two hid each other**: at a combined ~7.0% per run nobody asks which of the two
coins landed badly, and the second only became visible once the first was gone. When a test
turns out to be a sampled gate, the question is not "what is its rate" but "how many terms
does its rate have".

**And which NUMBERED TESTS decide a verdict from a fresh sample, which #310 asked and
left open (TODO #316).** #300 put that question to the 76 findings gates and found three
defects; #310 found `[53]` failing about one run in 16, fixed it, and recorded that nobody
had asked it of the numbered tests — which matters more, because these live in the four
REQUIRED `native-*` jobs where a flake is a red check on somebody else's PR. **184
numbered tests across the four languages decide a verdict from a fresh sample**, all of
them now recorded in `spec/check_language_parity.py`'s `_TEST_DRAWS`, with 20 carrying a
curated verdict code and a rate or an argument, 9 declared to draw nothing that reaches a
verdict, and a summed false-failure rate of 1.0e-5 against a JOB-level budget of 1e-4 —
job-level because #300's own first draft picked a per-gate 1e-6 and then flagged three
gates at 1.2e-6, a defect only against an arbitrary line. Five things carry forward. (1)
**THE DEFECT WAS A CRASH, NOT A `[FAIL]`.** Python's `[17]` Eve-forge claimed
`fake_chal = [0]*8`; the verifier recomputes the Fiat-Shamir challenge and rejects at the
first round that disagrees, so the `b = 0` branch was reached at `(1/3)^8` = 1.5e-5 — and
there it unpacked a `BitArray` where a real response carries an int and raised an uncaught
`TypeError` that aborted the whole harness. Measured 0.342 / 0.118 / 0.0130 / 0.0000 of
2000 attempts at rounds 1/2/4/8 against `(1/3)^R`. The fix REMOVES the sampling instead of
shrinking it (#310's rule: construct, do not hope) — typed correctly the verifier runs that
branch and rejects on the merits, so the check now exercises what it used to crash through.
`[22]` is the SAME mechanism at 16 rounds, i.e. 2.3e-7, so **the round count is the whole
distance between the two** and by eye they look equally safe. (2) **ONE TEST, FOUR PORTS,
FOUR DIFFERENT ANSWERS, none right.** `rnl_sigma_sign` gives up after 1000
rejection-sampling attempts — a legitimate signer outcome — and `[21]`/`[30]` scored it as:
Python, decrement the denominator (so an all-exhausted run prints `0/0 [PASS]`); C and Go,
`N = i + 1` (so ANY exhaustion FAILS the build); Java, `fails++` **directly below a comment
saying a null proof "is reported rather than counted as a verify failure"** — #295's
false-reason finding aimed at a test instead of a constant, which no checker here can see.
All four now follow #291's rule that a section which did not run must not be scored. (3)
**THE DETECTOR HAD TO BE VALIDATED AND FAILED THREE TIMES, always leniently.** A Go pattern
matching `randBA` and `crypto/rand` saw 32 of 53 tests drawing; adding `NewRandBitArray`,
`mrand.` and `mrand.Read` made it 49. C's spellings had to be ENUMERATED from source after
`bn_rand_n` sat two lines under `[15]`'s header and read as no draw. And **the marker is
not in the same place in all four** — C, Go and Python print their header first, but Java's
is the TRAILING `println("PASS [N]")`, so slicing Java forward reported `[35]` as drawing
nothing with `Stern.sternFKeygen(rng)` inside it. An under-matching detector makes the
completeness rule pass vacuously, which is #295's rule that the LENIENT direction is the
dangerous one. (4) **THE TABLE'S SHAPE WAS DECIDED BY MEASURING, not designed.** A cell per
(test, port) was the plan; ~50 of each language's 53 tests draw, so that is ~200 rows whose
majority would read "exact: a round-trip". #296 met this exact wall — "there are 109, and a
hundred prose reasons rot" — so the completeness half is a DERIVED SET and prose is spent
only where a verdict departs from the default. (5) **`[18]` IS THE ROW TO COPY.** A weight-2
code of length 32 is not uniquely decodable and that line reported `[FAIL]` on 7.4% of runs
until #233 SEPARATED the ambiguous-syndrome branch from the failure branch and scored only
the latter. That is how a probabilistic subject gets an exact verdict — prefer it to
widening a threshold, which is #234's vacuous pass waiting to happen.

**And a test that changes HOW it decides, which is the hole #316's own table left (TODO
#318).** #316 catches a numbered test that starts DRAWING fresh entropy. Nothing caught one
that starts DECIDING on a threshold: `_TEST_DRAWS` records which tests draw and
`_SAMPLED_TESTS` is curated, so `if mean > 0.9:` added to any of the ~160 already-drawing
tests with no curated row left every check green — verified before building anything, since
the checker read no verdict expression at all. Four things carry forward. (1) **THE OBVIOUS
DESIGN WAS THE WEAKER ONE.** A threshold detector cannot see the cases that matter most:
`[17]`'s defect was a `(1/3)^rounds` term with no numeric literal in its verdict, and so are
`[45]`'s `(2/3)^32` and `[22]`'s `(1/3)^16` — the three largest terms in #316's budget, all
invisible to it. And it needs every spelling of "this line decides", an enumeration that
went wrong THREE times in this item alone (Go's `verdict := "PASS"` and `status := "FAIL"`,
C's `[19]` deciding via `puts("  FAIL: empty"); pass = 0`). #306's sixth-spelling hazard,
met yet again. (2) **SO THE VERDICT REGION IS PINNED INSTEAD** — a hash over every
PASS/FAIL-bearing line of each of the 197 tests, comments excluded — which needs no
threshold theory and covers the non-syntactic terms: an edit to a test's WORK does not fire,
an edit to its VERDICT does. (3) **`"none"` IS A PINNED VALUE, not an absence.** 36 rows have
no verdict line (the benchmarks, plus Go's `[52]`, whose verdict is in a helper), so a
benchmark that GROWS a verdict fires — the direction #300 found
`qcmdpc_bgf_failure_rate.py` in, discovered and run every CI run for eleven items and unable
to go red. (4) **THE FALSE-POSITIVE CONTROL IS AS LOAD-BEARING AS THE THREE THAT FIRE.**
Editing a comment that mentions FAIL changes nothing, which is what keeps this from rotting
into the noise that trains people to re-generate without reading. **Known limit, stated**: it
sees that a decision changed, never what the new decision means — `[45]`'s rate lives in
`SDF_ROUNDS`, which the fingerprint does not contain, so a change there moves the real rate
and fires nothing here. That is `PARAMETERS`' axis, and folding it in would converge on
completeness again. **TODO #319 closed that limit**, and found on the way in that the
constant is not where this paragraph says it is in two of the four ports.

**And the rate that moves when a parameter moves, which is the limit #318 stated on
itself (TODO #319).** #316 gave every sampled numbered test a verdict code with a DERIVED
RATE or a stated ARGUMENT, and #318 pinned each test's verdict region by fingerprint.
Neither covers the case where **the decision is unchanged and the rate underneath it
moves**: a rate was a LITERAL and its formula was prose, so the arithmetic was checked by
nobody and its inputs by nobody. Lower `[45]`'s round count and `PARAMETERS` compares the
constant across four languages and finds them agreeing, the fingerprint excludes it, and
`_TEST_DRAWS` still sees the same draw — while the banner goes on printing 1.0e-05 against a
true rate of **7.8%**, the pre-#234 figure that made that test fail 38.5% of runs. A rate
in `_SAMPLED_TEST_RATES` is now an EXPRESSION over constants read out of the source per
port, and **8 of the 23 rated rows are evaluated from source every run** over 23 variable
cells; the other 9 are named in `_SAMPLED_TEST_RATE_LITERAL` with a reason they cannot be,
exhaustive in both directions so expressing a rate FORCES its literal entry out. Five
things carry forward. (1) **THE CONSTANT IS NOT WHERE THE PROSE SAID IT WAS, AND IN TWO
PORTS IT IS NOT A SUITE CONSTANT AT ALL.** The item was recommended as "move
`sdf-rounds-demo` and nothing fires", which is true of two ports and false of two: C reads
`SDF_ROUNDS` from `herradura.h` and Java `Stern.SDFR` from the suite — both the same
`PARAMETERS` row, and C's moves from the command line with `-DSDF_ROUNDS=219` — while
Python and Go carry a FUNCTION-LOCAL `STERN_ROUNDS` / `sternRounds` that no axis reads. One
rate, one test, two ports tracked and two untracked, with the row's own prose naming
`SDF_ROUNDS` for all three. That is #293's read-pattern split and #294's distribution split
one axis over, with a FLAKE RATE as the object, and it is why the derivation is per port and
a row takes its WORST one — any of the four required `native-*` jobs going red is a red
check. (2) **ONE PUBLISHED RATE WAS ALREADY WRONG BY 10x, AND UNFALSIFIABLY SO.** `[53]`
signs its forgery sub-check at 64 rounds in ONE trial, so its rate is `(2/3)^64` = 5.4e-12;
the row said 5.5e-11, and so did the comment in the test body, in all four ports. It is
wrong in the CONSERVATIVE direction — overstating the flake rate tenfold and eating ten
times its share of the budget — which is exactly why nothing could catch it: **a
hand-computed bound that is too LARGE fails no check and triggers no flake.** #304 found the
same shape on the findings-gate side and answered it with a `MEASURED` token; the answer
here is to stop hand-computing. (3) **THE CONTROL THAT MATTERS IS THE ONE WHERE THE OTHER
AXES STAY SILENT.** Lowering the constant in all four languages at once leaves `PARAMETERS`
green (they agree) and #318's fingerprints green (it is in no verdict line), and this check
alone fires, at 1.17e-1 — the item's premise, executed rather than argued. The
false-positive control is equally load-bearing: editing a comment that mentions
`STERN_TRIALS` changes nothing. (4) **THE SLICE THAT IS RIGHT FOR A DRAW IS WRONG FOR A
DECLARATION.** #316's forward slice starts at the `[N]` marker because a draw always happens
after the header; C declares `zkp_nl_rounds`, `enum { STERN_TRIALS = 2 }` and
`enum { RK = 3, RND = 12, FRND = 64 }` ABOVE the `printf` that carries the marker, so three
of C's four variables were invisible. The widened slice is the overlapping one #316
explicitly rejected, and it is safe HERE for a reason that does not transfer back — every
consumer requires EXACTLY ONE match (#261's rule), so bleed fails loudly where in the draw
census it made a silent test look busy. It is opt-in per variable, because widening them all
turned `[22]`'s three readable variables into three ambiguous ones in all three ports at
once. (5) **A VARIABLE THAT RESOLVES NOWHERE IS AN ERROR, NOT A SKIP.** Four ports spell one
constant four ways and C's `[53]` spells it a fifth inside an `enum` — #306's
sixth-spelling hazard again — and a skipped term silently SHRINKS the rate, which is #295's
lenient direction. **Known limit, stated**: this closes "the rate's INPUTS moved" and not
"the rate's DERIVATION was wrong" — a formula that is the wrong function of the right
constants still evaluates. And it cannot reach a rate whose input is not a constant:
`[4]`'s bar is `6 * 50/sqrt(n_run)`, a function of an iteration count `-r` supplies at run
time, so it stays hand-computed and its entry says why. **TODO #320 closed the first half
of that limit**, and found two wrong derivations doing it — one of them in #319's own
table.

**And validating the FORMULA, not just its inputs, which is the limit #319 stated on
itself (TODO #320).** #319 made every rate in `_SAMPLED_TEST_RATES` an EXPRESSION over
constants read out of the four ports' source, and said in the same breath what that does
not cover: *a formula that is the wrong function of the right constants still evaluates.*
The limit stopped being theoretical within the hour. The four ports state CONTRADICTORY
MECHANISMS for `[45]`'s rate — C, Go and Python "a bad syndrome is caught only in the b=0
round", Java "only b=2 references the syndrome" — and the VERIFIER settles it rather than
an argument doing so: the syndrome appears in exactly one branch,
`H(pi_seed, Hy ^ syndrome)` under `b == 2`, **identically in all four ports**, while
`b == 0` binds `wt(respA ^ respB)` and `b == 1` checks `Hr`. Neither touches it. **THE
NUMBER WAS RIGHT AND THE DERIVATION WAS WRONG**, which is the combination no other axis
here can see: it is `(2/3)^rounds` either way, because either way exactly one challenge
value in three is the detecting one, so #319's machinery evaluated it correctly,
`PARAMETERS` agreed, #318's fingerprint was unmoved and the budget was unchanged. It also
PROPAGATED — #319's own reason for `[45]` repeats the b=0 claim, copied from the harness
comment while writing the table meant to make rates trustworthy, which is #310's lesson
(*a reason exact about the wrong object reads exactly like a correct one*) landing on the
item that restated it. `_RATE_MECHANISMS` is #304's move one level down: that item required
a `follows` gate to carry a rate AND the token `MEASURED` because "the arithmetic is only
as good as the null it is done against", and here the arithmetic is only as good as the
MECHANISM, where #319 shipped 14 rated rows with **not one of them held to a measurement**.
**8 of the 8 derived rows carry a MEASURED mechanism**, over 5 validated formulas, with 0
declared unmeasurable. Five things carry forward. (1) **A FREQUENCY CHECK WOULD HAVE
CONFIRMED THE WRONG MECHANISM, and excluding that is the whole design.** Both stories
predict `(2/3)^rounds`, so the rate cannot separate them; what does is #310's shape —
record WHICH challenge strings the failures carried. Measured at `rounds = 2/4/6`:
acceptance tracked the prediction, and **every accepting trial carried a challenge string
with no b=2 round while every rejecting one carried at least one, 900/900 exactly**, where
the b=0 predicate tracked the outcome in 527/900. The alternative is not merely
unconfirmed, it is REFUTED. **A rate check validates the arithmetic; only a witness check
validates the mechanism** — and because the witness is EXACT, the instrument cannot flake
on its own account, which is #299 answered one level up rather than re-introduced. (2) **IT
FOUND A SECOND WRONG FORMULA, 3x, AND CONSERVATIVE AGAIN.** `[22]`'s rate had one term and
needs two: the poke reseeds Fiat-Shamir over the WHOLE commitment block, so all `rounds`
stored challenges must coincidentally re-match, AND round 0's challenge must leave the
poked `com_1` unopened — a further `1/3`, since `com_1` is opened for `e` in {0, 2}. Either
term alone tracked about four trials in five; the conjunction tracks every one, 900/900
over `rounds = 1/2/3`. It overstated the rate, exactly as #319's 10x did, so **the
direction this axis keeps failing in is the one where nothing red ever happens** — a bound
that is too large fails no check and triggers no flake. (3) **A THIRD DEFECTIVE REASON, AND
IT NAMED THE WRONG TEST.** `_SAMPLED_TEST_RATE_LITERAL[("java", 26)]` read "Java's ZKBoo
tamper-rejection at its own literal rounds"; `[26]` is the Stern RING round-trip and `[28]`
is the ZKBoo one, and the `_SAMPLED_TESTS` row for the same test two hundred lines up says
so correctly. That is #295's false-reason finding aimed at this table instead of at a
constant: a reason is prose, so nothing cross-checks WHICH test it describes. (4) **IT IS A
RECORD, NOT A CI GATE, and that is stated up front rather than discovered.** ~25 minutes
for a full run is #289's runtime problem in miniature, and a validation that itself decides
on a fresh sample is #299's defect one level up — so #304's model: the token and the
numbers are recorded, the checker holds the record to the expression (the `term` must be a
SUBSTRING of every covered row's formula, each rung's recorded prediction must EQUAL the
term evaluated at that rung, each rung's count must sit inside a 6σ band of its own
prediction, `note` must carry `MEASURED`), and the runner does not re-measure. The
instrument is `spec/measure_sampled_rates.py`, deliberately NOT in `SecurityProofsCode/`,
so `run_findings_gates.py` cannot discover it and no `NON_GATING` entry has to argue it
away. (5) **THE INSTRUMENT MUST NOT REACH A SHIPPED DEFAULT, checked rather than
asserted.** `[45]` at `rounds = 4` is the 19.75% the Testing section warns about by name,
used here as an instrument; #310's remedy for `[53]` was to give the sub-check its own
round count, and the inverse obligation is that a reduced count stays local. The SHIPPED
value of the same variable is read out of every port through #319's own readers and must be
strictly greater than the top of the ladder — the VARIABLE and not the rate, because `[45]`
carries a `trials` multiplier and comparing rates would have compared `2 * (2/3)^4` against
`(2/3)^4` and passed a build that had lowered `SDF_ROUNDS` to the instrument's own round
count. **Known limit, stated.** A measurement validates a formula against the
implementation as it is, so a property ALL FOUR PORTS get wrong is invisible here as it is
everywhere — the standing blind spot of #277, #294, #296 and #297, whose only exit is an
assertion about ONE implementation. What this closes is narrower and is the case that
actually occurred: a formula whose stated mechanism disagrees with the verifier, where the
arithmetic happens to come out the same. **TODO #321 did the same audit to the fifteen rows
that have no formula**, and found five of the nine literals wrong plus one `exact` row that
is not exact.

**And the ARGUED half, where an `exact` verdict owes a SLACK rather than a count of zeros
(TODO #321).** #319 made every rate an expression over constants read from source; #320 held
each such formula to a measured mechanism. Both act on the rows that HAVE a formula, and the
other **15 of the 20 curated rows rested on prose alone** — 6 declared `exact` and 9 carrying
a hand-computed literal — with nothing checking either kind. `exact` is the strongest claim
in the table (the rate is ZERO) and the only category contributing NOTHING to the advertised
budget, which is exactly #304's recorded erosion shape; the precedent on curated reasons is
unanimous (#295 found 2 of 6, #304 3 of 3, #310 one "exact about the wrong object", #320 one
naming the wrong test *incidentally*). Six things carry forward. (1) **A SAMPLED ZERO CANNOT
SHOW WHAT AN `exact` ROW ASKS OF IT, at any trial count.** `[14]`'s evidence was
`hkex_rnl_failure_rate.py`'s 0 failures over ≤ 2000 trials, whose Wilson interval tops out
near 1.8e-3 — **eighteen times the whole job budget** — so the measurement is equally
consistent with `exact` and with a rate that alone would blow it: #285's finding in another
protocol and #300's gate-that-cannot-go-red from the other side. What the claim rests on is a
MARGIN, and a margin is a different object — a MAXIMUM over coefficients, so one trial reports
as many samples as the statement has terms, with a visible tail where a failure count has
none. Nothing measured it. `_EXACT_BASES` now makes every `exact` row state why its rate is
zero and **what holds at the parameters the suite DEPLOYS when the test does not run there**,
and `_ARGUED_MEASUREMENTS` holds the evidence on #320's model —
**2 argued rows carry measured evidence**, one a margin and one a rate mechanism, each
with an exact per-trial witness. (2) **ONE `exact` ROW WAS NOT
EXACT.** `[21]`'s tampered-commitment case turns on a Fiat-Shamir CHALLENGE COLLISION, not on
the residual-norm check: the verifier recomputes the challenge over the tampered `w`, and on a
collision the norm check sees one coefficient shifted by 1 inside a slack of 36 and accepts.
`_iters(5)/(comb(32,4)·2^4)` = **8.7e-6, nine percent of the budget**, from the category
contributing none of it. (3) **THE OTHER `exact` ROW'S BOUND WAS 4x WRONG, and the correction
is EXACT rather than sampled.** `SecurityProofs-4.md` said HKEX-RNL reconciliation needs "max
per-coeff error ≪ q/8" in three places; swept over all 65537 residues the smallest error that
can flip a bucket is **q/32 down and 3q/32 up**, asymmetric 3:1. Lenient, so the documented safety factor was four times the
real one — and the real one still holds: at the DEPLOYED ring the worst slack over 1000 trials
is 1647 against a bound of 2047, 16 spreads clear of zero, so the row keeps `exact` and
finally has evidence. (4) **THE MARGIN HAD TO BE MEASURED WHERE THE SUITE RUNS, WHICH IS NOT
WHERE THE TEST RUNS.** `[14]` sweeps `RNL_SIZES = [32, 64, 128, 256]`, all four RETIRED by
#223, while the suite deploys `RNLN = 1024` — and the error accumulates as O(√n) through the
convolution, measured at 419.6 against n = 256's 206.8, a factor 2.03 for 4x the dimension. So
the tested widths are the FAVOURABLE ones: #295's lenient direction in a parameter instead of
a corpus, and #313's "nothing ever ran the algorithm at another width" aimed at a CORRECTNESS
property rather than a cost figure. (5) **THE LADDER IS WHAT MAKES THE WITNESS EVIDENCE, and
the decisive control proves it.** An instrument carrying the old q/8 quantity is witness-EXACT
at the deployed rung and at the first reduced rung, and is refuted only at the cliff (134/200
at p = 512) — so the deployed rung alone could not have told the two bounds apart, which is
#296's "a branch a random stream never enters is not covered either". (6) **THE LITERALS ARE
NOW ANCHORED**, each to a regex that must match exactly once in its port's whole harness and
exactly once inside its own test's body slice, because #320 found `("java", 26)`'s reason
describing `[28]` and found it by accident. That audit turned up four more: `[49]`'s rate was
**10^134 too large** and named n = 32 where the test hardcodes 256; `[10]`'s was read off the
sub-check that does not bind, publishing 1e-30 for a 2.3e-7 term — **the first error on this
axis in the unsafe direction**; `[4]`'s union bound enumerated three of its four widths; and
`("java", 26)` left the table entirely, its rate having become `(1/3)^rounds` when **TODO
#298** gave the `b = 0` branch a weight binding — 4.6 million times smaller than every copy
said, a rate that moved with no INPUT moving, which is the one shape #319 cannot see either.
**Scope, and one thing deliberately NOT filed**: this is about the rows with no formula, not
about widening `[14]` to run at n = 1024 in the harness — and the measurement answers the
question that would have justified that, since the deployed slack is 16 spreads clear of the
cliff. #321's own text said to file the cost decision if the margin said otherwise; it did not,
so nothing is filed, said out loud rather than left as an omission. **Known limit, stated.** A
margin measured on one port is #320's limit inherited: if all four ports shared a
reconciliation defect the slack would be the same wrong number in all four. **TODO #322 asked
the same question of the 126 cells that have no row at all**, and had its own model of a
mechanism refuted by measurement twice.

**And the DERIVED DEFAULT, where the category with no row at all is the largest one (TODO
#322).** #319 made every rate an expression over constants read from source, #320 held each
formula to a measured mechanism, #321 audited the fifteen curated rows that have no formula.
All three act on the twenty rows that are CURATED. The census counts 184 sampled cells, 20
curated and 9 declared to draw nothing that reaches a verdict — so **126 fall through to the
DERIVED DEFAULT**, which `_SAMPLED_TESTS`' own header states as "all-trials-must-succeed
conjunctions of round-trips, where a fresh sample changes WHICH instance is tested and not the
outcome". That sentence was asserted by nothing and the category contributed nothing to the
budget: #304's erosion shape a third time, after #321 found it in `exact` and #304 in
`follows`. Six things carry forward. (1) **THE DEFAULT IS RIGHT FOR A ROUND-TRIP, and this is
not 126 prose reasons.** #296's rule stands — "there are 109, and a hundred prose reasons rot"
— and a disagreement in a round-trip is a real defect, never a flake. What the default cannot
cover is a REJECTION assertion, because whether a deliberately bad input is DETECTABLE can
itself turn on a fresh coin: #310 found that in `[53]` (the forged witness was sometimes the
true error, one run in 16), #316 in `[17]` (a `(1/3)^8` branch that CRASHED), #320 in `[22]`
(one term where the mechanism needs two). Three items found the shape in a curated row and
nobody had asked it of the rest. **32 cells** assert a rejection; each now states a BASIS from
a CLOSED SET of nine kinds, 8 rest on a fresh coin and carry a rated row, 12 on a collision or
forgery at a stated WIDTH — a number, so the claim is falsifiable — and 10 on no coin at all.
(2) **THE POLARITY IS OPPOSITE TO #316's, AND THAT IS THE DESIGN NOTE.** #316 records why its
draw census slices FORWARD from the marker: an over-wide slice "hides a test that stopped
drawing behind a neighbour that did not", so over-matching is the LENIENT direction there.
Here a match means "you owe a statement", so over-matching is CONSERVATIVE. The first screen
written for this item read only the verdict LINES — #318's pinned region, which looked like
the principled choice — and MISSED `[44]` and `[50]`, whose verdict lines name only counters
(`ok_replay`, `rejected[...]`) while the rejection is asserted in the body. Both are HCRED and
both were among the largest candidate terms. The screen reads whole bodies now, and four of
the nine kinds exist to absorb what that over-matches (`reference-count` for a mismatch
counter, `not-a-verdict` for a declaration, a header string, or the last marker's slice
bleeding to end of file). (3) **TWO PROTOCOLS SAY "THE VERIFIER REJECTS A TAMPERED MESSAGE" IN
THE SAME WORDS AND MEAN THINGS 2^-256 APART.** ZKP-NL's commitments do NOT bind the message —
it enters only the challenge seed, and the verifier compares `h[0] % 3` against the stored
trit — so the rate is `(1/3)^rounds`, MEASURED at rounds = 1/2/3 with the witness holding
600/600, 600/600 and 900/900 EXACTLY, both branches covered. HCRED's per-round commitment
hashes the STATEMENT, so the rate is a collision; MEASURED over 180 trials, the challenge
vector coincided 41 times (40 of 120 at rounds = 1, 1 of 60 at rounds = 4, both within noise
of `(1/3)^rounds`) and the tampered proof was REJECTED in all 41 — the alternative is not
merely unconfirmed, it is refuted, with its own confounder occurring at its predicted rate.
`refutation` is therefore a THIRD record kind beside #321's `margin` and `rate`, and its
ladder counts the CONFOUNDER rather than the event, because the event is what must never
happen while the confounder must. (4) **THE ITEM'S OWN MODEL WAS WRONG TWICE, AND BOTH TIMES
CONSERVATIVELY, WHICH IS THE DIRECTION THAT FAILS NO CHECK.** HCRED's `wrong_msg` was modelled
at `(1/3)^4` = 1.2e-2 and measured at zero. HCRED-KKW's was then modelled at
`1/comb(M,tau)` = 1/6, revised to `1/(comb(M,tau)·N_par^tau)` = 1/96 — 105x the whole job
budget — and a four-port test change was written and BUILT against that number before the
measurement refuted it too: the opened subset coincides at exactly its predicted rate, and the
verifier still rejects, never even reaching the pbar comparison, because `rho` is drawn from a
hash over `stmt` and the residual check `Σρ(ẑ−v) == Σu` fails first at `1 - 1/q` per opened
emulation. THREE bindings, not one, and the true rate is ~2.4e-12. **The four-port change was
REVERTED** — a test edit justified by a wrong rate is a cost with no benefit, and #312's rule
that a refactor must not settle a question it happens to expose applies to a fix as much as to
a refactor. What survived is the one independent defect found on the way: C's `[50]` passed
`4, 4, 2` as bare positional arguments while its banner printed the triple as a STRING
LITERAL, so a retune would have printed the old numbers beside new behaviour — #295's
diagnostic-use rule inside a numbered test. The constants are named and the banner prints
them. (5) **THE BUDGET BARELY MOVED AND THAT IS THE RESULT, NOT AN ANTICLIMAX**: 1.7e-05 to
**1.9e-05** against 1e-04. Every term this axis was missing is small; what was missing was the
statement that it is small, and the two refuted models are the argument for why a stated one
cannot be trusted. #319's 10x, #320's 3x, #321's 10^134 and both of #322's own errors point
the same way — **the direction this axis keeps failing in is the one where nothing red ever
happens.** (6) **A THIRD LIMIT OF THE DERIVATION AXIS, and it is Java's marker convention.**
`[28]` and `[29]` share ONE `int n = 8, rounds = 16` declaration which sits ABOVE the
`PASS [28]` marker, so it is inside `[28]`'s slice and outside `[29]`'s — and outside the
WIDENED scope slice too. Java's TRAILING marker makes a shared declaration reachable from
exactly one of the two tests that use it, so `[28]` derives and `[29]` carries a literal. After
`[4]`'s run-time flag and `[21]`'s module-level `t`, that is the third. A fourth is recorded
with it: the KKW rate needs `comb(M, tau)`, and the formula evaluator runs with
`{"__builtins__": {}}`, so a rate that is not arithmetic over the read constants cannot be
expressed at all. **Known limit, stated.** The screen is syntactic, so a rejection asserted
without any of the nine vocabulary stems goes unseen; the guard is that over-matching is the
safe direction here and that a flagged cell cannot be silently dropped — only classified.

**And the three harnesses none of that read, which is prior to everything it says (TODO
#323).** #316 censused which numbered tests decide a verdict from a fresh sample, #318
pinned each verdict region, #319 made every rate an expression over constants read from
source, #320 held each formula to a measured mechanism, #321 audited the fifteen curated
rows with no formula, and #322 gave the 126 uncurated cells a derived default with a BASIS
for every rejection. **All six read exactly four files** — `NUMBERED_TEST_FILES`' three plus
`SelfTest.java`. (FIVE since TODO #333, which added `Bench.java` and made that entry a TUPLE
of paths per language; Java is the only one that needs more than one, and the generalisation
is not cosmetic — a `[36]` the axis cannot see is a `[36]` it cannot hold to anything.) `CryptosuiteTests/Herradura_tests.{s,asm,ino}` appear nowhere in `spec/`,
and no sentence anywhere said why: not a scope decision but an unexamined boundary, which is
#306's finding (*which code the census READS is prior to everything the census says*) and
#295's rule that getting the corpus wrong in the LENIENT direction makes the whole check pass
vacuously. `PARAM_USE_CORPUS` states its corpus forty lines into its own block for exactly
this reason; the ninth axis did not. The axis now reads **3 more gated harnesses**, and six
things carry forward. (1) **IT WAS NOT AN EMPTY GAP.** ARM and NASM both reseed their LCG
from `/dev/urandom` before test `[1]` (the SA-01 marker in each), so every verdict after that
is decided on a fresh sample; both carry `[10] HPKS-NL Eve resistance: random forgery
rejected (20 trials)`, which draws `s_fake` per trial and requires all 20 to be REFUSED, and
`[18] v2_weak_key_reject`. And `arm-i386` and `arduino` carry no `continue-on-error`, so a
flake in either is a red REQUIRED check on somebody else's PR — #316's own stated reason for
caring about the numbered tests more than about the findings gates. The advertised budget was
summed over four of the six gated harnesses with the omission unstated. (2) **THE SCREEN MUST
READ THE TITLE, WHICH INVERTS #322's OWN REMEDY.** That item found a verdict-line-only screen
missing `[44]` and `[50]` and widened it to whole BODIES. In assembly whole bodies are still
not enough: a test's title lives in `.rodata` (`fmt_t10: .asciz "... random forgery rejected
..."` at line 49) while its body is at line 808, and the body's only rejection wording is a
`/* random forgery */` comment the screen strips by design. **Demonstrated rather than
argued** — reducing the shipped screen back to bodies alone reports both assembly `[10]` rows
as unflagged, so the title is their only carrier. In C/Go/Python the title string IS the
marker and sits inside the slice by construction; in assembly the marker is a symbol
REFERENCE, so the symbol is resolved and an unresolved title is an ERROR rather than a skip
(#319's rule: a term that resolves nowhere silently SHRINKS the rate). (3) **ONE TEST NUMBER
IS SAMPLED IN TWO HARNESSES AND DETERMINISTIC IN THE THIRD.** `Herradura_tests.ino` sets
`prng_state = 0x12345678UL` and `setup()` only opens the UART — an AVR has no entropy source
and simavr supplies none — so it never reseeds, its 18 verdicts are identical every run, its
false-failure rate is exactly ZERO, and it cannot contribute to the budget. What it buys in
exchange is weaker coverage: its 20 "random" forgeries are the same 20 forever. So `[10]`
carries a RATED basis in ARM and NASM and an exact one in Arduino — #319's per-port split
with a FLAKE RATE as the object, one harness family over. The status is **DERIVED from each
harness's source, not curated**, cross-checked against the record in both directions, and a
harness recorded `fixed` is FORBIDDEN a rated basis, so the split is checked rather than
described. (4) **THE RATE IS NOT THE 2^-32 THE CONSTRUCTION SUGGESTS, AND COMPUTING IT IS
WHY.** `[10]` succeeds only if `g^s_fake · C^e == R`, i.e. one value of `s_fake` per
`ord(g)` — and in GF(2^32) mod `0x00400007` the generator **g = 3 generates an index-15
SUBGROUP**, `ord(3) = (2^32−1)/15 = 286331153`, so the rate is `20/ord` = **6.98e-08** per
harness rather than `20·2^-32`. Every input is read from the harness's own source (the
polynomial, the trial count, and the generator taken from the loads that actually FEED
`gf_pow_32`) and the order is computed exactly, so lowering the trial count or moving the
polynomial moves the published rate: verified, 20 → 4 trials takes it to 1.40e-08 and a
changed polynomial to 4.66e-09. #322's model of a rejection rate was wrong twice, both times
conservatively; the answer is to stop asserting them. (5) **A DOCUMENTATION CLAIM WITHDRAWN,
NOT WORKED AROUND.** The Testing section above said these harnesses "assert *correctness*
only, never *soundness*" — false, `[10]` and `[18]` are rejection assertions in all three —
while its `(2/3)^4` Stern warning is true and unviolated, `[11]`–`[14]` being completeness
checks. #295's false-reason shape aimed at this file's own Testing section: a curated
sentence about how code behaves cannot be validated by a checker that reads only
declarations. (6) **THE BUDGET MOVED 0.74% AND THAT IS THE RESULT**: 1.874e-05 to 1.888e-05
against 1e-04, both rounding to the published 1.9e-05, so the advertised figure did not
change at all. Every term this axis was missing is small; what was missing was the statement
that it is small — the fifth item in a row to find it so, after #319's 10x, #320's 3x,
#321's 10^134 and #322's two refuted models, all pointing the same way: **the direction this
axis keeps failing in is the one where nothing red ever happens.** **Scope, stated in the
item rather than discovered after it.** This does NOT port `_TEST_DRAWS`' draw detector or
#318's verdict fingerprints to Thumb-2 and NASM: a fingerprint over "verdict-bearing lines"
is a `cmp`/branch PAIR in assembly rather than a string, and a draw detector would need a
fifth and sixth dialect after #306's sixth-spelling hazard had already been met twice.
Folding either in converges on completeness again, which is #298's recorded reason for
splitting an item instead of widening it. **Known limit.** These harnesses run reduced demo
parameters by design, so a rate derived here is a rate for the demo instance and says nothing
about what ships — which is not a defect of the derivation, because the harness's own flake
rate is what the budget is about.

**And the code none of those checks compiles, which is prior to all of them (TODO
#324).**  #316 to #323 ask what the numbered tests assert and at what rate; every one of
them reads *sources*.  Nothing asked whether the shipped C actually RUNS.  It did not:
`bindings/ffi/herradura_shim.c` declares **26 `BitArray` locals across its 8 exported
functions and used `BA_INIT` zero times** where `herradura.h` uses it 82 times, so from
the moment #314 pass 2 put `uint16_t nbits` in the struct, `nbits` was whatever the stack
held — an uninitialised local measured at 65278, making `ba_nbytes()` hand back **8159
octets as a loop bound over a 32-octet buffer**.  `git log` dates it without argument: the
shim was last touched at the original FFI commit and `nbits` entered at v9.1.0, so **every
release from v9.1.0 to v9.5.12 shipped a binding layer that stack-smashed on its first
call**.  It was found by trying to run a benchmark.  Six things carry forward.  (1) **THREE
OF TEN TRANSLATION UNITS, AND THE WORST IS THE DOCUMENTED ONE.**  #315 wrote that "the
whole C tree is poison-built and RUN now" and named seven; all three it omitted had the
defect, and `docs/examples/c/hello_herradura.c` — what `docs/TUTORIAL.md` points a new user
at — **aborted on its first call even unpoisoned**.  (2) **THE SWEEP COULD NOT HAVE FOUND
THE SHIM, and that is the transferable part.**  Poisoning is a RUN-TIME detector and the
shim is the only TU with no `main()`; a library has nothing to run.  #315's list is seven
*programs*, so the eighth was not overlooked so much as structurally unreachable — which is
why `tools/poison_build.sh` splits its set by shape and makes "a TU with no `main()` and no
driver" an ERROR rather than a silence.  (3) **THE POISONED BUILD EXISTED IN NO SCRIPT AT
ALL.**  It was a manual invocation that left no artifact, so it could not be re-run, could
not be checked, and could not cover a file added later.  #314 pass 3 had already recorded
*a tool that enumerates sites enumerates the sites you point it at*; #315 answered it by
pointing at more sites instead of making the pointing reproducible, and that is the third
occurrence.  The set is DISCOVERED now, on #289's model.  (4) **THE HARNESS THAT WOULD HAVE
CAUGHT IT EXISTED, FAILED, AND NO JOB RAN IT.**  #287's coverage guard — whose own comment
says it catches "a NEW harness appearing outside `CliTest/` with nothing running it" —
globbed `bindings/ffi/test_*.py`, one directory too shallow, so it matched NOTHING, and
`benchmarks/test_*.py` matched nothing either.  **A glob that matches nothing is
indistinguishable from a glob that is satisfied**, which is #300's gate-that-cannot-go-red
written as a shell pattern.  It uses `find` now and fails if the search comes back empty.
(5) **A FALSE ARGUMENT MADE IT LOOK UNNECESSARY TO LOOK.**  `BITARRAY.md` §9 rested C's
source-compatibility ON the FFI — "the FFI ABI is flat byte buffers that never name
`BitArray`" — which is true of `herradura_shim.h`, naming it zero times, and false of the
`.c`, naming it eight.  The claim was verified against the header and applied to the shim:
#295's false-reason shape aimed at a versioning decision.  (6) **THE GUARD'S COST WAS
MEASURED AND THE FIRST TWO ANSWERS WERE BOTH WRONG.**  `ba_nbytes` now validates, because it
is the choke point its own comment claims to be and the 35 call sites cannot each be audited
— `ba_rand` calls it one line BEFORE its own check.  An A/B against an otherwise
byte-identical header said +15% on `ba_fscx_revolve`; that was not the check but two loop
CONDITIONS calling `ba_nbytes` per octet where every other site binds it to a local, with
the cold `noreturn` arm blocking the hoist.  Hoisted, the guard is **free** (0.7460 vs
0.7471 µs/op).  An earlier 17.5% on `ba_gf_mul` was an artefact of a benchmark that did not
consume its result — it would have been published as a SPEEDUP.  **Known limit**: the
poisoned build is a run-time detector, so it covers the paths its drivers take; what it
closes is the case that occurred, a TU nobody pointed it at and a library nobody could.

**And the harness in the next language along, which the fix for that one could not see
(TODO #325).**  #324 closed the case of a harness that existed, failed, and that no job
ran.  `bindings/ffi/go/` holds two more — `herradura_ffi_test.go` and
`herradura_ffi_native_test.go` — and **nothing in the repository ran either**: there was no
`go test` invocation in `ci.yml` at all, and the only one anywhere is
`Fuzz/run_fuzz.sh`'s `go test ./herradura/ -run=xxx -fuzz=...`, whose `-run=xxx` excludes
ordinary tests by design.  That exclusion is correct there and is why it does not help
here — `herradura/codec_fuzz_test.go` carries only `Fuzz*` targets, so the fuzz job covers
it completely and reaches nothing else.  Six things carry forward.  (1) **THEY WOULD HAVE
CAUGHT #324 ON THEIR FIRST RUN.**  Rebuilt against the shim that shipped from v9.1.0 to
v9.5.12 and run with the build cache bypassed, `go test -count=1` **hard-crashes** with a
register dump; against the v9.5.13 shim it passes in 0.57 s.  And `git log` makes it
sharper: they were last EDITED at v9.2.0, one release *after* the defect landed, so they
were touched while it was live by someone who did not run them.  (2) **THE GUARD HAD THE
BLIND SPOT IT WAS REWRITTEN TO CLOSE.**  #324 replaced #287's shell globs with `find`
because `bindings/ffi/test_*.py` was one directory too shallow — and the replacement
searched `test_*.py` and `*_test.py` only, so `*_test.go` could never match.  **The depth
was fixed and the LANGUAGE was not.**  (3) **SO THE RULE IS PER-PATTERN, NOT PER-SEARCH.**
Widening the list to `*_test.go` would fix the case in front of it and leave the next
extension invisible — #314 pass 3's *a tool that enumerates sites enumerates the sites you
point it at*, for the third time.  Each pattern is checked separately and **one that
matches nothing is an ERROR**, so deleting the last Go harness fails the guard until the
pattern goes with it.  The alternative — asking what EXECUTES a harness — needs a call
graph over shell and YAML and is not available.  (4) **THE NEW RULE FOUND A SECOND DEAD
PATTERN ON ITS FIRST RUN**: `*_test.py` matched nothing under the guard's roots, because
`find`'s OR makes a dead pattern indistinguishable from a live one — #324's own finding one
level down, in #324's own fix.  `SecurityProofsCode` is a root now, and its two scripts are
claimed by DISCOVERY rather than by a step, with the exemption checking
`run_findings_gates.py --list`'s EXIT STATUS rather than asserting the claim.  (5) **A
SMALL ANSWER IS ONLY RIGHT IF THE QUESTION WAS ASKED OF EVERYTHING.**  Every test-shaped
file outside `CliTest/` was checked against what `ci.yml` actually names, and the orphans
were exactly the two Go files — Java's `SelfTest`/`CodecTest` run under
`test_java_{bindings,codec}.sh`, the `SecurityProofsCode` pair is discovered, and
`codec_fuzz_test.go` is fully covered.  (6) **`herradura_ffi_native_test.go` IS THE ONLY
CROSS-IMPLEMENTATION CHECK OF THE FFI**, comparing the cgo binding against the native Go
suite for the classical quartet composed exactly as the suite's own `main()` composes it —
the shape this file repeatedly records as the only exit from a single-port blind spot, and
it had never run in CI.  It imports the Go package AND links the shared object, so it will
break on any future `BITARRAY.md` pass that moves either; that is an argument for running
it, not for leaving it out.  **Known limit**: this is still a pattern list, so a harness
named by none of the patterns stays invisible — a `main()` in a file called something else,
a shell script outside `CliTest/`.  What it closes is the case that occurred twice, a
harness whose NAME says exactly what it is in a place the pattern could not reach.

**And the entry point a newcomer is sent to first, which no job built (TODO #326).**
#325 stated its own limit — the coverage guard is a pattern list, so "a shell script
outside `CliTest/`" stays invisible — and a census of every `.sh` against what `ci.yml`
names found exactly one real orphan: `docker-entrypoint.sh`, with `Dockerfile`.  Both
appear in `ci.yml` only inside COMMENTS, for 437 commits since #139, while `README.md`
and this file both send a new user to `docker build -t herradurakex .`.  That is #324's
`hello_herradura.c` shape, and that file aborted on its first call.  Six things carry
forward.  (1) **IT WAS MEASURED BEFORE IT WAS FILED, AND BOTH HALVES PASS** — the image
builds (exit 0, so the dependency list survived 437 commits) and the entrypoint exits 0
with five harnesses green.  So this is COVERAGE AND CLAIMS, not a repair, and filing it as
a breakage would have been wrong; the two negative results are the useful part.  (2) **THE
MIRRORING SENTENCE WAS THE REAL DEFECT.**  `ci.yml`'s header says the matrix mirrors the
entrypoint's smoke run "so CI and the scripts can't silently drift apart", and nothing
compared them — #287's withdrawn trust-model sentence and #295's false-reason shape.  It
HAD drifted: **Java is absent from a "six-language build matrix"**, `grep -ci java`
returning 0 in both files, while a complete port shipped at #196–#203 and `native-java` is
REQUIRED.  Arduino's exclusion was deliberate and documented; Java's was neither.  (3)
**THE STALE NUMBER WAS LOAD-BEARING, NOT COSMETIC.**  The entrypoint claimed "several
minutes (e.g. an ARM SBC)" and measures **~75–90 minutes** — written at #139, before ~190
numbered-test items — and that figure is the input to "should CI run this", so a stale one
argues for the wrong answer.  It decided the design instead of leaving it to review: the
IMAGE BUILD is gated (cheap, and dependency rot is what actually threatens a quickstart)
while the ENTRYPOINT runs at REDUCED CAPS, because the twelve other jobs already run every
one of its targets at full size and what is unproven in the container is the SCRIPT.  (4)
**A STRING-PRESENCE RULE CANNOT TELL A CLAIM FROM ITS RETRACTION**, learned twice inside
one afternoon: the first check flagged `six-language` and then `several minutes` in the
very comments added to WITHDRAW them.  #324's guard met the mirror image — its own
rationale satisfied it — and answered by stripping comments, which is no use when the claim
under test IS a comment.  The rule is SCOPED instead (#299's prescription for a source
check): the phrase may appear only on a line marked retracted, over a two-line window with
comment markers stripped, because a wrapped comment splits the marker across the boundary.
Both discovered by running it.  And the rule has a POSITIVE half, or deleting the sentence
would satisfy it — #234's vacuous pass.  (5) **THE CHECK CAUGHT ITS OWN JOB, correctly.**
The `docker` job runs the entrypoint, so it cannot be "covered by" it without
circularity, and it is listed in `EXEMPT` with that reason rather than special-cased —
because the rule is exhaustive and a new job owes a statement either way.  (6) **NINE
CONTROLS, EIGHT FIRE.**  Including the two directions that matter: a job with neither
coverage nor reason, and the entrypoint running a target CI does not.  **Known limit**: it
compares INVOCATIONS, not work, so it cannot see that two runs of one harness use
different caps — which is exactly what the reduced caps are, by design.

**And the cost control that could not reach the cost, found by trusting a documented
limitation (TODO #327).**  #326 set the container smoke run to `-r 2 -t 0.05` expecting it
to be cheap, got a **20-minute CI job**, and blamed #225's `_trange` floor.  **That
diagnosis was wrong.**  `_bench` (Python) and `bench` (Go) warmed up 10 times and then
checked elapsed only AFTER a 100-call batch — a **hard floor of 110 invocations that no
time cap could reduce** — and the signature was in plain sight: every overshooting row read
exactly `100 ops`.  Measured on #326's own CI log, 66 of 138 rows overshot a 0.05 s cap,
the worst **334 s against it, 6683×**.  Six things carry forward.  (1) **THE FLAGS DID NOT
GOVERN THE RUNTIME AT ALL**, which is the statement worth keeping: at `-r` 2, 10, 50 and
500, every one with `-t 0.05`, the Python harness ran past a 600 s timeout — the most and
least aggressive settings indistinguishable, because `-r` bounds counts inside `_trange`,
`-t` is polled between batches, and the floor sits outside both.  (2) **C DID NOT HAVE THE
DEFECT, and that is the usual shape.**  C has no shared helper; its benchmark loops carry
**eight** hand-picked batch constants — 1000, 200, 100, 50, 20, 10, 5 and **2** for the slow
Stern-F — so Go and Python did **55× more unavoidable work** on the slowest operations.  A
2-vs-1 port split in a COST CONTROL, which no axis here can see: `PARAMETERS` compares a
constant's value, `PARAM_USE_CORPUS` whether it is read, `_TEST_DRAWS` draws,
`_SAMPLED_TESTS` verdicts.  A cap's REACHABILITY is none of them.  (3) **THE FIX DERIVES
WHAT C ENCODES BY HAND** — one timed probe call sizes the batch — rather than copying a
ninth constant into a third place, which is #294/#296's "there is a correct port, do not
invent a fourth design" applied to a timing helper.  (4) **RATES ARE THE INVARIANT, SAMPLE
SIZE IS NOT.**  A benchmark exists to report a rate, so the criterion is that rates hold
while `ops` moves: an operation faster than the budget keeps batch 100 and warmup 10
**exactly**, so its path is unchanged, and only a slower one sees a smaller batch.  (5)
**THE ACCEPTANCE TEST WAS WRITTEN SO IT COULD NOT PASS VACUOUSLY** — before, `-r 500 -t 1.0`
and `-r 2 -t 0.05` both simply timed out, so "both are fast now" would not have shown
control was restored; they must DIFFER.  (6) **TWO MEASUREMENTS WERE THROWN AWAY FOR BEING
INVALID BEFORE ANY WAS BELIEVED**: a 45× speed-up computed by comparing all five harnesses'
benchmark time against Python's alone (the honest figure is 40×), and a rate table
comparing a GitHub runner against an ARM SBC.  A third — a Go rate A/B — was discarded for
running CONTENDED beside another 600 s job, with `ops` counts of 1 to 300 where a rate is
meaningless.  **A cost measurement is worth exactly as much as the control over what else
was running.**  The replacement — sequential and uncontended — turned out to be
ORDER-CONFOUNDED on a thermally-throttling SBC (median 1.13x favouring whichever leg
ran first, where the fast rows' code path is provably identical), so it supports
"nothing regressed" and not a rate figure; the rate claim rests on the structural
fact that a fast operation's derived parameters are `(10, 100)` exactly.  And the row
that looked like a 10x regression was Go's `fmtRate` printing every rate below 1e6 in
K units, so 4.46 ops/sec reads as `0.00 K ops/sec` where Python has a plain-ops
branch — a reporting divergence that obscured a measurement of this very item
(**1-vs-2**, not 1-vs-1: TODO #328 corrected this, C and Python both having the
three-branch form and Go alone being the outlier),
recorded and NOT fixed here (#312).  **Known limit**: C is untouched, so its eight constants remain hand-picked
and a new C benchmark given the wrong one reintroduces the defect there — recorded rather
than fixed, since a refactor must not settle a question it happens to expose (#312).

**And a published rate of zero, in the layer every cost figure is read from (TODO
#328).**  #327 found this and left it per #312, and this is that question.  Go's `fmtRate`
had **two** branches where C's `print_rate` and Python's `_bench` have **three**:
everything below `1e6` printed in K units with no plain-ops fallback, so 4.46 ops/sec
rendered as `0.00 K ops/sec` — **false, not imprecise**, since it reads as zero
throughput.  Measured over 46 Go benchmark rows: **23 lost precision and 6 printed
`0.00`/`0.01 K`** against true rates of **0.36–8.57 ops/sec**, and those six are the
harness's most interesting benchmarks (Stern-F sign/verify at 256 bits, ZKP
prove+verify).  Five things carry forward.  (1) **IT OBSTRUCTED THE PREVIOUS ITEM'S
MEASUREMENT**, which is what earned it an item rather than a line in a diff: #327's
apparent `10 → 0` regression on `n=256 sign+verify` was `0.01 K` against `0.00 K`.  A
reporting layer that cannot express its own slowest measurements makes the harness
unusable for exactly the comparison the previous item needed.  (2) **A CORRECTION
CARRIED INTO THREE DOCUMENTS**: #327 called this "1-vs-1"; it is **1-vs-2**, C and
Python both carrying the three-branch form and **Go alone** the outlier, with Java
having no benchmark formatter at all.  Corrected in `CHANGELOG.md`, `TODO_DONE.md` and
here rather than left standing.  (3) **THE GUARD IS STATIC, AND THAT IS THE SCOPE
DECISION.**  No checker parses benchmark output — verified empty — and this does not
change it, because running benchmarks in CI is #289's runtime problem and a cost figure
is host-specific.  `tools/check_rate_format.py` holds the formatters against each
other instead: same thresholds, same branches, read from source — **three of them until TODO
#333 built Java's, four since**.  `PARAMETERS`' idea
aimed at a **branch structure**, which no axis reads.  (4) **THE CHECK'S FIRST VERSION
HAD A CONTROL THAT DID NOT FIRE**, and fixing that is the lesson: it scanned every
numeric literal, so moving Python's K branch to `>= 1e4` left `rate/1e3` in the body and
"1e3 appears" stayed true while the branch had drifted — the exact drift it exists to
catch.  Thresholds are read from the COMPARISON now.  (5) **A FINDING WAS WITHDRAWN
BEFORE IT WAS FILED.**  The recommendation claimed benchmark labels are not unique (`46
rows, 26 distinct labels, worst 6×`) and therefore unparseable.  False: every row sits
under its own `[N] Title` header, so six `bits= 32` rows are six groups.  The defect was
in the LABEL-KEYED PARSER used to check #327 — the same parser behind that item's three
discarded comparisons.  **The output was structured all along; the reader was not.**
Retracted in the item and the changelog rather than quietly dropped.  **Known limit**:
the check reads structure, not output, so a formatter with all three branches computing
the wrong number still passes.

**And the shipped executables no job builds, which is #325's other stated limit (TODO
#329).**  #325 recorded what its coverage guard cannot reach — *"a harness named by none
of the patterns stays invisible — a `main()` in a file called something else, a shell
script outside `CliTest/`"* — and #326 closed the shell-script half by census.  This is
the `main()` half, over the two directories holding shipped executables that are neither
tests nor the CLI: **15 executables, 11 with NO RUNNER AT ALL**, and two separate
five-release breakages inside them.  Six things carry forward.  (1) **IT IS A REPAIR, NOT
ONLY A CENSUS, AND THE BROKEN FILE IS A DOCUMENTED BASELINE.**
`benchmarks/rnl_ring_cost.py` exited **1** with `ValueError: E_WIDTH: 512`: it sweeps to
n=1024 and passed the ring dimension as the SESSION-KEY WIDTH too, which stopped being
legal at **v9.3.0 / #314 pass 4** — the very commit #315 found breaking two
`SecurityProofsCode` gates the same way.  **The third instance of one defect, in the one
directory neither item looked at**, red from v9.3.0 to v9.5.17, and it is the file this
document names as the HKEX-RNL cost baseline and as #225's audit instrument.  Fixed as
`min(n, 256)` rather than a flat 256, which is behaviour-preserving BY CHOICE: every row
that used to work keeps the width it was measured at, so no published figure moves, and
the two rows the rule broke land on what the deployed ring actually uses.  All six rows
report now and n=1024 reproduces #223's 5.2x (5.28x on the multiply, 5.13x end to end).
(2) **THREE MORE WERE ABORTING, BY #324's DEFECT RATHER THAN #314's.**  The three
`compare_*.py` that import `bindings/ffi/python/herradura_ffi.py` are FFI-shim consumers:
against the shim that shipped v9.1.0..v9.5.12 one `hkex_gf_pubkey` call gives **rc=134,
`E_WIDTH in ba_nbytes`**.  #324's record says it "was found by trying to run a benchmark"
— one of these three is how, by hand, and none had a runner.  **The third set of shim
consumers nothing ran**, after #324's C example and #325's two Go tests.  (3) **THE
COVERAGE THAT EXISTED WAS ACCIDENTAL, and both files that ever got a runner got one
because an item found them BROKEN** — #287's MCP example and #324's C example.  Three C
files are covered only because `poison_build.sh` discovers `herradura.h` consumers for a
width-guard reason; nobody ever decided to cover an example or a benchmark.  (4) **THE
PREDICATE IS THE ENTRY POINT, NOT THE NAME, and that is the whole mechanism.**
`hello_herradura.go` says exactly what it is and matches no test pattern, so no widening
of #325's list could reach it.  `tools/check_runnable_coverage.py` carries #325's
per-pattern rule over — a LANGUAGE whose detector matches nothing is an ERROR — and
`EXEMPT` is self-invalidating both ways, shipping EMPTY like #295's `PARAM_USE_EXEMPT`.
**Its first version MISSED BOTH Python examples**, looking for `if __name__ ==
"__main__"` where both are top-level scripts with no guard: 13 of 15 censused and OK
reported over a corpus with two holes, which is #306's sixth-spelling hazard and #295's
rule that the lenient direction is the dangerous one, since an under-matching detector
cannot fail.  Python is PARSED with `ast` now.  (5) **TWO DEFECTS WOULD HAVE MADE THE NEW
COVERAGE VACUOUS.**  `compare_fscx_revolve_closed_form.py` printed `"C: skipped (build
failed)"` and exited 0, so a compiler that rejected `herradura.h` read as a machine with
no compiler — #234's vacuous pass, and running it in CI would have detected nothing; a
missing tool is a skip, a failed build by a PRESENT compiler is an error.  And
`rnl_ring_cost.py` computed `K_A == K_B` and threw it away, `median_of` wanting only the
wall time — #291's 22 discarded verdicts, in a benchmark.  (6) **#292's EXCLUSION IS
EXACT ABOUT THE WRONG OBJECT**, so the Go benchmark is BUILD-ONLY: that item kept
host-specific cost figures out of CI, which is right about the NUMBERS and silent about
whether the file still COMPILES (#310's shape), and building it asserts nothing about a
rate.  A measurement was discarded on the way: a first `--quick` run put n=512 at `0.61x`
against n=256, nonsense caused by two stale benchmark processes — **#327's contention
error repeated**, re-measured at loadavg 0.29 with two runs agreeing to 0.01x.  **Known
limit**: this asks whether something is BUILT AND RUN, never whether the run asserts
anything, so a benchmark printing numbers nobody checks satisfies it; the two cases above
were fixed because they would have made this coverage vacuous, not because the check can
see the class.

**And the half of a rewrite that never happened, four majors on (TODO #330).**  TODO #276
rewrote the BGF decoder's unsatisfied-parity pass bit-sliced and its own checklist recorded it
in the word that turned out to be the finding — *"the Python decoder rewritten bit-sliced,
**first**"*.  **There was never a second.**  C, Go and Java carried the per-position `O(r·d)`
loop in the **deployed post-quantum KEM** at BIKE-128, where `QCMDPC_D × QCMDPC_R` is
**874 933** secret-indexed reads per plane per decoder iteration, two planes, five iterations —
so roughly **8.7 million** `BigInteger.testBit` calls per Java decapsulation.  All three carry
the bit-sliced form now, ported from the Python rather than redesigned (#294's and #296's
precedent).  Measured uncontended, ABBA-interleaved and round-robined over the four ports, with
**Python as the control** since its decoder did not change: the decoder alone goes **C `27.49` →
`2.18 ms`, Go `58.4` → `5.8`, Java `148.3` → `26.1`** (Python `5.60` → `5.63`), and CLI
decapsulation end to end **C `46.3` → `6.1`, Go `107.6` → `73.9`, Java `369.1` → `269.9`**.
Nothing on the wire moves.  Seven things carry forward.  (1) **THE SENTENCE THAT LET IT REST
WAS PORT-LOCAL AND READ AS GENERAL.**  #276 concluded, after bit-slicing Python, that *"the
decoder is no longer the cost centre… 90% of a decapsulation is now HFSCX-256"* — true where
measured and **false in C**, where the same hash over the 3114-byte decap buffer is `1.289 ms`
against a decoder in the tens of milliseconds.  Anyone optimising C or Go on it would have
worked on the hash.  #286's shape (present tense off one instance) and #310's (exact about the
wrong object); corrected in place in `CHANGELOG.md` and `TODO_DONE.md`, and true in C *now*
only because of this item.  (2) **THE MANIFEST COULD NOT SEE ITS OWN FALSE REASON, and that is
the transferable part.**  `PRIMITIVES["qcmdpc-upc"]` said *"Java factors the UPC counter out of
the decoder loop; C, Go and Python count inline"* and anchored on `computeUpc`, which this item
DELETED — and the row stayed green, because `check_primitives` read `if hits == 0: if reason:
continue`.  An `acknowledged` reason is meant to excuse an **absent cell**; it was also excusing
a **dead anchor**, so a row could describe a port's code and decline to point at it.  The same
hole hid the Python `CENSUS_EXEMPT` rule whose reason said the other three *"have nothing to
port"* — that one never failed either, its regex still matching while its reason had gone false.
Tightening the rule (a PRESENT marker must match exactly once, `acknowledged` or not)
**found three more on its first run**, all live functions whose signatures moved at #314 pass 5
and whose markers had been unanchored since v9.4.0: `qcprf-refill` (`int[]` → `byte[]`),
`nl-fscx-delta-v2` and `hske-nl-aead-streams` (`BigInteger` → `BitArray`).  Those three are the
negative control — the rule was not asserted to fire, it fired.  (3) **A COMMENT WENT STALE IN
ITS OWN RELEASE.**  #276's Python said four planes *"saturate at 15, which is exactly the
deployed `QCMDPC_D`"* — and #276 moved the deployed `d` to 71 in the same release.  The code was
right (it sized `nb` from `d`); the sentence invited the next reader to hardcode 4.  All four
ports derive `max(4, bit_length(d))` now, C through `QCMDPC_NPLANE` with a `_Static_assert`
tying it to `QCMDPC_D`, because a saturating counter yields a SMALLER UPC — fewer flips, a
higher DFR — with nothing to observe.  (4) **A WORD SHIFT CANNOT IGNORE WHAT A BIT LOOP COULD.**
`qcp_xor_rol` looped `i < QCMDPC_R`, so a `QcPoly` carrying bits at or above `r` was harmless;
the word-level rotation replacing it wraps them to the WRONG position.  Every producer in
`herradura.h` maintains the invariant and that was verified by reading them, but it is now
load-bearing where it was incidental, so `qcp_rotl` carries a one-AND choke-point guard on
#324's `ba_nbytes` model.  That rewrite is also why keygen moved: `qcp_mul` calls it `r` times,
so **C keygen goes `264.4` → `197.6 ms`** with no output changed.  (5) **THE SECURITY HALF IS
THE SAME ENGINEERING, and the defect was the JUSTIFICATION, not the status.**  `herradura.h`
always documented the decoder as non-constant-time; what rested on retired parameters was the
excuse.  SecurityProofs-5.md §11.8.7 said timing is *"not the binding constraint at these
parameters"*, written at v3.3.0 / #235 when the instance was worth about `2^21` classical —
true of a broken parameter set — and #276's adoption of BIKE-128 at about `2^128` **inverted**
it, because at that level a decode-success/failure channel is a candidate cheapest attack and
for QC-MDPC it is the GJS reaction signal against the PRIVATE KEY, the attack §11.8.7's own
table measures.  **Withdrawn rather than re-pointed** (#286's remedy), with
`dudect_timing_audit.c` **Batch 10** registering the decoder in the harness where it appeared in
none of fourteen cases, §11.11 Batch 10 carrying the numbers, and `SECURITY.md`'s C row naming
it rather than leaving it to be inferred from silence — in a section whose opening sentence is
that it is stated per target *"so it is not inferred from silence."*  (6) **THE DECISIVE AXIS IS
NOT A STATISTICAL ONE.**  A KEM attacker chooses the CIPHERTEXT, not the secret, so Batch 10
runs one key against two ciphertext classes: a decodable syndrome against freshly drawn
decodable ones gives `1.99` vs `2.09 ms` (`|t| = 7.07`) — the time depends on which error was
encapsulated — and a decodable against an UNDECODABLE one gives `1.99` vs `3.46 ms`, decoded
133/133 vs **0/133**.  The classes differ by the whole iteration count, so the means separate by
`74%` and a single trace distinguishes them; quoting its `|t| = 3281` would understate it by
implying the channel needs averaging.  What bit-slicing bought is the ADDRESS channel; what
remains is the ITERATION COUNT, and a FIXED one is **not** adopted because it moves the DFR
#285 and #250 measure (#312).  (7) **WHERE THIS ITEM FELL SHORT OF ITS OWN TEXT, said rather
than argued away.**  It called `hpke-stern-kem`'s missing benchmark row *"a prerequisite for
claiming any speed-up here"*; **no row was added**.  The speed-up is published as a reproducible
A/B against the tagged baseline instead — a stronger claim than a harness row, which publishes
an absolute host-specific rate — because a row would put a host-specific figure inside a
required job (#292's position) and the benchmark layer is #327's and #328's axis — filed as
**TODO #332**, which owes the choice between a plain rate row and a row with a control, because
#292's position is that a host-specific cost figure does not belong in a required job.  (8)
**AND ITS OWN CI RUN TURNED UP A DEFECT IN A TEST IT DOES NOT TOUCH, filed as TODO #331.**
`sanitizers` went red on
`[21] ZKP-RNL` at n = 32 with `tamper_reject=4/5` and PASSED on the same commit in the other
run — a sampled gate firing, not a regression. **THE RECORD PRICED ONE OF TWO IDENTICAL
BRANCHES**: `[21]` has two cheats requiring the verifier's recomputed Fiat-Shamir challenge to
DIFFER (a different MESSAGE, a tampered COMMITMENT), so each turns on a CHALLENGE COLLISION in a
space of `comb(n, t)·2^t` = 575 360 at n = 32, t = 4 — `8.7e-6` each. #321 took the row off
`exact` for the **w** case and recorded that number; its reason then said the other cheats
*"really are exact"*, true of `wrongkey` and `z_tamper` (residual-norm, ~`1e-93`) and **false of
the wrong-message one**, so the row advertised `8.7e-6` where the test carried `1.74e-5` — **92%
of the whole numbered-test budget**. Second time this row has carried a reason exact about the
wrong object. **And the verifier was RIGHT**: on a collision the proof genuinely IS valid for
the second message, so scoring the accept as a rejection failure scored the verifier for being
correct — a probabilistic property asserted as a deterministic one, the class #233 fixed in
three tests. **Measured in two instruments before anything changed**: a C probe at a reduced
t = 1 gave 28 accepts in 2000 trials, 28 collisions, THE SAME 28, exactly; `measure_sampled_
rates.py` gives witness 600/600 at t = 1 and 600/600 at t = 2; and at the shipped t = 4 the event
is 0 in 4000 under -O2 and 0 in 1200 under the job's own ASan+UBSan build. **Remedy: #310's for
`[53]` on the WIDTH axis** — both FS-binding cases run at n = 256 only, where t = 16 puts the
pair at `1.5e-29` — which **adopts the port that was already right**, `SelfTest.java`'s `[30]`
running at n = 256 only, so Java needed no change. A skipped case keeps its own denominator and
prints `n/a` (#291), and the skip has a POSITIVE half that `[FAIL]`s if NO width runs them
(#234, #326); both controls were verified to fire, and #318's fingerprints fired on the change
in all three ports and asked the right question first. The budget goes **1.9e-05 → 1.0e-05**.

**And the cost of the thing all of that protects, which no harness published (TODO #332).**
`[32]`-`[43]` benchmark FSCX, the classical quartet, the NL primitives, HKEX-RNL at the ring
#223 RETIRED, Stern-F and the two ZKPs — and **not the QC-MDPC KEM**, in a suite whose
`SECURITY.md` classifies `hpke-stern-kem` as the post-quantum key establishment it recommends
over the classical quartet.  Not keygen, not encapsulation, not decapsulation, in any of the six
harnesses.  Benchmark **`[54]`** is that row and is **the only one of the thirteen that carries
a CONTROL**.  Six things carry forward.  (1) **THE CONTROL IS HOW A COST FIGURE EARNS A PLACE IN
A REQUIRED JOB.**  #292's position is that host-specific cost figures do not belong in CI, and
this prints in four of them; the grandfathered benchmarks print a rate nobody asserts on —
#318 pins their verdict region as `"none"` so that a benchmark which GROWS a verdict fires —
and this one is a test as well, at no extra cost, because the operations it times are the ones it
checks.  `decap(encap(pk))` must reproduce the secret, and a uniform syndrome must give a
DIFFERENT key, so #235's implicit-rejection path is REACHED rather than assumed.  #300's rule
pointed forwards: if a required job will run the deployed KEM a few hundred times, the cheapest
honest thing is to check each time that it works.  (2) **THE MEASUREMENT THE ITEM DEMANDED FOUND
A DEFECT IN WHAT IT WAS ABOUT TO PUBLISH, IN ALL FOUR PORTS.**  Every port's `qcp_mul` loops over
its SECOND argument and every port called it as `qcp_mul(e1, h_pub)` — the SPARSE operand first
— so the loop walked `h_pub`'s ~6162 set bits where `e1` has ~`t/2` = 67, with
`qcp_mul_sparse` sitting right there, built by #276 and #330 for exactly that shape.
Convolution over GF(2) commutes, so the orders agree BIT FOR BIT: the multiply goes **C `5.237`
→ `0.050 ms` (105x)**, **Go `230.9` → `3.752` (62x)**, **Java `74.427` → `0.759` (98x)**,
**Python `26.487` → `0.125` (212x)**, and encapsulation **C `7.410` → `2.041 ms`**, **Go `298.7`
→ `48.0`**, **Java `85.0` → `11.3`**, **Python `104.3` → `76.2`** — Python least because what
remains is one 4623-byte `hfscx_256_ds` at `70.7 ms`, 94% of its encapsulation.  **It is not
#312's rule, because there is no question to settle**: a theorem, a bit-identical output, no
parameter and no wire change, verified by the oracles that already existed (identical `(syn, K)`
AND PRF state over 50 C encapsulations on one stream, `operation_replay.json`'s `qcmdpc_encap`
row in all four ports, `test_kat_pem.sh` 40/0).  Publishing a row whose first figure was a
defect would have been #276's port-local sentence repeated.  (3) **THE ROW'S FIRST SURPRISE IS
WHY IT EXISTS**: C's keygen was **4.1x SLOWER than interpreted Python's**, `198 ms` against
`48 ms`, because `_qceuc_*` walked a **3084**-byte array byte at a time where `_qcp_inv` shifts
native big integers.  Filed as **#334** rather than left in a changelog sentence — "the row
publishes it now" is not anyone acting on it — and **CLOSED at v9.5.22**, which is why this
sentence is past tense; the array length is corrected here too, 134 having been the figure at
the parameters #276 retired.  (4) **THREE OF SIX HARNESSES, TWO DIFFERENT REASONS, SAID
RATHER THAN INFERRED FROM SILENCE** (#323's finding): the ARM, NASM and Arduino harnesses carry
no QC-MDPC, and **Java ships the KEM and has NO BENCHMARK LAYER AT ALL** — no timing helper, no
rate formatter, no throughput row for any protocol, which is why `check_rate_format.py` held
THREE formatters in a four-port repo.  One LAYER wide against one ROW wide, filed as **#333**
and **CLOSED at v9.5.23** — Java's row is `[36]`, in that port's own numbering, and the past
tense here is because of it.
(5) **THE RATE IS THE INTERESTING TABLE ENTRY.**  `_REJECTION_BASES[("shared", 54)]` is
`sampled-accept-control`, because the cell's WEAKEST assertion is the accept-control and not the
rejection — the rejection needs two differently-domain-separated HFSCX-256 calls to collide,
`2^-256`, where the fresh-key round-trip fails on a DECODER FAILURE — so the row's rate is the
DFR, and it is a LITERAL because **it is not a function of the shipped constants and cannot be**:
#285's finding is that `r`, `d` and `t` are in `PARAMETERS` while the rate they imply is read off
BIKE's published analysis, and at BIKE-128 no trial count reaches it.  An expression over
`QCMDPC_R/D/T` would be #320's defect with the arithmetic wrong too.  Budget unchanged at
`1.0e-05`.  (6) **THE ITEM'S OWN PRESCRIPTION WAS WRONG TWICE, both about where the index
lives**: `llms.txt` indexes no numbered test at all, so it needed nothing; and `CLAUDE.md`'s own
test-command comment read "security tests [1]–[29] + benchmarks [30]–[41]", **two renumberings
stale**, found only because it had to be read to be added to.  **Known limit**: the control
asserts that the KEM works and the rate beside it is asserted by nothing, so a 10x regression
prints and passes — which is #292's position honoured rather than evaded, and the reason the
figure is published with the host it was measured on.

**And a verifier window no prover screened for, found as a flake on somebody else's PR (TODO
#335).**  `cross-lang-compat` went red on #332's commit and GREEN on the identical SHA in the
sibling run, `514 PASS / 4 FAIL`, the four being one leg: `FAIL hcred issue/prove=py ->
{py,c,go,java}-verify (rc=1)`.  **An honest HCRED presentation proof was refused by its own
verifier**, because `hcred_verify` enforces `1 <= W <= w_max` on `W = popcount(phi(s))` with
`w_max = int(n/4 + 4σ)` and **no prover in any port screened for it**.  Six things carry
forward.  (1) **THE SCRIPT WAS WRITTEN SO IT COULD NOT SAY WHAT BROKE.**  Every HCRED producer
step ran under `>/dev/null 2>&1` with its exit code ignored, so one producer failure was
reported as FOUR verifier failures with the diagnostic discarded — #234's vacuous pass pointed
the other way, the dependent cases scored instead of skipped (#291).  A test that cannot name
its own failure costs a day the next time it fires.  (2) **THE RATE IS EXACT ARITHMETIC AND THE
MODEL WAS CHECKED** (#304's rule): `W ~ Binomial(n, 1/4)`, measured mean/sd `8.23/2.49` at
n = 32 and `64.54/7.01` at n = 256 against the predicted `8.00/2.45` and `64.00/6.93`, so the
binomial tail IS the rate — **`2.6e-4` at n = 32** (`1.6e-4` from `W > w_max` plus `1.0e-4` from
`W = 0`, the window being two-sided), `1.2e-4` at n = 64, `6.5e-5` at n = 256.  `[44]` alone
carried **2.6x the whole numbered-test budget**, from a cell resting on #322's DERIVED DEFAULT
whose claim — a fresh sample changes WHICH instance is tested and not the outcome — is false for
it.  (3) **A FREQUENCY CHECK COULD NOT HAVE SETTLED IT, AND 400/400 IS THE PROOF OF THAT.**  400
honest prove/verify trials verified 400 times, which is exactly what a `2.6e-4` defect predicts
(expected `0.10`) and bounds the rate only at `7.4e-3`, **74x the job budget** — #321's finding
verbatim.  The mechanism is demonstrated with a WITNESS instead (#320): reduce the window until
the confounder is common, and acceptance tracks `1 <= W <= w_max` **60/60 and 60/60 exactly** at
reduced bounds of 10 and 8, with 11 and 21 rejections, so the agreement is not a quiet sample.
(4) **THE FIX MAKES THE RATE ZERO RATHER THAN SMALLER**, which is the distinction #234 and #300
both turn on: `hcred_user_keygen` screens the weight in all four ports, on `qcmdpc_keygen`'s
weak-key-screen precedent — a credential key that cannot present is useless, so the place to
refuse it is where it is made.  No verifier and no wire format move, every existing key stays
valid, and the screen's own control FIRES (reduced to 10/6/4 it caps the observed `W` at exactly
10/6/4 against an unscreened mean of 8) — because screening a 1-in-3800 tail is otherwise
invisible.  (5) **THE `spec/` BASIS NAMED THE ROW'S STRONGEST AXIS INSTEAD OF ITS WEAKEST.**
`_REJECTION_BASES[("shared", 44)]` was `hash-binding` at 256 bits, true of `ok_replay` and
irrelevant to the accept-control that was failing at `2.6e-4`.  #322's own warning — "taking the
strongest assertion would let a rate-bearing axis hide behind an exact neighbour, and that is
#295's lenient direction inside a single row" — with this row as the instance it was written
about.  (6) **ALL FOUR PORTS ENFORCED THE WINDOW AND NONE SCREENED FOR IT**, so no cross-port
check could see it: the standing blind spot of #277, #294, #296 and #297, exited here by
ARITHMETIC rather than by comparison or by a single-port assertion.  **Known limit, stated**:
the n = 256 CLI symptom was a producer RAISE where the window causes a REJECTION, so this closes
`[44]`'s shape with certainty and the n = 256 shape only if the raise shared the cause — three
candidate raises are ruled out by measurement (the eps window has 13 of its 16 free, worst
`|eps|` = 3 over 60 keys; 0/80 on the syndrome check and on the PEM round-trip), and if it
recurs the script now names the step and prints the error.

**And the cost the previous item PUBLISHED, where fixing one call site had left the trap
(TODO #334).**  `[54]`'s first run said C's `qcmdpc_keygen` costs `198 ms` against
interpreted Python's `48 ms` — the slowest of the four ports at one operation — and #332
filed it rather than fixing it, because an optimisation with no correctness content is not
something a benchmark item should do while nobody is looking (#312).  It is **`4.31 ms` in
C now, the fastest of the four**.  Six things carry forward.  (1) **THE LIMB WIDTH IS THE
SMALLER HALF OF IT.**  `_qceuc_*` ran extended Euclid over `uint8_t[3084]`, so
`uint64_t` limbs were the obvious 8x — but the predecessor also called `_qceuc_deg` **four
times per reduction step**, each from the top of the register, where a step cancels the
leading term BY CONSTRUCTION and the new degree is therefore strictly below the old one.
Tracking the degrees, pointer-swapping instead of five `memcpy` of the full register, and
folding `mod (x^r - 1)` in one limb pass instead of 24 672 individual bit positions is
**46.8x** on the inversion (`196.260` to `4.196 ms`, ABBA-interleaved in one process over
200 dense draws with both implementations compiled side by side), and the limb width can
account for at most 8 of those.  **The expensive part of a loop is not always the part that
moves the data.**  (2) **THE BUG WAS IN THE PART THAT LOOKED LIKE BOOKKEEPING.**  The byte-level
version recomputed both degrees from the arrays every iteration, so `b == 0` was seen on the
pass AFTER the swap that put a zero there; once the degrees are tracked, the SWAP has to be
what exposes it, so the termination test moves BELOW the swap.  With it above, the loop takes
one more reduction step against an empty divisor and **`h = 1` reports as not invertible** —
caught by `h = 1`, `h = x` and `h = 1 + x + x^3` before any random input was tried, which is
the cheapest test in the item and the one worth writing first.  **And a second bug in the same
place passed every vector**: the Bezout coefficient needs its own degree bound, the obvious
one ("`uw` limbs plus `sh` bits") rounds up once per step over ~`r` steps and so runs away
from the register, and the first version CLAMPED — dropping only zero limbs, so
`operation_replay.json`, `test_kat_pem.sh`, `test_stern_kem.sh` and 200 random round-trips
were green over a bound that was doing nothing.  Replacing the clamp with an abort
(`qcp_rotl`'s choke-point precedent) fired on the first key, and tracking the degree
properly is worth a further **2.4x** on top of the limb rewrite.  **A guard that only ever
drops zeros is indistinguishable from a guard that is working** — #300's gate-that-cannot-
go-red, as an array bound.  (3) **#332's COMMENT SAID THE
OTHER TRANSPOSITION WAS NOT THERE.**  That item fixed `qcmdpc_encap`'s `qcp_mul(e1, h_pub)`
and wrote, in the comment of the function it had just measured, that the surviving caller was
"keygen's `h1 · h0^-1`, where both operands are dense and there is nothing to choose".  `h1`
**is the private key half, of weight exactly `QCMDPC_D` = 71**; `h0^-1` is dense.  So keygen,
`pkey --pubout` and `kex --our-kem` were each walking ~6162 set bits where 71 would do, in
all four ports, a further ~87x — #295's false-reason shape one item after the item that cited
it, and a reminder that a comment asserting a cost property is as unvalidated as a curated
table's reason.  (4) **SO THE FUNCTION CHOOSES NOW, NOT THE CALL SITE.**  `qcp_mul` walks
whichever operand has fewer set bits, one weight of each against the 13 703 word XORs the
choice saves.  Fixing the call site is what #332 did and the next caller got it wrong again;
converting keygen to `qcp_mul_sparse` would have been marginally faster and would have left
the generic multiply with **no caller in the shipped path in any of the four ports**, which
is a dead-code question this item has no business settling (#312).  It is also the better
leak: the loop count becomes `min(wt(a), wt(b))`, the PUBLIC constant `QCMDPC_D` at every
call site here rather than the ~`r/2` weight of a secret-derived inverse.  (5) **THE ROW IS
THE INSTRUMENT, which is what #332 bought.**  The before/after is four ABBA legs of `[54]`
itself against a binary built from the `bd050f3` header with the same harness source, and
the three non-keygen rows are the control — they move by under 1.5% across every leg, this
host's own spread, so the whole of the change is in the row the item is about.  A scratch
probe could not have said that.  (6) **BIT-IDENTITY IS CHEAP HERE AND WAS CHECKED FIRST.**
The inverse mod `(x^r - 1)` is unique and convolution commutes, so there is no question to
settle (#312) and the existing oracles are decisive: `KAT/operation_replay.json`'s
`qcmdpc_keygen` row in all four ports, all four CLIs re-deriving `KAT/pem/kem_pub.pem` byte
for byte from `kem_priv.pem`, `test_kat_pem.sh` 40/0 and `test_stern_kem.sh` 18/0.  **Known
limit, and it is #332's**: `[54]` prints the rate and nothing asserts it, so a future
regression here prints and passes — which is #292's position honoured rather than evaded.

**And the layer the previous item could only measure around, in the port whose job is as
required as the other three (TODO #333).**  `[54]` gave the deployed QC-MDPC KEM a benchmark
row in C, Go and Python and owed "four ports or a stated reason for fewer"; the reason for
Java was not a KEM reason, so #332 filed it.  **`bindings/java/` contained no timing code of
any kind** — a grep across the whole port for `bench`, `throughput`, `ops/sec` or `nanoTime`
returned ZERO matches, so the gap was one LAYER wide where the other three ports' was one
ROW wide, and `tools/check_rate_format.py` held three formatters in a four-port repo while
its own text recorded that without filing it.  Java publishes `[36]` now, in
`bindings/java/herradurakex/Bench.java`: keygen `14.9 ms`, encapsulation `10.8`,
decapsulation `21.4` (success) and `25.1` (implicit rejection), uncontended on an aarch64
SBC.  Six things carry forward.  (1) **WHERE IT LIVES WAS THE DECISION, and it rests on
EXIT CONDITIONS rather than on tidiness.**  `SelfTest` asserts and exits non-zero; `Demo`
walks through and is `[FAIL]`-gated; a benchmark publishes a host-specific rate nothing
asserts on (#292's position) and is the only one of the three that needs `-r`/`-t`, which
neither of the others parses at all.  A section inside `SelfTest` would have made a cost
figure part of what that class asserts and left `-t` nowhere to live — so a third entry
point, with its own `native-java` step, which is also the only way CI's reduced caps can
differ from a developer's.  (2) **JIT WARMUP IS A CORRECTNESS QUESTION FOR THE FIGURE, and
the number is larger than the item guessed.**  Measured call by call: the FIRST
decapsulation costs `110.79 ms` against a warm `19.3` — **5.7x** — and the first keygen
`30.95` against `14.0`; #332's own hand figures for this port moved keygen `99` to `56 ms`
between runs on JIT state alone.  So the warmup count is PRINTED beside every rate, and it
is a FLOOR of ten calls rather than Go's `min(batch, 10)`, because what it is defending
against is compilation state and not noise — bounded by `-t`, since a fixed call count is
the unbounded version of exactly the defect #327 fixed.  (3) **THE BATCH IS DERIVED, FROM A
WARM PROBE.**  #327's remedy was one timed probe call, and Go's probe is the COLD one, which
under-sizes the batch by the JIT factor; here the probe is the last warmup call, so the
derivation is fed the number it was meant to have.  C's eight hand-picked constants are the
form deliberately not copied — #327 recorded them as its own known limit, and a ninth in a
fourth place is what #294 and #296 both answered with "adopt the port that is correct".
Demonstrated rather than asserted: `-t 0.05` runs in `1.1 s` with 1 op on the slowest row
and `-t 2.0` in `10.2 s` with 77, and `-r 2` caps every row at 2 ops against a 5 s budget —
they must DIFFER, because before #327 both settings simply timed out and "both are fast now"
would not have shown that control was restored.  (4) **A CONTROL THAT DID NOT FIRE SETTLED
THE SHAPE OF TWO LINES, AND FOUND THE SAME HOLE IN GO.**  #318 fingerprints a test's
PASS/FAIL-BEARING lines, so with the verdict written as `boolean ok = okAgree && okDiff;`
above the outcome pair, **flipping that `&&` to `||` left every check in `spec/` green** —
the decisive expression sat one line above the pinned region.  C's `[54]` and Python's both
put the decision inside the printf that carries the markers and never had it; **Go's did
not**, and flipping Go's conjunction was equally invisible, so that cell's pin could not go
red either.  Fixed in both, behaviour-identical, and re-verified to fire.  2 of 4, with Go
the outlier in the same row #328 found it the outlier of.  (5) **JAVA'S NUMBERING NOW SPANS
TWO FILES, which is a `spec/` change and not a formality.**  `NUMBERED_TEST_FILES` takes a
TUPLE of paths per language; had it stayed one file, `SelfTest.java`'s `[1]`-`[35]` would
still be contiguous and duplicate-free, every table would still be satisfied, and `[36]`
would have been invisible to the whole ninth axis — no draw cell, no verdict fingerprint, no
rejection basis, no rate.  That is #324's *a glob that matches nothing is indistinguishable
from a glob that is satisfied* one directory over.  `[36]` owes and has all four, its rate
the same inherited DFR the `shared` row carries (`2^-39`, a LITERAL for #285's reason: at
BIKE-128 the rate is not a function of `QCMDPC_R/D/T` and no trial count reaches it), and the
budget is unchanged at `1.0e-05`.  (6) **ONE ROW, NOT TWELVE, SAID IN THE ITEM.**  The other
eleven (`[32]`-`[43]`) are not ported: the question was whether Java has a benchmark layer
and what it looks like, one row settles it, and eleven more would add seconds per CI run of
figures nobody asserts on to answer a question already answered.  The layer exists, so a
twelfth row is a one-method change rather than a decision.  **Known limit, and it is
#332's**: the rate beside the control is asserted by nothing, so a 10x regression prints and
passes — #292's position honoured rather than evaded, which is why the figure is published
with the host it was measured on.

**And promoting the job that collects all of it, which every one of those items was
the precondition for (TODO #317).** `analysis-findings` ran `continue-on-error: true`
from TODO #289 until v9.5.6 — twelve jobs, eleven blocking — on the `arduino` job's #185
route: promote once a pass history exists. It is BLOCKING now, and the three things that
had to be true first are worth keeping, because they are the shape of the argument for
promoting any advisory check. (1) **THE HISTORY**: seven consecutive green runs, and the
only two failures in that window were a REAL defect — two gates raising `E_WIDTH` on
their first call after #314's pass 4 moved the BitArray width contract — found and fixed
by #315. A clean history is only evidence if a dirty one would have been visible, and
here it was. (2) **THE RISK THE FLAG NAMED IS NOW MEASURED.** The old comment said the
thing being watched was not build flakiness but SAMPLING, and that finding it out on a
required check would be the wrong way round. That was correct and it is now answered:
#300 censused all 76 gates at a nominal **6.4e-5 per run**, each carrying a verdict code
and a derived rate or a stated argument, and #304 audited the three `follows` entries and
found all three defective — which is how the number became 6.4e-5 rather than the 5.4e-5
it had been advertising. A rate somebody derived is a different object from a rate
somebody hopes is small. (3) **WHAT LEAVING IT COST**, which is the argument for acting
rather than waiting longer: #315 found two gates that had been **red for two releases**,
and the reason nobody noticed is the flag itself — a `continue-on-error` job's red is
indistinguishable from nobody having looked, which is #289's own premise inverted. A job
that collects exit statuses nobody reads collects nothing. The standing rule from here:
if a gate flakes, the fix is that gate's threshold (#299's replication — confirm an
exceedance against a second independent sample before failing), never re-adding the flag
to make a red run pass.

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

**And what a consolidation finds when it makes four ports comparable (TODO #312, #313).**
#311's triage said HSKE-NL-A1's plain mode was #308's shape one protocol over: Java's suite
had `hskeNlA1Encrypt` and Java's CLI called it, while C, Go and Python transcribed the
four-step construction — twice each, in `enc` AND `dec` — and called the suite for its AEAD
sibling in the same branch of the same command. #312 moved it. Two things came out of that
which the triage could not have predicted. (1) **Python's second copy of the KDF-seed
derivation was seven copies**, four in the CLI and **three in the suite file itself**,
because Python had no `rnl_kdf_seed` at all where C has had `ba_rnl_kdf_seed` and Go
`RnlKdfSeed` since v1.8.0 — the class tests [46], [47], [49] and [51] each exist to
cross-check, except that here there was no suite function to cross-check against. (2) **The
four ports do not interoperate below 256 bits, and `dec` exits 0** (TODO #313): at n = 128 a
single Python-written ciphertext decrypts to four different plaintexts, from a domain
constant truncated at opposite ends (Python HIGH bits, Go LOW bits) and two ports that
ignore the declared width. Three things to carry forward. **The bug was only visible once
the ports were asked the same question** — `hske-nla1` has no authentication tag, so a wrong
keystream is not a detectable event, and every test in the repo runs at the default 256 bits
where the four genuinely agree; a four-way divergence sat under a green 4x4 matrix because
nothing had ever run the algorithm at another width. **A refactor must not settle a wire
question it happens to expose**: #312 preserved each port's rule and filed the convergence
as its own item with a `MIGRATING.md` decision attached, because unifying it silently inside
a consolidation is the move #313's own "what must NOT happen" names. And **behaviour
preservation was measured, not claimed** — pre-change ciphertexts decrypt to identical bytes
under the post-change build in all three ports at three widths, which is #308's fixed-nonce
byte-identity standard available more cheaply, since an A1 nonce travels in the ciphertext.

**And the width nobody ever asked at (TODO #313, #314).** #312's consolidation made the
four ports comparable at a width other than 256 for the first time, and they are not:
`hske-nla1` produces four different keystreams below 256 bits, and `dec` **exits 0 with the
wrong plaintext** because A1 is a raw XOR keystream with no tag, so a wrong keystream is
not a detectable event. `CliTest/test_narrow_width_matrix.sh` is the prerequisite #313
named, and four things about it are the transferable part. (1) **It pins the DEFECT, not
the contract.** #313 is undecided between three routes; a script asserting the correct
contract would be red today and would have to be ignored, which is exactly the allow-list
the Testing section above refuses to have. Its header states the contract the fix should
aim at, so the pin is not mistaken for approval, and it says it must be REWRITTEN rather
than patched cell by cell when the route is chosen. (2) **An accept-control at n = 256
runs first**, because a CLI that cannot encrypt at all would score every narrow cell as
`refuse` and read as a clean route-2 fix — #234's vacuous pass wearing the shape of
success. (3) **Both negative controls were verified to FIRE**, and there is an independent
count check beside the per-cell table so a PARTIAL fix cannot pass quietly. (4)
**Measuring changed the item.** The filing said "four ports, four keystreams"; the matrix
says Java's `enc` already REFUSES a narrow key, C's `genpkey` does not accept `--bits` at
all, C writes `der_i_n256` into every ciphertext so its artifact is MISLABELLED 256 (which
is why `c -> go` works and `go -> c` does not — a third defect, distinct from the
truncation split), and Java's `dec` returns all-zero plaintext with exit 0. Two of the four
already refuse somewhere on the path, which strengthens route 2 and makes "document it and
change nothing" untenable. **TODO #314 is the shape underneath**: four ports implement "an
n-bit unsigned value" four different ways — C a fixed byte array, Go `math/big`, Python the
embedded int, Java `BigInteger` at a static N = 256 — so three delegate the arithmetic to a
type this project does not control and two cannot represent a narrow value at all. One
internally-developed variable-width BitArray, ported unchanged, is what makes "the four
agree" a property of the code rather than of four people's care at one width; it is also
what would let Java recover a constant-time property its own header records as abandoned
*because* of the dependency choice.

**And choosing the route, where the cheapest option was the one that does not foreclose
the others (TODO #313, closed v9.0.0).** #313 owed a decision between three routes and
picked ROUTE 2: refuse `n != 256` for `hske-nla1` in all four CLIs. Five things carry
forward. (1) **Route 1 was not available, and saying so is the load-bearing part.**
Converging the four truncation rules is the better end state, and C cannot follow it — it
is compiled for a single `KEYBITS` and cannot represent a 128-bit A1 operation at all — so
a convergence today would leave C differing from the other three *while reporting that the
divergence was closed*, which is precisely what #313's own "what must NOT happen" names.
Route 3 would have meant publishing that 16 cells return the wrong plaintext at exit 0.
**Relaxing a refusal later breaks nothing**, so route 2 is the state route 1 gets relaxed
out of once #314 lands, not a competitor to it. (2) **The width arrives in two places and
guarding one leaves the defect live.** It can come on the KEY or on the CIPHERTEXT's own
declared `nbits`, and the second is what catches a foreign artifact whose label disagrees
with the key — C's included, since C stamps `der_i_n256` on everything it writes whatever
the key says. Four paths, two carriers, all four ports, one message. (3) **The fix went to
the source in C rather than around it.** `load_sym_key` READ the declared width and threw
it away; `load_sym_key_n` returns it, and the labels are distinguished, because a SESSION
KEY PEM's field is a key width while an RNL/HYBRID RESPONSE's is a RING dimension — reading
a field that does not mean what the caller is about to ask is how this class starts. On the
way, C turned out to have **no width guard on `encfile`/`decfile` at all** where the other
three had one: a three-to-one parity gap invisible to every `spec/` table, because it is an
ENFORCEMENT gap and #278's recorded limit is that `PARAMETERS` reads declarations. (4) **A
guard needs a scope control, not just a negative control.** #313 authorised a guard on
`hske-nla1`; widening it to every symmetric algo would be a separate MAJOR with its own
unmeasured blast radius, and a widened guard passes every assertion about `hske-nla1`
perfectly. The test therefore asserts that `--algo hske` at a narrow width is still
accepted, and that control was verified to fire. C's `load_sym_key` still zero-extends for
the other symmetric algos: recorded as a known unmeasured asymmetry rather than fixed in
passing, because a refactor must not settle a question it happens to expose — #312's rule
one item on. (5) **MAJOR on the letter of the rule, and the reasoning is written down.** It
changes what an existing `--algo` ACCEPTS, so it is MAJOR and gets `MIGRATING.md` §19 —
even though it breaks no interoperability, because there was none to break: no two ports
agreed below 256, so no cross-port narrow artifact has ever been readable. The only loss is
a port reading back its own old narrow ciphertexts.

**And writing the contract before writing any of it, where measuring the thing everyone
assumed was the whole first pass (TODO #314, first pass v9.0.1).** #313 refused
`hske-nla1` at any width but 256 and said the convergence needed one BitArray library
written here and ported unchanged. `BITARRAY.md` is that contract, `KAT/bitarray.json` its
378 pinned cases, and **no shipped port was touched** — the suite, the four CLIs and every
existing test are byte-for-byte unchanged. Five things carry forward. (1) **The versioning
question the item demanded be settled in the item was settled by MEASUREMENT, and the
answer inverted the item's own expectation.** #314 assumed MAJOR because `bindings/ffi` and
`docs/examples` use `BitArray`. They do not: `herradura_shim.h` names the type **zero
times** — the FFI ABI is flat `uint8_t[KEYBYTES]` buffers by the shim's own design — and
`hello_herradura.c` calls `ba_*` only, so it compiles unchanged. `herradura.h` being
header-only means every consumer recompiles from one header and no ABI boundary for the
type exists at all. **An API-breakage worry is worth ten minutes of grep before it is worth
a version number.** (2) **The reference had to be proved behaviour-preserving BEFORE
anything rested on it**, or every later port would be chasing a new opinion instead of the
existing agreed one: it reproduces shipped C at n=256, shipped Go at n=256, and shipped
Python at 32/64/128/256 on eight operations, zero mismatches. (3) **The truncation rule is
decided by argument and the outlier identified by measurement, not by reading four
sources.** HIGH bits, the big-endian prefix — a slice rather than arithmetic, and arithmetic
is where the ports diverged. Python and C's declared narrow constants already say high
bits; Go's rule was CONFIRMED as `ROL(k,n/8) XOR (DC_256 & (2^n - 1))` by reproducing its
output at n=32, 64 and 128, which is a stronger statement than "Go slices the low octets".
(4) **Reason 2 stopped being an argument.** The item said an embedded bignum reports what
IT considers an error; the measurement is worse — one mixed-width XOR returns **two
different silent wrong answers**, Go's `Bytes()` rendering an over-wide value as eight ZERO
octets because it copies nothing, Python's mask discarding the other operand entirely. That
is #313's four-keystream shape one layer down, and it is why §3 is the clause to read first.
(5) **A currency check is not coverage and must say so in the file, not in a commit
message.** A vector generated by the reference and checked only by the reference proves
nobody edited it; `BITARRAY.md` §7 and the `test_kat_vectors.sh` block both state that,
because the alternative is #234's vacuous pass arriving by default rather than by mistake.
The gate/report split follows from the same rule the Testing section already states — there
is no allow-list, so an unconverted port's expected divergence CANNOT be a failing test, and
a port joins the gating set only when it is converted.

**And converting the port that could not pose the question, where the hard part was not
the type (TODO #314, second pass v9.1.0).** Pass 1 wrote the contract; pass 2 made C
satisfy it. `herradura.h`'s `BitArray` now carries `uint16_t nbits` beside its octets,
implements all of `BITARRAY.md` §4, and passes `KAT/bitarray.json` 376/376 — the port that
"cannot represent a narrow value at all" now spans 16 to 256 bits and agrees with the
reference at 32, 64, 128 and 256. Six things carry forward. (1) **A POISONED BUILD FOUND
THE SITES A GREP COULD NOT.** Adding a field is easy; finding every place that creates a
`BitArray` without setting a width is not — 122 declarations, ~50 arrays, 6 struct types,
24 heap allocations, and four shapes that defeat a regex outright: a declaration sharing
its line with a statement, one sharing its line with its opening brace, a `static` whose
zero-initialisation IS an invalid width, and a `memset(&x, 0, sizeof x)` that erases the
width it was just given. Compiling with `-ftrivial-auto-var-init=pattern` turns every
uninitialised local into a deterministic `0xFEFE` width that `ba_check_width` rejects and
`BA_FAIL` aborts on, with a backtrace naming the call site. Nine aborts, nine fixes, then
the harness ran clean. **A grep tells you where you looked; a poisoned build tells you
where you did not.** (2) **THE SPECIFICATION WAS CORRECTED BY ITS FIRST PORT, which is
what a first port is for.** §4.1 specified `to_uint` at every width — which the Python
reference satisfies *trivially because its integers are arbitrary-precision*, and that is
the dependency this whole item removes. Demanding a 256-bit integer return would force
`math/big` / `BigInteger` back in. The integer conversions are now bounded to `n <= 64`,
and the reference keeps a PRIVATE `_int()` for its own arithmetic so rotation, shifts,
compare and GF stay specified at every width: **the bound belongs on the public operation,
not on how the reference computes.** A reference written in the most capable language will
over-specify unless a port pushes back. (3) **THE EXISTING ORACLE CAUGHT THE NEW CODE
BEFORE THE NEW ORACLE DID.** A first `ba_try_gf_mul` walked the multiplier's bits the
wrong way and disagreed at every width *including 256* — caught by the 256-bit
behaviour-preservation probe, not by the conformance vectors. Write the behaviour-
preserving check first and it pays for itself immediately. (4) **C's compile-time GF
restriction is gone**: `#error "GF polynomial constants are only defined for KEYBITS=256"`
became a width-indexed table and a run-time `BA_E_NO_POLY`. (5) **Two small defects fell
out of doing it** — `ba_is_zero` had a data-dependent early exit in a file whose
neighbouring comparisons are all marked SA-08/SA-09 constant-time, and the CLI's
`ba_from_ra` now STATES the width it produces where TODO #313 had recorded its
zero-extension as known and unmeasured (behaviour unchanged on purpose: #312's rule that a
refactor must not settle a question it happens to expose). (6) **PASS 6 NEEDS ALL FOUR
PORTS, NOT THREE.** C agreeing with the reference is not the four agreeing with each
other, so #313's refusal stays. Until pass 3 this is ONE implementation against ONE pinned
answer — more than currency, less than a cross-implementation check — and both
`BITARRAY.md` §7 and `test_kat_vectors.sh` say so rather than letting 376/376 read as more
than it is.

**And converting the port whose silent wrong answer was the argument for the whole item
(TODO #314, third pass v9.2.0).**  Pass 1 wrote the contract, pass 2 made C satisfy it,
and pass 3 is Go — the port `BITARRAY.md` §6.1 measured returning **eight zero octets**
from a mixed-width XOR, with no error and no panic.  `herradura/herradura.go`'s `BitArray`
is now `{ nbits int; b []byte }`, both fields UNEXPORTED, and passes `KAT/bitarray.json`
**376/376** through `KAT/verify_bitarray_go.go`.  Six things carry forward.  (1) **THE
UNEXPORTED FIELD IS GO'S POISONED BUILD.**  Pass 2's `-ftrivial-auto-var-init=pattern` has
no Go equivalent and needed none: `Val` was an exported `big.Int` reached into from 237
sites across six files, and making it private turned every one into a COMPILE ERROR the
toolchain enumerates.  Same property as the poisoned build — the tool finds the sites, not
the author — by a different mechanism.  **When a type's representation changes, take away
the access the old representation gave, and the compiler produces the worklist.**  (2)
**THE EXISTING ORACLES CAUGHT THE CODE AND THE NEW ONE CAUGHT THE VECTOR.**  Behaviour
preservation at 256 was proved first, on pass 2's standing instruction — a 30-operation
probe is byte-identical before and after, and `KAT/verify_kat.go` passes unchanged — while
what the NEW consumer found was a defect in `KAT/bitarray.json`'s FORMAT: two cases carry
integers above 2^53, and Go is the first consumer to read that JSON at all, since C
consumes the transposed header where they are literals.  A float64 decode rounds one.  It
is **not silent** — the pinned answer disagrees and the case fails — so the fix is an exact
decode, not a change to the file.  (3) **TODO #313's TRUNCATION SPLIT IS CLOSED IN THE CODE
FOR C AND GO, at one site**: `RnlKdfSeed` took the LOW octets of the domain constant, the
outlier §4.4 settles against, and now takes the HIGH bits through the one specified
truncation.  `HskeNlA1Encrypt` did not have to change, which is the point of there being
exactly one truncation.  **The refusal stays** — `hske-nla1` is still refused below 256
bits in all four CLIs until Python and Java land, because two ports agreeing with the
reference is not four ports agreeing with each other.  (4) **THE GO API CHANGED WHERE C's
DID NOT, and the asymmetry was measured.**  §9 established C's source-compatibility from
the FFI ABI never naming `BitArray` and the header being header-only; Go has no such
shelter, because `Val` was exported and `GfMul`/`GfPow`/`GfPoly` took a `poly` and a width
the type now carries.  All six in-tree consumers move in the same commit.  It is a Go
PACKAGE API change and not a CLI/PEM/wire one, so MINOR.  (5) **`math/big` DOES NOT LEAVE
THE GO TREE AND WAS NEVER GOING TO — what changed is that the boundary has a name.**  It
stops implementing the BitArray and keeps representing what `BITARRAY.md` does not govern
(QC-MDPC dense polynomials at r = 12323, syndromes, Z_q coefficients, OPRF and threshold
scalars, the codec's DER INTEGERs), crossing at `NewBitArray` / `BitArray.BigInt` — two
named functions where there were 237 reach-ins.  A boundary you can count is a different
thing from one you cannot.  (6) **THE CENSUS CAUGHT THE PASS TWICE, both times correctly.**
`spec/check_language_parity.py`'s internal-surface census refused 16 new Go functions until
each had a reason, and its parameter-USE census (#295) refused a `BAMaxBytes` that Go
declared and never read.  And running the WHOLE of `CliTest/test_kat_vectors.sh` — which
pass 3 had to extend anyway — found `KAT/verify_kat_c` **aborting**, at v9.2.0 and equally
at v9.1.0: `BitArray seed_H;` with no initialiser, so `E_WIDTH in ba_fscx` once the stack
happened to hold invalid garbage.  Pass 2's poisoned build covered `herradura.h`, the CLI,
the test harness and the suite walkthrough and **not the C files outside those four**, so
twenty sites in `KAT/verify_kat_c.c`, `SecurityProofsCode/dudect_timing_audit.c` and
`benchmarks/rnl_deployed_ring_cost.c` were carrying a width nobody set.  **A tool that
enumerates sites enumerates the sites you point it at** — pass 2's "a grep tells you where
you looked" one level out — Go allocates exactly `nbits/8` octets, so a capacity in BYTES has
nothing to name there, and the constant was DELETED rather than exempted.  C's own `ba_`
exemption reason had to be rewritten in the same pass: it said "C alone needs it: Go and
Python carry big integers with these as built-ins", which pass 3 makes false.

**And the port whose integers made the over-specification invisible (TODO #314, fourth
pass v9.3.0).**  Pass 4 is Python — `BITARRAY.md` §6.2's other silent answer, where a
mixed-width `__xor__` returned the LEFT operand with the right one masked away entirely.
The type now stores `_nbits` plus `_b: bytes` and passes `KAT/bitarray.json` **376/376**
through `KAT/verify_bitarray_py.py`, so **three of the four ports gate**.  Six things carry
forward.  (1) **THE REPRESENTATION WAS CHOSEN BY MEASUREMENT.**  `BITARRAY.md` §1 leaves
the limb implementation-private, so the question was real: a pure byte-loop rotation at
n = 256 costs **7.60 µs against 0.35 µs** for the int form, 21x, in a suite that already
runs half an hour.  What makes octet STORAGE free is where the conversion sits —
`fscx_revolve(256, 64)` measures **100.9 µs either way** when the composite converts once
at its boundary, and +32% per step.  So: octets stored (§1.1's reason), the interpreter's
int as the private limb (§1's permission), conversions at the composite boundary.  **A
specification that leaves a choice open is asking for a measurement, not a preference.**
(2) **THE PUBLIC SURFACE DID NOT MOVE, and that is the whole difference in cost from pass
3.**  `.uint`, `.bytes`, `.hex`, `.rotated()`, `^`, `==` and the constructor all keep
their meaning, so the blast radius was **89 private reach-ins** in two files, not the
~380 `.uint` sites a grep suggests — and the twenty `SecurityProofsCode/` scripts that
load the suite through `importlib`, most of which GATE a finding, needed **no edit at
all** — except for two, and that exception was CORRECTED BY CI rather than measured here
(TODO #315): the accessor surface did not move, but §2's WIDTH RULE is new, and
`fscx_revolve_closed_form.py` (n = 8, n = 512) and `nl_fscx_v2_kex.py` (n = 8…40 step 4)
both build a `BitArray` at a width the type no longer admits.  Both are gates and both
raised `E_WIDTH` on their first call, unseen for two releases because the job that runs
them was, until TODO #317, the one job on probation.  Go's `Val` was exported; Python's equivalents were
private by name.  **What a
representation change costs is decided by what the old representation published.**  (3)
**`uint` is the bignum boundary and `to_uint` is the specified operation**, spelled
differently on purpose — and `to_uint`'s `n <= 64` bound exists because THIS port
satisfies the unbounded version trivially, which is the dependency the item removes.  (4)
**#313's site closes for the third port, and this one was already right**: Python took the
HIGH bits, but as an open-coded `>> (256 - n)` at the call site, and now goes through the
one named `truncate` — the rule moves into the TYPE, which is why Go could get it wrong at
all.  (5) **The harness keeps its own BitArray**, converted independently, because [46],
[47], [49] and [51] cross-check local copies against the shipped suite and a harness that
imported what it tests could not; a blind private-name rewrite produced a property whose
getter returned itself, and the harness failing to import is what caught it.  (6)
**`--report` has run out of ports to measure and says so** rather than printing rows that
duplicate a gate, and `_load_python_suite()` was DELETED rather than left unreferenced
beside the check — TODO #305's dead-code shape.  Both controls fire: low-octet truncation
fails **the same 14 of 376 Go's control failed**, which is two consumers demonstrably
exercising the same cases.

**And the port the third reason was written for, which had said so itself (TODO #314,
fifth pass v9.4.0).**  Java had no BitArray at all — bare `BigInteger` against a static
`Herradura.N = 256`, so a width was a property of the whole port rather than of a value
and the mixed-width question could not be posed.  It has one now, `int nbits` plus
`byte[] b`, immutable, passing `KAT/bitarray.json` **376/376**, and **all four ports
conform**, so `BITARRAY.md` §8's pass 6 is available for the first time.  Seven things
carry forward.  (1) **THE PORT WROTE DOWN REASON 3 ITSELF.**  `Herradura.java`'s header
said it mirrored Python "rather than herradura.h's constant-time C implementation:
java.math.BigInteger gives no constant-time guarantee regardless, **so there is nothing to
gain from porting the C branchless tricks**" — a security property conceded *because of a
dependency choice*, by the person who made it.  Over a `byte[]` there is something to
gain, so the CT-marked operations now touch every octet and fold with masks; that buys a
branch-free STRUCTURE, not a claim about what a JIT emits, and the header says so now.
(2) **IT HAD NO `rnl_kdf_seed` AND THE COPIES NUMBERED SIX** — two in `Hfscx256`, two in
`HerraduraNl`, one in `Hpake`, one in `KatVerify`, TODO #312's finding in a fourth port
and the concrete reason "exactly one truncation" was unavailable here.  (3) **ITS CLI
PASSED THE WIDTH BESIDE THE VALUE**: `loadKey` returned `BigInteger[] { value, nbits }`,
read as `key[1]` at nineteen sites — #313's defect shape stated in a type.  (4) **THE
CONVERSION'S OWN HAZARD IS THIS ITEM'S SUBJECT.**  Java's `equals(Object)` returns false
for a different type rather than failing to compile, so a `BitArray` compared with a
`BigInteger` is a round-trip check that always fails or a difference check that always
passes; **four instances survived three successive audits** and **every one was caught by
an existing oracle** — SelfTest, Demo, CodecTest and KatVerify each found one.  A
conversion that changes a type cannot lean on the compiler where equality is untyped.
(5) **THE CENSUS CAUGHT THE PASS THREE TIMES**: 32 manifest markers anchored on Java
signatures (TODO #299's shape), eleven suite functions that stopped drawing because
`BitArray.random` is a **seventh spelling** of "read the CSPRNG" (#306's blind spot, met
again), and a REPLAY_COVERAGE transitivity claim the call-graph check refused because
Java's `Stern.sternFKeygen` still draws its own seed.  (6) **ONE ROW WAS WAITING FOR IT** —
`rand_bitarray`'s `"java": None,  # Java inlines rng.nextBytes; it has no such helper`,
true when written and false the moment Java grew the type.  (7) **BEHAVIOUR IS PRESERVED
AT 256 AND IT IS THE SAME OCTETS**, agreeing value for value with the other three probes:
what #314 said was true "by four people's care" is now true by construction.

**And the pass the whole item existed for, where a 376-case conformance vector was not
enough (TODO #314, sixth and last pass v9.5.0).**  TODO #313's refusal is LIFTED:
`hske-nla1` is accepted at every width `BITARRAY.md` §2 permits — a multiple of 8 from 16
to 256 — in all four CLIs, and `CliTest/test_narrow_width_matrix.sh`, rewritten a second
time from "all four refuse" to "all four agree", measures the full 4 × 4 (writer × reader)
matrix at 256, 128, 64 and 32 bits: **85 PASS / 0 FAIL, 48 narrow cells**.  Six things
carry forward.  (1) **TWO PORTS PASSED `KAT/bitarray.json` 376/376 AND STILL PRODUCED THE
WRONG KEYSTREAM BELOW 256.**  Conforming to the TYPE is not the same as CONSUMING it at
the value's width, and nothing in passes 1–5 could see the difference: Java's NL-FSCX v1
round rotated by a static `Hfscx256.NL_V1_SHIFT = Herradura.N / 4`, correct at 256 and at
no other width, sitting one line below a `BitArray` that carries its width faithfully; C's
A1 path took `I_VALUE` steps over fixed-`KEYBYTES` arithmetic.  **What found both was the
cheapest test in the item and the last one written** — one probe asking the four SHIPPED
suites the same question at four widths, which agreed on `rnl_kdf_seed`, the site #313 was
*about*, and disagreed on the keystream.  (2) **THE NAMES WERE THE TELL.**  `ba_add256`,
`ba_sub256`, `ba_mul256` and `ba_rol64_256` are now `ba_add_mod2n`, `ba_sub_mod2n`,
`ba_mul_mod2n` and `ba_rol_quarter`, width-aware and mixed-width-checked.  A function whose
name contains its width cannot take another one; `ba_rol64_256` was the sharpest case,
since both its callers wanted n/4 and 64 is n/4 at exactly one width.  (3) **THE REFUSALS
THAT REMAIN ARE ABOUT FORMATS, NOT ABOUT PORTS DISAGREEING.**  A declared width no
`BitArray` can have is §2; a ciphertext whose declared width disagrees with the key's is
§3's mixed width, **never coerced** — and that one is load-bearing, because this layer used
to RESOLVE the disagreement by preferring one side (Go built the key at the CIPHERTEXT's
width, C stamped 256 on everything it wrote), so a reader that silently prefers either
passes the whole matrix and mis-decrypts a foreign artifact.  `encfile`/`decfile` keep
their 256-bit requirement because the `.hkx` container has **no width field** at all.
(4) **MINOR, NOT MAJOR, AND THE ASYMMETRY WITH #313 IS THE POINT.**  #313 was MAJOR because
a working invocation started failing; this only GROWS the accepted set, so nothing becomes
unreadable and 256 is byte-for-byte untouched.  `MIGRATING.md` §23 exists anyway, because
there is a migration to describe — a pre-9.0.0 narrow ciphertext is readable now if and
only if PYTHON wrote it, Python's rule being the one the other three converged on — and §19
is marked superseded rather than edited.  (5) **THE MATRIX NEEDED A CONTROL THAT LETS IT
FAIL**, since it is now its own accept-control: case 0 decrypts a genuine artifact under a
DIFFERENT key and requires the result to DIFFER, or an `hske-nla1` that ignored its key
entirely scores 64/64.  Both real fixes were verified by REVERTING them; each alone turns
85/0 into 19 failures.  (6) **THE SCOPE CONTROL SURVIVED AND POINTS THE OTHER WAY** — a
relaxation that quietly widened is as much a scope error as a guard that did, so
`--algo hske` at a narrow width must still behave exactly as it did, and C's
`load_sym_key` still zero-extends for every other symmetric algo, unmeasured and untouched.
**The standing lesson, and where it paid**: #313's divergence survived a green 518-assertion
cross-language matrix because nothing ever ran the algorithm at a second width, and then it
survived a 376-case conformance vector for the type underneath it, in two ports, for the
same reason one level up.  A test that only ever asks one question cannot tell you about
the others, however many assertions it makes.

**And the two things a green local sweep did not run (TODO #315).**  #314 shipped six
passes with every local check green, and CI went red in two jobs on the same push — both
of them pass-2 and pass-4 defects, failing in opposite directions.  (1) **A CAST IS NOT A
DECLARATION.**  `Herradura cryptographic suite.c` cast a `uint8_t[KEYBYTES]` to a
`BitArray *` for the two HKEX-RNL contributory nonces, correct while a `BitArray` WAS a
byte array and, since pass 2, a read of an unset width AND a `sizeof(BitArray)`-byte write
into a `KEYBYTES` buffer.  It ran here because those locals sit deep in `main`'s frame and
this host's stack happened to hold a legal width.  Pass 2's poisoned build is the tool
that finds this, and pass 3 had already recorded why it did not: **a tool that enumerates
sites enumerates the sites you point it at**, and pass 2 pointed it at four files while
checking them by a grep for `BitArray` declarations.  The whole C tree is poison-built and
RUN now — suite, tests, CLI, both KAT consumers, the dudect audit, the deployed-ring
benchmark — and these two casts were the only ones.  **That sentence named SEVEN targets
where the tree has TEN, and TODO #324 found all three omissions carrying the defect** —
this list is the thing it describes, so it was also the record that made them invisible.
It is `tools/poison_build.sh` now, which DISCOVERS its set instead of naming it.  (2) **A CONTRACT CHANGE COSTS WHAT
THE OLD IMPLEMENTATION HAPPENED TO ACCEPT, which is a separate bill from what its
representation published.**  Pass 4's "the twenty `SecurityProofsCode/` scripts needed no
edit at all" was true of the ACCESSOR surface and read rather than measured; `BITARRAY.md`
§2's width rule is new, and `fscx_revolve_closed_form.py` (n = 8, n = 512) and
`nl_fscx_v2_kex.py` (n = 8…40 step 4) both raised `E_WIDTH` on their first call.  Both are
GATES, and they ran red for two releases because the job that runs them is the one job on
probation (TODO #317 has since promoted it) — #289's own premise, inverted: a
`continue-on-error` job's red is
indistinguishable from nobody having looked.  (3) **THE FIX COSTS A PROPERTY AND THE
SCRIPT SAYS WHICH.**  §4 of the closed-form script was PAIR-EXHAUSTIVE at n = 8; the
narrowest legal width is 16, whose pair space is 2^32, so pair-exhaustiveness is gone
permanently rather than relocated.  What replaces it is exhaustiveness in each operand
SEPARATELY (3 145 728 cases against 2 686 976), its RESULTS block states that this is the
weaker statement, and the sweep was verified to FAIL against a one-step-off closed form.
`nl_fscx_v2_kex.py` §1's ALL-SHORT orbit anomaly lived at n = 8 and n = 12 and no legal
width shows it — reported as such rather than dropped, with the anomaly left standing on
`nl_fscx_v2_orbit.py`, whose primitives are integer-only and under no width rule.  **A
normative width rule narrows what the analysis layer can ask, and the honest response is
to name the question that was lost.**

`.github/workflows/codeql.yml` runs a separate, non-blocking CodeQL static-analysis
matrix (C/C++, Go, Python) on every push/PR plus a weekly schedule (TODO #189); alerts
surface under the repo's Security tab rather than as a required check.

Whenever a TODO adds or removes a test number or CLI subcommand, re-check this section (and `llms.txt`'s CLI section) for drift rather than waiting for the next major-version doc audit — see TODO #145.

```bash
# C/Go/Python — security tests [1]–[31] + benchmarks [32]–[43], then [44]–[53]
# security tests and [54] one more benchmark, both APPENDED rather than
# renumbered.  (This line said "[1]–[29] + benchmarks [30]–[41]" for six
# releases, two renumberings behind the harnesses it describes — corrected
# by TODO #332, which had to read the index to add to it.)
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
#  SelfTest.java's [34]
#  [54] is TODO #332's BENCHMARK row for the deployed QC-MDPC KEM, and the only
#  one of [32]-[43]+[54] that carries a CONTROL.  The suite's own recommended
#  post-quantum key establishment had no harness-published cost figure at all --
#  not keygen, not encapsulation, not decapsulation -- so the only numbers for
#  it were hand-measured ones in CHANGELOG.md and MIGRATING.md, held to
#  nothing.  It carries a control because TODO #292's position is that a
#  host-specific cost figure does not belong in CI and this row prints in four
#  REQUIRED jobs: the grandfathered benchmarks print a rate nobody asserts on,
#  and this one earns its place by also being a test, at no extra cost, since
#  the operations it times are the ones it checks (decap(encap(pk)) reproduces
#  the key; a uniform syndrome gives a DIFFERENT one, so #235's
#  implicit-rejection path is reached rather than assumed).  The two decap paths
#  are TIMED AND LABELLED SEPARATELY because they cost different amounts -- the
#  GJS channel #330 registered in dudect Batch 10 -- and an averaged figure
#  would be unusable.  THREE harnesses, with the reason stated in each: the ARM,
#  NASM and Arduino harnesses carry no QC-MDPC, and JAVA shipped the KEM with
#  NO BENCHMARK LAYER AT ALL, so its gap was one layer wide where this was one
#  row wide (TODO #333, closed at v9.5.23).  Java's counterpart is now
#  Bench.java's [36] -- a SEPARATE entry point from SelfTest.java, run by its
#  own native-java step:
#      java -cp bindings/java herradurakex.Bench [-r N] [-t S]
#  Java's [1]-[35] are SelfTest's and [36] is Bench's; the two files share one
#  numbering space and spec/check_language_parity.py reads both)
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

**What `-t` actually bounds (TODO #225, corrected by TODO #327).** **The paragraph below
is a correct account of ONE mechanism and was, until #327, the only one recorded — which
made it misleading, because it is not where the time went.** `_bench`/`bench`, the
benchmark timing helper, had a 10-call warmup and checked elapsed only AFTER a 100-call
batch, so a **floor of 110 invocations no cap could reduce**: 66 of 138 rows overshot a
0.05 s cap in #326's own CI run, the worst by 6683×, and the Python harness's runtime did
not depend on `-r` or `-t` at all (it ran past 600 s at `-r` 2, 10, 50 and 500 alike).
That is fixed — the batch is now derived from one timed probe call in Python and Go, C
having always sized its batches per benchmark — so `-t` now does bound wall time in the
benchmarks. Read the two together: `_trange` is what follows, `_bench` was the larger
term. It caps iteration *count*, not wall time, and only at the granularity of `_trange`'s poll — `(i & 63) == 63`. A call site requesting fewer than 64 iterations is never polled, so the cap cannot reach it however slow its work becomes: 18 of the Python suite's 95 capped sites are in that category and carry ~71% of the time spent inside capped sites (worst: `test_hpke_stern_f_correctness`, 30 iterations requested, ~97 s against a 2.0 s cap). A truncated site always stops at a multiple of 64, never in between. Separately, 16 sites pass a literal count to `_trange` instead of `_iters(...)`, so `-r` does not reach them either. Every run now prints a closing `--- Time cap: ... ---` line reporting sites entered, truncated, and unpollable. The startup banner reports whether `_rnl_poly_mul` took the numpy or pure-Python path, and the `RNL_SIZES` the tests exercise — which is **not** the suite's deployed `RNLN`. That
sentence sat here as a framing note about COST until TODO #321 connected it to `[14]`'s
correctness assertion: those four widths are the ones #223 retired, per-coefficient
reconciliation error grows O(√n), so the tested ring is the FAVOURABLE one and the deployed
one was never asserted at all. `[14]`'s margin is now measured at n = 1024 by
`spec/measure_sampled_rates.py`, not by the harness. Baseline: `benchmarks/rnl_ring_cost.py`; for what the deployed ring costs in each language, `benchmarks/rnl_deployed_ring_cost.{c,go,py}` (TODO #292) — benchmark [40]'s own HKEX-RNL rows stop at the retired n = 256.

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
