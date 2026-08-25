# HerraduraKEx — Open TODO Items

> **Completed, deprecated, and acknowledged items have moved to [`TODO_DONE.md`](TODO_DONE.md) (TODO #154).** This file holds only entries with `Status: **OPEN**`. Item numbers are global and preserved across both files — when an item here is completed, move its whole entry to the end of `TODO_DONE.md` and update its Status line, per CLAUDE.md's TODO policy.

---

## Open items

New items go here with `Status: **OPEN**`; see CLAUDE.md.

---

### #235: HPKE-Stern-KEM — add an FO transform with implicit rejection, and screen weak keys at keygen

Found while auditing the six `demo-only` entries in `spec/herradura-protocol-spec.json`.
`SecurityProofsCode/qcmdpc_dfr_weak_keys.py` (TODO #218) already established the facts;
this item is the remediation half that #218 deliberately left unfiled.

#218's §7 verdict lists four blockers, and states that they *compound rather than trade
off*: "Even a DFR of 2^-128 would not make this KEM IND-CCA2 while decapsulation reports
failure, and implicit rejection would not fix a 2^-8.8 DFR either."  Two of the four are
parameter choices that cannot be fixed without a redesign; **two are missing constructions
that can be added at the deployed parameters.**  This item is exactly those two.

**Out of scope, explicitly.** Raising `QCMDPC_R`/`_D`/`_T` from the deployed
`523 / 15 / 18` toward BIKE-128's `12323 / 71 / 134`, and moving Stern's `N=256` toward
the `N >= 17000` floor of SecurityProofs-5.md §11.8.4.  Those are a redesign, not a
tuning pass; the DFR(r) fit in #218 §3 is a lower bound (waterfall concavity) and r is
not even the right knob alone.  **Closing this item does not make HPKE-Stern-KEM
production-ready, and its `demo-only` status in `spec/` and SECURITY.md must not change.**
What it does is remove the two blockers that are cheap, self-contained, and currently
make the KEM weaker than its own parameters require.

**Part 1 — weak-key screen at keygen.**  `qcmdpc_keygen` retries only on a non-invertible
`h0`.  #218 §4 measures DFR varying materially with distance-spectrum multiplicity, and
~1 key in 3400 carrying roughly 10x the average DFR.  The screen is a rejection-sampling
loop around the existing support generation: compute the multiset of cyclic distances
within `sup0`/`sup1`, reject and redraw when max multiplicity exceeds the threshold #218
§4(c) pins.  Non-breaking — keygen output stays the same shape, only the accepted subset
of keys narrows.  Must land in C (`herradura.h`), Go (`herradura/herradura.go`) and
Python identically, since all three share the deployed parameters.

**Part 2 — FO transform with implicit rejection.**  `qcmdpc_decap_bgf` signals failure
explicitly, at every layer: a distinct library return value, and a distinct exit status
plus stderr message at the CLI (#218 §6).  That is the GJS oracle, and #218 §5 measures
the reaction attack end to end.  The fix is the standard one: decapsulation re-encrypts
and, on any mismatch or decoder failure, returns a pseudorandom key derived from a
secret seed rather than an error — the caller cannot distinguish success from failure.

**Primitive constraint (checked, not assumed).**  Both parts stay inside FSCX and add no
external primitive:
  * `qcprf_refill` (herradura.h) derives the QC-MDPC supports via
    `nl_fscx_revolve_v1_ba(&block, &rolx, &x, I_VALUE)` — the screen sits on top of an
    FSCX-derived support and touches no primitive at all.
  * `qcmdpc_encap` already derives `K = hfscx_256(e0 || e1)`, and `hfscx_256`'s
    compression step is `nl_fscx_revolve_v1_ba(&state, &state, &block, 64)`.  FO's
    re-encryption path reuses both.
  * **Use `hfscx_256_ds` (herradura.h:839), not bare `hfscx_256`, for every FO hash.**
    HFSCX-256 is Merkle-Damgard, so length-extension applies, and FO re-encryption hashes
    attacker-influenced data.  The domain-separated variant already exists (TODO #93) and
    `SecurityProofsCode/hfscx_dm_rf_model.py` (TODO #215) supplies the ideal-random-function
    argument the FO proof needs.  Bare HFSCX-256 here would be a real bug, not a style
    preference.

**Wire-format impact.**  Part 2 changes what decapsulation returns on a failure path, so
a `MIGRATING.md` entry is required per CLAUDE.md even though the ciphertext encoding need
not change.  Decide during implementation whether the re-encryption check alters the
ciphertext itself; if it does, this is the MAJOR-worthy half of the item and must say so.

**Interaction with the DFR retry policy.**  `CliTest/lib_dfr.sh` (TODO #221) retries a
fresh encapsulation on a *detected* DFR event.  Implicit rejection removes the signal that
policy keys off: after Part 2 a decoding failure is indistinguishable from success and
surfaces as a wrong shared secret instead.  Every script sourcing `lib_dfr.sh`, and the
CI DFR-guard step in `ci.yml` that enforces the sourcing, has to be revisited in the same
change — this is the part of the work most likely to be underestimated.

**Acceptance.**  #218's script is the oracle: re-run `qcmdpc_dfr_weak_keys.py` and require
§4's weak-key tail to be gone from what keygen emits, and §5's reaction-attack
distinguisher to lose its signal.  Update §11.8.7 of SecurityProofs-5.md and the
SECURITY.md row to state which two of the four blockers now fail to apply, and which two
still stand.

Status: **OPEN**

### #236: The C CLI's Stern round count is a compile-time wire parameter, and CI works around it by downgrading credentials to 32 rounds

Found while checking whether HPKS-Stern-F's `SDF_ROUNDS=32 -> 219` upgrade path
(SECURITY.md, spec `hpks-stern` notes) is actually reachable in each CLI.  In Python and
Go it is.  In C it is not, and the workaround is already in the test suite.

**The mechanism.**  The PEM *already carries the round count* — `stern_sig_load`
(HerraduraCli/herradura_cli.c:1835) reads it as item[1] and then rejects it:

    if (r != SDF_ROUNDS) { pem_key_free(&pk); return -1; }

`stern_sig_load_label` (line 4102) does the same for HCRED credentials.  The `SternSig`
struct (herradura.h:1889) is fixed-size — `BitArray c0[SDF_ROUNDS]`, and so on — as are
`STERN_COMMITS_BYTES` / `STERN_CHAL_BYTES` / `STERN_RESP_BYTES` (herradura_cli.c:1776-1778).
Go by contrast decodes `rounds := bytesToInt(ints[1])` (herradura_cli.go:2050) and
allocates from it, and Python does the same.

Measured, C CLI built both ways against Python-produced signatures:

    cli32  verifying python sig r=32:  Signature OK
    cli32  verifying python sig r=219: verify: cannot load Stern signature
    cli219 verifying python sig r=32:  verify: cannot load Stern signature
    cli219 verifying python sig r=219: Signature OK

So the two builds are mutually unreadable, in both directions.

**This is not hypothetical — CI is already accommodating it.**
`CliTest/test_cred_interop.sh:120-122` and `:146-148` issue HCRED credentials for the C
CLI to consume with an explicit `--rounds 32`, commented "must match C's SDF_ROUNDS=32
for interop".  Python's and Go's own default is `_HCRED_SIGN_ROUNDS = 219` /
`hcredSignRounds = 219`, chosen for 128-bit soundness.  The consequence: **cross-language
HCRED interop is only ever exercised at 32 rounds — (2/3)^32 rather than the (2/3)^219
the issuers otherwise use** — and any real deployment with a C consumer forces every
issuer down to the same demo soundness.

**Work.**  Make the C reader length-dynamic, matching Go: give `SternSig` a `rounds`
field and heap-allocate its arrays, derive the three `STERN_*_BYTES` sizes from the
decoded round count rather than the macro, and bound the decoded value (Go's decoder and
the existing ZKP-NL unpack at herradura_cli.c:327 both range-check; do the same).
`SDF_ROUNDS` remains the *signing* default.  About 45 references across
`herradura.h` (25) and `herradura_cli.c` (20).

**Explicitly non-breaking, and this is the point of doing it this way.**  The wire format
does not change — the round count is already on the wire.  A dynamic reader is purely
additive: it accepts everything the current build accepts, plus round counts it currently
rejects.  So this is a PATCH bump with no `MIGRATING.md` entry.  *Changing the signing
default* from 32 to 219 would be the breaking change (old readers reject new signatures),
and is deliberately not part of this item — do the reader first so the default can move
later without a flag day.

**Acceptance.**  Drop the two `--rounds 32` workarounds from `test_cred_interop.sh` and
let it run at the issuers' own 219-round default; add a C-side round-trip at a round count
other than `SDF_ROUNDS` to whichever of `test_c_*.sh` covers Stern-F.  Both must pass
against a stock `./build_c.sh` binary.

**Not in scope.**  The round count and the instance hardness are independent axes.  219
rounds over the deployed `N=256` instance is worth ~30-40 bits either way
(SecurityProofs-4.md:632), so this item does not change any `demo-only` status; it only
makes the soundness axis reachable from C.  See #235's out-of-scope note for the
parameter side.

Status: **OPEN**

### #237: `spec/` classifies OPRF and HSKE-NL-A1/A2 as `production` where SECURITY.md and the proofs disagree — adjudicate and reconcile

Found while auditing the six `demo-only` entries for #235/#236.  Both rows say
`status="production"` in `spec/generate_spec.py`; neither is supported by the security
documentation, but **they fail in different ways and need different work.**  The fix goes
in `spec/generate_spec.py` (lines 229-232 and the `"oprf"` entry), not the generated JSON.

**Part 1 — OPRF: not a disagreement, an absence.**

`grep -l OPRF SecurityProofs-*.md` returns nothing.  `grep -c OPRF SECURITY.md` returns 0.
Same for aPAKE.  Both shipped (TODO #80, #201, #203) with CLI subcommands
(`oprf-blind`/`oprf-eval`/`oprf-unblind`, `pake-register`/`pake-demo`) and, for OPRF, a
`production` label carrying no analysis anywhere in the repo.

The label is also internally inconsistent *within `generate_spec.py` itself*.  `oprf` is
`gf_pow` in the same group as `hkex-gf`/`hpks`/`hpke` — the suite's `oprf_eval` is

    return gf_pow(alpha & ORD, k & ORD, GF_POLY[KEYBITS], KEYBITS)

with `ORD = 2^KEYBITS - 1`.  Those three neighbours are all marked `status="pedagogical"`
with `classical_security_bits="~36.5 (n=256)"`, from TODO #212's Pohlig-Hellman result.
`oprf` gets `status="production"` and the note *"inherits GF(2^n)* classical-only
security"* — which understates a ~36.5-bit break as if it were a 128-bit classical one.

Confirmed by running TODO #212's own `pohlig_hellman()` against the exact relation
`oprf_eval` implements — one `(alpha, beta)` pair, solving for `k` with `g = alpha`:

    n= 32  largest prime factor 17 bits  recovered=YES  in 0.01s
    n= 64  largest prime factor 23 bits  recovered=YES  in 1.00s

At the deployed n=256 the largest prime factor of `2^256-1` is 73 bits, giving #212's
~2^36.5.  Recovering `k` is the whole ballgame for an OPRF: obliviousness protects the
*client's* input from the server, but `k`'s secrecy is what stops anyone who has seen one
transcript from evaluating `F(k, ·)` offline on inputs of their choosing — i.e. an offline
dictionary attack wherever the OPRF is used for password-like inputs, which is what aPAKE
uses it for.

**Work for Part 1.**  Reclassify `oprf` to match its neighbours (`pedagogical`, or
`demo-only` — pick one and say why), give it a real `classical_security_bits`, and rewrite
the note so it states the ~2^36.5 recovery rather than "classical-only".  Add SECURITY.md
rows for OPRF **and aPAKE**, and extend `SecurityProofsCode/hkex_gf_pohlig_hellman.py` to
cover the OPRF relation (it currently covers HKEX-GF/HPKS/HPKE only; the demo above is 20
lines and belongs in that script, not in a TODO entry).  Decide separately whether aPAKE
needs its own spec row at all — see Part 3.

**Part 2 — HSKE-NL-A1/A2: a real disagreement, and it needs adjudicating before either
document is edited.**

SECURITY.md:18 puts HSKE-NL-A1/A2 in one row with classical HSKE known-plaintext: *"Not
suitable for production — a single known-plaintext pair recovers the keystream."*
`spec/` says `production`.  The proofs support **both** readings, in different places:

  * **For `production`:** §11.3.1 gives a conditional CPA claim — *"Non-linearity prevents
    GF(2) linear recovery of K from any set of (plaintext, ciphertext) pairs.  Assuming
    NL-FSCX v1 acts as a pseudorandom function (PRF), CPA security follows from standard
    stream cipher arguments."*  And TODO #210's correction in §11.7 explicitly exempts
    these two from the fatal ciphertext-only leak: *"This does not extend to
    HSKE-NL-A1/A2, whose carry non-linearity breaks the affine identity the argument
    depends on."*
  * **For SECURITY.md:** the §11.7 table rows read `HSKE-NL-A1 (known-plaintext) — Linear
    recovery blocked; 1-pair attack still recovers keystream → **None** (keystream
    recoverable)`, and the prose says the NL variants *"do not eliminate the 1-pair attack
    because the underlying structure remains affine."*

**Those last two quotes contradict each other, two paragraphs apart in the same section.**
One says the carry non-linearity breaks the affine identity; the other says the structure
remains affine.  That contradiction is the actual bug to fix, and it must be settled
before the labels are touched — editing either document first would just pick a side.

The question to answer: for a counter-mode stream cipher, one KPT pair recovering *that
block's* keystream is inherent to the mode and is not a break.  Does the §11.7 row mean
only that (in which case `production` is right, and SECURITY.md:18 is miscategorising the
NL variants by merging them into classical HSKE's genuinely fatal 1-pair row), or does it
mean a pair yields *other* blocks' keystream or `K` itself (in which case `spec/` is
wrong)?  §11.3.1's nonce/counter construction and the ROL seed rotation are the relevant
detail.  TODO #214's exact-trail work (`nl_fscx_exact_trail_search.py`) is the closest
existing measurement of what survives statistically.

**Do not assume the answer from this entry.**  It is written to lay out both sides, not to
pre-judge; whichever way it goes, one of the two documents gets corrected and §11.7's
internal contradiction gets resolved in the same change.  If the outcome is that the NL
variants are sound, `hske-duplex` (also `production`, also unanalysed in SECURITY.md)
should be checked in the same pass, since it is the same family.

**Part 3 — root cause, and why this drifted (optional, decide during triage).**

`KAT/generate_kat.py` and `SecurityProofsCode/check_part_index.py` both have `--check`
modes wired into CI (TODO #190, #231).  `spec/generate_spec.py` has neither a `--check`
mode nor any CI job — nothing checks that the generated JSON is current, and nothing
checks that a `status=` in it agrees with SECURITY.md's table or with the proofs.  aPAKE
having no spec row at all (the string "PAKE" appears once in the whole JSON, as
`PEM_PAKE_RECORD`) is the same gap showing up as missing coverage rather than a wrong
label.  A `--check` mode plus a cross-reference assertion against SECURITY.md's table
would have caught all three findings above.  This is scope beyond the two rows named in
the title — split it into its own item if it makes this one too large.

Status: **OPEN**

---
