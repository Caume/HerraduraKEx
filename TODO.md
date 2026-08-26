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

### #241: `rand`, `fpe` and `twk` ship with no security analysis anywhere in the repository

Found by TODO #238 Part C's audit of CLI surface invisible to `spec/`.  Three subcommands
reach no protocol entry, no `SECURITY.md` row, and no `SecurityProofs-*.md` section:

| subcommand | construction | analysis |
|---|---|---|
| `rand` | HDRBG deterministic byte generator over HFSCX-256 | none |
| `fpe`  | format-preserving encryption of a 256-bit block (TODO #78.A) | none |
| `twk`  | tweakable wide-block encryption of a 256-bit block (TODO #78.B) | none |

They are not obscure: all three ship in the C, Go and Python CLIs, and `rand` writes a
`HERRADURA HDRBG STATE` PEM that `CliTest/test_rand.sh` round-trips.  What is missing is
any statement of what they are supposed to guarantee.

**Why this is not a documentation task.**  #238 could not classify them the way it
reclassified `hpks-t` and `hpks-nl`, because those two had an existing analysis to
propagate — `hpks` is pedagogical because of Pohlig-Hellman, and the threshold and NL
variants are over the same group, so the verdict follows.  These three have no such
parent.  `fpe` and `twk` are their own constructions; `rand`'s HDRBG has a `DrbgMaxBlocks
= 1 << 20` reseed bound in `herradura/herradura.go:933` and nothing anywhere saying what
that bound is for.  Classifying them means doing the analysis, which is TODO #237-shaped
work.

**Interim state, deliberately visible rather than silent.**  #238 recorded all three in
`spec/herradura-protocol-spec.json`'s `unfiled_cli_surface` array and gave them a single
shared `SECURITY.md` row reading "Unclassified — no analysis exists", with the warning
that absence of a documented weakness there is absence of analysis rather than evidence of
strength.  `spec/generate_spec.py` fails if a *new* subcommand appears that is neither
bound to a protocol nor listed as unfiled, so the hole cannot grow while this is open.

**Work.**  For each of the three: state the security goal, identify the closest standard
construction (FF1/FF3-1 for `fpe`, a wide-block tweakable cipher such as AEZ or HCTR2 for
`twk`, SP 800-90A for `rand`), analyse the shipped construction against it, add a
`SecurityProofs-*.md` section, then file a real `SECURITY.md` row and `spec/` entry and
delete the `unfiled_cli_surface` record.  Expect at least one of the three to come out
worse than `demo-only` — `fpe` over a 256-bit block with no documented tweak schedule is
the one to look at first.

**Not in scope.**  Removing the subcommands.  They are shipped surface; the deficiency is
that nobody can tell what they promise.

Status: **OPEN**
