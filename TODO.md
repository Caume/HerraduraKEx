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

### #238: `spec/generate_spec.py` has no `--check` mode and no CI job, and its protocol list cannot express aPAKE

Split out of TODO #237 Part 3, which found three wrong `status=` labels in `spec/`
(`oprf`, `hske-duplex`, and the HSKE-NL rows) and identified the same root cause behind
all of them: nothing checks the generated spec.

**Part A — no `--check` mode, no CI job.**  `KAT/generate_kat.py` and
`SecurityProofsCode/check_part_index.py` both have `--check` modes wired into CI (TODO
#190, #231), and the latter caught real drift during #237 — the math-expression count for
SecurityProofs-4.md moved 659 -> 684 and every copy of the part index had to be updated.
`spec/generate_spec.py` has neither.  Nothing verifies that
`spec/herradura-protocol-spec.json` is current with respect to its generator, so a change
to the generator that is never re-run ships a stale JSON silently.  Add `--check` and a CI
step, following the shape `check_part_index.py` already uses.

**Part B — cross-reference `status=` against SECURITY.md.**  All three #237 findings were
disagreements *between documents* that no tool could see: `spec/` said `production` where
SECURITY.md said "not suitable for production" (HSKE-NL-A1/A2), where the proofs said
"open research" (`hske-duplex`), and where no analysis existed at all (`oprf`).  A check
that every `--algo` tag in `spec/` has a row in SECURITY.md's protocol table, and that the
two classifications are consistent, would have caught all three.  The mapping between
`spec/`'s six-value status enum (`production`/`demo-only`/`pedagogical`/`deprecated`/
`broken`/`research`) and SECURITY.md's prose status column has to be defined first; that
definition is most of the work in this part.

**Part C — the protocol list cannot express aPAKE.**  `spec/`'s protocol array is keyed on
`--algo` tags.  aPAKE has none: it ships as the standalone subcommands `pake-register` and
`pake-demo`, so there is no key under which to file it, and the string "PAKE" appears once
in the whole JSON as `PEM_PAKE_RECORD`.  #237 gave it a SECURITY.md row (it inherits the
OPRF's ~2^36.5 server-key recovery, which voids the offline-dictionary resistance that is
its entire purpose) but deliberately did not invent a spec row, because doing so is a
schema question rather than a labelling one: either widen the protocol array's key beyond
`--algo` tags, or add a separate `subcommand_protocols` section.  Decide which, then file
aPAKE and audit whether anything else in the CLI is invisible to `spec/` for the same
reason.

Status: **OPEN**

### #239: `ring_sig_load` sizes its allocations from two unbounded PEM fields

Found while closing TODO #236, which bounded exactly this class of value for
`stern_sig_load` — the ring-signature reader next to it was never given the same
treatment.  `ring_sig_load` (HerraduraCli/herradura_cli.c:2024) is *not* affected by
#236's actual defect: it already decodes the round count and allocates from it, rather
than comparing it against `SDF_ROUNDS`.  The problem is that it trusts what it decodes.

**The mechanism.**  Both `k` and `rounds` come straight off the wire with no range check:

    int k      = (int)parse_be_uint(pk.vals[0], pk.vlens[0]);
    int rounds = (int)parse_be_uint(pk.vals[1], pk.vlens[1]);
    size_t entry = 5 * (size_t)KEYBYTES + 1;          /* 161 */
    size_t blen  = (size_t)k * rounds * entry;
    uint8_t *blob = (uint8_t *)calloc(blen ? blen : 1, 1);

`ring_load_members` bounds the *caller's* member count at `RING_MAX_K` (64), and the
signing path rejects `k >= RING_MAX_K` at line 1964, but neither applies here: the
signature's own `k` is compared against the caller's only *after* `ring_sig_load` has
returned (line 3388), so the allocation above happens first.

**Confirmed reachable, under `herradura_cli_asan`** with a hand-crafted
`HERRADURA HPKS-RING SIGNATURE` PEM and two genuine member public keys:

    k=2           rounds=2^30   -> allocator is trying to allocate 0x5080000000 bytes
    k=2^30        rounds=2^30   -> requested allocation size 0x1000000000000000 exceeds
                                   maximum supported size of 0x10000000000
    k=2^31-1      rounds=2                     -> same class

In a normal build `calloc` returns NULL and `die("out of memory")` fires, so **what is
demonstrated today is a denial of service / abort on a malformed signature, not memory
corruption.**  A verifier is exactly the component that handles attacker-supplied input,
so an unbounded allocation driven by two of its fields is still worth closing.

**Two latent defects behind it, neither currently reachable past the failing calloc:**

1. `blen = (size_t)k * rounds * entry` can wrap.  `k` and `rounds` are each up to
   `2^31-1`, so the product reaches ~7.4e20 against a `2^64` ~ 1.8e19 modulus.  A wrapped
   `blen` would allocate a small buffer while the `k * rounds` loop below it — whose bound
   does not depend on `blen` — kept reading, which is an out-of-bounds read rather than an
   abort.  A bounded search for a `(k, rounds)` pair that lands `blen` small enough to
   demonstrate this did not find one within the window tried; nothing rules it out, and
   the fix (bound the inputs) removes the question either way.
2. `stern_ring_alloc` (herradura.h:2078) computes `int sz = k * rounds` in `int`.  At
   `k = rounds = 2^30` that is signed overflow — undefined behaviour — before the result
   is passed to `malloc`.  Unreachable today only because the `calloc` above aborts first.

**Also missing: a declared-vs-actual length check.**  `pk.vlens[3]` is the real blob
length; when it is shorter than `blen` the reader right-aligns and zero-pads rather than
rejecting, so a signature whose declared `k`/`rounds` disagree with its payload is
silently treated as mostly zeros.  TODO #236 added exactly this check to the Stern-F
reader (`if (pk.vlens[2] > cm_len || ...) return -1`); the ring reader should get its
counterpart.

**Work.**  Range-check `k` and `rounds` immediately after decoding — `k` against
`RING_MAX_K` (the same bound the signing path and `ring_load_members` already use) and
`rounds` against `SDF_MAX_ROUNDS` (added in #236) — before either is used in an arithmetic
expression.  Reject rather than clamp: a signature declaring more members than
`RING_MAX_K` is malformed, not merely large.  Then add the `pk.vlens[3]` vs `blen`
agreement check, and make `stern_ring_alloc` compute its size in `size_t`.  Check the
other `parse_be_uint` readers in the same file for the same shape while there — this item
is about the pattern, not only this one call site.

**Not in scope.**  Raising or removing `RING_MAX_K`, and the ring signature's soundness
or parameters.  `hpks-ring` remains `demo-only` in `spec/`, inheriting `hpks-stern`'s
round-count caveat; this is an input-validation fix, not a security-level change.

Status: **OPEN**
