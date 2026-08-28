# HerraduraKEx — Open TODO Items

> **Completed, deprecated, and acknowledged items have moved to [`TODO_DONE.md`](TODO_DONE.md) (TODO #154).** This file holds only entries with `Status: **OPEN**`. Item numbers are global and preserved across both files — when an item here is completed, move its whole entry to the end of `TODO_DONE.md` and update its Status line, per CLAUDE.md's TODO policy.

---

## Open items

New items go here with `Status: **OPEN**`; see CLAUDE.md.

---

### #244: re-examine HSKE-NL-A2's "production-track (conjectured)" rating

Raised by TODO #243, which reviewed `twk` for promotion and kept it demo-only.  The two
rows are now inconsistent and the inconsistency is not in `twk`'s favour.

`twk` and HSKE-NL-A2 are the same permutation — `nl_fscx_revolve_v2` — at the same round
count.  #243 kept `twk` at demo-only because no SPRP result exists for that permutation.
A2 rests on exactly the same unproven claim and is rated **production-track
(conjectured)**, with *strictly worse* consequences if the claim fails: in `twk` the
subkey is a hash output, so recovery is confined to one (sector, block index) and does
not yield the key, while in A2 `B` **is** the caller's key.  Both ratings cannot be right.

**What #243 established that this item inherits** (SecurityProofs-7.md §11.25):

* v2-revolve is one unvaried round iterated 192 times, with no round constant and no key
  schedule, in C, Go and Python alike.
* One slid pair leaves ~1.7 candidate keys out of 2^16; two leave 1.08.  The barrier to a
  slide attack is only the ~2^128 birthday cost of finding a pair — **and that cost does
  not depend on the round count**, so A2's 192 rounds do nothing against this class.
* The only quantitative evidence for the permutation is TODO #214's trail bounds, which
  #214 itself labels an order-of-magnitude indication rather than a bound, and which are
  key-averaged precisely because the construction reuses one key every round.

**The question.**  Does "production-track (conjectured)" survive that?  The word
*conjectured* is carrying the whole rating, and #243's finding is that the conjecture has
less behind it than the label implies — in particular that a reader who sees
"production-track" will not infer "one unvaried round, no round constants, and a slide
structure the round count cannot improve".

**What has to be re-derived, not inherited.**  A2's row states two specific constraints
(determinism across messages; the degenerate affine key class rejected by
`nl_v2_key_is_valid`).  Whatever rating comes out, those two have to be restated against
whatever the new analysis finds rather than carried over unexamined — #237 and #238 exist
because propagated rows go stale.

**Scope is smaller than it looks, and worth stating up front.**  Four `SECURITY.md`
entries rest on NL-FSCX v2 — HSKE-NL-A2, HSKE-Duplex, `fpe` and `twk` — and three are
already research, broken or demo-only.  **A2 is the only production-track rating in the
suite that depends on this permutation.**  HPKS-NL / HPKE-NL name NL-FSCX but their
demo-only rating comes from Pohlig-Hellman on the GF(2^n)* group and does not depend on
v2's strength, so this item cannot make them worse.

**Two honest outcomes, and neither is foreordained.**  Either the conjecture is defensible
and the row should say plainly what it is conjecturing and what §11.25 found against it;
or it is not, and A2 joins `twk` at demo-only — which would be the first downgrade of a
production-track row in this suite and should be done deliberately, with `MIGRATING.md`
untouched (a rating is not a wire format) but the README's positioning of the NL/PQC
quartet revisited.

**Worth attempting first, because it could settle the item outright.**  Add round
constants.  A round-indexed constant XORed into each step would break the self-similarity
outright, and would cost nothing measurable — it is the standard fix and the reason round
constants exist.  If that is done, §11.25's slide finding stops applying and the rating
question narrows back to the trail bounds alone.  It is a wire-format break for A2,
`twk`, `fpe` and HSKE-Duplex together, so it belongs in one deliberate MAJOR rather than
being smuggled into a rating review — but a rating review that ignores an available
structural fix is the wrong shape.

Status: **OPEN**
