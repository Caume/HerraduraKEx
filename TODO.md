# HerraduraKEx — Open TODO Items

> **Completed, deprecated, and acknowledged items have moved to [`TODO_DONE.md`](TODO_DONE.md) (TODO #154).** This file holds only entries with `Status: **OPEN**`. Item numbers are global and preserved across both files — when an item here is completed, move its whole entry to the end of `TODO_DONE.md` and update its Status line, per CLAUDE.md's TODO policy.

---

## Open items

New items go here with `Status: **OPEN**`; see CLAUDE.md.

---

### #243: does `twk` still belong at demo-only now that its three blockers are closed?

TODO #241 classified `twk` demo-only and named exactly three reasons: it shared an
unseparated subkey derivation with `fpe` and collided with it, it ran
`nl_fscx_revolve_v2` at 64 steps where HSKE-NL-A2 uses 192, and its `key ‖ tweak`
boundary was unencoded.  TODO #242 (v4.0.0) closed all three.

The row was not moved at the same time, deliberately.  Reclassifying a protocol because
the specific defects someone found have been fixed is the reasoning TODO #237 and #238
were filed to undo — it mistakes "no known problems" for "analysed".  This item is the
deliberate review that a promotion would need.

**The question.**  `twk` is now HSKE-NL-A2's `nl_fscx_revolve_v2` at A2's own round
count, under a subkey derived from the key and a per-(sector, block) tweak rather than
supplied by the caller.  A2 is rated "Production-track (conjectured), with two
constraints".  Does `twk` inherit that, and if so with which constraints?

**What has to be established, not assumed.**

* **A security definition.**  A2's row is about a keyed bijection used once per message.
  `twk`'s claim is a *tweakable* one — the standard target is STPRP (strong tweakable
  pseudorandom permutation), and nothing in the repository argues `twk` meets it.  A
  per-tweak-derived subkey is a construction, not a proof: the reduction has to say what
  happens when an adversary queries many tweaks under one key.
* **Whether A2's two constraints transfer.**  Determinism is inherent here and expected
  (XTS-style, per tweak) rather than a caveat, which is arguably *better* than A2's
  position.  The weak-key class is unreachable because the subkey is a hash output, which
  is also better.  Both differences point the same way, and both should be stated as
  findings rather than assumed.
* **What the round count actually buys.**  #214's trail projection is explicitly its own
  weakest step (slope read off widths 16–32, not 256).  "Now matches A2" is a
  comparative statement; a promotion needs more than parity with something whose own
  rating is conjectural.

**Do not treat this as a formality.**  The honest outcome may well be that `twk` stays
demo-only because NL-FSCX v2 has no positive security result at all, only key-averaged
trail bounds — in which case A2's own "production-track (conjectured)" rating is the
thing that deserves re-examination, and this item should say so rather than quietly
promoting `twk` to match it.

**Not in scope.**  `fpe`, whose naming defect is its own open question, and `rand`.

Status: **OPEN**
