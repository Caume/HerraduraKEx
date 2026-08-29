# HerraduraKEx — Open TODO Items

> **Completed, deprecated, and acknowledged items have moved to [`TODO_DONE.md`](TODO_DONE.md) (TODO #154).** This file holds only entries with `Status: **OPEN**`. Item numbers are global and preserved across both files — when an item here is completed, move its whole entry to the end of `TODO_DONE.md` and update its Status line, per CLAUDE.md's TODO policy.

---

## Open items

New items go here with `Status: **OPEN**`; see CLAUDE.md.

---

### #245: remove NL-FSCX v2's self-similarity — round constants, or at least a prime round count

Raised by TODO #244, which downgraded HSKE-NL-A2 to demo-only.  Two candidate fixes came
out of #243 and #244 and neither was applied there, because both are wire-format breaks
and a rating review is the wrong place for one.  This item decides between them and
applies whichever survives.

**The problem.**  `nl_fscx_revolve_v2` is one unvaried round iterated `r` times, with no
round constant and no key schedule: `E_B = F_B^r`.  Two measured consequences
(SecurityProofs-7.md §11.25.2, §11.26.2):

* one slid pair leaves ~1.7 candidate keys out of `2^16` and two leave 1.08, so the only
  barrier to a slide attack is the ~`2^128` birthday cost of finding a pair — **a cost
  that does not depend on `r` at all**;
* `E[#fixed points] = tau(r) = tau(192) = 14` against an ideal cipher's 1, measured 13.84
  at `n = 16`.  Provably not an ideal cipher, as arithmetic rather than opinion.

Neither is an attack at `n = 256`.  Both are properties a production-track rating should
not have had to carry, and both are fixable.

**Option A — round constants.**  XOR a round-indexed constant into each step.  Breaks the
self-similarity outright: `E_B` stops being a power of one map, the slide structure goes,
and `tau(r)` stops being meaningful.  This is the standard fix and the reason round
constants exist.  Cost: a real change to the round function in C, Go, Python and the
Arduino/assembly ports, and **the existing trail bounds (#214) would have to be re-run** —
they are bounds on the current round, and adding a constant changes it.

**Option B — a prime round count.**  Change `R_VALUE` from 192 to 191 or 193.  One line
per language.  Drops the fixed-point excess from 13.8x to 1.04x (measured, §11.26.3).
Does **nothing** for the slide structure, which is the more serious of the two.  Cheap,
and strictly an improvement, but it treats the symptom.

**Recommendation to evaluate, not to assume.**  A alone is the principled fix; B alone is
insufficient; A+B together costs nothing extra over A, since both are the same wire break.
The open question is what A does to the trail bounds — if adding a round constant degrades
them, that has to be known before shipping, not after.  Re-running #214's SMT search on
the modified round is the gating work for this item.

**Reach — this is a four-construction break.**  `nl_fscx_revolve_v2` is used by HSKE-NL-A2,
`twk`, `fpe` and HSKE-Duplex.  Any change to the round function or the round count breaks
every stored artifact of all four, and for `twk` and `fpe` the failure is **silent**, since
both are unauthenticated permutations (MIGRATING.md §8 has the pattern).  One deliberate
MAJOR, one `MIGRATING.md` section, all four constructions at once.

**What this item may allow afterwards.**  If A lands and the trail bounds survive, the
structural objections in §11.25 and §11.26 stop applying and the ratings for A2 and `twk`
can be revisited on trail-bound evidence alone.  That would be a *separate* item — this one
ships the fix, it does not re-rate anything.  A rating review that grants itself a
promotion for work it also performed is the failure mode #237, #238, #243 and #244 have all
been about.

Status: **OPEN**
