# HerraduraKEx — Open TODO Items

> **Completed, deprecated, and acknowledged items have moved to [`TODO_DONE.md`](TODO_DONE.md) (TODO #154).** This file holds only entries with `Status: **OPEN**`. Item numbers are global and preserved across both files — when an item here is completed, move its whole entry to the end of `TODO_DONE.md` and update its Status line, per CLAUDE.md's TODO policy.

---

## No open items

All numbered work items (#1–#168) are currently resolved and archived in
[`TODO_DONE.md`](TODO_DONE.md) with `DONE` / `DEPRECATED` / `ACKNOWLEDGED` status lines.
The 2025-2026 cryptanalysis literature review that opened #156-#163 is complete; its
findings are recorded in `SecurityProofs-1.md` §6, `SecurityProofs-2.md` §11.8.4, §11.6,
§11.19, and the associated `SecurityProofsCode/` worksheets.

Add new items here with `Status: **OPEN**`, continuing the global numbering from #169 —
numbers are never reused across the two files, per CLAUDE.md's TODO policy.

Known follow-up work that is deliberately *not* filed as an item (recorded where it
belongs instead):

- Porting the NL-FSCX v2 affine weak-key guard (TODO #168) to the ARM Thumb-2, NASM i386,
  and Arduino targets, where the class density is $2^{-17}$ at $n=32$ rather than
  $2^{-129}$ at $n=256$. Those targets are demo-only; see `SecurityProofs-2.md` §11.19.2.
