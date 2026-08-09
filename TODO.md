# HerraduraKEx — Open TODO Items

> **Completed, deprecated, and acknowledged items have moved to [`TODO_DONE.md`](TODO_DONE.md) (TODO #154).** This file holds only entries with `Status: **OPEN**`. Item numbers are global and preserved across both files — when an item here is completed, move its whole entry to the end of `TODO_DONE.md` and update its Status line, per CLAUDE.md's TODO policy.

---

## Open items

### #181: Audit stale in-source TODO/FIXME comments

A repo-wide grep found ~180 TODO/FIXME comments scattered across source files (heaviest in `CryptosuiteTests/Herradura_tests.{c,py}` at 33/31, `HerraduraCli/herradura.py` at 40, and numerous `SecurityProofsCode/*.py` research scripts). Triage these for ones that are resolved-but-never-removed or otherwise stale, and either delete the cruft or promote genuinely open ones into tracked TODO.md entries with proper numbering.

Status: **OPEN**
