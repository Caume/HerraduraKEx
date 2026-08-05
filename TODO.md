# HerraduraKEx — Open TODO Items

> **Completed, deprecated, and acknowledged items have moved to [`TODO_DONE.md`](TODO_DONE.md) (TODO #154).** This file holds only entries with `Status: **OPEN**`. Item numbers are global and preserved across both files — when an item here is completed, move its whole entry to the end of `TODO_DONE.md` and update its Status line, per CLAUDE.md's TODO policy.

---

## Open items

### 177. SecurityProofs.md — back-link to beginner docs and declutter the index (Documentation, Low)

`SecurityProofs.md` is a thin, honest index redirecting to the five `SecurityProofs-N.md`
Part files (split due to GitHub's ~750-expression-per-page KaTeX limit), but it offers no
path back to `docs/CRYPTOGRAPHY_BASICS.md`/`docs/INTRODUCTION.md` for a reader who lands
here first (e.g. via search or citation) without the prerequisite background, even though
those docs link forward to it. Its dense version-history "Status" text is also mixed
into what should be a pure navigational index.

**Work items:**

1. Add one line near the top pointing readers without prerequisite background to
   `docs/CRYPTOGRAPHY_BASICS.md` and `docs/INTRODUCTION.md`.
2. Move the version-history "Status" paragraph out of the primary index view (e.g. into
   a trailing footnote or a separate changelog-style subsection) so the file's routing
   table is the first thing seen.

Status: **OPEN**
