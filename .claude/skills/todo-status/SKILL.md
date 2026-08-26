---
name: todo-status
description: "Status-line format for TODO.md / TODO_DONE.md entries in HerraduraKEx: the keyword table, parse rules, the missing-Status quick-check one-liner, and the grandfathered pre-#154 sections. Load when opening, closing, or auditing a TODO entry."
---

# TODO.md / TODO_DONE.md Status line standard

Every `### ` section in `TODO.md` or `TODO_DONE.md` must end with exactly one `Status:` line using one of these keywords:

| Keyword | Meaning | Format example |
|---|---|---|
| `DONE` | Implemented and shipped | `Status: **DONE vX.Y.Z** — one-line summary.` |
| `OPEN` | Pending — not yet started or in progress | `Status: **OPEN**` |
| `DEPRECATED` | Will not be fixed; reason documented | `Status: **DEPRECATED** — reason.` |
| `ACKNOWLEDGED` | Known issue, accepted by design, no action planned | `Status: **ACKNOWLEDGED** — reason.` |

Rules:
- The `Status:` keyword starts at column 0 with no leading `**`.
- The keyword (`DONE`, `OPEN`, etc.) is bold: `**KEYWORD**`.
- For `DONE`, append the version tag and a dash-separated summary: `**DONE vX.Y.Z** — summary.`
- No item should be left without a `Status:` line.  A missing Status line means "open" only by convention; always add an explicit `Status: **OPEN**` when creating a new item.
- When parsing programmatically, match `^Status: \*\*` at the start of a line within the section.

**Quick check:** `python3 -c "import re,sys; [print(m.group()) for f in ('TODO.md','TODO_DONE.md') for m in re.finditer(r'(?m)^### .+\n(?:(?!^Status:)[\s\S])*?(?=^###|\Z)', open(f).read()) if 'Status:' not in m.group()]"` — prints any `###` section (in either file) that is missing a Status line. `TODO.md` sections should additionally all say `**OPEN**`, and `TODO_DONE.md` sections should never say `**OPEN**` — a mismatch means an entry wasn't moved when its status changed. Sections predating the `Status:` line standard (TODO #154) — `TODO_DONE.md`'s `### 13`, `### 17`, `### 18`, `### 24`–`### 28`, `### 42`, `### 56`, `### 69`, `### 70`, `### 77`–`### 80` (16 sections in all) — carry no `Status:` line at all. Two of them (`### 13`, `### 26`) mark completion with an inline `✓ DONE`/`DONE (vX...)` marker in the heading; the other fourteen record it only by living in `TODO_DONE.md` and having a `CHANGELOG.md` entry. All 16 are grandfathered rather than backfilled, so the quick-check flagging them is expected and not itself a bug.
