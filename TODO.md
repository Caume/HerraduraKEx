# HerraduraKEx — Open TODO Items

> **Completed, deprecated, and acknowledged items have moved to [`TODO_DONE.md`](TODO_DONE.md) (TODO #154).** This file holds only entries with `Status: **OPEN**`. Item numbers are global and preserved across both files — when an item here is completed, move its whole entry to the end of `TODO_DONE.md` and update its Status line, per CLAUDE.md's TODO policy.

---

## Open items

### 174. docs/INTRODUCTION.md — numbering, notation consistency, and a chained worked example (Documentation, Medium)

`docs/INTRODUCTION.md` is the most didactic document in the repo (reading-order table,
toy examples, historical citations, glossary, decision tree) but at 1251 lines has no
progress markers, uses fractional Part numbers ("Part 4.5", "Part 10.4") that break the
otherwise-integer sequence, and its GF(2^n)* notation doesn't match README.md's
blackboard-bold `\mathbb{GF}(2^n)^*`. The Part 3.1 (paint-mixing DH) and Part 6.2
(Schnorr identification) sections describe step-by-step message exchanges in prose only,
with no diagram. There is also no single example that chains HKEX-GF's derived key
into an actual HSKE encrypt/decrypt with small, hand-verifiable numbers.

**Work items:**

1. Add a per-Part estimated read time or a short progress indicator at each Part
   heading so the document feels navigable.
2. Resolve the fractional Part numbers ("Part 4.5", "Part 10.4") — either renumber the
   sequence or explicitly label them as optional digressions.
3. Standardize GF(2^n)* notation with README.md (pick blackboard-bold or plain, not
   both) and add a one-time footnote noting they denote the same field.
4. Add one end-to-end worked example late in Part 4 that chains the Part 3 DH numbers
   into an HSKE encrypt/decrypt at a small bit-width, verifiable by hand.
5. Convert the Part 3.1 paint-mixing and Part 6.2 Schnorr descriptions into mermaid
   sequence diagrams (GitHub renders these natively) rather than prose-only.

Status: **OPEN**

### 175. docs/CRYPTOGRAPHY_BASICS.md — TL;DR box, negligibility example, and factoring caveat (Documentation, Low)

`docs/CRYPTOGRAPHY_BASICS.md` is close to ideal for its target reader but has three
specific gaps: no TL;DR/time-estimate at the top for a reader deciding whether to commit
to the full 324 lines; `negl(n)`/`poly(n)`/`Pr[event]` are introduced only as notation-
table rows (§4) with no worked example, unlike §3.2's clock-arithmetic treatment; and
§2.3's prime-factoring one-way-function example could read as what this codebase relies
on, when the suite's actual hard problem is discrete log over GF(2^n), not factoring.

**Work items:**

1. Add a 2-3 sentence TL;DR/abstract box after the title, naming the four core
   properties (confidentiality/integrity/authentication/non-repudiation) and an
   estimated reading time.
2. Add a short worked example directly below the notation table's `negl(n)`/`poly(n)`
   rows (e.g. comparing 2^128 brute-force guesses against a fast attacker's guess rate)
   so "negligible" is grounded the same way clock arithmetic was.
3. In §2.3, explicitly flag that prime factoring is illustrative of one-way functions
   in general (RSA), and separately name that this codebase's actual hard problem is
   the discrete-log problem over GF(2^n).
4. Add a small ASCII diagram for Kerckhoffs's principle (public algorithm box vs.
   secret key box) in §2 to visually anchor the public/private split.

Status: **OPEN**

### 176. docs/examples/ — add a local README and remove stray `__pycache__` (Documentation, Low)

The four samples in `docs/examples/` (`c/hello_herradura.c`, `go/hello_herradura.go`,
`python/hello_herradura.py`, `mcp/hello_herradura_mcp.py`) are consistently linked from
`README.md`, `llms.txt`, and `docs/TUTORIAL.md`, but the directory itself has no README
explaining what each sample demonstrates or what order to try them in. A stray
`docs/examples/mcp/__pycache__/` directory is also checked into the repo.

**Work items:**

1. Add `docs/examples/README.md` briefly describing each sample and a suggested
   reading order (e.g. Python first as the reference implementation, then C/Go, then
   the MCP example last since it depends on understanding the CLI surface).
2. Remove the checked-in `__pycache__` directory and add `__pycache__/` to `.gitignore`
   if not already covered.

Status: **OPEN**

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
