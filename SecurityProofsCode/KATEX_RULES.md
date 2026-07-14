# KaTeX Rendering Rules for Markdown Files

GitHub renders math in `README.md`, `SecurityProofs.md`, and similar files via KaTeX.  The pipeline is **markdown (CommonMark/GFM) first, then KaTeX**: backslash escapes inside math spans are resolved by the markdown layer **before** KaTeX sees the input.  Every patch below is verified against this pipeline (not against pure KaTeX) — see the validation script section.

Read this file before editing math in `SecurityProofs*.md`, `README.md`, or any other markdown file with `$...$`/`$$...$$` spans.

## Root cause behind most of these rules

CommonMark resolves `\_` (and other `\<ASCII-punctuation>` escapes) to the bare character **before** KaTeX ever sees the input. A bare `_` next to non-space, non-punctuation characters becomes a flanking emphasis delimiter, which CommonMark's emphasis parser can pair with any other flanking `_`/`*` later in the same paragraph — even across `$...$` boundaries — producing an `<em>` span that swallows part or all of the math. Rules 1, 2, 8, and 11 below are all instances of this one mechanism; the fix is always the same shape: eliminate the bare `_`/`*` (via `\text{...-...}` hyphenation, function notation, or braces) so there's nothing for the emphasis parser to grab.

### Rule 1 — never put `_` between `\text{}` blocks

CommonMark resolves `\_` inside math spans to a literal `_`, which KaTeX then parses as the **subscript operator**.  Two implications:

- `\text{A}\_\text{B}` becomes `\text{A}_\text{B}` after markdown — a single subscript that *renders* but visually attaches `B` underneath `A`.
- `\text{A}\_\text{B}\_\text{C}` becomes `\text{A}_\text{B}_\text{C}` — two subscripts on the same base, which KaTeX rejects with **"Double subscripts: use braces to clarify"**.

`\textunderscore` is also wrong — it is a text-mode-only command in KaTeX 0.16+, and rejected wherever the parser is in math mode (which includes positions between `\text{}` blocks).

### Rule 2 — never put a bare `_` inside `\text{}`

CommonMark resolves `\_` inside `\text{...}` to `_` as well.  KaTeX then sees `\text{FOO_BAR}` and rejects with **`"_" allowed only in math mode`**.

### Rule 3 — never use `\$` or `\textdollar` in math mode

`\$` inside `$...$` is consumed by markdown (the second `$` closes the span and KaTeX gets an unclosed brace).  `\textdollar` is text-mode-only in KaTeX 0.16+ and rejected anywhere in math mode.

### Rule 4 — never write `^*` inside a math span

A literal `*` in math mode is paired by markdown's emphasis parser with any other `*` later in the same paragraph (across math-span boundaries). The first `*` opens `<em>` mid-span, breaking math recognition entirely.  Use `^{\ast}` instead — `\ast` renders identically to `*` and the leading `\a` is not a markdown emphasis marker.

### Rule 5 — display `$$...$$` blocks must be on their own line with blank lines before and after

GitHub's renderer only emits `<math-renderer class="js-display-math">` when the `$$` block is on its own line (surrounded by blank lines).  **Only one valid format** is reliably rendered on GitHub:

```
$$expr$$
```

Single-line or content-attached multi-line are both valid:
- **Single-line:** `$$expr$$` — entire expression on one line.
- **Content-attached multi-line:** `$$first-content-line\n...\nlast-content-line$$` — the `$$` delimiters are attached to the first and last content lines respectively (not on separate blank lines).

**INVALID — standalone `$$` delimiter lines are not rendered by GitHub:**
```
$$
expr
$$
```
A bare `$$` on its own line is never correctly rendered as display math; use the content-attached form instead.

When a `$$` block follows immediately after prose (e.g. `**Compression function.**\n$$C(s,m) = ...$$`), GitHub fails to wrap it and the `$$...$$` is emitted as literal text with backslash escapes stripped — the visible "Unable to render expression" symptom.

Inside numbered/bulleted lists, avoid `$$` display blocks — move them before or after the list, or use inline `$...$` inside the item.

**CRITICAL — GitHub has a per-page math expression limit of approximately 750 expressions.**  Documents with more than ~750 math spans show a cascade failure: every math expression past the threshold renders as "Unable to render expression".  The root cause is a client-side rendering limit, not any specific syntax error.  The only fix is to split the document at a section boundary so that each part stays under ~750 math expressions.  SecurityProofs.md was split into SecurityProofs-1.md (§1–§10, ~753 spans) and SecurityProofs-2.md (§11–§11.9, ~725 spans) for this reason.

### Rule 6 — never place `$...$` directly after a non-space character

GitHub's math regex requires that the opening `$` be preceded by whitespace, start of line, or punctuation **other than** `-`/`)`/`.`/etc.  `degree-$k$` does **not** render; `degree $k$` does.  Same rule for the closing `$`: it must be followed by whitespace or end-of-line, not an alphanumeric.

### Rule 7 — never open a math span with `$[`

GitHub processes GFM link references (`[text](url)`) **before** math spans.  When a math span opens with `$[`, the link parser may consume the `[...]` portion before the math parser sees it, leaving orphaned `$` delimiters that prevent the following display block from being recognized.  Use `\lbrack`/`\rbrack` instead of bare `[`/`]` at the start of a math span.

### Rule 8 — never repeat `\command{...}_{...}` in multiple rows of a display environment

The sequence `}_{` (closing brace of a LaTeX command followed by an opening braced subscript) is treated by CommonMark as a **both-flanking** `_` delimiter — one that can both open AND close emphasis.  When this sequence appears in two or more rows of a `\begin{cases}` or `\begin{aligned}` environment, the `_` from row 1 opens emphasis and the `_` from row 2 closes it, creating an `<em>` span that crosses row boundaries and breaks the display math block.  The symptom is double-encoded `&amp;amp;` and spurious blank lines inserted between rows.

The trigger is specifically `\command{...}` (any backslash command with `{}` argument) followed by `_{...}` (subscript with braces) — e.g. `\mathrm{IV}_{\text{const}}`.  The same command with an **unbraced** single-character subscript (`\mathrm{IV}_c`) does **not** trigger emphasis (that `_` is only left-flanking, not right-flanking).

Fix: avoid repeating `\command{...}_{...}` across multiple rows.  Use either:
- **Text with hyphen:** `\text{IV-const}` instead of `\mathrm{IV}_{\text{const}}`
- **Unbraced subscript:** `\mathrm{IV}_c` (only safe for single-character subscripts)

### Rule 9 — never use any explicit spacing commands in math spans

**Both** families of spacing commands fail on GitHub's KaTeX pipeline:

- **Punctuation form** (`\;` `\!` `\,` `\:`): CommonMark resolves all `\<ASCII-punctuation>` sequences to the bare character before KaTeX sees the input (spec §6.7).  `\;` → `;`, `\!` → `!`, `\,` → `,`, `\:` → `:` — bare punctuation inside spacing position causes KaTeX to fail.
- **Alphabetic form** (`\thickspace` `\negthinspace` `\thinspace` `\medspace`): not stripped by CommonMark, but GitHub's client-side KaTeX renders these incorrectly (visible artifacts or wrong spacing) in multiple locations throughout the document.

The fix is to **omit spacing commands entirely**.  KaTeX automatically applies correct spacing to binary operators (`+`, `-`, `\oplus`, `=`, `\neq`, `\leq`, etc.) and relation operators without any explicit hints.  For negative spacing before big delimiters (`\bigl`, `\left`), simply omit the spacing command — `F^r\bigl(` renders correctly without `\!` or `\negthinspace`.

### Rule 10 — never use `\operatorname` (blocked by GitHub's KaTeX allowlist)

`\operatorname` is not in GitHub's KaTeX macro allowlist and produces the error "The following macros are not allowed: operatorname".  Use `\text{name}` instead — it renders identically for named operators (rank, ker, im, span, etc.) and is always permitted.

### Rule 11 — in inline paragraphs, `\command{}_{braced}` pairs with any downstream `letter_` as an emphasis span

Rule 8 covers display environments.  The same `}_{` mechanism also breaks **inline** paragraphs whenever a `\command{...}_{braced}` opener is followed anywhere in the same paragraph by a `letter_{...}` or `letter_letter` subscript that acts as a closer:

- **`\command{...}_{braced}`** (e.g. `\mathrm{ROL}_{n/4}`) — both-flanking: `}` (punctuation) before `_`, `{` (punctuation) after `_` → valid opener **and** closer.
- **`letter_{braced}`** (e.g. `c_{j-1}`) — right-flanking closer only: the plain letter before `_` satisfies the not-preceded-by-punctuation condition, so `_` is right-flanking and can **close** a preceding opener — even though `_` is not left-flanking and cannot itself open.
- **`letter_letter`** (e.g. `a_j`, `b_j`, `c_j`) — both-flanking: valid opener **and** closer.

CommonMark pairs the first opener with the first valid closer that follows, creating an `<em>` span that crosses all `$...$` boundaries between them and breaks every math span in the paragraph.

**Fix:** convert `\command{...}_{braced}` subscripts to function notation so the subscript `}_{` disappears entirely.  For example, `\mathrm{ROL}_{n/4}\bigl(x\bigr)` → `\mathrm{ROL}(x, n/4)`.  An unbraced single-character subscript `\command{...}_k` is also safe (left-flanking only, cannot close), but function notation is preferred for multi-character parameters.

### Correct patterns

The only pattern that survives both rules is **dashes inside a single `\text{}` block** for compound names, and **explicit subscript syntax** when the visual is genuinely a subscript.

| Pattern to avoid | Correct replacement |
|---|---|
| `\text{FOO}\textunderscore\text{BAR}` | `\text{FOO-BAR}` |
| `\text{FOO}\_\text{BAR}` | `\text{FOO-BAR}` |
| `\text{FOO\_BAR}` | `\text{FOO-BAR}` |
| `\text{A}\textunderscore\text{B}\textunderscore\text{C}` | `\text{A-B-C}` |
| `\text{A}\_\text{B}\_\text{C}` | `\text{A-B-C}` |
| `\mathit{IV}\textunderscore\text{const}` | `\mathrm{IV}_{\text{const}}` (subscript form) |
| `\mathrm{HFSCX\textunderscore 256}` | `\text{HFSCX-256}` |
| `C\textunderscore\text{DM}` | `C_{\text{DM}}` |
| `\xleftarrow{\textdollar}` / `\xleftarrow{\$}` | `\xleftarrow{R}` |
| `\overset{\textdollar}{\leftarrow}` / `\overset{\$}{\leftarrow}` | `\overset{R}{\leftarrow}` |
| `\mathbb{GF}(2^n)^*` | `\mathbb{GF}(2^n)^{\ast}` |
| `(R^*, s^*)` | `(R^{\ast}, s^{\ast})` |
| `**Bold.**\n$$x = y$$` (no blank line) | `**Bold.**\n\n$$x = y$$\n\n…` |
| `1. item\n\n    $$x = y$$\n\n    follow-up` (4-space indent in list) | **Never indent** — move `$$x = y$$` to before/after the entire list (cascade if indented; also cascade if column 0 between items) |
| `degree-$k$ Boolean` (no space before `$`) | `degree $k$ Boolean` |
| `$[N, k, t]$-code` (`[` right after `$`) | `$(N, k, t)$-code` (parentheses) or `[N, k, t]-code` (plain text) |
| `\mathrm{IV}_{\text{const}}` repeated in 2+ rows of `\begin{cases}` | `\text{IV-const}` (no subscript, hyphen in text) |
| `\mathrm{ROL}_{n/4}\bigl(x\bigr)` in a paragraph that also has `c_{j-1}` | `\mathrm{ROL}(x, n/4)` — function notation removes `}_{` opener (Rule 11) |
| `$$\nexpr\n$$` (standalone `$$` delimiter lines) | `$$expr$$` or `$$first-line\n...\nlast-line$$` |
| `\operatorname{rank}(\Phi)` | `\text{rank}(\Phi)` — `\operatorname` blocked by GitHub allowlist |
| `\;` / `\!` / `\,` / `\:` in math | (omit — rely on KaTeX auto-spacing) |
| `\thickspace` / `\negthinspace` / `\thinspace` / `\medspace` in math | (omit — renders incorrectly on GitHub's KaTeX) |
| `F^r\!\bigl(` or `F^r\negthinspace\bigl(` | `F^r\bigl(` (no spacing before big delimiter) |

The "uniformly random sample" arrow conventionally has a dollar sign on top; `R` (for "Random") is the standard alternative used in cryptography texts that need ASCII-safe LaTeX.

### Validation

Before pushing changes that add or modify math, simulate GitHub's pipeline locally:

```bash
mkdir -p /tmp/katex-validate && cd /tmp/katex-validate && npm install katex
NODE_PATH=/tmp/katex-validate/node_modules node \
    /path/to/HerraduraKEx/SecurityProofsCode/validate_katex.js \
    /path/to/HerraduraKEx/SecurityProofs-1.md
NODE_PATH=/tmp/katex-validate/node_modules node \
    /path/to/HerraduraKEx/SecurityProofsCode/validate_katex.js \
    /path/to/HerraduraKEx/SecurityProofs-2.md
# Expect: "753 OK, 0 FAIL" and "724 OK, 0 FAIL" (counts vary as the documents grow)
```

The validator at `SecurityProofsCode/validate_katex.js` extracts every `$...$` and `$$...$$` math span, applies CommonMark backslash escape resolution (all `\<ASCII-punctuation>` → bare character) to **both** inline and display spans — matching GitHub's actual pipeline — and then renders each through KaTeX in the correct display/inline mode.  It also flags `\;`/`\!`/`\,`/`\:` as PIPE-FAIL violations in both inline and display contexts.

Pure-KaTeX validation (`katex.renderToString` without escape resolution) **will give false positives** because it does not see the markdown layer; always use the pipeline simulator above.
