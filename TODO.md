# HerraduraKEx — Open TODO Items

> **Completed, deprecated, and acknowledged items have moved to [`TODO_DONE.md`](TODO_DONE.md) (TODO #154).** This file holds only entries with `Status: **OPEN**`. Item numbers are global and preserved across both files — when an item here is completed, move its whole entry to the end of `TODO_DONE.md` and update its Status line, per CLAUDE.md's TODO policy.

---

## Open items

New items go here with `Status: **OPEN**`; see CLAUDE.md.

---

### #241: `rand`, `fpe` and `twk` ship with no security analysis anywhere in the repository

Found by TODO #238 Part C's audit of CLI surface invisible to `spec/`.  Three subcommands
reach no protocol entry, no `SECURITY.md` row, and no `SecurityProofs-*.md` section:

| subcommand | construction | analysis |
|---|---|---|
| `rand` | HDRBG deterministic byte generator over HFSCX-256 | none |
| `fpe`  | format-preserving encryption of a 256-bit block (TODO #78.A) | none |
| `twk`  | tweakable wide-block encryption of a 256-bit block (TODO #78.B) | none |

They are not obscure: all three ship in the C, Go and Python CLIs, and `rand` writes a
`HERRADURA HDRBG STATE` PEM that `CliTest/test_rand.sh` round-trips.  What is missing is
any statement of what they are supposed to guarantee.

**Why this is not a documentation task.**  #238 could not classify them the way it
reclassified `hpks-t` and `hpks-nl`, because those two had an existing analysis to
propagate — `hpks` is pedagogical because of Pohlig-Hellman, and the threshold and NL
variants are over the same group, so the verdict follows.  These three have no such
parent.  `fpe` and `twk` are their own constructions; `rand`'s HDRBG has a `DrbgMaxBlocks
= 1 << 20` reseed bound in `herradura/herradura.go:933` and nothing anywhere saying what
that bound is for.  Classifying them means doing the analysis, which is TODO #237-shaped
work.

**Interim state, deliberately visible rather than silent.**  #238 recorded all three in
`spec/herradura-protocol-spec.json`'s `unfiled_cli_surface` array and gave them a single
shared `SECURITY.md` row reading "Unclassified — no analysis exists", with the warning
that absence of a documented weakness there is absence of analysis rather than evidence of
strength.  `spec/generate_spec.py` fails if a *new* subcommand appears that is neither
bound to a protocol nor listed as unfiled, so the hole cannot grow while this is open.

**Work.**  For each of the three: state the security goal, identify the closest standard
construction (FF1/FF3-1 for `fpe`, a wide-block tweakable cipher such as AEZ or HCTR2 for
`twk`, SP 800-90A for `rand`), analyse the shipped construction against it, add a
`SecurityProofs-*.md` section, then file a real `SECURITY.md` row and `spec/` entry and
delete the `unfiled_cli_surface` record.  Expect at least one of the three to come out
worse than `demo-only` — `fpe` over a 256-bit block with no documented tweak schedule is
the one to look at first.

**Not in scope.**  Removing the subcommands.  They are shipped surface; the deficiency is
that nobody can tell what they promise.

Status: **OPEN**
