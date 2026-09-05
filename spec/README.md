# Machine-readable protocol specification (TODO #133)

`herradura-protocol-spec.json` is the canonical, machine-readable source of truth for:
protocol parameters, PEM wire-format block labels, CLI `--algo` tags, and each
protocol's security-level classification (production / demo-only / pedagogical /
deprecated / broken / research). It validates against
`herradura-protocol-spec.schema.json` (JSON Schema draft 2020-12).

A tool or LLM that needs to generate a correct client against this suite should read
this file, not parse prose across `CLAUDE.md` / `docs/TUTORIAL.md` / `SecurityProofs-*.md`.

## Regenerating

```bash
python3 spec/generate_spec.py            # regenerate spec/herradura-protocol-spec.json
python3 spec/generate_spec.py --check    # exit 1 if the checked-in file is stale
python3 spec/check_security_md.py        # exit 1 if spec/ and SECURITY.md disagree
```

`--check` also validates the generated instance against
`herradura-protocol-spec.schema.json`. That needs the `jsonschema` package — the only
third-party dependency anywhere in this repository, and a **tooling** one: the suite, the
CLIs and the `SecurityProofsCode/` scripts still have none. So a bare `python3` gets a
printed NOTE and the rest of the check still runs. CI does not accept that, because a
silently-skipped validation is the same class of gap this whole area was filed about:
`native-python` installs `python3-jsonschema` and passes `--require-schema`, which turns
the NOTE into a failure.

```bash
python3 spec/generate_spec.py --check --require-schema   # what CI runs
```

Both run in CI's `native-python` job (TODO #238). `--check` had existed since TODO #133
but no job ever ran it, so nothing verified that the shipped JSON matched its generator —
the gap that let five wrong `status=` labels accumulate (three found by TODO #237, two
more by #238).

## What's mechanically extracted vs. curated

The generator (`generate_spec.py`) pulls the following **directly from source** by
regex, so these fields cannot silently drift from what the CLIs actually implement:

- Algo tag -> PEM private/public key label: `HerraduraCli/herradura.py`'s `_PRIV_ALGOS`
  dict (the most complete of the four CLIs — it's the only one that defines
  `hpks-xmss` and `hcred`).
- Every `PEM_*` wire-format label: `HerraduraCli/herradura_codec.h`.
- Per-subcommand `--algo` choices (enc/dec/sign/verify/kex/encfile/decfile/dgst):
  `HerraduraCli/herradura.py`'s argparse `choices=[...]` lists.
- Protocol parameter constants (`KEYBITS`, `SDF_*`, `ZKP_NL_*`, `WOTS_*`, `RNL_N`):
  `herradura.h` `#define`s, resolved numerically where the expression is a simple
  ratio of already-known constants (e.g. `SDF_N_ROWS = KEYBITS / 2` -> `128`).

- Which of the C/Go/Python/Java CLIs dispatch which algo tag: every string literal in
  `HerraduraCli/herradura_cli.c`, `herradura_cli.go` and
  `bindings/java/herradurakex/HerraduraCli.java`, intersected with the tag
  universe above (comments stripped). The Java column arrived in TODO #261: the
  table had been three-wide in a four-language repo since `bindings/java/` landed,
  so Java's coverage — 24 of the 29 tags — and its five gaps were invisible here
  by construction. Those five now appear in `cross_implementation_gaps` with a
  recorded reason each, which is what #261's acceptance criterion asks for
  ("all four cells filled, or ACKNOWLEDGED with a recorded reason, never a
  silent absence"). Dispatch code, not `--help` text — both banners
  under-document working tags. This was a curated `CLI_SUPPORT` table until TODO #238
  found it wrong in two places: it called `hpks-xmss` Python-only when all four
  implementations have shipped it since TODO #201/#208, and said `hcred` was missing from
  Go when the Go CLI dispatches `cred-issue`/`-prove`/`-verify`. `cross_implementation_gaps`
  is derived from the same data.
- Every CLI subcommand, and for those without `--algo`, the protocol they implement
  (`SUBCOMMAND_PROTOCOLS`, validated against the argparse subparser list).
- Which of the four CLIs implement which `--flag`, per subcommand
  (`cli_flag_matrix`), from each CLI's *own argument parser*: argparse
  `add_argument` calls in Python, `get_arg`/`has_flag`/`get_arg_multi` literals in
  C, the `flag.FlagSet` constructors and `stringFlags` in Go, and
  `opt.get`/`getOrDefault`/`containsKey`/`req` in Java. Each extractor maps
  subcommand -> handler first and then follows delegation, or C's
  `threshold-verify` flags (reached only through `cmd_verify`) and Go's
  `cmdKexRnl`/`cmdKexHybrid` flags would read as absent from the languages that
  have them. Each raises rather than returning empty when it maps no
  subcommands: a stale regex must fail as "the extractor broke", not as "port 26
  subcommands".

The following is **curated** in `generate_spec.py` (`SECURITY`, `PROTOCOL_KIND`,
`PROTOCOL_NAME`, `SUBCOMMAND_PROTOCOLS`, `UNFILED_CLI_SURFACE`) because it requires
judgment that can't be mechanically derived from source — e.g. deciding "SDF_ROUNDS=32
shipped vs. SDF_PRODUCTION_ROUNDS=219 needed" means `hpks-stern` is `demo-only`:

- Security status, quantum-resistance claim, and classical security bits per protocol.

**Drift-detection guarantee and its limit.** `--check` re-derives the mechanical fields
and fails if the checked-in JSON doesn't match — so a renamed, removed, *or newly
added* algo tag in `_PRIV_ALGOS`/`choices=[...]` always changes the generated output
and fails `--check` until you regenerate. Additionally, at generation time the script
asserts every algo tag referenced in the curated tables still exists in the
mechanically extracted set — so a tag *renamed or removed* in source is caught with a
clear error pointing at `generate_spec.py`, not a silent stale entry. What it can't
catch on its own: whether what the curated `SECURITY` table *says* about a tag is true.
That is what `check_security_md.py` is for — it cross-references every protocol's status
against SECURITY.md's prose table, which is the disagreement-between-documents class that
TODO #237 found three instances of and #238 two more (`hpks-t` classified `production`
while the `hpks` it is a threshold variant of is `pedagogical`; `hpks-nl`/`hpke-nl`
marked `deprecated`, conflating a withdrawn PQC claim with a superseded algorithm).

A new algo tag can no longer ship unclassified: generation fails if any tag the CLIs
accept has no `SECURITY` entry — the check that caught `hybrid-rnl-stern`, a shipped
`kex --algo` value in all three CLIs that had no protocol entry at all because
`build_protocols` keyed off `_PRIV_ALGOS | SECURITY` and it is in neither.

## The CLI FLAG surface (TODO #267)

`cross_implementation_gaps` answers *does this CLI dispatch this `--algo` tag*, and
TODO #261 declared that half met at v6.0.0 — all 29 tags in all four CLIs. That is
true and narrower than "the CLI surface": a subcommand's **flags** are capability
too, and they were never compared. `genpkey --passphrase` has been Python-only since
TODO #166 (v1.9.134), recorded in that item's own text and invisible to every check
once the item was archived; eight further asymmetries had never been recorded
anywhere at all, and one — the `--commits` / `--commit` spelling split — is not a
missing capability but the same capability under two names, so a documented
threshold-signing command line does not port between CLIs.

`cli_flag_matrix` is the derived matrix; `cli_surface_gaps` is every non-unanimous
cell of it joined to a curated reason, and it is **exhaustive by construction** —
generation fails if a derived gap has no recorded reason, if a recorded reason has
no derived gap, or if a reason's language set no longer matches what the parsers
say. So adding a flag to one CLI and not the others fails `--check` with the flag
named, and the only ways to make it pass are to port it or to write down why not.
That last direction is the half the deleted `CLI_SUPPORT` table never had: an
acknowledgement whose gap has closed must be removed, or the next reader inherits a
reason for something that is no longer true.

`status` separates the two legitimate answers the repo already uses in practice.
`acknowledged` is a deliberate per-language scope decision — `genpkey --bits` is
absent from C because the C CLI is compiled for a single `KEYBITS` and `RNL_N`, so
there is no runtime width for the flag to set. `defect` is a real asymmetry that is
merely recorded and counted. **#267 closes on this mechanism, not on the ports**, so
`defect` rows are an expected steady state here rather than a failing one; the
current count is 16 defect and 5 acknowledged.

Two limits worth stating. The matrix is at **flag granularity**: where a flag takes an
enumerated value the value sets can still differ — Python's `kex --kdf` accepts
`hfscx-256` and `sp800227` (TODO #165) where C and Go accept `hfscx-256` only — and
that second axis is carried in the gap's `reason`, not derived. And a flag gap is
reported only against CLIs that define the subcommand at all, so `rand`'s seven flags
are not re-reported as missing from Java, which lacks `rand` itself; that shows up
once, as a `kind: "subcommand"` row.

Subcommand-level parity lives in the same place. `cli_subcommands` is keyed on the
Python CLI's subparser list, which made a subcommand only another CLI defines
structurally invisible — Go's top-level `threshold-verify` was. Each entry now carries
`implementations`, and the union appears in `cli_flag_matrix`.

## Protocols without an `--algo` tag

`protocols` is keyed on a stable protocol id, which for most entries is also the `--algo`
tag. Some protocols have no tag: they ship as their own subcommands. aPAKE is the case
that exposed this (`pake-register`/`pake-demo`) — it had a `SECURITY.md` row from TODO
#237 and no spec entry at all, because there was no key to file it under. TODO #238 widened
the key rather than adding a parallel `subcommand_protocols` section, which would have let
a protocol fall between the two halves. Every protocol now carries `cli_binding`, recording
whether the CLI reaches it through an `--algo` tag or through its own subcommands.

`unfiled_cli_surface` is the rest of that audit: subcommands reaching no protocol entry.
`pkey` is a utility; `rand`, `fpe` and `twk` are real constructions with no security
analysis anywhere in the repository (TODO #241). Generation fails on a *new* unaccounted-for
subcommand, so the list cannot grow silently.

## Files

- `herradura-protocol-spec.schema.json` — the JSON Schema.
- `herradura-protocol-spec.json` — the generated instance (checked in).
- `generate_spec.py` — the generator + `--check` drift gate (also validates the
  generated instance against the schema when `jsonschema` is importable).
- `check_security_md.py` — the spec/ vs. SECURITY.md classification cross-reference.
