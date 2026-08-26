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

Both run in CI's `native-python` job (TODO #238). `--check` had existed since TODO #133
but no job ever ran it, so nothing verified that the shipped JSON matched its generator —
the gap that let five wrong `status=` labels accumulate (three found by TODO #237, two
more by #238).

## What's mechanically extracted vs. curated

The generator (`generate_spec.py`) pulls the following **directly from source** by
regex, so these fields cannot silently drift from what the CLIs actually implement:

- Algo tag -> PEM private/public key label: `HerraduraCli/herradura.py`'s `_PRIV_ALGOS`
  dict (the most complete of the three CLIs — it's the only one that defines
  `hpks-xmss` and `hcred`).
- Every `PEM_*` wire-format label: `HerraduraCli/herradura_codec.h`.
- Per-subcommand `--algo` choices (enc/dec/sign/verify/kex/encfile/decfile/dgst):
  `HerraduraCli/herradura.py`'s argparse `choices=[...]` lists.
- Protocol parameter constants (`KEYBITS`, `SDF_*`, `ZKP_NL_*`, `WOTS_*`, `RNL_N`):
  `herradura.h` `#define`s, resolved numerically where the expression is a simple
  ratio of already-known constants (e.g. `SDF_N_ROWS = KEYBITS / 2` -> `128`).

- Which of the C/Go/Python CLIs dispatch which algo tag: every string literal in
  `HerraduraCli/herradura_cli.c` and `herradura_cli.go`, intersected with the tag
  universe above (comments stripped). Dispatch code, not `--help` text — both banners
  under-document working tags. This was a curated `CLI_SUPPORT` table until TODO #238
  found it wrong in two places: it called `hpks-xmss` Python-only when all four
  implementations have shipped it since TODO #201/#208, and said `hcred` was missing from
  Go when the Go CLI dispatches `cred-issue`/`-prove`/`-verify`. `cross_implementation_gaps`
  is derived from the same data.
- Every CLI subcommand, and for those without `--algo`, the protocol they implement
  (`SUBCOMMAND_PROTOCOLS`, validated against the argparse subparser list).

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
