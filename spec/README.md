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
```

No CI exists in this repo (tests are run manually per `CLAUDE.md`), so `--check` is a
manual pre-commit-style gate: run it after touching `HerraduraCli/herradura.py`'s
`_PRIV_ALGOS` dict or `--algo choices=[...]` lists, `HerraduraCli/herradura_codec.h`'s
`PEM_*` constants, or `herradura.h`'s protocol parameter `#define`s.

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

The following is **curated** in `generate_spec.py` (`SECURITY`, `CLI_SUPPORT`,
`PROTOCOL_KIND`, `PROTOCOL_NAME`, `CROSS_IMPL_GAPS` dicts) because it requires judgment
that can't be mechanically derived from source — e.g. deciding "SDF_ROUNDS=32 shipped
vs. SDF_PRODUCTION_ROUNDS=219 needed" means `hpks-stern` is `demo-only`:

- Security status, quantum-resistance claim, and classical security bits per protocol.
- Which of the C/Go/Python CLIs support which algo tag (audited against dispatch code,
  not `--help` text — both the C and Go CLIs under-document some working algo tags in
  their usage banners; see `cross_implementation_gaps` in the generated spec).

**Drift-detection guarantee and its limit.** `--check` re-derives the mechanical fields
and fails if the checked-in JSON doesn't match — so a renamed, removed, *or newly
added* algo tag in `_PRIV_ALGOS`/`choices=[...]` always changes the generated output
and fails `--check` until you regenerate. Additionally, at generation time the script
asserts every algo tag referenced in the curated tables still exists in the
mechanically extracted set — so a tag *renamed or removed* in source is caught with a
clear error pointing at `generate_spec.py`, not a silent stale entry. What it can't
catch: a brand-new algo tag that's curated with placeholder data (status defaults to
`"research"` with a generic note) but never gets a real classification — that's a
review-discipline gap, not a tooling one. When you add a new algo tag, add a `SECURITY`
and `CLI_SUPPORT` entry for it in the same commit.

## Files

- `herradura-protocol-spec.schema.json` — the JSON Schema.
- `herradura-protocol-spec.json` — the generated instance (checked in).
- `generate_spec.py` — the generator + `--check` drift gate.
