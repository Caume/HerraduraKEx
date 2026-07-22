# Fuzzing harness (TODO #130)

No CI exists in this repo (tests are run manually per `CLAUDE.md`), so this directory
is the documented, manual entry point for adversarial testing of the PEM/DER codec and
CLI argument parsing — the most common real-world vulnerability surface in cryptographic
tooling (parser bugs, not algebra, are what usually get CVEs).

Run everything with a short time budget per target:

```bash
./Fuzz/run_fuzz.sh 30   # 30 seconds per target; omit for the default (30s)
```

## Toolchain

| Target | Tool | Why |
|---|---|---|
| C codec | libFuzzer (`clang -fsanitize=fuzzer,address,undefined`) | Standard for C; `clang`/`libclang-rt` are apt-installable on this host. |
| Go codec | native `go test -fuzz` (Go 1.18+) | Built into the toolchain already in use; no `go-fuzz` dependency needed. |
| Python codec | [Hypothesis](https://hypothesis.readthedocs.io/) (`python3-hypothesis`) | `atheris` has no working build path on this host/Python version; Hypothesis is pure-Python, apt-packaged, and property-based random generation over the same input space still exercises the malformed/adversarial cases that matter here (it isn't coverage-guided like atheris/libFuzzer). |
| CLI argument parsing (all 3 CLIs) | custom black-box argv fuzzer (`fuzz_cli_args.py`) | No existing tool fits "randomize argv + input files across three independent CLI binaries and watch for crash signals" — this is a thin, purpose-built driver. |

## Targets

- **`fuzz_b64_decode.c`** — `herradura_codec.h`'s `b64_decode`.
- **`fuzz_der_parse_seq.c`** — `herradura_codec.h`'s `der_parse_seq`.
- **`fuzz_pem_unwrap.c`** — `herradura_codec.h`'s `pem_unwrap` (PEM parse + base64 decode).
- **`herradura/codec_fuzz_test.go`** (`FuzzPemUnwrap`, `FuzzDerParseSeq`) — the Go codec
  equivalents in `herradura/codec.go`. Run directly with `go test -fuzz=<name>` from
  the repo root, or via `run_fuzz.sh`.
- **`fuzz_codec_py.py`** — Hypothesis properties for `HerraduraCli/codec.py`'s
  `der_parse_seq` and `pem_unwrap`: parsing arbitrary bytes/text must return normally
  or raise `ValueError`, never anything else (`IndexError`, etc.).
- **`fuzz_cli_args.py`** — randomizes subcommands, flags, and malformed input files
  across the C (ASan-instrumented), Go, and Python CLIs; a signal-terminated process
  (SIGSEGV/SIGABRT/SIGBUS) is a bug, since all three CLIs use a graceful
  `die()`/`exit(1)` path on recognized errors.

## Bugs found and fixed while building this harness

1. **`b64_decode`/`pem_unwrap` (C, `herradura_codec.h`) had no output-capacity bound.**
   The function signature and its callers' doc comments already claimed an input
   capacity contract, but the decode loop just wrote as many bytes as it decoded.
   `HerraduraCli/herradura_cli.c`'s `zkp_pem_peek_label` passed a fixed 4096-byte stack
   buffer expecting that contract to be honored — a crafted PEM file with a large
   enough base64 body caused a stack buffer overflow. Fixed by adding an explicit
   `out_cap`/`der_cap` parameter that both functions now enforce (returning -1 rather
   than overflowing); all call sites updated.
2. **`der_parse_seq` (C, `herradura_codec.h`) didn't validate the claimed SEQUENCE body
   length against the actual buffer size**, letting a 2-byte input (`30 40`, "SEQUENCE,
   64-byte body") drive an out-of-bounds read. Fixed with bounds checks on both the
   SEQUENCE body and each nested INTEGER length.
3. **`DerParseSeq` (Go, `herradura/codec.go`) had the equivalent gap** on the per-INTEGER
   length (the top-level SEQUENCE bound was already checked): a crafted DER blob
   caused a slice-bounds-out-of-range panic. Fixed with the same length check as (2).
4. **`der_parse_seq`/`pem_unwrap` (Python, `HerraduraCli/codec.py`) could raise
   `IndexError` instead of `ValueError`** on truncated length fields or empty PEM text —
   not memory-unsafe (Python), but an inconsistent error-handling contract across the
   three implementations. Hardened to always raise `ValueError` on malformed input.
5. **Pre-existing self-test buffer overflow** (unrelated to the above, caught incidentally
   by ASan while validating the fixes): `herradura_codec_selftest`'s DER-INTEGER test
   reused a 16-byte stack buffer for a 35-byte encode result. Fixed by sizing the buffer
   with `DER_INT_LEN(32)`.

After these fixes: all three libFuzzer targets ran 15M+ executions combined with zero
crashes, the Go native fuzz targets ran 4M+ executions with zero crashes, the Hypothesis
suite ran 60,000 examples with zero unexpected exceptions, and the CLI argv fuzzer ran
1,300+ trials across all three CLIs with zero crashes.

## Corpus

`corpus/<target>/` holds interesting inputs discovered by libFuzzer across runs (not
committed — regenerated locally each run via `.gitignore`). Delete and re-run
`run_fuzz.sh` any time for a fresh session.
