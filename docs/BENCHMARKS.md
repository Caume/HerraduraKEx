# Benchmark Comparison Against Established Libraries

`Herradura_tests.*` tests [30]-[41] measure this suite's own protocols in isolation. This
page adds a reference point against familiar, established libraries, so a reader can judge
whether the FSCX-based approach is competitive, and where — if anywhere — it actually has an
edge (multi-language parity, simplicity, PQC option breadth) relative to something they
already know.

**Read this before citing any number below:** every comparison here is apples-to-oranges.
This suite is a research/pedagogical proof-of-concept (TODO #127); the libraries it's
compared against are production-hardened, heavily audited, and — in Dilithium/Kyber's case —
NIST-standardized. Treat the *ratios* as the useful signal, not the absolute microsecond
figures, and re-run the scripts on your own hardware before drawing conclusions.

## Scripts

Reproducible comparison scripts live in `benchmarks/`:

```bash
bash bindings/ffi/build.sh                          # once, needed by both scripts
python3 benchmarks/compare_hpks_ed25519.py          # HPKS vs. libsodium Ed25519
python3 benchmarks/compare_stern_f_dilithium.py     # HPKS-Stern-F vs. liboqs Dilithium3
```

`compare_hpks_ed25519.py` uses the FFI bindings (`bindings/ffi/`, TODO #137) for HPKS and
libsodium via `ctypes` (no `libsodium-dev` headers needed — only the runtime `.so`).
`compare_stern_f_dilithium.py` drives `HerraduraCli/herradura_cli` (`build_c.sh`) for
HPKS-Stern-F, since the FFI bindings intentionally scope out the Stern-F protocols, and loads
liboqs via `ctypes` if present.

## HPKS vs. Ed25519 (classical DLP-based signature)

Measured on this repo's dev hardware (aarch64), N=500 operations:

| | sign (µs/op) | verify (µs/op) |
|---|---|---|
| HPKS (this suite, FFI/C) | ~4,070 | ~8,140 |
| Ed25519 (libsodium) | ~64 | ~210 |

HPKS is roughly **60x slower to sign and 40x slower to verify** than Ed25519 in this
measurement.

Caveats specific to this comparison:
- Ed25519 uses a decade-audited, hand-optimized reference implementation (`ref10`); HPKS runs
  through this suite's general-purpose `BitArray`/`GF(2^n)` arithmetic, not curve-specific
  optimized code.
- HPKS's security is classical DLP over `GF(2^256)*` — broken by Shor's algorithm, and at
  ~80-90 bits of classical security per the `GF(2^n)` table in the main README, below
  Ed25519's 128-bit target.
- Both are measured through this suite's FFI shim / libsodium's C API respectively — not a
  cross-language comparison.

## HPKS-Stern-F vs. ML-DSA-65 (code-based PQC vs. lattice-based PQC signature)

Measured end-to-end (TODO #186) against a from-source build of upstream liboqs 0.16.0
(`https://github.com/open-quantum-safe/liboqs`, plain `cmake`/`make` build, no extra options)
on this repo's dev hardware (aarch64), N=30 operations, averaged over 5 runs of
`benchmarks/compare_stern_f_dilithium.py`:

| | sign (ms/op) | verify (ms/op) |
|---|---|---|
| HPKS-Stern-F (this suite, CLI/C, demo params) | ~39 | ~29 |
| ML-DSA-65 (liboqs) | ~0.8 | ~0.2 |

HPKS-Stern-F is roughly **50x slower to sign and 130x slower to verify** than ML-DSA-65 in
this measurement — noisier than the sign ratio because ML-DSA-65 verify is sub-millisecond,
so per-call timing jitter dominates at N=30.

Note on naming: liboqs registers this algorithm as `ML-DSA-65`, its final NIST FIPS 204
identifier, not the pre-standardization `Dilithium3` name this page and the script originally
used — `compare_stern_f_dilithium.py` tries both, preferring `ML-DSA-65`. Older liboqs builds
that predate the FIPS 204 rename may still only register `Dilithium3`; either way it's the
same NIST security category 3 (~128-bit) parameter set.

Caveats specific to this comparison:
- HPKS-Stern-F's demo parameters (`N=256, t=16, 32 rounds`) give only ~30-40 bits of security
  per the CLI's own runtime warning; the code documents `N>=17000` for ~128-bit security,
  which would be substantially slower again. ML-DSA-65 targets NIST category 3 (~128-bit)
  out of the box.
- HPKS-Stern-F is measured through CLI process spawns (PEM encode/decode, file I/O per
  operation), not a direct library call — this adds fixed overhead a library-call benchmark
  wouldn't pay. A tighter comparison would extend `bindings/ffi/` to cover Stern-F and
  benchmark through that instead (out of scope for TODO #138/#186; see TODO #137's stated
  scope).

## HKEX-RNL vs. Kyber (lattice-based PQC key exchange)

Not yet benchmarked — liboqs was unavailable in this environment and this comparison was not
implemented in the initial pass of TODO #138. `benchmarks/compare_stern_f_dilithium.py`'s
`try_load_liboqs()` helper can be reused for an `OQS_KEM_*`-based script following the same
pattern as the Dilithium comparison above.
