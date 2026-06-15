# Changelog

All notable changes to the Herradura Cryptographic Suite are documented here.

---

## [1.9.46] - 2026-06-14

### UX/Docs — Stern-F demo-only status enforcement (TODO #91)

Reconciles the "Production-ready" claim in §11.10.5 with the §11.8.4 "demo only"
caveat, and adds runtime warnings to all three CLIs.

- **`SecurityProofs-3.md` §11.10.5**: changed HPKS-Stern-F recommendation note from
  "Production-ready, v1.5.18" to "Demo parameters (N=256, ~30–40 bits security);
  128-bit requires N≥17000".
- **`docs/TUTORIAL.md`** proof-size table: changed HPKS-Stern-F note from
  "Production code-based PQC" to "Demo params (N=256, ~30–40 bits); 128-bit needs N≥17000".
- **`HerraduraCli/herradura.py`**: emits a stderr warning when any Stern-F operation
  (genpkey, enc, dec, sign, verify) is invoked, noting demo-parameter security level.
- **`HerraduraCli/herradura_cli.c`**: same warning via `fprintf(stderr, ...)` at each
  Stern-F dispatch point (genpkey, enc, dec, sign, verify).
- **`HerraduraCli/herradura_cli.go`**: same warning via `fmt.Fprintln(os.Stderr, ...)`
  at each Stern-F dispatch point.

---

## [1.9.45] - 2026-06-14

### Analysis — HKEX-RNL-128 upgraded parameter set (TODO #90)

Defines **HKEX-RNL-128** ($n=512, q=65537, p=4096, \eta=1$) as the recommended
upgrade of HKEX-RNL to ≥128-bit classical Core-SVP security.

- **`SecurityProofsCode/hkex_rnl_failure_rate.py`**: adds §6 (LWE/LWR security
  analysis with calibrated linear scaling from the Albrecht/MATZOV baseline,
  candidate-parameter table, ML-KEM-512 cross-check) and §7 (Peikert reconciliation
  failure-rate verification at $n=512$: 0 failures in 2000 trials).
- **`SecurityProofs-2.md` §11.4.3**: documents HKEX-RNL-128 parameter set, security
  argument (≈220 classical / ≈200 quantum Core-SVP bits, lower-bounded by ML-KEM-512
  cross-check), NTT compatibility proof, and reconciliation correctness reference.
- **`SecurityProofs-2.md` §11.6 (security summary table)**: adds HKEX-RNL-128 row.
- **`TODO.md`** #90: marked DONE.

The $n=256$ wire format remains the default; HKEX-RNL-128 is documented as the
128-bit upgrade path for future deployment.

---

## [1.9.44] - 2026-06-14

### Feature — CLI multi-party threshold signing for HPKS-T (TODO #106)

Extends `HerraduraCli/` (Python, C, Go) with a 4-phase interactive HPKS-T workflow:
`threshold-commit`, `threshold-aggregate`, `threshold-respond`, `threshold-combine`.
Signatures are verifiable with `verify --algo hpks-t` (no `--pubkey` needed; C_agg
is embedded in the HPKST SIGNATURE PEM). Cross-language interoperability is complete:
any CLI can produce and any CLI can verify.

- **`HerraduraCli/herradura_codec.h`**: adds PEM label defines for `HPKST COMMITMENT`,
  `HPKST NONCE`, `HPKST AGGREGATE`, `HPKST PARTIAL`, `HPKST SIGNATURE`.
- **`HerraduraCli/codec.py`**: adds `encode_hpkst_commit/nonce/aggregate/partial/sig`
  and corresponding `decode_*` functions.
- **`HerraduraCli/primitives.py`**: exports `hpkst_aggregate_pubkeys`, `hpkst_sign`,
  `hpkst_verify` from the suite.
- **`HerraduraCli/herradura.py`**: adds `threshold-commit`, `threshold-aggregate`,
  `threshold-respond`, `threshold-combine` subcommands; extends `verify` to accept
  `--algo hpks-t` (no `--pubkey` required).
- **`HerraduraCli/herradura_cli.c`**: adds `cmd_threshold_commit/aggregate/respond/combine`
  and `cmd_threshold_verify`; extends `verify --algo hpks-t`.
- **`HerraduraCli/herradura_cli.go`**: adds `cmdThresholdCommit/Aggregate/Respond/Combine`
  and `cmdThresholdVerify`; extends `cmdVerify` for `hpks-t`; adds HPKST PEM label
  constants and encode/decode helpers.
- **`CliTest/test_threshold_sign.sh`**: Python 3-of-3 threshold sign + verify + tamper test.
- **`CliTest/test_threshold_interop.sh`**: 9-way cross-language interop (Python/C/Go sign ×
  Python/C/Go verify) plus a mixed-phase scenario.
- **`docs/TUTORIAL.md`**: new "Threshold Signing (HPKS-T)" section with 4-phase workflow,
  C/Go CLI equivalents, interop notes, and security notes.

---

## [1.9.43] - 2026-06-14

### Feature — HPKS-T: n-of-n Threshold Aggregate Schnorr over GF(2^n)* (TODO #98)

Implements HPKS-T (MuSig2-style threshold Schnorr) in Python, C, and Go, adds security
test [31] across all three targets, renumbers benchmarks to [32]–[43], and adds TODO #106
tracking the CLI multi-party signing capability.

**Protocol:** μ_j = HFSCX-256(L ∥ C_j) mod ord (rogue-key binding);
C_agg = Π C_j^{μ_j}; R = Π g^{k_j};
e = nl_fscx_revolve_v1(R, msg, n/4); s_j = (k_j − a_j·μ_j·e) mod ord;
s = Σ s_j mod ord. Verify: g^s · C_agg^e == R (identical to single-party HPKS-NL).

- **`herradura.h`**: adds `ba_add_mod_ord`, `GF_GEN_BA` macro, `_ba_mod_{add,sub,mul}_ord`
  aliases; adds `_hpkst_mu_coeff`, `_hpkst_aggregate`, `_hpkst_build_L`, `hpkst_sign`,
  `hpkst_verify`.
- **`herradura/herradura.go`**: adds `HpkstAggregatePublickeys`, `HpkstSign`, `HpkstVerify`
  (all using `*big.Int` GF arithmetic consistent with the existing package API).
- **`Herradura cryptographic suite.py`**: adds module-level `hpkst_aggregate_pubkeys`,
  `hpkst_sign`, `hpkst_verify`; demo block (3-of-3, tamper rejection).
- **`Herradura cryptographic suite.c`**: adds HPKS-T demo block (3-of-3, tamper rejection).
- **`Herradura cryptographic suite.go`**: adds HPKS-T demo block.
- **`CryptosuiteTests/Herradura_tests.c`**: adds `test_hpkst()` → security test [31];
  benchmarks renumbered [32]–[43].
- **`CryptosuiteTests/Herradura_tests.go`**: adds `testHpkst()` → security test [31];
  benchmarks renumbered [32]–[43].
- **`CryptosuiteTests/Herradura_tests.py`**: adds `test_hpkst()` → security test [31];
  benchmarks renumbered [32]–[43].
- **`SecurityProofsCode/hpks_threshold_demo.py`**: standalone analysis script (n=32,
  rogue-key attack demo, coefficient-binding fix, 2-of-2 and 3-of-3 correctness).
- **`TODO.md`**: TODO #98 marked DONE v1.9.43; TODO #106 added for CLI multi-party
  threshold signing capability (commit/aggregate/respond/combine 4-phase protocol).

---

## [1.9.42] - 2026-06-14

### Consistency — HPKS-WOTS-F / HPKS-XMSS-F ported to C and Go (TODO #102)

Ports the HPKS-WOTS-F / HPKS-XMSS-F hash-based signature scheme from the Python suite
(added in TODO #97, v1.9.39) to C (`herradura.h`), Go (`herradura/herradura.go`), the
C and Go suite demo files, and all three C/Go/Python test files.  Security test [30] is
added across all targets; performance benchmarks shift from [30]–[41] to [31]–[42].

- **`herradura.h`**: adds `WOTS_W/L/L1/L2` constants, `_wots_h_ba`, `_wots_chain_ba`,
  `_wots_leaf_seed`, `_wots_msg_to_digits`, `hpks_wots_keygen`, `hpks_wots_sign`,
  `hpks_wots_recover_pk`, `hpks_wots_verify`, `_wots_pk_bytes`, `HpksXmssSig` struct,
  `hpks_xmss_keygen`, `hpks_xmss_sign`, `hpks_xmss_sig_free`, `hpks_xmss_verify`.
  Chain step: `h(x) = nl_fscx_revolve_v1(ROL(x, n/8), x, n/4)`, w=16, ℓ=67 chains.
- **`herradura/herradura.go`**: adds `HpksWotsKeygen`, `HpksWotsSign`, `HpksWotsRecoverPk`,
  `HpksWotsVerify`, `HpksXmssKeypair`, `HpksXmssKeygen`, `HpksXmssSig`,
  `HpksXmssSign`, `HpksXmssVerify`.
- **`Herradura cryptographic suite.c`**: adds HPKS-XMSS-F demo block (h=3, 2 leaves,
  tamper + OTS-reuse rejection).
- **`Herradura cryptographic suite.go`**: adds matching demo block; adds `crypto/rand` import.
- **`CryptosuiteTests/Herradura_tests.c`**: adds `test_wots_xmss()` → security test [30]
  (3 random seeds × 8-leaf tree × sign/tamper/reuse checks); benchmarks renumbered [31]–[42].
- **`CryptosuiteTests/Herradura_tests.go`**: adds `testWotsXmss()` → security test [30];
  benchmarks renumbered [31]–[42].
- **`CryptosuiteTests/Herradura_tests.py`**: adds self-contained WOTS/XMSS helpers and
  `test_wots_xmss()` → security test [30]; benchmarks renumbered [31]–[42].

Assembly and Arduino targets are out of scope (WOTS chain length too large for 32-bit targets).

---

## [1.9.41] - 2026-06-14

### Consistency — FPE (78.A), Tweakable cipher (78.B), Accumulator (78.J) ported to ARM and NASM (TODO #104)

Ports the three 32-bit constructions that existed in C, Go, Python, and Arduino to the
ARM Thumb-2 and NASM i386 assembly targets.  All logic is inlined in `main()` using the
existing `hfscx_32`, `nl_fscx_revolve_v2`, and `nl_fscx_revolve_v2_inv` helpers — no
new subroutines needed.

- **`Herradura cryptographic suite.s`** (ARM): adds 9 format strings and three demo
  blocks (`FPE 78.A`, `Tweakable 78.B`, `Accumulator 78.J`) inserted before exit.
  Accumulator computes a 4-leaf Merkle tree and verifies a membership proof for index 2.
- **`Herradura cryptographic suite.asm`** (NASM i386): same three demo blocks in NASM
  syntax with cdecl register conventions; scratch variables added to `section .data`.
- **`CryptosuiteTests/Herradura_tests.s`** (ARM): adds tests `[15] FPE` (3 random
  round-trips), `[16] Tweakable` (3 random round-trips), `[17] Accumulator` (fixed
  4-leaf Merkle proof); all 17 tests pass under qemu-arm.
- **`CryptosuiteTests/Herradura_tests.asm`** (NASM i386): matching tests [15]–[17].

NASM i386 source-level correctness mirrors the ARM implementation; build-time
verification on this ARM64 host is blocked by the known elf_i386 linker limitation
(documented in CLAUDE.md).

---

## [1.9.40] - 2026-06-14

### Consistency — ZKP-NL ARM/NASM port; Go suite demos; ZKP-RNL n-size unification (TODOs #101, #103, #105)

Cross-language consistency audit (2026-06-14) identified three gaps; all fixed in this release.

**TODO #101 — Go suite demo lags behind C/Python (HSKE-NL-AEAD and HDRBG missing):**
- **`Herradura cryptographic suite.go`** (v1.8.8 → v1.9.40): adds `--- HDRBG` demo block
  (determinism + reseed separation) and `--- HSKE-NL-AEAD` demo block (round-trip +
  tamper/AD rejection) matching the equivalent blocks in the C and Python suite files.
  Adds `"bytes"` import. Protocol implementations live in `herradura/herradura.go`
  (unchanged); only the demo `main()` was updated.

**TODO #103 — ZKP-NL (NL-FSCX ZKBoo) missing from ARM Thumb-2 and NASM i386:**
- **`Herradura cryptographic suite.s`** (ARM): adds `zkp_nl_prg_bit_8`, `zkp_nl_commit_8`,
  `zkp_nl_prove_8`, `zkp_nl_verify_8` functions and their BSS scratch storage;
  adds ZKP-NL demo call in `main()`. Parameters: n=8, R=4, using `hfscx_32` for PRG
  and commitments, matching the Arduino reference implementation.
- **`Herradura cryptographic suite.asm`** (NASM i386): same additions in NASM syntax
  and cdecl calling convention.
- **`CryptosuiteTests/Herradura_tests.s`** (ARM): adds test `[14] ZKP-NL prove+verify
  (3 trials, n=8, R=4)`; all 14 tests pass under qemu-arm.
- **`CryptosuiteTests/Herradura_tests.asm`** (NASM i386): same test [14] in NASM syntax.

**TODO #105 — ZKP-RNL demo n-size: C=256, Go/Python=32 (inconsistent):**
- **`Herradura cryptographic suite.go`**: changes `zkpN := 32` → `zkpN := n` (256) and
  updates the demo header to print the actual n value dynamically.
- **`Herradura cryptographic suite.py`**: changes `_zkprnl_n = 32` → `_zkprnl_n = KEYBITS`
  (256) and updates the header format string accordingly.
- ARM/NASM assembly targets keep n=32 (32-bit architecture parameter constraint, intentional).

---

## [1.9.39] - 2026-06-14

### Feature — HPKS-WOTS-F / HPKS-XMSS-F hash-based many-time signature (TODO #97)

Implements the HPKS-WOTS-F one-time signature and HPKS-XMSS-F stateful many-time
signature specified in SecurityProofs-2 §11.8.3 (Theorem 16).

- **`Herradura cryptographic suite.py`**:
  - `hpks_wots_keygen(master_seed, leaf_idx)` — derives ℓ=67 SK/PK chains via
    HFSCX-256(seed‖idx‖j); pk_i = h^15(sk_i).
  - `hpks_wots_sign(msg, master_seed, leaf_idx)` — Winternitz sign; w=16, ℓ=67 chains.
  - `hpks_wots_verify(msg, sig, pk)` — apply h^{d_i}(sig_i) and compare to pk.
  - `hpks_wots_recover_pk(msg, sig)` — recover pk from sig for standalone verify.
  - `_wots_pk_bytes(pk)` — serialise WOTS pk to bytes.
  - `hpks_xmss_keygen(master_seed, h=10)` — build 2^h-leaf Merkle tree of WOTS pks.
  - `hpks_xmss_sign(msg, master_seed, leaf_hashes, leaf_idx)` — sign at given leaf;
    returns `{leaf_idx, wots_sig, auth_path}` (pk NOT stored; recovered on verify).
  - `hpks_xmss_verify(msg, sig, root)` — recover pk from sig, hash leaf, verify path.
  - Demo (h=3, 8 leaves): sign/verify, tamper rejection, OTS reuse rejection.
  - Eve bypass tests: random-sig forgery rejected; index-swap rejected.
  - Added `import secrets` (was missing).
- **`HerraduraCli/primitives.py`**: exports all new WOTS/XMSS symbols.
- **`HerraduraCli/herradura.py`**:
  - `genpkey --algo hpks-xmss [--xmss-height N]` — generates master seed + full tree.
  - `pkey --pubout` — extracts 32-byte Merkle root as public key PEM.
  - `sign --algo hpks-xmss --key K --in MSG --out SIG` — signs using next unused leaf;
    state tracked in `<key>.pem.idx` sidecar file; prints leaves remaining.
  - `verify --algo hpks-xmss --pubkey PUB --in MSG --sig SIG` — standalone verify
    (no private key or seed needed; pk recovered from sig).
  - `_encode_xmss_privkey` / `_decode_xmss_privkey` / `_encode_xmss_pubkey` /
    `_decode_xmss_pubkey` / `_pack_xmss_sig` / `_unpack_xmss_sig` helpers.
  - State management: `_xmss_read_idx` / `_xmss_write_idx`.
- **`SecurityProofs-2.md §11.8.3`**: added HPKS-XMSS-F implementation note with
  parameters (w=16, ℓ=67, h=10), sign/verify algorithm, state-management rationale,
  and security bound ($\Pr[\text{forge}] \leq 2^h \cdot \ell \cdot \Pr[\text{invert}(h)]
  + \Pr[\text{collision in HFSCX-256}]$).
  KaTeX validation: 910 OK, 0 FAIL.

---

## [1.9.38] - 2026-06-14

### Research — FSCX branch-number characterisation and SPN construction study (TODO #99)

Characterises M = I XOR ROL XOR ROR as a GF(2)-linear diffusion layer and quantifies
its diffusion properties as a foundation for NL-FSCX security arguments and future
SPN-based constructions (#95, #96).

- **`SecurityProofsCode/fscx_branch_number.py`** (new): exhaustive/sampled branch-number
  computation for M^k (k=1..6) at n=16,32,64; avalanche trajectory of A-influence (M^t)
  and B-influence (S_t = M+...+M^t); ASCON Σ0/Σ1 comparison; FSCX-SPN round-count
  recommendation.  Key findings:
  - M is self-transposed (Bn_d = Bn_l for all n, all powers).
  - Bn(M) ≥ 36 at n=64, comparable to ASCON Σ0 (34) and Σ1 (38).
  - S_t collapses to 0 at t = n/2 (proven: M has order n/2); complete B-diffusion is
    never achievable.
  - A,B half-coverage threshold: t_{1/2}(n) = n/2 − 1; suite heuristic i=n/4 sits at
    the midpoint before S_t collapse, providing ~25–30% mean B-activation per output bit.
- **`SecurityProofs-1.md` §3.7** (new): Theorem 11 (M self-transposed, Bn_d = Bn_l),
  measured branch-number table, Theorem 12 (S_{n/2} = 0 periodicity), Corollary 3
  (complete B-diffusion unachievable), diffusion trajectory table, assessment of i=n/4,
  and FSCX-SPN round-count sketch feeding #95/#96.

---

## [1.9.37] - 2026-06-13

### Security — HKEX-RNL m_blind substitution-attack mitigation (TODO #89)

A MITM or malicious peer could replace `a_rand` in Alice's public PEM with a chosen
value (e.g., `a_rand = -m(x)`, forcing `m_blind = 0`), degrading the Ring-LWR hardness
guarantee or leaking the shared key directly.

- **`herradura.h`**: added `rnl_validate_m_blind(poly, n)` — rejects a peer-supplied
  blinding polynomial if it has fewer than `n/4` non-zero coefficients or a coefficient
  range smaller than `q/4`. A legitimately uniform polynomial over Z_65537 passes both
  checks with overwhelming probability.
- **`herradura/herradura.go`**: added `RnlValidateMBlind(poly []int, q int) bool` with
  the same two checks.
- **`HerraduraCli/herradura_cli.c`**: Bob (step 1) calls `rnl_validate_m_blind` after
  unpacking `m_A`; exits with an error on failure.
- **`HerraduraCli/herradura.py`**: added `_rnl_validate_m_blind`; Bob (step 1) calls it
  and exits with a descriptive error on failure.
- **`HerraduraCli/herradura_cli.go`**: Bob (step 1) calls `RnlValidateMBlind`; exits
  with an error on failure.
- **`SecurityProofs-2.md` §11.4.3**: added "Active-adversary caveat" paragraph
  documenting the substitution attack, the v1.9.37 mitigation, and the remaining gap
  (non-contributory blinding — full fix deferred to a future protocol revision).
- **No wire-format change**: validation is receiver-side only; all existing keys and
  PEM files remain compatible.

---

## [1.9.36] - 2026-06-13

### Bug fix — HPKS-Stern-F CLI cross-language sign/verify interop (TODO #100)

Two bugs prevented Python, C, and Go CLI implementations from verifying each other's HPKS-Stern-F signatures:

1. **Python challenge derivation (`Herradura cryptographic suite.py`)** — `hpks_stern_f_sign`, `hpks_stern_f_verify`, `stern_ring_sign`, and `stern_ring_verify` used `ch_st.uint % 3` (full 256-bit integer mod 3) to extract each Fiat-Shamir challenge from the NL-FSCX v1 chain state. C and Go extract the low 32 bits of the state first (`uint32(state) % 3`). Fixed by changing to `(ch_st.uint & 0xFFFFFFFF) % 3`, matching C's `((uint32_t)ch_st.b[KEYBYTES-4..KEYBYTES-1]) % 3` and Go's `uint32(chSt.Val.Uint64()) % 3`.

2. **C syndrome-to-BitArray byte ordering (`herradura.h`, `HerraduraCli/herradura_cli.c`)** — `syndr_to_ba` stored syndrome byte `k` at `out->b[KEYBYTES/2 + k]`, putting syndrome bit `i` at integer bit `(15 - i/8)*8 + i%8` (reversed within each 8-bit group). Python and Go store syndrome bit `i` at integer bit `i` (big.Int / Python int convention). Fixed by changing `syndr_to_ba` to store `syndr[k]` at `out->b[KEYBYTES - 1 - k]`, so that syndrome bit `i` lands at integer bit `i`. The public key serialization in `herradura_cli.c` (pkey `--pubout`) and deserialization (verify) were updated to apply the same byte-reversal, so C-generated public keys are now wire-compatible with Python and Go.

- **New interop test** — `CliTest/test_stern_interop.sh` covers all 9 sign→verify combinations (Python→Python, Python→C, Python→Go, C→Python, C→C, C→Go, Go→Python, Go→C, Go→Go) and verifies all pass.
- **Wire-format breaking**: HPKS-Stern-F signatures generated with v1.9.35 and earlier are not verifiable with v1.9.36+ across language boundaries (Python→C/Go or C/Go→Python would have always failed; within a single language boundary no new breakage was introduced for self-tests).

---

## [1.9.35] - 2026-06-12

### Security — HFSCX-256-DM finalization of Stern parity-matrix rows (TODO #88)

- **`Herradura cryptographic suite.py` / `herradura.h` / `herradura/herradura.go`**: `_stern_matrix_row` / `stern_matrix_row` / `SternMatrixRow` now route the raw NL-FSCX v1 row output through HFSCX-256-DM before truncation to n bits, exactly as `_stern_hash` has done since v1.6.0 (TODO #43). This completes the F_stern-v2 fix specified in `SecurityProofs-2.md` §11.8.4: rows of the public parity-check matrix H were previously drawn from a range-compressed distribution (~21–28% distinct at n=32; predicted <10^-4 distinct fraction at n=256), making H distinguishable from a uniform random binary matrix by collision counting and weakening the SD(N,t) instance via reduced rank(H). Row outputs verified byte-identical across Python, C, and Go.
- **n=32 demos**: `stern32_matrix_row` (C suite, HFSCX-256 truncated to 32 bits) and `stern_matrix_row_32` (ARM Thumb-2 and NASM i386 — suite and test files — and Arduino suite) finalized via `hfscx_32`, matching their v1.6.0 `stern_hash*_32` pattern. The 256-bit test helper `stern_matrix_row_ba` in `CryptosuiteTests/Herradura_tests.c` updated to match the library. The un-finalized self-contained helpers in `CryptosuiteTests/Herradura_tests.ino` and the 64/128-bit C test variants are unchanged, per the TODO #43 precedent.
- **Wire-format breaking**: H changes, so HPKS-Stern-F public keys, syndromes, signatures, and HPKE-Stern-F KEM ciphertexts generated before v1.9.35 are incompatible with v1.9.35+ implementations.
- **`SecurityProofs-2.md` §11.8.4**: matrix-generation formula restated with the HFSCX-256-DM outer call; deployment-status paragraph added (hash step v1.6.0, matrix rows v1.9.35).
- **Known pre-existing issue (neither introduced nor fixed here)**: cross-language HPKS-Stern-F CLI signature interop (e.g. Python-signed, C/Go-verified) also fails at the pre-change baseline — matrix rows and `_stern_hash` are byte-identical across languages, so the divergence is elsewhere in the CLI sign/verify pipeline; tracked as TODO #100.
- **Test fix — `CryptosuiteTests/Herradura_tests.py` test [20]**: PASS condition compared `ok` against the requested iteration count instead of the actual iterations run, so a `-t` wall-clock early stop reported a spurious FAIL (e.g. `64 / 100 [FAIL]` with all 64 passing) — same `_trange` artifact fixed for `test_masked_hske` in v1.9.29; now counts actual iterations.

---

## [1.9.34] - 2026-06-12

### Feature — HDRBG: forward-secure deterministic random bit generator (TODO #96)

- **`Herradura cryptographic suite.py` / `herradura.h` / `herradura/herradura.go`**: new `drbg_seed` / `drbg_generate` / `drbg_reseed` (Go: `DrbgSeed`/`DrbgGenerate`/`DrbgReseed`) — fast-key-erasure DRBG over the NL-FSCX v1 OWF. Output block i = HFSCX-256(state ‖ i_be8 ‖ `DRBG-OUT`); state advances one-way via `nl_fscx_revolve_v1(state, DRBG-domain, 64)`; reseed mixes fresh entropy via HFSCX-256 with the `DRBG-RESEED` domain prefix. Backtracking resistance reduces to the Theorem 16 OWF conjecture; C erases superseded state with `explicit_bzero`. Per-seed output limit `DRBG_MAX_BLOCKS = 2^20` enforced (generate refuses past it; reseed resets). All three implementations byte-for-byte interoperable (shared KAT). Non-goals documented: not a NIST SP 800-90A validated DRBG.
- **`SecurityProofsCode/nl_fscx_v1_ratchet_collision.py`**: new §5 — HDRBG walk characterisation: composed-image contraction of the 64-step revolve (extrapolates to 2^218.8 at n=256 vs 2^243.8 single-step), Brent rho/cycle lengths at n=16/20/24 (sqrt-of-image scaling), and DRBG_MAX_BLOCKS validation: E[walk collision] ≈ 2^109.7 blocks, P(collision within 2^20) ≈ 2^-180 — SAFE vs the 2^-128 target. Also fixed `safe_steps` float underflow for tiny probabilities (§4 previously printed "safe ≤ 2^0.0 steps") and made the n=32 exhaustive sweep opt-out via `FULL_SWEEP=0`.
- **`CryptosuiteTests`**: new security test [29] (C/Go/Python) — cross-language KAT, determinism, personalization divergence, reseed separation, block-limit enforcement, monobit sanity. Benchmarks renumbered [30]–[41].
- **`SecurityProofs-2.md` §11.9.6**: HDRBG note — construction, collision analysis summary, non-goals.
- **`CLAUDE.md`**: test numbering updated to [1]–[29] / [30]–[41].

---

## [1.9.33] - 2026-06-12

### Feature — HSKE-NL-AEAD: authenticated encryption with associated data (TODO #95 option 1)

- **`Herradura cryptographic suite.py` / `herradura.h` / `herradura/herradura.go`**: new `hske_nl_aead_encrypt` / `hske_nl_aead_decrypt` (Go: `HskeNlAeadEncrypt`/`HskeNlAeadDecrypt`) — byte-level encrypt-then-MAC AEAD over the HSKE-NL-A1 CTR keystream. Tag = keyed HFSCX-256-DM over `HSKE-NL-AEAD-v1` DS prefix ‖ nonce ‖ len-framed AD ‖ len-framed ciphertext; MAC key uses the existing domain-separated `mac_key` schedule, DS-prefix-separated from the `.hkx` encfile MAC. Key-committing (the tag binds the MAC key through the collision-resistant keyed chain — a property AES-GCM lacks). Verify-then-decrypt with constant-time tag comparison (`hmac.compare_digest` / `ct_eq32` / `crypto/subtle`). All three implementations are byte-for-byte interoperable (shared KAT).
- **`HerraduraCli` (Python/C/Go)**: `enc --algo hske-nla1 --aead [--ad STR]` emits ciphertext PEM format tag 2 — `SEQ(2, nonce, E, tag, nbits)`; `dec` auto-detects format tag 2, verifies (optionally with `--ad`) before decrypting, and fails closed on tag mismatch. PEM outputs are cross-CLI compatible.
- **`CryptosuiteTests`**: new security test [28] (C/Go/Python) — cross-language KAT, round-trip over irregular lengths, and tamper rejection (ciphertext, tag, AD, nonce, key). Benchmarks renumbered [28]–[39] → [29]–[40]; stale C benchmark comments fixed to current labels.
- **`CliTest/test_aead.sh`**: new — all 9 producer/consumer CLI pairs, wrong-AD and wrong-key rejection (19 checks).
- **`SecurityProofs-2.md` §11.9.6**: HSKE-NL-AEAD note — construction, key-commitment argument, and TODO #95 option 2 (NL-FSCX v2 sponge/duplex AEAD) recorded as open research gated on TODO #99.
- **`CLAUDE.md`**: test numbering updated to [1]–[28] / [29]–[40].

---

## [1.9.32] - 2026-06-12

### Security/Proofs — ZKP-RNL Σ-protocol relaxed special soundness + structured cheat tests (TODO #94, items 1–2)

- **`SecurityProofs-3.md` §11.10.2**: The soundness argument is restated as **relaxed special soundness** (Lyubashevsky 2012). The previous sketch extracted (z−z')·(c−c')⁻¹, implicitly assuming challenge differences are invertible in R_q — unjustified for the suite parameters: q = 65537 gives 2n | q−1 for all power-of-two n ≤ 256, so x^n+1 splits into linear factors over F_q and R_q has zero divisors. Measured: 3/2000 random challenge pairs at n=32 yield nonzero non-invertible differences. The extractor now outputs the pair (z−z', c−c') as a relaxed witness (norm bounds stated) without inversion; the factor-2 norm relaxation is flagged for the open formal-reduction work (§11.10.6 item 1). Empirical-results table extended with the new cheat tests.
- **`SecurityProofsCode/zkp_pqc_exploration.py`**: new §2.4b structured cheating provers — wrong-key witness (honest prover run with fresh s′ ≠ s), tampered commitment w (Fiat-Shamir check), perturbed response z (residual-norm check), and bounded challenge grinding (64 attempts/trial); all 0 passes. New §2.6 challenge-difference invertibility scan: evaluates c−c' at the n roots of x^n+1 over F_q (CRT split), empirically confirming non-invertible differences exist and motivating the relaxed formulation.
- **`CryptosuiteTests/Herradura_tests.py`** test [21]: ZKP-RNL now also checks wrong-key rejection, tampered-w rejection, and perturbed-z rejection at n=32 and n=256 against the deployed `_rnl_sigma_sign`/`_rnl_sigma_verify`. (C/Go test extension deferred.)
- **`TODO.md`**: #94 items 1–2 done; #92 gains a related finding — §11.4.3's claim that x^256+1 "does not split into degree-1 factors over F_65537 since 512 ∤ q−1" is arithmetically wrong (512 | 65536; the ring splits fully). KaTeX pipeline validator: SecurityProofs-3.md 158 OK, 0 FAIL.

---

## [1.9.31] - 2026-06-11

### Housekeeping — Unify test numbering across C, Go, and Python (TODO #87)

- **`CryptosuiteTests/Herradura_tests.c`**: Security tests are now [1]–[27], identical to Go and Python. HPKS-Stern-Ring renumbered [28]→[20]. The C-only F_stern range test loses its `[N]` label (runs between [20] and [21]). The main() call order is restructured so [17]→[18]→[19] print sequentially: Stern-F section, then Hash (HFSCX-256), then Ring Signatures. Benchmarks shifted from [26]–[37] → [28]–[39] to eliminate collision with security tests [26]–[27]. New sections: "Code-Based PQC (Ring Signatures)" splits off from the Stern-F section. File header updated to v1.9.31 with accurate test index.
- **`CryptosuiteTests/Herradura_tests.go`**: HFSCX-256-DM reordered [17]→[19]; HPKS-Stern-F [18]→[17]; HPKE-Stern-F [19]→[18] (now matches C and Python). HPKS-Stern-Ring [27]→[20]. ZKP/FPE/TWK/Accumulator/Masked/Ratchet security tests shifted +1 ([20]–[26]→[21]–[27]). Benchmarks shifted from [22]–[33] → [28]–[39]. main() call order updated so Stern-F and HFSCX-256 execute before Ring test. Version banner updated to v1.9.31.
- **`CryptosuiteTests/Herradura_tests.py`**: HPKS-Stern-Ring [27]→[20]. ZKP/FPE/TWK/Accumulator/Masked/Ratchet security tests shifted +1 ([20]–[26]→[21]–[27]). Benchmarks shifted from [25]–[36] → [28]–[39]. main() call order fixed: HFSCX-256 now executes before Ring test, giving sequential output. Version banner updated to v1.9.31.
- **`CLAUDE.md`**: Testing section now accurately documents [1]–[27] security tests + [28]–[39] benchmarks for C/Go/Python; assembly count corrected [1]–[12]→[1]–[13].
- **`TODO.md`**: TODO #84 symptom updated to reference test [26] (was [25]) following Masked HSKE renumbering.

---

## [1.9.30] - 2026-06-10

### Fix — C test [25] Accumulator tamper-rejection incorrect for n=1 empty-proof case

- **`CryptosuiteTests/Herradura_tests.c`**: `test_accumulator_correctness` now correctly counts the n=1 (single-leaf, depth=0) case as a tamper-rejected trial, matching the Go and Python implementations. When `depth == 0` the proof is empty and there is nothing to tamper — Go and Python both already incremented `ok_reject` unconditionally for this case. The C test was skipping the increment, causing a deterministic `tamper_reject=30/31 [FAIL]`. Fixed by restructuring the tamper branch to `if (depth > 0) { flip, check, count } else { count unconditionally }`.

---

## [1.9.29] - 2026-06-10

### Fix — Spurious FAIL in Python test [25] Masked HSKE under time-limited runs (TODO #84)

- **`CryptosuiteTests/Herradura_tests.py`**: `test_masked_hske` compared `ok == N` (requested iterations) rather than `ok == n_run` (actual iterations run). When a `-t` time limit causes `_trange` to stop early (e.g., after 128 or 192 of 200 requested iterations), all passed iterations were reported as failures. Added `n_run` counter matching the pattern used by every other `_trange`-based test in the suite; PASS condition is now `ok == n_run`.

---

## [1.9.28] - 2026-06-10

### Security — Fix three vulnerabilities identified in security review (TODO #81, #82, #83)

- **`HerraduraCli/herradura_codec.h`** (TODO #81): added `PEM_LABEL_MAX 79` macro; `pem_unwrap` now rejects any PEM label longer than `PEM_LABEL_MAX` characters with `return -1` before the `memcpy`, preventing stack and heap buffer overflows when callers supply an 80-byte `label_out` buffer; self-test section 7 added — asserts that an 80-character label causes `pem_unwrap` to return `-1`.
- **`HerraduraCli/herradura_cli.c`** (TODO #82): `zkp_nl_unpack_proof` now validates `n` (`1 ≤ n ≤ ZKP_NL_MAX_N`) and `rounds` (`1 ≤ rounds ≤ 4096`) immediately after decoding from the proof buffer, before any allocation; prevents integer-overflow-induced undersized heap allocation on 32-bit targets.
- **`herradura.h`** (TODO #82): `zkp_nl_verify` entry guard added — returns 0 immediately if `n` or `rounds` are out of range, providing defence-in-depth for callers that use the header directly.
- **`herradura.h`** (TODO #83): added `ct_eq32` (32-byte) and `ct_eq_keybytes` (KEYBYTES-byte) constant-time equality helpers alongside `ba_equal`; replaced `memcmp(c_p1, coms[p1], 32) || memcmp(c_p2, coms[p2], 32)` in `zkp_nl_verify` with `ct_eq32`; replaced `memcmp(cur, root, KEYBYTES)` in `haccum_verify` with `ct_eq_keybytes`, eliminating timing side-channels in ZKP-NL and Merkle-accumulator verification.

---

## [1.9.27] - 2026-06-09

### Feature — aPAKE C+Go library + CLI (TODO #80 Batch 4-C/Go)

- **`herradura.h`**: added `HpakeRecord` struct, `HPAKE_ZKP_N` (32), `HPAKE_ROUNDS` (16) constants, `_hpake_zkp_witness`, `_hpake_rnl_kdf`, `hpake_register`, `hpake_login_demo` — aPAKE using HKEX-RNL + ZKBoo (NL-FSCX v1 at n=32) + OPRF; aPAKE demo block added to `Herradura cryptographic suite.c` `main()`.
- **`HerraduraCli/herradura_codec.h`**: added `PEM_PAKE_RECORD` label constant.
- **`HerraduraCli/herradura_cli.c`**: `pake-register` (outputs `HERRADURA PAKE RECORD` PEM with SEQUENCE of salt/B/y), `pake-demo` (full both-sides auth demo, prints session key and verifies wrong-password rejection); `_pake_der_uint32` helper; dispatch entries.
- **`herradura/herradura.go`**: added `HpakeZkpN` (32), `HpakeRounds` (16), `HpakeRecord` type, `hpakeDeriveZkpWitness`, `hpakeRnlKdf`, `HpakeRegister`, `HpakeLoginDemo`; aPAKE demo block added to `Herradura cryptographic suite.go` `main()`.
- **`HerraduraCli/herradura_cli.go`**: `lblPakeRecord` constant; `cmdPakeRegister`, `cmdPakeDemo` functions; dispatch cases.
- **`CliTest/test_c_pake.sh`**: 7 C CLI aPAKE integration tests — all passing.
- **`CliTest/test_go_pake.sh`**: 7 Go CLI aPAKE integration tests — all passing.

---

## [1.9.26] - 2026-06-09

### Feature — aPAKE Python suite + CLI (TODO #80 Batch 4)

- **Python suite** (`Herradura cryptographic suite.py`): added `hpake_register`, `hpake_login_demo`, `_hpake_derive_zkp_witness`, `_hpake_rnl_kdf` — aPAKE (augmented PAKE) using HKEX-RNL + ZKBoo + OPRF; demo block in `main()` validates correct-password login and wrong-password rejection; module docstring updated.
- **`HerraduraCli/primitives.py`**: exports `hpake_register`, `hpake_login_demo`.
- **Python CLI** (`HerraduraCli/herradura.py`): `pake-register` (outputs `HERRADURA PAKE RECORD` PEM), `pake-demo` (runs full both-sides auth demo); `_LABEL_PAKE_RECORD` constant; dispatch table entries.
- **`CliTest/test_pake.sh`**: 7 Python CLI aPAKE integration tests — all passing.

---

## [1.9.25] - 2026-06-09

### Feature — OPRF C+Go library + CLI + cross-language interop tests (TODO #80 Batches 2, 3, 6)

- **`herradura.h`**: added `ba_cmp256`, `_ba33_cmp`, `_ba33_iszero`, `ba_modinv_ord` (binary extended GCD mod 2^256-1 with coprimality retry), `oprf_hash_to_field`, `oprf_keygen`, `oprf_blind`, `oprf_eval`, `oprf_unblind`, `oprf_direct`; OPRF demo block added to `Herradura cryptographic suite.c` `main()`.
- **`HerraduraCli/herradura_codec.h`**: added `PEM_OPRF_PRIV`, `PEM_OPRF_STATE`, `PEM_OPRF_EVAL` label constants.
- **`HerraduraCli/herradura_cli.c`**: `genpkey --algo oprf`, `oprf-blind`, `oprf-eval`, `oprf-unblind` subcommands; `ba_from_der_item` helper; usage text updated.
- **`herradura/herradura.go`**: added `OprfKeygen`, `OprfBlind`, `OprfEval`, `OprfUnblind`, `OprfDirect`, `oprfOrd`, `oprfHashToField`; OPRF demo block added to `Herradura cryptographic suite.go` `main()`.
- **`HerraduraCli/herradura_cli.go`**: `lblOprfPriv`/`lblOprfState`/`lblOprfEval` constants; `genpkey --algo oprf`; `cmdOprfBlind`, `cmdOprfEval`, `cmdOprfUnblind` functions; dispatch cases.
- **`CliTest/test_c_oprf.sh`**: 7 C CLI integration tests — all passing.
- **`CliTest/test_go_oprf.sh`**: 7 Go CLI integration tests — all passing.
- **`CliTest/test_oprf_interop.sh`**: 8 cross-language interop tests (Python/C/Go key × blind × eval × unblind) — all passing.

---

## [1.9.24] - 2026-06-09

### Feature — OPRF library + Python CLI (TODO #80 Batch 1)

- **Python suite** (`Herradura cryptographic suite.py`): added 2HashDH OPRF over GF(2^256)* — `oprf_keygen`, `oprf_blind`, `oprf_eval`, `oprf_unblind`, `oprf_direct`; demo block in `main()` validates blind/eval/unblind round-trip and aPAKE pw_key derivation.
- **`HerraduraCli/primitives.py`**: exports all five `oprf_*` symbols.
- **Python CLI** (`HerraduraCli/herradura.py`): `genpkey --algo oprf` generates OPRF server key (PEM label `HERRADURA OPRF PRIVATE KEY`); `oprf-blind` (client blinding → `HERRADURA OPRF CLIENT STATE`), `oprf-eval` (server evaluation → `HERRADURA OPRF EVALUATION`), `oprf-unblind` (client unblinding → PRF output hex).
- **`CliTest/test_oprf.sh`**: 8 Python CLI integration tests — keygen, blind, eval, unblind, determinism, different-input, different-key, pkey inspect — all passing.

---

## [1.9.23] - 2026-06-09

### Research — Non-Abelian KEX analysis: orbit sweep, non-abelianness, Ko-Lee viability (TODO #78.E)

Added `SecurityProofsCode/nl_fscx_v2_kex.py`: five-section analysis of the non-abelian KEX construction.

- **§1 Orbit sweep n=8..40:** Anomaly confirmed at n=12 (ALL short ≤100); n=16,20,28,32,36,40 all-long (orbits > 4096); n=24 bounded (orbits ≤65536 — consistent with `nl_fscx_v2_orbit.py`).
- **§2 Non-abelianness:** 200/200 (100%) of tested triples are non-abelian at n=32; explicit witness provided.
- **§3 Commuting-pair density:** 0/300 single-step and 0/300 revolve-commuting pairs — Ko-Lee KEX not viable with random key selection.
- **§4 KEX protocol demo:** Same-key revolve KEX (abelian, DLP-reducible) works; cross-key KEX fails; group inverse round-trip verified.
- **§5 Obstacle status:** Obstacle 2 extended to n=8..40; Obstacles 1 and 3 remain research-open; Ko-Lee path blocked by absence of commuting subgroups.

---

## [1.9.22] - 2026-06-09

### Research — OPRF demo: Oblivious PRF constructions from GF(2^n)* and NL-FSCX (TODO #78.G)

Added `SecurityProofsCode/oprf_demo.py`: four-section analysis of OPRF constructions.

- **§1 2HashDH OPRF over GF(2^n)*:** `F(k,x) = gf_pow(H(x), k)`. Verifies GF exponent law empirically; demonstrates obliviousness (three blinded queries are indistinguishable under CDH). Correct unblinding via `r^{-1} mod (2^n−1)`.
- **§2 NL-FSCX commutativity:** Tests 500 random triples. Single-step symmetry A3 (`nl(A,B)==nl(B,A)`) holds 100%. Iterated commutativity (`NL_rev(NL_rev(X,R),K) == NL_rev(NL_rev(X,K),R)`) holds **0%** — pure NL-FSCX DH-style OPRF is not viable.
- **§3 Hybrid NL-FSCX OPRF:** `F_NL = nl_fscx_revolve_v1(gf_pow(H(x), k_dh), k_nl, t)`. k_nl is a public domain-separation parameter; obliviousness from CDH layer only.
- **§4 aPAKE integration:** Closes the offline dictionary attack gap from `hkex_pake_demo.py` by replacing `hfscx_256(pw+salt)` with `hfscx_256(OPRF(k_s,pw)+salt)`. Correct/wrong password paths demonstrated.

---

## [1.9.21] - 2026-06-09

### Research — VDF demo: FSCX and NL-FSCX Verifiable Delay Functions (TODO #78.F)

Added `SecurityProofsCode/vdf_demo.py`: four-section analysis of VDF constructions.

- **§1 FSCX VDF (limited model):** `eval = fscx_revolve(x, d, t)`, `verify = fscx_revolve(y, d, P−t) == x`. Period P always divides n (verified); verification is 11× faster than eval at t = P−1.
- **§2 Matrix attack:** Derives closed form `fscx_revolve(A, B, t) = M^t(A) ⊕ M·T_t·B` (GF(2) matrix exponentiation). Implements and verifies the formula; timing shows matrix beats sequential at t ≥ ~5000 for n=32. Confirms the FSCX VDF is broken in the standard model.
- **§3 NL-FSCX v1 VDF:** Non-linear — no matrix shortcut. Period > 2^16 at n=32 (consistent with `nl_fscx_v2_orbit.py §4`); setup and verification infeasible without an efficient proof system.
- **§4 Summary:** Neither construction is production-ready. Production VDF requires Pietrzak/Wesolowski succinct proofs, which need algebraic structure not yet found in FSCX.

---

## [1.9.20] - 2026-06-09

### Research — PAKE-ZKBoo: PQC Password-Authenticated Key Exchange demo (TODO #78.D)

Added `SecurityProofsCode/hkex_pake_demo.py`: demonstrates a native-primitive PAKE
construction using only HKEX-RNL + ZKBoo (ZKP-NL) + HFSCX-256.

**Protocol (3 messages):**
- Registration: `pw_key = hfscx_256(password‖salt)`, domain-separated `zkp_A` (32-bit for
  demo), `y = nl_fscx_v1(zkp_A, B)`.  Server stores `(salt, B, y)`; password never transmitted.
- Login: HKEX-RNL ephemeral key exchange + ZKBoo proof of `nl_fscx_v1(zkp_A, B) = y` bound
  to session's raw key `K_raw` via Fiat-Shamir message.  Both sides derive matching session key.
- Wrong-password fast abort: local `nl_fscx_v1` check (7 ms) before ZKBoo — no server round-trip.

**Demo output:** correct-password login succeeds (3.6 s, session keys match); wrong-password
aborts at client (7 ms).

**Open gaps documented in §4:** offline dictionary attack (PAKE not aPAKE — fix requires
OPRF, TODO #78.G); no formal security reduction; demo uses ZKP_N=32 (Python speed limit) and
R=16 rounds.

---

## [1.9.19] - 2026-06-09

### Research — NL-FSCX v2 orbit-length analysis script (TODO #78.E)

Added `SecurityProofsCode/nl_fscx_v2_orbit.py`: six-section empirical analysis of the
`pi_K` permutation family underpinning the NASG (Non-Abelian Symmetric Group) key-exchange
candidate (§11.8.5 "Option C").  Uses Brent's cycle detection to characterise orbit-length
distribution and assess obstacle 2 ("no verified lower bound on orbit lengths").

Key findings:
- **n=24 anomaly**: ALL sampled (K, G) pairs have orbit ≤ 65536 with typical lengths 7–100,
  despite a 2^24-element state space.  Orbit length is **non-monotone** in n.
- **n=32**: ALL 200 sampled pairs have orbit > 2^16; empirical lower bound confirmed.
- **Non-commutativity** (Theorem 15): 99.65% / 99.99% / 100% at n=8/16/32.
- **CSP collision rate**: ~2 solutions per (G, K2, C) triple at n=6,8 (~33% unique).
- Obstacle 2 is PARTIALLY addressed at n=32; the n=24 anomaly means production security
  (n=256) cannot be inferred by extrapolation — independent analysis required.

---

## [1.9.18] - 2026-06-09

### Fix — C ZKP-NL stack-buffer-overflow at n=64 and C CLI encfile/decfile KDF mismatch (TODO #79)

Two C-only bugs discovered during a full build-and-test sweep across all six language targets:

**79.A — `zkp_nl_eval_3p` stack-buffer-overflow when `n = 64` (`herradura.h`, `herradura_cli.c`, `CryptosuiteTests/Herradura_tests.c`, `Herradura cryptographic suite.c`):**
`ZKP_NL_MAX_N` was 32, allocating `carry[33][3]` on the stack.  The loop `carry[i+1][p] = ...` writes up to index `n-1 = 63` for `n=64`, overflowing by 30 rows (360 bytes) and triggering "stack smashing detected".  A secondary UB also fired: `(1u << n) - 1u` is undefined for `n ≥ 32` with a 32-bit type.
Fix: bumped `ZKP_NL_MAX_N` to 64, changed all ZKP-NL share/carry types from `uint32_t` to `uint64_t` (10 functions in `herradura.h`), updated the mask to `(n >= 64) ? UINT64_MAX : (1ULL << n) - 1ULL`, and updated all callers in the three affected source files (`printf` format updated to `%lx`).  Test [22] ZKP-NL now passes for both `n=32` and `n=64`.

**79.B — C CLI `encfile`/`decfile` computed keystream seed with old v1.7 formula, breaking cross-language interop (`HerraduraCli/herradura_cli.c`):**
Both `cmd_encfile` and `cmd_decfile` called `ba_rol_k(&seed, &base, KEYBITS/8)` instead of `ba_rnl_kdf_seed(&seed, &base)`.  The KDF step `ba_rnl_kdf_seed` (added in v1.8.0, TODO #38) XORs the SHA-256 constant `_RNL_KDF_DC` into the seed after the rotation; without it, C-generated `.hkx` files were unreadable by Go/Python and vice versa.  Fix: replaced the two `ba_rol_k` calls; also updated the stale comment at `herradura.h:633`.  All C↔Python and Go↔C encfile interop tests now pass.

---

## [1.9.17] - 2026-06-08

### Fix — ARM Thumb-2 assembly bugs found on first live build (gcc-arm-linux-gnueabi)

Two bugs in `Herradura cryptographic suite.s` and `CryptosuiteTests/Herradura_tests.s`, both latent since the code was written but never caught because the ARM cross-compiler was not previously installed:

- **IT-block condition mismatch in ratchet loop:** `it ne` block contained a `cmpeq` instruction (condition `eq` ≠ block condition `ne`), rejected by the assembler.  Replaced with a plain branch sequence (`bne ratch_check_coll` / `b ratch_continue`).
- **Missing `mov r0, r8` before `stern_popcount_eq2` in ring-sig verify (b=1 path):** `r8` held the response value but `r0` was never loaded before the call, so the weight-2 check always evaluated a stale/wrong value and caused every b=1 round to fail.  Fixed in both the suite file (`hrv2_b1`) and the test file (`thrv2_b1`).

All 13 ARM tests now pass under `qemu-arm`, including test [13] (HPKS-Stern-Ring: 3/3 ring-verified).

---

## [1.9.16] - 2026-06-08

### Feature — HPKS-Stern-Ring: Code-Based Ring / Group Signature via OR-Composition (78.I) across all language targets (TODO #78)

Implements `HPKS-Stern-Ring` — a k-member ring signature built from OR-composition of k HPKS-Stern-F identification instances, via the HVZK simulator / challenge-splitting technique. Signing proves knowledge of one secret key in the ring without revealing which member signed; verifier only checks that per-round challenge sums equal the Fiat-Shamir joint challenge.

**Protocol design:**
- Non-signer members i ≠ j: HVZK simulator chooses challenge b_i pre-commitment; produces valid (c0_i, c1_i, c2_i, resp_i) without knowing the secret key.
- Real signer j: commits normally; after Fiat-Shamir joint challenge is computed from all k×rounds×3 commits, splits challenge: b_j[r] = (joint[r] − Σ_{i≠j} b_i[r]) mod 3.
- Fiat-Shamir: hash(msg ∥ member-major commit chain) → joint challenges.
- Assembly/Arduino simplification: k=2, member 0 always uses b=0 (no HVZK case selection needed).

**Files modified:**
- `herradura.h` — `SternRingSig`, `stern_ring_alloc/free`, `stern_ring_challenges`, `stern_ring_simulate`, `stern_ring_sign`, `stern_ring_verify`.
- `herradura/herradura.go` — Go package: `SternRingSig`, `RingKeypair`, `sternRingChallenges`, `sternSimulateRound`, `HpksSternRingSign`, `HpksSternRingVerify`.
- `Herradura cryptographic suite.c` — C suite: ring demo (k=3, sign as member 1) + Eve bypass test.
- `Herradura cryptographic suite.go` — Go suite: ring demo (k=3, sign as member 1) + Eve bypass test.
- `Herradura cryptographic suite.py` — Python suite: ring demo (k=3, sign as member 1) + Eve bypass test.
- `Herradura cryptographic suite.s` — ARM Thumb-2: k=2 ring sig (`ring_fs_challenges_32`, `hpks_stern_ring2_sign_32`, `hpks_stern_ring2_verify_32`) + demo + Eve test.
- `Herradura cryptographic suite.asm` — NASM i386: same k=2 functions + demo + Eve test.
- `Herradura cryptographic suite.ino` — Arduino: `SternRingSig2_32`, `ring_fs_challenges2_32`, `hpks_stern_ring2_sign_32`, `hpks_stern_ring2_verify_32` + demo in `loop()` + Eve test.
- `CryptosuiteTests/Herradura_tests.c` — test [28]: HPKS-Stern-Ring correctness (k=3, N=256, rounds=8).
- `CryptosuiteTests/Herradura_tests.go` — test [27]: HPKS-Stern-Ring correctness (k=3, N=256, rounds=16).
- `CryptosuiteTests/Herradura_tests.py` — test [27]: HPKS-Stern-Ring correctness (k=3, N=32, rounds=4).
- `CryptosuiteTests/Herradura_tests.s` — ARM Thumb-2: test [13] (k=2, 3 iterations).
- `CryptosuiteTests/Herradura_tests.asm` — NASM i386: test [13] (k=2, 3 iterations).

---

## [1.9.15] - 2026-06-08

### Feature — Masking-Friendly FSCX (78.H) and Forward-Secret Ratchet (78.C) across all language targets (TODO #78)

Implements two new protocol directions from TODO #78 in C, Go, Python, ARM Thumb-2, NASM i386, and Arduino.

**78.H — Masking-Friendly FSCX (GF(2)-linearity):**
`FSCX(A⊕r, B, steps) ⊕ FSCX(r, 0, steps) = FSCX(A, B, steps)` — M = I⊕ROL⊕ROR is GF(2)-linear, so `M^steps(A⊕r) = M^steps(A) ⊕ M^steps(r)`. Mask `r` is fresh per call; no secret bits of `A` appear in any intermediate value. API: `fscx_revolve_masked`, `hske_encrypt_masked`, `hske_decrypt_masked`.

**78.C — Forward-Secret Unidirectional Ratchet:**
`state_{i+1} = NL-FSCX-v1(state_i, DOMAIN, 1)`; `msg_key_i = HFSCX-256(state_i ∥ 0x01)`. Domain constant: first 32 bytes of `NL-FSCX-RATCHET-V1\x00NL-FSCX-RATCHET-V`. One-way by Theorem 16 OWF conjecture. API: `ratchet_init`, `ratchet_advance`, `ratchet_erase`. Analysis script: `SecurityProofsCode/nl_fscx_v1_ratchet_collision.py`.

**Files modified:**
- `herradura.h` — `fscx_revolve_masked`, `hske_encrypt_masked`, `hske_decrypt_masked`, `ratchet_init`, `ratchet_advance`, `ratchet_erase` (static inline + `_RATCHET_DOMAIN_BYTES`).
- `herradura/herradura.go` — Go package: `FscxRevolveMasked`, `HskeEncryptMasked`, `HskeDecryptMasked`, `RatchetInit`, `RatchetAdvance`, `ratchetDomain`.
- `Herradura cryptographic suite.py` — Python suite: all 7 functions + demo blocks in `main()`.
- `Herradura cryptographic suite.c` — C suite: demo blocks for masked HSKE and ratchet in `main()`.
- `Herradura cryptographic suite.go` — Go suite: demo blocks in `main()`.
- `Herradura cryptographic suite.s` — ARM Thumb-2: `fscx_revolve_masked_32` demo + `ratchet_advance_32` demo blocks; format strings and `ratchet_domain_32` in `.data`.
- `Herradura cryptographic suite.asm` — NASM i386: same 32-bit demo blocks; strings and `ratchet_domain_32` in `.data`.
- `Herradura cryptographic suite.ino` — Arduino: `fscx_revolve_masked_32`, `hske_encrypt_masked_32`, `hske_decrypt_masked_32`, `ratchet_advance_32`, `RATCHET_DOMAIN_32` + demo in `loop()`.
- `HerraduraCli/primitives.py` — re-exports `fscx_revolve_masked`, `hske_encrypt_masked`, `hske_decrypt_masked`, `ratchet_init`, `ratchet_advance`.
- `CryptosuiteTests/Herradura_tests.c` — tests [26]–[27]: masked HSKE, ratchet forward secrecy.
- `CryptosuiteTests/Herradura_tests.go` — tests [25]–[26]: masked HSKE, ratchet.
- `CryptosuiteTests/Herradura_tests.py` — tests [25]–[26]: masked HSKE, ratchet.
- `SecurityProofsCode/nl_fscx_v1_ratchet_collision.py` — collision-probability analysis for the ratchet (birthday bound, image-size extrapolation to n=256, safe step bounds at 2^−128/2^−80/2^−64).

---

## [1.9.14] - 2026-06-07

### Feature — Cryptographic Accumulator (78.J), Format-Preserving Encryption (78.A), and Tweakable Wide-Block Cipher (78.B) across all language targets (TODO #78)

Implements three new protocol directions from TODO #78 in C, Go, Python, and Arduino (32-bit variants for Arduino; assembly targets skipped — no 256-bit HFSCX available).

**78.J — Cryptographic Accumulator (HFSCX-256 Merkle tree):**
Domain-separated leaf hash `HFSCX-256(0x00 ∥ data)` and node hash `HFSCX-256(0x01 ∥ left ∥ right)` per RFC 6962. Power-of-2 padding with zero-hashes. API: `haccum_leaf`, `haccum_node`, `haccum_root`, `haccum_prove`, `haccum_verify`.

**78.A — Format-Preserving Encryption (FPE):**
`B = HFSCX-256(key ∥ ctx)` → `C = NlFscxRevolveV2(P, B, 64)`. Deterministic and searchable on 256-bit blocks. `NlFscxRevolveV2Inv` for decryption. API: `fpe_encrypt`, `fpe_decrypt`.

**78.B — Tweakable Wide-Block Cipher:**
`B = HFSCX-256(key ∥ sector_be64 ∥ bidx_be32)` → per-block unique tweak resolving HSKE-NL-A2 determinism (TODO #12). API: `twk_encrypt`, `twk_decrypt`.

**Files modified:**
- `herradura.h` — `haccum_*`, `fpe_derive_b`, `fpe_encrypt`, `fpe_decrypt`, `twk_derive_b`, `twk_encrypt`, `twk_decrypt` (static inline functions).
- `herradura/herradura.go` — Go package: `HaccumLeaf`, `HaccumNode`, `HaccumRoot`, `HaccumProve`, `HaccumVerify`; `FpeEncrypt`, `FpeDecrypt`; `TwkEncrypt`, `TwkDecrypt`.
- `Herradura cryptographic suite.py` — Python suite: all 12 functions + demo blocks in `main()`.
- `Herradura cryptographic suite.c` — C suite: demo blocks in `main()`.
- `Herradura cryptographic suite.go` — Go suite: demo blocks in `main()`.
- `Herradura cryptographic suite.ino` — Arduino: 32-bit variants (`fpe_encrypt_32`, `twk_encrypt_32`, `haccum_root_32`, etc.) + demo in `loop()`.
- `HerraduraCli/herradura_cli.c` — C CLI: `cmd_fpe` and `cmd_twk` subcommands.
- `HerraduraCli/herradura_cli.go` — Go CLI: `cmdFpe` and `cmdTwk` subcommands.
- `HerraduraCli/herradura.py` — Python CLI: `cmd_fpe` and `cmd_twk` subcommands.
- `HerraduraCli/primitives.py` — re-exports for new functions.
- `CryptosuiteTests/Herradura_tests.c` — tests [23]–[25]: FPE, tweakable, accumulator; benchmarks renumbered [26]–[37].
- `CryptosuiteTests/Herradura_tests.go` — tests [22]–[24]: FPE, tweakable, accumulator; benchmarks remain [25]–[33].
- `CryptosuiteTests/Herradura_tests.py` — tests [22]–[24]: FPE, tweakable, accumulator; benchmarks renumbered [25]–[36].

---

## [1.9.13] - 2026-06-06

### Feature — ZKP documentation Batch 9: TUTORIAL.md ZKP Protocols section + SecurityProofs-3.md §11.10.4 implementation subsection (TODO #77, Batch 9)

Adds comprehensive ZKP documentation completing TODO #77.

**`docs/TUTORIAL.md`** — new top-level `## ZKP Protocols` section:
- When to use ZKP-RNL vs. ZKP-NL vs. HPKS-Stern-F (use-case guidance).
- ZKP-RNL API walk-through (keygen → sign → verify) with C, Go, and Python snippets.
- ZKP-NL API walk-through (keygen → prove → verify) with C, Go, and Python snippets.
- CLI usage: `genpkey hkex-rnl`, `sign --algo rnl-sigma`, `verify --algo rnl-sigma`;
  `genpkey hpks-zkp-nl`, `sign --algo nl-zkboo --rounds 4`, `verify --algo nl-zkboo`.
- Proof-size and performance comparison table (ZKP-RNL vs ZKP-NL vs HPKS-Stern-F vs ML-DSA-44).
- `### ZKP protocols` subsection added to Protocol reference.

**`SecurityProofs-3.md`** — new §11.10.4 Suite Implementation subsection:
- Function-name table per language target (C / Go / Python / ARM / NASM / Arduino).
- Implemented proof-size table.
- Comparison of ZKP-RNL 1,056 B vs HPKS-Stern-F 78 KB vs ML-DSA-44 2,420 B.
- Note: ZKP-NL at n=256 (920 KB) awaits ZKB++ (§11.10.6 open direction 3).
- Updated §11.10.1 applicability matrix: "Prototype" → "Implemented v1.9.x".
- Updated §11.10.5 comparison table: implementation status notes.
- Renumbered: old §11.10.4 Comparison → §11.10.5; old §11.10.5 Open → §11.10.6.

**Files changed:**
- `docs/TUTORIAL.md` — new ZKP Protocols section; ZKP entry in Protocol reference; Contents entry 4 added (5→6→7 renumber)
- `SecurityProofs-3.md` — §11.10.4 new; §11.10.4→§11.10.5; §11.10.5→§11.10.6; applicability matrix + comparison table updated
- `TODO.md` — Batch 9 marked DONE v1.9.13; Status updated
- `README.md` — version bumped to v1.9.13

---

## [1.9.12] - 2026-06-06

### Feature — ZKP CLI test suite Batch 8: CliTest ZKP-RNL + ZKP-NL shell tests (TODO #77, Batch 8)

Adds five CliTest shell scripts covering ZKP-RNL and ZKP-NL sign/verify through all three CLI implementations, with cross-language interop verification.  Also fixes Python CLI output consistency (`"Proof OK"` → `"Signature OK"` for `rnl-sigma` and `nl-zkboo` verify to match C and Go output).

**New scripts:**
- `CliTest/test_zkp_rnl.sh` — Python CLI `genpkey hkex-rnl` → `sign rnl-sigma` → `verify rnl-sigma`; correct-msg PASS, wrong-msg reject, wrong-pubkey reject.
- `CliTest/test_zkp_nl.sh` — Python CLI `genpkey hpks-zkp-nl` → `sign nl-zkboo --rounds 4` → `verify nl-zkboo`; correct PASS, wrong-msg reject, wrong-pubkey reject.
- `CliTest/test_c_zkp_rnl.sh` — C CLI same ZKP-RNL round-trip.
- `CliTest/test_go_zkp_rnl.sh` — Go CLI same ZKP-RNL round-trip.
- `CliTest/test_zkp_interop.sh` — Full 6-direction cross-language interop for ZKP-RNL (Python↔C↔Go) and ZKP-NL (Python↔C↔Go); `--rounds 4` for speed.

**Python CLI fix:** `cmd_verify` for `rnl-sigma` and `nl-zkboo` now prints `"Signature OK"` on success (was `"Proof OK"`), consistent with C and Go.

**Files changed:**
- `CliTest/test_zkp_rnl.sh` — new
- `CliTest/test_zkp_nl.sh` — new
- `CliTest/test_c_zkp_rnl.sh` — new
- `CliTest/test_go_zkp_rnl.sh` — new
- `CliTest/test_zkp_interop.sh` — new
- `HerraduraCli/herradura.py` — "Proof OK" → "Signature OK" for ZKP verify
- `TODO.md` — Batch 8 marked DONE v1.9.12
- `README.md` — version bumped to v1.9.12

---

## [1.9.11] - 2026-06-06

### Feature — ZKP test suite Batch 7: CryptosuiteTests ZKP-RNL + ZKP-NL security tests + benchmarks (TODO #77, Batch 7)

Adds ZKP correctness and tamper-rejection security tests plus throughput benchmarks to all three compiled test targets.  Tests call the production library functions (not self-contained stubs).

**`CryptosuiteTests/Herradura_tests.c`** — v1.9.11:
- `[21] ZKP-RNL` — `rnl_sigma_sign` + `rnl_sigma_verify` completeness + wrong-message tamper at n∈{32,256}.
- `[22] ZKP-NL` — `zkp_nl_prove` + `zkp_nl_verify` completeness + commitment-flip tamper at n∈{32,64}, R=16 rounds.
- `[33] bench_zkp_rnl` — sign+verify throughput at n=256.
- `[34] bench_zkp_nl` — prove+verify throughput at n=32, R=16.
- Benchmarks renumbered [21]–[30] → [23]–[32].

**`CryptosuiteTests/Herradura_tests.go`** — v1.9.11:
- `[20] testZkpRnlCorrectness` + `[21] testZkpNlCorrectness`; `[32] benchZkpRnl` + `[33] benchZkpNl`.
- Benchmarks renumbered [20]–[29] → [22]–[31].

**`CryptosuiteTests/Herradura_tests.py`** — v1.9.11:
- `[20] test_zkp_rnl_correctness` + `[21] test_zkp_nl_correctness`; `[32]`/`[33]` benchmarks.
- Benchmarks renumbered [20]–[29] → [22]–[31].

**Files changed:**
- `CryptosuiteTests/Herradura_tests.c` — new tests [21][22], benches [33][34], renumbered [23]–[32]
- `CryptosuiteTests/Herradura_tests.go` — new tests [20][21], benches [32][33], renumbered [22]–[31]
- `CryptosuiteTests/Herradura_tests.py` — new tests [20][21], benches [32][33], renumbered [22]–[31]
- `TODO.md` — Batch 7 marked DONE v1.9.11
- `README.md` — version bumped to v1.9.11

---

## [1.9.10] - 2026-06-05

### Feature — ZKP library Batch 6: Arduino ZKP-RNL + ZKBoo demo (TODO #77, Batch 6)

Adds ZKP-RNL Ring-LWR Σ-protocol and minimal ZKBoo MPC-in-the-head demo to the Arduino suite (`Herradura cryptographic suite.ino`, v1.9.10).  All allocation is via `static long` / `static uint8_t` arrays — no heap, no `malloc`.  Targets Arduino Mega (8 KB SRAM).

**New `#define` constants** — `SIGMA_GAMMA=4096`, `SIGMA_T=4`, `SIGMA_BOUND=4092`, `SIGMA_SLACK=32`, `SIGMA_RANGE=8193`; `ZKP_NL_N=8`, `ZKP_NL_R=4`.

**New ZKP-RNL functions (module-scope statics):**
- `sig_y`, `sig_w`, `sig_c`, `sig_z` — shared prover/verifier poly scratch (32 `long` each).
- `sig_tmp0`–`sig_tmp4` — additional poly scratch shared between sign and verify.
- `sigma_challenge(m, C_pub, w, msg)` — derives `SIGMA_T`-sparse ternary challenge into `sig_c` via chained `hfscx_32` seed expansion.
- `rnl_sigma_sign(m, s, C_pub, msg) → int` — rejection-sampling prover; up to 200 attempts; fills `sig_w`, `sig_c`, `sig_z`.
- `rnl_sigma_verify(m, C_pub, msg) → int` — three-step verifier: (1) ‖z‖∞ ≤ SIGMA_BOUND; (2) challenge consistency; (3) ‖m·z − c·lift(C) − w‖∞ ≤ SIGMA_SLACK.

**New ZKBoo functions:**
- `zkp_nl_f1_8(A, B)` — scalar F1(A,B) at 8 bits: FSCX_8(A,B) XOR ROL8((A+B) mod 256, 2).
- `zkp_eval(s0,s1,s2, t0,t1,t2, B, o0,o1,o2, gva,gvb,gvc)` — 3-party ripple-carry evaluation of F1 at 8 bits; gate views encoded as `ai|(ci<<1)|(ao<<2)`.
- `zkp_nl_prove_8(A, B, y, msg)` — Fiat-Shamir prover; stores proof in module-level statics `zkp_coms`, `zkp_e`, `zkp_sh1/2`, `zkp_tp1/2`, `zkp_out1/2`, `zkp_gv1/2`.
- `zkp_nl_verify_8(B, y, msg) → int` — recomputes Fiat-Shamir challenges; checks commitments and AND-gate consistency for revealed parties p1=(e+1)%3, p2=(e+2)%3.

**`loop()` changes:** HKEX-RNL key arrays (`m_blind`, `s_A`, `C_A`, etc.) lifted to `loop()`-scope statics for reuse by the ZKP-RNL demo. Two new demo blocks added before `delay(10000)`.

---

## [1.9.9] - 2026-06-05

### Feature — ZKP library Batch 5: NASM i386 `rnl_sigma_sign_32` / `rnl_sigma_verify_32` (TODO #77, Batch 5)

Adds ZKP-RNL Ring-LWR Σ-protocol sign and verify to the NASM i386 assembly suite (`Herradura cryptographic suite.asm`, v1.9.9). Reuses existing `rnl_poly_mul` (NTT-based), `hfscx_32` (DM-hash), and `rnl_lift` subroutines.

**New `%define` constants** — `SIGMA_GAMMA=4096`, `SIGMA_T=4`, `SIGMA_BOUND=4092`, `SIGMA_SLACK=32`, `SIGMA_RANGE=8193`.

**New `.bss` arrays** — `sig_y`, `sig_w`, `sig_c`, `sig_z` (128 B each), `sig_pos` (16 B for t=4 positions), `sigma_yq_tmp`, `sigma_liftc_tmp`, `sigma_mz_tmp`, `sigma_cw_tmp` (128 B each).

**New functions:**
- `sigma_fold_poly_32(eax=seed, ebx=poly_ptr) → eax=seed` — folds 32 coefficients into seed via hfscx_32; ESI/ECX preserved across hfscx_32 calls.
- `sigma_challenge_32(eax=m_ptr, ebx=C_ptr, ecx=w_ptr, edx=msg)` — local stack frame; derives sparse ternary challenge into `sig_c` via chained hfscx_32 seed expansion (t=4 nonzero positions, ±1 signs).
- `rnl_sigma_sign_32(eax=msg) → eax=0 ok / eax=-1 fail` — rejection-sampling prover with local stack frame; up to 200 attempts; fills `sig_w`, `sig_c`, `sig_z`; uses globals `rnl_s_A`, `rnl_m_blind`, `rnl_C_A` from HKEX-RNL.
- `rnl_sigma_verify_32(eax=msg) → eax=1 ok / eax=0 fail` — three-step verifier with local stack frame: (1) ‖z‖∞ ≤ SIGMA_BOUND=4092; (2) recomputed challenge matches stored; (3) ‖m·z − c·lift(C) − w‖∞ ≤ SIGMA_SLACK=32; saves/restores EBP around `rnl_lift` call.

**Demo block added to `_start`** — prints header, calls `rnl_sigma_sign_32(0xDEADB00B)` then `rnl_sigma_verify_32`, reports pass/fail before exit.

---

## [1.9.8] - 2026-06-05

### Feature — ZKP library Batch 4: ARM Thumb-2 `rnl_sigma_sign_32` / `rnl_sigma_verify_32` (TODO #77, Batch 4)

Adds ZKP-RNL Ring-LWR Σ-protocol sign and verify to the ARM Thumb-2 assembly suite (`Herradura cryptographic suite.s`, v1.9.8). Reuses existing `rnl_poly_mul` (NTT-based) and `hfscx_32` (DM-hash) subroutines.

**New `.equ` constants** — `SIGMA_GAMMA`, `SIGMA_T`, `SIGMA_BOUND`, `SIGMA_SLACK`, `SIGMA_RANGE` (n=32 parameters).

**New `.bss` arrays** — `sig_y`, `sig_w`, `sig_c`, `sig_z` (128 B each), `sig_pos` (16 B), `sigma_yq_tmp`, `sigma_liftc_tmp`, `sigma_mz_tmp`, `sigma_cw_tmp` (128 B each).

**New functions:**
- `sigma_fold_poly_32(r0=seed, r1=poly) → r0=seed` — chains 32 coefficients into seed via hfscx_32.
- `sigma_challenge_32(r0=m, r1=C, r2=w, r3=msg)` — derives sparse ternary challenge into `sig_c` using chained hfscx_32 seed, t=4 positions, sign bits.
- `rnl_sigma_sign_32(r0=msg) → r0=0 ok / 0xFFFFFFFF=fail` — rejection-sampling prover; fills `sig_w`, `sig_c`, `sig_z`; uses globals `rnl_s_A`, `rnl_m_blind`, `rnl_C_A` from HKEX-RNL.
- `rnl_sigma_verify_32(r0=msg) → r0=1 ok / r0=0 fail` — three-step verifier: (1) ‖z‖∞ ≤ SIGMA_BOUND; (2) recomputed c′ = stored c; (3) ‖m·z − c·lift(C) − w‖∞ ≤ SIGMA_SLACK.

**Demo block added to `main()`** — prints header, message scalar, calls sign then verify, reports pass/fail.

---

## [1.9.7] - 2026-06-05

### Feature — ZKP library Batch 3: Go package + Go CLI (TODO #77, Batch 3)

Adds ZKP-RNL (Ring-LWR Σ-protocol) and ZKP-NL (NL-FSCX ZKBoo) to the `herradurakex/herradura` Go package and extends `herradura_cli_go` with `sign`/`verify` subcommands for both proofs.

**New exported functions in `herradura/herradura.go`:**
- `ZkpRnlParams(n)` — returns (gamma, t) for ZKP-RNL at bit-width n.
- `RnlSigmaSign(s, m, C, n, msg)` — ZKP-RNL prover with rejection sampling; returns (w, c, z, err).
- `RnlSigmaVerify(m, C, n, msg, w, c, z)` — three-check ZKP-RNL verifier (‖z‖∞, FS challenge, rounding slack).
- `ZkpNlKeygen(n)` — generates (A, B, y=nl_fscx_v1(A,B), err) as uint32.
- `ZkpNlProve(A, B, y, n, rounds, msg)` — MPC-in-the-head ZKBoo prover; returns []ZkpNlRound.
- `ZkpNlVerify(B, y, n, rounds, msg, proof)` — verifies ZKBoo proof; re-evaluates p1 AND gates.
- `ZkpNlRound` struct — per-round ZKBoo proof with Com0/Com1/Com2 [32]byte, E int, ViewP1/ViewP2 []byte.

**New PEM label constants in `herradura/codec.go`:**
- `PemZkpRnlProof`, `PemZkpNlPriv`, `PemZkpNlPub`, `PemZkpNlProof`.

**Extensions to `HerraduraCli/herradura_cli.go`:**
- `genpkey --algo hpks-zkp-nl` — generates ZKP-NL keypair (raw binary PEM).
- `pkey --in zkpnl.pem (--pubout | --text)` — extracts public key or prints fields for ZKP-NL keys.
- `sign --algo rnl-sigma --key rnl.pem --in msg` — ZKP-RNL Σ-protocol signature.
- `sign --algo nl-zkboo --key zkpnl.pem --in msg` — ZKBoo proof (demo rounds=4).
- `verify --algo rnl-sigma --pubkey rnl_pub.pem --sig proof.pem` — verify ZKP-RNL proof.
- `verify --algo nl-zkboo --pubkey zkpnl_pub.pem --sig proof.pem` — verify ZKBoo proof.

**Demo blocks added to `Herradura cryptographic suite.go`:**
- ZKP-RNL proof at n=32; ZKP-NL proof at n=8, R=4.

---

## [1.9.6] - 2026-06-05

### Feature — ZKP library Batch 2: C header-only library + C CLI (TODO #77, Batch 2)

Adds the Ring-LWR Σ-protocol (ZKP-RNL) and NL-FSCX ZKBoo (ZKP-NL) as static inline functions in `herradura.h` and as `sign`/`verify` subcommands in `herradura_cli.c`.  Python↔C bidirectional PEM interoperability verified.

**New static functions in `herradura.h`:**
- `sigma_params(n, &gamma, &t)` — ZKP-RNL parameter selector (γ, t) by polynomial dimension.
- `sigma_poly_mul_n(h, f, g, n, q)` — O(n²) negacyclic multiplication for n ≠ RNL_N=256 (used for small-n demo; NTT path used for n=256).
- `sigma_poly_bytes(out, poly, n)` — serialize n coefficients as n×4 big-endian bytes (matches Python `_sigma_poly_bytes`).
- `sigma_challenge(m, Cp, w, n, q, t, msg, mlen, c_out)` — Fiat-Shamir sparse-ternary challenge derivation; uses `hfscx_256` with seed||"pos" / seed||"sgn" counter expansion.
- `rnl_sigma_sign(s, m, Cp, n, msg, mlen, urnd, w_out, c_out, z_out)` — ZKP-RNL prover with rejection sampling; returns 0 or -1.
- `rnl_sigma_verify(m, Cp, n, msg, mlen, w, c, z)` — three-check verifier (‖z‖∞ bound, FS challenge, rounding slack); returns 1/0.
- `ZkpNlRound` struct — per-round ZKBoo proof: three 32-byte commitments, hidden-party index, and two heap-allocated party views.
- `zkp_nl_proof_free(proof, rounds)` — free heap memory in a ZkpNlRound array.
- `zkp_nl_rol(x, r, n)` — n-bit cyclic left-rotate.
- `zkp_nl_commit(out, j, p, tape, out_share, nb)` — HFSCX-256 commitment: hash(j(4B)||p(1B)||tape(32B)||out_share(nb B)).
- `zkp_nl_prg_bit(tape, gate_id)` — deterministic PRG bit from tape and gate index.
- `zkp_nl_eval_3p(...)` — 3-party ZKBoo evaluation of nl_fscx_v1(A,B); carries the AND-gate chain; fills output shares and per-party gate-view bytes.
- `zkp_nl_pack_view` / `zkp_nl_unpack_view` — view buffer serialize/deserialize.
- `zkp_nl_f1(A, B, n)` — scalar evaluation of nl_fscx_v1 for keygen.
- `zkp_nl_keygen(n, urnd, A_out, B_out, y_out)` — ZKBoo keypair generation.
- `zkp_nl_prove(A, B, y, n, rounds, msg, mlen, urnd)` — heap-allocated ZkpNlRound proof array; fully Fiat-Shamir compiled.
- `zkp_nl_verify(B, y, n, rounds, msg, mlen, proof)` — commitment check + AND-gate re-evaluation.
- Constants: `SIGMA_MAX_ATTEMPTS` (1000), `ZKP_NL_DEFAULT_N` (8), `ZKP_NL_DEMO_ROUNDS` (4), `ZKP_NL_PROD_ROUNDS` (219), `ZKP_NL_MAX_N` (32).

**New PEM label macros in `HerraduraCli/herradura_codec.h`:**
- `PEM_ZKP_RNL_PROOF`, `PEM_ZKP_NL_PRIV`, `PEM_ZKP_NL_PUB`, `PEM_ZKP_NL_PROOF`.

**Extended `HerraduraCli/herradura_cli.c`:**
- Helper `zkp_raw_pem_read` — reads raw-binary (non-DER) PEM; label check before `pem_key_load`.
- Helper `zkp_pem_peek_label` — reads label without allocating DER parse result.
- Helpers `zkp_nl_pack_proof` / `zkp_nl_unpack_proof` — serialize/deserialize ZkpNlRound arrays matching Python `encode_zkp_nl_proof` / `decode_zkp_nl_proof`.
- `genpkey --algo hpks-zkp-nl` — writes `HERRADURA ZKP-NL PRIVATE KEY` PEM (raw binary: 4B n | nb A | nb B | nb y).
- `pkey --in zkpnl.pem --pubout` — detects `ZKP-NL PRIVATE KEY` label via peek; writes `HERRADURA ZKP-NL PUBLIC KEY`.
- `sign --algo rnl-sigma --key hkex-rnl.pem` — derives C_p from privkey, calls `rnl_sigma_sign`, writes `HERRADURA ZKP-RNL PROOF` PEM.
- `sign --algo nl-zkboo --key zkpnl.pem` — early-exit before `pem_key_load`; calls `zkp_nl_prove` at `ZKP_NL_PROD_ROUNDS=219`.
- `verify --algo rnl-sigma --pubkey hkex-rnl-pub.pem` — calls `rnl_sigma_verify`.
- `verify --algo nl-zkboo --pubkey zkpnl-pub.pem` — early-exit; calls `zkp_nl_verify`.

**Extended `Herradura cryptographic suite.c` `main()`:**
- ZKP-RNL demo block (n=256 keypair; sign + verify).
- ZKP-NL demo block (n=8, R=ZKP_NL_DEMO_ROUNDS=4; keygen, prove, verify, free).

---

## [1.9.5] - 2026-06-05

### Feature — ZKP library Batch 1: Python suite + codec + CLI (TODO #77, Batch 1)

Implements the Ring-LWR Σ-protocol (HPKS-ZKP-RNL) and NL-FSCX ZKBoo (HPKS-ZKP-NL) as first-class library functions, DER/PEM wire format, and OpenSSL-style CLI subcommands.  Derived from the reference prototype in `SecurityProofsCode/zkp_pqc_exploration.py`.

**New library functions in `Herradura cryptographic suite.py`:**
- `rnl_sigma_sign(s_poly, m_poly, C_poly, n, msg_bytes)` → `(w, c, z)` — Lyubashevsky rejection-sampling prover; Fiat-Shamir message binding via `hfscx_256`.
- `rnl_sigma_verify(m_poly, C_poly, n, msg_bytes, w, c, z)` → `bool` — three-check verifier (‖z‖∞, FS challenge, rounding slack).
- `zkp_nl_keygen(n)` → `(A, B, y)` — ZKBoo keypair where `y = nl_fscx_v1(A, B)`.
- `zkp_nl_prove(A, B, y, n, rounds, msg_bytes)` → proof list — 3-party MPC-in-the-head with per-party tapes, AND-gate carry chain, Fiat-Shamir challenge.
- `zkp_nl_verify(B, y, n, rounds, msg_bytes, proof_rounds)` → `bool` — commitment check + AND-gate consistency re-evaluation.
- Helper constants: `_SIGMA_GAMMA`, `_SIGMA_T`, `_SIGMA_MAX_ATTEMPTS`, `_ZKP_NL_DEFAULT_N` (8), `_ZKP_NL_DEMO_ROUNDS` (4), `_ZKP_NL_PROD_ROUNDS` (219).

**New codec functions in `HerraduraCli/codec.py`:**
- `encode_zkp_rnl_proof` / `decode_zkp_rnl_proof` — PEM label `HERRADURA ZKP-RNL PROOF`; raw binary: 4B n + n×4B w (s32-be) + n×4B c (u32-be) + n×4B z (s32-be).
- `encode_zkp_nl_privkey` / `decode_zkp_nl_privkey` — PEM label `HERRADURA ZKP-NL PRIVATE KEY`; stores (A, B, y, n) so `pkey --pubout` works without re-evaluation.
- `encode_zkp_nl_pubkey` / `decode_zkp_nl_pubkey` — PEM label `HERRADURA ZKP-NL PUBLIC KEY`.
- `encode_zkp_nl_proof` / `decode_zkp_nl_proof` — PEM label `HERRADURA ZKP-NL PROOF`; round-length-prefixed views.

**New CLI in `HerraduraCli/herradura.py` and `primitives.py`:**
- `genpkey --algo hpks-zkp-nl [--bits N]` — generates ZKP-NL keypair.
- `pkey --in priv.pem --pubout` — extracts ZKP-NL public key.
- `sign --algo rnl-sigma --key hkex-rnl.pem --in msg.bin --out proof.pem` — Ring-LWR Σ-proof.
- `sign --algo nl-zkboo --key zkpnl.pem --in msg.bin --out proof.pem [--rounds R]` — NL-FSCX ZKBoo proof (default R=219).
- `verify --algo rnl-sigma --pubkey hkex-rnl-pub.pem --in msg.bin --sig proof.pem`.
- `verify --algo nl-zkboo --pubkey zkpnl-pub.pem --in msg.bin --sig proof.pem`.

**Files changed:**
- `Herradura cryptographic suite.py` — new ZKP constants and 8 new functions; updated public API docstring and suite demo.
- `HerraduraCli/codec.py` — 8 new encode/decode functions + self-test additions.
- `HerraduraCli/primitives.py` — new re-exports for ZKP functions and constants.
- `HerraduraCli/herradura.py` — `hpks-zkp-nl` key type, `rnl-sigma`/`nl-zkboo` sign/verify subcommands, updated `build_parser`.
- `TODO.md` — TODO #77 Batch 1 marked done.
- `README.md` — version bumped to v1.9.5.

---

## [1.9.4-p1] - 2026-06-05

### Research — New application directions catalogue (TODO #78)

Ten candidate applications of the Herradura primitives catalogued in `TODO.md` with construction sketches, implementation distances, and open questions: FPE (78.A), tweakable block cipher (78.B), NL-FSCX ratchet (78.C), PQC PAKE (78.D), non-Abelian KEx (78.E), VDF limited model (78.F), OPRF (78.G), masking-friendly implementation (78.H), ring/group signature (78.I), and HFSCX-256 accumulator (78.J). Recommended first implementations: 78.B (tweakable cipher), 78.A (FPE), 78.J (accumulator).

**Files changed:**
- `TODO.md` — TODO #78 added with 10 sub-items and summary table
- `.claude/settings.json` — `bgIsolation: none` so background sessions edit devtest directly

---

## [1.9.4] - 2026-06-04

### Research — Zero-knowledge proof exploration for PQC algorithms (TODO #76)

Surveys and prototypes ZKP constructions for the two PQC hardness pillars not yet covered by ZKP infrastructure (B1: Ring-LWR; A: NL-FSCX OWF/PRF).  The third pillar (B2: syndrome decoding) is already implemented via HPKS-Stern-F (v1.5.18).

**New script:** `SecurityProofsCode/zkp_pqc_exploration.py` — five sections:
- §1 Applicability matrix across B2 (Stern), B1 (Ring-LWR), A (NL-FSCX).
- §2 Ring-LWR Σ-protocol (Lyubashevsky-style, Fiat-Shamir): commit/challenge/respond/verify with rejection sampling.  Completeness 0/1000 failures; soundness 0/200 cheat passes (n=32).  Proof size: 132 B (n=32) / 1 056 B (n=256) — smaller than ML-DSA-44 (2 420 B).
- §3 NL-FSCX ZKBoo: 3-party Boolean circuit for F1 (n=8 toy, 7 AND gates per step).  ZKBoo AND gate via XOR shares and per-party random coins.  Completeness 0/1000; soundness ≈ (1/3)^R coincidental FS passes (expected).  Proof sizes: 35 KB (n=8) / 920 KB (n=256, R=219 for 128-bit soundness).
- §4 Parameter comparison vs ML-DSA, SLH-DSA, Picnic, HPKS-Stern-F.
- §5 Open construction paths: NTT Σ-protocol, ZKB++, hybrid Ring-LWR + Stern-F credential.

**New documentation:** `SecurityProofs-3.md` — §11.10 Zero-Knowledge Proof Extensions (split from SecurityProofs-2.md to stay under GitHub KaTeX expression limit; 121 math expressions).  SecurityProofs.md index updated to Part 3.

**Files changed:**
- `SecurityProofsCode/zkp_pqc_exploration.py` — new script
- `SecurityProofs-3.md` — new Part 3 document
- `SecurityProofs.md` — index updated (two→three parts)
- `TODO.md` — TODO #76 marked DONE v1.9.4
- `README.md` — version bumped to v1.9.4
- `CLAUDE.md` — SecurityProofs-3.md added to repository structure

---

## [1.9.3] - 2026-06-04

### Research — Rotational differential analysis of NL-FSCX v1 (TODO #75)

Characterises the rotational open concern from TODO #74 by distinguishing one-sided from two-sided rotation.

**Key findings:**
- **One-sided rotation** (B fixed — all PRF uses: Stern-F, HSKE-NL-A1, HFSCX-256-DM): p ≈ 0 across all (r, k, B) tested (upper bound < 2^{-17}). PRF security is unaffected.
- **Two-sided rotation** (WOTS hash chain): power-law decay p(r) ≈ C(k)·r^{-alpha(k)}, not geometric. At r=64 (n=256): p(k=1) ≈ 0.78%, requiring ~90 query pairs for a 50%-advantage random-oracle distinguisher (q = ln2/p).
- Theorem 16 (HPKS-WOTS-F EUF-CMA) uses OWF only, not ROM — the RO-distinguisher does NOT break Theorem 16.

**New script:** `SecurityProofsCode/nl_fscx_rot_analysis.py` — five sections: single-round probability (§1), one-sided vs. two-sided comparison (§2), multi-round power-law decay (§3), extrapolation to n=256 (§4), protocol impact analysis (§5).

**Documentation:** SecurityProofs-2.md §11.8.3 extended with "Rotational structure (TODO #75)" subsection and updated "open concerns" paragraph.

**Files changed:**
- `SecurityProofsCode/nl_fscx_rot_analysis.py` — new analysis script
- `SecurityProofs-2.md` — §11.8.3 extended
- `TODO.md` — TODO #75 marked DONE v1.9.3
- `README.md` — version bumped to v1.9.3

---

## [1.9.2] - 2026-06-04

### Research — NL-FSCX v1 OWF cryptanalysis (TODO #74)

Completed the dedicated cryptanalysis of NL-FSCX v1 as a one-way function, fulfilling TODO #74 scope items 1–2 and 4.

**New script:** `SecurityProofsCode/nl_fscx_owf_analysis.py` — five classical analyses of $F_1^{n/4}(\cdot, B)$:
1. **Differential** — DDT at n=8 (exhaustive) and n=32 (sampled); key finding: MDP is B-dependent (generic B: ~0.10 at r=8; sparse-bit B: ~0.77 — degenerate trails).
2. **Linear bias** — Walsh spectrum at n=8 and sampled at n=32; max bias at n=32 (0.070) is within the Bernstein random-function bound (0.087) — PASS.
3. **Rotational cryptanalysis** — rotational-equivariance rates of **1–6%** at n=32, r=8 for all k ∈ {1,2,4,7,8,16}, far above the 2^{-32} random expectation.  Structural correlation inherited from the FSCX linear base; integer-carry NL term only partially breaks it.  Not a direct preimage attack (at most n-factor speedup), but an open design concern.
4. **B=0 degeneracy** — confirmed GF(2)-linear and singular (rank 2/8 for L_2 at n=8); negligible in all protocol uses (Pr[B=0] = 2^{-n}).
5. **MITM preimage** — 28.1% image coverage at n=20, average preimage count 3.52; MITM provides no asymptotic speedup (O(2^n) = brute force).

**Documentation:** SecurityProofs-2.md §11.8.3 extended with "Cryptanalytic evidence (TODO #74, v1.9.2)" subsection containing all empirical results, the rotational-structure open concern, and updated open gaps list.

**Files changed:**
- `SecurityProofsCode/nl_fscx_owf_analysis.py` — new analysis script
- `SecurityProofs-2.md` — §11.8.3 extended
- `TODO.md` — TODO #74 marked DONE v1.9.2 (formal reduction remains open gap)
- `README.md` — version bumped to v1.9.2

---

## [1.9.1] - 2026-06-04

### Security — Per-slot domain-separation tags for Assembly/Arduino Stern-F (TODO #73)

Added an explicit `ds` (domain-separation) parameter to `stern_hash1_32` and `stern_hash2_32` in all five 32-bit targets, closing the gap between the toy-demo and the full 256-bit QRO argument.

**Change:** `ds` is XOR'd into the first item before the initial `nl_fscx_revolve_v1` call:

```c
// Before (structural distinctness only)
stern_hash1_32(v):       nl(v, ROL(v,4), 8)
stern_hash2_32(a, b):    nl(nl(a, ROL(a,4), 8) ^ b, ROL(b,4), 8)

// After (explicit DS tag)
stern_hash1_32(ds, v):   nl(ds^v, ROL(v,4), 8)
stern_hash2_32(ds,a,b):  nl(nl(ds^a, ROL(a,4), 8) ^ b, ROL(b,4), 8)
```

Call-site DS values: c0=1, c1=2, c2=3, KEM key (encap+decap)=4.  Challenge hash uses ds=0 implicitly (the existing `stern_fs_challenges_32` accumulator is unchanged).

**Files changed:**
- `Herradura cryptographic suite.ino` — function signatures, all call sites
- `Herradura cryptographic suite.s` (ARM) — function bodies (r0=ds, r1=v / r0=ds, r1=a, r2=b), all call sites
- `CryptosuiteTests/Herradura_tests.s` (ARM tests) — identical
- `Herradura cryptographic suite.asm` (i386) — function bodies (EAX=ds, EBX=v / EAX=ds, EBX=a, ECX=b), all call sites
- `CryptosuiteTests/Herradura_tests.asm` (i386 tests) — identical
- `TODO.md` — TODO #73 marked DONE v1.9.1
- `README.md` — version bumped to v1.9.1

**Testing:** i386 tests [11] HPKS-Stern-F sign+verify and [12] HPKE-Stern-F encap+decap both PASS under qemu-i386.

---

## [1.9.0] - 2026-06-04

### Security — Davies-Meyer feed-forward for HFSCX-256-DM (TODO #72) ⚠ WIRE-FORMAT BREAKING

**Summary:** The HFSCX-256 compression function is upgraded to the Davies-Meyer variant.  The construction is renamed HFSCX-256-DM.  All pre-v1.9.0 HFSCX-256 digests, pre-hashed signatures, and AEAD tags are **incompatible** with v1.9.0.

**Change:** Every compression step now feeds the pre-compression state back in:

```
C_DM(s, m) = F_1^{64}(s, m) ⊕ s          (was: C(s, m) = F_1^{64}(s, m))
```

**Security gains** (see §11.9.8):
- **Fixed-point hardness:** A fixed point now requires $F_1^{64}(s, m) = 0$ — a preimage of zero under A2, requiring $\Omega(2^{128})$ work. Previously only an empirical (non-provable) absence was known.
- **Free-start collision hardness:** The DM structure rules out a structural speed-up from the non-bijectivity of $F_1$; free-start collisions are as hard as regular collisions under A1.
- **PGV-1 alignment:** $C_{\text{DM}}$ is one of the 12 provably-secure PGV compression functions [BRS 2002, PGV 1993].

**Files changed across all six language targets:**

- `herradura.h` — `hfscx_256` compression loop: `BitArray prev = state` before each block, `ba_xor(&state, &state, &prev)` after.
- `herradura/herradura.go` — `Hfscx256` compression loop: `prev := state.Copy()`, XOR back with `new(big.Int).Xor(&state.Val, &prev.Val)`.
- `Herradura cryptographic suite.py` — `hfscx_256` loop: `prev = state`, `state = BitArray(n, state.uint ^ prev.uint)`.
- `CryptosuiteTests/Herradura_tests.py` — self-contained copy of `hfscx_256` updated identically.
- `Herradura cryptographic suite.ino` — `hfscx_32`: `prev = 0xA3C5E7B9UL; s = nl(prev,x,8)^prev; return nl(s,LB,8)^s`.
- `Herradura cryptographic suite.s` (ARM) — `hfscx_32` extended to push `{r4, r5, lr}`, uses `r5` as prev register, adds two `eor` instructions.
- `CryptosuiteTests/Herradura_tests.s` (ARM tests) — identical `hfscx_32` update.
- `Herradura cryptographic suite.asm` (i386) — `hfscx_32` pushes/pops `edi`, uses it as prev, adds two `xor` instructions.
- `CryptosuiteTests/Herradura_tests.asm` (i386 tests) — identical `hfscx_32` update.

**KAV vectors updated** (C test [19], Go test [17], Python test [19]):
- Empty `""` : `e7082e7f038a6e32e480b5f1d969ea2c19565d327defb0f8500f6fac8fe246cc`
- `"a"` (0x61): `73b2d91bbdf0fc000de7cd16ac45d7f3f41be5609524dbeba30605a89d138ec5`
- `"abc"` : `394e2176329b94f4f6704730a01083bec51a49584bbb54abf05e5fa19cd05bb2`
- 33 × `"a"`: `49aee3b6126e44beff589d8288da6ec3f92f1f763368dfb85fb6b9664bc30adb`

**SecurityProofsCode/hfscx_256_analysis.py §7** updated: fixed-point search now tests $F_1^{64}(s,m) = 0$ rather than $F_1^{64}(s,m) = s$.

**SecurityProofs-2.md §11.9** updated throughout: construction name, §11.9.1 compression-function definition, §11.9.8 rewritten from "future work" to "DONE", §11.9.11 open hardenings list updated.

**Files changed:** `herradura.h`, `herradura/herradura.go`, `Herradura cryptographic suite.{py,ino,s,asm}`, `CryptosuiteTests/Herradura_tests.{py,s,asm}`, `CryptosuiteTests/Herradura_tests.{c,go}`, `SecurityProofsCode/hfscx_256_analysis.py`, `SecurityProofs-1.md`, `SecurityProofs-2.md`, `TODO.md`, `CHANGELOG.md`, `README.md`.

---

## [1.8.10] - 2026-06-03

### Documentation — Security proof corrections from landscape review (TODO #71)

**SecurityProofs-1.md corrections:**

- **§9.2.4 FFS complexity fix:** Corrected `L[1/2]` → `L[1/3]` for the Function Field Sieve attack on binary extension field DLP.  Added distinction between FFS (practical, L[1/3], demonstrated for all field sizes including GF(2^256)) and the Granger–Kleinjung–Zumbrägel quasi-polynomial algorithm (asymptotic, only demonstrated for highly composite extension degrees such as GF(2^6120) and GF(2^9234)).
- **§9.2.4 parameter table fix:** Corrected the security estimate for n=256 from "~128 bits" to "~80–90 bits (FFS L[1/3])".  Added note that binary-field DLP is deprecated by NIST SP 800-57 Rev. 5 (2020) and ENISA "Algorithms, Key Sizes and Parameters" (2022).  Added n=1024 row for reference.  Added "2026 landscape update" explanatory paragraph.
- **§10.8.4 Shor's table fix:** Updated the classical attacks row to split FFS (practical, ~80–90 bits at n=256) from quasi-polynomial (asymptotic, composite-degree fields only).
- **Prose fix:** Replaced LaTeX escaping `Zumbr{\"a}gel` with correct UTF-8 `Zumbrägel` in two locations.

**SecurityProofs-2.md additions and corrections:**

- **§11.4.3:** Added concrete security estimate paragraph for HKEX-RNL: ~105–115 classical Core-SVP bits, ~95–105 quantum Core-SVP bits (MATZOV Report 2022; Albrecht et al. LWE estimator 2023).  Documents that q=65537 has no known subfield attack (512 ∤ q−1), and that CBD(η=1) is secure at n=256 with less margin than η=2.
- **§11.6:** Added security estimate note cross-referencing §11.4.3.
- **§11.7 table updates:**
  - HKEX-GF classical attack column: FFS L[1/3] ~80–90 bits at n=256 (deprecated NIST/ENISA); GKZ quasi-poly asymptotic note.
  - HKEX-RNL post-quantum security: replaced "Conjectured — pending proof" with concrete BKZ estimates (~105 classical / ~100 quantum bits; §11.4.3).
  - HPKS-Stern-F and HPKE-Stern-F: replaced asymptotic ISD formula `2^{0.054N}` with concrete SDE estimates (~56–60 bits classical, ~30–40 bits quantum at N=256); marked as **demo only** with 128-bit threshold (N ≥ 17,000).
  - Added explanatory note below the table on data sources and BIKE-128 reference parameters.
- **§11.8.4:** Added "Deployed parameter caveat" paragraph: N=256, t=16 provides ~56–60 bits classical / ~30–40 bits quantum per the SDE estimator; BIKE-128 uses N≈24,646 for 128-bit classical security.

**TODO.md:** TODO #71 marked DONE with a findings summary table covering all six research areas.

---

## [1.8.9] - 2026-05-26

### Feature — HFSCX-256 KDF for `kex` and hash demo in suite programs (TODO #68)

**`--kdf hfscx-256` flag added to `kex` subcommand** (all three CLIs: C `herradura_cli.c`, Go `herradura_cli.go`, Python `herradura.py`).

When `--kdf hfscx-256` is specified, the raw shared secret is post-hashed through HFSCX-256 before being written to the SESSION KEY PEM.  This applies to both HKEX-GF (the raw $g^{ab}$ field element) and HKEX-RNL (the Ring-LWR reconciliation value, after the LSB→MSB reversal that converts it to canonical big-endian form).  The KDF produces a uniformly distributed 256-bit key and removes the algebraic structure present in raw GF($2^n$) DH values.

Both parties must supply `--kdf hfscx-256` to derive the same final key.

**HFSCX-256 demo block added to all three suite `main()` programs** (`Herradura cryptographic suite.c`, `.go`, `.py`).

A new protocol block inserted after the HPKE-Stern-F demonstration (before the Eve bypass tests) shows the hash primitive in action:

- Bare digest of `"HFSCX-256 test vector"` — deterministic cross-language value `fd84942b119b4cd7b7697e27db7c611b14b192f5fd67fd1ce4c76a3b0abf3d3d`.
- Keyed digest using `preshared XOR _HFSCX256_IV` as the MAC key.
- Confirmation that the two digests differ and that the output is 32 bytes.

**Side fixes (pre-existing bugs corrected as part of this work):**

- **Python hint encoding bug (`HerraduraCli/herradura.py`):** `_encode_rnl_response` packed the 2-bit Peikert hint coefficients at 1-bit offsets (`hint_int |= b << i`, `hint_nb = (len(hint)+7)//8`), causing `OverflowError` when any hint value was 2 or 3 at the last coefficient position, and producing an inconsistent round-trip (decoder read only 1 bit/coeff).  Fixed to 2 bits per coefficient: `(b & 3) << (2 * i)`, `hint_nb = (2 * len(hint) + 7) // 8`, decoder `(hint_int >> (2 * i)) & 3`.  This also resolved the pre-existing HKEX-RNL cross-party test failure in `CliTest/test_encrypt.sh`.
- **Missing re-export in `HerraduraCli/primitives.py`:** `_RNL_KDF_DC_256` was imported by `herradura.py` but never re-exported from `primitives.py`; added `_RNL_KDF_DC_256 = _s._RNL_KDF_DC_256`.

All 79 CLI tests pass (7 suites, 0 FAIL) after these changes.

**Files changed:** `Herradura cryptographic suite.c`, `Herradura cryptographic suite.go`, `Herradura cryptographic suite.py`, `HerraduraCli/herradura_cli.c`, `HerraduraCli/herradura_cli.go`, `HerraduraCli/herradura.py`, `HerraduraCli/primitives.py`, `TODO.md`, `CHANGELOG.md`, `README.md`.

---

## [1.8.8] - 2026-05-24

### Fix — Remove deprecated `ATOMIC_VAR_INIT` (C23 compatibility, Armbian/GCC 13+)

**`herradura.h:705`** — replaced `static _Atomic int rnl_tw_state = ATOMIC_VAR_INIT(0);`
with `static _Atomic int rnl_tw_state = 0;`.  `ATOMIC_VAR_INIT` was deprecated in C17
and removed in C23; GCC 13+ (as shipped on Armbian / Orange Pi 5b) rejects it with
"implicit declaration" and "initializer element is not constant".  Direct initialization
of `_Atomic` variables is valid since C11 and is the correct form.

**Files changed:** `herradura.h`, `CHANGELOG.md`.

---

## [1.8.7] - 2026-05-23

### Testing — Complete 32-bit benchmark columns; add N=128 HPKS-Stern-F in C (TODO #61 extension)

Extended all three benchmark suites and the README performance tables to full
32/64/128/256-bit coverage, and added a new N=128 HPKS-Stern-F implementation in C.

**Python (`CryptosuiteTests/Herradura_tests.py`)**

- Expanded `SIZES` from `[64, 128, 256]` to `[32, 64, 128, 256]`.  All benchmark
  functions using `SIZES` (FSCX, HSKE, NL-FSCX v1/v2, HSKE-NL-A1, HSKE-NL-A2)
  now emit 32-bit rows.
- Refactored `bench_hpks_stern_f` from a hardcoded `size=32` single-N run to a loop
  over `SIZES` with `rounds=4`, adding measured values at N=64 (15.6 ops/sec),
  N=128 (6.11 ops/sec), and N=256 (1.82 ops/sec).

**Go (`CryptosuiteTests/Herradura_tests.go`)**

- Expanded `var sizes` from `[]int{64, 128, 256}` to `[]int{32, 64, 128, 256}`.
  All benchmark functions using `sizes` now emit 32-bit rows.
- Refactored `benchHpksSternF` from hardcoded N=256 to a loop over `sizes` with
  `sdfTestRounds=4`, emitting N=32 (21.8), N=64 (16.5), N=128 (8.28), N=256
  (3.28 ops/sec).

**C (`CryptosuiteTests/Herradura_tests.c`)**

- Added 32-bit measurement blocks to `bench_fscx_throughput`, `bench_hske_roundtrip`,
  `bench_nl_fscx_revolve` (v1 and v2), `bench_hske_nl_a1_roundtrip`, and
  `bench_hske_nl_a2_roundtrip` using existing `fscx32`/`nl_fscx_revolve_v*_32`
  functions.
- Expanded `bench_hpks_stern_f` from N=256-only to N=32/64/256.

**N=128 HPKS-Stern-F in C (new implementation)**

Full Stern protocol at N=128 using `__uint128_t`:

- Parameters: N=128, T=8 (N/16), rows=64, rounds=8.  Type `SternSig128T`.
- `stern_hash_128`: NL-FSCX v1 revolve (NL\_I128=32 steps) with ROL-16 key
  derivation and HFSCX-256 finalizer — same design pattern as N=64.
- `stern_syndrome_128`: returns `uint64_t` (64 parity-check rows).
- `stern_gen_perm_128` / `stern_apply_perm_128` over 128 elements.
- `hpks_stern_f_sign_128` / `hpks_stern_f_verify_128`.
- Correctness test [17] extended to N=32/64/128/256 (all PASS).
- Benchmark [30] result: **467 ops/sec** (RK3588 Cortex-A76 @ 2.4 GHz, `-t 1.5`).

**README.md**

All `—` cells in the C performance table filled.  Stern-F row now covers N=32
(198 K ops/sec), N=64 (504 ops/sec), N=128 (467 ops/sec), N=256 (52.9 ops/sec).
Introductory note updated to remove stale "fixed sizes" qualifier.

**Files changed:** `CryptosuiteTests/Herradura_tests.py`, `CryptosuiteTests/Herradura_tests.go`,
`CryptosuiteTests/Herradura_tests.c`, `README.md`, `CHANGELOG.md`.

---

## [1.8.6] - 2026-05-23

### Documentation — KaTeX rendering fix in SecurityProofs-2.md §11.8.2 + Rule 11 (TODO #60)

**SecurityProofs-2.md line 406 — Theorem 13 proof paragraph**

`\mathrm{ROL}_{n/4}` created a `}_{` both-flanking `_` opener.  The `c_{j-1}`
shorthand introduced in the previous fix (TODO #59) acted as a right-flanking
closer: a plain letter (`c`) before `_` satisfies the CommonMark right-flanking
condition even when `_` is followed by `{`.  CommonMark paired opener and closer
across all math spans between them, breaking the entire paragraph.

Fixed by converting to function notation: `\mathrm{ROL}((A+B) \bmod 2^n, n/4)`.
The `}_{` opener disappears; the remaining `_` characters have no valid pairing
partner.

**CLAUDE.md — added Rule 11**

Documents the inline `\command{...}_{braced}` + `letter_{...}` pairing mechanism:
- `\command{...}_{braced}` — both-flanking (opener and closer)
- `letter_{braced}` (e.g. `c_{j-1}`) — right-flanking closer only
- `letter_letter` (e.g. `a_j`) — both-flanking

Fix: convert `\command{...}_{braced}` subscripts to function notation to remove
the `}_{` opener.  Added Rule 11 and a row in the correct-patterns table.

**Files changed:** `SecurityProofs-2.md`, `CLAUDE.md`, `TODO.md`, `CHANGELOG.md`.

---

## [1.8.5] - 2026-05-23

### Documentation — KaTeX rendering fixes in SecurityProofs-2.md (TODO #59)

Fixed two math rendering failures in `SecurityProofs-2.md`; all other sections untouched.

**Line 458 — `\operatorname` blocked (Rule 10)**

`\operatorname{invert}` inside a `$$...$$` display block is rejected by GitHub's
KaTeX macro allowlist.  Replaced with `\text{invert}`.

**Line 460 — `^*` emphasis breakage (Rule 4)**

A single proof sentence contained 5 bare `^*` patterns (`d_i^*` ×4 and
`\sigma_i^*` ×1).  CommonMark paired the `*` characters across `$...$`
boundaries, breaking every math span in the sentence.  Replaced all 5 with
`^{\ast}`.

A full scan of SecurityProofs-2.md confirmed no further Rule 4, Rule 6, or
Rule 10 violations outside table cells.

**Files changed:** `SecurityProofs-2.md`, `TODO.md`, `CHANGELOG.md`.

---

## [1.8.4] - 2026-05-23

### Documentation — KaTeX rendering fixes in SecurityProofs-1.md (TODO #57, #58)

Fixed math rendering failures in three sections of `SecurityProofs-1.md` caused by
KaTeX pipeline rule violations.  All other sections were unaffected and untouched.

**§10.6.2 HPKS — Classical Forgery Resistance (TODO #57)**

The forgery-resistance paragraph and bullet list contained 14 bare `^*` patterns
(`R^*`, `s^*`, `e^*`, `P^*`, `C^{-e^*}`).  CommonMark's emphasis parser paired the
`*` characters across `$...$` boundaries, breaking every math span in the block.
Replaced all 14 occurrences with `^{\ast}` (Rule 4).

**§10.6.1 HSKE — rank formula**

`rank$(\Phi) = 64$` placed `$` directly after a non-space character, preventing
GitHub from recognising the opening math delimiter.  Fixed to `$\text{rank}(\Phi) = 64$`
(Rule 6).  An intermediate attempt using `\operatorname` was rejected by GitHub's KaTeX
macro allowlist; `\text{}` is the correct substitute.

**§9.2.4 Security assumption (TODO #58)**

Two paragraphs contained multiple `^*` occurrences that caused the same emphasis-pairing
breakage:
- Line 730: three `$\mathbb{GF}(2^n)^*$` in one sentence.
- Lines 739–744: `$\mathbb{GF}(2^n)^*$` (×3) and `$\mathbb{Z}_p^*$` (×1).

Replaced all 7 occurrences with `^{\ast}` (Rule 4).

**CLAUDE.md — added Rule 10**

Documented that `\operatorname` is blocked by GitHub's KaTeX macro allowlist
("The following macros are not allowed: operatorname").  Use `\text{name}` instead.
Added Rule 10 and a corresponding row in the correct-patterns table.

**Files changed:** `SecurityProofs-1.md`, `CLAUDE.md`, `TODO.md`, `CHANGELOG.md`.

---

## [1.8.3] - 2026-05-22

### Documentation — Cryptographic concepts primer for general IT/security audience (TODO #56)

Added `docs/INTRODUCTION.md`: a 12-part, ~1 000-line plain-language guide covering
every core concept used in the suite, written for readers with a general IT/security
background but no formal cryptography training.

**Contents:**

| Part | Topic |
|---|---|
| 0 | Reading guide — four reader profiles, cross-reference notation |
| 1 | Bits, XOR, ROL/ROR — toy 8-bit examples, Shannon diffusion/confusion |
| 2 | Finite fields — GF(2), GF(2^n) polynomial arithmetic, discrete logarithm |
| 3 | Key exchange — DH paint analogy, integer DH, HKEX-GF 8-bit walkthrough, forward secrecy |
| 4 | FSCX and HSKE — bit-flow example, orbit period, encrypt/decrypt round-trip |
| 5 | Non-linearity — why linearity is exploitable, NL-FSCX v1/v2, quantum connection |
| 6 | Digital signatures — Schnorr commit-challenge-respond, Fiat-Shamir, HPKS |
| 7 | El Gamal encryption — hybrid encryption, HPKE walkthrough |
| 8 | Quantum threats — Shor/Grover in plain English, harvest-now-decrypt-later |
| 9 | Ring-LWR — lattices, LWE, HKEX-RNL full handshake, Peikert reconciliation |
| 10 | Code-based PQC — syndrome decoding, Niederreiter KEM, Stern ZKP, HPKS-Stern-F |
| 11 | Suite at a glance — 11-protocol reference table, decision tree, proof scope |
| 12 | Glossary — 25 terms, 2–4 sentences each |

Every section includes at least one verifiable reference (DOI, arXiv ID, or NIST
permalink) and cross-links to SecurityProofs-1.md/SecurityProofs-2.md and TUTORIAL.md.

**Also fixed in this release:**

- `docs/TUTORIAL.md`: added "Background reading" pointer to INTRODUCTION.md.
- `README.md`: corrected stale version number (was v1.5.40, now v1.8.3); fixed four
  `SecurityProofs.md` references to the correct split files (SecurityProofs-1.md
  §3/§6, SecurityProofs-2.md §11/§11.8.4); repaired six KaTeX rule violations
  (`\textunderscore` → hyphen in `\text{}`, `\!` removed from display block,
  `^*` → `^{\ast}` for the `GF(2^n)*` group); updated repository structure listing
  to include `herradura.h`, `HerraduraCli/`, `docs/`, and the split SecurityProofs
  files; added v1.7.4 and v1.8.3 version callout notes.

**Files changed:** `docs/INTRODUCTION.md` (new), `docs/TUTORIAL.md`, `README.md`,
`CHANGELOG.md`, `TODO.md`.

---

## [1.8.2] - 2026-05-21

### Performance — precompute H matrix in Stern sign/verify (TODO #52)

`stern_syndrome` / `SternSyndrome` rebuilt all `SDF_N_ROWS` (128) rows of the
parity-check matrix from seed on every call.  In `hpks_stern_f_sign` (32 rounds) and
`hpks_stern_f_verify` (up to 32 rounds) this meant 33+ full matrix constructions per
sign+verify cycle; at production parameters (≥219 rounds) the overhead is ~440 builds.
Each build costs 128 × `I_VALUE` (= 64) NL-FSCX v1 steps, so sign+verify was burning
~33 × 128 × 64 = **270 k PRF evaluations** on matrix generation alone.

**Fix:** Added `stern_build_H` (C, `herradura.h`) and `SternBuildH` (Go) that
precompute the full H matrix once; added `stern_syndrome_H` (C) and `sternSyndromeH`
(Go) that compute `H·e^T` from the prebuilt rows.  `hpks_stern_f_sign` and
`hpks_stern_f_verify` in both C and Go now build H once at entry and reuse it for all
per-round syndrome evaluations (32× → 1× matrix build per sign or verify call).
`stern_syndrome` / `SternSyndrome` are retained as one-off wrappers (keygen, encap).
Python already used this pattern via `_stern_build_H` / `_stern_syndrome_H`.

**Files changed:** `herradura.h`, `herradura/herradura.go`.

---

## [1.8.1] - 2026-05-21

### Security — `stern_gen_perm` PRNG bias eliminated (TODO #45)

`stern_gen_perm` / `SternGenPerm` / `_stern_gen_perm` previously extracted only the
bottom 16 bits of each NL-FSCX v1 state block and reduced modulo `(N-i)` without
rejection sampling, wasting 240 bits of entropy and introducing modular bias proportional
to `65536 mod (N-i)`.  A biased permutation leaks structural information about the secret
error vector `e` across Stern rounds.

**Fix:** Full 32-bit counter-mode extraction — all `KEYBYTES` of each NL-FSCX v1 state
block are consumed as sequential big-endian 32-bit words before the state is advanced
(no entropy wasted).  Rejection sampling uses `threshold = 2^32 − 2^32 mod range` kept
as `uint64` to prevent truncation to 0 when `range` divides `2^32` (which would cause an
infinite loop).

**Files changed:**
- `herradura.h` — `stern_gen_perm` rewritten
- `herradura/herradura.go` — `SternGenPerm` rewritten
- `Herradura cryptographic suite.py` — `_stern_gen_perm` rewritten
- `TODO.md` #45 — marked DONE

---

## [1.8.0] - 2026-05-21

### Security — KDF domain constant prevents rotation-periodic key degeneracy (TODO #38)

**Breaking wire change** (incompatible with v1.7.x derived keys).

The v1.5.10 `seed = ROL(K, n/8)` fix for step-1 FSCX degeneracy itself degenerates
when `K` has a rotational period dividing `n/8`.  XORing a nothing-up-my-sleeve constant
after the rotation breaks all such periodic keys.

`seed = ROL(K, n/8) XOR DC`

`DC` is the SHA-256 initial hash values (H0–H7 = `6A09E667 BB67AE85 3C6EF372 A54FF53A
510E527F 9B05688C 1F83D9AB 5BE0CD19`; 32-bit targets use H0 = `0x6A09E667`).

**Files changed:** `herradura.h` (`ba_rnl_kdf_seed`), `herradura/herradura.go` (`RnlKdfSeed`),
`Herradura cryptographic suite.py` (`_RNL_KDF_DC_256`), ARM Thumb-2 (`RNL_KDF_DC` equ),
NASM i386 (`%define RNL_KDF_DC`), Arduino (`#define RNL_KDF_DC`), all test/CLI files.

### Security — Stern-F Fiat-Shamir challenge consistency across languages (TODO #48)

C `stern_fs_challenges` and Go `sternFsChallenges` used raw NL-FSCX v1 output as the
challenge seed; Python `_stern_hash` applied the full HFSCX-256 finalizer.  The two
derivations produced different challenge sequences for identical inputs, making Stern
signatures generated in Python unverifiable in C/Go and vice versa.

**Fix:** HFSCX-256 finalizer added after the NL-FSCX v1 chaining loop in C and Go,
matching Python exactly.  C and Go sign+verify round-trips confirmed passing.

**Files changed:** `herradura.h` (`stern_fs_challenges`), `herradura/herradura.go`
(`sternFsChallenges`).

### Security — Stern-F soundness warning for demo parameters (TODO #46)

`SDF_ROUNDS = 32` gives only ~51-bit soundness (2^{−32} per round × challenge space 3),
far below the 128-bit target requiring ≥219 rounds.  Added:
- `SDF_PRODUCTION_ROUNDS 219` compile-time constant + `#pragma message` warning when
  `SDF_ROUNDS < SDF_PRODUCTION_ROUNDS` in `herradura.h`
- `SdfProductionRounds = 219` constant + `log.Printf` guard in `HpksSternFSign` (Go)

### Concurrency — Go `rnlTwCache` data race (TODO #49)

`rnlTwCache` was a plain `map[int]*rnlTwEntry` with no synchronization; concurrent
goroutines could race on map read/write.  Replaced with `sync.Map`; `rnlTwGet` updated
to use `Load` / `LoadOrStore`, matching the existing `mInvCache` pattern.

**Files changed:** `herradura/herradura.go`.

### Concurrency — C `rnl_twiddle_init` TOCTOU race (TODO #50)

`rnl_twiddle_init` used a plain `int ready` flag with no atomics.  Fixed by moving the
body to `rnl_twiddle_do_init` and wrapping in `pthread_once` on POSIX builds; falls back
to a CAS-based `_Atomic int` spin-once on non-POSIX builds.

**Files changed:** `herradura.h` (`rnl_twiddle_init`, `rnl_twiddle_do_init`).

### Safety — C `hfscx_256` unchecked `malloc` (TODO #51)

`hfscx_256` called `memcpy` into the `malloc` return value without a NULL check, causing
undefined behavior on allocation failure.  Added `if (!padded) { fprintf+exit(1); }`.

**Files changed:** `herradura.h`.

### Portability — Go `rnlMulModQ` 32-bit `int` overflow (TODO #53)

`a * b` with `a, b` as `int` silently overflows on 32-bit platforms (GOARCH=386/arm)
since 65536² = 4 294 836 225 > MaxInt32.  Changed local variables to `int64(a) * int64(b)`.

**Files changed:** `herradura/herradura.go`.

### Performance/Safety — C `hpks_stern_f_sign` VLA stack overflow risk (TODO #54)

Five `BitArray` arrays of size `SDF_ROUNDS` (5 × 219 × 32 = 34 KB at production rounds)
were stack-allocated.  Moved all five (`r`, `y`, `pi`, `sr`, `sy`) plus `Hr` to heap
via `malloc`; NULL checks with `exit(1)` added; all freed at function return.

**Files changed:** `herradura.h`.

### Documentation — Comment typo in `ba_rnl_kdf_seed` (TODO #55)

"ROL by KEYBYTES bytes" corrected to "ROL left by n/8 bits (KEYBYTES byte positions)".

**Files changed:** `herradura.h`.

---

## [1.7.4] - 2026-05-21

### Security — CSPRNG and timing-attack audit SA-01..SA-09

Full security audit of all six language targets.  Nine findings resolved:

| ID | Severity | Finding | Fix |
|---|---|---|---|
| SA-01 | Critical | Fixed LCG seed (`0xDEADBEEE`) in ARM Thumb-2 and NASM i386 — entire key/nonce sequence deterministic across runs | Replaced `prng_next` with `/dev/urandom` reads (`getrandom` syscall on NASM) |
| SA-02 | High | `gf_pow_ba` (C): variable-time square-and-multiply leaks private key bit-length and bit pattern via loop count and branch | Made constant-time |
| SA-03 | High | `gf_mul_ba` (C): `if (bb.b[KEYBYTES-1] & 1)` branches on secret bit | Made constant-time |
| SA-04 | High | `ba_mul_mod_ord` (C): `if (!ai) continue` skips multiply loop on zero bytes of Schnorr scalar | Made constant-time |
| SA-05 | High | `GfPow`/`GfMul` (Go): same variable-time pattern as SA-02/03 | Made constant-time |
| SA-06 | High | `gf_pow`/`gf_mul` (Python): `while exp:` early-exit + `if exp & 1:` branch on each key bit | Made constant-time |
| SA-07 | Medium | `random.sample()` (Mersenne Twister) used in Python test file for Stern-F private key and nonce | Replaced with `_csprng_weight_t()` / `os.urandom` |
| SA-08 | Low | `ba_equal` uses `memcmp` (early-exit) for commitment hash comparison in `hpks_stern_f_verify` | Replaced with constant-time comparison |
| SA-09 | Low | Stack private keys in C `main()` not zeroed via `explicit_bzero` | Added `explicit_bzero` on exit |

### Documentation — Developer tutorial and library API (TODO #44)

- **`herradura.h`:** Protocol Layer section — eight `static inline` wrappers
  (`hkex_gf_pubkey`, `hkex_gf_agree`, `hske_encrypt`, `hske_decrypt`,
  `hpks_sign`, `hpks_verify`, `hpke_encrypt`, `hpke_decrypt`)
- **`Herradura cryptographic suite.py`:** public aliases `hkex_rnl_keygen` /
  `hkex_rnl_agree` and "Library usage" docstring section added
- **`docs/TUTORIAL.md`:** comprehensive integration guide — getting started, per-protocol
  code recipes, parameter reference table, security notes
- **`docs/examples/`:** three minimal runnable programs (C, Go, Python) each demonstrating
  HKEX-GF, HSKE, HKEX-RNL, and HPKS-Stern-F in ~80 LOC

### Build — i386 ASM portability fix (build_asm_i386.sh)

`x86_64-linux-gnu-ld -m elf_i386` fails on ARM64 hosts (Raspberry Pi 5, Ubuntu) with
"unrecognized emulation mode: elf_i386".  `build_asm_i386.sh` now probes each linker
candidate (`x86_64-linux-gnu-ld`, `i686-linux-gnu-ld`, system `ld`) for actual `elf_i386`
emulation support before using it.  Emits a clear install hint if none is found.

**Files changed:** `build_asm_i386.sh`, `CLAUDE.md`.

---

## [1.7.3] - 2026-05-20

### Performance — NumPy NTT acceleration for HKEX-RNL (TODO #40)

Gates a vectorised NTT path behind `try: import numpy` in both
`Herradura cryptographic suite.py` and `CryptosuiteTests/Herradura_tests.py`.
When NumPy is present, `_rnl_poly_mul` uses the new path; otherwise falls back
to the existing pure-Python `_ntt_inplace` unchanged.

**Implementation:**
- `_ntt_tables(q, n)` — builds and caches (keyed by `(q, n)`) the bit-reversal
  permutation (`int32`), per-stage forward and inverse twiddle arrays (`int64`),
  scalar inverse `n`, and the negacyclic pre/post-twist power vectors.  Cache is
  populated on first call and reused on every subsequent call at the same parameters.
- `_ntt_np(arr, q, invert)` — applies the permutation via `arr[:] = arr[rev]`
  (safe: fancy indexing returns a copy), then iterates butterfly stages using
  `arr.reshape(n//length, length)` views and vectorised `int64` arithmetic.
- `_rnl_poly_mul` dispatch — converts `f`, `g` to `int64` arrays, applies the
  cached twist, calls `_ntt_np` three times (forward × 2, inverse × 1), applies
  inverse twist, and returns a plain Python list.  Pure-Python path unchanged.

**Files changed:**
- `Herradura cryptographic suite.py` — numpy try-block after imports; `_rnl_poly_mul` dispatch
- `CryptosuiteTests/Herradura_tests.py` — same
- `TODO.md` #40 — marked DONE

Wire format: unchanged.  Expected speedup when NumPy is installed: ~10× on
`_rnl_poly_mul` at n=256 (dominant cost in HKEX-RNL).

---

## [1.7.0] - 2026-05-20

### Feature — 2-bit Peikert reconciliation for HKEX-RNL (TODO #39)

Upgraded HKEX-RNL from 1-bit to 2-bit Peikert cross-rounding, doubling key density
(2 bits extracted per ring coefficient, pp=4 instead of pp=2).  At n=256 this halves
the polynomial size needed for a 256-bit output key.

**Correct formulas** (all six language targets):
- Hint: $h_i = \lfloor(8c_i + q/4)/q\rfloor \bmod 4$
- Extract: $b_i = \lfloor(4c_i + (2h_i+1)\lfloor q/4\rfloor)/q\rfloor \bmod 4$

The `(2h+1)` multiplier places extraction grid points at odd multiples of q/4,
ensuring correct modular wrap-around at the c≈0 and c≈q boundaries.

**Files changed:**
- `Herradura cryptographic suite.py` — `RNLPP`, `_rnl_hint`, `_rnl_reconcile_bits`
- `herradura.h` — `RNL_PP`, `rnl_hint`, `rnl_reconcile_bits`
- `herradura/herradura.go` — `RnlPP`, `RnlHint`, `RnlReconcileBits`
- `Herradura cryptographic suite.s` — `RNL_PP`, `rnl_hint32`, `rnl_reconcile32` (thresholds: 6145,14337,22529,30721,38913,47105,55297)
- `Herradura cryptographic suite.asm` — same
- `Herradura cryptographic suite.ino` — `RNL_PP`, `rnl_hint`, `rnl_reconcile`
- `CryptosuiteTests/Herradura_tests.py` — all four hint/reconcile variants
- `CryptosuiteTests/Herradura_tests.c` — all four hint/reconcile function families
- `CryptosuiteTests/Herradura_tests.s` / `.asm` — thresholds and formula
- `SecurityProofs-2.md` §11.4.2 — updated with 2-bit formulas
- `TODO.md` #39 — marked DONE

Test [14] HKEX-RNL: 20/20 agreed for n=32,64,128,256 (C, Go, ARM, NASM).

---

## [1.5.42] - 2026-05-19

### Research — Exhaustive Walsh-Hadamard spectrum added to PRF analysis (TODO #35)

`SecurityProofsCode/nl_fscx_prf_analysis.py` gains §9 (four sub-sections) that
replaces the §5 Monte-Carlo bias estimate with a rigorous exhaustive scan at small `n`:

- **§9.1 (n=8):** All 255×256 mask pairs; max\_bias=1.0 at r=2 steps (degenerate).
- **§9.2 (n=12):** All 4 095×4 096 = 16.7M mask pairs (~2 min, `EXHAUSTIVE_N12=True`).
  Result: max\_bias ≈ 0.43, ratio ≈ 4.7× the random-function bound 0.090.
  Affine baseline H\_linear: max\_bias=1.0 (correctly detected).
- **§9.3 (Range compression):** F\_stern maps only ~40–55% of inputs to distinct outputs
  at n=8/12/16 vs ~63% for a truly random function.  Identified as the primary cause
  of elevated Walsh coefficients at small n; open gap at the deployed n=32.
- **§9.4 (Extrapolation):** Bernstein bound E[max\_bias] ≈ sqrt(4n·ln2/2^n); at n=32
  this is ~1.44×10⁻⁴.

`SecurityProofs-2.md` §11.8.4 updated with an "Exhaustive Walsh analysis" paragraph
summarising the findings and identifying the range-compression open gap.
`TODO.md` #35 marked DONE with full result summary.

New helper functions: `_wht()`, `exhaustive_max_bias()`, `component_max_bias()`,
`random_fn_max_bias_bound()` (all standalone, no external dependencies).

---

## [1.5.41] - 2026-05-19

### Correctness — `rnl_lift` centered rounding across all targets (TODO #37)

`rnl_lift` / `_rnl_lift` / `RnlLift` previously rounded toward zero (`c * q / p`),
introducing a systematic positive bias of up to `q/(2p) ≈ 8` per coefficient when
lifting Ring-LWR public-key coefficients from `Z_p` to `Z_q`.  This is asymmetric
with `rnl_round`, which already uses centered rounding.

**Fix:** Switch all implementations to centered rounding:
`(c * q + p/2) / p mod q`

Applied consistently to every target in lockstep (wire-format change):

| Target | File | Change |
|---|---|---|
| Python suite | `Herradura cryptographic suite.py` | `_rnl_lift` |
| C header | `herradura.h` | `rnl_lift` |
| Go package | `herradura/herradura.go` | `RnlLift` |
| Arduino | `Herradura cryptographic suite.ino` | `rnl_lift` |
| ARM Thumb-2 | `Herradura cryptographic suite.s` | `rnl_lift` (add `r6, lsr #1` before udiv) |
| NASM i386 | `Herradura cryptographic suite.asm` | `rnl_lift` (shr+add before div) |
| ARM tests | `CryptosuiteTests/Herradura_tests.s` | same ARM change |
| i386 tests | `CryptosuiteTests/Herradura_tests.asm` | same NASM change |
| Python tests | `CryptosuiteTests/Herradura_tests.py` | `_rnl_lift` |
| C tests | `CryptosuiteTests/Herradura_tests.c` | `rnl_lift_n` |
| Analysis script | `SecurityProofsCode/hkex_rnl_failure_rate.py` | `_lift_poly` |

`hkex_rnl_failure_rate.py` re-run confirms post-reconciliation failure rate
remains 0 % at both `n=32` and `n=256`.  Pre-reconciliation rates are within
sampling noise of prior values (polynomial convolution dominates, not lift
quantization); SecurityProofs-2.md §11.5/§11.6 numbers unchanged.

---

## [1.5.40] - 2026-05-19

### Security — Constant-time audit: branchless `stern_apply_perm` across all targets (TODO #41)

All six language targets contained a data-dependent branch in `stern_apply_perm` /
`SternApplyPerm` that leaks the Hamming weight of the secret error vector `e` (used as
the HPKS-Stern-F private key and the Fiat-Shamir blinding vectors `r` and `y`).

**Root cause:** The inner loop branched on each secret bit:
```python
if (v_int >> i) & 1:           # branches on secret bit — timing leaks HW
    result |= 1 << perm[i]
```
An attacker timing multiple sign operations could recover the weight and reduce
the effective key space.

**Fix — branchless arithmetic mask:** Replace the conditional with a mask derived by
negating the extracted bit; the same instructions execute regardless of `v[i]`:

| Target | Old (branchy) | New (branchless) |
|---|---|---|
| C (`herradura.h`) | `if (v->b[byt] & ...)` | `mask = -(v_bit)` (0x00 or 0xFF) |
| Arduino (`.ino`) | `if ((v >> i) & 1)` | `mask = -(bit)` (0 or 0xFFFFFFFF) |
| Go (`herradura.go`) | `if v.Val.Bit(i) == 1 { SetBit(1) }` | `SetBit(Bit(i))` (unconditional) |
| ARM Thumb-2 (`.s`) | `tst r0,#1; beq sap_next` | `and r0,#1; neg r3,r0; and r1,r3` |
| NASM i386 (`.asm`) | `bt esi,ecx; jnc .sap_next` | `bt; sbb eax,eax; bts ebx,edx; and ebx,eax` |

**Python:** The Python reference implementation is intentionally **not** constant-time;
CPython big-integer arithmetic is inherently timing-variable at the VM level. Non-CT
documentation comments added to `_stern_apply_perm`, `_stern_syndrome_H`, and the
Stern-F section header; `SecurityProofsCode/stern_ct_demo.py` added to demonstrate and
measure the timing correlation empirically.

**Files changed:**
- `Herradura cryptographic suite.py` — non-CT documentation
- `herradura.h` — branchless `stern_apply_perm`
- `herradura/herradura.go` — branchless `SternApplyPerm`
- `Herradura cryptographic suite.s` — branchless ARM `stern_apply_perm_32`
- `Herradura cryptographic suite.asm` — branchless NASM `stern_apply_perm_32`
- `Herradura cryptographic suite.ino` — branchless Arduino `stern_apply_perm_32`
- `SecurityProofsCode/stern_ct_demo.py` — new timing demonstration script
- `TODO.md` — #41 marked DONE; #26/#28/KR-1 stale status lines corrected

---

## [1.5.23] - 2026-05-03

### New Feature — HerraduraCli: OpenSSL-style command-line tool (TODO #25)

A Python CLI in a new `HerraduraCli/` subdirectory exposing all non-broken Herradura
protocols through an interface analogous to OpenSSL's `genpkey`, `pkey`, `enc`, `dec`,
`sign`, `verify`, and `kex` subcommands. No external Python dependencies; uses only stdlib.

**File layout:**
- `HerraduraCli/herradura.py` — argparse dispatcher; all protocol subcommands
- `HerraduraCli/codec.py` — pure-Python PEM and minimal DER INTEGER/SEQUENCE codec;
  polynomial pack/unpack helpers for Ring-LWR polynomials
- `HerraduraCli/primitives.py` — loads `"Herradura cryptographic suite.py"` via
  `importlib.util` (space-in-filename workaround); re-exports all primitive symbols

**Supported subcommands:**
- `genpkey --algo <a>` — generate private key PEM for all 8 supported algorithms
- `pkey --pubout / --text` — extract public key or print key fields as hex
- `kex --algo hkex-gf/hkex-rnl --our … --their …` — HKEX-GF one-round or HKEX-RNL
  two-round key exchange; writes SESSION KEY PEM or RESPONSE PEM
- `enc / dec --algo hske/hske-nla1/hske-nla2/hpke/hpke-nl/hpke-stern` — encrypt and
  decrypt using symmetric session keys or asymmetric public/private keys
- `sign / verify --algo hpks/hpks-nl/hpks-stern` — Schnorr or Stern-F signatures;
  `verify` exits 0/1 and prints `Signature OK` / `Verification FAILED`

**HKEX-RNL 2-round protocol:** Alice publishes a fresh random `m_blind` polynomial in
her public key PEM; Bob re-derives `C_B = round_p(m_A * s_B)` on his side and writes a
RESPONSE PEM encoding `(K_B, C_B, Peikert-hint, n)`; Alice reads the response and
completes with `K_A = reconcile(s_A * C_B, hint)`. The RESPONSE PEM doubles as a session
key file (Bob's `K_B` is stored as the first field) so Bob can pass it directly to
`enc`/`dec` without a separate kex step.

**Key format summary (DER SEQUENCE):**
- Classical/NL private: `{priv_int, pub_int, nbits}` (nbits//8 bytes each)
- Classical/NL public: `{pub_int, nbits}`
- HKEX-RNL private: `{s_packed(4n bytes), m_packed(4n bytes), n}`
- HKEX-RNL public: `{C_packed(2n bytes), m_packed(4n bytes), n}`
- Stern private/public: `{e_int / syn_int, seed_uint, n}` (n//8 bytes each)

### New Feature — CliTest shell test suite (TODO #25)

Four bash scripts in `CliTest/` exercising the full CLI:
- `test_keygen.sh` — 16 cases: `genpkey` + `pkey --pubout` for all 8 algorithms; asserts
  PEM headers and non-empty output
- `test_encrypt.sh` — 7 cases: full enc/dec round-trips for hske, hske-nla1, hske-nla2
  (via HKEX-GF session key), HKEX-RNL cross-party, hpke, hpke-nl, hpke-stern
- `test_sign.sh` — 7 cases: sign/verify with correct and tampered messages for hpks,
  hpks-nl (including wrong-key rejection), and hpks-stern
- `test_vectors.sh` — 3 cases: HKEX-GF key-agreement (both parties produce identical
  SESSION KEY PEM) and HKEX-RNL bidirectional cross-party enc/dec (validates Peikert
  reconciliation)

### Maintenance — Version-banner sync

All 12 implementation files advanced from v1.5.22 (or v1.5.20 for Python suite/tests and
C tests, which had missed earlier bumps) to v1.5.23.

---

## [1.5.22] - 2026-05-01

### Fix — NASM i386 HKEX-RNL produced all-zero session keys (TODO #21)

**Root cause:** `rnl_round` in `Herradura cryptographic suite.asm` had a
triple-division bug in the `% to_p` section. After computing
`floor((in[i]*to_p + from_q/2) / from_q)` with `div ecx` (division 1),
the code should have performed one more `div ecx` to reduce the result
modulo `to_p`. Instead there were two consecutive `xor edx, edx; div ecx`
sequences: the first correctly left `edx = floor_result % to_p`, but the
spurious second `xor edx, edx` then wiped that value before a redundant
third division, causing `rnl_round` to return 0 for every coefficient.

**Impact:** C_A and C_B were both all-zeros, making K_poly all-zeros and
thus sk = 0 in every NASM i386 HKEX-RNL exchange.

**Fix:** Removed the extra `xor edx, edx; div ecx` block from the
`% to_p` section of `rnl_round` in `Herradura cryptographic suite.asm`.
The NASM tests file (`CryptosuiteTests/Herradura_tests.asm`) already had
the correct two-division form and was not affected.

### Improvement — CBD(eta=1) reads 4 coefficients per byte (TODO #16)

**Root cause:** `rnl_cbd_poly` (C), `rnlCBDPoly` (Go), `_rnl_cbd_poly` (Python)
each called the random source once per coefficient but only consumed 2 bits of
the 8-bit byte returned, discarding 75% of the entropy.

**Fix:** For eta=1, read `ceil(n/4)` bytes once and extract all n coefficients
using bit-pairs at positions (0-1), (2-3), (4-5), (6-7) within each byte.
In the C test file, the LCG-backed `rnl32_cbd_poly` and `rnl_cbd_poly_n` now
draw one `rand32()` word per 16 coefficients (bit-pairs 0-1…30-31).
The Python suite retains a general path for eta>1 while using the fast byte
packing for eta=1 (the only value used in all implementations).

### Improvement — Go test [14] HKEX-RNL extends to n=128 and n=256 (TODO #23)

`rnlSizes` in `CryptosuiteTests/Herradura_tests.go` was `{32, 64}`.
Extended to `{32, 64, 128, 256}` so test [14] and benchmark [25] cover
the same ring sizes as Python and C tests.

### Maintenance — Version-banner sync

All 12 implementation files advanced from v1.5.21 to v1.5.22.

---

## [1.5.21] - 2026-04-30

### Fix — ARM HSKE-NL-A2 used wrong step count (TODO #22)

**Root cause:** `Herradura cryptographic suite.s` called `nl_fscx_revolve_v2` and
`nl_fscx_revolve_v2_inv` with `#I_VALUE` (= n/4 = 8 steps) for HSKE-NL-A2, while
the protocol specifies `r = 3n/4 = R_VALUE = 24 steps`. NASM i386 and C were correct.
HPKE-NL was unaffected — it legitimately uses `I_VALUE` (n/4).

**Impact:** ARM and NASM i386 HSKE-NL-A2 ciphertexts were cross-incompatible; both
self-decrypted correctly (symmetric use of the wrong step count) so the bug was silent.

**Fix:** Changed both HSKE-NL-A2 call sites in `Herradura cryptographic suite.s`
(encrypt and decrypt) from `mov r2, #I_VALUE` to `mov r2, #R_VALUE`. Updated the
inline comments to match.

### Fix — Python HKEX-RNL demo banner printed q=3329 (TODO #20)

`Herradura cryptographic suite.py` line 953 printed `q=3329` (Kyber's modulus),
but `RNLQ = 65537` since v1.5.4. The same banner was fixed in C at v1.5.13 but the
Python file was missed. Changed to `q=65537`.

### Maintenance — Version-banner sync (TODO #19)

Nine files still carried `v1.5.18` in header comments and/or runtime-printed banner
strings; the project was at v1.5.20. Updated all header comments and printed banners
to v1.5.21 across:

- `Herradura cryptographic suite.go` (header comment)
- `CryptosuiteTests/Herradura_tests.go` (header changelog + printed banner)
- `CryptosuiteTests/Herradura_tests.py` (argparse description + printed banner)
- `Herradura cryptographic suite.s` / `CryptosuiteTests/Herradura_tests.s` (header + `.asciz` string)
- `Herradura cryptographic suite.asm` / `CryptosuiteTests/Herradura_tests.asm` (header + `db` string)
- `Herradura cryptographic suite.ino` / `CryptosuiteTests/Herradura_tests.ino` (header + `Serial.println`)

Historical changelog entries inside file headers (e.g. `v1.5.18: HPKS-Stern-F...`)
were left unchanged.

---

## [1.5.20] - 2026-04-30

### Performance — Fermat prime fast modulo for NTT inner loops (Batch 8 / TODO #15)

Replaces all `(uint64_t)a * b % RNL_Q` operations in the NTT hot paths with a
divisionless Fermat-prime reduction: since q = 65537 = 2^16+1, we have
2^16 ≡ −1 and 2^32 ≡ 1 (mod q), so for x = a·b: x ≡ (x & 0xFFFF) − ((x>>16) & 0xFFFF) + (x>>32) (mod q).
The result r ∈ [−65535, 65536], so at most one conditional add (`if r < 0 r += 65537`) is needed;
the `r ≥ q` branch is dead code (max r = 65536 < 65537).

#### New helpers

- C: `static inline uint32_t rnl_mulmodq(uint32_t a, uint32_t b)` — added to `Herradura cryptographic suite.c` and `CryptosuiteTests/Herradura_tests.c`
- Go: `func rnlMulModQ(a, b int) int` — added to `Herradura cryptographic suite.go` and `CryptosuiteTests/Herradura_tests.go`

#### Call sites replaced

- `rnl_ntt` / `rnl32_ntt` butterfly (3 multiplications): `* wn % q`, `* w % q`, invert-path `* inv_n % q`
- `rnl_poly_mul` / `rnl32_poly_mul` / `rnl_poly_mul_n` (4–9 multiplications): ψ-twist pre/post and pointwise product
- `rnlNTT` and `rnlPolyMul` in both Go files

#### Benchmark result (gcc -O2, `-t 3.0`, n=32)

| Benchmark | Before | After | Δ |
|-----------|--------|-------|---|
| HKEX-RNL handshake (n=32) | 65.7 K ops/sec | 77.3 K ops/sec | +17.6% |

#### Files changed

- `Herradura cryptographic suite.c` — `rnl_mulmodq` helper; `rnl_ntt` + `rnl_poly_mul` updated
- `CryptosuiteTests/Herradura_tests.c` — `rnl_mulmodq` helper; `rnl32_ntt` + `rnl32_poly_mul` + `rnl_poly_mul_n` updated
- `Herradura cryptographic suite.go` — `rnlMulModQ` helper; `rnlNTT` + `rnlPolyMul` updated
- `CryptosuiteTests/Herradura_tests.go` — `rnlMulModQ` helper; `rnlNTT` + `rnlPolyMul` updated

#### Test results (gcc -O2, `-t 3.0`)

- All 18 security tests pass [PASS]

---

### Feature — Parameterised integer arithmetic layer: bn_* (Batch 7 / TODO #18)

Adds a self-contained `bn_*` big-endian byte-array arithmetic library (Groups A–E) inside `CryptosuiteTests/Herradura_tests.c`, enabling protocol tests to run at any supported key width without per-size dispatch. Uses this to extend tests [7] (HPKS Schnorr), [8] (Schnorr Eve), and [15] (HPKS-NL) from `{32,64,128}` to `{32,64,128,256}` bits — previously blocked by the absence of a 256-bit scalar multiplication mod ord.

#### New functions (Groups A–E)

- **Group A** (bit primitives): `bn_zero`, `bn_copy`, `bn_xor_n`, `bn_equal_n`, `bn_is_zero_n`, `bn_popcount_n`, `bn_shl1_n`, `bn_shr1_n`, `bn_rol_k_n`
- **Group B** (mod 2^n): `bn_add_n`, `bn_sub_n`, `bn_mul_lo_n`, `bn_mul_full_n`
- **Group C** (mod 2^n−1): `bn_mul_mod_ord_n`, `bn_sub_mod_ord_n`, `bn_add_mod_ord_n`
- **Group D** (GF(2^n)): `gf_poly_for_n`, `bn_gf_mul_n`, `bn_gf_pow_n`
- **Group E** (FSCX + NL-FSCX): `bn_fscx_n`, `bn_fscx_revolve_n`, `bn_m_inv_n` (bootstrapped from M^{n/2−1}(e₀), lazy-cached per nbits), `bn_nl_fscx_v1_n`, `bn_nl_fscx_revolve_v1_n`, `bn_nl_delta_v2_n`, `bn_nl_fscx_v2_n`, `bn_nl_fscx_v2_inv_n`, `bn_nl_fscx_revolve_v2_n`, `bn_nl_fscx_revolve_v2_inv_n`
- **Utilities**: `bn_rand_n`, `bn_set_gen`

#### Tests extended to 256-bit

| Test | Old sizes | New sizes |
|------|-----------|-----------|
| [7] HPKS Schnorr correctness | {32,64,128} | {32,64,128,256} |
| [8] HPKS Schnorr Eve resistance | {32,64,128} | {32,64,128,256} |
| [15] HPKS-NL correctness | {32,64,128} | {32,64,128,256} |

#### Files changed

- `CryptosuiteTests/Herradura_tests.c` — `bn_*` section inserted; tests [7],[8],[15] rewritten using `bn_*`

#### Test results (gcc -O2, `-r 10 -t 5.0`)

- [7] 10/10 verified at all four sizes [PASS]
- [8] 0/10 Eve wins at all four sizes [PASS]
- [15] 10/10 verified at all four sizes [PASS]
- All other tests unchanged [PASS]

---

### Feature — Multi-size key-length standardization: C suite HPKE-Stern-F N=32 demo (Batch 6)

Adds N=32 brute-force HPKE-Stern-F demo to `Herradura cryptographic suite.c`, completing parity with the Python suite. New helpers: `s32_fscx`, `s32_nl_revolve`, `stern32_matrix_row`, `stern32_syndrome`, `stern32_hash`, `stern32_rand_error`, `hpke_stern_f_encap_32`, `hpke_stern_f_decap_32`. The demo now prints two blocks: N=32 brute-force (C(32,2)=496 candidates) then N=256 known-e'. Both success messages updated to specify size and path.

#### Files changed

- `Herradura cryptographic suite.c` — N=32 Stern-F helpers + N=32 demo block; N=256 success message updated
- `README.md` — v1.5.20 note updated

#### Test results

- N=32 brute-force: `K (encap) == K (decap)` [PASS]
- N=256 known-e': `K (encap) == K (decap)` [PASS]

---

### Feature — Multi-size key-length standardization: C tests Stern-F N=32/64 (Batch 5)

Expands Stern-F tests [17] and [18] to cover N=32 and N=64 parameter sets alongside the existing N=256. Adds N=32 HPKS-Stern-F sign/verify helpers (`stern32_gen_perm`, `stern32_apply_perm`, `stern32_hash_n`, `stern_fs_challenges_32`, `SternSig32T`, `hpks_stern_f_sign_32`, `hpks_stern_f_verify_32`) and a full N=64 Stern-F layer (`stern_hash_64`, `stern_matrix_row_64`, `stern_syndrome_64`, `stern_rand_error_64`, `stern64_rand_seed`, `stern_gen_perm_64`, `stern_apply_perm_64`, `stern_hash_64_n`, `stern_fs_challenges_64`, `SternSig64T`, `hpks_stern_f_sign_64`, `hpks_stern_f_verify_64`, `hpke_stern_f_encap_64`, `hpke_stern_f_decap_known_64`). Raises `SDF_TEST_ROUNDS` from 4 to 8 for all sizes.

#### Parameter sets

| N  | n_rows | t  | synbytes | rounds |
|----|--------|----|----------|--------|
| 32 | 16     | 2  | 2        | 8      |
| 64 | 32     | 4  | 4        | 8      |
| 256| 128    | 16 | 16       | 8      |

- Test [17]: loop `{32, 64, 256}` — HPKS-Stern-F sign+verify at each parameter set
- Test [18]: N=32 brute-force C(32,2)=496 + N=64 known-e' fast path (direct key derivation from e')

#### Files changed

- `CryptosuiteTests/Herradura_tests.c` — N=32 HPKS helpers, N=64 full Stern-F layer, tests [17] and [18] expanded; `SDF_TEST_ROUNDS` 4→8

#### Test results (gcc -O2, `-t 3.0`)

- [17] HPKS-Stern-F: 5/5 verified at N=32/64/256, rounds=8 [PASS]
- [18] HPKE-Stern-F: 20/20 decapsulated at N=32 (brute-force), 20/20 at N=64 (known-e') [PASS]

---

### Feature — Multi-size key-length standardization: C tests HKEX-RNL n=128/256 (Batch 4)

Expands HKEX-RNL to ring sizes n=128 and n=256 in C test [14]. The NTT twiddle table is extended from `n∈{32,64}` to `n∈{32,64,128,256}` (`psi_pow[256]`, `stage_w_fwd[8]`). Adds `rnl_hint_128`/`rnl_reconcile_128`/`rnl_agree_128` using `__uint128_t` keys, and `rnl_hint_ba`/`rnl_reconcile_ba`/`rnl_agree_ba` using `BitArray` keys with bit-packed hint representation.

#### Files changed

- `CryptosuiteTests/Herradura_tests.c` — NTT table + 4 new RNL helper functions; test [14] expanded to `{32,64,128,256}`

#### Test results (gcc -O2, `-t 3.0`)

- [14] HKEX-RNL: 200/200 raw agree + 200/200 sk agree at n=32/64/128/256 [PASS]

---

### Feature — Multi-size key-length standardization: C tests GF(2^128) (Batch 3)

Adds GF(2^128) arithmetic and expands C tests [1],[5]–[9],[15],[16] to include 128-bit (and 256-bit where scalar arithmetic is not required). Implements `gf_mul_128`, `gf_pow_128`, `mul128_mod_ord128`, and `s_op128` as `__uint128_t` helpers.

#### Expansion summary

- Tests [1],[5],[6]: `{32,64,256}` → `{32,64,128,256}` (HKEX-GF correctness, key sensitivity, Eve resistance)
- Tests [7],[8],[15]: `{32,64}` → `{32,64,128}` (HPKS Schnorr and HPKS-NL; 256-bit skipped — scalar `a·e mod 2^256−1` would require 512-bit intermediates)
- Tests [9],[16]: `{32,64}` → `{32,64,128,256}` (HPKE El Gamal and HPKE-NL; no scalar arithmetic needed)

#### Files changed

- `CryptosuiteTests/Herradura_tests.c` — `gf_mul_128`, `gf_pow_128`, `mul128_mod_ord128`, `s_op128`; tests [1],[5]–[9],[15],[16] expanded

#### Test results (gcc -O2, `-t 2.0`)

- [1] HKEX-GF correctness: 100/100 at 32/64/128 bits; 80/80 at 256 bits [PASS]
- [5] Key sensitivity: mean HD ≥ n/4 at 32/64/128/256 bits [PASS]
- [6] Eve resistance: 0 successes at 32/64/128/256 bits [PASS]
- [7] HPKS Schnorr: 100/100 verified at 32/64/128 bits [PASS]
- [8] HPKS Schnorr Eve: 0/100 wins at 32/64/128 bits [PASS]
- [9] HPKE El Gamal: 100/100 decrypted at 32/64/128/256 bits [PASS]
- [15] HPKS-NL: 100/100 verified at 32/64/128 bits [PASS]
- [16] HPKE-NL: 100/100 decrypted at 32/64/128/256 bits [PASS]

---

### Feature — Multi-size key-length standardization: C tests NL-FSCX 256-bit (Batch 2)

Adds 256-bit (BitArray) support to C tests [10]–[13] for all NL-FSCX v1/v2 protocols. Implements `ba_sub256`, `ba_mul256`, `m_inv_ba`, `nl_fscx_v2_ba`, `nl_fscx_v2_inv_ba`, `nl_fscx_revolve_v2_ba`, and `nl_fscx_revolve_v2_inv_ba` as BitArray helpers. The `M^{-1}` polynomial table for n=256 was derived by GCD computation: `(1+x+x^255)^{-1}` in `GF(2)[x]/(x^256+1)` yields the four-word table `{0xb6db6db6db6db6db, 0xdb6db6db6db6db6d, 0x6db6db6db6db6db6, 0xb6db6db6db6db6db}`.

#### Files changed

- `CryptosuiteTests/Herradura_tests.c` — new BitArray v2 helpers; tests [10]–[13] expanded to `{64,128,256}`; `NL_I256=64`, `NL_R256=192` macros added

#### Test results (gcc -O2, `-r 20 -t 10.0`)

- [10] NL-FSCX v1 non-linearity: 20/20 violations + no-period at 64/128/256 bits [PASS]
- [11] NL-FSCX v2 bijectivity: 0 collisions, 20/20 inv, 20/20 nonlinear at 64/128/256 bits [PASS]
- [12] HSKE-NL-A1 counter-mode: 20/20 at 64/128/256 bits [PASS]
- [13] HSKE-NL-A2 revolve-mode: 20/20 at 64/128/256 bits [PASS]

---

### Feature — Multi-size key-length standardization: Python tests and suite (Batch 1)

Expands protocol coverage to all four standard key sizes (32, 64, 128, 256 bits) in the Python test suite and adds an N=256 HPKE-Stern-F demo to the Python suite.

#### Test coverage changes (`CryptosuiteTests/Herradura_tests.py`)

- `GF_SIZES` expanded from `[32, 64]` to `[32, 64, 128, 256]` — affects tests [7]–[9] (HKEX-GF, HPKS, HPKE) and tests [15]–[16] (HPKS-NL, HPKE-NL) and benchmarks
- `RNL_SIZES` expanded from `[32, 64]` to `[32, 64, 128, 256]` — affects test [14] (HKEX-RNL) and benchmark
- Test [17] `SDF_SIZES` expanded from `[32, 64]` to `[32, 64, 128, 256]` — HPKS-Stern-F sign/verify at all four sizes
- Test [18] adds known-e' decap path for N=32,64,128,256 alongside the existing N=32 brute-force path; new helpers `hpke_stern_f_encap_with_e` and `hpke_stern_f_decap_known` added

#### Suite changes (`Herradura cryptographic suite.py`)

- Added N=256 known-e' HPKE-Stern-F demo after the existing N=32 brute-force demo
- `hpke_stern_f_decap` now supports two paths: known-e' (`e_int != 0`) and brute-force (`e_int = 0`)
- `hpke_stern_f_encap_with_e` helper added (returns `(K, ct, e_p)` for test/demo use)
- Version bumped to v1.5.20 in suite and tests headers

#### Files changed

- `CryptosuiteTests/Herradura_tests.py`
- `Herradura cryptographic suite.py`

---

## [1.5.19] - 2026-04-29

### Feature — HPKS-Stern-F and HPKE-Stern-F: Arduino implementation

Adds HPKS-Stern-F and HPKE-Stern-F to the Arduino target, completing the six-language suite started in v1.5.18. Parameters: SDF_N=32, SDF_T=2, SDF_NROWS=16, SDF_ROUNDS=4 (same as ARM Thumb-2 and NASM i386).

#### Files changed

- `Herradura cryptographic suite.ino` — `stern_hash1_32`, `stern_hash2_32`, `stern_matrix_row_32`, `stern_syndrome_32`, `stern_gen_perm_32`, `stern_apply_perm_32`, `stern_rand_error_32`, `SternSig32` struct, `stern_fs_challenges_32`, `hpks_stern_f_sign_32`, `hpks_stern_f_verify_32`, `hpke_stern_f_encap_32`, `hpke_stern_f_decap_32`; demo section + Eve tests in `loop()`; banner updated to v1.5.18
- `CryptosuiteTests/Herradura_tests.ino` — same 13 helper definitions + test [11] HPKS-Stern-F sign+verify (5 trials), test [12] HPKE-Stern-F encap+decap (5 trials); banner updated to v1.5.18

#### Test results

- [11] HPKS-Stern-F: 5/5 sign+verify correct (compile-verified via g++ mock)
- [12] HPKE-Stern-F: 5/5 encap+decap keys match (compile-verified via g++ mock)

---

## [1.5.18] - 2026-04-28

### Feature — HPKS-Stern-F and HPKE-Stern-F: code-based PQC across all 6 targets

Adds two new protocols based on the Stern identification scheme (ZKP for syndrome decoding), providing code-based post-quantum hardness independent of lattice assumptions. Both protocols are implemented in five language targets: Python, Go, C, ARM Thumb-2, and NASM i386. Arduino added in v1.5.19.

#### HPKS-Stern-F — Code-Based Signature (EUF-CMA)

3-challenge Fiat-Shamir transformed Stern ZKP for syndrome decoding. Parameters: N=32, t=2, nRows=16, rounds=4 (assembly targets use 32-bit operands for KEYBITS=32; C/Go/Python use 256-bit).

- **Commit phase** (per round): generate random r (weight t), y = e ⊕ r, permutation π; compute c0 = hash(π, H·r^T), c1 = hash(σ(r)), c2 = hash(σ(y)) where σ = apply(π, ·)
- **Challenge** (Fiat-Shamir via NL-FSCX): b ∈ {0, 1, 2} derived from H(msg, c0, c1, c2)
- **Response**: b=0 → (σ(r), σ(y)); b=1 → (π, r); b=2 → (π, y)
- **Verify**: consistency of commitments and weight-t checks per challenge branch
- Security: EUF-CMA under the Syndrome Decoding assumption

#### HPKE-Stern-F — Code-Based KEM (Niederreiter)

Niederreiter-style KEM with syndrome as ciphertext and NL-FSCX hash as session key.

- **Encap**: sample e' (weight t); ct = H·e'^T; K = hash(seed, e')
- **Decap** (known-e' demo): K = hash(seed, e'); production requires a QC-MDPC syndrome decoder

#### NL-FSCX primitives

Both protocols share `sternHash` (NL-FSCX v1 with ROL(v,4) key schedule, 8 steps) and `sternMatrixRow` (same construction for parity-check matrix H). Fisher-Yates permutation generation uses `nl_fscx_v1` as PRNG.

#### Files changed

- `Herradura cryptographic suite.py` — `stern_hash1/2`, `stern_matrix_row`, `stern_syndrome`, `stern_popcount_eq2`, `stern_gen_perm`, `stern_apply_perm`, `stern_rand_error`, `stern_fs_challenges`, `hpks_stern_f_sign/verify`, `hpke_stern_f_encap/decap_known`; demo + Eve tests in main
- `CryptosuiteTests/Herradura_tests.py` — tests [17]–[18] (Stern-F sign+verify, KEM), benchmark [28]
- `Herradura cryptographic suite.go` — same 13 functions (`SternHash1`, etc.); demo + Eve tests
- `CryptosuiteTests/Herradura_tests.go` — tests [17]–[18] (Stern-F sign+verify, KEM), benchmark [28]
- `Herradura cryptographic suite.c` — same 13 functions; demo + Eve tests
- `CryptosuiteTests/Herradura_tests.c` — tests [17]–[18] (Stern-F sign+verify, KEM), benchmark [28]
- `Herradura cryptographic suite.s` (ARM Thumb-2) — 13 Stern-F functions + demo + Eve tests; SDF_N=32
- `CryptosuiteTests/Herradura_tests.s` (ARM Thumb-2) — tests [11]–[12]
- `Herradura cryptographic suite.asm` (NASM i386) — 13 Stern-F functions + demo + Eve tests; SDF_N=32
- `CryptosuiteTests/Herradura_tests.asm` (NASM i386) — tests [11]–[12]

#### Test results

All targets produce passing correctness tests:
- Assembly targets (ARM/NASM, N=32): [11] 3/3 verified, [12] 3/3 keys match
- C/Go/Python (N=256): [17] sign+verify, [18] encap+decap KEM, plus Eve-resistance tests in main

---

## [1.5.17] - 2026-04-26

### Performance — NTT twiddle precomputation eliminates `rnl_mod_pow` calls per `rnl_poly_mul` (C, Go)

Adds a lazy-initialized static twiddle table to the NTT used by HKEX-RNL, eliminating all
`rnl_mod_pow` invocations from the hot path after the first `rnl_poly_mul` call.

#### What was recomputed on every call

Each `rnl_poly_mul` call previously executed:
- 2 `rnl_mod_pow` calls for ψ and ψ⁻¹ (pre/post-twist powers)
- 3 × `log₂n` `rnl_mod_pow` calls inside the three `rnl_ntt` invocations (one per butterfly stage)
- 1 additional `rnl_mod_pow` for n⁻¹ inside the inverse NTT

Total: ~27 modular exponentiations (each up to 16 multiplications) per `rnl_poly_mul`.

#### What is precomputed

- `psi_pow[n]` / `psi_inv_pow[n]` — ψ^i and ψ^{-i} for pre/post-twist
- `stage_w_fwd[log₂n]` / `stage_w_inv[log₂n]` — per-stage ω for forward/inverse NTT
- `inv_n` — n⁻¹ mod q for INTT scaling

Initialized on first use (same lazy-init pattern as `m_inv_ba`). After initialization the per-call
cost is ~3 table lookups per stage (replacing 3 `rnl_mod_pow` calls).

#### Files changed

- `Herradura cryptographic suite.c` — `rnl_twiddle_init`, `rnl_tw` struct; `rnl_ntt` and `rnl_poly_mul` use precomputed table
- `CryptosuiteTests/Herradura_tests.c` — `rnl32_tw_init`, `rnl32_tw` (2-entry array for n∈{32,64}); `rnl32_ntt`, `rnl32_poly_mul`, `rnl_poly_mul_n` use precomputed table
- `Herradura cryptographic suite.go` — `rnlTwEntry` struct, `rnlTwCache` map, `rnlTwGet`; `rnlNTT` and `rnlPolyMul` use precomputed table
- `CryptosuiteTests/Herradura_tests.go` — same

#### Observed speedup

Go bench [25] HKEX-RNL handshake (n=64): **3.15 K → 4.72 K ops/sec (+50%)**.
C bench [25] (n=32): 66.6 K ops/sec (single size; n=64 path also optimized via `rnl_poly_mul_n`).

---

## [1.5.16] - 2026-04-25

### Fix — HKEX-RNL: Peikert 1-bit reconciliation eliminates key-agreement failures (all targets)

Implements Peikert cross-rounding reconciliation for HKEX-RNL across all six language
targets (C, Go, Python, ARM Thumb-2, NASM i386, Arduino) in both suite and test files.
Reduces key-agreement failure rate from 2.04% (n=32) / 37.24% (n=256) to **0%**.

#### Protocol change

Alice (reconciler) generates a 1-bit hint per ring coefficient from her raw product
polynomial $K_\text{poly,A}$ and transmits it alongside her public key:
$$h_i = \left\lfloor \frac{4c_i + \lfloor q/2 \rfloor}{q} \right\rfloor \bmod 2$$
Both parties use Alice's hint to extract each key bit (NewHope cross-rounding):
$$b_i = \left\lfloor \frac{2c_i + h_i \cdot \lfloor q/2 \rfloor + \lfloor q/2 \rfloor}{q} \right\rfloor \bmod p'$$
Because `max|K_poly_A[i] − K_poly_B[i]| ≤ 379 ≪ q/4 = 16384`, the hint always
resolves boundary crossings exactly.  Security assumptions are unchanged.

#### Test criterion change

Test [14]/[7] pass criterion raised from ≥ 90% to **100%** agreement.

#### Files changed

- `Herradura cryptographic suite.py` — `_rnl_hint`, `_rnl_reconcile_bits`; `_rnl_agree` returns `(K_raw, hint)` on reconciler path, `K_raw` on receiver path
- `CryptosuiteTests/Herradura_tests.py` — same helpers; test [14] criterion 100%; bench [25] updated
- `Herradura cryptographic suite.c` — `rnl_hint`, `rnl_reconcile_bits`; `rnl_agree(…, hint_in, hint_out)` with NULL sentinel
- `CryptosuiteTests/Herradura_tests.c` — `rnl32_hint`, `rnl32_reconcile`, `rnl32_agree`; `rnl_hint_n`, `rnl_reconcile_n`, `rnl_agree_n`; test [14] criterion 100%
- `Herradura cryptographic suite.go` — `rnlHint`, `rnlReconcileBits`; `rnlAgree(…, hintIn []byte) (*BitArray, []byte)`
- `CryptosuiteTests/Herradura_tests.go` — same; test [14] criterion 100%; bench [25] updated
- `Herradura cryptographic suite.ino` — `rnl_hint`, `rnl_reconcile`; `rnl_agree(…, hint_in, hint_out)` with NULL sentinel
- `Herradura cryptographic suite.s` — `rnl_hint32`, `rnl_reconcile32`, `rnl_agree_full`, `rnl_agree_recv`; call site updated
- `CryptosuiteTests/Herradura_tests.s` — same four subroutines; test [7] criterion 10/10
- `Herradura cryptographic suite.asm` — `rnl_hint32`, `rnl_reconcile32`, `rnl_agree_full` (EAX=s,EBX=C_other→EAX=key,EDX=hint), `rnl_agree_recv` (ECX=hint); call site updated
- `CryptosuiteTests/Herradura_tests.asm` — same; test [7] criterion 10/10
- `SecurityProofs.md §11.4.2` — new "Peikert reconciliation" subsection with hint/extraction formulas and correctness guarantee
- `SecurityProofs.md §11.5 Q2` — two new rows confirming 0 failures at n=32 and n=256
- `SecurityProofs.md §11.6` — replaced ⚠ Correctness warning with confirmation table; status updated
- `SecurityProofsCode/hkex_rnl_failure_rate.py` — §5 added; `_rnl_hint`, `_rnl_reconcile_bits`, `_rnl_exchange_reconciled`; asserts 0 failures at both n=32 and n=256

---

## [1.5.15] - 2026-04-25

### Analysis — HKEX-RNL key-agreement failure rate characterized (all deployed parameters)

New script `SecurityProofsCode/hkex_rnl_failure_rate.py` measures the empirical
key-disagreement rate P(K_A ≠ K_B) at deployed parameters across four sections.

#### Results

| Parameters | Failures | Rate | 95% CI |
|---|---|---|---|
| n=32, p=4096, η=1, 10 000 trials | 204/10 000 | **2.04%** | 1.78–2.34% |
| n=256, p=4096, η=1, 5 000 trials | 1 862/5 000 | **37.24%** | 35.9–38.6% |

Single-bit errors dominate (201/204 at n=32; 1456/1862 at n=256). Maximum bit-error
count: 2 at n=32, 5 at n=256.

#### Root-cause analysis (§2)

Per-coefficient error (`max|eA−eB| = 134`) is tiny relative to the extraction threshold
(16 384 = q/4), yet failures occur at extraction boundaries.  Root cause: ring convolution
over n coefficients accumulates error as O(√n), so at n=256 boundary crossings are frequent.
A p-sensitivity sweep (§4) confirms no p value below q fixes the problem (0.80% at p=8192).

#### Verdict

**Reconciliation hints required.** The single-polynomial structure of HKEX-RNL (vs. the
k×k matrix in Kyber) gives insufficient noise averaging at n=256.  NewHope-style 1-bit
reconciliation hints are needed; they add n/8 bytes of public data per party and reduce the
failure rate to effectively zero.  Architectural fix planned (TODO.md item #13).

#### Files changed

- `SecurityProofsCode/hkex_rnl_failure_rate.py` — new; four-section analysis script
- `SecurityProofs.md §11.5 Q2` — four new rows; removed ⚠ pending-verification note;
  added p-sensitivity table
- `SecurityProofs.md §11.6` — replaced stale "reliable without reconciliation" claim with
  correctness-warning block; added failure-rate table and reconciliation-hint requirement

---

## [1.5.14] - 2026-04-25

### Documentation — HSKE-NL-A2 deterministic encryption caveat (all targets)

HSKE-NL-A2 carries no nonce: the same (plaintext, key) pair always produces the
same ciphertext.  It does not achieve IND-CPA security in the multi-message sense
unless an external session differentiator is embedded in the plaintext before
encryption.  This usage constraint was undocumented; added in all seven locations:

- **`SecurityProofs.md §11.3.2`** — new paragraph after the cost analysis:
  explains the IND-CPA gap, contrasts with HSKE-NL-A1's per-session nonce, and
  gives concrete guidance (embed sequence number / nonce / session ID in plaintext).
- **`Herradura cryptographic suite.py`** — `CAUTION:` line added to the HSKE-NL-A2
  protocol comment block.
- **`Herradura cryptographic suite.c`** — same `CAUTION:` added to the block comment.
- **`Herradura cryptographic suite.go`** — one-liner in the protocol list expanded to
  note determinism and multi-message constraint.
- **`Herradura cryptographic suite.s`** (ARM Thumb-2) — `CAUTION:` line added inside
  the block comment preceding the HSKE-NL-A2 section.
- **`Herradura cryptographic suite.asm`** (NASM i386) — `CAUTION:` comment added
  above the `mov eax, hske_nl2_hdr` instruction.
- **`Herradura cryptographic suite.ino`** (Arduino) — `CAUTION:` comment added inside
  the banner block.

**No functional code changes.**

---

## [1.5.13] - 2026-04-24

### Fixed — HSKE-NL-A1 counter=0 step-1 degeneracy (security, all targets)

**Root cause.** The HSKE-NL-A1 keystream call `nl_fscx_revolve_v1(base, base XOR ctr, n/4)`
passes `A = B = base` when `ctr = 0`.  With `A = B`, `FSCX(A, B) = M(A ⊕ B) = M(0) = 0`, so
step 1 contributes only the linear term `ROL(2·base, n/4)`.  Non-linearity accumulates only
from step 2 onward — the same degeneracy fixed for the HKEX-RNL KDF in v1.5.10.

**Fix.** Replace the A (seed) argument with `ROL(base, n/8)` across all language targets:

```
ks[i] = nl_fscx_revolve_v1(ROL(base, n/8), base XOR i, n/4)
```

For n=256 (C/Go/Python): `ROL(base, 32)`.
For n=32 (ARM Thumb-2, NASM i386, Arduino): `ROL(base, 4)` — implemented as `ROR(base, 28)` on ARM.

**Files changed (9):**
- `Herradura cryptographic suite.c` — seed via `ba_rol_k(&seed_a1, &base_a1, KEYBYTES)` (n/8=32)
- `Herradura cryptographic suite.go` — `baseA1.RotateLeft(n/8)`
- `Herradura cryptographic suite.py` — `base_a1.rotated(KEYBITS // 8)`
- `Herradura cryptographic suite.s` — `ror r0, r0, #28` before `bl nl_fscx_revolve_v1`
- `Herradura cryptographic suite.asm` — `rol eax, 4` before `call nl_fscx_revolve_v1`
- `Herradura cryptographic suite.ino` — `_rol32(base, 4)`
- `CryptosuiteTests/Herradura_tests.c` — inline ROL in test [12] for n=64 and n=128
- `CryptosuiteTests/Herradura_tests.go` — `base.RotateLeft(size/8)` in test [12]
- `CryptosuiteTests/Herradura_tests.py` — `base.rotated(size // 8)` in test [12] and bench [23]

**Documentation updated:**
- `SecurityProofs.md §11.3.1` — updated keystream formula and added seed-rotation rationale
- `SecurityProofs.md §11.6` — updated KDF table entry to reflect v1.5.10 seed fix (was stale)
- `Herradura cryptographic suite.c:933` — fixed stale `q=3329` comment (should be `q=65537` since v1.5.4)

**TODO.md items closed:** #9 (degeneracy fix), #10 (stale q comment), #11 (stale §11.6 KDF formula).

---

## [1.5.12] - 2026-04-24

### Changed — `SecurityProofs.md`: §12 integrated into earlier sections

`§12 (Classical and Quantum Security Analysis)` was a late appendix holding
analysis that logically belonged alongside the earlier protocol-development sections.
Content redistributed to match the development timeline:

- **§9.2.4** — expanded with full DLP attack taxonomy (BSGS, Pohlig–Hellman, index
  calculus, quasi-polynomial), n=32 BSGS experimental verification, and cross-reference
  to §10.9.
- **§6** — added cross-reference to §10.8 for post-fix quantum analysis.
- **§10.6** — classical security analysis of v1.4.0 protocols (HSKE known-plaintext,
  HPKS forgery resistance, HPKE CDH attack path).
- **§10.7** — HPKS challenge function algebraic properties (affine bijection,
  predictable delta identity, ROM gap for EUF-CMA).
- **§10.8** — quantum algorithm analysis for v1.4.0 (Grover, Simon, Bernstein–Vazirani,
  Shor, HHL).
- **§10.9** — root-cause analysis of GF(2^n)* as DLP group; comparison table across
  GF(2^n)*, Z_p*, ECDLP, Ring-LWR; motivation for HKEX-RNL.
- **§11.7** — protocol-level quantum security summary table (all protocols).
- **§12 removed** — no content lost; every subsection relocated.

**Files changed (1):** `SecurityProofs.md`.

---

## [1.5.11] - 2026-04-23

### Fixed — KaTeX rendering errors in `SecurityProofs.md` §11

Four incremental fixes resolving three distinct parse failures in §11.4:

1. **`\$` inside inline math** (§11.4.2, line 1065): GitHub's Markdown parser treats
   `\$` as closing the `$...$` span, leaving `\overset{` with an unclosed brace.
   Fix: `\overset{\$}` → `\overset{\textdollar}`.

2. **`\{`/`\}` inside italic span** (§11.4.1, line 1039): `\{`/`\}` inside `*...*`
   italic markup are Markdown-escaped to bare `{`/`}` before KaTeX sees them, making
   set braces invisible.
   Fix: `\{` → `\lbrace`, `\}` → `\rbrace` (letter-prefixed; not a Markdown escape).

3. **Italic span blocking math** (§11.4.1): the `*Verified for ...*` span prevented
   GitHub's math extension from parsing `$...$` delimiters inside it.
   Fix: removed the `*...*` italic markers; `\{`/`\}` reverted from `\lbrace`/`\rbrace`
   (not needed outside italic context).

4. **Nested parentheses breaking math span** (§11.4.2, KDF formula): formula
   `($sk = \text{NL-FSCX-REVOLVE}(K, K, n/4)$)` — the inner `(K, K, n/4)` parens
   satisfy GitHub's link-paren-depth tracker before the `$` math span closes.
   Fix: outer `(` `$...$` `)` rewritten as `, where $sk = ...,$` (no wrapping parens).

**Files changed (1):** `SecurityProofs.md`.

---

## [1.5.10] - 2026-04-22

### Changed — HKEX-RNL KDF simplified to single-pass with ROL(K, n/8) seed

The KDF seed degeneracy (`fscx(K, K) = 0` on step 1 when A₀ = B = K`) was the root
cause.  Two-pass chain (v1.5.10-initial) was simplified to a single pass once the v2
second pass was shown to be bijective for fixed K — adding no one-wayness.

**Final KDF (all targets):**
```
seed = ROL(K, n/8);  sk = nl_fscx_revolve_v1(seed, K, n/4)
```

For n=256 (C/Go/Python): `ROL(K, 32)`.
For n=32 (assembly/Arduino/C-tests): `ROL(K, 4)`.

`SecurityProofs.md §11.4` updated with algebraic rationale and revised table.

**Files changed (12):** all language targets (suite + tests) and `SecurityProofs.md`.

**TODO.md item closed:** #4 (HKEX-RNL KDF degeneracy fix).

---

## [1.5.9] - 2026-04-22

### Changed — `nl_fscx_revolve_v2_inv`: precompute δ(B) once; HSKE-NL-A1 per-session nonce

Two independent improvements across all language targets:

#### Performance — precompute δ(B) in `nl_fscx_revolve_v2_inv`

`delta(B)` was recomputed on every iteration even though B is constant throughout the
loop.  Now computed once before the loop; inner body becomes `z = y − delta; y = B ⊕ m_inv(z)`.
Eliminates one multiply-and-rotate (or big-integer multiply for n=256) per step in
Python, C (32/64/128-bit), Go, Arduino, ARM Thumb-2, and NASM i386.

**Files changed (12):** all language targets (suite + tests). Closes TODO #8.

#### Security — HSKE-NL-A1 per-session nonce

Added random nonce N to HSKE-NL-A1 counter-mode so the keystream changes each session
even when K is reused.  Session base becomes `K ⊕ N`; N is generated fresh per run and
displayed alongside ciphertext.  Applied to Python, C, Go, Arduino, ARM Thumb-2, and
NASM i386 suite + test files.

**Files changed (9):** suite and test files for all targets. Closes TODO #3.

---

## [1.5.8] - 2026-04-21

### Added — build and run scripts for all language targets

Eight shell scripts added to the repository root:

| Script | Purpose |
|---|---|
| `build_c.sh` | Build C suite and tests; checks for `gcc` |
| `build_go.sh` | Build Go suite and tests; checks for `go` |
| `build_arm.sh` | Build ARM Thumb-2 binaries; checks for `arm-linux-gnueabi-gcc` |
| `build_asm_i386.sh` | Build NASM i386 binaries; checks for `nasm` + linker |
| `build_arduino.sh` | Build Arduino firmware; checks for `arduino-cli` |
| `run_arm.sh` | Run ARM binaries via `qemu-arm`; usage instructions |
| `run_asm_i386.sh` | Run i386 binaries via `qemu-i386`; usage instructions |
| `run_arduino.sh` | Run Arduino firmware via `simavr`; usage instructions |

Each build script prints `apt-get install` instructions for any missing tool.

**Files changed (8):** new scripts only.

---

## [1.5.7] - 2026-04-21

### Changed — precomputed M⁻¹ rotation table for `nl_fscx_v2_inv`; Arduino banner fix

#### Performance — precomputed M⁻¹ rotation table

`M⁻¹(X) = M^{n/2−1}(X)` is now applied via a precomputed rotation table: XOR of
`ROL(X, k)` for each `k` where bit `k` of `M⁻¹(1)` is set.

- **n=256 (C/Go/Python):** table bootstrapped once on first call via the old
  `fscx_revolve` path (lazy init, cached per bit-size).
- **n=32 (assembly/Arduino/C-tests):** constant `0x6DB6DB6D` hardcoded
  (21 rotations, analytically verified).
- **n=64/128 (C test file):** 64-bit constants hardcoded.

Reduces each `nl_fscx_v2_inv` step from 127 FSCX iterations (n=256) to ~170
XOR-rotation pairs (~2n/3 density). All language targets updated: C, Go, Python,
Arduino (unrolled helper), ARM Thumb-2 (ROR+EOR pairs), NASM i386 (ROL+XOR pairs).

**Files changed (12):** all language targets (suite + tests).

#### Fixed — stale v1.5.3 version banner in Arduino `loop()`

`loop()` in both `.ino` files still printed `v1.5.3`; corrected to `v1.5.7`.

**Files changed (2):** `Herradura cryptographic suite.ino`, `CryptosuiteTests/Herradura_tests.ino`.

---

## [1.5.6] - 2026-04-20

### Fixed — modular bias in `rnl_rand_poly` — 3-byte rejection sampling

The previous 4-byte draw followed by naive `% Q` had ~1/2³² per-coefficient bias
(value 0 appeared once more than all others over the full 32-bit cycle).

**Fix (all targets):** 24-bit rejection-sampling loop with threshold
`(1<<24) − (1<<24)%65537 = 16711935`. Rejection probability ≈ 0.39%.

Added `rnl_rand_coeff()` helper to C tests (replaces `rand32()%Q` in
`rnl32_rand_poly` and `rnl_rand_poly_n`).

Applied to: Python, C, Go, ARM Thumb-2, NASM i386, Arduino.

**Files changed (9):** `Herradura cryptographic suite.{c,go,py,s,asm,ino}`,
`CryptosuiteTests/Herradura_tests.{c,go,py}`.

---

## [1.5.5] - 2026-04-20

### Changed — C test suite: multi-size loops, PQC benchmarks, output alignment (Phases 1–5)

Five-phase expansion bringing `Herradura_tests.c` to full parity with Python and Go:

#### Phase 1–2 (earlier) — infrastructure

Generalized `BitArray` with `int nbits`/`int nbytes` fields; added `ba_add` (mod 2ⁿ
addition) required by NL-FSCX at non-32-bit widths. Added `gf_mul_64`/`gf_pow_64`
(GF(2⁶⁴), poly `0x1B`) and corresponding 64-bit FSCX/NL-FSCX primitives.

#### Phase 3 — GF/NL multi-size loops (tests [1],[5]–[9],[14]–[16])

- Tests [1],[5],[6]: loop over `{32, 64, 256}`.
- Tests [7]–[9],[14]–[16]: loop over `{32, 64}`.
- Key-sensitivity PASS criterion aligned to `mean ≥ n/4` (matching Python/Go).
- 64-bit Schnorr uses `__uint128_t` for `(a·e) mod (2⁶⁴−1)` overflow safety.

#### Phase 4 — FSCX/NL-FSCX multi-size loops (tests [2]–[4],[10]–[13])

Added 128-bit FSCX primitives (`fscx128`/`fscx_revolve128` via `__uint128_t`) and full
128-bit NL-FSCX v1/v2/inv suite; `rol128_32` for n/4=32-bit shift; `rand128()` helper.

- Tests [2]–[4]: loop `{64, 128, 256}` using `fscx64`/`fscx128`/`ba_fscx` dispatch.
- Tests [10]–[13]: loop `{64, 128}` using 64/128-bit NL-FSCX scalar functions.
  (256-bit NL-FSCX deferred — requires 256-bit integer multiply.)
- `popcount128()` helper for 128-bit Hamming distance in test [2].

#### Phase 5 — test [11] bijectivity methodology alignment

Upgraded test [11] bijectivity sub-test to match Python/Go: sample
`BIJ_SAMPLES=256` random A values per B and detect output collisions via O(n²)
pairwise scan (vs. prior single-pair draw).

#### Output and benchmarks alignment

- Version banner bumped to v1.5.5 in `Herradura_tests.c`, `.py`, `.go`.
- C test labels: added `[CLASSICAL]` tag to tests [1]–[9] and `[PQC-EXT]` to
  [10]–[16], matching existing Python/Go output.
- C section headers renamed to match Python/Go.
- PQC benchmarks [22]–[25] ported from Python/Go to C:
  - [22] NL-FSCX v1 revolve throughput (32-bit, n/4=8 steps)
  - [22b] NL-FSCX v2 revolve+inv throughput (32-bit, r_val=24 steps)
  - [23] HSKE-NL-A1 counter-mode throughput (32-bit, ctr=0)
  - [24] HSKE-NL-A2 revolve-mode round-trip (32-bit, r_val=24 steps)
  - [25] HKEX-RNL full handshake throughput (n=32)

**Files changed (3):** `CryptosuiteTests/Herradura_tests.{c,go,py}`.

---

## [1.5.4] - 2026-04-20

### Changed — replace O(n²) polynomial multiplication with negacyclic NTT in all implementations

Cooley-Tukey NTT over Z₆₅₅₃₇ (Fermat prime) with negacyclic twist
`ψ = 3^{(q−1)/(2n)} mod q` replaces the naive O(n²) `_rnl_poly_mul` in every
language implementation and test suite. ~32× speedup at n=256; ~6× at n=32.

| Target | Change |
|---|---|
| C, Go, Python | `rnl_ntt`/`rnlNTT`/`_ntt_inplace` + NTT-based `poly_mul` |
| ARM Thumb-2 (.s) | Precomputed tables + `rnl_ntt` subroutine (`umull` + fast Fermat mod) |
| NASM i386 (.asm) | Precomputed tables + `rnl_ntt` (stack-frame cdecl) + NTT `poly_mul` |
| Arduino (.ino) | Same NTT using `uint64_t` multiply |

`SecurityProofs.md` status line updated with v1.5.4 NTT note.

**Files changed (13):** all language targets (suite + tests) and `SecurityProofs.md`.

---

## [1.5.3] - 2026-04-19

### Changed — HKEX-RNL secret sampler upgraded to CBD(η=1); assembly bug fixes

#### Security — CBD(η=1) secret polynomial sampler

Replaced the uniform `{0,1}` secret polynomial sampler (`rnl_small_poly` /
`rnlSmallPoly` / `_rnl_small_poly`) with centered binomial distribution CBD(η=1)
across all language targets.

CBD(1) samples each coefficient as `(a − b) mod q` where `a, b` are independent
uniform bits, producing values in `{−1, 0, 1}` with zero mean and `P(±1) = 1/4`.
This matches the Kyber/NIST PQC baseline secret distribution and eliminates the
positive mean bias of the previous `{0,1}` sampler — a prerequisite for standard
Ring-LWR hardness arguments. The max coefficient magnitude (1) is unchanged, so
the noise budget and parameter set `(n, q, p, p', η)` are unaffected.

`SecurityProofs.md §11.4.2` and `§11.6` updated to document CBD(η=1) and its rationale.

**Files changed (13):** all language targets (suite + tests) and `SecurityProofs.md`.

#### Fixed — ARM `cbz` hi-register and NASM `poly_mul` stack offset

- **ARM Thumb-2:** `cbz` only accepts lo-registers r0–r7; replaced `cbz r9`/`cbz r10`
  with `cmp`+`beq` pairs in both `.s` files.
- **NASM i386:** after `pop ebx` in `rnl_poly_mul`, `[esp]` = k and `[esp+4]` = i;
  the code was reading `[esp+4]` (= i) to get k, writing every partial product to
  `rnl_tmp[i]` instead of `rnl_tmp[k]`. Fixed to `[esp]` in both `.rpm_add_no_sub`
  and `.rpm_neg_no_sub` branches in both `.asm` files.

**Files changed (4):** `Herradura cryptographic suite.{asm,s}`,
`CryptosuiteTests/Herradura_tests.{asm,s}`.

---

## [1.5.2] - 2026-04-18

### Fixed — KaTeX rendering in `SecurityProofs.md` (`^*` and `\mathcal{R}_q` cross-span emphasis)

Three more broken rendering regions in `SecurityProofs.md` fixed:

- **`^*` cross-span `*`-emphasis** (lines 726, 1202–1206, 1249–1254): `*` (U+002A)
  between `^` and `$`/`,`/`}` (all CommonMark punctuation) is both-flanking — it can
  open AND close `*`-emphasis.  When multiple `$...\mathbb{GF}(2^n)^*...$` spans appear
  in the same paragraph, or when the forgery section packs many `$R^*$`, `$s^*$`,
  `$e^*$` spans together, opener/closer pairs form across span boundaries, consuming
  the intervening `$` math delimiters and garbling all affected text.
  Fix: replace `*` (U+002A) with `∗` (U+2217, ASTERISK OPERATOR) in each
  problematic span — only the three affected paragraphs, not the many safe
  single-occurrence spans elsewhere.  U+2217 is not a CommonMark emphasis delimiter;
  KaTeX renders it identically to `*` in math mode.
- **Lines 1068–1069** (`$$K_A$$`/`$$K_B$$` display math): `\mathcal{R}_q` (where `}`
  precedes `_q`) across the two consecutive display-math blocks creates a cross-block
  `_`-emphasis opener/closer pair; fixed with `\mathcal R_q`.

---

### Fixed — KaTeX rendering in `SecurityProofs.md` (cross-span emphasis collision)

Six formulas in `SecurityProofs.md` rendered as raw source code on GitHub due to
cmark-gfm processing emphasis `_` delimiters before detecting `$...$` inline math spans.

Root cause: `_` preceded by `}` (a CommonMark punctuation character) satisfies the
left-flanking delimiter rule and can open an emphasis run.  When a matching
right-flanking `_` appears in a later math span on the same line or paragraph,
GitHub's parser consumes both underscores as emphasis, destroying the enclosing
`$` math spans.

Fixes applied:

- **Lines 1062–1063** (`\mathcal{R}_q`, `\mathcal{R}_p`) — dropping the braces around
  the single-character `\mathcal` argument (`\mathcal R_q`) means `_q` is now preceded
  by the alphanumeric `R`, which is not left-flanking and cannot open emphasis.
- **Line 1171** (`\text{NL-FSCX-REVOLVE}_{v1}`) — `}_{v1}` still has `_` preceded by
  `}`, so the entire subscripted name is rewritten using `\textunderscore` separators:
  `\text{NL-FSCX}\textunderscore\text{REVOLVE}\textunderscore\text{v1}`.
- **Lines 1057–1059** (§11.4.2 shared polynomial setup) — same `\mathcal{R}_q` →
  `\mathcal R_q` fix; opener `_q` on line 1057 was pairing with `m_\text{blind}`
  closer on line 1059 across the paragraph boundary of two `$...$` spans.
- **Line 1071** (§11.4.2 commutativity sentence) — `\mathcal{R}_q` opener at start
  of line paired with `m_\text{blind}` closer in the adjacent span on the same line;
  fixed with `\mathcal R_q`.

---

### Proposed — multi-size key-length tests for `Herradura_tests.c`

Analysis of the gap between the Python and C test suites: `Herradura_tests.py`
loops each test over `SIZES = [64, 128, 256]` (FSCX tests) and `GF_SIZES = [32, 64]`
(GF protocol tests), while `Herradura_tests.c` runs each test at a single hardcoded
size (256-bit for tests [1]–[6], 32-bit for tests [7]–[16]).

Three structural changes proposed for a follow-up implementation commit:

1. **Generalize `BitArray`** — add `int nbits; int nbytes;` fields (max buffer stays
   32 bytes); thread `nbits` through all `ba_*` and `ba_fscx*` functions; add `ba_add`
   (mod 2^n addition) required by NL-FSCX v1/v2 at non-32-bit widths.

2. **Add 64-bit GF layer** — `gf_mul_64` / `gf_pow_64` (poly `0x1BULL`,
   GF(2^64)); `fscx64` / `fscx_revolve64`; `nl_fscx_v1_64` / `nl_fscx_v2_64` and
   their inverses, mirroring the existing `_32` helpers.

3. **Loop tests over multiple sizes**:
   ```c
   static const int SIZES[]    = {64, 128, 256}; /* tests 2,3,4,10,11,12,13 */
   static const int GF_SIZES[] = {32, 64};        /* tests 1,5,6,7,8,9,15,16 */
   ```

Version strings bumped to v1.5.2 in `Herradura_tests.c`, `Herradura_tests.py`,
and `Herradura_tests.go`.

---

## [1.5.1] - 2026-04-16

### Fixed / Added

#### Test execution limits (C, Python, Go)

- `CryptosuiteTests/Herradura_tests.c` — `--rounds`/`-r` and `--time`/`-t` CLI flags;
  `HTEST_ROUNDS` / `HTEST_TIME` environment variable fallbacks; wall-clock timeout
  via `CLOCK_MONOTONIC`; all 16 security tests scale iteration counts and pass
  thresholds to actual runs completed.
- `CryptosuiteTests/Herradura_tests.py` — same flags via `argparse`; `_trange()`
  generator checks `time.monotonic()` every 64 iterations.
- `CryptosuiteTests/Herradura_tests.go` — same flags via `flag` package;
  `timeExceeded()` helper with `time.Since()`.

#### Documentation — KaTeX rendering fixes (README.md, SecurityProofs.md)

Two separate KaTeX errors resolved (both caused by v1.5.0 content not applying
the conventions established in earlier fix commits):

- **`'_' allowed only in math mode`** — `\_` inside `\text{}` is rejected in
  text mode.  Fix: place `\_` in math mode between separate `\text{}` groups.
- **`Double subscripts: use braces to clarify`** — `\text{X}\_\text{Y}\_\text{Z}`
  parses `\_` as the subscript operator twice on the same base.  Fix: use
  `\textunderscore` (a text/math command that produces a literal `_` glyph) in
  place of `\_`.

Final correct pattern (58 occurrences across both files):
`\text{FSCX}\textunderscore\text{REVOLVE}` /
`\text{FSCX}\textunderscore\text{REVOLVE}\textunderscore\text{N}` /
`\text{fscx}\textunderscore\text{revolve}`.
`README.md`: also `\mathit{enc}\textunderscore\mathit{key}` and
`\mathit{dec}\textunderscore\mathit{key}`.

- **`Missing close brace`** (`SecurityProofs.md` line 702) — `\xleftarrow{\$}`
  inside `$...$` inline math: GitHub's markdown parser treats `\$` as closing
  the math span, leaving `\xleftarrow{` with no matching `}`.  Fix: replace
  `\$` with `\textdollar` (KaTeX's dollar-sign command, contains no literal
  `$` character).

#### Documentation and code inconsistency review

Cross-file audit of documentation vs. implementation; all inconsistencies resolved.

**CLAUDE.md:**
- Test count corrected: `9 security tests` → `16 security tests` (reflects v1.5.0 tests [1]–[16]).
- Repository structure: removed `SecurityProofs2.md` (never existed) and `PQCanalysis.md`
  (removed in v1.4.1, merged into `SecurityProofs.md §12`).
- Protocol stack section updated from v1.4.0 to v1.5.0; added five NL/PQC protocol entries
  (HSKE-NL-A1, HSKE-NL-A2, HKEX-RNL, HPKS-NL, HPKE-NL).

**README.md:**
- Version in title updated to v1.5.1.

**`CryptosuiteTests/Herradura_tests.c`:**
- Stale block comments on benchmark functions corrected: `[11]`–`[14]` → `[18]`–`[21]`
  (printf statements already printed the correct numbers; only the block comments lagged).

#### PQC proofs and tests review

**`SecurityProofs.md`:**
- §11 section header: `(v1.4.0)` → `(v1.5.0)`; opening sentence updated to "documents
  the verified fixes implemented in v1.5.0" (was "proposes verified fixes").
- §11.4.2 HKEX-RNL protocol: clarified that `m_blind = m(x) + a_rand` is a **shared**
  public polynomial (one party generates `a_rand` and transmits it; both use the same
  `m_blind`).  Previous wording "Bob generates analogously" implied independent polynomials,
  which breaks key agreement by commutativity.
- §11.4.3 attack table: added `(q=769, n=16, 200 trials…)` attribution — the q value
  used for the table was previously unstated.
- §11.5 Q1 table: first row description `B=0` corrected to `random B` (the verification
  script generates random B per trial, not a fixed B=0).
- §11.5 Q2 table: replaced two "not yet verified" rows with confirmed results for the
  deployed parameters `(q=65537, n=32)` and `(q=65537, n=256)`.
- §11.6: updated recommended parameters from `q=3329/p=1024/p'=32` to the deployed
  `q=65537/p=4096/pp=2`; replaced stale "code migration planned" status note with
  v1.5.0 implementation status and noise-amplification verification summary.
- §12.5 protocol summary table: added six new rows covering the v1.5.0 NL protocols
  (HSKE-NL-A1, HSKE-NL-A2 — both key-only and known-plaintext cases; HPKS-NL; HPKE-NL;
  HKEX-RNL).

**`SecurityProofsCode/hkex_nl_verification.py`:**
- §2.1 extended to verify `m(x)` invertibility for deployed parameters `(q=65537, n=32)`
  and `(q=65537, n=256)` — both confirmed invertible with `m·m⁻¹ = 1`.
- §2.3 extended to compute noise amplification `‖m⁻¹‖₁ · q/(2p)` for deployed
  `q=65537, n=32, p=4096` (result: ≈4.3×10⁶ ≫ q — structural protection confirmed).

**`CryptosuiteTests/Herradura_tests.{c,go,py}` — test [14] HKEX-RNL:**
- All three implementations now report both raw agreement (`K_A == K_B`) and
  KDF-processed agreement (`sk_A == sk_B`) — previously only the Go file checked both.
- Added explanatory comment describing the shared-polynomial protocol structure.
- Go benchmark [25]: same structural consistency (was already correct; comment added).

---

## [1.5.0] - 2026-04-11

### Added — NL-FSCX v2, HSKE-NL-A2, HKEX-RNL, HPKS-NL, HPKE-NL across all implementations

Version 1.5.0 adds non-linear extensions to FSCX (breaking GF(2)-linearity and period structure)
and a post-quantum key exchange (HKEX-RNL via Ring-LWR), porting them to every language
including C, Go, Python, ARM Thumb-2 assembly, NASM i386 assembly, and Arduino.

#### New primitives

- **NL-FSCX v1** — `nl_fscx(A,B) = fscx(A,B) ⊕ ROL(A+B, n/4)`: integer carry injection
  breaks GF(2) linearity and orbit periods; used as KDF/commitment function.
- **NL-FSCX v2** — `nl_fscx_v2(A,B) = fscx(A,B) + δ(B) mod 2^n`,
  where `δ(B) = ROL(B·⌊(B+1)/2⌋ mod 2^n, n/4)`: bijective in A for all B;
  closed-form inverse `A = B ⊕ M⁻¹((Y − δ(B)) mod 2^n)` (`M⁻¹ = fscx_revolve(·, 0, n/2−1)`).

#### New protocols

- **HSKE-NL-A1** (counter-mode): `ks = nl_fscx_revolve_v1(K, K⊕ctr, i)`;
  `E = P ⊕ ks`; `D = E ⊕ ks = P`.
- **HSKE-NL-A2** (revolve-mode): `E = nl_fscx_revolve_v2(P, K, r)`;
  `D = nl_fscx_revolve_v2_inv(E, K, r) = P`.
- **HKEX-RNL** (Ring-LWR key exchange; conjectured quantum-resistant):
  shared `m_blind = m(x) + a_rand` in `Z_q[x]/(x^n+1)`;
  Alice/Bob derive `C = round_p(m_blind · s)` with small secret `s`;
  agreement via `K = round_pp(s · lift(C_other))`; final `sk = nl_fscx_revolve_v1(K, K, i)`.
  Parameters: `n=256` (C/Go/Python), `n=32` (assembly/Arduino/C-tests); `q=65537`, `p=4096`.
- **HPKS-NL** (NL-hardened Schnorr): challenge `e = nl_fscx_revolve_v1(R, P, i)`.
- **HPKE-NL** (NL-hardened El Gamal): `E = nl_fscx_revolve_v2(P, enc_key, i)`;
  `D = nl_fscx_revolve_v2_inv(E, dec_key, i)`.

#### Files updated (all languages)

- `Herradura cryptographic suite.py` — NL-FSCX v1/v2, all five new protocols, Eve bypass tests.
- `CryptosuiteTests/Herradura_tests.py` — tests [10]–[16] (NL-FSCX, HSKE-NL-A1/A2, HKEX-RNL,
  HPKS-NL, HPKE-NL); benchmarks renumbered [17]–[25].
- `Herradura cryptographic suite.go` — same protocol additions as Python.
- `CryptosuiteTests/Herradura_tests.go` — same test additions.
- `Herradura cryptographic suite.c` — NL-FSCX v1/v2 (256-bit BitArray), HKEX-RNL (n=256),
  HPKS-NL, HPKE-NL; `ba_add256`, `ba_sub256`, `ba_mul256_lo`, `ba_rol64_256`, `m_inv_ba` added.
- `CryptosuiteTests/Herradura_tests.c` — tests [10]–[16] (32-bit NL-FSCX and RNL, n=32);
  benchmarks renumbered [17]–[21].
- `Herradura cryptographic suite.asm` — NASM i386: `nl_fscx_delta_v2`, `nl_fscx_v1/v2/v2_inv`,
  `nl_fscx_revolve_v1/v2/v2_inv`, `m_inv_32`; RNL poly helpers (n=32); new protocol sections.
- `CryptosuiteTests/Herradura_tests.asm` — NASM i386: tests [1]–[10] (v1.4.0 tests [1]–[4]
  plus new [5]–[10] for NL/RNL protocols); memory-variable loop counters; EBP pass counter.
- `Herradura cryptographic suite.s` — ARM Thumb-2: same additions as NASM; `umull`/`udiv`/`mls`
  for mod-65537 ring arithmetic; `.ltorg` after every subroutine.
- `CryptosuiteTests/Herradura_tests.s` — ARM Thumb-2: tests [1]–[10]; r10/r11 loop
  counter/pass count (callee-saved); `it`/conditional suffix pattern for modular arithmetic.
- `Herradura cryptographic suite.ino` — Arduino: NL-FSCX v1/v2/inverse, HKEX-RNL (n=32),
  HPKS-NL, HPKE-NL; LCG PRNG for RNL poly generation.
- `CryptosuiteTests/Herradura_tests.ino` — Arduino: tests [1]–[10], 30-second rerun loop.

#### Security proofs (SecurityProofs.md)

- **§11** — NL-FSCX non-linearity and PQC extensions (Theorems 11–12; HKEX-RNL,
  HSKE-NL-A1/A2, HPKS-NL, HPKE-NL; C3 hybrid recommendation).
- **§12** — Classical and quantum security analysis (merged from PQCanalysis.md in v1.4.1).

---

## [1.4.1] - 2026-04-08

### Documentation — PQCanalysis.md merged into SecurityProofs.md

`PQCanalysis.md` is removed.  All content has been integrated into `SecurityProofs.md`
as **§12 (Classical and Quantum Security Analysis)**, with duplicate sections eliminated
and the most up-to-date data retained.

#### Content added to SecurityProofs.md (§12)

- **§12.1 Classical DLP attacks on GF(2^n)*** — full attack complexity table (BSGS,
  Pohlig–Hellman, index calculus, Barbulescu quasi-polynomial); BSGS n=32 experiment
  (`A_PRIV=0xDEADBEEF`, solved in 0.622 s); effective-security discussion.
- **§12.2 Classical security of HSKE / HPKS / HPKE** — known-plaintext attack on HSKE
  (1 pair → full $c_K$, 0 unconstrained bits at n=64); classical forgery analysis for
  HPKS; CDH attack path for HPKE.
- **§12.3 HPKS challenge function — algebraic properties** — affine bijection proof
  (0 collisions in 50 000 trials); predictable challenge delta identity
  $e(R_2) \oplus e(R_1) = M^i \cdot (R_1 \oplus R_2)$ (100% verified); consequence for
  ROM-based security proofs and the forking lemma.
- **§12.4 Quantum algorithm analysis** — Grover (symmetric key-only), Simon (inapplicable
  to GF DLP, applicable to HSKE affine structure), Bernstein–Vazirani (HSKE 1-query
  recovery), Shor (primary quantum threat: O(n² log n) DLP for HKEX-GF/HPKS/HPKE),
  HHL (irrelevant — GF(2) systems already classically efficient).
- **§12.5 Protocol-level quantum security summary** — updated table including HKEX-RNL
  (§11.4) as the proposed PQC replacement.
- **§12.6 Root cause: why GF(2^n)* is the wrong group** — comparison table across
  GF(2^n)*, Z_p*, ECDLP, and Ring-LWR; motivation for the §11.4 HKEX-RNL proposal.

#### Files removed

- `PQCanalysis.md` — superseded by SecurityProofs.md §12.

#### Status update

- `SecurityProofs.md` header updated to reference §12.
- Last-updated date updated to 2026-04-08.

---

## [1.4.0] - 2026-04-06

### BREAKING CHANGE — HKEX replaced with HKEX-GF; HPKS upgraded to Schnorr; HPKE upgraded to El Gamal

The classical HKEX key exchange is **broken**: the shared secret `sk = S_{r+1}·(C⊕C2)` is directly computable from the two public wire values alone (proved in SecurityProofs.md, Theorem 7). Version 1.4.0 replaces it with Diffie-Hellman over `GF(2^n)*`, and replaces the trivially-reversible HPKS/HPKE XOR constructions with standard Schnorr signatures and El Gamal encryption.

#### Protocol changes (all languages)

- **HKEX-GF** replaces HKEX in every implementation:
  - Alice: private scalar `a`, public `C = g^a` (GF exponentiation)
  - Bob: private scalar `b`, public `C2 = g^b`
  - Shared: `sk = C2^a = C^b = g^{ab}` (field commutativity)
  - Arithmetic: carryless polynomial multiplication mod irreducible `p(x)` — XOR and left-shift only
- **`fscx_revolve_n` removed** from all files. The nonce contribution `S_k·N` cancels identically from both sides of the key-exchange equation (Theorem 8), providing zero security benefit.
- **HSKE** simplified to `fscx_revolve(P, key, i)` / `fscx_revolve(E, key, r)` (previously used `fscx_revolve_n`; functionally equivalent, now simplified).
- **HPKS** replaced with a **Schnorr-style signature** (32-bit GF parameters):
  - Sign: choose nonce `k`; `R = g^k`; challenge `e = fscx_revolve(R, msg, i)`; response `s = (k - a·e) mod (2^32-1)`
  - Verify: `g^s · C^e == R`
  - The 32-bit field is used because the Schnorr response requires modular integer arithmetic over the group order; at 256-bit this requires GMP-style big integers not available in plain C or assembly.
- **HPKE** replaced with **El Gamal + HSKE** (32-bit GF parameters):
  - Bob: ephemeral `r`; `R = g^r`; `enc_key = C^r = g^{ar}`; `E = fscx_revolve(P, enc_key, i)`
  - Alice: `dec_key = R^a = g^{ra}`; `D = fscx_revolve(E, dec_key, r) = P`
  - Correctness: `g^{ar} = g^{ra}` by field commutativity.

#### Security

| n | Primitive polynomial | Classical security |
|---|---------------------|-------------------|
| 32 | x³²+x²²+x²+x+1 = 0x00400007 | demo only |
| 64 | x⁶⁴+x⁴+x³+x+1 = 0x1B | ~40 bits |
| 128 | x¹²⁸+x⁷+x²+x+1 = 0x87 | ~60–80 bits |
| 256 | x²⁵⁶+x¹⁰+x⁵+x²+1 = 0x425 | ~128 bits (recommended) |

Generator `g = 3` (polynomial `x+1`) for all field sizes.

#### Files updated

- `Herradura cryptographic suite.py` — GF arithmetic added, HKEX-GF implemented, `fscx_revolve_n` removed, HPKS Schnorr and HPKE El Gamal implemented, Eve bypass tests updated.
- `Herradura_tests.py` — test [1] updated for HKEX-GF; tests [7] Schnorr correctness, [8] Schnorr Eve-resistance, [9] El Gamal correctness added; benchmarks renumbered [10]–[14].
- `Herradura cryptographic suite.go` — `GfMul`/`GfPow` added (`math/big`), `FscxRevolveN` removed, HPKS Schnorr and HPKE El Gamal implemented.
- `Herradura_tests.go` — same structural updates as Python tests.
- `Herradura cryptographic suite.c` — `gf_mul_ba`/`gf_pow_ba` added for GF(2^256) and `gf_mul_32`/`gf_pow_32` for 32-bit GF; `ba_fscx_revolve_n` removed; HPKS Schnorr and HPKE El Gamal implemented with 32-bit GF operands.
- `Herradura_tests.c` — tests [7] Schnorr (1000 trials), [8] Schnorr Eve-resistance, [9] El Gamal (1000 trials); benchmarks [10]–[14] updated.
- `Herradura cryptographic suite.s` — ARM Thumb-2: `gf_mul_32`/`gf_pow_32` and LCG PRNG added; `fscx_revolve_n` removed; Schnorr and El Gamal sections implemented using `umull`/`adds`/`addcs`/`subs`/`subcc` for 32-bit modular arithmetic.
- `Herradura_tests.s` — ARM Thumb-2: test_hpks (Schnorr, 20 trials) and test_hpke (El Gamal, 20 trials) added.
- `Herradura cryptographic suite.asm` — NASM i386: `gf_mul_32`/`gf_pow_32` and LCG PRNG added; `FSCX_revolve_n` removed; Schnorr and El Gamal sections using `mul`/`add`/`adc`/`sub`/`dec` for modular arithmetic.
- `Herradura_tests.asm` — NASM i386: test_hpks (Schnorr, 20 trials) and test_hpke (El Gamal, 20 trials) added.
- `Herradura cryptographic suite.ino` — Arduino: LCG PRNG added, HPKS Schnorr and HPKE El Gamal implemented.
- `Herradura_tests.ino` — Arduino: test_hpks and test_hpke replaced with Schnorr and El Gamal correctness tests.

#### Security proofs added (SecurityProofsCode/)

- `hkex_gf_test.py` — standalone HKEX-GF test suite (GF arithmetic, DH correctness 5K, Eve resistance 5K, BSGS DLP illustration, benchmarks).
- `hkex_cy_test.py` — FSCX-CY exhaustive analysis (non-linearity, HKEX-CY failure, period explosion, Eve resistance).

#### Files removed

- `Herradura_KEx.c` — basic HKEX-only C implementation (superseded by the full suite).
- `Herradura_KEx.go` — basic HKEX-only Go implementation (superseded by the full suite).
- `Herradura_KEx.py` — basic HKEX-only Python implementation (superseded by the full suite).
- `Herradura_KEx_bignum.c` — arbitrary-precision HKEX using GNU MP (superseded by the full suite with GF arithmetic).
- `HKEX_arm_linux.s` — basic HKEX-only ARM assembly example (superseded by `Herradura cryptographic suite.s`).
- `Herradura_AEn.c` — HAEN asymmetric encryption (deprecated since v1.0; superseded by HSKE).
- `HAEN.asm` — HAEN in NASM i386 assembly (deprecated).
- `FSCX_HAEN1.ino` — Arduino HAEN proof of concept (16-bit; deprecated).
- `FSCX_HAEN1_ulong.ino` — Arduino HAEN proof of concept (32-bit; deprecated).

#### Repository reorganised

- `CryptosuiteTests/` folder created. All `Herradura_tests.*` source files moved here.
- `CryptosuiteTests/go.mod` added (`module herradurakex/tests`, no external dependencies).
- The repository now contains only: cryptographic suite implementations, their tests, and security proof code/documentation.

#### Documentation updated

- `README.md` — rewritten for v1.4.0: HKEX-GF protocol description, Schnorr/El Gamal protocol summary, updated build instructions and performance table, repository structure diagram.
- `CLAUDE.md` — updated build commands, repository structure, and protocol stack description.
- `SecurityProofs.md` — Section 9 (non-linear proposals), Section 10 (v1.4.0 migration summary), Section 5.1/5.2 tables updated.
- `PQCanalysis.md` — fully revised for v1.4.0 protocols (HKEX-GF, HPKS Schnorr, HPKE El Gamal, HSKE).

#### Non-linearity and PQC analysis (SecurityProofsCode/, SecurityProofs.md §11)

This work addresses the two remaining structural weaknesses of v1.4.0:
FSCX GF(2)-linearity (linear key-recovery attacks) and the quantum vulnerability of
HKEX-GF (Shor's algorithm solves GF(2^n)* DLP).

**SecurityProofs.md §11** — NL-FSCX non-linearity and PQC extensions:
- Theorem 11: formal proof that fscx_revolve is GF(2)-affine (linear key-recovery
  attack surface) with closed-form `R·X ⊕ K·B`.
- **NL-FSCX v1** — `nl_fscx(A,B) = fscx(A,B) ⊕ ROL((A+B) mod 2^n, n/4)`: integer
  carry injection breaks GF(2) linearity; verified non-bijective (collisions at n=8
  and n=32); no consistent period.
- **NL-FSCX v2** — `nl_fscx_v2(A,B) = fscx(A,B) + ROL(B·⌊(B+1)/2⌋ mod 2^n, n/4)`:
  B-only offset; bijective (0/256 non-bijective at n=8); exact closed-form inverse
  `A = B ⊕ M⁻¹((Y − δ(B)) mod 2^n)`; verified correct 1000/1000.
- **HSKE-A1** (counter mode, v1) and **HSKE-A2** (revolve mode, v2) constructions.
- Theorem 12: m(x) = 1+x+x^{n-1} is invertible in Z_q[x]/(x^n+1); ‖m⁻¹‖_1 >> q
  (dense inverse amplifies rounding noise; naive algebraic attack 0/200 for all p).
- **HKEX-RNL** (B2): PQC key exchange via Ring-LWR with blinded FSCX polynomial
  `m_blind = m + a_rand`; reduces to standard Ring-LWR hardness (NIST-adjacent);
  NL-FSCX v1 used as KDF post-processor.
- **C3 hybrid** recommendation: v1 for one-way roles (KDF, HPKS commitment, counter
  HSKE); v2 for invertible roles (revolve HSKE, HPKE payload).

**SecurityProofsCode/hkex_nl_verification.py** (new) — three-part verification script:
- Q1: nl_fscx period analysis (n=8: 938/1024 no period; n=32: 500/500 no period);
  HSKE counter-mode correctness 200/200.
- Q2: negacyclic circulant matrix construction; invertibility for q ∈ {257…12289};
  algebraic attack 0/200 for all p; noise amplification analysis.
- Q3: v1 non-bijectivity (n=8: 256/256; n=32: collision A=0x4dbde3c0/A'=0x2a48fe58);
  iterative inverse divergence 500/500; v2 bijectivity + inverse 1000/1000.

**SecurityProofsCode/hkex_cfscx_preshared.py** (new) — preshared-value FSCX constructions
PS-1 through PS-5 (integer expansion); security analysis of each scheme.

**SecurityProofsCode/hkex_cfscx_twostep.py** (new) — two-step FSCX constructions with
compression/expansion; R2-CB (weakest: no S needed), R2-EC (B-cancellation proven).

**SecurityProofsCode/hkex_cfscx_intops.py** (new) — integer-operation schemes (padlock,
asymmetric, hash-like); includes AK-2 zero-matrix finding (S drops out entirely:
(I⊕R⊕R²⊕R³)=0) and PL-1 null-space finding (rank((R⊕I)·K)=2 → 25% commutativity).

**SecurityProofsCode/hkex_cfscx_compress.py** and **hkex_cfscx_blong.py** (new) —
cfscx_compress algebraic analysis and long-block construction variants.

---

## [1.3.7] - 2026-04-01

### Added — NASM i386, ARM Thumb, and Arduino implementations

Six new source files bring full HKEX + HSKE + HPKS + HPKE coverage to assembly
and embedded platforms.

#### `Herradura cryptographic suite.asm` (new — NASM i386)

- Full four-protocol suite (HKEX, HSKE, HPKS, HPKE) in NASM i386 assembly.
- Pure Linux syscall interface (`int 0x80`); no libc or `asm_io` dependency.
- 32-bit operands: `KEYBITS=32`, `I_VALUE=8`, `R_VALUE=24`.
- Fixed test values: A=0xDEADBEEF, B=0xCAFEBABE, A2=0x12345678, B2=0xABCDEF01,
  key=0x5A5A5A5A, plaintext=0xDEADC0DE.
- Build: `nasm -f elf32 … -o suite32.o && x86_64-linux-gnu-ld -m elf_i386 -o … suite32.o`
- Run: `qemu-i386 "./Herradura cryptographic suite_i386"` (or natively on x86/x86_64)

#### `Herradura_tests.asm` (new — NASM i386)

- Four correctness tests × 100 LCG-random trials each (HKEX, HSKE, HPKS, HPKE).
- LCG PRNG: Numerical Recipes constants (multiplier 1664525, addend 1013904223,
  seed 0x12345678).
- Outer loops use `dec ecx / jnz near` to avoid the ±127-byte limit of `loop`.
- All four tests verified: 100/100 passed.

#### `Herradura cryptographic suite.s` (new — GAS ARM 32-bit Thumb)

- Full four-protocol suite in ARM Thumb-2 assembly (`.cpu cortex-a7`).
- Defines both `fscx_revolve` and `fscx_revolve_n` (the existing
  `HKEX_arm_linux.s` calls `fscx_revolve_n` but never defines it).
- `.thumb_func` annotations required for ARM/Thumb interworking.
- Build: `arm-linux-gnueabi-gcc -o "Herradura cryptographic suite_arm" "Herradura cryptographic suite.s"`
- Run: `qemu-arm -L /usr/arm-linux-gnueabi "./Herradura cryptographic suite_arm"`

#### `Herradura_tests.s` (new — GAS ARM 32-bit Thumb)

- Four correctness tests × 100 LCG-random trials each (HKEX, HSKE, HPKS, HPKE).
- All four tests verified: 100/100 passed on qemu-arm.

#### `Herradura cryptographic suite.ino` (new — Arduino)

- Full four-protocol suite for Arduino (32-bit `unsigned long`).
- `Serial` output at 9600 baud; `printHex` / `printHexLine` helpers for
  zero-padded hex display.
- Compatible with boards using `unsigned long` as a 32-bit type (Uno, Nano,
  Mega, etc.).

#### `Herradura_tests.ino` (new — Arduino)

- Four correctness tests × 100 LCG-random trials each (HKEX, HSKE, HPKS, HPKE).
- Results printed over Serial; `loop()` reruns every 30 seconds.

#### `README.md`

- Updated Assembly build section with commands for the new NASM and ARM suite
  and test binaries.
- Added Arduino section with `arduino-cli` compile-check command.

---

## [1.3.6] - 2026-04-01

### Added — HPKS sign+verify correctness test across all three test files

#### `Herradura_tests.c`, `Herradura_tests.go`, `Herradura_tests.py`

- **Security test [7] — HPKS sign+verify correctness** added to all three test
  files. Each of 10 000 trials generates fresh random keys (A, B, A2, B2) and a
  random plaintext, then checks:

  ```
  C  = fscx_revolve(A, B, i)
  C2 = fscx_revolve(A2, B2, i)
  hn = C ⊕ C2
  S  = fscx_revolve_n(C2, B, hn, r) ⊕ A ⊕ P   (sign)
  V  = fscx_revolve_n(C,  B2, hn, r) ⊕ A2 ⊕ S  (verify)
  assert V == P
  ```

  Correctness follows from the HKEX equality: both sides of the shared-key
  computation equal `fscx_revolve_n(·, ·, hn, r) ⊕ A[2]`, so the XOR terms
  cancel and `V = P` holds for all valid key pairs. Expected: 10 000/10 000.

- **Benchmarks renumbered [8–12]** (were [7–11]) to accommodate the new test.

- **Version comment** updated to v1.3.6 in each test file header.

---

## [1.3.5] - 2026-04-01

### Added — README: guidance on when to use FSCX_REVOLVE vs FSCX_REVOLVE_N

#### `README.md`

- New subsection **'When to use FSCX_REVOLVE vs FSCX_REVOLVE_N'** added under
  the existing FSCX_REVOLVE_N section. Includes a per-operation reference table
  covering HKEX key setup, HKEX key derivation, HSKE, HPKS, and HPKE, with the
  function to use and the security rationale for each choice.

---

## [1.3.4] - 2026-04-01

### Fixed — SecurityProofs.md: formula corrections and HPKS₂ protocol

#### `SecurityProofs.md`

- **§1.4 nonce propagation (formula error):** Removed the unsupported claim
  "HD = r/n × n = r bits" for k = r = 3n/4. That expression was a tautology,
  not a derived result, and "HD = k" is false in general (counterexample:
  k = 3 gives HD = 4 via S₃·e₀ = e₁⊕e₂⊕e_(n-2)⊕e_(n-1)). Replaced with the
  correct statement: HD = popcount(S_k · e_j), which is deterministic, and the
  empirically confirmed result HD = n/4 for k = i = n/4 (test [6]).

- **§W4 solution count (formula error):** "n^n solutions" corrected to "2^n
  solutions". The map φ(A,B) = M^i·A + M·S_i·B is linear from GF(2)^(2n) to
  GF(2)^n; its kernel has dimension n, giving 2^n elements in every preimage.

- **§2.3 HPKS → HPKS₂ (theoretical protocol fix):** The original scheme
  S = sk_A ⊕ P trivially leaks sk_A from a single (P, S) pair. The corrected
  scheme HPKS₂ replaces the XOR with HSKE encryption of P under sk_A:

    Alice:  S = FSCX_REVOLVE_N(P, sk_A, sk_A, i)   [HSKE-encrypt]
    Bob:    V = FSCX_REVOLVE_N(S, sk_B, sk_B, r)   [HSKE-decrypt]; check V = P

  Correctness follows from HSKE (Theorem 5). The trivial key-recovery attack is
  eliminated because the coefficient of sk_A in the equation is S_i·(M+I) =
  S_i·x⁻¹(x+1)², which is a zero divisor in R_n (not a unit), so the equation
  has no unique solution for sk_A. The scheme remains GF(2)-linear in sk_A, so
  full EUF-CMA requires a non-linear primitive beyond the current suite.

- **§Summary table:** HPKS row updated to HPKS₂ with revised EUF-CMA status.

---

## [1.3.3] - 2026-03-30

### Added — HPKE performance benchmark across all three test files

#### `Herradura_tests.c`, `Herradura_tests.go`, `Herradura_tests.py`

- **Benchmark [11] — HPKE encrypt+decrypt round-trip** added to all three test
  files. Each iteration performs the full HPKE protocol cycle:
  1. Key setup: `C = fscx_revolve(A, B, i)`, `C2 = fscx_revolve(A2, B2, i)`,
     `hn = C ⊕ C2`
  2. Bob encrypts: `E = fscx_revolve_n(C, B2, hn, r) ⊕ A2 ⊕ P`
  3. Alice decrypts: `D = fscx_revolve_n(C2, B, hn, r) ⊕ A ⊕ E`

  Throughput on Raspberry Pi 5 (ARM Cortex-A76):

  | Implementation | 64-bit | 128-bit | 256-bit |
  |----------------|--------|---------|---------|
  | C (`gcc -O2`)  | — | — | 21.1 K ops/sec |
  | Go (`go run`)  | 2.80 K | 1.29 K | 0.61 K ops/sec |
  | Python 3       | 1.20 K | 604 | 303 ops/sec |

  HPKE throughput is comparable to HKEX because both require the same compute:
  2× `fscx_revolve(i)` for key setup and 2× `fscx_revolve_n(r)` for the
  encrypt/decrypt pair.

- **Version comment** added to each test file header referencing v1.3.3.

---

## [1.3.2] - 2026-03-29

### Changed — performance, readability, and cross-language structural consistency

#### All suite files (`Herradura cryptographic suite.{c,go,py}`)
- **Version headers** updated to v1.3.2; prior v1.1/v1.2 labels corrected to v1.3.

#### C — `Herradura cryptographic suite.c` and `Herradura_tests.c`
- **`ba_fscx` — fused single-pass**: ROL and ROR are now computed inline from
  adjacent bytes in a single loop, eliminating 4 temporary `BitArray` stack
  allocations and reducing 5 separate memory passes to 1.
  A `#if KEYBYTES < 2 #error` guard documents the KEYBITS ≥ 16 requirement.
- **`ba_fscx_revolve` / `ba_fscx_revolve_n` — double-buffering**: two local
  buffers alternate with `idx ^= 1`, eliminating one full `BitArray` struct
  copy per iteration step.
- **`ba_popcount` — hardware `__builtin_popcount`** (tests only): replaces the
  manual bit-shift loop; compiles to a single `POPCNT` instruction on x86-64/ARM.
- **`ba_xor_into` removed** (suite only): every call site replaced by
  `ba_xor(dst, dst, src)`, which is correct since `ba_xor` handles aliasing.
- **`ba_rol1` / `ba_ror1` removed**: rotation logic is now inlined inside
  `ba_fscx`; these helpers are no longer part of the API.

#### Go — `Herradura cryptographic suite.go` and `Herradura_tests.go`
- **`Fscx` rewritten**: replaces the parameter-shadowing style
  (`ba = ba.RotateLeft(1)`) with a direct formula expression — each of the six
  terms maps one-to-one to `A⊕B⊕ROL(A)⊕ROL(B)⊕ROR(A)⊕ROR(B)`.
- **Naming — suite file**: `Fscx_revolve` → `FscxRevolve`, `Fscx_revolve_n` →
  `FscxRevolveN`, `New_rand_bitarray` → `NewRandBitArray`; removes non-idiomatic
  underscores in exported Go names, consistent with the tests file.
- **Naming — tests file**: `New_rand_bitarray` → `newRandBitArray` (unexported).
- **Local variables in `main`**: `r_value`/`i_value` → `rValue`/`iValue`,
  `hkex_nonce` → `hkexNonce` (idiomatic Go camelCase).
- **`Popcount` — `math/bits.OnesCount8`** (tests only): replaces the manual
  bit-shift loop; compiles to a hardware popcount instruction.
- **`FlipBit` simplified** (tests only): `if cur == 0 / else` replaced by
  the one-liner `SetBit(&v, pos, v.Bit(pos)^1)`.

#### Python — `Herradura_KEx.py` (basic key-exchange demo)
- **`BitArray.rotated(n)`** added: same non-mutating rotation method as the suite
  and tests files; brings the basic demo into structural parity with those files.
- **`fscx` rewritten** using `rotated()`; no longer mutates its inputs.
- **`keybits` parameter removed** from `fscx`, `fscx_revolve`, and `fscx_revolve_n`:
  the parameter was unused in all three functions (size is carried by the
  `BitArray` object itself); callers in `main()` updated accordingly.

#### Python — `Herradura cryptographic suite.py` and `Herradura_tests.py`
- **`BitArray.rotated(n)`** — new non-mutating rotation method (both files):
  returns a new `BitArray` rotated left by `n` bits (right if `n < 0`).
  Positive and negative rotations share one method, matching `RotateLeft` in Go.
- **`fscx` rewritten** (both files): replaces the copy-then-mutate pattern
  (`a.ror(1); a.rol(2)`) with a direct expression using `rotated()`.
  No input mutation occurs — the function is now a pure transformation.
- **`BitArray.random()` classmethod added** (suite only): the suite now uses the
  same `BitArray.random(size)` interface as the tests file; `new_rand_bitarray()`
  is removed.
- **`main()` function and `if __name__ == '__main__':` guard** (suite only):
  protocol demonstration code is wrapped in `main()`, consistent with Go and C
  which have explicit entry-point functions.
- **`fscx` defined before `fscx_revolve`** (suite only): declaration order now
  matches C and Go (definition before first use).
- **Module-level constants** (suite only): `KEYBITS = 256`, `I_VALUE`,
  `R_VALUE` defined at module scope, matching the C `#define` names.

#### Not applicable — `Herradura_KEx.{c,go}`, `Herradura_KEx_bignum.c`, `HAEN.asm`, `HKEX_arm_linux.s`
The v1.3.2 optimisations do not apply to these files:
- The C and Go basic KEx files and the GMP bignum file implement FSCX via a
  bit-by-bit extraction loop (`BITX`/`BIT` helpers) rather than byte-parallel
  ROL/ROR operations, so the fused single-pass `ba_fscx` is architecturally
  inapplicable. Their `FSCX_REVOLVE` loops operate on scalar or GMP values
  with no per-step struct copy to eliminate.
- The x86 NASM and ARM assembly files are fixed instruction sequences; none of
  the language-level improvements (compiler hints, Python integer arithmetic,
  Go struct layout) apply.

---

## [1.3.1] - 2026-03-29

### Changed
- **`Herradura_tests.c`**, **`Herradura_tests.go`**, **`Herradura_tests.py`**:

  - **Test [1] (non-commutativity)**: switched from `fscx_revolve` to
    `fscx_revolve_n` with a random nonce per trial, confirming
    `FSCX_REVOLVE_N(A,B,N,n) ≠ FSCX_REVOLVE_N(B,A,N,n)` in general.
    The nonce term `T_n(N)` cancels from both sides so commutativity depends
    only on A and B; the test remains 0/10000.

  - **New test [6] — FSCX_REVOLVE_N nonce-avalanche**: flip 1 bit of the nonce
    N while keeping A and B constant and measure the output Hamming distance.
    The change equals `T_n(e_k)` where `T_n = I + L + … + L^(n-1)`, which
    is independent of A and B (deterministic, so min = max = mean).
    For `n = size/4` (i_val): `HD = size/4` exactly — 16/32/64 bits for
    64/128/256-bit parameters respectively — far above the 3-bit single-step
    FSCX diffusion.  Pass criterion: `HD ≥ size/4`.

  - **Benchmark [7]** (was [6]): FSCX throughput — unchanged.
  - **Benchmark [8]** (was [7]): renamed from *FSCX_REVOLVE throughput* to
    **FSCX_REVOLVE_N throughput**; benchmark now calls `fscx_revolve_n` with
    a random nonce.
  - **Benchmarks [9–10]** (were [8–9]): HKEX handshake and HSKE round-trip —
    unchanged, renumbered.

---

## [1.3] - 2026-03-29

### Changed
- **`Herradura_tests.c`**: replaced fixed 64-bit integers with the same `BitArray`
  type used in `Herradura cryptographic suite.c`. Default key size is now **256 bits**
  (`KEYBITS = 256`, `I_VALUE = 64`, `R_VALUE = 192`), matching the Go and Python
  test files. Added `ba_popcount`, `ba_get_bit`, and `ba_flip_bit` helpers.
  Benchmarks now run for a fixed wall-clock target (`BENCH_SEC = 1.0`) and report
  M ops/sec or K ops/sec, matching the Go test style.

  All five security tests pass at 256-bit:
  1. Non-commutativity — 0 / 10000 commutative pairs
  2. Linear diffusion  — mean exactly 3 bits per flip (min=3, max=3)
  3. Orbit period      — all periods are 256 or 128
  4. Bit-frequency     — each bit set 47–53% of the time
  5. Key sensitivity   — mean Hamming distance exactly 1 bit per A-flip

- **`Herradura cryptographic suite.c`**: replaced fixed 64-bit integers with a
  `BitArray` type — a fixed-width bit string backed by a big-endian byte array —
  matching the Python and Go implementations. Default key size is now **256 bits**
  (`KEYBITS = 256`, `I_VALUE = 64`, `R_VALUE = 192`), controlled by a single
  `#define KEYBITS` at the top of the file. All four protocols (HKEX, HSKE, HPKS,
  HPKE) and the EVE bypass tests operate on `BitArray` operands.

  `BitArray` API:
  - `ba_rand`          — fill from `/dev/urandom`
  - `ba_xor` / `ba_xor_into` — bitwise XOR (out-of-place / in-place)
  - `ba_rol1` / `ba_ror1`    — rotate left/right by 1 bit (big-endian)
  - `ba_equal`         — constant-time-style `memcmp` equality
  - `ba_print_hex`     — zero-padded hex output
  - `ba_fscx`          — Full Surroundings Cyclic XOR
  - `ba_fscx_revolve`  — iterate FSCX n times
  - `ba_fscx_revolve_n` — nonce-augmented FSCX_REVOLVE (v1.1)

  Build: `gcc -O2 -o "Herradura cryptographic suite" "Herradura cryptographic suite.c"`

---

## [1.2] - 2026-03-29

### Added
- **`Herradura cryptographic suite.c`**: C equivalent of the Go/Python cryptographic
  suites, implementing all four protocols (HKEX, HSKE, HPKS, HPKE) with
  `FSCX_REVOLVE_N` and the full EVE bypass test suite. Uses 64-bit integers
  (`uint64_t`) and `/dev/urandom` for randomness.
  Build: `gcc -O2 -o "Herradura cryptographic suite" "Herradura cryptographic suite.c"`

- **`Herradura_tests.c`**, **`Herradura_tests.py`**, **`Herradura_tests.go`**:
  Security assumption tests and performance benchmarks, self-contained (no external
  dependencies). Tests run across 64/128/256-bit operand sizes (Python and Go) and
  64-bit (C), covering:
  1. FSCX_REVOLVE non-commutativity (expected: 0 / 10000 commutative pairs)
  2. FSCX single-step linear diffusion (expected: exactly 3 bits per flip —
     consequence of FSCX being a GF(2) linear map; L = Id ⊕ ROL ⊕ ROR)
  3. Orbit period (expected: period = P or P/2 for all random inputs)
  4. Bit-frequency balance (expected: each output bit set 47–53% of the time)
  5. HKEX session key XOR construction (expected: exactly 1-bit change per
     single-bit A flip — algebraic nonce cancellation property)
  Plus benchmarks for FSCX throughput, FSCX_REVOLVE throughput, full HKEX
  handshake, and HSKE round-trip (encrypt + decrypt).

### Changed
- **`Herradura cryptographic suite.go`** and **`Herradura cryptographic suite.py`**:
  replaced external `go-bitarray` / `bitstring` library dependencies with
  self-contained `BitArray` implementations backed by `math/big.Int` (Go) and
  Python `int` (Python), eliminating all third-party runtime dependencies.

- **`go.mod`** / **`go.sum`**: removed `github.com/tunabay/go-bitarray` dependency.

### Fixed
- **`Herradura cryptographic suite.go`** line 380: `%x` format argument was `V2`
  (a variable from the HSKE section) instead of `D2` (the HKEX public value for
  the EVE HPKE test). This caused the wrong value to be printed in the Eve HPKE
  output line.

### Mathematical notes
- FSCX(A,B) = FSCX(B,A) for all A, B (the formula is symmetric under swap).
  Non-commutativity arises only in FSCX_REVOLVE, where B is held constant across
  iterations.
- For FSCX as a polynomial over GF(2): `L(x) = (1 + t + t⁻¹)x`. By the Frobenius
  endomorphism, `L^(2^k) = 1 + t^(2^k) + t^(-2^k)`, so any power-of-2 step count
  (including i_value = P/4 when P is a power of 2) always produces exactly 3-bit
  single-step diffusion.
- In the HKEX XOR construction `sk = FSCX_REVOLVE_N(C2, B, hn, r) ⊕ A`, flipping
  one bit of A changes the session key by exactly 1 bit. The nonce term
  `S_r · L^i(e_k)` cancels algebraically to zero, leaving only the direct XOR
  contribution.

---

## [1.1] - 2026

### Added
- **`FSCX_REVOLVE_N`** primitive in `Herradura cryptographic suite` (Go and Python).
  Each iteration XORs a nonce N into the result:
  ```
  result = FSCX(result, B) ⊕ N
  ```
  This converts `FSCX_REVOLVE` from a purely GF(2)-linear function to an affine
  function, breaking per-step linearity while preserving the HKEX equality and
  orbit properties. See the [FSCX_REVOLVE_N section in the README](README.md)
  for the mathematical proof.

- **Session-specific nonce derivation** (no new secrets required):
  - HKEX, HPKS, HPKE: `hkex_nonce = C ⊕ C2`, computable from the public key
    since A2 and B2 are public (C2 = fscx_revolve(A2, B2, i)).
  - HSKE: nonce = preshared key, injecting the key at every revolve step rather
    than only at the input/output boundaries.

### Changed
- `Herradura cryptographic suite.go` and `Herradura cryptographic suite.py`:
  replaced all `fscx_revolve` calls (except the initial public-value generation
  of C and C2) with `fscx_revolve_n` using the appropriate nonce.
- Copyright year ranges updated across all source files to include 2026.

---

## [1.0] - 2024

### Added
- Initial release of `Herradura cryptographic suite` (Go and Python) implementing:
  - **HKEX** – key exchange in the style of Diffie-Hellman, using `FSCX_REVOLVE`.
  - **HSKE** – symmetric key encryption: `E = fscx_revolve(P, key, i)`;
    decrypt with `P = fscx_revolve(E, key, r)`.
  - **HPKS** – public key signature (must be composed with HSKE to be secure).
  - **HPKE** – public key encryption.
  - EVE bypass test suite covering all four protocols.

---

## Earlier history

### ARM assembly example – 2023
- Added `HKEX_arm_linux.s`: HKEX in ARM 32-bit assembly for Linux (Cortex-A7,
  thumb mode), runnable via QEMU.

### Bug fixes and cleanup – 2024
- Fixed `getMax` function in the C sample (`Herradura_KEx.c`).
- General code cleanup across C implementations.

### Python HKEX refactor – 2024
- Refactored `Herradura_KEx.py` for clarity and correctness (argument parsing,
  type hints, secure random generation with `secrets.randbits`).

---

## Original samples – 2017

- `Herradura_KEx.c` – reference C implementation of HKEX (64-bit integers).
- `Herradura_KEx_bignum.c` – arbitrary-precision HKEX using GNU MP (libgmp).
- `Herradura_KEx.go` – Go HKEX sample using `math/big`.
- ~~`Herradura_AEn.c`~~ – removed in v1.4.0 (HAEN deprecated; superseded by HSKE).
- ~~`FSCX_HAEN1.ino`~~ / ~~`FSCX_HAEN1_ulong.ino`~~ – removed in v1.4.0.
- ~~`HAEN.asm`~~ – removed in v1.4.0.
