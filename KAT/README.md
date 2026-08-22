# KAT — Known-Answer-Test Vectors (TODO #190, #226)

Fixed, versioned test vectors for the classical (v1.4.0) HerraduraKEx
quartet — HKEX-GF, HSKE, HPKS, HPKE — in the spirit of NIST CAVP `.rsp`
files: deterministic inputs and outputs that a third-party
reimplementation can check against without depending on this repo's own
`CryptosuiteTests`/`CliTest` harness.

## Files

- `hkex_rnl.json` — HKEX-RNL Ring-LWR handshake vectors (TODO #226), at
  the deployed `n=1024` and at `n=64`. See the section below.
- `classical_quartet.json` — the vectors themselves, at n=256 bits.
  Every integer field is lowercase hex, zero-padded to 64 digits (256
  bits), with no `0x` prefix.
- `generate_kat.py` — the reference generator (Python). Re-running it
  must reproduce `classical_quartet.json` byte-for-byte; there is no
  randomness anywhere in the script. Run with `--check` to verify the
  checked-in file is still current instead of regenerating it.
- `verify_kat.go` — an independent cross-check that recomputes every
  vector using the `herradura` Go package (not the Python reference that
  generated the file) and confirms byte-identical results.

## Vector semantics

All four vector sets share `n=256` and the field's primitive polynomial
`poly` (`GF_POLY[256]` in the suite sources). `i_steps`/`r_steps` — where
present — are the FSCX revolve counts `n/4` and `3n/4` per CLAUDE.md's
protocol stack.

- **`hkex_gf`**: `alice_priv`, `bob_priv` are the two parties' private
  scalars; `alice_pub = g^alice_priv`, `bob_pub = g^bob_priv`;
  `shared_secret = bob_pub^alice_priv = alice_pub^bob_priv` (DH
  agreement over GF(2^256)*, generator `g=3`).
- **`hske`**: `ciphertext = fscx_revolve(plaintext, key, i_steps)`;
  decrypting is `fscx_revolve(ciphertext, key, r_steps) == plaintext`.
- **`hpks`**: a Schnorr signature. `pub = g^priv`; `R = g^ephemeral_k`;
  `s = (ephemeral_k - priv * e) mod (2^256 - 1)` where
  `e = fscx_revolve(R, message, i_steps)`. A verifier recomputes `e` from
  `(R, message)` and checks `g^s * pub^e == R`.
- **`hpke`**: El Gamal + fscx_revolve hybrid encryption. `recipient_pub
  = g^recipient_priv`; `R = g^ephemeral_r`; `enc_key =
  recipient_pub^ephemeral_r`; `ciphertext = fscx_revolve(plaintext,
  enc_key, i_steps)`. A recipient recomputes `dec_key =
  R^recipient_priv` (equal to `enc_key` by DH) and decrypts with
  `fscx_revolve(ciphertext, dec_key, r_steps)`.

## HKEX-RNL vectors (`hkex_rnl.json`, TODO #226)

Two full two-party handshakes: `deployed` at the shipping ring dimension
`n=1024` (TODO #223) and `small_ring` at `n=64`, which exercises the path
where the ring dimension and the derived key width coincide.

The deployed samplers draw from `os.urandom`, so the secrets here come
from a deterministic expansion instead — HFSCX-256 in counter mode over a
fixed label. **A KAT fixes the randomness as an input** and pins the
deterministic parts: ring multiplication, rounding, reconciliation, hint
packing, and the session KDF.

- `m_blind` = `m(x) + a_rand`, packed 4 bytes per coefficient.
- `alice_s` / `bob_s` are the CBD(1) secrets, 4 bytes per coefficient.
- `alice_C` / `bob_C` = `round_p(m_blind * s)`, 2 bytes per coefficient —
  the same packing the PEM codec uses, so a vector can be compared
  against wire bytes directly.
- `hint` is the *transmitted* hint: `hint_coefficients` = `n/2` two-bit
  values, 4 per byte, LSB-first within each byte.
- `k_raw` is the reconciled key at `key_bits`, and `session_key` is
  `NL-FSCX-v1(ROL(k_raw, KEYBITS/8) XOR _RNL_KDF_DC_256, k_raw,
  KEYBITS/4)`. `session_key` is `null` for `small_ring`, where the
  derived key is narrower than `KEYBITS`.

**What these vectors do not cover.** They pin the suite layer, not the
CLI layer: PEM/DER field layout, which field carries `n`, and the
key-width a response PEM is read at are all outside them. That matters,
because most of the bugs TODO #223 shipped and CI later caught lived in
exactly that CLI layer — these vectors would have caught a divergence in
`rnl_poly_mul`, `rnl_round`, the hint packing or the KDF, but not
`loadKey` reading a ring dimension as a key width. Wire-format-level
vectors are a separate, still-open gap.

The Stern-based variants (HPKS-NL/Stern-F, HPKE-NL/Stern-F/Stern-KEM) and
HSKE-NL remain uncovered, awaiting a compact fixed-vector representation
for QC-MDPC parity-check matrices and Stern commitments.

## Regenerating / verifying

```bash
# Regenerate (reference, Python) — must produce a byte-identical file:
python3 KAT/generate_kat.py --check

# Cross-check against the independent Go implementation:
go run KAT/verify_kat.go
```

Both are also run by `CliTest/test_kat_vectors.sh`.
