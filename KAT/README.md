# KAT — Known-Answer-Test Vectors (TODO #190)

Fixed, versioned test vectors for the classical (v1.4.0) HerraduraKEx
quartet — HKEX-GF, HSKE, HPKS, HPKE — in the spirit of NIST CAVP `.rsp`
files: deterministic inputs and outputs that a third-party
reimplementation can check against without depending on this repo's own
`CryptosuiteTests`/`CliTest` harness.

## Files

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

NL/PQC and Stern-based variants (HKEX-RNL, HSKE-NL, HPKS-NL/Stern-F,
HPKE-NL/Stern-F/Stern-KEM) are not yet covered — left for a follow-up
once a similarly compact fixed-vector representation is worked out for
their larger key/ciphertext material (Ring-LWR polynomials, QC-MDPC
parity-check matrices, Stern commitments).

## Regenerating / verifying

```bash
# Regenerate (reference, Python) — must produce a byte-identical file:
python3 KAT/generate_kat.py --check

# Cross-check against the independent Go implementation:
go run KAT/verify_kat.go
```

Both are also run by `CliTest/test_kat_vectors.sh`.
