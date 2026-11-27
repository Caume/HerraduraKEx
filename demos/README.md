# 32-bit demos: one program per algorithm

The ARM Thumb-2, NASM i386 and Arduino targets each run every protocol at
KEYBITS = 32, one small program per algorithm (TODO #425).  None is
interactive.  Each runs one whole operation and prints its inputs, every
intermediate and its verdict, through the shared `[FAIL]` gate:
- key exchange: both parties' keys and the shared secret;
- encryption: plaintext, ciphertext, decryption;
- signatures and proofs: sign or prove, verify, and the same verifier refusing
  what it must.

The message, plaintext and keys of the classical demos are fixed sample values
(`a_priv`, `b_priv`, `key`, `plain`).  Nonces and secrets are drawn from each
target's LCG: ARM and i386 seed it from `/dev/urandom`, and the Arduino starts
it from a fixed value.  **DEMO ONLY**: 32-bit parameters have no security.  The
64-, 128- and 256-bit suites are the C, Go, Python and Java ports.

| layout | shared code | one program |
|---|---|---|
| `arm/` | `core.s`, included by each program (`.include "core.s"`) | `<name>.s` → `<name>_arm` |
| `i386/` | `core.asm`, included by each program (`%include "core.asm"`) | `<name>.asm` → `<name>_i386` |
| `arduino/` | the `Herradura32` library, `libraries/Herradura32/src/Herradura32.h` | `<name>/<name>.ino` → `<name>/<name>_avr.elf` |

The core is included rather than linked, so no routine is copied and none needs
an exported symbol.  Each program is a few calls into it.

```bash
./build_arm.sh      && ./run_arm.sh suite          # every ARM demo, under qemu-arm
./build_asm_i386.sh && ./run_asm_i386.sh suite     # every i386 demo, under qemu-i386
./build_arduino.sh  && ./run_arduino.sh suite      # every Arduino demo, under simavr
./run_arm.sh suite hpks hske                       # named demos only (all three runners)
```

A run fails when any demo exits non-zero, reports `[FAIL]`, or never prints the
OK line.  In the Arduino IDE, copy `arduino/libraries/Herradura32` into your
sketchbook's `libraries/` folder and open any `arduino/<name>/<name>.ino`.

| program | algorithm | what it shows |
|---|---|---|
| `hkex_gf` | HKEX-GF key exchange | both public keys and the shared secret |
| `hske` | HSKE symmetric encryption | plaintext, ciphertext, decryption |
| `hpks` | HPKS Schnorr signature | nonce, R, e, s and the check; then (R, s) refused for another message |
| `hpke` | HPKE El Gamal encryption | R, ciphertext, decryption |
| `hske_nl_a1` | HSKE-NL-A1 counter-mode encryption | nonce, ciphertext, decryption |
| `hske_nl_a2` | HSKE-NL-A2 revolve-mode encryption | ciphertext, decryption |
| `hkex_rnl` | HKEX-RNL Ring-LWR key exchange | both session keys; Eve's random guess refused |
| `hpks_nl` | HPKS-NL Schnorr signature | R, s and the check; then (R, s) refused for another message |
| `hpke_nl` | HPKE-NL El Gamal encryption | ciphertext, decryption; Eve's wrong key refused |
| `hpks_stern_f` | HPKS-Stern-F signature | key, sign, verify; Eve's altered response refused |
| `hpke_stern_f` | HPKE-Stern-F KEM | ciphertext and both KEM keys; Eve's random guess refused |
| `hpks_stern_ring` | HPKS-Stern-Ring ring signature | sign as one of two members, verify in either ring order; a changed word and another message refused |
| `zkp_rnl` | ZKP-RNL Ring-LWR Sigma proof | prove and verify knowledge of a Ring-LWR secret |
| `zkp_nl` | ZKP-NL ZKBoo proof | prove and verify an NL-FSCX v1 preimage (ZKBoo, n = 8) |
| `masked_hske` | Masked HSKE | masked encryption equals the unmasked one |
| `ratchet` | Ratchet | five forward-secret steps, no repeated message key |
| `fpe` | FPE | format-preserving encrypt / decrypt |
| `tweakable` | Tweakable cipher | sector / block tweak encrypt / decrypt |
| `accumulator` | Accumulator | Merkle root and a membership proof |
| `oprf` | OPRF | blind, evaluate, unblind equals the direct PRF |

The test harnesses are `CryptosuiteTests/Herradura_tests.{s,asm,ino}`
(`[1]`–`[18]`), single programs on purpose.  Numbered-test parity depends on
them.
