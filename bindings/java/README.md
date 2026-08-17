# herradurakex — Java bindings (TODO #192, #197, #198, #199)

A pure-Java port of the classical (v1.4.0) HerraduraKEx quartet — HKEX-GF,
HSKE, HPKS, HPKE — plus the NL/PQC (v1.5.0) quartet — HKEX-RNL (Ring-LWR
key exchange), HSKE-NL-A1/A2, HPKS-NL, HPKE-NL — at n=256 bits, for
JVM-based integrations. Values are represented as `java.math.BigInteger`
(always non-negative, `< 2^256`), mirroring `"Herradura cryptographic
suite.py"`'s `BitArray`/`fscx`/`gf_*`/`nl_fscx_*`/`_rnl_*` functions rather
than `herradura.h`'s constant-time C implementation: `BigInteger` gives no
constant-time guarantee regardless of how the bit tricks are written, so
there's nothing to gain from porting the C branchless code, and the Python
source is the more readable reference.

Stern-F code-based PQC, hybrid-rnl-stern, ZKP-NL/ZKP-RNL, XMSS/WOTS, OPRF,
and HCRED remain out of scope for this binding (TODO #200/#201 and
beyond).

## Files

- `herradurakex/Herradura.java` — the port: `fscx`/`fscxRevolve`,
  `gfMul`/`gfPow`, and the guarded protocol API (`hkexGfAgree`,
  `hpksSign`/`hpksVerify`, `hpkeEncrypt`/`hpkeDecrypt` — all reject a
  degenerate GF(2^n)\* public element per TODO #144/#131, mirroring the
  Python suite's `gf_pub_is_valid` guard).
- `herradurakex/KatVerify.java` — recomputes every vector in
  `KAT/classical_quartet.json` (TODO #190) using this package and
  confirms byte-identical results — cross-language proof of correctness
  independent of both the Python reference and the Go verifier
  (`KAT/verify_kat.go`).
- `herradurakex/SelfTest.java` — end-to-end round-trip smoke test with
  fresh random keys each run (HKEX-GF agreement, HSKE round-trip, HPKS
  sign/verify + tamper rejection, HPKE round-trip).
- `herradurakex/Codec.java` (TODO #197) — PEM/DER codec for the classical
  quartet's wire format: Base64 (76-char lines), PEM wrap/unwrap, and a
  minimal DER (INTEGER 0x02 / SEQUENCE 0x30) subset, byte-for-byte
  compatible with `HerraduraCli/codec.py` / `herradura_codec.h` /
  `herradura/codec.go` (including the long-form length encoding,
  0x81-0x84, TODO #190). Provides encode/decode helpers for classical
  private/public keys, HPKE ciphertexts, HPKS signatures, HSKE session
  keys, and digests.
- `herradurakex/CodecTest.java` — round-trip test for `Codec` (also
  doubles as a CLI-ish `decode-priv`/`decode-pub`/`encode-priv` tool used
  by `CliTest/test_java_codec.sh` for cross-language checks).
- `herradurakex/Hfscx256.java` (TODO #198) — NL-FSCX v1 and the
  HFSCX-256-DM hash built on it, plus the HSKE-NL-A1 `.hkx` file
  container, originally ported only far enough to give `HerraduraCli`'s
  `dgst` and `encfile`/`decfile` subcommands wire-format parity with the
  other three CLIs; `HerraduraNl` (TODO #199) reuses `nlFscxV1`/
  `nlFscxRevolveV1` from here rather than duplicating them.
- `herradurakex/HerraduraNl.java` (TODO #199) — the NL/PQC quartet: NL-FSCX
  v2 (`nlFscxV2`/`nlFscxV2Inv`/`nlFscxRevolveV2`/`nlFscxRevolveV2Inv`,
  bijective in A with an exact `M^{-1}`-based inverse), the Ring-LWR ring
  arithmetic underlying HKEX-RNL (negacyclic NTT over Z_65537 —
  `rnlPolyMul`/`rnlRound`/`rnlLift`/`rnlKeygen`/`rnlAgree`/`rnlHint`, at
  RNLQ=65537, RNLP=4096, RNLPP=4, RNLB=1), and the four protocol-level
  entry points (`hkexRnlDeriveC`/`rnlContributoryKdf` for HKEX-RNL,
  `hskeNlA1Encrypt`/`Decrypt` for counter-mode, `hskeNlA2Encrypt`/`Decrypt`
  for revolve-mode, `hpksNlSign`/`Verify`, `hpkeNlEncrypt`/`Decrypt`).
- `herradurakex/HerraduraCli.java` (TODO #198, #199) — a CLI mirroring
  `HerraduraCli/herradura.py`/`herradura_cli.c`/`herradura_cli.go`'s
  subcommand interface (`genpkey`, `pkey`, `kex`, `enc`, `dec`, `sign`,
  `verify`, `dgst`, `encfile`, `decfile`) for the classical quartet
  (`--algo hkex-gf`/`hpks`/`hpke`, plus `hske` for symmetric enc/dec) and
  the NL/PQC quartet (`--algo hkex-rnl`/`hske-nla1`/`hske-nla2`/`hpks-nl`/
  `hpke-nl`). `kex --algo hkex-rnl` is two-round, matching the other
  CLIs' convention: Bob responds first (`--our` his priv key, `--their`
  Alice's pub key) with an RNL RESPONSE PEM; Alice then completes
  (`--our` her priv key, `--their` Bob's RNL RESPONSE PEM) into a plain
  SESSION KEY PEM. PEM/DER output is byte-for-byte identical to the other
  three CLIs.
- `build.sh` — compiles the package with `javac`.

## Build and run

```bash
bash bindings/java/build.sh

java -cp bindings/java herradurakex.KatVerify KAT/classical_quartet.json
java -cp bindings/java herradurakex.SelfTest
java -cp bindings/java herradurakex.CodecTest

# CLI (TODO #198)
java -cp bindings/java herradurakex.HerraduraCli genpkey --algo hkex-gf --out alice.pem
java -cp bindings/java herradurakex.HerraduraCli pkey --in alice.pem --pubout --out alice_pub.pem
```

These are also run by `CliTest/test_java_bindings.sh` /
`CliTest/test_java_codec.sh` / `CliTest/test_java_keygen.sh` /
`CliTest/test_java_interop.sh` / `CliTest/test_java_nl_interop.sh` (the
last three cross-check the CLI against the Python CLI in both directions
— `test_java_nl_interop.sh` covers the NL/PQC quartet, TODO #199).

## Usage sketch

```java
import herradurakex.Herradura;
import java.math.BigInteger;
import java.security.SecureRandom;

SecureRandom rng = new SecureRandom();

// HKEX-GF
BigInteger alicePriv = new BigInteger(Herradura.N, rng).and(Herradura.MASK);
BigInteger alicePub  = Herradura.hkexGfPubkey(alicePriv);
// ... exchange pubs with Bob, then:
BigInteger shared = Herradura.hkexGfAgree(alicePriv, bobPub);

// HPKS
Herradura.Signature sig = Herradura.hpksSign(msg, alicePriv, rng);
boolean ok = Herradura.hpksVerify(msg, alicePub, sig.r, sig.s);
```

## Interop with the other language implementations

`Herradura` values are big-endian 256-bit unsigned integers, same as the
suite's `BitArray` and `herradura.h`'s `KEYBYTES`-byte arrays. To
exchange values with the Python/C/Go/PEM-based CLI:

```java
byte[] bytes = value.toByteArray(); // may have a leading 0x00 sign byte or be short — normalize to 32 bytes
```

`herradurakex.Codec` (TODO #197) now implements PEM/DER key, ciphertext,
and signature read/write for the classical quartet, so JVM consumers can
exchange key/ciphertext/signature files directly with the Python/C/Go
CLIs (`CliTest/test_java_codec.sh` cross-checks both directions).
`herradurakex.HerraduraCli` (TODO #198, #199) is a full CLI on top of that
— `CliTest/test_java_interop.sh` / `CliTest/test_java_nl_interop.sh`
cross-check it against the Python CLI in both directions for every
subcommand, including HKEX-RNL's two-round handshake (Java responding to
a Python initiator, and vice versa).
