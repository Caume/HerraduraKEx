# herradurakex — Java bindings (TODO #192)

A pure-Java port of the classical (v1.4.0) HerraduraKEx quartet — HKEX-GF,
HSKE, HPKS, HPKE — at n=256 bits, for JVM-based integrations. Values are
represented as `java.math.BigInteger` (always non-negative, `< 2^256`),
mirroring `"Herradura cryptographic suite.py"`'s `BitArray`/`fscx`/`gf_*`
functions rather than `herradura.h`'s constant-time C implementation:
`BigInteger` gives no constant-time guarantee regardless of how the bit
tricks are written, so there's nothing to gain from porting the C
branchless code, and the Python source is the more readable reference.

Same scope as `bindings/ffi/` (TODO #137): the classical quartet only —
NL/PQC and Stern-F protocols are out of scope for this binding.

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
- `build.sh` — compiles the package with `javac`.

## Build and run

```bash
bash bindings/java/build.sh

java -cp bindings/java herradurakex.KatVerify KAT/classical_quartet.json
java -cp bindings/java herradurakex.SelfTest
```

Both are also run by `CliTest/test_java_bindings.sh`.

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

This binding does not implement the PEM/DER codec (`HerraduraCli/codec.py`,
`herradura_codec.h`, `herradura/codec.go`) — only the raw math. A future
TODO could add PEM read/write if JVM consumers need direct CLI-key
interop rather than exchanging raw values over an existing channel.
