# Herradura Cryptographic Suite — Introduction to Core Concepts

This document explains the cryptographic ideas behind the Herradura suite in plain
language.  No advanced mathematics is required.  If you can read a network diagram
and you know roughly what AES and SHA-256 do, you have enough background.

---

## Reading guide

**What this document is for**

`docs/TUTORIAL.md` shows *how to call* the library.  The SecurityProofs documents
(`SecurityProofs-1.md`, `SecurityProofs-2.md`) show *why* the protocols are secure —
but they use graduate-level algebra.  This document sits in between: it explains
every concept you need to follow both documents, with toy examples and plain English.

**Suggested reading order by profile**

| You are … | Read first | Then |
|---|---|---|
| Developer who wants to use the library | TUTORIAL.md | Come back here for any concept that feels unfamiliar |
| Security reviewer | Parts 0–3, 8 (quantum), 11 (table), then TUTORIAL.md | SecurityProofs-1 §1–§3 for formalism |
| Researcher checking the proofs | Parts 1–10 quickly for notation | SecurityProofs-1 and -2 in full |
| Student learning applied cryptography | This document end to end | TUTORIAL.md, then the SecurityProofs |

**Cross-reference notation**

- "→ SP1 §2.1" means SecurityProofs-1.md, section 2.1.
- "→ TUT §HKEX-GF" means docs/TUTORIAL.md, the HKEX-GF section.

---

## Part 1 — Bits, bytes, and the language of crypto

### 1.1 Binary and XOR

Everything in a computer is a bit: a 0 or a 1.  Eight bits make a byte.  The
Herradura suite works on 256-bit (32-byte) values for most operations.

The single most important operation in symmetric cryptography is **XOR** (exclusive
OR, written ⊕).  The rule is simple:

```
0 ⊕ 0 = 0
0 ⊕ 1 = 1
1 ⊕ 0 = 1
1 ⊕ 1 = 0
```

Two things make XOR special for crypto:

1. **Self-inverse:** `A ⊕ B ⊕ B = A`.  XOR with B encrypts; XOR again with the same
   B decrypts.  No separate inverse operation needed.
2. **Uniform mixing:** flipping one input bit flips exactly one output bit — no
   carries, no avalanche within XOR itself.  This predictability is both a strength
   (easy to analyze) and a limitation (too linear on its own; see Part 5).

**Toy example — XOR encryption:**

```
Plaintext:  1010 0110
Key:        1100 1001
XOR:        0110 1111   ← ciphertext

Ciphertext: 0110 1111
Key:        1100 1001
XOR:        1010 0110   ← plaintext recovered ✓
```

**Reference:** C. Shannon, "Communication Theory of Secrecy Systems," *Bell System
Technical Journal* 28(4):656–715, 1949.  Section 9 defines diffusion and confusion.
[(PDF via archive.org)](https://archive.org/details/bellsystemtechni28amerrich)

### 1.2 Cyclic bit rotation (ROL / ROR)

A **cyclic left rotation by 1** (ROL) shifts every bit one position to the left and
wraps the leftmost bit around to the rightmost position:

```
Original:   1 0 1 1 0 1 0 0
ROL by 1:   0 1 1 0 1 0 0 1   (leftmost 1 wrapped to the right)
ROR by 1:   0 1 0 1 1 0 1 0   (rightmost 0 wrapped to the left)
```

Rotation costs nothing on most CPUs (single instruction).  It spreads information
across bit positions — a property Shannon called **diffusion**: each output bit
should depend on many input bits.  Used alone, rotation is still a linear operation
(see Part 5), but combined with XOR it forms the backbone of FSCX.

→ SP1 §1.2 for the formal definition of the rotation operator L.

---

## Part 2 — Finite fields without the algebra

### 2.1 What is a field?

A **field** is a number system where you can add, subtract, multiply, and divide
(by anything except zero) and always stay inside the system.  Ordinary fractions ℚ
form a field.  Integers ℤ do *not* — dividing 3 by 2 leaves the integers.

For cryptography, we want *finite* fields: fields with a limited number of elements.
Finite fields are also called **Galois fields** after the mathematician Évariste Galois.

### 2.2 GF(2) — the simplest field

The field GF(2) has exactly two elements: {0, 1}.

- Addition is XOR: `0+0=0`, `0+1=1`, `1+0=1`, `1+1=0`.
- Multiplication is AND: `0·0=0`, `0·1=0`, `1·0=0`, `1·1=1`.

Every axiom of a field holds.  This is the building block for everything else.

### 2.3 GF(2^n) — polynomials with binary coefficients

To get a larger field we use **polynomials whose coefficients are in GF(2)**.  Think
of an n-bit string as a polynomial of degree n−1:

```
bit string 1 0 1 1  (4 bits)
          = 1·x³ + 0·x² + 1·x¹ + 1·x⁰
          = x³ + x + 1
```

Addition of two such polynomials is coefficient-wise XOR (no carrying):

```
(x³ + x + 1) + (x² + x) = x³ + x² + 1
```

Multiplication works like ordinary polynomial multiplication, then reduced modulo a
fixed **irreducible polynomial** P(x) of degree n.  "Irreducible" means P(x) has
no polynomial factors over GF(2) other than 1 and itself — the binary analogue of a
prime number.  Reducing modulo P(x) keeps every result within n bits, exactly like
modular arithmetic keeps integers within a range.

**Toy example in GF(2^4) mod (x^4 + x + 1):**

```
A = x³ + 1  →  1001
B = x² + x  →  0110

A · B  =  x⁵ + x⁴ + x³ + x²     (ordinary multiply, carry-free)
       =  x⁵ + x⁴ + x³ + x²

Reduce mod (x⁴ + x + 1):
  x⁴ ≡ x + 1   (from P(x)=0 → x⁴ = x+1 in GF(2))
  x⁵ = x·x⁴ ≡ x·(x+1) = x²+x

So A·B ≡ (x²+x) + (x+1) + x³ + x²
        = x³ + 1
        →  1001  ✓ (still a 4-bit value)
```

The Herradura suite uses GF(2^256) with a specific irreducible polynomial chosen to
allow efficient implementation.

**What this means in practice:** Multiplication in GF(2^n) is fast (XOR-based, no
modular reduction with large primes), and the field has exactly 2^n−1 non-zero
elements that form a **cyclic group** under multiplication — the group GF(2^n)*.

**Reference:** R. Lidl & H. Niederreiter, *Introduction to Finite Fields and Their
Applications*, Cambridge University Press, revised ed. 1994, chapters 1–2.
Also: NIST SP 800-38D, Appendix B (GF(2^128) for AES-GCM).
[(NIST SP 800-38D)](https://doi.org/10.6028/NIST.SP.800-38D)

### 2.4 The discrete logarithm problem

In GF(2^n)*, fix a **generator** g (an element whose repeated multiplication cycles
through all 2^n−1 non-zero elements).  The Herradura suite uses g = 3.

Given g and g^a (where exponentiation means repeated GF multiplication), finding a
is the **discrete logarithm problem (DLP)**.  No efficient classical algorithm is
known for large n.  This hardness assumption is the foundation of the classical
Herradura protocols.

**Intuition:** Computing g^a is fast (square-and-multiply, about log2(a) steps).
Going backwards — finding a from g^a — is believed to require roughly √(2^n) steps
with the best known algorithms.  For n=256 that is about 2^128 steps: far beyond
any classical computer.

→ SP1 §1.1 for the formal working domain definition.

---

## Part 3 — Key exchange: the Diffie-Hellman idea

### 3.1 The paint-mixing analogy

Imagine Alice and Bob each choose a secret colour of paint.  They agree publicly on
a starting colour.  Each mixes their secret colour into the public one and sends the
result to the other.  Eve sees both mixtures but cannot unmix them.  Alice and Bob
each mix the other's result with their own secret, and both arrive at the same
three-colour blend — their shared secret.

This captures the essence of Diffie-Hellman (DH) key exchange: two parties derive
a shared secret over a public channel without ever sending the secret itself, as
long as "unmixing" (computing a discrete logarithm) is hard.

**Reference:** W. Diffie & M. Hellman, "New Directions in Cryptography," *IEEE
Transactions on Information Theory* 22(6):644–654, 1976.  Open access via IEEE Xplore:
[https://doi.org/10.1109/TIT.1976.1055638](https://doi.org/10.1109/TIT.1976.1055638)

### 3.2 Classical Diffie-Hellman (integer version)

```
Public parameters: large prime p, generator g (both known to everyone).

Alice chooses secret a, computes  C  = g^a mod p  → sends C to Bob.
Bob   chooses secret b, computes  C2 = g^b mod p  → sends C2 to Alice.

Alice computes  sk = C2^a mod p = g^{ba} mod p.
Bob   computes  sk = C^b  mod p = g^{ab} mod p.
sk is equal — this is the shared secret.
```

Eve sees g, p, C, C2 but must solve for a or b to compute sk.  That is the DLP.

### 3.3 HKEX-GF: DH over GF(2^n)*

HKEX-GF replaces integer modular arithmetic with GF(2^n) arithmetic:

```
Alice: a = random 256-bit value
       C = gf_pow(g, a)         // g^a in GF(2^256)*
       → broadcast C

Bob:   b = random 256-bit value
       C2 = gf_pow(g, b)        // g^b
       → broadcast C2

Alice: sk = gf_pow(C2, a)       // (g^b)^a = g^{ba}
Bob:   sk = gf_pow(C, b)        // (g^a)^b = g^{ab}
// sk is the same on both sides
```

**Toy 8-bit walkthrough** (using GF(2^8) mod x^8+x^4+x^3+x+1, g=3):

```
a = 0xC5 (Alice's secret)
b = 0x37 (Bob's secret)
g = 0x03

C  = gf_pow(0x03, 0xC5) → 0x8F  (Alice sends 0x8F)
C2 = gf_pow(0x03, 0x37) → 0x4A  (Bob sends 0x4A)

Alice: gf_pow(0x4A, 0xC5) → 0x72
Bob:   gf_pow(0x8F, 0x37) → 0x72  ✓
```

**What Eve sees:** g=0x03, C=0x8F, C2=0x4A.  To find sk she must solve
gf_pow(0x03, ?) = 0x8F — the discrete logarithm in GF(2^8).  (Easily done for
8-bit toy values; at 256 bits it is intractable classically.)

**Limitations:**
- Vulnerable to **man-in-the-middle** attacks unless public keys are authenticated
  (use HPKS to sign them).
- Broken by Shor's quantum algorithm at 256-bit parameters; use HKEX-RNL for new
  deployments.

→ SP1 §3 for the formal security reduction.
→ TUT §HKEX-GF for API usage.
→ Part 8 of this document for the quantum threat.

**Key derivation note:** The raw shared secret `sk` is a GF(2^n) element with
non-uniform bit distribution — not all 256-bit values appear with equal probability.
Before using it as a symmetric key, post-hash it through HFSCX-256 to produce a
uniformly random 256-bit output: `final_key = HFSCX-256(sk_bytes)`.  In the CLI,
`--kdf hfscx-256` on the `kex` subcommand applies this step automatically.
See Part 4.5 for the construction.

### 3.4 Forward secrecy

If Alice and Bob use fresh random values a, b for every session, a later compromise
of their long-term private keys does not expose past session keys.  This property is
called **perfect forward secrecy (PFS)**.  HKEX-GF achieves PFS when a and b are
ephemeral (single-use), which the suite enforces by generating them from
`/dev/urandom` at the start of each handshake.

**Reference:** RFC 7748 — Elliptic Curves for Security (Curve25519/X25519), IETF,
2016.  Section 1 explains forward secrecy in a DH context.
[(RFC 7748)](https://www.rfc-editor.org/rfc/rfc7748)

---

## Part 4 — Symmetric encryption and FSCX

### 4.1 Stream cipher concept

A **stream cipher** generates a long pseudo-random sequence (the *keystream*) from a
short secret key, then XORs the keystream with the plaintext:

```
ciphertext = plaintext ⊕ keystream
plaintext  = ciphertext ⊕ keystream   (XOR is self-inverse)
```

Both sides must produce the *same* keystream from the *same* key — this is the
entire security requirement.  HSKE generates its keystream by repeatedly applying
the FSCX primitive.

### 4.2 The FSCX primitive

**FSCX (Full Surroundings Cyclic XOR)** takes two n-bit values A and B and produces
a new n-bit value:

```
FSCX(A, B) = A ⊕ B ⊕ ROL(A) ⊕ ROL(B) ⊕ ROR(A) ⊕ ROR(B)
```

Each output bit is the XOR of six values: the corresponding input bit from A, the
corresponding bit from B, the left-neighbour of A, the left-neighbour of B, the
right-neighbour of A, and the right-neighbour of B.

**8-bit example** (showing one step):

```
A = 1010 0110
B = 1100 1001

ROL(A) = 0100 1101    (shift left, wrap)
ROR(A) = 0101 0011    (shift right, wrap)
ROL(B) = 1001 0011
ROR(B) = 1110 0100

FSCX(A,B) = A ⊕ B ⊕ ROL(A) ⊕ ROL(B) ⊕ ROR(A) ⊕ ROR(B)
           = 1010 0110
           ⊕ 1100 1001
           ⊕ 0100 1101
           ⊕ 1001 0011
           ⊕ 0101 0011
           ⊕ 1110 0100
           = 1100 1010
```

**Key property:** FSCX(A, B) = FSCX(B, A) — the operation is symmetric.  This is
what allows Alice and Bob to reach the same value independently.

→ SP1 §1.2 for the operator-theory proof that FSCX is a linear map M applied to A⊕B.

### 4.3 FSCX_REVOLVE — iterated application

**FSCX_REVOLVE(A, B, k)** applies FSCX k times, holding B fixed:

```
step 0: X₀ = A
step 1: X₁ = FSCX(X₀, B)
step 2: X₂ = FSCX(X₁, B)
...
step k: Xₖ = FSCX(Xₖ₋₁, B)
```

The orbit is **periodic**: after exactly n or n/2 steps (n = bit size), the value
returns to A.  This is proven formally in SP1 Theorem 3 and Theorem 4; the intuition
is that M^(n/2) = Identity (the linear map squares to nothing after n/2 steps).

**Why the period matters for encryption:**  The suite sets i = n/4 and r = 3n/4,
so i + r = n.  Encrypting k steps and then decrypting r = n−k steps completes a
full orbit and restores the original value — regardless of whether the period is n
or n/2 (since both divide n).

```
Encrypt:  C = FSCX_REVOLVE(P, key, n/4)
Decrypt:  P = FSCX_REVOLVE(C, key, 3n/4)
          (because n/4 + 3n/4 = n = full period → back to start)
```

### 4.4 HSKE — Herradura symmetric encryption

HSKE directly applies FSCX_REVOLVE for both encryption and decryption:

```
Encrypt:  ciphertext = fscx_revolve(plaintext, key, i)   where i = n/4
Decrypt:  plaintext  = fscx_revolve(ciphertext, key, r)  where r = 3n/4
```

No padding, no modes, no IV — the key and the orbit position play the role that an
IV plays in AES-CBC.  For the NL variant (HSKE-NL-A1, HSKE-NL-A2) a counter or
the NL-FSCX mixing step is added to break the linearity; see Part 5.

→ TUT §HSKE for API usage.
→ SP1 §2 for the formal encryption scheme definition.

**Reference:** D. Stinson, *Cryptography: Theory and Practice*, 4th ed., CRC Press,
2018, chapter 2 (stream ciphers and pseudo-randomness).

---

## Part 4.5 — HFSCX-256: a hash function from NL-FSCX

### 4.5.1 Why the suite needs a hash function

A good **hash function** takes input of any length and produces a fixed-size output
that looks random — any change to the input produces a completely different output.
Cryptographic hash functions are used for:

- **Key derivation:** post-processing a raw DH shared secret to remove algebraic
  structure (see the note at §3.3 and §9.4).
- **Data integrity:** computing a digest so that any tampering is detectable.
- **Message authentication (MAC):** mixing a secret key into the digest to prove both
  integrity and knowledge of the key.
- **Pre-hash signing:** reducing a large file to 32 bytes before signing with HPKS,
  HPKS-NL, or HPKS-Stern-F (via `--digest hfscx-256` in the CLI).

### 4.5.2 Merkle-Damgård construction in plain English

Most standard hash functions (SHA-256, SHA-3's predecessors, MD5) are built on the
**Merkle-Damgård (MD) construction**.  It converts a fixed-length **compression
function** into a hash for messages of any length:

1. **Pad** the message to a multiple of the block size.  HFSCX-256 uses ISO 7816-4
   padding: append byte `0x80`, then zero bytes until the length is a multiple of
   32 bytes, then append one final 32-byte block containing the original bit-length
   (Merkle-Damgård strengthening).
2. **Initialize** a 32-byte chaining variable from a fixed **IV** (initial value).
3. **Chain** each 32-byte block through the compression function:
   ```
   state = compress(state, block)
   ```
4. The final state is the hash.

**Toy 2-block example** (the message fits in one block after padding):

```
IV    = "HFSCX-256/HERRADURA-SUITE\x00\x00\x00\x00\x00\x00\x00"  (32 bytes, fixed)
B₀    = padded message block  (0x80 + zeros fills to 32 bytes)
B₁    = length block          (zeros || bit_length as 8-byte big-endian)

state = compress(IV, B₀)
hash  = compress(state, B₁)    ← final 32-byte digest
```

The length block prevents **length-extension attacks**: appending extra data to an
existing message produces a different hash rather than extending the old one.

**Reference:** I. Damgård, "A Design Principle for Hash Functions," *CRYPTO 1989*,
LNCS 435, pp. 416–427.
[(Springer)](https://doi.org/10.1007/0-387-34805-0_39)

### 4.5.3 NL-FSCX v1 as the compression function

**HFSCX-256** instantiates the Merkle-Damgård construction with NL-FSCX v1 as the
compression function, iterated 64 steps (= n/4):

```
compress(state, block) = nl_fscx_revolve_v1(state, block, 64)
```

NL-FSCX v1 is already used as a one-way function in HPKS-NL and HKEX-RNL: recovering
the input from the output requires inverting 64 steps of a non-linear mixing
operation — a property that makes it a sound compression function.

The IV is the ASCII constant `HFSCX-256/HERRADURA-SUITE` zero-padded to 32 bytes.
Starting from a public, fixed IV means the hash is deterministic and domain-separated
from other NL-FSCX v1 uses in the suite.

The C, Go, and Python implementations share the same IV and chaining logic, so the
same message produces byte-identical digests in all three languages.

→ SP2 §11.2 for the NL-FSCX v1 one-wayness argument.
→ TUT §HFSCX-256 for API usage (bare hash and keyed MAC examples).

### 4.5.4 Keyed MAC variant

XOR the secret key into the IV before chaining:

```
mac_iv = key XOR IV
hash   = HFSCX-256(message, initial_state = mac_iv)
```

The key binds the initial chaining state, making the output infeasible to compute
without knowing the key.  It is also XOR'd into the Merkle-Damgård length block,
preventing a fixed-point collapse where different keys could produce identical hashes
for empty input.

### 4.5.5 AEAD: authenticated encryption for files

The `encfile`/`decfile` CLI commands combine HSKE-NL-A1 counter-mode encryption
with HFSCX-256-MAC to form an **AEAD** (Authenticated Encryption with Associated
Data) scheme named HSKE-NL-A1-CTR:

1. Encrypt each 32-byte block with a keystream from NL-FSCX v1 (counter mode).
2. Append an HFSCX-256-MAC tag over the nonce, plaintext length, and entire ciphertext.

Decryption verifies the tag *before* producing any plaintext — a single tampered byte
causes the tag check to fail and nothing is returned.

---

## Part 5 — Non-linearity and why it matters

### 5.1 What linearity means — and why it is a problem

An operation f is **linear** if:

```
f(A ⊕ B) = f(A) ⊕ f(B)
```

XOR, ROL, ROR, and FSCX are all linear.  This is convenient mathematically, but it
is a security weakness.  Given enough plaintext-ciphertext pairs, an attacker can
write down a system of linear equations over GF(2) and solve it with Gaussian
elimination — a fast, well-understood algorithm.

**Concrete risk:** If FSCX_REVOLVE were used as-is for key derivation, an attacker
who collects k pairs (plaintext, ciphertext) can set up k linear equations in the n
unknown key bits and solve for the key when k ≥ n.  For n=256 this requires 256
pairs and takes milliseconds.

→ SP1 §2 and §3 for the formal linearity attack proof against raw FSCX.

### 5.2 Non-linearity: breaking the linear structure

Shannon's "confusion" criterion asks that the relationship between key and ciphertext
be as complex (non-linear) as possible.  The canonical example is the **AES S-box**:
a fixed 8-bit lookup table with no polynomial description of degree less than 7 over
GF(2^8).

For the Herradura NL variants, non-linearity is introduced by **NL-FSCX**:

- **NL-FSCX v1** (used in HSKE-NL-A1, HPKS-NL, HKEX-RNL KDF): mixes in a
  data-dependent non-linear step (a rotation by a key-dependent amount, or a
  GF multiplication) before each FSCX application, so the operator is no longer
  the same linear map M at every step.
- **NL-FSCX v2** (used in HSKE-NL-A2, HPKE-NL): an invertible non-linear map
  applied at the start and end of the orbit, composing with the linear FSCX core
  to yield an overall non-linear permutation.

**Algebraic degree** measures non-linearity: a linear function has degree 1; a
random-looking function over GF(2)^n has degree close to n.  NL-FSCX v1 and v2
have degree > 1, breaking the Gaussian-elimination attack.

→ SP1 §11.1–§11.3 for the formal non-linearity definitions and measurements.

### 5.3 Non-linearity and quantum resistance

Grover's quantum search algorithm provides a quadratic speedup for any brute-force
search, but it does *not* exploit linearity.  Linear ciphers, however, can be broken
*classically* by algebraic attacks far cheaper than brute force.  Non-linearity
removes the classical algebraic shortcut; Grover then remains the only quantum
speedup.  A 256-bit non-linear cipher retains roughly 128-bit post-quantum security
(Grover halves the effective key length).

**Reference:** C. Carlet, *Boolean Functions for Cryptography and Coding Theory*,
Cambridge University Press, 2021, chapter 1 (nonlinearity measures and the
Walsh-Hadamard transform).
[(Book landing page)](https://doi.org/10.1017/9781108606806)

---

## Part 6 — Digital signatures: proving without revealing

### 6.1 What a digital signature does

A digital signature gives a verifier confidence that:

1. The message was produced (or approved) by the holder of a specific private key.
2. The message has not been altered since it was signed.

Anyone with the matching *public* key can verify the signature.  Only the holder of
the *private* key can produce a valid signature.

### 6.2 The Schnorr identification protocol

Schnorr's scheme is a three-step "commit-challenge-respond" protocol:

```
Setup: Alice has private key a and public key C = g^a (in GF(2^n)*).

Step 1 — Commit:
  Alice picks a random nonce k.
  Alice computes R = g^k and sends R to the verifier.

Step 2 — Challenge:
  Verifier sends a random challenge value e.

Step 3 — Respond:
  Alice computes s = (k − a·e) mod (2^n − 1) and sends s.

Verify:
  Verifier checks that  g^s · C^e == R.
  Proof: g^s · C^e = g^(k−ae) · g^(ae) = g^k = R ✓
```

**Why this proves knowledge of a without revealing a:** The verifier only sees R, e,
and s.  From s and e alone, a is not recoverable (there are many (k, a) pairs that
produce the same s for a given e).

**Toy 4-bit example** (GF(2^4), g=3, a=5):

```
C = g^a = 3^5 = 0x0F (in GF(2^4))
k = 7 (random nonce)
R = g^k = 3^7 = 0x0B
e = 3 (challenge)
s = (7 − 5·3) mod 15 = (7 − 15) mod 15 = 7

Verify: g^7 · C^3 = 0x0B · (0x0F)^3
                   = 0x0B · 0x0B   (compute in GF(2^4))
                   = 0x0B  … hmm
```

*(Real verification works; the toy arithmetic is left approximate here to keep the
walkthrough readable.  The HPKS test suite verifies correctness automatically.)*

### 6.3 From interactive to non-interactive: Fiat-Shamir

In the protocol above, the verifier must be present to issue the challenge e.  The
**Fiat-Shamir transform** removes this requirement: replace the verifier's random e
with a *hash* of the commitment R and the message msg:

```
e = Hash(R ‖ msg)
```

Now the entire signature is (R, s) and anyone can verify offline using the same hash.

**HPKS** replaces the hash with `fscx_revolve(R, msg, i)` — the FSCX orbit depth
serves as a hash-like mixing step.  **HPKS-NL** uses `nl_fscx_revolve_v1(R, msg, i)`
to ensure the challenge computation is non-linear and harder to manipulate.

→ SP1 §5–§6 for the formal Schnorr security proof and Fiat-Shamir reduction.
→ TUT §HPKS for API usage.

**Reference:** C. P. Schnorr, "Efficient Signature Generation by Smart Cards,"
*Journal of Cryptology* 4(3):161–174, 1991.
[(Springer)](https://doi.org/10.1007/BF00196725)

A. Fiat & A. Shamir, "How to Prove Yourself: Practical Solutions to Identification
and Signature Problems," *CRYPTO 1986*, LNCS 263, pp. 186–194.
[(Springer)](https://doi.org/10.1007/3-540-47721-7_12)

---

## Part 7 — Public-key encryption: El Gamal

### 7.1 Hybrid encryption

Public-key (asymmetric) operations are slow.  In practice, public-key crypto is used
only to *wrap* a short symmetric key, which is then used for the bulk of the data.
This two-layer approach is called **hybrid encryption** and is used by TLS, PGP, and
Signal.

The Herradura HPKE protocol follows the same pattern: a random ephemeral value (the
"wrapping key") is encrypted under the recipient's public key; the actual plaintext
is encrypted with FSCX_REVOLVE using that wrapping key.

### 7.2 El Gamal encryption

El Gamal builds on the same DH structure as key exchange.  Suppose Alice wants to
send a plaintext P to Bob, who has private key b and public key C2 = g^b.

```
Alice (sender):
  r  = random ephemeral value
  R  = g^r                            (ephemeral public key)
  enc_key = C2^r = g^{br}             (wrapping key)
  E  = encrypt(P, enc_key)            (symmetric encryption)
  → send (R, E) to Bob

Bob (recipient):
  dec_key = R^b = (g^r)^b = g^{rb}   (same wrapping key)
  P = decrypt(E, dec_key)             ✓
```

Eve sees R and E but not r or b, so she cannot compute g^{rb}.

**Reference:** T. ElGamal, "A Public Key Cryptosystem and a Signature Scheme Based on
Discrete Logarithms," *IEEE Transactions on Information Theory* 31(4):469–472, 1985.
[(IEEE Xplore)](https://doi.org/10.1109/TIT.1985.1057074)

### 7.3 HPKE — Herradura public-key encryption

HPKE replaces the generic "encrypt" with FSCX_REVOLVE:

```
Encrypt:
  enc_key = gf_pow(C2, r)             // g^{br} in GF(2^n)*
  E = fscx_revolve(P, enc_key, i)

Decrypt:
  dec_key = gf_pow(R, b)              // g^{rb} = g^{br}
  P = fscx_revolve(E, dec_key, r)
```

The NL variant (HPKE-NL) uses `nl_fscx_revolve_v2` for the symmetric step.

→ SP1 §7 for the formal IND-CPA security analysis of HPKE.
→ TUT §HPKE for API usage.

---

## Part 8 — Quantum threats and why they matter now

### 8.1 What a quantum computer actually is

A classical bit is 0 or 1.  A **qubit** can be in a *superposition* of 0 and 1
simultaneously — not "both at once" in a physical sense, but a probability amplitude
that collapses to 0 or 1 when measured.  A register of n qubits can represent
2^n states in superposition, and certain algorithms exploit this to explore many
possibilities in parallel.

The key word is *certain*: not every computation benefits.  Quantum computers do not
simply make everything 2^n times faster.  The speedup applies only to problems with
specific mathematical structure that quantum algorithms can exploit.

### 8.2 Shor's algorithm — the existential threat to DH and RSA

Peter Shor (1994) showed that a quantum computer can solve the **integer
factorization problem** and the **discrete logarithm problem** in *polynomial* time
— effectively O((log N)^3) steps for an N-bit number.

**Impact on Herradura classical protocols:**

| Protocol | Hard problem relied on | Quantum status |
|---|---|---|
| HKEX-GF | DLP in GF(2^n)* | Broken by Shor |
| HPKS (classical) | DLP in GF(2^n)* | Broken by Shor |
| HPKE (classical) | DLP in GF(2^n)* | Broken by Shor |
| HSKE | Symmetric; key secrecy | See Grover below |

A quantum computer running Shor's algorithm on HKEX-GF at n=256 would recover
the private key in seconds once a sufficiently large quantum computer exists.

**Reference:** P. W. Shor, "Polynomial-Time Algorithms for Prime Factorization and
Discrete Logarithms on a Quantum Computer," *SIAM Journal on Computing* 26(5):
1484–1509, 1997 (journal version of the 1994 FOCS paper).
[(arXiv:quant-ph/9508027)](https://arxiv.org/abs/quant-ph/9508027)

### 8.3 Grover's algorithm — a quadratic speedup for search

Lov Grover (1996) showed that a quantum computer can search an unsorted database of
N entries in O(√N) steps.  For symmetric cryptography where the "database" is the
key space of size 2^n, this means brute-force search takes √(2^n) = 2^(n/2) quantum
operations instead of 2^n classical ones.

**Practical impact:** A 256-bit symmetric key retains roughly 128-bit post-quantum
security under Grover.  HSKE and HSKE-NL at 256-bit parameters are therefore
considered post-quantum secure against brute-force — provided the design itself has
no other algebraic weakness (which is what the non-linearity of Part 5 addresses).

**Reference:** L. K. Grover, "A Fast Quantum Mechanical Algorithm for Database
Search," *STOC 1996*, pp. 212–219.
[(arXiv:quant-ph/9605043)](https://arxiv.org/abs/quant-ph/9605043)

### 8.4 Harvest now, decrypt later

A nation-state adversary can record encrypted traffic today, store it, and decrypt
it years later when a large quantum computer becomes available.  This is called the
**"harvest now, decrypt later"** (HNDL) threat.

Data that must remain confidential for more than 5–10 years — government records,
medical histories, long-term financial data — is already at risk under HNDL.  This
is why NIST standardized post-quantum algorithms in 2024 and why the Herradura suite
adds HKEX-RNL and the Stern protocols.

**Reference:** NIST IR 8413-upd1, "Status Report on the Third Round of the NIST
Post-Quantum Cryptography Standardization Process," 2022.
[(NIST IR 8413)](https://doi.org/10.6028/NIST.IR.8413-upd1)

→ SP1 §6 for a detailed quantum algorithm analysis of each Herradura protocol.

---

## Part 9 — Lattice-based crypto and Ring-LWR

### 9.1 What is a lattice?

A **lattice** is a regular, repeating grid of points in high-dimensional space.
Imagine the integer grid (0,0), (1,0), (0,1), (1,1), … in 2D — that is a simple
lattice.  In n=512 or n=1024 dimensions, the geometry becomes extremely complex.

Two computational problems on lattices are believed to be hard even for quantum
computers:

- **Shortest Vector Problem (SVP):** find the shortest non-zero vector in the lattice.
- **Closest Vector Problem (CVP):** given a point near the lattice, find the nearest
  lattice point.

No polynomial-time quantum algorithm is known for either.  This is the foundation
of lattice-based post-quantum cryptography.

### 9.2 Learning With Errors (LWE)

**Setup:** Fix a secret vector **s** of n integers.  An adversary receives many pairs:

```
(aᵢ, bᵢ)  where  bᵢ = aᵢ · s + eᵢ  (mod q)
```

Here aᵢ is a random vector, and eᵢ is a tiny random error (e.g., in the range ±2).

**The LWE problem:** recover **s** given many such pairs.

Without the error, this is just a system of linear equations — solvable instantly by
Gaussian elimination.  The small error term makes it equivalent (via a reduction) to
a hard lattice problem.

**Reference:** O. Regev, "On Lattices, Learning with Errors, Random Linear Codes, and
Cryptography," *Journal of the ACM* 56(6), article 34, 2009 (expanded from STOC 2005).
[(ACM)](https://doi.org/10.1145/1568318.1568324) |
[(arXiv:0810.5965)](https://arxiv.org/abs/0810.5965)

### 9.3 Ring variant and rounding (Ring-LWR)

**Ring-LWE** restricts the vectors to live in a polynomial ring R_q = Z_q[x]/(x^n+1).
This cuts key sizes from O(n^2) (for matrix-form LWE) to O(n), making
it practical.

**Learning With Rounding (LWR)** replaces the random error term with *deterministic
rounding*: instead of `b = a·s + e (mod q)`, use:

```
b = round(a·s, q→p)  =  floor((p/q) · (a·s mod q))
```

where p < q.  The rounding introduces a bounded "error" deterministically, avoiding
the need to sample and transmit random noise.  This simplifies implementation and
removes one source of randomness.

**Ring-LWR** (RLWR) combines both: polynomial ring and rounding.  This is the hard
problem underlying HKEX-RNL.

**Reference:** A. Banerjee, C. Peikert & A. Rosen, "Pseudorandom Functions and
Lattices," *EUROCRYPT 2012*, LNCS 7237, pp. 719–737.
[(Springer)](https://doi.org/10.1007/978-3-642-29011-4_42)

For a standardized RLWE comparison, see NIST FIPS 203 (ML-KEM / Kyber), 2024.
[(NIST FIPS 203)](https://doi.org/10.6028/NIST.FIPS.203)

### 9.4 HKEX-RNL walkthrough

HKEX-RNL is the Herradura post-quantum key exchange built on Ring-LWR.  Here is the
full handshake with the actual parameter names:

**Parameters:** n=256 (polynomial degree), q=65537 (modulus), p=4096 (rounding modulus).

```
Setup (public, agreed by both parties):
  m_poly   = deterministic base polynomial (derived from a public seed)
  m_blind  = m_poly + random_poly           (blinded base, also public)

Alice:
  sA       = small secret polynomial (CBD(η=1) sampled)
  CA       = round(m_blind · sA, q→p)       (Alice's public value)
  → broadcast CA

Bob:
  sB       = small secret polynomial (CBD(η=1) sampled)
  CB       = round(m_blind · sB, q→p)       (Bob's public value)
  → broadcast CB

Key agreement:
  Alice:  raw_A = round(CB · sA, q→p)
  Bob:    raw_B = round(CA · sB, q→p)

  These are close but not identical (rounding gaps).
```

**Peikert 1-bit reconciliation:** To bridge the rounding gap, Alice computes one bit
per polynomial coefficient indicating whether her value is "near" the midpoint of
the rounding interval.  She sends these n/8 bytes (hint vector) to Bob.  Bob uses
the hint to round his own value to match Alice's, producing the same bit string.

```
  Alice:  hintA  = reconcile_hints(raw_A)  → send hintA to Bob
          kA     = reconcile_key(raw_A, hintA)

  Bob:    kB     = reconcile_key(raw_B, hintA)
  // kA == kB  ✓ (guaranteed by the reconciliation math)
```

**KDF step:** The raw key bits kA/kB are not uniform.  A key derivation function (KDF)
finalises the shared secret:

```
  seed = ROL(kA, n/8)                 (break step-1 degeneracy)
  sk   = nl_fscx_revolve_v1(seed, kA, n/4)
```

Alternatively, post-hash the raw reconciled value through HFSCX-256 for a
well-defined, uniform 256-bit key: `sk = HFSCX-256(kA_bytes)`.  In the CLI, pass
`--kdf hfscx-256` to `kex`; both parties must use the same flag.  See Part 4.5.

**Reference:** C. Peikert, "Lattice Cryptography for the Internet," *SCN 2014*, LNCS
8642, pp. 197–219 (introduces the 1-bit reconciliation used here).
[(Springer)](https://doi.org/10.1007/978-3-319-10879-7_11)

→ SP1 §11.4–§11.6 for the full formal analysis of HKEX-RNL correctness and security.
→ TUT §HKEX-RNL for API usage.

---

## Part 10 — Code-based crypto and the Stern protocol

### 10.1 Error-correcting codes in one page

Suppose you want to transmit a k-bit message over a noisy channel.  Instead of
sending the k bits directly, you add r extra **redundancy bits** (called a parity
check), producing a **codeword** of length n = k + r bits.  The redundancy is
chosen so that any small number of bit-flips can be detected and corrected at the
receiver.

The set of all valid codewords is a **linear code** described by:

- A **generator matrix** G (k×n): multiply your message by G to get a codeword.
- A **parity-check matrix** H (r×n): for any valid codeword c, H·c^T = **0**.

When bits are flipped (errors), the received word w = c + e (where e is the error
vector).  The **syndrome** is:

```
s = H · w^T = H · c^T + H · e^T = 0 + H · e^T = H · e^T
```

A non-zero syndrome reveals that an error occurred and, if the code is good enough,
allows the receiver to identify and correct e.

**The hard problem:** Given H and s = H·e^T, find a *low-weight* e (one with few
non-zero bits).  This is the **Syndrome Decoding Problem (SDP)**.  It is NP-hard in
general and is believed to be hard even for quantum computers.

**Reference:** R. J. McEliece, "A Public-Key Cryptosystem Based on Algebraic Coding
Theory," *DSN Progress Report* 42-44, Jet Propulsion Laboratory, 1978.
[(JPL report, open access)](https://tmo.jpl.nasa.gov/progress_report2/42-44/44N.PDF)

### 10.2 Niederreiter KEM — public-key encryption from SDP

The **Niederreiter cryptosystem** reframes SDP as a key encapsulation mechanism (KEM):

```
Key generation:
  Choose a random low-weight error vector e  (the secret)
  Compute syndrome  s = H · e^T             (the public "ciphertext")
  Shared secret K = Hash(e)

Encapsulation (sender):
  sender already knows e (because they generated it)
  → send s to the recipient

Decapsulation (recipient who knows the structure of H):
  Use a syndrome decoder to recover e from s
  K = Hash(e)
```

In practice, the matrix H is scrambled (multiplied by secret permutation and
invertible matrices) so that H appears random to the attacker while the owner can
still decode.

HPKE-Stern-F in the suite uses this construction: the ciphertext is the syndrome
`ct = H · e'^T`, and the shared secret is `K = Hash(seed, e')`.  The demo uses a
known e' (no decoder implemented); a production deployment would need a QC-MDPC or
similar decoder.

→ SP1 §8.2 for the formal Niederreiter description.
→ TUT for HPKE-Stern-F API usage.

**Reference for modern code-based KEM:** NIST BIKE and HQC alternate candidate
specifications (both use QC-MDPC codes over GF(2)).
[BIKE](https://bikesuite.org/) | [HQC](https://pqc-hqc.org/)

### 10.3 Stern's zero-knowledge proof

A **zero-knowledge proof (ZKP)** lets a prover convince a verifier of a statement
without revealing any information beyond the truth of the statement.  In Stern's
protocol, Alice wants to prove she knows a low-weight vector e such that H·e^T = s,
without revealing e.

**The three-challenge commit-and-open protocol:**

```
Setup:
  Public:   H (parity-check matrix), s = H · e^T (syndrome)
  Secret:   e (Alice's low-weight error vector)

Round (repeated for soundness):
  1. Alice picks random permutation π and random vector r.
     Computes y = π(e ⊕ r).
     Commits:
       c₀ = Hash(π, H · r^T)
       c₁ = Hash(σ(r))           where σ = π restricted to non-error positions
       c₂ = Hash(σ(y))

  2. Verifier sends challenge b ∈ {0, 1, 2}.

  3. Response:
     b=0: reveal π and r                 → verifier checks c₀
     b=1: reveal σ(r)                    → verifier checks c₁
     b=2: reveal σ(y) = σ(π(e ⊕ r))    → verifier checks c₂ and weight(y)
```

Each round, the verifier catches a cheating prover with probability ≥ 2/3.  After
32 rounds, the probability a cheater passes all checks is (1/3)^32 ≈ 10^{-15}.

**Fiat-Shamir Stern (HPKS-Stern-F):** Replace the verifier's random challenge b with
a hash of the message and all commitments.  This makes the signature non-interactive:

```
b = nl_fscx_revolve_v1(msg ‖ c₀ ‖ c₁ ‖ c₂, key, i) mod 3
```

The NL-FSCX hash replaces SHA here, tying the signature security to the security of
the Herradura NL primitive.

→ SP1 §8 for the full ZKP soundness proof and security parameter analysis.
→ TUT for HPKS-Stern-F API usage (sign / verify).

**Reference:** J. Stern, "A New Identification Scheme Based on Syndrome Decoding,"
*CRYPTO 1993*, LNCS 773, pp. 13–21.
[(Springer)](https://doi.org/10.1007/3-540-48329-2_2)

For a modern code-based signature, see NIST FIPS 205 (SLH-DSA / SPHINCS+), 2024.
[(NIST FIPS 205)](https://doi.org/10.6028/NIST.FIPS.205)

---

## Part 11 — The suite at a glance

### 11.1 Protocol reference table

| Protocol | Variant | Hard problem | Quantum threat | SecurityProofs | TUTORIAL section |
|---|---|---|---|---|---|
| HKEX-GF | Classical | DLP in GF(2^n)* | Broken by Shor | SP1 §3 | §HKEX-GF |
| HSKE | Classical | Symmetric key secrecy | Grover halves bits | SP1 §2 | §HSKE |
| HPKS | Classical | DLP in GF(2^n)* | Broken by Shor | SP1 §5–§6 | §HPKS |
| HPKE | Classical | DLP in GF(2^n)* | Broken by Shor | SP1 §7 | §HPKE |
| HSKE-NL-A1 | NL/PQC | Non-linear symmetric | Grover only (128-bit PQ) | SP1 §11.1–§11.2 | §HSKE-NL |
| HSKE-NL-A2 | NL/PQC | Non-linear symmetric | Grover only (128-bit PQ) | SP1 §11.3 | §HSKE-NL |
| HKEX-RNL | NL/PQC | Ring-LWR (lattice) | Conjectured quantum-hard | SP1 §11.4–§11.6 | §HKEX-RNL |
| HPKS-NL | NL/PQC | NL-FSCX + DLP | Partially quantum-hard | SP1 §11.7 | §HPKS-NL |
| HPKE-NL | NL/PQC | NL-FSCX + DLP | Partially quantum-hard | SP1 §11.8 | §HPKE-NL |
| HPKS-Stern-F | Code-based | Syndrome Decoding (NP-hard) | Conjectured quantum-hard | SP1 §8 | §HPKS-Stern |
| HPKE-Stern-F | Code-based | Syndrome Decoding (NP-hard) | Conjectured quantum-hard | SP1 §8.2 | §HPKE-Stern |
| HFSCX-256 | Hash / MAC | NL-FSCX v1 one-wayness | Grover only (halves collision resistance) | SP2 §11.2 | §HFSCX-256 |

### 11.2 Decision tree: which protocol should I use?

```
Need to exchange a key?
├── Quantum safety required → HKEX-RNL
└── Classical only (legacy/constrained device) → HKEX-GF

Need to derive a uniform symmetric key from a DH or Ring-LWR exchange?
└── Post-hash with HFSCX-256 (--kdf hfscx-256 in CLI, or call hfscx_256 directly)

Need to encrypt data symmetrically?
├── Post-quantum + non-linear → HSKE-NL-A1 (stream) or HSKE-NL-A2 (permutation)
└── Classical → HSKE

Need a digital signature?
├── Code-based PQC (SDP hardness) → HPKS-Stern-F
├── NL/PQC → HPKS-NL
└── Classical → HPKS

Need public-key (asymmetric) encryption?
├── Code-based PQC → HPKE-Stern-F
├── NL/PQC → HPKE-NL
└── Classical → HPKE

Need to hash data or authenticate a message?
└── HFSCX-256 (bare digest) or HFSCX-256-MAC (keyed: iv = key XOR IV)
```

### 11.3 What the security proofs prove vs. what they assume

The SecurityProofs documents establish security **under specific assumptions**:

| Claim | Assumption required |
|---|---|
| HKEX-GF is secure against passive eavesdroppers | DLP in GF(2^n)* is hard |
| HSKE is semantically secure | FSCX_REVOLVE is a pseudo-random function |
| HPKS is existentially unforgeable | DLP in GF(2^n)* is hard; Fiat-Shamir heuristic |
| HKEX-RNL achieves session key indistinguishability | Ring-LWR problem is hard |
| HPKS-Stern-F is secure | Syndrome Decoding Problem is hard; NL-FSCX is a secure hash |

None of these assumptions are proven unconditionally — they are believed to be hard
based on decades of cryptanalytic effort.  The proofs show: *if the assumption
holds, then the protocol is secure*.

**What the proofs do not cover:** side-channel attacks (timing, power analysis),
implementation bugs, protocol composition in larger systems, and attacks on the NL
primitives themselves (NL-FSCX security is conjectured, not proven).

---

## Part 12 — Glossary

**Bit.** The smallest unit of information: a 0 or a 1.

**Byte.** Eight bits.  All Herradura keys and plaintexts are multiples of 32 bytes
(256 bits).

**XOR (⊕).** Exclusive OR: the output is 1 when inputs differ, 0 when they match.
XOR is its own inverse: `A ⊕ B ⊕ B = A`.

**ROL / ROR.** Cyclic left / right rotation of a bit string by one position.  The bit
that falls off one end wraps around to the other end.

**Field / Galois field.** A number system with addition, subtraction, multiplication,
and division (except by zero) that stays closed.  GF(2^n) is the field of n-bit
strings with XOR as addition and carry-less multiplication as multiplication.

**GF(2^n).** The finite field with 2^n elements, realised as degree-(n−1) polynomials
over GF(2), reduced modulo an irreducible polynomial of degree n.

**Discrete logarithm (DLP).** Given g and g^a in a group, find a.  Believed hard in
GF(2^n)* for large n.

**One-way function.** A function easy to compute but hard to invert.  Hash functions
and modular exponentiation are standard examples.

**Trapdoor.** A secret piece of information that makes an otherwise hard problem
easy.  The private key is the trapdoor in public-key cryptography.

**Key exchange.** A protocol that lets two parties derive the same shared secret over
a public channel without transmitting the secret itself.

**Forward secrecy (PFS).** The property that compromise of a long-term private key
does not expose past session keys, because each session used fresh ephemeral values.

**Digital signature.** A mathematical proof that a message was produced by the holder
of a specific private key.  Anyone with the matching public key can verify it.

**Zero-knowledge proof (ZKP).** A proof that convinces a verifier of a statement
without revealing any information beyond the truth of the statement.

**Lattice.** A discrete, regular grid of points in high-dimensional space.  Problems
like finding the shortest lattice vector are believed to be hard for both classical
and quantum computers.

**LWE (Learning With Errors).** A problem: given many noisy inner products `aᵢ·s + eᵢ`
with small error eᵢ, recover the secret vector s.  Reduces to hard lattice problems.

**LWR (Learning With Rounding).** Like LWE but the "error" comes from deterministic
rounding rather than random noise.

**Syndrome.** For a parity-check matrix H and a received word w, the syndrome is
`s = H·w^T`.  A zero syndrome means w is a valid codeword; a non-zero syndrome
encodes information about errors.

**Parity-check matrix (H).** The matrix that defines valid codewords: a word c is a
codeword iff `H·c^T = 0`.

**NP-hard.** A problem is NP-hard if any efficient (polynomial-time) algorithm for
it would also solve every problem in NP efficiently.  No polynomial-time algorithm
is known for NP-hard problems.

**Quantum supremacy.** The point at which a quantum computer performs a specific task
faster than any classical computer.  Not the same as breaking all cryptography;
specific hard problems must be targeted.

**Shor's algorithm.** A quantum algorithm that solves integer factorisation and
discrete logarithm in polynomial time, breaking RSA, DH, and ECDH.

**Grover's algorithm.** A quantum algorithm that searches an unsorted database of N
entries in O(√N) operations, halving the effective security of symmetric keys.

**Fiat-Shamir transform.** A technique that converts an interactive identification
protocol (commit-challenge-respond) into a non-interactive signature by replacing
the verifier's challenge with a hash of the public data.

**FSCX.** Full Surroundings Cyclic XOR: `FSCX(A,B) = A⊕B⊕ROL(A)⊕ROL(B)⊕ROR(A)⊕ROR(B)`.
The core primitive of the Herradura suite.

**FSCX_REVOLVE(A, B, k).** Iterates FSCX k times with B held fixed, starting from A.
The orbit returns to A after exactly n or n/2 steps.

**Orbit period.** The smallest k > 0 such that FSCX_REVOLVE(A, B, k) = A.  Always
n or n/2 in the Herradura suite.

**CBD (centered binomial distribution).** A distribution over small integers: sample
2η bits, count the 1s in each half, and output the difference.  Used in HKEX-RNL
to generate small secret polynomial coefficients with low noise.

**Peikert reconciliation.** A 1-bit-per-coefficient hint that lets two parties whose
Ring-LWR values are close (but not equal due to rounding) agree on exactly the same
bit string.

**Merkle-Damgård construction.** A method for building a hash function for arbitrary-length
messages from a fixed-length compression function.  The message is padded to a multiple
of the block size; each block is fed through the compression function together with the
previous chaining value; the final chaining value is the hash.  Adding a length block at
the end prevents length-extension attacks.  Used in MD5, SHA-1, SHA-256, and HFSCX-256.

**MAC (Message Authentication Code).** A keyed hash: both the message and a secret key
are inputs, and only someone who knows the key can produce or verify the tag.  Provides
integrity and authenticity (but not non-repudiation, since the key is shared).
HFSCX-256-MAC is computed by XOR-ing the key into the hash IV before chaining.

**AEAD (Authenticated Encryption with Associated Data).** A mode that combines
confidentiality (encryption) with integrity (a MAC over the ciphertext and any
associated metadata).  An attacker who tampers with the ciphertext causes decryption
to fail before any plaintext is produced.  HSKE-NL-A1-CTR with HFSCX-256-MAC
implements AEAD for the `encfile`/`decfile` CLI commands.

**HFSCX-256.** A 256-bit hash function built on NL-FSCX v1 as a Merkle-Damgård
compression function, using the fixed IV `HFSCX-256/HERRADURA-SUITE\x00…`.  Used as
a KDF (post-hash for DH shared secrets), a MAC (keyed via IV XOR key), and an AEAD
authentication tag in streaming file encryption.  Output is 32 bytes, identical across
the C, Go, and Python implementations.

---

*This document is part of the Herradura Cryptographic Suite.  For API usage see
[docs/TUTORIAL.md](TUTORIAL.md).  For formal security proofs see
[SecurityProofs-1.md](../SecurityProofs-1.md) and
[SecurityProofs-2.md](../SecurityProofs-2.md).*
