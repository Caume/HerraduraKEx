# Cryptography Basics

This document is a prerequisites primer for readers who are not yet comfortable with
cryptography or computing fundamentals. It assumes no prior programming or math
background beyond ordinary arithmetic. If you already know what AES, SHA-256, XOR,
and finite fields are, skip straight to
[docs/INTRODUCTION.md](INTRODUCTION.md), which is written for that audience.

**TL;DR (≈15-20 min read):** Cryptography gives four guarantees — confidentiality,
integrity, authentication, non-repudiation — over a channel anyone can read. It does
this with a public **algorithm** plus a secret **key** (Kerckhoffs's principle), built
on math problems that are fast to compute one way and infeasible to reverse without
the key (**one-way functions**). This document builds up the vocabulary — bits,
modular arithmetic, finite fields, notation, threat models — needed to read
`docs/INTRODUCTION.md` and the formal `SecurityProofs-*.md` documents next.

**Who this is for:** a recent graduate of *any* field — biology, law, business,
history, engineering, or computer science — who wants to genuinely understand
`docs/TUTORIAL.md`, `docs/INTRODUCTION.md`, and the `SecurityProofs-*.md` documents
rather than just copy-pasting code. Nothing here is specific to the Herradura suite;
these are the general ideas every cryptographic system is built from.

**Reading order:**

```
CRYPTOGRAPHY_BASICS.md (this document)
        ↓
docs/INTRODUCTION.md      — same ideas, in more depth, with toy walkthroughs
        ↓
docs/TUTORIAL.md          — how to call the library
        ↓
SecurityProofs-1.md … -5.md — formal proofs, graduate-level algebra
```

---

## 1. Why cryptography exists

Cryptography solves a handful of everyday problems using math instead of trust:

- **Confidentiality** — keep a message secret from anyone except the intended
  reader. (*"Only Bob can read this."*)
- **Integrity** — detect if a message was altered in transit. (*"This is exactly
  what Alice sent, nothing was changed."*)
- **Authentication** — prove who sent a message. (*"This really came from Alice,
  not an impostor."*)
- **Non-repudiation** — prevent someone from later denying they sent a message.
  (*"Alice cannot claim she didn't sign this."*)

Every protocol in this suite (and in cryptography generally) exists to provide one
or more of these four properties over a channel that is assumed to be
**public and untrusted** — anyone can read, copy, or tamper with messages sent over
it. The entire discipline of cryptography is about achieving these guarantees
*despite* that assumption, never by assuming the channel is somehow safe.

A convention used throughout cryptography (and this codebase): the two people
communicating are named **Alice** and **Bob**, and the eavesdropper/attacker
watching or interfering with the channel is named **Eve** (or, for an active
tamperer, **Mallory**). This is just shorthand — the same letters appear in
`SecurityProofs-*.md` and the test code.

---

## 2. Secrets, keys, and algorithms

A cryptographic **algorithm** is a precise, public, step-by-step procedure —
public because hiding *how* a scheme works is not a sound security strategy (an
attacker can often work it out anyway, e.g. by studying an open-source
implementation like this one). What must stay secret is a much smaller piece of
data called a **key**.

This separation — public algorithm, secret key — is known as **Kerckhoffs's
principle**: *a cryptosystem should be secure even if everything about the system,
except the key, is public knowledge.* It is the reason this entire codebase can be
open-source while individual users' keys remain private.

```
┌─────────────────────────────┐      ┌─────────────────────┐
│  ALGORITHM (public)         │      │  KEY (secret)       │
│  e.g. "HKEX-GF: C = g^a"    │  +   │  e.g. a = 0x9F3C...  │  →  secure output
│  anyone can read the code   │      │  known only to Alice │
└─────────────────────────────┘      └─────────────────────┘
     safe to publish on GitHub            never shared, never logged
```

Security lives entirely in the right-hand box. Publishing the left-hand box (as
this whole repository does) costs nothing in security and buys independent
review — the opposite of "security through obscurity."

**Reference:** A. Kerckhoffs, "La Cryptographie Militaire," *Journal des Sciences
Militaires*, vol. IX, pp. 5–38, 1883. English translation and discussion in
F. L. Bauer, *Decrypted Secrets*, 4th ed., Springer, 2007, ch. 3.

There are two broad families of algorithms, distinguished by how keys are used:

### 2.1 Symmetric cryptography

Both parties share the **same** secret key. Alice uses it to lock (encrypt) a
message; Bob uses the identical key to unlock (decrypt) it. This is fast and
simple, but it has one hard problem: how do Alice and Bob agree on a shared key
in the first place, over a channel Eve can read?

```
Alice: ciphertext = Encrypt(plaintext, key)   → sends ciphertext
Bob:   plaintext  = Decrypt(ciphertext, key)  ← same key as Alice
```

In this suite, HSKE and its NL/PQC variants (HSKE-NL-A1, HSKE-NL-A2) are symmetric
encryption schemes.

### 2.2 Asymmetric (public-key) cryptography

Each party generates a **pair** of mathematically linked keys: a **private key**
(kept secret, never shared) and a **public key** (published openly — anyone,
including Eve, can see it). Data locked with the public key can only be unlocked
with the matching private key, and vice versa. This solves the key-agreement
problem: Alice can encrypt something for Bob using only his *public* key, which he
may have posted anywhere, without any prior shared secret.

```
Bob publishes: public_key
Bob keeps secret: private_key

Alice: ciphertext = Encrypt(plaintext, bob's public_key)
Bob:   plaintext  = Decrypt(ciphertext, bob's private_key)
```

Asymmetric operations are typically much slower than symmetric ones, so in
practice they are used only to establish a shared symmetric key or to sign a
short digest — this is called **hybrid encryption** and it is exactly how HPKE
works (see Part 7 of `docs/INTRODUCTION.md`).

In this suite, HKEX-GF/HKEX-RNL (key exchange), HPKS/HPKS-NL/HPKS-Stern-F
(signatures), and HPKE/HPKE-NL/HPKE-Stern-F (public-key encryption) are all
asymmetric.

### 2.3 Why "hard math problems" make this work

Public-key cryptography relies on **one-way functions**: operations that are
cheap to compute in one direction but, as far as anyone currently knows,
infeasible to reverse without extra secret information (the private key). A
simple everyday analogy: mixing two paint colors together is easy; figuring out
the exact two original colors from the mixture alone is essentially impossible.
Multiplying two very large prime numbers together is fast; factoring the huge
result back into those two primes is (believed to be) extremely slow. Every
security proof in this codebase ultimately rests on one such problem being
computationally hard — see Part 4 below.

**A note on which problem this codebase actually uses:** prime factoring above is
the one-way function behind RSA — it's used here only as the most widely-known
illustration of "hard to reverse." Herradura's own classical protocols (HKEX-GF,
HPKS, HPKE) do not factor anything; they rest on a *different* one-way function,
the **discrete logarithm problem** in `GF(2^n)*` — introduced in §3.3 below and
formalized in §4.2. Both are one-way functions in the same general sense, but they
are different math problems with different attacks and different post-quantum
status.

---

## 3. Numbers, bits, and "clock arithmetic"

### 3.1 Bits

Computers store everything as **bits** — values that are only ever `0` or `1`. A
group of 8 bits is a **byte**. This suite works mostly with 256-bit (32-byte)
values, chosen because at that size the "hard math problems" above are believed
to require more computing power than exists on Earth to break by brute force.

### 3.2 Modular arithmetic — "clock arithmetic"

Almost every algorithm in this codebase performs arithmetic **modulo** some
number — a concept everyone already knows from reading a clock. A 12-hour clock
"wraps around": 9 + 5 = 14, but a clock shows 2, because 14 mod 12 = 2 (you
subtract 12 until the result fits between 0 and 11).

```
14 mod 12 = 2      (14 hours after 12:00 reads as 2:00)
23 mod 7  = 2      (23 = 3×7 + 2)
```

Formally, `a mod n` is the remainder left after dividing `a` by `n`. Modular
arithmetic keeps every intermediate result inside a fixed-size range, which is
essential when working with fixed-size keys (256 bits, in this suite). You will
see expressions like `mod (2^n − 1)` throughout `SecurityProofs-*.md` — this is
exactly the clock-wraparound idea, just with a much bigger "clock face."

### 3.3 Exponents as repeated multiplication, and why direction matters

`g^a` means "multiply g by itself a times" (with wraparound applied at each
step, via modular arithmetic). Computing this forward is fast — computers use a
shortcut called *square-and-multiply* that takes only about log₂(a) steps rather
than a steps. But given only `g` and the result `g^a`, working backward to find
`a` — called the **discrete logarithm problem** — has no known fast solution for
suitably large numbers. This asymmetry (fast forward, slow backward) is the
one-way function that the classical Herradura protocols (HKEX-GF, HPKS, HPKE)
are built on. See `docs/INTRODUCTION.md` §2.4 for the full explanation, and
Part 4.2 below for the formal notation.

---

## 4. Formal notation used throughout this codebase

The plain-English descriptions above map onto a small, consistent set of symbols
used in `SecurityProofs-*.md`, `docs/INTRODUCTION.md`, and code comments. This
table is a lookup reference — you do not need to memorize it before reading on.

| Symbol / notation | Read as | Meaning |
|---|---|---|
| `⊕` | "XOR" | Bitwise exclusive-or: differs → 1, matches → 0. Its own inverse: `A ⊕ B ⊕ B = A`. |
| `ROL(A)`, `ROR(A)` | "rotate left/right" | Cyclically shift the bits of A by one position, wrapping around. |
| `mod n`, `mod (2^n − 1)` | "modulo n" | Remainder after division by n — the "clock arithmetic" wraparound (§3.2). |
| `GF(2^n)` | "Galois field of 2 to the n" | A finite number system with exactly 2^n elements where addition, subtraction, multiplication, and division (except by zero) all stay inside the system. See §4.1. |
| `GF(2^n)*` | "GF(2^n) star" | The *non-zero* elements of GF(2^n) — i.e. everything you're allowed to divide by, and the group used for exponentiation. |
| `g` | "generator" | A fixed public element whose repeated multiplication cycles through every non-zero value in the field. This suite uses g = 3. |
| `g^a` | "g to the a" | Repeated multiplication of g by itself, a times, with modular wraparound. Fast to compute forward (§3.3). |
| `a`, `b`, `k`, `r` | (lowercase, usually secret) | Private/ephemeral scalar values — someone's secret exponent or nonce. |
| `A`, `B`, `C`, `R` (uppercase) | (usually public) | Public values — ciphertexts, public keys, commitments. |
| `sk` | "shared/session key" | The secret both parties end up agreeing on after a key exchange. |
| `≡` | "is congruent to" | Equality *within* a modular system (e.g. `14 ≡ 2 (mod 12)`). |
| `∈` | "is an element of" | Set membership, e.g. `a ∈ GF(2^n)` means a is a value in that field. |
| `Σ`, `∏` | "sum", "product" | Repeated addition / multiplication over a range, exactly like Σ in a spreadsheet's `SUM()`. |
| `Pr[event]` | "probability of" | The chance an event happens, between 0 (never) and 1 (always). |
| `negl(n)` | "negligible in n" | A quantity that shrinks faster than any polynomial as n grows — cryptography's definition of "so small it doesn't matter in practice." |
| `poly(n)` | "polynomial in n" | A quantity that grows no faster than n raised to some fixed power — cryptography's definition of "computationally feasible." |
| `O(f(n))` | "big-O of f(n)" | An upper bound on how an algorithm's running time or memory use grows as the input size n grows. `O(n²)` means roughly proportional to n squared. |
| `H(·)`, `Hash(·)` | "hash of" | A one-way function producing a fixed-size, unpredictable-looking output from an input of any size. See §4.3. |
| `π`, `σ` | "permutation" | A rearrangement of a list's order — used in zero-knowledge proofs (Stern protocol) to hide which element is which. |

**What "negligible" means in practice:** breaking a 256-bit key by brute force means
trying up to `2^256` possibilities. Suppose an attacker somehow builds a computer that
tries a trillion (`10^12`) keys per second — far beyond anything that exists today.
`2^256` is about `1.16 × 10^77`. Dividing:

```
1.16 × 10^77 keys ÷ 10^12 keys/sec ≈ 1.16 × 10^65 seconds
```

The universe is about `4.3 × 10^17` seconds old (≈13.8 billion years). The attacker's
search would take roughly `10^47` times longer than the universe has existed so far —
and that's with a computer far faster than any that exists. *That* gap between
"technically possible" and "will never happen" is what `negl(n)` captures formally:
as `n` (the key size) grows, the attacker's success probability shrinks faster than
`1/poly(n)` for every polynomial, so past a modest `n` it is smaller than any
probability that matters in practice — smaller, for instance, than the chance of
guessing correctly which atom in the solar system a friend is currently thinking of.

### 4.1 Fields, in one paragraph

A **field** is any number system where you can add, subtract, multiply, and
divide (except by zero) and the result always stays inside the system — ordinary
fractions form a field; whole numbers do not (3 ÷ 2 isn't a whole number). A
**finite field** (or **Galois field**, named after the mathematician Évariste
Galois) has only a limited number of elements. `GF(2^n)` is the finite field this
suite uses; `docs/INTRODUCTION.md` §2 works through it with a full worked
example, including how "addition" here is just XOR.

### 4.2 The discrete logarithm problem, formally

Given a generator `g` and a value `C = g^a` inside `GF(2^n)*`, the **discrete
logarithm problem (DLP)** is: find `a`. This is the one hard problem behind
HKEX-GF, HPKS, and HPKE (the classical, pre-quantum protocols in this suite).
`docs/INTRODUCTION.md` §2.4 and §3.3 give worked 8-bit examples small enough to
solve by hand, to build intuition before the 256-bit "real" version becomes
intractable.

### 4.3 Hash functions, in one paragraph

A **hash function** takes an input of any length and produces a fixed-size
output (this suite uses 256 bits) that looks unpredictable and changes
completely if even one input bit changes. Hash functions are one-way — like the
paint-mixing analogy in §2.3 — and are used throughout this suite for key
derivation, message digests before signing, and Fiat-Shamir challenges (turning
an interactive proof into a signature — see `docs/INTRODUCTION.md` §6.3).
HFSCX-256 is this suite's hash function; `docs/INTRODUCTION.md` §4.5 explains its
construction in depth.

---

## 5. Attackers and threat models

Cryptography does not claim to make attacks *impossible* — it claims attacks are
**computationally infeasible**: they would require more time, memory, or money
than is realistic even for a well-resourced adversary, given today's (and, for
post-quantum schemes, tomorrow's) computers. A **threat model** states precisely
what an attacker can and cannot do; every security claim in `SecurityProofs-*.md`
is only valid under its stated threat model. Common ones you'll see:

- **Passive eavesdropper (Eve):** can read every message on the channel but
  cannot modify or inject messages. Relevant to confidentiality claims.
- **Active attacker (Mallory):** can also modify, delay, replay, or inject
  messages. Relevant to integrity and authentication claims.
- **Classical attacker:** limited to ordinary computers. Most "hard problems" in
  this document are hard *only* against classical attackers.
- **Quantum attacker:** has access to a sufficiently large quantum computer,
  which can solve some (not all) of these hard problems efficiently — see below.

### 5.1 Why "quantum-resistant" matters

A quantum computer is not simply a faster computer — it can run fundamentally
different algorithms for a small set of specific mathematical problems. **Shor's
algorithm** solves the discrete logarithm problem (§4.2) efficiently on a quantum
computer, which is why this suite's classical protocols (HKEX-GF, HPKS, HPKE)
are considered broken *once* a large enough quantum computer exists — even
though no such computer exists today, encrypted data captured now could be
stored and decrypted later ("harvest now, decrypt later"). This is why the suite
also offers NL/PQC and code-based variants (HKEX-RNL, HPKS-Stern-F, HPKE-Stern-F,
etc.) built on different hard problems believed to resist even quantum
computers. `docs/INTRODUCTION.md` Part 8 covers this in full, with references to
the original Shor and Grover papers.

---

## 6. Where to go next

You now have enough vocabulary to read `docs/INTRODUCTION.md` comfortably — it
covers every concept above in more depth, with worked toy examples small enough
to compute by hand, and connects each concept directly to a Herradura protocol.
From there, `docs/TUTORIAL.md` shows how to call the library in C, Go, and
Python, and the `SecurityProofs-*.md` documents give the full formal proofs
using the notation introduced in §4 above.

---

## 7. Glossary

**Algorithm.** A precise, public, step-by-step procedure. Contrast with *key*.

**Key.** A piece of secret (or, for public keys, published-but-linked-to-a-secret)
data that parameterizes an algorithm. See §2.

**Symmetric cryptography.** Both parties share one secret key. See §2.1.

**Asymmetric (public-key) cryptography.** Each party has a private/public key
pair; operations with one key can only be undone with its pair. See §2.2.

**Kerckhoffs's principle.** A cryptosystem should remain secure even if the
attacker knows everything about it except the key. See §2.

**One-way function.** Easy to compute forward, infeasible to reverse without
extra secret information. See §2.3.

**Bit / byte.** A 0-or-1 value; 8 bits make a byte. See §3.1.

**Modular arithmetic.** Arithmetic that "wraps around" after reaching a fixed
range, like a clock. See §3.2.

**Discrete logarithm problem (DLP).** Given g and g^a, find a. Believed hard
classically, broken by Shor's algorithm on a quantum computer. See §4.2.

**Field / Galois field / GF(2^n).** A finite number system supporting add,
subtract, multiply, and divide (except by zero). See §4.1.

**Hash function.** A one-way function mapping any-length input to a fixed-size,
unpredictable-looking output. See §4.3.

**Threat model.** A precise statement of what an attacker is assumed to be able
to do; every security claim is only valid within its stated threat model. See §5.

**Alice, Bob, Eve, Mallory.** Conventional names for the two communicating
parties, a passive eavesdropper, and an active attacker, respectively. See §1
and §5.

**Quantum computer / Shor's algorithm / Grover's algorithm.** See §5.1 and
`docs/INTRODUCTION.md` Part 8 for the full treatment.

---

*This document is part of the Herradura Cryptographic Suite. For the next level
of depth see [docs/INTRODUCTION.md](INTRODUCTION.md); for API usage see
[docs/TUTORIAL.md](TUTORIAL.md); for formal security proofs see
[SecurityProofs-1.md](../SecurityProofs-1.md) through
[SecurityProofs-5.md](../SecurityProofs-5.md).*
