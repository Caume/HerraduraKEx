# HerraduraKEx — Open TODO Items

> **Completed, deprecated, and acknowledged items have moved to [`TODO_DONE.md`](TODO_DONE.md) (TODO #154).** This file holds only entries with `Status: **OPEN**`. Item numbers are global and preserved across both files — when an item here is completed, move its whole entry to the end of `TODO_DONE.md` and update its Status line, per CLAUDE.md's TODO policy.

---

## Open items

### 171. Add `CRYPTOGRAPHY_BASICS.md` — cryptography fundamentals primer for recent graduates (Documentation, Medium)

Create `docs/CRYPTOGRAPHY_BASICS.md` covering the cryptography concept basics and fundamentals underlying the suite's components (modular/finite-field arithmetic, GF(2^n)* structure, XOR/linear maps and periodic orbits, Diffie-Hellman key exchange, discrete-log hardness, symmetric vs. asymmetric encryption, digital signatures, Schnorr identification/signature scheme, El Gamal encryption, hash-based commitments, zero-knowledge proofs, lattice/LWE-style noise arguments, syndrome decoding/code-based cryptography), including formal notation used throughout `SecurityProofs-*.md` and `docs/TUTORIAL.md` (e.g. ⊕, ROL/ROR, g^a, mod (2^n − 1), Σ-protocol notation). The goal is a self-contained prerequisites document that prepares a recent graduate of most STEM/CS-adjacent backgrounds (not necessarily a cryptography specialist) to read and understand `docs/TUTORIAL.md`, `docs/INTRODUCTION.md`, and `SecurityProofs-1.md` through `SecurityProofs-5.md` without needing outside references. Link it from `docs/TUTORIAL.md` and `README.md`'s docs section once written. Follow `SecurityProofsCode/KATEX_RULES.md` for any math notation rendered as KaTeX.

Status: **OPEN**
