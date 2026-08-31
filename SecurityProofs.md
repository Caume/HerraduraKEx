# Formal Cryptographic Analysis of the Herradura Cryptographic Suite

> **New to the suite, or landed on this page from a search or citation?** This is the
> formal proofs index — it assumes graduate-level algebra and the notation defined in
> [`docs/CRYPTOGRAPHY_BASICS.md`](docs/CRYPTOGRAPHY_BASICS.md) and
> [`docs/INTRODUCTION.md`](docs/INTRODUCTION.md). Read those first if any of the section
> titles below are unfamiliar; `docs/INTRODUCTION.md` links back into these same
> Part files at the point where each concept is introduced.

**This document has been split into eight parts to avoid GitHub's per-page math rendering limit (~750 expressions):**

- **Part 1 — §1** (SecurityProofs-1.md): Algebraic Foundations (300 math expressions)
- **Part 2 — §2–§8** (SecurityProofs-2.md): Protocol Analysis · Security Analysis · Summary Tables · Quantum Attack Analysis · Experimental Code Index (409 math expressions)
- **Part 3 — §9–§10** (SecurityProofs-3.md): Non-Linear Proposals · v1.4.0 Migration (409 math expressions)
- **Part 4 — §11–§11.8.2** (SecurityProofs-4.md): Non-linearity and Post-quantum Extensions · NL-FSCX v1/v2 · HKEX-RNL (684 math expressions)
- **Part 5 — §11.8.3–§11.8.8** (SecurityProofs-5.md): PQ Signature Options · HPKE-Stern-KEM (587 math expressions)
- **Part 6 — §11.9** (SecurityProofs-6.md): HFSCX-256-DM (131 math expressions)
- **Part 7 — §11.10–§11.13, §11.15–§11.33** (SecurityProofs-7.md): Zero-Knowledge Proof Extensions · Research-Review Sections (698 math expressions)
- **Part 8 — §11.34** (SecurityProofs-8.md): NL-FSCX v3 — Exact Row Analysis (141 math expressions)

---

<details>
<summary><b>Version history</b> (implementation status by version — expand if you need it)</summary>

**Status:** Formal proof of insecurity complete; HKEX-GF fix implemented in v1.4.0.  NL-FSCX non-linearity and PQC extensions implemented in v1.5.0 (§11).  Full quantum algorithm analysis in §6 of SecurityProofs-2.md (merged from PQCanalysis.md, v1.4.1).  Deployed-parameter verification and §6 NL-protocol rows added in v1.5.1.  HKEX-RNL secret sampler upgraded to CBD(eta=1) in v1.5.3 (§11.4.2, §11.6).  HKEX-RNL polynomial multiplication replaced with negacyclic NTT over $\mathbb{Z}_{65537}$ in v1.5.4 (O(n log n), ~32× speedup at n=256).  Peikert 1-bit reconciliation deployed in v1.5.16 (§11.4.2, §11.6) — HKEX-RNL correctness now guaranteed.  HFSCX-256 finalizer added to stern_hash in v1.6.0; domain-separation parameter added in v1.6.1.  KDF domain constant added in v1.8.0.  N=128 HPKS-Stern-F implemented in v1.8.7.  ZKP extensions (Ring-LWR Σ-protocol + NL-FSCX ZKBoo) prototyped in v1.9.4 (§11.10, SecurityProofs-7.md).  NL-FSCX v2 affine weak-key guard ported to the ARM Thumb-2, NASM i386, and Arduino targets in v1.9.144 (§11.19.2, SecurityProofs-7.md).

**Last updated:** 2026-08-03 (v1.9.144)

</details>
