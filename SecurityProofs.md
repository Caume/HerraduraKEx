# Formal Cryptographic Analysis of the Herradura Cryptographic Suite

**Status:** Formal proof of insecurity complete; HKEX-GF fix implemented in v1.4.0.  NL-FSCX non-linearity and PQC extensions implemented in v1.5.0 (§11).  Full quantum algorithm analysis in §6 of SecurityProofs-1.md (merged from PQCanalysis.md, v1.4.1).  Deployed-parameter verification and §6 NL-protocol rows added in v1.5.1.  HKEX-RNL secret sampler upgraded to CBD(eta=1) in v1.5.3 (§11.4.2, §11.6).  HKEX-RNL polynomial multiplication replaced with negacyclic NTT over $\mathbb{Z}_{65537}$ in v1.5.4 (O(n log n), ~32× speedup at n=256).  Peikert 1-bit reconciliation deployed in v1.5.16 (§11.4.2, §11.6) — HKEX-RNL correctness now guaranteed.  HFSCX-256 finalizer added to stern_hash in v1.6.0; domain-separation parameter added in v1.6.1.  KDF domain constant added in v1.8.0.  N=128 HPKS-Stern-F implemented in v1.8.7.  ZKP extensions (Ring-LWR Σ-protocol + NL-FSCX ZKBoo) prototyped in v1.9.4 (§11.10, SecurityProofs-5.md).
**Last updated:** 2026-08-03 (v1.9.143)

---

> **This document has been split into five parts to avoid GitHub's per-page math rendering limit (~750 expressions).**
>
> - **Part 1 — §1–§8** (SecurityProofs-1.md): Algebraic Foundations · Protocol Analysis · Security Analysis · Quantum Attack Analysis · Experimental Code Index (551 math expressions)
> - **Part 2 — §9–§10** (SecurityProofs-2.md): Non-Linear Proposals · v1.4.0 Migration (363 math expressions)
> - **Part 3 — §11–§11.8.2** (SecurityProofs-3.md): Non-linearity and Post-quantum Extensions · NL-FSCX v1/v2 · HKEX-RNL (580 math expressions)
> - **Part 4 — §11.8.3–§11.9.11** (SecurityProofs-4.md): PQ Signature Options · HFSCX-256-DM (716 math expressions)
> - **Part 5 — §11.10–§11.13, §11.15–§11.19** (SecurityProofs-5.md): Zero-Knowledge Proof Extensions · Research-Review Sections (639 math expressions)
