# Formal Cryptographic Analysis of the Herradura Cryptographic Suite

**Status:** Formal proof of insecurity complete; HKEX-GF fix implemented in v1.4.0.  NL-FSCX non-linearity and PQC extensions implemented in v1.5.0 (§11).  Full quantum algorithm analysis in §12 (merged from PQCanalysis.md, v1.4.1).  Deployed-parameter verification and §12.5 NL-protocol rows added in v1.5.1.  HKEX-RNL secret sampler upgraded to CBD(eta=1) in v1.5.3 (§11.4.2, §11.6).  HKEX-RNL polynomial multiplication replaced with negacyclic NTT over $\mathbb{Z}_{65537}$ in v1.5.4 (O(n log n), ~32× speedup at n=256).  Peikert 1-bit reconciliation deployed in v1.5.16 (§11.4.2, §11.6) — HKEX-RNL correctness now guaranteed.
**Last updated:** 2026-04-25 (v1.5.16)

---

> **This document has been split into two parts to avoid GitHub's per-page math rendering limit (~750 expressions).**
>
> - **Part 1 — §1–§10** (SecurityProofs-1.md): Algebraic Foundations · Protocol Analysis · Security Analysis · Quantum Attack Analysis · v1.4.0 Migration (753 math expressions)
> - **Part 2 — §11–§11.9** (SecurityProofs-2.md): Non-linearity and Post-quantum Extensions · HFSCX-256 (724 math expressions)
