# HerraduraKEx — Open TODO Items

> **Completed, deprecated, and acknowledged items have moved to [`TODO_DONE.md`](TODO_DONE.md) (TODO #154).** This file holds only entries with `Status: **OPEN**`. Item numbers are global and preserved across both files — when an item here is completed, move its whole entry to the end of `TODO_DONE.md` and update its Status line, per CLAUDE.md's TODO policy.

---

## Research review — 2025-2026 cryptanalysis and primitive developments

The following items (#156-#163) were opened from a literature review of cryptanalysis
and cryptographic-primitive research published in roughly the 12 months prior to
2026-07-31, cross-checked against this repo's existing TODO/SecurityProofs coverage so
only genuinely new angles are recorded here (constant-time auditing, rotational
differential analysis of NL-FSCX, QC-MDPC decoder trapdoors, and hybrid Ring-LWR+Stern-F
credentials were already tracked as #41/#75/#83/#123/#125/#126/#128/#129 and are not
re-opened).

### 158. Apply the 2025 automated rotational-XOR differential search framework to FSCX/NL-FSCX (Research, Medium)

**Background:** A 2025 paper proposes an automatic search framework for
rotational-XOR (RX) differential characteristics in ARX ciphers
(https://link.springer.com/article/10.1007/s10623-025-01571-6), reporting characteristics
covering more rounds than previously known for SPECK, CHAM, SPARX, and Ballet (e.g.
17-24 round RX-differentials for SPECK variants, versus a prior best of 13 rounds).

TODO #75 (`Formal rotational differential analysis of NL-FSCX v1`) and TODO #125
(`Sparse-input rotational differential characterization of NL-FSCX v1 at large n`) are
already `DONE`/tracked in `TODO_DONE.md` and cover rotational analysis of FSCX/NL-FSCX,
but both predate this specific 2025 automated-search tool. FSCX's core operator
$M = I \oplus \text{ROL} \oplus \text{ROR}$ is XOR-and-rotation (not full ARX — it has no
modular addition), so the framework's addition-centric technique doesn't transfer
directly, but its automated RX-characteristic-search *methodology* (as opposed to the
addition-specific propagation rules) may still surface longer characteristics than the
manual/semi-automated analysis TODO #75/#125 used, especially for NL-FSCX v1/v2 where the
non-linear step reintroduces addition-like mixing.

**Work items:**

1. Read the paper closely to separate its ARX-modular-addition-specific propagation
   rules from its general RX-characteristic search methodology (SAT/SMT or MILP-based
   search, if that's what it uses).
2. Determine whether the general search methodology can be adapted to FSCX's pure
   XOR-rotation operator and to NL-FSCX v1/v2's added non-linear step, reusing
   `SecurityProofsCode/fscx_periodicity_z3.py`'s existing Z3-based approach as a starting
   point if the tooling is compatible.
3. If adaptable, run the search against FSCX_N and NL-FSCX v1/v2 at the suite's actual
   parameter sizes and compare any newly found characteristics against TODO #75/#125's
   prior bounds.
4. Document results in `SecurityProofs-2.md` regardless of outcome, and add a
   `SecurityProofsCode/` script if new characteristics are found (following the existing
   naming convention, e.g. `nl_fscx_rx_differential_2025.py`).

**Progress (2026-07-31):** paper's full text is paywalled beyond its abstract, so its
exact CNF/SAT encoding couldn't be reproduced. Added
`SecurityProofsCode/nl_fscx_rx_differential_2025.py`: a bounded, non-exhaustive
hill-climbing stand-in that searches over nonzero-XOR RX-differences $(da,db)$ (not just
the pure-rotation $da=db=0$ slice TODO #75/#125 already covered) for NL-FSCX v1's
modular-addition step, since FSCX's XOR-rotation linear part transmits every RX-difference
with probability 1 and contributes no search surface. Found no configuration with a
materially higher single-round transition probability than the existing pure-rotational
baseline at $n \in \{16,32\}$. Documented in `SecurityProofs-2.md` (end of the sparse-$B$
subsection) with explicit caveats: this is local search, not exhaustive SAT, and only
covers single-round (not chained multi-round) transitions. Stays **OPEN** — reproducing
the paper's actual automated search is future work, deferred due to paywalled access.

Status: **OPEN**

### 159. LLM/AI-assisted cryptanalysis stress-testing pass across HerraduraKEx's primitives (Research/Security, Medium)

**Background:** In the review window, LLM-driven cryptanalysis moved from a research
curiosity to a credible, NIST-adjacent methodology: Anthropic's Claude discovered a real
vulnerability in HAWK, a lattice-based signature scheme that was under active
consideration for NIST standardization, leading the HAWK team to withdraw it from
consideration entirely (2026-07-28;
https://www.govinfosecurity.com/claude-mythos-finds-new-cryptographic-algorithm-attacks-a-32360).
Separately, `CryptanalysisBench` (2026; https://arxiv.org/html/2607.18538v1) benchmarks
LLMs across 191 cryptanalysis tasks spanning six primitive families drawn from four NIST
standardization competitions, and other 2025-2026 work evaluates LLM-assisted
side-channel vulnerability discovery (https://arxiv.org/html/2505.24621) and automated
cryptographic exploitation agents (https://arxiv.org/pdf/2601.09129). This is a
meaningfully different validation channel from this repo's existing
`SecurityProofsCode/` manual/scripted proofs — it found a real flaw in a scheme that had
already passed multiple rounds of expert human review.

**Work items:**

1. Scope a bounded, well-defined stress-testing pass: pick 2-3 of HerraduraKEx's less
   battle-tested constructions as targets (e.g. NL-FSCX v2's CSP-based construction,
   HPKS-Stern-Ring's OR-composition, the HFSCX-256-DM finalizer) rather than attempting
   to cover the whole suite at once.
2. Define what "stress-testing" means concretely here given available tooling — this
   could be as simple as posing the same kind of structured cryptanalysis prompts used in
   `CryptanalysisBench`/the HAWK finding against this suite's own primitive definitions
   and existing `SecurityProofsCode/` proof scripts, to see whether an LLM surfaces gaps
   the existing manual proofs missed.
3. Treat any finding as a lead requiring the same manual verification standard as any
   other TODO in this file (a `SecurityProofsCode/` script reproducing it, not just an
   LLM's claim) before it's considered confirmed — mirroring how CryptanalysisBench's own
   authors note LLMs "fail comprehensively at algorithm-level cryptanalysis" in the
   general case, so a hit rate of zero is an expected, valid outcome here too.
4. Document the pass and its outcome (findings or a clean bill of health) in
   `SecurityProofs-2.md` or a new `SecurityProofsCode/` note, so this doesn't need
   re-justifying from scratch next time it comes up.

**Progress (2026-07-31) — first pass complete, one real finding.** Scoped the pass to
HPKS-Stern-Ring's OR-composition (herradura.h `stern_ring_sign`, the Python/Go suite
equivalents) as the target — the "less battle-tested" construction named in work item 1.
Reading `stern_ring_sign`'s non-signer challenge simulation against the joint
Fiat-Shamir challenge derivation surfaced a genuine, previously-undocumented modulo-3
bias: the C and Python implementations draw a single random byte and reduce mod 3 to
pick each non-signer's per-round challenge (256 is not divisible by 3, so residue 0 is
~0.39% overrepresented), while the real signer's own displayed challenge is forced by
subtraction from a hash-derived, effectively-uniform joint challenge — meaning the
signer's slot has an exactly-uniform marginal while every non-signer's slot carries the
skew. This is a statistical anonymity leak under repeated use of the same ring (not a
one-shot break): `SecurityProofsCode/stern_ring_challenge_bias.py` (added this pass)
verifies the exact 86/85/85-out-of-256 distribution, confirms it by Monte Carlo, and
estimates ~9,000+ same-ring signatures needed before the skew is statistically
distinguishable per slot at 3-sigma confidence. Per work item 3, this is filed as its own
actionable item — **TODO #164** — rather than treated as fixed here, since #159 is a
process/tracking item, not a fix ticket. Go's own implementation already reduces a wide
32-bit value mod 3 (bias ~2^-32, negligible), so this is a C/Python-specific gap, not a
protocol-level design flaw.

The other two candidate targets from work item 1 (NL-FSCX v2's CSP-based construction,
HFSCX-256-DM's finalizer) have not yet been passed over — stays **OPEN** for those two.

Status: **OPEN**







Status: **OPEN**


