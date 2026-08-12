# Formal Cryptographic Analysis of the Herradura Cryptographic Suite — Part 4

**Status:** See Part 1 (SecurityProofs-1.md) for full status header.

> **This is Part 4 of a split document.**
>
> - **Part 1 — §1–§8** (SecurityProofs-1.md): Algebraic Foundations · Protocol Analysis · Security Analysis · Quantum Attack Analysis · Experimental Code Index
> - **Part 2 — §9–§10** (SecurityProofs-2.md): Non-Linear Proposals · v1.4.0 Migration
> - **Part 3 — §11–§11.8.2** (SecurityProofs-3.md): Non-linearity and Post-quantum Extensions · NL-FSCX v1/v2 · HKEX-RNL
> - **Part 4 — §11.8.3–§11.9.11** (this file): PQ Signature Options · HFSCX-256-DM
> - **Part 5 — §11.10–§11.13, §11.15–§11.19** (SecurityProofs-5.md): Zero-Knowledge Proof Extensions · Research-Review Sections

---

### 11.8.3 Option A — HPKS-WOTS-F: Winternitz OTS with NL-FSCX v1

**Construction.**  Fix Winternitz width $w$ and set $\ell = \lceil|H_\mathrm{msg}|/\log_2 w\rceil$ where $|H_\mathrm{msg}|$ is the message-hash output length in bits.  Define the hash chain:

$$h(x) = F_1^{n/4}\bigl(\mathrm{ROL}(x, n/8), x\bigr)$$

(the same function used as the HKEX-RNL KDF in §11.4.2, with seed-rotation active from step 1).

- **Key generation.**  Draw $\mathrm{sk}_i \xleftarrow{R} \{0,1\}^n$ for $i = 0, \ldots, \ell-1$.  Publish $\mathrm{pk}_i = h^{w-1}(\mathrm{sk}_i)$.
- **Sign($\mathrm{msg}$).**  Compute $(d_0, \ldots, d_{\ell-1})$ from $H_\mathrm{msg}(\mathrm{msg})$ in base $w$.  Release $\sigma_i = h^{w-1-d_i}(\mathrm{sk}_i)$.
- **Verify.**  Accept iff $h^{d_i}(\sigma_i) = \mathrm{pk}_i$ for all $i$.

For multi-message use, combine OTS leaves in a Merkle tree (using $h$ as the tree hash) for XMSS-style stateful signatures, or embed in a hypertree for SPHINCS+-style stateless operation.

**Theorem 16 — EUF-CMA Security of HPKS-WOTS-F.**

If $h$ is a one-way function, then HPKS-WOTS-F is EUF-CMA secure for a single signing query with:

$$\Pr[\mathrm{forge}] \leq \ell \cdot \Pr[\text{invert}(h)].$$

*Proof.*  Any forger $\mathcal{A}$ producing $(d', \sigma')$ for $m' \neq m$ must, for some index $i$, produce $\sigma'_i$ with $h^{d'_i}(\sigma'_i) = \mathrm{pk}_i$ and $d'_i \neq d_i^{\ast}$.  Only $d'_i > d_i^{\ast}$ is useful (smaller $d'_i$ would reuse a revealed chain value).  Then $\mathcal{A}$ has computed $\sigma'_i$ with $h^{d'_i - d_i^{\ast}}(\sigma'_i) = \mathrm{pk}_i$, i.e.\ a preimage inversion starting from the released $\sigma_i^{\ast} = h^{w-1-d_i^{\ast}}(\mathrm{sk}_i)$.  This contradicts the OWF assumption.  A union bound over $\ell$ indices gives the stated bound. $\blacksquare$

**Quantum analysis.**  Grover's algorithm finds a preimage of $h^k$ in $O(2^{n/2})$ quantum queries.  By Corollary 2, NL-FSCX v1 preimage inversion (after $\geq 2$ rounds, which $n/4$ rounds certainly satisfies for $n \geq 8$) is a degree-$n$ system for which no sub-exponential quantum solver is known.  For $n = 256$: $2^{128}$ quantum query lower bound.

**Honest limitation.**  Theorem 16 reduces security to the NL-FSCX v1 one-wayness assumption, which is a **new assumption** not yet reduced to a studied hard problem.  Corollary 2 rules out Gröbner-basis algebraic attacks, but non-algebraic exploits are not excluded.  Independent cryptanalysis of NL-FSCX v1 as an OWF is required before deployment.

**Cryptanalytic evidence (TODO #74, v1.9.2).**  `SecurityProofsCode/nl_fscx_owf_analysis.py` applies five classical techniques to $F_{1}^{n/4}(\cdot, B)$ with fixed $B$; results are summarised below.

*Differential analysis.* At $n = 8$, the maximum differential probability (MDP) is strongly $B$-dependent: for generic $B$ (e.g. $B = \text{0xa5}$) MDP falls to $\approx 0.10$ at $r = 8$, while sparse-bit $B$ values (e.g. $B = \text{0x3c}$) retain MDP $\approx 0.77$ at $r = 8$, indicating degenerate differential trails along those $B$ values.  At $n = 32$, $r = 8$: zero repeated $(dA, dY)$ pairs in $10^5$ trials, consistent with uniform differential distribution.

*Linear bias.* At $n = 8$ the max Walsh bias falls to $0.24$–$0.40$ at $r = 8$; at $n = 32$, $r = 8$ the sampled max bias ($0.070$) is within the Bernstein random-function bound ($0.087$), consistent with no exploitable linear structure.

*Rotational cryptanalysis.* For all rotation amounts $k \in \{1,2,4,7,8,16\}$ at $n = 32$, $r = 8$, the fraction of random pairs $(A, B)$ satisfying $F_{1}^r(\mathrm{ROL}(A,k), \mathrm{ROL}(B,k)) = \mathrm{ROL}(F_{1}^r(A,B), k)$ is approximately $1$–$6\%$, far above the $2^{-32}$ expectation for a random function.  This structural correlation is inherited from the FSCX linear base (exactly rotation-equivariant by construction); the integer-carry non-linear term only partially breaks it.  See the **Rotational structure** follow-up below (TODO #75) for a full characterisation of which protocol uses are affected.

*B=0 degeneracy.* $F_{1}^r(A, 0) = L_{r}(A)$ is confirmed GF(2)-linear and **singular** (rank 2/8 for $L_{2}$ at $n = 8$), meaning $F_{1}^r(\cdot, 0)$ collapses most inputs.  All protocol instantiations have $\Pr[B = 0] = 2^{-n}$, negligible.

*MITM preimage.* Exhaustive enumeration at $n = 20$, $r = 5$ shows $28.1\%$ image coverage (average preimage count $3.52$).  Non-injectivity means backward enumeration requires $O(2^n)$ forward work, confirming MITM provides no asymptotic speedup.

*Open concerns from this analysis.* (1) Sparse-bit $B$ values exhibit elevated MDP at $n = 8$; large-$n$ behavior is characterised in the sparse-$B$ follow-up below (TODO #125) — the elevation persists at $n = 32$ and the safe-use bound is $\text{wt}(B) \geq n/2$.  (2) No formal hardness reduction to any studied problem.  Independent expert cryptanalysis is required before deployment.  (The rotational concern is characterised in the follow-up analysis below.)

**Rotational structure (TODO #75, v1.9.3).**  `SecurityProofsCode/nl_fscx_rot_analysis.py` resolves the rotational open concern by separating *one-sided* rotation ($A$ rotated, $B$ fixed) from *two-sided* rotation (both rotated simultaneously).

*One-sided rotation (B fixed).* For all $r$ and $k$ tested, $\Pr_{A}\bigl[F_{1}^r(\mathrm{ROL}(A,k), B) = \mathrm{ROL}(F_{1}^r(A,B), k)\bigr] < 10^{-5}$ (zero hits in $10^5$ trials per configuration).  The structural reason: one-sided equivariance requires $\mathrm{ROL}(\mathrm{ROL}(A,k)+B, n/4) \oplus \mathrm{ROL}(A+B, n/4+k)$ to equal the $A$-independent constant $M(B) \oplus M(\mathrm{ROL}(B,k))$, a condition that does not hold for generic $B$.

*Two-sided rotation (both inputs rotated).* The two-sided probability $p_{\text{rot}}(r,k)$ follows a power law rather than geometric decay:

$$p_{\text{rot}}(r,k) \approx C(k) \cdot r^{-\alpha(k)}$$

where empirically $\alpha(1) \approx 0.96$, $C(1) \approx 0.42$ and $\alpha(8) \approx 1.88$, $C(8) \approx 0.65$.  At the protocol round count $r = n/4 = 64$ for $n = 256$: $p_{\text{rot}}(64,1) \approx 0.78\%$, requiring approximately $90$ query pairs for a $50\%$-advantage random-oracle distinguisher ($q \approx \ln 2 / p$).

*Protocol impact.* All PRF uses of $F_{1}$ have a fixed key $B$: the Stern-F row generator $F_{K}(i) = F_{1}^{n/4}(\mathrm{ROL}(K \oplus i, n/8), K)$, the HSKE-NL-A1 keystream, and the HFSCX-256-DM compression function.  These are one-sided; $p \approx 0$ — **rotation-safe**.  The HPKS-WOTS-F hash chain $h(x) = F_{1}^{n/4}(\mathrm{ROL}(x, n/8), x)$ is two-sided (rotating $x$ rotates both $A$ and $B$), so a $\approx 90$-pair random-oracle distinguisher exists.  However, Theorem 16 reduces HPKS-WOTS-F to the OWF assumption on $h$, not to a random-oracle assumption — the distinguisher does **not** break Theorem 16.

*Conclusion.* The rotational NOTE from TODO #74 is now fully characterised: it is a polynomial-query random-oracle distinguisher against the WOTS hash chain that does **not** affect the current security proofs.  It is a design concern only for future constructions requiring $h$ to behave as a random oracle.

**Sparse-B rotational characterisation (TODO #125, v1.9.88).**  `nl_fscx_rot_analysis.py` §6–§8 resolve the sparse-$B$ open concern at $n = 32$ by stratifying the two-sided rotational rate by the Hamming weight of $B$ (50 000 trials per stratum, $r = 8$).

*Stratified rates (Q1).*  Sparse $B$ massively elevates the two-sided rate: at $\text{wt}(B) = 1$ the rate is $0.86$ at $k = 1$ — a $64\times$ elevation over the uniform-$B$ baseline ($0.058$).  The elevation decays monotonically with weight: $50\times$ at $\text{wt}(B) = 2$, $30\times$ at $4$, $10\times$ at $8$, and baseline parity at $16$.  The structural reason mirrors §1: with few set bits in $B$, the integer carry chain in $\mathrm{ROL}(A + B, n/4)$ is short, so the carry-mismatch events that break FSCX's exact rotation-equivariance are rare.  The $n = 8$ MDP elevation flagged by TODO #74 is therefore **not** a small-$n$ artifact — it persists at $n = 32$ and is expected at all $n$.

*Threshold weight (Q2).*  A fine-grained sweep places the safe-use threshold at $\text{wt}(B) \geq 16 = n/2$: the maximum elevation over baseline is $2.7\times$ at $\text{wt}(B) = 12$ and $0.8\times$ at $16$.  Safe-use lower bound for PRF applications: **$B$ density $\geq 1/2$**, i.e. $\text{wt}(B) \geq n/2$.  Uniformly random keys satisfy this with overwhelming probability (a binomial tail of $2^{-0.03n}$ order); the bound only constrains adversarially chosen or structured $B$.

**2025 automated RX-differential search re-check (TODO #158).**  "An Automatic Search
Framework for Rotational-XOR Differential Characteristics of ARX Ciphers" (2025,
doi:10.1007/s10623-025-01571-6) proposes a CNF/SAT-based automated search over the full
RX-difference space (rotation $k$ *and* an XOR-difference component, not just pure
rotation) for ARX ciphers, finding longer characteristics for SPECK/CHAM/SPARX/Ballet
than prior hand/semi-automated analysis. FSCX's linear map $M = I \oplus \mathrm{ROL}
\oplus \mathrm{ROR}$ is pure XOR-rotation and commutes exactly with both operations, so
it contributes probability $1$ to every RX-differential trail regardless of the
XOR-difference component — all probability mass in an NL-FSCX v1 round comes from the
$\mathrm{ROL}((A+B) \bmod 2^n, n/4)$ modular-addition term, which is exactly the kind of
object the paper's addition-specific propagation rules describe. The paper's full text
is paywalled beyond its abstract, so its exact CNF encoding could not be reproduced.

**Reproducing it proved unnecessary.**  For NL-FSCX v1 the RX-difference search space
collapses far enough to be solved *exactly*, which is strictly stronger than any
heuristic SAT/SMT trail search the paper could run.
`SecurityProofsCode/nl_fscx_rx_exact_search.py` carries this out and supersedes the
earlier Monte-Carlo hill-climbing stand-in (`nl_fscx_rx_differential_2025.py`), whose
estimates were within sampling noise and covered only single-round transitions.

*Reduction.*  Write the RX-relation with rotation offset $\gamma$ as $\bar{A} =
\mathrm{ROTL}(A,\gamma) \oplus da$ and $\bar{B} = \mathrm{ROTL}(B,\gamma) \oplus db$, and
put $dS = (\bar{A} + \bar{B}) \oplus \mathrm{ROTL}(A+B, \gamma)$.  Then the round's output
RX-difference is exactly

$$dY = M(da) \oplus M(db) \oplus \mathrm{ROL}(dS, n/4)$$

verified over 4000 random $(n, \gamma, da, db, A, B)$ against the deployed round function.
So $M$ contributes probability $1$, $dY$ is a *bijection* of $dS$, and the whole search
space is the RX-differential of modular addition — no trail branching survives the linear
layer at all.

*Exact solver.*  Matching bit $i$ of the barred sum against bit $j = (i-\gamma) \bmod n$
of the rotated unbarred sum gives, at every position, $\bar{c}_i \oplus c_j = da_i \oplus
db_i \oplus dS_i$ for the two addition carry chains.  Hence $dS$ is fully determined by
the carry pair, and an $O(n)$ dynamic program over states $(c_j, \bar{c}_i)$ computes the
exact distribution (the unbarred chain wraps, so its entering carry is guessed and checked
for consistency).  Validated against brute force over all $2^{2n}$ pairs at $n=8$: **0
mismatches**.

*Certified single-round optimum.*  Exhaustively enumerating **every** $(da, db, dS)$ and
every $\gamma$ at $n=8$ — a certified optimum, not a sampled one — the best characteristic
is $(da, db, dS) = (0,0,0)$ for all $\gamma$, i.e. exactly the pure-rotational slice
TODO #75/#125 already measured:

| $\gamma$ | 1 | 2 | 3 | 4 | 5 | 6 | 7 |
|---|---|---|---|---|---|---|---|
| optimal $p$ | $0.3779$ | $0.3174$ | $0.2900$ | $0.2822$ | $0.2900$ | $0.3174$ | $0.3779$ |

The probability is symmetric under $\gamma \mapsto n-\gamma$, is maximised at $\gamma=1$,
and decreases toward $1/4$ at $\gamma = n/2$.  At $\gamma=1$ it converges to $3/8 =
2^{-1.415}$ as $n$ grows ($0.37793$ at $n=8$, $0.37501$ at $n=16$) — reproducing the
classical rotational probability of modular addition, an independent check on the solver.
**The open question this item posed is therefore answered in the negative: no nonzero-XOR
RX-difference beats the pure-rotational one.**

*Multi-round.*  Building the full $2^n$-state transition graph and running a max-product
DP over rounds (with $B$ held constant, as in `nl_fscx_revolve_v1`) gives the optimal
$r$-round trail — the chained analysis the earlier stand-in could not perform.  For
$db=0$ the optimum is again exactly the pure-rotational trail, decaying geometrically at
$2^{-1.40}$ per round; nonzero $db$ is strictly worse.

*The trail methodology is not tight here.*  Comparing that trail estimate against $p$
measured **exactly** over all $2^{2n}$ pairs at $n=8$, $\gamma=1$:

| $r$ | 1 | 2 | 3 | 4 | 5 | 6 |
|---|---|---|---|---|---|---|
| exact $p$ | $0.3779$ | $0.2134$ | $0.1463$ | $0.1156$ | $0.0999$ | $0.0915$ |
| trail estimate | $0.3779$ | $0.1428$ | $0.0540$ | $0.0204$ | $0.0077$ | $0.0029$ |
| understated by | $1.0\times$ | $1.5\times$ | $2.7\times$ | $5.7\times$ | $13\times$ | $31\times$ |

The Markov/round-independence assumption underpinning *all* trail search — the paper's
methodology included — understates the true probability by a factor that grows without
bound, because $B$ is reused every round and successive rounds are strongly dependent.
This is the structural reason TODO #75/#125 found power-law rather than geometric decay.
Trail search therefore cannot be the binding analysis for NL-FSCX v1: it produces a bound
that is not merely loose but increasingly so, and the **direct measurement** of
TODO #75/#125 remains the operative characterisation.

*Corroboration at $n=16$.*  An exact sweep over all $(da, db)$ of Hamming weight
$\leq 2$ at $\gamma=1$ again finds the pure-rotational baseline optimal ($0.375011$,
matched but never beaten), and the same Markov gap appears — sampled $p$ against the
trail estimate runs $1.0\times$, $1.5\times$, $2.7\times$, $5.4\times$, $11.7\times$,
$26.4\times$ over rounds 1–6.  Neither conclusion is an artefact of the small $n=8$
instance where exhaustive certification is affordable.

*HFSCX-256-DM impact (Q3).*  For the compression function $C_{\text{DM}}(s,m) = F_{1}^{2n}(s, m) \oplus s$ with adversarially sparse message blocks $\text{wt}(m) \in \{1,2,4\}$: the **one-sided** rate in the chaining value $s$ remains $\approx 0$ ($\leq 4 \times 10^{-5}$ at $r = 64$), so a sparse message alone gives no rotational distinguisher — the per-call PRF safety of §5 is weight-independent.  The **two-sided** related-message rate (attacker submits both $m$ and $\mathrm{ROL}(m,k)$ with rotated chaining values) is *not* suppressed by iteration: $0.77$ at $\text{wt}(m) = 1$, $r = 64$, $k = 1$ (versus $0.86$ at $r = 8$), consistent with the §3 power law.  This is unrealisable against the Merkle-Damgård chain itself because the attacker does not control $s$ — the fixed IV breaks the required $s \to \mathrm{ROL}(s,k)$ alignment at the first block — but it is a documented related-message property: any future mode that lets an attacker align rotated chaining values with rotated sparse messages inherits a high-probability rotational distinguisher.

**HPKS-XMSS-F implementation (v1.9.39, TODO #97).** The HPKS-WOTS-F and HPKS-XMSS-F constructions are now implemented in the suite (Python) and CLI.

*Parameters.* $w = 16$ (Winternitz), $\ell_1 = 64$ message digits, $\ell_2 = 3$ checksum digits (max checksum $64 \times 15 = 960 < 16^3$), $\ell = 67$ chains total. Tree height $h = 10$ by default ($2^{10} = 1024$ leaves per key pair).

*Hash chain.* $h(x) = F_1^{n/4}(\mathrm{ROL}(x, n/8), x)$ at $n = 256$, identical to Theorem 16.

*Keygen.* Leaf seed $\text{sk}(i,j) = \text{HFSCX-256}(\text{master-seed} \mathbin\| \text{idx-32} \mathbin\| j_{16})$ for leaf index $\text{idx}$ and chain index $j \in \{0,\ldots,\ell-1\}$. Public key $\text{pk}(i,j) = h^{w-1}(\text{sk}(i,j))$. Leaf node $= \text{HFSCX-256}(0\text{x00} \mathbin\| \text{pk}(i,0) \mathbin\| \cdots \mathbin\| \text{pk}(i,\ell-1))$ (RFC 6962 domain separation). XMSS public key $= $ Merkle root of $2^h$ leaf nodes (§78.J accumulator).

*Sign.* Encode $\text{HFSCX-256}(\text{msg})$ as 64 base-16 digits; append 3-digit checksum. Release $\sigma_j = h^{w-1-d_j}(\text{sk}_j)$ per chain. Include Merkle authentication path for the leaf.

*Verify.* Recover $\text{pk}_j = h^{d_j}(\sigma_j)$ for all $j$; compute leaf hash from recovered pk; verify Merkle path against root. No stored public key needed in the signature: the pk is fully determined by $(\text{msg}, \sigma)$.

*State management.* Each signing operation consumes one leaf. The CLI tracks the next leaf index in a sidecar file `<key>.idx`. Exhaustion of all $2^h$ leaves is detected and rejected with an error. Re-use of the same leaf with a different message would allow an attacker to compute the SK from two partial chain openings (standard WOTS forgery); the state file prevents this in normal operation.

*Security.* Inherits Theorem 16 (EUF-CMA under NL-FSCX v1 OWF) and the standard Merkle-tree argument: forging an XMSS signature requires either (a) forging a WOTS signature on some leaf, or (b) finding a collision in HFSCX-256 (used as the Merkle hash). Bound: $\Pr[\text{forge}] \leq 2^h \cdot \ell \cdot \Pr[\text{invert}(h)] + \Pr[\text{collision in HFSCX-256}]$.

---

### 11.8.4 Option B — HPKS-Stern-F and HPKE-Stern-F (Code-Based via FSCX PRF)

Option B reduces security to **syndrome decoding**, which is NP-complete [Berlekamp-McEliece-Van Tilborg 1978] and has no known polynomial quantum algorithm.  NL-FSCX v1 acts as a pseudorandom generator for the public parity check matrix; all hardness derives from the code, not from assumptions about FSCX invertibility.

**Public matrix generation.**  For an $(N, k, t)$-code, generate the $(N-k) \times N$ binary parity matrix $H$ row by row:

$$H_i = \text{HFSCX-256-DM}\bigl(F_1^{n/4}(\mathrm{ROL}(\mathrm{seed} \oplus i, n/8), \mathrm{seed})\bigr) \bmod 2^n, \qquad i = 0, \ldots, N-k-1.$$

The outer HFSCX-256-DM finalization (deployed in v1.9.35, TODO #88) removes the NL-FSCX range compression documented below, so each row is drawn from the full digest range.  Under the PRF assumption for NL-FSCX v1 (implied by the OWF assumption via the GGM PRG-to-PRF construction [Goldreich-Goldwasser-Micali 1986]), $H$ is computationally indistinguishable from a uniformly random binary matrix.

**PRF Verification — Algebraic and Experimental Evidence.**

The security of Option B depends critically on NL-FSCX v1 behaving as a PRF.  The following analysis establishes, algebraically and empirically, that NL-FSCX v1 passes every canonical distinguishing test that linear FSCX fails.  All experiments use $n = 32$, $r = n/4 = 8$ steps, and 10 000-trial sample sizes; the script is `SecurityProofsCode/nl_fscx_prf_analysis.py`.

Two instantiations are tested:

$$F_K(i) = F_1^{n/4}\bigl(\mathrm{ROL}(K \oplus i, n/8), K\bigr) \qquad \text{(Stern-F row generator)}$$

$$G_K(i) = F_1^{n/4}\bigl(\mathrm{ROL}(K, n/8), K \oplus i\bigr) \qquad \text{(HSKE-NL-A1 keystream)}$$

The linear FSCX baseline $H_K(i) = M^r \cdot \mathrm{ROL}(K \oplus i, n/8) \oplus S_r \cdot K$ serves as the known-broken control.

*Key algebraic separations.*

**2-query differential.**  For the linear baseline:

$$H_K(i_1) \oplus H_K(i_2) = M^r \cdot \bigl(\mathrm{ROL}(i_1, n/8) \oplus \mathrm{ROL}(i_2, n/8)\bigr)$$

because the $S_r \cdot K$ key terms cancel.  This XOR is **K-independent** — any adversary holding two output queries can recover the relationship between inputs without knowing $K$, yielding a trivial 2-query distinguisher.

For NL-FSCX v1, each step mixes the carry of $(A + B) \bmod 2^n$ through channel $B = K$.  At the first step with $A_j = \mathrm{ROL}(K \oplus i_j, n/8)$:

$$\bigl[(A_1 + K) \bmod 2^n\bigr] \oplus \bigl[(A_2 + K) \bmod 2^n\bigr]$$

involves carries at each bit position that depend on the bits of $K$.  The resulting XOR **cannot** be written as $f(i_1 \oplus i_2)$ for any K-independent $f$, so the 2-query attack fails.  Experiment confirms: the K-independent prediction matches linear FSCX 10 000/10 000 (100 %) and NL-FSCX v1 0/10 000 (0 %).

**Cross-key linear structure.**  For the linear baseline:

$$H_{K_1}(i) \oplus H_{K_2}(i) = S_r(K_1) \oplus S_r(K_2) = S_r(K_1 \oplus K_2),$$

which is $i$-independent.  An adversary with two keys and any shared input $i$ learns $S_r(K_1 \oplus K_2)$ without evaluating the function at a second input.  For NL-FSCX v1 the carry terms depend jointly on $K$ and $A$, so no such cancellation occurs.  Experiment: cross-key delta is input-dependent for 0/10 000 linear FSCX trials vs.\ 10 000/10 000 for NL-FSCX v1.

*Experimental results (algebraic degree indicators).*

The BLR linearity test (Blum-Luby-Rubinfeld) measures whether $F(x \oplus y) \oplus F(x) \oplus F(y) \oplus F(0) = 0$ for random $(x, y)$.  This holds with probability 1 for any GF(2)-linear function and with probability $2^{-n}$ for a random function.  Linear FSCX: 100 % zero (confirmed affine).  NL-FSCX v1: 0 % zero (consistent with random function, $n = 32$).

The higher-order differential test measures the algebraic degree.  The second-order difference $\Delta_2(x, \delta_1, \delta_2) = F(x) \oplus F(x \oplus \delta_1) \oplus F(x \oplus \delta_2) \oplus F(x \oplus \delta_1 \oplus \delta_2)$ is identically zero for any degree-$\leq 1$ (affine) function and generically non-zero for degree $\geq 2$.  Third-order entropy $H(\Delta_3)$ is zero for degree $\leq 2$ and approaches $n$ bits for degree $\geq 3$.  Linear FSCX: 100 % zero at second order, 0 bits entropy at third order (degree 1, confirmed).  NL-FSCX v1: 0 % zero at second order, 11.97 bits entropy at third order — confirming degree $\geq 3$ (consistent with Theorem 13: degree saturates at $n$ after $\geq 2$ rounds).

*Full evidence matrix.*

| Test | Linear FSCX (baseline) | NL-FSCX v1 (both variants) |
|---|---|---|
| 2-query K-independent differential (§1) | **Fails** — 100 % match | **Passes** — 0 % match |
| BLR linearity test (§2) | **Fails** — 100 % linear | **Passes** — 0 % linear |
| SAC mean output-bit flips (§3) | 3.0 / 16.0 (affine column weight) | 15.99 ± 0.06 (≈ ideal $n/2$) |
| 2nd-order differential zero-fraction (§4) | **Fails** — 100 % zero | **Passes** — 0 % zero |
| 3rd-order differential entropy (§4) | 0.0 bits (degree 1) | 11.97 bits (degree $\geq 3$) |
| Max linear bias vs. random bound (§5) | 0.030 (known bias $= 1/2$ at correct mask) | 0.031 ≈ random bound |
| Key-bit sensitivity mean flips (§6) | 13.0 / 16.0 | 16.06 ± 2.9 (≈ ideal $n/2$) |
| Output collision rate vs. birthday bound (§7) | 0 excess (near-bijective) | 0 excess (injective) |
| Cross-key delta input-dependent (§8) | **Fails** — 0 % dependent | **Passes** — 100 % dependent |
| Range compression vs random fn (§9.3, §10) | n/a (bijective) | **Fails** — 21–28% at n=32; see TODO #43 |

Tests §1, §2, §4, §8 detect GF(2)-linearity and low algebraic degree; linear FSCX fails all four, NL-FSCX v1 passes all four.  Tests §3 and §6 measure diffusion; both functions achieve good avalanche.  Test §5 detects linear correlations; NL-FSCX v1's maximum sampled bias is consistent with the random-function Bernstein bound $O(\sqrt{n} / 2^{n/2})$.  Test §7 confirms near-uniform output distribution for random inputs.

*Scope and caveat.*  These tests rule out every polynomial-time distinguisher based on linearity, low algebraic degree, or cross-key structure.  They do **not** constitute a formal PRF proof.  A formal proof would require reducing PRF-security to a studied hardness assumption; the GGM construction (§11.8.4 above) provides that path once the NL-FSCX v1 OWF assumption is accepted.  The experimental evidence supports the assumption but does not replace it.

**Exhaustive Walsh analysis at small $n$ (v1.5.42 — TODO #35).**  To complement the §5 sampling at $n=32$, `nl_fscx_prf_analysis.py` §9 adds an exhaustive Walsh-Hadamard scan at $n=12$: all $4095 \times 4096 = 16.7$M mask pairs $(a, b)$ are evaluated for two random keys.  Key findings:

- **§9.1 (n=8):** max_bias = 1.0 — degenerate at r = 2 steps; a perfect linear correlation exists for some (a,b) pair.
- **§9.2 ($n=12$):** max\_bias $\approx 0.43$, ratio $\approx 4.7\times$ the random-function bound $\sqrt{4 \cdot 12 \cdot \ln 2 / 2^{12}} \approx 0.090$.  The affine baseline $H\_\mathrm{linear}$ gives max\_bias $= 1.0$ (correctly detected).
- **§9.3 (Range compression):** $F_K(\cdot)$ maps only $\approx 40$–$55\%$ of inputs to distinct outputs at $n = 8$/$12$/$16$, versus $\approx 63\%$ expected for a truly random function.  The compressed range inflates Walsh coefficients beyond the random bound.
- **§9.4 (Extrapolation):** $\mathbb{E}[\mathrm{max\_bias}(n)] \approx \sqrt{4n \ln 2 / 2^n}$; at $n=32$ this is $\approx 1.44 \times 10^{-4}$.

The elevated bias at n=12 is attributed to range compression, not to linear algebraic structure.  At the deployed n=32, §5 sampling is consistent with the random bound, but exhaustive verification requires scanning 2^64 pairs — infeasible in pure Python.

**Range compression at n=32 — exhaustively measured (v1.5.43, TODO #42).**  Test [20] in `CryptosuiteTests/Herradura_tests.c` uses HyperLogLog (m=16384 registers, ~0.81% std-error) over all 2^32 inputs to F_stern(K, ·) for three representative keys:

| K | Hamming weight | Distinct fraction | vs random 63.2% |
|---|---|---|---|
| `0x00000003` | 2 (min-t) | **20.9%** | 0.33× |
| `0xA3C5E7B9` | 17 | **21.7%** | 0.34× |
| `0xFFFFFFFD` | 30 (max-t) | **28.3%** | 0.45× |

The range compression does **not** shrink as n grows.  `nl_fscx_prf_analysis.py` §10 measures the step-by-step range fraction for n ∈ {8, 12, 16, 20} (exhaustive) and derives a per-step compression ratio of ~0.74–0.82× (increasing with n), versus 0.632× for a random function.  Because the step count r = n/4 grows linearly, cumulative compression worsens with n: at n=256 with r=64 steps, the predicted range fraction falls below 10^{-4}.

**Security implication.**  A distinguisher that counts output collisions can separate F_stern from a random function at n=32 using O(2^16) queries (birthday bound against a ~24% range).  This constitutes a concrete polynomial-time distinguisher that falsifies the PRF assumption underlying Theorem 17, removing the ε_PRF term from the EUF-CMA bound.  Until TODO #43 is applied, Theorem 17 holds only against adversaries that do not exploit this collision-counting attack.

**Fix (TODO #43).**  Composing F_stern with HFSCX-256-DM eliminates the range compression and restores ~63.2% distinct outputs (verified in `hfscx_256_analysis.py`):

$$F_{\text{stern-v2}}(K, i) = \text{HFSCX-256-DM}\bigl(F_1^{n/4}(\mathrm{ROL}(K \oplus i, n/8), K)\bigr) \bmod 2^n$$

One HFSCX-256-DM call is added per row of H and per hash step in the commitment scheme.  After the fix, no known collision-counting distinguisher applies to F_stern-v2.  This is a wire-format breaking change; old and new HPKS-Stern-F signatures are incompatible.

**Deployment status.**  The hash-step composition (`_stern_hash`) was deployed in v1.6.0 (TODO #43).  The per-row matrix finalization (`_stern_matrix_row`) was deployed in v1.9.35 (TODO #88) across all six language targets — Python/C/Go at n = 256, and the C/ARM/i386/Arduino n = 32 demos via HFSCX-32-DM — completing the F_stern-v2 fix as specified above.  Public keys, syndromes, signatures, and KEM ciphertexts generated before v1.9.35 are incompatible with the finalized matrix.

**Key generation.**
- Private key: $\mathbf{e} \xleftarrow{R} \{\mathbf{v} \in \{0,1\}^N : \mathrm{wt}(\mathbf{v}) = t\}$.
- Public key: $\mathbf{s} = H\mathbf{e}^\top \in \mathbb{GF}(2)^{N-k}$.

**HPKS-Stern-F: Stern's Three-Move Protocol [Stern 1993] + Fiat-Shamir.**

Each identification round:

1. **Commit.**  Draw $\mathbf{y} \xleftarrow{R} \{0,1\}^N$ and permutation $\pi \xleftarrow{R} S_N$.  Compute and send:

$$c_0 = \mathcal{H}\left(\pi, H\mathbf{y}^\top\right), \qquad c_1 = \mathcal{H}\left(\pi \circ \sigma_{\mathbf{e}}, H(\mathbf{y} \oplus \mathbf{e})^\top\right),$$

where $\sigma_{\mathbf{e}} \in S_N$ is a fixed permutation encoding the support of $\mathbf{e}$ and $\mathcal{H}$ is a collision-resistant hash.

2. **Challenge.**  Verifier sends $b \xleftarrow{R} \{0, 1, 2\}$.

3. **Response.**

   $b = 0$: reveal $(\pi, \mathbf{y})$; verifier checks $c_0$ and that $\pi$ is consistent with the support encoding.

   $b = 1$: reveal $(\pi \circ \sigma_{\mathbf{e}}, \mathbf{y} \oplus \mathbf{e})$; verifier checks $c_1$ and $H(\mathbf{y} \oplus \mathbf{e})^\top = H\mathbf{y}^\top \oplus \mathbf{s}$.

   $b = 2$: reveal $(\pi, \mathbf{y} \oplus \mathbf{e})$; verifier checks $\mathrm{wt}(\pi(\mathbf{y} \oplus \mathbf{e})) = t$ and the syndrome relation.

Soundness error per round: $2/3$.  After $\lceil\lambda / \log_2(3/2)\rceil \approx 1.7\lambda$ rounds, soundness error $\leq 2^{-\lambda}$.  Fiat-Shamir in the quantum random oracle model [Unruh 2015] produces a non-interactive signature.  The commitment hash `_stern_hash` (§11.9.9) now finalizes through HFSCX-256-DM with a per-slot domain-separation tag (ds=1 for $c_0$, ds=2 for $c_1$, ds=3 for $c_2$, ds=4 for the KEM key).  Under the ROM on HFSCX-256-DM (§11.9), this provides the independent quantum random oracles required by Unruh's transform.

**Theorem 17 — EUF-CMA of HPKS-Stern-F.**

Let $\mathrm{SD}(N,t)$ denote the syndrome decoding problem: given $(H, \mathbf{s})$ find $\mathbf{e}$ with $H\mathbf{e}^\top = \mathbf{s}$ and $\mathrm{wt}(\mathbf{e}) = t$.  If $\mathrm{SD}(N,t)$ requires $T_\mathrm{SD}$ quantum operations, NL-FSCX v1 is a secure PRF with advantage $\epsilon_\mathrm{PRF}$, and HFSCX-256-DM is modeled as a random oracle, then HPKS-Stern-F achieves EUF-CMA with:

$$\Pr[\mathrm{forge}] \leq \frac{q_H}{T_\mathrm{SD}} + \epsilon_\mathrm{PRF}$$

for $q_H$ quantum hash queries.

**Production round-count benchmark (TODO #184, v2.0.6).**  The soundness-error
bound above is per round; the shipped default of `SDF_ROUNDS = 32` (soundness
`(2/3)^32`, about 19 bits) is a demo parameter, while `SDF_PRODUCTION_ROUNDS =
219` reaches the 128-bit soundness floor. All three suites already supported a
runtime/compile-time round count, but the CLI didn't expose it end-to-end for
the base `sign --algo hpks-stern` / `hpks-ring` paths, and the DER length
encoder in `codec.py` / `herradura_codec.h` / `herradura/codec.go` was capped
at a 2-byte length field (65535 bytes) — too small for a 219-round signature.
Both were fixed (`--rounds` flag wired through in Python/Go; C reads
`-DSDF_ROUNDS=219` at compile time via `#ifndef`; DER codecs extended to the
standard 3- and 4-byte long-form length fields). Measured at N = 256 on the
same machine, single-threaded, no batching:

| Rounds | Sig. size | Python sign | Python verify | C sign | C verify | Go sign | Go verify |
|---|---|---|---|---|---|---|---|
| 32 (demo)  |  7 029 B | 0.85 s | — | 0.05 s | — | 0.49 s | — |
| 219 (prod) | 47 511 B | 2.24 s | 1.55 s | 0.13 s | 0.06 s | 2.01 s | 1.56 s |

Signature size and time both scale linearly in rounds, as expected from the
protocol structure (independent per-round commit/response). C is 15-40x faster
than Python/Go at this N because Stern-F's inner loop is dominated by
fixed-size bit operations that the C implementation performs without
interpreter or garbage-collector overhead; Python and Go track each other
closely. The 47 KB / ~2 s cost at production rounds is the honest price of
demo-scale N = 256 with real soundness — see the deployed-parameter caveat
below for why N itself, independent of round count, still falls short of
128-bit classical security.

*Proof.*  (i) **Completeness** — honest prover satisfies all three challenge cases by construction.  (ii) **Statistical zero-knowledge** — for each $b$, the revealed values $(\pi, \mathbf{y})$, $(\pi \circ \sigma_{\mathbf{e}}, \mathbf{y} \oplus \mathbf{e})$, $(\pi, \mathbf{y} \oplus \mathbf{e})$ are uniformly distributed over their respective domains independently of $\mathbf{e}$, since $\mathbf{y}$ and $\pi$ are fresh random.  (iii) **Soundness** — a prover that passes all three challenges can be rewound with challenges $b = 1$ and $b = 2$ on the same commitment, yielding two accepting transcripts from which $\mathbf{e}$ satisfying $H\mathbf{e}^\top = \mathbf{s}$ is extracted, solving $\mathrm{SD}(N,t)$.  (iv) **Fiat-Shamir in the QROM** — `_stern_hash` outputs `HFSCX-256-DM(ds || chain(...))` where `ds` is a per-slot domain tag; under the ROM on HFSCX-256-DM, the per-slot outputs are independent random oracles, satisfying Unruh's QROM requirement.  EUF-CMA security against quantum adversaries making $q_H$ quantum hash queries follows from [Unruh 2015, Theorem 5], with forgery probability bounded by $q_H/T_\mathrm{SD}$.  (v) **PRF reduction** — under the NL-FSCX v1 PRF assumption, $H$ is computationally indistinguishable from a random matrix; any distinguishing advantage contributes $\epsilon_\mathrm{PRF}$. $\blacksquare$

**HPKE-Stern-F: Niederreiter-Style KEM.**  Use the same $(H, \mathbf{s} = H\mathbf{e}^\top)$ for key encapsulation:

- **Encapsulate.**  Draw $\mathbf{e}' \xleftarrow{R} \{\mathrm{wt}(\cdot) = t\}$.  Session key $K = \mathcal{H}(\mathbf{e}')$; ciphertext $\mathbf{c} = H(\mathbf{e}')^\top$.
- **Decapsulate.**  Recover $\mathbf{e}'$ from $\mathbf{c} = H(\mathbf{e}')^\top$ using the private key $\mathbf{e}$ as a syndrome-decoding trapdoor.  Recompute $K = \mathcal{H}(\mathbf{e}')$.

For efficient decapsulation, $\mathbf{e}$ must embed a structured decoding trapdoor.  A direct application: derive the seed for a quasi-cyclic moderate-density parity-check (QC-MDPC) code (the BIKE design [Aragon et al. 2022]) via the NL-FSCX v1 PRF instead of a standard hash.  The security argument is unchanged; hardness remains quasi-cyclic syndrome decoding.

**QC-MDPC trapdoor prototype (TODO #126, v1.9.84).**  `SecurityProofsCode/qc_mdpc_bgf_prototype.py` implements this path end-to-end at toy scale: private sparse polynomials of odd weight $d$ over $\mathbb{GF}(2)\lbrack x\rbrack/(x^r - 1)$ with supports $h_0, h_1$; public key $h = h_1 \cdot h_0^{-1}$; syndrome $s = e_0 + e_1 \cdot h$; and a Black-Gray-Flip (BGF) decoder [Drucker-Gueron-Kostic 2019, adopted in BIKE v5].  The seed-expansion XOF is the HFSCX-256-DM counter-mode PRF — block $i$ is $F_1^{n/4}(\mathrm{ROL}(\text{seed} \oplus i, n/8), \text{seed} \oplus i)$ at $n = 256$ — with 16-bit rejection sampling to uniform indices.  Empirical results at $r = 523$, $d = 15$ ($w = 30$), $t = 18$: support-distribution chi-square consistent with uniform over 400 keygens; decoding failure rate 0/300 (0/500 across 5 keys during threshold tuning) with a two-phase threshold schedule; decapsulation ≈ 9 ms in Python versus a brute-force search of $\binom{1046}{18} \approx 2^{124}$ candidates.  The PRF substitution leaves the QCSD instance unchanged, so BIKE's production parameters carry over directly ($r = 12323$, $w = 142$, $t = 134$ for 128-bit security with extrapolated DFR $\leq 2^{-128}$).  Remaining for production: a constant-time C port of the rotation/popcount kernels, BIKE's weak-key rejection tests, and CLI integration.

**Quantum analysis for Option B.**

| Attacker | Algorithm | Complexity |
|---|---|---|
| Classical | ISD (Prange / BJMM) | $O(2^{0.054N})$ |
| Quantum | Quantum ISD (Kirshanova 2018) | $O(2^{0.042N})$ |
| Quantum | Grover brute-force | $O(2^{N/2})$ — dominated by ISD |

Syndrome decoding for random binary linear codes has no known polynomial quantum algorithm.  NIST alternates BIKE and HQC base their security on the quasi-cyclic special case of this same assumption.

**Deployed parameter caveat (2026 landscape review, TODO #71).**  The asymptotic exponents in the
table above apply in the regime where $N$ is large and the rate $k/N$ and relative distance $t/N$
are fixed.  At the deployed parameters $(N=256, k=128, t=16)$, the SDE estimator (Becker-Joux-May-Meurer,
2012) gives a concrete classical ISD estimate of approximately $2^{56}$–$2^{60}$ operations and a
quantum ISD estimate of approximately $2^{30}$–$2^{40}$ operations (Kirshanova 2018).  These are
**demonstration parameters only**; they do not achieve 128-bit security.  For reference, BIKE-128
(NIST alternate finalist) uses $N \approx 24646$, $t = 134$ to reach 128-bit classical and ~118-bit
quantum security.  The 128-bit classical floor requires approximately $N \geq 17000$ at $t/N \approx
0.0625$.  Until higher-$N$ parameters are adopted, HPKS-Stern-F and HPKE-Stern-F should be treated
as proof-of-concept implementations.

**2025–2026 ISD literature re-check (TODO #156).**  Three post-2024 ISD/syndrome-decoding
papers were reviewed against the $N \geq 17000$ production target above, plus a
cross-check against TODO #126's QC-MDPC parameters:

1. *"An Improved Both-May Information Set Decoding Algorithm: Towards More Efficient
   Time-Memory Trade-Offs"* [Furue-Aikawa, PQCrypto 2025, LNCS 15577 pp. 104-128,
   DOI 10.1007/978-3-031-86599-2_4]. The full text remains behind a Springer paywall,
   but the question it raised is now **resolved** on three independent grounds that do
   not require reading it:

   **(a) Wrong decoding regime.** The Both-May family targets *full distance decoding*
   (FDD) at high error rate — the setting of the original Both-May paper, *"Decoding
   Linear Codes with High Error Rate and its Impact for LPN Security"* (Eurocrypt 2018).
   In the FDD regime the best prior bound was BJMM's $2^{0.0953N}$, which Both-May
   lowered to $2^{0.0951N}$. HPKS-Stern-F/HPKE-Stern-F's demo parameters sit at
   $t/N = 16/256 = 0.0625$, and the QC-MDPC/BIKE production parameters at
   $t/N = 134/24646 \approx 0.0054$ — both far below full distance, in the low-weight
   regime governed instead by the half-distance exponent (May-Ozerov's $2^{0.0473N}$)
   and the $O(2^{0.054N})$ figure already cited above. FDD improvements are not the
   binding constraint for either construction.

   **(b) A trade-off curve, not a lower time exponent.** The paper's contribution, per
   its own title and abstract, is a more efficient asymptotic *time-memory trade-off*
   for the Both-May family — less memory at a given running time — not a reduction of
   the minimum-time exponent at unbounded memory. Even the family's headline FDD gain
   is a $0.0002$ change in the exponent constant.

   **(c) The underlying subroutine is galactic.** Both-May builds on the May-Ozerov
   nearest-neighbour subroutine, and that subroutine was proven *galactic* in 2025
   [Bouillaguet-Delaplace-Hamdad, *"The May-Ozerov Algorithm for Syndrome Decoding is
   Galactic"*, IACR Communications in Cryptology 2:1 (2025)]: it improves on plain
   Stern ISD only once the code length exceeds 1,874,400, at which point the attack
   itself costs more than $2^{63489}$ operations. No member of this family constrains
   concrete parameter selection anywhere in the $N \approx 17000$ to $24646$ range.

   **Resolution:** work items 1-2 of TODO #156 are closed as a negative result — the
   Furue-Aikawa improvement does not move the $N \geq 17000$ target, and no revision to
   the SDE-style worksheet is warranted. Should full text access become available, the
   figure to check is whether the improved trade-off lowers the *minimum-time* exponent
   in the low-weight regime; by the paper's own framing it does not.
2. *"Can we Speed up Information Set Decoding by Using Extension Field Structure?"*
   [Elbro-Weger, Cryptography and Communications 2025/2026, eprint 2025/1402]. This one
   **was** fully reviewed (open eprint). Its conclusion is negative for attackers:
   decoding over extension fields $\mathrm{GF}(2^m)$ is **not** easier than over prime
   fields of comparable size — expansion-map, subfield-subcode, and trace-map
   translation techniques were all checked and none produced a practical speedup, and
   Meurer's convergence result (advanced ISD variants collapsing back to Prange's
   exponent as parameters scale) was extended to this setting. HPKS-Stern-F/HPKE-Stern-F
   use plain binary $\mathrm{GF}(2)$ parity-check matrices (not an extension-field
   construction), so this paper's scope does not directly apply to the deployed
   construction either way, and its negative result gives no reason to revise the
   $N \geq 17000$ target.
3. **TODO #126 cross-check:** the QC-MDPC/Niederreiter trapdoor prototype (above) is a
   quasi-cyclic special case of ordinary binary syndrome decoding, not an extension-field
   or memory-bound-specific construction, so neither paper's findings change its
   $r = 12323$, $w = 142$, $t = 134$ BIKE-derived production parameters.
4. *"Refined Analysis of the Concrete Hardness of the Quasi-Cyclic Syndrome Decoding"*
   [Narisada-Okada-Aikawa-Fukushima, IWSEC 2025]. Added to this review as the most
   directly on-point QC-SD result: it re-estimates the concrete hardness of the syndrome
   decoding instances underlying BIKE, HQC, and Classic McEliece using Narisada et al.'s
   improved BJMM variant, with new record computations for the QC-3366, QC-3602, and
   QC-3846 challenge instances. Its bit-security estimates **closely match NIST's
   security requirements in most cases** — i.e. it *confirms* rather than erodes the
   BIKE-derived parameter set TODO #126 adopts, using an attack from the BJMM family
   that is genuinely practical (unlike the May-Ozerov/Both-May line in item 1).

**Net conclusion:** no revision to the $N \geq 17000$ / BIKE-128 parameter figures is
made. All four work items of TODO #156 are now resolved: the two ISD advances that
prompted the review are a negative result (item 2) and a non-binding, galactic-family
trade-off improvement in the wrong decoding regime (item 1), while the best available
concrete QC-SD re-analysis (item 4) independently corroborates the parameters in use.

---

### 11.8.5 Option C — Non-Abelian Research Direction

Theorem 15 establishes that $\{\pi_K : K \in \{0,1\}^n\}$ is a non-abelian family of permutations on $\{0,1\}^n$.  The **Conjugacy Search Problem** (CSP) for a non-abelian group $G$ is: given $u, v \in G$ with $v = g \cdot u \cdot g^{-1}$, find $g$.  No polynomial quantum algorithm is known for generic non-abelian CSP [Ettinger-Høyer-Knill 2004].

A candidate HPKS construction: choose random ephemeral $K_2$; let the public key be:

$$C = \pi_{K_1}\bigl(\pi_{K_2}\bigl(\pi_{K_1}^{-1}(G)\bigr)\bigr)$$

for a fixed public base point $G$.  Given $(C, \pi_{K_2})$, recovering $K_1$ is an instance of CSP in the group generated by the NL-FSCX v2 permutation family.

**Three obstacles prevent a complete security proof at this time:**

1. **Representation model.**  Standard CSP hardness is proven in the black-box model; NL-FSCX v2 is an explicit polynomial circuit.  An algebraic attacker can exploit the carry structure of $F_2$ directly rather than treating $\pi_K$ as a black box.  No transfer theorem from the black-box model to the circuit model is known for this problem.

2. **Group order lower bound.**  The period of NL-FSCX v2 orbits has no verified lower bound (analogous to the chaotic orbit lengths observed for v1 in §11.5 Q1).  Without a known lower bound on $|\langle \pi_K \rangle|$, small-subgroup confinement attacks cannot be excluded.

3. **No formal reduction to studied CSP.**  Braid group CSP hardness relies on specific group-theoretic properties not shared by permutation groups.  The transfer of hardness to the NL-FSCX v2 permutation family requires a dedicated reduction that does not currently exist.

This option is documented as a future research direction.

**Phase 0 decision gate — commuting-subgroup structure (TODO #78.E, v1.9.111).**  A Ko-Lee/Anshel-Anshel-Goldfeld (AAG) style key exchange over $\{\pi_K\}$ requires two independent commuting subgroups: Alice draws generators from one, Bob from the other, and correctness depends on the cross-commutators vanishing.  Before investing in the circuit-model CSP reduction (Obstacles 1 and 3 above), `SecurityProofsCode/nl_fscx_v2_csp.py` settles whether $\{\pi_K\}$ has any exploitable commuting structure at all, via three independent probes:

*Centralizer search ($\S$1).*  Exhaustive full-permutation commutativity test $\pi_{K_2} \circ \pi_{K_1} = \pi_{K_1} \circ \pi_{K_2}$ at $n \in \{4, 6, 8\}$: the centralizer of every $K_1$ tested has size $1$-$2$ (only $K_1$ itself and, at $n = 4$, one other key), with $0$ of $256$ keys at $n = 8$ having a centralizer larger than $2$.

*Theorem-15 necessary condition ($\S$2).*  The commutativity equation evaluated at $A = 0$, $\delta(K_1) - \delta(K_2) \equiv M(K_1 \oplus K_2) \pmod{2^n}$, is necessary but not sufficient for full commutativity, so its solution count upper-bounds $\S$1 and is cheap to compute exhaustively at larger $n$.  At $n \in \{8, 12\}$ (exhaustive) and $n = 16$ (sampled), the average solution count per $K_1$ stays flat near $1.9$-$2.0$ regardless of $n$ — meaning almost every $K_1$ has at most one non-trivial partner $K_2 \neq K_1$, not a growing coset.

*Subgroup-order growth ($\S$3).*  At $n \in \{4, 6\}$, two or three random generators $\{\pi_{K_1}, \ldots, \pi_{K_m}\}$ already generate a subgroup order that hits the search cap ($> 500000$) or a large fraction of $|\mathrm{Sym}(2^n)|$ — there is no proper subgroup with room for a structured, samplable KEX instance.

*Verdict.*  All three probes agree: centralizers are generically trivial, the necessary condition admits essentially no partner keys beyond $K_1$ itself, and a handful of generators already reach the full or near-full symmetric group.  This is decision-gate **VERDICT (a)**: Ko-Lee/AAG is **not instantiable** on $\{\pi_K\}$ — there are no two independent commuting subgroups to draw from.  Per the phased research plan's stated exit criteria, this is a **documented negative result** for the Ko-Lee/AAG instantiation of Option C; Phases 1-3 (orbit lower bound, circuit-model CSP transfer, formal reduction) are moot for that specific construction and are not pursued further.  A Stickel-type two-sided construction, $E = \pi_{K_1} \cdot A \cdot \pi_{K_2}$, does not require commutativity and remains a distinct, unexplored research direction if Option C is revisited.

**v2 cipher-stream-problem cryptanalysis status (TODO #124, v1.9.89).**  Independent of the conjugacy question above, the *cipher-stream problem* for NL-FSCX v2 — recovering $K$ from known-plaintext samples $C_i = F_2^r(P_i, K)$ — previously rested on Theorem 14's MQ argument alone, with none of the empirical cryptanalysis that v1 received (TODO #74/#75/#35).  `SecurityProofsCode/nl_fscx_v2_csp_analysis.py` closes that gap with the v1-equivalent battery:

*Offset structure.*  $\delta(K) = \mathrm{ROL}(K(K+1)/2 \bmod 2^n, n/4)$ is roughly 2-to-1: the image covers $\approx 0.55 \cdot 2^n$ values at $n \in \{8, 12, 16\}$ (140/256, 2220/4096, 35500/65536).  $\delta$-collision related-key pairs therefore exist, but no exploitable bias was found (next item).

*Related-key differential.*  At $n = 32$ with 50 000 trials per configuration, the output-difference distribution $F_2^r(A, K) \oplus F_2^r(A, K \oplus dK)$ is **flat at every round count tested, including $r = 1$** (top difference frequency within the uniform max-of-samples range, $\log_2 p \leq -13.3$), for $dK$ spanning low-bit, adjacent-bit, mid-bit, and end-around patterns.  Although the XOR layer propagates $dK$ linearly, the two independent constant-add carry words fully disperse the difference in a single step.  No related-key distinguisher exists at $n = 32$ even at one round.

*Algebraic degree (Theorem 14 verification).*  Exhaustive ANF over all keys at $n \in \{8, 12\}$: the key-to-output map has degree $\geq n - 2$ from $r = 1$ onward (mean degree $7.25$ of max $8$ at $n = 8$; $11.25$ of $12$ at $n = 12$).  Theorem 14's MQ claim is conservative — the actual system is dense and near-maximal-degree immediately, not merely quadratic.

*Key-recovery information.*  At $r = 3n/4$ (HSKE-A2 round count), a single known-plaintext pair leaves on average fewer than $2.1$ consistent keys ($40\%$ uniquely determined); two pairs determine $K$ uniquely in $\geq 99.5\%$ of trials.  The MQ system is heavily over-determined, as Theorem 14's $n$-equations-in-$n$-unknowns view predicts.

*Carry guess-and-determine.*  The only structural shortcut found: at $r = 1$, guessing the combined offset-plus-carry word collapses the step to a GF(2)-linear system in $K$.  Measured at $n = 12$, the guess space is the $\delta$-image ($\approx 2^{n-1}$), yielding only a $\approx 2\times$ speedup over brute force — and the linearization fails entirely at $r \geq 2$ because carries compose non-linearly across steps.  All deployed uses have $r \geq n/4 \geq 64$.

*Walsh spectrum of the key map.*  Exhaustive max linear bias of $K \mapsto F_2^r(P, K)$ at $n \in \{8, 12\}$: above the Bernstein random-function bound at $r \leq 2$, within range from $r = 4$ onward ($0.0952$ vs bound $0.0901$ at $n = 12$, $r = 4$; $0.0693$ at $r = 9$).  No exploitable linear structure at protocol round counts.

*Rotational rate.*  At $n = 32$, $r = 8$, 100 000 trials: both one-sided and two-sided rotational-equivariance rates are $0$ (no hits) for all $k \in \{1,2,4,8,16\}$ — versus v1's $1$–$6\%$ two-sided rate.  The integer multiplication inside $\delta(K)$ is not rotation-equivariant and destroys the FSCX base's rotational structure entirely; **v2 is strictly stronger than v1 rotationally**.

*Status.*  Cipher-stream-problem hardness for v2 remains a conjecture, but v2 now has the same empirical coverage as v1's OWF assumption, with no attack found beyond the $\approx 2\times$ single-round guess-and-determine.  Independent expert cryptanalysis is still required before treating it as a standard assumption.

---

### 11.8.6 Comparison and Recommendation

| | **Option A — HPKS-WOTS-F** | **Option B — HPKS / HPKE-Stern-F** | **Option C — NASG** |
|---|---|---|---|
| Protocols addressed | HPKS | HPKS + HPKE | HPKS |
| FSCX primitive | $F_1$ (v1) as OWF / hash | $F_1$ (v1) as PRF for matrix generation | $F_2$ (v2) permutation family |
| Hardness basis | NL-FSCX v1 OWF (**new assumption**) | $\mathrm{SD}(N,t)$ (NP-complete) + NL-FSCX v1 PRF | Non-abelian CSP; Ko-Lee/AAG instantiation ruled out (**negative result**) |
| Classical bound | $O(2^n)$ — Corollary 2 | $O(2^{0.054N})$ — ISD | Unknown |
| Quantum bound | $O(2^{n/2})$ — Grover | $O(2^{0.042N})$ — quantum ISD | Unknown |
| Reduction strength | Theorem 16: EUF-CMA $\leq$ OWF preimage | Theorem 17: EUF-CMA $\leq$ SD $\wedge$ PRF | No complete proof |
| Stateful? | Yes (Merkle tree for multi-use) | No (Fiat-Shamir in QROM) | — |

**What is algebraically established by this analysis:**

1. Shor's algorithm breaks HPKS-NL and HPKE-NL in $O(n^2 \log n)$ quantum time — §10.8.4 (established).
2. Inverting $F_1^r$ for $r \geq 2$ is a degree-$n$ Boolean system; Gröbner attacks offer no sub-exponential advantage — Theorem 13, Corollary 2.
3. Recovering $K$ from one evaluation pair of $F_2$ is MQ-hard, NP-complete for overdetermined instances — Theorem 14.
4. $F_2$ permutations are non-commutative for generic key pairs — Theorem 15.
5. HPKS-Stern-F EUF-CMA reduces to $\mathrm{SD}(N,t)$ (NP-complete [BMvT 1978]) and NL-FSCX v1 PRF — Theorem 17.
6. Best quantum attack on $\mathrm{SD}(N,t)$ is $O(2^{0.042N})$ quantum ISD [Kirshanova 2018]; no polynomial quantum algorithm is known.

**What remains a conjecture:** NL-FSCX v1 is a one-way function (required for both A and B via the GGM PRF chain); NL-FSCX v2 CSP hardness (C).

**Recommendation.**  Option B provides the only complete algebraic chain to an established NP-hard problem.  The NL-FSCX v1 PRF assumption it requires is identical to the assumption already implicit in HSKE-NL-A1's security argument (§11.3.1) — both protocols stand or fall on the same primitive.  Option A is simpler to implement as a near-term replacement for HPKS-NL using the existing NL-FSCX v1 primitive; it should be treated as a stopgap until NL-FSCX v1 OWF has received dedicated cryptanalysis.  Option C is algebraically native to $F_2$ but is not ready for deployment.

---

## 11.9 HFSCX-256-DM — Hash function on NL-FSCX v1

HFSCX-256-DM (deployed v1.9.0; originally HFSCX-256 from v1.5.24) is a 256-bit Merkle-Damgård hash built on NL-FSCX v1 with Davies-Meyer feed-forward compression.
It serves three roles in the suite:

- generic digest (the `dgst` subcommand of `HerraduraCli`),
- pre-hash for `sign` / `verify` flows (compresses arbitrary-length messages to a 256-bit input for HPKS / HPKS-NL / HPKS-Stern-F),
- authentication tag for `HSKE-NL-A1-CTR-AEAD` (large-file streaming encryption).

This section formalises the security claims for the deployed Davies-Meyer construction and is backed by `SecurityProofsCode/hfscx_256_analysis.py`.

### 11.9.1 Construction

Let $n = 256$, block size $b = 32$ bytes.  Write $F_1^r(s, m)$ for NL-FSCX v1 iterated $r$ times with state $s$ and message-block parameter $m$.  HFSCX-256-DM takes input bytes $D$ and an optional 256-bit key $K$; it produces a 256-bit digest as follows.

**Compression function (Davies-Meyer).**

$$C_{\text{DM}}(s, m) = F_1^{64}(s, m) \oplus s \in \{0,1\}^{256}.$$

**Initial state.**  Let $\text{IV-const}$ be the 32-byte ASCII constant `HFSCX-256/HERRADURA-SUITE\0\0\0\0\0\0\0` interpreted as a 256-bit integer.  Define

$$s_0 = \begin{cases} \text{IV-const} & \text{(unkeyed)} \cr K \oplus \text{IV-const} & \text{(keyed MAC mode)} \end{cases}$$

**Padding (ISO 7816-4 + finalization).**  Append `0x80` to $D$; zero-fill to a multiple of $b$; append a 32-byte finalization block $\mathit{fin}$:

$$\mathit{fin} = \bigl(8 \cdot |D|\bigr) \oplus s_0 \pmod{2^{256}}.$$

**Iteration.**  For padded message $D' = m_1 \| m_2 \| \cdots \| m_k$ (where the last block is $\mathit{fin}$):

$$s_i = C_{\text{DM}}(s_{i-1}, m_i) = F_1^{64}(s_{i-1}, m_i) \oplus s_{i-1}, \qquad i = 1, \ldots, k.$$

**Output.**  $\text{HFSCX-256-DM}(D, K) = s_k$.

### 11.9.2 Security model and assumptions

The security claims for HFSCX-256-DM are conditional on assumptions already used elsewhere in §11:

**A1 (NL-FSCX v1 PRF, §11.8.4).**  For random key $K$, the function $i \mapsto F_1^{64}(K \oplus i, K)$ is computationally indistinguishable from a uniformly random function $\{0,1\}^n \to \{0,1\}^n$ against polynomial-time distinguishers.

**A2 (NL-FSCX v1 OWF, §11.8.3, Theorem 16).**  Given $y = F_1^{64}(s, m)$ for known $m$ and unknown $s$, recovering $s$ requires $\Omega(2^n) = \Omega(2^{256})$ classical operations and $\Omega(2^{n/2}) = \Omega(2^{128})$ quantum queries (Grover lower bound; the classical bound is supported by Theorem 13's degree-saturation argument and Corollary 2's Gröbner-immunity result, which show no sub-exponential classical solver exists for the resulting degree-$n$ Boolean system).

**A3 (Symmetric structure).**  $F_1(A, B) = F_1(B, A)$, since

$$F_1(A, B) = M(A \oplus B) \oplus \mathrm{ROL}_{n/4}\bigl((A + B) \bmod 2^n\bigr)$$
is symmetric under the swap $A \leftrightarrow B$.  Consequently, NL-FSCX v1 is non-bijective in $B$ as well as in $A$ (§11.5 Q3, by symmetry); $C(\cdot, m)$ is non-bijective in either input.

A3 is structurally important: HFSCX-256-DM cannot claim ideal-cipher security from $C_{\text{DM}}$ as a pseudorandom permutation.  All hardness claims below are therefore PRF-based, not PRP-based.

### 11.9.3 Collision resistance

**Generic bound.**  For an ideal 256-bit hash, a generic collision search costs $\Theta(2^{n/2}) = \Theta(2^{128})$ classical operations (Pollard rho) or $\Theta(2^{n/3}) = \Theta(2^{85})$ quantum operations (BHT [Brassard-Høyer-Tapp 1997]).

**MD lemma.**  Any internal collision $C(s, m_1) = C(s', m_2)$ with $(s, m_1) \neq (s', m_2)$ propagates to a full hash collision through the standard Merkle-Damgård argument; conversely, every full collision implies an internal collision somewhere along the two chains.

**Heuristic claim.**  Under A1, the compression $C_{\text{DM}}$ is computationally indistinguishable from a random function $\{0,1\}^{256} \times \{0,1\}^{256} \to \{0,1\}^{256}$.  The expected number of evaluations to find a collision in such a function is $\sqrt{\pi \cdot 2^{n} / 2} \approx 2^{128.3}$.  Therefore, under A1, finding any HFSCX-256-DM collision requires $\approx 2^{128}$ work classically.

**Free-start collisions.**  Under the Davies-Meyer construction (§11.9.8), a free-start collision $C_{\text{DM}}(s_1, m_1) = C_{\text{DM}}(s_2, m_2)$ with $s_1 \neq s_2$ requires $F_1^{64}(s_1, m_1) \oplus F_1^{64}(s_2, m_2) = s_1 \oplus s_2$.  Even if $F_1^{64}$ maps both inputs to the same value (exploiting its non-bijectivity), that forces $s_1 = s_2$, contradicting the free-start hypothesis.  The $2^{128}$ bound is therefore structurally tighter than for the earlier plain-MD construction.

### 11.9.4 Preimage and second-preimage resistance

**Preimage.**  Given target digest $h$, find any $D$ with $\text{HFSCX-256-DM}(D) = h$.  Generic bound: $\Theta(2^n)$ classical, $\Theta(2^{n/2})$ quantum (Grover).  Reduction to A2: any preimage attack must invert $C_{\text{DM}}$ on the final compression (else the digest cannot match), contradicting A2.

**Second preimage.**  Given $D$, find $D' \neq D$ with the same digest.  Generic bound: $\Theta(2^n)$ classical (no birthday speed-up since one input is fixed).  Implied by collision resistance under standard hash arguments.

### 11.9.5 Length-extension resistance via finalization

A plain Merkle-Damgård hash without finalization admits the extension attack: given $h = H(D)$, an attacker can set the chain state to $h$ and continue, producing $H(D \| \mathrm{pad}(D) \| D')$ for arbitrary $D'$ without knowing $D$.

HFSCX-256-DM's finalization block makes the published digest $s_k = C_{\text{DM}}(s_{k-1}, \mathit{fin})$, where $s_{k-1}$ is the state after processing the real message blocks but before finalization.  The attacker is given $s_k$, not $s_{k-1}$.

**Theorem 18 — Length extension is infeasible under A2.**  Any extension attacker who, given $\text{HFSCX-256-DM}(D)$ alone, produces $\text{HFSCX-256-DM}(D \| X)$ for an attacker-chosen $X$ must recover $s_{k-1}$ from $s_k = C_{\text{DM}}(s_{k-1}, \mathit{fin})$ — an inversion of $C_{\text{DM}}$ that requires $\Omega(2^n)$ classical work (or $\Omega(2^{n/2})$ quantum work) under A2. $\blacksquare$

**Empirical confirmation.**  `hfscx_256_analysis.py` §5: 0 successful naive forgeries in 200 trials (the naive forgery treats $h_M$ directly as a chain state and processes one extension block using $C_{\text{DM}}$; this never matches the true digest of $D \| X$).

**Keyed mode bonus.**  In keyed mode the finalization block content is $(8|D|) \oplus K \oplus \text{IV-const}$, which the attacker cannot construct without $K$.  This adds a second layer of length-extension protection independent of A2.

### 11.9.6 Keyed mode and MAC use

HFSCX-256-DM supports a keyed mode by setting $s_0 = K \oplus \text{IV-const}$.  This mode is used by `HerraduraCli` for the `HSKE-NL-A1-CTR-AEAD` authentication tag.  Two MAC constructions are evaluated.

**(a) Raw keyed-IV MAC (deployed).**

$$\mathrm{MAC}(K, D) = \text{HFSCX-256-DM}(D, K).$$

*Properties.*  Under A1, HFSCX-256-DM with secret IV is a PRF: the chain state at every step is unpredictable to an adversary without $K$.  EUF-CMA security follows from the PRF property by standard arguments [Bellare-Canetti-Krawczyk 1996, §3.2].

*Caveat.*  The security claim applies A1 to the entire chain.  If A1 holds for one $F_1^{64}$ application but degrades when chained over many blocks, the raw keyed-IV MAC weakens.  Empirical avalanche tests (§11.9.10 §2) show ideal key-bit diffusion (mean 128.09 / 256 output bits flipped, σ = 7.98) for the deployed parameters, but this is a sanity check, not a chain-length proof.

**(b) HMAC-HFSCX-256-DM (recommended for cross-protocol key reuse).**

$$\mathrm{HMAC}(K, D) = \text{HFSCX-256-DM}\Bigl(\bigl(K \oplus \mathit{opad}\bigr) \| \text{HFSCX-256-DM}\bigl((K \oplus \mathit{ipad}) \| D\bigr)\Bigr)$$

with $\mathit{ipad} = \mathtt{0x36}$ repeated and $\mathit{opad} = \mathtt{0x5C}$ repeated, each 32 bytes.

*Properties.*  Bellare's HMAC proof [Bellare 2006] reduces HMAC security to two assumptions on the underlying compression function:

1. PRF under related-key attacks against the IV input.
2. Collision resistance of the compression.

Both follow from A1 + A2.  HMAC adds resistance against extension and key-recovery attacks even if the compression has minor structural weaknesses, at the cost of one extra hash invocation per MAC.

**Recommendation.**  The current single-purpose AEAD use is well-served by raw keyed-IV.  For protocols intending to reuse the same long-term key across multiple algorithms or modes (e.g. derive both an encryption key and a MAC key from one master), HMAC-HFSCX-256-DM should be preferred.  As of v1.9.48 (TODO #93), `hmac_hfscx_256(key, data)` / `HmacHfscx256` is available in the C, Go, and Python libraries; no existing call site is changed.

**HSKE-NL-AEAD (v1.9.33, TODO #95 option 1).**  The keyed-IV MAC mode is now also deployed as the tag of a general-purpose AEAD, `hske_nl_aead_encrypt` / `hske_nl_aead_decrypt` (C/Go/Python suites; CLI `enc`/`dec --aead`).  The construction is encrypt-then-MAC over the HSKE-NL-A1 CTR keystream with associated-data support: the tag is computed over the domain-separation prefix `HSKE-NL-AEAD-v1`, the nonce, and length-framed AD and ciphertext, with the MAC key derived from the same per-(key, nonce) schedule as the `.hkx` file format but separated from it by the DS prefix.  Because the tag binds the MAC key through the collision-resistant keyed chain, the scheme is *key-committing*: a ciphertext/tag pair cannot verify under two distinct keys without a keyed collision, ruled out by A2 — a property AES-GCM lacks.  Verification is constant-time and decrypt-after-verify.  A single-pass alternative — a MonkeyDuplex-style sponge AEAD using the bijective NL-FSCX v2 family as the duplex permutation (TODO #95 option 2) — remains open research; it requires the differential/linear characterisation of the v2 permutation tracked in TODO #99 before any deployment claim.

**HDRBG (v1.9.34, TODO #96).**  The bare hash mode also serves as the output filter of a forward-secure deterministic random bit generator, `drbg_seed` / `drbg_generate` / `drbg_reseed` (C/Go/Python suites).  The construction follows the fast-key-erasure pattern: each 32-byte output block is `HFSCX-256(state || counter_be8 || "DRBG-OUT")`, after which the state advances one-way via `nl_fscx_revolve_v1(state, DRBG-domain, 64)` and the superseded state is erased (`explicit_bzero` in C; best-effort in Go/Python).  Backtracking resistance reduces to the same NL-FSCX v1 OWF conjecture as Theorem 16.  Because the v1 state walk is non-bijective, walks can collide: `SecurityProofsCode/nl_fscx_v1_ratchet_collision.py` §5 measures the composed-walk image (the 64-step revolve image extrapolates to `2^218.8` at n = 256) and Brent rho/cycle lengths at n = 16–24, giving an expected walk-collision distance of `2^109.7` blocks; the enforced per-seed output limit of `2^20` blocks keeps the collision probability near `2^-180`, below the `2^-128` target.  *Non-goals:* HDRBG is not a NIST SP 800-90A validated DRBG — it has no health tests, prediction-resistance requests, or entropy-source assessment, and is intended only to expand seed material that is already full-entropy.

### 11.9.7 Domain separation across suite call sites

| Site | Role | Effective domain marker |
|---|---|---|
| `dgst` subcommand | generic digest | none — `iv = IV_const` |
| sign / verify pre-hash | message → 256-bit input | none — `iv = IV_const` |
| AEAD authentication tag | per-session MAC | $K \oplus \text{IV-const}$ ($K$ is the per-session MAC key, never zero) |
| `_stern_hash` | Stern commitment hash | distinct construction (rotates message into key slot, no finalization) — see §11.9.9 |

The `dgst` and pre-hash flows share the same effective IV.  This is acceptable when the input distributions cannot collide: the pre-hash flow always operates on attacker-supplied messages, but so does `dgst`, so a true cross-flow collision would only be an issue if (i) one flow appended additional content the other did not, *and* (ii) that content fell on a block boundary that mimicked the other's padding.  Neither holds in the current codebase.

The AEAD tag uses a distinct effective IV via the per-session key.  Cross-flow collision would require either a second-preimage on $\text{HFSCX-256-DM}(\cdot, K)$ for some $K$ (ruled out by collision resistance), or $K = 0$ (ruled out by the AEAD key-derivation step which produces $K$ from a Ring-LWR shared secret with negligible probability of $K = 0$).

**Hardening (v1.9.48, TODO #93).**  A domain-separated variant `hfscx_256_ds(ds, data)` is now available in the C, Go, and Python libraries.  The CLI exposes it as `dgst --algo hfscx-256-ds` with ds=0x01.  For a fully rigorous domain-separation argument that does not depend on collision-resistance reasoning, the suggested prefixes are: `0x01` for `dgst`, `0x02` for sign-pre-hash, `0x03` for AEAD-MAC.  Adoption at existing protocol call sites is a backwards-incompatible wire-format change and remains opt-in.

### 11.9.8 Davies-Meyer compression — DONE v1.9.0 (TODO #72)

As of v1.9.0 the compression function is the Davies-Meyer variant $C_{\text{DM}}(s, m) = F_1^{64}(s, m) \oplus s$ (see §11.9.1).  This section records the security benefits and the wire-format break.

**Benefits gained.**

1. **Fixed-point hardness.**  $C_{\text{DM}}(s, m) = s$ requires $F_1^{64}(s, m) = 0$, which under A2 requires $\Omega(2^n)$ classical work (preimage of zero under A2).  Before v1.9.0, fixed points were orbit-period-64 points of $F_1(\cdot, m)$; no formal lower bound existed, only empirical absence.
2. **Free-start collision hardness.**  As argued in §11.9.3, the Davies-Meyer structure rules out a structural speed-up from the non-bijectivity of $F_1$.
3. **PGV-1 alignment.**  $C_{\text{DM}}$ is one of the 12 provably-secure PGV compression functions [BRS 2002, PGV 1993].

**Wire-format note.**  This is a breaking change: all pre-v1.9.0 HFSCX-256 digests, pre-hashed signatures, and AEAD tags are incompatible with HFSCX-256-DM.  The cost per block is one 256-bit XOR (negligible).

### 11.9.9 `_stern_hash` QRO argument (TODO #36 — DONE v1.6.1)

As of v1.6.1 the Stern-F commitment hash is (ds = domain-separation tag):

$$\mathrm{StH}_{\mathrm{ds}}(v_1, \ldots, v_k) = \mathrm{HFSCX\text{-}256\text{-}DM}(h_k)[0{:}n/8], \quad h_0 = \mathrm{ds}, \quad h_i = F_1^{n/4}\bigl(h_{i-1} \oplus v_i, \mathrm{ROL}(v_i, n/8)\bigr)$$

Per-slot tags: ds=1 for c0, ds=2 for c1, ds=3 for c2, ds=4 for the KEM key, ds=0 for the Fiat-Shamir challenge.

**QRO argument.** Under the ROM on HFSCX-256-DM (§11.9.2, assumption A1), distinct per-slot ds values guarantee that c0, c1, c2, and the KEM key each invoke an independent random oracle.  By Unruh's composition theorem [Unruh 2015], this satisfies the QROM requirement for Theorem 17's Fiat-Shamir transform.  The range compression gap from TODO #42 (F_stern maps only ~24% of 2^32 inputs to distinct outputs at n=32) is resolved: the HFSCX-256-DM finalization maps the chained state through a full 256-bit hash before truncation, restoring the ~63.2% distinct-output fraction expected of a random function.

**Assembly/Arduino (n=32 toy demo).** The 32-bit `hfscx_32` finalizer and the KEM call with ds=4 provide the same QRO property for the KEM slot.  As of v1.9.48 (TODO #93), `stern_hash1_32`/`stern_hash2_32` carry explicit per-slot DS tags (ds=1 for $c_0$, ds=2 for $c_1$, ds=3 for $c_2$, ds=4 for the KEM key) in both the ARM Thumb-2 and NASM i386 implementations — the same tags as the C/Go/Python suite.  This satisfies the full QRO property at the assembly level and removes the prior reliance on structural distinctness.

### 11.9.10 Empirical evidence

`SecurityProofsCode/hfscx_256_analysis.py` measured the following at $n = 256$ (HFSCX-256-DM, v1.9.0):

| Test | Result | Interpretation |
|---|---|---|
| §1 Avalanche on input bit flips, 5 000 trials | mean = 128.013 / 256, σ = 7.980, range [99, 155] | Matches ideal random-function SAC (mean 128, σ ≈ 8 = $\sqrt{n/4}$). |
| §2 Avalanche on key bit flips (keyed mode), 5 000 trials | mean = 128.091 / 256, σ = 7.980, range [99, 159] | Matches ideal SAC; key bits diffuse fully through chain. |
| §3 Output Hamming weight uniformity, 5 000 trials | mean weight = 127.911, σ = 8.051 | Matches ideal output distribution. |
| §3 Byte-distribution chi², 5 000 × 32 bytes | $\chi^2 = 223.1$, df = 255 | $\chi^2 < 293.2$ (critical at $p = 0.05$); output bytes uniformly distributed. |
| §4 Collision sanity, $2^{17}$ trials (`--full`) | not run by default — birthday bound $2^{128}$ | Skipped: any observable collision below $2^{60}$ would falsify A1. |
| §5 Length-extension naive forgery, 200 trials | 0 / 200 successful | Confirms Theorem 18: finalization block defeats trivial extension. |
| §6 Domain separation (unkeyed vs keyed), 1 000 trials | 1000 / 1000 differ | Keyed mode distinct from unkeyed for all non-zero $K$. |
| §7 Fixed-point search (DM), 200 random $(s, m)$ pairs | 0 with $F_1^{64}(s,m)=0$, 0 near-zero | Fixed-point condition is preimage of zero under A2; no instances found, consistent with $\Omega(2^{256})$ classical hardness (§11.9.8). |

These tests rule out trivial weaknesses (low diffusion, biased output, length-extension, accidental key collisions, structural fixed points).  They do **not** constitute a formal proof: collision and preimage hardness rest on A1 + A2.

### 11.9.11 Summary

HFSCX-256-DM provides:

| Property | Bound | Assumption |
|---|---|---|
| Collision resistance | $2^{128}$ classical / $2^{85}$ quantum (BHT) | A1 |
| Preimage resistance | $2^{256}$ classical / $2^{128}$ quantum (Grover) | A2 |
| Second-preimage resistance | $2^{256}$ classical | A1 (collision implies 2nd-preimage) |
| Length-extension resistance | $2^{256}$ classical / $2^{128}$ quantum (Theorem 18) | A2 |
| MAC unforgeability (raw keyed-IV) | $2^{128}$ classical / $2^{128}$ quantum | A1 (full-chain PRF) |
| MAC unforgeability (HMAC, recommended for cross-protocol reuse) | as raw, plus related-key resistance | A1 + A2 [Bellare 2006] |

**Open hardenings** (not security-critical at current parameters):

1. ~~Switch to Davies-Meyer compression $C \oplus s$ at next major version (§11.9.8).~~ **DONE v1.9.0.**
2. ~~Add 1-byte domain-tag prefix per call site (§11.9.7).~~ **DONE v1.9.48** — `hfscx_256_ds(ds, data)` added to C, Go, Python libraries; `dgst --algo hfscx-256-ds` wired in all three CLIs (ds=0x01). Existing call sites unchanged (backward-compatible opt-in).
3. ~~Add HMAC-HFSCX-256-DM to the library (§11.9.6).~~ **DONE v1.9.48** — `hmac_hfscx_256(key, data)` / `HmacHfscx256` added to C, Go, Python libraries. Recommended when the same long-term key is reused across MAC and non-MAC modes; the current AEAD-only use retains the raw keyed-IV MAC.
4. ~~Assembly/Arduino per-slot DS tags on `stern_hash1_32`/`stern_hash2_32` (§11.9.9).~~ **DONE** — ARM Thumb-2 and NASM i386 implementations already carry ds=1/2/3/4 at all call sites (verified v1.9.48).

---


---

> **Continued in Part 5 — §11.10–§11.13, §11.15–§11.19** (SecurityProofs-5.md): Zero-Knowledge Proof Extensions · Research-Review Sections
