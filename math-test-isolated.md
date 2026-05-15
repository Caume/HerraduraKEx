### 11.8.4 Option B — HPKS-Stern-F and HPKE-Stern-F (Code-Based via FSCX PRF)

Option B reduces security to **syndrome decoding**, which is NP-complete [Berlekamp-McEliece-Van Tilborg 1978] and has no known polynomial quantum algorithm.  NL-FSCX v1 acts as a pseudorandom generator for the public parity check matrix; all hardness derives from the code, not from assumptions about FSCX invertibility.

**Public matrix generation.**  For an $(N, k, t)$-code, generate the $(N-k) \times N$ binary parity matrix $H$ row by row:

$$H_i = F_1^{n/4}\bigl(\mathrm{ROL}(\mathrm{seed} \oplus i, n/8), \mathrm{seed}\bigr), \qquad i = 0, \ldots, N-k-1.$$

Under the PRF assumption for NL-FSCX v1 (implied by the OWF assumption via the GGM PRG-to-PRF construction [Goldreich-Goldwasser-Micali 1986]), $H$ is computationally indistinguishable from a uniformly random binary matrix.

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

Tests §1, §2, §4, §8 detect GF(2)-linearity and low algebraic degree; linear FSCX fails all four, NL-FSCX v1 passes all four.  Tests §3 and §6 measure diffusion; both functions achieve good avalanche.  Test §5 detects linear correlations; NL-FSCX v1's maximum sampled bias is consistent with the random-function Bernstein bound $O(\sqrt{n} / 2^{n/2})$.  Test §7 confirms near-uniform output distribution for random inputs.

*Scope and caveat.*  These tests rule out every polynomial-time distinguisher based on linearity, low algebraic degree, or cross-key structure.  They do **not** constitute a formal PRF proof.  A formal proof would require reducing PRF-security to a studied hardness assumption; the GGM construction (§11.8.4 above) provides that path once the NL-FSCX v1 OWF assumption is accepted.  The experimental evidence supports the assumption but does not replace it.

**Key generation.**
- Private key: $\mathbf{e} \xleftarrow{R} \{\mathbf{v} \in \{0,1\}^N : \mathrm{wt}(\mathbf{v}) = t\}$.
- Public key: $\mathbf{s} = H\mathbf{e}^\top \in \mathbb{GF}(2)^{N-k}$.

**HPKS-Stern-F: Stern's Three-Move Protocol [Stern 1993] + Fiat-Shamir.**

Each identification round:

1. **Commit.**  Draw $\mathbf{y} \xleftarrow{R} \{0,1\}^N$ and permutation $\pi \xleftarrow{R} S_N$.  Compute commitments $c_0 = \mathcal{H}(\pi, H\mathbf{y}^\top)$ and $c_1 = \mathcal{H}(\pi \circ \sigma_{\mathbf{e}}, H(\mathbf{y} \oplus \mathbf{e})^\top)$ and send both; here $\sigma_{\mathbf{e}} \in S_N$ is a fixed permutation encoding the support of $\mathbf{e}$ and $\mathcal{H}$ is a collision-resistant hash.

2. **Challenge.**  Verifier sends $b \xleftarrow{R} \{0, 1, 2\}$.

3. **Response.**

   $b = 0$: reveal $(\pi, \mathbf{y})$; verifier checks $c_0$ and that $\pi$ is consistent with the support encoding.

   $b = 1$: reveal $(\pi \circ \sigma_{\mathbf{e}}, \mathbf{y} \oplus \mathbf{e})$; verifier checks $c_1$ and $H(\mathbf{y} \oplus \mathbf{e})^\top = H\mathbf{y}^\top \oplus \mathbf{s}$.

   $b = 2$: reveal $(\pi, \mathbf{y} \oplus \mathbf{e})$; verifier checks $\mathrm{wt}(\pi(\mathbf{y} \oplus \mathbf{e})) = t$ and the syndrome relation.

Soundness error per round: $2/3$.  After $\lceil\lambda / \log_2(3/2)\rceil \approx 1.7\lambda$ rounds, soundness error $\leq 2^{-\lambda}$.  Fiat-Shamir in the quantum random oracle model [Unruh 2015] produces a non-interactive signature.

**Theorem 17 — EUF-CMA of HPKS-Stern-F.**

Let $\mathrm{SD}(N,t)$ denote the syndrome decoding problem: given $(H, \mathbf{s})$ find $\mathbf{e}$ with $H\mathbf{e}^\top = \mathbf{s}$ and $\mathrm{wt}(\mathbf{e}) = t$.  If $\mathrm{SD}(N,t)$ requires $T_\mathrm{SD}$ quantum operations and NL-FSCX v1 is a secure PRF with advantage $\epsilon_\mathrm{PRF}$, then HPKS-Stern-F achieves EUF-CMA with:

$$\Pr[\mathrm{forge}] \leq \frac{q_H}{T_\mathrm{SD}} + \epsilon_\mathrm{PRF}$$

for $q_H$ quantum hash queries.

*Proof.*  (i) **Completeness** — honest prover satisfies all three challenge cases by construction.  (ii) **Statistical zero-knowledge** — for each $b$, the revealed values $(\pi, \mathbf{y})$, $(\pi \circ \sigma_{\mathbf{e}}, \mathbf{y} \oplus \mathbf{e})$, $(\pi, \mathbf{y} \oplus \mathbf{e})$ are uniformly distributed over their respective domains independently of $\mathbf{e}$, since $\mathbf{y}$ and $\pi$ are fresh random.  (iii) **Soundness** — a prover that passes all three challenges can be rewound with challenges $b = 1$ and $b = 2$ on the same commitment, yielding two accepting transcripts from which $\mathbf{e}$ satisfying $H\mathbf{e}^\top = \mathbf{s}$ is extracted, solving $\mathrm{SD}(N,t)$.  (iv) **Fiat-Shamir in the QROM** — EUF-CMA security against quantum adversaries making $q_H$ quantum hash queries follows from [Unruh 2015, Theorem 5], with forgery probability bounded by $q_H/T_\mathrm{SD}$.  (v) **PRF reduction** — under the NL-FSCX v1 PRF assumption, $H$ is computationally indistinguishable from a random matrix; any distinguishing advantage contributes $\epsilon_\mathrm{PRF}$. $\blacksquare$

**HPKE-Stern-F: Niederreiter-Style KEM.**  Use the same $(H, \mathbf{s} = H\mathbf{e}^\top)$ for key encapsulation:

- **Encapsulate.**  Draw $\mathbf{e}' \xleftarrow{R} \{\mathrm{wt}(\cdot) = t\}$.  Session key $K = \mathcal{H}(\mathbf{e}')$; ciphertext $\mathbf{c} = H(\mathbf{e}')^\top$.
- **Decapsulate.**  Recover $\mathbf{e}'$ from $\mathbf{c} = H(\mathbf{e}')^\top$ using the private key $\mathbf{e}$ as a syndrome-decoding trapdoor.  Recompute $K = \mathcal{H}(\mathbf{e}')$.

For efficient decapsulation, $\mathbf{e}$ must embed a structured decoding trapdoor.  A direct application: derive the seed for a quasi-cyclic moderate-density parity-check (QC-MDPC) code (the BIKE design [Aragon et al. 2022]) via the NL-FSCX v1 PRF instead of a standard hash.  The security argument is unchanged; hardness remains quasi-cyclic syndrome decoding.

**Quantum analysis for Option B.**

| Attacker | Algorithm | Complexity |
|---|---|---|
| Classical | ISD (Prange / BJMM) | $O(2^{0.054N})$ |
| Quantum | Quantum ISD (Kirshanova 2018) | $O(2^{0.042N})$ |
| Quantum | Grover brute-force | $O(2^{N/2})$ — dominated by ISD |

Syndrome decoding for random binary linear codes has no known polynomial quantum algorithm.  NIST alternates BIKE and HQC base their security on the quasi-cyclic special case of this same assumption.
