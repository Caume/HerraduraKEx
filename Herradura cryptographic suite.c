/*  Herradura Cryptographic Suite v1.6.1

    Copyright (C) 2024-2026 Omar Alejandro Herrera Reyna

    This program is free software: you can redistribute it and/or modify
    it under the terms of the MIT License or the GNU General Public License
    as published by the Free Software Foundation, either version 3 of the License,
    or (at your option) any later version.

    Under the terms of the GNU General Public License, please also consider that:

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.

    --- v1.5.18: HPKS-Stern-F + HPKE-Stern-F code-based PQC (Theorem 17, §11.8.4) ---
    Stern 3-challenge ZKP + Fiat-Shamir in QROM; security reduces to SD(N,t) + NL-FSCX PRF.
    N=256, n_rows=128, t=16, rounds=32 (production: >=219 for 128-bit soundness).

    --- v1.5.17: NTT twiddle precomputation — lazy-initialized static table eliminates rnl_mod_pow calls per rnl_poly_mul ---

    --- v1.5.13: HSKE-NL-A1 seed fix — ROL(base, n/8) breaks counter=0 step-1 degeneracy ---

    HSKE-NL-A1 keystream: seed = ba_rol_k(base, n/8); ks = nl_fscx_revolve_v1(seed, base^ctr, n/4).
    When A=B=base (counter=0), fscx(base,base)=0 so step 1 was a pure rotation (linear).
    ROL(base,n/8) ensures seed!=base, activating full carry non-linearity from step 1.
    Same degeneracy pattern fixed for HKEX-RNL KDF in v1.5.10; now applied consistently.
    Also fixes stale q=3329 comment (was 65537 since v1.5.4).

    --- v1.5.10: HKEX-RNL KDF seed fix — ROL(K, n/8) breaks step-1 degeneracy ---

    HKEX-RNL KDF: seed = ba_rol_k(K, n/8); sk = nl_fscx_revolve_v1(seed, K, n/4).
    When A0=B=K, fscx(K,K)=0 so step 1 was a pure rotation (linear).
    ROL(K,n/8) ensures seed!=K, activating full carry non-linearity from step 1.

    --- v1.5.9: HSKE-NL-A1 per-session nonce; nl_fscx_revolve_v2_inv_ba delta precompute ---
    HSKE-NL-A1 now generates a random per-session nonce N and derives session base
    = K XOR N (transmitted alongside ciphertext).  Eliminates keystream reuse when
    the same long-term key K is used across sessions.
    nl_fscx_revolve_v2_inv_ba precomputes delta(B) once before the loop.
    Loop body: ba_sub256(z, buf, delta); m_inv_ba(mz, z); ba_xor(buf, b, mz).
    Eliminates one nl_fscx_delta_v2 call (arbitrary-precision mul+rol) per step.

    --- v1.5.7: precomputed M^{-1} for nl_fscx_v2_inv_ba ---
    m_inv_ba now computes the rotation table for M^{-1} = M^{127}(X) once on first call
    (bootstrapping from ba_fscx_revolve(1, 0, 127)), caches the rotation offsets in a
    static array, then applies M^{-1}(X) as XOR of ba_rol_k(X, k) for each k in the
    table.  New ba_rol_k helper performs arbitrary-bit cyclic rotation on 256-bit arrays.

    --- v1.5.6: rnl_rand_poly bias fix — 3-byte rejection sampling ---
    rnl_rand_poly now draws 3 bytes (24-bit) with rejection sampling (threshold =
    (1<<24) - (1<<24)%RNL_Q = 16711935) to eliminate the ~1/2^32 modular bias.

    --- v1.5.4: NTT-based negacyclic polynomial multiplication (O(n log n)) ---
    rnl_poly_mul now uses Cooley-Tukey NTT over Z_{65537} with negacyclic twist.

    --- v1.5.3: HKEX-RNL secret sampler upgraded to CBD(eta=1) ---

    HKEX-RNL secret polynomial now uses a centered binomial distribution CBD(eta=1)
    instead of the previous uniform {0,1} sampler.  CBD(1) produces coefficients in
    {-1, 0, 1} (stored mod q) with zero mean, matching the Kyber/NIST baseline for
    proper Ring-LWR hardness without changing the noise budget.

    --- v1.5.0: NL-FSCX non-linear extension and PQC extensions ---

    New in v1.5.0:
      - NL-FSCX v1: fscx(A,B) XOR ROL((A+B) mod 2^n, n/4)
        Breaks additive linearity; used in HSKE-NL-A1 (counter-mode) and HPKS-NL.
      - NL-FSCX v2: fscx(A,B) + delta(B) mod 2^n, with invertible delta(B).
        Fully bijective; used in HSKE-NL-A2 (revolve-mode) and HPKE-NL.
      - HSKE-NL-A1: counter-mode symmetric encryption with NL-FSCX v1 keystream.
      - HSKE-NL-A2: revolve-mode symmetric encryption with NL-FSCX v2 (invertible).
      - HKEX-RNL: Ring-LWR key exchange (n=256; conjectured quantum-resistant).
      - HPKS-NL: NL-hardened Schnorr signature using NL-FSCX v1 challenge.
      - HPKE-NL: NL-hardened El Gamal encryption using NL-FSCX v2.

    All protocols operate at KEYBITS=256 by default.

    --- v1.4.0: HKEX replaced with HKEX-GF (Diffie-Hellman over GF(2^n)*) ---

    HKEX-GF replaces HKEX with Diffie-Hellman over GF(2^KEYBITS)*:
      - Alice: private scalar a, public C  = g^a  (GF exponentiation)
      - Bob:   private scalar b, public C2 = g^b
      - Shared: sk = C2^a = C^b = g^{ab}  (field commutativity)

    --- v1.3.2: performance and readability ---
    --- v1.3: BitArray (multi-byte parameter support) ---

    The C implementation uses a BitArray type: a fixed-width bit string backed
    by a big-endian byte array.  Default key size is 256 bits.

    The key size is controlled by KEYBITS (must be a positive multiple of 8
    and >= 16).  Change the #define to use a different bit width; all
    parameters and step counts scale automatically.
*/

/* Build: gcc -O2 -o "Herradura cryptographic suite" "Herradura cryptographic suite.c" */

#include "herradura.h"

/* ─────────────────────────────────────────────────────────────────────────────
 * HPKE-Stern-F N=32 brute-force demo helpers  (N=32, t=2, C(32,2)=496)
 * ───────────────────────────────────────────────────────────────────────────── */

#define SDF32_N     32
#define SDF32_T     2
#define SDF32_NROWS 16

static uint32_t s32_fscx(uint32_t a, uint32_t b)
{
    uint32_t r1a = (a << 1) | (a >> 31), r1b = (b << 1) | (b >> 31);
    uint32_t r1ar = (a >> 1) | (a << 31), r1br = (b >> 1) | (b << 31);
    return a ^ b ^ r1a ^ r1b ^ r1ar ^ r1br;
}

static uint32_t s32_nl_revolve(uint32_t a, uint32_t b, int steps)
{
    int i;
    for (i = 0; i < steps; i++)
        a = s32_fscx(a, b) ^ (((a + b) << 8) | ((a + b) >> 24));
    return a;
}

static uint32_t stern32_matrix_row(uint32_t seed, int row)
{
    uint32_t sxr = seed ^ (uint32_t)row;
    uint32_t a0  = (sxr << 4) | (sxr >> 28);  /* ROL by n/8 = 4 bits */
    return s32_nl_revolve(a0, seed, 8);        /* I = n/4 = 8 steps   */
}

static uint16_t stern32_syndrome(uint32_t seed, uint32_t e)
{
    uint16_t s = 0;
    int i;
    for (i = 0; i < SDF32_NROWS; i++)
        if (__builtin_popcount(stern32_matrix_row(seed, i) & e) & 1)
            s |= (uint16_t)(1u << i);
    return s;
}

static uint32_t stern32_hash(uint32_t h, uint32_t v)
{
    uint32_t key = (v << 4) | (v >> 28);
    uint32_t raw = s32_nl_revolve(h ^ v, key, 8);
    uint8_t buf[4], digest[32];
    buf[0]=(uint8_t)(raw>>24); buf[1]=(uint8_t)(raw>>16);
    buf[2]=(uint8_t)(raw>> 8); buf[3]=(uint8_t)(raw);
    hfscx_256(buf, 4, NULL, digest);
    return ((uint32_t)digest[0]<<24)|((uint32_t)digest[1]<<16)|
           ((uint32_t)digest[2]<< 8)| (uint32_t)digest[3];
}

static uint32_t stern32_rand_error(FILE *urnd)
{
    uint8_t idx[SDF32_N];
    uint32_t e = 0;
    int i;
    for (i = 0; i < SDF32_N; i++) idx[i] = (uint8_t)i;
    for (i = SDF32_N - 1; i >= SDF32_N - SDF32_T; i--) {
        unsigned int range = (unsigned int)(i + 1);
        unsigned int thresh = 256 - (256 % range);
        uint8_t rnd;
        int j;
        do {
            if (fread(&rnd, 1, 1, urnd) != 1) { fputs("urandom error\n", stderr); exit(1); }
        } while ((unsigned int)rnd >= thresh);
        j = (int)(rnd % range);
        { uint8_t tmp = idx[i]; idx[i] = idx[j]; idx[j] = tmp; }
        e |= 1u << idx[i];
    }
    return e;
}

static uint32_t hpke_stern_f_encap_32(uint32_t seed, uint16_t *ct_out,
                                        uint32_t *e_out, FILE *urnd)
{
    uint32_t e_p = stern32_rand_error(urnd);
    *ct_out = stern32_syndrome(seed, e_p);
    *e_out  = e_p;
    return stern32_hash(stern32_hash(4, seed), e_p);  /* ds=4: KEM key slot */
}

static uint32_t hpke_stern_f_decap_32(uint32_t seed, uint16_t ct)
{
    int i, j;
    for (i = 0; i < SDF32_N; i++)
        for (j = i + 1; j < SDF32_N; j++) {
            uint32_t e_p = (1u << i) | (1u << j);
            if (stern32_syndrome(seed, e_p) == ct)
                return stern32_hash(stern32_hash(4, seed), e_p);  /* ds=4: KEM key slot */
        }
    return 0xFFFFFFFFu; /* decode failed */
}

int main(void)
{
    FILE *urnd;
    BitArray a, b, preshared, plaintext, decoy;
    BitArray C, C2;
    /* saved for Eve tests */
    BitArray E_nl_saved, R_nl2_saved, sk_rnl_A_saved;
    BitArray sf_seed_saved, sf_K_enc_saved;
    uint8_t  sf_syn_saved[SDF_SYNBYTES];

    urnd = fopen("/dev/urandom", "rb");
    if (!urnd) {
        fputs("ERROR: cannot open /dev/urandom\n", stderr);
        return 1;
    }

    ba_rand(&a,         urnd);
    ba_rand(&b,         urnd);
    ba_rand(&preshared, urnd);
    ba_rand(&plaintext, urnd);
    ba_rand(&decoy,     urnd);

    /* Precompute GF DH public keys */
    gf_pow_ba(&C,  &GF_GEN, &a);
    gf_pow_ba(&C2, &GF_GEN, &b);

    ba_print_hex("a         : ", &a);
    ba_print_hex("b         : ", &b);
    ba_print_hex("preshared : ", &preshared);
    ba_print_hex("plaintext : ", &plaintext);
    ba_print_hex("decoy     : ", &decoy);
    ba_print_hex("C         : ", &C);
    ba_print_hex("C2        : ", &C2);

    /* --- HKEX-GF [CLASSICAL -- not PQC; Shor's algorithm breaks DLP] */
    printf("\n--- HKEX-GF [CLASSICAL \xe2\x80\x94 not PQC; Shor's algorithm breaks DLP]\n");
    printf("    (DH over GF(2^%d)*)\n", KEYBITS);
    {
        BitArray skA, skB;
        gf_pow_ba(&skA, &C2, &a);
        gf_pow_ba(&skB, &C,  &b);
        ba_print_hex("sk (Alice): ", &skA);
        ba_print_hex("sk (Bob)  : ", &skB);
        if (ba_equal(&skA, &skB))
            puts("+ session keys agree!");
        else
            puts("- session keys differ!");
    }

    /* --- HSKE [CLASSICAL -- not PQC; linear key recovery from 1 KPT pair] */
    printf("\n--- HSKE [CLASSICAL \xe2\x80\x94 not PQC; linear key recovery from 1 KPT pair]\n");
    puts("    (fscx_revolve symmetric encryption)");
    {
        BitArray E_hske, D_hske;
        ba_print_hex("P (plain) : ", &plaintext);
        ba_fscx_revolve(&E_hske, &plaintext, &preshared, I_VALUE);
        ba_print_hex("E (Alice) : ", &E_hske);
        ba_fscx_revolve(&D_hske, &E_hske, &preshared, R_VALUE);
        ba_print_hex("D (Bob)   : ", &D_hske);
        if (ba_equal(&D_hske, &plaintext))
            puts("+ plaintext correctly decrypted");
        else
            puts("- decryption failed!");
    }

    /* --- HPKS [CLASSICAL -- not PQC; DLP + linear challenge] */
    printf("\n--- HPKS [CLASSICAL \xe2\x80\x94 not PQC; DLP + linear challenge]\n");
    puts("    (Schnorr-like with fscx_revolve challenge)");
    {
        BitArray k_s, R_s, e_s, ae_s, s_s, gs, Ce, lhs;
        ba_rand(&k_s, urnd);
        gf_pow_ba(&R_s, &GF_GEN, &k_s);
        ba_fscx_revolve(&e_s, &R_s, &plaintext, I_VALUE);
        /* s = (k - a*e) mod (2^256-1) */
        ba_mul_mod_ord(&ae_s, &a, &e_s);
        ba_sub_mod_ord(&s_s, &k_s, &ae_s);
        /* verify: g^s * C^e == R */
        gf_pow_ba(&gs, &GF_GEN, &s_s);
        gf_pow_ba(&Ce, &C, &e_s);
        gf_mul_ba(&lhs, &gs, &Ce);
        ba_print_hex("P (msg)        : ", &plaintext);
        ba_print_hex("R [Alice,sign] : ", &R_s);
        ba_print_hex("e [Alice,sign] : ", &e_s);
        ba_print_hex("s [Alice,sign] : ", &s_s);
        ba_print_hex("  [Bob,verify] : g^s\xc2\xb7""C^e = ", &lhs);
        if (ba_equal(&lhs, &R_s))
            puts("  [Bob,verify] : + Schnorr verified: g^s \xc2\xb7 C^e == R");
        else
            puts("  [Bob,verify] : - Schnorr verification failed!");
    }

    /* --- HPKE [CLASSICAL -- not PQC; DLP + linear HSKE sub-protocol] */
    printf("\n--- HPKE [CLASSICAL \xe2\x80\x94 not PQC; DLP + linear HSKE sub-protocol]\n");
    puts("    (El Gamal + fscx_revolve)");
    {
        BitArray r_hpke, R_hpke, enc_key, E_hpke, dec_key, D_hpke;
        ba_rand(&r_hpke, urnd);
        gf_pow_ba(&R_hpke,  &GF_GEN, &r_hpke);
        gf_pow_ba(&enc_key, &C,      &r_hpke);
        ba_fscx_revolve(&E_hpke, &plaintext, &enc_key, I_VALUE);
        gf_pow_ba(&dec_key, &R_hpke, &a);
        ba_fscx_revolve(&D_hpke, &E_hpke, &dec_key, R_VALUE);
        ba_print_hex("P (plain) : ", &plaintext);
        ba_print_hex("E (Bob)   : ", &E_hpke);
        ba_print_hex("D (Alice) : ", &D_hpke);
        if (ba_equal(&D_hpke, &plaintext))
            puts("+ plaintext correctly decrypted");
        else
            puts("- decryption failed!");
    }

    /* --- HSKE-NL-A1 [PQC-HARDENED -- counter-mode with NL-FSCX v1] */
    printf("\n--- HSKE-NL-A1 [PQC-HARDENED \xe2\x80\x94 counter-mode with NL-FSCX v1]\n");
    {
        BitArray N_a1, base_a1, ks_nl1, E_nl1, D_nl1;
        ba_rand(&N_a1, urnd);                         /* per-session nonce          */
        ba_xor(&base_a1, &preshared, &N_a1);          /* base = K XOR N             */
        BitArray seed_a1;
        ba_rol_k(&seed_a1, &base_a1, KEYBYTES);       /* seed = ROL(base, n/8)      */
        nl_fscx_revolve_v1_ba(&ks_nl1, &seed_a1, &base_a1, I_VALUE); /* counter=0  */
        ba_xor(&E_nl1, &plaintext, &ks_nl1);
        ba_xor(&D_nl1, &E_nl1,    &ks_nl1);
        ba_print_hex("N (nonce) : ", &N_a1);
        ba_print_hex("P (plain) : ", &plaintext);
        ba_print_hex("E (Alice) : ", &E_nl1);
        ba_print_hex("D (Bob)   : ", &D_nl1);
        if (ba_equal(&D_nl1, &plaintext))
            puts("+ plaintext correctly decrypted");
        else
            puts("- decryption failed!");
    }

    /* --- HSKE-NL-A2 [PQC-HARDENED -- revolve-mode with NL-FSCX v2] */
    printf("\n--- HSKE-NL-A2 [PQC-HARDENED \xe2\x80\x94 revolve-mode with NL-FSCX v2]\n");
    {
        BitArray E_nl2, D_nl2;
        nl_fscx_revolve_v2_ba(&E_nl2, &plaintext, &preshared, R_VALUE);
        nl_fscx_revolve_v2_inv_ba(&D_nl2, &E_nl2, &preshared, R_VALUE);
        ba_print_hex("P (plain) : ", &plaintext);
        ba_print_hex("E (Alice) : ", &E_nl2);
        ba_print_hex("D (Bob)   : ", &D_nl2);
        if (ba_equal(&D_nl2, &plaintext))
            puts("+ plaintext correctly decrypted");
        else
            puts("- decryption failed!");
    }

    /* --- HKEX-RNL [PQC -- Ring-LWR key exchange; conjectured quantum-resistant] */
    printf("\n--- HKEX-RNL [PQC \xe2\x80\x94 Ring-LWR key exchange; conjectured quantum-resistant]\n");
    puts("    (Ring-LWR, m(x)=1+x+x^{n-1}, n=256, q=65537)");
    {
        rnl_poly_t m_base, a_rand_poly, m_blind;
        rnl_poly_t s_A_poly, s_B_poly;
        int32_t C_A[RNL_N], C_B[RNL_N];
        BitArray KA, KB, skA_nl, skB_nl;
        int i, bits_diff;
        BitArray diff_ba;

        rnl_m_poly(m_base);
        rnl_rand_poly(a_rand_poly, urnd);
        rnl_poly_add(m_blind, m_base, a_rand_poly);
        uint8_t hint_A[RNL_N / 8];
        rnl_keygen(s_A_poly, C_A, m_blind, urnd);
        rnl_keygen(s_B_poly, C_B, m_blind, urnd);
        rnl_agree(&KA, s_A_poly, C_B, NULL, hint_A);   /* Alice: reconciler */
        rnl_agree(&KB, s_B_poly, C_A, hint_A, NULL);   /* Bob: receiver */
        BitArray seedA, seedB;
        ba_rol_k(&seedA, &KA, KEYBYTES);           /* ROL(K, n/8) = ROL(K, 32) */
        nl_fscx_revolve_v1_ba(&skA_nl, &seedA, &KA, I_VALUE);
        ba_rol_k(&seedB, &KB, KEYBYTES);
        nl_fscx_revolve_v1_ba(&skB_nl, &seedB, &KB, I_VALUE);
        ba_print_hex("sk (Alice): ", &skA_nl);
        ba_print_hex("sk (Bob)  : ", &skB_nl);
        if (ba_equal(&KA, &KB)) {
            puts("+ raw key bits agree; shared session key established!");
        } else {
            ba_xor(&diff_ba, &KA, &KB);
            bits_diff = 0;
            for (i = 0; i < KEYBYTES; i++)
                bits_diff += __builtin_popcount(diff_ba.b[i]);
            printf("- raw key disagrees (%d bit(s)) \xe2\x80\x94 rounding noise (retry)\n",
                   bits_diff);
        }
        sk_rnl_A_saved = skA_nl;
    }

    /* --- HPKS-NL [NL-hardened Schnorr -- NL-FSCX v1 challenge] */
    printf("\n--- HPKS-NL [NL-hardened Schnorr \xe2\x80\x94 NL-FSCX v1 challenge]\n");
    puts("    (GF DLP still present; NL hardens linear challenge preimage)");
    {
        BitArray k_nl, R_nl, e_nl, ae_nl, s_nl, gs_nl, Ce_nl, lhs_nl;
        ba_rand(&k_nl, urnd);
        gf_pow_ba(&R_nl, &GF_GEN, &k_nl);
        nl_fscx_revolve_v1_ba(&e_nl, &R_nl, &plaintext, I_VALUE);
        ba_mul_mod_ord(&ae_nl, &a, &e_nl);
        ba_sub_mod_ord(&s_nl, &k_nl, &ae_nl);
        /* verify */
        nl_fscx_revolve_v1_ba(&e_nl, &R_nl, &plaintext, I_VALUE);
        gf_pow_ba(&gs_nl, &GF_GEN, &s_nl);
        gf_pow_ba(&Ce_nl, &C, &e_nl);
        gf_mul_ba(&lhs_nl, &gs_nl, &Ce_nl);
        ba_print_hex("P (msg)        : ", &plaintext);
        ba_print_hex("R [Alice,sign] : ", &R_nl);
        ba_print_hex("e [Alice,sign] : ", &e_nl);
        ba_print_hex("s [Alice,sign] : ", &s_nl);
        ba_print_hex("  [Bob,verify] : g^s\xc2\xb7""C^e = ", &lhs_nl);
        if (ba_equal(&lhs_nl, &R_nl))
            puts("  [Bob,verify] : + HPKS-NL verified: g^s \xc2\xb7 C^e == R");
        else
            puts("  [Bob,verify] : - HPKS-NL verification failed!");
    }

    /* --- HPKE-NL [NL-hardened El Gamal -- NL-FSCX v2 encryption] */
    printf("\n--- HPKE-NL [NL-hardened El Gamal \xe2\x80\x94 NL-FSCX v2 encryption]\n");
    puts("    (GF DLP still present; NL hardens linear HSKE sub-protocol)");
    {
        BitArray r_nl, R_nl2, enc_nl, E_nl, dec_nl, D_nl;
        ba_rand(&r_nl, urnd);
        gf_pow_ba(&R_nl2,  &GF_GEN, &r_nl);
        gf_pow_ba(&enc_nl, &C,      &r_nl);
        nl_fscx_revolve_v2_ba(&E_nl, &plaintext, &enc_nl, I_VALUE);
        gf_pow_ba(&dec_nl, &R_nl2, &a);
        nl_fscx_revolve_v2_inv_ba(&D_nl, &E_nl, &dec_nl, I_VALUE);
        ba_print_hex("P (plain) : ", &plaintext);
        ba_print_hex("E (Bob)   : ", &E_nl);
        ba_print_hex("D (Alice) : ", &D_nl);
        if (ba_equal(&D_nl, &plaintext))
            puts("+ plaintext correctly decrypted");
        else
            puts("- decryption failed!");
        /* save for Eve test */
        E_nl_saved   = E_nl;
        R_nl2_saved  = R_nl2;
    }

    /* --- HPKS-Stern-F [CODE-BASED PQC -- EUF-CMA <= q_H/T_SD + eps_PRF] */
    printf("\n--- HPKS-Stern-F [CODE-BASED PQC \xe2\x80\x94 EUF-CMA \xe2\x89\xa4 q_H/T_SD + \xce\xb5_PRF]\n");
    printf("    (N=%d, t=%d, rounds=%d; soundness=(2/3)^%d)\n",
           KEYBITS, SDF_T, SDF_ROUNDS, SDF_ROUNDS);
    {
        static SternSig sf_sig;
        BitArray sf_e;
        stern_f_keygen(&sf_seed_saved, &sf_e, sf_syn_saved, urnd);
        ba_print_hex("seed     : ", &sf_seed_saved);
        ba_print_hex("msg      : ", &plaintext);
        hpks_stern_f_sign(&sf_sig, &plaintext, &sf_e, &sf_seed_saved, urnd);
        if (hpks_stern_f_verify(&sf_sig, &plaintext, &sf_seed_saved, sf_syn_saved))
            puts("+ HPKS-Stern-F signature verified");
        else
            puts("- HPKS-Stern-F verification FAILED");
    }

    /* --- HPKE-Stern-F N=32 [CODE-BASED PQC -- Niederreiter KEM, brute-force] */
    printf("\n--- HPKE-Stern-F [CODE-BASED PQC \xe2\x80\x94 Niederreiter KEM, N=%d]\n", SDF32_N);
    printf("    (N=%d, t=%d; brute-force C(%d,%d)=496 candidates)\n",
           SDF32_N, SDF32_T, SDF32_N, SDF32_T);
    {
        uint8_t sf32_seed_buf[4];
        uint32_t sf32_seed, sf32_e_p, sf32_K_enc, sf32_K_dec;
        uint16_t sf32_ct;
        if (fread(sf32_seed_buf, 4, 1, urnd) != 1) {
            fputs("urandom error\n", stderr); return 1;
        }
        sf32_seed  = ((uint32_t)sf32_seed_buf[0] << 24) |
                     ((uint32_t)sf32_seed_buf[1] << 16) |
                     ((uint32_t)sf32_seed_buf[2] <<  8) |
                      (uint32_t)sf32_seed_buf[3];
        sf32_K_enc = hpke_stern_f_encap_32(sf32_seed, &sf32_ct, &sf32_e_p, urnd);
        sf32_K_dec = hpke_stern_f_decap_32(sf32_seed, sf32_ct);
        printf("K (encap): %08x\n", sf32_K_enc);
        printf("K (decap): %08x\n", sf32_K_dec);
        if (sf32_K_enc == sf32_K_dec)
            puts("+ HPKE-Stern-F session keys agree (N=32, brute-force)");
        else
            puts("- HPKE-Stern-F key agreement FAILED (N=32)");
    }

    /* --- HPKE-Stern-F N=256 [CODE-BASED PQC -- Niederreiter KEM, known-e'] */
    printf("\n--- HPKE-Stern-F [CODE-BASED PQC \xe2\x80\x94 Niederreiter KEM, N=%d]\n", KEYBITS);
    puts("    (brute-force decap infeasible at N=256; demo uses known e')");
    {
        BitArray sf_e_p, K_dec;
        uint8_t sf_ct[SDF_SYNBYTES];
        hpke_stern_f_encap(&sf_K_enc_saved, sf_ct, &sf_e_p, &sf_seed_saved, urnd);
        hpke_stern_f_decap_known(&K_dec, &sf_e_p, &sf_seed_saved);
        ba_print_hex("K (encap): ", &sf_K_enc_saved);
        ba_print_hex("K (decap): ", &K_dec);
        puts("    NOTE: decap uses known e' (demo only; production: QC-MDPC decoder)");
        if (ba_equal(&sf_K_enc_saved, &K_dec))
            puts("+ HPKE-Stern-F session keys agree (N=256, known-e')");
        else
            puts("- HPKE-Stern-F key agreement FAILED (N=256)");
    }

    /* *** EVE bypass TESTS *** */
    printf("\n\n*** EVE bypass TESTS\n");

    puts("*** HPKS-NL \xe2\x80\x94 Eve cannot forge Schnorr without knowing private key a");
    {
        BitArray rand_exp, R_eve, e_eve, s_eve, gs_eve, Ce_eve, lhs_eve;
        ba_rand(&rand_exp, urnd);
        gf_pow_ba(&R_eve, &GF_GEN, &rand_exp);
        nl_fscx_revolve_v1_ba(&e_eve, &R_eve, &decoy, I_VALUE);
        ba_rand(&s_eve, urnd);
        gf_pow_ba(&gs_eve,  &GF_GEN, &s_eve);
        gf_pow_ba(&Ce_eve,  &C,      &e_eve);
        gf_mul_ba(&lhs_eve, &gs_eve, &Ce_eve);
        if (ba_equal(&lhs_eve, &R_eve))
            puts("+ Eve forged HPKS-NL signature (Eve wins)!");
        else
            puts("- Eve could not forge: g^s_eve \xc2\xb7 C^e_eve \xe2\x89\xa0 R_eve  (DLP protection)");
    }

    puts("*** HPKE-NL \xe2\x80\x94 Eve cannot decrypt without Alice's private key");
    {
        BitArray eve_key, D_eve;
        /* Eve's wrong key: C XOR R_nl2 (should be C^r = GF product) */
        ba_xor(&eve_key, &C, &R_nl2_saved);
        nl_fscx_revolve_v2_inv_ba(&D_eve, &E_nl_saved, &eve_key, I_VALUE);
        if (ba_equal(&D_eve, &plaintext))
            puts("+ Eve decrypted plaintext (Eve wins)!");
        else
            puts("- Eve could not decrypt without Alice's private key (CDH + NL protection)");
    }

    puts("*** HKEX-RNL \xe2\x80\x94 Eve cannot derive shared key from public ring polynomials");
    {
        BitArray eve_rnl_guess;
        ba_rand(&eve_rnl_guess, urnd);
        if (ba_equal(&eve_rnl_guess, &sk_rnl_A_saved))
            puts("+ Eve guessed HKEX-RNL shared key (astronomically unlikely)!");
        else
            puts("- Eve random guess does not match shared key (Ring-LWR protection)");
    }

    puts("*** HPKS-Stern-F \xe2\x80\x94 Eve cannot forge without solving SD(N,t)");
    {
        static SternSig eve_sig;
        int i;
        for (i = 0; i < SDF_ROUNDS; i++) {
            ba_rand(&eve_sig.c0[i], urnd);
            ba_rand(&eve_sig.c1[i], urnd);
            ba_rand(&eve_sig.c2[i], urnd);
            eve_sig.b[i] = 0;
            ba_rand(&eve_sig.resp_a[i], urnd);
            ba_rand(&eve_sig.resp_b[i], urnd);
        }
        if (hpks_stern_f_verify(&eve_sig, &decoy, &sf_seed_saved, sf_syn_saved))
            puts("+ Eve forged HPKS-Stern-F (Eve wins)!");
        else
            puts("- Eve cannot forge: Fiat-Shamir mismatch  (SD + PRF protection)");
    }

    puts("*** HPKE-Stern-F \xe2\x80\x94 Eve cannot derive session key from syndrome ciphertext");
    {
        BitArray eve_K_guess;
        ba_rand(&eve_K_guess, urnd);
        if (ba_equal(&eve_K_guess, &sf_K_enc_saved))
            puts("+ Eve guessed HPKE-Stern-F session key (astronomically unlikely)!");
        else
            puts("- Eve random guess does not match session key  (SD protection)");
    }

    fclose(urnd);
    return 0;
}
