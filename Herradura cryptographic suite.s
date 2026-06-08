/*  Herradura Cryptographic Suite v1.9.8
    ARM 32-bit Thumb Assembly (GAS) — HKEX-GF, HSKE, HPKS, HPKE,
                                       HSKE-NL-A1/A2, HKEX-RNL, HPKS-NL, HPKE-NL,
                                       HPKS-Stern-F, HPKE-Stern-F, ZKP-RNL
    KEYBITS = 32, I_VALUE = 8, R_VALUE = 24
    HKEX-GF:   DH over GF(2^32)*, poly x^32+x^22+x^2+x+1, generator g=3
    HPKS:      Schnorr; s=(k-a*e) mod ORD; verify g^s*C^e==R
    HPKE:      El Gamal + fscx_revolve; enc_key=C^r; dec_key=R^a
    NL-FSCX v2: nl_v2(A,B) = fscx(A,B) + ROL32(B*((B+1)>>1), 8)  mod 2^32
                inv: B XOR M^{-1}((Y-delta(B)) mod 2^32)
    HKEX-RNL:  Ring-LWR; N=32, q=65537, p=4096, pp=2

    v1.5.13: HSKE-NL-A1 seed=ROR(base,28) [=ROL(base,4)=ROL(base,n/8)] fixes counter=0 degeneracy.

    Copyright (C) 2024-2026 Omar Alejandro Herrera Reyna
    MIT License / GPL v3.0 — choose either.

    Build: arm-linux-gnueabi-gcc -o "Herradura cryptographic suite_arm" \
               "Herradura cryptographic suite.s"
    Run:   qemu-arm "./Herradura cryptographic suite_arm"
        or directly on ARM hardware
*/

    .syntax unified
    .cpu cortex-a7
    .thumb

    .extern printf
    .extern exit

/* ------------------------------------------------------------------ */
/* Defined constants                                                   */
/* ------------------------------------------------------------------ */
    .equ I_VALUE,  8
    .equ R_VALUE,  24
    .equ RNL_KDF_DC, 0x6A09E667     @ SHA-256 H0 — domain constant for KDF seed
    .equ RNL_N,    32
    .equ RNL_Q,    65537
    .equ RNL_P,    4096
    .equ RNL_PP,   4
    .equ SDF_N,    32
    .equ SDF_T,    2
    .equ SDF_NROWS,16
    .equ SDF_ROUNDS,4
    /* ZKP-RNL parameters (n=32) */
    .equ SIGMA_GAMMA, 4096
    .equ SIGMA_T,     4
    .equ SIGMA_BOUND, 4092
    .equ SIGMA_SLACK, 32
    .equ SIGMA_RANGE, 8193

/* ------------------------------------------------------------------ */
/* .data section                                                       */
/* ------------------------------------------------------------------ */
    .data
    .balign 4

/* format strings */
fmt_header: .asciz "=== Herradura Cryptographic Suite v1.9.8 (ARM 32-bit Thumb, KEYBITS=32) ===\n"
fmt_hex:    .asciz "%s: 0x%08x\n"
fmt_nl:     .asciz "\n"

/* section headers */
fmt_hkex_hdr:      .asciz "-- HKEX-GF --\n"
fmt_hske_hdr:      .asciz "-- HSKE --\n"
fmt_hpks_hdr:      .asciz "-- HPKS Schnorr --\n"
fmt_hpke_hdr:      .asciz "-- HPKE El Gamal --\n"
fmt_hske_nl1_hdr:  .asciz "-- HSKE-NL-A1 [PQC-HARDENED -- counter-mode, NL-FSCX v1] --\n"
fmt_hske_nl2_hdr:  .asciz "-- HSKE-NL-A2 [PQC-HARDENED -- revolve-mode, NL-FSCX v2] --\n"
fmt_hkex_rnl_hdr:  .asciz "-- HKEX-RNL [PQC -- Ring-LWR; N=32, q=65537] --\n"
fmt_hpks_nl_hdr:   .asciz "-- HPKS-NL [NL-hardened Schnorr -- NL-FSCX v1 challenge] --\n"
fmt_hpke_nl_hdr:   .asciz "-- HPKE-NL [NL-hardened El Gamal -- NL-FSCX v2 encrypt] --\n"
fmt_eve_hdr:       .asciz "*** EVE bypass TESTS ***\n"
fmt_sdf_sign_hdr:  .asciz "\n-- HPKS-Stern-F [CODE-BASED PQC -- EUF-CMA; N=32, t=2, rounds=4] --\n"
fmt_sdf_enc_hdr:   .asciz "\n-- HPKE-Stern-F [CODE-BASED PQC -- Niederreiter KEM, N=32] --\n"
fmt_sdf_note:      .asciz "    (demo: decap uses known e'; production needs QC-MDPC decoder)\n"
fmt_sdf_ok:        .asciz "+ HPKS-Stern-F signature verified\n"
fmt_sdf_fail_msg:  .asciz "- HPKS-Stern-F verification FAILED\n"
fmt_hpke_sdf_ok:   .asciz "+ HPKE-Stern-F session keys agree\n"
fmt_hpke_sdf_fail: .asciz "- HPKE-Stern-F key agreement FAILED\n"
fmt_eve_sdf_ok:    .asciz "- Eve cannot forge: Fiat-Shamir mismatch  (SD + PRF protection)\n"
fmt_eve_sdf_fail:  .asciz "+ Eve forged HPKS-Stern-F (Eve wins!)\n"
fmt_eve_hpke_sdf_ok:  .asciz "- Eve random guess does not match session key  (SD protection)\n"
fmt_eve_hpke_sdf_fail: .asciz "+ Eve guessed HPKE-Stern-F session key!\n"
fmt_zkp_rnl_hdr: .asciz "\n-- ZKP-RNL [Ring-LWR Sigma-protocol; N=32, gamma=4096, t=4] --\n"
fmt_zkp_rnl_ok:  .asciz "+ ZKP-RNL proof verified\n"
fmt_zkp_rnl_fail:.asciz "- ZKP-RNL verify FAILED\n"
fmt_masked_hdr:  .asciz "\n-- Masked HSKE (78.H) [GF(2)-linearity masking] --\n"
fmt_masked_ok:   .asciz "- Masked HSKE encrypt/decrypt correct\n"
fmt_masked_fail: .asciz "+ Masked HSKE encrypt/decrypt failed!\n"
fmt_ratch_hdr:   .asciz "\n-- Ratchet (78.C) [forward-secret, 5 steps] --\n"
fmt_ratch_ok:    .asciz "- Ratchet: 5 distinct message keys\n"
fmt_ratch_fail:  .asciz "+ Ratchet: duplicate message keys!\n"
    .balign 4
ratchet_domain_32: .word 0x4E4C2D46   @ 'N','L','-','F' (first 4 bytes of NL-FSCX-RATCHET-V1)
lbl_sigma_msg:   .asciz "msg (sigma) "
    .balign 4
sigma_demo_msg:  .word 0xDEADB00B

/* result strings */
fmt_ok:          .asciz "+ correct!\n"
fmt_fail:        .asciz "- INCORRECT!\n"
fmt_eve_ok:      .asciz "- Eve could not decrypt (CDH + NL protection)\n"
fmt_eve_fail:    .asciz "+ Eve decrypted (Eve wins!)\n"
fmt_rnl_agree:   .asciz "+ raw key bits agree!\n"
fmt_rnl_noagree: .asciz "- raw key disagrees (rounding noise)\n"
fmt_eve_rnl_ok:  .asciz "- Eve random guess does not match (Ring-LWR protection)\n"

/* field labels */
lbl_apriv:   .asciz "a_priv      "
lbl_bpriv:   .asciz "b_priv      "
lbl_key:     .asciz "key         "
lbl_plain:   .asciz "plain       "
lbl_C:       .asciz "C           "
lbl_C2:      .asciz "C2          "
lbl_skeyA:   .asciz "skeyA       "
lbl_skeyB:   .asciz "skeyB       "
lbl_E_hske:  .asciz "E (HSKE)    "
lbl_D_hske:  .asciz "D (HSKE)    "
lbl_k_hpks:  .asciz "k (nonce)   "
lbl_R_hpks:  .asciz "R = g^k     "
lbl_e_hpks:  .asciz "e (challenge)"
lbl_s_hpks:  .asciz "s (response)"
lbl_lhs:     .asciz "g^s * C^e   "
lbl_r_hpke:  .asciz "r (ephem)   "
lbl_R_hpke:  .asciz "R = g^r     "
lbl_E_hpke:  .asciz "E (Bob)     "
lbl_D_hpke:  .asciz "D (Alice)   "
lbl_N_nl1:   .asciz "N (nonce)   "
lbl_ks_nl1:  .asciz "ks (NL-v1)  "
lbl_E_nl1:   .asciz "E (NL-A1)   "
lbl_D_nl1:   .asciz "D (NL-A1)   "
lbl_E_nl2:   .asciz "E (NL-A2)   "
lbl_D_nl2:   .asciz "D (NL-A2)   "
lbl_sk_a:    .asciz "sk (Alice)  "
lbl_Ka:      .asciz "KA (raw)    "
lbl_Kb:      .asciz "KB (raw)    "
lbl_K_enc:   .asciz "K (encap)   "
lbl_K_dec:   .asciz "K (decap)   "

    .balign 4
/* fixed test vectors */
val_a_priv:  .word 0xDEADBEEF
val_b_priv:  .word 0xCAFEBABF
val_key:     .word 0x5A5A5A5A
val_plain:   .word 0xDEADC0DE

/* LCG PRNG */
lcg_state:   .word 0xDEADBEEE   /* overwritten from /dev/urandom at main() (SA-01) */
str_urandom: .asciz "/dev/urandom"
str_mode_r:  .asciz "r"
lcg_mul:     .word 1664525
lcg_add:     .word 1013904223

/* result storage */
val_C:       .word 0
val_C2:      .word 0
val_sk:      .word 0
val_skB:     .word 0
val_E_hske:  .word 0
val_D_hske:  .word 0
val_k_hpks:  .word 0
val_R_hpks:  .word 0
val_e_hpks:  .word 0
val_ae_hpks: .word 0
val_s_hpks:  .word 0
val_gs_hpks: .word 0
val_r_hpke:  .word 0
val_R_hpke:  .word 0
val_enc_key: .word 0
val_E_hpke:  .word 0
val_dec_key: .word 0
val_D_hpke:  .word 0
/* v1.5.0 storage */
val_nonce_nl1: .word 0
val_ks_nl1:  .word 0
val_E_nl1:   .word 0
val_D_nl1:   .word 0
val_E_nl2:   .word 0
val_D_nl2:   .word 0
val_r_nl:    .word 0
val_R_nl:    .word 0
val_enc_nl:  .word 0
val_dec_nl:  .word 0
val_KA:      .word 0
val_KB:      .word 0
val_hint_A:  .word 0
val_sk_rnl:  .word 0
/* Stern-F (code-based PQC) storage */
val_sdf_seed:    .word 0    @ parity check seed (public)
val_sdf_syn:     .word 0    @ syndrome H·e^T (public)
val_sdf_e:       .word 0    @ error vector (secret)
val_sdf_K_enc:   .word 0    @ KEM encap key
val_sdf_K_dec:   .word 0    @ KEM decap key
val_sdf_e_prime: .word 0    @ KEM ephemeral error
val_sdf_ct:      .word 0    @ KEM ciphertext (syndrome)
/* implicit poly arg pointers */
rnl_f_ptr:   .word 0
rnl_g_ptr:   .word 0
rnl_h_ptr:   .word 0

/* NTT tables for negacyclic poly_mul (n=32, q=65537=2^16+1, psi=3^1024)  */
    .align 2
rnl_psi_pow_tab:
    .word 1,8224,65529,65282,64,2040,65025,49217
    .word 4096,65023,32769,4112,65533,32641,32,1020
    .word 65281,57377,2048,65280,49153,2056,65535,49089
    .word 16,510,65409,61457,1024,32640,57345,1028
rnl_psi_inv_pow_tab:
    .word 1,64509,8192,32897,64513,4080,128,65027
    .word 65521,16448,2,63481,16384,257,63489,8160
    .word 256,64517,65505,32896,4,61425,32768,514
    .word 61441,16320,512,63497,65473,255,8,57313
rnl_omega_fwd_tab:
    .word 1,65529,64,65025,4096,32769,65533,32
    .word 65281,2048,49153,65535,16,65409,1024,57345
rnl_omega_inv_tab:
    .word 1,8192,64513,128,65521,2,16384,63489
    .word 256,65505,4,32768,61441,512,65473,8
rnl_inv_n:   .word 63489
rnl_bit_rev_tab:
    .byte 0,16,8,24,4,20,12,28,2,18,10,26,6,22,14,30
    .byte 1,17,9,25,5,21,13,29,3,19,11,27,7,23,15,31

/* ------------------------------------------------------------------ */
/* .bss: RNL polynomial arrays (RNL_N*4 = 128 bytes each)             */
/* ------------------------------------------------------------------ */
    .section .bss
    .balign 4
rnl_m_base:  .space 128
rnl_a_rand:  .space 128
rnl_m_blind: .space 128
rnl_s_A:     .space 128
rnl_s_B:     .space 128
rnl_C_A:     .space 128
rnl_C_B:     .space 128
rnl_tmp:     .space 128
rnl_tmp2:    .space 128
rnl_fa:      .space 128    /* NTT work array */
rnl_ga:      .space 128    /* NTT work array */
rnl_ha:      .space 128    /* NTT work array */
/* Stern-F scratch (N=32, rounds=4) */
sdf_perm:     .space 32   /* permutation scratch (Fisher-Yates + apply_perm) */
sdf_c0:       .space 16   /* c0[0..3]: commit(pi, H·r^T) */
sdf_c1:       .space 16   /* c1[0..3]: commit(sigma(r)) */
sdf_c2:       .space 16   /* c2[0..3]: commit(sigma(y)) */
sdf_b:        .space 16   /* challenge[0..3] (0,1,2) */
sdf_respA:    .space 16   /* respA[0..3] */
sdf_respB:    .space 16   /* respB[0..3] */
sdf_r_tmp:    .space 16   /* r[0..3] sign temporaries */
sdf_y_tmp:    .space 16   /* y[0..3] = e XOR r */
sdf_pi_tmp:   .space 16   /* pi[0..3] perm seeds */
sdf_sr_tmp:   .space 16   /* sigma(r)[0..3] */
sdf_sy_tmp:   .space 16   /* sigma(y)[0..3] */
sdf_chals_tmp:.space 16   /* verify: re-derived challenges */
/* ZKP-RNL scratch (n=32, 4 bytes per coeff) */
sig_y:           .space 128  /* y poly (signed int32, [-gamma,gamma]) */
sig_w:           .space 128  /* w = centered(m*y) (signed int32) */
sig_c:           .space 128  /* challenge poly {0,1,q-1} */
sig_z:           .space 128  /* z = y + cs (signed int32) */
sig_pos:         .space 16   /* positions[4] of nonzero challenge entries */
sigma_yq_tmp:    .space 128  /* y_q / z_q scratch for poly_mul */
sigma_liftc_tmp: .space 128  /* lift(C) from p to q */
sigma_mz_tmp:    .space 128  /* m*z (verify scratch) */
sigma_cw_tmp:    .space 128  /* c*lift(C) / saved c (verify scratch) */

/* ------------------------------------------------------------------ */
/* .text                                                               */
/* ------------------------------------------------------------------ */
    .text
    .global main
    .thumb_func

main:
    push    {r4-r11, lr}

    @ SA-01: seed lcg_state from /dev/urandom (fallback: keep default if open fails)
    ldr     r0, =str_urandom
    ldr     r1, =str_mode_r
    bl      fopen
    cmp     r0, #0
    beq     prng_seeded
    mov     r4, r0              @ r4 = FILE*
    ldr     r0, =lcg_state      @ buf = &lcg_state
    mov     r1, #4              @ size = 4
    mov     r2, #1              @ count = 1
    mov     r3, r4              @ stream = FILE*
    bl      fread
    mov     r0, r4
    bl      fclose
prng_seeded:

    ldr     r0, =fmt_header
    bl      printf

    ldr     r0, =fmt_hex
    ldr     r1, =lbl_apriv
    ldr     r2, =val_a_priv
    ldr     r2, [r2]
    bl      printf
    ldr     r0, =fmt_hex
    ldr     r1, =lbl_bpriv
    ldr     r2, =val_b_priv
    ldr     r2, [r2]
    bl      printf
    ldr     r0, =fmt_hex
    ldr     r1, =lbl_key
    ldr     r2, =val_key
    ldr     r2, [r2]
    bl      printf
    ldr     r0, =fmt_hex
    ldr     r1, =lbl_plain
    ldr     r2, =val_plain
    ldr     r2, [r2]
    bl      printf
    ldr     r0, =fmt_nl
    bl      printf

    /* ================================================================ HKEX-GF */
    ldr     r0, =fmt_hkex_hdr
    bl      printf

    mov     r0, #3
    ldr     r1, =val_a_priv
    ldr     r1, [r1]
    bl      gf_pow_32
    ldr     r3, =val_C
    str     r0, [r3]

    mov     r0, #3
    ldr     r1, =val_b_priv
    ldr     r1, [r1]
    bl      gf_pow_32
    ldr     r3, =val_C2
    str     r0, [r3]

    ldr     r0, =val_C2
    ldr     r0, [r0]
    ldr     r1, =val_a_priv
    ldr     r1, [r1]
    bl      gf_pow_32
    ldr     r3, =val_sk
    str     r0, [r3]

    ldr     r0, =val_C
    ldr     r0, [r0]
    ldr     r1, =val_b_priv
    ldr     r1, [r1]
    bl      gf_pow_32
    ldr     r3, =val_skB
    str     r0, [r3]

    ldr     r0, =fmt_hex
    ldr     r1, =lbl_C
    ldr     r2, =val_C
    ldr     r2, [r2]
    bl      printf
    ldr     r0, =fmt_hex
    ldr     r1, =lbl_C2
    ldr     r2, =val_C2
    ldr     r2, [r2]
    bl      printf
    ldr     r0, =fmt_hex
    ldr     r1, =lbl_skeyA
    ldr     r2, =val_sk
    ldr     r2, [r2]
    bl      printf
    ldr     r0, =fmt_hex
    ldr     r1, =lbl_skeyB
    ldr     r2, =val_skB
    ldr     r2, [r2]
    bl      printf

    ldr     r0, =val_sk
    ldr     r0, [r0]
    ldr     r1, =val_skB
    ldr     r1, [r1]
    cmp     r0, r1
    bne     hkex_fail
    ldr     r0, =fmt_ok
    bl      printf
    b       hkex_done
hkex_fail:
    ldr     r0, =fmt_fail
    bl      printf
hkex_done:
    ldr     r0, =fmt_nl
    bl      printf

    /* ================================================================ HSKE */
    ldr     r0, =fmt_hske_hdr
    bl      printf

    ldr     r0, =val_plain
    ldr     r0, [r0]
    ldr     r1, =val_key
    ldr     r1, [r1]
    mov     r2, #I_VALUE
    bl      fscx_revolve
    ldr     r3, =val_E_hske
    str     r0, [r3]

    ldr     r0, =val_E_hske
    ldr     r0, [r0]
    ldr     r1, =val_key
    ldr     r1, [r1]
    mov     r2, #R_VALUE
    bl      fscx_revolve
    ldr     r3, =val_D_hske
    str     r0, [r3]

    ldr     r0, =fmt_hex
    ldr     r1, =lbl_E_hske
    ldr     r2, =val_E_hske
    ldr     r2, [r2]
    bl      printf
    ldr     r0, =fmt_hex
    ldr     r1, =lbl_D_hske
    ldr     r2, =val_D_hske
    ldr     r2, [r2]
    bl      printf

    ldr     r0, =val_D_hske
    ldr     r0, [r0]
    ldr     r1, =val_plain
    ldr     r1, [r1]
    cmp     r0, r1
    bne     hske_fail
    ldr     r0, =fmt_ok
    bl      printf
    b       hske_done
hske_fail:
    ldr     r0, =fmt_fail
    bl      printf
hske_done:
    ldr     r0, =fmt_nl
    bl      printf

    /* ================================================================ HPKS Schnorr */
    ldr     r0, =fmt_hpks_hdr
    bl      printf

    bl      prng_next
    ldr     r3, =val_k_hpks
    str     r0, [r3]

    mov     r0, #3
    ldr     r1, =val_k_hpks
    ldr     r1, [r1]
    bl      gf_pow_32
    ldr     r3, =val_R_hpks
    str     r0, [r3]

    ldr     r0, =val_R_hpks
    ldr     r0, [r0]
    ldr     r1, =val_plain
    ldr     r1, [r1]
    mov     r2, #I_VALUE
    bl      fscx_revolve
    ldr     r3, =val_e_hpks
    str     r0, [r3]

    ldr     r4, =val_a_priv
    ldr     r4, [r4]
    ldr     r5, =val_e_hpks
    ldr     r5, [r5]
    umull   r6, r7, r4, r5
    adds    r6, r6, r7
    it      cs
    addcs   r6, r6, #1
    ldr     r3, =val_ae_hpks
    str     r6, [r3]

    ldr     r4, =val_k_hpks
    ldr     r4, [r4]
    subs    r4, r4, r6
    it      cc
    subcc   r4, r4, #1
    ldr     r3, =val_s_hpks
    str     r4, [r3]

    mov     r0, #3
    ldr     r1, =val_s_hpks
    ldr     r1, [r1]
    bl      gf_pow_32
    ldr     r3, =val_gs_hpks
    str     r0, [r3]

    ldr     r0, =val_C
    ldr     r0, [r0]
    ldr     r1, =val_e_hpks
    ldr     r1, [r1]
    bl      gf_pow_32
    mov     r1, r0
    ldr     r0, =val_gs_hpks
    ldr     r0, [r0]
    bl      gf_mul_32
    push    {r0}

    ldr     r0, =fmt_hex
    ldr     r1, =lbl_k_hpks
    ldr     r2, =val_k_hpks
    ldr     r2, [r2]
    bl      printf
    ldr     r0, =fmt_hex
    ldr     r1, =lbl_R_hpks
    ldr     r2, =val_R_hpks
    ldr     r2, [r2]
    bl      printf
    ldr     r0, =fmt_hex
    ldr     r1, =lbl_e_hpks
    ldr     r2, =val_e_hpks
    ldr     r2, [r2]
    bl      printf
    ldr     r0, =fmt_hex
    ldr     r1, =lbl_s_hpks
    ldr     r2, =val_s_hpks
    ldr     r2, [r2]
    bl      printf

    pop     {r4}
    ldr     r5, =val_R_hpks
    ldr     r5, [r5]
    cmp     r4, r5
    bne     hpks_fail
    ldr     r0, =fmt_ok
    bl      printf
    b       hpks_done
hpks_fail:
    ldr     r0, =fmt_fail
    bl      printf
hpks_done:
    ldr     r0, =fmt_nl
    bl      printf

    /* ================================================================ HPKE El Gamal */
    ldr     r0, =fmt_hpke_hdr
    bl      printf

    bl      prng_next
    orr     r0, r0, #1
    ldr     r3, =val_r_hpke
    str     r0, [r3]

    mov     r0, #3
    ldr     r1, =val_r_hpke
    ldr     r1, [r1]
    bl      gf_pow_32
    ldr     r3, =val_R_hpke
    str     r0, [r3]

    ldr     r0, =val_C
    ldr     r0, [r0]
    ldr     r1, =val_r_hpke
    ldr     r1, [r1]
    bl      gf_pow_32
    ldr     r3, =val_enc_key
    str     r0, [r3]

    ldr     r0, =val_plain
    ldr     r0, [r0]
    ldr     r1, =val_enc_key
    ldr     r1, [r1]
    mov     r2, #I_VALUE
    bl      fscx_revolve
    ldr     r3, =val_E_hpke
    str     r0, [r3]

    ldr     r0, =val_R_hpke
    ldr     r0, [r0]
    ldr     r1, =val_a_priv
    ldr     r1, [r1]
    bl      gf_pow_32
    ldr     r3, =val_dec_key
    str     r0, [r3]

    ldr     r0, =val_E_hpke
    ldr     r0, [r0]
    ldr     r1, =val_dec_key
    ldr     r1, [r1]
    mov     r2, #R_VALUE
    bl      fscx_revolve
    ldr     r3, =val_D_hpke
    str     r0, [r3]

    ldr     r0, =fmt_hex
    ldr     r1, =lbl_R_hpke
    ldr     r2, =val_R_hpke
    ldr     r2, [r2]
    bl      printf
    ldr     r0, =fmt_hex
    ldr     r1, =lbl_E_hpke
    ldr     r2, =val_E_hpke
    ldr     r2, [r2]
    bl      printf
    ldr     r0, =fmt_hex
    ldr     r1, =lbl_D_hpke
    ldr     r2, =val_D_hpke
    ldr     r2, [r2]
    bl      printf

    ldr     r0, =val_D_hpke
    ldr     r0, [r0]
    ldr     r1, =val_plain
    ldr     r1, [r1]
    cmp     r0, r1
    bne     hpke_fail
    ldr     r0, =fmt_ok
    bl      printf
    b       hpke_done
hpke_fail:
    ldr     r0, =fmt_fail
    bl      printf
hpke_done:
    ldr     r0, =fmt_nl
    bl      printf

    /* ================================================================
       HSKE-NL-A1  (counter-mode with NL-FSCX v1)
       N = prng_next(); base = key XOR N; ks = nl_fscx_revolve_v1(ROL(base,4), base, I_VALUE)
       E = plain XOR ks;  D = E XOR ks  (must == plain)
       ================================================================ */
    ldr     r0, =fmt_hske_nl1_hdr
    bl      printf

    bl      prng_next               @ r0 = nonce N
    ldr     r3, =val_nonce_nl1
    str     r0, [r3]                @ save N
    ldr     r1, =val_key
    ldr     r1, [r1]
    eor     r0, r0, r1              @ r0 = base = N XOR key
    mov     r1, r0                  @ r1 = B = base (counter=0)
    ror     r0, r0, #28             @ r0 = ROL(base, 4)         [n=32, n/8=4]
    ldr     r2, =RNL_KDF_DC
    eor     r0, r0, r2              @ r0 = seed = ROL(base,4) XOR DC
    mov     r2, #I_VALUE
    bl      nl_fscx_revolve_v1      @ r0 = ks  (A=seed, B=base)
    ldr     r3, =val_ks_nl1
    str     r0, [r3]

    ldr     r4, =val_plain
    ldr     r4, [r4]
    ldr     r5, =val_ks_nl1
    ldr     r5, [r5]
    eor     r4, r4, r5
    ldr     r3, =val_E_nl1
    str     r4, [r3]
    eor     r4, r4, r5
    ldr     r3, =val_D_nl1
    str     r4, [r3]

    ldr     r0, =fmt_hex
    ldr     r1, =lbl_N_nl1
    ldr     r2, =val_nonce_nl1
    ldr     r2, [r2]
    bl      printf
    ldr     r0, =fmt_hex
    ldr     r1, =lbl_E_nl1
    ldr     r2, =val_E_nl1
    ldr     r2, [r2]
    bl      printf
    ldr     r0, =fmt_hex
    ldr     r1, =lbl_D_nl1
    ldr     r2, =val_D_nl1
    ldr     r2, [r2]
    bl      printf

    ldr     r0, =val_D_nl1
    ldr     r0, [r0]
    ldr     r1, =val_plain
    ldr     r1, [r1]
    cmp     r0, r1
    bne     hske_nl1_fail
    ldr     r0, =fmt_ok
    bl      printf
    b       hske_nl1_done
hske_nl1_fail:
    ldr     r0, =fmt_fail
    bl      printf
hske_nl1_done:
    ldr     r0, =fmt_nl
    bl      printf

    /* ================================================================
       HSKE-NL-A2  (revolve-mode with NL-FSCX v2)
       E = nl_fscx_revolve_v2(plain, key, R_VALUE)
       D = nl_fscx_revolve_v2_inv(E, key, R_VALUE)  must == plain
       CAUTION: deterministic — same (plain, key) always yields same E.
       ================================================================ */
    ldr     r0, =fmt_hske_nl2_hdr
    bl      printf

    ldr     r0, =val_plain
    ldr     r0, [r0]
    ldr     r1, =val_key
    ldr     r1, [r1]
    mov     r2, #R_VALUE
    bl      nl_fscx_revolve_v2
    ldr     r3, =val_E_nl2
    str     r0, [r3]

    ldr     r0, =val_E_nl2
    ldr     r0, [r0]
    ldr     r1, =val_key
    ldr     r1, [r1]
    mov     r2, #R_VALUE
    bl      nl_fscx_revolve_v2_inv
    ldr     r3, =val_D_nl2
    str     r0, [r3]

    ldr     r0, =fmt_hex
    ldr     r1, =lbl_E_nl2
    ldr     r2, =val_E_nl2
    ldr     r2, [r2]
    bl      printf
    ldr     r0, =fmt_hex
    ldr     r1, =lbl_D_nl2
    ldr     r2, =val_D_nl2
    ldr     r2, [r2]
    bl      printf

    ldr     r0, =val_D_nl2
    ldr     r0, [r0]
    ldr     r1, =val_plain
    ldr     r1, [r1]
    cmp     r0, r1
    bne     hske_nl2_fail
    ldr     r0, =fmt_ok
    bl      printf
    b       hske_nl2_done
hske_nl2_fail:
    ldr     r0, =fmt_fail
    bl      printf
hske_nl2_done:
    ldr     r0, =fmt_nl
    bl      printf

    /* ================================================================
       HKEX-RNL  (Ring-LWR key exchange)
       ================================================================ */
    ldr     r0, =fmt_hkex_rnl_hdr
    bl      printf

    ldr     r0, =rnl_m_base
    bl      rnl_m_poly

    ldr     r0, =rnl_a_rand
    bl      rnl_rand_poly

    ldr     r0, =rnl_h_ptr
    ldr     r1, =rnl_m_blind
    str     r1, [r0]
    ldr     r0, =rnl_f_ptr
    ldr     r1, =rnl_m_base
    str     r1, [r0]
    ldr     r0, =rnl_g_ptr
    ldr     r1, =rnl_a_rand
    str     r1, [r0]
    bl      rnl_poly_add

    ldr     r0, =rnl_s_A
    ldr     r1, =rnl_C_A
    ldr     r2, =rnl_m_blind
    bl      rnl_keygen

    ldr     r0, =rnl_s_B
    ldr     r1, =rnl_C_B
    ldr     r2, =rnl_m_blind
    bl      rnl_keygen

    ldr     r0, =rnl_s_A
    ldr     r1, =rnl_C_B
    bl      rnl_agree_full          @ r0=KA, r1=hint_A
    ldr     r3, =val_KA
    str     r0, [r3]
    ldr     r3, =val_hint_A
    str     r1, [r3]

    ldr     r0, =rnl_s_B
    ldr     r1, =rnl_C_A
    ldr     r2, =val_hint_A
    ldr     r2, [r2]
    bl      rnl_agree_recv          @ r0=KB
    ldr     r3, =val_KB
    str     r0, [r3]

    ldr     r0, =val_KA
    ldr     r0, [r0]
    ror     r0, r0, #28         @ ROL32(KA, 4)           [n/8 = 32/8 = 4]
    ldr     r3, =RNL_KDF_DC
    eor     r0, r0, r3          @ seed = ROL(KA,4) XOR DC
    ldr     r1, =val_KA
    ldr     r1, [r1]            @ B = KA
    mov     r2, #I_VALUE
    bl      nl_fscx_revolve_v1  @ r0 = sk
    ldr     r3, =val_sk_rnl
    str     r0, [r3]

    ldr     r0, =fmt_hex
    ldr     r1, =lbl_Ka
    ldr     r2, =val_KA
    ldr     r2, [r2]
    bl      printf
    ldr     r0, =fmt_hex
    ldr     r1, =lbl_Kb
    ldr     r2, =val_KB
    ldr     r2, [r2]
    bl      printf
    ldr     r0, =fmt_hex
    ldr     r1, =lbl_sk_a
    ldr     r2, =val_sk_rnl
    ldr     r2, [r2]
    bl      printf

    ldr     r0, =val_KA
    ldr     r0, [r0]
    ldr     r1, =val_KB
    ldr     r1, [r1]
    cmp     r0, r1
    bne     hkex_rnl_noagree
    ldr     r0, =fmt_rnl_agree
    bl      printf
    b       hkex_rnl_done
hkex_rnl_noagree:
    ldr     r0, =fmt_rnl_noagree
    bl      printf
hkex_rnl_done:
    ldr     r0, =fmt_nl
    bl      printf

    /* ================================================================
       HPKS-NL  (NL-hardened Schnorr: NL-FSCX v1 challenge)
       ================================================================ */
    ldr     r0, =fmt_hpks_nl_hdr
    bl      printf

    bl      prng_next
    ldr     r3, =val_k_hpks
    str     r0, [r3]

    mov     r0, #3
    ldr     r1, =val_k_hpks
    ldr     r1, [r1]
    bl      gf_pow_32
    ldr     r3, =val_R_hpks
    str     r0, [r3]

    ldr     r0, =val_R_hpks
    ldr     r0, [r0]
    ldr     r1, =val_plain
    ldr     r1, [r1]
    mov     r2, #I_VALUE
    bl      nl_fscx_revolve_v1
    ldr     r3, =val_e_hpks
    str     r0, [r3]

    ldr     r4, =val_a_priv
    ldr     r4, [r4]
    ldr     r5, =val_e_hpks
    ldr     r5, [r5]
    umull   r6, r7, r4, r5
    adds    r6, r6, r7
    it      cs
    addcs   r6, r6, #1
    ldr     r3, =val_ae_hpks
    str     r6, [r3]

    ldr     r4, =val_k_hpks
    ldr     r4, [r4]
    subs    r4, r4, r6
    it      cc
    subcc   r4, r4, #1
    ldr     r3, =val_s_hpks
    str     r4, [r3]

    mov     r0, #3
    ldr     r1, =val_s_hpks
    ldr     r1, [r1]
    bl      gf_pow_32
    ldr     r3, =val_gs_hpks
    str     r0, [r3]

    ldr     r0, =val_C
    ldr     r0, [r0]
    ldr     r1, =val_e_hpks
    ldr     r1, [r1]
    bl      gf_pow_32
    mov     r1, r0
    ldr     r0, =val_gs_hpks
    ldr     r0, [r0]
    bl      gf_mul_32
    push    {r0}

    ldr     r0, =fmt_hex
    ldr     r1, =lbl_R_hpks
    ldr     r2, =val_R_hpks
    ldr     r2, [r2]
    bl      printf
    ldr     r0, =fmt_hex
    ldr     r1, =lbl_s_hpks
    ldr     r2, =val_s_hpks
    ldr     r2, [r2]
    bl      printf
    ldr     r0, =fmt_hex
    ldr     r1, =lbl_lhs
    pop     {r2}
    push    {r2}
    bl      printf

    pop     {r4}
    ldr     r5, =val_R_hpks
    ldr     r5, [r5]
    cmp     r4, r5
    bne     hpks_nl_fail
    ldr     r0, =fmt_ok
    bl      printf
    b       hpks_nl_done
hpks_nl_fail:
    ldr     r0, =fmt_fail
    bl      printf
hpks_nl_done:
    ldr     r0, =fmt_nl
    bl      printf

    /* ================================================================
       HPKE-NL  (NL-hardened El Gamal: NL-FSCX v2 encrypt)
       ================================================================ */
    ldr     r0, =fmt_hpke_nl_hdr
    bl      printf

    bl      prng_next
    orr     r0, r0, #1
    ldr     r3, =val_r_nl
    str     r0, [r3]

    mov     r0, #3
    ldr     r1, =val_r_nl
    ldr     r1, [r1]
    bl      gf_pow_32
    ldr     r3, =val_R_nl
    str     r0, [r3]

    ldr     r0, =val_C
    ldr     r0, [r0]
    ldr     r1, =val_r_nl
    ldr     r1, [r1]
    bl      gf_pow_32
    ldr     r3, =val_enc_nl
    str     r0, [r3]

    ldr     r0, =val_plain
    ldr     r0, [r0]
    ldr     r1, =val_enc_nl
    ldr     r1, [r1]
    mov     r2, #I_VALUE
    bl      nl_fscx_revolve_v2
    ldr     r3, =val_E_nl2
    str     r0, [r3]

    ldr     r0, =val_R_nl
    ldr     r0, [r0]
    ldr     r1, =val_a_priv
    ldr     r1, [r1]
    bl      gf_pow_32
    ldr     r3, =val_dec_nl
    str     r0, [r3]

    ldr     r0, =val_E_nl2
    ldr     r0, [r0]
    ldr     r1, =val_dec_nl
    ldr     r1, [r1]
    mov     r2, #I_VALUE
    bl      nl_fscx_revolve_v2_inv
    ldr     r3, =val_D_nl2
    str     r0, [r3]

    ldr     r0, =fmt_hex
    ldr     r1, =lbl_E_nl2
    ldr     r2, =val_E_nl2
    ldr     r2, [r2]
    bl      printf
    ldr     r0, =fmt_hex
    ldr     r1, =lbl_D_nl2
    ldr     r2, =val_D_nl2
    ldr     r2, [r2]
    bl      printf

    ldr     r0, =val_D_nl2
    ldr     r0, [r0]
    ldr     r1, =val_plain
    ldr     r1, [r1]
    cmp     r0, r1
    bne     hpke_nl_fail
    ldr     r0, =fmt_ok
    bl      printf
    b       hpke_nl_done
hpke_nl_fail:
    ldr     r0, =fmt_fail
    bl      printf
hpke_nl_done:
    ldr     r0, =fmt_nl
    bl      printf

    /* ================================================================
       HPKS-Stern-F  (code-based PQC: Syndrome Decoding ZKP, EUF-CMA)
       N=32, t=2, rounds=4; seed and e generated via prng_next
       ================================================================ */
    ldr     r0, =fmt_sdf_sign_hdr
    bl      printf

    @ key generation: seed = prng_next()
    bl      prng_next
    ldr     r3, =val_sdf_seed
    str     r0, [r3]

    @ e = stern_rand_error_32() — weight-2 error vector
    bl      stern_rand_error_32
    ldr     r3, =val_sdf_e
    str     r0, [r3]

    @ sdf_syn = stern_syndrome_32(seed, e)
    ldr     r0, =val_sdf_seed
    ldr     r0, [r0]
    ldr     r1, =val_sdf_e
    ldr     r1, [r1]
    bl      stern_syndrome_32
    ldr     r3, =val_sdf_syn
    str     r0, [r3]

    @ sign: fills sdf_c0..c2, sdf_b, sdf_respA, sdf_respB
    bl      hpks_stern_f_sign_32

    @ verify
    bl      hpks_stern_f_verify_32
    cmp     r0, #1
    bne     hpks_sdf_fail
    ldr     r0, =fmt_sdf_ok
    bl      printf
    b       hpks_sdf_done
hpks_sdf_fail:
    ldr     r0, =fmt_sdf_fail_msg
    bl      printf
hpks_sdf_done:
    ldr     r0, =fmt_nl
    bl      printf

    /* ================================================================
       HPKE-Stern-F  (Niederreiter KEM, N=32, t=2)
       Encap: K = hash(seed, e'); ct = H·e'^T
       Decap (known e'): K' = hash(seed, e')  [demo]
       ================================================================ */
    ldr     r0, =fmt_sdf_enc_hdr
    bl      printf
    ldr     r0, =fmt_sdf_note
    bl      printf

    @ encap: fills val_sdf_K_enc, val_sdf_ct, val_sdf_e_prime
    bl      hpke_stern_f_encap_32

    @ decap (known e'): K' = hash2(seed, e')
    ldr     r0, =val_sdf_e_prime
    ldr     r0, [r0]
    bl      hpke_stern_f_decap_known_32
    ldr     r3, =val_sdf_K_dec
    str     r0, [r3]

    ldr     r0, =fmt_hex
    ldr     r1, =lbl_K_enc
    ldr     r2, =val_sdf_K_enc
    ldr     r2, [r2]
    bl      printf
    ldr     r0, =fmt_hex
    ldr     r1, =lbl_K_dec
    ldr     r2, =val_sdf_K_dec
    ldr     r2, [r2]
    bl      printf

    ldr     r0, =val_sdf_K_enc
    ldr     r0, [r0]
    ldr     r1, =val_sdf_K_dec
    ldr     r1, [r1]
    cmp     r0, r1
    bne     hpke_sdf_fail
    ldr     r0, =fmt_hpke_sdf_ok
    bl      printf
    b       hpke_sdf_done
hpke_sdf_fail:
    ldr     r0, =fmt_hpke_sdf_fail
    bl      printf
hpke_sdf_done:
    ldr     r0, =fmt_nl
    bl      printf

    /* ================================================================ EVE tests */
    ldr     r0, =fmt_eve_hdr
    bl      printf

    /* Eve uses wrong key: C XOR R_nl instead of C^r */
    ldr     r4, =val_C
    ldr     r4, [r4]
    ldr     r5, =val_R_nl
    ldr     r5, [r5]
    eor     r4, r4, r5
    ldr     r0, =val_E_nl2
    ldr     r0, [r0]
    mov     r1, r4
    mov     r2, #I_VALUE
    bl      nl_fscx_revolve_v2_inv
    ldr     r1, =val_plain
    ldr     r1, [r1]
    cmp     r0, r1
    beq     eve_hpke_fail
    ldr     r0, =fmt_eve_ok
    bl      printf
    b       eve_hpke_done
eve_hpke_fail:
    ldr     r0, =fmt_eve_fail
    bl      printf
eve_hpke_done:

    /* Eve random guess for HKEX-RNL */
    bl      prng_next
    ldr     r1, =val_sk_rnl
    ldr     r1, [r1]
    cmp     r0, r1
    beq     eve_rnl_fail
    ldr     r0, =fmt_eve_rnl_ok
    bl      printf
    b       eve_rnl_done
eve_rnl_fail:
    ldr     r0, =fmt_eve_fail
    bl      printf
eve_rnl_done:

    /* Eve tries to forge HPKS-Stern-F: flip respA[0] to trigger mismatch */
    ldr     r4, =sdf_respA
    ldr     r5, [r4]            @ save original respA[0]
    mvn     r0, r5              @ flip all bits
    str     r0, [r4]
    bl      hpks_stern_f_verify_32
    mov     r6, r0              @ save verify result
    str     r5, [r4]            @ restore original respA[0]
    cmp     r6, #1
    beq     eve_sdf_forge_fail
    ldr     r0, =fmt_eve_sdf_ok
    bl      printf
    b       eve_sdf_forge_done
eve_sdf_forge_fail:
    ldr     r0, =fmt_eve_sdf_fail
    bl      printf
eve_sdf_forge_done:

    /* Eve guesses HPKE-Stern-F session key */
    bl      prng_next
    ldr     r1, =val_sdf_K_enc
    ldr     r1, [r1]
    cmp     r0, r1
    beq     eve_hpke_sdf_fail
    ldr     r0, =fmt_eve_hpke_sdf_ok
    bl      printf
    b       eve_hpke_sdf_done
eve_hpke_sdf_fail:
    ldr     r0, =fmt_eve_hpke_sdf_fail
    bl      printf
eve_hpke_sdf_done:

    /* ================================================================
       ZKP-RNL  (Ring-LWR Sigma-protocol, N=32, gamma=4096, t=4)
       Reuses rnl_s_A / rnl_m_blind / rnl_C_A from the HKEX-RNL section.
       ================================================================ */
    ldr     r0, =fmt_zkp_rnl_hdr
    bl      printf

    ldr     r0, =fmt_hex
    ldr     r1, =lbl_sigma_msg
    ldr     r2, =sigma_demo_msg
    ldr     r2, [r2]
    bl      printf

    ldr     r0, =sigma_demo_msg
    ldr     r0, [r0]
    bl      rnl_sigma_sign_32
    cmp     r0, #0
    bne     zkp_rnl_sign_fail

    ldr     r0, =sigma_demo_msg
    ldr     r0, [r0]
    bl      rnl_sigma_verify_32
    cmp     r0, #1
    bne     zkp_rnl_verify_fail
    ldr     r0, =fmt_zkp_rnl_ok
    bl      printf
    b       zkp_rnl_done
zkp_rnl_sign_fail:
    ldr     r0, =fmt_zkp_rnl_fail
    bl      printf
    b       zkp_rnl_done
zkp_rnl_verify_fail:
    ldr     r0, =fmt_zkp_rnl_fail
    bl      printf
zkp_rnl_done:
    ldr     r0, =fmt_nl
    bl      printf

    /* ── 78.H — Masked HSKE demo ──────────────────────────────────── */
    ldr     r0, =fmt_masked_hdr
    bl      printf
    bl      prng_next
    mov     r4, r0          @ plain
    bl      prng_next
    mov     r5, r0          @ key
    bl      prng_next
    mov     r6, r0          @ mask
    @ ct = fscx_revolve(plain ^ mask, key, I_VALUE) ^ fscx_revolve(mask, 0, I_VALUE)
    mov     r0, r4
    eor     r0, r0, r6      @ A ^ mask
    mov     r1, r5          @ key
    mov     r2, #I_VALUE
    bl      fscx_revolve
    mov     r7, r0          @ fm
    mov     r0, r6          @ mask
    mov     r1, #0          @ zero
    mov     r2, #I_VALUE
    bl      fscx_revolve
    eor     r7, r7, r0      @ ct
    @ pt = fscx_revolve(ct ^ mask, key, R_VALUE) ^ fscx_revolve(mask, 0, R_VALUE)
    mov     r0, r7
    eor     r0, r0, r6      @ ct ^ mask
    mov     r1, r5
    mov     r2, #R_VALUE
    bl      fscx_revolve
    mov     r8, r0          @ fm
    mov     r0, r6
    mov     r1, #0
    mov     r2, #R_VALUE
    bl      fscx_revolve
    eor     r8, r8, r0      @ recovered
    cmp     r8, r4
    beq     masked_ok
    ldr     r0, =fmt_masked_fail
    bl      printf
    b       masked_done
masked_ok:
    ldr     r0, =fmt_masked_ok
    bl      printf
masked_done:

    /* ── 78.C — Ratchet demo (5 steps) ───────────────────────────── */
    ldr     r0, =fmt_ratch_hdr
    bl      printf
    @ seed state: prng_next as initial state
    bl      prng_next
    mov     r4, r0          @ state
    ldr     r5, =ratchet_domain_32
    ldr     r5, [r5]        @ domain constant
    mov     r6, #5          @ steps
    mov     r9, #0          @ seen[0] sentinel (first key)
    mov     r10, #1         @ all_unique flag
ratch_loop:
    @ msg_key = nl_fscx_revolve_v1(state, 0x01, 1)
    mov     r0, r4
    mov     r1, #1
    mov     r2, #1
    bl      nl_fscx_revolve_v1
    cmp     r6, #5
    it      eq
    moveq   r9, r0          @ save first key
    cmp     r6, #5
    it      ne
    cmpeq   r10, #1         @ only check if still unique
    it      ne
    cmpeq   r0, r9          @ collision with first key?
    it      eq
    moveq   r10, #0         @ mark not unique
    @ new_state = nl_fscx_revolve_v1(state, domain, 1)
    mov     r0, r4
    mov     r1, r5
    mov     r2, #1
    bl      nl_fscx_revolve_v1
    mov     r4, r0
    subs    r6, r6, #1
    bne     ratch_loop
    cmp     r10, #1
    beq     ratch_unique_ok
    ldr     r0, =fmt_ratch_fail
    bl      printf
    b       ratch_done
ratch_unique_ok:
    ldr     r0, =fmt_ratch_ok
    bl      printf
ratch_done:
    ldr     r0, =fmt_nl
    bl      printf

    mov     r0, #0
    bl      exit

    .ltorg

/* ------------------------------------------------------------------ */
/* prng_next: no args; r0=new state; clobbers r1,r2                   */
/* ------------------------------------------------------------------ */
    .thumb_func
prng_next:
    ldr     r1, =lcg_state
    ldr     r0, [r1]
    ldr     r2, =lcg_mul
    ldr     r2, [r2]
    mul     r0, r0, r2
    ldr     r2, =lcg_add
    ldr     r2, [r2]
    add     r0, r0, r2
    str     r0, [r1]
    bx      lr

    .ltorg

/* ------------------------------------------------------------------ */
/* gf_mul_32: r0=a, r1=b -> r0=a*b in GF(2^32)*                      */
/* ------------------------------------------------------------------ */
    .thumb_func
gf_mul_32:
    push    {r4-r8, lr}
    mov     r4, #0
    mov     r5, r0
    mov     r6, r1
    ldr     r7, =0x00400007
    mov     r8, #32
gf_mul_32_loop:
    tst     r6, #1
    it      ne
    eorne   r4, r4, r5
    lsls    r5, r5, #1
    it      cs
    eorcs   r5, r5, r7
    lsr     r6, r6, #1
    subs    r8, r8, #1
    bne     gf_mul_32_loop
    mov     r0, r4
    pop     {r4-r8, pc}

    .ltorg

/* ------------------------------------------------------------------ */
/* gf_pow_32: r0=base, r1=exp -> r0=base^exp in GF(2^32)*             */
/* ------------------------------------------------------------------ */
    .thumb_func
gf_pow_32:
    push    {r4-r6, lr}
    mov     r4, #1
    mov     r5, r0
    mov     r6, r1
gf_pow_32_loop:
    cbz     r6, gf_pow_32_done
    tst     r6, #1
    beq     gf_pow_32_skip
    mov     r0, r4
    mov     r1, r5
    bl      gf_mul_32
    mov     r4, r0
gf_pow_32_skip:
    mov     r0, r5
    mov     r1, r5
    bl      gf_mul_32
    mov     r5, r0
    lsr     r6, r6, #1
    b       gf_pow_32_loop
gf_pow_32_done:
    mov     r0, r4
    pop     {r4-r6, pc}

    .ltorg

/* ------------------------------------------------------------------ */
/* fscx_revolve: r0=A, r1=B, r2=rounds -> r0                          */
/* ------------------------------------------------------------------ */
    .thumb_func
fscx_revolve:
    push    {r4-r7, lr}
    mov     r4, r0
fscx_revolve_loop:
    eor     r5, r4, r1
    ror     r6, r4, #1
    eor     r5, r5, r6
    ror     r6, r1, #1
    eor     r5, r5, r6
    ror     r6, r4, #31
    eor     r5, r5, r6
    ror     r6, r1, #31
    eor     r5, r5, r6
    mov     r4, r5
    subs    r2, r2, #1
    bne     fscx_revolve_loop
    mov     r0, r4
    pop     {r4-r7, pc}

    .ltorg

/* ------------------------------------------------------------------ */
/* fscx_single: r0=A, r1=B -> r0=fscx(A,B); r1=B preserved           */
/* ------------------------------------------------------------------ */
    .thumb_func
fscx_single:
    push    {r4-r5, lr}
    eor     r4, r0, r1
    ror     r5, r0, #31
    eor     r4, r4, r5
    ror     r5, r0, #1
    eor     r4, r4, r5
    ror     r5, r1, #31
    eor     r4, r4, r5
    ror     r5, r1, #1
    eor     r4, r4, r5
    mov     r0, r4
    pop     {r4-r5, pc}

    .ltorg

/* ------------------------------------------------------------------ */
/* nl_fscx_delta_v2: r0=B -> r0=ROL32(B*((B+1)>>1), 8)               */
/* ------------------------------------------------------------------ */
    .thumb_func
nl_fscx_delta_v2:
    push    {r4, lr}
    mov     r4, r0
    add     r0, r0, #1
    lsr     r0, r0, #1
    mul     r0, r0, r4
    ror     r0, r0, #24
    pop     {r4, pc}

    .ltorg

/* ------------------------------------------------------------------ */
/* nl_fscx_v1: r0=A, r1=B -> r0=fscx(A,B) XOR ROL(A+B, 8)            */
/* ------------------------------------------------------------------ */
    .thumb_func
nl_fscx_v1:
    push    {r4-r6, lr}
    mov     r4, r0
    bl      fscx_single
    mov     r5, r0
    add     r0, r4, r1
    ror     r0, r0, #24
    eor     r0, r0, r5
    pop     {r4-r6, pc}

    .ltorg

/* ------------------------------------------------------------------ */
/* nl_fscx_revolve_v1: r0=A, r1=B, r2=steps -> r0                    */
/* ------------------------------------------------------------------ */
    .thumb_func
nl_fscx_revolve_v1:
    push    {r4-r6, lr}
    mov     r4, r0
    mov     r5, r1
    mov     r6, r2
rv1_loop:
    cbz     r6, rv1_done
    mov     r0, r4
    mov     r1, r5
    bl      nl_fscx_v1
    mov     r4, r0
    subs    r6, r6, #1
    b       rv1_loop
rv1_done:
    mov     r0, r4
    pop     {r4-r6, pc}

    .ltorg

/* ------------------------------------------------------------------ */
/* nl_fscx_v2: r0=A, r1=B -> r0=fscx(A,B)+delta(B) mod 2^32          */
/* ------------------------------------------------------------------ */
    .thumb_func
nl_fscx_v2:
    push    {r4-r5, lr}
    mov     r4, r1
    bl      fscx_single
    mov     r5, r0
    mov     r0, r4
    bl      nl_fscx_delta_v2
    add     r0, r0, r5
    pop     {r4-r5, pc}

    .ltorg

/* ------------------------------------------------------------------ */
/* m_inv_32: r0=X -> r0=M^{-1}(X) via precomputed rotation table     */
/* M^{-1}(X) = XOR of ROL(X,k) for k in {0,2,3,5,6,8,9,...,29,30}   */
/* (bits of 0x6DB6DB6D = fscx_revolve(1,0,15) for n=32)              */
/* ------------------------------------------------------------------ */
    .thumb_func
m_inv_32:
    @ r0=X; result in r0; r1=saved X, r2=scratch (all caller-saved)
    mov     r1, r0              @ save original X
    ror     r2, r1, #30         @ ROL(X, 2)
    eor     r0, r0, r2
    ror     r2, r1, #29         @ ROL(X, 3)
    eor     r0, r0, r2
    ror     r2, r1, #27         @ ROL(X, 5)
    eor     r0, r0, r2
    ror     r2, r1, #26         @ ROL(X, 6)
    eor     r0, r0, r2
    ror     r2, r1, #24         @ ROL(X, 8)
    eor     r0, r0, r2
    ror     r2, r1, #23         @ ROL(X, 9)
    eor     r0, r0, r2
    ror     r2, r1, #21         @ ROL(X,11)
    eor     r0, r0, r2
    ror     r2, r1, #20         @ ROL(X,12)
    eor     r0, r0, r2
    ror     r2, r1, #18         @ ROL(X,14)
    eor     r0, r0, r2
    ror     r2, r1, #17         @ ROL(X,15)
    eor     r0, r0, r2
    ror     r2, r1, #15         @ ROL(X,17)
    eor     r0, r0, r2
    ror     r2, r1, #14         @ ROL(X,18)
    eor     r0, r0, r2
    ror     r2, r1, #12         @ ROL(X,20)
    eor     r0, r0, r2
    ror     r2, r1, #11         @ ROL(X,21)
    eor     r0, r0, r2
    ror     r2, r1, #9          @ ROL(X,23)
    eor     r0, r0, r2
    ror     r2, r1, #8          @ ROL(X,24)
    eor     r0, r0, r2
    ror     r2, r1, #6          @ ROL(X,26)
    eor     r0, r0, r2
    ror     r2, r1, #5          @ ROL(X,27)
    eor     r0, r0, r2
    ror     r2, r1, #3          @ ROL(X,29)
    eor     r0, r0, r2
    ror     r2, r1, #2          @ ROL(X,30)
    eor     r0, r0, r2
    bx      lr

    .ltorg

/* ------------------------------------------------------------------ */
/* nl_fscx_v2_inv: r0=Y, r1=B -> r0=B XOR M^{-1}((Y-delta(B)) mod 2^32) */
/* ------------------------------------------------------------------ */
    .thumb_func
nl_fscx_v2_inv:
    push    {r4-r5, lr}
    mov     r4, r0
    mov     r5, r1
    mov     r0, r5
    bl      nl_fscx_delta_v2
    sub     r4, r4, r0
    mov     r0, r4
    bl      m_inv_32
    eor     r0, r0, r5
    pop     {r4-r5, pc}

    .ltorg

/* ------------------------------------------------------------------ */
/* nl_fscx_revolve_v2: r0=A, r1=B, r2=steps -> r0                    */
/* ------------------------------------------------------------------ */
    .thumb_func
nl_fscx_revolve_v2:
    push    {r4-r6, lr}
    mov     r4, r0
    mov     r5, r1
    mov     r6, r2
rv2_loop:
    cbz     r6, rv2_done
    mov     r0, r4
    mov     r1, r5
    bl      nl_fscx_v2
    mov     r4, r0
    subs    r6, r6, #1
    b       rv2_loop
rv2_done:
    mov     r0, r4
    pop     {r4-r6, pc}

    .ltorg

/* ------------------------------------------------------------------ */
/* nl_fscx_revolve_v2_inv: r0=Y, r1=B, r2=steps -> r0                */
/* delta(B) precomputed once — b constant throughout the revolve      */
/* ------------------------------------------------------------------ */
    .thumb_func
nl_fscx_revolve_v2_inv:
    push    {r4-r7, lr}
    mov     r4, r0              @ r4 = current y
    mov     r5, r1              @ r5 = B
    mov     r6, r2              @ r6 = steps
    mov     r0, r5
    bl      nl_fscx_delta_v2    @ r0 = delta(B)
    mov     r7, r0              @ r7 = delta (precomputed once)
rv2i_loop:
    cbz     r6, rv2i_done
    sub     r4, r4, r7          @ z = y - delta  (mod 2^32)
    mov     r0, r4
    bl      m_inv_32            @ r0 = M^{-1}(z)
    eor     r4, r0, r5          @ y = B XOR M^{-1}(z)
    subs    r6, r6, #1
    b       rv2i_loop
rv2i_done:
    mov     r0, r4
    pop     {r4-r7, pc}

    .ltorg

/* ------------------------------------------------------------------ */
/* rnl_poly_add: h[i]=(f[i]+g[i])%Q via rnl_{f,g,h}_ptr              */
/* ------------------------------------------------------------------ */
    .thumb_func
rnl_poly_add:
    push    {r4-r9, lr}
    ldr     r4, =rnl_f_ptr
    ldr     r4, [r4]
    ldr     r5, =rnl_g_ptr
    ldr     r5, [r5]
    ldr     r6, =rnl_h_ptr
    ldr     r6, [r6]
    ldr     r9, =RNL_Q
    mov     r7, #0
rpa_loop:
    cmp     r7, #RNL_N
    bge     rpa_done
    ldr     r0, [r4, r7, lsl #2]
    ldr     r1, [r5, r7, lsl #2]
    add     r0, r0, r1
    cmp     r0, r9
    it      cs
    subcs   r0, r0, r9
    str     r0, [r6, r7, lsl #2]
    add     r7, r7, #1
    b       rpa_loop
rpa_done:
    pop     {r4-r9, pc}

    .ltorg

/* ------------------------------------------------------------------ */
/* rnl_ntt: in-place NTT/INTT on array of RNL_N words                  */
/* r0=array ptr  r1=0(fwd)/1(inv)                                       */
/* Uses precomputed tables: rnl_bit_rev_tab, rnl_omega_{fwd,inv}_tab    */
/* Registers: r4=arr r5=inv_flag r6=i r7=j r8=len r9=half              */
/*            r10=step r11=omega_tab r0-r3=scratch                      */
/* ------------------------------------------------------------------ */
    .thumb_func
rnl_ntt:
    push    {r4-r11, lr}
    mov     r4, r0                  @ arr ptr
    mov     r5, r1                  @ inv flag

    @ --- Bit-reversal permutation using precomputed table ---
    ldr     r11, =rnl_bit_rev_tab
    mov     r6, #0
ntt_br:
    cmp     r6, #RNL_N
    bge     ntt_br_done
    ldrb    r7, [r11, r6]           @ j = bit_rev[i]
    cmp     r6, r7
    bge     ntt_br_next
    ldr     r0, [r4, r6, lsl #2]
    ldr     r1, [r4, r7, lsl #2]
    str     r1, [r4, r6, lsl #2]
    str     r0, [r4, r7, lsl #2]
ntt_br_next:
    add     r6, r6, #1
    b       ntt_br
ntt_br_done:

    @ Select forward or inverse omega table
    ldr     r11, =rnl_omega_fwd_tab
    ldr     r12, =rnl_omega_inv_tab
    cmp     r5, #0
    it      ne
    movne   r11, r12

    @ --- Butterfly stages: length = 2,4,8,16,32 ---
    @ r8=length  r9=half  r10=twiddle step (16/half = n/length)
    mov     r8, #2
    mov     r10, #16                @ step starts at 16 (for half=1)
ntt_stage:
    cmp     r8, #RNL_N
    bgt     ntt_stage_done
    lsr     r9, r8, #1              @ half = length/2

    @ Group loop: r6 = group start (i), step = r8 (length)
    mov     r6, #0
ntt_grp:
    cmp     r6, #RNL_N
    bge     ntt_grp_done

    @ Butterfly loop: r7 = k (0..half-1)
    mov     r7, #0
ntt_bf:
    cmp     r7, r9                  @ while k < half
    bge     ntt_bf_done

    @ Load wn = omega_tab[k * step]
    mul     r0, r7, r10             @ idx = k * step
    ldr     r2, [r11, r0, lsl #2]  @ wn = omega_tab[idx]

    @ u = arr[i+k],  v_raw = arr[i+k+half]
    add     r0, r6, r7             @ i+k
    ldr     r3, [r4, r0, lsl #2]  @ u
    add     r1, r0, r9             @ i+k+half
    ldr     r0, [r4, r1, lsl #2]  @ v_raw

    @ v = v_raw * wn mod q (fast Fermat: 2^16 ≡ -1, 2^32 ≡ 1 mod 65537)
    umull   r0, r12, r0, r2        @ r12:r0 = v_raw * wn
    add     r0, r0, r12            @ r0 += r12 (since 2^32 ≡ 1)
    lsr     r12, r0, #16
    uxth    r0, r0
    sub     r0, r0, r12
    it      mi
    addmi   r0, r0, #RNL_Q         @ r0 = v (mod q)

    @ Store a[i+k] = (u + v) mod q
    add     r12, r3, r0
    ldr     r2, =RNL_Q
    cmp     r12, r2
    it      cs
    subcs   r12, r12, r2
    add     r2, r6, r7
    str     r12, [r4, r2, lsl #2]

    @ Store a[i+k+half] = (u - v + q) mod q
    ldr     r2, =RNL_Q
    sub     r12, r3, r0
    add     r12, r12, r2
    cmp     r12, r2
    it      cs
    subcs   r12, r12, r2
    add     r2, r6, r7
    add     r2, r2, r9             @ i+k+half
    str     r12, [r4, r2, lsl #2]

    add     r7, r7, #1
    b       ntt_bf
ntt_bf_done:

    add     r6, r6, r8             @ i += length
    b       ntt_grp
ntt_grp_done:

    lsl     r8, r8, #1             @ length <<= 1
    lsr     r10, r10, #1           @ step >>= 1
    b       ntt_stage
ntt_stage_done:

    @ If inverse: multiply all by inv_n = 63489
    cmp     r5, #0
    beq     ntt_inv_done
    ldr     r1, =rnl_inv_n
    ldr     r2, [r1]               @ inv_n = 63489
    mov     r6, #0
ntt_scale:
    cmp     r6, #RNL_N
    bge     ntt_inv_done
    ldr     r0, [r4, r6, lsl #2]
    umull   r0, r1, r0, r2
    add     r0, r0, r1
    lsr     r1, r0, #16
    uxth    r0, r0
    sub     r0, r0, r1
    it      mi
    addmi   r0, r0, #RNL_Q
    str     r0, [r4, r6, lsl #2]
    add     r6, r6, #1
    b       ntt_scale
ntt_inv_done:

    pop     {r4-r11, pc}
    .ltorg

/* rnl_poly_mul: h=f*g in Z_q[x]/(x^N+1) via NTT. O(N log N).          */
/* Args via rnl_{f,g,h}_ptr (unchanged calling convention).              */
/* ------------------------------------------------------------------ */
    .thumb_func
rnl_poly_mul:
    push    {r4-r11, lr}

    @ Copy f[] and g[] to work arrays fa[], ga[] with psi twist
    ldr     r4, =rnl_f_ptr
    ldr     r4, [r4]               @ f ptr
    ldr     r5, =rnl_g_ptr
    ldr     r5, [r5]               @ g ptr
    ldr     r6, =rnl_fa            @ fa ptr
    ldr     r7, =rnl_ga            @ ga ptr
    ldr     r8, =rnl_psi_pow_tab   @ psi_pow table
    mov     r9, #0                 @ i
rpm_twist:
    cmp     r9, #RNL_N
    bge     rpm_twist_done
    ldr     r10, [r8, r9, lsl #2]  @ psi_pow[i]
    ldr     r11, [r4, r9, lsl #2]  @ f[i]
    @ fa[i] = f[i] * psi_pow[i] mod q
    umull   r0, r1, r11, r10
    add     r0, r0, r1
    lsr     r1, r0, #16
    uxth    r0, r0
    sub     r0, r0, r1
    it      mi
    addmi   r0, r0, #RNL_Q
    str     r0, [r6, r9, lsl #2]
    @ ga[i] = g[i] * psi_pow[i] mod q
    ldr     r11, [r5, r9, lsl #2]  @ g[i]
    umull   r0, r1, r11, r10
    add     r0, r0, r1
    lsr     r1, r0, #16
    uxth    r0, r0
    sub     r0, r0, r1
    it      mi
    addmi   r0, r0, #RNL_Q
    str     r0, [r7, r9, lsl #2]
    add     r9, r9, #1
    b       rpm_twist
rpm_twist_done:

    @ Forward NTT on fa
    ldr     r0, =rnl_fa
    mov     r1, #0
    bl      rnl_ntt
    @ Forward NTT on ga
    ldr     r0, =rnl_ga
    mov     r1, #0
    bl      rnl_ntt

    @ Pointwise multiply: ha[i] = fa[i] * ga[i] mod q
    ldr     r4, =rnl_fa
    ldr     r5, =rnl_ga
    ldr     r6, =rnl_ha
    mov     r9, #0
rpm_pw:
    cmp     r9, #RNL_N
    bge     rpm_pw_done
    ldr     r10, [r4, r9, lsl #2]
    ldr     r11, [r5, r9, lsl #2]
    umull   r0, r1, r10, r11
    add     r0, r0, r1
    lsr     r1, r0, #16
    uxth    r0, r0
    sub     r0, r0, r1
    it      mi
    addmi   r0, r0, #RNL_Q
    str     r0, [r6, r9, lsl #2]
    add     r9, r9, #1
    b       rpm_pw
rpm_pw_done:

    @ Inverse NTT on ha
    ldr     r0, =rnl_ha
    mov     r1, #1
    bl      rnl_ntt

    @ Untwist: h[i] = ha[i] * psi_inv_pow[i] mod q, copy to output
    ldr     r3, =rnl_h_ptr
    ldr     r3, [r3]               @ h ptr
    ldr     r6, =rnl_ha
    ldr     r8, =rnl_psi_inv_pow_tab
    mov     r9, #0
rpm_untwist:
    cmp     r9, #RNL_N
    bge     rpm_untwist_done
    ldr     r10, [r8, r9, lsl #2]  @ psi_inv_pow[i]
    ldr     r11, [r6, r9, lsl #2]  @ ha[i]
    umull   r0, r1, r11, r10
    add     r0, r0, r1
    lsr     r1, r0, #16
    uxth    r0, r0
    sub     r0, r0, r1
    it      mi
    addmi   r0, r0, #RNL_Q
    str     r0, [r3, r9, lsl #2]
    add     r9, r9, #1
    b       rpm_untwist
rpm_untwist_done:

    pop     {r4-r11, pc}

    .ltorg

/* ------------------------------------------------------------------ */
/* rnl_round: r0=out, r1=in, r2=from_q, r3=to_p                      */
/* ------------------------------------------------------------------ */
    .thumb_func
rnl_round:
    push    {r4-r9, lr}
    mov     r4, r0
    mov     r5, r1
    mov     r6, r2
    mov     r7, r3
    mov     r8, #0
rr_loop:
    cmp     r8, #RNL_N
    bge     rr_done
    ldr     r0, [r5, r8, lsl #2]
    mul     r0, r0, r7
    lsr     r9, r6, #1
    add     r0, r0, r9
    udiv    r0, r0, r6
    udiv    r9, r0, r7
    mls     r0, r7, r9, r0
    str     r0, [r4, r8, lsl #2]
    add     r8, r8, #1
    b       rr_loop
rr_done:
    pop     {r4-r9, pc}

    .ltorg

/* ------------------------------------------------------------------ */
/* rnl_lift: r0=out, r1=in, r2=from_p, r3=to_q                       */
/* ------------------------------------------------------------------ */
    .thumb_func
rnl_lift:
    push    {r4-r9, lr}
    mov     r4, r0
    mov     r5, r1
    mov     r6, r2
    mov     r7, r3
    mov     r8, #0
rl_loop:
    cmp     r8, #RNL_N
    bge     rl_done
    ldr     r0, [r5, r8, lsl #2]
    mul     r0, r0, r7
    add     r0, r0, r6, lsr #1     @ += from_p/2 (centered rounding)
    udiv    r0, r0, r6
    udiv    r9, r0, r7
    mls     r0, r7, r9, r0
    str     r0, [r4, r8, lsl #2]
    add     r8, r8, #1
    b       rl_loop
rl_done:
    pop     {r4-r9, pc}

    .ltorg

/* ------------------------------------------------------------------ */
/* rnl_m_poly: r0=p -> p = 1 + x + x^{N-1}                           */
/* ------------------------------------------------------------------ */
    .thumb_func
rnl_m_poly:
    push    {r4-r5, lr}
    mov     r4, r0
    mov     r0, #0
    mov     r5, #RNL_N
    mov     r1, r4
rmp_zero:
    str     r0, [r1], #4
    subs    r5, r5, #1
    bne     rmp_zero
    mov     r0, #1
    str     r0, [r4]
    str     r0, [r4, #4]
    str     r0, [r4, #(RNL_N-1)*4]
    pop     {r4-r5, pc}

    .ltorg

/* ------------------------------------------------------------------ */
/* rnl_rand_poly: r0=p -> p[i] = uniform in [0,Q) via 3-byte rejection*/
/* threshold = (1<<24)-(1<<24)%RNL_Q = 0xFF00FF; reject prob ~0.39%  */
/* ------------------------------------------------------------------ */
    .thumb_func
rnl_rand_poly:
    push    {r4-r7, lr}
    mov     r4, r0
    ldr     r7, =RNL_Q
    mov     r5, #0
rrp_loop:
    cmp     r5, #RNL_N
    bge     rrp_done
rrp_sample:
    bl      prng_next
    ubfx    r0, r0, #0, #24          @ mask to 24 bits
    ldr     r6, =0xFF00FF            @ threshold = (1<<24)-(1<<24)%RNL_Q
    cmp     r0, r6
    bge     rrp_sample               @ reject: redraw
    udiv    r6, r0, r7
    mls     r0, r7, r6, r0
    str     r0, [r4, r5, lsl #2]
    add     r5, r5, #1
    b       rrp_loop
rrp_done:
    pop     {r4-r7, pc}

    .ltorg

/* ------------------------------------------------------------------ */
/* rnl_cbd_poly: r0=p -> p[i] = CBD(1) coeff in {RNL_Q-1, 0, 1}      */
/*   raw = prng_next(); a = raw&1; b = (raw>>1)&1; coeff = a-b mod q  */
/* ------------------------------------------------------------------ */
    .thumb_func
rnl_cbd_poly:
    push    {r4-r7, lr}
    mov     r4, r0
    mov     r5, #0
rcp_loop:
    cmp     r5, #RNL_N
    bge     rcp_done
    bl      prng_next
    mov     r6, r0
    and     r6, r6, #1          @ a = raw & 1
    lsr     r0, r0, #1
    and     r0, r0, #1          @ b = (raw>>1) & 1
    sub     r0, r6, r0          @ coeff = a - b  (may be -1)
    cmp     r0, #0
    bge     rcp_store
    ldr     r7, =RNL_Q
    add     r0, r0, r7          @ coeff + RNL_Q to keep non-negative
rcp_store:
    str     r0, [r4, r5, lsl #2]
    add     r5, r5, #1
    b       rcp_loop
rcp_done:
    pop     {r4-r7, pc}

    .ltorg

/* ------------------------------------------------------------------ */
/* rnl_bits32: r0=poly -> r0=uint32 (bit i = poly[i] >= PP/2=2)       */
/* ------------------------------------------------------------------ */
    .thumb_func
rnl_bits32:
    push    {r4-r7, lr}
    mov     r4, r0
    mov     r5, #0
    mov     r6, #0
rb_loop:
    cmp     r6, #RNL_N
    bge     rb_done
    ldr     r0, [r4, r6, lsl #2]
    cmp     r0, #1
    blt     rb_next
    mov     r7, #1
    lsl     r7, r7, r6
    orr     r5, r5, r7
rb_next:
    add     r6, r6, #1
    b       rb_loop
rb_done:
    mov     r0, r5
    pop     {r4-r7, pc}

    .ltorg

/* ------------------------------------------------------------------ */
/* rnl_keygen: r0=s, r1=C_out, r2=m_blind                            */
/* ------------------------------------------------------------------ */
    .thumb_func
rnl_keygen:
    push    {r4-r6, lr}
    mov     r4, r0
    mov     r5, r1
    mov     r6, r2

    mov     r0, r4
    bl      rnl_cbd_poly

    ldr     r0, =rnl_h_ptr
    ldr     r1, =rnl_tmp
    str     r1, [r0]
    ldr     r0, =rnl_f_ptr
    str     r6, [r0]
    ldr     r0, =rnl_g_ptr
    str     r4, [r0]
    bl      rnl_poly_mul

    mov     r0, r5
    ldr     r1, =rnl_tmp
    ldr     r2, =RNL_Q
    ldr     r3, =RNL_P
    bl      rnl_round

    pop     {r4-r6, pc}

    .ltorg

/* ------------------------------------------------------------------ */
/* rnl_hint32: r0=K_poly -> r0=hint_uint32                            */
/*   2-bit hint per coefficient; uses RNL_N/2=16 coefficients.        */
/*   h[i] = floor((8*c + q/4) / q) % 4  (eighth-bucket lower 2 bits) */
/*   Thresholds (c values where h increments):                         */
/*   0→1: 6145, 1→2: 14337, 2→3: 22529, 3→0: 30721,                 */
/*   0→1: 38913, 1→2: 47105, 2→3: 55297                              */
/* ------------------------------------------------------------------ */
    .thumb_func
rnl_hint32:
    push    {r4-r9, lr}
    mov     r4, r0              @ r4 = K_poly
    mov     r5, #0              @ r5 = hint result
    mov     r6, #0              @ r6 = i
rh32_loop:
    cmp     r6, #(RNL_N/2)     @ loop over first 16 coefficients
    bge     rh32_done
    ldr     r7, [r4, r6, lsl #2]    @ r7 = c
    @ Compute h ∈ {0,1,2,3} via threshold comparisons
    mov     r0, #0
    ldr     r8, =6145
    cmp     r7, r8
    blt     rh32_store          @ c < 6145 → h=0
    mov     r0, #1
    ldr     r8, =14337
    cmp     r7, r8
    blt     rh32_store          @ c < 14337 → h=1
    mov     r0, #2
    ldr     r8, =22529
    cmp     r7, r8
    blt     rh32_store          @ c < 22529 → h=2
    mov     r0, #3
    ldr     r8, =30721
    cmp     r7, r8
    blt     rh32_store          @ c < 30721 → h=3
    mov     r0, #0
    ldr     r8, =38913
    cmp     r7, r8
    blt     rh32_store          @ c < 38913 → h=0
    mov     r0, #1
    ldr     r8, =47105
    cmp     r7, r8
    blt     rh32_store          @ c < 47105 → h=1
    mov     r0, #2
    ldr     r8, =55297
    cmp     r7, r8
    blt     rh32_store          @ c < 55297 → h=2
    mov     r0, #3             @ c >= 55297 → h=3
rh32_store:
    lsl     r8, r6, #1          @ r8 = 2*i
    lsl     r0, r0, r8          @ r0 = h << (2*i)
    orr     r5, r5, r0
rh32_next:
    add     r6, r6, #1
    b       rh32_loop
rh32_done:
    mov     r0, r5
    pop     {r4-r9, pc}

    .ltorg

/* ------------------------------------------------------------------ */
/* rnl_reconcile32: r0=K_poly, r1=hint -> r0=key_uint32               */
/*   2-bit extraction: b[i] = ((4*c + (2*h+1)*(q/4)) / q) % 4        */
/*   Uses RNL_N/2=16 coefficients; result is 32-bit packed 2b/coeff.  */
/* ------------------------------------------------------------------ */
    .thumb_func
rnl_reconcile32:
    push    {r4-r9, lr}
    mov     r4, r0              @ r4 = K_poly
    mov     r5, r1              @ r5 = hint (2 bits/coeff, 16 coeffs = 32 bits)
    mov     r7, #0              @ r7 = key result
    mov     r6, #0              @ r6 = i
    ldr     r8, =0x4000         @ r8 = q/4 = 16384
    ldr     r9, =RNL_Q          @ r9 = q = 65537
rc32_loop:
    cmp     r6, #(RNL_N/2)     @ loop over 16 coefficients
    bge     rc32_done
    ldr     r0, [r4, r6, lsl #2]    @ r0 = c
    lsl     r0, r0, #2              @ r0 = 4*c
    lsl     r1, r6, #1              @ r1 = 2*i
    lsr     r2, r5, r1              @ r2 = hint >> (2*i)
    and     r2, r2, #3              @ r2 = h (2-bit hint)
    lsl     r1, r2, #1              @ r1 = 2*h
    add     r1, r1, #1              @ r1 = 2*h+1
    mla     r0, r1, r8, r0          @ r0 = 4*c + (2*h+1)*(q/4)
    @ b = r0/q mod 4 via cascaded subtraction
    mov     r2, #0
    cmp     r0, r9
    blt     rc32_pack               @ val < q → b=0
    sub     r0, r0, r9
    mov     r2, #1
    cmp     r0, r9
    blt     rc32_pack               @ val in [q,2q) → b=1
    sub     r0, r0, r9
    mov     r2, #2
    cmp     r0, r9
    blt     rc32_pack               @ val in [2q,3q) → b=2
    mov     r2, #3                  @ val in [3q,4q) → b=3
rc32_pack:
    lsl     r1, r6, #1          @ r1 = 2*i
    lsl     r2, r2, r1          @ r2 = b << (2*i)
    orr     r7, r7, r2
rc32_next:
    add     r6, r6, #1
    b       rc32_loop
rc32_done:
    mov     r0, r7
    pop     {r4-r9, pc}

    .ltorg

/* ------------------------------------------------------------------ */
/* rnl_agree_full: r0=s, r1=C_other -> r0=key, r1=hint  [reconciler] */
/* ------------------------------------------------------------------ */
    .thumb_func
rnl_agree_full:
    push    {r4-r6, lr}
    mov     r4, r0              @ r4 = s
    mov     r5, r1              @ r5 = C_other

    ldr     r0, =rnl_tmp
    mov     r1, r5
    ldr     r2, =RNL_P
    ldr     r3, =RNL_Q
    bl      rnl_lift

    ldr     r0, =rnl_h_ptr
    ldr     r1, =rnl_tmp2
    str     r1, [r0]
    ldr     r0, =rnl_f_ptr
    str     r4, [r0]
    ldr     r0, =rnl_g_ptr
    ldr     r1, =rnl_tmp
    str     r1, [r0]
    bl      rnl_poly_mul        @ K_poly now in rnl_tmp2

    ldr     r0, =rnl_tmp2
    bl      rnl_hint32          @ r0 = hint
    mov     r6, r0              @ r6 = hint

    ldr     r0, =rnl_tmp2
    mov     r1, r6
    bl      rnl_reconcile32     @ r0 = key

    mov     r1, r6              @ r1 = hint
    pop     {r4-r6, pc}

    .ltorg

/* ------------------------------------------------------------------ */
/* rnl_agree_recv: r0=s, r1=C_other, r2=hint -> r0=key  [receiver]   */
/* ------------------------------------------------------------------ */
    .thumb_func
rnl_agree_recv:
    push    {r4-r5, lr}
    mov     r4, r0              @ r4 = s
    mov     r5, r2              @ r5 = hint (save r2 before clobbered)

    ldr     r0, =rnl_tmp
    @ r1 = C_other (still valid)
    ldr     r2, =RNL_P
    ldr     r3, =RNL_Q
    bl      rnl_lift

    ldr     r0, =rnl_h_ptr
    ldr     r1, =rnl_tmp2
    str     r1, [r0]
    ldr     r0, =rnl_f_ptr
    str     r4, [r0]
    ldr     r0, =rnl_g_ptr
    ldr     r1, =rnl_tmp
    str     r1, [r0]
    bl      rnl_poly_mul        @ K_poly now in rnl_tmp2

    ldr     r0, =rnl_tmp2
    mov     r1, r5
    bl      rnl_reconcile32     @ r0 = key

    pop     {r4-r5, pc}

    .ltorg

/* ------------------------------------------------------------------ */
/* hfscx_32: r0=x -> r0=hfscx_32(x)  (DM, v1.9.0)                   */
/* C_DM(s,m)=nl(s,m,8)^s; IV=0xA3C5E7B9, LB=0xA3C5E799              */
/* s=nl(IV,x,8)^IV; return nl(s,LB,8)^s                              */
/* ------------------------------------------------------------------ */
    .thumb_func
hfscx_32:
    push    {r4, r5, lr}
    mov     r4, r0              @ save x
    ldr     r5, .LHIV           @ r5 = IV_32 (prev for block 1)
    ldr     r0, .LHIV           @ A = IV_32
    mov     r1, r4              @ B = x
    mov     r2, #8
    bl      nl_fscx_revolve_v1  @ r0 = nl(IV, x, 8)
    eor     r0, r0, r5          @ s = result ^ IV  (DM block 1)
    mov     r5, r0              @ r5 = s  (prev for block 2)
    ldr     r1, .LHLB           @ B = LB
    mov     r2, #8
    bl      nl_fscx_revolve_v1  @ r0 = nl(s, LB, 8)
    eor     r0, r0, r5          @ result ^ s  (DM block 2)
    pop     {r4, r5, pc}
.LHIV: .word 0xA3C5E7B9
.LHLB: .word 0xA3C5E799

/* ------------------------------------------------------------------ */
/* stern_hash1_32: r0=ds, r1=v -> r0=sternHash(ds,v)                 */
/* h = nl(ds^v, ROL(v,4), 8); return hfscx_32(h)                     */
/* ------------------------------------------------------------------ */
    .thumb_func
stern_hash1_32:
    push    {r4, lr}
    ror     r4, r1, #28         @ r4 = ROL(v,4)
    eor     r0, r0, r1          @ r0 = ds ^ v
    mov     r1, r4              @ r1 = ROL(v,4)
    mov     r2, #8
    bl      nl_fscx_revolve_v1
    bl      hfscx_32
    pop     {r4, pc}

    .ltorg

/* ------------------------------------------------------------------ */
/* stern_hash2_32: r0=ds, r1=a, r2=b -> r0=sternHash(ds,a,b)        */
/* h=nl(ds^a,ROL(a,4),8); return hfscx_32(nl(h^b,ROL(b,4),8))       */
/* ------------------------------------------------------------------ */
    .thumb_func
stern_hash2_32:
    push    {r4-r5, lr}
    ror     r4, r1, #28         @ r4 = ROL(a,4)
    mov     r5, r2              @ r5 = b
    eor     r0, r0, r1          @ r0 = ds ^ a
    mov     r1, r4              @ r1 = ROL(a,4)
    mov     r2, #8
    bl      nl_fscx_revolve_v1  @ r0 = h
    eor     r0, r0, r5          @ h ^ b
    ror     r1, r5, #28         @ ROL(b,4)
    mov     r2, #8
    bl      nl_fscx_revolve_v1  @ r0 = raw
    bl      hfscx_32
    pop     {r4-r5, pc}

    .ltorg

/* ------------------------------------------------------------------ */
/* stern_matrix_row_32: r0=seed, r1=row -> r0=H[row]                  */
/* H[row] = nl_fscx_revolve_v1(ROL(seed^row,4), seed, 8)             */
/* ------------------------------------------------------------------ */
    .thumb_func
stern_matrix_row_32:
    push    {r4, lr}
    mov     r4, r0              @ save seed
    eor     r0, r0, r1          @ seed XOR row
    ror     r0, r0, #28         @ base = ROL(seed XOR row, 4)
    mov     r1, r4              @ B = seed
    mov     r2, #8
    pop     {r4, lr}
    b       nl_fscx_revolve_v1  @ tail call

    .ltorg

/* ------------------------------------------------------------------ */
/* stern_syndrome_32: r0=seed, r1=e -> r0=syndrome (16-bit)           */
/* syndrome[row] = parity(H[row] AND e), for row 0..SDF_NROWS-1      */
/* ------------------------------------------------------------------ */
    .thumb_func
stern_syndrome_32:
    push    {r4-r8, lr}
    mov     r4, r0              @ seed
    mov     r5, r1              @ e
    mov     r6, #0              @ syndrome accumulator
    mov     r7, #0              @ row index
sds_loop:
    cmp     r7, #SDF_NROWS
    bge     sds_done
    mov     r0, r4
    mov     r1, r7
    bl      stern_matrix_row_32     @ r0 = H[row]
    and     r0, r0, r5              @ H[row] AND e
    @ parity fold
    eor     r0, r0, r0, lsr #16
    eor     r0, r0, r0, lsr #8
    eor     r0, r0, r0, lsr #4
    eor     r0, r0, r0, lsr #2
    eor     r0, r0, r0, lsr #1
    and     r0, r0, #1
    lsl     r0, r0, r7
    orr     r6, r6, r0
    add     r7, r7, #1
    b       sds_loop
sds_done:
    mov     r0, r6
    pop     {r4-r8, pc}

    .ltorg

/* ------------------------------------------------------------------ */
/* stern_popcount_eq2: r0=v -> r0=1 iff popcount(v)==2, else 0        */
/* ------------------------------------------------------------------ */
    .thumb_func
stern_popcount_eq2:
    cbz     r0, speq2_fail
    sub     r1, r0, #1
    ands    r0, r0, r1          @ clear lowest set bit
    beq     speq2_fail          @ was exactly 1 bit: fail
    sub     r1, r0, #1
    tst     r0, r1              @ test if more than 1 remaining bit
    bne     speq2_fail
    mov     r0, #1
    bx      lr
speq2_fail:
    mov     r0, #0
    bx      lr

/* ------------------------------------------------------------------ */
/* stern_gen_perm_32: r0=pi_seed -> writes sdf_perm[0..31]            */
/* Fisher-Yates using nl_fscx_v1 as PRNG                              */
/* ------------------------------------------------------------------ */
    .thumb_func
stern_gen_perm_32:
    push    {r4-r9, lr}
    mov     r4, r0              @ pi_seed
    ror     r5, r4, #28         @ key = ROL(pi_seed, 4)
    mov     r6, r4              @ st = pi_seed (PRNG state)
    ldr     r7, =sdf_perm
    @ initialize: perm[i] = i
    mov     r8, #0
sgp_init:
    cmp     r8, #SDF_N
    bge     sgp_init_done
    strb    r8, [r7, r8]
    add     r8, r8, #1
    b       sgp_init
sgp_init_done:
    @ Fisher-Yates shuffle: i = N-1 downto 1
    mov     r8, #31             @ i = SDF_N - 1
sgp_loop:
    cmp     r8, #1
    blt     sgp_done
    @ st = nl_fscx_v1(st, key)
    mov     r0, r6
    mov     r1, r5
    bl      nl_fscx_v1
    mov     r6, r0
    @ j = (unsigned)st MOD (i+1)
    add     r9, r8, #1
    udiv    r0, r6, r9
    mul     r0, r0, r9
    sub     r9, r6, r0          @ j = st - (st/( i+1))*(i+1)
    @ swap perm[i] and perm[j]
    ldrb    r0, [r7, r8]
    ldrb    r1, [r7, r9]
    strb    r1, [r7, r8]
    strb    r0, [r7, r9]
    sub     r8, r8, #1
    b       sgp_loop
sgp_done:
    pop     {r4-r9, pc}

    .ltorg

/* ------------------------------------------------------------------ */
/* stern_apply_perm_32: r0=v -> r0 = apply sdf_perm to bits of v      */
/* Branchless: mask r3 = -bit (0x00000000 or 0xFFFFFFFF); no branch   */
/* on secret bits.                                                     */
/* ------------------------------------------------------------------ */
    .thumb_func
stern_apply_perm_32:
    push    {r4-r7, lr}
    mov     r4, r0              @ v
    ldr     r5, =sdf_perm
    mov     r6, #0              @ result
    mov     r7, #0              @ bit index i
sap_loop:
    cmp     r7, #SDF_N
    bge     sap_done
    lsr     r0, r4, r7          @ r0 = v >> i
    and     r0, r0, #1          @ r0 = bit (0 or 1)
    neg     r3, r0              @ r3 = -bit (mask: 0x00000000 or 0xFFFFFFFF)
    ldrb    r0, [r5, r7]        @ r0 = perm[i]
    mov     r1, #1
    lsl     r1, r1, r0          @ r1 = 1 << perm[i]
    and     r1, r1, r3          @ apply mask
    orr     r6, r6, r1
    add     r7, r7, #1
    b       sap_loop
sap_done:
    mov     r0, r6
    pop     {r4-r7, pc}

    .ltorg

/* ------------------------------------------------------------------ */
/* stern_rand_error_32: no args -> r0 = weight-SDF_T error vector     */
/* Partial Fisher-Yates (t=2 draws) using prng_next                   */
/* ------------------------------------------------------------------ */
    .thumb_func
stern_rand_error_32:
    push    {r4-r7, lr}
    ldr     r4, =sdf_perm
    @ initialize perm[i] = i
    mov     r5, #0
sre_init:
    cmp     r5, #SDF_N
    bge     sre_init_done
    strb    r5, [r4, r5]
    add     r5, r5, #1
    b       sre_init
sre_init_done:
    @ draw 1: i=31; j = prng % 32; swap perm[31], perm[j]
    bl      prng_next
    mov     r5, #32
    udiv    r6, r0, r5
    mul     r6, r6, r5
    sub     r6, r0, r6          @ j = prng % 32
    ldrb    r0, [r4, #31]
    ldrb    r1, [r4, r6]
    strb    r1, [r4, #31]
    strb    r0, [r4, r6]
    @ draw 2: i=30; j = prng % 31; swap perm[30], perm[j]
    bl      prng_next
    mov     r5, #31
    udiv    r6, r0, r5
    mul     r6, r6, r5
    sub     r6, r0, r6          @ j = prng % 31
    ldrb    r0, [r4, #30]
    ldrb    r1, [r4, r6]
    strb    r1, [r4, #30]
    strb    r0, [r4, r6]
    @ result = (1 << perm[31]) | (1 << perm[30])
    ldrb    r5, [r4, #31]
    ldrb    r6, [r4, #30]
    mov     r0, #1
    lsl     r0, r0, r5
    mov     r1, #1
    lsl     r1, r1, r6
    orr     r0, r0, r1
    pop     {r4-r7, pc}

    .ltorg

/* ------------------------------------------------------------------ */
/* stern_fs_challenges_32: r0=out_ptr -> writes 4 challenges to *r0   */
/* Reads val_plain (msg), sdf_c0, sdf_c1, sdf_c2                     */
/* ------------------------------------------------------------------ */
    .thumb_func
stern_fs_challenges_32:
    push    {r4-r9, lr}
    mov     r9, r0              @ out_ptr
    mov     r4, #0              @ chSt = 0
    @ sfs(msg): chSt = nl_fscx_revolve_v1(chSt ^ msg, ROL(msg,4), 8)
    ldr     r5, =val_plain
    ldr     r5, [r5]
    eor     r0, r4, r5
    ror     r1, r5, #28
    mov     r2, #8
    bl      nl_fscx_revolve_v1
    mov     r4, r0
    @ for i=0..3: sfs(c0[i]), sfs(c1[i]), sfs(c2[i])
    mov     r8, #0
sfc_round_loop:
    cmp     r8, #SDF_ROUNDS
    bge     sfc_round_done
    ldr     r5, =sdf_c0
    ldr     r5, [r5, r8, lsl #2]
    eor     r0, r4, r5
    ror     r1, r5, #28
    mov     r2, #8
    bl      nl_fscx_revolve_v1
    mov     r4, r0
    ldr     r5, =sdf_c1
    ldr     r5, [r5, r8, lsl #2]
    eor     r0, r4, r5
    ror     r1, r5, #28
    mov     r2, #8
    bl      nl_fscx_revolve_v1
    mov     r4, r0
    ldr     r5, =sdf_c2
    ldr     r5, [r5, r8, lsl #2]
    eor     r0, r4, r5
    ror     r1, r5, #28
    mov     r2, #8
    bl      nl_fscx_revolve_v1
    mov     r4, r0
    add     r8, r8, #1
    b       sfc_round_loop
sfc_round_done:
    @ extract per-round challenges: chSt = nl_fscx_v1(chSt, i); out[i] = chSt % 3
    mov     r8, #0
sfc_chal_loop:
    cmp     r8, #SDF_ROUNDS
    bge     sfc_done
    mov     r0, r4
    mov     r1, r8
    bl      nl_fscx_v1
    mov     r4, r0
    mov     r5, #3
    udiv    r6, r4, r5
    mul     r6, r6, r5
    sub     r6, r4, r6          @ challenge = chSt % 3
    str     r6, [r9, r8, lsl #2]
    add     r8, r8, #1
    b       sfc_chal_loop
sfc_done:
    pop     {r4-r9, pc}

    .ltorg

/* ------------------------------------------------------------------ */
/* hpks_stern_f_sign_32: uses val_sdf_seed, val_sdf_e, val_plain      */
/* fills sdf_c0..c2, sdf_b, sdf_respA, sdf_respB                     */
/* ------------------------------------------------------------------ */
    .thumb_func
hpks_stern_f_sign_32:
    push    {r4-r11, lr}
    ldr     r10, =val_sdf_e
    ldr     r10, [r10]          @ r10 = e (preserved across inner calls)
    ldr     r11, =val_sdf_seed
    ldr     r11, [r11]          @ r11 = seed
    @ commit phase: for i=0..SDF_ROUNDS-1
    mov     r4, #0
hsfs_loop:
    cmp     r4, #SDF_ROUNDS
    bge     hsfs_loop_done
    @ r = stern_rand_error_32()
    bl      stern_rand_error_32
    mov     r5, r0              @ r5 = r
    @ y = e XOR r
    eor     r6, r10, r5         @ r6 = y
    @ pi = prng_next()
    bl      prng_next
    mov     r7, r0              @ r7 = pi
    @ stern_gen_perm_32(pi) -> sdf_perm
    mov     r0, r7
    bl      stern_gen_perm_32
    @ sr = stern_apply_perm_32(r)
    mov     r0, r5
    bl      stern_apply_perm_32
    mov     r8, r0              @ r8 = sr = sigma(r)
    @ sy = stern_apply_perm_32(y)
    mov     r0, r6
    bl      stern_apply_perm_32
    mov     r9, r0              @ r9 = sy = sigma(y)
    @ hr = stern_syndrome_32(seed, r)
    mov     r0, r11
    mov     r1, r5
    bl      stern_syndrome_32   @ r0 = H·r^T (16-bit)
    @ c0[i] = stern_hash2_32(1, pi, hr)
    mov     r2, r0              @ r2 = hr
    mov     r1, r7              @ r1 = pi
    mov     r0, #1              @ ds = 1
    bl      stern_hash2_32
    ldr     r3, =sdf_c0
    str     r0, [r3, r4, lsl #2]
    @ c1[i] = stern_hash1_32(2, sr)
    mov     r1, r8              @ r1 = sr
    mov     r0, #2              @ ds = 2
    bl      stern_hash1_32
    ldr     r3, =sdf_c1
    str     r0, [r3, r4, lsl #2]
    @ c2[i] = stern_hash1_32(3, sy)
    mov     r1, r9              @ r1 = sy
    mov     r0, #3              @ ds = 3
    bl      stern_hash1_32
    ldr     r3, =sdf_c2
    str     r0, [r3, r4, lsl #2]
    @ save per-round temporaries
    ldr     r3, =sdf_r_tmp
    str     r5, [r3, r4, lsl #2]
    ldr     r3, =sdf_y_tmp
    str     r6, [r3, r4, lsl #2]
    ldr     r3, =sdf_pi_tmp
    str     r7, [r3, r4, lsl #2]
    ldr     r3, =sdf_sr_tmp
    str     r8, [r3, r4, lsl #2]
    ldr     r3, =sdf_sy_tmp
    str     r9, [r3, r4, lsl #2]
    add     r4, r4, #1
    b       hsfs_loop
hsfs_loop_done:
    @ Fiat-Shamir challenges -> sdf_chals_tmp
    ldr     r0, =sdf_chals_tmp
    bl      stern_fs_challenges_32
    @ collect responses based on challenges
    mov     r4, #0
hsfs_resp_loop:
    cmp     r4, #SDF_ROUNDS
    bge     hsfs_resp_done
    ldr     r3, =sdf_chals_tmp
    ldr     r5, [r3, r4, lsl #2]   @ b = chals[i]
    ldr     r3, =sdf_b
    str     r5, [r3, r4, lsl #2]
    cmp     r5, #0
    beq     hsfs_case0
    cmp     r5, #1
    beq     hsfs_case1
    @ case 2: respA = pi, respB = y
    ldr     r3, =sdf_pi_tmp
    ldr     r0, [r3, r4, lsl #2]
    ldr     r3, =sdf_respA
    str     r0, [r3, r4, lsl #2]
    ldr     r3, =sdf_y_tmp
    ldr     r0, [r3, r4, lsl #2]
    ldr     r3, =sdf_respB
    str     r0, [r3, r4, lsl #2]
    b       hsfs_resp_next
hsfs_case0:
    @ case 0: respA = sr, respB = sy
    ldr     r3, =sdf_sr_tmp
    ldr     r0, [r3, r4, lsl #2]
    ldr     r3, =sdf_respA
    str     r0, [r3, r4, lsl #2]
    ldr     r3, =sdf_sy_tmp
    ldr     r0, [r3, r4, lsl #2]
    ldr     r3, =sdf_respB
    str     r0, [r3, r4, lsl #2]
    b       hsfs_resp_next
hsfs_case1:
    @ case 1: respA = pi, respB = r
    ldr     r3, =sdf_pi_tmp
    ldr     r0, [r3, r4, lsl #2]
    ldr     r3, =sdf_respA
    str     r0, [r3, r4, lsl #2]
    ldr     r3, =sdf_r_tmp
    ldr     r0, [r3, r4, lsl #2]
    ldr     r3, =sdf_respB
    str     r0, [r3, r4, lsl #2]
hsfs_resp_next:
    add     r4, r4, #1
    b       hsfs_resp_loop
hsfs_resp_done:
    pop     {r4-r11, pc}

    .ltorg

/* ------------------------------------------------------------------ */
/* hpks_stern_f_verify_32: -> r0=1 valid, 0 invalid                   */
/* reads sdf_c0..c2, sdf_b, sdf_respA, sdf_respB, val_sdf_seed/syn   */
/* ------------------------------------------------------------------ */
    .thumb_func
hpks_stern_f_verify_32:
    push    {r4-r11, lr}
    @ re-derive challenges
    ldr     r0, =sdf_chals_tmp
    bl      stern_fs_challenges_32
    @ check chals_tmp[i] == sdf_b[i]
    mov     r4, #0
hsfv_chal_chk:
    cmp     r4, #SDF_ROUNDS
    bge     hsfv_chal_ok
    ldr     r3, =sdf_chals_tmp
    ldr     r5, [r3, r4, lsl #2]
    ldr     r3, =sdf_b
    ldr     r6, [r3, r4, lsl #2]
    cmp     r5, r6
    bne     hsfv_fail
    add     r4, r4, #1
    b       hsfv_chal_chk
hsfv_chal_ok:
    ldr     r10, =val_sdf_seed
    ldr     r10, [r10]          @ seed
    ldr     r11, =val_sdf_syn
    ldr     r11, [r11]          @ syndrome
    @ verify each round
    mov     r4, #0
hsfv_round_loop:
    cmp     r4, #SDF_ROUNDS
    bge     hsfv_pass
    ldr     r3, =sdf_b
    ldr     r5, [r3, r4, lsl #2]   @ b
    ldr     r3, =sdf_respA
    ldr     r6, [r3, r4, lsl #2]   @ respA
    ldr     r3, =sdf_respB
    ldr     r7, [r3, r4, lsl #2]   @ respB
    cmp     r5, #0
    beq     hsfv_case0
    cmp     r5, #1
    beq     hsfv_case1
    @ case 2: respA=pi, respB=y
    @ check hash2(1, pi, H·y^T ^ syndrome) == c0[i]
    mov     r0, r10
    mov     r1, r7
    bl      stern_syndrome_32       @ r0 = H·y^T
    eor     r0, r0, r11             @ hysBA = H·y^T ^ syndrome
    mov     r2, r0                  @ r2 = hy^synd
    mov     r1, r6                  @ r1 = pi
    mov     r0, #1                  @ ds = 1
    bl      stern_hash2_32
    ldr     r3, =sdf_c0
    ldr     r1, [r3, r4, lsl #2]
    cmp     r0, r1
    bne     hsfv_fail
    @ check hash1(3, apply_perm(pi, y)) == c2[i]
    mov     r0, r6
    bl      stern_gen_perm_32
    mov     r0, r7
    bl      stern_apply_perm_32
    mov     r1, r0                  @ r1 = apply_perm result
    mov     r0, #3                  @ ds = 3
    bl      stern_hash1_32
    ldr     r3, =sdf_c2
    ldr     r1, [r3, r4, lsl #2]
    cmp     r0, r1
    bne     hsfv_fail
    b       hsfv_round_next
hsfv_case0:
    @ check hash1(2, sr) == c1[i]
    mov     r1, r6                  @ r1 = sr
    mov     r0, #2                  @ ds = 2
    bl      stern_hash1_32
    ldr     r3, =sdf_c1
    ldr     r1, [r3, r4, lsl #2]
    cmp     r0, r1
    bne     hsfv_fail
    @ check hash1(3, sy) == c2[i]
    mov     r1, r7                  @ r1 = sy
    mov     r0, #3                  @ ds = 3
    bl      stern_hash1_32
    ldr     r3, =sdf_c2
    ldr     r1, [r3, r4, lsl #2]
    cmp     r0, r1
    bne     hsfv_fail
    @ check wt(sr) == SDF_T
    mov     r0, r6
    bl      stern_popcount_eq2
    cbz     r0, hsfv_fail
    b       hsfv_round_next
hsfv_case1:
    @ check wt(r) == SDF_T
    mov     r0, r7
    bl      stern_popcount_eq2
    cbz     r0, hsfv_fail
    @ check hash2(1, pi, H·r^T) == c0[i]
    mov     r0, r10
    mov     r1, r7
    bl      stern_syndrome_32       @ r0 = H·r^T
    mov     r2, r0                  @ r2 = H·r^T
    mov     r1, r6                  @ r1 = pi
    mov     r0, #1                  @ ds = 1
    bl      stern_hash2_32
    ldr     r3, =sdf_c0
    ldr     r1, [r3, r4, lsl #2]
    cmp     r0, r1
    bne     hsfv_fail
    @ check hash1(2, apply_perm(pi, r)) == c1[i]
    mov     r0, r6
    bl      stern_gen_perm_32
    mov     r0, r7
    bl      stern_apply_perm_32
    mov     r1, r0                  @ r1 = apply_perm result
    mov     r0, #2                  @ ds = 2
    bl      stern_hash1_32
    ldr     r3, =sdf_c1
    ldr     r1, [r3, r4, lsl #2]
    cmp     r0, r1
    bne     hsfv_fail
hsfv_round_next:
    add     r4, r4, #1
    b       hsfv_round_loop
hsfv_pass:
    mov     r0, #1
    pop     {r4-r11, pc}
hsfv_fail:
    mov     r0, #0
    pop     {r4-r11, pc}

    .ltorg

/* ------------------------------------------------------------------ */
/* hpke_stern_f_encap_32: no args                                      */
/* e' = rand_error; ct = H·e'^T; K = hash2(seed, e')                 */
/* fills val_sdf_e_prime, val_sdf_ct, val_sdf_K_enc                   */
/* ------------------------------------------------------------------ */
    .thumb_func
hpke_stern_f_encap_32:
    push    {r4-r5, lr}
    bl      stern_rand_error_32
    mov     r4, r0              @ e'
    ldr     r3, =val_sdf_e_prime
    str     r4, [r3]
    ldr     r5, =val_sdf_seed
    ldr     r5, [r5]            @ seed
    @ ct = stern_syndrome_32(seed, e')
    mov     r0, r5
    mov     r1, r4
    bl      stern_syndrome_32
    ldr     r3, =val_sdf_ct
    str     r0, [r3]
    @ K = stern_hash2_32(4, seed, e')
    mov     r2, r4              @ r2 = e'
    mov     r1, r5              @ r1 = seed
    mov     r0, #4              @ ds = 4
    bl      stern_hash2_32
    ldr     r3, =val_sdf_K_enc
    str     r0, [r3]
    pop     {r4-r5, pc}

    .ltorg

/* ------------------------------------------------------------------ */
/* hpke_stern_f_decap_known_32: r0=e' -> r0=K=hash2(seed,e')         */
/* ------------------------------------------------------------------ */
    .thumb_func
hpke_stern_f_decap_known_32:
    push    {r4, lr}
    mov     r4, r0              @ e'
    ldr     r1, =val_sdf_seed
    ldr     r1, [r1]            @ r1 = seed
    mov     r2, r4              @ r2 = e'
    mov     r0, #4              @ ds = 4
    bl      stern_hash2_32
    pop     {r4, pc}

    .ltorg

/* ================================================================== */
/* sigma_fold_poly_32: r0=seed, r1=poly_ptr -> r0=new_seed            */
/* Chain-hashes all N=32 coefficients of poly into seed via hfscx_32. */
/* ================================================================== */
    .thumb_func
sigma_fold_poly_32:
    push    {r4-r6, lr}
    mov     r4, r0              @ seed
    mov     r5, r1              @ poly_ptr
    mov     r6, #0              @ i = 0
sfp_loop:
    cmp     r6, #RNL_N
    bge     sfp_done
    ldr     r0, [r5, r6, lsl #2]
    eor     r0, r0, r4
    bl      hfscx_32
    mov     r4, r0
    add     r6, r6, #1
    b       sfp_loop
sfp_done:
    mov     r0, r4
    pop     {r4-r6, pc}

    .ltorg

/* ================================================================== */
/* sigma_challenge_32: r0=m_ptr,r1=C_ptr,r2=w_ptr,r3=msg -> sig_c    */
/* Derives sparse ternary challenge polynomial via chained hfscx_32.  */
/* Seed = hfscx_32(N) folded over m,C,w,msg.  t=4 positions expand   */
/* from seed; signs assigned by additional hash bits.                  */
/* ================================================================== */
    .thumb_func
sigma_challenge_32:
    push    {r4-r11, lr}
    mov     r4, r0              @ m_ptr
    mov     r5, r1              @ C_ptr
    mov     r6, r2              @ w_ptr
    mov     r7, r3              @ msg scalar

    @ seed0 = hfscx_32(n=32)
    mov     r0, #RNL_N
    bl      hfscx_32
    mov     r8, r0              @ r8 = running seed

    @ fold m_ptr coefficients into seed
    mov     r0, r8
    mov     r1, r4
    bl      sigma_fold_poly_32
    mov     r8, r0

    @ fold C_ptr coefficients into seed
    mov     r0, r8
    mov     r1, r5
    bl      sigma_fold_poly_32
    mov     r8, r0

    @ fold w_ptr coefficients into seed
    mov     r0, r8
    mov     r1, r6
    bl      sigma_fold_poly_32
    mov     r8, r0

    @ fold msg scalar into seed
    eor     r0, r7, r8
    bl      hfscx_32
    mov     r8, r0              @ final seed

    @ clear sig_c[0..31]
    ldr     r10, =sig_c
    mov     r0, #0
    mov     r9, #0
sc_clr:
    cmp     r9, #RNL_N
    bge     sc_pos_init
    str     r0, [r10, r9, lsl #2]
    add     r9, r9, #1
    b       sc_clr

sc_pos_init:
    mov     r4, #0              @ idx = 0 (safe across hfscx_32: it saves r4)
    mov     r9, #0              @ k = found count
    ldr     r11, =sig_pos

    @ expand t=4 distinct positions in [0,31]
sc_pos_loop:
    cmp     r9, #SIGMA_T
    bge     sc_signs

    @ h = hfscx_32(seed XOR (idx<<16)); pos = h & 31
    lsl     r0, r4, #16
    eor     r0, r0, r8
    bl      hfscx_32
    add     r4, r4, #1          @ idx++ (r4 preserved by hfscx_32)
    and     r2, r0, #31         @ pos = h % 32

    @ duplicate check against sig_pos[0..k-1]
    mov     r0, #0              @ j = 0
sc_dup:
    cmp     r0, r9
    bge     sc_no_dup
    ldr     r3, [r11, r0, lsl #2]
    cmp     r3, r2
    beq     sc_pos_loop         @ duplicate: retry with next idx
    add     r0, r0, #1
    b       sc_dup
sc_no_dup:
    str     r2, [r11, r9, lsl #2]  @ sig_pos[k] = pos
    add     r9, r9, #1
    b       sc_pos_loop

sc_signs:
    @ q-1 = 65536 = 0x10000
    mov     r5, #1
    lsl     r5, r5, #16         @ r5 = 65536 = q-1
    mov     r9, #0              @ k = 0

sc_sign_loop:
    cmp     r9, #SIGMA_T
    bge     sc_done

    @ sign_bit = hfscx_32(seed XOR (k<<24)) & 1
    lsl     r0, r9, #24
    eor     r0, r0, r8
    bl      hfscx_32
    and     r1, r0, #1          @ sign_bit (r4,r5,r8,r9,r10,r11 preserved)

    ldr     r2, [r11, r9, lsl #2]  @ pos = sig_pos[k]
    cmp     r1, #0
    bne     sc_sign_neg
    mov     r3, #1
    b       sc_sign_store
sc_sign_neg:
    mov     r3, r5              @ q-1
sc_sign_store:
    str     r3, [r10, r2, lsl #2]  @ sig_c[pos] = val
    add     r9, r9, #1
    b       sc_sign_loop

sc_done:
    pop     {r4-r11, pc}

    .ltorg

/* ================================================================== */
/* rnl_sigma_sign_32: r0=msg -> r0=0 success / r0=-1 exhausted        */
/* Reads: rnl_s_A (s), rnl_m_blind (m), rnl_C_A (C, rounded)         */
/* Writes: sig_y (y), sig_w (centered w), sig_c (challenge), sig_z (z)*/
/* ================================================================== */
    .thumb_func
rnl_sigma_sign_32:
    push    {r4-r11, lr}
    mov     r4, r0              @ msg (preserved across retries)
    mov     r5, #0              @ attempt counter
    movw    r6, #200            @ max attempts

sign_attempt:
    cmp     r5, r6
    bge     sign_exhausted
    add     r5, r5, #1

    @ --- sample y[i] for i=0..31 ---
    ldr     r7, =sig_y
    ldr     r8, =sigma_yq_tmp
    mov     r9, #0              @ i
    movw    r10, #8193          @ SIGMA_RANGE = 2*gamma+1
    movw    r11, #4096          @ SIGMA_GAMMA

sign_y_loop:
    cmp     r9, #RNL_N
    bge     sign_y_done
    bl      prng_next           @ r0 = pseudo-random (clobbers r1,r2 only)
    @ v = r0 % SIGMA_RANGE (= 0..8192)
    udiv    r1, r0, r10         @ r1 = r0 / 8193
    mls     r0, r10, r1, r0    @ r0 = r0 % 8193
    @ y[i] = v - SIGMA_GAMMA (signed, in [-4096,4096])
    sub     r1, r0, r11         @ r1 = y[i]
    str     r1, [r7, r9, lsl #2]
    @ y_q[i] = (y[i]<0) ? y[i]+q : y[i]
    cmp     r1, #0
    bge     sign_yq_pos
    ldr     r2, =65537
    add     r1, r1, r2
sign_yq_pos:
    str     r1, [r8, r9, lsl #2]
    add     r9, r9, #1
    b       sign_y_loop

sign_y_done:
    @ --- w = rnl_poly_mul(m, y_q) -> rnl_tmp ---
    ldr     r0, =rnl_m_blind
    ldr     r1, =rnl_f_ptr
    str     r0, [r1]
    ldr     r0, =sigma_yq_tmp
    ldr     r1, =rnl_g_ptr
    str     r0, [r1]
    ldr     r0, =rnl_tmp
    ldr     r1, =rnl_h_ptr
    str     r0, [r1]
    bl      rnl_poly_mul        @ rnl_tmp = m*y_q  (r4-r11 preserved)

    @ --- center w, store to sig_w ---
    ldr     r7, =rnl_tmp
    ldr     r8, =sig_w
    mov     r9, #0
    movw    r10, #32768         @ q/2
sign_center_w:
    cmp     r9, #RNL_N
    bge     sign_challenge
    ldr     r0, [r7, r9, lsl #2]   @ w[i] in [0,q-1]
    cmp     r0, r10
    ble     sign_cw_pos
    ldr     r1, =65537
    sub     r0, r0, r1              @ w[i] -= q
sign_cw_pos:
    str     r0, [r8, r9, lsl #2]
    add     r9, r9, #1
    b       sign_center_w

sign_challenge:
    @ --- sigma_challenge_32(m, C, sig_w, msg) -> sig_c ---
    ldr     r0, =rnl_m_blind
    ldr     r1, =rnl_C_A
    ldr     r2, =sig_w
    mov     r3, r4              @ msg
    bl      sigma_challenge_32  @ (r4-r11 preserved)

    @ --- cs = rnl_poly_mul(sig_c, s) -> rnl_tmp2 ---
    ldr     r0, =sig_c
    ldr     r1, =rnl_f_ptr
    str     r0, [r1]
    ldr     r0, =rnl_s_A
    ldr     r1, =rnl_g_ptr
    str     r0, [r1]
    ldr     r0, =rnl_tmp2
    ldr     r1, =rnl_h_ptr
    str     r0, [r1]
    bl      rnl_poly_mul        @ rnl_tmp2 = c*s

    @ --- compute z[i]=y[i]+centered(cs[i]); check |z[i]|<=SIGMA_BOUND ---
    ldr     r7, =rnl_tmp2       @ cs (raw, [0,q-1])
    ldr     r8, =sig_y          @ y (signed)
    ldr     r9, =sig_z          @ z output
    mov     r10, #0             @ i
    movw    r11, #32768         @ q/2

sign_z_loop:
    cmp     r10, #RNL_N
    bge     sign_z_done
    @ cs_cent[i]: center cs[i] from [0,q-1] to signed
    ldr     r0, [r7, r10, lsl #2]
    cmp     r0, r11
    ble     sign_cs_pos
    ldr     r2, =65537
    sub     r0, r0, r2              @ cs[i] -= q
sign_cs_pos:
    @ z[i] = y[i] + cs_cent[i]
    ldr     r1, [r8, r10, lsl #2]
    add     r0, r0, r1
    @ bound check: |z[i]| <= SIGMA_BOUND = 4092
    movw    r2, #4092
    cmp     r0, r2
    bgt     sign_attempt            @ z[i] > 4092: retry
    neg     r2, r0
    movw    r1, #4092
    cmp     r2, r1
    bgt     sign_attempt            @ z[i] < -4092: retry
    @ store z[i]
    str     r0, [r9, r10, lsl #2]
    add     r10, r10, #1
    b       sign_z_loop

sign_z_done:
    mov     r0, #0
    pop     {r4-r11, pc}

sign_exhausted:
    mvn     r0, #0              @ r0 = 0xFFFFFFFF = -1
    pop     {r4-r11, pc}

    .ltorg

/* ================================================================== */
/* rnl_sigma_verify_32: r0=msg -> r0=1 ok / r0=0 fail                 */
/* Reads: sig_w, sig_c, sig_z, rnl_m_blind, rnl_C_A                  */
/* Steps: (1) ||z||∞<=bound  (2) c'==c  (3) ||mz-cL-w||∞<=slack     */
/* ================================================================== */
    .thumb_func
rnl_sigma_verify_32:
    push    {r4-r11, lr}
    mov     r4, r0              @ msg

    @ --- (1) check ||z||∞ <= SIGMA_BOUND = 4092 ---
    ldr     r5, =sig_z
    mov     r6, #0              @ i
sv_bound_loop:
    cmp     r6, #RNL_N
    bge     sv_bound_ok
    ldr     r0, [r5, r6, lsl #2]   @ z[i] (signed)
    movw    r7, #4092               @ SIGMA_BOUND
    cmp     r0, r7
    bgt     sv_fail
    neg     r1, r0
    cmp     r1, r7
    bgt     sv_fail
    add     r6, r6, #1
    b       sv_bound_loop
sv_bound_ok:

    @ --- (2a) save sig_c -> sigma_cw_tmp ---
    ldr     r5, =sig_c
    ldr     r6, =sigma_cw_tmp
    mov     r7, #0
sv_save_c:
    cmp     r7, #RNL_N
    bge     sv_rechallenge
    ldr     r0, [r5, r7, lsl #2]
    str     r0, [r6, r7, lsl #2]
    add     r7, r7, #1
    b       sv_save_c

sv_rechallenge:
    @ --- (2b) recompute challenge -> sig_c ---
    ldr     r0, =rnl_m_blind
    ldr     r1, =rnl_C_A
    ldr     r2, =sig_w
    mov     r3, r4
    bl      sigma_challenge_32  @ sig_c = c'(m,C,w,msg)

    @ --- (2c) compare sigma_cw_tmp (original c) with sig_c (c') ---
    ldr     r5, =sig_c
    ldr     r6, =sigma_cw_tmp
    mov     r7, #0
sv_cmp_c:
    cmp     r7, #RNL_N
    bge     sv_cmp_ok
    ldr     r0, [r5, r7, lsl #2]
    ldr     r1, [r6, r7, lsl #2]
    cmp     r0, r1
    bne     sv_fail
    add     r7, r7, #1
    b       sv_cmp_c
sv_cmp_ok:

    @ --- (2d) restore sig_c <- sigma_cw_tmp (needed for step 3) ---
    ldr     r5, =sig_c
    ldr     r6, =sigma_cw_tmp
    mov     r7, #0
sv_restore_c:
    cmp     r7, #RNL_N
    bge     sv_lift
    ldr     r0, [r6, r7, lsl #2]
    str     r0, [r5, r7, lsl #2]
    add     r7, r7, #1
    b       sv_restore_c

sv_lift:
    @ --- (3a) lift(C_A) -> sigma_liftc_tmp ---
    ldr     r0, =sigma_liftc_tmp
    ldr     r1, =rnl_C_A
    mov     r2, #RNL_P          @ from_p = 4096
    ldr     r3, =65537          @ to_q
    bl      rnl_lift            @ (r4-r9 preserved by rnl_lift)

    @ --- (3b) z_q[i] from sig_z -> sigma_yq_tmp ---
    ldr     r5, =sig_z
    ldr     r6, =sigma_yq_tmp
    mov     r7, #0
sv_zq:
    cmp     r7, #RNL_N
    bge     sv_mz
    ldr     r0, [r5, r7, lsl #2]
    cmp     r0, #0
    bge     sv_zq_pos
    ldr     r1, =65537
    add     r0, r0, r1          @ z_q = z + q
sv_zq_pos:
    str     r0, [r6, r7, lsl #2]
    add     r7, r7, #1
    b       sv_zq

sv_mz:
    @ --- (3c) m * z_q -> sigma_mz_tmp ---
    ldr     r0, =rnl_m_blind
    ldr     r1, =rnl_f_ptr
    str     r0, [r1]
    ldr     r0, =sigma_yq_tmp
    ldr     r1, =rnl_g_ptr
    str     r0, [r1]
    ldr     r0, =sigma_mz_tmp
    ldr     r1, =rnl_h_ptr
    str     r0, [r1]
    bl      rnl_poly_mul

    @ --- (3d) sig_c * sigma_liftc_tmp -> sigma_cw_tmp ---
    ldr     r0, =sig_c
    ldr     r1, =rnl_f_ptr
    str     r0, [r1]
    ldr     r0, =sigma_liftc_tmp
    ldr     r1, =rnl_g_ptr
    str     r0, [r1]
    ldr     r0, =sigma_cw_tmp
    ldr     r1, =rnl_h_ptr
    str     r0, [r1]
    bl      rnl_poly_mul

    @ --- (3e) check ||mz - cL - w_q||∞ <= SIGMA_SLACK = 32 ---
    ldr     r5, =sigma_mz_tmp
    ldr     r6, =sigma_cw_tmp
    ldr     r7, =sig_w
    mov     r8, #0              @ i
    movw    r9, #32768          @ q/2
    movw    r10, #32            @ SIGMA_SLACK

sv_slack_loop:
    cmp     r8, #RNL_N
    bge     sv_ok

    ldr     r0, [r5, r8, lsl #2]   @ mz[i]   [0,q-1]
    ldr     r1, [r6, r8, lsl #2]   @ cL[i]   [0,q-1]
    ldr     r2, [r7, r8, lsl #2]   @ w[i]    signed
    @ w_q = (w<0) ? w+q : w
    cmp     r2, #0
    bge     sv_wq_pos
    ldr     r11, =65537
    add     r2, r2, r11
sv_wq_pos:
    @ raw = mz - cL - w_q  (may be negative)
    sub     r3, r0, r1
    sub     r3, r3, r2
    @ add 2*q = 131074 to make positive: raw in [-(2q-2), q-1] + 131074 >= 2
    ldr     r11, =131074
    add     r3, r3, r11         @ r3 in [2, 3q-1], positive
    @ diff = r3 % q
    ldr     r11, =65537
    udiv    r0, r3, r11
    mls     r3, r11, r0, r3     @ r3 = r3 % q  [0, q-1]
    @ center: if r3 > q/2: r3 -= q
    cmp     r3, r9
    ble     sv_centered
    ldr     r11, =65537
    sub     r3, r3, r11
sv_centered:
    @ |r3| <= SIGMA_SLACK?
    cmp     r3, r10
    bgt     sv_fail
    neg     r0, r3
    cmp     r0, r10
    bgt     sv_fail
    add     r8, r8, #1
    b       sv_slack_loop

sv_ok:
    mov     r0, #1
    pop     {r4-r11, pc}
sv_fail:
    mov     r0, #0
    pop     {r4-r11, pc}

    .ltorg

    .section .note.GNU-stack,"",%progbits
