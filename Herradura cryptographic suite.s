/*  Herradura Cryptographic Suite v1.5.10
    ARM 32-bit Thumb Assembly (GAS) — HKEX-GF, HSKE, HPKS, HPKE,
                                       HSKE-NL-A1/A2, HKEX-RNL, HPKS-NL, HPKE-NL
    KEYBITS = 32, I_VALUE = 8, R_VALUE = 24
    HKEX-GF:   DH over GF(2^32)*, poly x^32+x^22+x^2+x+1, generator g=3
    HPKS:      Schnorr; s=(k-a*e) mod ORD; verify g^s*C^e==R
    HPKE:      El Gamal + fscx_revolve; enc_key=C^r; dec_key=R^a
    NL-FSCX v2: nl_v2(A,B) = fscx(A,B) + ROL32(B*((B+1)>>1), 8)  mod 2^32
                inv: B XOR M^{-1}((Y-delta(B)) mod 2^32)
    HKEX-RNL:  Ring-LWR; N=32, q=65537, p=4096, pp=2

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
    .equ RNL_N,    32
    .equ RNL_Q,    65537
    .equ RNL_P,    4096
    .equ RNL_PP,   2

/* ------------------------------------------------------------------ */
/* .data section                                                       */
/* ------------------------------------------------------------------ */
    .data
    .balign 4

/* format strings */
fmt_header: .asciz "=== Herradura Cryptographic Suite v1.5.10 (ARM 32-bit Thumb, KEYBITS=32) ===\n"
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

    .balign 4
/* fixed test vectors */
val_a_priv:  .word 0xDEADBEEF
val_b_priv:  .word 0xCAFEBABF
val_key:     .word 0x5A5A5A5A
val_plain:   .word 0xDEADC0DE

/* LCG PRNG */
lcg_state:   .word 0xDEADBEEE
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
val_sk_rnl:  .word 0
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

/* ------------------------------------------------------------------ */
/* .text                                                               */
/* ------------------------------------------------------------------ */
    .text
    .global main
    .thumb_func

main:
    push    {r4-r11, lr}

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
       N = prng_next(); base = key XOR N; ks = nl_fscx_revolve_v1(base, base, I_VALUE)
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
    mov     r1, r0                  @ r1 = base (counter=0: B = base)
    mov     r2, #I_VALUE
    bl      nl_fscx_revolve_v1      @ r0 = ks
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
       E = nl_fscx_revolve_v2(plain, key, I_VALUE)
       D = nl_fscx_revolve_v2_inv(E, key, I_VALUE)  must == plain
       ================================================================ */
    ldr     r0, =fmt_hske_nl2_hdr
    bl      printf

    ldr     r0, =val_plain
    ldr     r0, [r0]
    ldr     r1, =val_key
    ldr     r1, [r1]
    mov     r2, #I_VALUE
    bl      nl_fscx_revolve_v2
    ldr     r3, =val_E_nl2
    str     r0, [r3]

    ldr     r0, =val_E_nl2
    ldr     r0, [r0]
    ldr     r1, =val_key
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
    bl      rnl_agree
    ldr     r3, =val_KA
    str     r0, [r3]

    ldr     r0, =rnl_s_B
    ldr     r1, =rnl_C_A
    bl      rnl_agree
    ldr     r3, =val_KB
    str     r0, [r3]

    ldr     r0, =val_KA
    ldr     r0, [r0]
    ror     r0, r0, #28         @ seed = ROL32(KA, 4)  [n/8 = 32/8 = 4]
    ldr     r1, =val_KA
    ldr     r1, [r1]
    mov     r2, #I_VALUE
    bl      nl_fscx_revolve_v1  @ r0 = mid
    ldr     r1, =val_KA
    ldr     r1, [r1]            @ reload B = KA
    mov     r2, #I_VALUE
    bl      nl_fscx_revolve_v2  @ r0 = sk
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
/* rnl_bits32: r0=poly -> r0=uint32 (bit i = poly[i] >= PP/2=1)       */
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
/* rnl_agree: r0=s, r1=C_other -> r0=uint32 key                       */
/* ------------------------------------------------------------------ */
    .thumb_func
rnl_agree:
    push    {r4-r6, lr}
    mov     r4, r0
    mov     r5, r1

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
    bl      rnl_poly_mul

    ldr     r0, =rnl_tmp
    ldr     r1, =rnl_tmp2
    ldr     r2, =RNL_Q
    ldr     r3, =RNL_PP
    bl      rnl_round

    ldr     r0, =rnl_tmp
    bl      rnl_bits32

    pop     {r4-r6, pc}

    .ltorg

    .section .note.GNU-stack,"",%progbits
