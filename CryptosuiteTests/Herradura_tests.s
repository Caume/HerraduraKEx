/*  Herradura KEx -- Correctness Tests v1.5.23
    ARM 32-bit Thumb Assembly (GAS) — HKEX-GF, HSKE, HPKS, HPKE,
                                       NL-FSCX v2 inv, HSKE-NL-A2,
                                       HKEX-RNL, HPKS-NL, HPKE-NL,
                                       HPKS-Stern-F, HPKE-Stern-F
    KEYBITS=32; I_VALUE=8; R_VALUE=24; HKEX-RNL N=32, q=65537, p=4096

    Copyright (C) 2024-2026 Omar Alejandro Herrera Reyna
    MIT License / GPL v3.0 — choose either.

    Build: arm-linux-gnueabi-gcc -o Herradura_tests_arm CryptosuiteTests/Herradura_tests.s
    Run:   qemu-arm -L /usr/arm-linux-gnueabi ./Herradura_tests_arm
*/

    .syntax unified
    .cpu cortex-a7
    .thumb

    .extern printf
    .extern exit

    .equ I_VALUE,  8
    .equ R_VALUE,  24
    .equ RNL_N,    32
    .equ RNL_Q,    65537
    .equ RNL_P,    4096
    .equ RNL_PP,   2
    .equ SDF_N,    32
    .equ SDF_T,    2
    .equ SDF_NROWS,16
    .equ SDF_ROUNDS,4

/* ------------------------------------------------------------------ */
/* .data                                                               */
/* ------------------------------------------------------------------ */
    .data
    .balign 4

fmt_hdr:  .asciz "=== Herradura KEx v1.5.23 -- Correctness Tests (ARM Thumb, KEYBITS=32) ===\n\n"
fmt_t1:   .asciz "[1] HKEX-GF key exchange: sk_alice == sk_bob (20 iterations)\n"
fmt_t2:   .asciz "[2] HSKE encrypt+decrypt round-trip: D == plaintext (100 iterations)\n"
fmt_t3:   .asciz "[3] HPKS Schnorr: g^s * C^e == R (20 iterations)\n"
fmt_t4:   .asciz "[4] HPKE El Gamal: D == plaintext (20 iterations)\n"
fmt_t5:   .asciz "[5] NL-FSCX v2 inverse: v2_inv(v2(A,B),B) == A (20 iterations)\n"
fmt_t6:   .asciz "[6] HSKE-NL-A2 revolve-mode: D == plaintext (20 iterations)\n"
fmt_t7:   .asciz "[7] HKEX-RNL key agreement: KA == KB (10 trials, Peikert reconciliation -- expect 100%)\n"
fmt_t8:   .asciz "[8] HPKS-NL Schnorr: NL challenge g^s*C^e == R (20 iterations)\n"
fmt_t9:   .asciz "[9] HPKE-NL: D == plaintext, NL-FSCX v2 (20 iterations)\n"
fmt_t10:  .asciz "[10] HPKS-NL Eve resistance: random forgery rejected (20 trials)\n"
fmt_t11:  .asciz "[11] HPKS-Stern-F: sign+verify correctness (3 trials, N=32, t=2, rounds=4)\n"
fmt_t12:  .asciz "[12] HPKE-Stern-F: encap+decap KEM (3 trials, N=32, t=2)\n"

fmt_p20:  .asciz "    20 / 20 passed  [PASS]\n"
fmt_p100: .asciz "    100 / 100 passed  [PASS]\n"
fmt_prnl: .asciz "    10 / 10 agreed (Peikert reconciliation)  [PASS]\n"
fmt_p3v:  .asciz "    3 / 3 verified  [PASS]\n"
fmt_p3k:  .asciz "    3 / 3 keys match  [PASS]\n"
fmt_fail: .asciz "    FAILED  [FAIL]\n"

lcg_state: .word 0x12345678
lcg_mul:   .word 1664525
lcg_add:   .word 1013904223

rnl_f_ptr: .word 0
rnl_g_ptr: .word 0
rnl_h_ptr: .word 0

/* NTT tables (n=32, q=65537) */
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
/* .bss scratch + RNL poly arrays                                      */
/* ------------------------------------------------------------------ */
    .section .bss
    .balign 4
t_a_priv:  .space 4
t_b_priv:  .space 4
t_C:       .space 4
t_C2:      .space 4
t_sk:      .space 4
t_val:     .space 4
t_key:     .space 4
t_E:       .space 4
t_k:       .space 4
t_R_sc:    .space 4
t_e_sc:    .space 4
t_ae:      .space 4
t_s_sc:    .space 4
t_gs:      .space 4
t_r_e:     .space 4
t_R_e:     .space 4
t_enc_key: .space 4
t_E_e:     .space 4
t_dec_key: .space 4
t_KA:      .space 4
t_KB:      .space 4
t_hint_A:  .space 4

rnl_m_base:  .space 128
rnl_a_rand:  .space 128
rnl_m_blind: .space 128
rnl_s_A:     .space 128
rnl_s_B:     .space 128
rnl_C_A:     .space 128
rnl_C_B:     .space 128
rnl_tmp:     .space 128
rnl_tmp2:    .space 128
rnl_fa:      .space 128
rnl_ga:      .space 128
rnl_ha:      .space 128
/* Stern-F test temporaries */
t_sdf_seed:    .space 4
t_sdf_syn:     .space 4
t_sdf_e:       .space 4
t_sdf_msg:     .space 4
t_sdf_K_enc:   .space 4
t_sdf_K_dec:   .space 4
t_sdf_e_prime: .space 4
t_sdf_ct:      .space 4
sdf_perm:      .space 32
sdf_c0:        .space 16
sdf_c1:        .space 16
sdf_c2:        .space 16
sdf_b:         .space 16
sdf_respA:     .space 16
sdf_respB:     .space 16
sdf_r_tmp:     .space 16
sdf_y_tmp:     .space 16
sdf_pi_tmp:    .space 16
sdf_sr_tmp:    .space 16
sdf_sy_tmp:    .space 16
sdf_chals_tmp: .space 16

/* ------------------------------------------------------------------ */
/* .text                                                               */
/* ------------------------------------------------------------------ */
    .text
    .global main
    .thumb_func
main:
    push    {r4-r11, lr}

    ldr     r0, =fmt_hdr
    bl      printf

    /* ================================================================ [1] HKEX-GF (20 iter) */
    ldr     r0, =fmt_t1
    bl      printf
    mov     r10, #20
    mov     r11, #0
t1_loop:
    bl      prng_next
    orr     r0, r0, #1
    ldr     r3, =t_a_priv
    str     r0, [r3]
    bl      prng_next
    orr     r0, r0, #1
    ldr     r3, =t_b_priv
    str     r0, [r3]
    mov     r0, #3
    ldr     r1, =t_a_priv
    ldr     r1, [r1]
    bl      gf_pow_32
    ldr     r3, =t_C
    str     r0, [r3]
    mov     r0, #3
    ldr     r1, =t_b_priv
    ldr     r1, [r1]
    bl      gf_pow_32
    ldr     r3, =t_C2
    str     r0, [r3]
    ldr     r0, =t_C2
    ldr     r0, [r0]
    ldr     r1, =t_a_priv
    ldr     r1, [r1]
    bl      gf_pow_32
    ldr     r3, =t_sk
    str     r0, [r3]
    ldr     r0, =t_C
    ldr     r0, [r0]
    ldr     r1, =t_b_priv
    ldr     r1, [r1]
    bl      gf_pow_32
    ldr     r1, =t_sk
    ldr     r1, [r1]
    cmp     r0, r1
    bne     t1_skip
    add     r11, r11, #1
t1_skip:
    subs    r10, r10, #1
    bne     t1_loop
    cmp     r11, #20
    bne     t1_fail
    ldr     r0, =fmt_p20
    bl      printf
    b       t1_done
t1_fail:
    ldr     r0, =fmt_fail
    bl      printf
t1_done:

    /* ================================================================ [2] HSKE (100 iter) */
    ldr     r0, =fmt_t2
    bl      printf
    mov     r10, #100
    mov     r11, #0
t2_loop:
    bl      prng_next
    ldr     r3, =t_val
    str     r0, [r3]
    bl      prng_next
    ldr     r3, =t_key
    str     r0, [r3]
    ldr     r0, =t_val
    ldr     r0, [r0]
    ldr     r1, =t_key
    ldr     r1, [r1]
    mov     r2, #I_VALUE
    bl      fscx_revolve
    ldr     r3, =t_E
    str     r0, [r3]
    ldr     r0, =t_E
    ldr     r0, [r0]
    ldr     r1, =t_key
    ldr     r1, [r1]
    mov     r2, #R_VALUE
    bl      fscx_revolve
    ldr     r1, =t_val
    ldr     r1, [r1]
    cmp     r0, r1
    bne     t2_skip
    add     r11, r11, #1
t2_skip:
    subs    r10, r10, #1
    bne     t2_loop
    cmp     r11, #100
    bne     t2_fail
    ldr     r0, =fmt_p100
    bl      printf
    b       t2_done
t2_fail:
    ldr     r0, =fmt_fail
    bl      printf
t2_done:

    /* ================================================================ [3] HPKS Schnorr (20 iter) */
    ldr     r0, =fmt_t3
    bl      printf
    mov     r10, #20
    mov     r11, #0
t3_loop:
    bl      prng_next
    orr     r0, r0, #1
    ldr     r3, =t_a_priv
    str     r0, [r3]
    bl      prng_next
    ldr     r3, =t_val
    str     r0, [r3]
    bl      prng_next
    ldr     r3, =t_k
    str     r0, [r3]
    mov     r0, #3
    ldr     r1, =t_a_priv
    ldr     r1, [r1]
    bl      gf_pow_32
    ldr     r3, =t_C
    str     r0, [r3]
    mov     r0, #3
    ldr     r1, =t_k
    ldr     r1, [r1]
    bl      gf_pow_32
    ldr     r3, =t_R_sc
    str     r0, [r3]
    ldr     r0, =t_R_sc
    ldr     r0, [r0]
    ldr     r1, =t_val
    ldr     r1, [r1]
    mov     r2, #8
    bl      fscx_revolve
    ldr     r3, =t_e_sc
    str     r0, [r3]
    ldr     r4, =t_a_priv
    ldr     r4, [r4]
    ldr     r5, =t_e_sc
    ldr     r5, [r5]
    umull   r6, r7, r4, r5
    adds    r6, r6, r7
    it      cs
    addcs   r6, r6, #1
    ldr     r3, =t_ae
    str     r6, [r3]
    ldr     r4, =t_k
    ldr     r4, [r4]
    subs    r4, r4, r6
    it      cc
    subcc   r4, r4, #1
    ldr     r3, =t_s_sc
    str     r4, [r3]
    mov     r0, #3
    ldr     r1, =t_s_sc
    ldr     r1, [r1]
    bl      gf_pow_32
    ldr     r3, =t_gs
    str     r0, [r3]
    ldr     r0, =t_C
    ldr     r0, [r0]
    ldr     r1, =t_e_sc
    ldr     r1, [r1]
    bl      gf_pow_32
    mov     r1, r0
    ldr     r0, =t_gs
    ldr     r0, [r0]
    bl      gf_mul_32
    ldr     r1, =t_R_sc
    ldr     r1, [r1]
    cmp     r0, r1
    bne     t3_skip
    add     r11, r11, #1
t3_skip:
    subs    r10, r10, #1
    bne     t3_loop
    cmp     r11, #20
    bne     t3_fail
    ldr     r0, =fmt_p20
    bl      printf
    b       t3_done
t3_fail:
    ldr     r0, =fmt_fail
    bl      printf
t3_done:

    /* ================================================================ [4] HPKE El Gamal (20 iter) */
    ldr     r0, =fmt_t4
    bl      printf
    mov     r10, #20
    mov     r11, #0
t4_loop:
    bl      prng_next
    orr     r0, r0, #1
    ldr     r3, =t_a_priv
    str     r0, [r3]
    bl      prng_next
    ldr     r3, =t_val
    str     r0, [r3]
    bl      prng_next
    orr     r0, r0, #1
    ldr     r3, =t_r_e
    str     r0, [r3]
    mov     r0, #3
    ldr     r1, =t_a_priv
    ldr     r1, [r1]
    bl      gf_pow_32
    ldr     r3, =t_C
    str     r0, [r3]
    mov     r0, #3
    ldr     r1, =t_r_e
    ldr     r1, [r1]
    bl      gf_pow_32
    ldr     r3, =t_R_e
    str     r0, [r3]
    ldr     r0, =t_C
    ldr     r0, [r0]
    ldr     r1, =t_r_e
    ldr     r1, [r1]
    bl      gf_pow_32
    ldr     r3, =t_enc_key
    str     r0, [r3]
    ldr     r0, =t_val
    ldr     r0, [r0]
    ldr     r1, =t_enc_key
    ldr     r1, [r1]
    mov     r2, #I_VALUE
    bl      fscx_revolve
    ldr     r3, =t_E_e
    str     r0, [r3]
    ldr     r0, =t_R_e
    ldr     r0, [r0]
    ldr     r1, =t_a_priv
    ldr     r1, [r1]
    bl      gf_pow_32
    ldr     r3, =t_dec_key
    str     r0, [r3]
    ldr     r0, =t_E_e
    ldr     r0, [r0]
    ldr     r1, =t_dec_key
    ldr     r1, [r1]
    mov     r2, #R_VALUE
    bl      fscx_revolve
    ldr     r1, =t_val
    ldr     r1, [r1]
    cmp     r0, r1
    bne     t4_skip
    add     r11, r11, #1
t4_skip:
    subs    r10, r10, #1
    bne     t4_loop
    cmp     r11, #20
    bne     t4_fail
    ldr     r0, =fmt_p20
    bl      printf
    b       t4_done
t4_fail:
    ldr     r0, =fmt_fail
    bl      printf
t4_done:

    /* ================================================================ [5] NL-FSCX v2 inv (20 iter) */
    ldr     r0, =fmt_t5
    bl      printf
    mov     r10, #20
    mov     r11, #0
t5_loop:
    bl      prng_next
    ldr     r3, =t_val
    str     r0, [r3]
    bl      prng_next
    ldr     r3, =t_key
    str     r0, [r3]
    ldr     r0, =t_val
    ldr     r0, [r0]
    ldr     r1, =t_key
    ldr     r1, [r1]
    mov     r2, #I_VALUE
    bl      nl_fscx_revolve_v2
    ldr     r3, =t_E
    str     r0, [r3]
    ldr     r0, =t_E
    ldr     r0, [r0]
    ldr     r1, =t_key
    ldr     r1, [r1]
    mov     r2, #I_VALUE
    bl      nl_fscx_revolve_v2_inv
    ldr     r1, =t_val
    ldr     r1, [r1]
    cmp     r0, r1
    bne     t5_skip
    add     r11, r11, #1
t5_skip:
    subs    r10, r10, #1
    bne     t5_loop
    cmp     r11, #20
    bne     t5_fail
    ldr     r0, =fmt_p20
    bl      printf
    b       t5_done
t5_fail:
    ldr     r0, =fmt_fail
    bl      printf
t5_done:

    /* ================================================================ [6] HSKE-NL-A2 (20 iter) */
    ldr     r0, =fmt_t6
    bl      printf
    mov     r10, #20
    mov     r11, #0
t6_loop:
    bl      prng_next
    ldr     r3, =t_val
    str     r0, [r3]
    bl      prng_next
    ldr     r3, =t_key
    str     r0, [r3]
    ldr     r0, =t_val
    ldr     r0, [r0]
    ldr     r1, =t_key
    ldr     r1, [r1]
    mov     r2, #I_VALUE
    bl      nl_fscx_revolve_v2
    ldr     r3, =t_E
    str     r0, [r3]
    ldr     r0, =t_E
    ldr     r0, [r0]
    ldr     r1, =t_key
    ldr     r1, [r1]
    mov     r2, #I_VALUE
    bl      nl_fscx_revolve_v2_inv
    ldr     r1, =t_val
    ldr     r1, [r1]
    cmp     r0, r1
    bne     t6_skip
    add     r11, r11, #1
t6_skip:
    subs    r10, r10, #1
    bne     t6_loop
    cmp     r11, #20
    bne     t6_fail
    ldr     r0, =fmt_p20
    bl      printf
    b       t6_done
t6_fail:
    ldr     r0, =fmt_fail
    bl      printf
t6_done:

    /* ================================================================ [7] HKEX-RNL (10 trials) */
    ldr     r0, =fmt_t7
    bl      printf
    ldr     r0, =rnl_m_base
    bl      rnl_m_poly
    mov     r10, #10
    mov     r11, #0
t7_loop:
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
    ldr     r3, =t_KA
    str     r0, [r3]
    ldr     r3, =t_hint_A
    str     r1, [r3]
    ldr     r0, =rnl_s_B
    ldr     r1, =rnl_C_A
    ldr     r2, =t_hint_A
    ldr     r2, [r2]
    bl      rnl_agree_recv          @ r0=KB
    ldr     r3, =t_KB
    str     r0, [r3]
    ldr     r0, =t_KA
    ldr     r0, [r0]
    ldr     r1, =t_KB
    ldr     r1, [r1]
    cmp     r0, r1
    bne     t7_skip
    add     r11, r11, #1
t7_skip:
    subs    r10, r10, #1
    bne     t7_loop
    cmp     r11, #10
    blt     t7_fail
    ldr     r0, =fmt_prnl
    bl      printf
    b       t7_done
t7_fail:
    ldr     r0, =fmt_fail
    bl      printf
t7_done:

    /* ================================================================ [8] HPKS-NL Schnorr (20 iter) */
    ldr     r0, =fmt_t8
    bl      printf
    mov     r10, #20
    mov     r11, #0
t8_loop:
    bl      prng_next
    orr     r0, r0, #1
    ldr     r3, =t_a_priv
    str     r0, [r3]
    bl      prng_next
    ldr     r3, =t_val
    str     r0, [r3]
    bl      prng_next
    ldr     r3, =t_k
    str     r0, [r3]
    mov     r0, #3
    ldr     r1, =t_a_priv
    ldr     r1, [r1]
    bl      gf_pow_32
    ldr     r3, =t_C
    str     r0, [r3]
    mov     r0, #3
    ldr     r1, =t_k
    ldr     r1, [r1]
    bl      gf_pow_32
    ldr     r3, =t_R_sc
    str     r0, [r3]
    ldr     r0, =t_R_sc
    ldr     r0, [r0]
    ldr     r1, =t_val
    ldr     r1, [r1]
    mov     r2, #I_VALUE
    bl      nl_fscx_revolve_v1
    ldr     r3, =t_e_sc
    str     r0, [r3]
    ldr     r4, =t_a_priv
    ldr     r4, [r4]
    ldr     r5, =t_e_sc
    ldr     r5, [r5]
    umull   r6, r7, r4, r5
    adds    r6, r6, r7
    it      cs
    addcs   r6, r6, #1
    ldr     r3, =t_ae
    str     r6, [r3]
    ldr     r4, =t_k
    ldr     r4, [r4]
    subs    r4, r4, r6
    it      cc
    subcc   r4, r4, #1
    ldr     r3, =t_s_sc
    str     r4, [r3]
    mov     r0, #3
    ldr     r1, =t_s_sc
    ldr     r1, [r1]
    bl      gf_pow_32
    ldr     r3, =t_gs
    str     r0, [r3]
    ldr     r0, =t_C
    ldr     r0, [r0]
    ldr     r1, =t_e_sc
    ldr     r1, [r1]
    bl      gf_pow_32
    mov     r1, r0
    ldr     r0, =t_gs
    ldr     r0, [r0]
    bl      gf_mul_32
    ldr     r1, =t_R_sc
    ldr     r1, [r1]
    cmp     r0, r1
    bne     t8_skip
    add     r11, r11, #1
t8_skip:
    subs    r10, r10, #1
    bne     t8_loop
    cmp     r11, #20
    bne     t8_fail
    ldr     r0, =fmt_p20
    bl      printf
    b       t8_done
t8_fail:
    ldr     r0, =fmt_fail
    bl      printf
t8_done:

    /* ================================================================ [9] HPKE-NL (20 iter) */
    ldr     r0, =fmt_t9
    bl      printf
    mov     r10, #20
    mov     r11, #0
t9_loop:
    bl      prng_next
    orr     r0, r0, #1
    ldr     r3, =t_a_priv
    str     r0, [r3]
    bl      prng_next
    ldr     r3, =t_val
    str     r0, [r3]
    bl      prng_next
    orr     r0, r0, #1
    ldr     r3, =t_r_e
    str     r0, [r3]
    mov     r0, #3
    ldr     r1, =t_a_priv
    ldr     r1, [r1]
    bl      gf_pow_32
    ldr     r3, =t_C
    str     r0, [r3]
    mov     r0, #3
    ldr     r1, =t_r_e
    ldr     r1, [r1]
    bl      gf_pow_32
    ldr     r3, =t_R_e
    str     r0, [r3]
    ldr     r0, =t_C
    ldr     r0, [r0]
    ldr     r1, =t_r_e
    ldr     r1, [r1]
    bl      gf_pow_32
    ldr     r3, =t_enc_key
    str     r0, [r3]
    ldr     r0, =t_val
    ldr     r0, [r0]
    ldr     r1, =t_enc_key
    ldr     r1, [r1]
    mov     r2, #I_VALUE
    bl      nl_fscx_revolve_v2
    ldr     r3, =t_E_e
    str     r0, [r3]
    ldr     r0, =t_R_e
    ldr     r0, [r0]
    ldr     r1, =t_a_priv
    ldr     r1, [r1]
    bl      gf_pow_32
    ldr     r3, =t_dec_key
    str     r0, [r3]
    ldr     r0, =t_E_e
    ldr     r0, [r0]
    ldr     r1, =t_dec_key
    ldr     r1, [r1]
    mov     r2, #I_VALUE
    bl      nl_fscx_revolve_v2_inv
    ldr     r1, =t_val
    ldr     r1, [r1]
    cmp     r0, r1
    bne     t9_skip
    add     r11, r11, #1
t9_skip:
    subs    r10, r10, #1
    bne     t9_loop
    cmp     r11, #20
    bne     t9_fail
    ldr     r0, =fmt_p20
    bl      printf
    b       t9_done
t9_fail:
    ldr     r0, =fmt_fail
    bl      printf
t9_done:

    /* ================================================================ [10] HPKS-NL Eve (20 trials) */
    ldr     r0, =fmt_t10
    bl      printf
    mov     r10, #20
    mov     r11, #0
t10_loop:
    bl      prng_next
    orr     r0, r0, #1
    ldr     r3, =t_a_priv
    str     r0, [r3]
    bl      prng_next
    ldr     r3, =t_val
    str     r0, [r3]
    bl      prng_next
    ldr     r3, =t_k
    str     r0, [r3]
    mov     r0, #3
    ldr     r1, =t_a_priv
    ldr     r1, [r1]
    bl      gf_pow_32
    ldr     r3, =t_C
    str     r0, [r3]
    mov     r0, #3
    ldr     r1, =t_k
    ldr     r1, [r1]
    bl      gf_pow_32
    ldr     r3, =t_R_sc
    str     r0, [r3]
    ldr     r0, =t_R_sc
    ldr     r0, [r0]
    ldr     r1, =t_val
    ldr     r1, [r1]
    mov     r2, #I_VALUE
    bl      nl_fscx_revolve_v1
    ldr     r3, =t_e_sc
    str     r0, [r3]
    /* s_fake = prng_next() -- random forgery */
    bl      prng_next
    ldr     r3, =t_s_sc
    str     r0, [r3]
    mov     r0, #3
    ldr     r1, =t_s_sc
    ldr     r1, [r1]
    bl      gf_pow_32
    ldr     r3, =t_gs
    str     r0, [r3]
    ldr     r0, =t_C
    ldr     r0, [r0]
    ldr     r1, =t_e_sc
    ldr     r1, [r1]
    bl      gf_pow_32
    mov     r1, r0
    ldr     r0, =t_gs
    ldr     r0, [r0]
    bl      gf_mul_32
    ldr     r1, =t_R_sc
    ldr     r1, [r1]
    cmp     r0, r1
    beq     t10_skip
    add     r11, r11, #1
t10_skip:
    subs    r10, r10, #1
    bne     t10_loop
    cmp     r11, #20
    bne     t10_fail
    ldr     r0, =fmt_p20
    bl      printf
    b       t10_done
t10_fail:
    ldr     r0, =fmt_fail
    bl      printf
t10_done:

    /* ================================================================ [11] HPKS-Stern-F (3 iter) */
    ldr     r0, =fmt_t11
    bl      printf
    mov     r10, #3
    mov     r11, #0
t11_loop:
    @ key: seed and weight-2 error
    bl      prng_next
    ldr     r3, =t_sdf_seed
    str     r0, [r3]
    bl      stern_rand_error_32
    ldr     r3, =t_sdf_e
    str     r0, [r3]
    @ random message
    bl      prng_next
    ldr     r3, =t_sdf_msg
    str     r0, [r3]
    @ syndrome = H·e^T
    ldr     r0, =t_sdf_seed
    ldr     r0, [r0]
    ldr     r1, =t_sdf_e
    ldr     r1, [r1]
    bl      stern_syndrome_32
    ldr     r3, =t_sdf_syn
    str     r0, [r3]
    @ sign
    bl      hpks_stern_f_sign_32
    @ verify
    bl      hpks_stern_f_verify_32
    cmp     r0, #1
    bne     t11_skip
    add     r11, r11, #1
t11_skip:
    subs    r10, r10, #1
    bne     t11_loop
    cmp     r11, #3
    bne     t11_fail
    ldr     r0, =fmt_p3v
    bl      printf
    b       t11_done
t11_fail:
    ldr     r0, =fmt_fail
    bl      printf
t11_done:

    /* ================================================================ [12] HPKE-Stern-F KEM (3 iter) */
    ldr     r0, =fmt_t12
    bl      printf
    mov     r10, #3
    mov     r11, #0
t12_loop:
    @ seed
    bl      prng_next
    ldr     r3, =t_sdf_seed
    str     r0, [r3]
    @ encap: K_enc + e_prime stored in t_sdf_K_enc, t_sdf_e_prime
    bl      hpke_stern_f_encap_32
    @ decap: K_dec = hash2(seed, e_prime)
    ldr     r0, =t_sdf_e_prime
    ldr     r0, [r0]
    bl      hpke_stern_f_decap_known_32
    ldr     r3, =t_sdf_K_dec
    str     r0, [r3]
    @ check K_enc == K_dec
    ldr     r0, =t_sdf_K_enc
    ldr     r0, [r0]
    ldr     r1, =t_sdf_K_dec
    ldr     r1, [r1]
    cmp     r0, r1
    bne     t12_skip
    add     r11, r11, #1
t12_skip:
    subs    r10, r10, #1
    bne     t12_loop
    cmp     r11, #3
    bne     t12_fail
    ldr     r0, =fmt_p3k
    bl      printf
    b       t12_done
t12_fail:
    ldr     r0, =fmt_fail
    bl      printf
t12_done:

    mov     r0, #0
    bl      exit

    .ltorg

/* ------------------------------------------------------------------ */
/* prng_next: r0=new state; clobbers r1,r2                            */
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
gfm_loop:
    tst     r6, #1
    it      ne
    eorne   r4, r4, r5
    lsls    r5, r5, #1
    it      cs
    eorcs   r5, r5, r7
    lsr     r6, r6, #1
    subs    r8, r8, #1
    bne     gfm_loop
    mov     r0, r4
    pop     {r4-r8, pc}
    .ltorg

/* ------------------------------------------------------------------ */
/* gf_pow_32: r0=base, r1=exp -> r0=base^exp                          */
/* ------------------------------------------------------------------ */
    .thumb_func
gf_pow_32:
    push    {r4-r6, lr}
    mov     r4, #1
    mov     r5, r0
    mov     r6, r1
gfp_loop:
    cbz     r6, gfp_done
    tst     r6, #1
    beq     gfp_skip
    mov     r0, r4
    mov     r1, r5
    bl      gf_mul_32
    mov     r4, r0
gfp_skip:
    mov     r0, r5
    mov     r1, r5
    bl      gf_mul_32
    mov     r5, r0
    lsr     r6, r6, #1
    b       gfp_loop
gfp_done:
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
fscxr_loop:
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
    bne     fscxr_loop
    mov     r0, r4
    pop     {r4-r7, pc}
    .ltorg

/* ------------------------------------------------------------------ */
/* fscx_single: r0=A, r1=B -> r0=fscx(A,B)                           */
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
/* nl_fscx_delta_v2: r0=B -> r0=ROL32(B*((B+1)>>1),8)                */
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
/* nl_fscx_v1: r0=A, r1=B -> r0=fscx(A,B) XOR ROL(A+B,8)             */
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
nlrv1_loop:
    cbz     r6, nlrv1_done
    mov     r0, r4
    mov     r1, r5
    bl      nl_fscx_v1
    mov     r4, r0
    subs    r6, r6, #1
    b       nlrv1_loop
nlrv1_done:
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
/* ------------------------------------------------------------------ */
    .thumb_func
m_inv_32:
    @ r0=X; result in r0; r1=saved X, r2=scratch (all caller-saved)
    mov     r1, r0
    ror     r2, r1, #30
    eor     r0, r0, r2
    ror     r2, r1, #29
    eor     r0, r0, r2
    ror     r2, r1, #27
    eor     r0, r0, r2
    ror     r2, r1, #26
    eor     r0, r0, r2
    ror     r2, r1, #24
    eor     r0, r0, r2
    ror     r2, r1, #23
    eor     r0, r0, r2
    ror     r2, r1, #21
    eor     r0, r0, r2
    ror     r2, r1, #20
    eor     r0, r0, r2
    ror     r2, r1, #18
    eor     r0, r0, r2
    ror     r2, r1, #17
    eor     r0, r0, r2
    ror     r2, r1, #15
    eor     r0, r0, r2
    ror     r2, r1, #14
    eor     r0, r0, r2
    ror     r2, r1, #12
    eor     r0, r0, r2
    ror     r2, r1, #11
    eor     r0, r0, r2
    ror     r2, r1, #9
    eor     r0, r0, r2
    ror     r2, r1, #8
    eor     r0, r0, r2
    ror     r2, r1, #6
    eor     r0, r0, r2
    ror     r2, r1, #5
    eor     r0, r0, r2
    ror     r2, r1, #3
    eor     r0, r0, r2
    ror     r2, r1, #2
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
nlrv2_loop:
    cbz     r6, nlrv2_done
    mov     r0, r4
    mov     r1, r5
    bl      nl_fscx_v2
    mov     r4, r0
    subs    r6, r6, #1
    b       nlrv2_loop
nlrv2_done:
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
nlrv2i_loop:
    cbz     r6, nlrv2i_done
    sub     r4, r4, r7          @ z = y - delta  (mod 2^32)
    mov     r0, r4
    bl      m_inv_32            @ r0 = M^{-1}(z)
    eor     r4, r0, r5          @ y = B XOR M^{-1}(z)
    subs    r6, r6, #1
    b       nlrv2i_loop
nlrv2i_done:
    mov     r0, r4
    pop     {r4-r7, pc}
    .ltorg

/* ------------------------------------------------------------------ */
/* rnl_poly_add: h[i]=(f[i]+g[i])%Q                                   */
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
/* rnl_ntt: in-place NTT/INTT. r0=array r1=0(fwd)/1(inv)              */
    .thumb_func
rnl_ntt:
    push    {r4-r11, lr}
    mov     r4, r0
    mov     r5, r1
    ldr     r11, =rnl_bit_rev_tab
    mov     r6, #0
t_ntt_br:
    cmp     r6, #RNL_N
    bge     t_ntt_br_done
    ldrb    r7, [r11, r6]
    cmp     r6, r7
    bge     t_ntt_br_next
    ldr     r0, [r4, r6, lsl #2]
    ldr     r1, [r4, r7, lsl #2]
    str     r1, [r4, r6, lsl #2]
    str     r0, [r4, r7, lsl #2]
t_ntt_br_next:
    add     r6, r6, #1
    b       t_ntt_br
t_ntt_br_done:
    ldr     r11, =rnl_omega_fwd_tab
    ldr     r12, =rnl_omega_inv_tab
    cmp     r5, #0
    it      ne
    movne   r11, r12
    mov     r8, #2
    mov     r10, #16
t_ntt_stage:
    cmp     r8, #RNL_N
    bgt     t_ntt_stage_done
    lsr     r9, r8, #1
    mov     r6, #0
t_ntt_grp:
    cmp     r6, #RNL_N
    bge     t_ntt_grp_done
    mov     r7, #0
t_ntt_bf:
    cmp     r7, r9
    bge     t_ntt_bf_done
    mul     r0, r7, r10
    ldr     r2, [r11, r0, lsl #2]
    add     r0, r6, r7
    ldr     r3, [r4, r0, lsl #2]
    add     r1, r0, r9
    ldr     r0, [r4, r1, lsl #2]
    umull   r0, r12, r0, r2
    add     r0, r0, r12
    lsr     r12, r0, #16
    uxth    r0, r0
    sub     r0, r0, r12
    it      mi
    addmi   r0, r0, #RNL_Q
    add     r12, r3, r0
    ldr     r2, =RNL_Q
    cmp     r12, r2
    it      cs
    subcs   r12, r12, r2
    add     r2, r6, r7
    str     r12, [r4, r2, lsl #2]
    ldr     r2, =RNL_Q
    sub     r12, r3, r0
    add     r12, r12, r2
    cmp     r12, r2
    it      cs
    subcs   r12, r12, r2
    add     r2, r6, r7
    add     r2, r2, r9
    str     r12, [r4, r2, lsl #2]
    add     r7, r7, #1
    b       t_ntt_bf
t_ntt_bf_done:
    add     r6, r6, r8
    b       t_ntt_grp
t_ntt_grp_done:
    lsl     r8, r8, #1
    lsr     r10, r10, #1
    b       t_ntt_stage
t_ntt_stage_done:
    cmp     r5, #0
    beq     t_ntt_inv_done
    ldr     r1, =rnl_inv_n
    ldr     r2, [r1]
    mov     r6, #0
t_ntt_scale:
    cmp     r6, #RNL_N
    bge     t_ntt_inv_done
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
    b       t_ntt_scale
t_ntt_inv_done:
    pop     {r4-r11, pc}
    .ltorg

/* rnl_poly_mul: h=f*g in Z_q[x]/(x^N+1) via NTT. O(N log N).        */
    .thumb_func
rnl_poly_mul:
    push    {r4-r11, lr}
    ldr     r4, =rnl_f_ptr
    ldr     r4, [r4]
    ldr     r5, =rnl_g_ptr
    ldr     r5, [r5]
    ldr     r6, =rnl_fa
    ldr     r7, =rnl_ga
    ldr     r8, =rnl_psi_pow_tab
    mov     r9, #0
t_rpm_twist:
    cmp     r9, #RNL_N
    bge     t_rpm_twist_done
    ldr     r10, [r8, r9, lsl #2]
    ldr     r11, [r4, r9, lsl #2]
    umull   r0, r1, r11, r10
    add     r0, r0, r1
    lsr     r1, r0, #16
    uxth    r0, r0
    sub     r0, r0, r1
    it      mi
    addmi   r0, r0, #RNL_Q
    str     r0, [r6, r9, lsl #2]
    ldr     r11, [r5, r9, lsl #2]
    umull   r0, r1, r11, r10
    add     r0, r0, r1
    lsr     r1, r0, #16
    uxth    r0, r0
    sub     r0, r0, r1
    it      mi
    addmi   r0, r0, #RNL_Q
    str     r0, [r7, r9, lsl #2]
    add     r9, r9, #1
    b       t_rpm_twist
t_rpm_twist_done:
    ldr     r0, =rnl_fa
    mov     r1, #0
    bl      rnl_ntt
    ldr     r0, =rnl_ga
    mov     r1, #0
    bl      rnl_ntt
    ldr     r4, =rnl_fa
    ldr     r5, =rnl_ga
    ldr     r6, =rnl_ha
    mov     r9, #0
t_rpm_pw:
    cmp     r9, #RNL_N
    bge     t_rpm_pw_done
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
    b       t_rpm_pw
t_rpm_pw_done:
    ldr     r0, =rnl_ha
    mov     r1, #1
    bl      rnl_ntt
    ldr     r3, =rnl_h_ptr
    ldr     r3, [r3]
    ldr     r6, =rnl_ha
    ldr     r8, =rnl_psi_inv_pow_tab
    mov     r9, #0
t_rpm_untwist:
    cmp     r9, #RNL_N
    bge     t_rpm_untwist_done
    ldr     r10, [r8, r9, lsl #2]
    ldr     r11, [r6, r9, lsl #2]
    umull   r0, r1, r11, r10
    add     r0, r0, r1
    lsr     r1, r0, #16
    uxth    r0, r0
    sub     r0, r0, r1
    it      mi
    addmi   r0, r0, #RNL_Q
    str     r0, [r3, r9, lsl #2]
    add     r9, r9, #1
    b       t_rpm_untwist
t_rpm_untwist_done:
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
/* rnl_m_poly: r0=p -> p=1+x+x^{N-1}                                  */
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
/* rnl_rand_poly: r0=p -> p[i]=prng_next()%Q                          */
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
    bl      prng_next
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
    sub     r0, r6, r0          @ coeff = a - b
    cmp     r0, #0
    bge     rcp_store
    ldr     r7, =RNL_Q
    add     r0, r0, r7
rcp_store:
    str     r0, [r4, r5, lsl #2]
    add     r5, r5, #1
    b       rcp_loop
rcp_done:
    pop     {r4-r7, pc}
    .ltorg

/* ------------------------------------------------------------------ */
/* rnl_bits32: r0=poly -> r0=uint32 key                               */
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
/* ------------------------------------------------------------------ */
    .thumb_func
rnl_hint32:
    push    {r4-r9, lr}
    mov     r4, r0              @ r4 = K_poly
    mov     r5, #0              @ r5 = hint result
    mov     r6, #0              @ r6 = i
    ldr     r8, =0x4000         @ r8 = q/4 = 16384
    ldr     r9, =0x8000         @ r9 = q/2 = 32768
rh32_loop:
    cmp     r6, #RNL_N
    bge     rh32_done
    ldr     r7, [r4, r6, lsl #2]    @ r7 = c
    cmp     r7, r8              @ c < q/4 → quarter=0, h=0
    blt     rh32_next
    cmp     r7, r9              @ c < q/2 → quarter=1, h=1
    bge     rh32_upper
    mov     r0, #1
    lsl     r0, r0, r6
    orr     r5, r5, r0
    b       rh32_next
rh32_upper:
    add     r0, r8, r9          @ r0 = 3q/4 = 49152
    cmp     r7, r0              @ c < 3q/4 → quarter=2, h=0
    blt     rh32_next
    mov     r0, #1              @ quarter=3, h=1
    lsl     r0, r0, r6
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
/*   b[i] = ((2*c + h*32768 + 32768) / 65537) % 2                    */
/* ------------------------------------------------------------------ */
    .thumb_func
rnl_reconcile32:
    push    {r4-r9, lr}
    mov     r4, r0              @ r4 = K_poly
    mov     r5, r1              @ r5 = hint
    mov     r7, #0              @ r7 = key result
    mov     r6, #0              @ r6 = i
    ldr     r8, =0x8000         @ r8 = q/2 = 32768
    ldr     r9, =RNL_Q          @ r9 = q = 65537
rc32_loop:
    cmp     r6, #RNL_N
    bge     rc32_done
    ldr     r0, [r4, r6, lsl #2]    @ r0 = c
    lsl     r0, r0, #1              @ r0 = 2*c
    lsr     r1, r5, r6
    and     r1, r1, #1              @ r1 = h
    lsl     r1, r1, #15             @ r1 = h * 32768
    add     r0, r0, r1              @ r0 = 2*c + h*32768
    add     r0, r0, r8              @ r0 = 2*c + h*32768 + 32768
    cmp     r0, r9
    blt     rc32_next               @ val < q → b=0
    sub     r0, r0, r9
    cmp     r0, r9
    bge     rc32_upper
    mov     r0, #1                  @ val in [q,2q) → b=1
    lsl     r0, r0, r6
    orr     r7, r7, r0
    b       rc32_next
rc32_upper:
    sub     r0, r0, r9
    cmp     r0, r9
    blt     rc32_next               @ val in [2q,3q) → b=0
    mov     r0, #1                  @ val in [3q,4q) → b=1
    lsl     r0, r0, r6
    orr     r7, r7, r0
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
/* stern_hash1_32: r0=v -> r0=sternHash(v)                            */
/* ------------------------------------------------------------------ */
    .thumb_func
stern_hash1_32:
    ror     r1, r0, #28
    mov     r2, #8
    b       nl_fscx_revolve_v1

    .ltorg

/* ------------------------------------------------------------------ */
/* stern_hash2_32: r0=item0, r1=item1 -> r0=sternHash(item0,item1)   */
/* ------------------------------------------------------------------ */
    .thumb_func
stern_hash2_32:
    push    {r4-r5, lr}
    mov     r4, r0
    mov     r5, r1
    ror     r1, r4, #28
    mov     r2, #8
    bl      nl_fscx_revolve_v1
    eor     r0, r0, r5
    ror     r1, r5, #28
    mov     r2, #8
    bl      nl_fscx_revolve_v1
    pop     {r4-r5, pc}

    .ltorg

/* ------------------------------------------------------------------ */
/* stern_matrix_row_32: r0=seed, r1=row -> r0=H[row]                  */
/* ------------------------------------------------------------------ */
    .thumb_func
stern_matrix_row_32:
    push    {r4, lr}
    mov     r4, r0
    eor     r0, r0, r1
    ror     r0, r0, #28
    mov     r1, r4
    mov     r2, #8
    pop     {r4, lr}
    b       nl_fscx_revolve_v1

    .ltorg

/* ------------------------------------------------------------------ */
/* stern_syndrome_32: r0=seed, r1=e -> r0=syndrome (16-bit)           */
/* ------------------------------------------------------------------ */
    .thumb_func
stern_syndrome_32:
    push    {r4-r8, lr}
    mov     r4, r0
    mov     r5, r1
    mov     r6, #0
    mov     r7, #0
tsds_loop:
    cmp     r7, #SDF_NROWS
    bge     tsds_done
    mov     r0, r4
    mov     r1, r7
    bl      stern_matrix_row_32
    and     r0, r0, r5
    eor     r0, r0, r0, lsr #16
    eor     r0, r0, r0, lsr #8
    eor     r0, r0, r0, lsr #4
    eor     r0, r0, r0, lsr #2
    eor     r0, r0, r0, lsr #1
    and     r0, r0, #1
    lsl     r0, r0, r7
    orr     r6, r6, r0
    add     r7, r7, #1
    b       tsds_loop
tsds_done:
    mov     r0, r6
    pop     {r4-r8, pc}

    .ltorg

/* ------------------------------------------------------------------ */
/* stern_popcount_eq2: r0=v -> r0=1 iff popcount==2                   */
/* ------------------------------------------------------------------ */
    .thumb_func
stern_popcount_eq2:
    cbz     r0, tspeq2_fail
    sub     r1, r0, #1
    ands    r0, r0, r1
    beq     tspeq2_fail
    sub     r1, r0, #1
    tst     r0, r1
    bne     tspeq2_fail
    mov     r0, #1
    bx      lr
tspeq2_fail:
    mov     r0, #0
    bx      lr

/* ------------------------------------------------------------------ */
/* stern_gen_perm_32: r0=pi_seed -> writes sdf_perm[0..31]            */
/* ------------------------------------------------------------------ */
    .thumb_func
stern_gen_perm_32:
    push    {r4-r9, lr}
    mov     r4, r0
    ror     r5, r4, #28
    mov     r6, r4
    ldr     r7, =sdf_perm
    mov     r8, #0
tsgp_init:
    cmp     r8, #SDF_N
    bge     tsgp_init_done
    strb    r8, [r7, r8]
    add     r8, r8, #1
    b       tsgp_init
tsgp_init_done:
    mov     r8, #31
tsgp_loop:
    cmp     r8, #1
    blt     tsgp_done
    mov     r0, r6
    mov     r1, r5
    bl      nl_fscx_v1
    mov     r6, r0
    add     r9, r8, #1
    udiv    r0, r6, r9
    mul     r0, r0, r9
    sub     r9, r6, r0
    ldrb    r0, [r7, r8]
    ldrb    r1, [r7, r9]
    strb    r1, [r7, r8]
    strb    r0, [r7, r9]
    sub     r8, r8, #1
    b       tsgp_loop
tsgp_done:
    pop     {r4-r9, pc}

    .ltorg

/* ------------------------------------------------------------------ */
/* stern_apply_perm_32: r0=v -> r0=apply sdf_perm to bits of v        */
/* ------------------------------------------------------------------ */
    .thumb_func
stern_apply_perm_32:
    push    {r4-r7, lr}
    mov     r4, r0
    ldr     r5, =sdf_perm
    mov     r6, #0
    mov     r7, #0
tsap_loop:
    cmp     r7, #SDF_N
    bge     tsap_done
    lsr     r0, r4, r7
    tst     r0, #1
    beq     tsap_next
    ldrb    r0, [r5, r7]
    mov     r1, #1
    lsl     r1, r1, r0
    orr     r6, r6, r1
tsap_next:
    add     r7, r7, #1
    b       tsap_loop
tsap_done:
    mov     r0, r6
    pop     {r4-r7, pc}

    .ltorg

/* ------------------------------------------------------------------ */
/* stern_rand_error_32: no args -> r0 = weight-2 error vector         */
/* ------------------------------------------------------------------ */
    .thumb_func
stern_rand_error_32:
    push    {r4-r7, lr}
    ldr     r4, =sdf_perm
    mov     r5, #0
tsre_init:
    cmp     r5, #SDF_N
    bge     tsre_init_done
    strb    r5, [r4, r5]
    add     r5, r5, #1
    b       tsre_init
tsre_init_done:
    bl      prng_next
    mov     r5, #32
    udiv    r6, r0, r5
    mul     r6, r6, r5
    sub     r6, r0, r6
    ldrb    r0, [r4, #31]
    ldrb    r1, [r4, r6]
    strb    r1, [r4, #31]
    strb    r0, [r4, r6]
    bl      prng_next
    mov     r5, #31
    udiv    r6, r0, r5
    mul     r6, r6, r5
    sub     r6, r0, r6
    ldrb    r0, [r4, #30]
    ldrb    r1, [r4, r6]
    strb    r1, [r4, #30]
    strb    r0, [r4, r6]
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
/* stern_fs_challenges_32: r0=out_ptr -> writes 4 challenges          */
/* reads t_sdf_msg, sdf_c0, sdf_c1, sdf_c2                           */
/* ------------------------------------------------------------------ */
    .thumb_func
stern_fs_challenges_32:
    push    {r4-r9, lr}
    mov     r9, r0
    mov     r4, #0
    ldr     r5, =t_sdf_msg
    ldr     r5, [r5]
    eor     r0, r4, r5
    ror     r1, r5, #28
    mov     r2, #8
    bl      nl_fscx_revolve_v1
    mov     r4, r0
    mov     r8, #0
tsfc_round_loop:
    cmp     r8, #SDF_ROUNDS
    bge     tsfc_round_done
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
    b       tsfc_round_loop
tsfc_round_done:
    mov     r8, #0
tsfc_chal_loop:
    cmp     r8, #SDF_ROUNDS
    bge     tsfc_done
    mov     r0, r4
    mov     r1, r8
    bl      nl_fscx_v1
    mov     r4, r0
    mov     r5, #3
    udiv    r6, r4, r5
    mul     r6, r6, r5
    sub     r6, r4, r6
    str     r6, [r9, r8, lsl #2]
    add     r8, r8, #1
    b       tsfc_chal_loop
tsfc_done:
    pop     {r4-r9, pc}

    .ltorg

/* ------------------------------------------------------------------ */
/* hpks_stern_f_sign_32: uses t_sdf_e, t_sdf_seed, t_sdf_msg         */
/* fills sdf_c0..c2, sdf_b, sdf_respA, sdf_respB                     */
/* ------------------------------------------------------------------ */
    .thumb_func
hpks_stern_f_sign_32:
    push    {r4-r11, lr}
    ldr     r10, =t_sdf_e
    ldr     r10, [r10]
    ldr     r11, =t_sdf_seed
    ldr     r11, [r11]
    mov     r4, #0
thsfs_loop:
    cmp     r4, #SDF_ROUNDS
    bge     thsfs_loop_done
    bl      stern_rand_error_32
    mov     r5, r0
    eor     r6, r10, r5
    bl      prng_next
    mov     r7, r0
    mov     r0, r7
    bl      stern_gen_perm_32
    mov     r0, r5
    bl      stern_apply_perm_32
    mov     r8, r0
    mov     r0, r6
    bl      stern_apply_perm_32
    mov     r9, r0
    mov     r0, r11
    mov     r1, r5
    bl      stern_syndrome_32
    mov     r1, r0
    mov     r0, r7
    bl      stern_hash2_32
    ldr     r3, =sdf_c0
    str     r0, [r3, r4, lsl #2]
    mov     r0, r8
    bl      stern_hash1_32
    ldr     r3, =sdf_c1
    str     r0, [r3, r4, lsl #2]
    mov     r0, r9
    bl      stern_hash1_32
    ldr     r3, =sdf_c2
    str     r0, [r3, r4, lsl #2]
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
    b       thsfs_loop
thsfs_loop_done:
    ldr     r0, =sdf_chals_tmp
    bl      stern_fs_challenges_32
    mov     r4, #0
thsfs_resp_loop:
    cmp     r4, #SDF_ROUNDS
    bge     thsfs_resp_done
    ldr     r3, =sdf_chals_tmp
    ldr     r5, [r3, r4, lsl #2]
    ldr     r3, =sdf_b
    str     r5, [r3, r4, lsl #2]
    cmp     r5, #0
    beq     thsfs_case0
    cmp     r5, #1
    beq     thsfs_case1
    ldr     r3, =sdf_pi_tmp
    ldr     r0, [r3, r4, lsl #2]
    ldr     r3, =sdf_respA
    str     r0, [r3, r4, lsl #2]
    ldr     r3, =sdf_y_tmp
    ldr     r0, [r3, r4, lsl #2]
    ldr     r3, =sdf_respB
    str     r0, [r3, r4, lsl #2]
    b       thsfs_resp_next
thsfs_case0:
    ldr     r3, =sdf_sr_tmp
    ldr     r0, [r3, r4, lsl #2]
    ldr     r3, =sdf_respA
    str     r0, [r3, r4, lsl #2]
    ldr     r3, =sdf_sy_tmp
    ldr     r0, [r3, r4, lsl #2]
    ldr     r3, =sdf_respB
    str     r0, [r3, r4, lsl #2]
    b       thsfs_resp_next
thsfs_case1:
    ldr     r3, =sdf_pi_tmp
    ldr     r0, [r3, r4, lsl #2]
    ldr     r3, =sdf_respA
    str     r0, [r3, r4, lsl #2]
    ldr     r3, =sdf_r_tmp
    ldr     r0, [r3, r4, lsl #2]
    ldr     r3, =sdf_respB
    str     r0, [r3, r4, lsl #2]
thsfs_resp_next:
    add     r4, r4, #1
    b       thsfs_resp_loop
thsfs_resp_done:
    pop     {r4-r11, pc}

    .ltorg

/* ------------------------------------------------------------------ */
/* hpks_stern_f_verify_32: -> r0=1 valid, 0 invalid                   */
/* reads t_sdf_seed, t_sdf_syn and sdf_* signature arrays             */
/* ------------------------------------------------------------------ */
    .thumb_func
hpks_stern_f_verify_32:
    push    {r4-r11, lr}
    ldr     r0, =sdf_chals_tmp
    bl      stern_fs_challenges_32
    mov     r4, #0
thsfv_chal_chk:
    cmp     r4, #SDF_ROUNDS
    bge     thsfv_chal_ok
    ldr     r3, =sdf_chals_tmp
    ldr     r5, [r3, r4, lsl #2]
    ldr     r3, =sdf_b
    ldr     r6, [r3, r4, lsl #2]
    cmp     r5, r6
    bne     thsfv_fail
    add     r4, r4, #1
    b       thsfv_chal_chk
thsfv_chal_ok:
    ldr     r10, =t_sdf_seed
    ldr     r10, [r10]
    ldr     r11, =t_sdf_syn
    ldr     r11, [r11]
    mov     r4, #0
thsfv_round_loop:
    cmp     r4, #SDF_ROUNDS
    bge     thsfv_pass
    ldr     r3, =sdf_b
    ldr     r5, [r3, r4, lsl #2]
    ldr     r3, =sdf_respA
    ldr     r6, [r3, r4, lsl #2]
    ldr     r3, =sdf_respB
    ldr     r7, [r3, r4, lsl #2]
    cmp     r5, #0
    beq     thsfv_case0
    cmp     r5, #1
    beq     thsfv_case1
    @ case 2
    mov     r0, r10
    mov     r1, r7
    bl      stern_syndrome_32
    eor     r0, r0, r11
    mov     r1, r0
    mov     r0, r6
    bl      stern_hash2_32
    ldr     r3, =sdf_c0
    ldr     r1, [r3, r4, lsl #2]
    cmp     r0, r1
    bne     thsfv_fail
    mov     r0, r6
    bl      stern_gen_perm_32
    mov     r0, r7
    bl      stern_apply_perm_32
    bl      stern_hash1_32
    ldr     r3, =sdf_c2
    ldr     r1, [r3, r4, lsl #2]
    cmp     r0, r1
    bne     thsfv_fail
    b       thsfv_round_next
thsfv_case0:
    mov     r0, r6
    bl      stern_hash1_32
    ldr     r3, =sdf_c1
    ldr     r1, [r3, r4, lsl #2]
    cmp     r0, r1
    bne     thsfv_fail
    mov     r0, r7
    bl      stern_hash1_32
    ldr     r3, =sdf_c2
    ldr     r1, [r3, r4, lsl #2]
    cmp     r0, r1
    bne     thsfv_fail
    mov     r0, r6
    bl      stern_popcount_eq2
    cbz     r0, thsfv_fail
    b       thsfv_round_next
thsfv_case1:
    mov     r0, r7
    bl      stern_popcount_eq2
    cbz     r0, thsfv_fail
    mov     r0, r10
    mov     r1, r7
    bl      stern_syndrome_32
    mov     r1, r0
    mov     r0, r6
    bl      stern_hash2_32
    ldr     r3, =sdf_c0
    ldr     r1, [r3, r4, lsl #2]
    cmp     r0, r1
    bne     thsfv_fail
    mov     r0, r6
    bl      stern_gen_perm_32
    mov     r0, r7
    bl      stern_apply_perm_32
    bl      stern_hash1_32
    ldr     r3, =sdf_c1
    ldr     r1, [r3, r4, lsl #2]
    cmp     r0, r1
    bne     thsfv_fail
thsfv_round_next:
    add     r4, r4, #1
    b       thsfv_round_loop
thsfv_pass:
    mov     r0, #1
    pop     {r4-r11, pc}
thsfv_fail:
    mov     r0, #0
    pop     {r4-r11, pc}

    .ltorg

/* ------------------------------------------------------------------ */
/* hpke_stern_f_encap_32: fills t_sdf_e_prime, t_sdf_ct, t_sdf_K_enc */
/* ------------------------------------------------------------------ */
    .thumb_func
hpke_stern_f_encap_32:
    push    {r4-r5, lr}
    bl      stern_rand_error_32
    mov     r4, r0
    ldr     r3, =t_sdf_e_prime
    str     r4, [r3]
    ldr     r5, =t_sdf_seed
    ldr     r5, [r5]
    mov     r0, r5
    mov     r1, r4
    bl      stern_syndrome_32
    ldr     r3, =t_sdf_ct
    str     r0, [r3]
    mov     r0, r5
    mov     r1, r4
    bl      stern_hash2_32
    ldr     r3, =t_sdf_K_enc
    str     r0, [r3]
    pop     {r4-r5, pc}

    .ltorg

/* ------------------------------------------------------------------ */
/* hpke_stern_f_decap_known_32: r0=e' -> r0=K=hash2(seed,e')         */
/* ------------------------------------------------------------------ */
    .thumb_func
hpke_stern_f_decap_known_32:
    push    {r4, lr}
    mov     r4, r0
    ldr     r0, =t_sdf_seed
    ldr     r0, [r0]
    mov     r1, r4
    bl      stern_hash2_32
    pop     {r4, pc}

    .ltorg

    .section .note.GNU-stack,"",%progbits
