/*  Herradura KEx -- Correctness Tests v1.5.3
    ARM 32-bit Thumb Assembly (GAS) — HKEX-GF, HSKE, HPKS, HPKE,
                                       NL-FSCX v2 inv, HSKE-NL-A2,
                                       HKEX-RNL, HPKS-NL, HPKE-NL
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

/* ------------------------------------------------------------------ */
/* .data                                                               */
/* ------------------------------------------------------------------ */
    .data
    .balign 4

fmt_hdr:  .asciz "=== Herradura KEx v1.5.3 -- Correctness Tests (ARM Thumb, KEYBITS=32) ===\n\n"
fmt_t1:   .asciz "[1] HKEX-GF key exchange: sk_alice == sk_bob (20 iterations)\n"
fmt_t2:   .asciz "[2] HSKE encrypt+decrypt round-trip: D == plaintext (100 iterations)\n"
fmt_t3:   .asciz "[3] HPKS Schnorr: g^s * C^e == R (20 iterations)\n"
fmt_t4:   .asciz "[4] HPKE El Gamal: D == plaintext (20 iterations)\n"
fmt_t5:   .asciz "[5] NL-FSCX v2 inverse: v2_inv(v2(A,B),B) == A (20 iterations)\n"
fmt_t6:   .asciz "[6] HSKE-NL-A2 revolve-mode: D == plaintext (20 iterations)\n"
fmt_t7:   .asciz "[7] HKEX-RNL key agreement: KA == KB (10 trials, pass >= 8)\n"
fmt_t8:   .asciz "[8] HPKS-NL Schnorr: NL challenge g^s*C^e == R (20 iterations)\n"
fmt_t9:   .asciz "[9] HPKE-NL: D == plaintext, NL-FSCX v2 (20 iterations)\n"
fmt_t10:  .asciz "[10] HPKS-NL Eve resistance: random forgery rejected (20 trials)\n"

fmt_p20:  .asciz "    20 / 20 passed  [PASS]\n"
fmt_p100: .asciz "    100 / 100 passed  [PASS]\n"
fmt_prnl: .asciz "    >= 8 / 10 raw keys agreed  [PASS]\n"
fmt_fail: .asciz "    FAILED  [FAIL]\n"

lcg_state: .word 0x12345678
lcg_mul:   .word 1664525
lcg_add:   .word 1013904223

rnl_f_ptr: .word 0
rnl_g_ptr: .word 0
rnl_h_ptr: .word 0

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

rnl_m_base:  .space 128
rnl_a_rand:  .space 128
rnl_m_blind: .space 128
rnl_s_A:     .space 128
rnl_s_B:     .space 128
rnl_C_A:     .space 128
rnl_C_B:     .space 128
rnl_tmp:     .space 128
rnl_tmp2:    .space 128

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
    bl      rnl_agree
    ldr     r3, =t_KA
    str     r0, [r3]
    ldr     r0, =rnl_s_B
    ldr     r1, =rnl_C_A
    bl      rnl_agree
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
    cmp     r11, #8
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
/* m_inv_32: r0=X -> r0=fscx_revolve(X,0,15)                          */
/* ------------------------------------------------------------------ */
    .thumb_func
m_inv_32:
    push    {lr}
    mov     r1, #0
    mov     r2, #15
    bl      fscx_revolve
    pop     {pc}
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
/* ------------------------------------------------------------------ */
    .thumb_func
nl_fscx_revolve_v2_inv:
    push    {r4-r6, lr}
    mov     r4, r0
    mov     r5, r1
    mov     r6, r2
nlrv2i_loop:
    cbz     r6, nlrv2i_done
    mov     r0, r4
    mov     r1, r5
    bl      nl_fscx_v2_inv
    mov     r4, r0
    subs    r6, r6, #1
    b       nlrv2i_loop
nlrv2i_done:
    mov     r0, r4
    pop     {r4-r6, pc}
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
/* rnl_poly_mul: h=f*g mod (x^N+1) in Z_q                            */
/* ------------------------------------------------------------------ */
    .thumb_func
rnl_poly_mul:
    push    {r4-r11, lr}
    ldr     r6, =rnl_tmp
    mov     r0, #0
    mov     r1, #RNL_N
rpm_zero:
    str     r0, [r6], #4
    subs    r1, r1, #1
    bne     rpm_zero
    ldr     r6, =rnl_tmp
    ldr     r4, =rnl_f_ptr
    ldr     r4, [r4]
    ldr     r5, =rnl_g_ptr
    ldr     r5, [r5]
    ldr     r11, =RNL_Q
    mov     r7, #0
rpm_outer:
    cmp     r7, #RNL_N
    bge     rpm_outer_done
    ldr     r9, [r4, r7, lsl #2]
    cbz     r9, rpm_outer_next
    mov     r8, #0
rpm_inner:
    cmp     r8, #RNL_N
    bge     rpm_inner_done
    ldr     r10, [r5, r8, lsl #2]
    cbz     r10, rpm_inner_next
    umull   r0, r1, r9, r10
    add     r0, r0, r1
    udiv    r1, r0, r11
    mls     r0, r11, r1, r0
    add     r10, r7, r8
    cmp     r10, #RNL_N
    bge     rpm_neg
    ldr     r1, [r6, r10, lsl #2]
    add     r1, r1, r0
    cmp     r1, r11
    it      cs
    subcs   r1, r1, r11
    str     r1, [r6, r10, lsl #2]
    b       rpm_inner_next
rpm_neg:
    sub     r10, r10, #RNL_N
    ldr     r1, [r6, r10, lsl #2]
    sub     r1, r1, r0
    add     r1, r1, r11
    cmp     r1, r11
    it      cs
    subcs   r1, r1, r11
    str     r1, [r6, r10, lsl #2]
rpm_inner_next:
    add     r8, r8, #1
    b       rpm_inner
rpm_inner_done:
rpm_outer_next:
    add     r7, r7, #1
    b       rpm_outer
rpm_outer_done:
    ldr     r3, =rnl_h_ptr
    ldr     r3, [r3]
    ldr     r6, =rnl_tmp
    mov     r7, #RNL_N
rpm_copy:
    ldr     r0, [r6], #4
    str     r0, [r3], #4
    subs    r7, r7, #1
    bne     rpm_copy
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
