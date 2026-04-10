/*  Herradura Cryptographic Suite v1.4.0 — Security Correctness Tests
    ARM 32-bit Thumb Assembly (GAS)
    KEYBITS = 32, I_VALUE = 8, R_VALUE = 24
    HKEX-GF: DH over GF(2^32)*, poly x^32+x^22+x^2+x+1, generator g=3
    HPKS:    Schnorr signature correctness: g^s*C^e == R
    HPKE:    El Gamal correctness: fscx_revolve(E, R^a, 24) == P

    Note: GFPow-heavy tests use 20 iterations for speed.

    Copyright (C) 2024-2026 Omar Alejandro Herrera Reyna
    MIT License / GPL v3.0 — choose either.

    Build: arm-linux-gnueabi-gcc -o Herradura_tests_arm Herradura_tests.s
    Run:   qemu-arm ./Herradura_tests_arm
        or directly on ARM hardware
*/

    .syntax unified
    .cpu cortex-a7
    .thumb

    .extern printf
    .extern exit

/* ------------------------------------------------------------------ */
/* .data section                                                       */
/* ------------------------------------------------------------------ */
    .data
    .balign 4

/* -- format strings -- */
fmt_main_hdr: .asciz "=== Herradura KEx v1.4.0 \xe2\x80\x94 Security Tests (ARM 32-bit Thumb) ===\n\n"

fmt_t1_hdr:   .asciz "[1] HKEX-GF key exchange correctness (20 iterations)\n"
fmt_t2_hdr:   .asciz "[2] HSKE encrypt+decrypt round-trip (100 iterations)\n"
fmt_t3_hdr:   .asciz "[3] HPKS Schnorr correctness: g^s*C^e == R (20 iterations)\n"
fmt_t4_hdr:   .asciz "[4] HPKE El Gamal encrypt+decrypt: D == P (20 iterations)\n"

fmt_result:   .asciz "    %d / 100 passed  [%s]\n\n"
fmt_result20: .asciz "    %d / 20 passed  [%s]\n\n"

str_pass:     .asciz "PASS"
str_fail:     .asciz "FAIL"

/* -- PRNG state -- */
    .balign 4
prng_state:   .word 0x12345678

/* -- scratch memory -- */
    .balign 4
test_C:       .word 0
test_C2:      .word 0
test_sk:      .word 0
test_val:     .word 0   /* general temp / plaintext */
test_k:       .word 0   /* Schnorr nonce k          */
test_R_sc:    .word 0   /* Schnorr R = g^k          */
test_e_sc:    .word 0   /* Schnorr challenge e      */
test_ae:      .word 0   /* a*e mod ORD              */
test_s_sc:    .word 0   /* Schnorr response s       */
test_gs:      .word 0   /* g^s                      */
test_r_e:     .word 0   /* El Gamal ephemeral r     */
test_R_e:     .word 0   /* El Gamal R = g^r         */
test_enc_key: .word 0   /* C^r                      */
test_dec_key: .word 0   /* R^a                      */
test_E_e:     .word 0   /* El Gamal ciphertext      */

/* LCG constants */
    .balign 4
lcg_mul:      .word 1664525
lcg_add:      .word 1013904223

/* ------------------------------------------------------------------ */
/* .text section                                                       */
/* ------------------------------------------------------------------ */
    .text
    .global main
    .thumb_func

/* ------------------------------------------------------------------ */
/* main                                                                */
/* ------------------------------------------------------------------ */
main:
    push    {r4-r11, lr}

    ldr     r0, =fmt_main_hdr
    bl      printf

    bl      test_hkex
    bl      test_hske
    bl      test_hpks
    bl      test_hpke

    mov     r0, #0
    bl      exit

    .ltorg

/* ================================================================
   test_hkex
   [1] HKEX-GF key exchange: gf_pow_32(C2, a) == gf_pow_32(C, b)
   20 iterations
   ================================================================ */
    .thumb_func
test_hkex:
    push    {r4-r11, lr}

    ldr     r0, =fmt_t1_hdr
    bl      printf

    mov     r4, #20             @ loop counter
    mov     r5, #0              @ pass counter

hkex_loop:
    /* a_priv, b_priv (odd) */
    bl      prng_next
    orr     r0, r0, #1
    mov     r6, r0              @ a_priv

    bl      prng_next
    orr     r0, r0, #1
    mov     r7, r0              @ b_priv

    /* C = gf_pow_32(3, a_priv) */
    mov     r0, #3
    mov     r1, r6
    bl      gf_pow_32
    ldr     r3, =test_C
    str     r0, [r3]

    /* C2 = gf_pow_32(3, b_priv) */
    mov     r0, #3
    mov     r1, r7
    bl      gf_pow_32
    ldr     r3, =test_C2
    str     r0, [r3]

    /* sk_alice = gf_pow_32(C2, a_priv) */
    ldr     r0, =test_C2
    ldr     r0, [r0]
    mov     r1, r6
    bl      gf_pow_32
    ldr     r3, =test_sk
    str     r0, [r3]

    /* sk_bob = gf_pow_32(C, b_priv) */
    ldr     r0, =test_C
    ldr     r0, [r0]
    mov     r1, r7
    bl      gf_pow_32

    ldr     r1, =test_sk
    ldr     r1, [r1]
    cmp     r0, r1
    bne     hkex_no_pass
    add     r5, r5, #1
hkex_no_pass:
    subs    r4, r4, #1
    bne     hkex_loop

    ldr     r0, =fmt_result20
    mov     r1, r5
    cmp     r5, #20
    bne     hkex_print_fail
    ldr     r2, =str_pass
    b       hkex_do_print
hkex_print_fail:
    ldr     r2, =str_fail
hkex_do_print:
    bl      printf

    pop     {r4-r11, pc}

    .ltorg

/* ================================================================
   test_hske
   [2] HSKE: fscx_revolve(fscx_revolve(P,k,8),k,24) == P
   100 iterations
   ================================================================ */
    .thumb_func
test_hske:
    push    {r4-r11, lr}

    ldr     r0, =fmt_t2_hdr
    bl      printf

    mov     r4, #100
    mov     r5, #0

hske_loop:
    bl      prng_next
    mov     r6, r0              @ plain

    bl      prng_next
    mov     r7, r0              @ key

    /* E = fscx_revolve(plain, key, 8) */
    mov     r0, r6
    mov     r1, r7
    mov     r2, #8
    bl      fscx_revolve
    ldr     r3, =test_val
    str     r0, [r3]

    /* D = fscx_revolve(E, key, 24) */
    ldr     r0, =test_val
    ldr     r0, [r0]
    mov     r1, r7
    mov     r2, #24
    bl      fscx_revolve

    cmp     r0, r6
    bne     hske_no_pass
    add     r5, r5, #1
hske_no_pass:
    subs    r4, r4, #1
    bne     hske_loop

    ldr     r0, =fmt_result
    mov     r1, r5
    cmp     r5, #100
    bne     hske_print_fail
    ldr     r2, =str_pass
    b       hske_do_print
hske_print_fail:
    ldr     r2, =str_fail
hske_do_print:
    bl      printf

    pop     {r4-r11, pc}

    .ltorg

/* ================================================================
   test_hpks
   [3] HPKS Schnorr correctness: g^s * C^e == R
       a   = prng_next() | 1  (private key)
       plain = prng_next()
       k   = prng_next()      (nonce)
       C   = g^a;  R = g^k
       e   = fscx_revolve(R, plain, 8)
       ae  = a * e mod ORD    (umull + lo+hi reduction)
       s   = (k - ae) mod ORD (subs/subcc trick)
       pass: gf_mul_32(g^s, C^e) == R
   20 iterations
   ================================================================ */
    .thumb_func
test_hpks:
    push    {r4-r11, lr}

    ldr     r0, =fmt_t3_hdr
    bl      printf

    mov     r4, #20             @ loop counter
    mov     r5, #0              @ pass counter

hpks_loop:
    /* a_priv (odd), plain, k */
    bl      prng_next
    orr     r0, r0, #1
    mov     r6, r0              @ a_priv (kept in r6 across calls)

    bl      prng_next
    ldr     r3, =test_val
    str     r0, [r3]            @ plain

    bl      prng_next
    ldr     r3, =test_k
    str     r0, [r3]            @ k

    /* C = gf_pow_32(3, a_priv) */
    mov     r0, #3
    mov     r1, r6
    bl      gf_pow_32
    ldr     r3, =test_C
    str     r0, [r3]            @ C = g^a

    /* R = gf_pow_32(3, k) */
    mov     r0, #3
    ldr     r1, =test_k
    ldr     r1, [r1]
    bl      gf_pow_32
    ldr     r3, =test_R_sc
    str     r0, [r3]            @ R = g^k

    /* e = fscx_revolve(R, plain, 8) */
    ldr     r0, =test_R_sc
    ldr     r0, [r0]
    ldr     r1, =test_val
    ldr     r1, [r1]
    mov     r2, #8
    bl      fscx_revolve
    ldr     r3, =test_e_sc
    str     r0, [r3]            @ e = challenge

    /* ae_mod = a_priv * e mod ORD
       hi*2^32 + lo == hi + lo (mod 2^32-1); carry adds 1.           */
    ldr     r7, =test_e_sc
    ldr     r7, [r7]            @ r7 = e
    umull   r8, r9, r6, r7      @ r9:r8 = a * e  (lo=r8, hi=r9)
    adds    r8, r8, r9          @ r8 = lo + hi;  C = carry
    it cs
    addcs   r8, r8, #1          @ if carry: r8 += 1
    ldr     r3, =test_ae
    str     r8, [r3]

    /* s = k - ae_mod mod ORD */
    ldr     r7, =test_k
    ldr     r7, [r7]            @ r7 = k
    ldr     r8, =test_ae
    ldr     r8, [r8]            @ r8 = ae_mod
    subs    r7, r7, r8          @ r7 = k - ae_mod  (may underflow)
    it cc
    subcc   r7, r7, #1          @ if borrow: s = wrapped - 1
    ldr     r3, =test_s_sc
    str     r7, [r3]

    /* gs = gf_pow_32(3, s) */
    mov     r0, #3
    ldr     r1, =test_s_sc
    ldr     r1, [r1]
    bl      gf_pow_32
    ldr     r3, =test_gs
    str     r0, [r3]            @ gs = g^s

    /* Ce = gf_pow_32(C, e) */
    ldr     r0, =test_C
    ldr     r0, [r0]
    ldr     r1, =test_e_sc
    ldr     r1, [r1]
    bl      gf_pow_32           @ r0 = C^e

    /* lhs = gf_mul_32(gs, Ce) */
    ldr     r1, =test_gs
    ldr     r1, [r1]            @ r1 = gs
    push    {r0}                @ save Ce
    mov     r0, r1              @ r0 = gs
    pop     {r1}                @ r1 = Ce
    bl      gf_mul_32           @ r0 = gs * Ce

    /* compare lhs with R */
    ldr     r1, =test_R_sc
    ldr     r1, [r1]
    cmp     r0, r1
    bne     hpks_no_pass
    add     r5, r5, #1
hpks_no_pass:
    subs    r4, r4, #1
    bne     hpks_loop

    ldr     r0, =fmt_result20
    mov     r1, r5
    cmp     r5, #20
    bne     hpks_print_fail
    ldr     r2, =str_pass
    b       hpks_do_print
hpks_print_fail:
    ldr     r2, =str_fail
hpks_do_print:
    bl      printf

    pop     {r4-r11, pc}

    .ltorg

/* ================================================================
   test_hpke
   [4] HPKE El Gamal: fscx_revolve(E, R^a, 24) == plain
       a    = prng_next() | 1  (Alice private key)
       plain = prng_next()
       r    = prng_next() | 1  (Bob ephemeral)
       C    = g^a;   R = g^r
       enc_key = C^r = g^{ar}  (Bob's encryption key)
       E    = fscx_revolve(plain, enc_key, 8)
       dec_key = R^a = g^{ra}  (Alice's decryption key)
       D    = fscx_revolve(E, dec_key, 24)  == plain?
   20 iterations
   ================================================================ */
    .thumb_func
test_hpke:
    push    {r4-r11, lr}

    ldr     r0, =fmt_t4_hdr
    bl      printf

    mov     r4, #20             @ loop counter
    mov     r5, #0              @ pass counter

hpke_loop:
    /* a_priv (odd), plain, r (odd) */
    bl      prng_next
    orr     r0, r0, #1
    mov     r6, r0              @ a_priv

    bl      prng_next
    ldr     r3, =test_val
    str     r0, [r3]            @ plain

    bl      prng_next
    orr     r0, r0, #1
    ldr     r3, =test_r_e
    str     r0, [r3]            @ r (ephemeral)

    /* C = gf_pow_32(3, a_priv) */
    mov     r0, #3
    mov     r1, r6
    bl      gf_pow_32
    ldr     r3, =test_C
    str     r0, [r3]            @ C = g^a

    /* R_e = gf_pow_32(3, r) */
    mov     r0, #3
    ldr     r1, =test_r_e
    ldr     r1, [r1]
    bl      gf_pow_32
    ldr     r3, =test_R_e
    str     r0, [r3]            @ R = g^r

    /* enc_key = gf_pow_32(C, r) = C^r = g^{ar} */
    ldr     r0, =test_C
    ldr     r0, [r0]
    ldr     r1, =test_r_e
    ldr     r1, [r1]
    bl      gf_pow_32
    ldr     r3, =test_enc_key
    str     r0, [r3]

    /* E = fscx_revolve(plain, enc_key, 8) */
    ldr     r0, =test_val
    ldr     r0, [r0]
    ldr     r1, =test_enc_key
    ldr     r1, [r1]
    mov     r2, #8
    bl      fscx_revolve
    ldr     r3, =test_E_e
    str     r0, [r3]            @ E (ciphertext)

    /* dec_key = gf_pow_32(R_e, a_priv) = R^a = g^{ra} */
    ldr     r0, =test_R_e
    ldr     r0, [r0]
    mov     r1, r6
    bl      gf_pow_32
    ldr     r3, =test_dec_key
    str     r0, [r3]

    /* D = fscx_revolve(E, dec_key, 24) */
    ldr     r0, =test_E_e
    ldr     r0, [r0]
    ldr     r1, =test_dec_key
    ldr     r1, [r1]
    mov     r2, #24
    bl      fscx_revolve        @ r0 = D

    /* compare D == plain */
    ldr     r1, =test_val
    ldr     r1, [r1]
    cmp     r0, r1
    bne     hpke_no_pass
    add     r5, r5, #1
hpke_no_pass:
    subs    r4, r4, #1
    bne     hpke_loop

    ldr     r0, =fmt_result20
    mov     r1, r5
    cmp     r5, #20
    bne     hpke_print_fail
    ldr     r2, =str_pass
    b       hpke_do_print
hpke_print_fail:
    ldr     r2, =str_fail
hpke_do_print:
    bl      printf

    pop     {r4-r11, pc}

    .ltorg

/* ------------------------------------------------------------------ */
/* prng_next: LCG — no args, returns new state in r0                  */
/*   state = state * 1664525 + 1013904223                             */
/*   Clobbers r1, r2                                                  */
/* ------------------------------------------------------------------ */
    .thumb_func
prng_next:
    ldr     r1, =prng_state
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
/* gf_mul_32: r0=a, r1=b -> r0 = a*b in GF(2^32)*                    */
/*   GF poly lower bits: 0x00400007                                   */
/*   Clobbers r4-r8 (saved/restored)                                  */
/* ------------------------------------------------------------------ */
    .thumb_func
gf_mul_32:
    push    {r4-r8, lr}
    mov     r4, #0          @ result = 0
    mov     r5, r0          @ aa = a
    mov     r6, r1          @ bb = b
    ldr     r7, =0x00400007 @ GF poly
    mov     r8, #32
gf_mul_32_loop:
    tst     r6, #1
    it      ne
    eorne   r4, r4, r5      @ if LSB of bb: result ^= aa
    lsls    r5, r5, #1      @ aa <<= 1; C flag = old bit 31
    it      cs
    eorcs   r5, r5, r7      @ if carry: aa ^= poly
    lsr     r6, r6, #1      @ bb >>= 1
    subs    r8, r8, #1
    bne     gf_mul_32_loop
    mov     r0, r4
    pop     {r4-r8, pc}
    .ltorg

/* ------------------------------------------------------------------ */
/* gf_pow_32: r0=base, r1=exp -> r0 = base^exp in GF(2^32)*          */
/*   Uses r4=result, r5=base, r6=exp                                  */
/*   Clobbers r4-r6 (saved/restored)                                  */
/* ------------------------------------------------------------------ */
    .thumb_func
gf_pow_32:
    push    {r4-r6, lr}
    mov     r4, #1          @ result = 1
    mov     r5, r0          @ base
    mov     r6, r1          @ exp
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
/* fscx_revolve: r0=A, r1=B, r2=rounds -> r0=result                  */
/*   FSCX(A,B) = A^B^ROL(A,1)^ROL(B,1)^ROR(A,1)^ROR(B,1)            */
/*   Clobbers r4-r6 (saved/restored)                                  */
/* ------------------------------------------------------------------ */
    .thumb_func
fscx_revolve:
    push    {r4-r7, lr}
    mov     r4, r0
fscx_revolve_test_loop:
    eor     r5, r4, r1          @ A ^ B
    ror     r6, r4, #1
    eor     r5, r5, r6          @ ^ ROR(A,1)
    ror     r6, r1, #1
    eor     r5, r5, r6          @ ^ ROR(B,1)
    ror     r6, r4, #31
    eor     r5, r5, r6          @ ^ ROL(A,1)
    ror     r6, r1, #31
    eor     r5, r5, r6          @ ^ ROL(B,1)
    mov     r4, r5
    subs    r2, r2, #1
    bne     fscx_revolve_test_loop
    mov     r0, r4
    pop     {r4-r7, pc}

    .ltorg

    .section .note.GNU-stack,"",%progbits
