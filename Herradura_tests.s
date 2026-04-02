/*  Herradura Cryptographic Suite v1.3.7 — Security Correctness Tests
    ARM 32-bit Thumb Assembly (GAS) — HKEX, HSKE, HPKS, HPKE
    KEYBITS = 32, I_VALUE = 8, R_VALUE = 24, 100 PRNG iterations each

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
fmt_main_hdr: .asciz "=== Herradura KEx \xe2\x80\x94 Security Tests (ARM 32-bit Thumb) ===\n\n"

fmt_t1_hdr:   .asciz "[1] HKEX key exchange correctness\n"
fmt_t2_hdr:   .asciz "[2] HSKE encrypt+decrypt round-trip\n"
fmt_t3_hdr:   .asciz "[3] HPKS sign+verify correctness\n"
fmt_t4_hdr:   .asciz "[4] HPKE encrypt+decrypt round-trip\n"

/* "    %d / 100 passed  [%s]\n" */
fmt_result:   .asciz "    %d / 100 passed  [%s]\n\n"

str_pass:     .asciz "PASS"
str_fail:     .asciz "FAIL"

/* -- PRNG state -- */
    .balign 4
prng_state:   .word 0x12345678

/* -- scratch memory for intermediate values -- */
    .balign 4
test_C:       .word 0
test_C2:      .word 0
test_hn:      .word 0
test_val:     .word 0     @ general temp

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
   [1] HKEX key exchange correctness: skeyA == skeyB
   Uses: r4=loop_counter, r5=pass_counter
         r6=A, r7=B, r8=A2, r9=B2
   ================================================================ */
    .thumb_func
test_hkex:
    push    {r4-r11, lr}

    ldr     r0, =fmt_t1_hdr
    bl      printf

    mov     r4, #100            @ loop counter
    mov     r5, #0              @ pass counter

hkex_loop:
    /* generate A, B, A2, B2 */
    bl      prng_next
    mov     r6, r0              @ A

    bl      prng_next
    mov     r7, r0              @ B

    bl      prng_next
    mov     r8, r0              @ A2

    bl      prng_next
    mov     r9, r0              @ B2

    /* C = fscx_revolve(A, B, 8) */
    mov     r0, r6
    mov     r1, r7
    mov     r2, #8
    bl      fscx_revolve
    ldr     r3, =test_C
    str     r0, [r3]            @ test_C = C
                                @ r6=A, r7=B, r8=A2, r9=B2 preserved (fscx_revolve saves r4-r7)

    /* C2 = fscx_revolve(A2, B2, 8) */
    mov     r0, r8
    mov     r1, r9
    mov     r2, #8
    bl      fscx_revolve
    ldr     r3, =test_C2
    str     r0, [r3]            @ test_C2 = C2

    /* hn = C ^ C2 */
    ldr     r0, =test_C
    ldr     r0, [r0]
    ldr     r1, =test_C2
    ldr     r1, [r1]
    eor     r0, r0, r1
    ldr     r3, =test_hn
    str     r0, [r3]

    /* skeyA = fscx_revolve_n(C2, B, 24, hn) ^ A */
    ldr     r0, =test_C2
    ldr     r0, [r0]
    mov     r1, r7              @ B
    mov     r2, #24
    ldr     r3, =test_hn
    ldr     r3, [r3]
    bl      fscx_revolve_n
    eor     r0, r0, r6          @ ^ A
    ldr     r3, =test_val
    str     r0, [r3]            @ save skeyA

    /* skeyB = fscx_revolve_n(C, B2, 24, hn) ^ A2 */
    ldr     r0, =test_C
    ldr     r0, [r0]
    mov     r1, r9              @ B2
    mov     r2, #24
    ldr     r3, =test_hn
    ldr     r3, [r3]
    bl      fscx_revolve_n
    eor     r0, r0, r8          @ ^ A2

    /* compare skeyA == skeyB */
    ldr     r1, =test_val
    ldr     r1, [r1]
    cmp     r0, r1
    bne     hkex_no_pass
    add     r5, r5, #1
hkex_no_pass:
    subs    r4, r4, #1
    bne     hkex_loop

    /* print result */
    ldr     r0, =fmt_result
    mov     r1, r5
    cmp     r5, #100
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
   [2] HSKE encrypt+decrypt round-trip: decrypt(encrypt(P)) == P
   Uses: r4=loop_counter, r5=pass_counter
         r6=plain, r7=key
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

    /* E = fscx_revolve_n(plain, key, 8, key) */
    mov     r0, r6
    mov     r1, r7
    mov     r2, #8
    mov     r3, r7
    bl      fscx_revolve_n
    ldr     r3, =test_val
    str     r0, [r3]            @ save E
                                @ r6=plain, r7=key preserved

    /* D = fscx_revolve_n(E, key, 24, key) */
    ldr     r0, =test_val
    ldr     r0, [r0]
    mov     r1, r7
    mov     r2, #24
    mov     r3, r7
    bl      fscx_revolve_n

    /* compare D == plain */
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
   [3] HPKS sign+verify correctness: V == plain
   Uses: r4=loop_counter, r5=pass_counter
         r6=A, r7=B, r8=A2, r9=B2
         plain stored in test_val between calls
   ================================================================ */
    .thumb_func
test_hpks:
    push    {r4-r11, lr}

    ldr     r0, =fmt_t3_hdr
    bl      printf

    mov     r4, #100
    mov     r5, #0

hpks_loop:
    bl      prng_next
    mov     r6, r0              @ A

    bl      prng_next
    mov     r7, r0              @ B

    bl      prng_next
    mov     r8, r0              @ A2

    bl      prng_next
    mov     r9, r0              @ B2

    bl      prng_next
    ldr     r3, =test_val
    str     r0, [r3]            @ plain -> test_val

    /* C = fscx_revolve(A, B, 8) */
    mov     r0, r6
    mov     r1, r7
    mov     r2, #8
    bl      fscx_revolve
    ldr     r3, =test_C
    str     r0, [r3]

    /* C2 = fscx_revolve(A2, B2, 8) */
    mov     r0, r8
    mov     r1, r9
    mov     r2, #8
    bl      fscx_revolve
    ldr     r3, =test_C2
    str     r0, [r3]

    /* hn = C ^ C2 */
    ldr     r0, =test_C
    ldr     r0, [r0]
    ldr     r1, =test_C2
    ldr     r1, [r1]
    eor     r0, r0, r1
    ldr     r3, =test_hn
    str     r0, [r3]

    /* S = fscx_revolve_n(C2, B, 24, hn) ^ A ^ plain */
    ldr     r0, =test_C2
    ldr     r0, [r0]
    mov     r1, r7              @ B
    mov     r2, #24
    ldr     r3, =test_hn
    ldr     r3, [r3]
    bl      fscx_revolve_n
    eor     r0, r0, r6          @ ^ A
    ldr     r3, =test_val
    ldr     r3, [r3]            @ plain
    eor     r0, r0, r3          @ ^ plain  => S
    /* store S in test_C2 (reuse; C2 no longer needed, C must be preserved) */
    ldr     r3, =test_C2
    str     r0, [r3]            @ test_C2 = S

    /* V = fscx_revolve_n(C, B2, 24, hn) ^ A2 ^ S */
    ldr     r0, =test_C
    ldr     r0, [r0]            @ C (Alice's public value)
    mov     r1, r9              @ B2
    mov     r2, #24
    ldr     r3, =test_hn
    ldr     r3, [r3]
    bl      fscx_revolve_n
    eor     r0, r0, r8          @ ^ A2
    ldr     r3, =test_C2
    ldr     r3, [r3]            @ S
    eor     r0, r0, r3          @ ^ S  => V

    /* compare V == plain */
    ldr     r1, =test_val
    ldr     r1, [r1]
    cmp     r0, r1
    bne     hpks_no_pass
    add     r5, r5, #1
hpks_no_pass:
    subs    r4, r4, #1
    bne     hpks_loop

    ldr     r0, =fmt_result
    mov     r1, r5
    cmp     r5, #100
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
   [4] HPKE encrypt+decrypt round-trip: D == plain
   Uses: r4=loop_counter, r5=pass_counter
         r6=A, r7=B, r8=A2, r9=B2
         plain stored in test_val
   ================================================================ */
    .thumb_func
test_hpke:
    push    {r4-r11, lr}

    ldr     r0, =fmt_t4_hdr
    bl      printf

    mov     r4, #100
    mov     r5, #0

hpke_loop:
    bl      prng_next
    mov     r6, r0              @ A

    bl      prng_next
    mov     r7, r0              @ B

    bl      prng_next
    mov     r8, r0              @ A2

    bl      prng_next
    mov     r9, r0              @ B2

    bl      prng_next
    ldr     r3, =test_val
    str     r0, [r3]            @ plain -> test_val

    /* C = fscx_revolve(A, B, 8) */
    mov     r0, r6
    mov     r1, r7
    mov     r2, #8
    bl      fscx_revolve
    ldr     r3, =test_C
    str     r0, [r3]

    /* C2 = fscx_revolve(A2, B2, 8) */
    mov     r0, r8
    mov     r1, r9
    mov     r2, #8
    bl      fscx_revolve
    ldr     r3, =test_C2
    str     r0, [r3]

    /* hn = C ^ C2 */
    ldr     r0, =test_C
    ldr     r0, [r0]
    ldr     r1, =test_C2
    ldr     r1, [r1]
    eor     r0, r0, r1
    ldr     r3, =test_hn
    str     r0, [r3]

    /* E = fscx_revolve_n(C, B2, 24, hn) ^ A2 ^ plain */
    ldr     r0, =test_C
    ldr     r0, [r0]
    mov     r1, r9              @ B2
    mov     r2, #24
    ldr     r3, =test_hn
    ldr     r3, [r3]
    bl      fscx_revolve_n
    eor     r0, r0, r8          @ ^ A2
    ldr     r3, =test_val
    ldr     r3, [r3]
    eor     r0, r0, r3          @ ^ plain
    /* store E in test_C (reuse) */
    ldr     r3, =test_C
    str     r0, [r3]            @ test_C = E

    /* D = fscx_revolve_n(C2, B, 24, hn) ^ A ^ E */
    ldr     r0, =test_C2
    ldr     r0, [r0]
    mov     r1, r7              @ B
    mov     r2, #24
    ldr     r3, =test_hn
    ldr     r3, [r3]
    bl      fscx_revolve_n
    eor     r0, r0, r6          @ ^ A
    ldr     r3, =test_C
    ldr     r3, [r3]            @ E
    eor     r0, r0, r3          @ ^ E  => D

    /* compare D == plain */
    ldr     r1, =test_val
    ldr     r1, [r1]
    cmp     r0, r1
    bne     hpke_no_pass
    add     r5, r5, #1
hpke_no_pass:
    subs    r4, r4, #1
    bne     hpke_loop

    ldr     r0, =fmt_result
    mov     r1, r5
    cmp     r5, #100
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
/* fscx_revolve: r0=A, r1=B, r2=rounds -> r0=result                  */
/*   FSCX(A,B) = A^B^ROL(A,1)^ROL(B,1)^ROR(A,1)^ROR(B,1)            */
/*   Clobbers r4-r6 (saved/restored)                                  */
/* ------------------------------------------------------------------ */
    .thumb_func
fscx_revolve:
    push    {r4-r7, lr}
    mov     r4, r0
3:
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
    bne     3b
    mov     r0, r4
    pop     {r4-r7, pc}

    .ltorg

/* ------------------------------------------------------------------ */
/* fscx_revolve_n: r0=A, r1=B, r2=rounds, r3=nonce -> r0=result      */
/*   Each step: result = FSCX(result, B) ^ nonce                      */
/*   Clobbers r4-r6 (saved/restored)                                  */
/* ------------------------------------------------------------------ */
    .thumb_func
fscx_revolve_n:
    push    {r4-r7, lr}
    mov     r4, r0
4:
    eor     r5, r4, r1          @ A ^ B
    ror     r6, r4, #1
    eor     r5, r5, r6          @ ^ ROR(A,1)
    ror     r6, r1, #1
    eor     r5, r5, r6          @ ^ ROR(B,1)
    ror     r6, r4, #31
    eor     r5, r5, r6          @ ^ ROL(A,1)
    ror     r6, r1, #31
    eor     r5, r5, r6          @ ^ ROL(B,1)
    eor     r5, r5, r3          @ ^ nonce
    mov     r4, r5
    subs    r2, r2, #1
    bne     4b
    mov     r0, r4
    pop     {r4-r7, pc}

    .ltorg

    .section .note.GNU-stack,"",%progbits
