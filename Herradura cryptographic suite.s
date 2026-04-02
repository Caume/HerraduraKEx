/*  Herradura Cryptographic Suite v1.3.7
    ARM 32-bit Thumb Assembly (GAS) — HKEX, HSKE, HPKS, HPKE with FSCX_REVOLVE_N
    KEYBITS = 32, I_VALUE = 8, R_VALUE = 24

    Copyright (C) 2024-2026 Omar Alejandro Herrera Reyna
    MIT License / GPL v3.0 — choose either.

    Build: arm-linux-gnueabi-gcc -o "Herradura cryptographic suite_arm" "Herradura cryptographic suite.s"
    Run:   qemu-arm "./Herradura cryptographic suite_arm"
        or directly on ARM hardware
*/

    .syntax unified
    .cpu cortex-a7
    .thumb

    .extern printf
    .extern exit

/* ------------------------------------------------------------------ */
/* .data section: constants, test vectors, result storage             */
/* ------------------------------------------------------------------ */
    .data
    .balign 4

/* -- format strings -- */
fmt_header: .asciz "=== Herradura Cryptographic Suite (ARM 32-bit Thumb, KEYBITS=32) ===\n"
fmt_hex:    .asciz "%s: 0x%08x\n"
fmt_nl:     .asciz "\n"

lbl_A:      .asciz "A        "
lbl_B:      .asciz "B        "
lbl_A2:     .asciz "A2       "
lbl_B2:     .asciz "B2       "
lbl_key:    .asciz "key      "
lbl_plain:  .asciz "plain    "
lbl_C:      .asciz "C        "
lbl_C2:     .asciz "C2       "
lbl_hn:     .asciz "hkex_nonce"
lbl_skeyA:  .asciz "skeyA    "
lbl_skeyB:  .asciz "skeyB    "
lbl_E_hske: .asciz "E (HSKE) "
lbl_D_hske: .asciz "D (HSKE) "
lbl_S_hpks: .asciz "S (HPKS) "
lbl_V_hpks: .asciz "V (HPKS) "
lbl_E_hpke: .asciz "E (HPKE) "
lbl_D_hpke: .asciz "D (HPKE) "

fmt_hkex_hdr:   .asciz "-- HKEX --\n"
fmt_hske_hdr:   .asciz "-- HSKE --\n"
fmt_hpks_hdr:   .asciz "-- HPKS --\n"
fmt_hpke_hdr:   .asciz "-- HPKE --\n"

fmt_hkex_ok:    .asciz "+ HKEX correct!\n"
fmt_hkex_fail:  .asciz "- HKEX INCORRECT!\n"
fmt_hske_ok:    .asciz "+ HSKE correct!\n"
fmt_hske_fail:  .asciz "- HSKE INCORRECT!\n"
fmt_hpks_ok:    .asciz "+ HPKS correct!\n"
fmt_hpks_fail:  .asciz "- HPKS INCORRECT!\n"
fmt_hpke_ok:    .asciz "+ HPKE correct!\n"
fmt_hpke_fail:  .asciz "- HPKE INCORRECT!\n"

    .balign 4
/* -- fixed test vectors -- */
val_A:      .word 0xDEADBEEF
val_B:      .word 0xCAFEBABE
val_A2:     .word 0x12345678
val_B2:     .word 0xABCDEF01
val_key:    .word 0x5A5A5A5A
val_plain:  .word 0xDEADC0DE

/* -- derived / result storage -- */
val_C:      .word 0
val_C2:     .word 0
val_hn:     .word 0
val_skeyA:  .word 0
val_skeyB:  .word 0
val_E_hske: .word 0
val_D_hske: .word 0
val_S_hpks: .word 0
val_V_hpks: .word 0
val_E_hpke: .word 0
val_D_hpke: .word 0

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

    /* ---- print header ---- */
    ldr     r0, =fmt_header
    bl      printf

    /* ================================================================
       Compute C = fscx_revolve(A, B, I_VALUE=8)
       ================================================================ */
    ldr     r0, =val_A
    ldr     r0, [r0]
    ldr     r1, =val_B
    ldr     r1, [r1]
    mov     r2, #8
    bl      fscx_revolve
    ldr     r3, =val_C
    str     r0, [r3]

    /* ================================================================
       Compute C2 = fscx_revolve(A2, B2, I_VALUE=8)
       ================================================================ */
    ldr     r0, =val_A2
    ldr     r0, [r0]
    ldr     r1, =val_B2
    ldr     r1, [r1]
    mov     r2, #8
    bl      fscx_revolve
    ldr     r3, =val_C2
    str     r0, [r3]

    /* ================================================================
       Compute hkex_nonce = C ^ C2
       ================================================================ */
    ldr     r0, =val_C
    ldr     r0, [r0]
    ldr     r1, =val_C2
    ldr     r1, [r1]
    eor     r0, r0, r1
    ldr     r3, =val_hn
    str     r0, [r3]

    /* ----------------------------------------------------------------
       Print shared values
       ---------------------------------------------------------------- */
    ldr     r0, =fmt_hex
    ldr     r1, =lbl_A
    ldr     r2, =val_A
    ldr     r2, [r2]
    bl      printf

    ldr     r0, =fmt_hex
    ldr     r1, =lbl_B
    ldr     r2, =val_B
    ldr     r2, [r2]
    bl      printf

    ldr     r0, =fmt_hex
    ldr     r1, =lbl_A2
    ldr     r2, =val_A2
    ldr     r2, [r2]
    bl      printf

    ldr     r0, =fmt_hex
    ldr     r1, =lbl_B2
    ldr     r2, =val_B2
    ldr     r2, [r2]
    bl      printf

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
    ldr     r1, =lbl_hn
    ldr     r2, =val_hn
    ldr     r2, [r2]
    bl      printf

    ldr     r0, =fmt_nl
    bl      printf

    /* ================================================================
       HKEX
       skeyA = fscx_revolve_n(C2, B, R_VALUE=24, hn) ^ A
       skeyB = fscx_revolve_n(C,  B2, R_VALUE=24, hn) ^ A2
       ================================================================ */
    ldr     r0, =fmt_hkex_hdr
    bl      printf

    /* skeyA */
    ldr     r0, =val_C2
    ldr     r0, [r0]
    ldr     r1, =val_B
    ldr     r1, [r1]
    mov     r2, #24
    ldr     r3, =val_hn
    ldr     r3, [r3]
    bl      fscx_revolve_n
    ldr     r3, =val_A
    ldr     r3, [r3]
    eor     r0, r0, r3
    ldr     r3, =val_skeyA
    str     r0, [r3]

    /* skeyB */
    ldr     r0, =val_C
    ldr     r0, [r0]
    ldr     r1, =val_B2
    ldr     r1, [r1]
    mov     r2, #24
    ldr     r3, =val_hn
    ldr     r3, [r3]
    bl      fscx_revolve_n
    ldr     r3, =val_A2
    ldr     r3, [r3]
    eor     r0, r0, r3
    ldr     r3, =val_skeyB
    str     r0, [r3]

    /* print skeyA, skeyB */
    ldr     r0, =fmt_hex
    ldr     r1, =lbl_skeyA
    ldr     r2, =val_skeyA
    ldr     r2, [r2]
    bl      printf

    ldr     r0, =fmt_hex
    ldr     r1, =lbl_skeyB
    ldr     r2, =val_skeyB
    ldr     r2, [r2]
    bl      printf

    /* verify HKEX */
    ldr     r0, =val_skeyA
    ldr     r0, [r0]
    ldr     r1, =val_skeyB
    ldr     r1, [r1]
    cmp     r0, r1
    bne     hkex_fail
    ldr     r0, =fmt_hkex_ok
    bl      printf
    b       hkex_done
hkex_fail:
    ldr     r0, =fmt_hkex_fail
    bl      printf
hkex_done:
    ldr     r0, =fmt_nl
    bl      printf

    /* ================================================================
       HSKE
       E = fscx_revolve_n(plain, key, I_VALUE=8, key)
       D = fscx_revolve_n(E,     key, R_VALUE=24, key)
       assert D == plain
       ================================================================ */
    ldr     r0, =fmt_hske_hdr
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

    /* E = fscx_revolve_n(plain, key, 8, key) */
    ldr     r0, =val_plain
    ldr     r0, [r0]
    ldr     r1, =val_key
    ldr     r1, [r1]
    mov     r2, #8
    ldr     r3, =val_key
    ldr     r3, [r3]
    bl      fscx_revolve_n
    ldr     r3, =val_E_hske
    str     r0, [r3]

    /* D = fscx_revolve_n(E, key, 24, key) */
    ldr     r0, =val_E_hske
    ldr     r0, [r0]
    ldr     r1, =val_key
    ldr     r1, [r1]
    mov     r2, #24
    ldr     r3, =val_key
    ldr     r3, [r3]
    bl      fscx_revolve_n
    ldr     r3, =val_D_hske
    str     r0, [r3]

    /* print */
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

    /* verify */
    ldr     r0, =val_D_hske
    ldr     r0, [r0]
    ldr     r1, =val_plain
    ldr     r1, [r1]
    cmp     r0, r1
    bne     hske_fail
    ldr     r0, =fmt_hske_ok
    bl      printf
    b       hske_done
hske_fail:
    ldr     r0, =fmt_hske_fail
    bl      printf
hske_done:
    ldr     r0, =fmt_nl
    bl      printf

    /* ================================================================
       HPKS
       S = fscx_revolve_n(C2, B, R=24, hn) ^ A ^ plain
       V = fscx_revolve_n(C, B2, R=24, hn) ^ A2 ^ S
       assert V == plain
       ================================================================ */
    ldr     r0, =fmt_hpks_hdr
    bl      printf

    /* S = fscx_revolve_n(C2, B, 24, hn) ^ A ^ plain */
    ldr     r0, =val_C2
    ldr     r0, [r0]
    ldr     r1, =val_B
    ldr     r1, [r1]
    mov     r2, #24
    ldr     r3, =val_hn
    ldr     r3, [r3]
    bl      fscx_revolve_n
    ldr     r3, =val_A
    ldr     r3, [r3]
    eor     r0, r0, r3
    ldr     r3, =val_plain
    ldr     r3, [r3]
    eor     r0, r0, r3
    ldr     r3, =val_S_hpks
    str     r0, [r3]

    /* V = fscx_revolve_n(C, B2, 24, hn) ^ A2 ^ S */
    ldr     r0, =val_C
    ldr     r0, [r0]
    ldr     r1, =val_B2
    ldr     r1, [r1]
    mov     r2, #24
    ldr     r3, =val_hn
    ldr     r3, [r3]
    bl      fscx_revolve_n
    ldr     r3, =val_A2
    ldr     r3, [r3]
    eor     r0, r0, r3
    ldr     r3, =val_S_hpks
    ldr     r3, [r3]
    eor     r0, r0, r3
    ldr     r3, =val_V_hpks
    str     r0, [r3]

    /* print */
    ldr     r0, =fmt_hex
    ldr     r1, =lbl_S_hpks
    ldr     r2, =val_S_hpks
    ldr     r2, [r2]
    bl      printf

    ldr     r0, =fmt_hex
    ldr     r1, =lbl_V_hpks
    ldr     r2, =val_V_hpks
    ldr     r2, [r2]
    bl      printf

    /* verify */
    ldr     r0, =val_V_hpks
    ldr     r0, [r0]
    ldr     r1, =val_plain
    ldr     r1, [r1]
    cmp     r0, r1
    bne     hpks_fail
    ldr     r0, =fmt_hpks_ok
    bl      printf
    b       hpks_done
hpks_fail:
    ldr     r0, =fmt_hpks_fail
    bl      printf
hpks_done:
    ldr     r0, =fmt_nl
    bl      printf

    /* ================================================================
       HPKE
       E = fscx_revolve_n(C, B2, R=24, hn) ^ A2 ^ plain
       D = fscx_revolve_n(C2, B, R=24, hn) ^ A ^ E
       assert D == plain
       ================================================================ */
    ldr     r0, =fmt_hpke_hdr
    bl      printf

    /* E = fscx_revolve_n(C, B2, 24, hn) ^ A2 ^ plain */
    ldr     r0, =val_C
    ldr     r0, [r0]
    ldr     r1, =val_B2
    ldr     r1, [r1]
    mov     r2, #24
    ldr     r3, =val_hn
    ldr     r3, [r3]
    bl      fscx_revolve_n
    ldr     r3, =val_A2
    ldr     r3, [r3]
    eor     r0, r0, r3
    ldr     r3, =val_plain
    ldr     r3, [r3]
    eor     r0, r0, r3
    ldr     r3, =val_E_hpke
    str     r0, [r3]

    /* D = fscx_revolve_n(C2, B, 24, hn) ^ A ^ E */
    ldr     r0, =val_C2
    ldr     r0, [r0]
    ldr     r1, =val_B
    ldr     r1, [r1]
    mov     r2, #24
    ldr     r3, =val_hn
    ldr     r3, [r3]
    bl      fscx_revolve_n
    ldr     r3, =val_A
    ldr     r3, [r3]
    eor     r0, r0, r3
    ldr     r3, =val_E_hpke
    ldr     r3, [r3]
    eor     r0, r0, r3
    ldr     r3, =val_D_hpke
    str     r0, [r3]

    /* print */
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

    /* verify */
    ldr     r0, =val_D_hpke
    ldr     r0, [r0]
    ldr     r1, =val_plain
    ldr     r1, [r1]
    cmp     r0, r1
    bne     hpke_fail
    ldr     r0, =fmt_hpke_ok
    bl      printf
    b       hpke_done
hpke_fail:
    ldr     r0, =fmt_hpke_fail
    bl      printf
hpke_done:

    mov     r0, #0
    bl      exit

    .ltorg

/* ------------------------------------------------------------------ */
/* fscx_revolve: r0=A, r1=B, r2=rounds -> r0=result                  */
/*   FSCX(A,B) = A^B^ROL(A,1)^ROL(B,1)^ROR(A,1)^ROR(B,1)            */
/*   ROL(x,1)  = ROR(x,31)  in ARM rotate terms                       */
/*   ROR(x,1)  = ROR(x,1)                                             */
/*   Clobbers r4-r6 (saved/restored via push/pop)                     */
/* ------------------------------------------------------------------ */
    .thumb_func
fscx_revolve:
    push    {r4-r7, lr}
    mov     r4, r0              @ r4 = current A (evolves each round)
                                @ r1 = B (constant)
1:
    eor     r5, r4, r1          @ r5 = A ^ B
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
    bne     1b
    mov     r0, r4
    pop     {r4-r7, pc}

    .ltorg

/* ------------------------------------------------------------------ */
/* fscx_revolve_n: r0=A, r1=B, r2=rounds, r3=nonce -> r0=result      */
/*   Each step: result = FSCX(result, B) ^ nonce                      */
/*   Clobbers r4-r6 (saved/restored via push/pop)                     */
/* ------------------------------------------------------------------ */
    .thumb_func
fscx_revolve_n:
    push    {r4-r7, lr}
    mov     r4, r0              @ r4 = current A
                                @ r1 = B (constant)
                                @ r3 = nonce (constant)
2:
    eor     r5, r4, r1          @ r5 = A ^ B
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
    bne     2b
    mov     r0, r4
    pop     {r4-r7, pc}

    .ltorg

    .section .note.GNU-stack,"",%progbits
