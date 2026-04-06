/*  Herradura Cryptographic Suite v1.4.0
    ARM 32-bit Thumb Assembly (GAS) — HKEX-GF, HSKE, HPKS Schnorr, HPKE El Gamal
    KEYBITS = 32, I_VALUE = 8, R_VALUE = 24
    HKEX-GF: DH over GF(2^32)*, poly x^32+x^22+x^2+x+1, generator g=3
    HPKS:    Schnorr signature; s=(k-a*e) mod ORD; verify g^s*C^e==R
    HPKE:    El Gamal + fscx_revolve; enc_key=C^r; dec_key=R^a

    Copyright (C) 2024-2026 Omar Alejandro Herrera Reyna
    MIT License / GPL v3.0 — choose either.

    Build: arm-linux-gnueabi-gcc -o "Herradura cryptographic suite_arm" "Herradura cryptographic suite.s"
    Run:   qemu-arm "./Herradura cryptographic suite_arm"
        or directly on ARM hardware

    Test vectors (fixed):
        a_priv=0xDEADBEEF, b_priv=0xCAFEBABF
        C=0x5b8ae480, C2=0xad8f4a2c, sk=0xd3db6bc3
        key=0x5A5A5A5A, plain=0xDEADC0DE
        E_hske=0xadb3b3c0, D_hske=0xdeadc0de
        k (Schnorr nonce) and r (El Gamal ephemeral) are LCG-generated.
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
fmt_header: .asciz "=== Herradura Cryptographic Suite v1.4.0 (ARM 32-bit Thumb, KEYBITS=32, HKEX-GF) ===\n"
fmt_hex:    .asciz "%s: 0x%08x\n"
fmt_nl:     .asciz "\n"

lbl_apriv:  .asciz "a_priv    "
lbl_bpriv:  .asciz "b_priv    "
lbl_key:    .asciz "key       "
lbl_plain:  .asciz "plain     "
lbl_C:      .asciz "C         "
lbl_C2:     .asciz "C2        "
lbl_skeyA:  .asciz "skeyA     "
lbl_skeyB:  .asciz "skeyB     "
lbl_E_hske: .asciz "E (HSKE)  "
lbl_D_hske: .asciz "D (HSKE)  "
lbl_k_hpks: .asciz "k (nonce) "
lbl_R_hpks: .asciz "R (g^k)   "
lbl_e_hpks: .asciz "e (fscx)  "
lbl_s_hpks: .asciz "s (resp)  "
lbl_lhs:    .asciz "g^s*C^e   "
lbl_r_hpke: .asciz "r (ephem) "
lbl_R_hpke: .asciz "R (g^r)   "
lbl_E_hpke: .asciz "E (Bob)   "
lbl_D_hpke: .asciz "D (Alice) "

fmt_hkex_hdr:   .asciz "-- HKEX-GF --\n"
fmt_hske_hdr:   .asciz "-- HSKE --\n"
fmt_hpks_hdr:   .asciz "-- HPKS Schnorr --\n"
fmt_hpke_hdr:   .asciz "-- HPKE El Gamal --\n"

fmt_hkex_ok:    .asciz "+ HKEX-GF correct!\n"
fmt_hkex_fail:  .asciz "- HKEX-GF INCORRECT!\n"
fmt_hske_ok:    .asciz "+ HSKE correct!\n"
fmt_hske_fail:  .asciz "- HSKE INCORRECT!\n"
fmt_hpks_ok:    .asciz "+ HPKS Schnorr: g^s*C^e == R  correct!\n"
fmt_hpks_fail:  .asciz "- HPKS Schnorr: g^s*C^e != R  INCORRECT!\n"
fmt_hpke_ok:    .asciz "+ HPKE El Gamal correct!\n"
fmt_hpke_fail:  .asciz "- HPKE El Gamal INCORRECT!\n"

    .balign 4
/* -- fixed test vectors -- */
val_a_priv: .word 0xDEADBEEF
val_b_priv: .word 0xCAFEBABF
val_key:    .word 0x5A5A5A5A
val_plain:  .word 0xDEADC0DE

/* -- LCG PRNG for nonces (k, r) -- */
lcg_state:  .word 0xDEADBEEE  /* seed = a_priv - 1 */
lcg_mul:    .word 1664525
lcg_add:    .word 1013904223

/* -- derived / result storage -- */
val_C:      .word 0
val_C2:     .word 0
val_sk:     .word 0
val_skB:    .word 0
val_E_hske: .word 0
val_D_hske: .word 0
val_k_hpks: .word 0   /* Schnorr nonce k */
val_R_hpks: .word 0   /* R = g^k         */
val_e_hpks: .word 0   /* e = fscx(R,P,8) */
val_ae_hpks:.word 0   /* a*e mod ORD     */
val_s_hpks: .word 0   /* s = k-a*e mod ORD */
val_gs_hpks:.word 0   /* g^s             */
val_r_hpke: .word 0   /* El Gamal ephemeral r */
val_R_hpke: .word 0   /* R = g^r         */
val_enc_key:.word 0   /* enc_key = C^r   */
val_E_hpke: .word 0
val_dec_key:.word 0   /* dec_key = R^a   */
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

    /* ---- print inputs ---- */
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

    /* ================================================================
       HKEX-GF
       ================================================================ */
    ldr     r0, =fmt_hkex_hdr
    bl      printf

    /* C = gf_pow_32(3, a_priv) */
    mov     r0, #3
    ldr     r1, =val_a_priv
    ldr     r1, [r1]
    bl      gf_pow_32
    ldr     r3, =val_C
    str     r0, [r3]

    /* C2 = gf_pow_32(3, b_priv) */
    mov     r0, #3
    ldr     r1, =val_b_priv
    ldr     r1, [r1]
    bl      gf_pow_32
    ldr     r3, =val_C2
    str     r0, [r3]

    /* sk = gf_pow_32(C2, a_priv) */
    ldr     r0, =val_C2
    ldr     r0, [r0]
    ldr     r1, =val_a_priv
    ldr     r1, [r1]
    bl      gf_pow_32
    ldr     r3, =val_sk
    str     r0, [r3]

    /* skB = gf_pow_32(C, b_priv) */
    ldr     r0, =val_C
    ldr     r0, [r0]
    ldr     r1, =val_b_priv
    ldr     r1, [r1]
    bl      gf_pow_32
    ldr     r3, =val_skB
    str     r0, [r3]

    /* print C, C2, sk, skB */
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

    /* verify HKEX-GF: sk == skB */
    ldr     r0, =val_sk
    ldr     r0, [r0]
    ldr     r1, =val_skB
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
       ================================================================ */
    ldr     r0, =fmt_hske_hdr
    bl      printf

    /* E = fscx_revolve(plain, key, 8) */
    ldr     r0, =val_plain
    ldr     r0, [r0]
    ldr     r1, =val_key
    ldr     r1, [r1]
    mov     r2, #8
    bl      fscx_revolve
    ldr     r3, =val_E_hske
    str     r0, [r3]

    /* D = fscx_revolve(E, key, 24) */
    ldr     r0, =val_E_hske
    ldr     r0, [r0]
    ldr     r1, =val_key
    ldr     r1, [r1]
    mov     r2, #24
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
       HPKS Schnorr (public key signature, 32-bit)
       k   = prng_next()
       R   = gf_pow_32(3, k)
       e   = fscx_revolve(R, plain, 8)
       ae  = a_priv * e  mod ORD    [umull + lo+hi reduction]
       s   = (k - ae) mod ORD       [subs/subcc trick]
       Verify: gf_mul_32(gf_pow_32(3,s), gf_pow_32(C,e)) == R
       ================================================================ */
    ldr     r0, =fmt_hpks_hdr
    bl      printf

    /* k = prng_next() */
    bl      prng_next
    ldr     r3, =val_k_hpks
    str     r0, [r3]

    /* R = gf_pow_32(3, k) */
    mov     r0, #3
    ldr     r1, =val_k_hpks
    ldr     r1, [r1]
    bl      gf_pow_32
    ldr     r3, =val_R_hpks
    str     r0, [r3]

    /* e = fscx_revolve(R, plain, 8) */
    ldr     r0, =val_R_hpks
    ldr     r0, [r0]
    ldr     r1, =val_plain
    ldr     r1, [r1]
    mov     r2, #8
    bl      fscx_revolve
    ldr     r3, =val_e_hpks
    str     r0, [r3]

    /* ae_mod = a_priv * e  mod  ORD
       ORD = 2^32-1.  Since 2^32 == 1 (mod ORD):
         hi*2^32 + lo  ==  hi + lo  (mod ORD)
       If adds carries, add 1 to compensate the extra 2^32.             */
    ldr     r4, =val_a_priv
    ldr     r4, [r4]            @ r4 = a_priv
    ldr     r5, =val_e_hpks
    ldr     r5, [r5]            @ r5 = e
    umull   r6, r7, r4, r5      @ r7:r6 = a * e  (lo=r6, hi=r7)
    adds    r6, r6, r7          @ r6 = lo + hi;  C = carry
    it cs
    addcs   r6, r6, #1          @ if carry: r6 += 1
    ldr     r3, =val_ae_hpks
    str     r6, [r3]

    /* s = k - ae_mod  mod ORD
       subs sets C=0 (LO/CC condition) if k < ae_mod (borrow).
       If borrow occurred, wrapped value = k - ae_mod + 2^32;
       subtracting 1 gives k - ae_mod + (2^32 - 1) = k - ae_mod + ORD. */
    ldr     r4, =val_k_hpks
    ldr     r4, [r4]            @ r4 = k
    ldr     r5, =val_ae_hpks
    ldr     r5, [r5]            @ r5 = ae_mod
    subs    r4, r4, r5          @ r4 = k - ae_mod  (may underflow)
    it cc
    subcc   r4, r4, #1          @ if borrow: s = wrapped - 1
    ldr     r3, =val_s_hpks
    str     r4, [r3]

    /* Verify: g^s * C^e == R */
    /* gs = gf_pow_32(3, s) */
    mov     r0, #3
    ldr     r1, =val_s_hpks
    ldr     r1, [r1]
    bl      gf_pow_32
    ldr     r3, =val_gs_hpks
    str     r0, [r3]            @ gs = g^s

    /* Ce = gf_pow_32(C, e) */
    ldr     r0, =val_C
    ldr     r0, [r0]
    ldr     r1, =val_e_hpks
    ldr     r1, [r1]
    bl      gf_pow_32           @ r0 = C^e

    /* lhs = gf_mul_32(gs, Ce) */
    ldr     r1, =val_gs_hpks
    ldr     r1, [r1]            @ r1 = gs
    push    {r0}                @ save Ce
    mov     r0, r1              @ r0 = gs
    pop     {r1}                @ r1 = Ce
    bl      gf_mul_32           @ r0 = gs * Ce

    /* print results */
    ldr     r3, =val_k_hpks
    ldr     r2, [r3]
    push    {r0}
    ldr     r0, =fmt_hex
    ldr     r1, =lbl_k_hpks
    bl      printf
    pop     {r0}

    push    {r0}
    ldr     r0, =fmt_hex
    ldr     r1, =lbl_R_hpks
    ldr     r2, =val_R_hpks
    ldr     r2, [r2]
    bl      printf
    pop     {r0}

    push    {r0}
    ldr     r0, =fmt_hex
    ldr     r1, =lbl_e_hpks
    ldr     r2, =val_e_hpks
    ldr     r2, [r2]
    bl      printf
    pop     {r0}

    push    {r0}
    ldr     r0, =fmt_hex
    ldr     r1, =lbl_s_hpks
    ldr     r2, =val_s_hpks
    ldr     r2, [r2]
    bl      printf
    pop     {r0}

    /* compare lhs (in r0) with val_R_hpks */
    ldr     r1, =val_R_hpks
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
       HPKE El Gamal (public key encryption, 32-bit)
       r        = prng_next()
       R_hpke   = gf_pow_32(3, r)
       enc_key  = gf_pow_32(C, r)       [C^r = g^{ar}]
       E        = fscx_revolve(plain, enc_key, 8)
       dec_key  = gf_pow_32(R_hpke, a)  [R^a = g^{ra} = g^{ar}]
       D        = fscx_revolve(E, dec_key, 24)  == plain
       ================================================================ */
    ldr     r0, =fmt_hpke_hdr
    bl      printf

    /* r = prng_next() | 1  (odd ephemeral) */
    bl      prng_next
    orr     r0, r0, #1
    ldr     r3, =val_r_hpke
    str     r0, [r3]

    /* R_hpke = gf_pow_32(3, r) */
    mov     r0, #3
    ldr     r1, =val_r_hpke
    ldr     r1, [r1]
    bl      gf_pow_32
    ldr     r3, =val_R_hpke
    str     r0, [r3]

    /* enc_key = gf_pow_32(C, r) */
    ldr     r0, =val_C
    ldr     r0, [r0]
    ldr     r1, =val_r_hpke
    ldr     r1, [r1]
    bl      gf_pow_32
    ldr     r3, =val_enc_key
    str     r0, [r3]

    /* E = fscx_revolve(plain, enc_key, 8) */
    ldr     r0, =val_plain
    ldr     r0, [r0]
    ldr     r1, =val_enc_key
    ldr     r1, [r1]
    mov     r2, #8
    bl      fscx_revolve
    ldr     r3, =val_E_hpke
    str     r0, [r3]

    /* dec_key = gf_pow_32(R_hpke, a_priv) */
    ldr     r0, =val_R_hpke
    ldr     r0, [r0]
    ldr     r1, =val_a_priv
    ldr     r1, [r1]
    bl      gf_pow_32
    ldr     r3, =val_dec_key
    str     r0, [r3]

    /* D = fscx_revolve(E, dec_key, 24) */
    ldr     r0, =val_E_hpke
    ldr     r0, [r0]
    ldr     r1, =val_dec_key
    ldr     r1, [r1]
    mov     r2, #24
    bl      fscx_revolve
    ldr     r3, =val_D_hpke
    str     r0, [r3]

    /* print */
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

    /* verify D == plain */
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
/* prng_next: LCG — no args, returns new state in r0                  */
/*   state = state * 1664525 + 1013904223                             */
/*   Clobbers r1, r2                                                  */
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
/*   ROL(x,1)  = ROR(x,31)  in ARM rotate terms                       */
/*   Clobbers r4-r6 (saved/restored via push/pop)                     */
/* ------------------------------------------------------------------ */
    .thumb_func
fscx_revolve:
    push    {r4-r7, lr}
    mov     r4, r0              @ r4 = current A (evolves each round)
                                @ r1 = B (constant)
fscx_revolve_loop:
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
    bne     fscx_revolve_loop
    mov     r0, r4
    pop     {r4-r7, pc}

    .ltorg

    .section .note.GNU-stack,"",%progbits
