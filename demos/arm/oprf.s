/*  demos/arm/oprf.s -- OPRF (ARM Thumb-2, KEYBITS=32; TODO #425)
    One algorithm end to end: its sample inputs, every intermediate, and its
    verdict through the shared [FAIL] gate.  The routines and data are in
    core.s, included rather than linked.  Build: ./build_arm.sh;
    run: ./run_arm.sh suite.
*/
    .include "core.s"

    .data
demo_name:  .asciz "OPRF"
    .balign 4

    .text
    .global main
    .thumb_func
main:
    push    {r4-r11, lr}
    bl      demo_start
    ldr     r0, =fmt_demo_hdr
    ldr     r1, =demo_name
    bl      hprintf

    /* ── OPRF (80) demo — blind/eval/unblind, n=32 ──────────────────── */
    /* Key k=0x13579BDF; blinding scalar r=7; r_inv=0x49249249 (7^{-1} mod 2^32-1) */
    ldr     r0, =fmt_oprf_hdr
    bl      hprintf

    @ H(x) = hfscx_32(0x50415353)  ["PASS" as 32-bit word]
    ldr     r0, =0x50415353
    bl      hfscx_32
    cmp     r0, #0
    it      eq
    moveq   r0, #1                  @ zero-guard
    mov     r4, r0                  @ r4 = H(x)
    ldr     r3, =val_oprf_hx
    str     r4, [r3]
    ldr     r0, =fmt_hex
    ldr     r1, =lbl_oprf_hx
    mov     r2, r4
    bl      hprintf

    @ alpha = H(x)^r,  r = 7  (client blind)
    mov     r0, r4
    mov     r1, #7
    bl      gf_pow_32
    mov     r5, r0                  @ r5 = alpha
    ldr     r3, =val_oprf_alpha
    str     r5, [r3]
    ldr     r0, =fmt_hex
    ldr     r1, =lbl_oprf_alpha
    mov     r2, r5
    bl      hprintf

    @ beta = alpha^k,  k = 0x13579BDF  (server eval)
    mov     r0, r5
    ldr     r1, =0x13579BDF
    bl      gf_pow_32
    mov     r6, r0                  @ r6 = beta
    ldr     r3, =val_oprf_beta
    str     r6, [r3]
    ldr     r0, =fmt_hex
    ldr     r1, =lbl_oprf_beta
    mov     r2, r6
    bl      hprintf

    @ F = beta^r_inv,  r_inv = 0x49249249 = 7^{-1} mod (2^32-1)  (client unblind)
    mov     r0, r6
    ldr     r1, =0x49249249
    bl      gf_pow_32
    mov     r7, r0                  @ r7 = F
    ldr     r3, =val_oprf_F
    str     r7, [r3]
    ldr     r0, =fmt_hex
    ldr     r1, =lbl_oprf_F
    mov     r2, r7
    bl      hprintf

    @ F_direct = H(x)^k  (should equal F — verifies blind/eval/unblind correctness)
    mov     r0, r4
    ldr     r1, =0x13579BDF
    bl      gf_pow_32
    ldr     r3, =val_oprf_Fd
    str     r0, [r3]

    cmp     r0, r7
    beq     oprf_suite_ok
    ldr     r0, =fmt_oprf_fail
    bl      hprintf
    b       oprf_suite_done
oprf_suite_ok:
    ldr     r0, =fmt_oprf_ok
    bl      hprintf
oprf_suite_done:

    b       demo_finish

    .ltorg
