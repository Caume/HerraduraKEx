/*  demos/arm/hske_nl_a2.s -- HSKE-NL-A2 revolve-mode encryption (ARM Thumb-2, KEYBITS=32; TODO #425)
    One algorithm end to end: its sample inputs, every intermediate, and its
    verdict through the shared [FAIL] gate.  The routines and data are in
    core.s, included rather than linked.  Build: ./build_arm.sh;
    run: ./run_arm.sh suite.
*/
    .include "core.s"

    .data
demo_name:  .asciz "HSKE-NL-A2 revolve-mode encryption"
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

    ldr     r0, =fmt_hex
    ldr     r1, =lbl_apriv
    ldr     r2, =val_a_priv
    ldr     r2, [r2]
    bl      hprintf
    ldr     r0, =fmt_hex
    ldr     r1, =lbl_bpriv
    ldr     r2, =val_b_priv
    ldr     r2, [r2]
    bl      hprintf
    ldr     r0, =fmt_hex
    ldr     r1, =lbl_key
    ldr     r2, =val_key
    ldr     r2, [r2]
    bl      hprintf
    ldr     r0, =fmt_hex
    ldr     r1, =lbl_plain
    ldr     r2, =val_plain
    ldr     r2, [r2]
    bl      hprintf
    ldr     r0, =fmt_nl
    bl      hprintf

    /* ================================================================
       HSKE-NL-A2  (revolve-mode with NL-FSCX v2)
       E = nl_fscx_revolve_v2(plain, key, R_VALUE)
       D = nl_fscx_revolve_v2_inv(E, key, R_VALUE)  must == plain
       CAUTION: deterministic — same (plain, key) always yields same E.
       ================================================================ */
    ldr     r0, =fmt_hske_nl2_hdr
    bl      hprintf

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
    bl      hprintf
    ldr     r0, =fmt_hex
    ldr     r1, =lbl_D_nl2
    ldr     r2, =val_D_nl2
    ldr     r2, [r2]
    bl      hprintf

    ldr     r0, =val_D_nl2
    ldr     r0, [r0]
    ldr     r1, =val_plain
    ldr     r1, [r1]
    cmp     r0, r1
    bne     hske_nl2_fail
    ldr     r0, =fmt_ok
    bl      hprintf
    b       hske_nl2_done
hske_nl2_fail:
    ldr     r0, =fmt_fail
    bl      hprintf
hske_nl2_done:
    ldr     r0, =fmt_nl
    bl      hprintf

    b       demo_finish

    .ltorg
