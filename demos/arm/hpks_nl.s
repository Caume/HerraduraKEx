/*  demos/arm/hpks_nl.s -- HPKS-NL Schnorr signature (ARM Thumb-2, KEYBITS=32; TODO #425)
    One algorithm end to end: its sample inputs, every intermediate, and its
    verdict through the shared [FAIL] gate.  The routines and data are in
    core.s, included rather than linked.  Build: ./build_arm.sh;
    run: ./run_arm.sh suite.
*/
    .include "core.s"

    .data
demo_name:  .asciz "HPKS-NL Schnorr signature"
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

    mov     r0, #3
    ldr     r1, =val_a_priv
    ldr     r1, [r1]
    bl      gf_pow_32
    ldr     r3, =val_C
    str     r0, [r3]
    /* ================================================================
       HPKS-NL  (NL-hardened Schnorr: HFSCX-32 challenge)
       ================================================================ */
    ldr     r0, =fmt_hpks_nl_hdr
    bl      hprintf

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
    bl      hpks_nl_challenge_32    @ e = HFSCX-32(TAG, R, P)  (TODO #348)
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
    bl      hprintf
    ldr     r0, =fmt_hex
    ldr     r1, =lbl_s_hpks
    ldr     r2, =val_s_hpks
    ldr     r2, [r2]
    bl      hprintf
    ldr     r0, =fmt_hex
    ldr     r1, =lbl_lhs
    pop     {r2}
    push    {r2}
    bl      hprintf

    pop     {r4}
    ldr     r5, =val_R_hpks
    ldr     r5, [r5]
    cmp     r4, r5
    bne     hpks_nl_fail
    ldr     r0, =fmt_ok
    bl      hprintf
    b       hpks_nl_done
hpks_nl_fail:
    ldr     r0, =fmt_fail
    bl      hprintf
hpks_nl_done:
    ldr     r0, =fmt_nl
    bl      hprintf

    /* Eve presents the same (R, s) for another message, plain ^ 1 */
    ldr     r0, =fmt_eve_hdr
    bl      hprintf
    ldr     r0, =val_R_hpks
    ldr     r0, [r0]
    ldr     r1, =val_plain
    ldr     r1, [r1]
    eor     r1, r1, #1
    bl      hpks_nl_challenge_32 @ e' = HFSCX-32(TAG, R, plain ^ 1)
    mov     r1, r0
    ldr     r0, =val_C
    ldr     r0, [r0]
    bl      gf_pow_32           @ C^e'
    mov     r1, r0
    ldr     r0, =val_gs_hpks
    ldr     r0, [r0]
    bl      gf_mul_32           @ g^s * C^e'
    ldr     r1, =val_R_hpks
    ldr     r1, [r1]
    cmp     r0, r1
    beq     eve_hpks_nl_fail
    ldr     r0, =fmt_eve_msg_ok
    bl      hprintf
    b       eve_hpks_nl_done
eve_hpks_nl_fail:
    ldr     r0, =fmt_eve_msg_fail
    bl      hprintf
eve_hpks_nl_done:

    b       demo_finish

    .ltorg
