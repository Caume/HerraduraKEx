/*  demos/arm/hpke_nl.s -- HPKE-NL El Gamal encryption (ARM Thumb-2, KEYBITS=32; TODO #425)
    One algorithm end to end: its sample inputs, every intermediate, and its
    verdict through the shared [FAIL] gate.  The routines and data are in
    core.s, included rather than linked.  Build: ./build_arm.sh;
    run: ./run_arm.sh suite.
*/
    .include "core.s"

    .data
demo_name:  .asciz "HPKE-NL El Gamal encryption"
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
       HPKE-NL  (NL-hardened El Gamal: NL-FSCX v2 encrypt)
       ================================================================ */
    ldr     r0, =fmt_hpke_nl_hdr
    bl      hprintf

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
    bne     hpke_nl_fail
    ldr     r0, =fmt_ok
    bl      hprintf
    b       hpke_nl_done
hpke_nl_fail:
    ldr     r0, =fmt_fail
    bl      hprintf
hpke_nl_done:
    ldr     r0, =fmt_nl
    bl      hprintf

    /* ================================================================ EVE tests */
    ldr     r0, =fmt_eve_hdr
    bl      hprintf

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
    bl      hprintf
    b       eve_hpke_done
eve_hpke_fail:
    ldr     r0, =fmt_eve_fail
    bl      hprintf
eve_hpke_done:

    b       demo_finish

    .ltorg
