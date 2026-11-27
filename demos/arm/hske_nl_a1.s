/*  demos/arm/hske_nl_a1.s -- HSKE-NL-A1 counter-mode encryption (ARM Thumb-2, KEYBITS=32; TODO #425)
    One algorithm end to end: its sample inputs, every intermediate, and its
    verdict through the shared [FAIL] gate.  The routines and data are in
    core.s, included rather than linked.  Build: ./build_arm.sh;
    run: ./run_arm.sh suite.
*/
    .include "core.s"

    .data
demo_name:  .asciz "HSKE-NL-A1 counter-mode encryption"
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
       HSKE-NL-A1  (counter-mode with NL-FSCX v1)
       N = prng_next(); base = key XOR N; ks = nl_fscx_revolve_v1(ROL(base,4) ^ DC, base, V1_MODE_STEPS)
       E = plain XOR ks;  D = E XOR ks  (must == plain)
       ================================================================ */
    ldr     r0, =fmt_hske_nl1_hdr
    bl      hprintf

    bl      prng_next               @ r0 = nonce N
    ldr     r3, =val_nonce_nl1
    str     r0, [r3]                @ save N
    ldr     r1, =val_key
    ldr     r1, [r1]
    eor     r0, r0, r1              @ r0 = base = N XOR key
    mov     r1, r0                  @ r1 = B = base (counter=0)
    ror     r0, r0, #28             @ r0 = ROL(base, 4)         [n=32, n/8=4]
    ldr     r2, =RNL_KDF_DC
    eor     r0, r0, r2              @ r0 = seed = ROL(base,4) XOR DC
    mov     r2, #V1_MODE_STEPS      @ 3n/4 (TODO #349)
    bl      nl_fscx_revolve_v1      @ r0 = ks  (A=seed, B=base)
    ldr     r3, =val_ks_nl1
    str     r0, [r3]

    ldr     r4, =val_plain
    ldr     r4, [r4]
    ldr     r5, =val_ks_nl1
    ldr     r5, [r5]
    eor     r4, r4, r5
    ldr     r3, =val_E_nl1
    str     r4, [r3]
    eor     r4, r4, r5
    ldr     r3, =val_D_nl1
    str     r4, [r3]

    ldr     r0, =fmt_hex
    ldr     r1, =lbl_N_nl1
    ldr     r2, =val_nonce_nl1
    ldr     r2, [r2]
    bl      hprintf
    ldr     r0, =fmt_hex
    ldr     r1, =lbl_E_nl1
    ldr     r2, =val_E_nl1
    ldr     r2, [r2]
    bl      hprintf
    ldr     r0, =fmt_hex
    ldr     r1, =lbl_D_nl1
    ldr     r2, =val_D_nl1
    ldr     r2, [r2]
    bl      hprintf

    ldr     r0, =val_D_nl1
    ldr     r0, [r0]
    ldr     r1, =val_plain
    ldr     r1, [r1]
    cmp     r0, r1
    bne     hske_nl1_fail
    ldr     r0, =fmt_ok
    bl      hprintf
    b       hske_nl1_done
hske_nl1_fail:
    ldr     r0, =fmt_fail
    bl      hprintf
hske_nl1_done:
    ldr     r0, =fmt_nl
    bl      hprintf

    b       demo_finish

    .ltorg
