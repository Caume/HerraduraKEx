/*  demos/arm/hkex_rnl.s -- HKEX-RNL Ring-LWR key exchange (ARM Thumb-2, KEYBITS=32; TODO #425)
    One algorithm end to end: its sample inputs, every intermediate, and its
    verdict through the shared [FAIL] gate.  The routines and data are in
    core.s, included rather than linked.  Build: ./build_arm.sh;
    run: ./run_arm.sh suite.
*/
    .include "core.s"

    .data
demo_name:  .asciz "HKEX-RNL Ring-LWR key exchange"
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

    /* ================================================================
       HKEX-RNL  (Ring-LWR key exchange)
       ================================================================ */
    ldr     r0, =fmt_hkex_rnl_hdr
    bl      hprintf

    ldr     r0, =rnl_m_base
    bl      rnl_m_poly

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
    bl      rnl_agree_full          @ r0=KA, r1=hint_A
    ldr     r3, =val_KA
    str     r0, [r3]
    ldr     r3, =val_hint_A
    str     r1, [r3]

    ldr     r0, =rnl_s_B
    ldr     r1, =rnl_C_A
    ldr     r2, =val_hint_A
    ldr     r2, [r2]
    bl      rnl_agree_recv          @ r0=KB
    ldr     r3, =val_KB
    str     r0, [r3]

    ldr     r0, =val_KA
    ldr     r0, [r0]
    ror     r0, r0, #28         @ ROL32(KA, 4)           [n/8 = 32/8 = 4]
    ldr     r3, =RNL_KDF_DC
    eor     r0, r0, r3          @ seed = ROL(KA,4) XOR DC
    ldr     r1, =val_KA
    ldr     r1, [r1]            @ B = KA
    mov     r2, #I_VALUE
    bl      nl_fscx_revolve_v1  @ r0 = sk
    ldr     r3, =val_sk_rnl
    str     r0, [r3]

    ldr     r0, =fmt_hex
    ldr     r1, =lbl_Ka
    ldr     r2, =val_KA
    ldr     r2, [r2]
    bl      hprintf
    ldr     r0, =fmt_hex
    ldr     r1, =lbl_Kb
    ldr     r2, =val_KB
    ldr     r2, [r2]
    bl      hprintf
    ldr     r0, =fmt_hex
    ldr     r1, =lbl_sk_a
    ldr     r2, =val_sk_rnl
    ldr     r2, [r2]
    bl      hprintf

    ldr     r0, =val_KA
    ldr     r0, [r0]
    ldr     r1, =val_KB
    ldr     r1, [r1]
    cmp     r0, r1
    bne     hkex_rnl_noagree
    ldr     r0, =fmt_rnl_agree
    bl      hprintf
    b       hkex_rnl_done
hkex_rnl_noagree:
    ldr     r0, =fmt_rnl_noagree
    bl      hprintf
hkex_rnl_done:
    ldr     r0, =fmt_nl
    bl      hprintf

    /* ================================================================ EVE tests */
    ldr     r0, =fmt_eve_hdr
    bl      hprintf

    /* Eve random guess for HKEX-RNL */
    bl      prng_next
    ldr     r1, =val_sk_rnl
    ldr     r1, [r1]
    cmp     r0, r1
    beq     eve_rnl_fail
    ldr     r0, =fmt_eve_rnl_ok
    bl      hprintf
    b       eve_rnl_done
eve_rnl_fail:
    ldr     r0, =fmt_eve_fail
    bl      hprintf
eve_rnl_done:

    b       demo_finish

    .ltorg
