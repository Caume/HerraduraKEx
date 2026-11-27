/*  demos/arm/zkp_rnl.s -- ZKP-RNL Ring-LWR Sigma proof (ARM Thumb-2, KEYBITS=32; TODO #425)
    One algorithm end to end: its sample inputs, every intermediate, and its
    verdict through the shared [FAIL] gate.  The routines and data are in
    core.s, included rather than linked.  Build: ./build_arm.sh;
    run: ./run_arm.sh suite.
*/
    .include "core.s"

    .data
demo_name:  .asciz "ZKP-RNL Ring-LWR Sigma proof"
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
    /* ================================================================
       ZKP-RNL  (Ring-LWR Sigma-protocol, N=32, gamma=4096, t=4)
       Reuses rnl_s_A / rnl_m_blind / rnl_C_A from the HKEX-RNL section.
       ================================================================ */
    ldr     r0, =fmt_zkp_rnl_hdr
    bl      hprintf

    ldr     r0, =fmt_hex
    ldr     r1, =lbl_sigma_msg
    ldr     r2, =sigma_demo_msg
    ldr     r2, [r2]
    bl      hprintf

    ldr     r0, =sigma_demo_msg
    ldr     r0, [r0]
    bl      rnl_sigma_sign_32
    cmp     r0, #0
    bne     zkp_rnl_sign_fail

    ldr     r0, =sigma_demo_msg
    ldr     r0, [r0]
    bl      rnl_sigma_verify_32
    cmp     r0, #1
    bne     zkp_rnl_verify_fail
    ldr     r0, =fmt_zkp_rnl_ok
    bl      hprintf
    b       zkp_rnl_done
zkp_rnl_sign_fail:
    ldr     r0, =fmt_zkp_rnl_fail
    bl      hprintf
    b       zkp_rnl_done
zkp_rnl_verify_fail:
    ldr     r0, =fmt_zkp_rnl_fail
    bl      hprintf
zkp_rnl_done:
    ldr     r0, =fmt_nl
    bl      hprintf

    b       demo_finish

    .ltorg
