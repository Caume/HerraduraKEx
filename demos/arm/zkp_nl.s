/*  demos/arm/zkp_nl.s -- ZKP-NL ZKBoo proof (ARM Thumb-2, KEYBITS=32; TODO #425)
    One algorithm end to end: its sample inputs, every intermediate, and its
    verdict through the shared [FAIL] gate.  The routines and data are in
    core.s, included rather than linked.  Build: ./build_arm.sh;
    run: ./run_arm.sh suite.
*/
    .include "core.s"

    .data
demo_name:  .asciz "ZKP-NL ZKBoo proof"
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

    /* ── ZKP-NL demo (NL-FSCX ZKBoo; n=8, R=4) ───────────────────── */
    ldr     r0, =fmt_zkp_nl_hdr
    bl      hprintf
    bl      prng_next
    and     r4, r0, #0xFF       @ A
    bl      prng_next
    and     r5, r0, #0xFF       @ B
    bl      prng_next
    and     r6, r0, #0xFF       @ msg
    mov     r0, r4
    mov     r1, r5
    bl      nl_fscx_v1
    and     r7, r0, #0xFF       @ y = nl_fscx_v1(A,B) & 0xFF
    mov     r0, r4
    mov     r1, r5
    mov     r2, r7
    mov     r3, r6
    bl      zkp_nl_prove_8
    mov     r0, r5              @ B
    mov     r1, r7              @ y
    mov     r2, r6              @ msg
    bl      zkp_nl_verify_8
    cmp     r0, #1
    beq     .zkp_nl_suite_ok
    ldr     r0, =fmt_zkp_nl_fail
    bl      hprintf
    b       .zkp_nl_suite_done
.zkp_nl_suite_ok:
    ldr     r0, =fmt_zkp_nl_ok
    bl      hprintf
.zkp_nl_suite_done:

    b       demo_finish

    .ltorg
