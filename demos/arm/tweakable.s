/*  demos/arm/tweakable.s -- Tweakable cipher (ARM Thumb-2, KEYBITS=32; TODO #425)
    One algorithm end to end: its sample inputs, every intermediate, and its
    verdict through the shared [FAIL] gate.  The routines and data are in
    core.s, included rather than linked.  Build: ./build_arm.sh;
    run: ./run_arm.sh suite.
*/
    .include "core.s"

    .data
demo_name:  .asciz "Tweakable cipher"
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

    /* ── Tweakable cipher (78.B): B = hfscx_32(hfscx_32(key^sector) ^ bidx) */
    ldr     r0, =fmt_twk_hdr
    bl      hprintf
    bl      prng_next
    mov     r4, r0                  @ block (random)
    ldr     r5, =0x12345678         @ key
    mov     r6, #7                  @ sector
    mov     r9, #3                  @ bidx
    mov     r0, r5
    eor     r0, r0, r6
    bl      hfscx_32
    eor     r0, r0, r9
    bl      hfscx_32
    mov     r7, r0                  @ B
    mov     r0, r4
    mov     r1, r7
    mov     r2, #I_VALUE
    bl      nl_fscx_revolve_v2
    mov     r8, r0                  @ ct
    mov     r0, r8
    mov     r1, r7
    mov     r2, #I_VALUE
    bl      nl_fscx_revolve_v2_inv
    cmp     r0, r4
    beq     twk_suite_ok
    ldr     r0, =fmt_twk_fail
    bl      hprintf
    b       twk_suite_done
twk_suite_ok:
    ldr     r0, =fmt_twk_ok
    bl      hprintf
twk_suite_done:

    b       demo_finish

    .ltorg
