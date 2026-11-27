/*  demos/arm/ratchet.s -- Ratchet (ARM Thumb-2, KEYBITS=32; TODO #425)
    One algorithm end to end: its sample inputs, every intermediate, and its
    verdict through the shared [FAIL] gate.  The routines and data are in
    core.s, included rather than linked.  Build: ./build_arm.sh;
    run: ./run_arm.sh suite.
*/
    .include "core.s"

    .data
demo_name:  .asciz "Ratchet"
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

    /* ── 78.C — Ratchet demo (5 steps) ───────────────────────────── */
    ldr     r0, =fmt_ratch_hdr
    bl      hprintf
    @ seed state: prng_next as initial state
    bl      prng_next
    mov     r4, r0          @ state
    ldr     r5, =ratchet_domain_32
    ldr     r5, [r5]        @ domain constant
    mov     r6, #5          @ steps
    mov     r9, #0          @ seen[0] sentinel (first key)
    mov     r10, #1         @ all_unique flag
ratch_loop:
    @ msg_key = nl_fscx_revolve_v1(state, 0x01, 1)
    mov     r0, r4
    mov     r1, #1
    mov     r2, #1
    bl      nl_fscx_revolve_v1
    cmp     r6, #5
    bne     ratch_check_coll
    mov     r9, r0          @ save first key
    b       ratch_continue
ratch_check_coll:
    cmp     r10, #1         @ still unique?
    bne     ratch_continue
    cmp     r0, r9          @ collision with first key?
    bne     ratch_continue
    mov     r10, #0         @ mark not unique
ratch_continue:
    @ new_state = nl_fscx_revolve_v1(state, domain, 1)
    mov     r0, r4
    mov     r1, r5
    mov     r2, #1
    bl      nl_fscx_revolve_v1
    mov     r4, r0
    subs    r6, r6, #1
    bne     ratch_loop
    cmp     r10, #1
    beq     ratch_unique_ok
    ldr     r0, =fmt_ratch_fail
    bl      hprintf
    b       ratch_done
ratch_unique_ok:
    ldr     r0, =fmt_ratch_ok
    bl      hprintf
ratch_done:
    ldr     r0, =fmt_nl
    bl      hprintf

    b       demo_finish

    .ltorg
