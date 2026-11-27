/*  demos/arm/masked_hske.s -- Masked HSKE (ARM Thumb-2, KEYBITS=32; TODO #425)
    One algorithm end to end: its sample inputs, every intermediate, and its
    verdict through the shared [FAIL] gate.  The routines and data are in
    core.s, included rather than linked.  Build: ./build_arm.sh;
    run: ./run_arm.sh suite.
*/
    .include "core.s"

    .data
demo_name:  .asciz "Masked HSKE"
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

    /* ── 78.H — Masked HSKE demo ──────────────────────────────────── */
    ldr     r0, =fmt_masked_hdr
    bl      hprintf
    bl      prng_next
    mov     r4, r0          @ plain
    bl      prng_next
    mov     r5, r0          @ key
    bl      prng_next
    mov     r6, r0          @ mask
    @ ct = fscx_revolve(plain ^ mask, key, I_VALUE) ^ fscx_revolve(mask, 0, I_VALUE)
    mov     r0, r4
    eor     r0, r0, r6      @ A ^ mask
    mov     r1, r5          @ key
    mov     r2, #I_VALUE
    bl      fscx_revolve
    mov     r7, r0          @ fm
    mov     r0, r6          @ mask
    mov     r1, #0          @ zero
    mov     r2, #I_VALUE
    bl      fscx_revolve
    eor     r7, r7, r0      @ ct
    @ pt = fscx_revolve(ct ^ mask, key, R_VALUE) ^ fscx_revolve(mask, 0, R_VALUE)
    mov     r0, r7
    eor     r0, r0, r6      @ ct ^ mask
    mov     r1, r5
    mov     r2, #R_VALUE
    bl      fscx_revolve
    mov     r8, r0          @ fm
    mov     r0, r6
    mov     r1, #0
    mov     r2, #R_VALUE
    bl      fscx_revolve
    eor     r8, r8, r0      @ recovered
    cmp     r8, r4
    beq     masked_ok
    ldr     r0, =fmt_masked_fail
    bl      hprintf
    b       masked_done
masked_ok:
    ldr     r0, =fmt_masked_ok
    bl      hprintf
masked_done:

    b       demo_finish

    .ltorg
