/*  demos/arm/accumulator.s -- Accumulator (ARM Thumb-2, KEYBITS=32; TODO #425)
    One algorithm end to end: its sample inputs, every intermediate, and its
    verdict through the shared [FAIL] gate.  The routines and data are in
    core.s, included rather than linked.  Build: ./build_arm.sh;
    run: ./run_arm.sh suite.
*/
    .include "core.s"

    .data
demo_name:  .asciz "Accumulator"
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

    /* ── Accumulator (78.J): leaf = hfscx_32(data); node = hfscx_32(hfscx_32(0x01000000^L)^R) */
    ldr     r0, =fmt_acc_hdr
    bl      hprintf
    @ compute 4 leaves
    ldr     r0, =0xAAAAAAAA
    bl      hfscx_32
    mov     r4, r0                  @ leaf0
    ldr     r0, =0xBBBBBBBB
    bl      hfscx_32
    mov     r5, r0                  @ leaf1
    ldr     r0, =0xCCCCCCCC
    bl      hfscx_32
    mov     r6, r0                  @ leaf2
    ldr     r0, =0xDDDDDDDD
    bl      hfscx_32
    mov     r7, r0                  @ leaf3
    @ n01 = node(leaf0, leaf1)
    ldr     r0, =0x01000000
    eor     r0, r0, r4
    bl      hfscx_32
    eor     r0, r0, r5
    bl      hfscx_32
    mov     r8, r0                  @ n01
    @ n23 = node(leaf2, leaf3)
    ldr     r0, =0x01000000
    eor     r0, r0, r6
    bl      hfscx_32
    eor     r0, r0, r7
    bl      hfscx_32
    mov     r9, r0                  @ n23
    @ root = node(n01, n23)
    ldr     r0, =0x01000000
    eor     r0, r0, r8
    bl      hfscx_32
    eor     r0, r0, r9
    bl      hfscx_32
    mov     r10, r0                 @ root
    @ proof for index 2: cur = node(leaf2, leaf3), then node(n01, cur)
    ldr     r0, =0x01000000
    eor     r0, r0, r6
    bl      hfscx_32
    eor     r0, r0, r7
    bl      hfscx_32
    mov     r11, r0                 @ node(leaf2,leaf3) == n23
    ldr     r0, =0x01000000
    eor     r0, r0, r8
    bl      hfscx_32
    eor     r0, r0, r11
    bl      hfscx_32                @ reconstructed root
    cmp     r0, r10
    beq     acc_suite_ok
    ldr     r0, =fmt_acc_fail
    bl      hprintf
    b       acc_suite_done
acc_suite_ok:
    ldr     r0, =fmt_acc_ok
    bl      hprintf
acc_suite_done:

    /* Eve presents a member's proof path for a leaf that is not in the set */
    ldr     r0, =fmt_eve_hdr
    bl      hprintf
    ldr     r0, =0xEEEEEEEE
    bl      hfscx_32                @ Eve's leaf
    mov     r11, r0
    ldr     r0, =0x01000000
    eor     r0, r0, r11
    bl      hfscx_32
    eor     r0, r0, r7
    bl      hfscx_32                @ node(Eve's leaf, leaf3)
    mov     r11, r0
    ldr     r0, =0x01000000
    eor     r0, r0, r8
    bl      hfscx_32
    eor     r0, r0, r11
    bl      hfscx_32                @ the root that path implies
    cmp     r0, r10
    beq     eve_acc_fail
    ldr     r0, =fmt_eve_acc_ok
    bl      hprintf
    b       eve_acc_done
eve_acc_fail:
    ldr     r0, =fmt_eve_acc_fail
    bl      hprintf
eve_acc_done:

    b       demo_finish

    .ltorg
