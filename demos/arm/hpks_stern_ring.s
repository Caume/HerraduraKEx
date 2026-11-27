/*  demos/arm/hpks_stern_ring.s -- HPKS-Stern-Ring ring signature (ARM Thumb-2, KEYBITS=32; TODO #425)
    One algorithm end to end: its sample inputs, every intermediate, and its
    verdict through the shared [FAIL] gate.  The routines and data are in
    core.s, included rather than linked.  Build: ./build_arm.sh;
    run: ./run_arm.sh suite.
*/
    .include "core.s"

    .data
demo_name:  .asciz "HPKS-Stern-Ring ring signature"
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

    @ key generation: seed = prng_next()
    bl      prng_next
    ldr     r3, =val_sdf_seed
    str     r0, [r3]

    @ e = stern_rand_error_32() — weight-2 error vector
    bl      stern_rand_error_32
    ldr     r3, =val_sdf_e
    str     r0, [r3]

    @ sdf_syn = stern_syndrome_32(seed, e)
    ldr     r0, =val_sdf_seed
    ldr     r0, [r0]
    ldr     r1, =val_sdf_e
    ldr     r1, [r1]
    bl      stern_syndrome_32
    ldr     r3, =val_sdf_syn
    str     r0, [r3]

    /* ================================================================
       HPKS-Stern-Ring (TODO #424)  k=2, N=32, t=2, rounds=4
       Ring = (another key, Alice's Stern key val_sdf_seed / val_sdf_syn);
       Alice signs as member 1 with val_sdf_e.  One Stern proof over the
       ring; the signature does not say which member signed.
       ================================================================ */
    ldr     r0, =fmt_ring_hdr
    bl      hprintf
    ldr     r4, =ring_in
    bl      prng_next
    str     r0, [r4]            @ member 0: another key
    bl      stern_rand_error_32
    mov     r1, r0
    ldr     r0, [r4]
    bl      stern_syndrome_32
    str     r0, [r4, #4]
    ldr     r0, =val_sdf_seed
    ldr     r0, [r0]
    str     r0, [r4, #8]        @ member 1: Alice
    ldr     r0, =val_sdf_syn
    ldr     r0, [r0]
    str     r0, [r4, #12]
    ldr     r0, =val_sdf_e
    ldr     r0, [r0]
    ldr     r1, =ring_e
    str     r0, [r1]
    mov     r0, #1
    ldr     r1, =ring_j
    str     r0, [r1]
    ldr     r0, =val_plain
    ldr     r0, [r0]
    ldr     r1, =ring_msg
    str     r0, [r1]
    bl      hpks_stern_ring_sign_32
    mov     r5, r0
    ldr     r0, =val_plain
    ldr     r0, [r0]
    bl      hpks_stern_ring_verify_32
    and     r0, r0, r5
    cmp     r0, #1
    bne     hpks_ring_fail
    ldr     r0, =fmt_ring_ok
    bl      hprintf
    b       hpks_ring_done
hpks_ring_fail:
    ldr     r0, =fmt_ring_fail
    bl      hprintf
hpks_ring_done:
    ldr     r4, =ring_in        @ the same ring in the other order
    ldm     r4, {r0-r3}
    str     r2, [r4]
    str     r3, [r4, #4]
    str     r0, [r4, #8]
    str     r1, [r4, #12]
    ldr     r0, =val_plain
    ldr     r0, [r0]
    bl      hpks_stern_ring_verify_32
    cmp     r0, #1
    bne     hpks_ring_rev_fail
    ldr     r0, =fmt_ring_rev_ok
    bl      hprintf
    b       hpks_ring_rev_done
hpks_ring_rev_fail:
    ldr     r0, =fmt_ring_rev_fail
    bl      hprintf
hpks_ring_rev_done:
    @ Eve changes one opening word (round 1's first r / PI r word)
    ldr     r4, =ring_sig
    ldr     r5, [r4, #52]
    eor     r0, r5, #1
    str     r0, [r4, #52]
    ldr     r0, =val_plain
    ldr     r0, [r0]
    bl      hpks_stern_ring_verify_32
    str     r5, [r4, #52]       @ restore
    cmp     r0, #0
    bne     eve_ring_forge_fail
    ldr     r0, =fmt_eve_ring_ok
    bl      hprintf
    b       eve_ring_forge_done
eve_ring_forge_fail:
    ldr     r0, =fmt_eve_ring_fail
    bl      hprintf
eve_ring_forge_done:
    @ Eve presents the signature for another message
    ldr     r0, =val_plain
    ldr     r0, [r0]
    eor     r0, r0, #1
    bl      hpks_stern_ring_verify_32
    cmp     r0, #0
    bne     eve_ring_msg_fail
    ldr     r0, =fmt_eve_ring_msg_ok
    bl      hprintf
    b       eve_ring_msg_done
eve_ring_msg_fail:
    ldr     r0, =fmt_eve_ring_msg_fail
    bl      hprintf
eve_ring_msg_done:
    ldr     r0, =fmt_nl
    bl      hprintf

    b       demo_finish

    .ltorg
