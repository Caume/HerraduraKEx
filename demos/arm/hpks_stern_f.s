/*  demos/arm/hpks_stern_f.s -- HPKS-Stern-F signature (ARM Thumb-2, KEYBITS=32; TODO #425)
    One algorithm end to end: its sample inputs, every intermediate, and its
    verdict through the shared [FAIL] gate.  The routines and data are in
    core.s, included rather than linked.  Build: ./build_arm.sh;
    run: ./run_arm.sh suite.
*/
    .include "core.s"

    .data
demo_name:  .asciz "HPKS-Stern-F signature"
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
       HPKS-Stern-F  (code-based PQC: Syndrome Decoding ZKP, EUF-CMA)
       N=32, t=2, rounds=4; seed and e generated via prng_next
       ================================================================ */
    ldr     r0, =fmt_sdf_sign_hdr
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

    @ sign: fills sdf_c0..c2, sdf_b, sdf_respA, sdf_respB
    bl      hpks_stern_f_sign_32

    @ verify
    bl      hpks_stern_f_verify_32
    cmp     r0, #1
    bne     hpks_sdf_fail
    ldr     r0, =fmt_sdf_ok
    bl      hprintf
    b       hpks_sdf_done
hpks_sdf_fail:
    ldr     r0, =fmt_sdf_fail_msg
    bl      hprintf
hpks_sdf_done:
    ldr     r0, =fmt_nl
    bl      hprintf

    /* ================================================================ EVE tests */
    ldr     r0, =fmt_eve_hdr
    bl      hprintf

    /* Eve tries to forge HPKS-Stern-F: flip respA[0] to trigger mismatch */
    ldr     r4, =sdf_respA
    ldr     r5, [r4]            @ save original respA[0]
    mvn     r0, r5              @ flip all bits
    str     r0, [r4]
    bl      hpks_stern_f_verify_32
    mov     r6, r0              @ save verify result
    str     r5, [r4]            @ restore original respA[0]
    cmp     r6, #1
    beq     eve_sdf_forge_fail
    ldr     r0, =fmt_eve_sdf_ok
    bl      hprintf
    b       eve_sdf_forge_done
eve_sdf_forge_fail:
    ldr     r0, =fmt_eve_sdf_fail
    bl      hprintf
eve_sdf_forge_done:

    b       demo_finish

    .ltorg
