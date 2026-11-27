/*  demos/arm/hpke_stern_f.s -- HPKE-Stern-F KEM (ARM Thumb-2, KEYBITS=32; TODO #425)
    One algorithm end to end: its sample inputs, every intermediate, and its
    verdict through the shared [FAIL] gate.  The routines and data are in
    core.s, included rather than linked.  Build: ./build_arm.sh;
    run: ./run_arm.sh suite.
*/
    .include "core.s"

    .data
demo_name:  .asciz "HPKE-Stern-F KEM"
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
       HPKE-Stern-F  (Niederreiter KEM, N=32, t=2)
       Encap: K = hash(seed, e'); ct = H·e'^T
       Decap (known e'): K' = hash(seed, e')  [demo]
       ================================================================ */
    ldr     r0, =fmt_sdf_enc_hdr
    bl      hprintf
    ldr     r0, =fmt_sdf_note
    bl      hprintf

    @ encap: fills val_sdf_K_enc, val_sdf_ct, val_sdf_e_prime
    bl      hpke_stern_f_encap_32

    @ decap (known e'): K' = hash2(seed, e')
    ldr     r0, =val_sdf_e_prime
    ldr     r0, [r0]
    bl      hpke_stern_f_decap_known_32
    ldr     r3, =val_sdf_K_dec
    str     r0, [r3]

    ldr     r0, =fmt_hex
    ldr     r1, =lbl_K_enc
    ldr     r2, =val_sdf_K_enc
    ldr     r2, [r2]
    bl      hprintf
    ldr     r0, =fmt_hex
    ldr     r1, =lbl_K_dec
    ldr     r2, =val_sdf_K_dec
    ldr     r2, [r2]
    bl      hprintf

    ldr     r0, =val_sdf_K_enc
    ldr     r0, [r0]
    ldr     r1, =val_sdf_K_dec
    ldr     r1, [r1]
    cmp     r0, r1
    bne     hpke_sdf_fail
    ldr     r0, =fmt_hpke_sdf_ok
    bl      hprintf
    b       hpke_sdf_done
hpke_sdf_fail:
    ldr     r0, =fmt_hpke_sdf_fail
    bl      hprintf
hpke_sdf_done:
    ldr     r0, =fmt_nl
    bl      hprintf

    /* ================================================================ EVE tests */
    ldr     r0, =fmt_eve_hdr
    bl      hprintf

    /* Eve guesses HPKE-Stern-F session key */
    bl      prng_next
    ldr     r1, =val_sdf_K_enc
    ldr     r1, [r1]
    cmp     r0, r1
    beq     eve_hpke_sdf_fail
    ldr     r0, =fmt_eve_hpke_sdf_ok
    bl      hprintf
    b       eve_hpke_sdf_done
eve_hpke_sdf_fail:
    ldr     r0, =fmt_eve_hpke_sdf_fail
    bl      hprintf
eve_hpke_sdf_done:

    b       demo_finish

    .ltorg
