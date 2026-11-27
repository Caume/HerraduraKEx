;  demos/i386/hpke_stern_f.asm -- HPKE-Stern-F KEM (NASM i386, KEYBITS=32; TODO #425)
;  One algorithm end to end: its sample inputs, every intermediate, and its
;  verdict through the shared [FAIL] gate.  The routines and data are in
;  core.asm, included rather than linked.  Build: ./build_asm_i386.sh;
;  run: ./run_asm_i386.sh suite.

%include "core.asm"

section .data
    demo_name   db "HPKE-Stern-F KEM"
    demo_name_l equ $-demo_name

section .text
_start:
    call demo_start
    mov  eax, demo_hdr_pre
    mov  ecx, demo_hdr_pre_l
    call print_str
    mov  eax, demo_name
    mov  ecx, demo_name_l
    call print_str
    mov  eax, demo_hdr_post
    mov  ecx, demo_hdr_post_l
    call print_str

    ; key: seed = prng_next(), e = rand_error (weight-2)
    call prng_next
    mov  [val_sdf_seed], eax
    call stern_rand_error_32
    mov  [val_sdf_e], eax
    ; syndrome = H·e^T
    mov  eax, [val_sdf_seed]
    mov  ebx, [val_sdf_e]
    call stern_syndrome_32
    mov  [val_sdf_syn], eax
    ; ================================================================== HPKE-Stern-F
    mov  eax, sdf_enc_hdr
    mov  ecx, sdf_enc_hdr_l
    call print_str
    mov  eax, sdf_note
    mov  ecx, sdf_note_l
    call print_str

    ; encap
    call hpke_stern_f_encap_32
    ; decap (known e')
    mov  eax, [val_sdf_e_prime]
    call hpke_stern_f_decap_known_32
    mov  [val_sdf_K_dec], eax

    mov  eax, lbl_K_enc
    mov  ecx, lbl_K_enc_l
    call print_str
    mov  eax, [val_sdf_K_enc]
    call print_hex32
    mov  eax, lbl_K_dec
    mov  ecx, lbl_K_dec_l
    call print_str
    mov  eax, [val_sdf_K_dec]
    call print_hex32

    mov  eax, [val_sdf_K_enc]
    cmp  eax, [val_sdf_K_dec]
    jne  .hpke_sdf_fail
    mov  eax, hpke_sdf_ok
    mov  ecx, hpke_sdf_ok_l
    call print_str
    jmp  .hpke_sdf_done
.hpke_sdf_fail:
    mov  eax, hpke_sdf_fail
    mov  ecx, hpke_sdf_fail_l
    call print_str
.hpke_sdf_done:

    ; ================================================================== EVE tests
    mov  eax, eve_hdr
    mov  ecx, eve_hdr_l
    call print_str

    ; Eve guesses HPKE-Stern-F session key
    call prng_next
    cmp  eax, [val_sdf_K_enc]
    je   .eve_hpke_sdf_fail
    mov  eax, eve_hpke_sdf_ok
    mov  ecx, eve_hpke_sdf_ok_l
    call print_str
    jmp  .eve_hpke_sdf_done
.eve_hpke_sdf_fail:
    mov  eax, eve_hpke_sdf_fail
    mov  ecx, eve_hpke_sdf_fail_l
    call print_str
.eve_hpke_sdf_done:

    jmp  demo_finish
