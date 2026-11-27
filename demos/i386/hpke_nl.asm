;  demos/i386/hpke_nl.asm -- HPKE-NL El Gamal encryption (NASM i386, KEYBITS=32; TODO #425)
;  One algorithm end to end: its sample inputs, every intermediate, and its
;  verdict through the shared [FAIL] gate.  The routines and data are in
;  core.asm, included rather than linked.  Build: ./build_asm_i386.sh;
;  run: ./run_asm_i386.sh suite.

%include "core.asm"

section .data
    demo_name   db "HPKE-NL El Gamal encryption"
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

    ; ------------------------------------------------------------------ print inputs
    mov  eax, lbl_apriv
    mov  ecx, lbl_apriv_l
    call print_str
    mov  eax, [val_a_priv]
    call print_hex32

    mov  eax, lbl_bpriv
    mov  ecx, lbl_bpriv_l
    call print_str
    mov  eax, [val_b_priv]
    call print_hex32

    mov  eax, lbl_key
    mov  ecx, lbl_key_l
    call print_str
    mov  eax, [val_key]
    call print_hex32

    mov  eax, lbl_plain
    mov  ecx, lbl_pl_l
    call print_str
    mov  eax, [val_plain]
    call print_hex32

    mov  eax, 3
    mov  ebx, [val_a_priv]
    call gf_pow_32
    mov  [val_C], eax
    ; ================================================================== HPKE-NL
    mov  eax, hpke_nl_hdr
    mov  ecx, hpke_nl_hdr_l
    call print_str

    call prng_next
    or   eax, 1
    mov  [val_r_nl], eax

    mov  eax, 3
    mov  ebx, [val_r_nl]
    call gf_pow_32
    mov  [val_R_nl2], eax           ; save for Eve test

    mov  eax, [val_C]
    mov  ebx, [val_r_nl]
    call gf_pow_32
    mov  [val_enc_nl], eax

    ; E = nl_fscx_revolve_v2(plain, enc_nl, I_VALUE)
    mov  eax, [val_plain]
    mov  ebx, [val_enc_nl]
    mov  ecx, I_VALUE
    call nl_fscx_revolve_v2
    mov  [val_E_nl2], eax           ; save for Eve test

    mov  eax, [val_R_nl2]
    mov  ebx, [val_a_priv]
    call gf_pow_32
    mov  [val_dec_nl], eax

    ; D = nl_fscx_revolve_v2_inv(E, dec_nl, I_VALUE)
    mov  eax, [val_E_nl2]
    mov  ebx, [val_dec_nl]
    mov  ecx, I_VALUE
    call nl_fscx_revolve_v2_inv

    push eax
    mov  eax, lbl_Eb
    mov  ecx, lbl_Eb_l
    call print_str
    mov  eax, [val_E_nl2]
    call print_hex32

    mov  eax, lbl_Da
    mov  ecx, lbl_Da_l
    call print_str
    pop  eax
    push eax
    call print_hex32

    pop  eax
    cmp  eax, [val_plain]
    jne  .hpke_nl_fail
    mov  eax, pass_msg
    mov  ecx, pass_l
    call print_str
    jmp  .hpke_nl_done
.hpke_nl_fail:
    mov  eax, fail_msg
    mov  ecx, fail_l
    call print_str
.hpke_nl_done:

    ; ================================================================== EVE tests
    mov  eax, eve_hdr
    mov  ecx, eve_hdr_l
    call print_str

    ; Eve uses wrong key (C XOR R instead of C^r)
    mov  eax, [val_C]
    xor  eax, [val_R_nl2]
    mov  ebx, eax               ; eve_key = C XOR R_nl2
    mov  eax, [val_E_nl2]
    mov  ecx, I_VALUE
    call nl_fscx_revolve_v2_inv
    cmp  eax, [val_plain]
    je   .eve_hpke_fail
    mov  eax, eve_ok_msg
    mov  ecx, eve_ok_l
    call print_str
    jmp  .eve_hpke_done
.eve_hpke_fail:
    mov  eax, eve_fail_msg
    mov  ecx, eve_fail_l
    call print_str
.eve_hpke_done:

    jmp  demo_finish
