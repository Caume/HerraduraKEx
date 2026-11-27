;  demos/i386/hpks.asm -- HPKS Schnorr signature (NASM i386, KEYBITS=32; TODO #425)
;  One algorithm end to end: its sample inputs, every intermediate, and its
;  verdict through the shared [FAIL] gate.  The routines and data are in
;  core.asm, included rather than linked.  Build: ./build_asm_i386.sh;
;  run: ./run_asm_i386.sh suite.

%include "core.asm"

section .data
    demo_name   db "HPKS Schnorr signature"
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
    ; ================================================================== HPKS Schnorr
    mov  eax, hpks_hdr
    mov  ecx, hpks_hdr_l
    call print_str

    call prng_next
    mov  [val_k_hpks], eax

    mov  eax, 3
    mov  ebx, [val_k_hpks]
    call gf_pow_32
    mov  [val_R_hpks], eax

    mov  eax, [val_R_hpks]
    mov  ebx, [val_plain]
    mov  ecx, 8
    call FSCX_revolve
    mov  [val_e_hpks], eax

    push ebx
    push edx
    mov  eax, [val_a_priv]
    mov  ebx, [val_e_hpks]
    mul  ebx
    add  eax, edx
    adc  eax, 0
    mov  [val_ae_hpks], eax
    pop  edx
    pop  ebx

    mov  eax, [val_k_hpks]
    sub  eax, [val_ae_hpks]
    jnc  .s_no_borrow
    dec  eax
.s_no_borrow:
    mov  [val_s_hpks], eax

    mov  eax, 3
    mov  ebx, [val_s_hpks]
    call gf_pow_32
    mov  [val_gs_hpks], eax

    mov  eax, [val_C]
    mov  ebx, [val_e_hpks]
    call gf_pow_32

    mov  ebx, eax
    mov  eax, [val_gs_hpks]
    call gf_mul_32

    push eax
    mov  eax, lbl_k_hpks
    mov  ecx, lbl_k_l
    call print_str
    mov  eax, [val_k_hpks]
    call print_hex32

    mov  eax, lbl_R_hpks
    mov  ecx, lbl_R_hpks_l
    call print_str
    mov  eax, [val_R_hpks]
    call print_hex32

    mov  eax, lbl_e_hpks
    mov  ecx, lbl_e_l
    call print_str
    mov  eax, [val_e_hpks]
    call print_hex32

    mov  eax, lbl_s_hpks
    mov  ecx, lbl_s_l
    call print_str
    mov  eax, [val_s_hpks]
    call print_hex32

    mov  eax, lbl_lhs
    mov  ecx, lbl_lhs_l
    call print_str
    pop  eax
    push eax
    call print_hex32

    pop  eax
    cmp  eax, [val_R_hpks]
    jne  .hpks_fail
    mov  eax, pass_msg
    mov  ecx, pass_l
    call print_str
    jmp  .hpks_done
.hpks_fail:
    mov  eax, fail_msg
    mov  ecx, fail_l
    call print_str
.hpks_done:

    ; Eve presents the same (R, s) for another message, plain ^ 1
    mov  eax, eve_hdr
    mov  ecx, eve_hdr_l
    call print_str
    mov  eax, [val_R_hpks]
    mov  ebx, [val_plain]
    xor  ebx, 1
    mov  ecx, 8
    call FSCX_revolve           ; e' = fscx_revolve(R, plain ^ 1, i)
    mov  ebx, eax
    mov  eax, [val_C]
    call gf_pow_32              ; C^e'
    mov  ebx, eax
    mov  eax, [val_gs_hpks]
    call gf_mul_32              ; g^s * C^e'
    cmp  eax, [val_R_hpks]
    je   .eve_hpks_fail
    mov  eax, eve_msg_ok
    mov  ecx, eve_msg_ok_l
    call print_str
    jmp  .eve_hpks_done
.eve_hpks_fail:
    mov  eax, eve_msg_fail
    mov  ecx, eve_msg_fail_l
    call print_str
.eve_hpks_done:

    jmp  demo_finish
