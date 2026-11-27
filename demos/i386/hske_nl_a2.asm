;  demos/i386/hske_nl_a2.asm -- HSKE-NL-A2 revolve-mode encryption (NASM i386, KEYBITS=32; TODO #425)
;  One algorithm end to end: its sample inputs, every intermediate, and its
;  verdict through the shared [FAIL] gate.  The routines and data are in
;  core.asm, included rather than linked.  Build: ./build_asm_i386.sh;
;  run: ./run_asm_i386.sh suite.

%include "core.asm"

section .data
    demo_name   db "HSKE-NL-A2 revolve-mode encryption"
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

    ; ================================================================== HSKE-NL-A2
    ; CAUTION: deterministic — same (plain, key) always yields same E.
    mov  eax, hske_nl2_hdr
    mov  ecx, hske_nl2_hdr_l
    call print_str

    ; E = nl_fscx_revolve_v2(plain, K, R_VALUE)
    mov  eax, [val_plain]
    mov  ebx, [val_key]
    mov  ecx, R_VALUE
    call nl_fscx_revolve_v2
    mov  [val_E_nl2], eax

    ; D = nl_fscx_revolve_v2_inv(E, K, R_VALUE)
    mov  eax, [val_E_nl2]
    mov  ebx, [val_key]
    mov  ecx, R_VALUE
    call nl_fscx_revolve_v2_inv

    push eax
    mov  eax, lbl_E_nl
    mov  ecx, lbl_E_nl_l
    call print_str
    mov  eax, [val_E_nl2]
    call print_hex32

    mov  eax, lbl_D_nl
    mov  ecx, lbl_D_nl_l
    call print_str
    pop  eax
    push eax
    call print_hex32

    pop  eax
    cmp  eax, [val_plain]
    jne  .nl2_fail
    mov  eax, pass_msg
    mov  ecx, pass_l
    call print_str
    jmp  .nl2_done
.nl2_fail:
    mov  eax, fail_msg
    mov  ecx, fail_l
    call print_str
.nl2_done:

    jmp  demo_finish
