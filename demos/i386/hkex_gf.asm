;  demos/i386/hkex_gf.asm -- HKEX-GF key exchange (NASM i386, KEYBITS=32; TODO #425)
;  One algorithm end to end: its sample inputs, every intermediate, and its
;  verdict through the shared [FAIL] gate.  The routines and data are in
;  core.asm, included rather than linked.  Build: ./build_asm_i386.sh;
;  run: ./run_asm_i386.sh suite.

%include "core.asm"

section .data
    demo_name   db "HKEX-GF key exchange"
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

    ; ================================================================== HKEX-GF
    mov  eax, hkex_hdr
    mov  ecx, hkex_hdr_l
    call print_str

    mov  eax, 3
    mov  ebx, [val_a_priv]
    call gf_pow_32
    mov  [val_C], eax

    mov  eax, lbl_C
    mov  ecx, lbl_C_l
    call print_str
    mov  eax, [val_C]
    call print_hex32

    mov  eax, 3
    mov  ebx, [val_b_priv]
    call gf_pow_32
    mov  [val_C2], eax

    mov  eax, lbl_C2
    mov  ecx, lbl_C2_l
    call print_str
    mov  eax, [val_C2]
    call print_hex32

    mov  eax, [val_C2]
    mov  ebx, [val_a_priv]
    call gf_pow_32
    mov  [val_skA], eax

    mov  eax, lbl_skA
    mov  ecx, lbl_skA_l
    call print_str
    mov  eax, [val_skA]
    call print_hex32

    mov  eax, [val_C]
    mov  ebx, [val_b_priv]
    call gf_pow_32
    mov  [val_skB], eax

    mov  eax, lbl_skB
    mov  ecx, lbl_skB_l
    call print_str
    mov  eax, [val_skB]
    call print_hex32

    mov  eax, [val_skA]
    cmp  eax, [val_skB]
    jne  .hkex_fail
    mov  eax, pass_msg
    mov  ecx, pass_l
    call print_str
    jmp  .hkex_done
.hkex_fail:
    mov  eax, fail_msg
    mov  ecx, fail_l
    call print_str
.hkex_done:

    jmp  demo_finish
