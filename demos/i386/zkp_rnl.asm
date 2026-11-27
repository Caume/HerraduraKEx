;  demos/i386/zkp_rnl.asm -- ZKP-RNL Ring-LWR Sigma proof (NASM i386, KEYBITS=32; TODO #425)
;  One algorithm end to end: its sample inputs, every intermediate, and its
;  verdict through the shared [FAIL] gate.  The routines and data are in
;  core.asm, included rather than linked.  Build: ./build_asm_i386.sh;
;  run: ./run_asm_i386.sh suite.

%include "core.asm"

section .data
    demo_name   db "ZKP-RNL Ring-LWR Sigma proof"
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

    ; rnl_m_poly(rnl_m_base)
    mov  eax, rnl_m_base
    call rnl_m_poly

    ; rnl_rand_poly(rnl_a_rand)
    mov  eax, rnl_a_rand
    call rnl_rand_poly

    ; rnl_poly_add(rnl_m_blind, rnl_m_base, rnl_a_rand)
    mov  dword [rnl_h_ptr], rnl_m_blind
    mov  dword [rnl_f_ptr], rnl_m_base
    mov  dword [rnl_g_ptr], rnl_a_rand
    call rnl_poly_add

    ; rnl_keygen(rnl_s_A, rnl_C_A, rnl_m_blind)
    mov  eax, rnl_s_A
    mov  ebx, rnl_C_A
    mov  ecx, rnl_m_blind
    call rnl_keygen
    ; ================================================================== ZKP-RNL
    mov  eax, zkp_rnl_hdr
    mov  ecx, zkp_rnl_hdr_l
    call print_str

    mov  eax, [sigma_demo_msg]
    call rnl_sigma_sign_32
    test eax, eax
    jnz  .zkp_rnl_fail

    mov  eax, [sigma_demo_msg]
    call rnl_sigma_verify_32
    cmp  eax, 1
    jne  .zkp_rnl_fail

    mov  eax, zkp_rnl_ok
    mov  ecx, zkp_rnl_ok_l
    call print_str
    jmp  .zkp_rnl_done
.zkp_rnl_fail:
    mov  eax, zkp_rnl_fail
    mov  ecx, zkp_rnl_fail_l
    call print_str
.zkp_rnl_done:

    jmp  demo_finish
