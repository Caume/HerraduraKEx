;  demos/i386/zkp_nl.asm -- ZKP-NL ZKBoo proof (NASM i386, KEYBITS=32; TODO #425)
;  One algorithm end to end: its sample inputs, every intermediate, and its
;  verdict through the shared [FAIL] gate.  The routines and data are in
;  core.asm, included rather than linked.  Build: ./build_asm_i386.sh;
;  run: ./run_asm_i386.sh suite.

%include "core.asm"

section .data
    demo_name   db "ZKP-NL ZKBoo proof"
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

    ; ------------------------------------------------------------------ ZKP-NL demo
    mov  eax, zkp_nl_hdr
    mov  ecx, zkp_nl_hdr_l
    call print_str
    call prng_next
    and  eax, 0xFF
    mov  [zkp_arg_A], eax
    call prng_next
    and  eax, 0xFF
    mov  [zkp_arg_B], eax
    call prng_next
    and  eax, 0xFF
    mov  [zkp_arg_msg], eax
    ; y = nl_fscx_v1(A,B) & 0xFF
    mov  eax, [zkp_arg_A]
    mov  ebx, [zkp_arg_B]
    call nl_fscx_v1
    and  eax, 0xFF
    mov  [zkp_arg_y], eax
    call zkp_nl_prove_8
    call zkp_nl_verify_8
    cmp  eax, 1
    jne  .zkp_nl_fail
    mov  eax, zkp_nl_ok
    mov  ecx, zkp_nl_ok_l
    call print_str
    jmp  .zkp_nl_done
.zkp_nl_fail:
    mov  eax, zkp_nl_fail
    mov  ecx, zkp_nl_fail_l
    call print_str
.zkp_nl_done:

    jmp  demo_finish
