;  demos/i386/hpks_stern_f.asm -- HPKS-Stern-F signature (NASM i386, KEYBITS=32; TODO #425)
;  One algorithm end to end: its sample inputs, every intermediate, and its
;  verdict through the shared [FAIL] gate.  The routines and data are in
;  core.asm, included rather than linked.  Build: ./build_asm_i386.sh;
;  run: ./run_asm_i386.sh suite.

%include "core.asm"

section .data
    demo_name   db "HPKS-Stern-F signature"
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

    ; ================================================================== HPKS-Stern-F
    mov  eax, sdf_sign_hdr
    mov  ecx, sdf_sign_hdr_l
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
    ; sign
    call hpks_stern_f_sign_32
    ; verify
    call hpks_stern_f_verify_32
    cmp  eax, 1
    jne  .hpks_sdf_fail
    mov  eax, sdf_ok_msg
    mov  ecx, sdf_ok_l
    call print_str
    jmp  .hpks_sdf_done
.hpks_sdf_fail:
    mov  eax, sdf_fail_msg
    mov  ecx, sdf_fail_l
    call print_str
.hpks_sdf_done:

    ; ================================================================== EVE tests
    mov  eax, eve_hdr
    mov  ecx, eve_hdr_l
    call print_str

    ; Eve tries to forge HPKS-Stern-F: flip respA[0]
    mov  eax, [sdf_respA]      ; original respA[0]
    push eax                   ; save original
    not  eax
    mov  [sdf_respA], eax      ; corrupted
    call hpks_stern_f_verify_32
    mov  ebx, eax              ; save result
    pop  eax
    mov  [sdf_respA], eax      ; restore
    cmp  ebx, 1
    je   .eve_sdf_forge_fail
    mov  eax, eve_sdf_ok
    mov  ecx, eve_sdf_ok_l
    call print_str
    jmp  .eve_sdf_forge_done
.eve_sdf_forge_fail:
    mov  eax, eve_sdf_fail_s
    mov  ecx, eve_sdf_fail_l
    call print_str
.eve_sdf_forge_done:

    jmp  demo_finish
