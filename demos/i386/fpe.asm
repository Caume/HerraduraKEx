;  demos/i386/fpe.asm -- FPE (NASM i386, KEYBITS=32; TODO #425)
;  One algorithm end to end: its sample inputs, every intermediate, and its
;  verdict through the shared [FAIL] gate.  The routines and data are in
;  core.asm, included rather than linked.  Build: ./build_asm_i386.sh;
;  run: ./run_asm_i386.sh suite.

%include "core.asm"

section .data
    demo_name   db "FPE"
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

    ; ── FPE (78.A): B = hfscx_32(hfscx_32(key) ^ ctx); enc/dec via nl_fscx_revolve_v2
    mov  eax, fpe_hdr
    mov  ecx, fpe_hdr_l
    call print_str
    call prng_next
    mov  [val_fpe_plain], eax       ; plain (random)
    mov  eax, 0xABCD1234            ; key
    call hfscx_32
    xor  eax, 0x42                  ; ^ context
    call hfscx_32
    mov  [val_fpe_B], eax           ; B
    mov  eax, [val_fpe_plain]
    mov  ebx, [val_fpe_B]
    mov  ecx, I_VALUE
    call nl_fscx_revolve_v2
    mov  [val_fpe_ct], eax          ; ct
    mov  eax, [val_fpe_ct]
    mov  ebx, [val_fpe_B]
    mov  ecx, I_VALUE
    call nl_fscx_revolve_v2_inv
    cmp  eax, [val_fpe_plain]
    jne  .fpe_fail
    mov  eax, fpe_ok
    mov  ecx, fpe_ok_l
    call print_str
    jmp  .fpe_done
.fpe_fail:
    mov  eax, fpe_fail
    mov  ecx, fpe_fail_l
    call print_str
.fpe_done:

    jmp  demo_finish
