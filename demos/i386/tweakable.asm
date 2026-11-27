;  demos/i386/tweakable.asm -- Tweakable cipher (NASM i386, KEYBITS=32; TODO #425)
;  One algorithm end to end: its sample inputs, every intermediate, and its
;  verdict through the shared [FAIL] gate.  The routines and data are in
;  core.asm, included rather than linked.  Build: ./build_asm_i386.sh;
;  run: ./run_asm_i386.sh suite.

%include "core.asm"

section .data
    demo_name   db "Tweakable cipher"
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

    ; ── Tweakable cipher (78.B): B = hfscx_32(hfscx_32(key^sector) ^ bidx)
    mov  eax, twk_hdr
    mov  ecx, twk_hdr_l
    call print_str
    call prng_next
    mov  [val_twk_plain], eax       ; block (random)
    mov  eax, 0x12345678            ; key
    xor  eax, 7                     ; ^ sector
    call hfscx_32
    xor  eax, 3                     ; ^ bidx
    call hfscx_32
    mov  [val_twk_B], eax           ; B
    mov  eax, [val_twk_plain]
    mov  ebx, [val_twk_B]
    mov  ecx, I_VALUE
    call nl_fscx_revolve_v2
    mov  [val_twk_ct], eax          ; ct
    mov  eax, [val_twk_ct]
    mov  ebx, [val_twk_B]
    mov  ecx, I_VALUE
    call nl_fscx_revolve_v2_inv
    cmp  eax, [val_twk_plain]
    jne  .twk_fail
    mov  eax, twk_ok
    mov  ecx, twk_ok_l
    call print_str
    jmp  .twk_done
.twk_fail:
    mov  eax, twk_fail
    mov  ecx, twk_fail_l
    call print_str
.twk_done:

    jmp  demo_finish
