;  demos/i386/masked_hske.asm -- Masked HSKE (NASM i386, KEYBITS=32; TODO #425)
;  One algorithm end to end: its sample inputs, every intermediate, and its
;  verdict through the shared [FAIL] gate.  The routines and data are in
;  core.asm, included rather than linked.  Build: ./build_asm_i386.sh;
;  run: ./run_asm_i386.sh suite.

%include "core.asm"

section .data
    demo_name   db "Masked HSKE"
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

    ; ── 78.H — Masked HSKE demo ──────────────────────────────────────
    mov  eax, masked_hdr
    mov  ecx, masked_hdr_l
    call print_str
    call prng_next
    mov  esi, eax          ; plain
    call prng_next
    mov  edi, eax          ; key
    call prng_next
    mov  ebp, eax          ; mask
    ; ct = fscx_revolve(plain^mask, key, I_VALUE) ^ fscx_revolve(mask, 0, I_VALUE)
    mov  eax, esi
    xor  eax, ebp          ; plain ^ mask
    mov  ebx, edi          ; key
    mov  ecx, I_VALUE
    call FSCX_revolve
    push eax               ; save fm
    mov  eax, ebp          ; mask
    xor  ebx, ebx          ; zero
    mov  ecx, I_VALUE
    call FSCX_revolve
    pop  ebx
    xor  eax, ebx          ; ct
    mov  [val_E], eax      ; store ct
    ; rec = fscx_revolve(ct^mask, key, R_VALUE) ^ fscx_revolve(mask, 0, R_VALUE)
    xor  eax, ebp          ; ct ^ mask
    mov  ebx, edi
    mov  ecx, R_VALUE
    call FSCX_revolve
    push eax               ; save fm
    mov  eax, ebp
    xor  ebx, ebx
    mov  ecx, R_VALUE
    call FSCX_revolve
    pop  ebx
    xor  eax, ebx          ; recovered
    cmp  eax, esi
    jne  .masked_fail
    mov  eax, masked_ok
    mov  ecx, masked_ok_l
    call print_str
    jmp  .masked_done
.masked_fail:
    mov  eax, masked_fail
    mov  ecx, masked_fail_l
    call print_str
.masked_done:

    jmp  demo_finish
