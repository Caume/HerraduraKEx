;  demos/i386/ratchet.asm -- Ratchet (NASM i386, KEYBITS=32; TODO #425)
;  One algorithm end to end: its sample inputs, every intermediate, and its
;  verdict through the shared [FAIL] gate.  The routines and data are in
;  core.asm, included rather than linked.  Build: ./build_asm_i386.sh;
;  run: ./run_asm_i386.sh suite.

%include "core.asm"

section .data
    demo_name   db "Ratchet"
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

    ; ── 78.C — Ratchet demo (5 steps) ────────────────────────────────
    mov  eax, ratch_hdr
    mov  ecx, ratch_hdr_l
    call print_str
    call prng_next
    mov  esi, eax          ; state
    mov  ebp, 5            ; step counter
    mov  dword [val_ratch_first_key], 0
    mov  edi, 1            ; all_unique flag
.ratch_loop:
    ; msg_key = nl_fscx_revolve_v1(state, 1, 1)
    mov  eax, esi
    mov  ebx, 1
    mov  ecx, 1
    call nl_fscx_revolve_v1
    cmp  ebp, 5
    jne  .ratch_not_first
    mov  [val_ratch_first_key], eax
.ratch_not_first:
    cmp  ebp, 5
    je   .ratch_skip_cmp
    cmp  edi, 1
    jne  .ratch_skip_cmp
    cmp  eax, [val_ratch_first_key]
    jne  .ratch_skip_cmp
    mov  edi, 0            ; collision with first key
.ratch_skip_cmp:
    ; new_state = nl_fscx_revolve_v1(state, domain, 1)
    mov  eax, esi
    mov  ebx, [ratchet_domain_32]
    mov  ecx, 1
    call nl_fscx_revolve_v1
    mov  esi, eax
    dec  ebp
    jnz  .ratch_loop
    cmp  edi, 1
    jne  .ratch_fail
    mov  eax, ratch_ok
    mov  ecx, ratch_ok_l
    call print_str
    jmp  .ratch_done
.ratch_fail:
    mov  eax, ratch_fail
    mov  ecx, ratch_fail_l
    call print_str
.ratch_done:

    jmp  demo_finish
