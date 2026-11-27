;  demos/i386/oprf.asm -- OPRF (NASM i386, KEYBITS=32; TODO #425)
;  One algorithm end to end: its sample inputs, every intermediate, and its
;  verdict through the shared [FAIL] gate.  The routines and data are in
;  core.asm, included rather than linked.  Build: ./build_asm_i386.sh;
;  run: ./run_asm_i386.sh suite.

%include "core.asm"

section .data
    demo_name   db "OPRF"
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

    ; ── OPRF (80) demo — blind/eval/unblind, n=32 ─────────────────────
    ; Key k=0x13579BDF; blinding scalar r=7; r_inv=0x49249249 (7^{-1} mod 2^32-1)
    mov  eax, oprf_hdr
    mov  ecx, oprf_hdr_l
    call print_str

    ; H(x) = hfscx_32(0x50415353)  ["PASS" as 32-bit word]
    mov  eax, 0x50415353
    call hfscx_32
    test eax, eax
    jnz  .oprf_hx_ok
    mov  eax, 1                     ; zero-guard
.oprf_hx_ok:
    mov  [val_oprf_hx], eax
    mov  eax, lbl_oprf_hx
    mov  ecx, lbl_oprf_hx_l
    call print_str
    mov  eax, [val_oprf_hx]
    call print_hex32

    ; alpha = H(x)^r,  r = 7  (client blind)
    mov  eax, [val_oprf_hx]
    mov  ebx, 7
    call gf_pow_32
    mov  [val_oprf_alpha], eax
    mov  eax, lbl_oprf_alpha
    mov  ecx, lbl_oprf_al_l
    call print_str
    mov  eax, [val_oprf_alpha]
    call print_hex32

    ; beta = alpha^k,  k = 0x13579BDF  (server eval)
    mov  eax, [val_oprf_alpha]
    mov  ebx, 0x13579BDF
    call gf_pow_32
    mov  [val_oprf_beta], eax
    mov  eax, lbl_oprf_beta
    mov  ecx, lbl_oprf_be_l
    call print_str
    mov  eax, [val_oprf_beta]
    call print_hex32

    ; F = beta^r_inv,  r_inv = 0x49249249 = 7^{-1} mod (2^32-1)  (client unblind)
    mov  eax, [val_oprf_beta]
    mov  ebx, 0x49249249
    call gf_pow_32
    mov  [val_oprf_F], eax
    mov  eax, lbl_oprf_F
    mov  ecx, lbl_oprf_F_l
    call print_str
    mov  eax, [val_oprf_F]
    call print_hex32

    ; F_direct = H(x)^k  (should equal F — verifies correctness)
    mov  eax, [val_oprf_hx]
    mov  ebx, 0x13579BDF
    call gf_pow_32
    mov  [val_oprf_Fd], eax

    cmp  eax, [val_oprf_F]
    jne  .oprf_fail
    mov  eax, oprf_ok
    mov  ecx, oprf_ok_l
    call print_str
    jmp  .oprf_done
.oprf_fail:
    mov  eax, oprf_fail
    mov  ecx, oprf_fail_l
    call print_str
.oprf_done:

    jmp  demo_finish
