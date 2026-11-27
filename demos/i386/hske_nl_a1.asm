;  demos/i386/hske_nl_a1.asm -- HSKE-NL-A1 counter-mode encryption (NASM i386, KEYBITS=32; TODO #425)
;  One algorithm end to end: its sample inputs, every intermediate, and its
;  verdict through the shared [FAIL] gate.  The routines and data are in
;  core.asm, included rather than linked.  Build: ./build_asm_i386.sh;
;  run: ./run_asm_i386.sh suite.

%include "core.asm"

section .data
    demo_name   db "HSKE-NL-A1 counter-mode encryption"
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

    ; ================================================================== HSKE-NL-A1
    mov  eax, hske_nl1_hdr
    mov  ecx, hske_nl1_hdr_l
    call print_str

    ; N = prng_next(); base = key XOR N; ks = nl_fscx_revolve_v1(ROL(base,4) ^ DC, base, V1_MODE_STEPS)
    call prng_next              ; eax = nonce N
    mov  [val_nonce_nl1], eax
    xor  eax, [val_key]         ; eax = base = N XOR key
    mov  ebx, eax               ; ebx = B = base (counter=0)
    rol  eax, 4                 ; eax = ROL(base, 4)         [n=32, n/8=4]
    xor  eax, RNL_KDF_DC        ; eax = seed = ROL(base,4) XOR DC
    mov  ecx, V1_MODE_STEPS     ; 3n/4 (TODO #349)
    call nl_fscx_revolve_v1     ; eax = ks  (A=seed, B=base)
    mov  [val_ks_nl1], eax

    ; E = plain XOR ks
    mov  eax, [val_plain]
    xor  eax, [val_ks_nl1]
    mov  [val_E_nl1], eax

    ; print N
    mov  eax, lbl_N_nl1
    mov  ecx, lbl_N_nl1_l
    call print_str
    mov  eax, [val_nonce_nl1]
    call print_hex32

    ; print E
    mov  eax, lbl_E_nl
    mov  ecx, lbl_E_nl_l
    call print_str
    mov  eax, [val_E_nl1]
    call print_hex32

    mov  eax, lbl_D_nl
    mov  ecx, lbl_D_nl_l
    call print_str
    ; D = E XOR ks
    mov  eax, [val_E_nl1]
    xor  eax, [val_ks_nl1]
    push eax
    call print_hex32
    pop  eax

    cmp  eax, [val_plain]
    jne  .nl1_fail
    mov  eax, pass_msg
    mov  ecx, pass_l
    call print_str
    jmp  .nl1_done
.nl1_fail:
    mov  eax, fail_msg
    mov  ecx, fail_l
    call print_str
.nl1_done:

    jmp  demo_finish
