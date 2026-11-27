;  demos/i386/hkex_rnl.asm -- HKEX-RNL Ring-LWR key exchange (NASM i386, KEYBITS=32; TODO #425)
;  One algorithm end to end: its sample inputs, every intermediate, and its
;  verdict through the shared [FAIL] gate.  The routines and data are in
;  core.asm, included rather than linked.  Build: ./build_asm_i386.sh;
;  run: ./run_asm_i386.sh suite.

%include "core.asm"

section .data
    demo_name   db "HKEX-RNL Ring-LWR key exchange"
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

    ; ================================================================== HKEX-RNL
    mov  eax, hkex_rnl_hdr
    mov  ecx, hkex_rnl_hdr_l
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

    ; rnl_keygen(rnl_s_B, rnl_C_B, rnl_m_blind)
    mov  eax, rnl_s_B
    mov  ebx, rnl_C_B
    mov  ecx, rnl_m_blind
    call rnl_keygen

    ; KA, hint_A = rnl_agree_full(rnl_s_A, rnl_C_B)
    mov  eax, rnl_s_A
    mov  ebx, rnl_C_B
    call rnl_agree_full     ; EAX=KA, EDX=hint_A
    mov  [val_KA], eax
    mov  [val_hint_A], edx

    ; KB = rnl_agree_recv(rnl_s_B, rnl_C_A, hint_A)
    mov  eax, rnl_s_B
    mov  ebx, rnl_C_A
    mov  ecx, [val_hint_A]
    call rnl_agree_recv     ; EAX=KB
    mov  [val_KB], eax

    ; skA = nl_fscx_revolve_v1(ROL32(KA,4) XOR DC, KA, I_VALUE)
    mov  eax, [val_KA]
    rol  eax, 4              ; ROL32(KA, 4)          [n/8 = 32/8 = 4]
    xor  eax, RNL_KDF_DC     ; seed = ROL(KA,4) XOR DC
    mov  ebx, [val_KA]
    mov  ecx, I_VALUE
    call nl_fscx_revolve_v1  ; eax = sk
    mov  [val_sk_rnl], eax

    ; skB = nl_fscx_revolve_v1(ROL32(KB,4) XOR DC, KB, I_VALUE)
    mov  eax, [val_KB]
    rol  eax, 4
    xor  eax, RNL_KDF_DC     ; seed = ROL(KB,4) XOR DC
    mov  ebx, [val_KB]
    mov  ecx, I_VALUE
    call nl_fscx_revolve_v1

    push eax
    mov  eax, lbl_sk_alice
    mov  ecx, lbl_sk_alice_l
    call print_str
    mov  eax, [val_sk_rnl]
    call print_hex32

    mov  eax, lbl_sk_bob
    mov  ecx, lbl_sk_bob_l
    call print_str
    pop  eax
    call print_hex32

    ; check KA == KB
    mov  eax, [val_KA]
    cmp  eax, [val_KB]
    jne  .rnl_disagree
    mov  eax, rnl_agree_msg
    mov  ecx, rnl_agree_l
    call print_str
    jmp  .rnl_done
.rnl_disagree:
    mov  eax, rnl_disagree_msg
    mov  ecx, rnl_disagree_l
    call print_str
.rnl_done:

    ; ================================================================== EVE tests
    mov  eax, eve_hdr
    mov  ecx, eve_hdr_l
    call print_str

    ; Eve random guess for HKEX-RNL
    call prng_next
    cmp  eax, [val_sk_rnl]
    je   .eve_rnl_fail
    mov  eax, eve_rnl_ok
    mov  ecx, eve_rnl_ok_l
    call print_str
    jmp  .eve_rnl_done
.eve_rnl_fail:
    mov  eax, eve_fail_msg
    mov  ecx, eve_fail_l
    call print_str
.eve_rnl_done:

    jmp  demo_finish
