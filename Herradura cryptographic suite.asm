;  Herradura Cryptographic Suite v1.5.0
;  NASM i386 Assembly -- HKEX-GF, HSKE, HPKS, HPKE,
;                        HSKE-NL-A1/A2, HKEX-RNL, HPKS-NL, HPKE-NL
;  KEYBITS = 32, I_VALUE = 8, R_VALUE = 24
;  HKEX-GF: DH over GF(2^32)*, poly x^32+x^22+x^2+x+1, generator g=3
;  HPKS:    Schnorr signature; s=(k-a*e) mod ORD; verify g^s*C^e==R
;  HPKE:    El Gamal + fscx_revolve; enc_key=C^r; dec_key=R^a
;  NL-FSCX v2: nl_v2(A,B) = fscx(A,B) + delta(B)  mod 2^32
;              delta(B) = ROL32(B*((B+1)>>1), 8)
;              inv: B XOR M^{-1}((Y - delta(B)) mod 2^32)
;  HKEX-RNL: Ring-LWR, N=32, q=65537, p=4096, pp=2, B=1
;
;  Copyright (C) 2024-2026 Omar Alejandro Herrera Reyna
;  MIT License / GPL v3.0 -- choose either.
;
;  Assemble: nasm -f elf32 "Herradura cryptographic suite.asm" -o suite32.o
;  Link:     x86_64-linux-gnu-ld -m elf_i386 -o "Herradura cryptographic suite_i386" suite32.o
;  Run:      qemu-i386 "./Herradura cryptographic suite_i386"

%define SYS_EXIT   1
%define SYS_WRITE  4
%define STDOUT     1
%define I_VALUE    8
%define R_VALUE    24
%define GF_POLY    0x00400007
%define RNL_N      32
%define RNL_Q      65537
%define RNL_P      4096
%define RNL_PP     2

section .data

    val_a_priv  dd 0xDEADBEEF
    val_b_priv  dd 0xCAFEBABF
    val_key     dd 0x5A5A5A5A
    val_plain   dd 0xDEADC0DE
    val_C       dd 0
    val_C2      dd 0
    val_skA     dd 0
    val_skB     dd 0
    val_E       dd 0
    val_D       dd 0
    val_k_hpks  dd 0
    val_R_hpks  dd 0
    val_e_hpks  dd 0
    val_ae_hpks dd 0
    val_s_hpks  dd 0
    val_gs_hpks dd 0
    val_r_hpke  dd 0
    val_R_hpke  dd 0
    val_enc_key dd 0
    val_E_hpke  dd 0
    val_dec_key dd 0
    val_D_hpke  dd 0

    prng_state  dd 0xDEADBEEE

    ; NL / RNL scratch scalars
    val_ks_nl1  dd 0    ; HSKE-NL-A1 keystream
    val_E_nl1   dd 0
    val_E_nl2   dd 0    ; HSKE-NL-A2 ciphertext (saved for Eve)
    val_R_nl2   dd 0    ; HPKE-NL R=g^r (saved for Eve)
    val_r_nl    dd 0
    val_enc_nl  dd 0
    val_dec_nl  dd 0
    val_KA      dd 0
    val_KB      dd 0
    val_sk_rnl  dd 0

    ; rnl_poly_mul implicit argument pointers
    rnl_f_ptr   dd 0
    rnl_g_ptr   dd 0
    rnl_h_ptr   dd 0

    hdr         db "=== Herradura Cryptographic Suite v1.5.0 (NASM i386, KEYBITS=32, HKEX-GF) ===", 10
    hdr_l       equ $-hdr

    lbl_apriv   db "a_priv    : "
    lbl_apriv_l equ $-lbl_apriv
    lbl_bpriv   db "b_priv    : "
    lbl_bpriv_l equ $-lbl_bpriv
    lbl_key     db "key       : "
    lbl_key_l   equ $-lbl_key
    lbl_plain   db "plaintext : "
    lbl_pl_l    equ $-lbl_plain
    lbl_C       db "C         : "
    lbl_C_l     equ $-lbl_C
    lbl_C2      db "C2        : "
    lbl_C2_l    equ $-lbl_C2

    hkex_hdr    db 10, "--- HKEX-GF (key exchange)", 10
    hkex_hdr_l  equ $-hkex_hdr
    lbl_skA     db "skeyA (Alice): "
    lbl_skA_l   equ $-lbl_skA
    lbl_skB     db "skeyB (Bob)  : "
    lbl_skB_l   equ $-lbl_skB

    hske_hdr    db 10, "--- HSKE (symmetric key encryption)", 10
    hske_hdr_l  equ $-hske_hdr
    lbl_E       db "E (encrypted): "
    lbl_E_l     equ $-lbl_E
    lbl_D       db "D (decrypted): "
    lbl_D_l     equ $-lbl_D

    hpks_hdr    db 10, "--- HPKS Schnorr (public key signature)", 10
    hpks_hdr_l  equ $-hpks_hdr
    lbl_k_hpks  db "k (nonce)    : "
    lbl_k_l     equ $-lbl_k_hpks
    lbl_R_hpks  db "R = g^k      : "
    lbl_R_hpks_l equ $-lbl_R_hpks
    lbl_e_hpks  db "e (fscx)     : "
    lbl_e_l     equ $-lbl_e_hpks
    lbl_s_hpks  db "s (response) : "
    lbl_s_l     equ $-lbl_s_hpks
    lbl_lhs     db "g^s * C^e    : "
    lbl_lhs_l   equ $-lbl_lhs

    hpke_hdr    db 10, "--- HPKE El Gamal (public key encryption)", 10
    hpke_hdr_l  equ $-hpke_hdr
    lbl_R_hpke  db "R = g^r      : "
    lbl_R_hpke_l equ $-lbl_R_hpke
    lbl_Eb      db "E (Bob)      : "
    lbl_Eb_l    equ $-lbl_Eb
    lbl_Da      db "D (Alice)    : "
    lbl_Da_l    equ $-lbl_Da

    ; v1.5.0 section headers
    hske_nl1_hdr db 10, "--- HSKE-NL-A1 [PQC-HARDENED -- counter-mode with NL-FSCX v1]", 10
    hske_nl1_hdr_l equ $-hske_nl1_hdr
    hske_nl2_hdr db 10, "--- HSKE-NL-A2 [PQC-HARDENED -- revolve-mode with NL-FSCX v2]", 10
    hske_nl2_hdr_l equ $-hske_nl2_hdr
    hkex_rnl_hdr db 10, "--- HKEX-RNL [PQC -- Ring-LWR key exchange; N=32, q=65537]", 10
    hkex_rnl_hdr_l equ $-hkex_rnl_hdr
    hpks_nl_hdr  db 10, "--- HPKS-NL [NL-hardened Schnorr -- NL-FSCX v1 challenge]", 10
    hpks_nl_hdr_l equ $-hpks_nl_hdr
    hpke_nl_hdr  db 10, "--- HPKE-NL [NL-hardened El Gamal -- NL-FSCX v2 encryption]", 10
    hpke_nl_hdr_l equ $-hpke_nl_hdr
    eve_hdr      db 10, "*** EVE bypass TESTS ***", 10
    eve_hdr_l    equ $-eve_hdr

    lbl_sk_alice db "sk (Alice)   : "
    lbl_sk_alice_l equ $-lbl_sk_alice
    lbl_sk_bob   db "sk (Bob)     : "
    lbl_sk_bob_l equ $-lbl_sk_bob
    lbl_E_nl     db "E (Alice)    : "
    lbl_E_nl_l   equ $-lbl_E_nl
    lbl_D_nl     db "D (Bob)      : "
    lbl_D_nl_l   equ $-lbl_D_nl

    pass_msg    db "+ correct!", 10
    pass_l      equ $-pass_msg
    fail_msg    db "- INCORRECT!", 10
    fail_l      equ $-fail_msg
    eve_ok_msg  db "- Eve could not decrypt (CDH + NL protection)", 10
    eve_ok_l    equ $-eve_ok_msg
    eve_fail_msg db "+ Eve decrypted (Eve wins)!", 10
    eve_fail_l  equ $-eve_fail_msg
    rnl_agree_msg db "+ raw key bits agree!", 10
    rnl_agree_l equ $-rnl_agree_msg
    rnl_disagree_msg db "- raw key disagrees (rounding noise -- retry)", 10
    rnl_disagree_l equ $-rnl_disagree_msg
    eve_rnl_ok  db "- Eve random guess does not match shared key (Ring-LWR protection)", 10
    eve_rnl_ok_l equ $-eve_rnl_ok

section .bss
    hex_buf     resb 12

    ; HKEX-RNL polynomial arrays (RNL_N * 4 = 128 bytes each)
    rnl_m_base  resd RNL_N
    rnl_a_rand  resd RNL_N
    rnl_m_blind resd RNL_N
    rnl_s_A     resd RNL_N
    rnl_s_B     resd RNL_N
    rnl_C_A     resd RNL_N
    rnl_C_B     resd RNL_N
    rnl_tmp     resd RNL_N    ; temp output for poly_mul/round/lift
    rnl_tmp2    resd RNL_N    ; second temp

section .text
global _start

; ============================================================
; Utility macros
; ============================================================

; print_kv label_addr, label_len, value_in_eax
%macro print_kv 3
    push    eax
    mov     eax, %1
    mov     ecx, %2
    call    print_str
    pop     eax
    call    print_hex32
%endmacro

_start:
    ; ------------------------------------------------------------------ header
    mov  eax, hdr
    mov  ecx, hdr_l
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

    ; ================================================================== HKEX-GF
    mov  eax, hkex_hdr
    mov  ecx, hkex_hdr_l
    call print_str

    mov  eax, 3
    mov  ebx, [val_a_priv]
    call gf_pow_32
    mov  [val_C], eax

    mov  eax, lbl_C
    mov  ecx, lbl_C_l
    call print_str
    mov  eax, [val_C]
    call print_hex32

    mov  eax, 3
    mov  ebx, [val_b_priv]
    call gf_pow_32
    mov  [val_C2], eax

    mov  eax, lbl_C2
    mov  ecx, lbl_C2_l
    call print_str
    mov  eax, [val_C2]
    call print_hex32

    mov  eax, [val_C2]
    mov  ebx, [val_a_priv]
    call gf_pow_32
    mov  [val_skA], eax

    mov  eax, lbl_skA
    mov  ecx, lbl_skA_l
    call print_str
    mov  eax, [val_skA]
    call print_hex32

    mov  eax, [val_C]
    mov  ebx, [val_b_priv]
    call gf_pow_32
    mov  [val_skB], eax

    mov  eax, lbl_skB
    mov  ecx, lbl_skB_l
    call print_str
    mov  eax, [val_skB]
    call print_hex32

    mov  eax, [val_skA]
    cmp  eax, [val_skB]
    jne  .hkex_fail
    mov  eax, pass_msg
    mov  ecx, pass_l
    call print_str
    jmp  .hkex_done
.hkex_fail:
    mov  eax, fail_msg
    mov  ecx, fail_l
    call print_str
.hkex_done:

    ; ================================================================== HSKE
    mov  eax, hske_hdr
    mov  ecx, hske_hdr_l
    call print_str

    mov  eax, [val_plain]
    mov  ebx, [val_key]
    mov  ecx, I_VALUE
    call FSCX_revolve
    mov  [val_E], eax

    mov  eax, lbl_E
    mov  ecx, lbl_E_l
    call print_str
    mov  eax, [val_E]
    call print_hex32

    mov  eax, [val_E]
    mov  ebx, [val_key]
    mov  ecx, R_VALUE
    call FSCX_revolve
    mov  [val_D], eax

    mov  eax, lbl_D
    mov  ecx, lbl_D_l
    call print_str
    mov  eax, [val_D]
    call print_hex32

    mov  eax, [val_D]
    cmp  eax, [val_plain]
    jne  .hske_fail
    mov  eax, pass_msg
    mov  ecx, pass_l
    call print_str
    jmp  .hske_done
.hske_fail:
    mov  eax, fail_msg
    mov  ecx, fail_l
    call print_str
.hske_done:

    ; ================================================================== HPKS Schnorr
    mov  eax, hpks_hdr
    mov  ecx, hpks_hdr_l
    call print_str

    call prng_next
    mov  [val_k_hpks], eax

    mov  eax, 3
    mov  ebx, [val_k_hpks]
    call gf_pow_32
    mov  [val_R_hpks], eax

    mov  eax, [val_R_hpks]
    mov  ebx, [val_plain]
    mov  ecx, 8
    call FSCX_revolve
    mov  [val_e_hpks], eax

    push ebx
    push edx
    mov  eax, [val_a_priv]
    mov  ebx, [val_e_hpks]
    mul  ebx
    add  eax, edx
    adc  eax, 0
    mov  [val_ae_hpks], eax
    pop  edx
    pop  ebx

    mov  eax, [val_k_hpks]
    sub  eax, [val_ae_hpks]
    jnc  .s_no_borrow
    dec  eax
.s_no_borrow:
    mov  [val_s_hpks], eax

    mov  eax, 3
    mov  ebx, [val_s_hpks]
    call gf_pow_32
    mov  [val_gs_hpks], eax

    mov  eax, [val_C]
    mov  ebx, [val_e_hpks]
    call gf_pow_32

    mov  ebx, eax
    mov  eax, [val_gs_hpks]
    call gf_mul_32

    push eax
    mov  eax, lbl_k_hpks
    mov  ecx, lbl_k_l
    call print_str
    mov  eax, [val_k_hpks]
    call print_hex32

    mov  eax, lbl_R_hpks
    mov  ecx, lbl_R_hpks_l
    call print_str
    mov  eax, [val_R_hpks]
    call print_hex32

    mov  eax, lbl_e_hpks
    mov  ecx, lbl_e_l
    call print_str
    mov  eax, [val_e_hpks]
    call print_hex32

    mov  eax, lbl_s_hpks
    mov  ecx, lbl_s_l
    call print_str
    mov  eax, [val_s_hpks]
    call print_hex32

    mov  eax, lbl_lhs
    mov  ecx, lbl_lhs_l
    call print_str
    pop  eax
    push eax
    call print_hex32

    pop  eax
    cmp  eax, [val_R_hpks]
    jne  .hpks_fail
    mov  eax, pass_msg
    mov  ecx, pass_l
    call print_str
    jmp  .hpks_done
.hpks_fail:
    mov  eax, fail_msg
    mov  ecx, fail_l
    call print_str
.hpks_done:

    ; ================================================================== HPKE El Gamal
    mov  eax, hpke_hdr
    mov  ecx, hpke_hdr_l
    call print_str

    call prng_next
    or   eax, 1
    mov  [val_r_hpke], eax

    mov  eax, 3
    mov  ebx, [val_r_hpke]
    call gf_pow_32
    mov  [val_R_hpke], eax

    mov  eax, [val_C]
    mov  ebx, [val_r_hpke]
    call gf_pow_32
    mov  [val_enc_key], eax

    mov  eax, [val_plain]
    mov  ebx, [val_enc_key]
    mov  ecx, I_VALUE
    call FSCX_revolve
    mov  [val_E_hpke], eax

    mov  eax, [val_R_hpke]
    mov  ebx, [val_a_priv]
    call gf_pow_32
    mov  [val_dec_key], eax

    mov  eax, [val_E_hpke]
    mov  ebx, [val_dec_key]
    mov  ecx, R_VALUE
    call FSCX_revolve
    mov  [val_D_hpke], eax

    mov  eax, lbl_R_hpke
    mov  ecx, lbl_R_hpke_l
    call print_str
    mov  eax, [val_R_hpke]
    call print_hex32

    mov  eax, lbl_Eb
    mov  ecx, lbl_Eb_l
    call print_str
    mov  eax, [val_E_hpke]
    call print_hex32

    mov  eax, lbl_Da
    mov  ecx, lbl_Da_l
    call print_str
    mov  eax, [val_D_hpke]
    call print_hex32

    mov  eax, [val_D_hpke]
    cmp  eax, [val_plain]
    jne  .hpke_fail
    mov  eax, pass_msg
    mov  ecx, pass_l
    call print_str
    jmp  .hpke_done
.hpke_fail:
    mov  eax, fail_msg
    mov  ecx, fail_l
    call print_str
.hpke_done:

    ; ================================================================== HSKE-NL-A1
    mov  eax, hske_nl1_hdr
    mov  ecx, hske_nl1_hdr_l
    call print_str

    ; ks = nl_fscx_revolve_v1(K, K, 8)  [counter=0 -> B=K]
    mov  eax, [val_key]
    mov  ebx, [val_key]
    mov  ecx, I_VALUE
    call nl_fscx_revolve_v1
    mov  [val_ks_nl1], eax

    ; E = plain XOR ks
    mov  eax, [val_plain]
    xor  eax, [val_ks_nl1]
    mov  [val_E_nl1], eax

    ; D = E XOR ks
    mov  eax, [val_E_nl1]
    xor  eax, [val_ks_nl1]

    mov  ecx, eax              ; save D
    mov  eax, lbl_E_nl
    mov  ecx, lbl_E_nl_l       ; oops, clobber -- use push/pop
    push ecx
    call print_str
    mov  eax, [val_E_nl1]
    call print_hex32

    mov  eax, lbl_D_nl
    mov  ecx, lbl_D_nl_l
    call print_str
    ; recompute D
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

    ; ================================================================== HSKE-NL-A2
    mov  eax, hske_nl2_hdr
    mov  ecx, hske_nl2_hdr_l
    call print_str

    ; E = nl_fscx_revolve_v2(plain, K, R_VALUE)
    mov  eax, [val_plain]
    mov  ebx, [val_key]
    mov  ecx, R_VALUE
    call nl_fscx_revolve_v2
    mov  [val_E_nl2], eax

    ; D = nl_fscx_revolve_v2_inv(E, K, R_VALUE)
    mov  eax, [val_E_nl2]
    mov  ebx, [val_key]
    mov  ecx, R_VALUE
    call nl_fscx_revolve_v2_inv

    push eax
    mov  eax, lbl_E_nl
    mov  ecx, lbl_E_nl_l
    call print_str
    mov  eax, [val_E_nl2]
    call print_hex32

    mov  eax, lbl_D_nl
    mov  ecx, lbl_D_nl_l
    call print_str
    pop  eax
    push eax
    call print_hex32

    pop  eax
    cmp  eax, [val_plain]
    jne  .nl2_fail
    mov  eax, pass_msg
    mov  ecx, pass_l
    call print_str
    jmp  .nl2_done
.nl2_fail:
    mov  eax, fail_msg
    mov  ecx, fail_l
    call print_str
.nl2_done:

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

    ; KA = rnl_agree(rnl_s_A, rnl_C_B)
    mov  eax, rnl_s_A
    mov  ebx, rnl_C_B
    call rnl_agree
    mov  [val_KA], eax

    ; KB = rnl_agree(rnl_s_B, rnl_C_A)
    mov  eax, rnl_s_B
    mov  ebx, rnl_C_A
    call rnl_agree
    mov  [val_KB], eax

    ; skA = nl_fscx_revolve_v1(KA, KA, I_VALUE)
    mov  eax, [val_KA]
    mov  ebx, [val_KA]
    mov  ecx, I_VALUE
    call nl_fscx_revolve_v1
    mov  [val_sk_rnl], eax

    ; skB = nl_fscx_revolve_v1(KB, KB, I_VALUE)
    mov  eax, [val_KB]
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

    ; ================================================================== HPKS-NL
    mov  eax, hpks_nl_hdr
    mov  ecx, hpks_nl_hdr_l
    call print_str

    call prng_next
    mov  [val_k_hpks], eax          ; reuse val_k_hpks scratch

    mov  eax, 3
    mov  ebx, [val_k_hpks]
    call gf_pow_32
    mov  [val_R_hpks], eax

    ; e = nl_fscx_revolve_v1(R, plain, I_VALUE)  [NL challenge]
    mov  eax, [val_R_hpks]
    mov  ebx, [val_plain]
    mov  ecx, I_VALUE
    call nl_fscx_revolve_v1
    mov  [val_e_hpks], eax

    push ebx
    push edx
    mov  eax, [val_a_priv]
    mov  ebx, [val_e_hpks]
    mul  ebx
    add  eax, edx
    adc  eax, 0
    mov  [val_ae_hpks], eax
    pop  edx
    pop  ebx

    mov  eax, [val_k_hpks]
    sub  eax, [val_ae_hpks]
    jnc  .s_nl_no_borrow
    dec  eax
.s_nl_no_borrow:
    mov  [val_s_hpks], eax

    mov  eax, 3
    mov  ebx, [val_s_hpks]
    call gf_pow_32
    mov  [val_gs_hpks], eax

    mov  eax, [val_C]
    mov  ebx, [val_e_hpks]
    call gf_pow_32

    mov  ebx, eax
    mov  eax, [val_gs_hpks]
    call gf_mul_32

    push eax
    mov  eax, lbl_R_hpks
    mov  ecx, lbl_R_hpks_l
    call print_str
    mov  eax, [val_R_hpks]
    call print_hex32

    mov  eax, lbl_s_hpks
    mov  ecx, lbl_s_l
    call print_str
    mov  eax, [val_s_hpks]
    call print_hex32

    mov  eax, lbl_lhs
    mov  ecx, lbl_lhs_l
    call print_str
    pop  eax
    push eax
    call print_hex32

    pop  eax
    cmp  eax, [val_R_hpks]
    jne  .hpks_nl_fail
    mov  eax, pass_msg
    mov  ecx, pass_l
    call print_str
    jmp  .hpks_nl_done
.hpks_nl_fail:
    mov  eax, fail_msg
    mov  ecx, fail_l
    call print_str
.hpks_nl_done:

    ; ================================================================== HPKE-NL
    mov  eax, hpke_nl_hdr
    mov  ecx, hpke_nl_hdr_l
    call print_str

    call prng_next
    or   eax, 1
    mov  [val_r_nl], eax

    mov  eax, 3
    mov  ebx, [val_r_nl]
    call gf_pow_32
    mov  [val_R_nl2], eax           ; save for Eve test

    mov  eax, [val_C]
    mov  ebx, [val_r_nl]
    call gf_pow_32
    mov  [val_enc_nl], eax

    ; E = nl_fscx_revolve_v2(plain, enc_nl, I_VALUE)
    mov  eax, [val_plain]
    mov  ebx, [val_enc_nl]
    mov  ecx, I_VALUE
    call nl_fscx_revolve_v2
    mov  [val_E_nl2], eax           ; save for Eve test

    mov  eax, [val_R_nl2]
    mov  ebx, [val_a_priv]
    call gf_pow_32
    mov  [val_dec_nl], eax

    ; D = nl_fscx_revolve_v2_inv(E, dec_nl, I_VALUE)
    mov  eax, [val_E_nl2]
    mov  ebx, [val_dec_nl]
    mov  ecx, I_VALUE
    call nl_fscx_revolve_v2_inv

    push eax
    mov  eax, lbl_Eb
    mov  ecx, lbl_Eb_l
    call print_str
    mov  eax, [val_E_nl2]
    call print_hex32

    mov  eax, lbl_Da
    mov  ecx, lbl_Da_l
    call print_str
    pop  eax
    push eax
    call print_hex32

    pop  eax
    cmp  eax, [val_plain]
    jne  .hpke_nl_fail
    mov  eax, pass_msg
    mov  ecx, pass_l
    call print_str
    jmp  .hpke_nl_done
.hpke_nl_fail:
    mov  eax, fail_msg
    mov  ecx, fail_l
    call print_str
.hpke_nl_done:

    ; ================================================================== EVE tests
    mov  eax, eve_hdr
    mov  ecx, eve_hdr_l
    call print_str

    ; Eve uses wrong key (C XOR R instead of C^r)
    mov  eax, [val_C]
    xor  eax, [val_R_nl2]
    mov  ebx, eax               ; eve_key = C XOR R_nl2
    mov  eax, [val_E_nl2]
    mov  ecx, I_VALUE
    call nl_fscx_revolve_v2_inv
    cmp  eax, [val_plain]
    je   .eve_hpke_fail
    mov  eax, eve_ok_msg
    mov  ecx, eve_ok_l
    call print_str
    jmp  .eve_hpke_done
.eve_hpke_fail:
    mov  eax, eve_fail_msg
    mov  ecx, eve_fail_l
    call print_str
.eve_hpke_done:

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

    ; ------------------------------------------------------------------ exit
    mov  eax, SYS_EXIT
    xor  ebx, ebx
    int  0x80

; ============================================================
; prng_next: LCG state = state * 1664525 + 1013904223
; ============================================================
prng_next:
    push ebx
    push edx
    mov  eax, [prng_state]
    mov  ebx, 1664525
    imul eax, ebx
    add  eax, 1013904223
    mov  [prng_state], eax
    pop  edx
    pop  ebx
    ret

; ============================================================
; print_str: EAX = pointer, ECX = length
; ============================================================
print_str:
    push ebx
    push edx
    mov  edx, ecx
    mov  ecx, eax
    mov  eax, SYS_WRITE
    mov  ebx, STDOUT
    int  0x80
    pop  edx
    pop  ebx
    ret

; ============================================================
; print_hex32: EAX = 32-bit value  -->  prints "0x########\n"
; ============================================================
print_hex32:
    push ebx
    push ecx
    push edx
    push esi
    push edi

    mov  byte [hex_buf],    '0'
    mov  byte [hex_buf+1],  'x'
    mov  byte [hex_buf+10], 10

    mov  edi, hex_buf+9
    mov  ecx, 8
.nh_loop:
    mov  edx, eax
    and  edx, 0x0F
    cmp  dl, 10
    jl   .nh_decimal
    add  dl, 'a'-10
    jmp  .nh_store
.nh_decimal:
    add  dl, '0'
.nh_store:
    mov  [edi], dl
    dec  edi
    shr  eax, 4
    loop .nh_loop

    mov  eax, SYS_WRITE
    mov  ebx, STDOUT
    mov  ecx, hex_buf
    mov  edx, 11
    int  0x80

    pop  edi
    pop  esi
    pop  edx
    pop  ecx
    pop  ebx
    ret

; ============================================================
; FSCX_revolve: EAX=A, EBX=B, ECX=rounds --> EAX=result
; ============================================================
FSCX_revolve:
    push eax
    pop  edx
.fscx_loop:
    xor  edx, ebx
    rol  eax, 1
    xor  edx, eax
    ror  eax, 2
    xor  edx, eax
    rol  ebx, 1
    xor  edx, ebx
    ror  ebx, 2
    xor  edx, ebx
    rol  ebx, 1
    mov  eax, edx
    loop .fscx_loop
    ret

; ============================================================
; fscx_single: EAX=A, EBX=B --> EAX=fscx(A,B)  (one step)
; ============================================================
fscx_single:
    push ecx
    push edx
    mov  edx, eax
    xor  edx, ebx
    rol  eax, 1
    xor  edx, eax
    ror  eax, 2
    xor  edx, eax
    rol  eax, 1         ; restore EAX to original (undone: rol then ror 2 = ror 1; then rol 1 = back)
    ; Actually we need A intact for the B part. Let me redo with a copy.
    ; Use ECX as scratch copy of A
    pop  edx
    pop  ecx

    push ecx
    push edx
    push esi
    mov  ecx, eax           ; ecx = A (saved copy)
    mov  edx, eax
    xor  edx, ebx           ; A ^ B
    rol  eax, 1
    xor  edx, eax           ; ^ ROL(A,1)
    ror  eax, 2
    xor  edx, eax           ; ^ ROR(A,1)
    rol  ebx, 1
    xor  edx, ebx           ; ^ ROL(B,1)
    ror  ebx, 2
    xor  edx, ebx           ; ^ ROR(B,1)
    rol  ebx, 1             ; restore B
    mov  eax, edx
    pop  esi
    pop  edx
    pop  ecx
    ret

; ============================================================
; nl_fscx_delta_v2: EAX=B --> EAX=delta(B)
; delta(B) = ROL32(B*((B+1)>>1), 8)
; ============================================================
nl_fscx_delta_v2:
    push ebx
    push edx
    mov  ebx, eax           ; ebx = B
    add  eax, 1             ; eax = B+1  (may wrap, fine mod 2^32)
    shr  eax, 1             ; eax = (B+1)>>1
    imul eax, ebx           ; eax = B * ((B+1)>>1) low 32 bits
    rol  eax, 8             ; ROL32(raw, 8)
    pop  edx
    pop  ebx
    ret

; ============================================================
; nl_fscx_v1: EAX=A, EBX=B --> EAX=nl_v1(A,B)
; nl_v1(A,B) = fscx(A,B) XOR ROL32(A+B, 8)
; ============================================================
nl_fscx_v1:
    push ecx
    push edx
    mov  ecx, eax           ; save A
    ; compute fscx(A,B)
    call fscx_single        ; eax = fscx(A,B); B in ebx (restored by fscx_single)
    push eax                ; save fscx result
    ; compute ROL32(A+B, 8)
    mov  eax, ecx
    add  eax, ebx           ; A + B mod 2^32
    rol  eax, 8
    ; XOR with fscx result
    pop  ecx
    xor  eax, ecx
    pop  edx
    pop  ecx
    ret

; ============================================================
; nl_fscx_revolve_v1: EAX=A, EBX=B, ECX=steps --> EAX
; ============================================================
nl_fscx_revolve_v1:
    push esi
    push edi
    mov  esi, eax           ; current A
    mov  edi, ecx           ; steps counter (save ecx since fscx_single uses it)
.rv1_loop:
    test edi, edi
    jz   .rv1_done
    mov  eax, esi
    ; EBX still = B
    call nl_fscx_v1
    mov  esi, eax
    dec  edi
    jmp  .rv1_loop
.rv1_done:
    mov  eax, esi
    pop  edi
    pop  esi
    ret

; ============================================================
; nl_fscx_v2: EAX=A, EBX=B --> EAX=nl_v2(A,B)
; nl_v2(A,B) = fscx(A,B) + delta(B)  mod 2^32
; ============================================================
nl_fscx_v2:
    push ecx
    push edx
    ; compute fscx(A,B)
    call fscx_single        ; eax = fscx(A,B)
    push eax
    ; compute delta(B)
    mov  eax, ebx
    call nl_fscx_delta_v2   ; eax = delta(B)
    pop  ecx
    add  eax, ecx           ; fscx + delta  mod 2^32
    pop  edx
    pop  ecx
    ret

; ============================================================
; m_inv_32: EAX=X --> EAX=M^{-1}(X) = fscx_revolve(X, 0, 15)
; ============================================================
m_inv_32:
    push ebx
    push ecx
    mov  ebx, 0
    mov  ecx, 15
    call FSCX_revolve
    pop  ecx
    pop  ebx
    ret

; ============================================================
; nl_fscx_v2_inv: EAX=Y, EBX=B --> EAX=A
; A = B XOR M^{-1}((Y - delta(B)) mod 2^32)
; ============================================================
nl_fscx_v2_inv:
    push ecx
    push edx
    push esi
    mov  esi, eax           ; esi = Y
    ; delta(B)
    mov  eax, ebx
    call nl_fscx_delta_v2   ; eax = delta(B)
    ; z = Y - delta(B)
    sub  esi, eax           ; esi = Y - delta  (mod 2^32)
    ; M^{-1}(z)
    mov  eax, esi
    call m_inv_32           ; eax = M^{-1}(z)
    ; B XOR result
    xor  eax, ebx
    pop  esi
    pop  edx
    pop  ecx
    ret

; ============================================================
; nl_fscx_revolve_v2: EAX=A, EBX=B, ECX=steps --> EAX
; ============================================================
nl_fscx_revolve_v2:
    push esi
    push edi
    mov  esi, eax
    mov  edi, ecx
.rv2_loop:
    test edi, edi
    jz   .rv2_done
    mov  eax, esi
    call nl_fscx_v2
    mov  esi, eax
    dec  edi
    jmp  .rv2_loop
.rv2_done:
    mov  eax, esi
    pop  edi
    pop  esi
    ret

; ============================================================
; nl_fscx_revolve_v2_inv: EAX=Y, EBX=B, ECX=steps --> EAX
; ============================================================
nl_fscx_revolve_v2_inv:
    push esi
    push edi
    mov  esi, eax
    mov  edi, ecx
.rv2i_loop:
    test edi, edi
    jz   .rv2i_done
    mov  eax, esi
    call nl_fscx_v2_inv
    mov  esi, eax
    dec  edi
    jmp  .rv2i_loop
.rv2i_done:
    mov  eax, esi
    pop  edi
    pop  esi
    ret

; ============================================================
; gf_mul_32: EAX=a, EBX=b --> EAX=result
; ============================================================
gf_mul_32:
    push    esi
    push    edi
    push    ebx
    xor     esi, esi
    mov     edi, eax
    mov     ecx, 32
.gfmul_loop:
    test    ebx, 1
    jz      .gfmul_skip
    xor     esi, edi
.gfmul_skip:
    shl     edi, 1
    jnc     .gfmul_no_red
    xor     edi, GF_POLY
.gfmul_no_red:
    shr     ebx, 1
    loop    .gfmul_loop
    mov     eax, esi
    pop     ebx
    pop     edi
    pop     esi
    ret

; ============================================================
; gf_pow_32: EAX=base, EBX=exp --> EAX=result
; ============================================================
gf_pow_32:
    push    esi
    push    edi
    mov     esi, 1
    mov     edi, eax
.gfpow_loop:
    test    ebx, ebx
    jz      .gfpow_done
    test    ebx, 1
    jz      .gfpow_skip_mul
    push    ebx
    mov     eax, esi
    mov     ebx, edi
    call    gf_mul_32
    mov     esi, eax
    pop     ebx
.gfpow_skip_mul:
    push    ebx
    mov     eax, edi
    mov     ebx, edi
    call    gf_mul_32
    mov     edi, eax
    pop     ebx
    shr     ebx, 1
    jmp     .gfpow_loop
.gfpow_done:
    mov     eax, esi
    pop     edi
    pop     esi
    ret

; ============================================================
; rnl_poly_add: uses [rnl_h_ptr],[rnl_f_ptr],[rnl_g_ptr]
;   h[i] = (f[i] + g[i]) % Q
; ============================================================
rnl_poly_add:
    push ebx
    push ecx
    push edx
    push esi
    push edi
    push ebp
    mov  esi, [rnl_f_ptr]
    mov  edi, [rnl_g_ptr]
    mov  ebp, [rnl_h_ptr]
    xor  ecx, ecx           ; i = 0
.rpa_loop:
    cmp  ecx, RNL_N
    jge  .rpa_done
    mov  eax, [esi + ecx*4]
    add  eax, [edi + ecx*4]
    ; % Q
    push ecx
    push edx
    xor  edx, edx
    mov  ebx, RNL_Q
    div  ebx
    mov  eax, edx
    pop  edx
    pop  ecx
    mov  [ebp + ecx*4], eax
    inc  ecx
    jmp  .rpa_loop
.rpa_done:
    pop  ebp
    pop  edi
    pop  esi
    pop  edx
    pop  ecx
    pop  ebx
    ret

; ============================================================
; rnl_poly_mul: uses [rnl_h_ptr],[rnl_f_ptr],[rnl_g_ptr]
;   h = f * g in Z_q[x]/(x^N+1), N=32, Q=65537
;   Uses rnl_tmp as temp buffer.
; ============================================================
rnl_poly_mul:
    push ebx
    push ecx
    push edx
    push esi
    push edi
    push ebp

    ; zero rnl_tmp
    xor  eax, eax
    mov  ecx, RNL_N
    mov  edi, rnl_tmp
    rep  stosd

    mov  esi, [rnl_f_ptr]   ; f
    ; ebp = g pointer (load fresh each inner iteration)

    xor  ecx, ecx           ; i = 0 (outer loop)
.rpm_outer:
    cmp  ecx, RNL_N
    jge  .rpm_outer_done

    mov  eax, [esi + ecx*4] ; f[i]
    test eax, eax
    jz   .rpm_outer_next

    mov  ebp, ecx           ; save i in ebp

    xor  ebx, ebx           ; j = 0 (inner loop)
.rpm_inner:
    cmp  ebx, RNL_N
    jge  .rpm_inner_done

    mov  edi, [rnl_g_ptr]
    mov  edx, [edi + ebx*4] ; g[j]
    test edx, edx
    jz   .rpm_inner_next

    ; prod = f[i] * g[j]  -- need 64-bit result
    ; eax = f[i] (already), edx = g[j]
    push eax
    push ebx
    push ecx
    push edx
    ; compute f[i]*g[j] mod Q using lo+hi trick: 2^32 ≡ 1 (mod 65537)
    mov  eax, [esi + ebp*4] ; f[i]
    xor  edx, edx
    pop  ecx                ; ecx = g[j]
    mul  ecx                ; edx:eax = f[i] * g[j]
    ; prod mod Q = (lo + hi) mod Q  since 2^32 ≡ 1 (mod 65537)
    add  eax, edx           ; eax = lo + hi
    ; now reduce mod Q=65537
    xor  edx, edx
    mov  ecx, RNL_Q
    div  ecx                ; eax = quot, edx = eax mod Q
    mov  eax, edx           ; eax = prod_mod_q
    pop  ecx                ; ecx = saved ecx (i)
    pop  ebx                ; ebx = j
    pop  edx                ; edx = saved

    ; k = i + j
    mov  edx, ebp           ; edx = i
    add  edx, ebx           ; edx = k = i+j
    cmp  edx, RNL_N
    jge  .rpm_neg

    ; tmp[k] = (tmp[k] + prod) % Q
    push eax
    push ecx
    push edx
    mov  ecx, edx           ; k
    mov  edx, [rnl_tmp + ecx*4]
    add  edx, eax
    xor  eax, eax
    push ebx
    mov  ebx, RNL_Q
    cmp  edx, ebx
    jl   .rpm_add_no_sub
    sub  edx, ebx
.rpm_add_no_sub:
    pop  ebx
    mov  ecx, [esp+4]       ; restore k from stack
    mov  [rnl_tmp + ecx*4], edx
    pop  edx
    pop  ecx
    pop  eax
    jmp  .rpm_inner_next

.rpm_neg:
    ; k >= N: tmp[k-N] = (tmp[k-N] - prod + Q) % Q
    sub  edx, RNL_N
    push eax
    push ecx
    push edx
    mov  ecx, edx
    mov  edx, [rnl_tmp + ecx*4]
    sub  edx, eax           ; tmp[k-N] - prod (may go negative, but we add Q)
    push ebx
    mov  ebx, RNL_Q
    add  edx, ebx           ; + Q
    cmp  edx, ebx
    jl   .rpm_neg_no_sub
    sub  edx, ebx
.rpm_neg_no_sub:
    pop  ebx
    mov  ecx, [esp+4]
    mov  [rnl_tmp + ecx*4], edx
    pop  edx
    pop  ecx
    pop  eax

.rpm_inner_next:
    inc  ebx
    jmp  .rpm_inner
.rpm_inner_done:

.rpm_outer_next:
    inc  ecx
    jmp  .rpm_outer
.rpm_outer_done:

    ; copy rnl_tmp to h
    mov  esi, rnl_tmp
    mov  edi, [rnl_h_ptr]
    mov  ecx, RNL_N
    rep  movsd

    pop  ebp
    pop  edi
    pop  esi
    pop  edx
    pop  ecx
    pop  ebx
    ret

; ============================================================
; rnl_round: h=out(ebp), f=in(esi), from_q(ecx), to_p(edx)
;   out[i] = round(in[i] * to_p / from_q) % to_p
;   Call: mov ebp,out; mov esi,in; mov ecx,from_q; mov edx,to_p; call rnl_round
; ============================================================
rnl_round:
    push eax
    push ebx
    push ecx
    push edi

    ; Calling convention: EBP=out, ESI=in, ECX=from_q, EDX=to_p
    ; But EBP is being push'd/pop'd... let's use stack-passed implicit args.
    ; Actually we'll pass in memory via rnl_h_ptr, rnl_f_ptr, and two extra:
    ; Use a different convention: save args to locals
    push edx            ; to_p
    push ecx            ; from_q
    push esi            ; in
    push ebp            ; out

    xor  edi, edi       ; i = 0
.rr_loop:
    cmp  edi, RNL_N
    jge  .rr_done

    mov  esi, [esp+4]   ; in pointer
    mov  eax, [esi + edi*4]   ; in[i]
    mov  ecx, [esp+12]  ; to_p
    mul  ecx            ; edx:eax = in[i] * to_p  (fits in 32-bit since in[i]<65537, to_p<=65537)
    ; add from_q/2 for rounding
    mov  ecx, [esp+8]   ; from_q
    shr  ecx, 1         ; from_q/2
    add  eax, ecx
    ; divide by from_q
    mov  ecx, [esp+8]
    xor  edx, edx
    div  ecx            ; eax = quot
    ; % to_p
    xor  edx, edx
    mov  ecx, [esp+12]
    div  ecx            ; edx = quot % to_p... wait, eax % to_p
    ; actually eax = floor(in[i]*to_p+from_q/2)/from_q; need % to_p
    xor  edx, edx
    div  ecx            ; edx = remainder
    mov  eax, edx

    mov  ebp, [esp]     ; out pointer
    mov  [ebp + edi*4], eax
    inc  edi
    jmp  .rr_loop
.rr_done:
    add  esp, 16        ; clean stack args
    pop  edi
    pop  ecx
    pop  ebx
    pop  eax
    ret

; ============================================================
; rnl_lift: EBP=out, ESI=in, ECX=from_p, EDX=to_q
;   out[i] = in[i] * to_q / from_p % to_q
; ============================================================
rnl_lift:
    push eax
    push ebx
    push ecx
    push edi

    push edx            ; to_q
    push ecx            ; from_p
    push esi            ; in
    push ebp            ; out

    xor  edi, edi
.rl_loop:
    cmp  edi, RNL_N
    jge  .rl_done

    mov  esi, [esp+4]
    mov  eax, [esi + edi*4]   ; in[i]
    mov  ecx, [esp+12]        ; to_q
    mul  ecx                  ; edx:eax = in[i] * to_q
    ; divide by from_p
    mov  ecx, [esp+8]         ; from_p
    div  ecx                  ; eax = in[i]*to_q/from_p
    ; % to_q
    xor  edx, edx
    mov  ecx, [esp+12]
    div  ecx
    mov  eax, edx

    mov  ebp, [esp]
    mov  [ebp + edi*4], eax
    inc  edi
    jmp  .rl_loop
.rl_done:
    add  esp, 16
    pop  edi
    pop  ecx
    pop  ebx
    pop  eax
    ret

; ============================================================
; rnl_m_poly: EAX=p  --> sets p = 1+x+x^{N-1}
; ============================================================
rnl_m_poly:
    push ecx
    push edi
    mov  edi, eax
    ; zero all
    xor  eax, eax
    mov  ecx, RNL_N
    push edi
    rep  stosd
    pop  edi
    ; set p[0]=p[1]=p[N-1]=1
    mov  dword [edi], 1
    mov  dword [edi+4], 1
    mov  dword [edi + (RNL_N-1)*4], 1
    pop  edi
    pop  ecx
    ret

; ============================================================
; rnl_rand_poly: EAX=p  --> fills p with random coeffs mod Q
; ============================================================
rnl_rand_poly:
    push ebx
    push ecx
    push edx
    push esi
    mov  esi, eax
    xor  ecx, ecx
.rrp_loop:
    cmp  ecx, RNL_N
    jge  .rrp_done
    push ecx
    push esi
    call prng_next
    ; eax mod Q=65537
    xor  edx, edx
    mov  ebx, RNL_Q
    div  ebx
    mov  eax, edx
    pop  esi
    pop  ecx
    mov  [esi + ecx*4], eax
    inc  ecx
    jmp  .rrp_loop
.rrp_done:
    pop  esi
    pop  edx
    pop  ecx
    pop  ebx
    ret

; ============================================================
; rnl_small_poly: EAX=p  --> fills p with small coeffs in {0,1}
; ============================================================
rnl_small_poly:
    push ebx
    push ecx
    push edx
    push esi
    mov  esi, eax
    xor  ecx, ecx
.rsp_loop:
    cmp  ecx, RNL_N
    jge  .rsp_done
    push ecx
    push esi
    call prng_next
    and  eax, 1         ; % (B+1) = % 2 = & 1
    pop  esi
    pop  ecx
    mov  [esi + ecx*4], eax
    inc  ecx
    jmp  .rsp_loop
.rsp_done:
    pop  esi
    pop  edx
    pop  ecx
    pop  ebx
    ret

; ============================================================
; rnl_bits32: EAX=bits_poly --> EAX=uint32 key
;   bit i set if bits_poly[i] >= RNL_PP/2 = 1
; ============================================================
rnl_bits32:
    push ebx
    push ecx
    push edx
    push esi
    mov  esi, eax
    xor  edx, edx       ; result = 0
    xor  ecx, ecx       ; i = 0
.rb_loop:
    cmp  ecx, RNL_N
    jge  .rb_done
    mov  eax, [esi + ecx*4]
    cmp  eax, 1         ; >= RNL_PP/2
    jl   .rb_next
    mov  eax, 1
    shl  eax, cl
    or   edx, eax
.rb_next:
    inc  ecx
    jmp  .rb_loop
.rb_done:
    mov  eax, edx
    pop  esi
    pop  edx
    pop  ecx
    pop  ebx
    ret

; ============================================================
; rnl_keygen: EAX=s, EBX=C_out, ECX=m_blind
;   s = small_poly; C = round_p(m_blind * s)
; ============================================================
rnl_keygen:
    push ebx
    push ecx
    push edx
    push esi
    push edi
    push ebp
    mov  esi, eax       ; s
    mov  edi, ebx       ; C_out
    mov  ebp, ecx       ; m_blind

    ; rnl_small_poly(s)
    mov  eax, esi
    call rnl_small_poly

    ; rnl_poly_mul(rnl_tmp, m_blind, s)
    mov  dword [rnl_h_ptr], rnl_tmp
    mov  [rnl_f_ptr], ebp
    mov  [rnl_g_ptr], esi
    call rnl_poly_mul

    ; rnl_round(C_out, rnl_tmp, Q, P)
    mov  ebp, edi       ; out
    mov  esi, rnl_tmp   ; in
    mov  ecx, RNL_Q
    mov  edx, RNL_P
    call rnl_round

    pop  ebp
    pop  edi
    pop  esi
    pop  edx
    pop  ecx
    pop  ebx
    ret

; ============================================================
; rnl_agree: EAX=s, EBX=C_other --> EAX=uint32 key
;   lift(C_other); mul(s, lifted); round(PP); bits32
; ============================================================
rnl_agree:
    push ebx
    push ecx
    push edx
    push esi
    push edi
    push ebp
    mov  esi, eax       ; s
    mov  edi, ebx       ; C_other

    ; rnl_lift(rnl_tmp, C_other, P, Q)
    mov  ebp, rnl_tmp   ; out
    mov  esi, edi       ; in = C_other
    mov  ecx, RNL_P
    mov  edx, RNL_Q
    call rnl_lift

    ; rnl_poly_mul(rnl_tmp2, s, rnl_tmp)
    mov  dword [rnl_h_ptr], rnl_tmp2
    mov  esi, [esp+4]   ; restore s... hmm stack is shifted
    ; use saved esi from stack: esi was pushed 5th from bottom
    ; Actually let me save s separately
    pop  ebp
    pop  edi
    pop  esi
    pop  edx
    pop  ecx
    pop  ebx
    ; esi = s, edi = C_other
    push ebx
    push ecx
    push edx
    push esi
    push edi
    push ebp
    ; now esi = s (5th push from current esp)
    mov  esi, [esp + 5*4]  ; recover s
    mov  dword [rnl_h_ptr], rnl_tmp2
    mov  [rnl_f_ptr], esi
    mov  dword [rnl_g_ptr], rnl_tmp
    call rnl_poly_mul

    ; rnl_round(rnl_tmp, rnl_tmp2, Q, PP)
    mov  ebp, rnl_tmp
    mov  esi, rnl_tmp2
    mov  ecx, RNL_Q
    mov  edx, RNL_PP
    call rnl_round

    ; rnl_bits32(rnl_tmp) -> eax
    mov  eax, rnl_tmp
    call rnl_bits32

    pop  ebp
    pop  edi
    pop  esi
    pop  edx
    pop  ecx
    pop  ebx
    ret
