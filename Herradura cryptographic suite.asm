;  Herradura Cryptographic Suite v1.5.23
;  NASM i386 Assembly -- HKEX-GF, HSKE, HPKS, HPKE,
;                        HSKE-NL-A1/A2, HKEX-RNL, HPKS-NL, HPKE-NL,
;                        HPKS-Stern-F, HPKE-Stern-F
;  KEYBITS = 32, I_VALUE = 8, R_VALUE = 24
;  HKEX-GF: DH over GF(2^32)*, poly x^32+x^22+x^2+x+1, generator g=3
;  HPKS:    Schnorr signature; s=(k-a*e) mod ORD; verify g^s*C^e==R
;  HPKE:    El Gamal + fscx_revolve; enc_key=C^r; dec_key=R^a
;  NL-FSCX v2: nl_v2(A,B) = fscx(A,B) + delta(B)  mod 2^32
;              delta(B) = ROL32(B*((B+1)>>1), 8)
;              inv: B XOR M^{-1}((Y - delta(B)) mod 2^32)
;  HKEX-RNL: Ring-LWR, N=32, q=65537, p=4096, pp=2, B=1
;
;  v1.5.13: HSKE-NL-A1 seed=ROL(base,4) [n/8=4] fixes counter=0 step-1 degeneracy.
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
%define SDF_N      32
%define SDF_T      2
%define SDF_NROWS  16
%define SDF_ROUNDS 4

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
    val_nonce_nl1 dd 0  ; HSKE-NL-A1 per-session nonce
    val_ks_nl1  dd 0    ; HSKE-NL-A1 keystream
    val_E_nl1   dd 0
    val_E_nl2   dd 0    ; HSKE-NL-A2 ciphertext (saved for Eve)
    val_R_nl2   dd 0    ; HPKE-NL R=g^r (saved for Eve)
    val_r_nl    dd 0
    val_enc_nl  dd 0
    val_dec_nl  dd 0
    val_KA      dd 0
    val_KB      dd 0
    val_hint_A  dd 0
    val_sk_rnl  dd 0

    ; rnl_poly_mul implicit argument pointers
    rnl_f_ptr   dd 0
    rnl_g_ptr   dd 0
    rnl_h_ptr   dd 0

    ; NTT tables (n=32, q=65537, psi=3^1024 mod q)
    rnl_psi_pow_tab:
        dd 1,8224,65529,65282,64,2040,65025,49217
        dd 4096,65023,32769,4112,65533,32641,32,1020
        dd 65281,57377,2048,65280,49153,2056,65535,49089
        dd 16,510,65409,61457,1024,32640,57345,1028
    rnl_psi_inv_pow_tab:
        dd 1,64509,8192,32897,64513,4080,128,65027
        dd 65521,16448,2,63481,16384,257,63489,8160
        dd 256,64517,65505,32896,4,61425,32768,514
        dd 61441,16320,512,63497,65473,255,8,57313
    rnl_omega_fwd_tab:
        dd 1,65529,64,65025,4096,32769,65533,32
        dd 65281,2048,49153,65535,16,65409,1024,57345
    rnl_omega_inv_tab:
        dd 1,8192,64513,128,65521,2,16384,63489
        dd 256,65505,4,32768,61441,512,65473,8
    rnl_inv_n:   dd 63489
    rnl_bit_rev_tab:
        db 0,16,8,24,4,20,12,28,2,18,10,26,6,22,14,30
        db 1,17,9,25,5,21,13,29,3,19,11,27,7,23,15,31

    hdr         db "=== Herradura Cryptographic Suite v1.5.23 (NASM i386, KEYBITS=32, HKEX-GF) ===", 10
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
    lbl_N_nl1    db "N (nonce)    : "
    lbl_N_nl1_l  equ $-lbl_N_nl1
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

    ; Stern-F (code-based PQC) strings
    sdf_sign_hdr db 10, "--- HPKS-Stern-F [CODE-BASED PQC -- EUF-CMA; N=32, t=2, rounds=4]", 10
    sdf_sign_hdr_l equ $-sdf_sign_hdr
    sdf_enc_hdr  db 10, "--- HPKE-Stern-F [CODE-BASED PQC -- Niederreiter KEM, N=32]", 10
    sdf_enc_hdr_l equ $-sdf_enc_hdr
    sdf_note     db "    (demo: decap uses known e'; production needs QC-MDPC decoder)", 10
    sdf_note_l   equ $-sdf_note
    sdf_ok_msg   db "+ HPKS-Stern-F signature verified", 10
    sdf_ok_l     equ $-sdf_ok_msg
    sdf_fail_msg db "- HPKS-Stern-F verification FAILED", 10
    sdf_fail_l   equ $-sdf_fail_msg
    hpke_sdf_ok  db "+ HPKE-Stern-F session keys agree", 10
    hpke_sdf_ok_l equ $-hpke_sdf_ok
    hpke_sdf_fail db "- HPKE-Stern-F key agreement FAILED", 10
    hpke_sdf_fail_l equ $-hpke_sdf_fail
    eve_sdf_ok   db "- Eve cannot forge: Fiat-Shamir mismatch  (SD + PRF protection)", 10
    eve_sdf_ok_l equ $-eve_sdf_ok
    eve_sdf_fail_s db "+ Eve forged HPKS-Stern-F (Eve wins!)", 10
    eve_sdf_fail_l equ $-eve_sdf_fail_s
    eve_hpke_sdf_ok db "- Eve random guess does not match session key  (SD protection)", 10
    eve_hpke_sdf_ok_l equ $-eve_hpke_sdf_ok
    eve_hpke_sdf_fail db "+ Eve guessed HPKE-Stern-F session key!", 10
    eve_hpke_sdf_fail_l equ $-eve_hpke_sdf_fail
    lbl_K_enc    db "K (encap) : "
    lbl_K_enc_l  equ $-lbl_K_enc
    lbl_K_dec    db "K (decap) : "
    lbl_K_dec_l  equ $-lbl_K_dec
    ; Stern-F storage
    val_sdf_seed dd 0
    val_sdf_syn  dd 0
    val_sdf_e    dd 0
    val_sdf_K_enc dd 0
    val_sdf_K_dec dd 0
    val_sdf_e_prime dd 0
    val_sdf_ct   dd 0

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
    rnl_fa      resd RNL_N   ; NTT work arrays
    rnl_ga      resd RNL_N
    rnl_ha      resd RNL_N
    ; Stern-F scratch (N=32, rounds=4)
    sdf_perm    resb SDF_N
    sdf_c0      resd SDF_ROUNDS
    sdf_c1      resd SDF_ROUNDS
    sdf_c2      resd SDF_ROUNDS
    sdf_b       resd SDF_ROUNDS
    sdf_respA   resd SDF_ROUNDS
    sdf_respB   resd SDF_ROUNDS
    sdf_r_tmp   resd SDF_ROUNDS
    sdf_y_tmp   resd SDF_ROUNDS
    sdf_pi_tmp  resd SDF_ROUNDS
    sdf_sr_tmp  resd SDF_ROUNDS
    sdf_sy_tmp  resd SDF_ROUNDS
    sdf_chals_tmp resd SDF_ROUNDS

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

    ; N = prng_next(); base = key XOR N; ks = nl_fscx_revolve_v1(ROL(base,4), base, I_VALUE)
    call prng_next              ; eax = nonce N
    mov  [val_nonce_nl1], eax
    xor  eax, [val_key]         ; eax = base = N XOR key
    mov  ebx, eax               ; ebx = B = base (counter=0)
    rol  eax, 4                 ; eax = ROL(base, 4) = seed  [n=32, n/8=4]
    mov  ecx, I_VALUE
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

    ; ================================================================== HSKE-NL-A2
    ; CAUTION: deterministic — same (plain, key) always yields same E.
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

    ; skA = nl_fscx_revolve_v1(ROL32(KA,4), KA, I_VALUE)
    mov  eax, [val_KA]
    rol  eax, 4              ; seed = ROL32(KA, 4)  [n/8 = 32/8 = 4]
    mov  ebx, [val_KA]
    mov  ecx, I_VALUE
    call nl_fscx_revolve_v1  ; eax = sk
    mov  [val_sk_rnl], eax

    ; skB = nl_fscx_revolve_v1(ROL32(KB,4), KB, I_VALUE)
    mov  eax, [val_KB]
    rol  eax, 4
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

    ; ================================================================== HPKE-Stern-F
    mov  eax, sdf_enc_hdr
    mov  ecx, sdf_enc_hdr_l
    call print_str
    mov  eax, sdf_note
    mov  ecx, sdf_note_l
    call print_str

    ; encap
    call hpke_stern_f_encap_32
    ; decap (known e')
    mov  eax, [val_sdf_e_prime]
    call hpke_stern_f_decap_known_32
    mov  [val_sdf_K_dec], eax

    mov  eax, lbl_K_enc
    mov  ecx, lbl_K_enc_l
    call print_str
    mov  eax, [val_sdf_K_enc]
    call print_hex32
    mov  eax, lbl_K_dec
    mov  ecx, lbl_K_dec_l
    call print_str
    mov  eax, [val_sdf_K_dec]
    call print_hex32

    mov  eax, [val_sdf_K_enc]
    cmp  eax, [val_sdf_K_dec]
    jne  .hpke_sdf_fail
    mov  eax, hpke_sdf_ok
    mov  ecx, hpke_sdf_ok_l
    call print_str
    jmp  .hpke_sdf_done
.hpke_sdf_fail:
    mov  eax, hpke_sdf_fail
    mov  ecx, hpke_sdf_fail_l
    call print_str
.hpke_sdf_done:

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

    ; Eve guesses HPKE-Stern-F session key
    call prng_next
    cmp  eax, [val_sdf_K_enc]
    je   .eve_hpke_sdf_fail
    mov  eax, eve_hpke_sdf_ok
    mov  ecx, eve_hpke_sdf_ok_l
    call print_str
    jmp  .eve_hpke_sdf_done
.eve_hpke_sdf_fail:
    mov  eax, eve_hpke_sdf_fail
    mov  ecx, eve_hpke_sdf_fail_l
    call print_str
.eve_hpke_sdf_done:

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
; m_inv_32: EAX=X --> EAX=M^{-1}(X) via precomputed rotation table
; M^{-1}(X) = XOR of ROL(X,k) for k in {0,2,3,5,6,8,9,...,29,30}
; (bits of 0x6DB6DB6D = fscx_revolve(1,0,15) for n=32)
; ============================================================
m_inv_32:
    push    ebx
    mov     ebx, eax            ; save original X; eax = ROL(X,0) = X
    mov     ecx, ebx
    rol     ecx, 2              ; ROL(X, 2)
    xor     eax, ecx
    mov     ecx, ebx
    rol     ecx, 3
    xor     eax, ecx
    mov     ecx, ebx
    rol     ecx, 5
    xor     eax, ecx
    mov     ecx, ebx
    rol     ecx, 6
    xor     eax, ecx
    mov     ecx, ebx
    rol     ecx, 8
    xor     eax, ecx
    mov     ecx, ebx
    rol     ecx, 9
    xor     eax, ecx
    mov     ecx, ebx
    rol     ecx, 11
    xor     eax, ecx
    mov     ecx, ebx
    rol     ecx, 12
    xor     eax, ecx
    mov     ecx, ebx
    rol     ecx, 14
    xor     eax, ecx
    mov     ecx, ebx
    rol     ecx, 15
    xor     eax, ecx
    mov     ecx, ebx
    rol     ecx, 17
    xor     eax, ecx
    mov     ecx, ebx
    rol     ecx, 18
    xor     eax, ecx
    mov     ecx, ebx
    rol     ecx, 20
    xor     eax, ecx
    mov     ecx, ebx
    rol     ecx, 21
    xor     eax, ecx
    mov     ecx, ebx
    rol     ecx, 23
    xor     eax, ecx
    mov     ecx, ebx
    rol     ecx, 24
    xor     eax, ecx
    mov     ecx, ebx
    rol     ecx, 26
    xor     eax, ecx
    mov     ecx, ebx
    rol     ecx, 27
    xor     eax, ecx
    mov     ecx, ebx
    rol     ecx, 29
    xor     eax, ecx
    mov     ecx, ebx
    rol     ecx, 30
    xor     eax, ecx
    pop     ebx
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
; delta(B) precomputed once — B constant throughout the revolve
; ============================================================
nl_fscx_revolve_v2_inv:
    push esi
    push edi
    push ebp
    mov  esi, eax               ; esi = current y
    mov  edi, ecx               ; edi = steps
    mov  eax, ebx
    call nl_fscx_delta_v2       ; eax = delta(B)
    mov  ebp, eax               ; ebp = delta (precomputed once)
.rv2i_loop:
    test edi, edi
    jz   .rv2i_done
    sub  esi, ebp               ; z = y - delta  (mod 2^32)
    mov  eax, esi
    call m_inv_32               ; eax = M^{-1}(z)
    xor  eax, ebx               ; y = B XOR M^{-1}(z)
    mov  esi, eax
    dec  edi
    jmp  .rv2i_loop
.rv2i_done:
    mov  eax, esi
    pop  ebp
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
; rnl_ntt: in-place NTT/INTT  [cdecl: push arr; push invert; call]
;   arr=array ptr (dwords), invert=0(fwd)/1(inv)
; ============================================================
rnl_ntt:
    push  ebp
    mov   ebp, esp
    sub   esp, 24
    ; locals: [ebp-4]=omega_l [ebp-8]=half [ebp-12]=grp_i
    ;         [ebp-16]=wn     [ebp-20]=omega_tab [ebp-24]=length
    push  ebx
    push  ecx
    push  edx
    push  esi
    push  edi
    ; args: [ebp+8]=arr  [ebp+12]=invert
    mov   esi, [ebp+8]

    ; Bit-reversal permutation
    xor   ecx, ecx
.ntt_br:
    cmp   ecx, RNL_N
    jge   .ntt_br_done
    movzx eax, byte [rnl_bit_rev_tab + ecx]
    cmp   ecx, eax
    jge   .ntt_br_skip
    mov   edx, [esi + ecx*4]
    mov   ebx, [esi + eax*4]
    mov   [esi + ecx*4], ebx
    mov   [esi + eax*4], edx
.ntt_br_skip:
    inc   ecx
    jmp   .ntt_br
.ntt_br_done:

    ; Select omega table
    mov   eax, rnl_omega_fwd_tab
    cmp   dword [ebp+12], 0
    je    .ntt_tab_ok
    mov   eax, rnl_omega_inv_tab
.ntt_tab_ok:
    mov   [ebp-20], eax

    ; Stage loop: length = 2,4,8,16,32
    mov   dword [ebp-24], 2
.ntt_stage:
    mov   ebx, [ebp-24]
    cmp   ebx, RNL_N
    jg    .ntt_stage_done

    mov   ecx, ebx
    shr   ecx, 1
    mov   [ebp-8], ecx          ; half

    ; step = 32/length; omega_l = omega_tab[step]
    mov   eax, 32
    xor   edx, edx
    div   ebx                    ; eax = step
    mov   ecx, [ebp-20]
    mov   eax, [ecx + eax*4]
    mov   [ebp-4], eax           ; omega_l

    ; Group loop
    mov   dword [ebp-12], 0
.ntt_grp:
    cmp   dword [ebp-12], RNL_N
    jge   .ntt_grp_done
    mov   dword [ebp-16], 1     ; wn = 1

    ; Butterfly loop: k via edi
    xor   edi, edi
.ntt_bf:
    cmp   edi, [ebp-8]
    jge   .ntt_bf_done

    ; u = arr[grp_i+k]
    mov   eax, [ebp-12]
    add   eax, edi
    mov   ecx, [esi + eax*4]    ; u

    ; v_raw = arr[grp_i+k+half]
    add   eax, [ebp-8]
    mov   edx, [esi + eax*4]    ; v_raw

    ; v = v_raw * wn mod q
    push  eax
    push  ecx
    mov   eax, edx
    mul   dword [ebp-16]
    add   eax, edx
    xor   edx, edx
    mov   ecx, RNL_Q
    div   ecx                   ; edx = v
    pop   ecx                   ; u
    pop   eax                   ; idx2

    ; arr[grp_i+k] = (u+v) mod q
    push  eax
    mov   eax, [ebp-12]
    add   eax, edi
    mov   ebx, ecx
    add   ebx, edx
    cmp   ebx, RNL_Q
    jl    .ntt_nosub1
    sub   ebx, RNL_Q
.ntt_nosub1:
    mov   [esi + eax*4], ebx

    ; arr[grp_i+k+half] = (u-v+q) mod q
    pop   eax
    sub   ecx, edx
    add   ecx, RNL_Q
    cmp   ecx, RNL_Q
    jl    .ntt_nosub2
    sub   ecx, RNL_Q
.ntt_nosub2:
    mov   [esi + eax*4], ecx

    ; wn = wn * omega_l mod q
    mov   eax, [ebp-16]
    mul   dword [ebp-4]
    add   eax, edx
    xor   edx, edx
    mov   ecx, RNL_Q
    div   ecx
    mov   [ebp-16], edx

    inc   edi
    jmp   .ntt_bf
.ntt_bf_done:

    mov   eax, [ebp-24]
    add   [ebp-12], eax
    jmp   .ntt_grp
.ntt_grp_done:

    shl   dword [ebp-24], 1
    jmp   .ntt_stage
.ntt_stage_done:

    ; If inverse: scale by inv_n
    cmp   dword [ebp+12], 0
    je    .ntt_inv_done
    xor   ecx, ecx
.ntt_scale:
    cmp   ecx, RNL_N
    jge   .ntt_inv_done
    mov   eax, [esi + ecx*4]
    mul   dword [rnl_inv_n]
    add   eax, edx
    xor   edx, edx
    mov   ebx, RNL_Q
    div   ebx
    mov   [esi + ecx*4], edx
    inc   ecx
    jmp   .ntt_scale
.ntt_inv_done:

    pop   edi
    pop   esi
    pop   edx
    pop   ecx
    pop   ebx
    leave
    ret

; ============================================================
; rnl_poly_mul: h=f*g in Z_q[x]/(x^N+1) via NTT. O(N log N).
; ============================================================
rnl_poly_mul:
    push  ebx
    push  ecx
    push  edx
    push  esi
    push  edi
    push  ebp

    ; Twist: fa[i]=f[i]*psi_pow[i] mod q, ga[i]=g[i]*psi_pow[i] mod q
    mov   esi, [rnl_f_ptr]
    mov   edi, [rnl_g_ptr]
    xor   ecx, ecx
.rpm_twist:
    cmp   ecx, RNL_N
    jge   .rpm_twist_done
    mov   ebp, [rnl_psi_pow_tab + ecx*4]  ; psi_pow[i]
    mov   eax, [esi + ecx*4]
    mul   ebp
    add   eax, edx
    xor   edx, edx
    mov   ebx, RNL_Q
    div   ebx
    mov   [rnl_fa + ecx*4], edx
    mov   eax, [edi + ecx*4]
    mul   ebp
    add   eax, edx
    xor   edx, edx
    mov   ebx, RNL_Q
    div   ebx
    mov   [rnl_ga + ecx*4], edx
    inc   ecx
    jmp   .rpm_twist
.rpm_twist_done:

    push  dword 0
    push  dword rnl_fa
    call  rnl_ntt
    add   esp, 8

    push  dword 0
    push  dword rnl_ga
    call  rnl_ntt
    add   esp, 8

    ; Pointwise multiply: ha[i] = fa[i]*ga[i] mod q
    xor   ecx, ecx
.rpm_pw:
    cmp   ecx, RNL_N
    jge   .rpm_pw_done
    mov   eax, [rnl_fa + ecx*4]
    mul   dword [rnl_ga + ecx*4]
    add   eax, edx
    xor   edx, edx
    mov   ebx, RNL_Q
    div   ebx
    mov   [rnl_ha + ecx*4], edx
    inc   ecx
    jmp   .rpm_pw
.rpm_pw_done:

    push  dword 1
    push  dword rnl_ha
    call  rnl_ntt
    add   esp, 8

    ; Untwist: h[i] = ha[i]*psi_inv_pow[i] mod q
    mov   edi, [rnl_h_ptr]
    xor   ecx, ecx
.rpm_untwist:
    cmp   ecx, RNL_N
    jge   .rpm_untwist_done
    mov   eax, [rnl_ha + ecx*4]
    mul   dword [rnl_psi_inv_pow_tab + ecx*4]
    add   eax, edx
    xor   edx, edx
    mov   ebx, RNL_Q
    div   ebx
    mov   [edi + ecx*4], edx
    inc   ecx
    jmp   .rpm_untwist
.rpm_untwist_done:

    pop   ebp
    pop   edi
    pop   esi
    pop   edx
    pop   ecx
    pop   ebx
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
    div  ecx            ; edx = floor_result % to_p
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
; rnl_rand_poly: EAX=p  --> fills p with uniform coeffs in [0,Q)
;   3-byte rejection sampling; threshold=0xFF00FF; reject prob ~0.39%
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
.rrp_sample:
    push ecx
    push esi
    call prng_next
    pop  esi
    pop  ecx
    and  eax, 0xFFFFFF          ; mask to 24 bits
    cmp  eax, 0xFF00FF          ; threshold = (1<<24)-(1<<24)%RNL_Q
    jae  .rrp_sample            ; reject: redraw
    xor  edx, edx
    mov  ebx, RNL_Q
    div  ebx                    ; edx = eax % RNL_Q
    mov  eax, edx
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
; rnl_cbd_poly: EAX=p  --> fills p with CBD(1) coeffs in {RNL_Q-1, 0, 1}
;   raw = prng_next(); a = raw&1; b = (raw>>1)&1; coeff = a-b mod RNL_Q
; ============================================================
rnl_cbd_poly:
    push ebx
    push ecx
    push edx
    push esi
    push edi
    mov  esi, eax
    xor  ecx, ecx
.rcp_loop:
    cmp  ecx, RNL_N
    jge  .rcp_done
    push ecx
    push esi
    call prng_next
    mov  edi, eax
    and  edi, 1         ; a = raw & 1
    shr  eax, 1
    and  eax, 1         ; b = (raw>>1) & 1
    sub  edi, eax       ; coeff = a - b  (may be -1)
    jge  .rcp_store
    add  edi, RNL_Q     ; coeff + RNL_Q to keep non-negative
.rcp_store:
    pop  esi
    pop  ecx
    mov  [esi + ecx*4], edi
    inc  ecx
    jmp  .rcp_loop
.rcp_done:
    pop  edi
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

    ; rnl_cbd_poly(s)
    mov  eax, esi
    call rnl_cbd_poly

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
; rnl_hint32: EAX=K_poly -> EAX=hint_uint32
;   For each coeff c: quarter = c / (q/4); h = quarter % 2
; ============================================================
rnl_hint32:
    push ebx
    push ecx
    push edx
    push esi
    push edi
    mov  esi, eax
    xor  edi, edi
    xor  ecx, ecx
.rh32_loop:
    cmp  ecx, RNL_N
    jge  .rh32_done
    mov  eax, [esi + ecx*4]
    cmp  eax, 0x4000         ; q/4
    jl   .rh32_next
    cmp  eax, 0x8000         ; q/2
    jge  .rh32_upper
    mov  edx, 1
    shl  edx, cl
    or   edi, edx
    jmp  .rh32_next
.rh32_upper:
    cmp  eax, 0xC000         ; 3q/4
    jl   .rh32_next
    mov  edx, 1
    shl  edx, cl
    or   edi, edx
.rh32_next:
    inc  ecx
    jmp  .rh32_loop
.rh32_done:
    mov  eax, edi
    pop  edi
    pop  esi
    pop  edx
    pop  ecx
    pop  ebx
    ret

; ============================================================
; rnl_reconcile32: EAX=K_poly, EBX=hint -> EAX=key_uint32
;   b[i] = ((2*c + h*32768 + 32768) / 65537) % 2
; ============================================================
rnl_reconcile32:
    push ebx
    push ecx
    push edx
    push esi
    push edi
    push ebp
    mov  esi, eax
    mov  ebp, ebx
    xor  edi, edi
    xor  ecx, ecx
.rc32_loop:
    cmp  ecx, RNL_N
    jge  .rc32_done
    mov  eax, [esi + ecx*4]  ; c
    shl  eax, 1              ; 2*c
    mov  edx, ebp
    shr  edx, cl
    and  edx, 1              ; h
    shl  edx, 15             ; h * 32768
    add  eax, edx            ; 2*c + h*32768
    add  eax, 0x8000         ; + 32768
    ; b = (eax / 65537) % 2; eax/65537 ∈ {0,1,2,3}
    cmp  eax, RNL_Q
    jl   .rc32_next          ; val < q → b=0
    sub  eax, RNL_Q
    cmp  eax, RNL_Q
    jge  .rc32_upper
    ; val in [q, 2q) → b=1
    mov  edx, 1
    shl  edx, cl
    or   edi, edx
    jmp  .rc32_next
.rc32_upper:
    sub  eax, RNL_Q
    cmp  eax, RNL_Q
    jl   .rc32_next          ; val in [2q, 3q) → b=0
    ; val in [3q, 4q) → b=1
    mov  edx, 1
    shl  edx, cl
    or   edi, edx
.rc32_next:
    inc  ecx
    jmp  .rc32_loop
.rc32_done:
    mov  eax, edi
    pop  ebp
    pop  edi
    pop  esi
    pop  edx
    pop  ecx
    pop  ebx
    ret

; ============================================================
; rnl_agree_full: EAX=s, EBX=C_other -> EAX=key, EDX=hint
; ============================================================
rnl_agree_full:
    push ebx
    push esi
    push edi
    push ebp
    sub  esp, 4                 ; [esp] = hint slot

    mov  edi, eax               ; edi = s  (rnl_lift preserves edi)
    mov  esi, ebx               ; esi = C_other

    mov  ebp, rnl_tmp
    mov  ecx, RNL_P
    mov  edx, RNL_Q
    call rnl_lift

    mov  dword [rnl_h_ptr], rnl_tmp2
    mov  [rnl_f_ptr], edi
    mov  dword [rnl_g_ptr], rnl_tmp
    call rnl_poly_mul

    mov  eax, rnl_tmp2
    call rnl_hint32
    mov  [esp], eax

    mov  eax, rnl_tmp2
    mov  ebx, [esp]
    call rnl_reconcile32

    mov  edx, [esp]
    add  esp, 4
    pop  ebp
    pop  edi
    pop  esi
    pop  ebx
    ret

; ============================================================
; rnl_agree_recv: EAX=s, EBX=C_other, ECX=hint -> EAX=key
; ============================================================
rnl_agree_recv:
    push ebx
    push esi
    push edi
    push ebp
    sub  esp, 4                 ; [esp] = hint slot

    mov  edi, eax               ; edi = s  (rnl_lift preserves edi)
    mov  esi, ebx               ; esi = C_other
    mov  [esp], ecx             ; save hint

    mov  ebp, rnl_tmp
    mov  ecx, RNL_P
    mov  edx, RNL_Q
    call rnl_lift

    mov  dword [rnl_h_ptr], rnl_tmp2
    mov  [rnl_f_ptr], edi
    mov  dword [rnl_g_ptr], rnl_tmp
    call rnl_poly_mul

    mov  eax, rnl_tmp2
    mov  ebx, [esp]
    call rnl_reconcile32

    add  esp, 4
    pop  ebp
    pop  edi
    pop  esi
    pop  ebx
    ret

; ============================================================
; stern_hash1_32: EAX=v -> EAX=sternHash(v)
; h = nl_fscx_revolve_v1(v, ROL(v,4), 8)
; ============================================================
stern_hash1_32:
    push ecx
    push ebx
    mov  ebx, eax
    rol  ebx, 4
    mov  ecx, 8
    call nl_fscx_revolve_v1
    pop  ebx
    pop  ecx
    ret

; ============================================================
; stern_hash2_32: EAX=item0, EBX=item1 -> EAX=sternHash(item0,item1)
; ============================================================
stern_hash2_32:
    push esi
    push ecx
    mov  esi, ebx           ; save item1
    ; step1: h = nl_fscx_revolve_v1(item0, ROL(item0,4), 8)
    mov  ebx, eax
    rol  ebx, 4
    mov  ecx, 8
    call nl_fscx_revolve_v1 ; eax = h
    ; step2: h = nl_fscx_revolve_v1(h^item1, ROL(item1,4), 8)
    xor  eax, esi
    mov  ebx, esi
    rol  ebx, 4
    call nl_fscx_revolve_v1
    pop  ecx
    pop  esi
    ret

; ============================================================
; stern_matrix_row_32: EAX=seed, EBX=row -> EAX=H[row]
; H[row] = nl_fscx_revolve_v1(ROL(seed^row,4), seed, 8)
; ============================================================
stern_matrix_row_32:
    push ecx
    push esi
    mov  esi, eax           ; save seed
    xor  eax, ebx           ; seed XOR row
    rol  eax, 4             ; base
    mov  ebx, esi           ; B = seed
    mov  ecx, 8
    call nl_fscx_revolve_v1
    pop  esi
    pop  ecx
    ret

; ============================================================
; stern_syndrome_32: EAX=seed, EBX=e -> EAX=syndrome (16-bit)
; ============================================================
stern_syndrome_32:
    push ebx
    push esi
    push edi
    push ebp
    push ecx
    push edx
    mov  esi, eax           ; seed
    mov  edi, ebx           ; e
    xor  ebp, ebp           ; accumulator
    xor  ecx, ecx           ; row = 0
.sds_loop:
    cmp  ecx, SDF_NROWS
    jge  .sds_done
    push ecx
    mov  eax, esi
    mov  ebx, ecx
    call stern_matrix_row_32
    pop  ecx
    and  eax, edi
    mov  edx, eax
    shr  edx, 16
    xor  eax, edx
    mov  edx, eax
    shr  edx, 8
    xor  eax, edx
    mov  edx, eax
    shr  edx, 4
    xor  eax, edx
    mov  edx, eax
    shr  edx, 2
    xor  eax, edx
    mov  edx, eax
    shr  edx, 1
    xor  eax, edx
    and  eax, 1
    shl  eax, cl
    or   ebp, eax
    inc  ecx
    jmp  .sds_loop
.sds_done:
    mov  eax, ebp
    pop  edx
    pop  ecx
    pop  ebp
    pop  edi
    pop  esi
    pop  ebx
    ret

; ============================================================
; stern_popcount_eq2: EAX=v -> EAX=1 iff popcount==2
; ============================================================
stern_popcount_eq2:
    push ecx
    test eax, eax
    jz   .speq2_fail
    lea  ecx, [eax-1]
    and  eax, ecx
    jz   .speq2_fail
    lea  ecx, [eax-1]
    test eax, ecx
    jnz  .speq2_fail
    mov  eax, 1
    jmp  .speq2_done
.speq2_fail:
    xor  eax, eax
.speq2_done:
    pop  ecx
    ret

; ============================================================
; stern_gen_perm_32: EAX=pi_seed -> sdf_perm[0..31]
; Fisher-Yates using nl_fscx_v1 as PRNG
; ============================================================
stern_gen_perm_32:
    push ebx
    push esi
    push edi
    push ebp
    push ecx
    push edx
    mov  esi, eax
    mov  edi, eax
    rol  edi, 4             ; key = ROL(pi_seed, 4)
    xor  ecx, ecx
.sgp_init:
    cmp  ecx, SDF_N
    jge  .sgp_init_done
    mov  byte [sdf_perm + ecx], cl
    inc  ecx
    jmp  .sgp_init
.sgp_init_done:
    mov  ebp, SDF_N - 1
.sgp_loop:
    cmp  ebp, 1
    jl   .sgp_done
    mov  eax, esi
    mov  ebx, edi
    call nl_fscx_v1
    mov  esi, eax
    xor  edx, edx
    mov  ecx, ebp
    inc  ecx
    div  ecx                ; edx = esi % (i+1)
    movzx eax, byte [sdf_perm + ebp]
    movzx ecx, byte [sdf_perm + edx]
    mov  byte [sdf_perm + ebp], cl
    mov  byte [sdf_perm + edx], al
    dec  ebp
    jmp  .sgp_loop
.sgp_done:
    pop  edx
    pop  ecx
    pop  ebp
    pop  edi
    pop  esi
    pop  ebx
    ret

; ============================================================
; stern_apply_perm_32: EAX=v -> EAX = apply(sdf_perm, v)
; ============================================================
stern_apply_perm_32:
    push ebx
    push esi
    push edi
    push ecx
    mov  esi, eax
    xor  edi, edi
    xor  ecx, ecx
.sap_loop:
    cmp  ecx, SDF_N
    jge  .sap_done
    bt   esi, ecx
    jnc  .sap_next
    movzx eax, byte [sdf_perm + ecx]
    bts  edi, eax
.sap_next:
    inc  ecx
    jmp  .sap_loop
.sap_done:
    mov  eax, edi
    pop  ecx
    pop  edi
    pop  esi
    pop  ebx
    ret

; ============================================================
; stern_rand_error_32: -> EAX = weight-2 error vector
; ============================================================
stern_rand_error_32:
    push ebx
    push esi
    push edi
    push ecx
    push edx
    xor  ecx, ecx
.sre_init:
    cmp  ecx, SDF_N
    jge  .sre_init_done
    mov  byte [sdf_perm + ecx], cl
    inc  ecx
    jmp  .sre_init
.sre_init_done:
    call prng_next
    xor  edx, edx
    mov  ecx, 32
    div  ecx
    movzx eax, byte [sdf_perm + 31]
    movzx ecx, byte [sdf_perm + edx]
    mov  byte [sdf_perm + 31], cl
    mov  byte [sdf_perm + edx], al
    call prng_next
    xor  edx, edx
    mov  ecx, 31
    div  ecx
    movzx eax, byte [sdf_perm + 30]
    movzx ecx, byte [sdf_perm + edx]
    mov  byte [sdf_perm + 30], cl
    mov  byte [sdf_perm + edx], al
    movzx ecx, byte [sdf_perm + 31]
    mov  eax, 1
    shl  eax, cl
    movzx ecx, byte [sdf_perm + 30]
    mov  edx, 1
    shl  edx, cl
    or   eax, edx
    pop  edx
    pop  ecx
    pop  edi
    pop  esi
    pop  ebx
    ret

; ============================================================
; stern_fs_challenges_32: -> sdf_chals_tmp[0..3]
; reads val_plain (msg), sdf_c0, sdf_c1, sdf_c2
; ============================================================
stern_fs_challenges_32:
    push ebx
    push esi
    push edi
    push ecx
    push edx
    xor  esi, esi
    mov  eax, [val_plain]
    xor  eax, esi
    mov  ebx, [val_plain]
    rol  ebx, 4
    mov  ecx, 8
    call nl_fscx_revolve_v1
    mov  esi, eax
    xor  edi, edi
.sfc_round_loop:
    cmp  edi, SDF_ROUNDS
    jge  .sfc_round_done
    mov  eax, [sdf_c0 + edi*4]
    xor  eax, esi
    mov  ebx, [sdf_c0 + edi*4]
    rol  ebx, 4
    mov  ecx, 8
    call nl_fscx_revolve_v1
    mov  esi, eax
    mov  eax, [sdf_c1 + edi*4]
    xor  eax, esi
    mov  ebx, [sdf_c1 + edi*4]
    rol  ebx, 4
    call nl_fscx_revolve_v1
    mov  esi, eax
    mov  eax, [sdf_c2 + edi*4]
    xor  eax, esi
    mov  ebx, [sdf_c2 + edi*4]
    rol  ebx, 4
    call nl_fscx_revolve_v1
    mov  esi, eax
    inc  edi
    jmp  .sfc_round_loop
.sfc_round_done:
    xor  edi, edi
.sfc_chal_loop:
    cmp  edi, SDF_ROUNDS
    jge  .sfc_done
    mov  eax, esi
    mov  ebx, edi
    call nl_fscx_v1
    mov  esi, eax
    xor  edx, edx
    mov  ecx, 3
    div  ecx
    mov  [sdf_chals_tmp + edi*4], edx
    inc  edi
    jmp  .sfc_chal_loop
.sfc_done:
    pop  edx
    pop  ecx
    pop  edi
    pop  esi
    pop  ebx
    ret

; ============================================================
; hpks_stern_f_sign_32: reads val_sdf_e, val_sdf_seed, val_plain
; fills sdf_c0..c2, sdf_b, sdf_respA, sdf_respB
; ============================================================
hpks_stern_f_sign_32:
    push ebx
    push esi
    push edi
    push ebp
    push ecx
    push edx
    mov  esi, [val_sdf_seed]
    mov  edi, [val_sdf_e]
    xor  ebp, ebp
.hsfs_loop:
    cmp  ebp, SDF_ROUNDS
    jge  .hsfs_loop_done
    call stern_rand_error_32
    mov  [sdf_r_tmp + ebp*4], eax
    xor  eax, edi
    mov  [sdf_y_tmp + ebp*4], eax
    call prng_next
    mov  [sdf_pi_tmp + ebp*4], eax
    call stern_gen_perm_32
    mov  eax, [sdf_r_tmp + ebp*4]
    call stern_apply_perm_32
    mov  [sdf_sr_tmp + ebp*4], eax
    mov  eax, [sdf_y_tmp + ebp*4]
    call stern_apply_perm_32
    mov  [sdf_sy_tmp + ebp*4], eax
    mov  eax, esi
    mov  ebx, [sdf_r_tmp + ebp*4]
    call stern_syndrome_32
    mov  ebx, eax
    mov  eax, [sdf_pi_tmp + ebp*4]
    call stern_hash2_32
    mov  [sdf_c0 + ebp*4], eax
    mov  eax, [sdf_sr_tmp + ebp*4]
    call stern_hash1_32
    mov  [sdf_c1 + ebp*4], eax
    mov  eax, [sdf_sy_tmp + ebp*4]
    call stern_hash1_32
    mov  [sdf_c2 + ebp*4], eax
    inc  ebp
    jmp  .hsfs_loop
.hsfs_loop_done:
    call stern_fs_challenges_32
    xor  ebp, ebp
.hsfs_resp_loop:
    cmp  ebp, SDF_ROUNDS
    jge  .hsfs_resp_done
    mov  eax, [sdf_chals_tmp + ebp*4]
    mov  [sdf_b + ebp*4], eax
    cmp  eax, 0
    je   .hsfs_case0
    cmp  eax, 1
    je   .hsfs_case1
    mov  eax, [sdf_pi_tmp + ebp*4]
    mov  [sdf_respA + ebp*4], eax
    mov  eax, [sdf_y_tmp + ebp*4]
    mov  [sdf_respB + ebp*4], eax
    jmp  .hsfs_resp_next
.hsfs_case0:
    mov  eax, [sdf_sr_tmp + ebp*4]
    mov  [sdf_respA + ebp*4], eax
    mov  eax, [sdf_sy_tmp + ebp*4]
    mov  [sdf_respB + ebp*4], eax
    jmp  .hsfs_resp_next
.hsfs_case1:
    mov  eax, [sdf_pi_tmp + ebp*4]
    mov  [sdf_respA + ebp*4], eax
    mov  eax, [sdf_r_tmp + ebp*4]
    mov  [sdf_respB + ebp*4], eax
.hsfs_resp_next:
    inc  ebp
    jmp  .hsfs_resp_loop
.hsfs_resp_done:
    pop  edx
    pop  ecx
    pop  ebp
    pop  edi
    pop  esi
    pop  ebx
    ret

; ============================================================
; hpks_stern_f_verify_32: -> EAX=1 valid, 0 invalid
; ============================================================
hpks_stern_f_verify_32:
    push ebx
    push esi
    push edi
    push ebp
    push ecx
    push edx
    call stern_fs_challenges_32
    xor  ecx, ecx
.hsfv_chal_chk:
    cmp  ecx, SDF_ROUNDS
    jge  .hsfv_chal_ok
    mov  eax, [sdf_chals_tmp + ecx*4]
    cmp  eax, [sdf_b + ecx*4]
    jne  .hsfv_fail
    inc  ecx
    jmp  .hsfv_chal_chk
.hsfv_chal_ok:
    mov  esi, [val_sdf_seed]
    mov  edi, [val_sdf_syn]
    xor  ebp, ebp
.hsfv_round_loop:
    cmp  ebp, SDF_ROUNDS
    jge  .hsfv_pass
    mov  ecx, [sdf_b + ebp*4]
    mov  edx, [sdf_respA + ebp*4]
    cmp  ecx, 0
    je   .hsfv_case0
    cmp  ecx, 1
    je   .hsfv_case1
    mov  eax, esi
    mov  ebx, [sdf_respB + ebp*4]
    call stern_syndrome_32
    xor  eax, edi
    mov  ebx, eax
    mov  eax, edx
    call stern_hash2_32
    cmp  eax, [sdf_c0 + ebp*4]
    jne  .hsfv_fail
    mov  eax, edx
    call stern_gen_perm_32
    mov  eax, [sdf_respB + ebp*4]
    call stern_apply_perm_32
    call stern_hash1_32
    cmp  eax, [sdf_c2 + ebp*4]
    jne  .hsfv_fail
    jmp  .hsfv_round_next
.hsfv_case0:
    mov  eax, edx
    call stern_hash1_32
    cmp  eax, [sdf_c1 + ebp*4]
    jne  .hsfv_fail
    mov  eax, [sdf_respB + ebp*4]
    call stern_hash1_32
    cmp  eax, [sdf_c2 + ebp*4]
    jne  .hsfv_fail
    mov  eax, edx
    call stern_popcount_eq2
    test eax, eax
    jz   .hsfv_fail
    jmp  .hsfv_round_next
.hsfv_case1:
    mov  eax, [sdf_respB + ebp*4]
    call stern_popcount_eq2
    test eax, eax
    jz   .hsfv_fail
    mov  eax, esi
    mov  ebx, [sdf_respB + ebp*4]
    call stern_syndrome_32
    mov  ebx, eax
    mov  eax, edx
    call stern_hash2_32
    cmp  eax, [sdf_c0 + ebp*4]
    jne  .hsfv_fail
    mov  eax, edx
    call stern_gen_perm_32
    mov  eax, [sdf_respB + ebp*4]
    call stern_apply_perm_32
    call stern_hash1_32
    cmp  eax, [sdf_c1 + ebp*4]
    jne  .hsfv_fail
.hsfv_round_next:
    inc  ebp
    jmp  .hsfv_round_loop
.hsfv_pass:
    mov  eax, 1
    jmp  .hsfv_exit
.hsfv_fail:
    xor  eax, eax
.hsfv_exit:
    pop  edx
    pop  ecx
    pop  ebp
    pop  edi
    pop  esi
    pop  ebx
    ret

; ============================================================
; hpke_stern_f_encap_32: fills val_sdf_e_prime, val_sdf_ct, val_sdf_K_enc
; ============================================================
hpke_stern_f_encap_32:
    push ebx
    push esi
    push ecx
    push edx
    call stern_rand_error_32
    mov  esi, eax
    mov  [val_sdf_e_prime], eax
    mov  eax, [val_sdf_seed]
    mov  ebx, esi
    call stern_syndrome_32
    mov  [val_sdf_ct], eax
    mov  eax, [val_sdf_seed]
    mov  ebx, esi
    call stern_hash2_32
    mov  [val_sdf_K_enc], eax
    pop  edx
    pop  ecx
    pop  esi
    pop  ebx
    ret

; ============================================================
; hpke_stern_f_decap_known_32: EAX=e' -> EAX=K=hash2(seed,e')
; ============================================================
hpke_stern_f_decap_known_32:
    push ebx
    mov  ebx, eax
    mov  eax, [val_sdf_seed]
    call stern_hash2_32
    pop  ebx
    ret
