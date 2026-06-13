;  Herradura KEx -- Correctness Tests v1.8.0
;  NASM i386 Assembly -- HKEX-GF, HSKE, HPKS Schnorr, HPKE El Gamal,
;                        NL-FSCX v2 inv, HSKE-NL-A2, HKEX-RNL, HPKS-NL, HPKE-NL,
;                        HPKS-Stern-F, HPKE-Stern-F
;  KEYBITS=32; I_VALUE=8; R_VALUE=24; HKEX-RNL N=32, q=65537, p=4096
;  20 iterations per HKEX/HPKS/HPKE test; 100 per HSKE; 20 per NL tests; 10 per RNL
;
;  Copyright (C) 2024-2026 Omar Alejandro Herrera Reyna
;  MIT License / GPL v3.0 -- choose either.
;
;  Assemble: nasm -f elf32 Herradura_tests.asm -o tests32.o
;  Link:     x86_64-linux-gnu-ld -m elf_i386 -o Herradura_tests_i386 tests32.o
;  Run:      ./Herradura_tests_i386  or  qemu-i386 ./Herradura_tests_i386

%define SYS_EXIT   1
%define SYS_WRITE  4
%define SYS_READ   3
%define SYS_OPEN   5
%define SYS_CLOSE  6
%define STDOUT     1
%define I_VALUE    8
%define R_VALUE    24
%define GF_POLY    0x00400007
%define RNL_N      32
%define RNL_Q      65537
%define RNL_P      4096
%define RNL_PP     4
%define SDF_N      32
%define SDF_T      2
%define SDF_NROWS  16
%define SDF_ROUNDS 4

section .data

    prng_state  dd 0x12345678   ; overwritten from /dev/urandom at _start (SA-01)
    urandom_path db '/dev/urandom', 0

    ; implicit arg pointers for rnl_poly_mul/add
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

    hdr         db "=== Herradura KEx v1.8.0 -- Correctness Tests (NASM i386, KEYBITS=32) ===", 10, 10
    hdr_l       equ $-hdr

    t1_hdr      db "[1] HKEX-GF key exchange correctness: sk_alice == sk_bob (20 iterations)", 10
    t1_hdr_l    equ $-t1_hdr
    t2_hdr      db "[2] HSKE encrypt+decrypt round-trip: D == plaintext (100 iterations)", 10
    t2_hdr_l    equ $-t2_hdr
    t3_hdr      db "[3] HPKS Schnorr correctness: g^s * C^e == R (20 iterations)", 10
    t3_hdr_l    equ $-t3_hdr
    t4_hdr      db "[4] HPKE El Gamal encrypt+decrypt: D == plaintext (20 iterations)", 10
    t4_hdr_l    equ $-t4_hdr
    t5_hdr      db "[5] NL-FSCX v2 inverse roundtrip: v2_inv(v2(A,B),B) == A (20 iterations)", 10
    t5_hdr_l    equ $-t5_hdr
    t6_hdr      db "[6] HSKE-NL-A2 revolve-mode correctness: D == plaintext (20 iterations)", 10
    t6_hdr_l    equ $-t6_hdr
    t7_hdr      db "[7] HKEX-RNL key agreement: KA == KB (10 trials, Peikert reconciliation -- expect 100%)", 10
    t7_hdr_l    equ $-t7_hdr
    t8_hdr      db "[8] HPKS-NL Schnorr correctness: g^s * C^e == R with NL challenge (20 iter)", 10
    t8_hdr_l    equ $-t8_hdr
    t9_hdr      db "[9] HPKE-NL encrypt+decrypt: D == plaintext (NL-FSCX v2) (20 iterations)", 10
    t9_hdr_l    equ $-t9_hdr
    t10_hdr     db "[10] HPKS-NL Eve resistance: random forgery rejected (20 trials)", 10
    t10_hdr_l   equ $-t10_hdr
    t11_hdr     db "[11] HPKS-Stern-F: sign+verify correctness (3 trials, N=32, t=2, rounds=4)", 10
    t11_hdr_l   equ $-t11_hdr
    t12_hdr     db "[12] HPKE-Stern-F: encap+decap KEM (3 trials, N=32, t=2)", 10
    t12_hdr_l   equ $-t12_hdr
    t13_hdr     db "[13] HPKS-Stern-Ring (78.I): ring-sign+verify (3 trials, k=2, N=32, rounds=4)", 10
    t13_hdr_l   equ $-t13_hdr
    pass3r      db "    3 / 3 ring-verified  [PASS]", 10
    pass3r_l    equ $-pass3r

    pass20      db "    20 / 20 passed  [PASS]", 10
    pass20_l    equ $-pass20
    pass100     db "    100 / 100 passed  [PASS]", 10
    pass100_l   equ $-pass100
    pass_rnl    db "    10 / 10 agreed (Peikert reconciliation)  [PASS]", 10
    pass_rnl_l  equ $-pass_rnl
    pass3v      db "    3 / 3 verified  [PASS]", 10
    pass3v_l    equ $-pass3v
    pass3k      db "    3 / 3 keys match  [PASS]", 10
    pass3k_l    equ $-pass3k
    fail_msg    db "    FAILED  [FAIL]", 10
    fail_msg_l  equ $-fail_msg
    ; Stern-F test storage
    t_sdf_seed  dd 0
    t_sdf_syn   dd 0
    t_sdf_e     dd 0
    t_sdf_msg   dd 0
    t_sdf_K_enc dd 0
    t_sdf_K_dec dd 0
    t_sdf_e_prime dd 0
    t_sdf_ct    dd 0

section .bss

    ; test scratch
    t_a_priv    resd 1
    t_b_priv    resd 1
    t_C         resd 1
    t_C2        resd 1
    t_sk        resd 1
    t_val       resd 1    ; plaintext / A
    t_key       resd 1    ; key / B
    t_E         resd 1
    ; Schnorr scratch
    t_k         resd 1
    t_R_sc      resd 1
    t_e_sc      resd 1
    t_ae        resd 1
    t_s_sc      resd 1
    t_gs        resd 1
    ; El Gamal scratch
    t_r_e       resd 1
    t_R_e       resd 1
    t_enc_key   resd 1
    t_E_e       resd 1
    t_dec_key   resd 1
    ; RNL scratch
    t_KA        resd 1
    t_KB        resd 1
    t_hint_A    resd 1
    t_ctr       resd 1    ; loop counter (memory-saved)

    ; HKEX-RNL polynomial arrays (RNL_N dwords = 128 bytes each)
    rnl_m_base  resd RNL_N
    rnl_a_rand  resd RNL_N
    rnl_m_blind resd RNL_N
    rnl_s_A     resd RNL_N
    rnl_s_B     resd RNL_N
    rnl_C_A     resd RNL_N
    rnl_C_B     resd RNL_N
    rnl_tmp     resd RNL_N
    rnl_tmp2    resd RNL_N
    rnl_fa      resd RNL_N   ; NTT work arrays
    rnl_ga      resd RNL_N
    rnl_ha      resd RNL_N
    ; Stern-F scratch
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
    ; Ring-Sig (78.I) scratch: k=2, rounds=4
    ring0_c0    resd SDF_ROUNDS
    ring0_c1    resd SDF_ROUNDS
    ring0_c2    resd SDF_ROUNDS
    ring0_b     resd SDF_ROUNDS
    ring0_respA resd SDF_ROUNDS
    ring0_respB resd SDF_ROUNDS
    ring_joint_b resd SDF_ROUNDS

section .text
global _start

_start:
    ; SA-01: seed prng_state from /dev/urandom (fallback: keep default if open fails)
    mov  eax, SYS_OPEN
    mov  ebx, urandom_path
    xor  ecx, ecx
    xor  edx, edx
    int  0x80
    test eax, eax
    js   .tests_prng_seeded
    mov  esi, eax
    mov  eax, SYS_READ
    mov  ebx, esi
    mov  ecx, prng_state
    mov  edx, 4
    int  0x80
    mov  eax, SYS_CLOSE
    mov  ebx, esi
    int  0x80
.tests_prng_seeded:
    mov  eax, hdr
    mov  ecx, hdr_l
    call print_str

    ; ================================================================== [1] HKEX-GF
    mov  eax, t1_hdr
    mov  ecx, t1_hdr_l
    call print_str

    mov  ecx, 20
    xor  ebp, ebp

.t1_loop:
    push ecx

    call prng_next
    or   eax, 1
    mov  [t_a_priv], eax
    call prng_next
    or   eax, 1
    mov  [t_b_priv], eax

    mov  eax, 3
    mov  ebx, [t_a_priv]
    call gf_pow_32
    mov  [t_C], eax

    mov  eax, 3
    mov  ebx, [t_b_priv]
    call gf_pow_32
    mov  [t_C2], eax

    mov  eax, [t_C2]
    mov  ebx, [t_a_priv]
    call gf_pow_32
    mov  [t_sk], eax

    mov  eax, [t_C]
    mov  ebx, [t_b_priv]
    call gf_pow_32

    cmp  eax, [t_sk]
    jne  .t1_skip
    inc  ebp
.t1_skip:
    pop  ecx
    dec  ecx
    jnz  near .t1_loop

    cmp  ebp, 20
    jne  .t1_fail
    mov  eax, pass20
    mov  ecx, pass20_l
    call print_str
    jmp  .t1_done
.t1_fail:
    mov  eax, fail_msg
    mov  ecx, fail_msg_l
    call print_str
.t1_done:

    ; ================================================================== [2] HSKE
    mov  eax, t2_hdr
    mov  ecx, t2_hdr_l
    call print_str

    mov  ecx, 100
    xor  ebp, ebp

.t2_loop:
    push ecx

    call prng_next
    mov  [t_val], eax
    call prng_next
    mov  [t_key], eax

    mov  eax, [t_val]
    mov  ebx, [t_key]
    mov  ecx, I_VALUE
    call FSCX_revolve
    mov  [t_E], eax

    mov  eax, [t_E]
    mov  ebx, [t_key]
    mov  ecx, R_VALUE
    call FSCX_revolve

    cmp  eax, [t_val]
    jne  .t2_skip
    inc  ebp
.t2_skip:
    pop  ecx
    dec  ecx
    jnz  near .t2_loop

    cmp  ebp, 100
    jne  .t2_fail
    mov  eax, pass100
    mov  ecx, pass100_l
    call print_str
    jmp  .t2_done
.t2_fail:
    mov  eax, fail_msg
    mov  ecx, fail_msg_l
    call print_str
.t2_done:

    ; ================================================================== [3] HPKS Schnorr
    mov  eax, t3_hdr
    mov  ecx, t3_hdr_l
    call print_str

    mov  ecx, 20
    xor  ebp, ebp

.t3_loop:
    push ecx

    call prng_next
    or   eax, 1
    mov  [t_a_priv], eax
    call prng_next
    mov  [t_val], eax
    call prng_next
    mov  [t_k], eax

    mov  eax, 3
    mov  ebx, [t_a_priv]
    call gf_pow_32
    mov  [t_C], eax

    mov  eax, 3
    mov  ebx, [t_k]
    call gf_pow_32
    mov  [t_R_sc], eax

    mov  eax, [t_R_sc]
    mov  ebx, [t_val]
    mov  ecx, 8
    call FSCX_revolve
    mov  [t_e_sc], eax

    push ebx
    push edx
    mov  eax, [t_a_priv]
    mov  ebx, [t_e_sc]
    mul  ebx
    add  eax, edx
    adc  eax, 0
    mov  [t_ae], eax
    pop  edx
    pop  ebx

    mov  eax, [t_k]
    sub  eax, [t_ae]
    jnc  near .t3_no_borrow
    dec  eax
.t3_no_borrow:
    mov  [t_s_sc], eax

    mov  eax, 3
    mov  ebx, [t_s_sc]
    call gf_pow_32
    mov  [t_gs], eax

    mov  eax, [t_C]
    mov  ebx, [t_e_sc]
    call gf_pow_32

    mov  ebx, eax
    mov  eax, [t_gs]
    call gf_mul_32

    cmp  eax, [t_R_sc]
    jne  .t3_skip
    inc  ebp
.t3_skip:
    pop  ecx
    dec  ecx
    jnz  near .t3_loop

    cmp  ebp, 20
    jne  .t3_fail
    mov  eax, pass20
    mov  ecx, pass20_l
    call print_str
    jmp  .t3_done
.t3_fail:
    mov  eax, fail_msg
    mov  ecx, fail_msg_l
    call print_str
.t3_done:

    ; ================================================================== [4] HPKE El Gamal
    mov  eax, t4_hdr
    mov  ecx, t4_hdr_l
    call print_str

    mov  ecx, 20
    xor  ebp, ebp

.t4_loop:
    push ecx

    call prng_next
    or   eax, 1
    mov  [t_a_priv], eax
    call prng_next
    mov  [t_val], eax
    call prng_next
    or   eax, 1
    mov  [t_r_e], eax

    mov  eax, 3
    mov  ebx, [t_a_priv]
    call gf_pow_32
    mov  [t_C], eax

    mov  eax, 3
    mov  ebx, [t_r_e]
    call gf_pow_32
    mov  [t_R_e], eax

    mov  eax, [t_C]
    mov  ebx, [t_r_e]
    call gf_pow_32
    mov  [t_enc_key], eax

    mov  eax, [t_val]
    mov  ebx, [t_enc_key]
    mov  ecx, I_VALUE
    call FSCX_revolve
    mov  [t_E_e], eax

    mov  eax, [t_R_e]
    mov  ebx, [t_a_priv]
    call gf_pow_32
    mov  [t_dec_key], eax

    mov  eax, [t_E_e]
    mov  ebx, [t_dec_key]
    mov  ecx, R_VALUE
    call FSCX_revolve

    cmp  eax, [t_val]
    jne  .t4_skip
    inc  ebp
.t4_skip:
    pop  ecx
    dec  ecx
    jnz  near .t4_loop

    cmp  ebp, 20
    jne  .t4_fail
    mov  eax, pass20
    mov  ecx, pass20_l
    call print_str
    jmp  .t4_done
.t4_fail:
    mov  eax, fail_msg
    mov  ecx, fail_msg_l
    call print_str
.t4_done:

    ; ================================================================== [5] NL-FSCX v2 inv roundtrip
    mov  eax, t5_hdr
    mov  ecx, t5_hdr_l
    call print_str

    mov  dword [t_ctr], 20
    xor  ebp, ebp

.t5_loop:
    call prng_next
    mov  [t_val], eax       ; A
    call prng_next
    mov  [t_key], eax       ; B

    ; E = nl_fscx_revolve_v2(A, B, I_VALUE)
    mov  eax, [t_val]
    mov  ebx, [t_key]
    mov  ecx, I_VALUE
    call nl_fscx_revolve_v2
    mov  [t_E], eax

    ; D = nl_fscx_revolve_v2_inv(E, B, I_VALUE)
    mov  eax, [t_E]
    mov  ebx, [t_key]
    mov  ecx, I_VALUE
    call nl_fscx_revolve_v2_inv

    cmp  eax, [t_val]
    jne  .t5_skip
    inc  ebp
.t5_skip:
    dec  dword [t_ctr]
    jnz  near .t5_loop

    cmp  ebp, 20
    jne  .t5_fail
    mov  eax, pass20
    mov  ecx, pass20_l
    call print_str
    jmp  .t5_done
.t5_fail:
    mov  eax, fail_msg
    mov  ecx, fail_msg_l
    call print_str
.t5_done:

    ; ================================================================== [6] HSKE-NL-A2 revolve-mode
    mov  eax, t6_hdr
    mov  ecx, t6_hdr_l
    call print_str

    mov  dword [t_ctr], 20
    xor  ebp, ebp

.t6_loop:
    call prng_next
    mov  [t_val], eax       ; plaintext
    call prng_next
    mov  [t_key], eax       ; key

    ; E = nl_fscx_revolve_v2(plain, key, I_VALUE)
    mov  eax, [t_val]
    mov  ebx, [t_key]
    mov  ecx, I_VALUE
    call nl_fscx_revolve_v2
    mov  [t_E], eax

    ; D = nl_fscx_revolve_v2_inv(E, key, I_VALUE)
    mov  eax, [t_E]
    mov  ebx, [t_key]
    mov  ecx, I_VALUE
    call nl_fscx_revolve_v2_inv

    cmp  eax, [t_val]
    jne  .t6_skip
    inc  ebp
.t6_skip:
    dec  dword [t_ctr]
    jnz  near .t6_loop

    cmp  ebp, 20
    jne  .t6_fail
    mov  eax, pass20
    mov  ecx, pass20_l
    call print_str
    jmp  .t6_done
.t6_fail:
    mov  eax, fail_msg
    mov  ecx, fail_msg_l
    call print_str
.t6_done:

    ; ================================================================== [7] HKEX-RNL
    mov  eax, t7_hdr
    mov  ecx, t7_hdr_l
    call print_str

    ; set up fixed m_base once
    mov  eax, rnl_m_base
    call rnl_m_poly

    mov  dword [t_ctr], 10
    xor  ebp, ebp

.t7_loop:
    ; randomise: a_rand, m_blind
    mov  eax, rnl_a_rand
    call rnl_rand_poly

    mov  dword [rnl_h_ptr], rnl_m_blind
    mov  dword [rnl_f_ptr], rnl_m_base
    mov  dword [rnl_g_ptr], rnl_a_rand
    call rnl_poly_add

    ; keygen A
    mov  eax, rnl_s_A
    mov  ebx, rnl_C_A
    mov  ecx, rnl_m_blind
    call rnl_keygen

    ; keygen B
    mov  eax, rnl_s_B
    mov  ebx, rnl_C_B
    mov  ecx, rnl_m_blind
    call rnl_keygen

    ; KA, hint_A = rnl_agree_full(s_A, C_B)
    mov  eax, rnl_s_A
    mov  ebx, rnl_C_B
    call rnl_agree_full         ; EAX=KA, EDX=hint_A
    mov  [t_KA], eax
    mov  [t_hint_A], edx

    ; KB = rnl_agree_recv(s_B, C_A, hint_A)
    mov  eax, rnl_s_B
    mov  ebx, rnl_C_A
    mov  ecx, [t_hint_A]
    call rnl_agree_recv         ; EAX=KB
    mov  [t_KB], eax

    mov  eax, [t_KA]
    cmp  eax, [t_KB]
    jne  .t7_skip
    inc  ebp
.t7_skip:
    dec  dword [t_ctr]
    jnz  near .t7_loop

    cmp  ebp, 10
    jl   .t7_fail
    mov  eax, pass_rnl
    mov  ecx, pass_rnl_l
    call print_str
    jmp  .t7_done
.t7_fail:
    mov  eax, fail_msg
    mov  ecx, fail_msg_l
    call print_str
.t7_done:

    ; ================================================================== [8] HPKS-NL Schnorr
    mov  eax, t8_hdr
    mov  ecx, t8_hdr_l
    call print_str

    mov  dword [t_ctr], 20
    xor  ebp, ebp

.t8_loop:
    call prng_next
    or   eax, 1
    mov  [t_a_priv], eax
    call prng_next
    mov  [t_val], eax        ; plain
    call prng_next
    mov  [t_k], eax

    ; C = g^a
    mov  eax, 3
    mov  ebx, [t_a_priv]
    call gf_pow_32
    mov  [t_C], eax

    ; R = g^k
    mov  eax, 3
    mov  ebx, [t_k]
    call gf_pow_32
    mov  [t_R_sc], eax

    ; e = nl_fscx_revolve_v1(R, plain, I_VALUE)  -- NL challenge
    mov  eax, [t_R_sc]
    mov  ebx, [t_val]
    mov  ecx, I_VALUE
    call nl_fscx_revolve_v1
    mov  [t_e_sc], eax

    ; ae = a * e mod ORD
    push ebx
    push edx
    mov  eax, [t_a_priv]
    mov  ebx, [t_e_sc]
    mul  ebx
    add  eax, edx
    adc  eax, 0
    mov  [t_ae], eax
    pop  edx
    pop  ebx

    ; s = k - ae mod ORD
    mov  eax, [t_k]
    sub  eax, [t_ae]
    jnc  near .t8_no_borrow
    dec  eax
.t8_no_borrow:
    mov  [t_s_sc], eax

    ; gs = g^s
    mov  eax, 3
    mov  ebx, [t_s_sc]
    call gf_pow_32
    mov  [t_gs], eax

    ; Ce = C^e
    mov  eax, [t_C]
    mov  ebx, [t_e_sc]
    call gf_pow_32

    ; lhs = gs * Ce
    mov  ebx, eax
    mov  eax, [t_gs]
    call gf_mul_32

    ; pass: lhs == R
    cmp  eax, [t_R_sc]
    jne  .t8_skip
    inc  ebp
.t8_skip:
    dec  dword [t_ctr]
    jnz  near .t8_loop

    cmp  ebp, 20
    jne  .t8_fail
    mov  eax, pass20
    mov  ecx, pass20_l
    call print_str
    jmp  .t8_done
.t8_fail:
    mov  eax, fail_msg
    mov  ecx, fail_msg_l
    call print_str
.t8_done:

    ; ================================================================== [9] HPKE-NL
    mov  eax, t9_hdr
    mov  ecx, t9_hdr_l
    call print_str

    mov  dword [t_ctr], 20
    xor  ebp, ebp

.t9_loop:
    call prng_next
    or   eax, 1
    mov  [t_a_priv], eax
    call prng_next
    mov  [t_val], eax        ; plaintext
    call prng_next
    or   eax, 1
    mov  [t_r_e], eax

    ; C = g^a
    mov  eax, 3
    mov  ebx, [t_a_priv]
    call gf_pow_32
    mov  [t_C], eax

    ; R = g^r
    mov  eax, 3
    mov  ebx, [t_r_e]
    call gf_pow_32
    mov  [t_R_e], eax

    ; enc_key = C^r
    mov  eax, [t_C]
    mov  ebx, [t_r_e]
    call gf_pow_32
    mov  [t_enc_key], eax

    ; E = nl_fscx_revolve_v2(plain, enc_key, I_VALUE)
    mov  eax, [t_val]
    mov  ebx, [t_enc_key]
    mov  ecx, I_VALUE
    call nl_fscx_revolve_v2
    mov  [t_E_e], eax

    ; dec_key = R^a
    mov  eax, [t_R_e]
    mov  ebx, [t_a_priv]
    call gf_pow_32
    mov  [t_dec_key], eax

    ; D = nl_fscx_revolve_v2_inv(E, dec_key, I_VALUE)
    mov  eax, [t_E_e]
    mov  ebx, [t_dec_key]
    mov  ecx, I_VALUE
    call nl_fscx_revolve_v2_inv

    cmp  eax, [t_val]
    jne  .t9_skip
    inc  ebp
.t9_skip:
    dec  dword [t_ctr]
    jnz  near .t9_loop

    cmp  ebp, 20
    jne  .t9_fail
    mov  eax, pass20
    mov  ecx, pass20_l
    call print_str
    jmp  .t9_done
.t9_fail:
    mov  eax, fail_msg
    mov  ecx, fail_msg_l
    call print_str
.t9_done:

    ; ================================================================== [10] HPKS-NL Eve resistance
    ; For each trial: sign with real (a,k); create random forgery s_fake.
    ; Compute lhs = g^{s_fake} * C^e; pass if lhs != R (forgery rejected).
    mov  eax, t10_hdr
    mov  ecx, t10_hdr_l
    call print_str

    mov  dword [t_ctr], 20
    xor  ebp, ebp            ; count rejected forgeries

.t10_loop:
    call prng_next
    or   eax, 1
    mov  [t_a_priv], eax
    call prng_next
    mov  [t_val], eax        ; message
    call prng_next
    mov  [t_k], eax          ; real nonce (for R)

    ; C = g^a
    mov  eax, 3
    mov  ebx, [t_a_priv]
    call gf_pow_32
    mov  [t_C], eax

    ; R = g^k  (real commitment)
    mov  eax, 3
    mov  ebx, [t_k]
    call gf_pow_32
    mov  [t_R_sc], eax

    ; e = nl_fscx_revolve_v1(R, plain, I_VALUE)
    mov  eax, [t_R_sc]
    mov  ebx, [t_val]
    mov  ecx, I_VALUE
    call nl_fscx_revolve_v1
    mov  [t_e_sc], eax

    ; s_fake = prng_next()  (random forgery, not k - a*e)
    call prng_next
    mov  [t_s_sc], eax

    ; lhs = g^{s_fake} * C^e
    mov  eax, 3
    mov  ebx, [t_s_sc]
    call gf_pow_32
    mov  [t_gs], eax

    mov  eax, [t_C]
    mov  ebx, [t_e_sc]
    call gf_pow_32

    mov  ebx, eax
    mov  eax, [t_gs]
    call gf_mul_32

    ; forgery rejected iff lhs != R
    cmp  eax, [t_R_sc]
    je   .t10_skip
    inc  ebp
.t10_skip:
    dec  dword [t_ctr]
    jnz  near .t10_loop

    cmp  ebp, 20
    jne  .t10_fail
    mov  eax, pass20
    mov  ecx, pass20_l
    call print_str
    jmp  .t10_done
.t10_fail:
    mov  eax, fail_msg
    mov  ecx, fail_msg_l
    call print_str
.t10_done:

    ; ================================================================== [11] HPKS-Stern-F (3 trials)
    mov  eax, t11_hdr
    mov  ecx, t11_hdr_l
    call print_str
    mov  dword [t_ctr], 3
    mov  dword [t_sk], 0       ; pass counter
.t11_loop:
    ; seed = prng_next()
    call prng_next
    mov  [t_sdf_seed], eax
    ; e = weight-2 error
    call stern_rand_error_32
    mov  [t_sdf_e], eax
    ; msg = prng_next()
    call prng_next
    mov  [t_sdf_msg], eax
    ; syndrome = H·e^T
    mov  eax, [t_sdf_seed]
    mov  ebx, [t_sdf_e]
    call stern_syndrome_32
    mov  [t_sdf_syn], eax
    ; sign
    call hpks_stern_f_sign_32
    ; verify
    call hpks_stern_f_verify_32
    cmp  eax, 1
    jne  .t11_skip
    inc  dword [t_sk]
.t11_skip:
    dec  dword [t_ctr]
    jnz  .t11_loop
    cmp  dword [t_sk], 3
    jne  .t11_fail
    mov  eax, pass3v
    mov  ecx, pass3v_l
    call print_str
    jmp  .t11_done
.t11_fail:
    mov  eax, fail_msg
    mov  ecx, fail_msg_l
    call print_str
.t11_done:

    ; ================================================================== [12] HPKE-Stern-F KEM (3 trials)
    mov  eax, t12_hdr
    mov  ecx, t12_hdr_l
    call print_str
    mov  dword [t_ctr], 3
    mov  dword [t_sk], 0
.t12_loop:
    ; seed = prng_next()
    call prng_next
    mov  [t_sdf_seed], eax
    ; encap
    call hpke_stern_f_encap_32
    ; decap (known e')
    mov  eax, [t_sdf_e_prime]
    call hpke_stern_f_decap_known_32
    mov  [t_sdf_K_dec], eax
    ; check K_enc == K_dec
    mov  eax, [t_sdf_K_enc]
    cmp  eax, [t_sdf_K_dec]
    jne  .t12_skip
    inc  dword [t_sk]
.t12_skip:
    dec  dword [t_ctr]
    jnz  .t12_loop
    cmp  dword [t_sk], 3
    jne  .t12_fail
    mov  eax, pass3k
    mov  ecx, pass3k_l
    call print_str
    jmp  .t12_done
.t12_fail:
    mov  eax, fail_msg
    mov  ecx, fail_msg_l
    call print_str
.t12_done:

    ; ================================================================== [13] HPKS-Stern-Ring (3 trials)
    mov  eax, t13_hdr
    mov  ecx, t13_hdr_l
    call print_str
    mov  dword [t_ctr], 3
    mov  dword [t_sk], 0
.t13_loop:
    call prng_next
    mov  [t_sdf_seed], eax
    call prng_next
    mov  [t_sdf_e], eax        ; use raw random as e (wt may not be exactly 2; ok for ring test)
    call prng_next
    mov  [t_sdf_syn], eax      ; recompute proper syndrome below
    ; compute e as rand_error_32 (weight 2)
    call stern_rand_error_32
    mov  [t_sdf_e], eax
    call prng_next
    mov  [t_sdf_seed], eax
    ; syndrome = stern_syndrome_32(seed, e)
    mov  eax, [t_sdf_seed]
    mov  ebx, [t_sdf_e]
    call stern_syndrome_32
    mov  [t_sdf_syn], eax
    call prng_next
    mov  [t_sdf_msg], eax
    call hpks_stern_ring2_sign_32
    call hpks_stern_ring2_verify_32
    cmp  eax, 1
    jne  .t13_skip
    inc  dword [t_sk]
.t13_skip:
    dec  dword [t_ctr]
    jnz  .t13_loop
    cmp  dword [t_sk], 3
    jne  .t13_fail
    mov  eax, pass3r
    mov  ecx, pass3r_l
    call print_str
    jmp  .t13_done
.t13_fail:
    mov  eax, fail_msg
    mov  ecx, fail_msg_l
    call print_str
.t13_done:

    ; ------------------------------------------------------------------ exit
    mov  eax, SYS_EXIT
    xor  ebx, ebx
    int  0x80

; ============================================================
; prng_next: LCG  state = state * 1664525 + 1013904223
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
; FSCX_revolve: EAX=A, EBX=B, ECX=rounds  -->  EAX=result
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
    mov  ebx, eax
    add  eax, 1
    shr  eax, 1
    imul eax, ebx
    rol  eax, 8
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
    mov  ecx, eax
    call fscx_single
    push eax
    mov  eax, ecx
    add  eax, ebx
    rol  eax, 8
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
    mov  esi, eax
    mov  edi, ecx
.rv1_loop:
    test edi, edi
    jz   .rv1_done
    mov  eax, esi
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
    call fscx_single
    push eax
    mov  eax, ebx
    call nl_fscx_delta_v2
    pop  ecx
    add  eax, ecx
    pop  edx
    pop  ecx
    ret

; ============================================================
; m_inv_32: EAX=X --> EAX=M^{-1}(X) via precomputed rotation table
; M^{-1}(X) = XOR of ROL(X,k) for k in {0,2,3,5,6,8,9,...,29,30}
; ============================================================
m_inv_32:
    push    ebx
    mov     ebx, eax
    mov     ecx, ebx
    rol     ecx, 2
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
    mov  esi, eax
    mov  eax, ebx
    call nl_fscx_delta_v2
    sub  esi, eax
    mov  eax, esi
    call m_inv_32
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
    xor  ecx, ecx
.rpa_loop:
    cmp  ecx, RNL_N
    jge  .rpa_done
    mov  eax, [esi + ecx*4]
    add  eax, [edi + ecx*4]
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
; rnl_round: EBP=out, ESI=in, ECX=from_q, EDX=to_p
; ============================================================
rnl_round:
    push eax
    push ebx
    push ecx
    push edi

    push edx
    push ecx
    push esi
    push ebp

    xor  edi, edi
.rr_loop:
    cmp  edi, RNL_N
    jge  .rr_done

    mov  esi, [esp+4]
    mov  eax, [esi + edi*4]
    mov  ecx, [esp+12]
    mul  ecx
    mov  ecx, [esp+8]
    shr  ecx, 1
    add  eax, ecx
    mov  ecx, [esp+8]
    xor  edx, edx
    div  ecx
    xor  edx, edx
    mov  ecx, [esp+12]
    div  ecx
    mov  eax, edx

    mov  ebp, [esp]
    mov  [ebp + edi*4], eax
    inc  edi
    jmp  .rr_loop
.rr_done:
    add  esp, 16
    pop  edi
    pop  ecx
    pop  ebx
    pop  eax
    ret

; ============================================================
; rnl_lift: EBP=out, ESI=in, ECX=from_p, EDX=to_q
; ============================================================
rnl_lift:
    push eax
    push ebx
    push ecx
    push edi

    push edx
    push ecx
    push esi
    push ebp

    xor  edi, edi
.rl_loop:
    cmp  edi, RNL_N
    jge  .rl_done

    mov  esi, [esp+4]
    mov  eax, [esi + edi*4]   ; in[i]
    mov  ecx, [esp+12]        ; to_q
    mul  ecx                  ; edx:eax = in[i] * to_q  (fits in 32 bits; edx=0)
    ; add from_p // 2 (centered rounding)
    mov  ecx, [esp+8]         ; from_p
    shr  ecx, 1               ; ecx = from_p / 2
    add  eax, ecx             ; eax += from_p / 2
    ; divide by from_p
    mov  ecx, [esp+8]         ; from_p (reload after shr)
    div  ecx                  ; eax = (in[i]*to_q + from_p/2) / from_p
    xor  edx, edx
    mov  ecx, [esp+12]        ; to_q
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
    xor  eax, eax
    mov  ecx, RNL_N
    push edi
    rep  stosd
    pop  edi
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
    sub  edi, eax       ; coeff = a - b
    jge  .rcp_store
    add  edi, RNL_Q
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
; ============================================================
rnl_bits32:
    push ebx
    push ecx
    push edx
    push esi
    mov  esi, eax
    xor  edx, edx
    xor  ecx, ecx
.rb_loop:
    cmp  ecx, RNL_N
    jge  .rb_done
    mov  eax, [esi + ecx*4]
    cmp  eax, 1
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
; ============================================================
rnl_keygen:
    push ebx
    push ecx
    push edx
    push esi
    push edi
    push ebp
    mov  esi, eax
    mov  edi, ebx
    mov  ebp, ecx

    mov  eax, esi
    call rnl_cbd_poly

    mov  dword [rnl_h_ptr], rnl_tmp
    mov  [rnl_f_ptr], ebp
    mov  [rnl_g_ptr], esi
    call rnl_poly_mul

    mov  ebp, edi
    mov  esi, rnl_tmp
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
;   2-bit hint per coeff; RNL_N/2=16 coefficients used.
;   Thresholds: 6145, 14337, 22529, 30721, 38913, 47105, 55297
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
    cmp  ecx, (RNL_N/2)
    jge  .rh32_done
    mov  eax, [esi + ecx*4]
    xor  edx, edx
    cmp  eax, 6145
    jl   .rh32_store
    mov  edx, 1
    cmp  eax, 14337
    jl   .rh32_store
    mov  edx, 2
    cmp  eax, 22529
    jl   .rh32_store
    mov  edx, 3
    cmp  eax, 30721
    jl   .rh32_store
    xor  edx, edx
    cmp  eax, 38913
    jl   .rh32_store
    mov  edx, 1
    cmp  eax, 47105
    jl   .rh32_store
    mov  edx, 2
    cmp  eax, 55297
    jl   .rh32_store
    mov  edx, 3
.rh32_store:
    push ecx
    shl  ecx, 1              ; ecx = 2*i
    shl  edx, cl             ; edx = h << (2*i)
    or   edi, edx
    pop  ecx
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
;   b[i] = ((4*c + (2*h+1)*(q/4)) / q) % 4; 16 coefficients.
; ============================================================
rnl_reconcile32:
    push ebx
    push ecx
    push edx
    push esi
    push edi
    push ebp
    mov  esi, eax
    mov  ebp, ebx            ; ebp = hint
    xor  edi, edi
    xor  ecx, ecx
.rc32_loop:
    cmp  ecx, (RNL_N/2)
    jge  .rc32_done
    mov  eax, [esi + ecx*4]  ; c
    shl  eax, 2              ; 4*c
    push ecx
    shl  ecx, 1              ; ecx = 2*i
    mov  edx, ebp
    shr  edx, cl             ; hint >> (2*i)
    and  edx, 3              ; h
    shl  edx, 1              ; 2*h
    inc  edx                 ; 2*h+1
    imul edx, 0x4000         ; (2*h+1) * (q/4)
    add  eax, edx            ; 4*c + (2*h+1)*(q/4)
    xor  edx, edx
    cmp  eax, RNL_Q
    jl   .rc32_pack
    sub  eax, RNL_Q
    mov  edx, 1
    cmp  eax, RNL_Q
    jl   .rc32_pack
    sub  eax, RNL_Q
    mov  edx, 2
    cmp  eax, RNL_Q
    jl   .rc32_pack
    mov  edx, 3
.rc32_pack:
    shl  edx, cl             ; edx = b << (2*i)
    or   edi, edx
    pop  ecx
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
    sub  esp, 4

    mov  edi, eax
    mov  esi, ebx

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
    sub  esp, 4

    mov  edi, eax
    mov  esi, ebx
    mov  [esp], ecx

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
; hfscx_32: EAX=x -> EAX=hfscx_32(x)  (DM, v1.9.0)
; C_DM(s,m)=nl(s,m,8)^s; IV=0xA3C5E7B9, LB=0xA3C5E799
; s=nl(IV,x,8)^IV; return nl(s,LB,8)^s
; ============================================================
hfscx_32:
    push ecx
    push ebx
    push edi               ; save edi (callee-saved)
    mov  ebx, eax          ; B = x
    mov  edi, 0xA3C5E7B9   ; prev = IV_32
    mov  eax, 0xA3C5E7B9   ; A = IV_32
    mov  ecx, 8
    call nl_fscx_revolve_v1 ; eax = nl(IV, x, 8)
    xor  eax, edi           ; eax ^= IV  (DM block 1)
    mov  edi, eax           ; prev = s
    mov  ebx, 0xA3C5E799   ; B = LB = 0x20 ^ IV_32
    mov  ecx, 8
    call nl_fscx_revolve_v1 ; eax = nl(s, LB, 8)
    xor  eax, edi           ; eax ^= s  (DM block 2)
    pop  edi
    pop  ebx
    pop  ecx
    ret

; ============================================================
; stern_hash1_32: EAX=ds, EBX=v -> EAX=sternHash(ds,v)
; ============================================================
stern_hash1_32:
    push ecx
    push ebx
    xor  eax, ebx           ; eax = ds ^ v  (ebx = v)
    rol  ebx, 4             ; ebx = ROL(v,4)
    mov  ecx, 8
    call nl_fscx_revolve_v1
    pop  ebx
    pop  ecx
    jmp  hfscx_32

; ============================================================
; stern_hash2_32: EAX=ds, EBX=a, ECX=b -> EAX=sternHash(ds,a,b)
; ============================================================
stern_hash2_32:
    push esi
    push edi
    push ecx
    push ebx
    mov  esi, ebx           ; esi = a
    mov  edi, ecx           ; edi = b
    xor  eax, esi           ; eax = ds ^ a
    mov  ebx, esi
    rol  ebx, 4             ; ebx = ROL(a,4)
    mov  ecx, 8
    call nl_fscx_revolve_v1 ; eax = h
    xor  eax, edi           ; h ^ b
    mov  ebx, edi
    rol  ebx, 4             ; ebx = ROL(b,4)
    mov  ecx, 8
    call nl_fscx_revolve_v1 ; eax = raw
    pop  ebx
    pop  ecx
    pop  edi
    pop  esi
    jmp  hfscx_32

; ============================================================
; stern_matrix_row_32: EAX=seed, EBX=row -> EAX=H[row]
; ============================================================
stern_matrix_row_32:
    push ecx
    push esi
    mov  esi, eax
    xor  eax, ebx
    rol  eax, 4
    mov  ebx, esi
    mov  ecx, 8
    call nl_fscx_revolve_v1
    pop  esi
    pop  ecx
    jmp  hfscx_32           ; finalize (TODO #88); preserves ECX/ESI

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
    mov  esi, eax
    mov  edi, ebx
    xor  ebp, ebp
    xor  ecx, ecx
.tsds_loop:
    cmp  ecx, SDF_NROWS
    jge  .tsds_done
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
    jmp  .tsds_loop
.tsds_done:
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
    jz   .tspeq2_fail
    lea  ecx, [eax-1]
    and  eax, ecx
    jz   .tspeq2_fail
    lea  ecx, [eax-1]
    test eax, ecx
    jnz  .tspeq2_fail
    mov  eax, 1
    jmp  .tspeq2_done
.tspeq2_fail:
    xor  eax, eax
.tspeq2_done:
    pop  ecx
    ret

; ============================================================
; stern_gen_perm_32: EAX=pi_seed -> sdf_perm[0..31]
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
    rol  edi, 4
    xor  ecx, ecx
.tsgp_init:
    cmp  ecx, SDF_N
    jge  .tsgp_init_done
    mov  byte [sdf_perm + ecx], cl
    inc  ecx
    jmp  .tsgp_init
.tsgp_init_done:
    mov  ebp, SDF_N - 1
.tsgp_loop:
    cmp  ebp, 1
    jl   .tsgp_done
    mov  eax, esi
    mov  ebx, edi
    call nl_fscx_v1
    mov  esi, eax
    xor  edx, edx
    mov  ecx, ebp
    inc  ecx
    div  ecx
    movzx eax, byte [sdf_perm + ebp]
    movzx ecx, byte [sdf_perm + edx]
    mov  byte [sdf_perm + ebp], cl
    mov  byte [sdf_perm + edx], al
    dec  ebp
    jmp  .tsgp_loop
.tsgp_done:
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
.tsap_loop:
    cmp  ecx, SDF_N
    jge  .tsap_done
    bt   esi, ecx
    jnc  .tsap_next
    movzx eax, byte [sdf_perm + ecx]
    bts  edi, eax
.tsap_next:
    inc  ecx
    jmp  .tsap_loop
.tsap_done:
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
.tsre_init:
    cmp  ecx, SDF_N
    jge  .tsre_init_done
    mov  byte [sdf_perm + ecx], cl
    inc  ecx
    jmp  .tsre_init
.tsre_init_done:
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
; reads t_sdf_msg, sdf_c0, sdf_c1, sdf_c2
; ============================================================
stern_fs_challenges_32:
    push ebx
    push esi
    push edi
    push ecx
    push edx
    xor  esi, esi
    mov  eax, [t_sdf_msg]
    xor  eax, esi
    mov  ebx, [t_sdf_msg]
    rol  ebx, 4
    mov  ecx, 8
    call nl_fscx_revolve_v1
    mov  esi, eax
    xor  edi, edi
.tsfc_round_loop:
    cmp  edi, SDF_ROUNDS
    jge  .tsfc_round_done
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
    jmp  .tsfc_round_loop
.tsfc_round_done:
    xor  edi, edi
.tsfc_chal_loop:
    cmp  edi, SDF_ROUNDS
    jge  .tsfc_done
    mov  eax, esi
    mov  ebx, edi
    call nl_fscx_v1
    mov  esi, eax
    xor  edx, edx
    mov  ecx, 3
    div  ecx
    mov  [sdf_chals_tmp + edi*4], edx
    inc  edi
    jmp  .tsfc_chal_loop
.tsfc_done:
    pop  edx
    pop  ecx
    pop  edi
    pop  esi
    pop  ebx
    ret

; ============================================================
; hpks_stern_f_sign_32: reads t_sdf_e, t_sdf_seed, t_sdf_msg
; fills sdf_c0..c2, sdf_b, sdf_respA, sdf_respB
; ============================================================
hpks_stern_f_sign_32:
    push ebx
    push esi
    push edi
    push ebp
    push ecx
    push edx
    mov  esi, [t_sdf_seed]
    mov  edi, [t_sdf_e]
    xor  ebp, ebp
.thsfs_loop:
    cmp  ebp, SDF_ROUNDS
    jge  .thsfs_loop_done
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
    mov  ecx, eax                       ; ecx = hr
    mov  ebx, [sdf_pi_tmp + ebp*4]     ; ebx = pi
    mov  eax, 1                         ; ds = 1
    call stern_hash2_32
    mov  [sdf_c0 + ebp*4], eax
    mov  ebx, [sdf_sr_tmp + ebp*4]     ; ebx = sr
    mov  eax, 2                         ; ds = 2
    call stern_hash1_32
    mov  [sdf_c1 + ebp*4], eax
    mov  ebx, [sdf_sy_tmp + ebp*4]     ; ebx = sy
    mov  eax, 3                         ; ds = 3
    call stern_hash1_32
    mov  [sdf_c2 + ebp*4], eax
    inc  ebp
    jmp  .thsfs_loop
.thsfs_loop_done:
    call stern_fs_challenges_32
    xor  ebp, ebp
.thsfs_resp_loop:
    cmp  ebp, SDF_ROUNDS
    jge  .thsfs_resp_done
    mov  eax, [sdf_chals_tmp + ebp*4]
    mov  [sdf_b + ebp*4], eax
    cmp  eax, 0
    je   .thsfs_case0
    cmp  eax, 1
    je   .thsfs_case1
    mov  eax, [sdf_pi_tmp + ebp*4]
    mov  [sdf_respA + ebp*4], eax
    mov  eax, [sdf_y_tmp + ebp*4]
    mov  [sdf_respB + ebp*4], eax
    jmp  .thsfs_resp_next
.thsfs_case0:
    mov  eax, [sdf_sr_tmp + ebp*4]
    mov  [sdf_respA + ebp*4], eax
    mov  eax, [sdf_sy_tmp + ebp*4]
    mov  [sdf_respB + ebp*4], eax
    jmp  .thsfs_resp_next
.thsfs_case1:
    mov  eax, [sdf_pi_tmp + ebp*4]
    mov  [sdf_respA + ebp*4], eax
    mov  eax, [sdf_r_tmp + ebp*4]
    mov  [sdf_respB + ebp*4], eax
.thsfs_resp_next:
    inc  ebp
    jmp  .thsfs_resp_loop
.thsfs_resp_done:
    pop  edx
    pop  ecx
    pop  ebp
    pop  edi
    pop  esi
    pop  ebx
    ret

; ============================================================
; hpks_stern_f_verify_32: -> EAX=1 valid, 0 invalid
; reads t_sdf_seed, t_sdf_syn
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
.thsfv_chal_chk:
    cmp  ecx, SDF_ROUNDS
    jge  .thsfv_chal_ok
    mov  eax, [sdf_chals_tmp + ecx*4]
    cmp  eax, [sdf_b + ecx*4]
    jne  .thsfv_fail
    inc  ecx
    jmp  .thsfv_chal_chk
.thsfv_chal_ok:
    mov  esi, [t_sdf_seed]
    mov  edi, [t_sdf_syn]
    xor  ebp, ebp
.thsfv_round_loop:
    cmp  ebp, SDF_ROUNDS
    jge  .thsfv_pass
    mov  ecx, [sdf_b + ebp*4]
    mov  edx, [sdf_respA + ebp*4]
    cmp  ecx, 0
    je   .thsfv_case0
    cmp  ecx, 1
    je   .thsfv_case1
    mov  eax, esi
    mov  ebx, [sdf_respB + ebp*4]
    call stern_syndrome_32
    xor  eax, edi               ; hy^synd
    mov  ecx, eax               ; ecx = hy^synd
    mov  ebx, edx               ; ebx = pi
    mov  eax, 1                 ; ds = 1
    call stern_hash2_32
    cmp  eax, [sdf_c0 + ebp*4]
    jne  .thsfv_fail
    mov  eax, edx
    call stern_gen_perm_32
    mov  eax, [sdf_respB + ebp*4]
    call stern_apply_perm_32
    mov  ebx, eax               ; ebx = apply_perm result
    mov  eax, 3                 ; ds = 3
    call stern_hash1_32
    cmp  eax, [sdf_c2 + ebp*4]
    jne  .thsfv_fail
    jmp  .thsfv_round_next
.thsfv_case0:
    mov  ebx, edx               ; ebx = ra
    mov  eax, 2                 ; ds = 2
    call stern_hash1_32
    cmp  eax, [sdf_c1 + ebp*4]
    jne  .thsfv_fail
    mov  ebx, [sdf_respB + ebp*4]  ; ebx = rb
    mov  eax, 3                 ; ds = 3
    call stern_hash1_32
    cmp  eax, [sdf_c2 + ebp*4]
    jne  .thsfv_fail
    mov  eax, edx
    call stern_popcount_eq2
    test eax, eax
    jz   .thsfv_fail
    jmp  .thsfv_round_next
.thsfv_case1:
    mov  eax, [sdf_respB + ebp*4]
    call stern_popcount_eq2
    test eax, eax
    jz   .thsfv_fail
    mov  eax, esi
    mov  ebx, [sdf_respB + ebp*4]
    call stern_syndrome_32
    mov  ecx, eax               ; ecx = H·r^T
    mov  ebx, edx               ; ebx = pi
    mov  eax, 1                 ; ds = 1
    call stern_hash2_32
    cmp  eax, [sdf_c0 + ebp*4]
    jne  .thsfv_fail
    mov  eax, edx
    call stern_gen_perm_32
    mov  eax, [sdf_respB + ebp*4]
    call stern_apply_perm_32
    mov  ebx, eax               ; ebx = apply_perm result
    mov  eax, 2                 ; ds = 2
    call stern_hash1_32
    cmp  eax, [sdf_c1 + ebp*4]
    jne  .thsfv_fail
.thsfv_round_next:
    inc  ebp
    jmp  .thsfv_round_loop
.thsfv_pass:
    mov  eax, 1
    jmp  .thsfv_exit
.thsfv_fail:
    xor  eax, eax
.thsfv_exit:
    pop  edx
    pop  ecx
    pop  ebp
    pop  edi
    pop  esi
    pop  ebx
    ret

; ============================================================
; hpke_stern_f_encap_32: fills t_sdf_e_prime, t_sdf_ct, t_sdf_K_enc
; ============================================================
hpke_stern_f_encap_32:
    push ebx
    push esi
    push ecx
    push edx
    call stern_rand_error_32
    mov  esi, eax
    mov  [t_sdf_e_prime], eax
    mov  eax, [t_sdf_seed]
    mov  ebx, esi
    call stern_syndrome_32
    mov  [t_sdf_ct], eax
    mov  ecx, esi               ; ecx = e'
    mov  ebx, [t_sdf_seed]     ; ebx = seed
    mov  eax, 4                 ; ds = 4
    call stern_hash2_32
    mov  [t_sdf_K_enc], eax
    pop  edx
    pop  ecx
    pop  esi
    pop  ebx
    ret

; ============================================================
; hpke_stern_f_decap_known_32: EAX=e' -> EAX=K=hash2(seed,e')
; reads t_sdf_seed
; ============================================================
hpke_stern_f_decap_known_32:
    push ecx
    push ebx
    mov  ecx, eax               ; ecx = e'
    mov  ebx, [t_sdf_seed]     ; ebx = seed
    mov  eax, 4                 ; ds = 4
    call stern_hash2_32
    pop  ebx
    pop  ecx
    ret

; ============================================================
; ring_fs_challenges_32: writes ring_joint_b[0..3]
; Hashes t_sdf_msg then member0 (ring0_c0/c1/c2) then member1
; (sdf_c0/c1/c2) in member-major order.
; ============================================================
ring_fs_challenges_32:
    push ebx
    push esi
    push edi
    push ecx
    push edx
    xor  esi, esi
    mov  eax, [t_sdf_msg]
    xor  eax, esi
    mov  ebx, [t_sdf_msg]
    rol  ebx, 4
    mov  ecx, 8
    call nl_fscx_revolve_v1
    mov  esi, eax
    xor  edi, edi
.trfc_m0_loop:
    cmp  edi, SDF_ROUNDS
    jge  .trfc_m0_done
    mov  eax, [ring0_c0 + edi*4]
    xor  eax, esi
    mov  ebx, [ring0_c0 + edi*4]
    rol  ebx, 4
    mov  ecx, 8
    call nl_fscx_revolve_v1
    mov  esi, eax
    mov  eax, [ring0_c1 + edi*4]
    xor  eax, esi
    mov  ebx, [ring0_c1 + edi*4]
    rol  ebx, 4
    call nl_fscx_revolve_v1
    mov  esi, eax
    mov  eax, [ring0_c2 + edi*4]
    xor  eax, esi
    mov  ebx, [ring0_c2 + edi*4]
    rol  ebx, 4
    call nl_fscx_revolve_v1
    mov  esi, eax
    inc  edi
    jmp  .trfc_m0_loop
.trfc_m0_done:
    xor  edi, edi
.trfc_m1_loop:
    cmp  edi, SDF_ROUNDS
    jge  .trfc_m1_done
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
    jmp  .trfc_m1_loop
.trfc_m1_done:
    xor  edi, edi
.trfc_chal_loop:
    cmp  edi, SDF_ROUNDS
    jge  .trfc_done
    mov  eax, esi
    mov  ebx, edi
    call nl_fscx_v1
    mov  esi, eax
    xor  edx, edx
    mov  ecx, 3
    div  ecx
    mov  [ring_joint_b + edi*4], edx
    inc  edi
    jmp  .trfc_chal_loop
.trfc_done:
    pop  edx
    pop  ecx
    pop  edi
    pop  esi
    pop  ebx
    ret

; ============================================================
; hpks_stern_ring2_sign_32: k=2, signer=1, b0[r]=0 always
; Reads t_sdf_seed/t_sdf_e/t_sdf_msg for member 1.
; ============================================================
hpks_stern_ring2_sign_32:
    push ebx
    push esi
    push edi
    push ebp
    push ecx
    push edx
    ; Phase 1: simulate member 0 (b=0 all rounds)
    xor  ebp, ebp
.thrs2_sim_loop:
    cmp  ebp, SDF_ROUNDS
    jge  .thrs2_sim_done
    mov  dword [ring0_b + ebp*4], 0
    mov  eax, 1
    xor  ebx, ebx
    xor  ecx, ecx
    call stern_hash2_32
    mov  [ring0_c0 + ebp*4], eax
    call stern_rand_error_32
    mov  esi, eax
    mov  [ring0_respA + ebp*4], esi
    mov  eax, 2
    mov  ebx, esi
    call stern_hash1_32
    mov  [ring0_c1 + ebp*4], eax
    call prng_next
    mov  edi, eax
    mov  [ring0_respB + ebp*4], edi
    mov  eax, 3
    mov  ebx, edi
    call stern_hash1_32
    mov  [ring0_c2 + ebp*4], eax
    inc  ebp
    jmp  .thrs2_sim_loop
.thrs2_sim_done:
    ; Phase 2: commit phase for member 1
    mov  esi, [t_sdf_seed]
    mov  edi, [t_sdf_e]
    xor  ebp, ebp
.thrs2_commit_loop:
    cmp  ebp, SDF_ROUNDS
    jge  .thrs2_commit_done
    call stern_rand_error_32
    mov  [sdf_r_tmp + ebp*4], eax
    mov  ebx, eax
    xor  ebx, edi
    mov  [sdf_y_tmp + ebp*4], ebx
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
    mov  ecx, eax
    mov  ebx, [sdf_pi_tmp + ebp*4]
    mov  eax, 1
    call stern_hash2_32
    mov  [sdf_c0 + ebp*4], eax
    mov  eax, 2
    mov  ebx, [sdf_sr_tmp + ebp*4]
    call stern_hash1_32
    mov  [sdf_c1 + ebp*4], eax
    mov  eax, 3
    mov  ebx, [sdf_sy_tmp + ebp*4]
    call stern_hash1_32
    mov  [sdf_c2 + ebp*4], eax
    inc  ebp
    jmp  .thrs2_commit_loop
.thrs2_commit_done:
    ; Phase 3: joint FS challenges
    call ring_fs_challenges_32
    ; Phase 4: assign member 1 challenges and responses
    xor  ebp, ebp
.thrs2_resp_loop:
    cmp  ebp, SDF_ROUNDS
    jge  .thrs2_resp_done
    mov  eax, [ring_joint_b + ebp*4]
    mov  [sdf_b + ebp*4], eax
    cmp  eax, 0
    je   .thrs2_case0
    cmp  eax, 1
    je   .thrs2_case1
    mov  eax, [sdf_pi_tmp + ebp*4]
    mov  [sdf_respA + ebp*4], eax
    mov  eax, [sdf_y_tmp + ebp*4]
    mov  [sdf_respB + ebp*4], eax
    jmp  .thrs2_resp_next
.thrs2_case0:
    mov  eax, [sdf_sr_tmp + ebp*4]
    mov  [sdf_respA + ebp*4], eax
    mov  eax, [sdf_sy_tmp + ebp*4]
    mov  [sdf_respB + ebp*4], eax
    jmp  .thrs2_resp_next
.thrs2_case1:
    mov  eax, [sdf_pi_tmp + ebp*4]
    mov  [sdf_respA + ebp*4], eax
    mov  eax, [sdf_r_tmp + ebp*4]
    mov  [sdf_respB + ebp*4], eax
.thrs2_resp_next:
    inc  ebp
    jmp  .thrs2_resp_loop
.thrs2_resp_done:
    pop  edx
    pop  ecx
    pop  ebp
    pop  edi
    pop  esi
    pop  ebx
    ret

; ============================================================
; hpks_stern_ring2_verify_32: -> EAX=1 valid, 0 invalid
; ============================================================
hpks_stern_ring2_verify_32:
    push ebx
    push esi
    push edi
    push ebp
    push ecx
    push edx
    call ring_fs_challenges_32
    ; check challenge sum
    xor  ebp, ebp
.thrv2_sum_loop:
    cmp  ebp, SDF_ROUNDS
    jge  .thrv2_sum_ok
    mov  eax, [ring0_b + ebp*4]
    add  eax, [sdf_b + ebp*4]
    xor  edx, edx
    mov  ecx, 3
    div  ecx
    cmp  edx, [ring_joint_b + ebp*4]
    jne  .thrv2_fail
    inc  ebp
    jmp  .thrv2_sum_loop
.thrv2_sum_ok:
    ; verify member 0 (b=0)
    xor  ebp, ebp
.thrv2_m0_loop:
    cmp  ebp, SDF_ROUNDS
    jge  .thrv2_m0_done
    cmp  dword [ring0_b + ebp*4], 0
    jne  .thrv2_fail
    mov  eax, 2
    mov  ebx, [ring0_respA + ebp*4]
    call stern_hash1_32
    cmp  eax, [ring0_c1 + ebp*4]
    jne  .thrv2_fail
    mov  eax, [ring0_respA + ebp*4]
    call stern_popcount_eq2
    cmp  eax, 1
    jne  .thrv2_fail
    mov  eax, 3
    mov  ebx, [ring0_respB + ebp*4]
    call stern_hash1_32
    cmp  eax, [ring0_c2 + ebp*4]
    jne  .thrv2_fail
    inc  ebp
    jmp  .thrv2_m0_loop
.thrv2_m0_done:
    ; verify member 1
    mov  esi, [t_sdf_seed]
    mov  edi, [t_sdf_syn]
    xor  ebp, ebp
.thrv2_m1_loop:
    cmp  ebp, SDF_ROUNDS
    jge  .thrv2_m1_done
    mov  ecx, [sdf_b + ebp*4]
    cmp  ecx, 0
    je   .thrv2_b0
    cmp  ecx, 1
    je   .thrv2_b1
    mov  eax, esi
    mov  ebx, [sdf_respB + ebp*4]
    call stern_syndrome_32
    xor  eax, edi
    mov  ecx, eax
    mov  ebx, [sdf_respA + ebp*4]
    mov  eax, 1
    call stern_hash2_32
    cmp  eax, [sdf_c0 + ebp*4]
    jne  .thrv2_fail
    mov  eax, [sdf_respA + ebp*4]
    call stern_gen_perm_32
    mov  eax, [sdf_respB + ebp*4]
    call stern_apply_perm_32
    mov  ebx, eax
    mov  eax, 3
    call stern_hash1_32
    cmp  eax, [sdf_c2 + ebp*4]
    jne  .thrv2_fail
    jmp  .thrv2_m1_next
.thrv2_b0:
    mov  eax, 2
    mov  ebx, [sdf_respA + ebp*4]
    call stern_hash1_32
    cmp  eax, [sdf_c1 + ebp*4]
    jne  .thrv2_fail
    mov  eax, [sdf_respA + ebp*4]
    call stern_popcount_eq2
    cmp  eax, 1
    jne  .thrv2_fail
    mov  eax, 3
    mov  ebx, [sdf_respB + ebp*4]
    call stern_hash1_32
    cmp  eax, [sdf_c2 + ebp*4]
    jne  .thrv2_fail
    jmp  .thrv2_m1_next
.thrv2_b1:
    mov  eax, [sdf_respB + ebp*4]
    call stern_popcount_eq2
    cmp  eax, 1
    jne  .thrv2_fail
    mov  eax, esi
    mov  ebx, [sdf_respB + ebp*4]
    call stern_syndrome_32
    mov  ecx, eax
    mov  ebx, [sdf_respA + ebp*4]
    mov  eax, 1
    call stern_hash2_32
    cmp  eax, [sdf_c0 + ebp*4]
    jne  .thrv2_fail
    mov  eax, [sdf_respA + ebp*4]
    call stern_gen_perm_32
    mov  eax, [sdf_respB + ebp*4]
    call stern_apply_perm_32
    mov  ebx, eax
    mov  eax, 2
    call stern_hash1_32
    cmp  eax, [sdf_c1 + ebp*4]
    jne  .thrv2_fail
.thrv2_m1_next:
    inc  ebp
    jmp  .thrv2_m1_loop
.thrv2_m1_done:
    mov  eax, 1
    jmp  .thrv2_exit
.thrv2_fail:
    xor  eax, eax
.thrv2_exit:
    pop  edx
    pop  ecx
    pop  ebp
    pop  edi
    pop  esi
    pop  ebx
    ret
