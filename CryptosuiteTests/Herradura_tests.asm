;  Herradura KEx -- Correctness Tests v1.5.3
;  NASM i386 Assembly -- HKEX-GF, HSKE, HPKS Schnorr, HPKE El Gamal,
;                        NL-FSCX v2 inv, HSKE-NL-A2, HKEX-RNL, HPKS-NL, HPKE-NL
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
%define STDOUT     1
%define I_VALUE    8
%define R_VALUE    24
%define GF_POLY    0x00400007
%define RNL_N      32
%define RNL_Q      65537
%define RNL_P      4096
%define RNL_PP     2

section .data

    prng_state  dd 0x12345678

    ; implicit arg pointers for rnl_poly_mul/add
    rnl_f_ptr   dd 0
    rnl_g_ptr   dd 0
    rnl_h_ptr   dd 0

    hdr         db "=== Herradura KEx v1.5.3 -- Correctness Tests (NASM i386, KEYBITS=32) ===", 10, 10
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
    t7_hdr      db "[7] HKEX-RNL key agreement: KA == KB (10 trials, pass >= 8)", 10
    t7_hdr_l    equ $-t7_hdr
    t8_hdr      db "[8] HPKS-NL Schnorr correctness: g^s * C^e == R with NL challenge (20 iter)", 10
    t8_hdr_l    equ $-t8_hdr
    t9_hdr      db "[9] HPKE-NL encrypt+decrypt: D == plaintext (NL-FSCX v2) (20 iterations)", 10
    t9_hdr_l    equ $-t9_hdr
    t10_hdr     db "[10] HPKS-NL Eve resistance: random forgery rejected (20 trials)", 10
    t10_hdr_l   equ $-t10_hdr

    pass20      db "    20 / 20 passed  [PASS]", 10
    pass20_l    equ $-pass20
    pass100     db "    100 / 100 passed  [PASS]", 10
    pass100_l   equ $-pass100
    pass_rnl    db "    >= 8 / 10 raw keys agreed  [PASS]", 10
    pass_rnl_l  equ $-pass_rnl
    fail_msg    db "    FAILED  [FAIL]", 10
    fail_msg_l  equ $-fail_msg

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

section .text
global _start

_start:
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

    ; KA = agree(s_A, C_B)
    mov  eax, rnl_s_A
    mov  ebx, rnl_C_B
    call rnl_agree
    mov  [t_KA], eax

    ; KB = agree(s_B, C_A)
    mov  eax, rnl_s_B
    mov  ebx, rnl_C_A
    call rnl_agree
    mov  [t_KB], eax

    mov  eax, [t_KA]
    cmp  eax, [t_KB]
    jne  .t7_skip
    inc  ebp
.t7_skip:
    dec  dword [t_ctr]
    jnz  near .t7_loop

    cmp  ebp, 8
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
; rnl_poly_mul: uses [rnl_h_ptr],[rnl_f_ptr],[rnl_g_ptr]
; Uses rnl_tmp as temp buffer.
; ============================================================
rnl_poly_mul:
    push ebx
    push ecx
    push edx
    push esi
    push edi
    push ebp

    xor  eax, eax
    mov  ecx, RNL_N
    mov  edi, rnl_tmp
    rep  stosd

    mov  esi, [rnl_f_ptr]

    xor  ecx, ecx
.rpm_outer:
    cmp  ecx, RNL_N
    jge  .rpm_outer_done

    mov  eax, [esi + ecx*4]
    test eax, eax
    jz   .rpm_outer_next

    mov  ebp, ecx

    xor  ebx, ebx
.rpm_inner:
    cmp  ebx, RNL_N
    jge  .rpm_inner_done

    mov  edi, [rnl_g_ptr]
    mov  edx, [edi + ebx*4]
    test edx, edx
    jz   .rpm_inner_next

    push eax
    push ebx
    push ecx
    push edx
    mov  eax, [esi + ebp*4]
    xor  edx, edx
    pop  ecx
    mul  ecx
    add  eax, edx
    xor  edx, edx
    mov  ecx, RNL_Q
    div  ecx
    mov  eax, edx
    pop  ecx
    pop  ebx
    pop  edx

    mov  edx, ebp
    add  edx, ebx
    cmp  edx, RNL_N
    jge  .rpm_neg

    push eax
    push ecx
    push edx
    mov  ecx, edx
    mov  edx, [rnl_tmp + ecx*4]
    add  edx, eax
    push ebx
    mov  ebx, RNL_Q
    cmp  edx, ebx
    jl   .rpm_add_no_sub
    sub  edx, ebx
.rpm_add_no_sub:
    pop  ebx
    mov  ecx, [esp+4]
    mov  [rnl_tmp + ecx*4], edx
    pop  edx
    pop  ecx
    pop  eax
    jmp  .rpm_inner_next

.rpm_neg:
    sub  edx, RNL_N
    push eax
    push ecx
    push edx
    mov  ecx, edx
    mov  edx, [rnl_tmp + ecx*4]
    sub  edx, eax
    push ebx
    mov  ebx, RNL_Q
    add  edx, ebx
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
    mov  eax, [esi + edi*4]
    mov  ecx, [esp+12]
    mul  ecx
    mov  ecx, [esp+8]
    div  ecx
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
; rnl_agree: EAX=s, EBX=C_other --> EAX=uint32 key
; ============================================================
rnl_agree:
    push ebx
    push ecx
    push edx
    push esi
    push edi
    push ebp
    mov  esi, eax
    mov  edi, ebx

    mov  ebp, rnl_tmp
    mov  esi, edi
    mov  ecx, RNL_P
    mov  edx, RNL_Q
    call rnl_lift

    pop  ebp
    pop  edi
    pop  esi
    pop  edx
    pop  ecx
    pop  ebx
    push ebx
    push ecx
    push edx
    push esi
    push edi
    push ebp

    mov  esi, [esp + 5*4]
    mov  dword [rnl_h_ptr], rnl_tmp2
    mov  [rnl_f_ptr], esi
    mov  dword [rnl_g_ptr], rnl_tmp
    call rnl_poly_mul

    mov  ebp, rnl_tmp
    mov  esi, rnl_tmp2
    mov  ecx, RNL_Q
    mov  edx, RNL_PP
    call rnl_round

    mov  eax, rnl_tmp
    call rnl_bits32

    pop  ebp
    pop  edi
    pop  esi
    pop  edx
    pop  ecx
    pop  ebx
    ret
