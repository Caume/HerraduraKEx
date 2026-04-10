;  Herradura KEx -- Correctness Tests v1.4.0
;  NASM i386 Assembly -- HKEX-GF, HSKE, HPKS Schnorr, HPKE El Gamal
;  HKEX-GF: DH over GF(2^32)*, poly x^32+x^22+x^2+x+1, generator g=3
;  HPKS Schnorr: g^s * C^e == R  (s = k-a*e mod ORD; ORD = 2^32-1)
;  HPKE El Gamal: D = fscx_revolve(E, R^a, 24) == P
;  20 LCG-random iterations per GFPow test, 100 per HSKE
;
;  Copyright (C) 2024-2026 Omar Alejandro Herrera Reyna
;  MIT License / GPL v3.0 -- choose either.
;
;  Assemble: nasm -f elf32 Herradura_tests.asm -o tests32.o
;  Link:     ld -m elf_i386 -o Herradura_tests_i386 tests32.o
;  Run:      ./Herradura_tests_i386  or  qemu-i386 ./Herradura_tests_i386

%define SYS_EXIT   1
%define SYS_WRITE  4
%define STDOUT     1
%define I_VALUE    8
%define R_VALUE    24
%define GF_POLY    0x00400007

section .data

    prng_state  dd 0x12345678

    hdr         db "=== Herradura KEx v1.4.0 -- Correctness Tests (NASM i386, KEYBITS=32, HKEX-GF) ===", 10, 10
    hdr_l       equ $-hdr

    t1_hdr      db "[1] HKEX-GF key exchange correctness: sk_alice == sk_bob (20 iterations)", 10
    t1_hdr_l    equ $-t1_hdr
    t2_hdr      db "[2] HSKE encrypt+decrypt round-trip: D == plaintext (100 iterations)", 10
    t2_hdr_l    equ $-t2_hdr
    t3_hdr      db "[3] HPKS Schnorr correctness: g^s * C^e == R (20 iterations)", 10
    t3_hdr_l    equ $-t3_hdr
    t4_hdr      db "[4] HPKE El Gamal encrypt+decrypt: D == plaintext (20 iterations)", 10
    t4_hdr_l    equ $-t4_hdr

    pass20      db "    20 / 20 passed  [PASS]", 10
    pass20_l    equ $-pass20
    pass100     db "    100 / 100 passed  [PASS]", 10
    pass100_l   equ $-pass100
    fail_msg    db "    FAILED            [FAIL]", 10
    fail_msg_l  equ $-fail_msg

section .bss

    t_a_priv    resd 1
    t_b_priv    resd 1
    t_C         resd 1
    t_C2        resd 1
    t_sk        resd 1
    t_val       resd 1    ; scratch / plaintext
    t_key       resd 1
    t_E         resd 1
    ; Schnorr scratch
    t_k         resd 1    ; nonce k
    t_R_sc      resd 1    ; R = g^k
    t_e_sc      resd 1    ; e = fscx(R, plain, 8)
    t_ae        resd 1    ; a*e mod ORD
    t_s_sc      resd 1    ; s = k - ae mod ORD
    t_gs        resd 1    ; g^s
    ; El Gamal scratch
    t_r_e       resd 1    ; ephemeral r
    t_R_e       resd 1    ; R = g^r
    t_enc_key   resd 1    ; C^r
    t_E_e       resd 1    ; ciphertext E
    t_dec_key   resd 1    ; R^a

    hex_buf     resb 12

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
    mov  [t_val], eax        ; plaintext
    call prng_next
    mov  [t_key], eax        ; key

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
    ; a   = prng_next() | 1
    ; plain = prng_next()
    ; k   = prng_next()
    ; C   = g^a;  R = g^k
    ; e   = FSCX_revolve(R, plain, 8)
    ; ae  = a*e mod ORD  (mul edx:eax, lo+hi reduction)
    ; s   = k - ae mod ORD  (sub; if CF: dec)
    ; lhs = gf_mul_32(g^s, C^e)
    ; pass: lhs == R
    mov  eax, t3_hdr
    mov  ecx, t3_hdr_l
    call print_str

    mov  ecx, 20
    xor  ebp, ebp

.t3_loop:
    push ecx

    call prng_next
    or   eax, 1
    mov  [t_a_priv], eax     ; a_priv (odd)
    call prng_next
    mov  [t_val], eax        ; plain
    call prng_next
    mov  [t_k], eax          ; k (nonce)

    ; C = gf_pow_32(3, a_priv)
    mov  eax, 3
    mov  ebx, [t_a_priv]
    call gf_pow_32
    mov  [t_C], eax

    ; R = gf_pow_32(3, k)
    mov  eax, 3
    mov  ebx, [t_k]
    call gf_pow_32
    mov  [t_R_sc], eax

    ; e = FSCX_revolve(R, plain, 8)
    mov  eax, [t_R_sc]
    mov  ebx, [t_val]
    mov  ecx, 8
    call FSCX_revolve
    mov  [t_e_sc], eax

    ; ae_mod = a_priv * e  mod ORD  (ORD = 2^32-1)
    ; mul gives edx:eax; hi + lo + carry == value mod ORD
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

    ; s = k - ae_mod mod ORD
    mov  eax, [t_k]
    sub  eax, [t_ae]
    jnc  near .t3_no_borrow
    dec  eax
.t3_no_borrow:
    mov  [t_s_sc], eax

    ; gs = gf_pow_32(3, s)
    mov  eax, 3
    mov  ebx, [t_s_sc]
    call gf_pow_32
    mov  [t_gs], eax

    ; Ce = gf_pow_32(C, e)
    mov  eax, [t_C]
    mov  ebx, [t_e_sc]
    call gf_pow_32            ; eax = Ce

    ; lhs = gf_mul_32(gs, Ce)
    mov  ebx, eax             ; ebx = Ce
    mov  eax, [t_gs]          ; eax = gs
    call gf_mul_32            ; eax = lhs = gs * Ce

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
    ; a    = prng_next() | 1
    ; plain = prng_next()
    ; r    = prng_next() | 1
    ; C    = g^a;  R = g^r
    ; enc_key = gf_pow_32(C, r) = C^r = g^{ar}
    ; E    = FSCX_revolve(plain, enc_key, 8)
    ; dec_key = gf_pow_32(R, a) = R^a = g^{ra}
    ; D    = FSCX_revolve(E, dec_key, 24)
    ; pass: D == plain
    mov  eax, t4_hdr
    mov  ecx, t4_hdr_l
    call print_str

    mov  ecx, 20
    xor  ebp, ebp

.t4_loop:
    push ecx

    call prng_next
    or   eax, 1
    mov  [t_a_priv], eax     ; a_priv (odd)
    call prng_next
    mov  [t_val], eax        ; plain
    call prng_next
    or   eax, 1
    mov  [t_r_e], eax        ; r (odd ephemeral)

    ; C = gf_pow_32(3, a_priv)
    mov  eax, 3
    mov  ebx, [t_a_priv]
    call gf_pow_32
    mov  [t_C], eax           ; C = g^a

    ; R = gf_pow_32(3, r)
    mov  eax, 3
    mov  ebx, [t_r_e]
    call gf_pow_32
    mov  [t_R_e], eax         ; R = g^r

    ; enc_key = gf_pow_32(C, r) = C^r
    mov  eax, [t_C]
    mov  ebx, [t_r_e]
    call gf_pow_32
    mov  [t_enc_key], eax

    ; E = FSCX_revolve(plain, enc_key, 8)
    mov  eax, [t_val]
    mov  ebx, [t_enc_key]
    mov  ecx, 8
    call FSCX_revolve
    mov  [t_E_e], eax         ; E (ciphertext)

    ; dec_key = gf_pow_32(R, a_priv) = R^a
    mov  eax, [t_R_e]
    mov  ebx, [t_a_priv]
    call gf_pow_32
    mov  [t_dec_key], eax

    ; D = FSCX_revolve(E, dec_key, 24)
    mov  eax, [t_E_e]
    mov  ebx, [t_dec_key]
    mov  ecx, R_VALUE
    call FSCX_revolve         ; eax = D

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

    ; ------------------------------------------------------------------ exit
    mov  eax, SYS_EXIT
    xor  ebx, ebx
    int  0x80

; ============================================================
; prng_next: LCG  state = state * 1664525 + 1013904223
;            returns new state in EAX
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
; gf_mul_32: EAX=a, EBX=b --> EAX=result  (a*b in GF(2^32)*)
; Saves/restores ESI, EDI, EBX.
; ============================================================
gf_mul_32:
    push    esi
    push    edi
    push    ebx
    xor     esi, esi    ; result = 0
    mov     edi, eax    ; aa = a
    ; ebx = bb
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
; gf_pow_32: EAX=base, EBX=exp --> EAX=result  (base^exp in GF(2^32)*)
; Saves/restores ESI, EDI.
; ============================================================
gf_pow_32:
    push    esi
    push    edi
    mov     esi, 1      ; result = 1
    mov     edi, eax    ; base
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
