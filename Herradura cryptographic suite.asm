;  Herradura Cryptographic Suite v1.4.0
;  NASM i386 Assembly -- HKEX-GF, HSKE, HPKS Schnorr, HPKE El Gamal
;  KEYBITS = 32, I_VALUE = 8, R_VALUE = 24
;  HKEX-GF: DH over GF(2^32)*, poly x^32+x^22+x^2+x+1, generator g=3
;  HPKS:    Schnorr signature; s=(k-a*e) mod ORD; verify g^s*C^e==R
;  HPKE:    El Gamal + fscx_revolve; enc_key=C^r; dec_key=R^a
;
;  Copyright (C) 2024-2026 Omar Alejandro Herrera Reyna
;  MIT License / GPL v3.0 -- choose either.
;
;  Assemble: nasm -f elf32 "Herradura cryptographic suite.asm" -o suite32.o
;  Link:     ld -m elf_i386 -o "Herradura cryptographic suite_i386" suite32.o
;  Run:      ./"Herradura cryptographic suite_i386"  or  qemu-i386 ...
;
;  Test vectors (fixed):
;    a_priv=0xDEADBEEF, b_priv=0xCAFEBABF
;    C=0x5b8ae480, C2=0xad8f4a2c, sk=0xd3db6bc3
;    key=0x5A5A5A5A, plain=0xDEADC0DE
;    E_hske=0xadb3b3c0, D_hske=0xdeadc0de
;    k (Schnorr nonce) and r (El Gamal ephemeral) are LCG-generated.

%define SYS_EXIT   1
%define SYS_WRITE  4
%define STDOUT     1
%define I_VALUE    8
%define R_VALUE    24
%define GF_POLY    0x00400007

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
    val_k_hpks  dd 0      ; Schnorr nonce k
    val_R_hpks  dd 0      ; R = g^k
    val_e_hpks  dd 0      ; e = fscx(R, plain, 8)
    val_ae_hpks dd 0      ; a*e mod ORD
    val_s_hpks  dd 0      ; s = k - ae mod ORD
    val_gs_hpks dd 0      ; g^s
    val_r_hpke  dd 0      ; El Gamal ephemeral r
    val_R_hpke  dd 0      ; R = g^r
    val_enc_key dd 0      ; enc_key = C^r
    val_E_hpke  dd 0      ; ciphertext E
    val_dec_key dd 0      ; dec_key = R^a
    val_D_hpke  dd 0      ; plaintext D

    prng_state  dd 0xDEADBEEE   ; LCG seed = a_priv - 1

    hdr         db "=== Herradura Cryptographic Suite v1.4.0 (NASM i386, KEYBITS=32, HKEX-GF) ===", 10
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

    pass_msg    db "+ correct!", 10
    pass_l      equ $-pass_msg
    fail_msg    db "- INCORRECT!", 10
    fail_l      equ $-fail_msg

section .bss
    hex_buf resb 12         ; "0x" + 8 hex digits + newline + spare

section .text
global _start

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

    ; C = gf_pow_32(3, a_priv)
    mov  eax, 3
    mov  ebx, [val_a_priv]
    call gf_pow_32
    mov  [val_C], eax

    mov  eax, lbl_C
    mov  ecx, lbl_C_l
    call print_str
    mov  eax, [val_C]
    call print_hex32

    ; C2 = gf_pow_32(3, b_priv)
    mov  eax, 3
    mov  ebx, [val_b_priv]
    call gf_pow_32
    mov  [val_C2], eax

    mov  eax, lbl_C2
    mov  ecx, lbl_C2_l
    call print_str
    mov  eax, [val_C2]
    call print_hex32

    ; skA = gf_pow_32(C2, a_priv)
    mov  eax, [val_C2]
    mov  ebx, [val_a_priv]
    call gf_pow_32
    mov  [val_skA], eax

    mov  eax, lbl_skA
    mov  ecx, lbl_skA_l
    call print_str
    mov  eax, [val_skA]
    call print_hex32

    ; skB = gf_pow_32(C, b_priv)
    mov  eax, [val_C]
    mov  ebx, [val_b_priv]
    call gf_pow_32
    mov  [val_skB], eax

    mov  eax, lbl_skB
    mov  ecx, lbl_skB_l
    call print_str
    mov  eax, [val_skB]
    call print_hex32

    ; pass/fail: skA == skB
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
    ; k   = prng_next()
    ; R   = gf_pow_32(3, k)
    ; e   = FSCX_revolve(R, plain, 8)
    ; ae  = a_priv * e mod ORD  [mul edx:eax, then add lo+hi, adc 0]
    ; s   = k - ae mod ORD      [sub; if CF: dec]
    ; lhs = gf_mul_32(g^s, C^e)
    ; verify lhs == R
    mov  eax, hpks_hdr
    mov  ecx, hpks_hdr_l
    call print_str

    ; k = prng_next()
    call prng_next
    mov  [val_k_hpks], eax

    ; R = gf_pow_32(3, k)
    mov  eax, 3
    mov  ebx, [val_k_hpks]
    call gf_pow_32
    mov  [val_R_hpks], eax

    ; e = FSCX_revolve(R, plain, 8)
    mov  eax, [val_R_hpks]
    mov  ebx, [val_plain]
    mov  ecx, 8
    call FSCX_revolve
    mov  [val_e_hpks], eax

    ; ae_mod = a_priv * e mod ORD  (ORD = 2^32-1)
    ; mul gives edx:eax = a * e
    ; Since 2^32 == 1 (mod ORD): hi*2^32 + lo == hi + lo (mod ORD)
    push ebx
    push edx
    mov  eax, [val_a_priv]
    mov  ebx, [val_e_hpks]
    mul  ebx              ; edx:eax = a * e
    add  eax, edx         ; eax = lo + hi; CF = carry
    adc  eax, 0           ; if carry: eax += 1
    mov  [val_ae_hpks], eax
    pop  edx
    pop  ebx

    ; s = k - ae_mod mod ORD
    ; after sub, if CF=1 (borrow), wrapped = k - ae + 2^32
    ; s = wrapped - 1  (since ORD = 2^32 - 1)
    mov  eax, [val_k_hpks]
    sub  eax, [val_ae_hpks]
    jnc  .s_no_borrow
    dec  eax
.s_no_borrow:
    mov  [val_s_hpks], eax

    ; gs = gf_pow_32(3, s)
    mov  eax, 3
    mov  ebx, [val_s_hpks]
    call gf_pow_32
    mov  [val_gs_hpks], eax

    ; Ce = gf_pow_32(C, e)
    mov  eax, [val_C]
    mov  ebx, [val_e_hpks]
    call gf_pow_32        ; eax = Ce

    ; lhs = gf_mul_32(gs, Ce)
    mov  ebx, eax         ; ebx = Ce
    mov  eax, [val_gs_hpks]
    call gf_mul_32        ; eax = lhs = gs * Ce

    ; print k, R, e, s, lhs
    push eax              ; save lhs
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
    pop  eax              ; restore lhs
    push eax
    call print_hex32

    ; verify lhs == R
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
    ; r        = prng_next() | 1
    ; R_hpke   = gf_pow_32(3, r)
    ; enc_key  = gf_pow_32(C, r)       = C^r = g^{ar}
    ; E        = FSCX_revolve(plain, enc_key, 8)
    ; dec_key  = gf_pow_32(R_hpke, a)  = R^a = g^{ra}
    ; D        = FSCX_revolve(E, dec_key, 24)  == plain
    mov  eax, hpke_hdr
    mov  ecx, hpke_hdr_l
    call print_str

    ; r = prng_next() | 1
    call prng_next
    or   eax, 1
    mov  [val_r_hpke], eax

    ; R_hpke = gf_pow_32(3, r)
    mov  eax, 3
    mov  ebx, [val_r_hpke]
    call gf_pow_32
    mov  [val_R_hpke], eax

    ; enc_key = gf_pow_32(C, r) = C^r
    mov  eax, [val_C]
    mov  ebx, [val_r_hpke]
    call gf_pow_32
    mov  [val_enc_key], eax

    ; E = FSCX_revolve(plain, enc_key, 8)
    mov  eax, [val_plain]
    mov  ebx, [val_enc_key]
    mov  ecx, 8
    call FSCX_revolve
    mov  [val_E_hpke], eax

    ; dec_key = gf_pow_32(R_hpke, a_priv) = R^a
    mov  eax, [val_R_hpke]
    mov  ebx, [val_a_priv]
    call gf_pow_32
    mov  [val_dec_key], eax

    ; D = FSCX_revolve(E, dec_key, 24)
    mov  eax, [val_E_hpke]
    mov  ebx, [val_dec_key]
    mov  ecx, 24
    call FSCX_revolve
    mov  [val_D_hpke], eax

    ; print R, E, D
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

    ; verify D == plain
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

    ; ------------------------------------------------------------------ exit
    mov  eax, SYS_EXIT
    xor  ebx, ebx
    int  0x80

; ============================================================
; prng_next: LCG state = state * 1664525 + 1013904223
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
    mov  edx, ecx       ; length
    mov  ecx, eax       ; buffer
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
    mov  byte [hex_buf+10], 10      ; newline

    ; fill nibbles LSB-first into positions 9..2
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
; FSCX_revolve: EAX=A, EBX=B, ECX=rounds  -->  EAX=result
; FSCX(A,B) = A ^ B ^ ROL(A,1) ^ ROL(B,1) ^ ROR(A,1) ^ ROR(B,1)
; ============================================================
FSCX_revolve:
    push eax
    pop  edx            ; edx = running result (starts as A)
.fscx_loop:
    xor  edx, ebx       ; edx ^= B
    rol  eax, 1         ; eax = ROL(A,1)
    xor  edx, eax       ; edx ^= ROL(A)
    ror  eax, 2         ; eax = ROR(A,1)  [undo ROL, then ROR]
    xor  edx, eax       ; edx ^= ROR(A)
    rol  ebx, 1         ; ebx = ROL(B,1)
    xor  edx, ebx       ; edx ^= ROL(B)
    ror  ebx, 2         ; ebx = ROR(B,1)
    xor  edx, ebx       ; edx ^= ROR(B)
    rol  ebx, 1         ; ebx restored to B
    mov  eax, edx       ; eax = FSCX result (new A for next iteration)
    loop .fscx_loop
    ret                 ; EAX = result

; ============================================================
; gf_mul_32: EAX=a, EBX=b --> EAX=result  (a*b in GF(2^32)*)
; Uses ESI=result, EDI=aa; EBX=bb (clobbered).
; Saves/restores ESI, EDI, EBX.
; ============================================================
gf_mul_32:
    push    esi
    push    edi
    push    ebx         ; save caller's ebx
    xor     esi, esi    ; result = 0
    mov     edi, eax    ; aa = a
    ; ebx = bb (already set by caller)
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
