;  Herradura Cryptographic Suite v1.3.7
;  NASM i386 Assembly -- HKEX, HSKE, HPKS, HPKE with FSCX_REVOLVE_N
;  KEYBITS = 32, I_VALUE = 8, R_VALUE = 24
;
;  Copyright (C) 2024-2026 Omar Alejandro Herrera Reyna
;  MIT License / GPL v3.0 -- choose either.
;
;  Assemble: nasm -f elf32 "Herradura cryptographic suite.asm" -o suite32.o
;  Link:     ld -m elf_i386 -o "Herradura cryptographic suite_i386" suite32.o
;  Run:      ./suite_i386   (x86_32 Linux) or  qemu-i386 ./suite_i386

%define SYS_EXIT   1
%define SYS_WRITE  4
%define STDOUT     1
%define I_VALUE    8
%define R_VALUE    24

section .data

    val_A     dd 0xDEADBEEF
    val_B     dd 0xCAFEBABE
    val_A2    dd 0x12345678
    val_B2    dd 0xABCDEF01
    val_key   dd 0x5A5A5A5A
    val_plain dd 0xDEADC0DE
    val_C     dd 0
    val_C2    dd 0
    val_hn    dd 0
    val_skA   dd 0
    val_skB   dd 0
    val_E     dd 0
    val_D     dd 0
    val_S     dd 0
    val_V     dd 0
    val_nonce dd 0          ; ESI-pointed nonce for fscx_revolve_n

    hdr       db "=== Herradura Cryptographic Suite (NASM i386, KEYBITS=32) ===", 10
    hdr_l     equ $-hdr

    lbl_A     db "A         : "
    lbl_A_l   equ $-lbl_A
    lbl_B     db "B         : "
    lbl_B_l   equ $-lbl_B
    lbl_A2    db "A2        : "
    lbl_A2_l  equ $-lbl_A2
    lbl_B2    db "B2        : "
    lbl_B2_l  equ $-lbl_B2
    lbl_key   db "key       : "
    lbl_key_l equ $-lbl_key
    lbl_plain db "plaintext : "
    lbl_pl_l  equ $-lbl_plain
    lbl_C     db "C         : "
    lbl_C_l   equ $-lbl_C
    lbl_C2    db "C2        : "
    lbl_C2_l  equ $-lbl_C2
    lbl_hn    db "hkex_nonce: "
    lbl_hn_l  equ $-lbl_hn

    hkex_hdr  db 10, "--- HKEX (key exchange)", 10
    hkex_hdr_l equ $-hkex_hdr
    lbl_skA   db "skeyA (Alice): "
    lbl_skA_l equ $-lbl_skA
    lbl_skB   db "skeyB (Bob)  : "
    lbl_skB_l equ $-lbl_skB

    hske_hdr  db 10, "--- HSKE (symmetric key encryption)", 10
    hske_hdr_l equ $-hske_hdr
    lbl_E     db "E (encrypted): "
    lbl_E_l   equ $-lbl_E
    lbl_D     db "D (decrypted): "
    lbl_D_l   equ $-lbl_D

    hpks_hdr  db 10, "--- HPKS (public key signature)", 10
    hpks_hdr_l equ $-hpks_hdr
    lbl_S     db "S (signature): "
    lbl_S_l   equ $-lbl_S
    lbl_V     db "V (verified) : "
    lbl_V_l   equ $-lbl_V

    hpke_hdr  db 10, "--- HPKE (public key encryption)", 10
    hpke_hdr_l equ $-hpke_hdr
    lbl_Eb    db "E (Bob)  : "
    lbl_Eb_l  equ $-lbl_Eb
    lbl_Da    db "D (Alice): "
    lbl_Da_l  equ $-lbl_Da

    pass_msg  db "+ correct!", 10
    pass_l    equ $-pass_msg
    fail_msg  db "- INCORRECT!", 10
    fail_l    equ $-fail_msg

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
    mov  eax, lbl_A
    mov  ecx, lbl_A_l
    call print_str
    mov  eax, [val_A]
    call print_hex32

    mov  eax, lbl_B
    mov  ecx, lbl_B_l
    call print_str
    mov  eax, [val_B]
    call print_hex32

    mov  eax, lbl_A2
    mov  ecx, lbl_A2_l
    call print_str
    mov  eax, [val_A2]
    call print_hex32

    mov  eax, lbl_B2
    mov  ecx, lbl_B2_l
    call print_str
    mov  eax, [val_B2]
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

    ; ---- C = fscx_revolve(A, B, I_VALUE)
    mov  eax, [val_A]
    mov  ebx, [val_B]
    mov  ecx, I_VALUE
    call FSCX_revolve
    mov  [val_C], eax

    mov  eax, lbl_C
    mov  ecx, lbl_C_l
    call print_str
    mov  eax, [val_C]
    call print_hex32

    ; ---- C2 = fscx_revolve(A2, B2, I_VALUE)
    mov  eax, [val_A2]
    mov  ebx, [val_B2]
    mov  ecx, I_VALUE
    call FSCX_revolve
    mov  [val_C2], eax

    mov  eax, lbl_C2
    mov  ecx, lbl_C2_l
    call print_str
    mov  eax, [val_C2]
    call print_hex32

    ; ---- hkex_nonce = C ^ C2
    mov  eax, [val_C]
    xor  eax, [val_C2]
    mov  [val_hn], eax

    mov  eax, lbl_hn
    mov  ecx, lbl_hn_l
    call print_str
    mov  eax, [val_hn]
    call print_hex32

    ; ================================================================== HKEX
    mov  eax, hkex_hdr
    mov  ecx, hkex_hdr_l
    call print_str

    ; skeyA = fscx_revolve_n(C2, B, R_VALUE, &val_hn) ^ A
    mov  eax, [val_C2]
    mov  ebx, [val_B]
    mov  ecx, R_VALUE
    mov  esi, val_hn
    call FSCX_revolve_n
    xor  eax, [val_A]
    mov  [val_skA], eax

    mov  eax, lbl_skA
    mov  ecx, lbl_skA_l
    call print_str
    mov  eax, [val_skA]
    call print_hex32

    ; skeyB = fscx_revolve_n(C, B2, R_VALUE, &val_hn) ^ A2
    mov  eax, [val_C]
    mov  ebx, [val_B2]
    mov  ecx, R_VALUE
    mov  esi, val_hn
    call FSCX_revolve_n
    xor  eax, [val_A2]
    mov  [val_skB], eax

    mov  eax, lbl_skB
    mov  ecx, lbl_skB_l
    call print_str
    mov  eax, [val_skB]
    call print_hex32

    ; pass/fail
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

    ; E = fscx_revolve_n(plaintext, key, I_VALUE, &val_key)
    mov  eax, [val_plain]
    mov  ebx, [val_key]
    mov  ecx, I_VALUE
    mov  esi, val_key
    call FSCX_revolve_n
    mov  [val_E], eax

    mov  eax, lbl_E
    mov  ecx, lbl_E_l
    call print_str
    mov  eax, [val_E]
    call print_hex32

    ; D = fscx_revolve_n(E, key, R_VALUE, &val_key)
    mov  eax, [val_E]
    mov  ebx, [val_key]
    mov  ecx, R_VALUE
    mov  esi, val_key
    call FSCX_revolve_n
    mov  [val_D], eax

    mov  eax, lbl_D
    mov  ecx, lbl_D_l
    call print_str
    mov  eax, [val_D]
    call print_hex32

    ; pass/fail: D == plaintext
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

    ; ================================================================== HPKS
    mov  eax, hpks_hdr
    mov  ecx, hpks_hdr_l
    call print_str

    ; S = fscx_revolve_n(C2, B, R_VALUE, &val_hn) ^ A ^ plaintext
    mov  eax, [val_C2]
    mov  ebx, [val_B]
    mov  ecx, R_VALUE
    mov  esi, val_hn
    call FSCX_revolve_n
    xor  eax, [val_A]
    xor  eax, [val_plain]
    mov  [val_S], eax

    mov  eax, lbl_S
    mov  ecx, lbl_S_l
    call print_str
    mov  eax, [val_S]
    call print_hex32

    ; V = fscx_revolve_n(C, B2, R_VALUE, &val_hn) ^ A2 ^ S   (should == plaintext)
    mov  eax, [val_C]
    mov  ebx, [val_B2]
    mov  ecx, R_VALUE
    mov  esi, val_hn
    call FSCX_revolve_n
    xor  eax, [val_A2]
    xor  eax, [val_S]
    mov  [val_V], eax

    mov  eax, lbl_V
    mov  ecx, lbl_V_l
    call print_str
    mov  eax, [val_V]
    call print_hex32

    ; pass/fail: V == plaintext
    mov  eax, [val_V]
    cmp  eax, [val_plain]
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

    ; ================================================================== HPKE
    mov  eax, hpke_hdr
    mov  ecx, hpke_hdr_l
    call print_str

    ; E = fscx_revolve_n(C, B2, R_VALUE, &val_hn) ^ A2 ^ plaintext   (Bob encrypts)
    mov  eax, [val_C]
    mov  ebx, [val_B2]
    mov  ecx, R_VALUE
    mov  esi, val_hn
    call FSCX_revolve_n
    xor  eax, [val_A2]
    xor  eax, [val_plain]
    mov  [val_E], eax

    mov  eax, lbl_Eb
    mov  ecx, lbl_Eb_l
    call print_str
    mov  eax, [val_E]
    call print_hex32

    ; D = fscx_revolve_n(C2, B, R_VALUE, &val_hn) ^ A ^ E   (Alice decrypts, should == plaintext)
    mov  eax, [val_C2]
    mov  ebx, [val_B]
    mov  ecx, R_VALUE
    mov  esi, val_hn
    call FSCX_revolve_n
    xor  eax, [val_A]
    xor  eax, [val_E]
    mov  [val_D], eax

    mov  eax, lbl_Da
    mov  ecx, lbl_Da_l
    call print_str
    mov  eax, [val_D]
    call print_hex32

    ; pass/fail: D == plaintext
    mov  eax, [val_D]
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
; B is kept constant across all iterations.
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
; FSCX_revolve_n: EAX=A, EBX=B, ECX=rounds, ESI=&nonce
;                 -->  EAX=result
; Like FSCX_revolve but XORs [ESI] (nonce) after each step.
; ESI is not clobbered.
; ============================================================
FSCX_revolve_n:
    push eax
    pop  edx            ; edx = running result (starts as A)
.fscxn_loop:
    xor  edx, ebx       ; edx ^= B
    rol  eax, 1
    xor  edx, eax       ; edx ^= ROL(A)
    ror  eax, 2
    xor  edx, eax       ; edx ^= ROR(A)
    rol  ebx, 1
    xor  edx, ebx       ; edx ^= ROL(B)
    ror  ebx, 2
    xor  edx, ebx       ; edx ^= ROR(B)
    rol  ebx, 1         ; ebx restored to B
    xor  edx, [esi]     ; edx ^= nonce  (nonce-augmented step)
    mov  eax, edx       ; eax = new A for next iteration
    loop .fscxn_loop
    ret                 ; EAX = result
