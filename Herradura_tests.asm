;  Herradura KEx -- Correctness Tests v1.3.7
;  NASM i386 Assembly -- HKEX, HSKE, HPKS, HPKE correctness tests
;  100 LCG-random iterations per test, KEYBITS=32, I_VALUE=8, R_VALUE=24
;
;  Copyright (C) 2024-2026 Omar Alejandro Herrera Reyna
;  MIT License / GPL v3.0 -- choose either.
;
;  Assemble: nasm -f elf32 Herradura_tests.asm -o tests32.o
;  Link:     ld -m elf_i386 -o Herradura_tests_i386 tests32.o
;  Run:      ./Herradura_tests_i386  (x86_32 Linux) or  qemu-i386 ./Herradura_tests_i386

%define SYS_EXIT   1
%define SYS_WRITE  4
%define STDOUT     1
%define I_VALUE    8
%define R_VALUE    24

section .data

    prng_state dd 0x12345678

    hdr        db "=== Herradura KEx -- Correctness Tests (NASM i386, KEYBITS=32) ===", 10, 10
    hdr_l      equ $-hdr

    t1_hdr     db "[1] HKEX key exchange correctness: skeyA == skeyB", 10
    t1_hdr_l   equ $-t1_hdr
    t2_hdr     db "[2] HSKE encrypt+decrypt round-trip: D == plaintext", 10
    t2_hdr_l   equ $-t2_hdr
    t3_hdr     db "[3] HPKS sign+verify correctness: V == plaintext", 10
    t3_hdr_l   equ $-t3_hdr
    t4_hdr     db "[4] HPKE encrypt+decrypt round-trip: D == plaintext", 10
    t4_hdr_l   equ $-t4_hdr

    pass100    db "    100 / 100 passed  [PASS]", 10
    pass100_l  equ $-pass100
    fail_msg   db "    FAILED            [FAIL]", 10
    fail_msg_l equ $-fail_msg

section .bss

    t_A        resd 1
    t_B        resd 1
    t_A2       resd 1
    t_B2       resd 1
    t_C        resd 1
    t_C2       resd 1
    t_hn       resd 1
    t_val      resd 1   ; scratch / plaintext / key
    t_key      resd 1
    t_E        resd 1
    t_S        resd 1

    hex_buf    resb 12

section .text
global _start

_start:
    mov  eax, hdr
    mov  ecx, hdr_l
    call print_str

    ; ================================================================== [1] HKEX
    mov  eax, t1_hdr
    mov  ecx, t1_hdr_l
    call print_str

    mov  ecx, 100
    xor  ebp, ebp           ; pass counter

.t1_loop:
    push ecx

    ; A, B, A2, B2 = prng_next()
    call prng_next
    mov  [t_A], eax
    call prng_next
    mov  [t_B], eax
    call prng_next
    mov  [t_A2], eax
    call prng_next
    mov  [t_B2], eax

    ; C = fscx_revolve(A, B, I_VALUE)
    mov  eax, [t_A]
    mov  ebx, [t_B]
    mov  ecx, I_VALUE
    call FSCX_revolve
    mov  [t_C], eax

    ; C2 = fscx_revolve(A2, B2, I_VALUE)
    mov  eax, [t_A2]
    mov  ebx, [t_B2]
    mov  ecx, I_VALUE
    call FSCX_revolve
    mov  [t_C2], eax

    ; hkex_nonce = C ^ C2
    mov  eax, [t_C]
    xor  eax, [t_C2]
    mov  [t_hn], eax

    ; skeyA = fscx_revolve_n(C2, B, R_VALUE, &t_hn) ^ A
    mov  eax, [t_C2]
    mov  ebx, [t_B]
    mov  ecx, R_VALUE
    mov  esi, t_hn
    call FSCX_revolve_n
    xor  eax, [t_A]
    mov  [t_val], eax       ; save skeyA

    ; skeyB = fscx_revolve_n(C, B2, R_VALUE, &t_hn) ^ A2
    mov  eax, [t_C]
    mov  ebx, [t_B2]
    mov  ecx, R_VALUE
    mov  esi, t_hn
    call FSCX_revolve_n
    xor  eax, [t_A2]        ; eax = skeyB

    cmp  eax, [t_val]       ; skeyB == skeyA?
    jne  .t1_skip
    inc  ebp
.t1_skip:
    pop  ecx
    dec  ecx
    jnz  near .t1_loop

    cmp  ebp, 100
    jne  .t1_fail
    mov  eax, pass100
    mov  ecx, pass100_l
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
    mov  [t_val], eax       ; plaintext
    call prng_next
    mov  [t_key], eax       ; key (also used as nonce)

    ; E = fscx_revolve_n(plain, key, I_VALUE, &t_key)
    mov  eax, [t_val]
    mov  ebx, [t_key]
    mov  ecx, I_VALUE
    mov  esi, t_key
    call FSCX_revolve_n
    mov  [t_E], eax

    ; D = fscx_revolve_n(E, key, R_VALUE, &t_key)
    mov  eax, [t_E]
    mov  ebx, [t_key]
    mov  ecx, R_VALUE
    mov  esi, t_key
    call FSCX_revolve_n     ; eax = D

    cmp  eax, [t_val]       ; D == plaintext?
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

    ; ================================================================== [3] HPKS
    mov  eax, t3_hdr
    mov  ecx, t3_hdr_l
    call print_str

    mov  ecx, 100
    xor  ebp, ebp

.t3_loop:
    push ecx

    ; A, B, A2, B2 = prng_next()
    call prng_next
    mov  [t_A], eax
    call prng_next
    mov  [t_B], eax
    call prng_next
    mov  [t_A2], eax
    call prng_next
    mov  [t_B2], eax
    call prng_next
    mov  [t_val], eax       ; plaintext

    ; C = fscx_revolve(A, B, I_VALUE)
    mov  eax, [t_A]
    mov  ebx, [t_B]
    mov  ecx, I_VALUE
    call FSCX_revolve
    mov  [t_C], eax

    ; C2 = fscx_revolve(A2, B2, I_VALUE)
    mov  eax, [t_A2]
    mov  ebx, [t_B2]
    mov  ecx, I_VALUE
    call FSCX_revolve
    mov  [t_C2], eax

    ; hkex_nonce = C ^ C2
    mov  eax, [t_C]
    xor  eax, [t_C2]
    mov  [t_hn], eax

    ; S = fscx_revolve_n(C2, B, R_VALUE, &t_hn) ^ A ^ plaintext
    mov  eax, [t_C2]
    mov  ebx, [t_B]
    mov  ecx, R_VALUE
    mov  esi, t_hn
    call FSCX_revolve_n
    xor  eax, [t_A]
    xor  eax, [t_val]
    mov  [t_S], eax

    ; V = fscx_revolve_n(C, B2, R_VALUE, &t_hn) ^ A2 ^ S  (should == plaintext)
    mov  eax, [t_C]
    mov  ebx, [t_B2]
    mov  ecx, R_VALUE
    mov  esi, t_hn
    call FSCX_revolve_n
    xor  eax, [t_A2]
    xor  eax, [t_S]         ; eax = V

    cmp  eax, [t_val]       ; V == plaintext?
    jne  .t3_skip
    inc  ebp
.t3_skip:
    pop  ecx
    dec  ecx
    jnz  near .t3_loop

    cmp  ebp, 100
    jne  .t3_fail
    mov  eax, pass100
    mov  ecx, pass100_l
    call print_str
    jmp  .t3_done
.t3_fail:
    mov  eax, fail_msg
    mov  ecx, fail_msg_l
    call print_str
.t3_done:

    ; ================================================================== [4] HPKE
    mov  eax, t4_hdr
    mov  ecx, t4_hdr_l
    call print_str

    mov  ecx, 100
    xor  ebp, ebp

.t4_loop:
    push ecx

    ; A, B, A2, B2 = prng_next()
    call prng_next
    mov  [t_A], eax
    call prng_next
    mov  [t_B], eax
    call prng_next
    mov  [t_A2], eax
    call prng_next
    mov  [t_B2], eax
    call prng_next
    mov  [t_val], eax       ; plaintext

    ; C = fscx_revolve(A, B, I_VALUE)
    mov  eax, [t_A]
    mov  ebx, [t_B]
    mov  ecx, I_VALUE
    call FSCX_revolve
    mov  [t_C], eax

    ; C2 = fscx_revolve(A2, B2, I_VALUE)
    mov  eax, [t_A2]
    mov  ebx, [t_B2]
    mov  ecx, I_VALUE
    call FSCX_revolve
    mov  [t_C2], eax

    ; hkex_nonce = C ^ C2
    mov  eax, [t_C]
    xor  eax, [t_C2]
    mov  [t_hn], eax

    ; E = fscx_revolve_n(C, B2, R_VALUE, &t_hn) ^ A2 ^ plaintext   (Bob encrypts)
    mov  eax, [t_C]
    mov  ebx, [t_B2]
    mov  ecx, R_VALUE
    mov  esi, t_hn
    call FSCX_revolve_n
    xor  eax, [t_A2]
    xor  eax, [t_val]
    mov  [t_E], eax

    ; D = fscx_revolve_n(C2, B, R_VALUE, &t_hn) ^ A ^ E   (Alice decrypts, should == plaintext)
    mov  eax, [t_C2]
    mov  ebx, [t_B]
    mov  ecx, R_VALUE
    mov  esi, t_hn
    call FSCX_revolve_n
    xor  eax, [t_A]
    xor  eax, [t_E]         ; eax = D

    cmp  eax, [t_val]       ; D == plaintext?
    jne  .t4_skip
    inc  ebp
.t4_skip:
    pop  ecx
    dec  ecx
    jnz  near .t4_loop

    cmp  ebp, 100
    jne  .t4_fail
    mov  eax, pass100
    mov  ecx, pass100_l
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
    imul eax, ebx           ; lower 32 bits of state * 1664525
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
; FSCX_revolve_n: EAX=A, EBX=B, ECX=rounds, ESI=&nonce
;                 -->  EAX=result  (ESI not clobbered)
; ============================================================
FSCX_revolve_n:
    push eax
    pop  edx
.fscxn_loop:
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
    xor  edx, [esi]         ; XOR nonce from memory
    mov  eax, edx
    loop .fscxn_loop
    ret
