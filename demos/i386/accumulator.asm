;  demos/i386/accumulator.asm -- Accumulator (NASM i386, KEYBITS=32; TODO #425)
;  One algorithm end to end: its sample inputs, every intermediate, and its
;  verdict through the shared [FAIL] gate.  The routines and data are in
;  core.asm, included rather than linked.  Build: ./build_asm_i386.sh;
;  run: ./run_asm_i386.sh suite.

%include "core.asm"

section .data
    demo_name   db "Accumulator"
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

    ; ── Accumulator (78.J): leaf = hfscx_32(data); node = hfscx_32(hfscx_32(0x01000000^L)^R)
    mov  eax, acc_hdr
    mov  ecx, acc_hdr_l
    call print_str
    ; compute 4 leaves
    mov  eax, 0xAAAAAAAA
    call hfscx_32
    mov  [acc_leaf0], eax
    mov  eax, 0xBBBBBBBB
    call hfscx_32
    mov  [acc_leaf1], eax
    mov  eax, 0xCCCCCCCC
    call hfscx_32
    mov  [acc_leaf2], eax
    mov  eax, 0xDDDDDDDD
    call hfscx_32
    mov  [acc_leaf3], eax
    ; n01 = hfscx_32(hfscx_32(0x01000000 ^ leaf0) ^ leaf1)
    mov  eax, 0x01000000
    xor  eax, [acc_leaf0]
    call hfscx_32
    xor  eax, [acc_leaf1]
    call hfscx_32
    mov  [acc_n01], eax
    ; n23 = hfscx_32(hfscx_32(0x01000000 ^ leaf2) ^ leaf3)
    mov  eax, 0x01000000
    xor  eax, [acc_leaf2]
    call hfscx_32
    xor  eax, [acc_leaf3]
    call hfscx_32
    mov  ebx, eax                   ; n23 in ebx
    ; root = hfscx_32(hfscx_32(0x01000000 ^ n01) ^ n23)
    mov  eax, 0x01000000
    xor  eax, [acc_n01]
    call hfscx_32
    xor  eax, ebx
    call hfscx_32
    mov  [acc_root], eax
    ; proof for index 2: cur=node(leaf2,leaf3)=n23, then node(n01,cur)=root
    ; n23 already in ebx; recompute it and then the second level
    mov  eax, 0x01000000
    xor  eax, [acc_leaf2]
    call hfscx_32
    xor  eax, [acc_leaf3]
    call hfscx_32
    mov  ebx, eax                   ; cur = node(leaf2,leaf3)
    mov  eax, 0x01000000
    xor  eax, [acc_n01]
    call hfscx_32
    xor  eax, ebx
    call hfscx_32                   ; reconstructed root
    cmp  eax, [acc_root]
    jne  .acc_fail
    mov  eax, acc_ok
    mov  ecx, acc_ok_l
    call print_str
    jmp  .acc_done
.acc_fail:
    mov  eax, acc_fail
    mov  ecx, acc_fail_l
    call print_str
.acc_done:

    ; Eve presents a member's proof path for a leaf that is not in the set
    mov  eax, eve_hdr
    mov  ecx, eve_hdr_l
    call print_str
    mov  eax, 0xEEEEEEEE
    call hfscx_32                   ; Eve's leaf
    xor  eax, 0x01000000
    call hfscx_32
    xor  eax, [acc_leaf3]
    call hfscx_32                   ; node(Eve's leaf, leaf3)
    mov  ebx, eax
    mov  eax, 0x01000000
    xor  eax, [acc_n01]
    call hfscx_32
    xor  eax, ebx
    call hfscx_32                   ; the root that path implies
    cmp  eax, [acc_root]
    je   .eve_acc_fail
    mov  eax, eve_acc_ok
    mov  ecx, eve_acc_ok_l
    call print_str
    jmp  .eve_acc_done
.eve_acc_fail:
    mov  eax, eve_acc_fail
    mov  ecx, eve_acc_fail_l
    call print_str
.eve_acc_done:

    jmp  demo_finish
