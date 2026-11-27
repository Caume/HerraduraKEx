;  demos/i386/hpks_stern_ring.asm -- HPKS-Stern-Ring ring signature (NASM i386, KEYBITS=32; TODO #425)
;  One algorithm end to end: its sample inputs, every intermediate, and its
;  verdict through the shared [FAIL] gate.  The routines and data are in
;  core.asm, included rather than linked.  Build: ./build_asm_i386.sh;
;  run: ./run_asm_i386.sh suite.

%include "core.asm"

section .data
    demo_name   db "HPKS-Stern-Ring ring signature"
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
    ; ========================================================== HPKS-Stern-Ring (TODO #424)
    ; Ring = (another key, Alice's Stern key val_sdf_seed / val_sdf_syn); Alice
    ; signs as member 1 with val_sdf_e.  One Stern proof over the ring; the
    ; signature does not say which member signed.
    mov  eax, ring_hdr
    mov  ecx, ring_hdr_l
    call print_str
    call prng_next
    mov  [ring_in], eax         ; member 0: another key
    call stern_rand_error_32
    mov  ebx, eax
    mov  eax, [ring_in]
    call stern_syndrome_32
    mov  [ring_in+4], eax
    mov  eax, [val_sdf_seed]    ; member 1: Alice
    mov  [ring_in+8], eax
    mov  eax, [val_sdf_syn]
    mov  [ring_in+12], eax
    mov  eax, [val_sdf_e]
    mov  [ring_e], eax
    mov  dword [ring_j], 1
    mov  eax, [val_plain]
    mov  [ring_msg], eax
    call hpks_stern_ring_sign_32
    mov  ebx, eax
    mov  eax, [val_plain]
    call hpks_stern_ring_verify_32
    and  eax, ebx
    cmp  eax, 1
    jne  .ring_fail
    mov  eax, ring_ok
    mov  ecx, ring_ok_l
    call print_str
    jmp  .ring_done
.ring_fail:
    mov  eax, ring_fail
    mov  ecx, ring_fail_l
    call print_str
.ring_done:
    mov  eax, [ring_in]         ; the same ring in the other order
    mov  ebx, [ring_in+8]
    mov  [ring_in], ebx
    mov  [ring_in+8], eax
    mov  eax, [ring_in+4]
    mov  ebx, [ring_in+12]
    mov  [ring_in+4], ebx
    mov  [ring_in+12], eax
    mov  eax, [val_plain]
    call hpks_stern_ring_verify_32
    cmp  eax, 1
    jne  .ring_rev_fail
    mov  eax, ring_rev_ok
    mov  ecx, ring_rev_ok_l
    call print_str
    jmp  .ring_rev_done
.ring_rev_fail:
    mov  eax, ring_rev_fail
    mov  ecx, ring_rev_fail_l
    call print_str
.ring_rev_done:
    ; Eve changes one opening word (round 1's first r / PI r word)
    xor  dword [ring_sig+52], 1
    mov  eax, [val_plain]
    call hpks_stern_ring_verify_32
    xor  dword [ring_sig+52], 1  ; restore
    test eax, eax
    jnz  .eve_ring_fail
    mov  eax, eve_ring_ok
    mov  ecx, eve_ring_ok_l
    call print_str
    jmp  .eve_ring_done
.eve_ring_fail:
    mov  eax, eve_ring_fail
    mov  ecx, eve_ring_fail_l
    call print_str
.eve_ring_done:
    ; Eve presents the signature for another message
    mov  eax, [val_plain]
    xor  eax, 1
    call hpks_stern_ring_verify_32
    test eax, eax
    jnz  .eve_ringm_fail
    mov  eax, eve_ringm_ok
    mov  ecx, eve_ringm_ok_l
    call print_str
    jmp  .eve_ringm_done
.eve_ringm_fail:
    mov  eax, eve_ringm_fail
    mov  ecx, eve_ringm_fail_l
    call print_str
.eve_ringm_done:

    jmp  demo_finish
