/*
    Herradura KEx (HKEX) example in ARM assembler for Linux
    Equivalent functionality to Herradura_KEx.py

    Copyright (C) 2023 Omar Alejandro Herrera Reyna

    This program is free software: you can redistribute it and/or modify
    it under the terms of the MIT License or the GNU General Public License
    as published by the Free Software Foundation, either version 3 of the License,
    or (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
*/

/*
    Example build (arm 32 bit):
        arm-linux-gnueabi-gcc -o HKEX_arm HKEX_arm_linux.s

    Example run (using qemu-user for ARM 32 bit):
        qemu-arm ./HKEX_arm
*/

    .syntax unified
    .cpu cortex-a7
    .thumb

    .data
fmt_msg:    .asciz "HKEX executed correctly!\n"
fmt_hex:    .asciz "0x%08x\n"

rounds1:    .word   (32/4*3)        @ 24 rounds
rounds2:    .word   (32/4)          @ 8 rounds

keyA:   .word 0x01AB0234
keyB:   .word 0x02F46A8B
keyA2:  .word 0xF1E30102
keyB2:  .word 0x5C45404B

@ placeholders for intermediate and final values
 dA:    .word 0
 dA2:   .word 0
 skey:  .word 0
 skey2: .word 0

    .text
    .global main
    .extern printf
main:
    push    {r4-r7, lr}

    @ -- FSCX initial rounds ALICE
    ldr r0, =keyA
    ldr r0, [r0]
    ldr r1, =keyB
    ldr r1, [r1]
    ldr r2, =rounds1
    ldr r2, [r2]
    bl  fscx_revolve
    ldr r3, =dA
    str r0, [r3]

    @ -- FSCX initial rounds BOB
    ldr r0, =keyA2
    ldr r0, [r0]
    ldr r1, =keyB2
    ldr r1, [r1]
    ldr r2, =rounds1
    ldr r2, [r2]
    bl  fscx_revolve
    ldr r3, =dA2
    str r0, [r3]

    @ -- FSCX final rounds ALICE
    ldr r0, =dA2
    ldr r0, [r0]
    ldr r1, =keyB
    ldr r1, [r1]
    ldr r2, =rounds2
    ldr r2, [r2]
    bl  fscx_revolve
    ldr r3, =keyA
    ldr r3, [r3]
    eor r0, r0, r3
    ldr r3, =skey
    str r0, [r3]

    @ -- FSCX final rounds BOB
    ldr r0, =dA
    ldr r0, [r0]
    ldr r1, =keyB2
    ldr r1, [r1]
    ldr r2, =rounds2
    ldr r2, [r2]
    bl  fscx_revolve
    ldr r3, =keyA2
    ldr r3, [r3]
    eor r0, r0, r3
    ldr r3, =skey2
    str r0, [r3]

    @ -- verify
    ldr r0, [r3]       @ r0 = skey2
    ldr r1, =skey
    ldr r1, [r1]
    cmp r0, r1
    bne end

    ldr r0, =fmt_msg
    bl  printf

end:
    mov r0, #0
    bl  exit

@ -- FSCX_revolve implementation
@ r0 <- A, r1 <- B, r2 <- rounds, returns result in r0
@ clobbers r3-r7
fscx_revolve:
    push    {r4-r7, lr}
    mov r4, r0          @ current value
1:
    eor r5, r4, r1      @ result = A ^ B
    mov r6, r4, ror #1  @ ror(A,1)
    eor r5, r5, r6
    mov r6, r1, ror #1  @ ror(B,1)
    eor r5, r5, r6
    mov r6, r4, ror #31 @ rol(A,1)
    eor r5, r5, r6
    mov r6, r1, ror #31 @ rol(B,1)
    eor r5, r5, r6
    mov r4, r5
    subs r2, r2, #1
    bne 1b
    mov r0, r4
    pop {r4-r7, pc}
