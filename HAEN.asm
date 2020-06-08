; HAEN.asm, (c) 2020 by Omar A. Herrera Reyna
; Herradura Assymetric Encryption (and Herradura Key Exchange)example in 
; assembler, for Linux i386, using NASM
; 	assemble:	nasm -f elf -l HAEN_HAEN.lst  HAEN.asm
;               nasm -f elf -d ELF_TYPE asm_io.asm
; 	link:		gcc -m32 -o HAEN  HAEN.o asm_io.o
;
; 	run:	    ./HAEN 
;
; 	gdb:		nasm -g -f elf -l HAEN.lst HAEN.asm
;               nasm -g -f elf -d ELF_TYPE asm_io.asm 
;	gdb link:	gcc -m32 -g -o HAEN  HAEN.o asm_io.o

%include "asm_io.inc"			;IO library from Paul Carter's PCASM 
								;http://pacman128.github.io/static/linux-ex.zip
rounds1 equ (32 / 4) * 3	    ;HKEX/HAEN initial rounds (24)
rounds2 equ (32 / 4)		    ;HKEX/HAEN final rounds (8)

    segment .data	; data section
msg1	db "Hello World",10,0	    ;the string to encrypt (plaintext) 10=cr
len1	equ $-msg1		            ;("$" means "here")
		align 4,db 0	            ;align to double words
msg2  	db 10,"Encrypted:",10,0
len2	equ $-msg2
		align 4,db 0	
msg3  	db 10,"Decrypted:",10,0
len3	equ $-msg3
		align 4,db 0	
ctext  times (msg2 - msg1+1) db 0x0	;placeholder for encrypted string
		align 4,db 0	
ptext  times (msg2 - msg1+1) db 0x0	;placeholder for decrypted string
		align 4,db 0	
msg4  	db "HKEX executed correctly!",10,0
len4	equ $-msg4
		align 4,db 0	

		;HKEX parameters and placeholders:
keyA   	dd 0x01AB0234	
keyB	dd 0x02F46A8B
keyA2	dd 0xF1E30102
keyB2	dd 0x5C45404B
dA		dd 0x0
dA2		dd 0x0
skey	dd 0x0		;placeholder for HKEX shared key (HAEN secret key) 
skey2	dd 0x0

;---START---------------------------------------------------------------
	segment .text	; code section
    global main		; make label available to linker 
main:	            ; standard  gcc  entry point, for nasm use asm_main

HKEX:				; creates shared key for HAEN encryption
	;FSCX initial rounds ALICE:
	mov eax,[keyA]
	mov ebx,[keyB]
	mov ecx,rounds1
	call FSCX_revolve
	mov [dA],eax
	;FSCX initial rounds BOB:
	mov eax,[keyA2]
	mov ebx,[keyB2]
	mov ecx,rounds1
	call FSCX_revolve
	mov [dA2],eax	
	;FSCX final rounds ALICE:
	mov eax,[dA2]
	mov ebx,[keyB]
	mov ecx,rounds2
	call FSCX_revolve
	xor eax,[keyA]
	mov [skey],eax
	;FSCX final rounds BOB:
	mov eax,[dA]
	mov ebx,[keyB2]
	mov ecx,rounds2
	call FSCX_revolve
	xor eax,[keyA2]
	mov [skey2],eax	
	cmp eax,[skey]
	jne hkexNOk
hkexOk:	
	mov eax,msg4
	call print_string
hkexNOk:	
	nop
print_msg1:
	mov eax,msg1
	call print_string

HAEN:				; HAEN encryption/decryption example
encrypt:
	mov eax,[keyA]
	mov edx,[skey]
	mov ebx,[keyB]
	mov ecx,(msg2 - msg1) / 4	; = len1 + alignment
	mov esi,msg1
	mov edi,ctext
	call HAEN_enc
print_encrypted:
	mov eax,msg2
	call print_string
print_ctext:	
	mov eax,ctext
	call print_string
decrypt:
	mov edx,[keyA2]
	mov ebx,[keyB2]
	mov ecx,(msg2 - msg1) / 4	; = len1 + alignment
	mov esi,ctext
	mov edi,ptext
	call HAEN_dec
print_decrypted:
	mov eax,msg3
	call print_string
print_ptext:
	mov eax,ptext
	call print_string	
exit:
	mov	ebx,0	; exit code, 0=normal
	mov	eax,1	; exit command to kernel
	int	0x80	; interrupt 80 hex, call kernel

;---END of _start-------------------------------------------------------   

FSCX_revolve:	;FSCX = A ^ B ^ rol(A) ^ rol(B) ^ ror(A) ^ ror(B)
                ;params: EAX <- A, EBX <- B, ECX <- rounds
                ; sets: EDX = intermediate FSCX results
                ;returns result D in EAX
	push eax
	pop edx	    ;smaller than mov edx,eax 
FSCX_loop:			
	xor edx,ebx
	rol eax,1
	xor edx,eax
	ror eax,2
	xor edx,eax
	rol ebx,1
	xor edx,ebx
	ror ebx,2
	xor edx,ebx
	rol ebx,1
	mov eax,edx
	loop FSCX_loop
	ret	        ;EAX <- result 

HAEN_enc:	    ;HAEN_encrypt of message A in 32 bit blocks, with 
                ; preshared Key PSK (from HKEX) and secret B =
                ; FSCX_revolve(A ^ PSK ^ PT,B,rounds1) = ciphertext CT
                ;params: EAX <-A, EDX <- PSK, EBX <- B, ECX <- 32bit block #, 
                ;		 ESI <- src address of plaintext A, EDI <- dst 
                ;               address of ciphertext
                ;sets: EAX = intermadiate results
                ;returns CT in EDI
	push eax
	push edx
	push ecx	;save block counter
	xor edx,eax
	mov eax,[esi+4*ecx-4]	;read block to encrypt
	xor eax,edx
	xor eax,ecx	            ;CTR mode using block counter
	push rounds1
	pop ecx
	call FSCX_revolve	    ;encrypt
	pop ecx	                ;restore block counter
	mov [edi+4*ecx-4],eax	;write encrypted block
	pop edx
	pop eax
	loop HAEN_enc	        ;encrypt all blocks in reverse order
	ret

HAEN_dec:	    ;HAEN decrypt of ciphertext CT in 32 bit blocks, with 
                ; implicit preshared Key PSK (from HKEX) and secret B2 =
                ; FSCX_revolve(CT,B2,rounds2) = Plaintext A
                ;params: EBX <- B2, ECX <- 32bit block #, EDX <- A2
                ;		 ESI <- src address of ciphertext A, EDI <- dst 
                ;               address of decrypted text
                ;sets: EAX = 32bit blocks from ciphertext
                ;returns: decrypted plaintext in EDI
	mov eax,[esi+4*ecx-4]	;read block to decrypt
	push ecx	            ;save block counter
	push edx	            ;save A2
	push rounds2
	pop ecx
	call FSCX_revolve
	pop edx	                ;restore A2
	pop ecx	                ;restore block counter
	xor eax,edx	            ;last part: xor A2
	xor eax,ecx	            ;CTR mode using block counter
	mov [edi+4*ecx-4],eax	;write decrypted block
	loop HAEN_dec	        ;encrypt all blocks in reverse order
	ret
	
