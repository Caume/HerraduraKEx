# Herradura KEx (HKEX)
HKEX is a lightweight Key Exchange scheme in the style of Diffie-Hellman Key Exchange, based on bitwise operations.

This Key Exchange scheme is demonstrated through the exchange of values produced by the FSCX_REVOLVE function. This function implements an iteration of XOR operations, where each bit at position An of the first input is XORed with its surrounding bits, positions An-1 mod P and An+1 mod P, as well as with bits of the second input in positions Bn-1 mod P, Bn and Bn+1 mod P,  where P is the size in bits of the input numbers (say 64 bits).

So, let A, B, C be bitstrings of size P, where A_{i} is the ith bit in the string (from left to right) of bitstring A, and i belongs to the set N={0..P-1}. Let XOR be the bitwise exclusive OR operator. Let MOD be the modulo operator. We define the FSCX multivariate function as follows:

	FSCX (A,B) = (C,B), where C := A_{i MOD P} XOR A_{(i+1) MOD P} XOR A_{(i-1) MOD P} XOR B_{i MOD P} XOR B_{(i+1) MOD P} XOR B_{(i-1) MOD P}, for each i in the set N.

An alternate definition using circular shifts (bitwise rotations) is as follows: Let XOR be the bitwise exclusive OR operator, and let ROR(x) and ROL(x) be the bitwise rotation (i.e. circular bit shift) functions by one bit of bit string x to the right and to the left respectively.

	FSCX (A,B) = C = A XOR B XOR ROL(A) XOR ROL(B) XOR ROR(A) XOR ROR(B)

Using the following symbols for ROL, ROR and XOR respectively,  $\circlearrowleft, \circlearrowright, \oplus$, we can rewrite the FSCX definition as follows:

$fscx (A,B) = (C,B) = [(A \oplus B \oplus ( \circlearrowleft A) \oplus (\circlearrowleft B) \oplus (\circlearrowright A) \oplus (\circlearrowright B)), B]$

FSCX_REVOLVE is an iterated version of the FSCX function with the 2nd parameter (bit string B) constant, that produces a ring of numbers of size P or P/2 . That is, the FSCX_REVOLVE function takes the result of the previous iteration as the first input, and maintains the second input constant. For 64 bit long bit strings, iterations will produce a number field of 32 or 64 numbers, where the result of the last iteration will be equal to A (i.e. the orbit of the iterated function will be 32 or 64 in this example).

The result of several iterations with the exception of iterations equal to P or P/2 (e.g. 32 and 64 for P=64 bits) which produce as a result the first input, cannot be used to identify the unique inputs used at the first iteration, since there are several combinations of inputs that produce the same result at each iteration.

The FSCX_REVOLVE function is defined as follows (where $\circ n$ means n iterations):

$fscxRevolve (A,B,n) = fscx^{\circ n}(A,B) = (Z, B), \forall n\in \mathbb{N}$

That is, the FSCX_REVOLVE function is the FSCX function applied to bitstrings A and B, iterated n times. We also denote the existance of a periodic orbit q where A = Z, as follows:

$\forall q\in \mathbb{N},\exists{n} \mid fscx^{\circ nq}(A,B) = (A, B)$

For bitstrings A and B of size P in bits, and where P is of the form 2^n it, it stands that for all q in the natural number set, there exists a number of iterations n where the result of the iterated function is the identity (A,B). That is: you can iterate indefinitely producing the identity (A,B) every P or P/2 iterations. 

The Herradura Key Exchange Scheme is as follows:
1) Alice and Bob select 2 random numbers each, A and B, of length P bits, such that P is 2^n (n=6 -> P= 64, for 64bit numbers), and apply i < P FSCX, using the FSXC_REVOLVE function with A and B as the inputs for the first iteration, and the result of each iteration along with B as the inputs for subsequent iterations (e.g. i=16 iterations for P=64). Recommended value for i is P/4. So, let D and D2 be the result of the FSCX_REVOLVE function for Alice and Bob respectively, using 64 bit numbers:
		
		Alice:  D  = FSCX_REVOLVE(A,B,16)
		Bob:    D2 = FSCX_REVOLVE(A2,B2,16)

2) Both parties exchange the result of FSCX_REVOLVE from step 1)
		
		Alice: sends D to Bob
		Bob:   sends D2 to Alice
		
3) Alice and Bob apply FSCX_REVOLVE with the remaining iterations r needed to complete the size in bit of the inputs, so that r+i=P (r=48 in our 64bit example), using as inputs the result obtained from the other party from step 2), and the same number, B, that each party has used during step 1), and then XOR the result with A and A2 respectively. Recommended value for r is P/4 * 3.

		Alice: FA  = FSCX_REVOLVE(D2,B,48)
		Bob:   FA2 = FSCX_REVOLVE(D,B2,48)
		where  FA == FA2 (shared secret frome HKEX)

An attacker in the middle can only see the exchanged numbers at step 2) (D, D2). The security of the Herradura scheme relies on the difficulty to trace back (brute force) all possible inputs through all the iterations (16 iterations in our 64bit example) of the FSCX_REVOLVE function.

In addition to the Key Exchange (HKEX), the Herradura base function (FSCX_REVOLVE) can be used to implement a lightweight one-to-one assymetric key encryption (Herradura AEn).



# Herradura AEn (HAEN)
HAEN is a lightweight encryption scheme using assymetric keys for one-to-one communication (not suitable to be used directly for public key encryption).

The Herradura Assymetric Encryption scheme is as follows (i = P/4, r = P-i):
1) Alice and Bob obtain a shared value (PSV) with the HKEX protocol

		Alice: PSV = FA  = HKEX_with_Bob (A,B,r,i)
		Bob:   PSV = FA2 = HKEX_with_Alice (A2,B2,r,i)

2) Alice encrypts cleatext C using FSCX_REVOLVE function with C XOR PSV XOR A as parameter 1, B as parameter 2 and i as parameter 3, and sends the encrypted result, E, to Bob.
	
		Alice: sends to Bob E = FSCX_REVOLVE(C XOR PSV XOR A, B, 16)

3) Bob decrypts E with FSCX_REVOLVE, with E as parameter 1, B2 as parameter 2, and r as parameter 3, xoring the result with A2.

		Bob: decrypts E so that C2 = FSCX_REVOLVE(E,B2,48) XOR A2, where C == C2
	
The security of the HAEN protocol relies on the security of HKEX. It should be noted that, as with other encryption protocols, repeated use of the key material for subsecuent encryptions might leak information. It is recomended to have a prearranged way to change PSV with each subsequent encryption (e.g. incrementing PSV with each subsequent encryption, similar to the CTR encryption mode with symmetric encryption algorithms).

Also note that although keys are assymetric in HAEN, it can't be used directly for public key encryption since you can decrypt with both keys (e.g. Alice can decrypt again E with C = FSCX_REVOLVE(E,B,48) XOR A XOR PSV).

# Herradura Cryptographic Suite
These source code files contain examples and battery tests for the following cryptographic protocols that use the Herradura Cryptographic primitives FSCX and FSCX_REVOLVE:

1) HKEX (key exchange)
2) HSKE (symmetric key encryption) --> replaces HAEN.
3) HPKS (public key signature)  --> must be used with HSKE (i.e. HPKS+HSKE) to be secure (see the examples)!
4) HPKE (public key encryption)

Documentation for the new public key encryption and signature protocols is included in within the code.

Example implementations are provided in multiple languages, including C, Go, Python
and assembler.  Assembly examples for both x86 and ARM Linux are available in the
source tree.

# FSCX_REVOLVE_N (v1.1)

FSCX_REVOLVE_N is a nonce-augmented variant of FSCX_REVOLVE introduced in v1.1 of the Herradura Cryptographic Suite. Instead of iterating FSCX alone, each step applies:

	result = FSCX(result, B) ⊕ N

where N is a nonce derived from protocol context (no new secrets required):

- **HKEX, HPKS, HPKE**: N = C ⊕ C2, computable from the public key (C is published; C2 = FSCX_REVOLVE(A2, B2, i) is derivable from the public parameters A2, B2 and the public round count i).
- **HSKE**: N = key (the shared key is injected at every revolve step, not only at the input/output boundaries).

Using the linear operator notation L = Id ⊕ ROL ⊕ ROR, the two variants compare as:

	FSCX_REVOLVE  (A, B,    n) = L^n(A) ⊕ S_n(B)           [purely linear in A over GF(2)]
	FSCX_REVOLVE_N(A, B, N, n) = L^n(A) ⊕ T_n(L(B) ⊕ N)    [affine in A over GF(2)]

where S_n = L + L² + ... + L^n and T_n = I + L + ... + L^(n-1).

The key security improvement is that the purely linear structure is broken: an attacker observing two public values C₁ and C₂ computed with the same B but different A values can no longer extract L^i(A₁ ⊕ A₂) from C₁ ⊕ C₂ across sessions, because the session-specific nonce N mixes into the affine constant at every step.

**Proof that the HKEX equality is preserved under FSCX_REVOLVE_N:**

The equality FSCX_REVOLVE_N(C2, B, N, r) ⊕ A = FSCX_REVOLVE_N(C, B2, N, r) ⊕ A2 holds because expanding both sides with C = FSCX_REVOLVE(A, B, i) and C2 = FSCX_REVOLVE(A2, B2, i), and applying L^(r+i) = I (since r+i = P), the condition reduces to:

	L^r(T_i(Z)) = T_r(Z)   for all Z

This is identical to the condition without the nonce — N cancels from both sides identically. The same condition guarantees correctness for HSKE, HPKS, and HPKE.

**Orbit properties** are preserved: FSCX_REVOLVE_N(·, B, N, ·) is a bijection on GF(2)^P, so all orbits are finite. Empirical validation confirms orbit lengths remain ≤ 2P.

# Build & Run Instructions

## C

```bash
# Basic HKEX (64-bit)
gcc -DINTSZ=64 -O2 -o HKEX Herradura_KEx.c
./HKEX

# Basic HKEX with verbose output (brute-force attack simulation)
gcc -DINTSZ=64 -DVERBOSE -O2 -o HKEX_verbose Herradura_KEx.c
./HKEX_verbose

# Basic HKEX with GMP big numbers (requires libgmp-dev)
gcc -DINTSZ=256 -O2 -o HKEX_bignum Herradura_KEx_bignum.c -lgmp
./HKEX_bignum

# Full cryptographic suite (HKEX + HSKE + HPKS + HPKE) — 256-bit BitArray parameters
gcc -O2 -o "Herradura cryptographic suite" "Herradura cryptographic suite.c"
./"Herradura cryptographic suite"

# Security & performance tests
gcc -O2 -o Herradura_tests Herradura_tests.c
./Herradura_tests
```

## Go

```bash
# Basic HKEX
go run Herradura_KEx.go

# Full cryptographic suite (HKEX + HSKE + HPKS + HPKE)
go run "Herradura cryptographic suite.go"

# Security & performance tests
go run Herradura_tests.go
```

## Python

```bash
# Basic HKEX
python3 Herradura_KEx.py -b 64 -v

# Full cryptographic suite (HKEX + HSKE + HPKS + HPKE)
python3 "Herradura cryptographic suite.py"

# Security & performance tests
python3 Herradura_tests.py
```

## Assembly

```bash
# ARM Linux (requires arm-linux-gnueabi-gcc; run with QEMU on non-ARM host)
arm-linux-gnueabi-gcc -o HKEX_arm HKEX_arm_linux.s
./HKEX_arm          # on ARM hardware
qemu-arm ./HKEX_arm # on non-ARM host

# x86 NASM assembly (requires NASM and asm_io.o library)
nasm -f elf HAEN.asm
gcc -m32 -o HAEN HAEN.o asm_io.o
./HAEN
```

# Final note
These cryptographic algorithms and protocols are released in the hope that they will be useful for building efficient and robust schemes, based on bitwise operations.


OAHR
