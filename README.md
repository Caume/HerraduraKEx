# Herradura KEx (HKEX)
HKEX is a lightweight Key Exchange scheme in the style of Diffie-Hellman Key Exchange, based on bitwise operations.

This Key Exchange scheme is demonstrated through the exchange of values produced by the FSCX_REVOLVE function. This function implements an iteration of XOR operations, where each bit at position An of the first input is XORed with its surrounding bits, positions An-1 mod P and An+1 mod P, as well as with bits of the second input in positions Bn-1 mod P, Bn and Bn+1 mod P,  where P is the size in bits of the input numbers (say 64 bits).

So, let A, B, C be bitstrings of size P, where A_{i} is the ith bit in the string (from left to right) of bitstring A, and i belongs to the set N={0..P-1}. Let XOR be the bitwise exclusive OR operator. Let MOD be the modulo operator. We define the FSCX multivariate function as follows:

	FSCX (A,B) = (C,B), where C := A_{i MOD P} XOR A_{(i+1) MOD P} XOR A_{(i-1) MOD P} XOR B_{i MOD P} XOR B_{(i+1) MOD P} XOR B_{(i-1) MOD P}, for each i in the set N.

An alternate definition using circular shifts (bitwise rotations) is as follows: Let XOR be the bitwise exclusive OR operator, and let ROR(x) and ROL(x) be the bitwise rotation (i.e. circular bit shift) functions by one bit of bit string x to the right and to the left respectively.

	FSCX (A,B) = C = A XOR B XOR ROL(A) XOR ROL(B) XOR ROR(A) XOR ROR(B)

Using the following symbols for ROL, ROR and XOR respectively, 
<img src="https://render.githubusercontent.com/render/math?math=\circlearrowleft, \circlearrowright, \otimes">, We can rewrite the FSCX definition as follows:

<img src="https://render.githubusercontent.com/render/math?math=fscx (A,B) = (C,B) = [(A \otimes B \otimes ( \circlearrowleft A) \otimes (\circlearrowleft B)  \otimes (\circlearrowright A) \otimes (\circlearrowright B)), B]">

FSCX_REVOLVE is an iterated version of the FSCX function with the 2nd parameter (bit string B) constant, that produces a ring of numbers of size P or P/2 . That is, the FSCX_REVOLVE function takes the result of the previous iteration as the first input, and maintains the second input constant. For 64 bit long bit strings, iterations will produce a number field of 32 or 64 numbers, where the result of the last iteration will be equal to A (i.e. the orbit of the iterated function will be 32 or 64 in this example).

The result of several iterations with the exception of iterations equal to P or P/2 (e.g. 32 and 64 for P=64 bits) which produce as a result the first input, cannot be used to identify the unique inputs used at the first iteration, since there are several combinations of inputs that produce the same result at each iteration.

Using formal notation the FSCX_REVOLVE function is defined as follows:

<img src="https://render.githubusercontent.com/render/math?math=fscxRevolve (A,B,n) = fscx^{\circ n}(A,B) = (C, B), \forall n\in \mathbb{N}">

That is, the FSCX_REVOLVE function is the FSCX function over bitstrings A and B, iterated n times. We also denote the existance of a periodoc orbit as follows:

<img src="https://render.githubusercontent.com/render/math?math=\forall p\in \mathbb{N},\exists{n} \mid fscx^{\circ np}(A,B) = (A, B)">

For all p in the natural number set, there exists a number of iterations n where the result of the iterated function is the identity (A,B); you can iterate indefinitely producing the identity (A,B) every n iterations (in the case of the FSCX_REVOLVE function, n is either the length of the longest bitstring from A or B, or half of that length). 

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

In addition to the Key Exchange (HKEX), the Herradura base function (FSCX_REVOLVE) can be used to implement efficient and lightweight one-to-one assymetric key encryption (Herradura AEn).



# Herradura AEn (HAEN)
HAEN is an efficient and lightweight encryption scheme using assymetric keys for one-to-one communication (not suitable to be used directly for public key encryption).

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



# Final note
These cryptographic algorithms and protocols are released in the hope that they will be useful for building efficient and robust schemes, based on fast bitwise operations. 


OAHR
