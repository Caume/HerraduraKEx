# HerraduraKEx
Herradura is a Key Exchange scheme in the style of Diffie-Hellman Key Exchange, based on bitwise operations.

This Key Exchange scheme is demonstrated through the exchange of values produced by the FSCX_REVOLVE function. This function implements an iterated process of XOR operations, where each bit at position An of the first input is XORed with its surrounding bits, positions An-1 mod P and An+1 mod P, as well as with bits of the second input in positions Bn-1 mod P, Bn and Bn+1 mod P,  where P is the size in bits of the input numbers (say 64 bits).

So, let A, B, C be bitsreams of size P, where A_{n} is the nth bit in the stream from left to right of bitstream A, and n belongs to the set N={0..P-1}. Let XOR be the bitwise exclusive OR operator. Let MOD be the modulo operator.

FSCX (A,B) = C = A_{n MOD P} XOR A_{(n+1) MOD P} XOR A_{(n-1) MOD P} XOR B_{n MOD P} XOR B_{(n+1) MOD P} XOR B_{(n-1) MOD P}, for each n in the set N.

FSCX_REVOLVE is an iterated version of the FSCX function with the 2nd parameter (bitstream B) constant, that produces a ring of numbers of size P or P/2. That is, iterations within de FSCX_REVOLVE function take the result of the previous iteration as the first input, and maintain the second input constant. For 64 bit long bitstreams, iterations will produce a number field of 32 or 64 numbers, where the result of the last iteration will be equal to A.

The result of several iterations with the exeption of iterations #32 and #64 (which yield as result the first input, depending on the inputs chosen) cannot be used to identify the unique inputs used at the first iteration, since there are multiple combinations of inputs that produce the same result at each iteration.

The Herradura Key Exchange Scheme is as follows:
1) Each party select 2 random numbers A and B, of length P bits, such that P is 2^n (n=6 -> P= 64, for 64bit numbers), and applies several iterations i < P, with FSXC_REVOLVE with A and B as the inputs for the first iteration, and the result of each iteration with B as inputs for subsequent iterations (e.g. 16 iterations for P=64). Recommended value for i is P/4.
2) Both parties exchange the result of the last iteration of FSCX_REVOLVE from step 1)
3) Apply FSCX_REVOLVE with the remaining iterations r neded to complete the size in bit of the inputs, so that r+i=P (r=48 in our 64bit example), using as inputs the result obtained from the other party from step 2), and the same number, B, that each party have used during step 1). Recommended value for r is P/4 * 3.
4) Finally, both parties XOR the result with the first input, A, that each used in step 1) - Both parties will get the same number (shared key/secret) 

An attacker in the middle can only see the exchanged numbers at step 2). The security of the Herradura scheme relies then on how difficult and process consuming it is to calculate all possible inputs through the iterations of the FSCX_REVOLVE funcions before the exchange (16 iterations in our 64bit example), until some of the original inputs/secrets can be discovered.

OAHR
