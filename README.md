# HerraduraKEx
Herradura is a Key Exchange scheme in the style of Diffie-Hellman Key Exchange, based on bitwise operations.

This Key Exchange scheme is demonstrated through the exchange of values produced by the FSCX_REVOLVE function. This function implements an iterated process of XOR operations, where each bit at position An of the first input is XORed with its surrounding bits, positions An-1 mod P and An+1 mod P, as well as with bits of the second input in positions Bn-1 mod P, Bn and Bn+1 mod P,  where P is the size in bits of the input numbers (64 bits in the demonstration code).

Iterations within de FSCX_REVOLVE function take the result of the previous iteration as the first input, and maintain the second input constant. Depending on the inputs, iterations will produced a field of 32 or 64 numbers for 64 bit integers.

The result of several iterations with the exeption of iterations #32 and #64 (which yield as result the first input, depending on the inputs chosen) cannot be used to identify the unique inputs used at the first iteration, since there are multiple combinations of inputs that produce the same result at each iteration.

The Herradura Key Exchange Scheme is as follows:
1) Each party select 2 random numbers (64bit in the example code provided), and applies several iterations with FSXC_REVOLVE with those numbers as first input (16 iterations in the example code).
2) Both parties exchange the result of the 16 rounds of FSCX_REVOLVE
3) Apply FSCX_REVOLVE with the remaining iterations neded to complete the size in bit of the inputs (48 in the example code), using as inputs the result obtained from the other party from step 2), and the same number they have used as second input since step 1).
4) Finally, they XOR the result with the first input that they used in step 1) - Both parties will get the same number (key) 

An attacker in the middle can only see the exchanged numbers at step 2). The security of the Herradura scheme relies then on how difficult and process consuming it is to calculate all possible inputs through the iterations of the FSCX_REVOLVE funcions before the exchange (16 in the example provided), so that some of the original inputs (secrets can be discovered).

OAHR
