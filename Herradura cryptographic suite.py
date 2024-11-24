from bitstring import BitArray
import hashlib
import os

def new_rand_bitarray(bitlength):
    result = BitArray(bitlength)
    result.bytes = os.urandom(bitlength // 8) # bytes([1] * (bitlength // 8))  # Replace with a secure random number generator
    return result

def fscx_revolve(A, B, steps, verbose=False):
    result = A.copy()
    for step in range(steps):
        result = fscx(result, B)
        if verbose:
            print(f"Step {step + 1}: {result.hex}")
    return result

def fscx(A, B):     # [binary] full surroundings cyclic xor
    result = A ^ B
    A.rol(1)
    B.rol(1)
    result ^= A ^ B
    A.ror(2)
    B.ror(2)
    result ^= A ^ B
    A.rol(1)
    B.rol(1)
    return result

'''  
let,    Alice, Bob: i + r == bitlength b;  i == 1/4 bitlength; r == 3/4 bitlength; bitlength is a power of 2 >= 8
        P be a plaintext message of bitlength b,
        E the encrypted version of plaintext P,
        D == P the decrypted version of E.
let,    Alice: A,B be random values of bitlength b,
        Bob: A2,B2 be random values of bitlength b
let,    Alice: C = fscx_revolve(A, B, i) ,
        Bob: C2 = fscx_revolve(A2, B2, i)
then,   Alice: D = fscx_revolve(C2, B, r) ^ A , 
        Bob: D2 = fscx_revolve(C, B2, r) ^ A2
where,  Alice, Bob: D == D2
then,   fscx_revolve(C2, B, r) ^ A  == fscx_revolve(C, B2, r) ^ A2,
        fscx_revolve(C2, B, r) ^ A ^ P == fscx_revolve(C, B2, r) ^ A2 ^ P,
        fscx_revolve(C2, B, R) ^ A ^ A2 ^ P == fscx_revolve(C, B2, r)  ^ P #Note that this form breaks trapdoor
also,   fscx_revolve(C2, B, r) ^ A  ^ P == fscx_revolve(C2 ^ P, B, r) ^ A

let,    public key => {C,B2,A2,r},
        private key => {C2,B,A,r}
then,   E = fscx_revolve(C, B2, r) ^ A2  ^ P,
        P == (D = fscx_revolve(C2, B, r) ^ A ^ E)

let,    E = fscx_revolve(C2, B, r) ^ A  ^ P
then,   fscx_revolve(E, B2, i) ^ A2 ^ P  == 0  
        fscx_revolve(E ^ P, B2, i) == 0

HKEX (key exchange)
    Alice:  C = fscx_revolve(A,B,i)
            send C to Bob and get C2
            shared_key = fscx_revolve(C2, B, r) ^ A,
    Bob:    C2 = fscx_revolve(A2,B2,i)
            send C2 to Alice and get C
            shared_key => fscx_revolve(C, B2, r) ^ A2

HSKE (symmetric key encryption):
    Alice,Bob:  share key of bitlength b
    Alice:  E = fscx_revolve(P , key , i)
            shares E with Bob 
    Bob:    P = fscx_revolve(E , key , r)
        
HPKS (public key signature)
    Alice:  C = fscx_revolve(A,B,i)
            C2 = fscx_revolve(A2,B2,i)
            {publish (C,B2,A2,r) as public key, also disclose b,r,i; keep the rest of parameters (C2,B,A) as private key},
            S = fscx_revolve(C2, B, r) ^ A ^ P
            shares E, S with Bob
    Bob:    P = fscx_revolve(C,B2, r) ^ A2  ^ S

HPKE (public key encryption)
    Alice:  C = fscx_revolve(A,B,i),
            C2 = fscx_revolve(A2,B2,i),
            {publish (C,B2,A2,r) as public key, keep the rest of parameters as private key},
    Bob:    E = fscx_revolve(C, B2, r) ^ A2  ^ P
            shares E with Alice
    Alice:  P = fscx_revolve(C2, B, r) ^ A ^ E             
'''
# Examples with b = 256 bits:
r_value = 192  # Adjust as needed
i_value = 64   # Adjust as needed

A = new_rand_bitarray(256)
print(f"A         : {A.hex}")
B = new_rand_bitarray(256)
print(f"B         : {B.hex}")
A2 = new_rand_bitarray(256)
print(f"A2        : {A2.hex}")
B2 = new_rand_bitarray(256)
print(f"B2        : {B2.hex}")
C = fscx_revolve(A, B, i_value)
print(f"C         : {C.hex}")
C2 = fscx_revolve(A2, B2, i_value)
print(f"C2        : {C2.hex}")
nonce = new_rand_bitarray(256)
print(f"nonce     : {nonce.hex}")
preshared = new_rand_bitarray(256)
print(f"preshared : {preshared.hex}")
plaintext = new_rand_bitarray(256)
print(f"plaintext : {plaintext.hex}")

print (f"\n--- HKEX (key exchange)")
skeyA = fscx_revolve(C2 , B, r_value) ^ A
print(f"skeyA (Alice): {skeyA.hex}")
skeyB = fscx_revolve(C , B2, r_value) ^ A2
print(f"skeyB (Bob)  : {skeyB.hex}")
if skeyA == skeyB: # Assert equality
    print("+ session keys skeyA and skeyB are equal!")
else:
    print("- session keys skeyA and skeyB are different!")

print ("\n--- HSKE (symmetric key encryption)")
E = fscx_revolve(plaintext,  preshared , i_value)  
print(f"E (Alice) : {E.hex}")
D = fscx_revolve(E , preshared , r_value)
print(f"D (Bob)   : {D.hex}")
if D == plaintext: # Assert equality
    print("+ plaintext is correctly decrypted from E with preshared key!")
else:
    print("- plaintext is different from decrypted E with preshared key!")

print ("\n--- HPKS (public key signature)")
S = fscx_revolve(C2 , B, r_value) ^ A  ^ plaintext
print(f"S (Alice) : {S.hex}")
V = fscx_revolve(C, B2, r_value) ^ A2 ^ S  
print(f"V (Bob)   : {V.hex}")
if V == plaintext: # Assert equality
    print("+ signature S from plaintext is correct!")
else:
    print("- signature S from plaintext is incorrect!")

print ("\n--- HPKS (public key signature) + HSKE (symmetric key encryption) with preshared key made public")
E = fscx_revolve(plaintext, preshared, i_value)
print(f"E (Alice) : {E.hex}")
S = fscx_revolve(C2 , B, r_value) ^ A  ^ E # A+B2+C is the trapdoor for deceiving EVE!!!!
print(f"S (Alice) : {S.hex}")
V = fscx_revolve(C, B2, r_value) ^ A2 ^ S   # => E
print(f"V (Bob)   : {V.hex}")
D = fscx_revolve(V, preshared, r_value)  # => plainText
print(f"D (Bob)   : {D.hex}")
if D == plaintext: # Assert equality
    print("+ signature S(E) from plaintext is correct!")
else:
    print("- signature S(E) from plaintext is incorrect!")

print ("\n--- HPKE (public key encryption)")
E = fscx_revolve(C, B2, r_value) ^ A2 ^ plaintext
print(f"E (Bob)   : {E.hex}")
D = fscx_revolve(C2 , B, r_value)  ^ A ^ E  # => plaintext
print(f"D (Alice) : {D.hex}")
if D == plaintext: # Assert equality
    print("+ plaintext is correctly decrypted from E with private key!")
else:
    print("- plaintext is different from decrypted E with private key!")

print (f"\n\n*** EVE bypass TESTS")
print (f"\n*** HPKS (public key signature)")
S = fscx_revolve(C, B2, r_value) ^ nonce  # ^ bruteForceValue  ## w/o A+B+C2 Eve would be forced to do a Brute force attack to find it.
print(f"S (Eve)   : {S.hex}")
V = fscx_revolve(C, B2, r_value) ^ A2  # X
print(f"V (Bob)   : {V.hex}")
if V == nonce: # Assert equality
    print("+ nonce fake signature 1 verification with Alice public key is correct!")
else:
    print("- nonce fake signature 1 verification with Alice public key is incorrect!")
S2 = V ^ nonce
print(f"S2 (Eve)  : {S2.hex}")
V2 = fscx_revolve(C, B2, r_value) ^ A2 ^ S2 # KK
print(f"V2 (Bob)  : {V2.hex}")
if V2 == nonce: # Assert equality
    print("+ nonce fake signature 2 verification with Alice public key is correct!")
else:
    print("- nonce fake signature 2 verification with Alice public key is incorrect!")

print (f"\n*** HPKS (public key signature) + HSKE (symmetric key encryption) with preshared key made public")
E = fscx_revolve(nonce, preshared, i_value)
print(f"E (Eve)   : {E.hex}")
S = fscx_revolve(C, B2, r_value) ^ A2 ^ E  # ^ bruteForceValue  ## w/o A+B2+C  Eve would be forced to do a Brute force attack to find it.
print(f"S (Eve)   : {S.hex}")
V = fscx_revolve(C, B2, r_value) ^ A2 #X
print(f"V (Eve)   : {V.hex}")
S2 = V ^ S
print(f"S2 (Eve)  : {S2.hex}")
V2 = fscx_revolve(C, B2, r_value) ^ A2 ^ S2 # KK
print(f"V2 (Bob)  : {V2.hex}")
D = fscx_revolve(V2, preshared, r_value)
print(f"D (Bob)   : {D.hex}") #X
if D == nonce: # Assert equality
    print("+ fake signature(encrypted nonce) verification with Alice public key is correct!")
else:
    print("- fake signature(encrypted nonce) verification with Alice public key is incorrect!")

print (f"\n*** HPKS (public key signature) + HSKE (symmetric key encryption) with preshared key made public - v2")
S = fscx_revolve(C, B2, r_value) ^ A2 ^ nonce  # ^ bruteForceValue  ## w/o A+B2+C  Eve would be forced to do a Brute force attack to find it.
print(f"S (Eve)   : {S.hex}")
E = fscx_revolve(S, preshared, i_value)
print(f"E (Eve)   : {E.hex}")
V = fscx_revolve(C, B2, r_value) ^ A2 #X
print(f"V (Eve)   : {V.hex}")
S2 = V ^ E
print(f"S2 (Eve)  : {S2.hex}")
V2 = fscx_revolve(C, B2, r_value) ^ A2 ^ S2 # KK
print(f"V2 (Bob)  : {V2.hex}")
D = fscx_revolve(V2, preshared, r_value)
print(f"D (Bob)   : {D.hex}") #X
if D == nonce: # Assert equality
    print("+ fake signature(encrypted nonce) v2 verification with Alice public key is correct!")
else:
    print("- fake signature(encrypted nonce) v2 verification with Alice public key is incorrect!")

print (f"\n*** HPKE (public key encryption)")
E = fscx_revolve(C, B2, r_value) ^ A2 ^ plaintext  # ^ bruteForceValue  ## w/o A+B2+C  Eve would be forced to do a Brute force attack to find it.
print(f"E (Bob)   : {E.hex}")
D = fscx_revolve(C, B2, r_value) ^ A2 #X, but == fsession from private/public key generation if components had been reused from an HKEX!?
print(f"D (Eve)   : {D.hex}")
E2 = D ^ E
D2 = fscx_revolve(C, B2, r_value) ^ E2 # KK
print(f"D2 (Eve)  : {D2.hex}")
if (D == nonce) or (D2 == nonce): # Assert equality
    print("+ Eve could decrypt plaintext without Alice's private key!")
else:
    print("- Eve could not decrypt plaintext without Alice's private key!")