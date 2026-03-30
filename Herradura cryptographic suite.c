/*  Herradura Cryptographic Suite v1.3.2

    Copyright (C) 2024-2026 Omar Alejandro Herrera Reyna

    This program is free software: you can redistribute it and/or modify
    it under the terms of the MIT License or the GNU General Public License
    as published by the Free Software Foundation, either version 3 of the License,
    or (at your option) any later version.

    Under the terms of the GNU General Public License, please also consider that:

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.

    --- v1.3.2: performance and readability ---

    - ba_fscx: fused into a single-pass loop.  Eliminates 4 temporary BitArray
      allocations and reduces 5 separate memory passes to 1.
    - ba_fscx_revolve / ba_fscx_revolve_n: double-buffered with index swap;
      eliminates one full BitArray copy per iteration step.
    - ba_rol1 / ba_ror1: removed from the public API; their logic is now
      inlined inside ba_fscx.
    - ba_xor_into: removed; replaced by ba_xor(dst, dst, src) at every call
      site (aliasing dst == a is safe in ba_xor).
    - Version header updated; build comment moved to a single line.

    --- v1.3: BitArray (multi-byte parameter support) ---

    The C implementation uses a BitArray type: a fixed-width bit string backed
    by a big-endian byte array, matching the Python and Go versions.
    Default key size is 256 bits (I_VALUE = 64, R_VALUE = 192).

    BitArray supports:
      - XOR (ba_xor — aliasing-safe)
      - Equality comparison (ba_equal)
      - Hex printing (ba_print_hex)
      - Secure random fill from /dev/urandom (ba_rand)

    The key size is controlled by KEYBITS (must be a positive multiple of 8
    and >= 16 for the single-pass ba_fscx implementation).
    Change the #define to use a different bit width; all parameters and step
    counts scale automatically.

    --- v1.1: FSCX_REVOLVE_N ---

    v1.1 introduces FSCX_REVOLVE_N: a nonce-augmented variant of FSCX_REVOLVE
    where each iteration XORs a nonce N after the FSCX step:
        result = FSCX(result, B) XOR N

    This converts the purely linear GF(2) function to affine, breaking linearity
    while preserving the HKEX equality and orbit properties.

    Nonce derivation (no new secrets):
    - For HKEX, HPKS, HPKE: hkex_nonce = C XOR C2  -- computable from the public key
      (C is in the public key; C2 = fscx_revolve(A2, B2, i) can be computed from
      A2, B2 also in the public key)
    - For HSKE: N = preshared key -- the key is injected at every revolve step,
      not just at input/output boundaries

    Mathematical proof that HKEX equality is preserved:
    The HKEX equality
        FSCX_REVOLVE_N(C2, B, N, r) XOR A = FSCX_REVOLVE_N(C, B2, N, r) XOR A2
    holds because when you expand with C = FSCX_REVOLVE(A, B, i) and
    C2 = FSCX_REVOLVE(A2, B2, i), and use L^(r+i) = I (since r+i=P), the
    condition reduces to L^r(T_i(Z)) = T_r(Z) -- the same condition as without
    the nonce. N cancels identically from both sides.
*/

/* Build: gcc -O2 -o "Herradura cryptographic suite" "Herradura cryptographic suite.c" */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* Key size in bits -- must be a positive multiple of 8 and >= 16.
   Change this to use a different parameter width; I_VALUE and R_VALUE scale
   automatically. Equivalent to 256-bit parameters in the Go and Python versions. */
#define KEYBITS  256
#define KEYBYTES (KEYBITS / 8)
#define I_VALUE  (KEYBITS / 4)       /* 64  for 256-bit */
#define R_VALUE  (3 * KEYBITS / 4)   /* 192 for 256-bit */

#if KEYBYTES < 2
#  error "KEYBITS must be >= 16 for the single-pass ba_fscx implementation"
#endif

/* Fixed-width bit array backed by a big-endian byte array.
   b[0] holds the most-significant byte; size is always KEYBYTES. */
typedef struct {
    uint8_t b[KEYBYTES];
} BitArray;

/* Fill dst with KEYBYTES random bytes from /dev/urandom. */
static void ba_rand(BitArray *dst, FILE *urnd)
{
    if (fread(dst->b, 1, KEYBYTES, urnd) != (size_t)KEYBYTES) {
        fputs("ERROR: could not read from /dev/urandom\n", stderr);
        exit(1);
    }
}

/* dst = a XOR b.  Aliasing dst == a or dst == b is safe. */
static void ba_xor(BitArray *dst, const BitArray *a, const BitArray *b)
{
    int i;
    for (i = 0; i < KEYBYTES; i++)
        dst->b[i] = a->b[i] ^ b->b[i];
}

/* Returns 1 if a == b, 0 otherwise. */
static int ba_equal(const BitArray *a, const BitArray *b)
{
    return memcmp(a->b, b->b, KEYBYTES) == 0;
}

/* Print label + hex representation of a + newline. */
static void ba_print_hex(const char *label, const BitArray *a)
{
    int i;
    printf("%s", label);
    for (i = 0; i < KEYBYTES; i++)
        printf("%02x", a->b[i]);
    putchar('\n');
}

/* Full Surroundings Cyclic XOR:
   result = a XOR b XOR ROL(a) XOR ROL(b) XOR ROR(a) XOR ROR(b)

   Fused single-pass implementation: ROL and ROR are computed inline from
   adjacent bytes, avoiding 4 temporary BitArray allocations and 5 separate
   memory passes.  Requires KEYBYTES >= 2. */
static void ba_fscx(BitArray *result, const BitArray *a, const BitArray *b)
{
    /* Wrap-around bits extracted before the loop */
    uint8_t a_msbit = a->b[0] >> 7;
    uint8_t b_msbit = b->b[0] >> 7;
    uint8_t a_lsbit = a->b[KEYBYTES - 1] & 1;
    uint8_t b_lsbit = b->b[KEYBYTES - 1] & 1;
    int i;

    /* byte 0: ROR wraps in from the last byte */
    result->b[0] = a->b[0] ^ b->b[0]
        ^ (uint8_t)((a->b[0] << 1) | (a->b[1] >> 7))   /* ROL(a)[0] */
        ^ (uint8_t)((b->b[0] << 1) | (b->b[1] >> 7))   /* ROL(b)[0] */
        ^ (uint8_t)((a->b[0] >> 1) | (a_lsbit << 7))   /* ROR(a)[0] */
        ^ (uint8_t)((b->b[0] >> 1) | (b_lsbit << 7));  /* ROR(b)[0] */

    /* middle bytes: no wrap-around */
    for (i = 1; i < KEYBYTES - 1; i++)
        result->b[i] = a->b[i] ^ b->b[i]
            ^ (uint8_t)((a->b[i] << 1) | (a->b[i + 1] >> 7))
            ^ (uint8_t)((b->b[i] << 1) | (b->b[i + 1] >> 7))
            ^ (uint8_t)((a->b[i] >> 1) | (a->b[i - 1] << 7))
            ^ (uint8_t)((b->b[i] >> 1) | (b->b[i - 1] << 7));

    /* last byte: ROL wraps in from the first byte */
    result->b[KEYBYTES - 1] = a->b[KEYBYTES-1] ^ b->b[KEYBYTES-1]
        ^ (uint8_t)((a->b[KEYBYTES-1] << 1) | a_msbit)
        ^ (uint8_t)((b->b[KEYBYTES-1] << 1) | b_msbit)
        ^ (uint8_t)((a->b[KEYBYTES-1] >> 1) | (a->b[KEYBYTES-2] << 7))
        ^ (uint8_t)((b->b[KEYBYTES-1] >> 1) | (b->b[KEYBYTES-2] << 7));
}

/* FSCX_REVOLVE: iterate fscx(a, b) n times keeping b constant.
   Double-buffered: alternates between two local buffers to avoid
   copying the result back every step. */
static void ba_fscx_revolve(BitArray *result, const BitArray *a,
                             const BitArray *b, int steps)
{
    BitArray buf[2];
    int idx = 0, i;
    buf[0] = *a;
    for (i = 0; i < steps; i++) {
        ba_fscx(&buf[1 - idx], &buf[idx], b);
        idx ^= 1;
    }
    *result = buf[idx];
}

/* FSCX_REVOLVE_N (v1.1): nonce-augmented iteration.
   Each step: result = FSCX(result, b) XOR nonce */
static void ba_fscx_revolve_n(BitArray *result, const BitArray *a,
                               const BitArray *b, const BitArray *nonce,
                               int steps)
{
    BitArray buf[2];
    int idx = 0, i;
    buf[0] = *a;
    for (i = 0; i < steps; i++) {
        ba_fscx(&buf[1 - idx], &buf[idx], b);
        ba_xor(&buf[1 - idx], &buf[1 - idx], nonce);
        idx ^= 1;
    }
    *result = buf[idx];
}

/*
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
        fscx_revolve(C2, B, R) ^ A ^ A2 ^ P == fscx_revolve(C, B2, r)  ^ P  #Note that this form breaks trapdoor
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
*/

int main(void)
{
    FILE *urnd;
    BitArray A, B, A2, B2, C, C2, hkex_nonce;
    BitArray nonce, preshared, plaintext;
    BitArray skeyA, skeyB;
    BitArray E, D, S, V, S2, V2, D2, E2;
    BitArray tmp;

    urnd = fopen("/dev/urandom", "rb");
    if (!urnd) {
        fputs("ERROR: cannot open /dev/urandom\n", stderr);
        return 1;
    }

    ba_rand(&A,         urnd);
    ba_rand(&B,         urnd);
    ba_rand(&A2,        urnd);
    ba_rand(&B2,        urnd);
    ba_rand(&nonce,     urnd);
    ba_rand(&preshared, urnd);
    ba_rand(&plaintext, urnd);

    ba_fscx_revolve(&C,  &A,  &B,  I_VALUE);
    ba_fscx_revolve(&C2, &A2, &B2, I_VALUE);
    ba_xor(&hkex_nonce, &C, &C2);

    ba_print_hex("A         : ", &A);
    ba_print_hex("B         : ", &B);
    ba_print_hex("A2        : ", &A2);
    ba_print_hex("B2        : ", &B2);
    ba_print_hex("preshared : ", &preshared);
    ba_print_hex("plaintext : ", &plaintext);
    ba_print_hex("nonce     : ", &nonce);
    ba_print_hex("C         : ", &C);
    ba_print_hex("C2        : ", &C2);
    ba_print_hex("hkex_nonce: ", &hkex_nonce);

    /* --- HKEX (key exchange) --- */
    printf("\n--- HKEX (key exchange)\n");
    ba_fscx_revolve_n(&tmp, &C2, &B,  &hkex_nonce, R_VALUE);
    ba_xor(&skeyA, &tmp, &A);
    ba_print_hex("skeyA (Alice): ", &skeyA);
    ba_fscx_revolve_n(&tmp, &C,  &B2, &hkex_nonce, R_VALUE);
    ba_xor(&skeyB, &tmp, &A2);
    ba_print_hex("skeyB (Bob)  : ", &skeyB);
    if (ba_equal(&skeyA, &skeyB))
        puts("+ session keys skeyA and skeyB are equal!");
    else
        puts("- session keys skeyA and skeyB are different!");

    /* --- HSKE (symmetric key encryption) --- */
    printf("\n--- HSKE (symmetric key encryption)\n");
    ba_fscx_revolve_n(&E, &plaintext, &preshared, &preshared, I_VALUE);
    ba_print_hex("E (Alice) : ", &E);
    ba_fscx_revolve_n(&D, &E, &preshared, &preshared, R_VALUE);
    ba_print_hex("D (Bob)   : ", &D);
    if (ba_equal(&D, &plaintext))
        puts("+ plaintext is correctly decrypted from E with preshared key");
    else
        puts("- plaintext is different from decrypted E with preshared key!");

    /* --- HPKS (public key signature) --- */
    printf("\n--- HPKS (public key signature)\n");
    ba_fscx_revolve_n(&tmp, &C2, &B, &hkex_nonce, R_VALUE);
    ba_xor(&S, &tmp, &A);
    ba_xor(&S, &S, &plaintext);
    ba_print_hex("S (Alice) : ", &S);
    ba_fscx_revolve_n(&tmp, &C, &B2, &hkex_nonce, R_VALUE);
    ba_xor(&V, &tmp, &A2);
    ba_xor(&V, &V, &S);
    ba_print_hex("V (Bob)   : ", &V);
    if (ba_equal(&V, &plaintext))
        puts("+ signature S from plaintext is correct!");
    else
        puts("- signature S from plaintext is incorrect!");

    /* --- HPKS + HSKE with preshared key made public --- */
    printf("\n--- HPKS (public key signature) + HSKE (symmetric key encryption) with preshared key made public\n");
    ba_fscx_revolve_n(&E, &plaintext, &preshared, &preshared, I_VALUE);
    ba_print_hex("E (Alice) : ", &E);
    ba_fscx_revolve_n(&tmp, &C2, &B, &hkex_nonce, R_VALUE);
    ba_xor(&S, &tmp, &A);
    ba_xor(&S, &S, &E);   /* A+B2+C is the trapdoor */
    ba_print_hex("S (Alice) : ", &S);
    ba_fscx_revolve_n(&tmp, &C, &B2, &hkex_nonce, R_VALUE);
    ba_xor(&V, &tmp, &A2);
    ba_xor(&V, &V, &S);   /* => E */
    ba_print_hex("V (Bob)   : ", &V);
    ba_fscx_revolve_n(&D, &V, &preshared, &preshared, R_VALUE);   /* => plaintext */
    ba_print_hex("D (Bob)   : ", &D);
    if (ba_equal(&D, &plaintext))
        puts("+ signature S(E) from plaintext is correct!");
    else
        puts("- signature S(E) from plaintext is incorrect!");

    /* --- HPKE (public key encryption) --- */
    printf("\n--- HPKE (public key encryption)\n");
    ba_fscx_revolve_n(&tmp, &C, &B2, &hkex_nonce, R_VALUE);
    ba_xor(&E, &tmp, &A2);
    ba_xor(&E, &E, &plaintext);
    ba_print_hex("E (Bob)   : ", &E);
    ba_fscx_revolve_n(&tmp, &C2, &B, &hkex_nonce, R_VALUE);
    ba_xor(&D, &tmp, &A);
    ba_xor(&D, &D, &E);   /* => plaintext */
    ba_print_hex("D (Alice) : ", &D);
    if (ba_equal(&D, &plaintext))
        puts("+ plaintext is correctly decrypted from E with private key!");
    else
        puts("- plaintext is different from decrypted E with private key!");

    /* *** EVE bypass TESTS *** */
    printf("\n\n*** EVE bypass TESTS\n");

    /* EVE HPKS */
    printf("\n*** HPKS (public key signature)\n");
    ba_fscx_revolve_n(&tmp, &C, &B2, &hkex_nonce, R_VALUE);
    ba_xor(&S, &tmp, &nonce);
    ba_print_hex("S (Eve)   : ", &S);
    ba_fscx_revolve_n(&tmp, &C, &B2, &hkex_nonce, R_VALUE);
    ba_xor(&V, &tmp, &A2);   /* X */
    ba_print_hex("V (Bob)   : ", &V);
    if (ba_equal(&V, &nonce))
        puts("+ nonce fake signature 1 verification with Alice public key is correct!");
    else
        puts("- nonce fake signature 1 verification with Alice public key is incorrect!");
    ba_xor(&S2, &V, &nonce);
    ba_print_hex("S2 (Eve)  : ", &S2);
    ba_fscx_revolve_n(&tmp, &C, &B2, &hkex_nonce, R_VALUE);
    ba_xor(&V2, &tmp, &A2);
    ba_xor(&V2, &V2, &S2);   /* KK */
    ba_print_hex("V2 (Bob)  : ", &V2);
    if (ba_equal(&V2, &nonce))
        puts("+ nonce fake signature 2 verification with Alice public key is correct!");
    else
        puts("- nonce fake signature 2 verification with Alice public key is incorrect!");

    /* EVE HPKS + HSKE with preshared made public */
    printf("\n*** HPKS (public key signature) + HSKE (symmetric key encryption) with preshared key made public\n");
    ba_fscx_revolve_n(&E, &nonce, &preshared, &preshared, I_VALUE);
    ba_print_hex("E (Eve)   : ", &E);
    ba_fscx_revolve_n(&tmp, &C, &B2, &hkex_nonce, R_VALUE);
    ba_xor(&S, &tmp, &A2);
    ba_xor(&S, &S, &E);
    ba_print_hex("S (Eve)   : ", &S);
    ba_fscx_revolve_n(&tmp, &C, &B2, &hkex_nonce, R_VALUE);
    ba_xor(&V, &tmp, &A2);   /* X */
    ba_print_hex("V (Eve)   : ", &V);
    ba_xor(&S2, &V, &S);
    ba_print_hex("S2 (Eve)  : ", &S2);
    ba_fscx_revolve_n(&tmp, &C, &B2, &hkex_nonce, R_VALUE);
    ba_xor(&V2, &tmp, &A2);
    ba_xor(&V2, &V2, &S2);   /* KK */
    ba_print_hex("V2 (Bob)  : ", &V2);
    ba_fscx_revolve_n(&D, &V2, &preshared, &preshared, R_VALUE);
    ba_print_hex("D (Bob)   : ", &D);   /* X */
    if (ba_equal(&D, &nonce))
        puts("+ fake signature(encrypted nonce) verification with Alice public key is correct!");
    else
        puts("- fake signature(encrypted nonce) verification with Alice public key is incorrect!");

    /* EVE HPKS + HSKE with preshared made public - v2 */
    printf("\n*** HPKS (public key signature) + HSKE (symmetric key encryption) with preshared key made public - v2\n");
    ba_fscx_revolve_n(&tmp, &C, &B2, &hkex_nonce, R_VALUE);
    ba_xor(&S, &tmp, &A2);
    ba_xor(&S, &S, &nonce);
    ba_print_hex("S (Eve)   : ", &S);
    ba_fscx_revolve_n(&E, &S, &preshared, &preshared, I_VALUE);
    ba_print_hex("E (Eve)   : ", &E);
    ba_fscx_revolve_n(&tmp, &C, &B2, &hkex_nonce, R_VALUE);
    ba_xor(&V, &tmp, &A2);   /* X */
    ba_print_hex("V (Eve)   : ", &V);
    ba_xor(&S2, &V, &E);
    ba_print_hex("S2 (Eve)  : ", &S2);
    ba_fscx_revolve_n(&tmp, &C, &B2, &hkex_nonce, R_VALUE);
    ba_xor(&V2, &tmp, &A2);
    ba_xor(&V2, &V2, &S2);   /* KK */
    ba_print_hex("V2 (Bob)  : ", &V2);
    ba_fscx_revolve_n(&D, &V2, &preshared, &preshared, R_VALUE);
    ba_print_hex("D (Bob)   : ", &D);   /* X */
    if (ba_equal(&D, &nonce))
        puts("+ fake signature(encrypted nonce) v2 verification with Alice public key is correct!");
    else
        puts("- fake signature(encrypted nonce) v2 verification with Alice public key is incorrect!");

    /* EVE HPKE */
    printf("\n*** HPKE (public key encryption)\n");
    ba_fscx_revolve_n(&tmp, &C, &B2, &hkex_nonce, R_VALUE);
    ba_xor(&E, &tmp, &A2);
    ba_xor(&E, &E, &plaintext);
    ba_print_hex("E (Bob)   : ", &E);
    ba_fscx_revolve_n(&tmp, &C, &B2, &hkex_nonce, R_VALUE);
    ba_xor(&D, &tmp, &A2);   /* X */
    ba_print_hex("D (Eve)   : ", &D);
    ba_xor(&E2, &D, &E);
    ba_fscx_revolve_n(&tmp, &C, &B2, &hkex_nonce, R_VALUE);
    ba_xor(&D2, &tmp, &E2);   /* KK */
    ba_print_hex("D2 (Eve)  : ", &D2);
    if (ba_equal(&D, &nonce) || ba_equal(&D2, &nonce))
        puts("+ Eve could decrypt plaintext without Alice's private key!");
    else
        puts("- Eve could not decrypt plaintext without Alice's private key!");

    fclose(urnd);
    return 0;
}
