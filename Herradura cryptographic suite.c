/*  Herradura Cryptographic Suite v1.1

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

#define INTSZ    64
#define I_VALUE  16   /* INTSZ / 4 */
#define R_VALUE  48   /* 3 * INTSZ / 4 */

typedef uint64_t u64;

/* Read exactly 8 bytes from /dev/urandom */
static u64 rand64(FILE *urnd)
{
	uint8_t buf[8];
	if (fread(buf, 1, 8, urnd) != 8) {
		fputs("ERROR: could not read from /dev/urandom\n", stderr);
		exit(1);
	}
	return ((u64)buf[0] << 56) | ((u64)buf[1] << 48) |
	       ((u64)buf[2] << 40) | ((u64)buf[3] << 32) |
	       ((u64)buf[4] << 24) | ((u64)buf[5] << 16) |
	       ((u64)buf[6] <<  8) | ((u64)buf[7]);
}

/* Rotate left */
static u64 rol64(u64 x, int n)
{
	n &= 63;
	if (n == 0) return x;
	return (x << n) | (x >> (64 - n));
}

/* Rotate right */
static u64 ror64(u64 x, int n)
{
	n &= 63;
	if (n == 0) return x;
	return (x >> n) | (x << (64 - n));
}

/* Full Surroundings Cyclic XOR (rotation-based, 64-bit) */
static u64 fscx(u64 a, u64 b)
{
	u64 result;
	result  = a ^ b;
	result ^= rol64(a, 1) ^ rol64(b, 1);
	result ^= ror64(a, 1) ^ ror64(b, 1);
	return result;
}

/* FSCX_REVOLVE: iterate fscx n times */
static u64 fscx_revolve(u64 a, u64 b, int steps)
{
	int i;
	for (i = 0; i < steps; i++)
		a = fscx(a, b);
	return a;
}

/* FSCX_REVOLVE_N (v1.1): nonce-augmented iteration */
static u64 fscx_revolve_n(u64 a, u64 b, u64 nonce, int steps)
{
	int i;
	for (i = 0; i < steps; i++)
		a = fscx(a, b) ^ nonce;
	return a;
}

int main(void)
{
	FILE *urnd;
	u64 A, B, A2, B2, C, C2, hkex_nonce;
	u64 nonce, preshared, plaintext;
	u64 skeyA, skeyB;
	u64 E, D, S, V, S2, V2, D2, E2;

	urnd = fopen("/dev/urandom", "rb");
	if (!urnd) {
		fputs("ERROR: cannot open /dev/urandom\n", stderr);
		return 1;
	}

	A         = rand64(urnd);
	B         = rand64(urnd);
	A2        = rand64(urnd);
	B2        = rand64(urnd);
	nonce     = rand64(urnd);
	preshared = rand64(urnd);
	plaintext = rand64(urnd);

	C  = fscx_revolve(A,  B,  I_VALUE);
	C2 = fscx_revolve(A2, B2, I_VALUE);
	hkex_nonce = C ^ C2;

	printf("A         : %016llx\n", (unsigned long long)A);
	printf("B         : %016llx\n", (unsigned long long)B);
	printf("A2        : %016llx\n", (unsigned long long)A2);
	printf("B2        : %016llx\n", (unsigned long long)B2);
	printf("preshared : %016llx\n", (unsigned long long)preshared);
	printf("plaintext : %016llx\n", (unsigned long long)plaintext);
	printf("nonce     : %016llx\n", (unsigned long long)nonce);
	printf("C         : %016llx\n", (unsigned long long)C);
	printf("C2        : %016llx\n", (unsigned long long)C2);
	printf("hkex_nonce: %016llx\n", (unsigned long long)hkex_nonce);

	/* --- HKEX (key exchange) --- */
	printf("\n--- HKEX (key exchange)\n");
	skeyA = fscx_revolve_n(C2, B,  hkex_nonce, R_VALUE) ^ A;
	printf("skeyA (Alice): %016llx\n", (unsigned long long)skeyA);
	skeyB = fscx_revolve_n(C,  B2, hkex_nonce, R_VALUE) ^ A2;
	printf("skeyB (Bob)  : %016llx\n", (unsigned long long)skeyB);
	if (skeyA == skeyB)
		puts("+ session keys skeyA and skeyB are equal!");
	else
		puts("- session keys skeyA and skeyB are different!");

	/* --- HSKE (symmetric key encryption) --- */
	printf("\n--- HSKE (symmetric key encryption)\n");
	E = fscx_revolve_n(plaintext, preshared, preshared, I_VALUE);
	printf("E (Alice) : %016llx\n", (unsigned long long)E);
	D = fscx_revolve_n(E, preshared, preshared, R_VALUE);
	printf("D (Bob)   : %016llx\n", (unsigned long long)D);
	if (D == plaintext)
		puts("+ plaintext is correctly decrypted from E with preshared key");
	else
		puts("- plaintext is different from decrypted E with preshared key!");

	/* --- HPKS (public key signature) --- */
	printf("\n--- HPKS (public key signature)\n");
	S = fscx_revolve_n(C2, B, hkex_nonce, R_VALUE) ^ A ^ plaintext;
	printf("S (Alice) : %016llx\n", (unsigned long long)S);
	V = fscx_revolve_n(C, B2, hkex_nonce, R_VALUE) ^ A2 ^ S;
	printf("V (Bob)   : %016llx\n", (unsigned long long)V);
	if (V == plaintext)
		puts("+ signature S from plaintext is correct!");
	else
		puts("- signature S from plaintext is incorrect!");

	/* --- HPKS + HSKE with preshared key made public --- */
	printf("\n--- HPKS (public key signature) + HSKE (symmetric key encryption) with preshared key made public\n");
	E = fscx_revolve_n(plaintext, preshared, preshared, I_VALUE);
	printf("E (Alice) : %016llx\n", (unsigned long long)E);
	S = fscx_revolve_n(C2, B, hkex_nonce, R_VALUE) ^ A ^ E; /* A+B2+C is the trapdoor */
	printf("S (Alice) : %016llx\n", (unsigned long long)S);
	V = fscx_revolve_n(C, B2, hkex_nonce, R_VALUE) ^ A2 ^ S; /* => E */
	printf("V (Bob)   : %016llx\n", (unsigned long long)V);
	D = fscx_revolve_n(V, preshared, preshared, R_VALUE); /* => plaintext */
	printf("D (Bob)   : %016llx\n", (unsigned long long)D);
	if (D == plaintext)
		puts("+ signature S(E) from plaintext is correct!");
	else
		puts("- signature S(E) from plaintext is incorrect!");

	/* --- HPKE (public key encryption) --- */
	printf("\n--- HPKE (public key encryption)\n");
	E = fscx_revolve_n(C, B2, hkex_nonce, R_VALUE) ^ A2 ^ plaintext;
	printf("E (Bob)   : %016llx\n", (unsigned long long)E);
	D = fscx_revolve_n(C2, B, hkex_nonce, R_VALUE) ^ A ^ E; /* => plaintext */
	printf("D (Alice) : %016llx\n", (unsigned long long)D);
	if (D == plaintext)
		puts("+ plaintext is correctly decrypted from E with private key!");
	else
		puts("- plaintext is different from decrypted E with private key!");

	/* *** EVE bypass TESTS *** */
	printf("\n\n*** EVE bypass TESTS\n");

	/* EVE HPKS */
	printf("\n*** HPKS (public key signature)\n");
	S = fscx_revolve_n(C, B2, hkex_nonce, R_VALUE) ^ nonce;
	printf("S (Eve)   : %016llx\n", (unsigned long long)S);
	V = fscx_revolve_n(C, B2, hkex_nonce, R_VALUE) ^ A2; /* X */
	printf("V (Bob)   : %016llx\n", (unsigned long long)V);
	if (V == nonce)
		puts("+ nonce fake signature 1 verification with Alice public key is correct!");
	else
		puts("- nonce fake signature 1 verification with Alice public key is incorrect!");
	S2 = V ^ nonce;
	printf("S2 (Eve)  : %016llx\n", (unsigned long long)S2);
	V2 = fscx_revolve_n(C, B2, hkex_nonce, R_VALUE) ^ A2 ^ S2; /* KK */
	printf("V2 (Bob)  : %016llx\n", (unsigned long long)V2);
	if (V2 == nonce)
		puts("+ nonce fake signature 2 verification with Alice public key is correct!");
	else
		puts("- nonce fake signature 2 verification with Alice public key is incorrect!");

	/* EVE HPKS + HSKE with preshared made public */
	printf("\n*** HPKS (public key signature) + HSKE (symmetric key encryption) with preshared key made public\n");
	E = fscx_revolve_n(nonce, preshared, preshared, I_VALUE);
	printf("E (Eve)   : %016llx\n", (unsigned long long)E);
	S = fscx_revolve_n(C, B2, hkex_nonce, R_VALUE) ^ A2 ^ E;
	printf("S (Eve)   : %016llx\n", (unsigned long long)S);
	V = fscx_revolve_n(C, B2, hkex_nonce, R_VALUE) ^ A2; /* X */
	printf("V (Eve)   : %016llx\n", (unsigned long long)V);
	S2 = V ^ S;
	printf("S2 (Eve)  : %016llx\n", (unsigned long long)S2);
	V2 = fscx_revolve_n(C, B2, hkex_nonce, R_VALUE) ^ A2 ^ S2; /* KK */
	printf("V2 (Bob)  : %016llx\n", (unsigned long long)V2);
	D = fscx_revolve_n(V2, preshared, preshared, R_VALUE);
	printf("D (Bob)   : %016llx\n", (unsigned long long)D); /* X */
	if (D == nonce)
		puts("+ fake signature(encrypted nonce) verification with Alice public key is correct!");
	else
		puts("- fake signature(encrypted nonce) verification with Alice public key is incorrect!");

	/* EVE HPKS + HSKE with preshared made public - v2 */
	printf("\n*** HPKS (public key signature) + HSKE (symmetric key encryption) with preshared key made public - v2\n");
	S = fscx_revolve_n(C, B2, hkex_nonce, R_VALUE) ^ A2 ^ nonce;
	printf("S (Eve)   : %016llx\n", (unsigned long long)S);
	E = fscx_revolve_n(S, preshared, preshared, I_VALUE);
	printf("E (Eve)   : %016llx\n", (unsigned long long)E);
	V = fscx_revolve_n(C, B2, hkex_nonce, R_VALUE) ^ A2; /* X */
	printf("V (Eve)   : %016llx\n", (unsigned long long)V);
	S2 = V ^ E;
	printf("S2 (Eve)  : %016llx\n", (unsigned long long)S2);
	V2 = fscx_revolve_n(C, B2, hkex_nonce, R_VALUE) ^ A2 ^ S2; /* KK */
	printf("V2 (Bob)  : %016llx\n", (unsigned long long)V2);
	D = fscx_revolve_n(V2, preshared, preshared, R_VALUE);
	printf("D (Bob)   : %016llx\n", (unsigned long long)D); /* X */
	if (D == nonce)
		puts("+ fake signature(encrypted nonce) v2 verification with Alice public key is correct!");
	else
		puts("- fake signature(encrypted nonce) v2 verification with Alice public key is incorrect!");

	/* EVE HPKE */
	printf("\n*** HPKE (public key encryption)\n");
	E = fscx_revolve_n(C, B2, hkex_nonce, R_VALUE) ^ A2 ^ plaintext;
	printf("E (Bob)   : %016llx\n", (unsigned long long)E);
	D = fscx_revolve_n(C, B2, hkex_nonce, R_VALUE) ^ A2; /* X */
	printf("D (Eve)   : %016llx\n", (unsigned long long)D);
	E2 = D ^ E;
	D2 = fscx_revolve_n(C, B2, hkex_nonce, R_VALUE) ^ E2; /* KK */
	printf("D2 (Eve)  : %016llx\n", (unsigned long long)D2);
	if ((D == nonce) || (D2 == nonce))
		puts("+ Eve could decrypt plaintext without Alice's private key!");
	else
		puts("- Eve could not decrypt plaintext without Alice's private key!");

	fclose(urnd);
	return 0;
}
