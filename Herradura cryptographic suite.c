/*  Herradura Cryptographic Suite v1.4.0

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

    --- v1.4.0: HKEX replaced with HKEX-GF (Diffie-Hellman over GF(2^n)*) ---

    The classical HKEX key exchange is BROKEN: sk = S_{r+1}*(C XOR C2) is a
    publicly computable linear formula (proved in SecurityProofs.md, Theorem 7).
    fscx_revolve_n offered no fix (nonce cancels identically, Theorem 10).

    HKEX-GF replaces HKEX with Diffie-Hellman over GF(2^KEYBITS)*:
      - Alice: private scalar a, public C  = g^a  (GF exponentiation)
      - Bob:   private scalar b, public C2 = g^b
      - Shared: sk = C2^a = C^b = g^{ab}  (field commutativity)
    Security: CDH/DLP in GF(2^n)*. For n=256, classical security ~128 bits
    under the best known index-calculus attacks.

    fscx_revolve_n is removed — it provided no security benefit.
    HSKE, HPKS, HPKE keep standard fscx_revolve unchanged.

    --- v1.3.2: performance and readability ---

    - ba_fscx: fused into a single-pass loop.
    - ba_fscx_revolve: double-buffered with index swap.
    - ba_rol1 / ba_ror1: inlined inside ba_fscx.
    - ba_xor_into: replaced by ba_xor(dst, dst, src).

    --- v1.3: BitArray (multi-byte parameter support) ---

    The C implementation uses a BitArray type: a fixed-width bit string backed
    by a big-endian byte array.  Default key size is 256 bits.

    The key size is controlled by KEYBITS (must be a positive multiple of 8
    and >= 16).  Change the #define to use a different bit width; all
    parameters and step counts scale automatically.
*/

/* Build: gcc -O2 -o "Herradura cryptographic suite" "Herradura cryptographic suite.c" */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* Key size in bits -- must be a positive multiple of 8 and >= 16.
   Change this to use a different parameter width; I_VALUE and R_VALUE scale
   automatically.  n=256 gives ~128-bit classical DLP security in GF(2^n)*. */
#define KEYBITS  256
#define KEYBYTES (KEYBITS / 8)
#define I_VALUE  (KEYBITS / 4)       /* 64  for 256-bit */
#define R_VALUE  (3 * KEYBITS / 4)   /* 192 for 256-bit */

#if KEYBYTES < 2
#  error "KEYBITS must be >= 16"
#endif
#if KEYBITS != 256
#  error "GF polynomial constants are only defined for KEYBITS=256 in this build"
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

   Fused single-pass implementation.  Requires KEYBYTES >= 2. */
static void ba_fscx(BitArray *result, const BitArray *a, const BitArray *b)
{
    uint8_t a_msbit = a->b[0] >> 7;
    uint8_t b_msbit = b->b[0] >> 7;
    uint8_t a_lsbit = a->b[KEYBYTES - 1] & 1;
    uint8_t b_lsbit = b->b[KEYBYTES - 1] & 1;
    int i;

    result->b[0] = a->b[0] ^ b->b[0]
        ^ (uint8_t)((a->b[0] << 1) | (a->b[1] >> 7))
        ^ (uint8_t)((b->b[0] << 1) | (b->b[1] >> 7))
        ^ (uint8_t)((a->b[0] >> 1) | (a_lsbit << 7))
        ^ (uint8_t)((b->b[0] >> 1) | (b_lsbit << 7));

    for (i = 1; i < KEYBYTES - 1; i++)
        result->b[i] = a->b[i] ^ b->b[i]
            ^ (uint8_t)((a->b[i] << 1) | (a->b[i + 1] >> 7))
            ^ (uint8_t)((b->b[i] << 1) | (b->b[i + 1] >> 7))
            ^ (uint8_t)((a->b[i] >> 1) | (a->b[i - 1] << 7))
            ^ (uint8_t)((b->b[i] >> 1) | (b->b[i - 1] << 7));

    result->b[KEYBYTES - 1] = a->b[KEYBYTES-1] ^ b->b[KEYBYTES-1]
        ^ (uint8_t)((a->b[KEYBYTES-1] << 1) | a_msbit)
        ^ (uint8_t)((b->b[KEYBYTES-1] << 1) | b_msbit)
        ^ (uint8_t)((a->b[KEYBYTES-1] >> 1) | (a->b[KEYBYTES-2] << 7))
        ^ (uint8_t)((b->b[KEYBYTES-1] >> 1) | (b->b[KEYBYTES-2] << 7));
}

/* FSCX_REVOLVE: iterate fscx(a, b) steps times keeping b constant.
   Double-buffered to avoid copying the result back every step. */
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

/* ─────────────────────────────────────────────────────────────────────────────
 * GF(2^KEYBITS) arithmetic — carryless polynomial multiplication mod p(x)
 *
 * Primitive polynomial for GF(2^256): p(x) = x^256 + x^10 + x^5 + x^2 + 1
 *   Lower 256 bits = x^10 + x^5 + x^2 + 1 = 0x0425
 *   Big-endian 32-byte repr: bytes 0..29 = 0x00, byte30 = 0x04, byte31 = 0x25
 *
 * Generator g = x+1 = 3.
 * ───────────────────────────────────────────────────────────────────────────── */

static const BitArray GF_POLY = {{
    0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,
    0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0x04,0x25
}};

static const BitArray GF_GEN = {{
    0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,
    0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0x03
}};

/* Returns 1 if a is the zero element. */
static int ba_is_zero(const BitArray *a)
{
    int i;
    for (i = 0; i < KEYBYTES; i++)
        if (a->b[i]) return 0;
    return 1;
}

/* Shift big-endian BitArray left by 1 bit.  Returns the MSB shifted out. */
static int ba_shl1(BitArray *a)
{
    int carry = (a->b[0] >> 7) & 1;
    int i;
    for (i = 0; i < KEYBYTES - 1; i++)
        a->b[i] = (uint8_t)((a->b[i] << 1) | (a->b[i + 1] >> 7));
    a->b[KEYBYTES - 1] <<= 1;
    return carry;
}

/* Shift big-endian BitArray right by 1 bit.  Returns the LSB shifted out. */
static int ba_shr1(BitArray *a)
{
    int carry = a->b[KEYBYTES - 1] & 1;
    int i;
    for (i = KEYBYTES - 1; i > 0; i--)
        a->b[i] = (uint8_t)((a->b[i] >> 1) | (a->b[i - 1] << 7));
    a->b[0] >>= 1;
    return carry;
}

/* GF(2^KEYBITS) multiplication: dst = a * b mod GF_POLY.
   Shift-and-XOR: O(KEYBITS) iterations, XOR and shift only. */
static void gf_mul_ba(BitArray *dst, const BitArray *a, const BitArray *b)
{
    BitArray r, aa, bb;
    int i;
    memset(r.b, 0, KEYBYTES);
    aa = *a;
    bb = *b;
    for (i = 0; i < KEYBITS; i++) {
        if (bb.b[KEYBYTES - 1] & 1)
            ba_xor(&r, &r, &aa);
        if (ba_shl1(&aa))
            ba_xor(&aa, &aa, &GF_POLY);
        ba_shr1(&bb);
    }
    *dst = r;
}

/* GF(2^KEYBITS) exponentiation: dst = base^exp mod GF_POLY.
   Binary repeated squaring: O(KEYBITS) multiplications. */
static void gf_pow_ba(BitArray *dst, const BitArray *base, const BitArray *exp)
{
    BitArray r, b, e;
    memset(r.b, 0, KEYBYTES);
    r.b[KEYBYTES - 1] = 1;   /* multiplicative identity: 1 */
    b = *base;
    e = *exp;
    while (!ba_is_zero(&e)) {
        if (e.b[KEYBYTES - 1] & 1)
            gf_mul_ba(&r, &r, &b);
        gf_mul_ba(&b, &b, &b);
        ba_shr1(&e);
    }
    *dst = r;
}

/* ─────────────────────────────────────────────────────────────────────────────
 * 32-bit GF(2^32) arithmetic and FSCX for HPKS Schnorr and HPKE El Gamal.
 *
 * Schnorr requires s = (k - a*e) mod ORD where ORD = 2^32-1.  Using 32-bit
 * parameters keeps this computable with a uint64_t intermediate for a*e.
 *
 * Primitive polynomial for GF(2^32): x^32+x^22+x^2+x+1 = 0x00400007
 * Generator g = 3.
 * ───────────────────────────────────────────────────────────────────────────── */

#define GF_POLY32  0x00400007UL
#define GF_GEN32   3UL
#define I_VALUE32  8             /* 32/4 */
#define R_VALUE32  24            /* 3*32/4 */

static uint32_t gf_mul_32(uint32_t a, uint32_t b)
{
    uint32_t r = 0;
    int i;
    for (i = 0; i < 32; i++) {
        if (b & 1) r ^= a;
        { uint32_t carry = a >> 31; a <<= 1; if (carry) a ^= (uint32_t)GF_POLY32; }
        b >>= 1;
    }
    return r;
}

static uint32_t gf_pow_32(uint32_t base, uint32_t exp)
{
    uint32_t r = 1;
    while (exp) {
        if (exp & 1) r = gf_mul_32(r, base);
        base = gf_mul_32(base, base);
        exp >>= 1;
    }
    return r;
}

static uint32_t rol32(uint32_t x) { return (x << 1) | (x >> 31); }
static uint32_t ror32(uint32_t x) { return (x >> 1) | (x << 31); }

static uint32_t fscx32(uint32_t a, uint32_t b)
{
    return a ^ b ^ rol32(a) ^ rol32(b) ^ ror32(a) ^ ror32(b);
}

static uint32_t fscx_revolve32(uint32_t a, uint32_t b, int steps)
{
    int i;
    for (i = 0; i < steps; i++) a = fscx32(a, b);
    return a;
}

static uint32_t rand32(FILE *urnd)
{
    uint32_t v;
    if (fread(&v, 4, 1, urnd) != 1) {
        fputs("ERROR: could not read from /dev/urandom\n", stderr);
        exit(1);
    }
    return v;
}

/*
HKEX-GF (key exchange — Diffie-Hellman over GF(2^n)*):
    Pre-agreed: irreducible polynomial p(x), generator g.
    Alice:  private a -> public C  = g^a
    Bob:    private b -> public C2 = g^b
    Shared: sk = C2^a = C^b = g^{ab}  (field multiplication is commutative)

HSKE (symmetric key encryption — FSCX-based, unchanged):
    share key of bitlength n
    Alice:  E = fscx_revolve(P, key, i)
    Bob:    P = fscx_revolve(E, key, r)  [i+r=n -> orbit closes]

HPKS (Schnorr public key signature, 32-bit GF params):
    Alice private: a,  public C = g^a,  ORD = 2^32-1
    Sign(P):  k random; R=g^k; e=fscx_revolve(R,P,i); s=(k-a*e) mod ORD
    Verify:   g^s * C^e == R

HPKE (El Gamal public key encryption, 32-bit GF params):
    Alice private: a,  public C = g^a
    Bob encrypts: r random; R=g^r; enc_key=C^r; E=fscx_revolve(P,enc_key,i)
    Alice decrypts: dec_key=R^a; D=fscx_revolve(E,dec_key,r) = P
*/

int main(void)
{
    FILE *urnd;
    BitArray a_priv, b_priv;          /* HKEX-GF private scalars */
    BitArray C, C2;                    /* public values: g^a, g^b */
    BitArray skeyA, skeyB;             /* shared session key */
    BitArray preshared, plaintext;
    BitArray E, D;

    /* 32-bit parameters for HPKS Schnorr and HPKE El Gamal */
    uint32_t a32, plain32, preshared32;
    uint32_t C32;                      /* Alice's public key g^a */
    uint32_t k32, R32, e32, s32;       /* Schnorr: nonce, R=g^k, challenge, response */
    uint32_t r32, R_hpke, enc_key32;   /* El Gamal: ephemeral, R=g^r, enc_key=C^r */
    uint32_t dec_key32, E32, D32;
    uint64_t ae64;
    uint64_t ord32 = 0xFFFFFFFFULL;

    urnd = fopen("/dev/urandom", "rb");
    if (!urnd) {
        fputs("ERROR: cannot open /dev/urandom\n", stderr);
        return 1;
    }

    ba_rand(&a_priv,    urnd);
    ba_rand(&b_priv,    urnd);
    ba_rand(&preshared, urnd);
    ba_rand(&plaintext, urnd);
    /* Ensure private scalars are odd (non-zero in GF(2^n)*) */
    a_priv.b[KEYBYTES - 1] |= 1;
    b_priv.b[KEYBYTES - 1] |= 1;

    /* 32-bit private scalars for Schnorr / El Gamal */
    a32          = rand32(urnd) | 1;
    plain32      = rand32(urnd);
    preshared32  = rand32(urnd);
    C32          = gf_pow_32((uint32_t)GF_GEN32, a32);

    ba_print_hex("a_priv    : ", &a_priv);
    ba_print_hex("b_priv    : ", &b_priv);
    ba_print_hex("preshared : ", &preshared);
    ba_print_hex("plaintext : ", &plaintext);

    /* --- HKEX-GF (key exchange) --- */
    printf("\n--- HKEX-GF (key exchange)\n");
    gf_pow_ba(&C,     &GF_GEN, &a_priv);   /* C  = g^a  (Alice sends) */
    gf_pow_ba(&C2,    &GF_GEN, &b_priv);   /* C2 = g^b  (Bob sends)   */
    gf_pow_ba(&skeyA, &C2,     &a_priv);   /* sk = (g^b)^a = g^{ab}   */
    gf_pow_ba(&skeyB, &C,      &b_priv);   /* sk = (g^a)^b = g^{ab}   */
    ba_print_hex("C         : ", &C);
    ba_print_hex("C2        : ", &C2);
    ba_print_hex("skeyA     : ", &skeyA);
    ba_print_hex("skeyB     : ", &skeyB);
    if (ba_equal(&skeyA, &skeyB))
        puts("+ session keys skeyA and skeyB are equal!");
    else
        puts("- session keys skeyA and skeyB are different!");

    /* --- HSKE (symmetric key encryption) --- */
    printf("\n--- HSKE (symmetric key encryption)\n");
    ba_fscx_revolve(&E, &plaintext, &preshared, I_VALUE);
    ba_print_hex("E (Alice) : ", &E);
    ba_fscx_revolve(&D, &E, &preshared, R_VALUE);
    ba_print_hex("D (Bob)   : ", &D);
    if (ba_equal(&D, &plaintext))
        puts("+ plaintext is correctly decrypted from E with preshared key");
    else
        puts("- plaintext is different from decrypted E with preshared key!");

    /* === 32-bit parameters for HPKS Schnorr and HPKE El Gamal === */
    printf("\n--- 32-bit parameters (Schnorr HPKS and El Gamal HPKE)\n");
    printf("a32       : 0x%08x\n", a32);
    printf("C32 (g^a) : 0x%08x\n", C32);
    printf("plain32   : 0x%08x\n", plain32);

    /* --- HPKS Schnorr (public key signature, 32-bit) --- */
    printf("\n--- HPKS Schnorr (public key signature)\n");
    k32  = rand32(urnd);
    R32  = gf_pow_32((uint32_t)GF_GEN32, k32);         /* R = g^k             */
    e32  = fscx_revolve32(R32, plain32, I_VALUE32);     /* e = fscx(R, P, i)   */
    ae64 = (uint64_t)a32 * (uint64_t)e32 % ord32;
    s32  = (uint32_t)(((uint64_t)k32 + ord32 - ae64) % ord32); /* s = k-a*e mod ORD */
    printf("R (g^k)   : 0x%08x\n", R32);
    printf("e (fscx)  : 0x%08x\n", e32);
    printf("s (resp)  : 0x%08x\n", s32);
    /* Verify: g^s * C^e == R */
    {
        uint32_t gs = gf_pow_32((uint32_t)GF_GEN32, s32);
        uint32_t Ce = gf_pow_32(C32, e32);
        uint32_t lhs = gf_mul_32(gs, Ce);
        printf("g^s*C^e   : 0x%08x\n", lhs);
        if (lhs == R32)
            puts("+ HPKS Schnorr signature verified!");
        else
            puts("- HPKS Schnorr signature verification FAILED!");
    }

    /* --- HPKS Schnorr + HSKE (sign encrypted message) --- */
    printf("\n--- HPKS Schnorr + HSKE (sign HSKE-encrypted message)\n");
    {
        uint32_t E_hske32, k2, R2, e2, s2;
        E_hske32 = fscx_revolve32(plain32, preshared32, I_VALUE32);
        printf("E_hske32  : 0x%08x\n", E_hske32);
        k2  = rand32(urnd);
        R2  = gf_pow_32((uint32_t)GF_GEN32, k2);
        e2  = fscx_revolve32(R2, E_hske32, I_VALUE32);
        ae64 = (uint64_t)a32 * (uint64_t)e2 % ord32;
        s2  = (uint32_t)(((uint64_t)k2 + ord32 - ae64) % ord32);
        uint32_t gs2 = gf_pow_32((uint32_t)GF_GEN32, s2);
        uint32_t Ce2 = gf_pow_32(C32, e2);
        uint32_t lhs2 = gf_mul_32(gs2, Ce2);
        /* decrypt and verify */
        uint32_t D_hske32 = fscx_revolve32(E_hske32, preshared32, R_VALUE32);
        if (lhs2 == R2 && D_hske32 == plain32)
            puts("+ HPKS Schnorr + HSKE: signature and decryption correct!");
        else
            puts("- HPKS Schnorr + HSKE: FAILED!");
    }

    /* --- HPKE El Gamal (public key encryption, 32-bit) --- */
    printf("\n--- HPKE El Gamal (public key encryption)\n");
    r32      = rand32(urnd) | 1;
    R_hpke   = gf_pow_32((uint32_t)GF_GEN32, r32);     /* R = g^r             */
    enc_key32 = gf_pow_32(C32, r32);                    /* enc_key = C^r=g^ar  */
    E32      = fscx_revolve32(plain32, enc_key32, I_VALUE32);
    dec_key32 = gf_pow_32(R_hpke, a32);                 /* dec_key = R^a=g^ra  */
    D32      = fscx_revolve32(E32, dec_key32, R_VALUE32);
    printf("R (g^r)   : 0x%08x\n", R_hpke);
    printf("E (Bob)   : 0x%08x\n", E32);
    printf("D (Alice) : 0x%08x\n", D32);
    if (D32 == plain32)
        puts("+ HPKE El Gamal decryption correct!");
    else
        puts("- HPKE El Gamal decryption FAILED!");

    /* *** EVE bypass TESTS *** */
    printf("\n\n*** EVE bypass TESTS\n");

    /* Eve attempts Schnorr forgery: pick random (R_eve, s_eve), check g^s_eve * C^e_eve == R_eve */
    printf("\n*** HPKS Schnorr — Eve cannot forge without DLP solution\n");
    {
        uint32_t r_eve = rand32(urnd);
        uint32_t s_eve = rand32(urnd);
        uint32_t e_eve = fscx_revolve32(r_eve, plain32, I_VALUE32);
        uint32_t gs_eve = gf_pow_32((uint32_t)GF_GEN32, s_eve);
        uint32_t Ce_eve = gf_pow_32(C32, e_eve);
        uint32_t lhs_eve = gf_mul_32(gs_eve, Ce_eve);
        printf("R_eve     : 0x%08x\n", r_eve);
        printf("lhs_eve   : 0x%08x\n", lhs_eve);
        if (lhs_eve == r_eve)
            puts("+ Eve forged signature (attack succeeded - UNEXPECTED!)");
        else
            puts("- Eve could not forge signature (DLP protection holds)");
    }

    /* Eve attempts CDH attack on HPKE: guess enc_key from C and R using XOR */
    printf("\n*** HPKE El Gamal — Eve cannot decrypt without CDH solution\n");
    {
        uint32_t eve_key = C32 ^ R_hpke;   /* wrong key: C XOR R (not C^r) */
        uint32_t D_eve   = fscx_revolve32(E32, eve_key, R_VALUE32);
        printf("eve_key   : 0x%08x (C XOR R, not C^r)\n", eve_key);
        printf("D_eve     : 0x%08x\n", D_eve);
        if (D_eve == plain32)
            puts("+ Eve decrypted plaintext (attack succeeded - UNEXPECTED!)");
        else
            puts("- Eve could not decrypt without CDH solution (DLP protection holds)");
    }

    fclose(urnd);
    return 0;
}
