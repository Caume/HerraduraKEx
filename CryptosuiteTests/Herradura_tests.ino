/*  Herradura KEx — Security Tests v1.4.0 (Arduino, 32-bit)
    HKEX-GF, HSKE, HPKS, HPKE correctness tests with LCG PRNG (100 iterations each)

    Copyright (C) 2024-2026 Omar Alejandro Herrera Reyna
    MIT License / GPL v3.0 — choose either.

    Target: Any Arduino board with Serial support.
    Upload via Arduino IDE. Monitor at 9600 baud.

    v1.4.0: HKEX-GF; Schnorr HPKS; El Gamal HPKE.
      - fscx_revolve_n removed.
      - [1] HKEX-GF correctness: g^{ab} == g^{ba}.
      - [2] HSKE round-trip: fscx_revolve(fscx_revolve(P,K,i),K,r) == P.
      - [3] HPKS Schnorr: g^s * C^e == R  (s = k-a*e mod ORD).
      - [4] HPKE El Gamal: fscx_revolve(E, R^a, r) == P.
*/

#define KEYBITS  32
#define I_VALUE  (KEYBITS / 4)        /* 8  */
#define R_VALUE  (3 * KEYBITS / 4)    /* 24 */

#define GF_POLY32 0x00400007UL
#define GF_GEN    3UL

typedef unsigned long uint32;

/* ------------------------------------------------------------------ */
/* LCG PRNG                                                            */
/* ------------------------------------------------------------------ */

uint32 prng_state = 0x12345678UL;

uint32 prng_next() {
    prng_state = prng_state * 1664525UL + 1013904223UL;
    return prng_state;
}

/* ------------------------------------------------------------------ */
/* FSCX primitives                                                     */
/* ------------------------------------------------------------------ */

uint32 rol32(uint32 x) { return (x << 1) | (x >> 31); }
uint32 ror32(uint32 x) { return (x >> 1) | (x << 31); }

uint32 fscx(uint32 a, uint32 b) {
    return a ^ b ^ rol32(a) ^ rol32(b) ^ ror32(a) ^ ror32(b);
}

uint32 fscx_revolve(uint32 a, uint32 b, int steps) {
    for (int i = 0; i < steps; i++) a = fscx(a, b);
    return a;
}

/* ------------------------------------------------------------------ */
/* GF(2^32) arithmetic                                                */
/* ------------------------------------------------------------------ */

uint32 gf_mul_32(uint32 a, uint32 b) {
    uint32 r = 0;
    for (int i = 0; i < 32; i++) {
        if (b & 1) r ^= a;
        uint32 carry = a >> 31;
        a <<= 1;
        if (carry) a ^= GF_POLY32;
        b >>= 1;
    }
    return r;
}

uint32 gf_pow_32(uint32 base, uint32 exp) {
    uint32 r = 1;
    while (exp) {
        if (exp & 1) r = gf_mul_32(r, base);
        base = gf_mul_32(base, base);
        exp >>= 1;
    }
    return r;
}

/* ------------------------------------------------------------------ */
/* Test functions                                                      */
/* ------------------------------------------------------------------ */

/*
 * [1] HKEX-GF correctness: g^{ab} == g^{ba}
 *     C = g^a, C2 = g^b, skA = C2^a, skB = C^b; Pass: skA == skB
 */
void test_hkex_gf() {
    Serial.println("[1] HKEX-GF correctness: g^{ab} == g^{ba}");
    int pass = 0;
    for (int i = 0; i < 20; i++) {
        uint32 a = prng_next() | 1;   /* ensure odd */
        uint32 b = prng_next() | 1;
        uint32 C   = gf_pow_32(GF_GEN, a);
        uint32 C2  = gf_pow_32(GF_GEN, b);
        uint32 skA = gf_pow_32(C2, a);
        uint32 skB = gf_pow_32(C,  b);
        if (skA == skB) pass++;
    }
    Serial.print("    "); Serial.print(pass); Serial.print(" / 20 passed  [");
    Serial.println(pass == 20 ? "PASS]" : "FAIL]");
    Serial.println();
}

/*
 * [2] HSKE symmetric encryption correctness
 *     E = fscx_revolve(P, key, I)
 *     D = fscx_revolve(E, key, R)
 *     Pass condition: D == P
 */
void test_hske() {
    Serial.println("[2] HSKE symmetric encryption correctness");
    int pass = 0;
    for (int i = 0; i < 100; i++) {
        uint32 p   = prng_next();
        uint32 key = prng_next();
        uint32 enc = fscx_revolve(p,   key, I_VALUE);
        uint32 dec = fscx_revolve(enc, key, R_VALUE);
        if (dec == p) pass++;
    }
    Serial.print("    "); Serial.print(pass); Serial.print(" / 100 passed  [");
    Serial.println(pass == 100 ? "PASS]" : "FAIL]");
    Serial.println();
}

/*
 * [3] HPKS Schnorr correctness: g^s * C^e == R
 *     a private; C = g^a; k nonce; R = g^k
 *     e = fscx_revolve(R, p, I_VALUE)
 *     s = (k - a*e) mod ORD  (ORD = 2^32-1)
 *     pass: gf_mul_32(g^s, C^e) == R
 */
void test_hpks() {
    Serial.println("[3] HPKS Schnorr correctness: g^s*C^e == R");
    int pass = 0;
    for (int i = 0; i < 20; i++) {
        uint32 a  = prng_next() | 1;
        uint32 p  = prng_next();
        uint32 k  = prng_next();
        uint32 C  = gf_pow_32(GF_GEN, a);
        uint32 R  = gf_pow_32(GF_GEN, k);
        uint32 e  = fscx_revolve(R, p, I_VALUE);
        uint64_t ae = ((uint64_t)a * (uint64_t)e) % 0xFFFFFFFFULL;
        uint32 s  = (uint32)(((uint64_t)k + 0xFFFFFFFFULL - ae) % 0xFFFFFFFFULL);
        uint32 gs = gf_pow_32(GF_GEN, s);
        uint32 Ce = gf_pow_32(C, e);
        if (gf_mul_32(gs, Ce) == R) pass++;
    }
    Serial.print("    "); Serial.print(pass); Serial.print(" / 20 passed  [");
    Serial.println(pass == 20 ? "PASS]" : "FAIL]");
    Serial.println();
}

/*
 * [4] HPKE El Gamal encrypt+decrypt correctness
 *     a private; C = g^a; r ephemeral; R = g^r
 *     enc_key = C^r = g^{ar}; E = fscx_revolve(P, enc_key, I_VALUE)
 *     dec_key = R^a = g^{ra}; D = fscx_revolve(E, dec_key, R_VALUE)
 *     pass: D == P
 */
void test_hpke() {
    Serial.println("[4] HPKE El Gamal encrypt+decrypt: D == P");
    int pass = 0;
    for (int i = 0; i < 20; i++) {
        uint32 a       = prng_next() | 1;
        uint32 p       = prng_next();
        uint32 r       = prng_next() | 1;
        uint32 C       = gf_pow_32(GF_GEN, a);
        uint32 R       = gf_pow_32(GF_GEN, r);
        uint32 enc_key = gf_pow_32(C, r);
        uint32 E       = fscx_revolve(p, enc_key, I_VALUE);
        uint32 dec_key = gf_pow_32(R, a);
        uint32 D       = fscx_revolve(E, dec_key, R_VALUE);
        if (D == p) pass++;
    }
    Serial.print("    "); Serial.print(pass); Serial.print(" / 20 passed  [");
    Serial.println(pass == 20 ? "PASS]" : "FAIL]");
    Serial.println();
}

/* ------------------------------------------------------------------ */
/* Arduino entry points                                                */
/* ------------------------------------------------------------------ */

void setup() {
    Serial.begin(9600);
    while (!Serial) {
        ; /* wait for serial port — needed for Leonardo/Due */
    }
}

void loop() {
    Serial.println("=== Herradura KEx - Security Tests (Arduino, 32-bit) ===");
    Serial.println();

    test_hkex_gf();
    test_hske();
    test_hpks();
    test_hpke();

    delay(30000);
}
