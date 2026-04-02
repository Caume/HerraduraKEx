/*  Herradura KEx — Security Tests v1.3.7 (Arduino, 32-bit)
    HKEX, HSKE, HPKS, HPKE correctness tests with LCG PRNG (100 iterations each)

    Copyright (C) 2024-2026 Omar Alejandro Herrera Reyna
    MIT License / GPL v3.0 — choose either.

    Target: Any Arduino board with Serial support.
    Upload via Arduino IDE. Monitor at 9600 baud.
*/

#define KEYBITS  32
#define I_VALUE  (KEYBITS / 4)        /* 8  */
#define R_VALUE  (3 * KEYBITS / 4)    /* 24 */

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

uint32 fscx_revolve_n(uint32 a, uint32 b, uint32 nonce, int steps) {
    for (int i = 0; i < steps; i++) a = fscx(a, b) ^ nonce;
    return a;
}

/* ------------------------------------------------------------------ */
/* Test functions                                                      */
/* ------------------------------------------------------------------ */

/*
 * [1] HKEX key exchange correctness
 *     skeyA = fscx_revolve_n(C2, B,  hn, R) ^ A
 *     skeyB = fscx_revolve_n(C,  B2, hn, R) ^ A2
 *     Pass condition: skeyA == skeyB
 */
void test_hkex() {
    Serial.println("[1] HKEX key exchange correctness");
    int pass = 0;
    for (int i = 0; i < 100; i++) {
        uint32 a  = prng_next(), b  = prng_next();
        uint32 a2 = prng_next(), b2 = prng_next();
        uint32 c  = fscx_revolve(a,  b,  I_VALUE);
        uint32 c2 = fscx_revolve(a2, b2, I_VALUE);
        uint32 hn = c ^ c2;
        uint32 skA = fscx_revolve_n(c2, b,  hn, R_VALUE) ^ a;
        uint32 skB = fscx_revolve_n(c,  b2, hn, R_VALUE) ^ a2;
        if (skA == skB) pass++;
    }
    Serial.print("    "); Serial.print(pass); Serial.print(" / 100 passed  [");
    Serial.println(pass == 100 ? "PASS]" : "FAIL]");
    Serial.println();
}

/*
 * [2] HSKE symmetric encryption correctness
 *     E = fscx_revolve_n(P, key, key, I)
 *     D = fscx_revolve_n(E, key, key, R)
 *     Pass condition: D == P
 */
void test_hske() {
    Serial.println("[2] HSKE symmetric encryption correctness");
    int pass = 0;
    for (int i = 0; i < 100; i++) {
        uint32 p   = prng_next();
        uint32 key = prng_next();
        uint32 enc = fscx_revolve_n(p,   key, key, I_VALUE);
        uint32 dec = fscx_revolve_n(enc, key, key, R_VALUE);
        if (dec == p) pass++;
    }
    Serial.print("    "); Serial.print(pass); Serial.print(" / 100 passed  [");
    Serial.println(pass == 100 ? "PASS]" : "FAIL]");
    Serial.println();
}

/*
 * [3] HPKS public key signature correctness
 *     S = fscx_revolve_n(C2, B,  hn, R) ^ A  ^ P
 *     V = fscx_revolve_n(C,  B2, hn, R) ^ A2 ^ S
 *     Pass condition: V == P
 */
void test_hpks() {
    Serial.println("[3] HPKS public key signature correctness");
    int pass = 0;
    for (int i = 0; i < 100; i++) {
        uint32 a  = prng_next(), b  = prng_next();
        uint32 a2 = prng_next(), b2 = prng_next();
        uint32 p  = prng_next();
        uint32 c  = fscx_revolve(a,  b,  I_VALUE);
        uint32 c2 = fscx_revolve(a2, b2, I_VALUE);
        uint32 hn = c ^ c2;
        uint32 S  = fscx_revolve_n(c2, b,  hn, R_VALUE) ^ a  ^ p;
        uint32 V  = fscx_revolve_n(c,  b2, hn, R_VALUE) ^ a2 ^ S;
        if (V == p) pass++;
    }
    Serial.print("    "); Serial.print(pass); Serial.print(" / 100 passed  [");
    Serial.println(pass == 100 ? "PASS]" : "FAIL]");
    Serial.println();
}

/*
 * [4] HPKE public key encryption correctness
 *     E = fscx_revolve_n(C,  B2, hn, R) ^ A2 ^ P
 *     D = fscx_revolve_n(C2, B,  hn, R) ^ A  ^ E
 *     Pass condition: D == P
 */
void test_hpke() {
    Serial.println("[4] HPKE public key encryption correctness");
    int pass = 0;
    for (int i = 0; i < 100; i++) {
        uint32 a  = prng_next(), b  = prng_next();
        uint32 a2 = prng_next(), b2 = prng_next();
        uint32 p  = prng_next();
        uint32 c  = fscx_revolve(a,  b,  I_VALUE);
        uint32 c2 = fscx_revolve(a2, b2, I_VALUE);
        uint32 hn = c ^ c2;
        uint32 E  = fscx_revolve_n(c,  b2, hn, R_VALUE) ^ a2 ^ p;
        uint32 D  = fscx_revolve_n(c2, b,  hn, R_VALUE) ^ a  ^ E;
        if (D == p) pass++;
    }
    Serial.print("    "); Serial.print(pass); Serial.print(" / 100 passed  [");
    Serial.println(pass == 100 ? "PASS]" : "FAIL]");
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

    test_hkex();
    test_hske();
    test_hpks();
    test_hpke();

    delay(30000);
}
