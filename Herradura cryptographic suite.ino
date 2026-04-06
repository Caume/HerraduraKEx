/*  Herradura Cryptographic Suite v1.4.0 — Arduino (32-bit)
    HKEX-GF, HSKE, HPKS, HPKE, KEYBITS = 32

    Copyright (C) 2024-2026 Omar Alejandro Herrera Reyna
    MIT License / GPL v3.0 — choose either.

    Target: Arduino Uno/Mega/Leonardo or any board with Serial support.
    Upload via Arduino IDE or: arduino --upload --board arduino:avr:uno Herradura\ cryptographic\ suite.ino
    Monitor: 9600 baud serial monitor.

    v1.4.0: HKEX replaced with HKEX-GF; Schnorr HPKS; El Gamal HPKE.
      - fscx_revolve_n removed (nonce cancels identically, proved in SecurityProofs.md).
      - HSKE uses standard fscx_revolve (unchanged).
      - HPKS: Schnorr signature; s=(k-a*e) mod ORD; verify g^s*C^e==R.
      - HPKE: El Gamal + fscx_revolve; enc_key=C^r; dec_key=R^a.
      - Security: CDH in GF(2^32)* — for demo only; use n>=256 in production.
*/

#define KEYBITS  32
#define I_VALUE  (KEYBITS / 4)        /* 8  */
#define R_VALUE  (3 * KEYBITS / 4)    /* 24 */

/* GF(2^32) polynomial: x^32 + x^22 + x^2 + x + 1 */
#define GF_POLY32 0x00400007UL
#define GF_GEN    3UL

typedef unsigned long uint32;

/* ------------------------------------------------------------------ */
/* FSCX primitives (HSKE, unchanged)                                  */
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
/* LCG PRNG for nonces (k in Schnorr, r in El Gamal)                 */
/* ------------------------------------------------------------------ */

uint32 lcg_state = 0xDEADBEEEUL;   /* seed = A_PRIV - 1 */

uint32 lcg_next() {
    lcg_state = lcg_state * 1664525UL + 1013904223UL;
    return lcg_state;
}

/* ------------------------------------------------------------------ */
/* Hex printing helpers                                                */
/* ------------------------------------------------------------------ */

static void printHex(uint32 val) {
    char buf[9];
    for (int i = 7; i >= 0; i--) {
        buf[i] = "0123456789ABCDEF"[val & 0xF];
        val >>= 4;
    }
    buf[8] = '\0';
    Serial.println(buf);
}

static void printHexLine(const char *label, uint32 val) {
    Serial.print(label);
    printHex(val);
}

/* ------------------------------------------------------------------ */
/* Fixed test vectors                                                  */
/* ------------------------------------------------------------------ */

const uint32 A_PRIV = 0xDEADBEEFUL;   /* Alice's private scalar (odd) */
const uint32 B_PRIV = 0xCAFEBABFUL;   /* Bob's private scalar   (odd) */
const uint32 K      = 0x5A5A5A5AUL;   /* preshared key (HSKE)         */
const uint32 PLAIN  = 0xDEADC0DEUL;

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
    Serial.println("=== Herradura Cryptographic Suite (Arduino, 32-bit) ===");
    Serial.println();

    printHexLine("a_priv : ", A_PRIV);
    printHexLine("b_priv : ", B_PRIV);
    printHexLine("K      : ", K);
    printHexLine("PLAIN  : ", PLAIN);
    Serial.println();

    /* ---------------------------------------------------------------- */
    /* HKEX-GF (key exchange — DH over GF(2^32)*)                      */
    /* C = g^a,  C2 = g^b,  sk = C2^a = C^b = g^{ab}                  */
    /* ---------------------------------------------------------------- */
    Serial.println("--- HKEX-GF (key exchange)");
    uint32 C    = gf_pow_32(GF_GEN, A_PRIV);
    uint32 C2   = gf_pow_32(GF_GEN, B_PRIV);
    uint32 skeyA = gf_pow_32(C2, A_PRIV);
    uint32 skeyB = gf_pow_32(C,  B_PRIV);
    printHexLine("C        : ", C);
    printHexLine("C2       : ", C2);
    printHexLine("skeyA    : ", skeyA);
    printHexLine("skeyB    : ", skeyB);
    if (skeyA == skeyB)
        Serial.println("+ session keys skeyA and skeyB are equal!");
    else
        Serial.println("- session keys skeyA and skeyB are different!");
    Serial.println();

    /* ---------------------------------------------------------------- */
    /* HSKE (symmetric key encryption)                                  */
    /* E = fscx_revolve(P, key, I)   D = fscx_revolve(E, key, R) = P  */
    /* ---------------------------------------------------------------- */
    Serial.println("--- HSKE (symmetric key encryption)");
    uint32 hskeE = fscx_revolve(PLAIN, K, I_VALUE);
    uint32 hskeD = fscx_revolve(hskeE, K, R_VALUE);
    printHexLine("E (Alice) : ", hskeE);
    printHexLine("D (Bob)   : ", hskeD);
    if (hskeD == PLAIN)
        Serial.println("+ plaintext is correctly decrypted from E with preshared key");
    else
        Serial.println("- plaintext is different from decrypted E with preshared key!");
    Serial.println();

    /* ---------------------------------------------------------------- */
    /* HPKS Schnorr (public key signature)                             */
    /* k random; R=g^k; e=fscx(R,P,i); s=(k-a*e) mod ORD             */
    /* verify: g^s * C^e == R                                          */
    /* ---------------------------------------------------------------- */
    Serial.println("--- HPKS Schnorr (public key signature)");
    {
        uint32 k   = lcg_next() | 1;
        uint32 R   = gf_pow_32(GF_GEN, k);
        uint32 e   = fscx_revolve(R, PLAIN, I_VALUE);
        uint64_t ae = ((uint64_t)A_PRIV * (uint64_t)e) % 0xFFFFFFFFULL;
        uint32 s   = (uint32)(((uint64_t)k + 0xFFFFFFFFULL - ae) % 0xFFFFFFFFULL);
        uint32 gs  = gf_pow_32(GF_GEN, s);
        uint32 Ce  = gf_pow_32(C, e);
        uint32 lhs = gf_mul_32(gs, Ce);
        printHexLine("R (g^k)   : ", R);
        printHexLine("s (resp)  : ", s);
        printHexLine("g^s*C^e   : ", lhs);
        if (lhs == R)
            Serial.println("+ HPKS Schnorr signature verified!");
        else
            Serial.println("- HPKS Schnorr signature verification FAILED!");
    }
    Serial.println();

    /* ---------------------------------------------------------------- */
    /* HPKE El Gamal (public key encryption)                           */
    /* r random; R=g^r; enc_key=C^r; E=fscx(P,enc_key,i)             */
    /* Alice: dec_key=R^a; D=fscx(E,dec_key,r) == P                  */
    /* ---------------------------------------------------------------- */
    Serial.println("--- HPKE El Gamal (public key encryption)");
    {
        uint32 r        = lcg_next() | 1;
        uint32 R        = gf_pow_32(GF_GEN, r);
        uint32 enc_key  = gf_pow_32(C, r);
        uint32 hpkeE    = fscx_revolve(PLAIN, enc_key, I_VALUE);
        uint32 dec_key  = gf_pow_32(R, A_PRIV);
        uint32 hpkeD    = fscx_revolve(hpkeE, dec_key, R_VALUE);
        printHexLine("R (g^r)   : ", R);
        printHexLine("E (Bob)   : ", hpkeE);
        printHexLine("D (Alice) : ", hpkeD);
        if (hpkeD == PLAIN)
            Serial.println("+ HPKE El Gamal decryption correct!");
        else
            Serial.println("- HPKE El Gamal decryption FAILED!");
    }
    Serial.println();

    delay(10000);
}
