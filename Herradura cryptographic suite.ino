/*  Herradura Cryptographic Suite v1.3.7 — Arduino (32-bit)
    HKEX, HSKE, HPKS, HPKE with FSCX_REVOLVE_N, KEYBITS = 32

    Copyright (C) 2024-2026 Omar Alejandro Herrera Reyna
    MIT License / GPL v3.0 — choose either.

    Target: Arduino Uno/Mega/Leonardo or any board with Serial support.
    Upload via Arduino IDE or: arduino --upload --board arduino:avr:uno Herradura\ cryptographic\ suite.ino
    Monitor: 9600 baud serial monitor.
*/

#define KEYBITS  32
#define I_VALUE  (KEYBITS / 4)        /* 8  */
#define R_VALUE  (3 * KEYBITS / 4)    /* 24 */

typedef unsigned long uint32;

/* Fixed test vectors (same as C suite) */
const uint32 A     = 0xDEADBEEFUL;
const uint32 B     = 0xCAFEBABEUL;
const uint32 A2    = 0x12345678UL;
const uint32 B2    = 0xABCDEF01UL;
const uint32 K     = 0x5A5A5A5AUL;   /* preshared key   */
const uint32 PLAIN = 0xDEADC0DEUL;

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
/* Hex printing helpers                                                */
/* ------------------------------------------------------------------ */

/* Print an 8-digit zero-padded hex value followed by a newline. */
static void printHex(uint32 val) {
    /* Print leading zeros manually so output is always 8 hex digits. */
    char buf[9];
    for (int i = 7; i >= 0; i--) {
        buf[i] = "0123456789ABCDEF"[val & 0xF];
        val >>= 4;
    }
    buf[8] = '\0';
    Serial.println(buf);
}

/* Print label, then zero-padded 8-digit hex, then newline. */
static void printHexLine(const char *label, uint32 val) {
    Serial.print(label);
    printHex(val);
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
    Serial.println("=== Herradura Cryptographic Suite (Arduino, 32-bit) ===");
    Serial.println();

    /* --- Shared public values --- */
    uint32 C  = fscx_revolve(A,  B,  I_VALUE);
    uint32 C2 = fscx_revolve(A2, B2, I_VALUE);
    uint32 hn = C ^ C2;   /* HKEX nonce derived from public values */

    printHexLine("A      : ", A);
    printHexLine("B      : ", B);
    printHexLine("A2     : ", A2);
    printHexLine("B2     : ", B2);
    printHexLine("K      : ", K);
    printHexLine("PLAIN  : ", PLAIN);
    printHexLine("C      : ", C);
    printHexLine("C2     : ", C2);
    printHexLine("hn     : ", hn);
    Serial.println();

    /* ---------------------------------------------------------------- */
    /* HKEX (key exchange)                                              */
    /* skeyA = fscx_revolve_n(C2, B,  hn, R) ^ A                       */
    /* skeyB = fscx_revolve_n(C,  B2, hn, R) ^ A2                      */
    /* ---------------------------------------------------------------- */
    Serial.println("--- HKEX (key exchange)");
    uint32 skeyA = fscx_revolve_n(C2, B,  hn, R_VALUE) ^ A;
    uint32 skeyB = fscx_revolve_n(C,  B2, hn, R_VALUE) ^ A2;
    printHexLine("skeyA (Alice): ", skeyA);
    printHexLine("skeyB (Bob)  : ", skeyB);
    if (skeyA == skeyB)
        Serial.println("+ session keys skeyA and skeyB are equal!");
    else
        Serial.println("- session keys skeyA and skeyB are different!");
    Serial.println();

    /* ---------------------------------------------------------------- */
    /* HSKE (symmetric key encryption)                                  */
    /* E = fscx_revolve_n(PLAIN, K, K, I)                               */
    /* D = fscx_revolve_n(E,     K, K, R)   => PLAIN                   */
    /* ---------------------------------------------------------------- */
    Serial.println("--- HSKE (symmetric key encryption)");
    uint32 hskeE = fscx_revolve_n(PLAIN, K, K, I_VALUE);
    uint32 hskeD = fscx_revolve_n(hskeE, K, K, R_VALUE);
    printHexLine("E (Alice) : ", hskeE);
    printHexLine("D (Bob)   : ", hskeD);
    if (hskeD == PLAIN)
        Serial.println("+ plaintext is correctly decrypted from E with preshared key");
    else
        Serial.println("- plaintext is different from decrypted E with preshared key!");
    Serial.println();

    /* ---------------------------------------------------------------- */
    /* HPKS (public key signature)                                      */
    /* S = fscx_revolve_n(C2, B,  hn, R) ^ A  ^ PLAIN                  */
    /* V = fscx_revolve_n(C,  B2, hn, R) ^ A2 ^ S     => PLAIN         */
    /* ---------------------------------------------------------------- */
    Serial.println("--- HPKS (public key signature)");
    uint32 hpksS = fscx_revolve_n(C2, B,  hn, R_VALUE) ^ A  ^ PLAIN;
    uint32 hpksV = fscx_revolve_n(C,  B2, hn, R_VALUE) ^ A2 ^ hpksS;
    printHexLine("S (Alice) : ", hpksS);
    printHexLine("V (Bob)   : ", hpksV);
    if (hpksV == PLAIN)
        Serial.println("+ signature S from plaintext is correct!");
    else
        Serial.println("- signature S from plaintext is incorrect!");
    Serial.println();

    /* ---------------------------------------------------------------- */
    /* HPKE (public key encryption)                                     */
    /* E = fscx_revolve_n(C,  B2, hn, R) ^ A2 ^ PLAIN                  */
    /* D = fscx_revolve_n(C2, B,  hn, R) ^ A  ^ E      => PLAIN        */
    /* ---------------------------------------------------------------- */
    Serial.println("--- HPKE (public key encryption)");
    uint32 hpkeE = fscx_revolve_n(C,  B2, hn, R_VALUE) ^ A2 ^ PLAIN;
    uint32 hpkeD = fscx_revolve_n(C2, B,  hn, R_VALUE) ^ A  ^ hpkeE;
    printHexLine("E (Bob)   : ", hpkeE);
    printHexLine("D (Alice) : ", hpkeD);
    if (hpkeD == PLAIN)
        Serial.println("+ plaintext is correctly decrypted from E with private key!");
    else
        Serial.println("- plaintext is different from decrypted E with private key!");
    Serial.println();

    delay(10000);
}
