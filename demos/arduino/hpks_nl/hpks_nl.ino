/*  demos/arduino/hpks_nl/hpks_nl.ino -- HPKS-NL Schnorr signature (Arduino, 32-bit; TODO #425)
    One algorithm end to end: its sample inputs, every intermediate, and its
    verdict through the shared [FAIL] gate.  The routines are in the Herradura32
    library (demos/arduino/libraries/Herradura32).  Build: ./build_arduino.sh;
    run: ./run_arduino.sh suite.  Monitor at 9600 baud.
*/
#include <Herradura32.h>

void setup() {
    Serial.begin(9600);
    while (!Serial) { ; }
}

void loop() {
    Serial.println(F("=== Herradura KEx demo: HPKS-NL Schnorr signature (Arduino, 32-bit) ==="));
    Serial.println();

    printHexLine(F("a_priv : "), A_PRIV);
    printHexLine(F("b_priv : "), B_PRIV);
    printHexLine(F("K      : "), K);
    printHexLine(F("PLAIN  : "), PLAIN);
    Serial.println();
    uint32 C = gf_pow_32(GF_GEN, A_PRIV);   /* Alice's public key */
    printHexLine(F("C (g^a)   : "), C);
    Serial.println();

    /* ---------------------------------------------------------------- */
    /* HPKS-NL [NL-hardened Schnorr -- HFSCX-32 challenge]          */
    /* ---------------------------------------------------------------- */
    Serial.println(F("--- HPKS-NL [NL-hardened Schnorr -- HFSCX-32 challenge]"));
    {
        uint32 k_nl = lcg_next();
        uint32 R_nl = gf_pow_32(GF_GEN, k_nl);
        uint32 e_nl = hpks_nl_challenge_32(R_nl, PLAIN);
        uint64_t ae_nl = ((uint64_t)A_PRIV * (uint64_t)e_nl) % 0xFFFFFFFFULL;
        uint32 s_nl = (uint32)(((uint64_t)k_nl + 0xFFFFFFFFULL - ae_nl) % 0xFFFFFFFFULL);
        uint32 gs_nl = gf_pow_32(GF_GEN, s_nl);
        uint32 Ce_nl = gf_pow_32(C, e_nl);
        uint32 lhs_nl = gf_mul_32(gs_nl, Ce_nl);
        printHexLine(F("R (g^k)   : "), R_nl);
        printHexLine(F("s (resp)  : "), s_nl);
        printHexLine(F("g^s*C^e   : "), lhs_nl);
        check(lhs_nl == R_nl,
          F("+ HPKS-NL verified!"),
          F("[FAIL] HPKS-NL FAILED!"));
        Serial.println(F("*** EVE: the same (R, s) for another message, PLAIN ^ 1"));
        uint32 e2 = hpks_nl_challenge_32(R_nl, PLAIN ^ 1u);
        check(gf_mul_32(gs_nl, gf_pow_32(C, e2)) != R_nl,
          F("- Eve's signature for another message refused (g^s * C^e' != R)"),
          F("[FAIL] the signature verified another message!"));
    }
    Serial.println();

    demo_finish();
}
