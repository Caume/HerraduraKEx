/*  demos/arduino/hpks/hpks.ino -- HPKS Schnorr signature (Arduino, 32-bit; TODO #425)
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
    Serial.println(F("=== Herradura KEx demo: HPKS Schnorr signature (Arduino, 32-bit) ==="));
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
    /* HPKS Schnorr [CLASSICAL]                                        */
    /* ---------------------------------------------------------------- */
    Serial.println(F("--- HPKS Schnorr [CLASSICAL -- not PQC; DLP + linear challenge]"));
    {
        uint32 k   = lcg_next() | 1;
        uint32 R   = gf_pow_32(GF_GEN, k);
        uint32 e   = fscx_revolve(R, PLAIN, I_VALUE);
        uint64_t ae = ((uint64_t)A_PRIV * (uint64_t)e) % 0xFFFFFFFFULL;
        uint32 s   = (uint32)(((uint64_t)k + 0xFFFFFFFFULL - ae) % 0xFFFFFFFFULL);
        uint32 gs  = gf_pow_32(GF_GEN, s);
        uint32 Ce  = gf_pow_32(C, e);
        uint32 lhs = gf_mul_32(gs, Ce);
        printHexLine(F("R (g^k)   : "), R);
        printHexLine(F("s (resp)  : "), s);
        printHexLine(F("g^s*C^e   : "), lhs);
        check(lhs == R,
          F("+ HPKS Schnorr verified!"),
          F("[FAIL] HPKS Schnorr FAILED!"));
        Serial.println(F("*** EVE: the same (R, s) for another message, PLAIN ^ 1"));
        uint32 e2 = fscx_revolve(R, PLAIN ^ 1u, I_VALUE);
        check(gf_mul_32(gs, gf_pow_32(C, e2)) != R,
          F("- Eve's signature for another message refused (g^s * C^e' != R)"),
          F("[FAIL] the signature verified another message!"));
    }
    Serial.println();

    demo_finish();
}
