/*  demos/arduino/hkex_gf/hkex_gf.ino -- HKEX-GF key exchange (Arduino, 32-bit; TODO #425)
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
    Serial.println(F("=== Herradura KEx demo: HKEX-GF key exchange (Arduino, 32-bit) ==="));
    Serial.println();

    printHexLine(F("a_priv : "), A_PRIV);
    printHexLine(F("b_priv : "), B_PRIV);
    printHexLine(F("K      : "), K);
    printHexLine(F("PLAIN  : "), PLAIN);
    Serial.println();
    /* ---------------------------------------------------------------- */
    /* HKEX-GF [CLASSICAL]                                              */
    /* ---------------------------------------------------------------- */
    Serial.println(F("--- HKEX-GF [CLASSICAL -- not PQC; Shor breaks DLP]"));
    uint32 C    = gf_pow_32(GF_GEN, A_PRIV);
    uint32 C2   = gf_pow_32(GF_GEN, B_PRIV);
    uint32 skeyA = gf_pow_32(C2, A_PRIV);
    uint32 skeyB = gf_pow_32(C,  B_PRIV);
    printHexLine(F("C        : "), C);
    printHexLine(F("C2       : "), C2);
    printHexLine(F("skeyA    : "), skeyA);
    printHexLine(F("skeyB    : "), skeyB);
    check(skeyA == skeyB,
          F("+ session keys agree!"),
          F("[FAIL] session keys differ!"));
    Serial.println();

    demo_finish();
}
