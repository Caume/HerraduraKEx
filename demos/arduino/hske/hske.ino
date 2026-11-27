/*  demos/arduino/hske/hske.ino -- HSKE symmetric encryption (Arduino, 32-bit; TODO #425)
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
    Serial.println(F("=== Herradura KEx demo: HSKE symmetric encryption (Arduino, 32-bit) ==="));
    Serial.println();

    printHexLine(F("a_priv : "), A_PRIV);
    printHexLine(F("b_priv : "), B_PRIV);
    printHexLine(F("K      : "), K);
    printHexLine(F("PLAIN  : "), PLAIN);
    Serial.println();
    /* ---------------------------------------------------------------- */
    /* HSKE [CLASSICAL]                                                 */
    /* ---------------------------------------------------------------- */
    Serial.println(F("--- HSKE [CLASSICAL -- not PQC; linear key recovery]"));
    uint32 hskeE = fscx_revolve(PLAIN, K, I_VALUE);
    uint32 hskeD = fscx_revolve(hskeE, K, R_VALUE);
    printHexLine(F("E (Alice) : "), hskeE);
    printHexLine(F("D (Bob)   : "), hskeD);
    check(hskeD == PLAIN,
          F("+ plaintext correctly decrypted"),
          F("[FAIL] decryption failed!"));
    Serial.println();

    demo_finish();
}
