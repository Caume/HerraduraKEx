/*  demos/arduino/hske_nl_a2/hske_nl_a2.ino -- HSKE-NL-A2 revolve-mode encryption (Arduino, 32-bit; TODO #425)
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
    Serial.println(F("=== Herradura KEx demo: HSKE-NL-A2 revolve-mode encryption (Arduino, 32-bit) ==="));
    Serial.println();

    printHexLine(F("a_priv : "), A_PRIV);
    printHexLine(F("b_priv : "), B_PRIV);
    printHexLine(F("K      : "), K);
    printHexLine(F("PLAIN  : "), PLAIN);
    Serial.println();
    /* ---------------------------------------------------------------- */
    /* HSKE-NL-A2 [PQC-HARDENED -- revolve-mode with NL-FSCX v2]      */
    /* CAUTION: deterministic -- same (P, K) always yields the same E. */
    /* ---------------------------------------------------------------- */
    Serial.println(F("--- HSKE-NL-A2 [PQC-HARDENED -- revolve-mode with NL-FSCX v2]"));
    {
        uint32 E = nl_fscx_revolve_v2(PLAIN, K, R_VALUE);
        uint32 D = nl_fscx_revolve_v2_inv(E, K, R_VALUE);
        printHexLine(F("E (Alice) : "), E);
        printHexLine(F("D (Bob)   : "), D);
        check(D == PLAIN,
          F("+ plaintext correctly decrypted"),
          F("[FAIL] decryption failed!"));
    }
    Serial.println();

    demo_finish();
}
