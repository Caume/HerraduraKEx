/*  demos/arduino/hske_nl_a1/hske_nl_a1.ino -- HSKE-NL-A1 counter-mode encryption (Arduino, 32-bit; TODO #425)
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
    Serial.println(F("=== Herradura KEx demo: HSKE-NL-A1 counter-mode encryption (Arduino, 32-bit) ==="));
    Serial.println();

    printHexLine(F("a_priv : "), A_PRIV);
    printHexLine(F("b_priv : "), B_PRIV);
    printHexLine(F("K      : "), K);
    printHexLine(F("PLAIN  : "), PLAIN);
    Serial.println();
    /* ---------------------------------------------------------------- */
    /* HSKE-NL-A1 [PQC-HARDENED -- counter-mode with NL-FSCX v1]      */
    /* ---------------------------------------------------------------- */
    Serial.println(F("--- HSKE-NL-A1 [PQC-HARDENED -- counter-mode with NL-FSCX v1]"));
    {
        uint32 N    = lcg_next();              /* per-session nonce            */
        uint32 base = K ^ N;                   /* session key base = K XOR N   */
        uint32 ks   = nl_fscx_revolve_v1(_rol32(base, 4) ^ RNL_KDF_DC, base, V1_MODE_STEPS);
        uint32 E    = PLAIN ^ ks;
        uint32 D    = E ^ ks;
        printHexLine(F("N (nonce) : "), N);
        printHexLine(F("E (Alice) : "), E);
        printHexLine(F("D (Bob)   : "), D);
        check(D == PLAIN,
          F("+ plaintext correctly decrypted"),
          F("[FAIL] decryption failed!"));
    }
    Serial.println();

    demo_finish();
}
