/*  demos/arduino/masked_hske/masked_hske.ino -- Masked HSKE (Arduino, 32-bit; TODO #425)
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
    Serial.println(F("=== Herradura KEx demo: Masked HSKE (Arduino, 32-bit) ==="));
    Serial.println();

    /* Masked HSKE (78.H)                                               */
    /* ---------------------------------------------------------------- */
    Serial.println(F("--- Masked HSKE (78.H) [GF(2)-linearity masking; 32-bit]"));
    {
        uint32 plain32 = 0xDEADC0DEUL;
        uint32 key32   = 0xCAFEBABEUL;
        uint32 mask32  = 0xA5A5A5A5UL;
        uint32 ct32    = hske_encrypt_masked_32(plain32, key32, mask32);
        uint32 rec32   = hske_decrypt_masked_32(ct32,    key32, mask32);
        printHexLine(F("cipher : "), ct32);
        printHexLine(F("recover: "), rec32);
        check(rec32 == plain32,
          F("+ Masked HSKE correct"),
          F("[FAIL] Masked HSKE FAILED"));
    }
    Serial.println();

    demo_finish();
}
