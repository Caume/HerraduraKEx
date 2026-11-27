/*  demos/arduino/fpe/fpe.ino -- FPE (Arduino, 32-bit; TODO #425)
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
    Serial.println(F("=== Herradura KEx demo: FPE (Arduino, 32-bit) ==="));
    Serial.println();

    /* ---------------------------------------------------------------- */
    /* FPE (78.A)                                                       */
    /* ---------------------------------------------------------------- */
    Serial.println(F("--- FPE (78.A) [format-preserving encrypt/decrypt; 32-bit]"));
    {
        uint32 fpe_key = 0xABCD1234UL;
        uint32 fpe_ctx = 0x00000042UL; /* record 66 */
        uint32 fpe_ct  = fpe_encrypt_32(PLAIN, fpe_key, fpe_ctx);
        uint32 fpe_rec = fpe_decrypt_32(fpe_ct, fpe_key, fpe_ctx);
        printHexLine(F("plain  : "), PLAIN);
        printHexLine(F("cipher : "), fpe_ct);
        printHexLine(F("recover: "), fpe_rec);
        check(fpe_rec == PLAIN,
          F("+ FPE round-trip correct"),
          F("[FAIL] FPE round-trip FAILED"));
    }
    Serial.println();

    demo_finish();
}
