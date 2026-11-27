/*  demos/arduino/tweakable/tweakable.ino -- Tweakable cipher (Arduino, 32-bit; TODO #425)
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
    Serial.println(F("=== Herradura KEx demo: Tweakable cipher (Arduino, 32-bit) ==="));
    Serial.println();

    /* ---------------------------------------------------------------- */
    /* Tweakable cipher (78.B)                                          */
    /* ---------------------------------------------------------------- */
    Serial.println(F("--- Tweakable cipher (78.B) [sector/block tweak; 32-bit]"));
    {
        uint32 twk_key = 0x12345678UL;
        uint32 twk_ct  = twk_encrypt_32(PLAIN, twk_key, 7, 3);
        uint32 twk_rec = twk_decrypt_32(twk_ct, twk_key, 7, 3);
        printHexLine(F("plain  : "), PLAIN);
        printHexLine(F("cipher : "), twk_ct);
        printHexLine(F("recover: "), twk_rec);
        check(twk_rec == PLAIN,
          F("+ Tweakable cipher correct"),
          F("[FAIL] Tweakable cipher FAILED"));
    }
    Serial.println();

    demo_finish();
}
