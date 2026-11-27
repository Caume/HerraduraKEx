/*  demos/arduino/ratchet/ratchet.ino -- Ratchet (Arduino, 32-bit; TODO #425)
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
    Serial.println(F("=== Herradura KEx demo: Ratchet (Arduino, 32-bit) ==="));
    Serial.println();

    /* Ratchet (78.C)                                                   */
    /* ---------------------------------------------------------------- */
    Serial.println(F("--- Ratchet (78.C) [forward-secret; 32-bit; 5 steps]"));
    {
        uint32 state32 = 0x12345678UL;
        uint32 mk0 = 0, mk;
        bool unique = true;
        for (int i = 0; i < 5; i++) {
            state32 = ratchet_advance_32(state32, &mk);
            if (i == 0) mk0 = mk;
            else if (mk == mk0) unique = false;
        }
        check(unique,
          F("- Ratchet: 5 distinct message keys"),
          F("[FAIL] Ratchet: duplicate message keys!"));
    }
    Serial.println();

    demo_finish();
}
