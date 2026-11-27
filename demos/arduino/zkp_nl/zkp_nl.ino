/*  demos/arduino/zkp_nl/zkp_nl.ino -- ZKP-NL ZKBoo proof (Arduino, 32-bit; TODO #425)
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
    Serial.println(F("=== Herradura KEx demo: ZKP-NL ZKBoo proof (Arduino, 32-bit) ==="));
    Serial.println();

    /* ---------------------------------------------------------------- */
    /* ZKP-NL [ZKBoo MPC-in-the-head; n=8 bits, R=4 rounds]            */
    /* ---------------------------------------------------------------- */
    Serial.println(F("--- ZKP-NL [ZKBoo concept demo; n=8, R=4 rounds]"));
    {
        uint32 A_nl = lcg_next() & 0xFFu;
        uint32 B_nl = lcg_next() & 0xFFu;
        uint32 y_nl = zkp_nl_f1_8(A_nl, B_nl);
        zkp_nl_prove_8(A_nl, B_nl, y_nl, PLAIN);
        int ok = zkp_nl_verify_8(B_nl, y_nl, PLAIN);
        printHexLine(F("A (wit)   : "), A_nl);
        printHexLine(F("B (pub)   : "), B_nl);
        printHexLine(F("y=F1(A,B) : "), y_nl);
        check(ok,
          F("+ ZKP-NL proof verified!"),
          F("[FAIL] ZKP-NL FAILED"));
    }
    Serial.println();

    demo_finish();
}
