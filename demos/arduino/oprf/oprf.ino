/*  demos/arduino/oprf/oprf.ino -- OPRF (Arduino, 32-bit; TODO #425)
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
    Serial.println(F("=== Herradura KEx demo: OPRF (Arduino, 32-bit) ==="));
    Serial.println();

    /* OPRF (80) — blind / eval / unblind round-trip                     */
    /* ---------------------------------------------------------------- */
    Serial.println(F("--- OPRF (80) [DEMO n=32 -- NOT PRODUCTION SECURE]"));
    {
        /* Fixed params: x = 0x50415353 ("PASS"), k = 0x13579BDF,        */
        /*               r = 7, r_inv = 0x49249249 = 7^{-1} mod 2^32-1  */
        const uint32 oprf_x     = 0x50415353UL;
        const uint32 oprf_k     = 0x13579BDFUL;
        const uint32 oprf_r     = 7UL;
        const uint32 oprf_r_inv = 0x49249249UL;

        uint32 hx     = oprf_hash_to_field_32(oprf_x);
        uint32 alpha  = oprf_blind_32(oprf_x,  oprf_r);
        uint32 beta   = oprf_eval_32(alpha,     oprf_k);
        uint32 F      = oprf_unblind_32(beta,   oprf_r_inv);
        uint32 F_direct = oprf_direct_32(oprf_x, oprf_k);

        printHexLine(F("H(x)  : "), hx);
        printHexLine(F("alpha : "), alpha);
        printHexLine(F("beta  : "), beta);
        printHexLine(F("F     : "), F);
        check(F == F_direct,
          F("+ OPRF blind/eval/unblind correct"),
          F("[FAIL] OPRF round-trip FAILED"));
    }
    Serial.println();

    demo_finish();
}
