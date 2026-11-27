/*  demos/arduino/hpks_stern_f/hpks_stern_f.ino -- HPKS-Stern-F signature (Arduino, 32-bit; TODO #425)
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
    Serial.println(F("=== Herradura KEx demo: HPKS-Stern-F signature (Arduino, 32-bit) ==="));
    Serial.println();

    /* ---------------------------------------------------------------- */
    /* HPKS-Stern-F [PQC -- Fiat-Shamir Stern ZKP signature, N=32]     */
    /* ---------------------------------------------------------------- */
    Serial.println(F("--- HPKS-Stern-F [PQC -- Fiat-Shamir Stern ZKP, N=32, t=2, rounds=4]"));
    uint32 sf_seed = 0, sf_synd = 0, sf_e = 0;
    {
        static SternSig32 sf_sig;
        sf_seed = lcg_next();
        sf_e    = stern_rand_error_32();
        sf_synd = stern_syndrome_32(sf_seed, sf_e);
        hpks_stern_f_sign_32(&sf_sig, PLAIN, sf_e, sf_seed);
        int ok = hpks_stern_f_verify_32(&sf_sig, PLAIN, sf_seed, sf_synd);
        printHexLine(F("seed     : "), sf_seed);
        printHexLine(F("error e  : "), sf_e);
        printHexLine(F("syndrome : "), sf_synd);
        check(ok,
          F("+ HPKS-Stern-F verified!"),
          F("[FAIL] HPKS-Stern-F FAILED!"));
    }
    Serial.println();

    Serial.println(F("*** EVE bypass TESTS ***"));

    Serial.println(F("*** HPKS-Stern-F -- Eve forges signature (random data)"));
    {
        static SternSig32 eve_sig;
        for (int i = 0; i < SDF_ROUNDS; i++) {
            eve_sig.c0[i] = lcg_next(); eve_sig.c1[i] = lcg_next();
            eve_sig.c2[i] = lcg_next(); eve_sig.b[i]  = lcg_next() % 3;
            eve_sig.respA[i] = lcg_next(); eve_sig.respB[i] = lcg_next();
        }
        int ok = hpks_stern_f_verify_32(&eve_sig, PLAIN, sf_seed, sf_synd);
        check(!(ok),
          F("- Eve forge rejected (SD soundness)"),
          F("[FAIL] Eve forged signature (soundness failure)!"));
    }

    demo_finish();
}
