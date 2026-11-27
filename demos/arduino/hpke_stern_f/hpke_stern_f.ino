/*  demos/arduino/hpke_stern_f/hpke_stern_f.ino -- HPKE-Stern-F KEM (Arduino, 32-bit; TODO #425)
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
    Serial.println(F("=== Herradura KEx demo: HPKE-Stern-F KEM (Arduino, 32-bit) ==="));
    Serial.println();

    /* Alice's Stern key (the HPKS-Stern-F demo's keygen) */
    uint32 sf_seed = lcg_next();
    uint32 sf_e    = stern_rand_error_32();
    uint32 sf_synd = stern_syndrome_32(sf_seed, sf_e);
    printHexLine(F("seed     : "), sf_seed);
    printHexLine(F("syndrome : "), sf_synd);
    Serial.println();

    /* ---------------------------------------------------------------- */
    /* HPKE-Stern-F [PQC -- Niederreiter KEM, N=32, t=2]               */
    /* ---------------------------------------------------------------- */
    Serial.println(F("--- HPKE-Stern-F [PQC -- Niederreiter KEM, N=32, t=2]"));
    uint32 sf_K_enc_saved = 0;
    {
        uint32 e_prime, ct;
        sf_K_enc_saved = hpke_stern_f_encap_32(sf_seed, &ct, &e_prime);
        uint32 K_dec   = hpke_stern_f_decap_32(sf_seed, e_prime);
        printHexLine(F("ct       : "), ct);
        printHexLine(F("K (enc)  : "), sf_K_enc_saved);
        printHexLine(F("K (dec)  : "), K_dec);
        check(sf_K_enc_saved == K_dec,
          F("+ HPKE-Stern-F KEM keys agree!"),
          F("[FAIL] HPKE-Stern-F KEM keys differ!"));
    }
    Serial.println();

    Serial.println(F("*** EVE bypass TESTS ***"));

    Serial.println(F("*** HPKE-Stern-F -- Eve random guess vs KEM key"));
    {
        uint32 eve_K = lcg_next();
        check(!(eve_K == sf_K_enc_saved),
          F("- Eve random K does not match KEM key (SD protection)"),
          F("[FAIL] Eve guessed KEM key (astronomically unlikely)!"));
    }
    Serial.println();

    demo_finish();
}
