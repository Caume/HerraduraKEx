/*  demos/arduino/hpke_nl/hpke_nl.ino -- HPKE-NL El Gamal encryption (Arduino, 32-bit; TODO #425)
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
    Serial.println(F("=== Herradura KEx demo: HPKE-NL El Gamal encryption (Arduino, 32-bit) ==="));
    Serial.println();

    printHexLine(F("a_priv : "), A_PRIV);
    printHexLine(F("b_priv : "), B_PRIV);
    printHexLine(F("K      : "), K);
    printHexLine(F("PLAIN  : "), PLAIN);
    Serial.println();
    uint32 C = gf_pow_32(GF_GEN, A_PRIV);   /* Alice's public key */
    printHexLine(F("C (g^a)   : "), C);
    Serial.println();

    /* ---------------------------------------------------------------- */
    /* HPKE-NL [NL-hardened El Gamal -- NL-FSCX v2 encryption]        */
    /* ---------------------------------------------------------------- */
    Serial.println(F("--- HPKE-NL [NL-hardened El Gamal -- NL-FSCX v2 encryption]"));
    uint32 E_nl_saved = 0, R_nl2_saved = 0;
    {
        uint32 r_nl    = lcg_next() | 1;
        uint32 R_nl2   = gf_pow_32(GF_GEN, r_nl);
        uint32 enc_nl  = gf_pow_32(C, r_nl);
        uint32 E_nl    = nl_fscx_revolve_v2(PLAIN, enc_nl, I_VALUE);
        uint32 dec_nl  = gf_pow_32(R_nl2, A_PRIV);
        uint32 D_nl    = nl_fscx_revolve_v2_inv(E_nl, dec_nl, I_VALUE);
        printHexLine(F("E (Bob)   : "), E_nl);
        printHexLine(F("D (Alice) : "), D_nl);
        check(D_nl == PLAIN,
          F("+ plaintext correctly decrypted"),
          F("[FAIL] decryption failed!"));
        E_nl_saved  = E_nl;
        R_nl2_saved = R_nl2;
    }
    Serial.println();

    Serial.println(F("*** EVE bypass TESTS ***"));

    Serial.println(F("*** HPKE-NL -- Eve uses wrong key (C XOR R instead of C^r)"));
    {
        uint32 eve_key = C ^ R_nl2_saved;
        uint32 D_eve   = nl_fscx_revolve_v2_inv(E_nl_saved, eve_key, I_VALUE);
        check(!(D_eve == PLAIN),
          F("- Eve could not decrypt (CDH + NL protection)"),
          F("[FAIL] Eve decrypted (Eve wins)!"));
    }

    demo_finish();
}
