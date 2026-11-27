/*  demos/arduino/hpke/hpke.ino -- HPKE El Gamal encryption (Arduino, 32-bit; TODO #425)
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
    Serial.println(F("=== Herradura KEx demo: HPKE El Gamal encryption (Arduino, 32-bit) ==="));
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
    /* HPKE El Gamal [CLASSICAL]                                       */
    /* ---------------------------------------------------------------- */
    Serial.println(F("--- HPKE El Gamal [CLASSICAL -- not PQC; DLP + linear HSKE]"));
    {
        uint32 r        = lcg_next() | 1;
        uint32 R        = gf_pow_32(GF_GEN, r);
        uint32 enc_key  = gf_pow_32(C, r);
        uint32 hpkeE    = fscx_revolve(PLAIN, enc_key, I_VALUE);
        uint32 dec_key  = gf_pow_32(R, A_PRIV);
        uint32 hpkeD    = fscx_revolve(hpkeE, dec_key, R_VALUE);
        printHexLine(F("R (g^r)   : "), R);
        printHexLine(F("E (Bob)   : "), hpkeE);
        printHexLine(F("D (Alice) : "), hpkeD);
        check(hpkeD == PLAIN,
          F("+ plaintext correctly decrypted"),
          F("[FAIL] decryption failed!"));
    }
    Serial.println();

    demo_finish();
}
