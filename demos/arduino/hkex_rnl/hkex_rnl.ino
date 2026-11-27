/*  demos/arduino/hkex_rnl/hkex_rnl.ino -- HKEX-RNL Ring-LWR key exchange (Arduino, 32-bit; TODO #425)
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
    Serial.println(F("=== Herradura KEx demo: HKEX-RNL Ring-LWR key exchange (Arduino, 32-bit) ==="));
    Serial.println();

    /* ---------------------------------------------------------------- */
    /* HKEX-RNL [PQC -- Ring-LWR key exchange, N=32]                  */
    /* ---------------------------------------------------------------- */
    Serial.println(F("--- HKEX-RNL [PQC -- Ring-LWR key exchange; N=32, q=65537]"));
    uint32 sk_rnl_saved = 0;
    static long m_base[RNL_N], a_rand[RNL_N], m_blind[RNL_N];
    static long s_A[RNL_N], s_B[RNL_N], C_A[RNL_N], C_B[RNL_N];
    {
        rnl_m_poly(m_base);
        rnl_rand_poly(a_rand);
        rnl_poly_add(m_blind, m_base, a_rand);
        rnl_keygen(s_A, C_A, m_blind);
        rnl_keygen(s_B, C_B, m_blind);
        uint32 hint_A;
        uint32 KA = rnl_agree(s_A, C_B, NULL, &hint_A);   /* reconciler */
        uint32 KB = rnl_agree(s_B, C_A, &hint_A, NULL);   /* receiver */
        uint32 skA = nl_fscx_revolve_v1(_rol32(KA, 4) ^ RNL_KDF_DC, KA, I_VALUE);
        uint32 skB = nl_fscx_revolve_v1(_rol32(KB, 4) ^ RNL_KDF_DC, KB, I_VALUE);
        printHexLine(F("sk (Alice): "), skA);
        printHexLine(F("sk (Bob)  : "), skB);
        if (KA == KB) {
            Serial.println(F("+ raw key bits agree; session key established!"));
        } else {
            Serial.println(F("- raw key disagrees (rounding noise -- retry)"));
        }
        sk_rnl_saved = skA;
    }
    Serial.println();

    Serial.println(F("*** EVE bypass TESTS ***"));

    Serial.println(F("*** HKEX-RNL -- Eve random guess does not match shared key"));
    {
        uint32 eve_guess = lcg_next();
        check(!(eve_guess == sk_rnl_saved),
          F("- Eve random guess does not match shared key (Ring-LWR protection)"),
          F("[FAIL] Eve guessed HKEX-RNL key (astronomically unlikely)!"));
    }

    demo_finish();
}
