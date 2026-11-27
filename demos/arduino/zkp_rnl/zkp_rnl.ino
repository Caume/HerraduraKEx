/*  demos/arduino/zkp_rnl/zkp_rnl.ino -- ZKP-RNL Ring-LWR Sigma proof (Arduino, 32-bit; TODO #425)
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
    Serial.println(F("=== Herradura KEx demo: ZKP-RNL Ring-LWR Sigma proof (Arduino, 32-bit) ==="));
    Serial.println();

    /* Alice's Ring-LWR key (the HKEX-RNL demo's keygen) */
    static long m_base[RNL_N], a_rand[RNL_N], m_blind[RNL_N];
    static long s_A[RNL_N], C_A[RNL_N];
    rnl_m_poly(m_base);
    rnl_rand_poly(a_rand);
    rnl_poly_add(m_blind, m_base, a_rand);
    rnl_keygen(s_A, C_A, m_blind);

    /* ---------------------------------------------------------------- */
    /* ZKP-RNL [Lyubashevsky Ring-LWR Sigma-protocol; n=32, t=4]       */
    /* ---------------------------------------------------------------- */
    Serial.println(F("--- ZKP-RNL [Ring-LWR Sigma-protocol; N=32, gamma=4096, t=4]"));
    {
        int ok = rnl_sigma_sign(m_blind, s_A, C_A, PLAIN);
        if (ok) ok = rnl_sigma_verify(m_blind, C_A, PLAIN);
        check(ok,
          F("+ ZKP-RNL proof verified!"),
          F("[FAIL] ZKP-RNL FAILED"));
    }
    Serial.println();

    demo_finish();
}
