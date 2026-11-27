/*  demos/arduino/hpks_stern_ring/hpks_stern_ring.ino -- HPKS-Stern-Ring ring signature (Arduino, 32-bit; TODO #425)
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
    Serial.println(F("=== Herradura KEx demo: HPKS-Stern-Ring ring signature (Arduino, 32-bit) ==="));
    Serial.println();

    /* Alice's Stern key (the HPKS-Stern-F demo's keygen) */
    uint32 sf_seed = lcg_next();
    uint32 sf_e    = stern_rand_error_32();
    uint32 sf_synd = stern_syndrome_32(sf_seed, sf_e);
    printHexLine(F("seed     : "), sf_seed);
    printHexLine(F("syndrome : "), sf_synd);
    Serial.println();

    /* ---------------------------------------------------------------- */
    /* HPKS-Stern-Ring [PQC -- one Stern proof over the ring, N=32]     */
    /* Alice signs as one of two members; the signature does not say    */
    /* which (TODO #424, SPEC.md §11.2).                                */
    /* ---------------------------------------------------------------- */
    Serial.println(F("--- HPKS-Stern-Ring [PQC -- one Stern proof over a k=2 ring, N=32, rounds=4]"));
    {
        static SternRing32 rsig;
        uint32 m_seed = lcg_next();
        uint32 m_synd = stern_syndrome_32(m_seed, stern_rand_error_32());
        int ok = hpks_stern_ring_sign_32(&rsig, PLAIN, sf_e, 1, m_seed, m_synd, sf_seed, sf_synd)
              && hpks_stern_ring_verify_32(&rsig, PLAIN, m_seed, m_synd, sf_seed, sf_synd);
        check(ok,
          F("+ HPKS-Stern-Ring signature verified (k=2; it does not name the signer)"),
          F("[FAIL] HPKS-Stern-Ring verification FAILED"));
        ok = hpks_stern_ring_verify_32(&rsig, PLAIN, sf_seed, sf_synd, m_seed, m_synd);
        check(ok,
          F("+ HPKS-Stern-Ring verified with the ring in the other order"),
          F("[FAIL] HPKS-Stern-Ring refused the reordered ring"));

        Serial.println(F("*** HPKS-Stern-Ring -- Eve changes one opening word / the message"));
        rsig.rw[1][3] ^= 1u;
        ok = hpks_stern_ring_verify_32(&rsig, PLAIN, m_seed, m_synd, sf_seed, sf_synd);
        rsig.rw[1][3] ^= 1u;
        check(!(ok),
          F("- Eve's altered signature refused (the digest no longer matches)"),
          F("[FAIL] Eve's altered ring signature verified!"));
        ok = hpks_stern_ring_verify_32(&rsig, PLAIN ^ 1u, m_seed, m_synd, sf_seed, sf_synd);
        check(!(ok),
          F("- Eve's other message refused"),
          F("[FAIL] ring signature verified another message!"));
    }
    Serial.println();

    demo_finish();
}
