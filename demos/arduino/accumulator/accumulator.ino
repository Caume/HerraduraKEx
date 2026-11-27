/*  demos/arduino/accumulator/accumulator.ino -- Accumulator (Arduino, 32-bit; TODO #425)
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
    Serial.println(F("=== Herradura KEx demo: Accumulator (Arduino, 32-bit) ==="));
    Serial.println();

    /* ---------------------------------------------------------------- */
    /* Accumulator (78.J)                                               */
    /* ---------------------------------------------------------------- */
    Serial.println(F("--- Accumulator (78.J) [Merkle root + membership; 32-bit]"));
    {
        uint32 leaves[4] = {
            haccum_leaf_32(0xAAAAAAAAUL),
            haccum_leaf_32(0xBBBBBBBBUL),
            haccum_leaf_32(0xCCCCCCCCUL),
            haccum_leaf_32(0xDDDDDDDDUL),
        };
        uint32 root = haccum_root_32(leaves, 4);
        /* manual proof for index 2: sibling is leaves[3], parent's sibling is node(l[0],l[1]) */
        uint32 sib0 = leaves[3];
        uint32 sib1 = haccum_node_32(leaves[0], leaves[1]);
        uint32 cur  = haccum_node_32(leaves[2], sib0);
        cur         = haccum_node_32(sib1, cur);
        printHexLine(F("root         : "), root);
        printHexLine(F("verify (idx2): "), cur);
        check(cur == root,
          F("+ Accumulator proof correct"),
          F("[FAIL] Accumulator proof FAILED"));
        Serial.println(F("*** EVE: a member's proof path for a leaf not in the set"));
        uint32 eve = haccum_node_32(sib1, haccum_node_32(haccum_leaf_32(0xEEEEEEEEUL), sib0));
        check(eve != root,
          F("- Eve's leaf with a member's proof path refused (the root differs)"),
          F("[FAIL] a leaf outside the set verified!"));
    }
    Serial.println();

    demo_finish();
}
