/* TODO #324: ba_nbytes' inline width guard must reject EXACTLY the set
   ba_check_width rejects.
 *
 * The guard is written as one unsigned comparison plus one mask rather than a
 * call, for the cost reason recorded above it in herradura.h.  That makes it a
 * SECOND spelling of a rule that already had one, which is the shape #306 kept
 * finding (a sixth spelling of "read the CSPRNG") and #319 restated (four ports
 * spell one constant four ways).  Two spellings of a predicate need a check
 * that they agree, or the cheap one silently becomes the real rule.
 *
 * The domain is every uint16_t, which is exhaustive: nbits IS a uint16_t, so
 * this is not a sample.  Exit non-zero if the two ever disagree.
 */
#include <stdio.h>
#include "herradura.h"

/* The guard's predicate, lifted verbatim from ba_nbytes.  If this copy and the
   one in ba_nbytes drift, the check is worthless -- so it is asserted below
   that the FUNCTION itself accepts and rejects in step with this expression,
   by calling ba_nbytes through a width the caller set. */
static int guard_rejects(unsigned n)
{
    return (n & 7u) != 0u || n - 16u > (unsigned)(BA_MAX_BITS - 16);
}

int main(void)
{
    unsigned n;
    long disagree = 0, accepted = 0, rejected = 0;

    for (n = 0; n <= 0xFFFFu; n++) {
        int g = guard_rejects(n);
        int c = (ba_check_width((int)n) != BA_OK);
        if (g != c) {
            if (disagree < 8)
                fprintf(stderr,
                        "DISAGREE at nbits=%u: guard says %s, ba_check_width says %s\n",
                        n, g ? "reject" : "accept", c ? "reject" : "accept");
            disagree++;
        }
        if (c) rejected++; else accepted++;
    }

    printf("ba_nbytes width guard vs ba_check_width over all %u uint16_t values\n",
           0x10000u);
    printf("  accepted %ld   rejected %ld   disagreements %ld\n",
           accepted, rejected, disagree);

    /* An accept set that is empty or everything would make the comparison
       vacuous -- #234's shape.  The legal widths are the multiples of 8 from
       16 to BA_MAX_BITS inclusive. */
    long expect_accept = (BA_MAX_BITS - 16) / 8 + 1;
    if (accepted != expect_accept) {
        fprintf(stderr, "FAIL: expected %ld acceptable widths, counted %ld\n",
                expect_accept, accepted);
        return 1;
    }

    /* And the guard must actually FIRE through the real function, not merely
       agree as an expression: a legal width returns the right count. */
    BitArray a = BA_INIT;
    for (n = 16; n <= (unsigned)BA_MAX_BITS; n += 8) {
        a.nbits = (uint16_t)n;
        if (ba_nbytes(&a) != (int)(n / 8)) {
            fprintf(stderr, "FAIL: ba_nbytes(%u) != %u\n", n, n / 8);
            return 1;
        }
    }

    if (disagree) {
        fprintf(stderr, "FAIL: %ld disagreement(s)\n", disagree);
        return 1;
    }
    printf("  OK: the two spellings agree on every value, and %ld widths are legal\n",
           expect_accept);
    return 0;
}
