/* HerraduraCli/codec_selftest.c — runs herradura_codec.h's self-test (TODO #401)
 *
 * herradura_codec_selftest() checks base64, the #398 base64 grammar, DER, PEM
 * wrap/unwrap and the #400 framing table with assert().  Before #401 nothing
 * compiled it.  build_c.sh builds this driver as HerraduraCli/codec_selftest_c
 * and build_c_sanitize.sh as codec_selftest_asan; ci.yml runs the first in
 * native-c and the second in sanitizers.
 *
 * Every check is an assert, several with the call under test inside it, so an
 * NDEBUG build would compile them away and pass having checked nothing.  The
 * #error below refuses that build instead.
 */
#ifdef NDEBUG
#error "codec_selftest.c needs assert(): build it without -DNDEBUG"
#endif
#include <assert.h>
#include <stdio.h>

#define HERRADURA_CODEC_SELFTEST
#include "herradura_codec.h"

int main(void)
{
    if (herradura_codec_selftest() != 1) {   /* a failed assert aborts first */
        printf("[FAIL] herradura_codec_selftest did not return 1\n");
        return 1;
    }
    printf("*** OK: herradura_codec.h self-test passed ***\n");
    return 0;
}
