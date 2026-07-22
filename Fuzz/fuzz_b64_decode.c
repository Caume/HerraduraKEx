/* libFuzzer harness for herradura_codec.h's b64_decode.
 * Build: clang -fsanitize=fuzzer,address,undefined -I.. -o fuzz_b64_decode fuzz_b64_decode.c
 * Run:   ./fuzz_b64_decode corpus/b64_decode
 */
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include "../HerraduraCli/herradura_codec.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Undersized relative to worst-case decode length so the out_cap
     * rejection path gets exercised, not just successful decodes. */
    size_t out_cap = size / 8 + 1;
    uint8_t *out = (uint8_t *)malloc(out_cap);
    if (!out) return 0;
    size_t out_len = 0;

    (void)b64_decode((const char *)data, size, out, out_cap, &out_len);

    free(out);
    return 0;
}
