/* libFuzzer harness for herradura_codec.h's der_parse_seq (DER SEQUENCE/INTEGER
 * parsing). Build: clang -fsanitize=fuzzer,address,undefined -I.. -o fuzz_der_parse_seq fuzz_der_parse_seq.c
 * Run:   ./fuzz_der_parse_seq corpus/der_parse_seq
 */
#include <stdint.h>
#include <stddef.h>
#include "../HerraduraCli/herradura_codec.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size == 0) return 0;

    const uint8_t *vals[16];
    size_t vlens[16];
    int n_out = 0;

    (void)der_parse_seq(data, size, vals, vlens, 16, &n_out);
    return 0;
}
