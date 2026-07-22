/* libFuzzer harness for herradura_codec.h's pem_unwrap (PEM parsing + base64
 * decode). Build: clang -fsanitize=fuzzer,address,undefined -I.. -o fuzz_pem_unwrap fuzz_pem_unwrap.c
 * Run:   ./fuzz_pem_unwrap corpus/pem_unwrap
 */
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "../HerraduraCli/herradura_codec.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size == 0) return 0;

    char label[PEM_LABEL_MAX + 1];
    /* Deliberately undersized relative to worst-case input, to also exercise
     * pem_unwrap's der_cap rejection path (not just well-formed decodes). */
    size_t der_cap = 256;
    uint8_t *der = (uint8_t *)malloc(der_cap);
    if (!der) return 0;
    size_t der_len = 0;

    char *buf = (char *)malloc(size);
    if (!buf) { free(der); return 0; }
    memcpy(buf, data, size);

    (void)pem_unwrap(buf, size, label, der, der_cap, &der_len);

    free(buf);
    free(der);
    return 0;
}
