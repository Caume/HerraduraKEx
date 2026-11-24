/* Fuzz/pem_diff/pem_diff_c.c — the C reader's side of the PEM reader
 * differential (TODO #403; CliTest/test_pem_reader_diff.sh drives it).
 *
 * stdin: one case per line, the file's bytes in hex.  stdout: one line per
 * case, "OK <label hex> <der hex>" or "ERR <message hex>", where the message is
 * what herradura_cli.c prints after "cannot parse PEM from: PATH: ".  The bytes
 * go to pem_unwrap as the CLI reads them: raw.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../../HerraduraCli/herradura_codec.h"

static void hex_out(const uint8_t *p, size_t n)
{
    size_t i;
    if (n == 0) { fputs("-", stdout); return; }
    for (i = 0; i < n; i++) printf("%02x", p[i]);
}

static int hexval(int c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return -1;
}

int main(void)
{
    size_t cap = 1 << 16, len = 0;
    char *line = malloc(cap);
    int c;
    if (!line) return 2;
    for (;;) {
        len = 0;
        while ((c = getchar()) != EOF && c != '\n') {
            if (len + 1 >= cap) { cap *= 2; line = realloc(line, cap); if (!line) return 2; }
            line[len++] = (char)c;
        }
        if (c == EOF && len == 0) break;
        size_t n = len / 2, i;
        uint8_t *in = malloc(n + 1), *der = malloc(n + 1);
        if (!in || !der) return 2;
        for (i = 0; i < n; i++) {
            int h = hexval(line[2 * i]), l = hexval(line[2 * i + 1]);
            if (h < 0 || l < 0) { fprintf(stderr, "bad hex\n"); return 2; }
            in[i] = (uint8_t)(h << 4 | l);
        }
        char label[PEM_LABEL_MAX + 1];
        size_t dl = 0;
        /* der_cap = the input length: a decode never exceeds it, so B64_ERR_CAP
         * (a full buffer, not a property of the file) cannot occur. */
        int rc = pem_unwrap((const char *)in, n, label, der, n + 1, &dl);
        if (rc == 0) {
            fputs("OK ", stdout);
            hex_out((const uint8_t *)label, strlen(label));
            fputc(' ', stdout);
            hex_out(der, dl);
        } else {
            const char *m = pem_strerror(rc);
            if (!m) { fprintf(stderr, "unnamed pem_unwrap code %d\n", rc); return 2; }
            fputs("ERR ", stdout);
            hex_out((const uint8_t *)m, strlen(m));
        }
        fputc('\n', stdout);
        free(in); free(der);
        if (c == EOF) break;
    }
    free(line);
    return 0;
}
