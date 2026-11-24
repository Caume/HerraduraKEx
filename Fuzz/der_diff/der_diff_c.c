/* Fuzz/der_diff/der_diff_c.c — the C parser's side of the DER parser
 * differential (TODO #404; CliTest/test_der_reader_diff.sh drives it).
 *
 * stdin: one case per line, the DER bytes in hex.  stdout: one line per case,
 * "OK v/w/z ..." (each INTEGER's value in minimal hex, its encoded width and
 * lead, as der_seq_scan reports them) or "ERR <message hex>".  The steps and
 * texts are pem_key_load's (herradura_cli.c), for the label "L":
 * der_seq_check (TODO #405), then der_seq_scan, then der_parse_seq, which
 * cannot fail after the check (a failure is printed as EXC, a finding).  The
 * CLI stores 16 items; this
 * driver stores DIFF_MAX so it can print every value -- the 16-item path is
 * held by the codec self-test and by the test's CLI cells.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../../HerraduraCli/herradura_codec.h"

#define DIFF_MAX 4096

static int hexval(int c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return -1;
}

static void err(const char *m)
{
    fputs("ERR ", stdout);
    for (; *m; m++) printf("%02x", (unsigned char)*m);
    fputc('\n', stdout);
}

static size_t ew[DIFF_MAX];
static unsigned char lz[DIFF_MAX];
static const uint8_t *vals[DIFF_MAX];
static size_t vlens[DIFF_MAX];

int main(void)
{
    size_t cap = 1 << 16, len;
    char *line = malloc(cap), msg[256];
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
        uint8_t *d = malloc(n + 1);
        if (!d) return 2;
        for (i = 0; i < n; i++) {
            int h = hexval(line[2 * i]), l = hexval(line[2 * i + 1]);
            if (h < 0 || l < 0) { fprintf(stderr, "bad hex\n"); return 2; }
            d[i] = (uint8_t)(h << 4 | l);
        }
        int bad = 0, rc, k = 0;
        if (der_seq_check("L", d, n, msg, sizeof msg)) {
            err(msg);
        } else if ((rc = der_seq_scan(d, n, ew, lz, DIFF_MAX, &bad)) != 0) {
            snprintf(msg, sizeof msg, "EXC der_seq_scan returned %d after der_seq_check passed", rc);
            err(msg);
        } else if ((rc = der_parse_seq(d, n, vals, vlens, DIFF_MAX, &k)) != 0) {
            err(rc == DER_ERR_ITEMS ? "more items than the driver stores"
                                    : "EXC der_parse_seq failed after der_seq_check passed");
        } else {
            fputs("OK", stdout);
            for (int j = 0; j < k; j++) {
                size_t a = 0;
                while (a < vlens[j] && vals[j][a] == 0) a++;
                fputc(' ', stdout);
                if (a == vlens[j]) fputc('0', stdout);
                else {
                    printf("%x", vals[j][a++]);
                    for (; a < vlens[j]; a++) printf("%02x", vals[j][a]);
                }
                printf("/%zu/%d", ew[j], lz[j]);
            }
            fputc('\n', stdout);
        }
        free(d);
        if (c == EOF) break;
    }
    free(line);
    return 0;
}
