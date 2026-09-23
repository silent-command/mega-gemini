/* A page to disk: the response's body, raw, as a SEQ (or PRG) file on
 * the boot disk through the CBM DOS module. */
#ifndef SAVE_H
#define SAVE_H
#include <stdint.h>

/* A name for the file from the URL's last path segment: A-Z, 0-9, else
 * '-', at most 16, "PAGE" if nothing; into out (17 bytes). */
void save_suggest(const char *url, char *out);

/* Writes the raw body from `from` to the end as `name`, PRG if `prg`
 * else SEQ, on `drive`. Returns 0 with *err on failure. The screen must
 * be re-initialised afterwards by the caller. */
uint8_t save_body(const char *name, uint8_t prg, unsigned char drive, uint32_t from, uint32_t to, const char **err);

#endif
