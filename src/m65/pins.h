/* The servers' keys, pinned on first use: host, port, the SHA-256 of
 * the SubjectPublicKeyInfo. The table is in bank 1 at $1D000, 16
 * entries; between runs it is GEMHOSTS on the boot disk, the table's
 * 100-byte records as they are (host 64, port 2, pin 32; 5.8). */
#ifndef PINS_H
#define PINS_H

#include <stdint.h>

#define PIN_NEW 0        /* not seen before: now pinned */
#define PIN_KNOWN 1
#define PIN_CHANGED 2    /* seen before with another key: refused by the caller */

void pins_init(void);
void pins_load(unsigned char drive);     /* GEMHOSTS from the drive, if there is one */
unsigned char pins_save(void);           /* the table to GEMHOSTS on the drive loaded from; 1 on success */
extern unsigned char pins_dirty;         /* a pin added or replaced since the last save */
uint8_t pins_check(const char *host, uint16_t port, const uint8_t pin[32]);
void pins_replace(const char *host, uint16_t port, const uint8_t pin[32]);   /* the user's override */

#endif
