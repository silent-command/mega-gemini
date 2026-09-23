/* The MEGA65 side of the kit beyond tlskit.h: bringing the bank up and
 * feeding it entropy. The bank image (CRYPTO on the disk) is loaded to
 * $12000 and the trampoline to $1700 by m65_boot; then INIT. */
#ifndef M65_TLSKIT_H
#define M65_TLSKIT_H

#include <stdint.h>

/* INIT: the bank's crt0. 1 on success. After the image is in place. */
uint8_t m65_tlskit_init(void);

/* Entropy into the bank's pool: hardware samples from the client. */
void m65_tlskit_seed(const uint8_t *p, uint16_t n);

/* 1 if the bank passes its self-test on this machine: 0 the AEAD (RFC 8439, fast), 1 P-256 (RFC 6979, minutes). */
uint8_t m65_tlskit_selftest(uint8_t which);

/* After tk_verify returned TK_WRONG: 1 too long, 2 no certificate, 3 key kind, 4 refused. */
extern uint8_t tk_verify_reason;
extern uint16_t tk_frames_keys, tk_frames_verify;   /* frames the bank spent on the shared secret and the signature (5.12) */

/* The raw body rendered into rows and links by the bank's top window (render.c). */
void m65_tlskit_render(uint32_t from, uint32_t len, uint8_t plain, uint16_t *rows, uint16_t *links, uint8_t *truncated);

#endif
