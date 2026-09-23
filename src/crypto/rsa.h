/* RSASSA-PSS verification (RFC 8017 8.1.2) with SHA-256, MGF1-SHA256
 * and a 32-byte salt, as TLS 1.3's rsa_pss_rsae_sha256: one modular
 * exponentiation over mp.h, then the padding check. Moduli up to 4096
 * bits. Verification only. */
#ifndef RSA_H
#define RSA_H

#include <stdint.h>

/* n and e big-endian without leading zeros; sig of n's length; hash the
 * SHA-256 of the message. 1 if valid. Needs about 3 KB of stack. */
uint8_t rsa_pss_verify(const uint8_t *n, uint16_t nlen, const uint8_t *e, uint16_t elen,
                       const uint8_t *sig, uint16_t siglen, const uint8_t hash[32]);

#endif
