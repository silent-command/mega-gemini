/* HMAC-SHA256 (RFC 2104) and HKDF (RFC 5869) over the SHA-256 in
 * crypto.h, which TLS 1.3 derives every key with. Same style as the
 * rest: C99, stdint.h, no allocation, host-tested against the RFC
 * vectors. Kept out of crypto.h so that file stays identical to the SSH
 * client's. */
#ifndef HKDF_H
#define HKDF_H

#include <stdint.h>
#include <stddef.h>
#include "crypto.h"

typedef struct {
  sha256_ctx inner;
  uint8_t opad[64];
} hmac_ctx;

void hmac_init(hmac_ctx *c, const uint8_t *key, size_t keylen);
void hmac_update(hmac_ctx *c, const uint8_t *p, size_t n);
void hmac_final(hmac_ctx *c, uint8_t out[32]);
void hmac_sha256(const uint8_t *key, size_t keylen, const uint8_t *p, size_t n, uint8_t out[32]);

/* PRK = HMAC(salt, IKM); a null salt is 32 zero bytes. */
void hkdf_extract(const uint8_t *salt, size_t saltlen, const uint8_t *ikm, size_t ikmlen, uint8_t prk[32]);
/* OKM of `outlen` bytes (at most 255 * 32) from PRK and info. */
void hkdf_expand(const uint8_t prk[32], const uint8_t *info, size_t infolen, uint8_t *out, size_t outlen);

#endif
