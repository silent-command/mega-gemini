/* AEAD_CHACHA20_POLY1305 (RFC 8439 2.8), the TLS 1.3 record protection
 * of TLS_CHACHA20_POLY1305_SHA256, streamed: a record can be longer than
 * any buffer this client has, so the payload goes through in pieces and
 * the tag is checked at the end. Whatever was decrypted before a bad
 * tag must be thrown away by the caller; nothing acts on it. */
#ifndef AEAD_H
#define AEAD_H

#include <stdint.h>
#include <stddef.h>
#include "crypto.h"

typedef struct {
  uint8_t key[32];
  uint8_t nonce[12];
  uint32_t counter;          /* the next keystream block; 1 for the first byte of payload */
  uint8_t ks[64];            /* the current keystream block */
  uint8_t ks_used;           /* bytes of it consumed, 64 = none left */
  poly1305_ctx poly;
  uint32_t aad_len, ct_len;
} aead_ctx;

/* Starts one record: the one-time Poly1305 key from block 0, the AAD
 * absorbed and padded. */
void aead_start(aead_ctx *c, const uint8_t key[32], const uint8_t nonce[12], const uint8_t *aad, size_t aadlen);
/* Encrypts n bytes in place, authenticating the ciphertext. */
void aead_encrypt(aead_ctx *c, uint8_t *p, size_t n);
/* Authenticates n bytes of ciphertext, then decrypts them in place. */
void aead_decrypt(aead_ctx *c, uint8_t *p, size_t n);
/* The tag over what went through. */
void aead_tag(aead_ctx *c, uint8_t tag[16]);
/* 1 if `tag` is the tag over what went through. */
int aead_check(aead_ctx *c, const uint8_t tag[16]);

#endif
