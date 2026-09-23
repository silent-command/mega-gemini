#include "aead.h"

static const uint8_t zeros[16] = { 0 };

static void pad16(aead_ctx *c, uint32_t len)
{
  if (len & 15) poly1305_update(&c->poly, zeros, 16 - (len & 15));
}

void aead_start(aead_ctx *c, const uint8_t key[32], const uint8_t nonce[12], const uint8_t *aad, size_t aadlen)
{
  uint8_t i;
  for (i = 0; i < 32; i++) c->key[i] = key[i];
  for (i = 0; i < 12; i++) c->nonce[i] = nonce[i];
  chacha20_block(key, nonce, 0, c->ks);            /* the one-time key is the first 32 bytes of block 0 */
  poly1305_init(&c->poly, c->ks);
  c->counter = 1;
  c->ks_used = 64;
  c->aad_len = (uint32_t)aadlen;
  c->ct_len = 0;
  if (aadlen) poly1305_update(&c->poly, aad, aadlen);
  pad16(c, c->aad_len);
}

static void xor_stream(aead_ctx *c, uint8_t *p, size_t n)
{
  while (n) {
    if (c->ks_used == 64) { chacha20_block(c->key, c->nonce, c->counter++, c->ks); c->ks_used = 0; }
    *p++ ^= c->ks[c->ks_used++];
    n--;
  }
}

void aead_encrypt(aead_ctx *c, uint8_t *p, size_t n)
{
  xor_stream(c, p, n);
  poly1305_update(&c->poly, p, n);
  c->ct_len += (uint32_t)n;
}

void aead_decrypt(aead_ctx *c, uint8_t *p, size_t n)
{
  poly1305_update(&c->poly, p, n);
  c->ct_len += (uint32_t)n;
  xor_stream(c, p, n);
}

void aead_tag(aead_ctx *c, uint8_t tag[16])
{
  uint8_t lens[16];
  uint8_t i;
  pad16(c, c->ct_len);
  for (i = 0; i < 16; i++) lens[i] = 0;
  for (i = 0; i < 4; i++) { lens[i] = (uint8_t)(c->aad_len >> (8 * i)); lens[8 + i] = (uint8_t)(c->ct_len >> (8 * i)); }
  poly1305_update(&c->poly, lens, 16);
  poly1305_final(&c->poly, tag);
}

int aead_check(aead_ctx *c, const uint8_t tag[16])
{
  uint8_t t[16];
  aead_tag(c, t);
  return crypto_equal(t, tag, 16);
}
