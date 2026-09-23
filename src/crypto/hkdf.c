#include "hkdf.h"

void hmac_init(hmac_ctx *c, const uint8_t *key, size_t keylen)
{
  uint8_t k[64];
  uint8_t i;
  for (i = 0; i < 64; i++) k[i] = 0;
  if (keylen > 64) sha256(key, keylen, k);
  else for (i = 0; i < keylen; i++) k[i] = key[i];
  for (i = 0; i < 64; i++) { c->opad[i] = (uint8_t)(k[i] ^ 0x5c); k[i] ^= 0x36; }
  sha256_init(&c->inner);
  sha256_update(&c->inner, k, 64);
}

void hmac_update(hmac_ctx *c, const uint8_t *p, size_t n)
{
  sha256_update(&c->inner, p, n);
}

void hmac_final(hmac_ctx *c, uint8_t out[32])
{
  sha256_ctx outer;
  sha256_final(&c->inner, out);
  sha256_init(&outer);
  sha256_update(&outer, c->opad, 64);
  sha256_update(&outer, out, 32);
  sha256_final(&outer, out);
}

void hmac_sha256(const uint8_t *key, size_t keylen, const uint8_t *p, size_t n, uint8_t out[32])
{
  hmac_ctx c;
  hmac_init(&c, key, keylen);
  hmac_update(&c, p, n);
  hmac_final(&c, out);
}

void hkdf_extract(const uint8_t *salt, size_t saltlen, const uint8_t *ikm, size_t ikmlen, uint8_t prk[32])
{
  static const uint8_t zero[32] = { 0 };
  if (!salt) { salt = zero; saltlen = 32; }
  hmac_sha256(salt, saltlen, ikm, ikmlen, prk);
}

void hkdf_expand(const uint8_t prk[32], const uint8_t *info, size_t infolen, uint8_t *out, size_t outlen)
{
  hmac_ctx c;
  uint8_t t[32], ctr = 0, i;
  size_t done = 0, take;
  while (done < outlen) {
    ctr++;
    hmac_init(&c, prk, 32);
    if (ctr > 1) hmac_update(&c, t, 32);
    hmac_update(&c, info, infolen);
    hmac_update(&c, &ctr, 1);
    hmac_final(&c, t);
    take = outlen - done < 32 ? outlen - done : 32;
    for (i = 0; i < take; i++) out[done + i] = t[i];
    done += take;
  }
}
