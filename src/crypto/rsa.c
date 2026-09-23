#include "rsa.h"
#include "mp.h"
#include "crypto.h"

#define ctx mp_shared

/* MGF1-SHA256(seed, out): the mask, XORed into out. */
static void mgf1_xor(const uint8_t seed[32], uint8_t *out, uint16_t len)
{
  sha256_ctx c;
  uint8_t ctr[4] = { 0, 0, 0, 0 }, block[32];
  uint16_t done = 0, i;
  while (done < len) {
    sha256_init(&c); sha256_update(&c, seed, 32); sha256_update(&c, ctr, 4); sha256_final(&c, block);
    for (i = 0; i < 32 && done < len; i++) out[done++] ^= block[i];
    ctr[3]++;
  }
}

uint8_t rsa_pss_verify(const uint8_t *n, uint16_t nlen, const uint8_t *e, uint16_t elen,
                       const uint8_t *sig, uint16_t siglen, const uint8_t hash[32])
{
  mp_limb *s = mp_scratch, *m = mp_scratch + MP_MAX_LIMBS;   /* the bank keeps sig where m will go: read before m is written, and mp_init multiplies (5.12) */
  uint8_t *em = (uint8_t *)ctx.rr;                 /* R^2 is not needed after the exponentiation */
  uint16_t embits, emlen, dblen, i;
  uint8_t h[32], top_bits;
  sha256_ctx c;

  if (nlen < 128 || nlen > 2 * MP_MAX_LIMBS || (nlen & 3) || siglen != nlen || !(n[0] & 0x80)) return 0;   /* whole 32-bit limbs, the top bit set: the machine's multiplier (5.12) */
  mp_init(&ctx, n, nlen);
  mp_from_be(&ctx, s, sig, siglen);
  if (mp_cmp(&ctx, s, ctx.m) >= 0) return 0;
  mp_to_mont(&ctx, s, s);
  mp_mont_exp(&ctx, m, s, e, elen);
  mp_from_mont(&ctx, m, m);

  /* EM of emLen = ceil((modBits - 1) / 8) bytes; modBits = 8 nlen since n's top bit is set */
  embits = (uint16_t)(8 * nlen - 1);
  emlen = (uint16_t)((embits + 7) / 8);            /* = nlen */
  mp_to_be(&ctx, m, em, emlen);
  if (emlen < 32 + 32 + 2) return 0;
  if (em[emlen - 1] != 0xbc) return 0;
  dblen = (uint16_t)(emlen - 32 - 1);
  for (i = 0; i < 32; i++) h[i] = em[dblen + i];
  mgf1_xor(h, em, dblen);                          /* DB = maskedDB xor MGF1(H) */
  top_bits = (uint8_t)(8 * emlen - embits);        /* the leftmost bits of DB are cleared */
  em[0] &= (uint8_t)(0xff >> top_bits);
  /* DB = zeros, 0x01, salt(32) */
  for (i = 0; i + 33 < dblen; i++) if (em[i]) return 0;
  if (em[dblen - 33] != 0x01) return 0;
  /* H' = SHA-256(8 zeros, mHash, salt) */
  { static const uint8_t zeros[8] = { 0 };
    sha256_init(&c); sha256_update(&c, zeros, 8); sha256_update(&c, hash, 32);
    sha256_update(&c, em + dblen - 32, 32); sha256_final(&c, em); }
  return (uint8_t)crypto_equal(em, h, 32);
}
