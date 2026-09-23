/* ChaCha20's block function (RFC 8439 2.3) with the rounds as a loop
 * over a table, for the bank: the SSH client's chacha20.c unrolls them
 * and comes to 4 KB on this CPU, this to under one. The bank builds
 * with this file in place of chacha20.c; the host suite checks the two
 * agree. Only the RFC form, which the AEAD uses. */
#include "crypto.h"

static const uint8_t qr[8][4] = {
  { 0, 4, 8, 12 }, { 1, 5, 9, 13 }, { 2, 6, 10, 14 }, { 3, 7, 11, 15 },
  { 0, 5, 10, 15 }, { 1, 6, 11, 12 }, { 2, 7, 8, 13 }, { 3, 4, 9, 14 }
};

static uint32_t rotl(uint32_t v, uint8_t n) { return (v << n) | (v >> (32 - n)); }

static uint32_t le32(const uint8_t *p) { return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24); }

void chacha20_block(const uint8_t key[32], const uint8_t nonce[12], uint32_t counter, uint8_t out[64])
{
  static const uint8_t sigma[17] = "expand 32-byte k";   /* the NUL is not used */
  uint32_t s[16], x[16];
  uint8_t i, q, a, b, c, d;

  for (i = 0; i < 4; i++) s[i] = le32(sigma + 4 * i);
  for (i = 0; i < 8; i++) s[4 + i] = le32(key + 4 * i);
  s[12] = counter;
  for (i = 0; i < 3; i++) s[13 + i] = le32(nonce + 4 * i);
  for (i = 0; i < 16; i++) x[i] = s[i];
  for (i = 0; i < 10; i++) {
    for (q = 0; q < 8; q++) {
      a = qr[q][0]; b = qr[q][1]; c = qr[q][2]; d = qr[q][3];
      x[a] += x[b]; x[d] = rotl(x[d] ^ x[a], 16);
      x[c] += x[d]; x[b] = rotl(x[b] ^ x[c], 12);
      x[a] += x[b]; x[d] = rotl(x[d] ^ x[a], 8);
      x[c] += x[d]; x[b] = rotl(x[b] ^ x[c], 7);
    }
  }
  for (i = 0; i < 16; i++) {
    uint32_t v = x[i] + s[i];
    out[4 * i] = (uint8_t)v; out[4 * i + 1] = (uint8_t)(v >> 8);
    out[4 * i + 2] = (uint8_t)(v >> 16); out[4 * i + 3] = (uint8_t)(v >> 24);
  }
}
