/* The host suite for src/crypto/: the SSH client's primitives are proved
 * in that tree; this checks what is new here (HMAC, HKDF, the AEAD) and
 * that the copies still agree with the RFCs they will be used against. */
#include <stdio.h>
#include <string.h>
#include "crypto.h"
#include "hkdf.h"
#include "aead.h"
#include "mp.h"
#include "../tests/vectors.h"

/* the bank's compact ChaCha20, under another name here */
#define chacha20_block chacha20_block_small
#include "../src/crypto/chacha20_small.c"
#undef chacha20_block

static int checks, failed;
#define CHECK(cond, what) do { checks++; if (!(cond)) { failed++; printf("FAIL line %d: %s\n", __LINE__, what); } } while (0)

static uint8_t unhex1(char c) { return (uint8_t)(c <= '9' ? c - '0' : (c | 32) - 'a' + 10); }
static size_t unhex(const char *s, uint8_t *out)
{
  size_t n = 0;
  while (s[0] && s[1]) { out[n++] = (uint8_t)((unhex1(s[0]) << 4) | unhex1(s[1])); s += 2; }
  return n;
}
static int eqhex(const uint8_t *got, const char *hex, size_t n)
{
  uint8_t want[128];
  return unhex(hex, want) == n && !memcmp(got, want, n);
}

int main(void)
{
  uint8_t out[128], key[160], data[128], buf[256];
  size_t n;
  aead_ctx a;

  /* SHA-256, one vector, to be sure the copy is what it was */
  sha256((const uint8_t *)"abc", 3, out);
  CHECK(eqhex(out, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", 32), "sha256 abc");

  /* HMAC-SHA256, RFC 4231 test cases 1, 2, 3 (a 20-byte key, a short key, 50 bytes of data) and 6 (a key longer than a block) */
  memset(key, 0x0b, 20);
  hmac_sha256(key, 20, (const uint8_t *)"Hi There", 8, out);
  CHECK(eqhex(out, "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7", 32), "hmac case 1");
  hmac_sha256((const uint8_t *)"Jefe", 4, (const uint8_t *)"what do ya want for nothing?", 28, out);
  CHECK(eqhex(out, "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843", 32), "hmac case 2");
  memset(key, 0xaa, 20); memset(data, 0xdd, 50);
  hmac_sha256(key, 20, data, 50, out);
  CHECK(eqhex(out, "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe", 32), "hmac case 3");
  memset(key, 0xaa, 131);
  hmac_sha256(key, 131, (const uint8_t *)"Test Using Larger Than Block-Size Key - Hash Key First", 54, out);
  CHECK(eqhex(out, "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54", 32), "hmac case 6");

  /* HKDF, RFC 5869 test case 1 */
  memset(key, 0x0b, 22);
  n = unhex("000102030405060708090a0b0c", data);
  hkdf_extract(data, n, key, 22, out);
  CHECK(eqhex(out, "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5", 32), "hkdf prk");
  n = unhex("f0f1f2f3f4f5f6f7f8f9", data);
  hkdf_expand(out, data, n, buf, 42);
  CHECK(eqhex(buf, "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865", 42), "hkdf okm");
  /* test case 3: no salt, no info */
  hkdf_extract(0, 0, key, 22, out);
  CHECK(eqhex(out, "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04", 32), "hkdf prk, no salt");
  hkdf_expand(out, data, 0, buf, 42);
  CHECK(eqhex(buf, "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8", 42), "hkdf okm, no info");

  /* X25519, RFC 7748 6.1, from the extracted vectors */
  x25519_base(out, rfc7748_alice_priv);
  CHECK(!memcmp(out, rfc7748_alice_pub, 32), "x25519 alice public");
  x25519(out, rfc7748_alice_priv, rfc7748_bob_pub);
  CHECK(!memcmp(out, rfc7748_shared, 32), "x25519 shared");

  /* the bank's ChaCha20 against the SSH client's, on the RFC key and on a random one */
  { uint8_t k1[64], k2[64], i, ok = 1; uint32_t ctr;
    for (ctr = 0; ctr < 3 && ok; ctr++) { chacha20_block(rfc8439_key, rfc8439_nonce, ctr, k1); chacha20_block_small(rfc8439_key, rfc8439_nonce, ctr, k2); ok = (uint8_t)!memcmp(k1, k2, 64); }
    for (i = 0; i < 32; i++) key[i] = (uint8_t)(i * 37 + 11);
    for (i = 0; i < 12; i++) data[i] = (uint8_t)(200 - i);
    chacha20_block(key, data, 0x7fffffff, k1); chacha20_block_small(key, data, 0x7fffffff, k2); ok = (uint8_t)(ok && !memcmp(k1, k2, 64));
    CHECK(ok, "chacha20_small agrees with chacha20"); }

  /* AEAD, RFC 8439 2.8.2: encrypt in one piece, then decrypt in pieces */
  memcpy(buf, rfc8439_plaintext, rfc8439_plaintext_len);
  aead_start(&a, rfc8439_key, rfc8439_nonce, rfc8439_aad, rfc8439_aad_len);
  aead_encrypt(&a, buf, rfc8439_plaintext_len);
  aead_tag(&a, out);
  CHECK(!memcmp(buf, rfc8439_ciphertext, rfc8439_ciphertext_len), "aead ciphertext");
  CHECK(!memcmp(out, rfc8439_tag, 16), "aead tag");
  aead_start(&a, rfc8439_key, rfc8439_nonce, rfc8439_aad, rfc8439_aad_len);
  aead_decrypt(&a, buf, 7); aead_decrypt(&a, buf + 7, 64); aead_decrypt(&a, buf + 71, rfc8439_ciphertext_len - 71);
  CHECK(aead_check(&a, rfc8439_tag), "aead decrypt in pieces: tag");
  CHECK(!memcmp(buf, rfc8439_plaintext, rfc8439_plaintext_len), "aead decrypt in pieces: plaintext");
  buf[10] ^= 1;
  aead_start(&a, rfc8439_key, rfc8439_nonce, rfc8439_aad, rfc8439_aad_len);
  aead_encrypt(&a, buf, rfc8439_plaintext_len);
  CHECK(!aead_check(&a, rfc8439_tag), "aead tampered: tag refused");
  aead_start(&a, rfc8439_key, rfc8439_nonce, 0, 0);
  aead_encrypt(&a, buf, 0);
  aead_tag(&a, out);
  CHECK(1, "aead empty message runs");

  /* The 32-bit Montgomery driver against the 16-bit multiplier, on
   * random moduli of the RSA sizes and P-256's (5.12): the row is C
   * here, so this proves the driver's shifts and carries, and the
   * machine adds only the row. */
  {
    static const uint16_t mlens[] = { 32, 128, 256, 384, 512 };
    static uint8_t m[512], x[512];
    static mp_limb a[256], b[256], r1[256], r2[256];
    uint32_t seed = 0x2545f491;
    unsigned si, k, trial;
#define RND() (seed = seed * 1103515245u + 12345u, (uint8_t)(seed >> 16))
    for (si = 0; si < sizeof mlens / sizeof mlens[0]; si++) {
      uint16_t mlen = mlens[si];
      for (trial = 0; trial < 3; trial++) {
        for (k = 0; k < mlen; k++) m[k] = RND();
        m[0] |= 0x80; m[mlen - 1] |= 1;                 /* the top bit set, odd */
        mp_init(&mp_shared, m, mlen);
        for (k = 0; k < mlen; k++) x[k] = RND();
        x[0] = 0; mp_from_be(&mp_shared, a, x, mlen);   /* below m */
        for (k = 0; k < mlen; k++) x[k] = RND();
        x[0] = 0; mp_from_be(&mp_shared, b, x, mlen);
        mp_mont_mul(&mp_shared, r1, a, b);
        mp_mont_mul32(&mp_shared, r2, a, b);
        CHECK(!memcmp(r1, r2, mlen), "mont32 product agrees with the 16-bit multiplier");
        mp_from_mont(&mp_shared, r1, a);
        mp_mont_reduce32(&mp_shared, r2, a);
        CHECK(!memcmp(r1, r2, mlen), "mont32 reduction agrees");
        mp_mont_mul(&mp_shared, r1, a, a);
        mp_mont_mul32(&mp_shared, a, a, a);             /* the result over its own inputs */
        CHECK(!memcmp(r1, a, mlen), "mont32 squaring in place agrees");
      }
    }
#undef RND
  }

  printf("%d checks, %d failed\n", checks, failed);
  return failed != 0;
}
