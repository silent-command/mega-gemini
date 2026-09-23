#include "x509.h"
#include "../crypto/crypto.h"
#include "../crypto/p256.h"
#include "../crypto/rsa.h"

/* A DER element at `off`: tag, then the content's offset and length.
 * Returns 0 if it does not fit in `len`. */
static uint8_t element(x509_read read, void *ctx, uint16_t len, uint16_t off, uint8_t *tag, uint16_t *coff, uint16_t *clen)
{
  uint8_t h[4];
  uint16_t n;
  if (off + 2 > len) return 0;
  read(ctx, off, h, (uint16_t)(off + 4 <= len ? 4 : len - off));
  *tag = h[0];
  if (h[1] < 0x80) { n = h[1]; *coff = (uint16_t)(off + 2); }
  else if (h[1] == 0x81) { n = h[2]; *coff = (uint16_t)(off + 3); }
  else if (h[1] == 0x82) { n = (uint16_t)(((uint16_t)h[2] << 8) | h[3]); *coff = (uint16_t)(off + 4); }
  else return 0;                                   /* longer than 64 KB, or indefinite */
  if ((uint32_t)*coff + n > len) return 0;
  *clen = n;
  return 1;
}

static uint8_t oid_is(x509_read read, void *ctx, uint16_t off, uint16_t n, const uint8_t *oid, uint8_t oidlen)
{
  uint8_t b[12], i;
  if (n != oidlen || n > sizeof b) return 0;
  read(ctx, off, b, n);
  for (i = 0; i < n; i++) if (b[i] != oid[i]) return 0;
  return 1;
}

static const uint8_t oid_ec[] = { 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01 };            /* 1.2.840.10045.2.1 */
static const uint8_t oid_p256[] = { 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07 };    /* 1.2.840.10045.3.1.7 */
static const uint8_t oid_rsa[] = { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01 }; /* 1.2.840.113549.1.1.1 */
static const uint8_t oid_ed25519[] = { 0x2b, 0x65, 0x70 };                              /* 1.3.101.112 */

/* An INTEGER's content without its leading zero. */
static void integer(x509_read read, void *ctx, uint16_t off, uint16_t n, uint16_t *voff, uint16_t *vlen)
{
  uint8_t b;
  while (n > 1) { read(ctx, off, &b, 1); if (b) break; off++; n--; }
  *voff = off; *vlen = n;
}

uint8_t x509_key_of(x509_read read, void *ctx, uint16_t len, x509_key *key)
{
  uint8_t tag;
  uint16_t off, n, tbs, tbs_len, alg, alg_len, oid, oid_len, bits, bits_len, i;

  key->kind = X509_KEY_NONE; key->spki_len = 0;
  if (!element(read, ctx, len, 0, &tag, &tbs, &tbs_len) || tag != 0x30) return 0;      /* Certificate */
  if (!element(read, ctx, len, tbs, &tag, &off, &n) || tag != 0x30) return 0;          /* TBSCertificate */
  len = (uint16_t)(off + n);
  if (!element(read, ctx, len, off, &tag, &off, &n)) return 0;
  if (tag == 0xa0) { off = (uint16_t)(off + n); if (!element(read, ctx, len, off, &tag, &off, &n)) return 0; }   /* [0] version */
  if (tag != 0x02) return 0;                                                            /* serial */
  for (i = 0; i < 4; i++) {                                                             /* signature, issuer, validity, subject */
    off = (uint16_t)(off + n);
    if (!element(read, ctx, len, off, &tag, &off, &n) || tag != 0x30) return 0;
  }
  off = (uint16_t)(off + n);
  key->spki_off = off;
  if (!element(read, ctx, len, off, &tag, &off, &n) || tag != 0x30) return 0;          /* SubjectPublicKeyInfo */
  key->spki_len = (uint16_t)(off + n - key->spki_off);
  if (!element(read, ctx, len, off, &tag, &alg, &alg_len) || tag != 0x30) return 0;    /* AlgorithmIdentifier */
  bits = (uint16_t)(alg + alg_len);
  if (!element(read, ctx, len, alg, &tag, &oid, &oid_len) || tag != 0x06) return 0;
  if (!element(read, ctx, len, bits, &tag, &bits, &bits_len) || tag != 0x03 || bits_len < 2) return 0;   /* BIT STRING */
  read(ctx, bits, &tag, 1);
  if (tag != 0) return 0;                                                               /* unused bits */
  bits++; bits_len--;

  if (oid_is(read, ctx, oid, oid_len, oid_ec, sizeof oid_ec)) {
    uint16_t poff, plen;
    if (!element(read, ctx, len, (uint16_t)(oid + oid_len), &tag, &poff, &plen) || tag != 0x06) return 0;
    if (!oid_is(read, ctx, poff, plen, oid_p256, sizeof oid_p256)) return 0;          /* another curve */
    if (bits_len != 65) return 0;
    read(ctx, bits, &tag, 1);
    if (tag != 0x04) return 0;                                                          /* uncompressed only */
    read(ctx, (uint16_t)(bits + 1), key->p256, 64);
    key->kind = X509_KEY_P256;
    return 1;
  }
  if (oid_is(read, ctx, oid, oid_len, oid_ed25519, sizeof oid_ed25519)) {
    if (bits_len != 32) return 0;
    read(ctx, bits, key->ed25519, 32);
    key->kind = X509_KEY_ED25519;
    return 1;
  }
  if (oid_is(read, ctx, oid, oid_len, oid_rsa, sizeof oid_rsa)) {
    uint16_t seq, seq_len, ioff, ilen;
    if (!element(read, ctx, len, bits, &tag, &seq, &seq_len) || tag != 0x30) return 0;  /* RSAPublicKey */
    if (!element(read, ctx, len, seq, &tag, &ioff, &ilen) || tag != 0x02) return 0;
    integer(read, ctx, ioff, ilen, &key->n_off, &key->n_len);
    if (!element(read, ctx, len, (uint16_t)(ioff + ilen), &tag, &ioff, &ilen) || tag != 0x02) return 0;
    integer(read, ctx, ioff, ilen, &key->e_off, &key->e_len);
    key->kind = X509_KEY_RSA;
    return 1;
  }
  return 0;
}

void x509_spki_hash(x509_read read, void *ctx, const x509_key *key, uint8_t out[32])
{
  sha256_ctx c;
  uint8_t buf[64];
  uint16_t off = key->spki_off, left = key->spki_len, take;
  sha256_init(&c);
  while (left) {
    take = left < sizeof buf ? left : (uint16_t)sizeof buf;
    read(ctx, off, buf, take);
    sha256_update(&c, buf, take);
    off = (uint16_t)(off + take); left = (uint16_t)(left - take);
  }
  sha256_final(&c, out);
}

uint8_t x509_scheme_supported(uint16_t scheme)
{
#ifndef X509_NO_ED25519
  if (scheme == 0x0807) return 1;                  /* ed25519: the host has it; the bank leaves it out for room */
#endif
  return (uint8_t)(scheme == 0x0403 || scheme == 0x0804);   /* ecdsa_secp256r1_sha256, rsa_pss_rsae_sha256 */
}

/* An ECDSA signature is DER: SEQUENCE { INTEGER r, INTEGER s }, each
 * integer possibly with a leading zero, possibly short. */
static uint8_t der_int(const uint8_t *p, uint16_t len, uint16_t *at, uint8_t out[32])
{
  uint16_t n, i;
  if (*at + 2 > len || p[*at] != 0x02) return 0;
  n = p[*at + 1];
  if (n >= 0x80 || *at + 2 + n > len) return 0;
  *at += 2;
  while (n && p[*at] == 0) { (*at)++; n--; }       /* leading zeros */
  if (n > 32) return 0;
  for (i = 0; i < 32; i++) out[i] = 0;
  for (i = 0; i < n; i++) out[32 - n + i] = p[*at + i];
  *at = (uint16_t)(*at + n);
  return 1;
}

uint8_t x509_ecdsa_p256_verify(const uint8_t pub[64], const uint8_t hash[32], const uint8_t *sig, uint16_t siglen)
{
  uint8_t r[32], s[32];
  uint16_t at, seq_len;
  if (siglen < 8 || sig[0] != 0x30) return 0;
  if (sig[1] < 0x80) { seq_len = sig[1]; at = 2; }
  else if (sig[1] == 0x81) { seq_len = sig[2]; at = 3; }
  else return 0;
  if (at + seq_len != siglen) return 0;
  if (!der_int(sig, siglen, &at, r) || !der_int(sig, siglen, &at, s) || at != siglen) return 0;
  return p256_verify(pub, hash, r, s);
}

uint8_t x509_rsa_pss_verify(x509_read read, void *ctx, const x509_key *key, const uint8_t hash[32], const uint8_t *sig, uint16_t siglen)
{
  static uint8_t n[512], e[8];
  if (key->n_len > sizeof n || key->e_len > sizeof e || key->e_len == 0) return 0;
  read(ctx, key->n_off, n, key->n_len);
  read(ctx, key->e_off, e, key->e_len);
  return rsa_pss_verify(n, key->n_len, e, key->e_len, sig, siglen, hash);
}
