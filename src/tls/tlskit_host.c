/* The kit on the host: the C in src/crypto, called directly. The same
 * operations the bank performs on the MEGA65, so a page fetched here
 * exercises what runs there. */
#include <stdlib.h>
#include "tlskit.h"
#include "keys.h"
#include "x509.h"
#include "../crypto/crypto.h"
#include "../crypto/aead.h"

static sha256_ctx transcript;
static uint8_t priv[32];
static tls_schedule sched;
static tls_traffic rd, wr;
static uint32_t rd_seq, wr_seq;
static aead_ctx in;
static uint8_t cert[8192];
static uint16_t cert_len;

void tk_random(uint8_t *out, uint8_t n)
{
#ifdef __APPLE__
  arc4random_buf(out, n);
#else
  { uint8_t i; for (i = 0; i < n; i++) out[i] = (uint8_t)rand(); }   /* a test harness, not a product */
#endif
}

void tk_transcript_init(void) { sha256_init(&transcript); }
void tk_transcript_update(const uint8_t *p, uint16_t n) { sha256_update(&transcript, p, n); }
void tk_transcript_hash(uint8_t out[32]) { sha256_ctx c = transcript; sha256_final(&c, out); }

void tk_keyshare(uint8_t pub[32])
{
  tk_random(priv, 32);
  x25519_base(pub, priv);
}

void tk_keys_handshake(const uint8_t peer_pub[32], const uint8_t hash[32])
{
  uint8_t ecdhe[32];
  x25519(ecdhe, priv, peer_pub);
  tls_schedule_start(&sched);
  tls_schedule_handshake(&sched, ecdhe, hash);
  tls_traffic_keys(sched.s_hs, &rd); rd_seq = 0;
  tls_traffic_keys(sched.c_hs, &wr); wr_seq = 0;
}

#ifdef TLS_P256
#include "../crypto/p256.h"
static uint8_t priv256[32];

void tk_keyshare_p256(uint8_t pub[65])
{
  pub[0] = 4;                                      /* uncompressed */
  do tk_random(priv256, 32); while (!p256_keygen(pub + 1, priv256));   /* a zero scalar is refused; astronomically rare */
}

uint8_t tk_keys_handshake_p256(const uint8_t peer_pub[65], const uint8_t hash[32])
{
  uint8_t ecdhe[32];
  if (peer_pub[0] != 4 || !p256_ecdh(ecdhe, priv256, peer_pub + 1)) return 0;
  tls_schedule_start(&sched);
  tls_schedule_handshake(&sched, ecdhe, hash);
  tls_traffic_keys(sched.s_hs, &rd); rd_seq = 0;
  tls_traffic_keys(sched.c_hs, &wr); wr_seq = 0;
  return 1;
}
#endif

void tk_keys_master(const uint8_t hash[32]) { tls_schedule_master(&sched, hash); }

void tk_write_switch(void)
{
  tls_traffic_keys(sched.c_ap, &wr); wr_seq = 0;
}

void tk_read_switch(void)
{
  tls_traffic_keys(sched.s_ap, &rd); rd_seq = 0;
}

void tk_finished(uint8_t server, const uint8_t hash[32], uint8_t out[32])
{
  tls_finished(server ? sched.s_hs : sched.c_hs, hash, out);
}

void tk_seal(uint8_t *rec, uint16_t len)
{
  uint8_t nonce[12];
  aead_ctx a;
  rec[3] = (uint8_t)((len + 16) >> 8); rec[4] = (uint8_t)(len + 16);
  tls_nonce(&wr, 0, wr_seq++, nonce);
  aead_start(&a, wr.key, nonce, rec, 5);
  aead_encrypt(&a, rec + 5, len);
  aead_tag(&a, rec + 5 + len);
}

void tk_open_start(const uint8_t hdr[5])
{
  uint8_t nonce[12];
  tls_nonce(&rd, 0, rd_seq, nonce);
  aead_start(&in, rd.key, nonce, hdr, 5);
}

void tk_open_data(uint8_t *p, uint16_t n) { aead_decrypt(&in, p, n); }

uint8_t tk_open_check(const uint8_t tag[16])
{
  rd_seq++;
  return (uint8_t)aead_check(&in, tag);
}

void tk_cert_reset(void) { cert_len = 0; }

void tk_cert_append(const uint8_t *p, uint16_t n)
{
  uint16_t i;
  for (i = 0; i < n && cert_len < sizeof cert; i++) cert[cert_len++] = p[i];
}

uint16_t tk_cert_len(void) { return cert_len; }

static void cert_read(void *ctx, uint16_t off, uint8_t *dst, uint16_t n)
{
  uint16_t i;
  (void)ctx;
  for (i = 0; i < n; i++) dst[i] = off + i < cert_len ? cert[off + i] : 0;
}

void tk_cert_read(uint16_t off, uint8_t *dst, uint16_t n) { cert_read(0, off, dst, n); }

/* The content signed in CertificateVerify: 64 spaces, the context
 * string, a zero, the transcript hash (RFC 8446 4.4.3). */
static void cv_content(const uint8_t hash[32], uint8_t out[130])
{
  static const char ctx[] = "TLS 1.3, server CertificateVerify";
  uint8_t i;
  for (i = 0; i < 64; i++) out[i] = ' ';
  for (i = 0; ctx[i]; i++) out[64 + i] = (uint8_t)ctx[i];
  out[97] = 0;
  for (i = 0; i < 32; i++) out[98 + i] = hash[i];
}

uint8_t tk_verify(uint16_t scheme, const uint8_t hash[32], const uint8_t *sig, uint16_t siglen)
{
  uint8_t content[130], digest[32];
  x509_key key;
  if (!x509_scheme_supported(scheme)) return TK_UNCHECKED;
  if (!x509_key_of(cert_read, 0, cert_len, &key)) return TK_WRONG;
  cv_content(hash, content);
  switch (scheme) {
  case 0x0807:
    if (key.kind != X509_KEY_ED25519 || siglen != 64) return TK_WRONG;
    return ed25519_verify(sig, content, 130, key.ed25519) ? TK_VERIFIED : TK_WRONG;
  case 0x0403:
    if (key.kind != X509_KEY_P256) return TK_WRONG;
    sha256(content, 130, digest);
    return x509_ecdsa_p256_verify(key.p256, digest, sig, siglen) ? TK_VERIFIED : TK_WRONG;
  case 0x0804:
    if (key.kind != X509_KEY_RSA) return TK_WRONG;
    sha256(content, 130, digest);
    return x509_rsa_pss_verify(cert_read, 0, &key, digest, sig, siglen) ? TK_VERIFIED : TK_WRONG;
  }
  return TK_UNCHECKED;
}

uint8_t tk_pin(uint8_t out[32])
{
  x509_key key;
  x509_key_of(cert_read, 0, cert_len, &key);
  if (!key.spki_len) return 0;
  x509_spki_hash(cert_read, 0, &key, out);
  return 1;
}
