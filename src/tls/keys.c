#include "keys.h"
#include "../crypto/hkdf.h"

void tls_expand_label(const uint8_t secret[32], const char *label, const uint8_t *ctx, uint8_t ctxlen, uint8_t *out, uint8_t outlen)
{
  uint8_t info[2 + 1 + 6 + 12 + 1 + 32];
  uint8_t n = 0, i;
  info[n++] = 0; info[n++] = outlen;
  for (i = 0; label[i]; i++) ;
  info[n++] = (uint8_t)(6 + i);
  info[n++] = 't'; info[n++] = 'l'; info[n++] = 's'; info[n++] = '1'; info[n++] = '3'; info[n++] = ' ';
  for (i = 0; label[i]; i++) info[n++] = (uint8_t)label[i];
  info[n++] = ctxlen;
  for (i = 0; i < ctxlen; i++) info[n++] = ctx[i];
  hkdf_expand(secret, info, n, out, outlen);
}

void tls_derive_secret(const uint8_t secret[32], const char *label, const uint8_t hash[32], uint8_t out[32])
{
  tls_expand_label(secret, label, hash, 32, out, 32);
}

void tls_traffic_keys(const uint8_t secret[32], tls_traffic *t)
{
  tls_expand_label(secret, "key", 0, 0, t->key, 32);
  tls_expand_label(secret, "iv", 0, 0, t->iv, 12);
}

void tls_nonce(const tls_traffic *t, uint32_t seq_hi, uint32_t seq_lo, uint8_t nonce[12])
{
  uint8_t i;
  for (i = 0; i < 12; i++) nonce[i] = t->iv[i];
  for (i = 0; i < 4; i++) {
    nonce[4 + i] ^= (uint8_t)(seq_hi >> (24 - 8 * i));
    nonce[8 + i] ^= (uint8_t)(seq_lo >> (24 - 8 * i));
  }
}

void tls_finished(const uint8_t base_key[32], const uint8_t hash[32], uint8_t out[32])
{
  uint8_t fk[32];
  tls_expand_label(base_key, "finished", 0, 0, fk, 32);
  hmac_sha256(fk, 32, hash, 32, out);
}

/* SHA-256 of nothing, the transcript hash Derive-Secret(…, "derived", "") uses. */
static const uint8_t empty_hash[32] = {
  0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
  0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55
};
static const uint8_t zero32[32] = { 0 };

void tls_schedule_start(tls_schedule *s)
{
  hkdf_extract(0, 0, zero32, 32, s->early);
}

void tls_schedule_handshake(tls_schedule *s, const uint8_t ecdhe[32], const uint8_t hash_ch_sh[32])
{
  uint8_t salt[32];
  tls_derive_secret(s->early, "derived", empty_hash, salt);
  hkdf_extract(salt, 32, ecdhe, 32, s->handshake);
  tls_derive_secret(s->handshake, "c hs traffic", hash_ch_sh, s->c_hs);
  tls_derive_secret(s->handshake, "s hs traffic", hash_ch_sh, s->s_hs);
}

void tls_schedule_master(tls_schedule *s, const uint8_t hash_ch_sfin[32])
{
  uint8_t salt[32];
  tls_derive_secret(s->handshake, "derived", empty_hash, salt);
  hkdf_extract(salt, 32, zero32, 32, s->master);
  tls_derive_secret(s->master, "c ap traffic", hash_ch_sfin, s->c_ap);
  tls_derive_secret(s->master, "s ap traffic", hash_ch_sfin, s->s_ap);
}
