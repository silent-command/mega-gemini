#include "tls.h"

/* record and handshake types */
#define REC_CCS 20
#define REC_ALERT 21
#define REC_HANDSHAKE 22
#define REC_APPDATA 23
#define HS_CLIENT_HELLO 1
#define HS_SERVER_HELLO 2
#define HS_ENCRYPTED_EXT 8
#define HS_CERTIFICATE 11
#define HS_CERT_REQUEST 13
#define HS_CERT_VERIFY 15
#define HS_FINISHED 20

#define REC_MAX (16384 + 256)

static void fail_at(tls *t, uint8_t err, uint16_t line)
{
  if (t->state != TLS_FAILED) { t->state = TLS_FAILED; t->error = err; t->error_line = line; }
}
#define fail(t, e) fail_at(t, e, __LINE__)         /* which check, for the host harness */

static void put8(tls *t, uint8_t b) { if (t->out_len < t->out_cap) t->out[t->out_len] = b; t->out_len++; }
static void put16(tls *t, uint16_t v) { put8(t, (uint8_t)(v >> 8)); put8(t, (uint8_t)v); }
static void putn(tls *t, const uint8_t *p, uint16_t n) { const uint8_t *end = p + n; while (p < end) put8(t, *p++); }   /* a walk, not a count (ssh 5.6) */

/* ---- sending ---------------------------------------------------------- */

/* Seals [start, out_len) as one record of `type`, given the plaintext
 * was written after a 5-byte header at `start`. */
static uint8_t seal(tls *t, uint16_t start, uint8_t type)
{
  uint16_t len;
  put8(t, type);                                   /* the inner type */
  if (t->out_len + 16 > t->out_cap) { t->out_len = start; return 0; }
  len = (uint16_t)(t->out_len - start - 5);
  t->out[start] = REC_APPDATA; t->out[start + 1] = 3; t->out[start + 2] = 3;
  tk_seal(t->out + start, len);
  t->out_len = (uint16_t)(t->out_len + 16);
  return 1;
}

static void send_alert(tls *t, uint8_t level, uint8_t desc)
{
  uint16_t start = t->out_len;
  if (t->wr_on) {
    if (start + 5 + 2 + 1 + 16 > t->out_cap) return;
    t->out_len = (uint16_t)(start + 5); put8(t, level); put8(t, desc);
    seal(t, start, REC_ALERT);
  } else {
    if (start + 7 > t->out_cap) return;
    put8(t, REC_ALERT); put16(t, 0x0303); put16(t, 2); put8(t, level); put8(t, desc);
  }
}

#ifdef TLS_P256
/* The ClientHello, appended to the out buffer and hashed into the
 * transcript: `pub` is the key share, `publen` bytes, for `group`. Both
 * groups are offered, and the same hello is sent again with a P-256
 * share if the server asks for one (server_hello). 0 if the buffer
 * cannot hold it, with out_len put back. Compiled only under TLS_P256:
 * without it, tls_start below is the original, so gemini's build is
 * byte for byte what it was (mega-irc 5.12). */
static uint8_t hello(tls *t, const uint8_t rnd[32], const char *sni, uint16_t group, const uint8_t *pub, uint8_t publen)
{
  uint16_t sni_len = 0, ext_start, body_start, i, start = t->out_len;

  while (sni[sni_len]) sni_len++;
  /* record header, filled in below */
  put8(t, REC_HANDSHAKE); put16(t, 0x0301); put16(t, 0);
  body_start = t->out_len;
  put8(t, HS_CLIENT_HELLO); put8(t, 0); put16(t, 0);   /* length, below */
  put16(t, 0x0303);
  putn(t, rnd, 32);
  put8(t, 0);                                      /* no session id */
  put16(t, 2); put16(t, 0x1303);                   /* TLS_CHACHA20_POLY1305_SHA256 */
  put8(t, 1); put8(t, 0);                          /* no compression */
  put16(t, 0);                                     /* extensions length, below */
  ext_start = t->out_len;
  /* server_name */
  put16(t, 0); put16(t, (uint16_t)(sni_len + 5)); put16(t, (uint16_t)(sni_len + 3)); put8(t, 0); put16(t, sni_len);
  for (i = 0; i < sni_len; i++) put8(t, (uint8_t)sni[i]);
  /* supported_groups: x25519, and secp256r1 for a server that will not
   * take x25519 and asks with a HelloRetryRequest (OFTC, mega-irc 5.12) */
  put16(t, 10); put16(t, 6); put16(t, 4); put16(t, 0x001d); put16(t, 0x0017);
  /* signature_algorithms: ecdsa_secp256r1_sha256, rsa_pss_rsae_sha256, ed25519, and the two
   * ECDSA schemes this client cannot verify, so that such a server still answers */
  put16(t, 13); put16(t, 12); put16(t, 10);
  put16(t, 0x0403); put16(t, 0x0804); put16(t, 0x0807); put16(t, 0x0503); put16(t, 0x0603);
  /* supported_versions: 1.3 */
  put16(t, 43); put16(t, 3); put8(t, 2); put16(t, 0x0304);
  /* key_share */
  put16(t, 51); put16(t, (uint16_t)(publen + 6)); put16(t, (uint16_t)(publen + 4)); put16(t, group); put16(t, publen); putn(t, pub, publen);
  if (t->out_len > t->out_cap) { t->out_len = start; return 0; }
  /* the lengths */
  { uint16_t ext_len = (uint16_t)(t->out_len - ext_start), hs_len = (uint16_t)(t->out_len - body_start - 4);
    t->out[ext_start - 2] = (uint8_t)(ext_len >> 8); t->out[ext_start - 1] = (uint8_t)ext_len;
    t->out[body_start + 2] = (uint8_t)(hs_len >> 8); t->out[body_start + 3] = (uint8_t)hs_len;
    t->out[start + 3] = (uint8_t)((hs_len + 4) >> 8); t->out[start + 4] = (uint8_t)(hs_len + 4); }
  tk_transcript_update(t->out + body_start, (uint16_t)(t->out_len - body_start));
  return 1;
}
#endif

uint8_t tls_start(tls *t, const tls_hooks *hooks, const char *sni, uint8_t *out, uint16_t out_cap)
{
#ifdef TLS_P256
  uint8_t rnd[32], pub[32];
  uint16_t sni_len = 0;

  while (sni[sni_len]) sni_len++;
  t->hooks = hooks; t->out = out; t->out_cap = out_cap; t->out_len = 0;
  t->state = TLS_IDLE; t->error = TLS_E_NONE; t->alert = 0;
  t->sig_state = TLS_SIG_UNCHECKED; t->sig_scheme = 0;
  t->rd_on = t->wr_on = 0;
  t->hdr_len = 0; t->rec_len = t->rec_pos = 0;
  t->msg_len = t->msg_pos = 0; t->msg_type = 0;
  t->cert_requested = 0; t->cert_req_ctx_len = 0; t->rd_switch = 0; t->rec_connected = 0; t->rec_index = 0; t->cv_seen = 0;
  if (out_cap < TLS_OUT_MIN + sni_len) return 0;

  tk_random(rnd, 32);
  tk_keyshare(pub);
  { uint8_t i; for (i = 0; i < 32; i++) t->rnd[i] = rnd[i]; }
  t->sni = sni; t->hrr_done = 0;
  tk_transcript_init();
  if (!hello(t, rnd, sni, 0x001d, pub, 32)) return 0;
  t->state = TLS_WAIT_SH;
  return 1;
#else
  uint8_t rnd[32], pub[32];
  uint16_t sni_len = 0, ext_start, body_start, i;

  while (sni[sni_len]) sni_len++;
  t->hooks = hooks; t->out = out; t->out_cap = out_cap; t->out_len = 0;
  t->state = TLS_IDLE; t->error = TLS_E_NONE; t->alert = 0;
  t->sig_state = TLS_SIG_UNCHECKED; t->sig_scheme = 0;
  t->rd_on = t->wr_on = 0;
  t->hdr_len = 0; t->rec_len = t->rec_pos = 0;
  t->msg_len = t->msg_pos = 0; t->msg_type = 0;
  t->cert_requested = 0; t->cert_req_ctx_len = 0; t->rd_switch = 0; t->rec_connected = 0; t->rec_index = 0; t->cv_seen = 0;
  if (out_cap < TLS_OUT_MIN + sni_len) return 0;

  tk_random(rnd, 32);
  tk_keyshare(pub);

  /* record header, filled in below */
  put8(t, REC_HANDSHAKE); put16(t, 0x0301); put16(t, 0);
  body_start = t->out_len;
  put8(t, HS_CLIENT_HELLO); put8(t, 0); put16(t, 0);   /* length, below */
  put16(t, 0x0303);
  putn(t, rnd, 32);
  put8(t, 0);                                      /* no session id */
  put16(t, 2); put16(t, 0x1303);                   /* TLS_CHACHA20_POLY1305_SHA256 */
  put8(t, 1); put8(t, 0);                          /* no compression */
  put16(t, 0);                                     /* extensions length, below */
  ext_start = t->out_len;
  /* server_name */
  put16(t, 0); put16(t, (uint16_t)(sni_len + 5)); put16(t, (uint16_t)(sni_len + 3)); put8(t, 0); put16(t, sni_len);
  for (i = 0; i < sni_len; i++) put8(t, (uint8_t)sni[i]);
  /* supported_groups: x25519 */
  put16(t, 10); put16(t, 4); put16(t, 2); put16(t, 0x001d);
  /* signature_algorithms: ecdsa_secp256r1_sha256, rsa_pss_rsae_sha256, ed25519, and the two
   * ECDSA schemes this client cannot verify, so that such a server still answers */
  put16(t, 13); put16(t, 12); put16(t, 10);
  put16(t, 0x0403); put16(t, 0x0804); put16(t, 0x0807); put16(t, 0x0503); put16(t, 0x0603);
  /* supported_versions: 1.3 */
  put16(t, 43); put16(t, 3); put8(t, 2); put16(t, 0x0304);
  /* key_share */
  put16(t, 51); put16(t, 38); put16(t, 36); put16(t, 0x001d); put16(t, 32); putn(t, pub, 32);
  if (t->out_len > out_cap) { t->out_len = 0; return 0; }
  /* the lengths */
  { uint16_t ext_len = (uint16_t)(t->out_len - ext_start), hs_len = (uint16_t)(t->out_len - body_start - 4);
    t->out[ext_start - 2] = (uint8_t)(ext_len >> 8); t->out[ext_start - 1] = (uint8_t)ext_len;
    t->out[body_start + 2] = (uint8_t)(hs_len >> 8); t->out[body_start + 3] = (uint8_t)hs_len;
    t->out[3] = (uint8_t)((hs_len + 4) >> 8); t->out[4] = (uint8_t)(hs_len + 4); }
  tk_transcript_init();
  tk_transcript_update(t->out + body_start, (uint16_t)(t->out_len - body_start));
  t->state = TLS_WAIT_SH;
  return 1;
#endif
}

void tls_out_consumed(tls *t, uint16_t n)
{
  uint16_t i;
  if (n >= t->out_len) { t->out_len = 0; return; }
  for (i = 0; i + n < t->out_len; i++) t->out[i] = t->out[i + n];
  t->out_len = (uint16_t)(t->out_len - n);
}

uint8_t tls_write(tls *t, const uint8_t *p, uint16_t n)
{
  uint16_t start = t->out_len;
  if (t->state != TLS_CONNECTED || !t->wr_on) return 0;
  if ((uint32_t)start + 5 + n + 1 + 16 > t->out_cap) return 0;
  t->out_len = (uint16_t)(start + 5);
  putn(t, p, n);
  return seal(t, start, REC_APPDATA);
}

uint8_t tls_write_here(tls *t, uint16_t n)
{
  uint16_t start = t->out_len;
  if (t->state != TLS_CONNECTED || !t->wr_on) return 0;
  if ((uint32_t)start + 5 + n + 1 + 16 > t->out_cap) return 0;
  t->out_len = (uint16_t)(start + 5 + n);
  return seal(t, start, REC_APPDATA);
}

uint8_t tls_close(tls *t)
{
  if (t->state != TLS_CONNECTED && t->state != TLS_CLOSED) return 0;
  send_alert(t, 1, 0);                             /* warning, close_notify */
  return 1;
}

/* ---- the handshake messages ------------------------------------------ */

static void hash_now(tls *t, uint8_t out[32])
{
  (void)t;
  tk_transcript_hash(out);
}

#ifdef TLS_P256
/* The P-256-aware ServerHello: it also handles a HelloRetryRequest, by
 * sending a second ClientHello with a P-256 key share (OFTC, mega-irc
 * 5.12). Without TLS_P256 the original below is compiled instead, so
 * gemini is unchanged. */
static void server_hello(tls *t)
{
  const uint8_t *m = t->msg;
  uint32_t n = t->msg_len, p, share_at = 0;
  uint16_t share_group = 0, share_len = 0;
  uint8_t sid, got_version = 0, is_hrr, cookie = 0;
  static const uint8_t hrr[8] = { 0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11 };
  uint8_t i;

  if (n < 38) { fail(t, TLS_E_MESSAGE); return; }
  if (m[0] != 3 || m[1] != 3) { fail(t, TLS_E_VERSION); return; }
  for (i = 0; i < 8 && m[2 + i] == hrr[i]; i++) ;
  is_hrr = (uint8_t)(i == 8);
  sid = m[34];
  p = 35 + sid;
  if (p + 3 > n) { fail(t, TLS_E_MESSAGE); return; }
  if (m[p] != 0x13 || m[p + 1] != 0x03) { fail(t, TLS_E_SUITE); return; }
  if (m[p + 2] != 0) { fail(t, TLS_E_SUITE); return; }
  p += 3;
  if (p + 2 > n) { fail(t, TLS_E_MESSAGE); return; }
  { uint16_t ext_len = (uint16_t)(((uint16_t)m[p] << 8) | m[p + 1]); p += 2;
    if (p + ext_len != n) { fail(t, TLS_E_MESSAGE); return; }
    while (p + 4 <= n) {
      uint16_t type = (uint16_t)(((uint16_t)m[p] << 8) | m[p + 1]), len = (uint16_t)(((uint16_t)m[p + 2] << 8) | m[p + 3]);
      p += 4;
      if (p + len > n) { fail(t, TLS_E_MESSAGE); return; }
      if (type == 43) { if (len != 2 || m[p] != 3 || m[p + 1] != 4) { fail(t, TLS_E_VERSION); return; } got_version = 1; }
      else if (type == 51) {
        /* a ServerHello carries the group and its share; a retry request
         * names the group alone */
        if (len < 2) { fail(t, TLS_E_SUITE); return; }
        share_group = (uint16_t)(((uint16_t)m[p] << 8) | m[p + 1]);
        if (len > 2) {
          if (len < 4) { fail(t, TLS_E_SUITE); return; }
          share_len = (uint16_t)(((uint16_t)m[p + 2] << 8) | m[p + 3]);
          if (4 + (uint32_t)share_len != len) { fail(t, TLS_E_SUITE); return; }
          share_at = p + 4;
        }
      }
      else if (type == 44) cookie = 1;
      p += len;
    }
  }
  if (!got_version) { fail(t, TLS_E_VERSION); return; }

  if (is_hrr) {
    /* The server will not take x25519 and asks for secp256r1 (OFTC,
     * mega-irc 5.12). RFC 8446 4.4.1: the transcript becomes a synthetic
     * message_hash of the first ClientHello, then this retry, then the
     * same ClientHello again with a P-256 share. hash_to_cv holds the
     * hash of the first hello: hs_feed took it before this message's
     * first byte. The retry itself is whole in msg. A cookie would have
     * to be echoed and is refused instead; nothing met so far sends one. */
    uint8_t pub[65], hdr[4];
    if (t->hrr_done || cookie || share_group != 0x0017 || share_len != 0) { fail(t, TLS_E_HRR); return; }
    t->hrr_done = 1;
    hdr[0] = 254; hdr[1] = 0; hdr[2] = 0; hdr[3] = 32;
    tk_transcript_init();
    tk_transcript_update(hdr, 4);
    tk_transcript_update(t->hash_to_cv, 32);
    hdr[0] = HS_SERVER_HELLO; hdr[1] = (uint8_t)(n >> 16); hdr[2] = (uint8_t)(n >> 8); hdr[3] = (uint8_t)n;
    tk_transcript_update(hdr, 4);
    tk_transcript_update(m, (uint16_t)n);
    tk_keyshare_p256(pub);
    if (!hello(t, t->rnd, t->sni, 0x0017, pub, 65)) { fail(t, TLS_E_BUFFER); return; }
    t->state = TLS_WAIT_SH;                        /* the real ServerHello next */
    return;
  }
  if (share_group == 0x0017) {
    if (share_len != 65 || m[share_at] != 4) { fail(t, TLS_E_SUITE); return; }
    hash_now(t, t->hash_ch_sh);
    if (!tk_keys_handshake_p256(m + share_at, t->hash_ch_sh)) { fail(t, TLS_E_SUITE); return; }
    t->rd_on = t->wr_on = 1;
    t->state = TLS_WAIT_HS;
    return;
  }
  if (share_group != 0x001d || share_len != 32) { fail(t, TLS_E_SUITE); return; }
  { uint8_t server_pub[32];
    for (i = 0; i < 32; i++) server_pub[i] = m[share_at + i];
    hash_now(t, t->hash_ch_sh);
    tk_keys_handshake(server_pub, t->hash_ch_sh); }
  t->rd_on = t->wr_on = 1;
  t->state = TLS_WAIT_HS;
}
#else
static void server_hello(tls *t)
{
  const uint8_t *m = t->msg;
  uint32_t n = t->msg_len, p;
  uint8_t sid, got_version = 0, got_share = 0;
  uint8_t server_pub[32];
  static const uint8_t hrr[8] = { 0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11 };
  uint8_t i;

  if (n < 38) { fail(t, TLS_E_MESSAGE); return; }
  if (m[0] != 3 || m[1] != 3) { fail(t, TLS_E_VERSION); return; }
  for (i = 0; i < 8 && m[2 + i] == hrr[i]; i++) ;
  if (i == 8) { fail(t, TLS_E_HRR); return; }
  sid = m[34];
  p = 35 + sid;
  if (p + 3 > n) { fail(t, TLS_E_MESSAGE); return; }
  if (m[p] != 0x13 || m[p + 1] != 0x03) { fail(t, TLS_E_SUITE); return; }
  if (m[p + 2] != 0) { fail(t, TLS_E_SUITE); return; }
  p += 3;
  if (p + 2 > n) { fail(t, TLS_E_MESSAGE); return; }
  { uint16_t ext_len = (uint16_t)(((uint16_t)m[p] << 8) | m[p + 1]); p += 2;
    if (p + ext_len != n) { fail(t, TLS_E_MESSAGE); return; }
    while (p + 4 <= n) {
      uint16_t type = (uint16_t)(((uint16_t)m[p] << 8) | m[p + 1]), len = (uint16_t)(((uint16_t)m[p + 2] << 8) | m[p + 3]);
      p += 4;
      if (p + len > n) { fail(t, TLS_E_MESSAGE); return; }
      if (type == 43) { if (len != 2 || m[p] != 3 || m[p + 1] != 4) { fail(t, TLS_E_VERSION); return; } got_version = 1; }
      else if (type == 51) {
        if (len != 36 || m[p] != 0 || m[p + 1] != 0x1d || m[p + 2] != 0 || m[p + 3] != 32) { fail(t, TLS_E_SUITE); return; }
        for (i = 0; i < 32; i++) server_pub[i] = m[p + 4 + i];
        got_share = 1;
      }
      p += len;
    }
  }
  if (!got_version) { fail(t, TLS_E_VERSION); return; }
  if (!got_share) { fail(t, TLS_E_SUITE); return; }

  hash_now(t, t->hash_ch_sh);
  tk_keys_handshake(server_pub, t->hash_ch_sh);
  t->rd_on = t->wr_on = 1;
  t->state = TLS_WAIT_HS;
}
#endif

static void cert_verify(tls *t)
{
  const uint8_t *m = t->msg;
  uint16_t sig_len;
  if (t->msg_len < 4) { fail(t, TLS_E_MESSAGE); return; }
  t->sig_scheme = (uint16_t)(((uint16_t)m[0] << 8) | m[1]);
  sig_len = (uint16_t)(((uint16_t)m[2] << 8) | m[3]);
  if (4 + (uint32_t)sig_len != t->msg_len) { fail(t, TLS_E_MESSAGE); return; }
  t->cv_seen = 1;                                  /* the message stays in msg; tls_verify() checks it */
}

void tls_verify(tls *t)
{
  const uint8_t *m = t->msg;
  uint16_t sig_len = (uint16_t)(((uint16_t)m[2] << 8) | m[3]);
  if (t->state != TLS_VERIFYING) return;
  if (!t->cv_seen) { fail(t, TLS_E_MESSAGE); return; }
  /* hash_to_cv is the transcript before CertificateVerify: what is signed */
  t->sig_state = tk_verify(t->sig_scheme, t->hash_to_cv, m + 4, sig_len);
  if (t->sig_state == TK_WRONG) { fail(t, TLS_E_SIGNATURE); return; }
  t->state = TLS_CONNECTED;
}

static void server_finished(tls *t)
{
  uint8_t want[32], hash[32];
  uint16_t s, i;
  if (t->msg_len != 32) { fail(t, TLS_E_MESSAGE); return; }
  hash_now(t, hash);                               /* through CertificateVerify: this message is not yet hashed */
  tk_finished(1, hash, want);
  for (i = 0; i < 32; i++) if (want[i] != t->fin[i]) { fail(t, TLS_E_FINISHED); return; }
  /* now with the server Finished in the transcript */
  { uint8_t hdr[4] = { HS_FINISHED, 0, 0, 32 };
    tk_transcript_update(hdr, 4); tk_transcript_update(t->fin, 32); }
  hash_now(t, t->hash_to_sfin);
  tk_keys_master(t->hash_to_sfin);
  /* the client's flight, under the handshake keys: an empty Certificate
   * if one was asked for (its context echoed), then Finished */
  s = t->out_len;
  if (s + 5 + 8 + t->cert_req_ctx_len + 36 + 1 + 16 > t->out_cap) { fail(t, TLS_E_BUFFER); return; }
  t->out_len = (uint16_t)(s + 5);
  if (t->cert_requested) {
    uint16_t body_start = t->out_len;
    put8(t, HS_CERTIFICATE); put8(t, 0); put16(t, (uint16_t)(1 + t->cert_req_ctx_len + 3));
    put8(t, t->cert_req_ctx_len);
    for (i = 0; i < t->cert_req_ctx_len; i++) put8(t, t->cert_req_ctx[i]);
    put8(t, 0); put8(t, 0); put8(t, 0);            /* no certificates */
    tk_transcript_update(t->out + body_start, (uint16_t)(t->out_len - body_start));
    hash_now(t, hash);
  } else {
    for (i = 0; i < 32; i++) hash[i] = t->hash_to_sfin[i];
  }
  put8(t, HS_FINISHED); put8(t, 0); put16(t, 32);
  tk_finished(0, hash, want);
  putn(t, want, 32);
  seal(t, s, REC_HANDSHAKE);                       /* under the handshake keys */
  /* application keys: writing from now; reading once this record has ended */
  tk_write_switch();
  t->rd_switch = 1;
  t->state = TLS_VERIFYING;                        /* the signature next, once this is sent */
}

/* A whole handshake message header has arrived: decide how to take the body. */
static void msg_begin(tls *t)
{
  if (t->state == TLS_WAIT_SH) {
    if (t->msg_type != HS_SERVER_HELLO) { fail(t, TLS_E_MESSAGE); return; }
  } else if (t->state == TLS_WAIT_HS) {
    if (t->msg_type == HS_CERTIFICATE) {
      t->msg_whole = 0; t->cert_phase = 0; t->cert_index = 0; t->cert_lenlen = 0; t->leaf_len = 0;
      tk_cert_reset();
      return;
    }
    if (t->msg_type != HS_ENCRYPTED_EXT && t->msg_type != HS_CERT_REQUEST && t->msg_type != HS_CERT_VERIFY && t->msg_type != HS_FINISHED) { fail(t, TLS_E_MESSAGE); return; }
  } else { fail(t, TLS_E_MESSAGE); return; }
  t->msg_whole = (uint8_t)(t->msg_type == HS_FINISHED ? 2 : 1);
  if (t->msg_type == HS_FINISHED ? t->msg_len != 32 : t->msg_len > TLS_MSG_MAX) fail(t, TLS_E_MESSAGE);
}

/* Bytes of a streamed Certificate body. */
static void cert_stream(tls *t, const uint8_t *p, uint16_t n)
{
  while (n && t->state != TLS_FAILED) {
    uint32_t take;
    switch (t->cert_phase) {
    case 0:                                        /* certificate_request_context length: must be 0 */
      if (*p != 0) { fail(t, TLS_E_MESSAGE); return; }
      p++; n--; t->cert_phase = 1; t->cert_lenlen = 0;
      break;
    case 1: case 2: case 4:                        /* a 3-byte or 2-byte length */
      t->cert_lenbuf[t->cert_lenlen++] = *p++; n--;
      if (t->cert_phase == 4 && t->cert_lenlen == 2) {
        t->ext_left = (uint32_t)(((uint16_t)t->cert_lenbuf[0] << 8) | t->cert_lenbuf[1]);
        t->cert_phase = 5; t->cert_lenlen = 0;
      } else if (t->cert_phase != 4 && t->cert_lenlen == 3) {
        uint32_t v = ((uint32_t)t->cert_lenbuf[0] << 16) | ((uint32_t)t->cert_lenbuf[1] << 8) | t->cert_lenbuf[2];
        if (t->cert_phase == 1) { t->cert_list_left = v; t->cert_phase = 2; }
        else { t->cert_left = v; t->cert_phase = 3; if (t->cert_index == 0) t->leaf_len = (uint16_t)(v > 0xffff ? 0xffff : v); }
        t->cert_lenlen = 0;
        if (t->cert_phase == 2 && v == 0) { fail(t, TLS_E_CERT); return; }
      }
      break;
    case 3:                                        /* DER */
      take = t->cert_left < n ? t->cert_left : n;
      tk_cert_append(p, (uint16_t)take);           /* every certificate, the leaf first: this client reads only the leaf, at offset 0; the IRC client verifies the chain (mega-irc 5.5, 5.10) */
      p += take; n = (uint16_t)(n - take); t->cert_left -= take;
      if (!t->cert_left) t->cert_phase = 4;
      break;
    case 5:                                        /* extensions, skipped */
      take = t->ext_left < n ? t->ext_left : n;
      p += take; n = (uint16_t)(n - take); t->ext_left -= take;
      if (!t->ext_left) { t->cert_phase = 2; t->cert_index++; }
      break;
    }
  }
}

static void msg_end(tls *t)
{
  if (t->state == TLS_FAILED) return;
  switch (t->msg_type) {
  case HS_SERVER_HELLO: server_hello(t); break;
  case HS_ENCRYPTED_EXT: break;                    /* nothing this client asked for */
  case HS_CERT_REQUEST:                            /* answered with no certificate; the context is echoed */
    if (t->msg_len < 1 || t->msg[0] > sizeof t->cert_req_ctx || 1 + (uint32_t)t->msg[0] > t->msg_len) { fail(t, TLS_E_MESSAGE); return; }
    t->cert_requested = 1; t->cert_req_ctx_len = t->msg[0];
    { uint8_t i; for (i = 0; i < t->cert_req_ctx_len; i++) t->cert_req_ctx[i] = t->msg[1 + i]; }
    break;
  case HS_CERTIFICATE: if (!t->leaf_len) fail(t, TLS_E_CERT); break;
  case HS_CERT_VERIFY: cert_verify(t); break;
  case HS_FINISHED: server_finished(t); return;    /* hashes itself, after checking */
  default: fail(t, TLS_E_MESSAGE); return;
  }
}

/* Plaintext handshake bytes: message framing, the transcript, dispatch. */
static void hs_feed(tls *t, const uint8_t *p, uint16_t n)
{
  while (n && t->state != TLS_FAILED) {
    if (t->msg_pos < 4) {                          /* the header: type, 24-bit length */
      uint8_t b = *p++; n--;
      if (t->msg_pos == 0) { t->msg_type = b; t->msg_len = 0; if (!t->cv_seen) hash_now(t, t->hash_to_cv); }   /* the transcript before this message: what CertificateVerify signs; kept once it has */
      else t->msg_len = (t->msg_len << 8) | b;
      t->msg_pos++;
      if (t->msg_type != HS_FINISHED) tk_transcript_update(&b, 1);   /* Finished is hashed after it is checked */
      else t->msg[TLS_MSG_MAX - 4 + t->msg_pos - 1] = b;
      if (t->msg_pos == 4) { msg_begin(t); if (t->msg_len == 0) { msg_end(t); t->msg_pos = 0; } }
    } else {
      uint32_t left = t->msg_len - (t->msg_pos - 4);
      uint16_t take = left < n ? (uint16_t)left : n;
      if (t->msg_type != HS_FINISHED) tk_transcript_update(p, take);
      if (t->msg_whole == 1) { uint16_t i, at = (uint16_t)(t->msg_pos - 4); for (i = 0; i < take; i++) t->msg[at + i] = p[i]; }
      else if (t->msg_whole == 2) { uint16_t i, at = (uint16_t)(t->msg_pos - 4); for (i = 0; i < take; i++) t->fin[at + i] = p[i]; }
      else cert_stream(t, p, take);
      t->msg_pos += take; p += take; n = (uint16_t)(n - take);
      if (t->msg_pos - 4 == t->msg_len) { msg_end(t); t->msg_pos = 0; }
    }
  }
}

/* ---- records ---------------------------------------------------------- */

static void alert_in(tls *t, const uint8_t *p, uint16_t n)
{
  if (n < 2) { fail(t, TLS_E_RECORD); return; }
  t->alert = p[1];
  if (p[1] == 0) { t->state = TLS_CLOSED; return; }   /* close_notify */
  fail(t, TLS_E_ALERT);
}

static void record_start(tls *t)
{
  t->rec_type = t->hdr[0];
  t->rec_len = (uint16_t)(((uint16_t)t->hdr[3] << 8) | t->hdr[4]);
  t->rec_pos = 0; t->tag_len = 0; t->rec_index++;
  t->rec_connected = (uint8_t)(t->state == TLS_CONNECTED);
  if (t->hdr[1] != 3 || t->rec_len > REC_MAX) { fail(t, TLS_E_RECORD); return; }
  if (t->rd_on && t->rec_type == REC_APPDATA) {
    if (t->rec_len < 17) { fail(t, TLS_E_RECORD); return; }
    tk_open_start(t->hdr);
  } else if (t->rd_on && t->rec_type != REC_CCS && t->rec_type != REC_ALERT) {
    fail(t, TLS_E_RECORD);                         /* plaintext handshake after the keys are up */
  }
  if (t->rec_len == 0) t->hdr_len = 0;             /* an empty record: nothing follows */
}

static void record_end(tls *t)
{
  t->hdr_len = 0;
  if (!(t->rd_on && t->rec_type == REC_APPDATA)) return;
  {
    uint8_t ok = tk_open_check(t->tag);
    if (t->rd_switch) { tk_read_switch(); t->rd_switch = 0; }
    if (t->rec_connected)
      t->hooks->on_record_end(t->hooks->ctx, (uint8_t)(ok && t->inner_type == REC_APPDATA));
    if (!ok) { fail(t, TLS_E_TAG); return; }
    switch (t->inner_type) {
    case REC_APPDATA:
      if (!t->rec_connected) fail(t, TLS_E_MESSAGE);
      break;
    case REC_HANDSHAKE:
      /* during the handshake its bytes went to the message parser as they
       * came; once connected (a session ticket, a key update) they went to
       * on_data and were just taken back */
      break;
    case REC_ALERT:
      alert_in(t, t->last2, 2);                    /* the two bytes before the type */
      break;
    default:
      fail(t, TLS_E_RECORD);
    }
  }
}

/* Encrypted record bytes: decrypted in place, in one piece up to the
 * record's ciphertext boundary (on the MEGA65 a piece is a bank call and
 * two DMA jobs, so the fewer the better: 5.8), and handed to whoever is
 * reading this phase; the record's inner type is only known at its end
 * (the last plaintext byte), so record_end() sorts out anything else. */
static void enc_feed(tls *t, uint8_t *p, uint16_t n)
{
  uint16_t ct_len = (uint16_t)(t->rec_len - 16);
  while (n) {
    uint16_t pos = t->rec_pos, take, content, i;
    if (pos < ct_len) {
      take = (uint16_t)(ct_len - pos); if (take > n) take = n;
      tk_open_data(p, take);
      content = take;
      if (pos + take == ct_len) { t->inner_type = p[take - 1]; content--; }   /* the type byte is not content */
      if (content) {
        if (content >= 2) { t->last2[0] = p[content - 2]; t->last2[1] = p[content - 1]; }
        else { t->last2[0] = t->last2[1]; t->last2[1] = p[0]; }
        if (t->state == TLS_CONNECTED) t->hooks->on_data(t->hooks->ctx, p, content);
        else hs_feed(t, p, content);
      }
    } else {
      take = (uint16_t)(t->rec_len - pos); if (take > n) take = n;
      for (i = 0; i < take; i++) t->tag[t->tag_len++] = p[i];
    }
    p += take; n = (uint16_t)(n - take); t->rec_pos = (uint16_t)(t->rec_pos + take);
    if (t->state == TLS_FAILED) return;
  }
}

void tls_in(tls *t, uint8_t *p, uint16_t n)
{
  while (n && t->state != TLS_FAILED && t->state != TLS_CLOSED) {
    if (t->hdr_len < 5) {
      t->hdr[t->hdr_len++] = *p++; n--;
      if (t->hdr_len == 5) record_start(t);
      continue;
    }
    { uint16_t left = (uint16_t)(t->rec_len - t->rec_pos), take = left < n ? left : n;
      if (t->rd_on && t->rec_type == REC_APPDATA) enc_feed(t, p, take);
      else {
        /* plaintext: only whole small records are handled (alerts, CCS, the ServerHello) */
        if (t->rec_type == REC_HANDSHAKE) hs_feed(t, p, take);
        else if (t->rec_type == REC_ALERT) { if (take >= 2) alert_in(t, p, take); }
        else if (t->rec_type != REC_CCS) fail(t, TLS_E_RECORD);
        t->rec_pos = (uint16_t)(t->rec_pos + take);
      }
      p += take; n = (uint16_t)(n - take);
      if (t->rec_pos == t->rec_len) record_end(t);
    }
  }
}

const char *tls_error_text(const tls *t)
{
  switch (t->error) {
  case TLS_E_NONE: return "no error";
  case TLS_E_VERSION: return "the server does not speak TLS 1.3";
  case TLS_E_SUITE: return "the server offers neither ChaCha20-Poly1305 nor X25519";
  case TLS_E_ALERT: return "the server sent an alert";
  case TLS_E_RECORD: return "a malformed record";
  case TLS_E_MESSAGE: return "a malformed handshake";
  case TLS_E_TAG: return "a record failed authentication";
  case TLS_E_FINISHED: return "the server's Finished did not verify";
  case TLS_E_CERT: return "no usable certificate";
  case TLS_E_SIGNATURE: return "the server's signature is wrong";
  case TLS_E_BUFFER: return "the send buffer is too small";
  case TLS_E_HRR: return "the server wants another key exchange";
  }
  return "?";
}
