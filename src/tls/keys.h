/* The TLS 1.3 key schedule (RFC 8446 7.1) for TLS_CHACHA20_POLY1305_SHA256
 * with an (EC)DHE key exchange and no PSK: the three extracts, the
 * derived secrets, the traffic keys, the Finished MACs. C99 over
 * crypto/hkdf.h; proved on the host against RFC 8448. */
#ifndef TLS_KEYS_H
#define TLS_KEYS_H

#include <stdint.h>
#include <stddef.h>

/* HKDF-Expand-Label(secret, label, context, len), the "tls13 " prefix
 * added here; label at most 12 characters, context at most 32 bytes. */
void tls_expand_label(const uint8_t secret[32], const char *label, const uint8_t *ctx, uint8_t ctxlen, uint8_t *out, uint8_t outlen);

/* Derive-Secret(secret, label, transcript) with the transcript's hash. */
void tls_derive_secret(const uint8_t secret[32], const char *label, const uint8_t hash[32], uint8_t out[32]);

typedef struct { uint8_t key[32], iv[12]; } tls_traffic;

/* A traffic key and IV from a traffic secret. */
void tls_traffic_keys(const uint8_t secret[32], tls_traffic *t);

/* The nonce for record `seq` under `t`: the IV with the 64-bit sequence
 * number XORed into its last 8 bytes, big-endian. */
void tls_nonce(const tls_traffic *t, uint32_t seq_hi, uint32_t seq_lo, uint8_t nonce[12]);

/* verify_data = HMAC(Expand-Label(base_key, "finished", "", 32), transcript hash). */
void tls_finished(const uint8_t base_key[32], const uint8_t hash[32], uint8_t out[32]);

typedef struct {
  uint8_t early[32];         /* Extract(0, 0): no PSK */
  uint8_t handshake[32];     /* Extract(Derive(early, "derived", ""), ECDHE) */
  uint8_t master[32];        /* Extract(Derive(handshake, "derived", ""), 0) */
  uint8_t c_hs[32], s_hs[32], c_ap[32], s_ap[32];
} tls_schedule;

/* Steps of the schedule, in order: */
void tls_schedule_start(tls_schedule *s);                                    /* early and the derived salt */
void tls_schedule_handshake(tls_schedule *s, const uint8_t ecdhe[32], const uint8_t hash_ch_sh[32]);
void tls_schedule_master(tls_schedule *s, const uint8_t hash_ch_sfin[32]);   /* through the server Finished */

#endif
