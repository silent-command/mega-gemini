/* A TLS 1.3 client (RFC 8446) for one connection at a time, the shape
 * a Gemini request has: connect, send one line, read until the server
 * closes. One cipher suite, TLS_CHACHA20_POLY1305_SHA256; one group,
 * X25519; no resumption, no client certificate, no renegotiation of
 * anything. Every cryptographic step is asked of the kit (tlskit.h),
 * which keeps the keys and the server's certificate: on the MEGA65 that
 * is the bank; here only the framing and the parsing.
 *
 * Nothing here blocks or owns a socket: the caller moves bytes.
 *   tls_start()  builds the ClientHello into the out buffer;
 *   tls_in()     takes bytes the socket delivered, any amount;
 *   tls_out_*()  says what to send, and the caller sends it;
 *   tls_write()  queues application data for sending;
 *   tls_close()  queues close_notify.
 * Received application data reaches the caller through on_data() as it
 * is decrypted, before the record's tag has been checked; at the end
 * of every record on_record_end() says whether to keep it. A record
 * that turns out to be something else (a session ticket, an alert) is
 * likewise taken back. So the caller keeps a mark per record.
 *
 * C99 and the crypto/ tree only; the host harness in tests/ runs it
 * against real servers. */
#ifndef TLS_H
#define TLS_H

#include <stdint.h>
#include <stddef.h>
#include "tlskit.h"

/* states */
#define TLS_IDLE 0
#define TLS_WAIT_SH 1          /* ClientHello sent */
#define TLS_WAIT_HS 2          /* keys up; the encrypted handshake is arriving */
#define TLS_CONNECTED 3
#define TLS_CLOSED 4           /* the server's close_notify: the end of the data */
#define TLS_FAILED 5           /* tls_error() says why */
#define TLS_VERIFYING 6        /* the handshake is complete and the client's Finished queued; the server's
                                  signature is still to be verified: tls_verify() next, after sending */

/* errors */
#define TLS_E_NONE 0
#define TLS_E_VERSION 1        /* not TLS 1.3 */
#define TLS_E_SUITE 2          /* the server chose another suite or group */
#define TLS_E_ALERT 3          /* an alert; tls_alert() has it */
#define TLS_E_RECORD 4         /* a malformed record, or one too long */
#define TLS_E_MESSAGE 5        /* a malformed or unexpected handshake message */
#define TLS_E_TAG 6            /* a record failed authentication */
#define TLS_E_FINISHED 7       /* the server's Finished did not verify */
#define TLS_E_CERT 8           /* no usable certificate */
#define TLS_E_SIGNATURE 9      /* the CertificateVerify signature is wrong */
#define TLS_E_BUFFER 10        /* the out buffer is too small for what must be sent */
#define TLS_E_HRR 11           /* the server asked for another key share */

/* how the server's signature was handled */
#define TLS_SIG_UNCHECKED TK_UNCHECKED   /* a scheme this client cannot verify: the key is pinned but not proven */
#define TLS_SIG_VERIFIED TK_VERIFIED

#define TLS_MSG_MAX 528        /* the largest handshake message buffered whole (all but Certificate): CertificateVerify with an RSA-4096 signature is 520 */
#define TLS_OUT_MIN 200        /* the out buffer must hold a ClientHello */

typedef struct tls tls;

typedef struct {
  void *ctx;
  /* application data as decrypted; then keep or discard the record */
  void (*on_data)(void *ctx, const uint8_t *p, uint16_t n);
  void (*on_record_end)(void *ctx, uint8_t keep);
} tls_hooks;

struct tls {
  const tls_hooks *hooks;
  uint8_t state, error, alert;
  uint16_t error_line;        /* the tls.c line that failed, for diagnosis */
  uint8_t sig_state;          /* TLS_SIG_* once the handshake is done */
  uint16_t sig_scheme;        /* the server's, e.g. 0x0403 */

  /* the out buffer: what the caller must send, in order */
  uint8_t *out; uint16_t out_cap, out_len;

  uint8_t rd_on, wr_on;       /* the keys are up: records are encrypted from here */

  /* the record being read */
  uint8_t hdr[5], hdr_len;
  uint16_t rec_len, rec_pos;  /* total and consumed, tag included */
  uint8_t rec_type;           /* the outer type */
  uint16_t rec_index;         /* records read so far, for diagnosis */
  uint8_t inner_type;         /* the byte before the tag */
  uint8_t tag[16], tag_len;
  uint8_t last2[2];           /* the last two content bytes: an alert, if the record is one */
  uint8_t rec_connected;      /* the record began after the handshake: its data is the caller's */
  uint8_t rd_switch;          /* to the application read keys when this record ends */
  uint8_t cert_requested, cert_req_ctx_len, cert_req_ctx[32];   /* the server's CertificateRequest, answered empty */
  uint8_t cv_seen;            /* CertificateVerify is in msg, awaiting tls_verify() */

  /* the handshake message being read (plaintext) */
  uint8_t msg_type; uint32_t msg_len, msg_pos;
  uint8_t msg[TLS_MSG_MAX];   /* the message body, when it is buffered whole */
  uint8_t fin[32];            /* the server's Finished, kept apart: msg still holds CertificateVerify for tls_verify() */
  uint8_t msg_whole;          /* 1 buffered in msg, 2 in fin, 0 streamed (Certificate) */
  /* Certificate streaming */
  uint32_t cert_list_left;    /* bytes of the certificate list still to come */
  uint32_t cert_left;         /* bytes of the current entry's DER still to come */
  uint32_t ext_left;          /* bytes of the current entry's extensions still to come */
  uint8_t cert_index;         /* 0 = the leaf */
  uint8_t cert_phase;         /* 0 context, 1 list length, 2 entry length, 3 der, 4 ext length, 5 ext */
  uint8_t cert_lenbuf[3], cert_lenlen;
  uint16_t leaf_len;          /* the leaf DER's length, for the caller */

  /* transcript hashes taken along the way */
  uint8_t hash_ch_sh[32], hash_to_cv[32], hash_to_sfin[32];
#ifdef TLS_P256
  /* for answering a HelloRetryRequest with a P-256 share: the second
   * ClientHello must repeat the first except for that share (RFC 8446
   * 4.1.2), so the first's random and name are kept (mega-irc 5.12) */
  uint8_t rnd[32];
  const char *sni;            /* the caller's; it stays valid through the handshake */
  uint8_t hrr_done;           /* a second retry is refused */
#endif
};

/* Starts a connection to `sni` (the name in the request; ASCII). The out
 * buffer holds what to send. Returns 0 if the buffer is too small. */
uint8_t tls_start(tls *t, const tls_hooks *hooks, const char *sni, uint8_t *out, uint16_t out_cap);

/* Bytes from the socket; decrypted in place, so the buffer is the
 * caller's to give up: what is in it afterwards is plaintext (or the
 * record's tag, or a header), not to be fed again. */
void tls_in(tls *t, uint8_t *p, uint16_t n);

/* The bytes to send, and how many the caller has now sent. */
static inline const uint8_t *tls_out_data(const tls *t) { return t->out; }
static inline uint16_t tls_out_len(const tls *t) { return t->out_len; }
void tls_out_consumed(tls *t, uint16_t n);

/* Queues n bytes of application data. Returns 0 if they do not fit the
 * out buffer now (send what is there first). */
uint8_t tls_write(tls *t, const uint8_t *p, uint16_t n);
/* The same for n bytes the caller has already written at
 * tls_write_at(t): the send buffer's next record's payload position,
 * so a request can be built where it is sealed (the MEGA65 client's
 * send buffer shares its memory with its scratch line: 5.8). */
static inline uint8_t *tls_write_at(tls *t) { return t->out + t->out_len + 5; }
uint8_t tls_write_here(tls *t, uint16_t n);
/* Queues close_notify. */
uint8_t tls_close(tls *t);

/* The server's signature over the handshake, checked once the client's
 * Finished has been sent (the long computation on a small machine then
 * runs against the server's request timer, not its handshake timer).
 * Nothing is trusted or sent until it passes: TLS_VERIFYING becomes
 * TLS_CONNECTED, or TLS_FAILED. */
void tls_verify(tls *t);

static inline uint8_t tls_state(const tls *t) { return t->state; }
static inline uint8_t tls_error(const tls *t) { return t->error; }
const char *tls_error_text(const tls *t);

#endif
