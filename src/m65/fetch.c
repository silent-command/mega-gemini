#include "lowram.h"
#include "mega65/memory.h"
#include "tls/tls.h"
#include "url.h"
#include "netutil.h"
#include "doc.h"
#include "pins.h"
#include "ui.h"
#include "rnd.h"
#include "fetch.h"
#include "m65_tlskit.h"

#define FIRST_BYTE_FRAMES 1500     /* 30 s to the first byte: the handshake's arithmetic is inside this */
#define IDLE_FRAMES 500            /* 10 s between bytes */
#define CLOSE_FRAMES 60

/* The program window is full (5.6, 5.9): the engine's state overlays
 * the caller's next-URL buffer (main.c), which is dead from the moment
 * the URL it held has become the page's own, before fetch() is called,
 * until the fetch is over; 774 bytes in 1025. */
#define t (*(tls *)next_url)
#define in ((uint8_t *)0x1400)      /* the receive buffer, $1400-$14FF, low RAM (5.6, 5.8) */
#define IN_CAP 256
/* the send buffer: the ClientHello, the Finished, then a 1024-byte
 * request line sealed (5 + 1026 + 1 + 16); it shares $1A00 with the
 * scratch line, which is dead during a fetch, so the request is built
 * in place with tls_write_here() rather than copied in (5.8) */
#define out ((uint8_t *)0x1A00)
#define OUT_CAP 1060
static fetch_result *res;
static uint8_t hdr_done;
static const char *fail_why;
#define fail_text LOW_FAIL_TEXT           /* 80 bytes, low RAM (5.9) */
const char *fetch_diag = LOW_DIAG;        /* " in N.N s": the handshake's arithmetic, 31 bytes of low RAM (5.12, 5.15) */
const char *fetch_cut_why;                /* why a page that arrived was cut short, else null */


/* The engine's error with the tls.c line that raised it: the diagnosis
 * that found every host-side fault (REQUIREMENTS.md 5.2). */
static char *put_s(char *p, const char *s) { while (*s) *p++ = *s++; return p; }
static char *put_n(char *p, uint16_t v)
{
  char d[5]; uint8_t n = 0;
  do { d[n++] = (char)('0' + v % 10); v /= 10; } while (v);
  while (n) *p++ = d[--n];
  return p;
}

static const char *tls_fail(void)
{
  const char *m = tls_error_text(&t);
  char *p = fail_text;
  while (*m && p < fail_text + 60) *p++ = *m++;
  p = put_n(put_s(p, " (tls.c:"), t.error_line);
  *p++ = ')';
  if (t.error == TLS_E_SIGNATURE) { p = put_s(p, " why "); *p++ = (char)('0' + tk_verify_reason); }
  if (t.error == TLS_E_TAG)                        /* which record, and what it turned out to be */
    p = put_n(put_s(put_n(put_s(p, " rec "), t.rec_index), " type "), t.inner_type);
  if (t.error == TLS_E_RECORD)                     /* which record, its header's version byte and its length (5.12) */
    p = put_n(put_s(put_n(put_s(put_n(put_s(p, " rec "), t.rec_index), " v "), t.hdr[1]), " len "), t.rec_len);
  *p = 0;
  return fail_text;
}

/* application data, tentative until the record's tag */
static void on_data(void *ctx, const uint8_t *p, uint16_t n)
{
  (void)ctx;
  doc_append(p, n);
}

/* the record kept: the status line is parsed from what is now known
 * good, once, from the start of the raw document */
static void on_record_end(void *ctx, uint8_t keep)
{
  (void)ctx;
  if (!keep) { doc_rollback(); return; }
  doc_mark();
  if (!hdr_done) {
    /* The status line is parsed from the raw document through a buffer of
     * its own, never through `in`: `in` is the live receive chunk, and the
     * next record's header may still be sitting in it behind the record
     * that just ended. bbs.geminispace.org sends the whole page as its
     * first application record with close_notify in the same chunk, and
     * reading the document into `in` here wrote page text over that
     * header: "a malformed record" at the record after the page (5.13). */
#define hdrbuf ((uint8_t *)LOW_ROW_TEXT)   /* the pager's row text, idle during a fetch; HDRBUF_LEN bytes (a pointer: not sizeof, 5.8) */
#define HDRBUF_LEN 64
    uint32_t len = doc_raw_len(), at = 0;
    uint16_t take, used;
    gem_start(&res->resp);
    while (at < len && !res->resp.done) {
      take = len - at < HDRBUF_LEN ? (uint16_t)(len - at) : (uint16_t)HDRBUF_LEN;
      doc_raw_read(at, hdrbuf, take);
      used = gem_feed(&res->resp, hdrbuf, take);
      at += used;
      if (used < take) break;
    }
    if (res->resp.done) { hdr_done = 1; res->body_off = at; }
    else if (len > GEM_HDR_MAX) { res->resp.done = 1; res->resp.kind = GEM_BAD; hdr_done = 1; res->body_off = len; }
  }
}

static const tls_hooks hooks = { 0, on_data, on_record_end };

/* Sends what the engine has queued; 0 if the connection is gone. */
static uint8_t push_out(void)
{
  unsigned int n;
  while (tls_out_len(&t)) {
    n = net_send(tls_out_data(&t), tls_out_len(&t));
    if (n) tls_out_consumed(&t, (uint16_t)n);
    else { net_poll(); if (!net_alive()) return 0; }
    ui_spin();
  }
  return 1;
}

/* Pumps the connection until `done` or a bound; returns 0 on the bound
 * or a cancel, with fail_why set. */
static uint8_t pump(uint8_t (*done)(void), unsigned int bound)
{
  unsigned int n;
  net_frames = 0;
  for (;;) {
    net_poll();
    n = net_recv(in, IN_CAP);
    if (n) { tls_in(&t, in, (uint16_t)n); net_frames = 0; rnd_stir((uint8_t)n); }
    if (!push_out()) { fail_why = "the connection was lost"; return 0; }
    if (tls_state(&t) == TLS_FAILED) { fail_why = tls_fail(); return 0; }
    if (done()) return 1;
    if (!n && !net_alive()) return 1;              /* the peer is gone: the caller judges */
    if (net_frames > bound) { fail_why = "no answer from the server"; return 0; }
    if (ui_key() == KEY_STOP) { fail_why = "cancelled"; return 0; }
    ui_spin();
  }
}

static uint8_t handshake_done(void) { return (uint8_t)(tls_state(&t) != TLS_WAIT_SH && tls_state(&t) != TLS_WAIT_HS); }
static uint8_t transfer_done(void) { return (uint8_t)(tls_state(&t) != TLS_CONNECTED); }

uint8_t fetch(const char *url, uint8_t trust_change, fetch_result *r, const char **err)
{
  url_parts u;
  unsigned char ip[4];
  uint16_t n;
  const char *why;

  res = r; hdr_done = 0; fail_why = 0; fetch_cut_why = 0;
  r->resp.done = 0; r->body_off = 0;
  if (!url_parse(url, &u) || !u.host[0]) { *err = "not a URL"; return 0; }
  if (u.scheme[0] && (u.scheme[0] != 'g' || u.scheme[1] != 'e' || u.scheme[2] != 'm' || u.scheme[3] != 'i' || u.scheme[4] != 'n' || u.scheme[5] != 'i' || u.scheme[6])) { *err = "only gemini:// here"; return 0; }
  for (n = 0; u.host[n] && n < sizeof r->host - 1; n++) r->host[n] = u.host[n];
  r->host[n] = 0;
  r->port = u.port ? u.port : 1965;

  ui_status("looking up ", r->host);
  if (!net_resolve(r->host, ip, &why)) { *err = why; return 0; }
  ui_status("connecting...", 0);
  if (!net_connect(ip, r->port, &why)) { *err = why; return 0; }

  doc_clear();
  ui_status("the handshake: keys, then the server's signature...", 0);
  if (!tls_start(&t, &hooks, r->host, out, OUT_CAP)) { net_abort(); *err = "the send buffer is too small"; return 0; }
  if (!pump(handshake_done, FIRST_BYTE_FRAMES) || tls_state(&t) != TLS_VERIFYING) {
    net_abort(); *err = fail_why ? fail_why : "the server hung up during the handshake"; return 0;
  }
  /* the client's Finished goes out first, then the signature is checked:
   * the minutes of arithmetic run against the server's request timer,
   * not its handshake timer (5.6); nothing is sent until it passes */
  if (!push_out()) { net_abort(); *err = "the connection was lost"; return 0; }
  ui_status("the server's signature...", 0);
  tls_verify(&t);
  if (tls_state(&t) != TLS_CONNECTED) { net_abort(); *err = tls_fail(); return 0; }
  { uint16_t frames = (uint16_t)(tk_frames_keys + tk_frames_verify), secs = 0;   /* frames at 50 a second: the shared secret and the signature, as whole seconds (5.15) */
    while (frames >= 50) { frames = (uint16_t)(frames - 50); secs++; }   /* a loop, not a division: the room (5.15) */
    *put_s(put_n(put_s(LOW_DIAG, " in "), secs), " s") = 0; }
  r->sig_state = t.sig_state;
  if (!tk_pin(r->pin)) { net_abort(); *err = "no usable certificate"; return 0; }
  r->pin_state = pins_check(r->host, r->port, r->pin);
  if (r->pin_state == PIN_CHANGED) {
    if (!trust_change) { net_abort(); *err = "the server's key has CHANGED since it was pinned"; return 0; }
    pins_replace(r->host, r->port, r->pin);
  }

  ui_status("asking for ", url);
  if (!push_out()) { net_abort(); *err = "the connection was lost"; return 0; }   /* the buffer empty: the request goes at its start */
  { uint8_t *req = tls_write_at(&t);             /* the request line, built where it is sealed */
    for (n = 0; url[n] && n < URL_MAX; n++) req[n] = (uint8_t)url[n];
    req[n++] = '\r'; req[n++] = '\n';
    if (!tls_write_here(&t, n)) { net_abort(); *err = "the request is too long"; return 0; } }
  if (!push_out()) { net_abort(); *err = "the connection was lost"; return 0; }
  ui_status("receiving...", 0);
  doc_mark();
  if (!pump(transfer_done, IDLE_FRAMES)) {
    /* what arrived so far is kept if the header was seen: a page cut short is still a page */
    net_abort();
    if (!hdr_done) { *err = fail_why; return 0; }
    fetch_cut_why = fail_why;                    /* said on the status row beside the page */
  }
  if (tls_state(&t) == TLS_FAILED && !hdr_done) { net_abort(); *err = tls_fail(); return 0; }
  /* a polite end: close_notify and the socket, briefly */
  tls_close(&t); push_out();
  net_close();
  net_frames = 0;
  while (net_frames < CLOSE_FRAMES && net_alive()) net_poll();
  net_abort();
  ui_spin_clear();
  if (!hdr_done) { *err = doc_raw_len() ? "not a Gemini response" : "the server sent nothing"; return 0; }
  *err = 0;
  return 1;
}
