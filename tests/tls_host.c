/* The TLS client over a real socket, on the host: fetches one Gemini URL
 * and prints what came back. The proof that src/tls/ talks to real
 * servers before any of it goes near the MEGA65.
 *
 *   build/host/tls_host gemini://geminiprotocol.net/ [--quiet] [--pin HEX]
 *
 * Prints the signature state, the key's pin (SHA-256 of the
 * SubjectPublicKeyInfo), the status line and the body. Exit 0 on a
 * 2x response, 2 on any other status, 1 on a failure. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <netdb.h>
#include <sys/socket.h>
#include "tls/tls.h"
#include "url.h"

static uint8_t *body;
static size_t body_len, body_cap, mark;
static int quiet;

static void h_on_data(void *ctx, const uint8_t *p, uint16_t n)
{
  (void)ctx;
  if (body_len + n > body_cap) { body_cap = (body_cap + n) * 2; body = realloc(body, body_cap); }
  memcpy(body + body_len, p, n); body_len += n;
}
static void h_on_record_end(void *ctx, uint8_t keep)
{
  (void)ctx;
  if (keep) mark = body_len; else body_len = mark;   /* the mark: what was known good before this record */
}

static const tls_hooks hooks = { 0, h_on_data, h_on_record_end };

static int send_all(int fd, tls *t)
{
  while (tls_out_len(t)) {
    ssize_t k = write(fd, tls_out_data(t), tls_out_len(t));
    if (k <= 0) return 0;
    tls_out_consumed(t, (uint16_t)k);
  }
  return 1;
}

int main(int argc, char **argv)
{
  static tls t;
  static uint8_t out[1600], in[512];
  url_parts u;
  char host[URL_HOST_MAX + 1], port[8], url[URL_MAX + 3];
  struct addrinfo hints, *ai;
  int fd, i;
  ssize_t k;
  const char *want_pin = 0;
  int delay = 0;                                   /* seconds between the handshake and the request: a server's request timer, measured (5.11) */

  if (argc < 2) { fprintf(stderr, "usage: tls_host gemini://host/path [--quiet] [--pin HEX] [--delay SECONDS]\n"); return 1; }
  for (i = 2; i < argc; i++) {
    if (!strcmp(argv[i], "--quiet")) quiet = 1;
    else if (!strcmp(argv[i], "--pin") && i + 1 < argc) want_pin = argv[++i];
    else if (!strcmp(argv[i], "--delay") && i + 1 < argc) delay = atoi(argv[++i]);
  }
  if (!url_from_typed(argv[1], url) || !url_parse(url, &u) || !u.host[0]) { fprintf(stderr, "not a URL: %s\n", argv[1]); return 1; }
  strcpy(host, u.host);
  snprintf(port, sizeof port, "%u", u.port ? u.port : 1965);

  memset(&hints, 0, sizeof hints); hints.ai_socktype = SOCK_STREAM;
  if (getaddrinfo(host, port, &hints, &ai)) { fprintf(stderr, "%s: no such host\n", host); return 1; }
  fd = socket(ai->ai_family, ai->ai_socktype, 0);
  if (connect(fd, ai->ai_addr, ai->ai_addrlen)) { perror("connect"); return 1; }
  freeaddrinfo(ai);

  if (!tls_start(&t, &hooks, host, out, sizeof out)) { fprintf(stderr, "tls_start failed\n"); return 1; }
  if (!send_all(fd, &t)) { perror("write"); return 1; }
  while (tls_state(&t) == TLS_WAIT_SH || tls_state(&t) == TLS_WAIT_HS) {
    k = read(fd, in, sizeof in);
    if (k <= 0) { fprintf(stderr, "the server hung up during the handshake\n"); return 1; }
    tls_in(&t, in, (uint16_t)k);
    if (!send_all(fd, &t)) { perror("write"); return 1; }
  }
  if (tls_state(&t) == TLS_VERIFYING) { if (!send_all(fd, &t)) { perror("write"); return 1; } tls_verify(&t); }
  if (tls_state(&t) != TLS_CONNECTED) { fprintf(stderr, "handshake: %s (alert %u, tls.c:%u, state %u, msg type %u len %u)\n", tls_error_text(&t), t.alert, t.error_line, t.state, t.msg_type, (unsigned)t.msg_len); return 1; }
  {
    uint8_t pin[32];
    char hex[65];
    if (!tk_pin(pin)) { fprintf(stderr, "certificate: no key found\n"); return 1; }
    for (i = 0; i < 32; i++) sprintf(hex + 2 * i, "%02x", pin[i]);
    if (!quiet)
      printf("signature: %s (scheme %04x); pin: %s\n",
             t.sig_state == TLS_SIG_VERIFIED ? "verified" : t.sig_state == TLS_SIG_UNCHECKED ? "UNCHECKED" : "wrong", t.sig_scheme, hex);
    if (want_pin && strcmp(want_pin, hex)) { fprintf(stderr, "PIN CHANGED\n"); return 1; }
  }
  if (delay) sleep((unsigned)delay);
  {
    size_t n = strlen(url);
    memcpy(url + n, "\r\n", 3);
    if (!tls_write(&t, (const uint8_t *)url, (uint16_t)(n + 2))) { fprintf(stderr, "request too long\n"); return 1; }
    if (!send_all(fd, &t)) { perror("write"); return 1; }
  }
  while (tls_state(&t) == TLS_CONNECTED) {
    k = read(fd, in, sizeof in);
    if (k <= 0) break;                             /* EOF: the end too, if no close_notify came */
    tls_in(&t, in, (uint16_t)k);
  }
  if (tls_state(&t) == TLS_FAILED) { fprintf(stderr, "transfer: %s (tls.c:%u)\n", tls_error_text(&t), t.error_line); return 1; }
  tls_close(&t); send_all(fd, &t); close(fd);
  if (!quiet) fprintf(stderr, "%zu bytes, %s\n", body_len, tls_state(&t) == TLS_CLOSED ? "close_notify" : "EOF");
  fwrite(body, 1, body_len, stdout);
  return body_len >= 2 && body[0] == '2' ? 0 : 2;
}
