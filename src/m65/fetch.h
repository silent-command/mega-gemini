/* One Gemini request: resolve, connect, TLS, the request line, the
 * response into the document store, the connection closed. The status
 * line is parsed once its record has been kept, so nothing is believed
 * before its tag. Every wait bounded; RUN/STOP cancels. */
#ifndef FETCH_H
#define FETCH_H

#include <stdint.h>
#include "gemini.h"

typedef struct {
  gem_response resp;         /* done and classified when fetch() returns 1 */
  uint32_t body_off;         /* where the body starts in the raw document */
  uint8_t sig_state;         /* TK_VERIFIED, TK_UNCHECKED */
  uint8_t pin_state;         /* PIN_NEW, PIN_KNOWN, PIN_CHANGED */
  uint8_t pin[32];
  char host[128];
  uint16_t port;
} fetch_result;

/* 1 with r filled; 0 with *err. With `trust_change`, a changed key is
 * accepted for this fetch and replaces the pin. */
/* main.c's buffer for the URL to fetch next, URL_MAX + 1 bytes: the
 * engine's state lives in it during a fetch (5.9), so the URL passed to
 * fetch() is never this one, and nothing reads it until fetch() returns. */
extern char next_url[];

uint8_t fetch(const char *url, uint8_t trust_change, fetch_result *r, const char **err);
/* after a fetch that returned 1: " in N.N s", the seconds the bank spent on the shared secret and the signature (5.12, 5.15) */
extern const char *fetch_diag;
/* after a fetch that returned 1 with the page cut short: why the transfer ended; else null */
extern const char *fetch_cut_why;

#endif
