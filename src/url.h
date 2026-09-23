/* URLs as Gemini uses them: gemini://host[:port]/path[?query], and the
 * resolution of a link's target against the page it is on (RFC 3986
 * section 5, the parts that matter). C99 and stdint.h only. */
#ifndef URL_H
#define URL_H

#include <stdint.h>

#define URL_MAX 1024                /* the request line's limit, less CRLF */
#define URL_HOST_MAX 127
#define URL_SCHEME_MAX 15

typedef struct {
  char scheme[URL_SCHEME_MAX + 1]; /* lower-cased; "" if none */
  char host[URL_HOST_MAX + 1];     /* lower-cased; "" if none */
  uint16_t port;                   /* 0 if none given */
  const char *path;                /* into the source; "" if none */
  uint16_t path_len;
  const char *query;               /* after the '?', or 0 */
  uint16_t query_len;
} url_parts;

/* Splits `s` (NUL-terminated). Returns 0 for a malformed URL (a bad
 * port, a host too long). A missing scheme leaves scheme "" and host "";
 * the caller decides what that means. Fragments are dropped. */
uint8_t url_parse(const char *s, url_parts *out);

/* Resolves `ref` against `base` into `out` (at least URL_MAX + 1 bytes),
 * normalising dot segments. `ref` may be absolute, host-relative
 * ("//host/x"), path-absolute ("/x"), path-relative ("x", "../x") or
 * empty (the base itself, without its query). Returns 0 if the result
 * would not fit or `base` is not absolute. */
uint8_t url_resolve(const char *base, const char *ref, char *out);

/* A bare name typed by the user: "example.org", "example.org/path",
 * "gemini://…" or "//example.org" all become "gemini://…". */
uint8_t url_from_typed(const char *typed, char *out);

#endif
