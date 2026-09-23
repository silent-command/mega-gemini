/* The Gemini response: the status line, then the body. Fed the bytes
 * as they arrive; says when the header is complete and what it means,
 * then passes body bytes on. C99 and stdint.h only. */
#ifndef GEMINI_H
#define GEMINI_H

#include <stdint.h>

#define GEM_META_MAX 512         /* kept of the meta; a header may run to 1024 + CRLF and is read to there */
#define GEM_HDR_MAX 1027

/* what the status means for the client */
#define GEM_INPUT 1            /* 1x: ask the user a line (11: hidden), re-request with it as the query */
#define GEM_SUCCESS 2          /* 2x: the body follows; meta is the MIME type */
#define GEM_REDIRECT 3         /* 3x: meta is the new URL */
#define GEM_TEMP_FAIL 4        /* 4x */
#define GEM_PERM_FAIL 5        /* 5x */
#define GEM_CERT 6             /* 6x: a client certificate wanted; this client has none */
#define GEM_BAD 0              /* not a Gemini status line */

typedef struct {
  uint8_t done;                /* the header has been read */
  uint8_t status;              /* the two digits as a number, e.g. 20 */
  uint8_t kind;                /* GEM_* from the first digit */
  char meta[GEM_META_MAX + 4];   /* the status and space are read here first, then stripped */
  uint16_t meta_len;
  uint16_t hdr_len;            /* bytes of header seen (to bound it) */
  uint8_t cr;                  /* the CR seen, awaiting LF */
  /* for GEM_SUCCESS: */
  uint8_t is_text;             /* a text type of any kind */
  uint8_t is_gemini;           /* text/gemini */
  uint8_t charset_ok;          /* utf-8, us-ascii, iso-8859-1 or none: something this client can fold */
  uint8_t is_latin1;           /* charset=iso-8859-1: one byte per character, folded as such (5.10) */
} gem_response;

void gem_start(gem_response *r);

/* Takes bytes; returns how many were header (consumed here); the rest,
 * from p + returned, is body. After the header, returns 0. Sets
 * r->done, and kind = GEM_BAD if the header was malformed or too long. */
uint16_t gem_feed(gem_response *r, const uint8_t *p, uint16_t n);

/* The header as a message for the user, e.g. "51 Not found" or the
 * meta of a 1x prompt; at most 79 characters into out. */
void gem_describe(const gem_response *r, char *out, uint8_t cap);

#endif
