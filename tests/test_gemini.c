/* The host suite for src/gemini.c: status lines, byte by byte and in one piece. */
#include <stdio.h>
#include <string.h>
#include "gemini.h"

static int checks, failed;
#define CHECK(cond, what) do { checks++; if (!(cond)) { failed++; printf("FAIL line %d: %s\n", __LINE__, what); } } while (0)

/* Feeds the text one byte at a time, then checks; returns the body offset. */
static uint16_t feed(gem_response *r, const char *text, uint8_t bytewise)
{
  uint16_t n = (uint16_t)strlen(text), used = 0, k;
  gem_start(r);
  if (bytewise) {
    while (used < n && !r->done) { k = gem_feed(r, (const uint8_t *)text + used, 1); used = (uint16_t)(used + k); }
  } else {
    used = gem_feed(r, (const uint8_t *)text, n);
  }
  return used;
}

int main(void)
{
  gem_response r;
  char d[80];
  uint8_t mode;

  for (mode = 0; mode < 2; mode++) {
    uint16_t at = feed(&r, "20 text/gemini\r\n# Hello\n", mode);
    CHECK(r.done && r.status == 20 && r.kind == GEM_SUCCESS && !strcmp(r.meta, "text/gemini") && r.is_gemini && r.is_text && r.charset_ok, "20 text/gemini");
    CHECK(at == 16, "body starts after CRLF");
    feed(&r, "20 text/gemini; charset=utf-8; lang=en\r\n", mode);
    CHECK(r.is_gemini && r.charset_ok, "parameters after the type");
    feed(&r, "20 text/gemini;charset=iso-8859-1\r\n", mode);
    CHECK(r.is_gemini && r.charset_ok, "latin-1 is foldable");
    feed(&r, "20 text/gemini; charset=utf-16\r\n", mode);
    CHECK(r.is_gemini && !r.charset_ok, "utf-16 is not");
    feed(&r, "20 TEXT/Plain\r\n", mode);
    CHECK(r.is_text && !r.is_gemini, "text/plain, any case");
    feed(&r, "20 text/geminiX\r\n", mode);
    CHECK(r.is_text && !r.is_gemini, "text/geminiX is not gemtext");
    feed(&r, "20 application/octet-stream\r\n", mode);
    CHECK(r.kind == GEM_SUCCESS && !r.is_text, "binary");
    feed(&r, "20\r\n", mode);
    CHECK(r.kind == GEM_SUCCESS && r.is_gemini && r.charset_ok, "no meta: the default type");
    feed(&r, "10 What is your name?\r\n", mode);
    CHECK(r.kind == GEM_INPUT && r.status == 10 && !strcmp(r.meta, "What is your name?"), "10 input");
    gem_describe(&r, d, sizeof d);
    CHECK(!strcmp(d, "10 What is your name?"), "describe 10");
    feed(&r, "11 Password\r\n", mode);
    CHECK(r.kind == GEM_INPUT && r.status == 11, "11 sensitive input");
    feed(&r, "31 gemini://other/\r\n", mode);
    CHECK(r.kind == GEM_REDIRECT && r.status == 31 && !strcmp(r.meta, "gemini://other/"), "31 redirect");
    feed(&r, "51 Not found\r\n", mode);
    CHECK(r.kind == GEM_PERM_FAIL, "51");
    gem_describe(&r, d, sizeof d);
    CHECK(!strcmp(d, "51 not found: Not found"), "describe 51");
    feed(&r, "44\r\n", mode);
    gem_describe(&r, d, sizeof d);
    CHECK(!strcmp(d, "44 slow down: try again later"), "describe 44 without meta");
    feed(&r, "60\r\n", mode);
    CHECK(r.kind == GEM_CERT, "60");
    feed(&r, "2x text/gemini\r\n", mode);
    CHECK(r.done && r.kind == GEM_BAD, "digits required");
    feed(&r, "20text/gemini\r\n", mode);
    CHECK(r.done && r.kind == GEM_BAD, "a space after the status");
    feed(&r, "20 text/gemini\n", mode);
    CHECK(r.done && r.kind == GEM_BAD, "bare LF refused");
    feed(&r, "20 text/gemini\r\rx", mode);
    CHECK(r.done && r.kind == GEM_BAD, "CR not followed by LF refused");
    feed(&r, "70 what\r\n", mode);
    CHECK(r.done && r.kind == GEM_BAD, "status 7x refused");
    gem_describe(&r, d, sizeof d);
    CHECK(!strcmp(d, "not a Gemini response: what"), "describe bad");
    { static char big[1100]; memset(big, 'a', sizeof big - 1); big[0] = '2'; big[1] = '0'; big[2] = ' '; big[sizeof big - 1] = 0;
      feed(&r, big, mode);
      CHECK(r.done && r.kind == GEM_BAD, "header over 1027 refused");
      memcpy(big + 900, "\r\n", 3);
      feed(&r, big, mode);
      CHECK(r.done && r.kind == GEM_SUCCESS && r.meta_len == GEM_META_MAX && r.hdr_len == 900, "a 897-byte meta is kept to 512 and the header read whole"); }
  }
  /* fed in pieces across the CRLF */
  gem_start(&r);
  CHECK(gem_feed(&r, (const uint8_t *)"20 text/gem", 11) == 11 && !r.done, "piece 1");
  CHECK(gem_feed(&r, (const uint8_t *)"ini\r", 4) == 4 && !r.done, "piece 2");
  CHECK(gem_feed(&r, (const uint8_t *)"\nbody", 5) == 1 && r.done && r.is_gemini, "piece 3: one byte of header, the rest body");
  CHECK(gem_feed(&r, (const uint8_t *)"more", 4) == 0, "after the header nothing is header");

  printf("%d checks, %d failed\n", checks, failed);
  return failed != 0;
}
