#include "gemini.h"

void gem_start(gem_response *r)
{
  r->done = 0; r->status = 0; r->kind = GEM_BAD;
  r->meta_len = 0; r->meta[0] = 0; r->hdr_len = 0; r->cr = 0;
  r->is_text = r->is_gemini = r->charset_ok = r->is_latin1 = 0;
}

static char lower(char c) { return (char)((c >= 'A' && c <= 'Z') ? c + 32 : c); }

/* Compares meta at `at` with a lower-case word, case-insensitively. */
static uint8_t word_at(const gem_response *r, uint16_t at, const char *w)
{
  uint16_t i;
  for (i = 0; w[i]; i++) if (at + i >= r->meta_len || lower(r->meta[at + i]) != w[i]) return 0;
  return 1;
}

static void classify(gem_response *r)
{
  uint16_t i;
  r->kind = (uint8_t)(r->status / 10);
  if (r->kind < 1 || r->kind > 6) r->kind = GEM_BAD;
  if (r->kind != GEM_SUCCESS) return;
  if (!r->meta_len) {                             /* the default type */
    const char *d = "text/gemini; charset=utf-8";
    for (i = 0; d[i]; i++) r->meta[i] = d[i];
    r->meta[i] = 0; r->meta_len = i;
  }
  r->is_text = word_at(r, 0, "text/");
  r->is_gemini = word_at(r, 0, "text/gemini") && (r->meta_len == 11 || r->meta[11] == ';' || r->meta[11] == ' ');
  r->charset_ok = 1;
  for (i = 0; i + 8 <= r->meta_len; i++) {
    if (word_at(r, i, "charset=")) {
      uint16_t v = (uint16_t)(i + 8);
      r->is_latin1 = word_at(r, v, "iso-8859-1");
      r->charset_ok = (uint8_t)(word_at(r, v, "utf-8") || word_at(r, v, "us-ascii") || r->is_latin1 || word_at(r, v, "ascii"));
      break;
    }
  }
}

uint16_t gem_feed(gem_response *r, const uint8_t *p, uint16_t n)
{
  uint16_t used = 0;
  if (r->done) return 0;
  while (used < n) {
    uint8_t b = p[used++];
    if (r->cr) {
      if (b != '\n') { r->kind = GEM_BAD; r->done = 1; return used; }
      /* the line: two digits, a space (or nothing), the meta */
      if (r->hdr_len < 2 || r->meta[0] < '0' || r->meta[0] > '9' || r->meta[1] < '0' || r->meta[1] > '9') { r->kind = GEM_BAD; r->done = 1; return used; }
      r->status = (uint8_t)((r->meta[0] - '0') * 10 + (r->meta[1] - '0'));
      if (r->meta_len > 2 && r->meta[2] != ' ') { r->kind = GEM_BAD; r->done = 1; return used; }
      if (r->meta_len > 3) {
        uint16_t i;
        for (i = 3; i < r->meta_len; i++) r->meta[i - 3] = r->meta[i];
        r->meta_len = (uint16_t)(r->meta_len - 3);
      } else r->meta_len = 0;
      r->meta[r->meta_len] = 0;
      r->done = 1;
      classify(r);
      return used;
    }
    if (b == '\r') { r->cr = 1; continue; }
    if (b == '\n') { r->kind = GEM_BAD; r->done = 1; return used; }   /* a bare LF is not a Gemini header */
    if (r->hdr_len >= GEM_HDR_MAX) { r->kind = GEM_BAD; r->done = 1; return used; }
    if (r->meta_len < GEM_META_MAX + 3) r->meta[r->meta_len++] = (char)b;   /* the rest of a long meta is counted, not kept */
    r->hdr_len++;
  }
  return used;
}

void gem_describe(const gem_response *r, char *out, uint8_t cap)
{
  const char *why = 0;
  uint8_t n = 0;
  uint16_t i;
  if (r->kind == GEM_BAD) why = "not a Gemini response";
  else switch (r->status) {
  case 10: case 11: why = r->meta_len ? 0 : "input wanted"; break;
  case 20: why = 0; break;
  case 30: case 31: why = "redirect"; break;
  case 40: why = "temporary failure"; break;
  case 41: why = "server unavailable"; break;
  case 42: why = "CGI error"; break;
  case 43: why = "proxy error"; break;
  case 44: why = "slow down: try again later"; break;
  case 50: why = "permanent failure"; break;
  case 51: why = "not found"; break;
  case 52: why = "gone"; break;
  case 53: why = "proxy request refused"; break;
  case 59: why = "bad request"; break;
  case 60: why = "a client certificate is required, which this client has none of"; break;
  case 61: why = "certificate not authorised"; break;
  case 62: why = "certificate not valid"; break;
  default: why = r->kind == GEM_SUCCESS ? 0 : "status"; break;
  }
  if (r->kind != GEM_BAD) { out[n++] = (char)('0' + r->status / 10); out[n++] = (char)('0' + r->status % 10); out[n++] = ' '; }
  if (why) { for (i = 0; why[i] && n < cap - 1; i++) out[n++] = why[i]; }
  if (r->meta_len && n < cap - 1) {
    if (why) { out[n++] = ':'; if (n < cap - 1) out[n++] = ' '; }
    for (i = 0; i < r->meta_len && n < cap - 1; i++) out[n++] = r->meta[i];
  }
  out[n] = 0;
}
