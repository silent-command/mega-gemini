#include "url.h"

static char lower(char c) { return (char)((c >= 'A' && c <= 'Z') ? c + 32 : c); }

static uint16_t slen(const char *s) { uint16_t n = 0; while (s[n]) n++; return n; }

static uint8_t scheme_char(char c)
{
  return (uint8_t)((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
                   c == '+' || c == '-' || c == '.');
}

/* The scheme's length if `s` starts with "scheme:", else 0. */
static uint16_t scheme_len(const char *s)
{
  uint16_t i = 0;
  if (!((s[0] >= 'a' && s[0] <= 'z') || (s[0] >= 'A' && s[0] <= 'Z'))) return 0;
  while (scheme_char(s[i])) i++;
  return (uint16_t)(s[i] == ':' ? i : 0);
}

uint8_t url_parse(const char *s, url_parts *out)
{
  uint16_t n, i;
  const char *p = s, *q;

  out->scheme[0] = 0; out->host[0] = 0; out->port = 0;
  out->path = ""; out->path_len = 0; out->query = 0; out->query_len = 0;

  n = scheme_len(p);
  if (n) {
    if (n > URL_SCHEME_MAX) return 0;
    for (i = 0; i < n; i++) out->scheme[i] = lower(p[i]);
    out->scheme[n] = 0;
    p += n + 1;
  }
  if (p[0] == '/' && p[1] == '/') {
    p += 2;
    for (q = p; *q && *q != '/' && *q != '?' && *q != '#' && *q != ':'; q++) ;
    if ((uint16_t)(q - p) > URL_HOST_MAX) return 0;
    for (i = 0; i < (uint16_t)(q - p); i++) out->host[i] = lower(p[i]);
    out->host[i] = 0;
    if (*q == ':') {
      uint32_t port = 0;
      q++;
      while (*q >= '0' && *q <= '9') { port = port * 10 + (uint32_t)(*q - '0'); if (port > 65535) return 0; q++; }
      if (*q && *q != '/' && *q != '?' && *q != '#') return 0;
      out->port = (uint16_t)port;
    }
    p = q;
  }
  for (q = p; *q && *q != '?' && *q != '#'; q++) ;
  out->path = p; out->path_len = (uint16_t)(q - p);
  if (*q == '?') {
    q++;
    out->query = q;
    while (*q && *q != '#') q++;
    out->query_len = (uint16_t)(q - out->query);
  }
  return 1;
}

/* Copies [s, s+n) to out+*at, bounded by URL_MAX. */
static uint8_t put(char *out, uint16_t *at, const char *s, uint16_t n)
{
  uint16_t i;
  if (*at + n > URL_MAX) return 0;
  for (i = 0; i < n; i++) out[*at + i] = s[i];
  *at = (uint16_t)(*at + n);
  return 1;
}

static uint8_t puts_(char *out, uint16_t *at, const char *s) { return put(out, at, s, slen(s)); }

/* ":port", when there is one */
static uint8_t put_port(char *out, uint16_t *at, uint16_t v)
{
  char t[7];
  uint8_t n = 6;
  if (!v) return 1;
  t[n] = 0;
  do { t[--n] = (char)('0' + v % 10); v /= 10; } while (v);
  t[--n] = ':';
  return puts_(out, at, t + n);
}

/* RFC 3986 5.2.4: removes "." and ".." segments in place, returning the
 * new length. Works on a path that starts with '/'. */
static uint16_t remove_dots(char *path, uint16_t len)
{
  uint16_t in = 0, out = 0;
  while (in < len) {
    /* the segment at `in`, up to the next '/' or the end */
    uint16_t seg = in + 1, seglen;
    while (seg < len && path[seg] != '/') seg++;
    seglen = (uint16_t)(seg - in - 1);
    if (seglen == 1 && path[in + 1] == '.') {
      in = seg;
      if (in >= len) { path[out++] = '/'; }          /* "/a/." -> "/a/" */
    } else if (seglen == 2 && path[in + 1] == '.' && path[in + 2] == '.') {
      while (out && path[out - 1] != '/') out--;     /* drop the last segment */
      if (out) out--;
      in = seg;
      if (in >= len) path[out++] = '/';              /* "/a/b/.." -> "/a/" */
    } else {
      while (in < seg) path[out++] = path[in++];
    }
  }
  if (!out) path[out++] = '/';
  return out;
}

uint8_t url_resolve(const char *base, const char *ref, char *out)
{
  url_parts b, r;
  uint16_t at = 0, pstart;

  if (!url_parse(base, &b) || !b.scheme[0] || !b.host[0]) return 0;
  if (!url_parse(ref, &r)) return 0;

  if (r.scheme[0]) {                                  /* absolute: as is, less a fragment */
    uint16_t n;
    for (n = 0; ref[n] && ref[n] != '#'; n++) ;
    if (!put(out, &at, ref, n)) return 0;
    out[at] = 0;
    return 1;
  }
  if (!puts_(out, &at, b.scheme) || !puts_(out, &at, "://")) return 0;
  if (r.host[0]) {                                    /* "//host/x": the base's scheme */
    if (!puts_(out, &at, r.host) || !put_port(out, &at, r.port)) return 0;
    pstart = at;
    if (r.path_len) { if (!put(out, &at, r.path, r.path_len)) return 0; }
    else if (!puts_(out, &at, "/")) return 0;
  } else {
    if (!puts_(out, &at, b.host) || !put_port(out, &at, b.port)) return 0;
    pstart = at;
    if (!r.path_len) {                                /* "" or "?q": the base's path */
      if (b.path_len) { if (!put(out, &at, b.path, b.path_len)) return 0; }
      else if (!puts_(out, &at, "/")) return 0;
      if (!r.query) {                                 /* the base's query too */
        if (b.query) { if (!puts_(out, &at, "?") || !put(out, &at, b.query, b.query_len)) return 0; }
        out[at] = 0;
        return 1;
      }
    } else if (r.path[0] == '/') {
      if (!put(out, &at, r.path, r.path_len)) return 0;
    } else {                                          /* merge: the base's directory, then the reference */
      uint16_t dir = b.path_len;
      while (dir && b.path[dir - 1] != '/') dir--;
      if (!dir) { if (!puts_(out, &at, "/")) return 0; }
      else if (!put(out, &at, b.path, dir)) return 0;
      if (!put(out, &at, r.path, r.path_len)) return 0;
    }
  }
  at = (uint16_t)(pstart + remove_dots(out + pstart, (uint16_t)(at - pstart)));
  if (r.query) { if (!puts_(out, &at, "?") || !put(out, &at, r.query, r.query_len)) return 0; }
  out[at] = 0;
  return 1;
}

uint8_t url_from_typed(const char *typed, char *out)
{
  uint16_t at = 0, n;
  while (*typed == ' ') typed++;
  for (n = 0; typed[n] && typed[n] != ' '; n++) ;
  if (!n) return 0;
  if (scheme_len(typed)) return put(out, &at, typed, n) && (out[at] = 0, 1);
  if (!puts_(out, &at, "gemini://")) return 0;
  if (typed[0] == '/' && typed[1] == '/') { typed += 2; n = (uint16_t)(n - 2); }
  if (!put(out, &at, typed, n)) return 0;
  { url_parts p; out[at] = 0; if (!url_parse(out, &p)) return 0; if (!p.path_len) { if (!puts_(out, &at, "/")) return 0; } }
  out[at] = 0;
  return 1;
}
