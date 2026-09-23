/* The host suite for src/gemtext.c and src/url.c: python3 build.py test. */
#include <stdio.h>
#include <string.h>
#include "gemtext.h"
#include "url.h"

static int checks, failed;
#define CHECK(cond, what) do { checks++; if (!(cond)) { failed++; printf("FAIL line %d: %s\n", __LINE__, what); } } while (0)

static gt_state st;

static void line(const char *s, uint8_t kind, const char *text, const char *url)
{
  gt_line l;
  char msg[160];
  gt_classify(&st, s, (uint16_t)strlen(s), &l);
  snprintf(msg, sizeof msg, "\"%s\": kind %d text \"%.*s\" url \"%.*s\"", s, l.kind, l.text_len, l.text, l.url_len, l.url ? l.url : "");
  CHECK(l.kind == kind && l.text_len == strlen(text) && !memcmp(l.text, text, l.text_len) &&
        ((!url && !l.url) || (url && l.url && l.url_len == strlen(url) && !memcmp(l.url, url, l.url_len))), msg);
}

static void wrap(const char *text, uint8_t width, const char *want)
{
  char got[512] = "", msg[600];
  uint16_t pos = 0, start, n;
  for (;;) {
    start = pos;                                    /* the row begins where the last call left off */
    n = gt_wrap(text, (uint16_t)strlen(text), &pos, width);
    if (!n) break;
    strncat(got, text + start, n); strcat(got, "|");
  }
  snprintf(msg, sizeof msg, "wrap %d \"%s\" -> \"%s\" (want \"%s\")", width, text, got, want);
  CHECK(!strcmp(got, want), msg);
}

static void resolve(const char *base, const char *ref, const char *want)
{
  char out[URL_MAX + 1], msg[400];
  uint8_t ok = url_resolve(base, ref, out);
  snprintf(msg, sizeof msg, "resolve \"%s\" + \"%s\" -> \"%s\" (want \"%s\")", base, ref, ok ? out : "<fail>", want ? want : "<fail>");
  CHECK(want ? (ok && !strcmp(out, want)) : !ok, msg);
}

static void typed(const char *in, const char *want)
{
  char out[URL_MAX + 1], msg[300];
  uint8_t ok = url_from_typed(in, out);
  snprintf(msg, sizeof msg, "typed \"%s\" -> \"%s\" (want \"%s\")", in, ok ? out : "<fail>", want ? want : "<fail>");
  CHECK(want ? (ok && !strcmp(out, want)) : !ok, msg);
}

int main(void)
{
  url_parts p;
  char big[URL_MAX + 40], out[URL_MAX + 1];

  /* classification */
  line("Plain text", GT_TEXT, "Plain text", 0);
  line("", GT_TEXT, "", 0);
  line("Plain text\r", GT_TEXT, "Plain text", 0);
  line("=> /a Label here", GT_LINK, "Label here", "/a");
  line("=>/a", GT_LINK, "/a", "/a");
  line("=>\t/a\tTabbed", GT_LINK, "Tabbed", "/a");
  line("=>   gemini://x.org/  Spaced   out ", GT_LINK, "Spaced   out ", "gemini://x.org/");
  line("=>", GT_LINK, "", "");
  line("# H1", GT_H1, "H1", 0);
  line("#H1 tight", GT_H1, "H1 tight", 0);
  line("##  H2", GT_H2, "H2", 0);
  line("### H3", GT_H3, "H3", 0);
  line("#### four", GT_TEXT, "#### four", 0);
  line("* item", GT_LIST, "item", 0);
  line("*item", GT_TEXT, "*item", 0);
  line("* ", GT_LIST, "", 0);
  line("> quoted", GT_QUOTE, "quoted", 0);
  line(">tight", GT_QUOTE, "tight", 0);
  line("```alt", GT_TOGGLE, "", 0);
  line("=> /x not a link", GT_PRE, "=> /x not a link", 0);
  line("# not a heading", GT_PRE, "# not a heading", 0);
  line("   spaced", GT_PRE, "   spaced", 0);
  line("```", GT_TOGGLE, "", 0);
  line("# heading again", GT_H1, "heading again", 0);
  line("``", GT_TEXT, "``", 0);

  /* wrap */
  wrap("short", 10, "short|");
  wrap("one two three four", 9, "one two|three|four|");
  wrap("one two three four", 18, "one two three four|");
  wrap("one two three four", 17, "one two three|four|");
  wrap("abcdefghijkl", 5, "abcde|fghij|kl|");
  wrap("a  b", 3, "a|b|");
  wrap("ends with space ", 10, "ends with|space|");
  wrap("", 10, "");

  /* parse */
  CHECK(url_parse("gemini://Example.ORG:1965/a/b?q=1#frag", &p) && !strcmp(p.scheme, "gemini") && !strcmp(p.host, "example.org") &&
        p.port == 1965 && p.path_len == 4 && !memcmp(p.path, "/a/b", 4) && p.query_len == 3 && !memcmp(p.query, "q=1", 3), "full parse");
  CHECK(url_parse("gemini://x.org", &p) && !p.port && !p.path_len && !p.query, "no path");
  CHECK(url_parse("/a?b", &p) && !p.scheme[0] && !p.host[0] && p.path_len == 2 && p.query_len == 1, "relative");
  CHECK(url_parse("gemini://x.org:99999/", &p) == 0, "port too big");
  CHECK(url_parse("gemini://x.org:12x/", &p) == 0, "port not a number");
  CHECK(url_parse("mailto:someone@x.org", &p) && !strcmp(p.scheme, "mailto") && !p.host[0] && p.path_len == 13, "no authority");
  memset(big, 'h', sizeof big); memcpy(big, "gemini://", 9); big[sizeof big - 1] = 0;
  CHECK(url_parse(big, &p) == 0, "host too long");

  /* resolve: RFC 3986 5.4 examples, gemini flavoured */
  resolve("gemini://a/b/c/d;p?q", "g:h", "g:h");
  resolve("gemini://a/b/c/d;p?q", "g", "gemini://a/b/c/g");
  resolve("gemini://a/b/c/d;p?q", "./g", "gemini://a/b/c/g");
  resolve("gemini://a/b/c/d;p?q", "g/", "gemini://a/b/c/g/");
  resolve("gemini://a/b/c/d;p?q", "/g", "gemini://a/g");
  resolve("gemini://a/b/c/d;p?q", "//g", "gemini://g/");
  resolve("gemini://a/b/c/d;p?q", "?y", "gemini://a/b/c/d;p?y");
  resolve("gemini://a/b/c/d;p?q", "g?y", "gemini://a/b/c/g?y");
  resolve("gemini://a/b/c/d;p?q", "#s", "gemini://a/b/c/d;p?q");
  resolve("gemini://a/b/c/d;p?q", "", "gemini://a/b/c/d;p?q");
  resolve("gemini://a/b/c/d;p?q", ".", "gemini://a/b/c/");
  resolve("gemini://a/b/c/d;p?q", "./", "gemini://a/b/c/");
  resolve("gemini://a/b/c/d;p?q", "..", "gemini://a/b/");
  resolve("gemini://a/b/c/d;p?q", "../", "gemini://a/b/");
  resolve("gemini://a/b/c/d;p?q", "../g", "gemini://a/b/g");
  resolve("gemini://a/b/c/d;p?q", "../..", "gemini://a/");
  resolve("gemini://a/b/c/d;p?q", "../../", "gemini://a/");
  resolve("gemini://a/b/c/d;p?q", "../../g", "gemini://a/g");
  resolve("gemini://a/b/c/d;p?q", "../../../g", "gemini://a/g");
  resolve("gemini://a/b/c/d;p?q", "../../../../g", "gemini://a/g");
  resolve("gemini://a/b/c/d;p?q", "/./g", "gemini://a/g");
  resolve("gemini://a/b/c/d;p?q", "/../g", "gemini://a/g");
  resolve("gemini://a/b/c/d;p?q", "g.", "gemini://a/b/c/g.");
  resolve("gemini://a/b/c/d;p?q", ".g", "gemini://a/b/c/.g");
  resolve("gemini://a/b/c/d;p?q", "g..", "gemini://a/b/c/g..");
  resolve("gemini://a/b/c/d;p?q", "..g", "gemini://a/b/c/..g");
  resolve("gemini://a/b/c/d;p?q", "./../g", "gemini://a/b/g");
  resolve("gemini://a/b/c/d;p?q", "./g/.", "gemini://a/b/c/g/");
  resolve("gemini://a/b/c/d;p?q", "g/./h", "gemini://a/b/c/g/h");
  resolve("gemini://a/b/c/d;p?q", "g/../h", "gemini://a/b/c/h");
  resolve("gemini://a/b/c/d;p?q", "g?y/./x", "gemini://a/b/c/g?y/./x");
  resolve("gemini://a/b/c/d;p?q", "g#s/../x", "gemini://a/b/c/g");
  /* the ones the test site uses */
  resolve("gemini://localhost/", "nested/page.gmi", "gemini://localhost/nested/page.gmi");
  resolve("gemini://localhost/nested/page.gmi", "../", "gemini://localhost/");
  resolve("gemini://localhost/nested/page.gmi", "other.gmi", "gemini://localhost/nested/other.gmi");
  resolve("gemini://localhost:1966/x", "/y", "gemini://localhost:1966/y");
  resolve("gemini://localhost/x", "//other:1970/y", "gemini://other:1970/y");
  resolve("gemini://localhost/x", "gopher://gopher.floodgap.com/", "gopher://gopher.floodgap.com/");
  resolve("gemini://localhost", "a", "gemini://localhost/a");
  resolve("gemini://localhost", "", "gemini://localhost/");
  resolve("/relative/base", "a", 0);
  memset(big, 'x', sizeof big); big[sizeof big - 1] = 0;
  resolve("gemini://localhost/", big, 0);
  (void)out;

  /* typed */
  typed("example.org", "gemini://example.org/");
  typed("  example.org/path?q ", "gemini://example.org/path?q");
  typed("//example.org", "gemini://example.org/");
  typed("gemini://example.org", "gemini://example.org");
  typed("gopher://x/", "gopher://x/");
  typed("", 0);

  printf("%d checks, %d failed\n", checks, failed);
  return failed != 0;
}
