/* MEGA65 Gemini client: the address, the fetch, the page, the links,
 * back. REQUIREMENTS.md section 2 for the decisions. */
#include "mega65/memory.h"
#include "meganet.h"
#include "m65_screen.h"
#include "m65_boot.h"
#include "m65_exit.h"
#include "tls/tlskit.h"
#include "url.h"
#include "gemini.h"
#include "netutil.h"
#include "boot.h"
#include "m65_tlskit.h"
#include "rnd.h"
#include "doc.h"
#include "pins.h"
#include "fetch.h"
#include "pager.h"
#include "marks.h"
#include "cache.h"
#include "ui.h"
#include "lowram.h"

#define GEMINI_VERSION "0.1.1"
#define HOME_URL "gemini://geminiprotocol.net/"
#define HISTORY_BASE 0x8300000UL     /* attic: the URLs behind, URL_MAX + 1 each */
#define HISTORY_MAX 16                           /* a power of two: the ring */
#define REDIRECTS_MAX 5

static char url[URL_MAX + 1];
char next_url[URL_MAX + 1];                   /* the engine's during a fetch (fetch.h, 5.9) */
#define typed doc_scratch            /* DOC_SCRATCH bytes (a pointer: not sizeof); the address typed, a link's target, an answer: never during a render */
#define note LOW_NOTE                /* LOW_NOTE_LEN bytes, low RAM (5.9) */
static uint8_t history, history_at, back;         /* the URLs behind, a ring of HISTORY_MAX; back: the next fetch is one of them, the cache first */
static fetch_result res;
static uint32_t shown_off, shown_end;             /* the page on the screen: its body in the raw document... */
static uint8_t shown_flags, cacheable;            /* ...its RENDER_* flags, and whether it is a page at all */

/* Leaving the page: its URL onto the history, its body into the cache. */
static void history_push(const char *u)
{
  if (cacheable) cache_put(u, shown_off, shown_flags, note);
  lcopy((uint32_t)(uintptr_t)u, HISTORY_BASE + (uint32_t)history_at * (URL_MAX + 1), URL_MAX + 1);
  history_at = (uint8_t)((history_at + 1) & (HISTORY_MAX - 1));   /* a ring: the oldest is overwritten */
  if (history < HISTORY_MAX) history++;
}

static uint8_t history_pop(char *u)
{
  if (!history) return 0;
  history--;
  history_at = (uint8_t)((history_at - 1) & (HISTORY_MAX - 1));
  lcopy(HISTORY_BASE + (uint32_t)history_at * (URL_MAX + 1), (uint32_t)(uintptr_t)u, URL_MAX + 1);
  return 1;
}

static uint16_t strlen_of(const char *s) { uint16_t n = 0; while (s[n]) n++; return n; }

static void copy(char *to, const char *from, uint16_t cap)
{
  uint16_t n = 0;
  while (from[n] && n < cap - 1) { to[n] = from[n]; n++; }
  to[n] = 0;
}

static void cat(char *to, const char *from, uint16_t cap)
{
  char *p = to, *end = to + cap - 1;
  while (*p) p++;
  while (*from && p < end) *p++ = *from++;     /* a walk, not a count (ssh 5.6) */
  *p = 0;
}

/* The typed answer to a 1x status, percent-encoded, as the query. */
static void add_query(char *u, const char *answer)
{
  static const char hex[] = "0123456789ABCDEF";
  uint16_t n = 0;
  while (u[n]) n++;
  if (n < URL_MAX) u[n++] = '?';
  for (; *answer && n + 3 < URL_MAX; answer++) {
    char c = *answer;
    if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '.' || c == '_' || c == '~') u[n++] = c;
    else { u[n++] = '%'; u[n++] = hex[((uint8_t)c) >> 4]; u[n++] = hex[c & 15]; }
  }
  u[n] = 0;
}

/* One line on an otherwise empty page, so a failure reads like a page. */
static void message_page(const char *a, const char *b)
{
  doc_clear();
  doc_append((const uint8_t *)a, strlen_of(a));
  if (b) doc_append((const uint8_t *)b, strlen_of(b));
  doc_append((const uint8_t *)"\n", 1);
  doc_render(RENDER_PLAIN);
  shown_off = 0; shown_end = doc_raw_len(); shown_flags = RENDER_PLAIN; cacheable = 0;
}

#define ROW_MARKS 5

/* The bookmarks under the prompt: a number at the prompt opens one, D
 * and the number deletes it (the FTP client's screen). The self-test
 * build leaves this screen out for the room its keys take, as the bank
 * leaves RSA out (5.6, 5.14). */
#ifdef CK_SELFTEST
#define draw_marks() ((void)0)
#else
static void draw_marks(void)
{
  unsigned char i;
  char *t = next_url;                               /* not the scratch line: marks.c stages its text there (5.8) */
  if (!marks_count) return;
  ui_line(ROW_MARKS, "Bookmarks: a number opens one; D and the number deletes it", 0);
  for (i = 0; i < marks_count && ROW_MARKS + 1 + i < 22; i++) {
    if (!marks_get(i, t + 4)) break;
    t[0] = ' '; t[1] = (char)('1' + i); t[2] = '.'; t[3] = ' ';
    ui_line((unsigned char)(ROW_MARKS + 1 + i), t, 0);
  }
}
#endif

static uint8_t ask_address(void)
{
  ui_clear_rows(1, 22);
  ui_line(UI_ROW_TITLE, "MEGA65 Gemini Client - version " GEMINI_VERSION, 0);
  ui_line(UI_ROW_KEYS, "RETURN fetches   STOP goes back", 0);
  ui_status("a gemini:// address, or a host name", 0);
  draw_marks();
  copy(typed, url[0] ? url : HOME_URL, DOC_SCRATCH);
  for (;;) {
    if (!ui_read_line(3, "Address: ", typed, URL_MAX)) return 0;
#ifndef CK_SELFTEST
    { unsigned char n = 0, del = 0, i = 0, digits = 0;
    /* a number picks a bookmark; D and a number deletes one */
    if (typed[0] == 'd' || typed[0] == 'D') { del = 1; i = 1; }
    while (typed[i] >= '0' && typed[i] <= '9') { n = (unsigned char)(n * 10 + (typed[i] - '0')); i++; digits++; }
    if (digits && !typed[i]) {
      if (n < 1 || n > marks_count) { ui_status("no such bookmark", 0); copy(typed, url[0] ? url : HOME_URL, DOC_SCRATCH); continue; }
      if (del) {
        unsigned char ok = marks_remove((unsigned char)(n - 1));
        m65_screen_init(); ui_clear_rows(1, 22);
        ui_line(UI_ROW_TITLE, "MEGA65 Gemini Client - version " GEMINI_VERSION, 0); ui_line(UI_ROW_KEYS, "RETURN fetches   STOP goes back", 0);
        draw_marks(); ui_status(ok ? "bookmark removed" : "could not write GEMMARKS", 0);
        copy(typed, url[0] ? url : HOME_URL, DOC_SCRATCH); continue;
      }
      marks_get((unsigned char)(n - 1), next_url);
      return 1;
    } }
#endif
#ifdef CK_SELFTEST                               /* the bank's P-256 self-test, timed from the screen (5.6); built with CK_SELFTEST=1 */
    if (typed[0] == 'g' && !typed[1]) { m65_tlskit_selftest(3); ui_status("2G and 3G at mp_scratch+640; any key", 0); ui_wait_key(); copy(typed, url[0] ? url : HOME_URL, DOC_SCRATCH); continue; }
    if (typed[0] == 't' && !typed[1]) {
      ui_status("P-256 self-test running...", 0);
      { uint8_t ok = m65_tlskit_selftest(1);
        static char why[] = "P-256 self-test: FAILED at step 0; any key";
        why[31] = (char)('0' + tk_verify_reason);
        ui_status(ok ? "P-256 self-test: ok; any key" : why, 0); }
      ui_wait_key();
      copy(typed, url[0] ? url : HOME_URL, DOC_SCRATCH);
      continue;
    }
#endif
    return url_from_typed(typed, next_url);
  }
}

/* Fetches next_url, following redirects and answering prompts; leaves
 * the document rendered and `note` set. Returns 1 to show the page. */
static uint8_t go(uint8_t trust_change)
{
  const char *err;
  uint8_t hops = 0;
  if (back) {                                       /* a page behind: as it was, if it is still kept */
    back = 0;
    if (cache_get(next_url, &shown_off, &shown_flags, note)) {
      copy(url, next_url, sizeof url);
      cacheable = 1; shown_end = doc_raw_len();
      doc_render_from(shown_off, shown_flags);
      return 1;
    }
  }
  for (;;) {
    copy(url, next_url, sizeof url);                /* the page's URL from here: next_url is the engine's during the fetch (5.9) */
    ui_line(UI_ROW_TITLE, url, 0);
    if (!fetch(url, trust_change, &res, &err)) {
      copy(note, err, LOW_NOTE_LEN);
      message_page(err, 0);
      return 1;
    }
    switch (res.resp.kind) {
    case GEM_REDIRECT:
      if (++hops > REDIRECTS_MAX) { message_page("too many redirects", 0); copy(note, "too many redirects", LOW_NOTE_LEN); return 1; }
      if (!url_resolve(url, res.resp.meta, next_url)) { message_page("a redirect to nowhere: ", res.resp.meta); return 1; }
      continue;
    case GEM_INPUT: {
      typed[0] = 0;
      ui_clear_rows(1, 22);
      ui_line(UI_ROW_TITLE, url, 0);
      ui_status(res.resp.status == 11 ? "the server asks (not echoed):" : "the server asks:", 0);
      cat(res.resp.meta, ": ", GEM_META_MAX + 3);   /* the prompt apart from the answer (5.10); meta has the room */
      if (!ui_read_line(3, res.resp.meta, typed, 200)) { message_page("no answer given", 0); copy(note, "", LOW_NOTE_LEN); return 1; }
      copy(next_url, url, sizeof next_url);
      { url_parts p; if (url_parse(next_url, &p) && p.query) next_url[p.query - next_url - 1] = 0; }   /* the old query off */
      add_query(next_url, typed);
      continue;
    }
    case GEM_SUCCESS:
      if (!res.resp.is_text) {                    /* the body is kept, for S: the page shown is a line after it (5.11) */
        shown_off = shown_end = doc_raw_len();
        doc_append((const uint8_t *)"not text: ", 10);
        doc_append((const uint8_t *)res.resp.meta, res.resp.meta_len);
        doc_append((const uint8_t *)"\nS saves it as it came.\n", strlen_of("\nS saves it as it came.\n"));
        doc_render_from(shown_off, RENDER_PLAIN);
        shown_off = res.body_off; shown_flags = RENDER_PLAIN; cacheable = 0;
        copy(note, res.resp.meta, LOW_NOTE_LEN);
        return 1;
      }
      shown_off = res.body_off; shown_end = doc_raw_len(); cacheable = 1;
      shown_flags = (uint8_t)((res.resp.is_gemini ? 0 : RENDER_PLAIN) | (res.resp.is_latin1 ? RENDER_LATIN1 : 0));
      doc_render_from(shown_off, shown_flags);
      copy(note, res.sig_state == TK_VERIFIED ? "verified" : "UNCHECKED signature", LOW_NOTE_LEN);
      if (fetch_cut_why) { cat(note, "; cut short: ", LOW_NOTE_LEN); cat(note, fetch_cut_why, LOW_NOTE_LEN); }
      else cat(note, fetch_diag, LOW_NOTE_LEN);         /* "verified in 10 s": the handshake's arithmetic (5.12, 5.15) */
      if (res.pin_state == PIN_NEW) cat(note, ", key pinned", LOW_NOTE_LEN);
      if (!res.resp.charset_ok) cat(note, ", charset not shown right", LOW_NOTE_LEN);
      return 1;
    default: {
      char d[80];
      gem_describe(&res.resp, d, sizeof d);
      message_page(d, 0);
      copy(note, d, LOW_NOTE_LEN);
      return 1;
    }
    }
  }
}

#define CRUMB(n) lpoke(0x15FFUL, (n))               /* where the boot got to, for mon.py 'm 15ff' (5.6) */

int main(void)
{
  const char *err;
  uint8_t action;

  mega65_io_enable();
  CRUMB(1);
  /* The ethernet controller's queue flags survive a reset, and on this
   * core they reach the IRQ line past the enables (mega-net 5.16). With
   * the vectors taken from the KERNAL nothing would acknowledge them and
   * the stub storms before the program gets anywhere (5.6). So first:
   * the controller into reset, the receive ring rotated and the queues
   * acknowledged as mega-net's driver does, the enables clear. */
  POKE(0xd6e0, 0x00);
  POKE(0xd6e1, 0x01); POKE(0xd6e1, 0x03); POKE(0xd6e1, 0x00);
  m65_own_vectors();                              /* then: a stray ethernet event before this enters the KERNAL's handler (mega-net 5.18) */
  CRUMB(2);
  m65_screen_init();
  CRUMB(3);
  ui_line(UI_ROW_TITLE, "MEGA65 Gemini Client - version " GEMINI_VERSION, 0);
  if (!doc_init()) { ui_status("no attic RAM (the 8 MB expansion): this client needs it", 0); for (;;) ; }
  CRUMB(4);
  ui_status("loading mega-net...", 0);
  if (!net_load(&err)) { ui_status("network: ", err); for (;;) ; }
  CRUMB(8);
  ui_status("loading the TLS bank...", 0);
  if (!boot_bank(&err)) { ui_status("TLS: ", err); for (;;) ; }
  CRUMB(9);
  ui_status("gathering randomness...", 0);
  rnd_init();
  pins_init();
  pins_load(boot_drive);
  marks_load(boot_drive);
  ui_status("waiting for an address...", 0);
  if (!net_dhcp(&err)) { ui_status("network: ", err); for (;;) ; }
  ui_idle = 0;
  url[0] = 0;

  if (!ask_address()) m65_exit_to_basic();
  for (;;) {
    if (!go(0)) continue;
    if (pins_dirty) {                             /* a key pinned: kept before the page is read */
      ui_status("pinning the key in GEMHOSTS...", 0);
      if (!pins_save()) cat(note, ", NOT saved to disk", LOW_NOTE_LEN);
      m65_screen_init();
    }
    action = pager_show(url, note, shown_off, shown_end);
    switch (action) {
    case PAGER_FOLLOW:
      if (doc_link_url(pager_link, typed) && url_resolve(url, typed, next_url)) { history_push(url); }
      else continue;
      break;
    case PAGER_BACK:
      if (history_pop(next_url)) back = 1;
      else if (!ask_address()) m65_exit_to_basic();
      break;
    case PAGER_ADDRESS:
      if (!ask_address()) continue;
      history_push(url);
      break;
    case PAGER_HOME:
      history_push(url);
      copy(next_url, HOME_URL, sizeof next_url);
      break;
    case PAGER_QUIT:
      m65_exit_to_basic();
      break;
    }
  }
}
