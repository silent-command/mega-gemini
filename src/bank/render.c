/* The renderer, in the bank's top window ($E000-$F7FF of bank 1, the
 * window the SSH client's terminal parser used): the raw body in attic
 * RAM to rows of DOC_ROW_SIZE and a link table, once per page, by DMA
 * in and DMA out. It left the client for room (REQUIREMENTS.md 5.8):
 * the client's program window was 5 KB short with the disk writer in.
 * The gemtext parser and wrap are src/gemtext.c, host-tested; the fold
 * is the FTP client's, with 16-bit lengths, in place. */
#include <stdint.h>
#include "gemtext.h"
#include "docmem.h"
#include "dma.h"

#define HI_BSS(n) __attribute__((section(".bss.hi." n)))   /* placed in the top window with the code */

/* The buffers are the client's, in bank 0's low RAM, which the bank's
 * map leaves visible ($0000-$1FFF is not remapped; the trampoline's
 * mailbox is reached the same way): the scratch line at $1A00 and the
 * receive buffer at $1400, both idle during a render, and a row's
 * worth after the translation buffer. Bank 0's addresses are their
 * physical addresses, so DMA reaches them as they are. */
#define line ((char *)0x1A00)             /* DOC_LINE_MAX + 1 */
#define inbuf ((uint8_t *)0x1400)         /* 256 */
#define row ((uint8_t *)0x1560)           /* 80: to $15AF */
#define out ((char *)0x15B0)              /* DOC_ROW_TEXT + 1: to $15FD */
#define PHYS0(p) ((uint32_t)(uintptr_t)(p))
#define PHYS(p) ((uint32_t)(uintptr_t)(p) + CK_PHYS_BASE)
#define INBUF_CAP 256

static uint8_t rec[8] HI_BSS("rec");
static uint16_t rows HI_BSS("rows"), links HI_BSS("links");
static uint32_t urls_len HI_BSS("urls_len");
static uint8_t truncated HI_BSS("truncated");
static uint8_t blk[14] HI_BSS("blk");               /* the entry's argument block, by DMA */
extern volatile uint8_t ck_api_a, ck_api_x, ck_api_y;   /* the caller's A/X/Y: the block's 28-bit address */

/* ---- the fold: UTF-8 to one byte per column (the FTP client's rules) ---- */

static char fold_codepoint(uint16_t cp)
{
  if (cp >= 0xc0 && cp <= 0xc6) return 0x41;
  if (cp == 0xc7) return 0x43;
  if (cp >= 0xc8 && cp <= 0xcb) return 0x45;
  if (cp >= 0xcc && cp <= 0xcf) return 0x49;
  if (cp == 0xd1) return 0x4e;
  if ((cp >= 0xd2 && cp <= 0xd6) || cp == 0xd8) return 0x4f;
  if (cp >= 0xd9 && cp <= 0xdc) return 0x55;
  if (cp == 0xdd) return 0x59;
  if (cp == 0xdf) return 0x73;
  if (cp >= 0xe0 && cp <= 0xe6) return 0x61;
  if (cp == 0xe7) return 0x63;
  if (cp >= 0xe8 && cp <= 0xeb) return 0x65;
  if (cp >= 0xec && cp <= 0xef) return 0x69;
  if (cp == 0xf1) return 0x6e;
  if ((cp >= 0xf2 && cp <= 0xf6) || cp == 0xf8) return 0x6f;
  if (cp >= 0xf9 && cp <= 0xfc) return 0x75;
  if (cp == 0xfd || cp == 0xff) return 0x79;
  if (cp == 0xa0) return 0x20;
  if (cp == 0x2018 || cp == 0x2019) return 0x27;
  if (cp == 0x201c || cp == 0x201d) return 0x22;
  if (cp == 0x2013 || cp == 0x2014) return 0x2d;
  if (cp == 0x2026) return 0x2e;
  if (cp == 0x2022) return 0x2a;
  return 0x2e;
}

/* In place: the fold never writes past what it has read. With `latin`
 * a byte past 0x7F is a Latin-1 character, not a UTF-8 lead (5.10). */
static uint16_t fold_line(char *s, uint16_t len, uint8_t latin)
{
  uint16_t n = 0, i = 0, cp;
  uint8_t b, need, k;
  while (i < len) {
    b = (uint8_t)s[i++];
    if (b < 0x80) { s[n++] = (b >= 0x20) ? (char)b : 0x20; continue; }
    if (latin) { s[n++] = fold_codepoint(b); continue; }
    if ((b & 0xe0) == 0xc0) { cp = b & 0x1f; need = 1; }
    else if ((b & 0xf0) == 0xe0) { cp = b & 0x0f; need = 2; }
    else if ((b & 0xf8) == 0xf0) { cp = b & 0x07; need = 3; }
    else { s[n++] = 0x2e; continue; }
    for (k = 0; k < need && i < len; k++) {
      if (((uint8_t)s[i] & 0xc0) != 0x80) break;
      cp = (uint16_t)((cp << 6) | ((uint8_t)s[i++] & 0x3f));
    }
    s[n++] = (k != need) ? 0x2e : fold_codepoint(cp);
  }
  return n;
}

/* ---- the stores ---------------------------------------------------------- */

static void put_row(uint8_t kind, uint16_t link, const char *text, uint16_t n)
{
  uint8_t i;
  if (rows >= DOC_ROWS_MAX) { truncated = 1; return; }
  row[0] = kind; row[1] = (uint8_t)link; row[2] = (uint8_t)(link >> 8);
  if (n > DOC_ROW_TEXT) n = DOC_ROW_TEXT;
  for (i = 0; i < n; i++) row[3 + i] = (uint8_t)text[i];
  for (i = (uint8_t)n; i < DOC_ROW_SIZE - 3; i++) row[3 + i] = 0;
  ck_dma_copy(PHYS0(row), DOC_ROWS_BASE + (uint32_t)rows * DOC_ROW_SIZE, DOC_ROW_SIZE);
  rows++;
}

/* A link's target kept, and its table entry: offset, length, row. */
static uint16_t add_link(const char *url, uint16_t n)
{
  if (links >= DOC_LINKS_MAX || urls_len + n > DOC_URLS_MAX) { truncated = 1; return 0xffff; }
  if (n) ck_dma_copy(PHYS0(url), DOC_URLS_BASE + urls_len, n);   /* the URL is in the line, bank 0 */
  rec[0] = (uint8_t)urls_len; rec[1] = (uint8_t)(urls_len >> 8); rec[2] = (uint8_t)(urls_len >> 16); rec[3] = (uint8_t)(urls_len >> 24);
  rec[4] = (uint8_t)n; rec[5] = (uint8_t)(n >> 8);
  rec[6] = (uint8_t)rows; rec[7] = (uint8_t)(rows >> 8);
  ck_dma_copy(PHYS(rec), DOC_LINKS_BASE + (uint32_t)links * 8, 8);
  urls_len += n;
  return links++;
}

/* Wraps folded text into rows of `kind`, the continuation rows indented
 * by `indent` columns (list items and links keep their text aligned). */
static void wrap_rows(uint8_t kind, uint8_t more_kind, uint16_t link, const char *text, uint16_t len, const char *prefix, uint8_t indent)
{
  uint16_t pos = 0, start, n;
  uint8_t plen = 0, first = 1, i, width;
  while (prefix[plen]) plen++;
  width = (uint8_t)(DOC_ROW_TEXT - plen);
  if (!len) { for (i = 0; i < plen; i++) out[i] = prefix[i]; put_row(kind, link, out, plen); return; }
  for (;;) {
    start = pos;
    n = gt_wrap(text, len, &pos, width);
    if (!n) break;
    if (first) { for (i = 0; i < plen; i++) out[i] = prefix[i]; }
    else { for (i = 0; i < indent; i++) out[i] = ' '; plen = indent; }
    for (i = 0; i < n; i++) out[plen + i] = text[start + i];
    put_row(first ? kind : more_kind, first ? link : 0xffff, out, (uint16_t)(plen + n));
    first = 0;
    width = (uint8_t)(DOC_ROW_TEXT - indent);
  }
}

static void render_line(gt_state *st, uint8_t flags, char *text, uint16_t len)
{
  gt_line l;
  uint16_t flen, link = 0xffff;
  char *folded;
  if (flags & RENDER_PLAIN) { l.kind = GT_PRE; l.text = text; l.text_len = len; }
  else gt_classify(st, text, len, &l);
  if (l.kind == GT_TOGGLE) return;
  /* the target first, raw; then the text folded in place */
  if (l.kind == GT_LINK) link = add_link(l.url, l.url_len);
  folded = (char *)l.text;
  flen = fold_line(folded, l.text_len, (uint8_t)(flags & RENDER_LATIN1));
  switch (l.kind) {
  case GT_LINK: wrap_rows(ROW_LINK, ROW_LINK_MORE, link, folded, flen, "=> ", 3); break;
  case GT_H1: wrap_rows(ROW_H1, ROW_H1, 0xffff, folded, flen, "# ", 2); break;
  case GT_H2: wrap_rows(ROW_H2, ROW_H2, 0xffff, folded, flen, "## ", 3); break;
  case GT_H3: wrap_rows(ROW_H3, ROW_H3, 0xffff, folded, flen, "### ", 4); break;
  case GT_LIST: wrap_rows(ROW_LIST, ROW_LIST, 0xffff, folded, flen, "* ", 2); break;
  case GT_QUOTE: wrap_rows(ROW_QUOTE, ROW_QUOTE, 0xffff, folded, flen, "> ", 2); break;
  case GT_PRE: put_row(ROW_PRE, 0xffff, folded, flen); break;   /* as is, cut at the row's width */
  default: wrap_rows(ROW_TEXT, ROW_TEXT, 0xffff, folded, flen, "", 0); break;
  }
}

/* The raw body from `from` to `len`, as gemtext or as plain text (RENDER_* flags). */
void render_document(uint32_t from, uint32_t len, uint8_t flags, uint16_t *out_rows, uint16_t *out_links, uint8_t *out_truncated)
{
  gt_state st;
  uint32_t at = from;
  uint16_t take, i, ll = 0;
  st.pre = 0;
  rows = 0; links = 0; urls_len = 0; truncated = 0;
  while (at < len) {
    take = len - at < INBUF_CAP ? (uint16_t)(len - at) : (uint16_t)INBUF_CAP;
    ck_dma_copy(DOC_RAW_BASE + at, PHYS0(inbuf), take);
    at += take;
    for (i = 0; i < take; i++) {
      char c = (char)inbuf[i];
      if (c == '\n') { line[ll] = 0; render_line(&st, flags, line, ll); ll = 0; }
      else if (ll < DOC_LINE_MAX) line[ll++] = c;
    }
  }
  if (ll) { line[ll] = 0; render_line(&st, flags, line, ll); }
  *out_rows = rows; *out_links = links; *out_truncated = truncated;
}

/* The entry ($2045): {from u32, len u32, flags u8; out: rows u16, links
 * u16, truncated u8}. It lives here, with the renderer, for the room
 * below the bank's stack (5.8: the bank had 47 bytes to spare). */
void ck_api_render(void)
{
  uint16_t r, l;
  uint8_t t;
  uint32_t arg = (uint32_t)ck_api_a | ((uint32_t)ck_api_x << 8) | ((uint32_t)ck_api_y << 16);
  ck_dma_copy(arg, PHYS(blk), sizeof blk);
  render_document((uint32_t)blk[0] | ((uint32_t)blk[1] << 8) | ((uint32_t)blk[2] << 16) | ((uint32_t)blk[3] << 24),
                  (uint32_t)blk[4] | ((uint32_t)blk[5] << 8) | ((uint32_t)blk[6] << 16) | ((uint32_t)blk[7] << 24),
                  blk[8], &r, &l, &t);
  blk[9] = (uint8_t)r; blk[10] = (uint8_t)(r >> 8);
  blk[11] = (uint8_t)l; blk[12] = (uint8_t)(l >> 8);
  blk[13] = t;
  ck_dma_copy(PHYS(blk + 9), arg + 9, 5);
}
