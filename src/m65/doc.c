#include "mega65/memory.h"
#include "m65_tlskit.h"
#include "doc.h"
#include "lowram.h"

/* The raw body fills here during the fetch (with a mark per record);
 * the rendering into rows is the bank's (src/bank/render.c, 5.8); the
 * rows and links are read back here for the pager. */

static uint32_t raw_len, raw_mark;
static uint16_t rows, links;
static uint8_t truncated;
char *const doc_line = doc_scratch;
#define row LOW_ROW_REC                  /* the renderer's row record, idle between renders (5.9) */

/* Attic RAM is optional hardware: prove it holds what is written, in
 * each region this module uses (the gopher client's method). */
static uint8_t attic_present(void)
{
  uint8_t i;
  for (i = 0; i < 4; i++) lpoke(DOC_RAW_BASE + ((uint32_t)i << 20), (uint8_t)(0x5a + i));   /* one per area, 1 MB apart */
  for (i = 0; i < 4; i++) if (lpeek(DOC_RAW_BASE + ((uint32_t)i << 20)) != (uint8_t)(0x5a + i)) return 0;
  return 1;
}

uint8_t doc_init(void) { return attic_present(); }

void doc_clear(void)
{
  raw_len = raw_mark = 0; rows = links = 0; truncated = 0;
}

void doc_mark(void) { raw_mark = raw_len; }
void doc_rollback(void) { raw_len = raw_mark; }

uint8_t doc_append(const uint8_t *p, uint16_t n)
{
  if (!n) return 1;
  if (raw_len + n > DOC_RAW_MAX) { truncated = 1; return 0; }
  lcopy((uint32_t)(uintptr_t)p, DOC_RAW_BASE + raw_len, n);
  raw_len += n;
  return 1;
}

uint32_t doc_raw_len(void) { return raw_len; }
uint8_t doc_truncated(void) { return truncated; }

void doc_raw_read(uint32_t at, uint8_t *out, uint16_t n)
{
  if (!n) return;
  lcopy(DOC_RAW_BASE + at, (uint32_t)(uintptr_t)out, n);
}

/* The raw body to and from elsewhere in attic RAM (the page cache, 5.9),
 * in DMA jobs of 32 KB: a job's count is 16-bit. */
static void raw_copy(uint32_t src, uint32_t dst, uint32_t len)
{
  uint8_t jobs = (uint8_t)(len >> 15);
  uint16_t last = (uint16_t)len & 0x7fff;
  while (jobs) { lcopy(src, dst, 0x8000); src += 0x8000; dst += 0x8000; jobs--; }
  if (last) lcopy(src, dst, last);
}

void doc_raw_stash(uint32_t to) { raw_copy(DOC_RAW_BASE, to, raw_len); }

void doc_raw_restore(uint32_t from, uint32_t len)
{
  doc_clear();
  raw_copy(from, DOC_RAW_BASE, len);
  raw_len = len;
}

void doc_render_from(uint32_t from, uint8_t flags)
{
  uint8_t cut;
  m65_tlskit_render(from, raw_len, flags, &rows, &links, &cut);
  if (cut) truncated = 1;
}

uint16_t doc_rows(void) { return rows; }
uint16_t doc_links(void) { return links; }

void doc_row(uint16_t i, uint8_t *kind, uint16_t *link, char *text)
{
  uint8_t k;
  if (i >= rows) { *kind = ROW_TEXT; *link = 0xffff; text[0] = 0; return; }
  lcopy(DOC_ROWS_BASE + (uint32_t)i * DOC_ROW_SIZE, (uint32_t)(uintptr_t)row, DOC_ROW_SIZE);
  *kind = row[0];
  *link = (uint16_t)(row[1] | ((uint16_t)row[2] << 8));
  for (k = 0; k < DOC_ROW_TEXT; k++) text[k] = (char)row[3 + k];
  text[DOC_ROW_TEXT] = 0;
}

static void link_rec(uint16_t i, uint8_t rec[8]) { lcopy(DOC_LINKS_BASE + (uint32_t)i * 8, (uint32_t)(uintptr_t)rec, 8); }

uint8_t doc_link_url(uint16_t i, char *out)
{
  uint8_t rec[8];
  uint32_t off;
  uint16_t n;
  if (i >= links) { out[0] = 0; return 0; }
  link_rec(i, rec);
  off = (uint32_t)rec[0] | ((uint32_t)rec[1] << 8) | ((uint32_t)rec[2] << 16) | ((uint32_t)rec[3] << 24);
  n = (uint16_t)(rec[4] | ((uint16_t)rec[5] << 8));
  if (n > 1024) n = 1024;
  if (n) lcopy(DOC_URLS_BASE + off, (uint32_t)(uintptr_t)out, n);
  out[n] = 0;
  return 1;
}

uint16_t doc_link_row(uint16_t i)
{
  uint8_t rec[8];
  if (i >= links) return 0xffff;
  link_rec(i, rec);
  return (uint16_t)(rec[6] | ((uint16_t)rec[7] << 8));
}
