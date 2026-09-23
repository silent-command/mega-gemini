/* The document: the response body as it arrives, raw, in attic RAM,
 * with a mark per TLS record so a record that fails its tag (or turns
 * out not to be data) is taken back; then, once the transfer has ended,
 * rendered once, by the bank's top window (src/bank/render.c, 5.8),
 * into screen rows of a fixed width, the way the gopher client stores
 * text, so the pager shows row N with one copy. Links
 * keep their targets in a third area, indexed by a small table in bank
 * 1, so RETURN on a link row has the URL.
 *
 *   attic $8000000  the raw body, up to DOC_RAW_MAX
 *   attic $8100000  the rows, DOC_ROW_SIZE each, up to DOC_ROWS_MAX
 *   attic $8200000  the link targets, one after another
 *   attic $8300000  the history (main.c); $8400000 the page cache, four 1 MB slots (cache.c, 5.9)
 *   bank 1 $1C000   the link table: 8 bytes per link (offset u32, len u16, row u16), DOC_LINKS_MAX
 *
 * Attic RAM is optional hardware: doc_init() probes for it and refuses
 * without it. DMA fills the raw area during the transfer and reads it
 * back only afterwards, which is the one pattern attic RAM keeps
 * (PLATFORM.md trap 8). */
#ifndef DOC_H
#define DOC_H

#include <stdint.h>

#include "docmem.h"

uint8_t doc_init(void);              /* 1 if attic RAM is there */

/* One line of scratch, DOC_SCRATCH bytes: the render's line buffer, and
 * between renders anyone's (the address typed, the request line). The
 * program window is tight (5.5), so it is shared, not duplicated. */
#define DOC_SCRATCH 1040
#define doc_scratch ((char *)0x1A00)   /* $1A00-$1E0F, low RAM (5.6) */

/* the raw body */
void doc_clear(void);
void doc_mark(void);                 /* the start of a record */
void doc_rollback(void);             /* back to the mark */
uint8_t doc_append(const uint8_t *p, uint16_t n);   /* 0 once full (the transfer goes on; the page is cut) */
uint32_t doc_raw_len(void);
uint8_t doc_truncated(void);         /* the body, the rows or the links overflowed */

/* rendering: raw bytes from `from` to rows; `flags` are RENDER_* (docmem.h) */
void doc_render_from(uint32_t from, uint8_t flags);
#define doc_render(flags) doc_render_from(0, (flags))
uint16_t doc_rows(void);
uint16_t doc_links(void);
/* row i: the kind, the link index if a link (else 0xffff), the text (NUL-terminated, at most DOC_ROW_TEXT) */
void doc_row(uint16_t i, uint8_t *kind, uint16_t *link, char *text);
/* the target of link i into out (at least 1025 bytes); 0 if none */
uint8_t doc_link_url(uint16_t i, char *out);
/* the row a link starts on, or 0xffff */
uint16_t doc_link_row(uint16_t i);

/* the raw body, for saving or showing as text: bytes [at, at+n) */
void doc_raw_read(uint32_t at, uint8_t *out, uint16_t n);
/* the whole raw body copied to `to` in attic RAM, and a body put back from there (the page cache, 5.9) */
void doc_raw_stash(uint32_t to);
void doc_raw_restore(uint32_t from, uint32_t len);

#endif
