/* Where the document lives, shared by the client (src/m65/doc.c, which
 * fills the raw body and reads the rows) and the bank (src/bank/render.c,
 * which turns the one into the other). Every address is 28-bit; both
 * sides reach them by DMA. */
#ifndef DOCMEM_H
#define DOCMEM_H

#define DOC_RAW_BASE 0x8000000UL     /* the raw body, up to DOC_RAW_MAX */
#define DOC_RAW_MAX 0xF0000UL        /* 960 KB */
#define DOC_ROWS_BASE 0x8100000UL    /* the rows, DOC_ROW_SIZE each */
#define DOC_URLS_BASE 0x8200000UL    /* the link targets, one after another */
#define DOC_URLS_MAX 0x40000UL       /* 256 KB */
#define DOC_LINKS_BASE 0x1C000UL     /* bank 1: the link table, 8 bytes per link: offset u32, len u16, row u16 */

#define DOC_ROW_SIZE 80
#define DOC_ROW_TEXT 77              /* the text of a row: 80 less the kind byte and the link index (5.7) */
#define DOC_ROWS_MAX 4000u
#define DOC_LINKS_MAX 500u
#define DOC_LINE_MAX 1024            /* a gemtext line longer than this is cut */

/* how to render, the flags byte of the render entry */
#define RENDER_PLAIN 1               /* text/plain: no gemtext, every line as is */
#define RENDER_LATIN1 2              /* charset=iso-8859-1: a byte is a character, not UTF-8 (5.10) */

/* row kinds, the first byte of a row record */
#define ROW_TEXT 0
#define ROW_LINK 1                   /* the first row of a link line; the link index follows */
#define ROW_LINK_MORE 2              /* a link's wrapped continuation */
#define ROW_H1 3
#define ROW_H2 4
#define ROW_H3 5
#define ROW_LIST 6
#define ROW_QUOTE 7
#define ROW_PRE 8

#endif
