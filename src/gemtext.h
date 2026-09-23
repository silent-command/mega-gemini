/* Gemtext (text/gemini), line by line: what kind of line, and where its
 * text and its link target are. Also the word wrap to a column width.
 * C99 and stdint.h only, so tests/test_gemtext.c runs it on the host.
 *
 * A gemtext line is one of: a link "=>", a heading "#", "##", "###", a
 * list item "* ", a quote ">", the preformatting toggle "```", or plain
 * text. Inside a preformatted block every line is preformatted text
 * whatever it starts with. Nothing is inline: there is no markup within
 * a line. */
#ifndef GEMTEXT_H
#define GEMTEXT_H

#include <stdint.h>

#define GT_TEXT 0
#define GT_LINK 1
#define GT_H1 2
#define GT_H2 3
#define GT_H3 4
#define GT_LIST 5
#define GT_QUOTE 6
#define GT_PRE 7               /* a line inside a preformatted block, as is */
#define GT_TOGGLE 8            /* the ``` line itself; nothing to show */

typedef struct {
  uint8_t kind;
  const char *text;            /* the text to show, not NUL-terminated */
  uint16_t text_len;
  const char *url;             /* GT_LINK: the target, not NUL-terminated */
  uint16_t url_len;
} gt_line;

/* Parser state: whether a preformatted block is open. Zero to start. */
typedef struct { uint8_t pre; } gt_state;

/* Classifies one line (without its newline; a trailing CR is dropped).
 * A link with no label has text = url. */
void gt_classify(gt_state *st, const char *line, uint16_t len, gt_line *out);

/* Word wrap: the next row of at most `width` bytes from text[pos..len),
 * breaking at the last space that fits, or mid-word if there is none.
 * Returns the row's length and advances *pos past it and past the spaces
 * that follow. Returns 0 at the end. `text` is assumed already folded
 * to one byte per column. */
uint16_t gt_wrap(const char *text, uint16_t len, uint16_t *pos, uint8_t width);

#endif
