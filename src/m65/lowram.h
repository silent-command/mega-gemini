/* The client's buffers in bank 0's low RAM, below the program: the
 * family's map (mega-net PLATFORM.md) leaves $1400-$15FF and
 * $1A00-$1FAF to clients, verified free by the gopher client, and the
 * program window is full (5.6, 5.8, 5.9). What is here is reached by
 * absolute address; nothing is an array, so sizeof is 2 and the length
 * is written next to it.
 *
 *   $1400  256   the engine's receive buffer, the renderer's input block   fetch.c `in`, render.c
 *   $1500   81   the screen translation buffer                             screen.c
 *   $1560   80   a row record: the renderer's out, the pager's in          render.c, doc.c
 *   $15B0   78   the renderer's row text                                   render.c
 *   $15FF    1   the boot crumb                                            main.c
 *   $1A00 1060   the scratch line: the request, the renderer's line,
 *                the address typed, marks.c's staging                      doc.h `doc_scratch`, fetch.c `out`
 *   $1E30   81   a screen row being built                                  ui.c
 *   $1E90   80   the status note                                           main.c
 *   $1EE0   80   the failure text; the line editor's row while a line
 *                is typed (5.15)                                           fetch.c, ui.c
 *   $1F30   78   a row's text for the pager; during a fetch, the status
 *                line parsed from the raw document (64 bytes, 5.13)       pager.c, fetch.c
 *   $1F80   17   a file name being typed                                   pager.c
 *   $1F91   31   the fetch's timing note, " in N.N s"          fetch.c
 *   $1FB0        the family's exit stub: nothing past $1FAF */
#ifndef LOWRAM_H
#define LOWRAM_H

#define LOW_ROW_REC ((unsigned char *)0x1560)
#define LOW_ROW_BUF ((char *)0x1E30)
#define LOW_NOTE ((char *)0x1E90)
#define LOW_NOTE_LEN 80
#define LOW_FAIL_TEXT ((char *)0x1EE0)
#define LOW_ROW_TEXT ((char *)0x1F30)
#define LOW_NAME ((char *)0x1F80)
#define LOW_DIAG ((char *)0x1F91)

#endif
