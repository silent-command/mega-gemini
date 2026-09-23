/* The page on the screen: the rendered rows, scrolled, with a link
 * selected; what the user asked for on leaving. */
#ifndef PAGER_H
#define PAGER_H

#include <stdint.h>

#define PAGER_BACK 1
#define PAGER_FOLLOW 2       /* pager_link is the link index */
#define PAGER_ADDRESS 3
#define PAGER_HOME 4
#define PAGER_QUIT 5

extern uint16_t pager_link;

/* Shows the current document under `title` (the URL) with `note` on the
 * status row until a key; returns a PAGER_* action. The body is the raw
 * document from `body_off` to `body_end`, for saving. */
uint8_t pager_show(const char *title, const char *note, uint32_t body_off, uint32_t body_end);

#endif
