/* The pages behind, for back: four slots in attic RAM, each a page's
 * raw body with its URL and its status text, so that RUN/STOP shows
 * the page again without the handshake (5.9). Only pages that arrived
 * are kept; a failure is fetched again. */
#ifndef CACHE_H
#define CACHE_H

#include <stdint.h>

#define CACHE_NOTE 80

/* `url` is a URL_MAX + 1 buffer and `note` a CACHE_NOTE one, copied whole; the body is the document's raw body as it stands */
void cache_put(const char *url, uint32_t body_off, uint8_t flags, const char *note);
/* 1 with the raw body put back and the rest filled in, 0 if the page is not kept */
uint8_t cache_get(const char *url, uint32_t *body_off, uint8_t *flags, char *note);

#endif
