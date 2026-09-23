#include "mega65/memory.h"
#include "url.h"
#include "doc.h"
#include "cache.h"

#define CACHE_BASE 0x8400000UL
#define CACHE_SLOT 0x100000UL             /* 1 MB each: the URL, the tail at +$800, the body from +$1000 */
#define CACHE_TAIL 0x800UL
#define CACHE_BODY 0x1000UL
#define CACHE_SLOTS 4

typedef struct { uint32_t len, body_off; uint8_t flags; } cache_tail;   /* the note follows it, CACHE_NOTE bytes */
static cache_tail tail;
static uint8_t next_slot;                 /* the ring: the oldest goes */
static uint8_t used;                      /* a bit per slot */

static uint32_t slot_at(uint8_t i) { return CACHE_BASE + (uint32_t)i * CACHE_SLOT; }

/* The slot holding `url`, or 0xff; compared through the scratch line,
 * idle whenever this is called (between a page and the next fetch). */
static uint8_t cache_find(const char *url)
{
  uint8_t i;
  const char *a, *b;
  for (i = 0; i < CACHE_SLOTS; i++) {
    if (!(used & (uint8_t)(1 << i))) continue;
    lcopy(slot_at(i), (uint32_t)(uintptr_t)doc_scratch, URL_MAX + 1);
    for (a = url, b = doc_scratch; *a && *a == *b; a++, b++) ;
    if (!*a && !*b) return i;
  }
  return 0xff;
}

void cache_put(const char *url, uint32_t body_off, uint8_t flags, const char *note)
{
  uint8_t i = cache_find(url);
  uint32_t s;
  if (i == 0xff) { i = next_slot; next_slot = (uint8_t)((next_slot + 1) & (CACHE_SLOTS - 1)); }
  s = slot_at(i);
  lcopy((uint32_t)(uintptr_t)url, s, URL_MAX + 1);
  tail.len = doc_raw_len(); tail.body_off = body_off; tail.flags = flags;
  lcopy((uint32_t)(uintptr_t)&tail, s + CACHE_TAIL, sizeof tail);
  lcopy((uint32_t)(uintptr_t)note, s + CACHE_TAIL + sizeof tail, CACHE_NOTE);
  doc_raw_stash(s + CACHE_BODY);
  used |= (uint8_t)(1 << i);
}

uint8_t cache_get(const char *url, uint32_t *body_off, uint8_t *flags, char *note)
{
  uint8_t i = cache_find(url);
  uint32_t s;
  if (i == 0xff) return 0;
  s = slot_at(i);
  lcopy(s + CACHE_TAIL, (uint32_t)(uintptr_t)&tail, sizeof tail);
  lcopy(s + CACHE_TAIL + sizeof tail, (uint32_t)(uintptr_t)note, CACHE_NOTE);
  doc_raw_restore(s + CACHE_BODY, tail.len);
  *body_off = tail.body_off; *flags = tail.flags;
  return 1;
}
