#include "mega65/memory.h"
#include "m65_cbmdos.h"
#include "pins.h"
#include "doc.h"

#define PINS_BASE 0x1D000UL
#define PINS_MAX 16
#define PIN_REC 100                  /* host 64 + port 2 + pin 32 + used 1, rounded */

#define PINS_FILE "GEMHOSTS"

static uint8_t count;
#define rec ((uint8_t *)(doc_scratch + 512))   /* one record, staged in the scratch line, which is idle whenever the pins are read or written: boot, after a verify, before a page (5.16); PIN_REC bytes, not sizeof */
static unsigned char pins_drive;
unsigned char pins_dirty;

void pins_init(void) { count = 0; }

static void load(uint8_t i) { lcopy(PINS_BASE + (uint32_t)i * PIN_REC, (uint32_t)(uintptr_t)rec, PIN_REC); }
static void store(uint8_t i) { lcopy((uint32_t)(uintptr_t)rec, PINS_BASE + (uint32_t)i * PIN_REC, PIN_REC); }

static void fill(const char *host, uint16_t port, const uint8_t pin[32])
{
  uint8_t i;
  for (i = 0; i < 64; i++) { rec[i] = (uint8_t)host[i]; if (!host[i]) break; }
  for (; i < 64; i++) rec[i] = 0;
  rec[64] = (uint8_t)port; rec[65] = (uint8_t)(port >> 8);
  for (i = 0; i < 32; i++) rec[66 + i] = pin[i];
}

static uint8_t find(const char *host, uint16_t port)
{
  uint8_t i, j;
  for (i = 0; i < count; i++) {
    load(i);
    if (rec[64] != (uint8_t)port || rec[65] != (uint8_t)(port >> 8)) continue;
    for (j = 0; j < 64; j++) { if (rec[j] != (uint8_t)host[j]) break; if (!host[j]) return i; }
  }
  return 0xff;
}

uint8_t pins_check(const char *host, uint16_t port, const uint8_t pin[32])
{
  uint8_t i, j;
  i = find(host, port);
  if (i == 0xff) {
    if (count < PINS_MAX) { fill(host, port, pin); store(count++); pins_dirty = 1; }
    return PIN_NEW;
  }
  for (j = 0; j < 32; j++) if (rec[66 + j] != pin[j]) return PIN_CHANGED;
  return PIN_KNOWN;
}

void pins_replace(const char *host, uint16_t port, const uint8_t pin[32])
{
  uint8_t i = find(host, port);
  fill(host, port, pin);
  if (i == 0xff) { if (count < PINS_MAX) store(count++); }
  else store(i);
  pins_dirty = 1;
}

/* ---- the file: the table's records, raw ------------------------------- */

void pins_load(unsigned char drive)
{
  unsigned long len;
  pins_drive = drive;
  pins_dirty = 0;
  len = cbmdos_load(PINS_FILE, drive, PINS_BASE, (unsigned long)PINS_MAX * PIN_REC);
  count = (uint8_t)((uint16_t)len / PIN_REC);           /* 16-bit: the file is at most PINS_MAX records, and a 32-bit divide is 360 bytes of client */
}

unsigned char pins_save(void)
{
  unsigned int i, n = (unsigned int)count * PIN_REC;
  cbmdos_delete(PINS_FILE, pins_drive);            /* absent the first time; fine */
  if (cbmdos_create(PINS_FILE, pins_drive) != CBMDOS_OK) return 0;
  for (i = 0; i < n; i++)
    if (cbmdos_put(lpeek(PINS_BASE + i)) != CBMDOS_OK) { cbmdos_close(); return 0; }
  if (cbmdos_close() != CBMDOS_OK) return 0;
  pins_dirty = 0;
  return 1;
}
