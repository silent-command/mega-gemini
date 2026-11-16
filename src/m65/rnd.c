/* Entropy for the bank's pool: as the SSH client does, timing jitter is
 * sampled over about a second (the raster, the frame counter, a CIA
 * timer, the ethernet controller's counter), with the machine's random
 * register and thermal noise bit beside it (hwrng below), and stirred
 * into the bank's SHA-256 pool; keystrokes and network events add more.
 * A hobbyist's source, not a certified one; REQUIREMENTS.md says so. */
#include "mega65/memory.h"
#include "m65_tlskit.h"
#include "rnd.h"
#include "doc.h"

static uint8_t stir_byte;

/* The MEGA65's own random-number generator (the MEGA65 book, K-17:
 * $D7EF HWRNGRAND, a read starts the next; $D7FE bit 7 HWRNGNOTRDY) and
 * the FPGA's thermal noise bit ($D6DE bit 0, mega65-libc's random.c).
 * Both go into the pool beside the timing, never instead of it: the wait
 * is bounded, so a core without them costs a few cycles and adds
 * nothing, and neither has been measured on this machine. */
static uint8_t hwrng(void)
{
  uint8_t i;
  for (i = 0; i < 32; i++)
    if (!(PEEK(0xd7fe) & 0x80)) break;
  return PEEK(0xd7ef);
}

#define SAMPLE 8

static void sample(uint8_t *s)
{
  s[0] = PEEK(0xd012); s[1] = PEEK(0xd7fa); s[2] = PEEK(0xdc04); s[3] = PEEK(0xdc05);
  s[4] = PEEK(0xd6e1); s[5] = stir_byte++; s[6] = hwrng(); s[7] = PEEK(0xd6de);
}

void rnd_init(void)
{
#define buf ((uint8_t *)doc_scratch)   /* RND_BUF bytes of the scratch line: rnd_init runs at boot, before any fetch (5.16); not sizeof */
#define RND_BUF (SAMPLE * 6)
  unsigned n, at = 0;
  uint8_t last = PEEK(0xd7fa);
  for (n = 0; n < 60; ) {                          /* sixty frames, about 1.2 s; a bank call per RND_BUF bytes */
    if (PEEK(0xd7fa) != last) { last = PEEK(0xd7fa); n++; }
    sample(buf + at); at += SAMPLE;
    if (at == RND_BUF) { m65_tlskit_seed(buf, RND_BUF); at = 0; }
  }
  if (at) m65_tlskit_seed(buf, at);
}

void rnd_stir(uint8_t v)
{
  uint8_t s[SAMPLE + 1];
  sample(s); s[SAMPLE] = v;
  m65_tlskit_seed(s, SAMPLE + 1);
}
