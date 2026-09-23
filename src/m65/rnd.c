/* Entropy for the bank's pool: the MEGA65 has no random-number hardware
 * this program can reach, so, as the SSH client does, timing jitter is
 * sampled over about a second (the raster, the frame counter, a CIA
 * timer, the ethernet controller's counter) and stirred into the
 * bank's SHA-256 pool; keystrokes and network events add more. A
 * hobbyist's source, not a certified one; REQUIREMENTS.md says so. */
#include "mega65/memory.h"
#include "m65_tlskit.h"
#include "rnd.h"
#include "doc.h"

static uint8_t stir_byte;

static void sample(uint8_t *s)
{
  s[0] = PEEK(0xd012); s[1] = PEEK(0xd7fa); s[2] = PEEK(0xdc04); s[3] = PEEK(0xdc05);
  s[4] = PEEK(0xd6e1); s[5] = stir_byte++;
}

void rnd_init(void)
{
#define buf ((uint8_t *)doc_scratch)   /* RND_BUF bytes of the scratch line: rnd_init runs at boot, before any fetch (5.16); not sizeof */
#define RND_BUF (6 * 8)
  unsigned n, at = 0;
  uint8_t last = PEEK(0xd7fa);
  for (n = 0; n < 60; ) {                          /* sixty frames, about 1.2 s; a bank call per 48 bytes */
    if (PEEK(0xd7fa) != last) { last = PEEK(0xd7fa); n++; }
    sample(buf + at); at += 6;
    if (at == RND_BUF) { m65_tlskit_seed(buf, RND_BUF); at = 0; }
  }
  if (at) m65_tlskit_seed(buf, at);
}

void rnd_stir(uint8_t v)
{
  uint8_t s[7];
  sample(s); s[6] = v;
  m65_tlskit_seed(s, 7);
}
