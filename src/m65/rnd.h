#ifndef RND_H
#define RND_H
#include <stdint.h>
void rnd_init(void);          /* about a second of sampling into the bank's pool; after the bank's INIT */
void rnd_stir(uint8_t v);     /* a keystroke, a packet: more entropy */
#endif
