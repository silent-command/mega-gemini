/* Multi-precision arithmetic modulo an odd number, for ECDSA P-256 and
 * RSA: Montgomery multiplication in 16-bit limbs with 32-bit
 * accumulators, so nothing here needs 64-bit arithmetic (the family's
 * rule: no int64_t, uint32_t only in accumulators). One multiplier
 * serves the P-256 field, the P-256 group order and an RSA modulus of
 * up to 4096 bits; the modulus and its constants live in an mp_ctx.
 * Numbers are little-endian limb arrays of the context's length. */
#ifndef MP_H
#define MP_H

#include <stdint.h>

#define MP_MAX_LIMBS 256           /* 4096 bits */

typedef uint16_t mp_limb;

typedef struct {
  uint16_t n;                      /* limbs */
  mp_limb m[MP_MAX_LIMBS];         /* the modulus */
  mp_limb rr[MP_MAX_LIMBS];        /* R^2 mod m, R = 2^(16n) */
  mp_limb n0;                      /* -m^-1 mod 2^16 */
  uint32_t n0_32;                  /* -m^-1 mod 2^32, for the 32-bit paths on the machine */
  mp_limb t[MP_MAX_LIMBS + 6];     /* the multiplier's scratch: n + 2 limbs, and a 32-bit limb below them for the reduction row (5.12) */
} mp_ctx;

/* The one context in the tree: ECDSA and RSA never run at once, and a
 * context is 1.5 KB, so p256.c and rsa.c share this and re-initialise
 * it for each modulus (a few hundred doublings). */
extern mp_ctx mp_shared;
/* 512 limbs of scratch for whoever holds the context: RSA's two numbers,
 * or ECDSA's points and scalars. */
#define MP_SCRATCH_LIMBS 512
extern mp_limb mp_scratch[MP_SCRATCH_LIMBS];

/* The modulus from big-endian bytes (odd, at most 512 bytes). */
void mp_init(mp_ctx *c, const uint8_t *m, uint16_t mlen);

/* Conversions: big-endian bytes of any length up to the modulus's, and back. */
void mp_from_be(const mp_ctx *c, mp_limb *x, const uint8_t *be, uint16_t len);
void mp_to_be(const mp_ctx *c, const mp_limb *x, uint8_t *be, uint16_t len);   /* the low `len` bytes */

/* r = a * b / R mod m (Montgomery product); r may alias a or b. On the
 * machine this is the 256-bit path for 16 limbs and the 32-bit rows for
 * any even number of limbs; the host multiplies in 16-bit limbs. */
void mp_mont_mul(mp_ctx *c, mp_limb *r, const mp_limb *a, const mp_limb *b);
/* The 32-bit driver by name, for an even n: the host's suite checks it
 * against the 16-bit multiplier (5.12). */
void mp_mont_mul32(mp_ctx *c, mp_limb *r, const mp_limb *a, const mp_limb *b);
void mp_mont_reduce32(mp_ctx *c, mp_limb *r, const mp_limb *a);
/* Into and out of Montgomery form (a * R, a / R); r may alias a. */
void mp_to_mont(mp_ctx *c, mp_limb *r, const mp_limb *a);
void mp_from_mont(mp_ctx *c, mp_limb *r, const mp_limb *a);
/* r = a^e, a and r in Montgomery form, e big-endian; r must not alias a. */
void mp_mont_exp(mp_ctx *c, mp_limb *r, const mp_limb *a, const uint8_t *e, uint16_t elen);
/* r = a^-1 for a prime modulus (a^(m-2)), in Montgomery form; r must
 * not alias a; the modulus's low limb must be at least 2. */
void mp_mont_inv(mp_ctx *c, mp_limb *r, const mp_limb *a);

/* Plain modular add and subtract (both forms), and helpers. */
void mp_add(const mp_ctx *c, mp_limb *r, const mp_limb *a, const mp_limb *b);
void mp_sub(const mp_ctx *c, mp_limb *r, const mp_limb *a, const mp_limb *b);
uint8_t mp_is_zero(const mp_ctx *c, const mp_limb *a);
int8_t mp_cmp(const mp_ctx *c, const mp_limb *a, const mp_limb *b);      /* -1, 0, 1 */
void mp_copy(const mp_ctx *c, mp_limb *r, const mp_limb *a);
void mp_set_small(const mp_ctx *c, mp_limb *r, uint16_t v);

/* A yield between rounds of the long loops, so a client can poll the
 * network; the same pointer as crypto.h's. */
extern void (*crypto_yield)(void);

#endif
