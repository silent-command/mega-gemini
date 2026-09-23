#include "p256.h"
#include "mp.h"

#define L 16                       /* limbs of a P-256 number */

static const uint8_t P[32] = {
  0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
};
static const uint8_t N[32] = {
  0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51
};
static const uint8_t B[32] = {
  0x5a, 0xc6, 0x35, 0xd8, 0xaa, 0x3a, 0x93, 0xe7, 0xb3, 0xeb, 0xbd, 0x55, 0x76, 0x98, 0x86, 0xbc,
  0x65, 0x1d, 0x06, 0xb0, 0xcc, 0x53, 0xb0, 0xf6, 0x3b, 0xce, 0x3c, 0x3e, 0x27, 0xd2, 0x60, 0x4b
};
static const uint8_t GX[32] = {
  0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4, 0x40, 0xf2,
  0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98, 0xc2, 0x96
};
static const uint8_t GY[32] = {
  0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b, 0x8e, 0xe7, 0xeb, 0x4a, 0x7c, 0x0f, 0x9e, 0x16,
  0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e, 0xce, 0xcb, 0xb6, 0x40, 0x68, 0x37, 0xbf, 0x51, 0xf5
};

typedef struct { mp_limb x[L], y[L], z[L]; } point;   /* Jacobian, Montgomery form; z = 0 is infinity */

/* The shared context is the order n while u1 and u2 are made, then the
 * field p for the point arithmetic; n's limbs are kept for the end. */
#define fp mp_shared
#define fn mp_shared
/* The scratch's layout: the four points at 0, the nine scalars at 192,
 * the temporaries of dbl and add at 336 (add's nine are dead when it
 * calls dbl), the order's limbs at 480; 496 of 512 limbs. */
#define TMP (mp_scratch + 336)
#define n_limbs (mp_scratch + 480)
#ifdef CK_SELFTEST
uint8_t p256_step;                                 /* where a verification said no, for the machine (5.6) */
#define STEP(n) (p256_step = (n))
#else
#define STEP(n) ((void)0)
#endif

static void fmul(mp_limb *r, const mp_limb *a, const mp_limb *b) { mp_mont_mul(&fp, r, a, b); }
static void fsqr(mp_limb *r, const mp_limb *a) { mp_mont_mul(&fp, r, a, a); }
static void fadd(mp_limb *r, const mp_limb *a, const mp_limb *b) { mp_add(&fp, r, a, b); }
static void fsub(mp_limb *r, const mp_limb *a, const mp_limb *b) { mp_sub(&fp, r, a, b); }

static uint8_t is_inf(const point *p) { return mp_is_zero(&fp, p->z); }

/* r = 2p (a = -3): S = 4XY^2, M = 3(X - Z^2)(X + Z^2), X' = M^2 - 2S,
 * Y' = M(S - X') - 8Y^4, Z' = 2YZ. */
static void dbl(point *r, const point *p)
{
  mp_limb *s = TMP, *m = TMP + L, *t = TMP + 2 * L, *u = TMP + 3 * L;
  if (is_inf(p)) { *r = *p; return; }
  fsqr(t, p->z);                                   /* Z^2 */
  fsub(u, p->x, t); fadd(t, p->x, t); fmul(m, u, t);
  fadd(t, m, m); fadd(m, m, t);                    /* M = 3(X - Z^2)(X + Z^2) */
  fsqr(t, p->y);                                   /* Y^2 */
  fmul(s, p->x, t); fadd(s, s, s); fadd(s, s, s);  /* S = 4XY^2 */
  fsqr(u, t); fadd(u, u, u); fadd(u, u, u); fadd(u, u, u);   /* 8Y^4 */
  fmul(r->z, p->y, p->z); fadd(r->z, r->z, r->z);  /* Z' = 2YZ */
  fsqr(t, m); fsub(t, t, s); fsub(r->x, t, s);     /* X' = M^2 - 2S */
  fsub(t, s, r->x); fmul(t, m, t); fsub(r->y, t, u);   /* Y' = M(S - X') - 8Y^4 */
}

/* r = p + q, general Jacobian addition. */
static void add(point *r, const point *p, const point *q)
{
  mp_limb *z1z1 = TMP, *z2z2 = TMP + L, *u1 = TMP + 2 * L, *u2 = TMP + 3 * L, *s1 = TMP + 4 * L, *s2 = TMP + 5 * L, *h = TMP + 6 * L, *rr = TMP + 7 * L, *t = TMP + 8 * L;
  if (is_inf(p)) { *r = *q; return; }
  if (is_inf(q)) { *r = *p; return; }
  fsqr(z1z1, p->z); fsqr(z2z2, q->z);
  fmul(u1, p->x, z2z2); fmul(u2, q->x, z1z1);
  fmul(t, z2z2, q->z); fmul(s1, p->y, t);
  fmul(t, z1z1, p->z); fmul(s2, q->y, t);
  fsub(h, u2, u1); fsub(rr, s2, s1);
  if (mp_is_zero(&fp, h)) {
    if (mp_is_zero(&fp, rr)) { dbl(r, p); return; }
    mp_set_small(&fp, r->z, 0); return;            /* p = -q */
  }
  fmul(t, p->z, q->z); fmul(r->z, t, h);           /* Z3 = Z1 Z2 H */
  fsqr(t, h);                                      /* H^2 */
  fmul(u1, u1, t);                                 /* U1 H^2 */
  fmul(t, t, h);                                   /* H^3 */
  fmul(s1, s1, t);                                 /* S1 H^3 */
  fsqr(r->x, rr); fsub(r->x, r->x, t); fsub(r->x, r->x, u1); fsub(r->x, r->x, u1);   /* X3 = R^2 - H^3 - 2 U1 H^2 */
  fsub(t, u1, r->x); fmul(t, rr, t); fsub(r->y, t, s1);   /* Y3 = R(U1 H^2 - X3) - S1 H^3 */
}

static uint8_t bit_of(const mp_limb *k, uint16_t i) { return (uint8_t)((k[i / 16] >> (i % 16)) & 1); }

uint8_t p256_verify(const uint8_t pub[64], const uint8_t hash[32], const uint8_t r[32], const uint8_t s[32])
{
  point *g = (point *)mp_scratch, *q = g + 1, *gq = g + 2, *acc = g + 3;   /* 4 x 48 limbs */
  mp_limb *rn = mp_scratch + 192, *sn = rn + L, *e = sn + L, *w = e + L, *u1 = w + L, *u2 = u1 + L, *t = u2 + L, *x = t + L, *b = x + L;   /* to limb 336 */
  int16_t i;
  uint8_t i1, i2;

  /* the order first: r and s in [1, n-1], w = s^-1, u1 = e w, u2 = r w */
  mp_init(&fn, N, 32);
  mp_copy(&fn, n_limbs, fn.m);
  mp_from_be(&fn, rn, r, 32); mp_from_be(&fn, sn, s, 32);
  STEP(2);
  if (mp_is_zero(&fn, rn) || mp_is_zero(&fn, sn)) return 0;
  STEP(3);
  if (mp_cmp(&fn, rn, fn.m) >= 0 || mp_cmp(&fn, sn, fn.m) >= 0) return 0;
  mp_from_be(&fn, t, hash, 32);
  if (mp_cmp(&fn, t, fn.m) >= 0) mp_sub(&fn, t, t, fn.m);
  mp_to_mont(&fn, e, t);
  mp_to_mont(&fn, t, sn); mp_mont_inv(&fn, w, t);
  mp_mont_mul(&fn, u1, e, w); mp_from_mont(&fn, u1, u1);
  mp_to_mont(&fn, t, rn); mp_mont_mul(&fn, u2, t, w); mp_from_mont(&fn, u2, u2);

  /* then the field: the public key, on the curve (y^2 = x^3 - 3x + b) */
  mp_init(&fp, P, 32);
  mp_from_be(&fp, t, pub, 32); mp_to_mont(&fp, q->x, t);
  mp_from_be(&fp, t, pub + 32, 32); mp_to_mont(&fp, q->y, t);
  STEP(4);
  if (mp_cmp(&fp, q->x, fp.m) >= 0 || mp_cmp(&fp, q->y, fp.m) >= 0) return 0;
  mp_from_be(&fp, t, B, 32); mp_to_mont(&fp, b, t);
  fsqr(t, q->x); fmul(t, t, q->x);                   /* x^3 */
  fsub(t, t, q->x); fsub(t, t, q->x); fsub(t, t, q->x); fadd(t, t, b);
  fsqr(x, q->y);
  if (mp_cmp(&fp, t, x) != 0) return 0;
  mp_from_mont(&fp, q->z, fp.rr);                   /* Z = 1 */

  /* G, and G + Q for Shamir's trick */
  mp_from_be(&fp, t, GX, 32); mp_to_mont(&fp, g->x, t);
  mp_from_be(&fp, t, GY, 32); mp_to_mont(&fp, g->y, t);
  mp_copy(&fp, g->z, q->z);
  add(gq, g, q);

  /* acc = u1 G + u2 Q */
  mp_set_small(&fp, acc->z, 0);
  for (i = 255; i >= 0; i--) {
    dbl(acc, acc);
    i1 = bit_of(u1, (uint16_t)i); i2 = bit_of(u2, (uint16_t)i);
    if (i1 && i2) add(acc, acc, gq);
    else if (i1) add(acc, acc, g);
    else if (i2) add(acc, acc, q);
    if (crypto_yield && (i & 7) == 0) crypto_yield();
  }
  STEP(6);
  if (is_inf(acc)) return 0;
  STEP(7);

  /* x = X / Z^2 mod p, then mod n, against r */
  mp_mont_inv(&fp, t, acc->z); fsqr(t, t); fmul(x, acc->x, t);
  mp_from_mont(&fp, x, x);
  if (mp_cmp(&fp, x, n_limbs) >= 0) mp_sub(&fp, x, x, n_limbs);   /* x mod n: one subtraction suffices, n > p/2, and no borrow */
  return (uint8_t)(mp_cmp(&fp, x, rn) == 0);
}

#ifdef TLS_P256
/* ---- key agreement, for the IRC client (mega-irc 5.12) ----------------
 * k * P for one point: p256_verify's loop without Shamir's trick, on the
 * same scratch layout, with dbl and add as they are. */
static void mul(point *acc, const point *pt, const mp_limb *k)
{
  int16_t i;
  mp_set_small(&fp, acc->z, 0);
  for (i = 255; i >= 0; i--) {
    dbl(acc, acc);
    if (bit_of(k, (uint16_t)i)) add(acc, acc, pt);
    if (crypto_yield && (i & 7) == 0) crypto_yield();
  }
}

/* Affine, big-endian: x = X / Z^2, and y = Y / Z^3 if wanted. */
static void affine(const point *acc, uint8_t *x, uint8_t *y)
{
  mp_limb *t = mp_scratch + 192 + 4 * L, *zi = t + L, *r = zi + L;   /* past the scalar, short of TMP */
  mp_mont_inv(&fp, zi, acc->z);
  fsqr(t, zi); fmul(r, acc->x, t); mp_from_mont(&fp, r, r); mp_to_be(&fp, r, x, 32);
  if (y) { fmul(t, t, zi); fmul(r, acc->y, t); mp_from_mont(&fp, r, r); mp_to_be(&fp, r, y, 32); }
}

/* 32 bytes into a scalar in [1, n-1]: one subtraction reduces, as the
 * hash is reduced in p256_verify. 0 if that leaves zero. */
static uint8_t scalar(mp_limb *k, const uint8_t priv[32])
{
  mp_init(&fn, N, 32);
  mp_from_be(&fn, k, priv, 32);
  if (mp_cmp(&fn, k, fn.m) >= 0) mp_sub(&fn, k, k, fn.m);
  return (uint8_t)!mp_is_zero(&fn, k);
}

uint8_t p256_keygen(uint8_t pub[64], const uint8_t priv[32])
{
  point *g = (point *)mp_scratch, *acc = g + 1;
  mp_limb *k = mp_scratch + 192, *t = k + L;
  if (!scalar(k, priv)) return 0;
  mp_init(&fp, P, 32);
  mp_from_be(&fp, t, GX, 32); mp_to_mont(&fp, g->x, t);
  mp_from_be(&fp, t, GY, 32); mp_to_mont(&fp, g->y, t);
  mp_from_mont(&fp, g->z, fp.rr);                   /* Z = 1 */
  mul(acc, g, k);
  if (is_inf(acc)) return 0;
  affine(acc, pub, pub + 32);
  return 1;
}

uint8_t p256_ecdh(uint8_t out[32], const uint8_t priv[32], const uint8_t peer[64])
{
  point *q = (point *)mp_scratch, *acc = q + 1;
  mp_limb *k = mp_scratch + 192, *t = k + L, *x = t + L, *b = x + L;
  if (!scalar(k, priv)) return 0;
  /* the peer's point, on the curve: the check p256_verify makes of a key */
  mp_init(&fp, P, 32);
  mp_from_be(&fp, t, peer, 32); mp_to_mont(&fp, q->x, t);
  mp_from_be(&fp, t, peer + 32, 32); mp_to_mont(&fp, q->y, t);
  if (mp_cmp(&fp, q->x, fp.m) >= 0 || mp_cmp(&fp, q->y, fp.m) >= 0) return 0;
  mp_from_be(&fp, t, B, 32); mp_to_mont(&fp, b, t);
  fsqr(t, q->x); fmul(t, t, q->x);
  fsub(t, t, q->x); fsub(t, t, q->x); fsub(t, t, q->x); fadd(t, t, b);
  fsqr(x, q->y);
  if (mp_cmp(&fp, t, x) != 0) return 0;
  mp_from_mont(&fp, q->z, fp.rr);
  mul(acc, q, k);
  if (is_inf(acc)) return 0;
  affine(acc, out, 0);
  return 1;
}
#endif

#ifdef CK_SELFTEST
/* For the machine's self-test: 2G and 3G, affine, big-endian x then y,
 * 128 bytes into out; the same computed in Python says whether the
 * point arithmetic holds on this CPU (5.6). */
void p256_test_points(uint8_t *out)
{
  point *g = (point *)mp_scratch, *g2 = g + 1, *g3 = g + 2;
  mp_limb *t = mp_scratch + 192, *x = t + L, *y = x + L, *zi = y + L;
  uint8_t which;
  mp_init(&fp, P, 32);
  mp_from_be(&fp, t, GX, 32); mp_to_mont(&fp, g->x, t);
  mp_from_be(&fp, t, GY, 32); mp_to_mont(&fp, g->y, t);
  mp_from_mont(&fp, g->z, fp.rr);
  dbl(g2, g);
  add(g3, g2, g);
  for (which = 0; which < 2; which++) {
    point *pt = which ? g3 : g2;
    mp_mont_inv(&fp, zi, pt->z);
    fsqr(t, zi); fmul(x, pt->x, t);              /* X / Z^2 */
    fmul(t, t, zi); fmul(y, pt->y, t);           /* Y / Z^3 */
    mp_from_mont(&fp, x, x); mp_from_mont(&fp, y, y);
    mp_to_be(&fp, x, out + which * 64, 32);
    mp_to_be(&fp, y, out + which * 64 + 32, 32);
  }
}
#endif
