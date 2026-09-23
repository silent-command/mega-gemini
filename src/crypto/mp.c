#include "mp.h"

mp_ctx mp_shared;
mp_limb mp_scratch[MP_SCRATCH_LIMBS];

static int8_t cmp_n(uint16_t n, const mp_limb *a, const mp_limb *b);
static mp_limb sub_n(uint16_t n, mp_limb *r, const mp_limb *a, const mp_limb *b);

/* ---- the rows ------------------------------------------------------------ */

/* One row over 32-bit limbs: out[k] = in[k] + a * p[k] + carry for cnt
 * limbs, the carry carried through; the limbs are the 16-bit arrays'
 * bytes read four at a time, little-endian either way. On the MEGA65
 * the row runs on the math unit in the Q register (mp32_m65.S, any
 * length); on the host it is C over 16-bit pieces, so the driver
 * around it is tested where it is written (5.12). */
#ifdef __mos__
extern uint32_t mp32_a, mp32_cy;
extern uint16_t mp32_in, mp32_p, mp32_out;
extern uint8_t mp32_cnt;
void mp_row32_m65(void);
static void row32(uint32_t a, const uint32_t *in, const uint32_t *p, uint32_t *out, uint8_t cnt, uint32_t *carry)
{
  mp32_a = a; mp32_cy = *carry;
  mp32_in = (uint16_t)(uintptr_t)in; mp32_p = (uint16_t)(uintptr_t)p; mp32_out = (uint16_t)(uintptr_t)out;
  mp32_cnt = cnt;
  mp_row32_m65();
  *carry = mp32_cy;
}
#else
/* a * b as two words, from four 16-bit products (no 64-bit arithmetic here either) */
static void mul32(uint32_t a, uint32_t b, uint32_t *lo, uint32_t *hi)
{
  uint32_t al = a & 0xffff, ah = a >> 16, bl = b & 0xffff, bh = b >> 16;
  uint32_t ll = al * bl, lh = al * bh, hl = ah * bl, hh = ah * bh;
  uint32_t mid = (ll >> 16) + (lh & 0xffff) + (hl & 0xffff);   /* at most 3 * 0xffff */
  *lo = (ll & 0xffff) | (mid << 16);
  *hi = hh + (lh >> 16) + (hl >> 16) + (mid >> 16);
}
static void row32(uint32_t a, const uint32_t *in, const uint32_t *p, uint32_t *out, uint8_t cnt, uint32_t *carry)
{
  uint32_t lo, hi, c = *carry, s;
  for (; cnt; cnt--) {
    mul32(a, *p++, &lo, &hi);
    s = lo + *in++; hi += (s < lo);              /* the whole is under 2^64: neither carry overflows hi */
    lo = s + c; hi += (lo < s);
    *out++ = lo; c = hi;
  }
  *carry = c;
}
#endif

#ifdef __mos__
/* The 256-bit product and reduction on the math unit (mp256_m65.S and
 * the SSH client's fe_mul_m65): the same Montgomery form as the rows,
 * R = 2^256, so the paths are interchangeable for a 16-limb modulus. */
extern uint16_t fe_mul_in_a[16], fe_mul_in_b[16], fe_mul_out[32];
extern uint16_t mp_asm_m[16];
extern uint32_t mp_asm_mu;
extern uint8_t mp_asm_i, mp_asm_top;
void fe_mul_m65(void);
void mp_round256_m65(void);
static uint16_t mults256;
static void mont_mul256(mp_ctx *c, mp_limb *r, const mp_limb *a, const mp_limb *b)
{
  uint16_t *p = fe_mul_in_a, *q = fe_mul_in_b, *end = fe_mul_in_a + 16;
  const mp_limb *t;
  while (p < end) { *p++ = *a++; *q++ = *b++; }
  fe_mul_m65();
  mp_asm_top = 0;
  for (mp_asm_i = 0; mp_asm_i < 8; mp_asm_i++) {  /* eight rounds: mu = t[i] * n0 mod 2^32, then the row on the math unit */
    const uint16_t *ti = fe_mul_out + 2 * mp_asm_i;
    mp_asm_mu = ((uint32_t)ti[0] | ((uint32_t)ti[1] << 16)) * c->n0_32;
    mp_round256_m65();
  }
  t = fe_mul_out + 16;
  if (mp_asm_top || cmp_n(16, t, c->m) >= 0) sub_n(16, r, t, c->m);
  else { mp_limb *o = r; const mp_limb *e = t + 16; while (t < e) *o++ = *t++; }
  if (crypto_yield && (++mults256 & 31) == 0) crypto_yield();
}
#else
/* One row over 16-bit limbs, the host's multiplier (and the reference
 * the 32-bit driver is checked against). */
static void mac_row(uint16_t a, const mp_limb *in, const mp_limb *p, mp_limb *out, uint16_t cnt, uint16_t *carry)
{
  const mp_limb *end = in + cnt;
  uint32_t acc = (uint32_t)*carry << 16;           /* the carry in, where the loop reads it from */
  while (in < end) {
    acc = (uint32_t)*in++ + (uint32_t)a * *p++ + (acc >> 16);
    *out++ = (mp_limb)acc;
  }
  *carry = (mp_limb)(acc >> 16);
}
#endif

/* ---- the helpers ---------------------------------------------------------- */

/* Compares a and b as n-limb numbers. */
static int8_t cmp_n(uint16_t n, const mp_limb *a, const mp_limb *b)
{
  while (n--) {
    if (a[n] != b[n]) return a[n] > b[n] ? 1 : -1;
  }
  return 0;
}

/* r = a - b, returning the borrow. */
static mp_limb sub_n(uint16_t n, mp_limb *r, const mp_limb *a, const mp_limb *b)
{
  uint32_t borrow = 0;
  uint16_t i;
  for (i = 0; i < n; i++) {
    uint32_t d = (uint32_t)a[i] - b[i] - borrow;
    r[i] = (mp_limb)d;
    borrow = (d >> 16) & 1;
  }
  return (mp_limb)borrow;
}

/* r = a + b, returning the carry. */
static mp_limb add_n(uint16_t n, mp_limb *r, const mp_limb *a, const mp_limb *b)
{
  uint32_t carry = 0;
  uint16_t i;
  for (i = 0; i < n; i++) {
    uint32_t s = (uint32_t)a[i] + b[i] + carry;
    r[i] = (mp_limb)s;
    carry = s >> 16;
  }
  return (mp_limb)carry;
}

void mp_copy(const mp_ctx *c, mp_limb *r, const mp_limb *a)
{
  uint16_t i;
  for (i = 0; i < c->n; i++) r[i] = a[i];
}

void mp_set_small(const mp_ctx *c, mp_limb *r, uint16_t v)
{
  uint16_t i;
  r[0] = v;
  for (i = 1; i < c->n; i++) r[i] = 0;
}

uint8_t mp_is_zero(const mp_ctx *c, const mp_limb *a)
{
  uint16_t i;
  for (i = 0; i < c->n; i++) if (a[i]) return 0;
  return 1;
}

int8_t mp_cmp(const mp_ctx *c, const mp_limb *a, const mp_limb *b) { return cmp_n(c->n, a, b); }

void mp_add(const mp_ctx *c, mp_limb *r, const mp_limb *a, const mp_limb *b)
{
  mp_limb carry = add_n(c->n, r, a, b);
  if (carry || cmp_n(c->n, r, c->m) >= 0) sub_n(c->n, r, r, c->m);
}

void mp_sub(const mp_ctx *c, mp_limb *r, const mp_limb *a, const mp_limb *b)
{
  if (sub_n(c->n, r, a, b)) add_n(c->n, r, r, c->m);
}

void mp_from_be(const mp_ctx *c, mp_limb *x, const uint8_t *be, uint16_t len)
{
  uint16_t i;
  for (i = 0; i < c->n; i++) x[i] = 0;
  for (i = 0; i < len && i / 2 < c->n; i++) {
    uint8_t b = be[len - 1 - i];
    x[i / 2] |= (mp_limb)((i & 1) ? ((uint16_t)b << 8) : b);
  }
}

void mp_to_be(const mp_ctx *c, const mp_limb *x, uint8_t *be, uint16_t len)
{
  uint16_t i;
  for (i = 0; i < len; i++) {
    uint16_t limb = i / 2 < c->n ? x[i / 2] : 0;
    be[len - 1 - i] = (uint8_t)((i & 1) ? (limb >> 8) : limb);
  }
}

/* ---- the multipliers ------------------------------------------------------ */

/* CIOS Montgomery multiplication (Koc, Acar, Kaliski 1996) over 32-bit
 * limbs, for an even number of 16-bit ones: every RSA modulus (rsa.c
 * refuses the rest), and P-256's on the host. With b, r = a * b / R;
 * with b null, r = a / R, the reduction rounds alone. The scratch keeps
 * a spare limb below t: the reduction row, which shifts t down by one
 * limb, writes its dropped low limb there (5.12). */
static void mont32(mp_ctx *c, mp_limb *r, const mp_limb *a, const mp_limb *b)
{
  uint8_t N = (uint8_t)(c->n >> 1), i;
  uint32_t *t = (uint32_t *)(c->t + 2), *tp;
  const uint32_t *A = (const uint32_t *)a, *B = (const uint32_t *)b, *M = (const uint32_t *)c->m;
  uint32_t carry, acc, mu;
  if (b) { for (tp = t; tp <= t + N + 1; tp++) *tp = 0; }
  else { for (tp = t; tp < t + N; tp++) *tp = *A++; t[N] = t[N + 1] = 0; }
  for (i = 0; i < N; i++) {
    if (b) {
      carry = 0;
      row32(A[i], t, B, t, N, &carry);
      acc = t[N] + carry; t[N + 1] = (acc < carry); t[N] = acc;
    }
    mu = t[0] * c->n0_32;
    carry = 0;
    row32(mu, t, M, t - 1, N, &carry);            /* t[k] + mu m[k] + carry into t[k - 1]: the low limb, zero, lands below t */
    acc = t[N] + carry; t[N - 1] = acc; t[N] = t[N + 1] + (acc < carry); t[N + 1] = 0;
    if (crypto_yield && (i & 15) == 15) crypto_yield();
  }
  if (t[N] || cmp_n(c->n, (const mp_limb *)t, c->m) >= 0) sub_n(c->n, r, (const mp_limb *)t, c->m);
  else { const mp_limb *s = (const mp_limb *)t, *e = s + c->n; while (s < e) *r++ = *s++; }
}

void mp_mont_mul32(mp_ctx *c, mp_limb *r, const mp_limb *a, const mp_limb *b) { mont32(c, r, a, b); }
void mp_mont_reduce32(mp_ctx *c, mp_limb *r, const mp_limb *a) { mont32(c, r, a, 0); }

#ifdef __mos__
void mp_mont_mul(mp_ctx *c, mp_limb *r, const mp_limb *a, const mp_limb *b)
{
  if (c->n == 16) mont_mul256(c, r, a, b);
  else mont32(c, r, a, b);                         /* n even: rsa.c sees to it (5.12) */
}

void mp_from_mont(mp_ctx *c, mp_limb *r, const mp_limb *a)
{
  static const mp_limb one[16] = { 1 };
  if (c->n == 16) mont_mul256(c, r, a, one);
  else mont32(c, r, a, 0);
}
#else
/* The host's CIOS over 16-bit limbs. Every sum here is at most
 * 0xFFFF + 0xFFFF * 0xFFFF + 0xFFFF = 0xFFFFFFFF. Each of the two inner
 * loops is one row (mac_row); the reduction's first step, whose result
 * is dropped, is done here. */
void mp_mont_mul(mp_ctx *c, mp_limb *r, const mp_limb *a, const mp_limb *b)
{
  mp_limb *t = c->t, *tp, *end = c->t + c->n;
  const mp_limb *ap;
  uint16_t carry;
  uint32_t acc, mu;

  for (tp = t; tp <= end + 1; tp++) *tp = 0;
  for (ap = a; ap < a + c->n; ap++) {
    carry = 0;
    mac_row(*ap, t, b, t, c->n, &carry);
    acc = (uint32_t)end[0] + carry;
    end[0] = (mp_limb)acc;
    end[1] = (mp_limb)(acc >> 16);

    mu = ((uint32_t)t[0] * c->n0) & 0xffff;
    acc = (uint32_t)t[0] + mu * c->m[0];
    carry = (mp_limb)(acc >> 16);
    mac_row((uint16_t)mu, t + 1, c->m + 1, t, (uint16_t)(c->n - 1), &carry);
    acc = (uint32_t)end[0] + carry;
    end[-1] = (mp_limb)acc;
    end[0] = (mp_limb)(end[1] + (acc >> 16));
    if (crypto_yield && ((ap - a) & 15) == 15) crypto_yield();
  }
  if (end[0] || cmp_n(c->n, t, c->m) >= 0) sub_n(c->n, r, t, c->m);
  else for (tp = t; tp < end; tp++) *r++ = *tp;
}

/* Montgomery reduction alone, r = a / R mod m: the product with one,
 * without an array of one. */
void mp_from_mont(mp_ctx *c, mp_limb *r, const mp_limb *a)
{
  mp_limb *t = c->t, *tp, *end = c->t + c->n;
  const mp_limb *ap = a, *round;
  uint16_t carry;
  uint32_t acc, mu;

  for (tp = t; tp < end; tp++) *tp = *ap++;
  end[0] = end[1] = 0;
  for (round = c->m; round < c->m + c->n; round++) {   /* n rounds, as a walk: the checker refuses counted loops here */
    mu = ((uint32_t)t[0] * c->n0) & 0xffff;
    acc = (uint32_t)t[0] + mu * c->m[0];
    carry = (mp_limb)(acc >> 16);
    mac_row((uint16_t)mu, t + 1, c->m + 1, t, (uint16_t)(c->n - 1), &carry);
    acc = (uint32_t)end[0] + carry;
    end[-1] = (mp_limb)acc;
    end[0] = (mp_limb)(end[1] + (acc >> 16));
    end[1] = 0;
  }
  if (end[0] || cmp_n(c->n, t, c->m) >= 0) sub_n(c->n, r, t, c->m);
  else for (tp = t; tp < end; tp++) *r++ = *tp;
}
#endif

void mp_to_mont(mp_ctx *c, mp_limb *r, const mp_limb *a) { mp_mont_mul(c, r, a, c->rr); }

void mp_init(mp_ctx *c, const uint8_t *m, uint16_t mlen)
{
  uint16_t i, d;
  uint8_t s = 0;
  uint32_t inv, m0;

  c->n = (uint16_t)((mlen + 1) / 2);
  if (c->n > MP_MAX_LIMBS) c->n = MP_MAX_LIMBS;
  mp_from_be(c, c->m, m, mlen);
  /* -m^-1 mod 2^16 by Newton's iteration: each step doubles the bits */
  m0 = c->m[0];
  inv = 1;
  for (i = 0; i < 5; i++) inv = (inv * (2 - m0 * inv)) & 0xffff;
  c->n0 = (mp_limb)((0x10000 - inv) & 0xffff);
  /* the same for 2^32, from m's low word; 6 steps: 1, 2, 4, 8, 16, 32 bits */
  m0 = (uint32_t)c->m[0] | ((uint32_t)c->m[1] << 16);
  inv = 1;
  for (i = 0; i < 6; i++) inv = inv * (2 - m0 * inv);
  c->n0_32 = 0 - inv;
#ifdef __mos__
  if (c->n == 16) {                                /* the machine's 256-bit path reads these */
    mp_limb *dm = mp_asm_m, *e = mp_asm_m + 16; const mp_limb *sm = c->m;
    while (dm < e) *dm++ = *sm++;
  }
#endif
  /* R^2 mod m. R mod m is R - m, m's top bit being set (rsa.c checks it;
   * the P-256 moduli have it), so R < 2m. Doubled d times it is R 2^d;
   * squared s times, in Montgomery form, R 2^(d 2^s); with 16n = d 2^s
   * that is R^2. A doubling is about a two-hundredth of a product on
   * the machine, so d is the largest power-of-two share of 16n that
   * stays at or under 256: for RSA-4096, 256 doublings and four
   * squarings, against 8,192 doublings, or twelve squarings (5.12). */
  mp_set_small(c, c->rr, 0);
  sub_n(c->n, c->rr, c->rr, c->m);
  for (d = (uint16_t)(16 * c->n); d > 256; d >>= 1) s++;   /* 16n has four factors of two: d stays whole */
  for (; d; d--) mp_add(c, c->rr, c->rr, c->rr);
  for (; s; s--) mp_mont_mul(c, c->rr, c->rr, c->rr);
}

/* Square-and-multiply, most significant bit first, over bits supplied
 * by `bit(i)`; r must not alias a. */
static void exp_bits(mp_ctx *c, mp_limb *r, const mp_limb *a, uint16_t nbits, uint8_t (*bit)(const void *, uint16_t), const void *e)
{
  uint16_t i;
  uint8_t started = 0;
  mp_from_mont(c, r, c->rr);                       /* R mod m: one, in Montgomery form */
  for (i = nbits; i-- > 0;) {
    if (started) mp_mont_mul(c, r, r, r);
    if (bit(e, i)) { if (started) mp_mont_mul(c, r, r, a); else { mp_copy(c, r, a); started = 1; } }
  }
}

typedef struct { const uint8_t *e; uint16_t len; } be_exp;
static uint8_t be_bit(const void *v, uint16_t i)
{
  const be_exp *x = v;
  return (uint8_t)((x->e[x->len - 1 - i / 8] >> (i % 8)) & 1);
}

void mp_mont_exp(mp_ctx *c, mp_limb *r, const mp_limb *a, const uint8_t *e, uint16_t elen)
{
  be_exp x;
  x.e = e; x.len = elen;
  exp_bits(c, r, a, (uint16_t)(8 * elen), be_bit, &x);
}

/* The bits of m - 2, read off m itself: only the low limb differs,
 * since m is odd and at least 3 (2^16 - 1 or more here). */
typedef struct { const mp_limb *m; mp_limb low; } m2_exp;
static uint8_t m2_bit(const void *v, uint16_t i)
{
  const m2_exp *x = v;
  mp_limb limb = i < 16 ? x->low : x->m[i / 16];
  return (uint8_t)((limb >> (i % 16)) & 1);
}

void mp_mont_inv(mp_ctx *c, mp_limb *r, const mp_limb *a)
{
  m2_exp x;
  x.m = c->m; x.low = (mp_limb)(c->m[0] - 2);
  exp_bits(c, r, a, (uint16_t)(16 * c->n), m2_bit, &x);
}
