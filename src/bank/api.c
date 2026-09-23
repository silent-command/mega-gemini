/* The TLS bank's entries: the C behind each jump in jumptable.S, which
 * is the kit (src/tls/tlskit.h) as the bank sees it. Every entry reads
 * a parameter block from the caller's memory by DMA (A/X/Y hold its
 * 28-bit address), moves data through a staging buffer, and never
 * touches the caller's memory with the CPU, which is hidden while the
 * bank is mapped. The keys, the transcript, the record cipher and the
 * server's certificate all live here; the client sees none of them.
 * INIT is this image's crt0 (ssh src/bank/api.c; mega-net 5.7, 5.11).
 * The long operations yield to mega-net's poll between rounds. */
#include <stdint.h>
#include "crypto.h"
#include "aead.h"
#include "hkdf.h"
#include "keys.h"
#include "x509.h"
#include "dma.h"
#include "mp.h"

#define IN_BSS(n) __attribute__((section(".bss." n)))
#define POKE(a, v) (*(volatile uint8_t *)(a) = (uint8_t)(v))
#define PEEK(a) (*(volatile uint8_t *)(a))
#define PHYS(p) ((uint32_t)(uintptr_t)(p) + CK_PHYS_BASE)

#define CERT_FAR 0x5E900UL       /* bank 5, above mega-net's socket pool: the leaf certificate */
#define CERT_CAP 0x1700U         /* 5888 bytes; a bigger certificate is refused */

extern volatile uint8_t ck_api_a, ck_api_x, ck_api_y, ck_api_z;
extern volatile uint8_t ck_api_ra, ck_api_rx, ck_api_ry, ck_api_rz;
extern char __bss_start[], __bss_size[];
extern char __zp_bss_start[], __zp_bss_size[];
extern char __zp_data_start[], __zp_data_load_start[], __zp_data_size[];

static uint8_t stage[256] IN_BSS("stage");
static uint8_t blk[16] IN_BSS("blk");
static uint8_t small[64] IN_BSS("small");
static sha256_ctx transcript IN_BSS("transcript");
static uint8_t pool[32] IN_BSS("pool");          /* the random pool: a hash, stirred by the client's samples */
static uint32_t pool_ctr IN_BSS("pool_ctr");
static uint8_t priv[32] IN_BSS("priv");
static tls_schedule sched IN_BSS("sched");
static tls_traffic rd IN_BSS("rd"), wr IN_BSS("wr");
static uint32_t rd_seq IN_BSS("rd_seq"), wr_seq IN_BSS("wr_seq");
static aead_ctx cipher IN_BSS("cipher");         /* reading: a record may still be open while... */
static aead_ctx sealer IN_BSS("sealer");         /* ...the client's Finished is sealed (5.5) */
static uint16_t cert_len IN_BSS("cert_len");
#define sig ((uint8_t *)(mp_scratch + 256))      /* an RSA-4096 signature, 512 bytes: the upper half of the scratch, which RSA fills only after it has read the signature; not the multiplier's t, which mp_init now uses (5.12) */
static uint8_t digest[32] IN_BSS("digest");
/* verify's content and key overlay the stage (off the 512-byte soft
 * stack, and the bank is full): the content is hashed into digest
 * before the certificate is read through rdbuf, which is the stage's
 * first 64 bytes; the key sits above them (5.6). */
#define content stage
#define vkey (*(x509_key *)(stage + 130))

static uint32_t arg_ptr(void)
{
  return (uint32_t)ck_api_a | ((uint32_t)ck_api_x << 8) | ((uint32_t)ck_api_y << 16);
}

static uint32_t p28(const uint8_t *b)
{
  return (uint32_t)b[0] | ((uint32_t)b[1] << 8) | ((uint32_t)b[2] << 16) | ((uint32_t)b[3] << 24);
}

static uint16_t u16(const uint8_t *b) { return (uint16_t)(b[0] | ((uint16_t)b[1] << 8)); }

static void get_block(void) { ck_dma_copy(arg_ptr(), PHYS(blk), sizeof blk); }

/* ---- the yield: mega-net's poll, with the map put back to ours ------ */

#define NET_TR 0x1600
#define NET_ENTRY_POLL 0x200F

static uint16_t yield_frames IN_BSS("yield_frames");   /* frames of $D7FA seen at the yields: how long an entry ran (5.12) */
static uint8_t yield_last IN_BSS("yield_last");
static void count_frames(void) { uint8_t f = PEEK(0xd7fa); yield_frames = (uint16_t)(yield_frames + (uint8_t)(f - yield_last)); yield_last = f; }
static void frames_start(void) { yield_frames = 0; yield_last = PEEK(0xd7fa); }
static void frames_done(void) { count_frames(); blk[14] = (uint8_t)yield_frames; blk[15] = (uint8_t)(yield_frames >> 8); ck_dma_copy(PHYS(blk + 14), arg_ptr() + 14, 2); }   /* the frames into the caller's block: not a return register, so Z stays zero (trap 2, 5.12) */

static void net_poll(void)
{
  uint8_t sa, sx, sy, sz;
  count_frames();
  sa = PEEK(NET_TR + 0x0A); sx = PEEK(NET_TR + 0x0B); sy = PEEK(NET_TR + 0x0C); sz = PEEK(NET_TR + 0x0D);
  POKE(NET_TR + 0x0A, 0x00); POKE(NET_TR + 0x0B, 0xE1);       /* our map, as the trampoline sets it */
  POKE(NET_TR + 0x0C, 0x00); POKE(NET_TR + 0x0D, 0xB1);
  POKE(NET_TR + 0x00, NET_ENTRY_POLL & 0xff); POKE(NET_TR + 0x01, NET_ENTRY_POLL >> 8);
  POKE(NET_TR + 0x02, 0); POKE(NET_TR + 0x03, 0); POKE(NET_TR + 0x04, 0); POKE(NET_TR + 0x05, 0);
  ((void (*)(void))(NET_TR + 0x0E))();
  POKE(NET_TR + 0x0A, sa); POKE(NET_TR + 0x0B, sx); POKE(NET_TR + 0x0C, sy); POKE(NET_TR + 0x0D, sz);
}

/* ---- entries ---------------------------------------------------------- */

void ck_api_init(void)
{
  uint16_t n = (uint16_t)(uintptr_t)__bss_size, i;
  for (i = 0; i < n; i++) __bss_start[i] = 0;
  n = (uint16_t)(uintptr_t)__zp_bss_size;
  for (i = 0; i < n; i++) __zp_bss_start[i] = 0;
  n = (uint16_t)(uintptr_t)__zp_data_size;
  for (i = 0; i < n; i++) __zp_data_start[i] = __zp_data_load_start[i];
  /* the vectors in force while the bank is mapped: an RTI at $FFF0 */
  POKE(0xFFF0, 0x40);
  POKE(0xFFFA, 0xF0); POKE(0xFFFB, 0xFF);
  POKE(0xFFFC, 0xF0); POKE(0xFFFD, 0xFF);
  POKE(0xFFFE, 0xF0); POKE(0xFFFF, 0xFF);
  crypto_yield = net_poll;
  ck_api_ra = 0;
}

void ck_api_version(void) { ck_api_ra = 0; ck_api_rx = 1; }

/* Runs f over the caller's bytes in stage-sized pieces. */
static void each_piece(uint32_t src, uint16_t left, void (*f)(uint8_t *, uint16_t), uint8_t back)
{
  uint16_t take;
  while (left) {
    take = left < sizeof stage ? left : (uint16_t)sizeof stage;
    ck_dma_copy(src, PHYS(stage), take);
    f(stage, take);
    if (back) ck_dma_copy(PHYS(stage), src, take);
    src += take; left = (uint16_t)(left - take);
  }
}

/* ---- random: pool = SHA-256(pool, sample); out = SHA-256(pool, counter) */

static void stir(uint8_t *p, uint16_t n)
{
  sha256_ctx c;
  sha256_init(&c); sha256_update(&c, pool, 32); sha256_update(&c, p, n); sha256_final(&c, pool);
}

/* {ptr28, len16} */
void ck_api_random_seed(void) { get_block(); each_piece(p28(blk), u16(blk + 4), stir, 0); }

static void random_fill(uint8_t *out, uint8_t n)
{
  sha256_ctx c;
  uint8_t i, take;
  while (n) {
    sha256_init(&c); sha256_update(&c, pool, 32); sha256_update(&c, (const uint8_t *)&pool_ctr, 4); sha256_final(&c, small);
    pool_ctr++;
    take = n < 32 ? n : 32;
    for (i = 0; i < take; i++) out[i] = small[i];
    out += take; n = (uint8_t)(n - take);
  }
}

/* {out28, n u8} */
void ck_api_random(void)
{
  get_block();
  random_fill(small, blk[4]);
  ck_dma_copy(PHYS(small), p28(blk), blk[4]);
}

/* ---- the transcript ---------------------------------------------------- */

void ck_api_transcript_init(void) { sha256_init(&transcript); }

static void tr_update(uint8_t *p, uint16_t n) { sha256_update(&transcript, p, n); }

/* {ptr28, len16} */
void ck_api_transcript_update(void) { get_block(); each_piece(p28(blk), u16(blk + 4), tr_update, 0); }

/* {out28} */
void ck_api_transcript_hash(void)
{
  sha256_ctx c = transcript;
  get_block();
  sha256_final(&c, small);
  ck_dma_copy(PHYS(small), p28(blk), 32);
}

/* ---- keys -------------------------------------------------------------- */

/* {out28} */
void ck_api_keyshare(void)
{
  get_block();
  random_fill(priv, 32);
  x25519_base(small, priv);
  ck_dma_copy(PHYS(small), p28(blk), 32);
}

/* {peer28, hash28} */
void ck_api_keys_handshake(void)
{
  uint8_t ecdhe[32];
  get_block();
  ck_dma_copy(p28(blk), PHYS(small), 32);        /* the peer's share */
  ck_dma_copy(p28(blk + 4), PHYS(small + 32), 32);   /* hash(CH, SH) */
  frames_start();
  x25519(ecdhe, priv, small);
  tls_schedule_start(&sched);
  tls_schedule_handshake(&sched, ecdhe, small + 32);
  tls_traffic_keys(sched.s_hs, &rd); rd_seq = 0;
  tls_traffic_keys(sched.c_hs, &wr); wr_seq = 0;
  frames_done();
}

/* {hash28} */
void ck_api_keys_master(void)
{
  get_block();
  ck_dma_copy(p28(blk), PHYS(small), 32);
  tls_schedule_master(&sched, small);
}

void ck_api_write_switch(void) { tls_traffic_keys(sched.c_ap, &wr); wr_seq = 0; }
void ck_api_read_switch(void) { tls_traffic_keys(sched.s_ap, &rd); rd_seq = 0; }

/* {server u8, hash28, out28} */
void ck_api_finished(void)
{
  get_block();
  ck_dma_copy(p28(blk + 1), PHYS(small), 32);
  tls_finished(blk[0] ? sched.s_hs : sched.c_hs, small, small + 32);
  ck_dma_copy(PHYS(small + 32), p28(blk + 5), 32);
}

/* ---- records ----------------------------------------------------------- */

static void enc_piece(uint8_t *p, uint16_t n) { aead_encrypt(&sealer, p, n); }
static void dec_piece(uint8_t *p, uint16_t n) { aead_decrypt(&cipher, p, n); }

/* {rec28, len16}: the header's length filled in, the plaintext
 * encrypted in place, the tag appended */
void ck_api_seal(void)
{
  uint8_t nonce[12];
  uint32_t rec;
  uint16_t len;
  get_block();
  rec = p28(blk); len = u16(blk + 4);
  ck_dma_copy(rec, PHYS(small), 5);
  small[3] = (uint8_t)((len + 16) >> 8); small[4] = (uint8_t)(len + 16);
  ck_dma_copy(PHYS(small), rec, 5);
  tls_nonce(&wr, 0, wr_seq++, nonce);
  aead_start(&sealer, wr.key, nonce, small, 5);
  each_piece(rec + 5, len, enc_piece, 1);
  aead_tag(&sealer, small);
  ck_dma_copy(PHYS(small), rec + 5 + len, 16);
  /* Poly1305's multiplier table on this machine is one global, valid for
   * whichever context built it last (poly1305.c, rr_ready): the record
   * being read, if one is open, must rebuild its own (5.5) */
  cipher.poly.rr_ready = 0;
}

/* {hdr28} */
void ck_api_open_start(void)
{
  uint8_t nonce[12];
  get_block();
  ck_dma_copy(p28(blk), PHYS(small), 5);
  tls_nonce(&rd, 0, rd_seq, nonce);
  aead_start(&cipher, rd.key, nonce, small, 5);
}

/* {ptr28, len16}: in place */
void ck_api_open_data(void) { get_block(); each_piece(p28(blk), u16(blk + 4), dec_piece, 1); }

/* {tag28}; A = 1 if it matched */
void ck_api_open_check(void)
{
  get_block();
  ck_dma_copy(p28(blk), PHYS(small), 16);
  rd_seq++;
  ck_api_ra = (uint8_t)aead_check(&cipher, small);
}

/* ---- the certificate ---------------------------------------------------- */

void ck_api_cert_reset(void) { cert_len = 0; }

/* {ptr28, len16}: appended in far memory, up to CERT_CAP */
void ck_api_cert_append(void)
{
  uint16_t n;
  get_block();
  n = u16(blk + 4);
  if ((uint32_t)cert_len + n > CERT_CAP) n = (uint16_t)(CERT_CAP - cert_len);
  if (n) { ck_dma_copy(p28(blk), CERT_FAR + cert_len, n); cert_len = (uint16_t)(cert_len + n); }
}

void ck_api_cert_len(void) { ck_api_ra = (uint8_t)cert_len; ck_api_rx = (uint8_t)(cert_len >> 8); }

/* The certificate's bytes into `dst`, which is whatever the walker hands
 * over: a local, often in zero page, which a DMA cannot reach (zero page
 * is bank 0's, not this image's, so PHYS() of it is wrong: 5.5). So the
 * DMA lands in a pinned buffer and the CPU copies from there. */
#define rdbuf stage                              /* the stage's first RDBUF_CAP bytes, idle during a verify */
#define RDBUF_CAP 64                             /* not sizeof stage: the key sits at stage + 130, and an RSA modulus is 256 bytes (5.10) */
static void cert_read(void *ctx, uint16_t off, uint8_t *dst, uint16_t n)
{
  uint8_t *end = dst + n, *q, *qend;
  uint16_t take;
  (void)ctx;
  while (dst < end) {                              /* walks, not counts: the checker's rule (ssh 5.6) */
    if (off >= cert_len) { while (dst < end) *dst++ = 0; return; }
    take = (uint16_t)(end - dst);
    if (take > RDBUF_CAP) take = RDBUF_CAP;
    if ((uint32_t)off + take > cert_len) take = (uint16_t)(cert_len - off);
    ck_dma_copy(CERT_FAR + off, PHYS(rdbuf), take);
    for (q = rdbuf, qend = rdbuf + take; q < qend; q++) *dst++ = *q;
    off = (uint16_t)(off + take);
  }
}

/* The content signed in CertificateVerify: 64 spaces, the context
 * string, a zero, the transcript hash (RFC 8446 4.4.3). */
static void cv_content(const uint8_t hash[32], uint8_t out[130])
{
  static const char ctx[] = "TLS 1.3, server CertificateVerify";
  uint8_t i;
  for (i = 0; i < 64; i++) out[i] = ' ';
  for (i = 0; ctx[i]; i++) out[64 + i] = (uint8_t)ctx[i];
  out[97] = 0;
  for (i = 0; i < 32; i++) out[98 + i] = hash[i];
}

/* {scheme16, hash28, sig28, siglen16}; A = 0 wrong, 1 verified, 2
 * unchecked; X = why, when wrong: 1 the signature is too long, 2 the
 * certificate could not be read, 3 the key is of another kind, 4 the
 * arithmetic (or the DER) refused it. */
void ck_api_verify(void)
{
  uint16_t scheme, siglen;
  get_block();
  scheme = (uint16_t)(((uint16_t)blk[0] << 8) | blk[1]); siglen = u16(blk + 10);
  if (!x509_scheme_supported(scheme)) { ck_api_ra = 2; return; }
  ck_api_ra = 0; ck_api_rx = 1;
  frames_start();
  if (siglen > 512) return;                        /* sig is 512 bytes; RSA-4096 is 512 */
  ck_dma_copy(p28(blk + 2), PHYS(small), 32);
  ck_dma_copy(p28(blk + 6), PHYS(sig), siglen);
  cv_content(small, content);
  sha256(content, 130, digest);                    /* before the certificate is read: content overlays the stage */
  ck_api_rx = 2;
  if (!x509_key_of(cert_read, 0, cert_len, &vkey)) return;
  ck_api_rx = 3;
  switch (scheme) {
#ifndef X509_NO_ED25519
#error "the bank's Ed25519 path needs content after the certificate is read, and content overlays the stage (5.6)"
#endif
  case 0x0403:
    if (vkey.kind != X509_KEY_P256) return;
    ck_api_rx = 4;
    ck_api_ra = x509_ecdsa_p256_verify(vkey.p256, digest, sig, siglen);
    frames_done();
    return;
#ifndef CK_SELFTEST                              /* the timing build leaves RSA out for the room the test vector takes */
  case 0x0804:
    if (vkey.kind != X509_KEY_RSA) return;
    ck_api_rx = 4;
    ck_api_ra = x509_rsa_pss_verify(cert_read, 0, &vkey, digest, sig, siglen);
    frames_done();
    return;
#endif
  }
}

/* {out28}; A = 1 if the certificate could be read */
void ck_api_pin(void)
{
  get_block();                                     /* key overlays the stage, as in verify */
  x509_key_of(cert_read, 0, cert_len, &vkey);
  ck_api_ra = 0;
  if (!vkey.spki_len) return;
  x509_spki_hash(cert_read, 0, &vkey, small);
  ck_dma_copy(PHYS(small), p28(blk), 32);
  ck_api_ra = 1;
}

#ifdef CK_SELFTEST
/* One 32-bit row on known inputs, for mon.py and Python (5.12): in at
 * mp_scratch, p at +64 bytes, out at +128, the carry out at +192. In
 * every build while the row is being proved. */
extern uint32_t mp32_a, mp32_cy;
extern uint16_t mp32_in, mp32_p, mp32_out;
extern uint8_t mp32_cnt;
void mp_row32_m65(void);
static void row32_test(void)
{
  mp_limb *in = mp_scratch, *p = mp_scratch + 32, *out = mp_scratch + 64;
  uint8_t k;
  for (k = 0; k < 32; k++) { in[k] = (mp_limb)(0x1000 * (k + 1)); p[k] = (mp_limb)(0xffff - 0x0101 * k); out[k] = 0xeeee; }
  mp32_a = 0xffffffffUL; mp32_cy = 0xffffffffUL;
  mp32_in = (uint16_t)(uintptr_t)in; mp32_p = (uint16_t)(uintptr_t)p; mp32_out = (uint16_t)(uintptr_t)out; mp32_cnt = 16;
  mp_row32_m65();
  mp_scratch[96] = (mp_limb)mp32_cy; mp_scratch[97] = (mp_limb)(mp32_cy >> 16);
}

/* The time of 512 rows of 128 limbs over the scratch, in frames of $D7FA (5.12) */
static uint8_t time_rows(void (*row)(void))
{
  uint16_t rows; uint8_t f0 = PEEK(0xd7fa);
  for (rows = 0; rows < 512; rows++) {
    mp32_a = 0x89abcdefUL; mp32_cy = 0;
    mp32_in = (uint16_t)(uintptr_t)mp_scratch; mp32_p = (uint16_t)(uintptr_t)(mp_scratch + 256); mp32_out = mp32_in; mp32_cnt = 128;
    row();
  }
  return (uint8_t)(PEEK(0xd7fa) - f0);
}
void fe_mul_m65(void);
static uint8_t time_fe_mul(void)
{
  uint16_t k; uint8_t f0 = PEEK(0xd7fa);
  for (k = 0; k < 1024; k++) fe_mul_m65();          /* 64 products each: 65536, as the rows */
  return (uint8_t)(PEEK(0xd7fa) - f0);
}

/* The benchmarks in turn, one per call: the row, then fe_mul, 65536 limb-steps each (5.12; the unpatched and I/O-less rows were measured and dropped) */
static uint8_t bench_next(void)
{
  static uint8_t which;
  switch (which++ & 3) {
  case 0: row32_test(); return time_rows(mp_row32_m65);
  case 1: return time_fe_mul();
  default: return 0;
  }
}

#endif

/* A = 1 if the P-256 verifier accepts RFC 6979 A.2.5's first signature
 * here, on this machine: the arithmetic judged apart from any handshake. */
#ifdef CK_SELFTEST
/* RFC 6979 A.2.5, the key and the signature over "sample", as tests/sigvectors.h has them */
static const uint8_t st_pub[64] = {
  0x60, 0xfe, 0xd4, 0xba, 0x25, 0x5a, 0x9d, 0x31, 0xc9, 0x61, 0xeb, 0x74, 0xc6, 0x35, 0x6d, 0x68,
  0xc0, 0x49, 0xb8, 0x92, 0x3b, 0x61, 0xfa, 0x6c, 0xe6, 0x69, 0x62, 0x2e, 0x60, 0xf2, 0x9f, 0xb6,
  0x79, 0x03, 0xfe, 0x10, 0x08, 0xb8, 0xbc, 0x99, 0xa4, 0x1a, 0xe9, 0xe9, 0x56, 0x28, 0xbc, 0x64,
  0xf2, 0xf1, 0xb2, 0x0c, 0x2d, 0x7e, 0x9f, 0x51, 0x77, 0xa3, 0xc2, 0x94, 0xd4, 0x46, 0x22, 0x99
};
static const uint8_t st_hash[32] = {
  0xaf, 0x2b, 0xdb, 0xe1, 0xaa, 0x9b, 0x6e, 0xc1, 0xe2, 0xad, 0xe1, 0xd6, 0x94, 0xf4, 0x1f, 0xc7,
  0x1a, 0x83, 0x1d, 0x02, 0x68, 0xe9, 0x89, 0x15, 0x62, 0x11, 0x3d, 0x8a, 0x62, 0xad, 0xd1, 0xbf
};
static const uint8_t st_sig[72] = {
  0x30, 0x46, 0x02, 0x21, 0x00, 0xef, 0xd4, 0x8b, 0x2a, 0xac, 0xb6, 0xa8, 0xfd, 0x11, 0x40, 0xdd,
  0x9c, 0xd4, 0x5e, 0x81, 0xd6, 0x9d, 0x2c, 0x87, 0x7b, 0x56, 0xaa, 0xf9, 0x91, 0xc3, 0x4d, 0x0e,
  0xa8, 0x4e, 0xaf, 0x37, 0x16, 0x02, 0x21, 0x00, 0xf7, 0xcb, 0x1c, 0x94, 0x2d, 0x65, 0x7c, 0x41,
  0xd4, 0x36, 0xc7, 0xa1, 0xb6, 0xe2, 0x9f, 0x65, 0xf3, 0xe9, 0x00, 0xdb, 0xb9, 0xaf, 0xf4, 0x06,
  0x4d, 0xc4, 0xab, 0x2f, 0x84, 0x3a, 0xcd, 0xa8
};

/* P-256 against RFC 6979 A.2.5. Returns 1 if it passed. */
extern uint16_t fe_mul_out[32];
void ck_api_selftest(void)
{
  if (ck_api_a == 4) { ck_api_rx = bench_next(); ck_api_ra = 1; return; }
  if (ck_api_a == 3) { extern void p256_test_points(uint8_t *); p256_test_points((uint8_t *)(mp_scratch + 320)); ck_api_ra = 1; return; }   /* 2G, 3G at mp_scratch + 640 bytes */
  { extern uint8_t p256_step;
    ck_api_ra = x509_ecdsa_p256_verify(st_pub, st_hash, st_sig, sizeof st_sig);   /* the AEAD test of 5.5 is gone for room; it passed */
    ck_api_rx = p256_step; }
}
#else
void ck_api_selftest(void) { ck_api_ra = 0; ck_api_rx = 9; }   /* not built in: -DCK_SELFTEST (5.5) */
#endif
