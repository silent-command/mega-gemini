/* The kit on the MEGA65: every call goes through the TLS bank's
 * trampoline at $1700 (the page after mega-net's), a mailbox and a JSR,
 * as the SSH client's ckit.c does. Parameter blocks are byte arrays in
 * this program's memory, 28-bit pointers with a zero high byte (bank
 * 0: physical is the CPU address). No key is ever here. */
#include <stdint.h>
#include "tls/tlskit.h"
#include "ck_payload.h"          /* generated: the trampoline bytes and the image size */
#include "m65_tlskit.h"

#define CK_TR 0x1700U
#define TR(o) (*(volatile uint8_t *)(CK_TR + (o)))
#define ck_tr_call ((void (*)(void))(CK_TR + 0x0E))

enum {
  E_INIT = 0x2000, E_VERSION = 0x2003, E_RANDOM_SEED = 0x2006, E_RANDOM = 0x2009,
  E_TRANSCRIPT_INIT = 0x200C, E_TRANSCRIPT_UPDATE = 0x200F, E_TRANSCRIPT_HASH = 0x2012,
  E_KEYSHARE = 0x2015, E_KEYS_HANDSHAKE = 0x2018, E_KEYS_MASTER = 0x201B,
  E_WRITE_SWITCH = 0x201E, E_READ_SWITCH = 0x2021, E_FINISHED = 0x2024,
  E_SEAL = 0x2027, E_OPEN_START = 0x202A, E_OPEN_DATA = 0x202D, E_OPEN_CHECK = 0x2030,
  E_CERT_RESET = 0x2033, E_CERT_APPEND = 0x2036, E_CERT_LEN = 0x2039, E_VERIFY = 0x203C, E_PIN = 0x203F, E_SELFTEST = 0x2042, E_RENDER = 0x2045
};

static uint8_t blk[16];
uint8_t tk_verify_reason;
uint16_t tk_frames_keys, tk_frames_verify;         /* the bank's frames for the shared secret and the signature: Y/Z of those entries (5.12) */
#define FRAMES() ((uint16_t)(blk[14] | ((uint16_t)blk[15] << 8)))   /* the bank writes them there (5.12) */

static uint8_t call(uint16_t entry, uint8_t a, uint8_t x, uint8_t y)
{
  TR(0) = (uint8_t)entry; TR(1) = (uint8_t)(entry >> 8);
  TR(2) = a; TR(3) = x; TR(4) = y; TR(5) = 0;
  ck_tr_call();
  return TR(6);
}

static uint8_t call_blk(uint16_t entry)
{
  uint16_t p = (uint16_t)(uintptr_t)blk;
  return call(entry, (uint8_t)p, (uint8_t)(p >> 8), 0);
}

static void put28(uint8_t *at, const void *p)
{
  uint16_t a = (uint16_t)(uintptr_t)p;
  at[0] = (uint8_t)a; at[1] = (uint8_t)(a >> 8); at[2] = 0; at[3] = 0;
}

static void put16(uint8_t *at, uint16_t v) { at[0] = (uint8_t)v; at[1] = (uint8_t)(v >> 8); }

uint8_t m65_tlskit_init(void)
{
  return (uint8_t)(call(E_INIT, 0, 0, 0) == 0);
}

void m65_tlskit_seed(const uint8_t *p, uint16_t n)
{
  put28(blk, p); put16(blk + 4, n);
  call_blk(E_RANDOM_SEED);
}

void tk_random(uint8_t *out, uint8_t n)
{
  put28(blk, out); blk[4] = n;
  call_blk(E_RANDOM);
}

void tk_transcript_init(void) { call(E_TRANSCRIPT_INIT, 0, 0, 0); }

void tk_transcript_update(const uint8_t *p, uint16_t n)
{
  put28(blk, p); put16(blk + 4, n);
  call_blk(E_TRANSCRIPT_UPDATE);
}

void tk_transcript_hash(uint8_t out[32]) { put28(blk, out); call_blk(E_TRANSCRIPT_HASH); }

void tk_keyshare(uint8_t pub[32]) { put28(blk, pub); call_blk(E_KEYSHARE); }

void tk_keys_handshake(const uint8_t peer_pub[32], const uint8_t hash[32])
{
  put28(blk, peer_pub); put28(blk + 4, hash);
  call_blk(E_KEYS_HANDSHAKE);
  tk_frames_keys = FRAMES();
}

void tk_keys_master(const uint8_t hash[32]) { put28(blk, hash); call_blk(E_KEYS_MASTER); }
void tk_write_switch(void) { call(E_WRITE_SWITCH, 0, 0, 0); }
void tk_read_switch(void) { call(E_READ_SWITCH, 0, 0, 0); }

void tk_finished(uint8_t server, const uint8_t hash[32], uint8_t out[32])
{
  blk[0] = server; put28(blk + 1, hash); put28(blk + 5, out);
  call_blk(E_FINISHED);
}

void tk_seal(uint8_t *rec, uint16_t len)
{
  put28(blk, rec); put16(blk + 4, len);
  call_blk(E_SEAL);
}

void tk_open_start(const uint8_t hdr[5]) { put28(blk, hdr); call_blk(E_OPEN_START); }

void tk_open_data(uint8_t *p, uint16_t n)
{
  put28(blk, p); put16(blk + 4, n);
  call_blk(E_OPEN_DATA);
}

uint8_t tk_open_check(const uint8_t tag[16]) { put28(blk, tag); return call_blk(E_OPEN_CHECK); }

void tk_cert_reset(void) { call(E_CERT_RESET, 0, 0, 0); }

void tk_cert_append(const uint8_t *p, uint16_t n)
{
  put28(blk, p); put16(blk + 4, n);
  call_blk(E_CERT_APPEND);
}

uint16_t tk_cert_len(void)
{
  uint8_t lo = call(E_CERT_LEN, 0, 0, 0);
  return (uint16_t)(lo | ((uint16_t)TR(7) << 8));
}

uint8_t tk_verify(uint16_t scheme, const uint8_t hash[32], const uint8_t *sig, uint16_t siglen)
{
  uint8_t r;
  blk[0] = (uint8_t)(scheme >> 8); blk[1] = (uint8_t)scheme;
  put28(blk + 2, hash); put28(blk + 6, sig); put16(blk + 10, siglen);
  r = call_blk(E_VERIFY);
  tk_verify_reason = TR(7);
  tk_frames_verify = FRAMES();
  return r;
}

uint8_t tk_pin(uint8_t out[32]) { put28(blk, out); return call_blk(E_PIN); }

uint8_t m65_tlskit_selftest(uint8_t which) { uint8_t r = call(E_SELFTEST, which, 0, 0); tk_verify_reason = TR(7); return r; }

void m65_tlskit_render(uint32_t from, uint32_t len, uint8_t plain, uint16_t *rows, uint16_t *links, uint8_t *truncated)
{
  blk[0] = (uint8_t)from; blk[1] = (uint8_t)(from >> 8); blk[2] = (uint8_t)(from >> 16); blk[3] = (uint8_t)(from >> 24);
  blk[4] = (uint8_t)len; blk[5] = (uint8_t)(len >> 8); blk[6] = (uint8_t)(len >> 16); blk[7] = (uint8_t)(len >> 24);
  blk[8] = plain;
  call_blk(E_RENDER);
  *rows = (uint16_t)(blk[9] | ((uint16_t)blk[10] << 8));
  *links = (uint16_t)(blk[11] | ((uint16_t)blk[12] << 8));
  *truncated = blk[13];
}
