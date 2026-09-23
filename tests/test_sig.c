/* The host suite for mp.c, p256.c and rsa.c, against tests/sigvectors.h
 * (tools/sig_vectors.py) and RFC 6979. */
#include <stdio.h>
#include <string.h>
#include "mp.h"
#include "p256.h"
#include "rsa.h"
#include "tls/x509.h"
#include "../tests/sigvectors.h"

static int checks, failed;
#define CHECK(cond, what) do { checks++; if (!(cond)) { failed++; printf("FAIL line %d: %s\n", __LINE__, what); } } while (0)

static mp_ctx c;

static void mp_case(const char *name, const uint8_t *m, uint16_t mlen, const uint8_t *a, const uint8_t *b,
                    const uint8_t *e, uint16_t elen, const uint8_t *ab, const uint8_t *ae, const uint8_t *ainv)
{
  mp_limb x[MP_MAX_LIMBS], y[MP_MAX_LIMBS], r[MP_MAX_LIMBS];
  uint8_t out[512];
  char msg[64];
  mp_init(&c, m, mlen);
  mp_from_be(&c, x, a, mlen); mp_from_be(&c, y, b, mlen);
  mp_to_be(&c, x, out, mlen);
  snprintf(msg, sizeof msg, "%s: bytes round trip", name); CHECK(!memcmp(out, a, mlen), msg);
  mp_to_mont(&c, x, x); mp_to_mont(&c, y, y);
  mp_mont_mul(&c, r, x, y); mp_from_mont(&c, r, r); mp_to_be(&c, r, out, mlen);
  snprintf(msg, sizeof msg, "%s: a*b mod m", name); CHECK(!memcmp(out, ab, mlen), msg);
  mp_mont_exp(&c, r, x, e, elen); mp_from_mont(&c, r, r); mp_to_be(&c, r, out, mlen);
  snprintf(msg, sizeof msg, "%s: a^e mod m", name); CHECK(!memcmp(out, ae, mlen), msg);
  if (ainv) {
    mp_mont_inv(&c, r, x); mp_from_mont(&c, r, r); mp_to_be(&c, r, out, mlen);
    snprintf(msg, sizeof msg, "%s: a^-1 mod m", name); CHECK(!memcmp(out, ainv, mlen), msg);
  }
  mp_from_mont(&c, r, x); mp_to_be(&c, r, out, mlen);
  snprintf(msg, sizeof msg, "%s: Montgomery round trip", name); CHECK(!memcmp(out, a, mlen), msg);
}

static void ecdsa_case(int i, const uint8_t *hash, const uint8_t *sig, uint16_t siglen)
{
  uint8_t bad[80];
  char msg[64];
  snprintf(msg, sizeof msg, "ecdsa %d verifies", i);
  CHECK(x509_ecdsa_p256_verify(ecdsa_pub, hash, sig, siglen), msg);
  memcpy(bad, sig, siglen); bad[siglen - 1] ^= 1;
  snprintf(msg, sizeof msg, "ecdsa %d: a tampered signature fails", i);
  CHECK(!x509_ecdsa_p256_verify(ecdsa_pub, hash, bad, siglen), msg);
}

int main(void)
{
  uint8_t bad[512], badhash[32];

  mp_case("p256 p", mp_p256p_m, 32, mp_p256p_a, mp_p256p_b, mp_p256p_e, 32, mp_p256p_ab, mp_p256p_ae, mp_p256p_ainv);
  mp_case("p256 n", mp_p256n_m, 32, mp_p256n_a, mp_p256n_b, mp_p256n_e, 32, mp_p256n_ab, mp_p256n_ae, mp_p256n_ainv);
  mp_case("rsa 2048", mp_rsa2048_m, 256, mp_rsa2048_a, mp_rsa2048_b, mp_rsa2048_e, 3, mp_rsa2048_ab, mp_rsa2048_ae, 0);

  /* ECDSA: RFC 6979 A.2.5 (0, 1) and three from OpenSSL (2-4) */
  ecdsa_case(0, ecdsa_hash0, ecdsa_sig0, ecdsa_sig0_len);
  ecdsa_case(1, ecdsa_hash1, ecdsa_sig1, ecdsa_sig1_len);
  ecdsa_case(2, ecdsa_hash2, ecdsa_sig2, ecdsa_sig2_len);
  ecdsa_case(3, ecdsa_hash3, ecdsa_sig3, ecdsa_sig3_len);
  ecdsa_case(4, ecdsa_hash4, ecdsa_sig4, ecdsa_sig4_len);
  memcpy(badhash, ecdsa_hash0, 32); badhash[5] ^= 0x80;
  CHECK(!x509_ecdsa_p256_verify(ecdsa_pub, badhash, ecdsa_sig0, ecdsa_sig0_len), "ecdsa: another hash fails");
  CHECK(!x509_ecdsa_p256_verify(ecdsa_pub, ecdsa_hash1, ecdsa_sig0, ecdsa_sig0_len), "ecdsa: the wrong signature fails");
  memcpy(bad, ecdsa_pub, 64); bad[63] ^= 1;
  CHECK(!x509_ecdsa_p256_verify(bad, ecdsa_hash0, ecdsa_sig0, ecdsa_sig0_len), "ecdsa: a point off the curve fails");
  CHECK(!x509_ecdsa_p256_verify(ecdsa_pub, ecdsa_hash0, ecdsa_sig0, 10), "ecdsa: truncated DER fails");

  /* RSA-PSS */
  CHECK(rsa_pss_verify(pss_rsa2048_n, 256, pss_rsa2048_e, 3, pss_rsa2048_sig, 256, pss_rsa2048_hash), "pss 2048 verifies");
  CHECK(rsa_pss_verify(pss_rsa4096_n, 512, pss_rsa4096_e, 3, pss_rsa4096_sig, 512, pss_rsa4096_hash), "pss 4096 verifies");
  memcpy(bad, pss_rsa2048_sig, 256); bad[100] ^= 1;
  CHECK(!rsa_pss_verify(pss_rsa2048_n, 256, pss_rsa2048_e, 3, bad, 256, pss_rsa2048_hash), "pss: a tampered signature fails");
  memcpy(badhash, pss_rsa2048_hash, 32); badhash[0] ^= 1;
  CHECK(!rsa_pss_verify(pss_rsa2048_n, 256, pss_rsa2048_e, 3, pss_rsa2048_sig, 256, badhash), "pss: another hash fails");
  CHECK(!rsa_pss_verify(pss_rsa2048_n, 256, pss_rsa2048_e, 3, pss_rsa4096_sig, 512, pss_rsa2048_hash), "pss: the wrong length fails");

  printf("%d checks, %d failed\n", checks, failed);
  return failed != 0;
}
