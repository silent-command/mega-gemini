/* What this client needs from a server's X.509 certificate: its public
 * key, and the SubjectPublicKeyInfo to pin. The certificate is read
 * through a hook by byte range, so it can sit anywhere. No chain, no
 * names, no dates: trust is on first use, by the key (REQUIREMENTS.md 2).
 * The signature verifiers for CertificateVerify live here too. */
#ifndef X509_H
#define X509_H

#include <stdint.h>

typedef void (*x509_read)(void *ctx, uint16_t off, uint8_t *dst, uint16_t n);

#define X509_KEY_NONE 0
#define X509_KEY_P256 1
#define X509_KEY_ED25519 2
#define X509_KEY_RSA 3

typedef struct {
  uint8_t kind;
  uint16_t spki_off, spki_len;   /* the SubjectPublicKeyInfo, tag and all */
  uint8_t p256[64];              /* X then Y, when P-256 */
  uint8_t ed25519[32];
  uint16_t n_off, n_len;         /* the RSA modulus and exponent, in the certificate, leading zeros dropped */
  uint16_t e_off, e_len;
} x509_key;

/* Finds the key in a DER certificate of `len` bytes. Returns 0 if the
 * certificate cannot be walked or the key is of no kind known here
 * (kind is then X509_KEY_NONE but spki may still be set, for pinning). */
uint8_t x509_key_of(x509_read read, void *ctx, uint16_t len, x509_key *key);

/* SHA-256 of the SubjectPublicKeyInfo: the pin. */
void x509_spki_hash(x509_read read, void *ctx, const x509_key *key, uint8_t out[32]);

/* ECDSA over P-256 with a SHA-256 digest; the signature DER-encoded (r, s). 1 if valid. */
uint8_t x509_ecdsa_p256_verify(const uint8_t pub[64], const uint8_t hash[32], const uint8_t *sig, uint16_t siglen);
/* RSASSA-PSS with SHA-256 and MGF1-SHA256, salt length 32 (rsa_pss_rsae_sha256). 1 if valid. */
uint8_t x509_rsa_pss_verify(x509_read read, void *ctx, const x509_key *key, const uint8_t hash[32], const uint8_t *sig, uint16_t siglen);

/* 1 if this client can verify signatures of `scheme` (a TLS SignatureScheme). */
uint8_t x509_scheme_supported(uint16_t scheme);

#endif
