/* ECDSA verification over NIST P-256 (secp256r1) with a SHA-256 digest,
 * over mp.h: Jacobian coordinates in Montgomery form, Shamir's trick for
 * the two scalar multiplications. Verification only; this client never
 * signs. C99; host-tested against RFC 6979 and generated signatures. */
#ifndef P256_H
#define P256_H

#include <stdint.h>

/* pub: X then Y, 32 bytes each; sig: r then s, 32 bytes each (already
 * out of DER). 1 if the signature is valid. */
uint8_t p256_verify(const uint8_t pub[64], const uint8_t hash[32], const uint8_t r[32], const uint8_t s[32]);

#ifdef TLS_P256
/* Key agreement on the same curve, for a server that will not take
 * x25519 (OFTC: mega-irc 5.12). Compiled only where TLS_P256 is defined;
 * this client never needs it. pub is X then Y; priv is 32 bytes reduced
 * into [1, n-1]. Both return 0 for a zero scalar, a point off the curve,
 * or a result at infinity. */
uint8_t p256_keygen(uint8_t pub[64], const uint8_t priv[32]);
uint8_t p256_ecdh(uint8_t out[32], const uint8_t priv[32], const uint8_t peer[64]);
#endif

#endif
