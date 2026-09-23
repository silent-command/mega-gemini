/* What the TLS engine asks of the cryptography, and nothing else: the
 * line between the client (tls.c, framing and parsing) and the bank
 * (the keys, the hashes, the ciphers, the verifiers). On the host
 * tlskit_host.c answers with the C in src/crypto; on the MEGA65 the
 * client's kit calls the bank through its trampoline, and no key ever
 * leaves the bank. One connection at a time. */
#ifndef TLSKIT_H
#define TLSKIT_H

#include <stdint.h>

/* random bytes, for the ClientHello */
void tk_random(uint8_t *out, uint8_t n);

/* the transcript hash: started, fed, and read without ending */
void tk_transcript_init(void);
void tk_transcript_update(const uint8_t *p, uint16_t n);
void tk_transcript_hash(uint8_t out[32]);

/* a fresh X25519 pair; the private key stays inside */
void tk_keyshare(uint8_t pub[32]);
/* the handshake secrets from the peer's share and hash(CH, SH); the
 * handshake traffic keys installed for reading and writing, sequence 0 */
void tk_keys_handshake(const uint8_t peer_pub[32], const uint8_t hash[32]);
#ifdef TLS_P256
/* the same two steps on P-256, for a server that will not take x25519
 * and says so with a HelloRetryRequest (OFTC, mega-irc 5.12): a fresh
 * pair, 65 bytes uncompressed (04, X, Y), the private key staying
 * inside; then the handshake secrets from the peer's 65-byte share.
 * The second returns 0 if the peer's point is not on the curve. */
void tk_keyshare_p256(uint8_t pub[65]);
uint8_t tk_keys_handshake_p256(const uint8_t peer_pub[65], const uint8_t hash[32]);
#endif
/* the application secrets from hash(CH..SFin); nothing switches yet */
void tk_keys_master(const uint8_t hash[32]);
/* writing switches to the application keys (after the client's Finished
 * is sealed); reading, after the server's Finished record has ended */
void tk_write_switch(void);
void tk_read_switch(void);
/* verify_data under the server's (1) or the client's (0) handshake secret */
void tk_finished(uint8_t server, const uint8_t hash[32], uint8_t out[32]);

/* rec: a 5-byte header (type, version; the length is written here)
 * followed by `len` bytes of plaintext ending in the inner type;
 * encrypted in place and the tag appended, so rec needs len + 21 bytes */
void tk_seal(uint8_t *rec, uint16_t len);
/* a record being read: the header (as AAD), the ciphertext in pieces
 * decrypted in place, then the tag; returns 1 if it matched */
void tk_open_start(const uint8_t hdr[5]);
void tk_open_data(uint8_t *p, uint16_t n);
uint8_t tk_open_check(const uint8_t tag[16]);

/* the server's certificates, kept by the kit as they stream in: the leaf
 * first, then the rest of the chain end to end, as far as the store holds */
void tk_cert_reset(void);
void tk_cert_append(const uint8_t *p, uint16_t n);
uint16_t tk_cert_len(void);
/* bytes of that store, for a chain verifier; zero past the end */
void tk_cert_read(uint16_t off, uint8_t *dst, uint16_t n);
/* the signature over the transcript before CertificateVerify */
#define TK_WRONG 0
#define TK_VERIFIED 1
#define TK_UNCHECKED 2         /* a scheme this kit cannot verify */
uint8_t tk_verify(uint16_t scheme, const uint8_t hash[32], const uint8_t *sig, uint16_t siglen);
/* the key's pin: SHA-256 of the SubjectPublicKeyInfo; 0 if the certificate cannot be read */
uint8_t tk_pin(uint8_t out[32]);

#endif
