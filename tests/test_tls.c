/* The host suite for src/tls/: the key schedule against RFC 8448
 * section 3, message by message. */
#include <stdio.h>
#include <string.h>
#include "crypto.h"
#include "hkdf.h"
#include "tls/keys.h"
#include "../tests/vectors.h"

static int checks, failed;
#define CHECK(cond, what) do { checks++; if (!(cond)) { failed++; printf("FAIL line %d: %s\n", __LINE__, what); } } while (0)
#define V(name) rfc8448_##name

int main(void)
{
  tls_schedule s;
  sha256_ctx tr;
  uint8_t hash[32], ecdhe[32], out[32], nonce[12];
  tls_traffic t;

  /* the exchange: the client's private key against the server's public */
  x25519_base(out, V(client_create_an_ephemeral_x25519_key_pair_private_key));
  CHECK(!memcmp(out, V(client_create_an_ephemeral_x25519_key_pair_public_key), 32), "client key share");
  x25519(ecdhe, V(client_create_an_ephemeral_x25519_key_pair_private_key), V(server_create_an_ephemeral_x25519_key_pair_public_key));
  CHECK(!memcmp(ecdhe, V(server_extract_secret_handshake_ikm), 32), "ECDHE shared secret");

  tls_schedule_start(&s);
  CHECK(!memcmp(s.early, V(server_extract_secret_early_secret), 32), "early secret");

  /* transcript: ClientHello, ServerHello */
  sha256_init(&tr);
  sha256_update(&tr, V(client_construct_a_clienthello_handshake_message_clienthello), V(client_construct_a_clienthello_handshake_message_clienthello_len));
  sha256_update(&tr, V(server_construct_a_serverhello_handshake_message_serverhello), V(server_construct_a_serverhello_handshake_message_serverhello_len));
  { sha256_ctx c = tr; sha256_final(&c, hash); }
  CHECK(!memcmp(hash, V(server_derive_secret_tls13_c_hs_traffic_hash), 32), "hash(CH, SH)");
  tls_schedule_handshake(&s, ecdhe, hash);
  CHECK(!memcmp(s.handshake, V(server_extract_secret_handshake_secret), 32), "handshake secret");
  CHECK(!memcmp(s.c_hs, V(server_derive_secret_tls13_c_hs_traffic_expanded), 32), "client handshake traffic secret");
  CHECK(!memcmp(s.s_hs, V(server_derive_secret_tls13_s_hs_traffic_expanded), 32), "server handshake traffic secret");

  /* traffic keys: the RFC's suite is AES-128-GCM, so its key is 16 bytes;
   * the same expansion at 16 must match, and the IV at 12 */
  tls_expand_label(s.s_hs, "key", 0, 0, out, 16);
  CHECK(!memcmp(out, V(server_derive_write_traffic_keys_for_handshake_data_key_expanded), 16), "server handshake key (16)");
  tls_traffic_keys(s.s_hs, &t);
  CHECK(!memcmp(t.iv, V(server_derive_write_traffic_keys_for_handshake_data_iv_expanded), 12), "server handshake iv");
  tls_nonce(&t, 0, 0, nonce);
  CHECK(!memcmp(nonce, t.iv, 12), "nonce 0 is the iv");
  tls_nonce(&t, 0, 1, nonce);
  CHECK(nonce[11] == (t.iv[11] ^ 1) && !memcmp(nonce, t.iv, 11), "nonce 1");
  tls_nonce(&t, 1, 0, nonce);
  CHECK(nonce[7] == (t.iv[7] ^ 1) && nonce[11] == t.iv[11], "nonce 2^32");

  /* transcript on: EncryptedExtensions, Certificate, CertificateVerify; the server Finished */
  sha256_update(&tr, V(server_construct_an_encryptedextensions_handshake_message_encryptedextensions), V(server_construct_an_encryptedextensions_handshake_message_encryptedextensions_len));
  sha256_update(&tr, V(server_construct_a_certificate_handshake_message_certificate), V(server_construct_a_certificate_handshake_message_certificate_len));
  sha256_update(&tr, V(server_construct_a_certificateverify_handshake_message_certificateverify), V(server_construct_a_certificateverify_handshake_message_certificateverify_len));
  { sha256_ctx c = tr; sha256_final(&c, hash); }
  tls_finished(s.s_hs, hash, out);
  CHECK(!memcmp(out, V(server_calculate_finished_tls13_finished_finished), 32), "server Finished verify_data");
  CHECK(V(server_construct_a_finished_handshake_message_finished)[0] == 0x14 && !memcmp(V(server_construct_a_finished_handshake_message_finished) + 4, out, 32), "server Finished message body");

  /* master: through the server Finished */
  sha256_update(&tr, V(server_construct_a_finished_handshake_message_finished), V(server_construct_a_finished_handshake_message_finished_len));
  { sha256_ctx c = tr; sha256_final(&c, hash); }
  CHECK(!memcmp(hash, V(server_derive_secret_tls13_c_ap_traffic_hash), 32), "hash(CH..SFin)");
  tls_schedule_master(&s, hash);
  CHECK(!memcmp(s.master, V(server_extract_secret_master_secret), 32), "master secret");
  CHECK(!memcmp(s.c_ap, V(server_derive_secret_tls13_c_ap_traffic_expanded), 32), "client application traffic secret");
  CHECK(!memcmp(s.s_ap, V(server_derive_secret_tls13_s_ap_traffic_expanded), 32), "server application traffic secret");
  tls_traffic_keys(s.s_ap, &t);
  CHECK(!memcmp(t.iv, V(server_derive_write_traffic_keys_for_application_data_iv_expanded), 12), "server application iv");

  /* the client's Finished: over the same transcript, with its own handshake secret */
  tls_finished(s.c_hs, hash, out);
  CHECK(!memcmp(out, V(client_calculate_finished_tls13_finished_finished), 32), "client Finished verify_data");

  printf("%d checks, %d failed\n", checks, failed);
  return failed != 0;
}
