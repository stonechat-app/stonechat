// Bridging header: the stonechat-core C ABI (repo /core, src/ffi.rs) —
// the same static library the app links. Return codes: 0 ok, -1 bad
// input, -2 panic, -3 crypto refusal (normal; state unchanged). Buffers
// written to (*out_ptr, *out_len) must be released with stonechat_free.
#ifndef StonechatCore_h
#define StonechatCore_h

#include <stddef.h>
#include <stdint.h>

uint32_t stonechat_core_abi_version(void);
void stonechat_free(uint8_t *ptr, size_t len);

// state-in/state-out; JSON bytes in, JSON bytes out.
int32_t stonechat_session_decrypt(
    const uint8_t *state_json, size_t state_len,
    const uint8_t *header_json, size_t header_len,
    const uint8_t *nonce,                       // 24 bytes
    const uint8_t *ciphertext, size_t ciphertext_len,
    const uint8_t *ad, size_t ad_len,
    const uint8_t *fresh_ratchet_sk,            // 32 bytes CSPRNG
    const uint8_t *pq_random,                   // 64 bytes CSPRNG, independent
    uint8_t **out_ptr, size_t *out_len);        // {"state":…,"plaintext":"<b64>"}

// Takes the FULL 64-byte libsodium secret key, as crypto.dart does.
int32_t stonechat_pq_seed_from_ed_secret(const uint8_t *ed_secret, // 64 bytes
                                         uint8_t *pq_seed_out);    // 32 bytes

int32_t stonechat_unseal(const uint8_t *pq_seed,                 // 32 bytes
                         const uint8_t *sealed, size_t sealed_len,
                         uint8_t **out_ptr, size_t *out_len);

int32_t stonechat_tls_fingerprint(const uint8_t *cert_der, size_t der_len,
                                  uint8_t *fp_out);              // 32 bytes

#endif
