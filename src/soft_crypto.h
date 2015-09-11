#ifndef JOSECSOFT_CRYPTO_H_
#define JOSECSOFT_CRYPTO_H_

#include "../libjosec.h"
#include <stdint.h>
#include <stddef.h>

#define JOSE_SHA256_LEN 32

int
jose_soft_sign(const uint8_t *signing_input, size_t si_len,
               jwa_t alg, jose_context_t *ctx,
               uint8_t **out, size_t *out_len);

int
jose_soft_verify(const char *jwt, jwa_t alg, jose_context_t *ctx);

void
jose_hmac_256 (const uint8_t *key, size_t key_len,
               const uint8_t *data, size_t data_len,
               uint8_t *mac);

void
jose_sha256 (const uint8_t *in, size_t len, uint8_t *out);

#endif
