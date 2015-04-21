#ifndef JOSECSOFT_CRYPTO_H_
#define JOSECSOFT_CRYPTO_H_

#include "../libjosec.h"
#include <stdint.h>
#include <stddef.h>

int
jose_soft_sign(const uint8_t *signing_input, size_t si_len,
               jwa_t alg, jose_context_t *ctx,
               uint8_t **out, size_t *out_len);

int
jose_soft_verify(const char *jwt, jwa_t alg, jose_context_t *ctx);



#endif
