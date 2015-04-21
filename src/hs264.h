#ifndef JOSECHS264_H_
#define JOSECHS264_H_

#include "jwt.h"

uint8_t *
hs264_soft_hmac (const char *signing_input, int si_len,
                 const uint8_t *key, int k_len);

char *
hs264_encode(const char *signing_input, int si_len,
             const uint8_t *key, int k_len,
             sign_funcp sfunc);

int
hs256_soft_verify (const char *jwt, const uint8_t *key, int k_len);

#endif
