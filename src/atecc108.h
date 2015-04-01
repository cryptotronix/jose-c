#ifndef ATECC108_H_
#define ATECC108_H_

#include <gcrypt.h>

int
ecc108_sign (const uint8_t *to_sign, size_t len,
             jwa_t alg, void *cookie,
             uint8_t **out, size_t *out_len);

#endif
