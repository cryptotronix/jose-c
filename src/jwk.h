#ifndef JOSECJWK_H_
#define JOSECJWK_H_

#include "config.h"
#include <stdint.h>
#include <unistd.h>
#include <jansson.h>
#include <yacl.h>

json_t *
jc_eckey2jwk (const uint8_t *x, size_t xlen, const uint8_t *y, size_t ylen,
              const uint8_t *d, size_t dlen, const char *curve,
              const char *use, const char* kid);

int
jwk2rawpub (const json_t *jwk, uint8_t pub[YACL_P256_COORD_SIZE*2]);

int
jwk_ecdsa_sign_raw (const uint8_t *data, size_t data_len,
                    const json_t *private_jwk,
                    uint8_t raw_sig[YACL_P256_COORD_SIZE*2]);

int
es256_soft_verify (const char *jwt, const json_t *jwk);

#endif
