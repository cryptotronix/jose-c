#ifndef JOSECJWK_H_
#define JOSECJWK_H_

#include "config.h"
#include <stdint.h>
#include <unistd.h>
#include <jansson.h>

json_t *
jc_eckey2jwk (const uint8_t *x, size_t xlen, const uint8_t *y, size_t ylen,
              const uint8_t *d, size_t dlen, const char *curve,
              const char *use, const char* kid);

#endif
