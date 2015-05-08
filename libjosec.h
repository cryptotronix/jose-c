/* -*- mode: c; c-file-style: "gnu" -*-
 * Copyright (C) 2015 Cryptotronix, LLC.
 *
 * This file is part of libjose-c.
 *
 * libjose-c is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * any later version.
 *
 * libjose-c is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with libjose-c.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#ifndef LIBJOSEC_H_
#define LIBJOSEC_H_

//This is a main header - it includes everything else.

#include <jansson.h>
#include <stdint.h>

typedef enum
  {
    INVALID,
    ES256,
    HS256,
    NONE,
    JWA_MAX
  } jwa_t;



typedef struct jose_context_t jct;

/* Sign function pointer
   const uint8_t *data_to_sign,
   size_t dlen,
   jwa_t alg,
   jose_context_t *cookie,
   uint8_t **out,
   size_t *out_len

*/
typedef int (*sign_funcp)(const uint8_t *, size_t len,
                          jwa_t, const jct *,
                          uint8_t **, size_t *);

typedef int (*verify_funcp)(const char *,
                            jwa_t, const jct *);


typedef struct
{
  jwa_t alg_type;
  uint8_t *key;
  unsigned int k_len;
} jose_key_t;

typedef struct
{
  sign_funcp sign_func;
  verify_funcp verify_func;
  jose_key_t key_container[JWA_MAX];
  void *cookie;
} jose_context_t;


int
jose_create_context (jose_context_t *ctx, sign_funcp sf, verify_funcp vf,
                     void *cookie);

int
jose_add_key (jose_context_t *ctx, jose_key_t key);

void
jose_close_context (jose_context_t *ctx);

char *
jwt_encode(jose_context_t *ctx, const json_t *claims, jwa_t alg);

int
jwt_verify_sig(jose_context_t *ctx, const char *jwt, jwa_t alg);

int
jwt_decode (const char *jwt, json_t **header, json_t **claims);



#endif // LIBCRYPTOAUTH_H_
