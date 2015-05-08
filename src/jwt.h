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

#ifndef JOSECJWT_H_
#define JOSECJWT_H_

#include <stdint.h>
#include <jansson.h>
#include <gcrypt.h>
#include "jwa.h"
#include "../libjosec.h"

char *
jwt_encode_old(json_t *claims, jwa_t alg, sign_funcp sfunc);

json_t *
b64url2json (const char *encoded, size_t len);

size_t
json2b64url (const json_t *j, char **out);

int
jwk2pubkey (const json_t *jwk, gcry_sexp_t *pubkey);

int
jws2sig (const char* b64urlsig, gcry_sexp_t *sig);

int
jwt2signinput (const char *jwt, gcry_sexp_t *out);

int
jwt_verify (const json_t *pub_jwk, const char *jwt);

char *
make_signing_input (const json_t* header, const json_t* claims);

int
jwt_split (const char *jwt, json_t **header, json_t **claims);

#endif // LIBJOSECJWT_H_
