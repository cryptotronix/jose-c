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

#ifndef JOSECHS264_H_
#define JOSECHS264_H_

#include "jwt.h"

uint8_t *
hs256_soft_hmac (const char *signing_input, int si_len,
                 const uint8_t *key, int k_len);

char *
hs256_encode(const char *signing_input, int si_len,
             const uint8_t *key, int k_len,
             sign_funcp sfunc);

int
hs256_soft_verify (const char *jwt, const uint8_t *key, int k_len);

#endif
