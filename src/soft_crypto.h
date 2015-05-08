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
