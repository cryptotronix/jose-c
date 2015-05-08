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

#ifndef b64_h
#define b64_h

#include "config.h"
#include <stddef.h>
#include <stdint.h>
#include <base64.h>

// length of data resulting from encoding/decoding
#define base64_encode_length(x) (8 * (((x) + 2) / 6)) + 1
#define base64_decode_length(x) ((((x) + 2) * 6) / 8)

// Encode and malloc out
size_t
base64url_encode_alloc (const uint8_t *data, size_t len, char **out);

size_t
base64url_decode_alloc (const uint8_t *data, size_t len, char **out);

#endif
