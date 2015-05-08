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

#include "base64url.h"
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <base64.h>
#include <stdlib.h>

size_t
base64url_encode_alloc (const uint8_t *data, size_t len, char **out)
{
  size_t i;

  assert(NULL != data);
  assert(NULL != out);

  size_t s = base64_encode_alloc (data, len, out);

  char *burl = *out;

  for (i = 0; i < s; i++)
    {
      if ('+' == *(burl+i))
        *(burl+i) = '-';
      else if ('/' == *(burl+i))
        *(burl+i) = '_';
      else if ('=' == *(burl+i))
        *(burl+i) = 0;
    }

  return strnlen (burl, s);
}


size_t
base64url_decode_alloc (const uint8_t *data, size_t l, char **out)
{
  size_t i, s, pad;
  char *burl;
  size_t len;

  assert(NULL != data);

  len = strnlen ((const char *)data, l);

  pad = len + (4 - len % 4) % 4;

  assert (pad >= len);

  burl = malloc (pad + 1);
  assert (NULL != burl);
  memset (burl, 0, pad + 1);

  strncpy (burl, (const char *)data, len);

  for (i = 0; i < len; i++)
    {
      if ('-' == *(burl+i))
        *(burl+i) = '+';
      else if ('_' == *(burl+i))
        *(burl+i) = '/';
    }

  for (i = 0; i < (pad - len); i++)
    {
      burl[len + i] = '=';
    }

  if (!base64_decode_alloc (burl, pad, out, &s))
    {
      s = -1;
    }

  free (burl);

  return s;
}
