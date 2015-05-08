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

#include "config.h"
#include "soft_crypto.h"
#include <assert.h>
#include "hs256.h"
#include <syslog.h>

int
jose_soft_sign(const uint8_t *signing_input, size_t si_len,
               jwa_t alg, jose_context_t *ctx,
               uint8_t **out, size_t *out_len)
{
  assert (signing_input);
  assert (ctx);
  int rc = -1;

  if (alg == HS256)
    {
      uint8_t *key;
      size_t k_len;

      assert (ctx->key_container[HS256].key);
      key = ctx->key_container[HS256].key;
      k_len = ctx->key_container[HS256].k_len;

      uint8_t *mac = hs256_soft_hmac((const char *)signing_input,
                                     si_len, key, k_len);
      *out = mac;
      *out_len = 32;
      rc = 0;
    }

  return rc;

}

int
jose_soft_verify(const char *jwt, jwa_t alg, jose_context_t *ctx)
{

  assert (jwt);
  assert (ctx);
  int rc = -1;

  if (alg == HS256)
    {
      uint8_t *key;
      size_t k_len;

      assert (ctx->key_container[HS256].key);
      key = ctx->key_container[HS256].key;
      k_len = ctx->key_container[HS256].k_len;

      rc = hs256_soft_verify (jwt, key, k_len);

    }
  else if (alg == NONE)
    {
      /* check to see if alg is really set to none */
      json_t *h, *c;
      rc = jwt_decode (jwt, &h, &c);
      if (rc == 0)
        {
          const char *field = "alg";
          json_t *alg_type = json_object_get(h, field);
          if (alg_type)
            {
              rc = strncmp (json_string_value (alg_type), "none", strlen("none"));
            }
          else
            rc = -2;

          json_decref (h);
          json_decref (c);
        }
      else
        {
          syslog (LOG_DEBUG, "JOSEC: Falied to decoded JWT");
        }

    }

  return rc;

}
