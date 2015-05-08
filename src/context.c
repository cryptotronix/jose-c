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
#include "../libjosec.h"
#include <assert.h>
#include "soft_crypto.h"

int
jose_create_context (jose_context_t *ctx, sign_funcp sf, verify_funcp vf,
                     void *cookie)
{
  int x;

  assert (ctx);

  if (NULL == sf)
    ctx->sign_func = jose_soft_sign;
  else
    ctx->sign_func = sf;

  if (NULL == vf)
    {
      ctx->verify_func = jose_soft_verify;
    }
  else
    ctx->verify_func = vf;

  ctx->cookie = cookie;

  for (x = 0; x < JWA_MAX; x++)
    {
      ctx->key_container[x].key = NULL;
      ctx->key_container[x].alg_type = NONE;
    }

  return 0;

}


int
jose_add_key (jose_context_t *ctx, jose_key_t key)
{
  assert (ctx);

  ctx->key_container[key.alg_type] = key;


  return 0;
}

void
jose_close_context (jose_context_t *ctx)
{

}
