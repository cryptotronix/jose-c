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
#include "jws.h"
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <gcrypt.h>
#include "base64url.h"

char *
jws_append_signing_input (const char* si, int si_len,
                          const uint8_t *sig, int sig_len)
{
    char *b64sig;
    size_t b64sig_len;
    char *result;

    assert (si);
    assert (sig);

    b64sig_len = base64url_encode_alloc (sig, sig_len, &b64sig);

    size_t jwt_len = si_len + b64sig_len + 2;

    result = malloc (jwt_len);
    memset (result, 0, jwt_len);
    assert (result);

    strncpy (result, si, si_len);

    result[si_len] = '.';

    strncpy (result + si_len + 1, b64sig, b64sig_len);

    free (b64sig);

    return result;
}

char *
jws2signing_input (const char *jwt)
{
    assert (NULL != jwt);

    char *dot;
    int sign_input_len;
    char *si;

    dot = (char *)memrchr (jwt, (int)'.', strlen(jwt));

    if(NULL == dot)
        return NULL;

    sign_input_len = dot - jwt + 1;

    si = malloc(sign_input_len);
    memset (si, 0, sign_input_len);

    memcpy(si, jwt, dot - jwt);

    return si;
}
