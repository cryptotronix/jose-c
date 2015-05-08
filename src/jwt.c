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

#include <stdio.h>
#include <stdlib.h>
#include <jansson.h>
#include <assert.h>
#include <string.h>
#include <gcrypt.h>
#include "jwt.h"
#include "base64url.h"
#include <libcryptoauth.h>
#include "jws.h"
#include "../libjosec.h"


jwa_t
jwa2enum (const char *str)
{
    assert (NULL != str);

    jwa_t jwa = INVALID;

    if (0 == strcmp (str, "none") || 0 == strcmp (str, "NONE"))
        jwa = NONE;
    else if (0 == strcmp (str, "ES256"))
        jwa = ES256;

    return jwa;
}

char *
jwt_encode(jose_context_t *ctx, const json_t *claims, jwa_t alg)
{

    char *result = NULL;

    assert (ctx);
    assert (claims);


    const char *alg_type;

    switch (alg)
    {
    case ES256:
        alg_type = "ES256";
        break;
    case NONE:
        alg_type = "none";
        break;
    case HS256:
        alg_type = "HS256";
        break;
    default:
        assert (0);
    }

    json_t *head_j = json_object();
    json_object_set_new(head_j, "alg", json_string(alg_type));

    char *signing_input = make_signing_input (head_j, claims);

    if (NONE == alg)
    {
        int new_len = strlen(signing_input) + 2;
        result = malloc (new_len);
        assert (NULL != result);
        memset (result, 0, new_len);

        strcpy (result, signing_input);
        result[strlen(signing_input)] = '.';

    }
    else
    {
        assert (NULL != ctx->sign_func);
        uint8_t *sig;
        size_t sig_len;
        if (ctx->sign_func ((uint8_t *)signing_input, strlen(signing_input),
                            alg, ctx,
                            &sig, &sig_len))
        {
            //failure
        }
        else
        {
            size_t si_len = strlen(signing_input);

            result = jws_append_signing_input (signing_input, si_len,
                                               sig, sig_len);

        }

    }

    json_decref (head_j);
    free (signing_input);

    return result;
}

char *
jwt_encode_old(json_t *claims, jwa_t alg, sign_funcp sfunc)
{
    char *result = NULL;
    size_t sig_len;


    assert (NULL != claims);


    char *alg_type;

    switch (alg)
    {
    case ES256:
        alg_type = "ES256";
        break;
    case NONE:
        alg_type = "none";
        break;
    default:
        assert (0);
    }

    json_t *head_j = json_object();
    json_object_set_new(head_j, "alg", json_string(alg_type));


    char *signing_input = make_signing_input (head_j, claims);



    if (NONE == alg)
    {
        result = malloc (strlen(signing_input) + 2);
        assert (NULL != result);
        strcpy (result, signing_input);
        result[strlen(signing_input)] = '.';

    }
    else
    {
        assert (NULL != sfunc);
        uint8_t *sig;
        if (sfunc ((const uint8_t *)signing_input, strlen(signing_input), alg, NULL,
                   &sig, &sig_len))
        {
            //failure
        }
        else
        {
            size_t si_len = strlen(signing_input);

            result = jws_append_signing_input (signing_input, si_len,
                                               sig, sig_len);

            /* b64sig_len = base64url_encode_alloc (sig, sig_len, &b64sig); */

            /* size_t a; */
            /* char *b; */

            /* a = base64url_decode_alloc (b64sig, b64sig_len, &b); */

            /* size_t jwt_len = si_len + b64sig_len + 1; */

            /* result = malloc (jwt_len); */
            /* assert (NULL != result); */

            /* strcpy (result, signing_input); */
            /* result[si_len] = '.'; */

            /* strncpy (result + si_len + 1, b64sig, b64sig_len); */

            /* free (b64sig); */
        }

    }

    json_decref (head_j);
    free (signing_input);


    return result;
}

char *
make_signing_input (const json_t* header, const json_t* claims)
{
    char *h_str, *c_str, *sign_input = NULL;
    size_t hlen, clen, slen;

    assert (header); assert (claims);

    hlen = json2b64url (header, &h_str);
    clen = json2b64url (claims, &c_str);

    if (hlen == 0 || clen == 0)
        goto OUT;

    slen = hlen + 1 + clen + 1;

    sign_input = (char *) malloc (slen);

    assert (NULL != sign_input);
    memset (sign_input, 0, slen);

    strcpy (sign_input, h_str);
    sign_input[hlen] = '.';

    strcpy (sign_input + hlen + 1, c_str);

OUT:
    free (h_str);
    free (c_str);

    return sign_input;

}
size_t
json2b64url (const json_t *j, char **out)
{
    assert (NULL != j);

    size_t s = 0;
    char *str;

    str = json_dumps(j, 0);

    if (str)
    {
        s = base64url_encode_alloc ((uint8_t *)str, strlen(str), out);

        free (str);
    }

    return s;
}

json_t *
b64url2json (const char *encoded, size_t len)
{
    assert (NULL != encoded);

    char *str;
    size_t d_len;
    json_t *j = NULL;

    json_error_t jerr;

    d_len = base64url_decode_alloc ((const uint8_t *)encoded, len, &str);

    if (d_len <= 0)
        goto OUT;

    j = json_loadb(str, d_len, 0, &jerr);

    if (!j)
        fprintf(stderr, "%s\n", jerr.text);

OUT:
    free (str);

    return j;

}

int
jwt2signinput (const char *jwt, gcry_sexp_t *out)
{
    assert (NULL != jwt);

    char *dot;
    uint8_t *digest;
    int rc = -1;
    int sign_input_len;

    dot = (char *)memrchr (jwt, (int)'.', strlen(jwt));

    if(NULL == dot)
        return rc;

    const unsigned int DLEN = gcry_md_get_algo_dlen (GCRY_MD_SHA256);

    digest = (uint8_t *)malloc (DLEN);
    assert (NULL != digest);

    sign_input_len = dot - jwt;

    gcry_md_hash_buffer (GCRY_MD_SHA256, digest, jwt, sign_input_len);


    rc = gcry_sexp_build (out, NULL,
                          "(data (flags raw)\n"
                          " (value %b))",
                          DLEN, digest);

    free (digest);

    return rc;

}


int
jws2sig (const char* b64urlsig, gcry_sexp_t *sig)
{
    assert (NULL != b64urlsig);
    assert (NULL != sig);

    size_t s_len;
    uint8_t *raw_sig;

    int rc = -1;

    s_len = base64url_decode_alloc ((const uint8_t *)b64urlsig,
                                    strlen (b64urlsig),
                                    (char **)&raw_sig);


    if (s_len <= 0)
        goto OUT;


    /* Currently only support ECDSA P-256 */
    if (s_len != 64)
    {
        rc = -4;
        goto OUT;
    }

    rc = gcry_sexp_build (sig, NULL,
                          "(sig-val(ecdsa(r %b)(s %b)))",
                          32, raw_sig,
                          32, raw_sig + 32);

OUT:
    free (raw_sig);

    return rc;
}

static int
jwt2sig (const char* jwt, gcry_sexp_t *sig)
{
    assert (NULL != jwt);
    assert (NULL != sig);

    char *dot;

    dot = memrchr (jwt, (int)'.', strlen(jwt));

    if (NULL == dot)
        return -1;
    else
        return jws2sig (dot + 1, sig);

}
int
jwk2pubkey (const json_t *jwk, gcry_sexp_t *pubkey)
{
    assert (NULL != jwk);
    assert (NULL != pubkey);

    int rc = -1;
    json_t *j_x = json_object_get(jwk, "x");
    json_t *j_y = json_object_get(jwk, "y");
    uint8_t *x, *y, *q;
    size_t x_len, y_len, q_len;

    if (NULL == j_x || NULL == j_y)
        return rc;

    x_len = base64url_decode_alloc (json_string_value (j_x),
                                    strlen (json_string_value (j_x)),
                                    (char **)&x);

    y_len = base64url_decode_alloc (json_string_value (j_y),
                                    strlen (json_string_value (j_y)),
                                    (char **)&y);

    if (x_len <= 0 || y_len <= 0 || x_len > 256 || y_len > 256)
        goto OUT;

    q_len = x_len + y_len + 1;
    q = (uint8_t *)malloc(q_len);
    assert (NULL != q);

    q[0] = 0x04;

    memcpy (q+1, x, x_len);
    memcpy (q+1+x_len, y, y_len);

    rc = gcry_sexp_build (pubkey, NULL,
                          "(public-key\n"
                          " (ecdsa\n"
                          "  (curve \"NIST P-256\")\n"
                          "  (q %b)"
                          "))", q_len, q);

    free (q);
OUT:
    free (x);
    free (y);


    return rc;

}

int
jwt_verify_sig(jose_context_t *ctx, const char *jwt, jwa_t alg)
{
    assert (ctx);
    assert (jwt);
    assert (ctx->verify_func);

    return ctx->verify_func (jwt, alg, ctx);

}

int
jwt_verify (const json_t *pub_jwk, const char *jwt)
{

    assert (NULL != jwt);

    int rc = -1;
    gcry_sexp_t pubkey, digest, sig;
    json_t *head, *claims, *alg_type;
    const char *alg;

    if ((rc = jwt_split (jwt, &head, &claims)))
        goto OUT;

    if (NULL == (alg_type = json_object_get (head, "alg")))
        goto FREE_JSON;

    if (NULL == (alg = json_string_value (alg_type)))
        goto FREE_JSON;

    if (0 == strcmp ("NONE", alg))
    {
        /* signatures of type none are by definition, always verified */
        rc = 0;
        goto FREE_JSON;
    }
    else if (0 == strcmp ("ES256", alg))
    {
        if (NULL == pub_jwk)
        {
            rc = -4;
            goto FREE_JSON;
        }

        rc = jwk2pubkey (pub_jwk, &pubkey);
        if (rc)
            goto FREE_JSON;

        rc = jwt2signinput (jwt, &digest);
        if (rc)
            goto FREE_PUB;

        rc = jwt2sig (jwt, &sig);
        if (rc)
            goto FREE_DIGEST;

        rc = gcry_pk_verify (sig, digest, pubkey);

        gcry_free (sig);
    FREE_DIGEST:
        gcry_free (digest);
    FREE_PUB:
        gcry_free (pubkey);
    }
    else
    {
        /* unsupported */
        rc = -3;
    }


FREE_JSON:
    json_decref (head);
    json_decref (claims);
OUT:

    return rc;

}

int
jwt_decode (const char *jwt, json_t **header, json_t **claims)
{
    return jwt_split (jwt, header, claims);
}

int
jwt_split (const char *jwt, json_t **header, json_t **claims)
{

    assert (NULL != jwt);

    char *dot;
    char *dot_2;
    int rc = -1;
    const size_t j_len = strlen (jwt);

    dot = memchr (jwt, (int)'.', j_len);

    if(NULL == dot)
        return rc;

    if (NULL == (*header = b64url2json (jwt, dot - jwt)))
        return -5;

    if (NULL == (dot_2 = memrchr (jwt, (int)'.', j_len)))
    {
        json_decref (*header);
        return -3;
    }

    if (NULL == (*claims = b64url2json (dot + 1, dot_2 - dot - 1)))
    {
        json_decref (*header);
        return -6;
    }

    rc = 0;

    return rc;


}
