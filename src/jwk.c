#include <stdio.h>
#include <stdlib.h>
#include <jansson.h>
#include <assert.h>
#include <string.h>
#include "jwk.h"
#include "base64url.h"

static json_t*
build_ec_jwk (const char *x, const char *y, const char *d, const char *use,
              const char *kid)
{
    assert (NULL != x);
    assert (NULL != y);

    json_t *jwk = json_object();

    if (!jwk)
        return NULL;

    if (json_object_set_new(jwk, "kty", json_string("EC")))
    {
        goto FAIL;
    }
    if (json_object_set_new(jwk, "crv", json_string("P-256")))
    {
        goto FAIL;
    }
    if (json_object_set_new(jwk, "x", json_string(x)))
    {
        goto FAIL;
    }
    if (json_object_set_new(jwk, "y", json_string(y)))
    {
        goto FAIL;
    }
    if (use)
    {
        if (json_object_set_new(jwk, "use", json_string(use)))
        {
            goto FAIL;
        }
    }
    if (kid)
    {
        if (json_object_set_new(jwk, "kid", json_string(kid)))
        {
            goto FAIL;
        }
    }
    if (d)
    {
        if (json_object_set_new(jwk, "d", json_string(d)))
        {
            goto FAIL;
        }
    }

    goto OUT;

FAIL:
    json_decref (jwk);
    jwk = NULL;
OUT:
    return jwk;
}

static json_t *
raw_pubkey2jwk (uint8_t *q, size_t q_len)
{
    uint8_t *x, *y;
    char *x_b64, *y_b64;
    const int COORD_LEN = 32;
    size_t x_b64_len, y_b64_len;
    json_t *jwk = NULL;

    if (65 != q_len) /* Only P-256 ECDSA */
        goto OUT;


    x = q + 1; /* skips the uncompressed tag */
    y = q + 1 + COORD_LEN;


    if (0 == (x_b64_len = base64url_encode_alloc (x, COORD_LEN, &x_b64)))
        goto FREE_X;

    if (0 == (y_b64_len = base64url_encode_alloc (y, COORD_LEN, &y_b64)))
        goto FREE_Y;

    /* for now ... set to one */
    jwk = build_ec_jwk (x_b64, y_b64, NULL, "sig", "1");

FREE_Y:
    free (y_b64);
FREE_X:
    free (x_b64);
OUT:
    return jwk;

}

json_t *
jc_eckey2jwk (const uint8_t *x, size_t xlen, const uint8_t *y, size_t ylen,
              const uint8_t *d, size_t dlen, const char *curve,
              const char *use, const char* kid)
{
    char *x_b64 = NULL;
    char *y_b64 = NULL;
    char *d_b64 = NULL;
    size_t x_b64_len, y_b64_len, d_b64_len;
    json_t *jwk = NULL;
    const int COORD_LEN = 32;

    assert (x);
    assert (y);

    assert (curve);
    /* P-256 only supported */
    assert (strcmp ("P-256", curve) == 0);

    if (0 == (x_b64_len = base64url_encode_alloc (x, COORD_LEN, &x_b64)))
        goto FREE_X;

    if (0 == (y_b64_len = base64url_encode_alloc (y, COORD_LEN, &y_b64)))
        goto FREE_Y;

    if (d)
        if (0 == (d_b64_len = base64url_encode_alloc (d, COORD_LEN, &d_b64)))
            goto FREE_D;

    jwk = build_ec_jwk (x_b64, y_b64, d_b64, use, kid);

FREE_D:
    if (d)
        free (d_b64);
FREE_Y:
    free (y_b64);
FREE_X:
    free (x_b64);
OUT:
    return jwk;

}
