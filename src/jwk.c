#include <stdio.h>
#include <stdlib.h>
#include <jansson.h>
#include <assert.h>
#include <string.h>
#include "jwk.h"
#include "base64url.h"
#include <yacl.h>
#include "../libjosec.h"

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

int
b64url_decode_helper (const char *to_dec, uint8_t *decoded, size_t len)
{
    assert (to_dec);
    size_t dec_len;
    uint8_t *out;
    int rc = -1;

    dec_len = base64url_decode_alloc ((uint8_t *)to_dec, strlen (to_dec),
                                      (char **) &out);

    if (0 == dec_len)
        return rc;

    if (dec_len != len)
    {
        free (out);
        return dec_len;
    }

    memcpy (decoded, out, len);

    memset (out, 0, len);
    free (out);

    rc = 0;

    return rc;
}

int
jwk2rawpub (const json_t *jwk, uint8_t pub[YACL_P256_COORD_SIZE*2])
{
    assert (jwk);
    int rc = -1;

    json_t *x_j = json_object_get (jwk, "x");
    json_t *y_j = json_object_get (jwk, "y");

    if (NULL == x_j || NULL == y_j)
        return rc;

    const char *x_s = json_string_value (x_j);
    const char *y_s = json_string_value (y_j);

    if (NULL == x_s || NULL == y_s)
        return -2;

    rc = b64url_decode_helper(x_s, pub, YACL_P256_COORD_SIZE);
    if (rc) return rc;

    rc = b64url_decode_helper(y_s, pub + YACL_P256_COORD_SIZE,
                              YACL_P256_COORD_SIZE);

    return rc;

}

int
jwk_ecdsa_sign_raw (const uint8_t *data, size_t data_len,
                    const json_t *private_jwk,
                    uint8_t raw_sig[YACL_P256_COORD_SIZE*2])
{
    assert (data); assert (private_jwk);

    int rc = -1;
    uint8_t raw_private_key[YACL_P256_COORD_SIZE];
    json_t *d = json_object_get (private_jwk, "d");
    assert (d);

    rc = b64url_decode_helper (json_string_value (d), raw_private_key,
                               YACL_P256_COORD_SIZE);

    if (rc) return rc;

    rc = yacl_hash_ecdsa_sign(data, data_len,
                              raw_private_key,
                              raw_sig);

    return rc;
}

int
jwk_ecdsa_sign (const uint8_t *data, size_t data_len,
                const json_t *private_jwk,
                const char **b64urlsig)
{
    assert (data); assert (private_jwk); assert (b64urlsig);

    int rc = -1;
    uint8_t raw_sig[YACL_P256_COORD_SIZE*2];

    rc = jwk_ecdsa_sign_raw(data, data_len, private_jwk, raw_sig);
    if (rc) return rc;

    size_t encode_len;
    encode_len = base64url_encode_alloc (raw_sig, sizeof(raw_sig),
                                         (char **)b64urlsig);

    if (encode_len > 0)
        return 0;
    else
        return -2;

}

int
jwk_ecdsa_verify (const uint8_t *data, size_t data_len,
                  const char *b64urlsig,
                  const json_t *public_jwk)
{
    assert (data); assert (b64urlsig); assert (public_jwk);
    int rc = -1;
    uint8_t raw_pub[YACL_P256_COORD_SIZE*2];
    uint8_t raw_sig[YACL_P256_COORD_SIZE*2];

    rc = jwk2rawpub (public_jwk, raw_pub);
    if (rc) return rc;

    rc = b64url_decode_helper (b64urlsig, raw_sig, sizeof(raw_sig));
    if (rc) return rc;

    rc = yacl_hash_verify(data, data_len, raw_pub, raw_sig);

    return rc;
}

int
es256_soft_verify (const char *jwt, const json_t *jwk)
{
    assert (jwk);

    int rc = -1;
    char *dot, *sig;

    char *si = jws2signing_input (jwt);
    assert (si);

    dot = (char *)memrchr (jwt, (int)'.', strlen(jwt));

    if(NULL == dot)
        return rc;

    sig = dot + 1;

    rc = jwk_ecdsa_verify (si, strlen(si), sig, jwk);

    free (si);

    return rc;

}

json_t *
jwk_create_p256_key_pair (void)
{
    int rc;
    uint8_t public_key[YACL_P256_COORD_SIZE*2];
    uint8_t private_key[YACL_P256_COORD_SIZE];
    size_t xb64len, yb64len, db64len;
    char *x, *y, *d;
    json_t *jwk;

    rc = yacl_create_key_pair(public_key, private_key);

    if (rc) return NULL;

    xb64len = base64url_encode_alloc (public_key, YACL_P256_COORD_SIZE, &x);
    assert (xb64len);

    yb64len = base64url_encode_alloc (public_key + YACL_P256_COORD_SIZE,
                                      YACL_P256_COORD_SIZE, &y);
    assert  (yb64len);

    db64len = base64url_encode_alloc (private_key, YACL_P256_COORD_SIZE, &d);
    assert (db64len);

    jwk = json_object();
    assert (jwk);


    assert (0 == json_object_set_new (jwk, "x", json_string (x)));
    assert (0 == json_object_set_new (jwk, "y", json_string (y)));
    assert (0 == json_object_set_new (jwk, "d", json_string (d)));

    assert (0 == json_object_set_new (jwk, "kty", json_string ("EC")));
    assert (0 == json_object_set_new (jwk, "crv", json_string ("P-256")));


    free (x);
    free (y);
    memset (d, 0, db64len);
    free (d);

    return jwk;

}


json_t *
jwk_create_es256_key_pair (void)
{
    json_t *jwk = jwk_create_p256_key_pair();

    if (NULL == jwk) return NULL;

    assert (0 == json_object_set_new (jwk, "alg", json_string ("ES256")));

    return jwk;
}
