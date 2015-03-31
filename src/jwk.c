#include <stdio.h>
#include <stdlib.h>
#include <jansson.h>
#include <assert.h>
#include <string.h>
#include <gcrypt.h>
#include "jwk.h"
#include "base64url.h"
#include <libcryptoauth.h>

json_t*
build_ec_jwk (char *x, char *y, char *d, char *use, char *kid)
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

json_t *
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
        goto OUT;

    if (0 == (y_b64_len = base64url_encode_alloc (y, COORD_LEN, &y_b64)))
        goto FREE_X;

    jwk = build_ec_jwk (x_b64, y_b64, NULL, "sig", NULL);

    free (y_b64);
FREE_X:
    free (x_b64);
OUT:
    return jwk;

}

json_t *
gcry_pubkey2jwk (gcry_sexp_t * pubkey)
{

    assert (NULL != pubkey);

    gcry_error_t  rc = -1;
    gcry_sexp_t sexp_q;
    gcry_mpi_t mpi_q;
    unsigned char *raw_q;
    size_t size_q;
    json_t *jwk = NULL;

    if (NULL == (sexp_q = gcry_sexp_find_token(*pubkey, "q", 0)))
        goto OUT;

    if (NULL == (mpi_q = gcry_sexp_nth_mpi (sexp_q, 1, GCRYMPI_FMT_USG)))
        goto FREE_Q;

    if (rc = gcry_mpi_aprint(GCRYMPI_FMT_USG, &raw_q, &size_q, mpi_q))
        goto FREE_MPI_Q;

    jwk = raw_pubkey2jwk (raw_q, size_q);

    gcry_free (raw_q);

FREE_MPI_Q:
    gcry_mpi_release (mpi_q);
FREE_Q:
    gcry_sexp_release (sexp_q);
OUT:
    return jwk;
}
