#include "config.h"
#include "hs256.h"
#include <assert.h>
#include <string.h>
#include "jws.h"
#include "soft_crypto.h"

uint8_t *
hs256_soft_hmac (const char *signing_input, int si_len,
                 const uint8_t *key, int k_len)
{
    uint8_t *digest;
    assert (signing_input);
    assert (key);

    digest = malloc (JOSE_SHA256_LEN);
    assert (digest);
    memset (digest, 0, JOSE_SHA256_LEN);

    jose_hmac_256 (key, k_len, signing_input, si_len, digest);

    return digest;

}

static int
memcmp_constant_time (const void *a, const void *b, size_t size)
{
    const uint8_t *ap = a;
    const uint8_t *bp = b;
    int rc = 0;
    size_t i;

    if (NULL == a || NULL == b) return -1;

    for (i = 0; i < size; i++)
        rc |= *ap++ ^ *bp++;

    return rc;
}
int
hs256_soft_verify (const char *jwt, const uint8_t *key, int k_len)
{

    assert (key);

    char *si = jws2signing_input (jwt);
    assert (si);

    char *calc = hs256_encode (si, strlen(si), key, k_len, NULL);

    int rc = memcmp_constant_time (jwt, calc, strlen(calc));

    free (si);
    free (calc);

    return rc;

}

char *
hs256_encode(const char *signing_input, int si_len,
             const uint8_t *key, int k_len,
             sign_funcp sfunc)
{
    uint8_t *digest;
    char *result;
    assert (signing_input);

    if (NULL == sfunc && NULL != key)
    {

        assert (signing_input);

        digest = malloc (JOSE_SHA256_LEN);
        assert (digest);
        memset (digest, 0, JOSE_SHA256_LEN);

        jose_hmac_256 (key, k_len, signing_input, si_len, digest);

        assert (digest);
    }
    else if (NULL != sfunc)
    {
        /* not implemented */
        return NULL;
    }
    else if (NULL == sfunc && NULL == key)
    {
        /* need to pass some way to sign this*/
        assert(key);
    }

    result =
        jws_append_signing_input (signing_input, si_len,
                                  digest, JOSE_SHA256_LEN);

    return result;

}
