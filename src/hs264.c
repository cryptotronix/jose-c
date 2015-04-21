#include "hs264.h"
#include <gcrypt.h>
#include <assert.h>
#include "jws.h"

uint8_t *
hs264_soft_hmac (const char *signing_input, int si_len,
                 const uint8_t *key, int k_len)
{
    gcry_md_hd_t hd;
    uint8_t *digest, *tmp;
    int d_len = gcry_md_get_algo_dlen (GCRY_MD_SHA256);
    assert (signing_input);
    assert (key);

    digest = malloc (d_len);
    memset (digest, 0, d_len);
    assert (digest);

    assert (GPG_ERR_NO_ERROR == gcry_md_open (&hd, GCRY_MD_SHA256,
                                              GCRY_MD_FLAG_HMAC));

    assert (GPG_ERR_NO_ERROR == gcry_md_setkey (hd, key, k_len));

    gcry_md_write (hd, signing_input, si_len);

    assert (tmp = gcry_md_read (hd, GCRY_MD_SHA256));

    memcpy (digest, tmp, d_len);


    gcry_md_close (hd);

    return digest;

}

char *
hs264_encode(const char *signing_input, int si_len,
             const uint8_t *key, int k_len,
             sign_funcp sfunc)
{
    gcry_md_hd_t hd;
    uint8_t *digest;
    char *result;
    int d_len = gcry_md_get_algo_dlen (GCRY_MD_SHA256);
    assert (signing_input);

    if (NULL == sfunc && NULL != key)
    {

        assert (signing_input);

        assert (GPG_ERR_NO_ERROR == gcry_md_open (&hd, GCRY_MD_SHA256,
                                                  GCRY_MD_FLAG_HMAC));

        assert (GPG_ERR_NO_ERROR == gcry_md_setkey (hd, key, k_len));

        gcry_md_write (hd, signing_input, si_len);

        assert (digest = gcry_md_read (hd, GCRY_MD_SHA256));
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
                                  digest, d_len);

    gcry_md_close (hd);

    return result;

}
