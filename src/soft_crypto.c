#include "soft_crypto.h"
#include <assert.h>
#include "hs264.h"

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

        printf("Input: %s\n", signing_input);

        uint8_t *mac = hs264_soft_hmac(signing_input, si_len, key, k_len);
        *out = mac;
        *out_len = 32;
        rc = 0;
    }

    return rc;

}
