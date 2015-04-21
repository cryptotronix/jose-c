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

    if (!sf)
        ctx->sign_func = jose_soft_sign;
    else
        ctx->sign_func = sf;

    if (!vf)
        ctx->verify_func = jose_soft_verify;
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
