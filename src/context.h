#ifndef JOSECCONTEXT_H_
#define JOSECCONTEXT_H_

#include "jwa.h"
#include <stdint.h>
#include <stddef.h>


typedef struct jose_context_t jct;

/* Sign function pointer
   const uint8_t *data_to_sign,
   size_t dlen,
   jwa_t alg,
   jose_context_t *cookie,
   uint8_t **out,
   size_t *out_len

*/
typedef int (*sign_funcp)(const uint8_t *, size_t len,
                              jwa_t, const jct *,
                              uint8_t **, size_t *);

typedef struct
{
    jwa_t alg_type;
    uint8_t *key;
    unsigned int k_len;
} jose_key_t;

typedef struct
{
    sign_funcp sign_func;
    jose_key_t key_container[JWA_MAX];
    void *cookie;
} jose_context_t;


int
jose_create_context (jose_context_t *ctx, sign_funcp sf, void *cookie);

int
jose_add_key (jose_context_t *ctx, jose_key_t key);

void
jose_close_context (jose_context_t *ctx);


#endif
