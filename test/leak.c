#include "config.h"
#include <jansson.h>
#include <string.h>
#include <stdlib.h>
#include <argp.h>
#include <assert.h>
#include "../libjosec.h"
#include "../src/soft_crypto.h"
#include "jwt.h"
#include <mcheck.h>

int
main (void)
{
    jose_context_t ctx;
    char *hmac_key = "secret";
    char *jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9";

    json_t *header, *claims;
    int rc;

    mtrace();

    rc = jwt_split (jwt, &header, &claims);

    assert (0 == jose_create_context (&ctx, NULL, NULL, NULL));

    assert (ctx.cookie == NULL);
    assert (ctx.verify_func == jose_soft_verify);
    assert (ctx.sign_func == jose_soft_sign);

    assert (ctx.key_container[HS256].key == NULL);

    jose_key_t key;
    key.alg_type = HS256;
    key.key = (uint8_t *)hmac_key;
    key.k_len = strlen (hmac_key);

    assert (0 == jose_add_key (&ctx, key));

    char *result = jwt_encode(&ctx, claims, HS256);

    assert(NULL != result);



    printf ("jwt: %s\n", result);

    assert (0 == jwt_verify_sig (&ctx, result, HS256));
    printf ("verified\n");

    free (result);
    json_decref (header);
    json_decref (claims);

    muntrace();
}
