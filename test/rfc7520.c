#include "config.h"
#include <stdlib.h>
#include "../libjosec.h"
#include <jansson.h>
#include <assert.h>
#include <yacl.h>
#include "../src/hs256.h"
#include "soft_crypto.h"
#include "../src/jwk.h"
#include "base64url.h"
#include <glib.h>

#if defined(__GNUC__) && (__GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 6))
#pragma GCC diagnostic push
#endif
#pragma GCC diagnostic ignored "-Wunknown-pragmas"
#pragma GCC diagnostic ignored "-Wpragmas"
#pragma GCC diagnostic ignored "-Winitializer-overrides"
#pragma GCC diagnostic ignored "-Woverride-init"
#pragma GCC diagnostic ignored "-Wcast-qual"

const char *hmac_key =
    "{"
        "\"kty\": \"oct\","
        "\"kid\": \"018c0ae5-4d9b-471b-bfd6-eef314bc7037\","
        "\"use\": \"sig\","
        "\"alg\": \"HS256\","
        "\"k\": \"hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG-Onbc6mxCcYg\""
    "}";

const char *section_4_4_3_jwt =
    "eyJhbGciOiJIUzI1NiIsImtpZCI6IjAxOGMwYWU1LTRkOWItNDcxYi1iZmQ2LWVlZjMxNGJjN"
    "zAzNyJ9.SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywgZ29pbmcgb3V0IHlvd"
    "XIgZG9vci4gWW91IHN0ZXAgb250byB0aGUgcm9hZCwgYW5kIGlmIHlvdSBkb24ndCBrZWVwIH"
    "lvdXIgZmVldCwgdGhlcmXigJlzIG5vIGtub3dpbmcgd2hlcmUgeW91IG1pZ2h0IGJlIHN3ZXB"
    "0IG9mZiB0by4.s0h6KThzkfBBBkLspW1h84VsJZFTsPPqMDA7g1Md7p0";

static int
fill_random(uint8_t *ptr, const size_t len)
{

    for (size_t i=0; i<len; i++)
    {
        guint32 num = g_random_int ();
        uint8_t *p =(uint8_t *)&num;
        ptr[i] = p[0];
    }

    return len;
}

int sign_callback_called = 0;

static int
sign (const uint8_t *to_sign, size_t len,
      jwa_t alg, const jct* jct,
      uint8_t **out, size_t *out_len)
{
    sign_callback_called += 1;

    *out = malloc (64);

    fill_random (*out, 64);
    *out_len = 64;


    return 0;
}


static void t_section_4_4_3(void)
{
    json_error_t jerr;
    int rc = -1;
    json_t *jwk = json_loads(hmac_key, 0, &jerr);
    uint8_t raw_key[32];

    g_assert (NULL != jwk);

    jose_context_t ctx = {0};
    g_assert (0 == jose_create_context (&ctx, NULL, NULL, NULL));

    rc = b64url_decode_helper (json_string_value (json_object_get (jwk, "k")),
                               raw_key, 32);
    g_assert (0 == rc);

    jose_key_t key;
    key.alg_type = HS256;
    key.key = raw_key;
    key.k_len = 32;

    g_assert (0 == jose_add_key (&ctx, key));

    g_assert (0 == jwt_verify_sig (&ctx, section_4_4_3_jwt, HS256));

}

int
main(int argc, char *argv[])
{
    g_test_init (&argc, &argv, NULL);

    g_test_add_func ("/rfc7520/t_section_4_4_3", t_section_4_4_3);

    return g_test_run ();
}



#if defined(__GNUC__) && (__GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 6))
#pragma GCC diagnostic pop
#endif
