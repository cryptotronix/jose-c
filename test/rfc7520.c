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
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

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
    int rc = -1;
    int fd = open("/dev/urandom", O_RDONLY);
    size_t num = 0;

    if (fd < 0)
        return rc;

    while (num < len)
    {
        rc = read(fd, ptr + num, 1);
        if (rc < 0)
        {
            return rc;
        }
        else
        {
            num += rc;
        }
    }

    close (fd);

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


START_TEST(t_section_4_4_3)
{
    json_error_t jerr;
    int rc = -1;
    json_t *jwk = json_loads(hmac_key, 0, &jerr);
    uint8_t raw_key[32];

    ck_assert (NULL != jwk);

    jose_context_t ctx = {0};
    ck_assert (0 == jose_create_context (&ctx, NULL, NULL, NULL));

    rc = b64url_decode_helper (json_string_value (json_object_get (jwk, "k")),
                               raw_key, 32);
    ck_assert (0 == rc);

    jose_key_t key;
    key.alg_type = HS256;
    key.key = raw_key;
    key.k_len = 32;

    ck_assert (0 == jose_add_key (&ctx, key));

    ck_assert (0 == jwt_verify_sig (&ctx, section_4_4_3_jwt, HS256));

}
END_TEST



static Suite *
rfc7520_suite(void)
{
    Suite *s;
    TCase *tc_core;

    s = suite_create("RFC 7520");

    /* Core test case */
    tc_core = tcase_create("Core");

    tcase_add_test(tc_core, t_section_4_4_3);

    suite_add_tcase(s, tc_core);


    return s;
}

int main(void)
{
    int number_failed;
    Suite *s;
    SRunner *sr;

    s = rfc7520_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}


#if defined(__GNUC__) && (__GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 6))
#pragma GCC diagnostic pop
#endif
