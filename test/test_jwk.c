/* -*- mode: c; c-file-style: "gnu" -*- */
#include "config.h"
#include <check.h>
#include <stdlib.h>
#include "../libjosec.h"
#include <jansson.h>
#include <assert.h>
#include <gcrypt.h>
#include <yacl.h>
#include "../src/hs256.h"
#include "soft_crypto.h"
#include "../src/jwk.h"
#include "base64url.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#if defined(__GNUC__) && (__GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 6))
#pragma GCC diagnostic push
#endif
#pragma GCC diagnostic ignored "-Wunknown-pragmas"
#pragma GCC diagnostic ignored "-Wpragmas"
#pragma GCC diagnostic ignored "-Winitializer-overrides"
#pragma GCC diagnostic ignored "-Woverride-init"
#pragma GCC diagnostic ignored "-Wcast-qual"


static void
init_ssl()
{
  SSL_load_error_strings();
  SSL_library_init();
}

START_TEST(t_2pubkey)
{
  uint8_t key[65];
  key[0] = 0x04;

  memset (&key[1], 1, 32);
  memset (&key[1+32], 2, 32);

  const char *kidin="my kid";

  json_t *pub= jwk_pubkey2jwk (key, sizeof(key), kidin);

  ck_assert (NULL != pub);

  static const char *fmt = "{s:s, s:s, s:s, s:s, s:s, s:s}";

  const char *crv;
  const char *kty;
  const char *kid;
  const char *use;
  const char *x;
  const char *y;

  json_error_t jerr;

  int rc = json_unpack_ex ((json_t *)pub, &jerr, JSON_STRICT, fmt,
                           "kty", &kty,
                           "crv", &crv,
                           "use", &use,
                           "kid", &kid,
                           "x", &x,
                           "y", &y);

  ck_assert (0 == rc);

  ck_assert (0 == strcmp (kty, "EC"));
  ck_assert (0 == strcmp (use, "sig"));
  ck_assert (0 == strcmp (crv, "P-256"));
  ck_assert (0 == strcmp (kid, kidin));

  uint8_t xraw[32];
  uint8_t yraw[32];
  rc = b64url_decode_helper (x, xraw, 32);

  ck_assert (0 == rc);

  rc = b64url_decode_helper (y, yraw, 32);

  ck_assert (0 == rc);

  ck_assert (0 == memcmp (xraw, &key[1], 32));
  ck_assert (0 == memcmp (yraw, &key[1+32], 32));


}
END_TEST


static Suite *
jwk_suite(void)
{
    Suite *s;
    TCase *tc_core;

    s = suite_create("JWK");

    /* Core test case */
    tc_core = tcase_create("Core");

    tcase_add_test(tc_core, t_2pubkey);

    suite_add_tcase(s, tc_core);


    return s;
}

int main(void)
{
    int number_failed;
    Suite *s;
    SRunner *sr;

    s = jwk_suite();
    sr = srunner_create(s);

    init_ssl();
    //srunner_set_fork_status (sr, CK_NOFORK);
    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}




#if defined(__GNUC__) && (__GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 6))
#pragma GCC diagnostic pop
#endif
