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

const char *good_jwe = "eyJhbGciOiAiQTI1NktXIiwgImVuYyI6ICJBMjU2R0NNIn0.b2NmvRU4r4oyKC7RMSDsT8TE9yYdIChlzTjgIVylUWVKu2flezaTAg.Lc7BDBSQozOr3nZKsOYJbA.yoJHkBUXZx2TsRw1gkca8ahYI9aIc6oANkmvFXnY7ZcXXcPTyT0Q4LCXWy2iZQ_Qer_d8IOMb6BnpxcPM4itTiUxrMH5FV4oc1Q0WFVSgTYunr9e_I5L_xNI33I8fybiqhS9o_kgFXivxNgLCsbuAlowrVt_kQ1Lc5Zoasevx9iqkbKX2s2X5daluxr7voJRuSeKoR_Sv0011qiaRXqoEVzqPN_ioyXfGf4jL3t6y43V0tFJPUeP5Vo9eVd1nZNruqI4Aml43n5vYzAYuawhPsUmJGWCwN5kZ1Q4RLjNYjb6U7kDkyaGudvKHoLGc1D6_fDZHtVXgthJc2W05uJOtw.uoZ7-5udnH_SjpPgPSk2Uw";

static void
init_ssl()
{
  SSL_load_error_strings();
  SSL_library_init();
}
START_TEST(t_build_key)
{
  json_t *alg = json_string ("A256GCM");
  uint8_t t[32];
  uint8_t tmp[32];
  memset (t, 0x61, 32);

  json_t *jwk = jwk_build_symmetric_key (alg, t, 32);
  ck_assert (NULL != jwk);

  int rc = strcmp (json_string_value (json_object_get (jwk, "kty")), "oct");
  ck_assert (rc == 0);

  rc = strcmp (json_string_value (json_object_get (jwk, "alg")), "A256GCM");
  ck_assert (rc == 0);

  const char* k = json_string_value (json_object_get (jwk, "k"));
  ck_assert (NULL != k);


  rc = b64url_decode_helper (k, tmp, 32);
  ck_assert (0 == rc);

  rc = memcmp (t, tmp, 32);
  ck_assert (0 == rc);

}
END_TEST

START_TEST(test_jwe_encrypt)
{

  json_t *alg = json_string ("A256KW");
  uint8_t t[32];
  memset (t, 0x61, 32);

  json_t *jwk = jwk_build_symmetric_key (alg, t, 32);

  uint8_t p[256];
  memset (p, 0x62, 256);

  const char *jwe;
  int rc = jwe_encrypt (A256KW, A256GCM, p, 256, jwk, &jwe);

  ck_assert_msg (0 == rc, "RC = %d", rc);
  printf ("JWE: %s\n", jwe);

  uint8_t *out;
  size_t outl;
  rc = jwe_decrypt (jwk, jwe, &out, &outl);

  ck_assert_msg (0 == rc, "RC: %d", rc);
}
END_TEST

START_TEST(test_jwe_failures)
{
  uint8_t *out;
  size_t outl;
  int rc;
  json_t *alg = json_string ("A256KW1");
  uint8_t t[32];
  memset (t, 0x61, 32);

  json_t *jwk = jwk_build_symmetric_key (alg, t, 32);

  uint8_t p[256];
  memset (p, 0x62, 256);

  const char *jwe;
  rc = jwe_encrypt (A256KW, A256GCM, p, 256, jwk, &jwe);

  ck_assert_msg (rc != 0, "%s %d\n", "RC:", rc);

  rc = jwe_encrypt (A256GCM, A256KW, p, 256, jwk, &jwe);

  ck_assert_msg (rc != 0, "%s %d\n", "RC:", rc);

  json_t *bad_jwk = json_deep_copy (jwk);
  ck_assert (0 == json_object_set (bad_jwk, "nope", json_string("nope")));

  rc = jwe_encrypt (A256KW, A256GCM, p, 256, bad_jwk, &jwe);

  ck_assert_msg (rc != 0, "%s %d\n", "RC:", rc);


  rc = jwe_decrypt (bad_jwk, jwe, &out, &outl);

  ck_assert_msg (0 != rc, "RC: %d", rc);

  const char *bad_jwe = "a.a.a.a.a";

  rc = jwe_decrypt (jwk, bad_jwe, &out, &outl);

  ck_assert_msg (-1 == rc, "RC: %d", rc);

  const char *bad1 = "eyJhbGciOiAiQTI1NktXIiwgImVuYyI6ICJBMjU2R0NNIn0.a.a.a.a";

  rc = jwe_decrypt (jwk, bad1, &out, &outl);

  ck_assert_msg (-2 == rc, "RC: %d", rc);

  const char *bad2 = "eyJhbGciOiAiQTI1NktXIiwgImVuYyI6ICJBMjU2R0NNIn0.b2NmvRU4r4oyKC7RMSDsT8TE9yYdIChlzTjgIVylUWVKu2flezaTAg.a.a.a";

  rc = jwe_decrypt (jwk, bad2, &out, &outl);

  ck_assert_msg (-3 == rc, "RC: %d", rc);


  /* Bad three has a manipulted header */
  const char *bad3 = "eyJlbmMiOiJBMjU2R0NNIiwiYWxnIjoiQTI1NktXIn0.b2NmvRU4r4oyKC7RMSDsT8TE9yYdIChlzTjgIVylUWVKu2flezaTAg.Lc7BDBSQozOr3nZKsOYJbA.yoJHkBUXZx2TsRw1gkca8ahYI9aIc6oANkmvFXnY7ZcXXcPTyT0Q4LCXWy2iZQ_Qer_d8IOMb6BnpxcPM4itTiUxrMH5FV4oc1Q0WFVSgTYunr9e_I5L_xNI33I8fybiqhS9o_kgFXivxNgLCsbuAlowrVt_kQ1Lc5Zoasevx9iqkbKX2s2X5daluxr7voJRuSeKoR_Sv0011qiaRXqoEVzqPN_ioyXfGf4jL3t6y43V0tFJPUeP5Vo9eVd1nZNruqI4Aml43n5vYzAYuawhPsUmJGWCwN5kZ1Q4RLjNYjb6U7kDkyaGudvKHoLGc1D6_fDZHtVXgthJc2W05uJOtw.uoZ7-5udnH_SjpPgPSk2Uw";

  alg = json_string ("A256KW");

  jwk = jwk_build_symmetric_key (alg, t, 32);

  rc = jwe_decrypt (jwk, bad3, &out, &outl);

  ck_assert_msg (-10 == rc, "RC: %d", rc);
}
END_TEST

START_TEST(t_loop)
{
  int i;
  for (i=0; i<1000; i++)
    {
      json_t *alg = json_string ("A256KW");
      uint8_t t[32];
      memset (t, 0x61, 32);

      json_t *jwk = jwk_build_symmetric_key (alg, t, 32);

      uint8_t p[256];
      memset (p, 0x62, 256);

      const char *jwe;
      int rc = jwe_encrypt (A256KW, A256GCM, p, 256, jwk, &jwe);

      ck_assert_msg (0 == rc, "RC = %d", rc);
      printf ("JWE: %s\n", jwe);

      uint8_t *out;
      size_t outl;
      rc = jwe_decrypt (jwk, jwe, &out, &outl);

      ck_assert_msg (0 == rc, "RC: %d", rc);
    }
}
END_TEST

static Suite *
jwe_suite(void)
{
    Suite *s;
    TCase *tc_core;

    s = suite_create("JWE");

    /* Core test case */
    tc_core = tcase_create("Core");


    tcase_add_test(tc_core, t_build_key);
    tcase_add_test(tc_core, test_jwe_encrypt);
    tcase_add_test(tc_core, test_jwe_failures);
    tcase_add_test(tc_core, t_loop);

    suite_add_tcase(s, tc_core);


    return s;
}

int main(void)
{
    int number_failed;
    Suite *s;
    SRunner *sr;

    s = jwe_suite();
    sr = srunner_create(s);

    init_ssl();
    srunner_set_fork_status (sr, CK_NOFORK);
    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}




#if defined(__GNUC__) && (__GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 6))
#pragma GCC diagnostic pop
#endif
