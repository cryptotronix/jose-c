/* -*- mode: c; c-file-style: "gnu" -*- */
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
#include <glib.h>
#include <string.h>

#if defined(__GNUC__) && (__GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 6))
#pragma GCC diagnostic push
#endif
#pragma GCC diagnostic ignored "-Wunknown-pragmas"
#pragma GCC diagnostic ignored "-Wpragmas"
#pragma GCC diagnostic ignored "-Winitializer-overrides"
#pragma GCC diagnostic ignored "-Woverride-init"
#pragma GCC diagnostic ignored "-Wcast-qual"

const char *good_jwe = "eyJhbGciOiAiQTI1NktXIiwgImVuYyI6ICJBMjU2R0NNIn0.b2NmvRU4r4oyKC7RMSDsT8TE9yYdIChlzTjgIVylUWVKu2flezaTAg.Lc7BDBSQozOr3nZKsOYJbA.yoJHkBUXZx2TsRw1gkca8ahYI9aIc6oANkmvFXnY7ZcXXcPTyT0Q4LCXWy2iZQ_Qer_d8IOMb6BnpxcPM4itTiUxrMH5FV4oc1Q0WFVSgTYunr9e_I5L_xNI33I8fybiqhS9o_kgFXivxNgLCsbuAlowrVt_kQ1Lc5Zoasevx9iqkbKX2s2X5daluxr7voJRuSeKoR_Sv0011qiaRXqoEVzqPN_ioyXfGf4jL3t6y43V0tFJPUeP5Vo9eVd1nZNruqI4Aml43n5vYzAYuawhPsUmJGWCwN5kZ1Q4RLjNYjb6U7kDkyaGudvKHoLGc1D6_fDZHtVXgthJc2W05uJOtw.uoZ7-5udnH_SjpPgPSk2Uw";

static void t_build_key(void)
{
  json_t *alg = json_string ("A256GCM");
  uint8_t t[32];
  uint8_t tmp[32];
  memset (t, 0x61, 32);

  json_t *jwk = jwk_build_symmetric_key (alg, t, 32);
  g_assert (NULL != jwk);

  int rc = strcmp (json_string_value (json_object_get (jwk, "kty")), "oct");
  g_assert (rc == 0);

  rc = strcmp (json_string_value (json_object_get (jwk, "alg")), "A256GCM");
  g_assert (rc == 0);

  const char* k = json_string_value (json_object_get (jwk, "k"));
  g_assert (NULL != k);


  rc = b64url_decode_helper (k, tmp, 32);
  g_assert (0 == rc);

  rc = memcmp (t, tmp, 32);
  g_assert (0 == rc);

}


static void test_jwe_encrypt(void)
{

  json_t *alg = json_string ("A256KW");
  uint8_t t[32];
  memset (t, 0x61, 32);

  json_t *jwk = jwk_build_symmetric_key (alg, t, 32);
  g_assert (jwk);

  uint8_t p[256];
  memset (p, 0x62, 256);

  const char *jwe;
  int rc = jwe_encrypt (A256KW, A256GCM, p, 256, jwk, &jwe);

  g_assert_cmpint(0, ==, rc);
  g_assert_nonnull (jwe);
  printf ("JWE: %s\n", jwe);

  uint8_t *out;
  size_t outl;
  rc = jwe_decrypt (jwk, jwe, &out, &outl);

  g_assert_cmpint(0, ==, rc);
}


static void test_jwe_failures(void)
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

  g_assert_cmpint(0, !=, rc);

  rc = jwe_encrypt (A256GCM, A256KW, p, 256, jwk, &jwe);

  g_assert_cmpint(0, !=, rc);

  json_t *bad_jwk = json_deep_copy (jwk);
  g_assert (0 == json_object_set (bad_jwk, "nope", json_string("nope")));


  rc = jwe_encrypt (A256KW, A256GCM, p, 256, bad_jwk, &jwe);
  g_assert_cmpint(0, !=, rc);

  /* if (g_test_subprocess ()) */
  /*   { */
  /*     rc = jwe_decrypt (bad_jwk, jwe, &out, &outl); */
  /*   } */

  /* g_test_trap_subprocess (NULL, 0, 0); */
  /* g_test_trap_assert_failed (); */
  /* g_test_trap_assert_stderr ("*ERROR*too large*"); */

  /* g_assert_cmpint(0, !=, rc); */



  const char *bad_jwe = "a.a.a.a.a";

  rc = jwe_decrypt (jwk, bad_jwe, &out, &outl);

  g_assert_cmpint(-1, ==, rc);



  const char *bad1 = "eyJhbGciOiAiQTI1NktXIiwgImVuYyI6ICJBMjU2R0NNIn0.a.a.a.a";

  rc = jwe_decrypt (jwk, bad1, &out, &outl);

  g_assert_cmpint(-2, ==, rc);



  const char *bad2 = "eyJhbGciOiAiQTI1NktXIiwgImVuYyI6ICJBMjU2R0NNIn0.b2NmvRU4r4oyKC7RMSDsT8TE9yYdIChlzTjgIVylUWVKu2flezaTAg.a.a.a";

  rc = jwe_decrypt (jwk, bad2, &out, &outl);

  g_assert_cmpint(-3, ==, rc);


  /* Bad three has a manipulted header */
  const char *bad3 = "eyJlbmMiOiJBMjU2R0NNIiwiYWxnIjoiQTI1NktXIn0.b2NmvRU4r4oyKC7RMSDsT8TE9yYdIChlzTjgIVylUWVKu2flezaTAg.Lc7BDBSQozOr3nZKsOYJbA.yoJHkBUXZx2TsRw1gkca8ahYI9aIc6oANkmvFXnY7ZcXXcPTyT0Q4LCXWy2iZQ_Qer_d8IOMb6BnpxcPM4itTiUxrMH5FV4oc1Q0WFVSgTYunr9e_I5L_xNI33I8fybiqhS9o_kgFXivxNgLCsbuAlowrVt_kQ1Lc5Zoasevx9iqkbKX2s2X5daluxr7voJRuSeKoR_Sv0011qiaRXqoEVzqPN_ioyXfGf4jL3t6y43V0tFJPUeP5Vo9eVd1nZNruqI4Aml43n5vYzAYuawhPsUmJGWCwN5kZ1Q4RLjNYjb6U7kDkyaGudvKHoLGc1D6_fDZHtVXgthJc2W05uJOtw.uoZ7-5udnH_SjpPgPSk2Uw";

  alg = json_string ("A256KW");

  jwk = jwk_build_symmetric_key (alg, t, 32);

  rc = jwe_decrypt (jwk, bad3, &out, &outl);

  //IV size changed with new yacl
  //g_assert_cmpint(-10, ==, rc);
  g_assert_cmpint(16, ==, rc);


}


static void t_loop(void)
{
  int i;
  for (i=0; i<1000; i++)
    {
      printf ("Looping: %d\n", i);
      json_t *alg = json_string ("A256KW");
      uint8_t t[32];
      memset (t, 0x61, 32);

      json_t *jwk = jwk_build_symmetric_key (alg, t, 32);

      uint8_t p[256];
      memset (p, 0x62, 256);

      const char *jwe;
      int rc = jwe_encrypt (A256KW, A256GCM, p, 256, jwk, &jwe);

      g_assert_cmpint(0, ==, rc);
      printf ("JWE: %s\n", jwe);

      uint8_t *out;
      size_t outl;
      rc = jwe_decrypt (jwk, jwe, &out, &outl);

      g_assert_cmpint(0, ==, rc);
    }
}



int
main(int argc, char *argv[])
{

  yacl_init();
    g_test_init (&argc, &argv, NULL);

    g_test_add_func ("/jwe/t_build_key", t_build_key);
    g_test_add_func ("/jwe/test_jwe_encrypt", test_jwe_encrypt);
    g_test_add_func ("/jwe/test_jwe_failures", test_jwe_failures);
    g_test_add_func ("/jwe/t_loop", t_loop);


    return g_test_run ();
}




#if defined(__GNUC__) && (__GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 6))
#pragma GCC diagnostic pop
#endif
