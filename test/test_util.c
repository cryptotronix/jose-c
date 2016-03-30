/* -*- mode: c; c-file-style: "gnu" -*- */
#include "config.h"
#include <stdlib.h>
#include "../libjosec.h"
#include <assert.h>
#include "../src/util.h"
#include "base64url.h"
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

static void test_b64url(void)
{
  uint8_t bin[32] = {};

  printf ("about to fill\n");

  fill_random (bin, 32);

  printf ("about to encoded\n");
  const char *encoded = b64url_encode (bin, 32);

  g_assert_nonnull (encoded);

  printf ("Encoded: %s\n", encoded);

  size_t outl;
  uint8_t *bin_out = b64url_decode (encoded, &outl);

  g_assert_nonnull (bin_out);
  g_assert (outl == 32);




}
static void test_trim(void)
{
  char *sample_strings[] =
    {
            "nothing to trim",
            "    trim the front",
            "trim the back     ",
            " trim one char front and back ",
            " trim one char front",
            "trim one char back ",
            "                   ",
            " ",
            "a",
            "",
            NULL
    };
    char test_buffer[64];
    int index;

    for( index = 0; sample_strings[index] != NULL; ++index )
    {
      memset (test_buffer, 0, sizeof(test_buffer));
      strcpy( test_buffer, sample_strings[index] );
      char *gt = strdup (test_buffer);
      char *t = trim(test_buffer);
      char *t2 = g_strstrip(gt);

      printf("[%s] -> [%s]\n", sample_strings[index],
             t);

      g_assert_cmpstr (t2, ==, t);
    }

    /* The test prints the following:
    [nothing to trim] -> [nothing to trim]
    [    trim the front] -> [trim the front]
    [trim the back     ] -> [trim the back]
    [ trim one char front and back ] -> [trim one char front and back]
    [ trim one char front] -> [trim one char front]
    [trim one char back ] -> [trim one char back]
    [                   ] -> []
    [ ] -> []
    [a] -> [a]
    [] -> []
    */
}




int
main(int argc, char *argv[])
{
  g_test_init (&argc, &argv, NULL);

  g_test_add_func ("/util/test_trim", test_trim);
  g_test_add_func ("/util/b64url", test_b64url);

  return g_test_run ();
}




#if defined(__GNUC__) && (__GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 6))
#pragma GCC diagnostic pop
#endif
