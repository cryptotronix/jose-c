/* -*- mode: c; c-file-style: "gnu" -*- */
#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <jansson.h>
#include <assert.h>
#include <string.h>
#include "base64url.h"
#include <yacl.h>
#include "../libjosec.h"
#include "jwk.h"

#if defined(__GNUC__) && (__GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 6))
#pragma GCC diagnostic push
#endif
#pragma GCC diagnostic ignored "-Wunknown-pragmas"
#pragma GCC diagnostic ignored "-Wpragmas"
#pragma GCC diagnostic ignored "-Winitializer-overrides"
#pragma GCC diagnostic ignored "-Woverride-init"
#pragma GCC diagnostic ignored "-Wcast-qual"
#pragma GCC diagnostic ignored "-Wmissing-field-initializers"

int
jwa_ecdh (const json_t *pub_jwk, const json_t *pri_jwk,
          uint8_t **shared_secret, size_t *ss_len)
{
  assert (pub_jwk);
  assert (pri_jwk);
  int rc = -1;

  uint8_t public_key[YACL_P256_COORD_SIZE*2];
  uint8_t private_key[YACL_P256_COORD_SIZE];


  rc = jwk2rawpub (pub_jwk, public_key);
  if (rc) return rc;

  rc = jwk2rawpri (pri_jwk, private_key);
  if (rc) return rc;

  uint8_t *secret = malloc (YACL_P256_COORD_SIZE);
  assert (secret);
  memset (secret, 0, YACL_P256_COORD_SIZE);

  rc = yacl_ecdh (public_key, private_key, secret);

  if (0 == rc)
    {
      *shared_secret = secret;
      *ss_len = YACL_P256_COORD_SIZE;
    }

  else
    free (secret);

  return rc;
}



#if defined(__GNUC__) && (__GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 6))
#pragma GCC diagnostic pop
#endif
