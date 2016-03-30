/* -*- mode: c; c-file-style: "gnu" -*- */
#include "config.h"
 #include <libguile.h>
#include <assert.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "extension.h"
#include <jansson.h>
#include "../base64url.h"
#include "../../libjosec.h"

static void
copy_to_bytevector (const uint8_t *src, unsigned int len, SCM bv)
{
  unsigned int x = 0;

  assert (SCM_BYTEVECTOR_LENGTH (bv) == len);

  for (x = 0; x < len; x++)
    {
      scm_c_bytevector_set_x (bv, x, src[x]);
    }

}

/* SCM */
/* yacl_scm_sha256 (SCM bv) */
/* { */
/*     int rc; */
/*     uint8_t out[YACL_SHA256_LEN] = {}; */
/*     signed char* p = SCM_BYTEVECTOR_CONTENTS (bv); */
/*     size_t len = SCM_BYTEVECTOR_LENGTH (bv); */

/*     rc = yacl_sha256 (p, len, out); */

/*     SCM digest = scm_c_make_bytevector (YACL_SHA256_LEN); */

/*     memcpy (SCM_BYTEVECTOR_CONTENTS (digest), &out, YACL_SHA256_LEN); */

/*     return digest; */

/* } */

/* SCM */
/* yacl_scm_gen_p256_key_pair (void) */
/* { */
/*     int rc; */
/*     uint8_t q[YACL_P256_COORD_SIZE*2]; */
/*     uint8_t d[YACL_P256_COORD_SIZE]; */
/*     rc = yacl_create_key_pair(q, d); */

/*     SCM qs = scm_c_make_bytevector (YACL_SHA256_LEN*2); */
/*     SCM ds = scm_c_make_bytevector (YACL_SHA256_LEN); */

/*     memcpy (SCM_BYTEVECTOR_CONTENTS (qs), &q, YACL_SHA256_LEN*2); */
/*     memcpy (SCM_BYTEVECTOR_CONTENTS (ds), &d, YACL_SHA256_LEN); */

/*     SCM q_list = scm_list_2 (scm_from_locale_symbol ("q"), qs); */
/*     SCM d_list = scm_list_2 (scm_from_locale_symbol ("d"), ds); */
/*     SCM curve_list = scm_list_2 (scm_from_locale_symbol ("curve"), */
/*                                  scm_from_locale_string("NIST P-256")); */
/*     SCM l = scm_list_4 (scm_from_locale_symbol ("ecc"), */
/*                         curve_list, */
/*                         q_list, */
/*                         d_list); */


/*     SCM pri_key = scm_list_2 (scm_from_locale_symbol ("private-key"), */
/*                               l); */


/*     return pri_key; */
/* } */

/* SCM */
/* yacl_scm_p256_sign(SCM data, SCM d) */
/* { */
/*     int rc; */
/*     uint8_t out[YACL_SHA256_LEN*2] = {}; */
/*     unsigned char* data_ptr = SCM_BYTEVECTOR_CONTENTS (data); */
/*     size_t data_len = SCM_BYTEVECTOR_LENGTH (data); */

/*     unsigned char* d_ptr = SCM_BYTEVECTOR_CONTENTS (d); */
/*     size_t d_len = SCM_BYTEVECTOR_LENGTH (d); */

/*     rc = yacl_hash_ecdsa_sign(data_ptr, data_len, d_ptr, out); */

/*     SCM sig = scm_c_make_bytevector (YACL_SHA256_LEN*2); */
/*     memcpy (SCM_BYTEVECTOR_CONTENTS (sig), &out, YACL_SHA256_LEN*2); */

/*     return sig; */
/* } */

/* SCM */
/* yacl_scm_p256_verify(SCM data, SCM q, SCM sig) */
/* { */
/*     int rc; */
/*     unsigned char* data_ptr = SCM_BYTEVECTOR_CONTENTS (data); */
/*     size_t data_len = SCM_BYTEVECTOR_LENGTH (data); */

/*     unsigned char* q_ptr = SCM_BYTEVECTOR_CONTENTS (q); */
/*     size_t q_len = SCM_BYTEVECTOR_LENGTH (q); */

/*     unsigned char* sig_ptr = SCM_BYTEVECTOR_CONTENTS (sig); */
/*     size_t sig_len = SCM_BYTEVECTOR_LENGTH (sig); */

/*     rc = yacl_hash_verify(data_ptr, data_len, q_ptr, sig_ptr); */

/*     if (0 == rc) */
/*         return SCM_BOOL_T; */
/*     else */
/*         return SCM_BOOL_F; */

/* } */

SCM
josec_scm_base64url_encode(SCM bv)
{
  char *out;
  unsigned char* data_ptr = SCM_BYTEVECTOR_CONTENTS (bv);
  size_t data_len = SCM_BYTEVECTOR_LENGTH (bv);

  size_t size_out = base64url_encode_alloc (data_ptr, data_len, &out);


  SCM encoded = scm_from_locale_stringn (out, size_out);

  memset (out, 0, size_out);
  free (out);


  return encoded;

}

SCM
josec_scm_base64url_decode (SCM str)
{
  char *c_str = scm_to_locale_string (str);

  char *decoded;
  size_t out = base64url_decode_alloc (c_str, strlen(c_str), &decoded);

  SCM result = scm_c_make_bytevector (out);
  memcpy (SCM_BYTEVECTOR_CONTENTS (result), decoded, out);

  free (c_str);
  free (decoded);

  return result;

}

SCM
josec_scm_decode(SCM jwt)
{
  int rc;
  json_t *header, *claims;
  SCM decoded;
  char *jwt_str = scm_to_locale_string (jwt);
  rc = jwt_decode (jwt_str, &header, &claims);

  if (0 != rc)
    {
      decoded = SCM_EOL;
      goto OUT;
    }

  char *h = json_dumps (header, 0);
  char *c = json_dumps (claims, 0);

  SCM hs = scm_from_locale_string (h);
  SCM cs = scm_from_locale_string (c);

  free (h);
  free (c);

  decoded = scm_list_3 (scm_from_locale_symbol ("jwt"),
                        scm_list_2 (scm_from_locale_symbol ("header"), hs),
                        scm_list_2 (scm_from_locale_symbol ("claims"), cs));

  OUT:
    free (jwt_str);

  return decoded;
}

SCM
josec_scm_encode_hs256(SCM claims_str, SCM bv_key)
{
  unsigned char* keyp = SCM_BYTEVECTOR_CONTENTS (bv_key);
  size_t keyl = SCM_BYTEVECTOR_LENGTH (bv_key);
  char *c_str = scm_to_locale_string (claims_str);
  SCM result = SCM_EOL;

  json_t *claims = json_loads (c_str, 0, NULL);
  if (NULL == claims)
    goto OUT;

  jose_context_t ctx = {};
  int rc = jose_create_context (&ctx, NULL, NULL, NULL);

  if (rc) goto OUT;

  jose_key_t key;
  key.alg_type = HS256;
  key.key = keyp;
  key.k_len = keyl;

  rc = jose_add_key (&ctx, key);
  if (rc) goto OUT;


  char *jwt_str = jwt_encode(&ctx, claims, HS256);

  if (NULL == jwt_str)
    goto OUT;

  result = scm_from_locale_string (jwt_str);

  free (jwt_str);
  json_decref (claims);
  free (c_str);


 OUT:
  return result;
}


void
josec_init_guile (void)
{
  scm_c_define_gsubr ("bv->base64url", 1, 0, 0, josec_scm_base64url_encode);
  scm_c_define_gsubr ("base64url->bv", 1, 0, 0, josec_scm_base64url_decode);
  scm_c_define_gsubr ("jwt->scm", 1, 0, 0, josec_scm_decode);
  scm_c_define_gsubr ("jwt-encode-hs256", 2, 0, 0, josec_scm_encode_hs256);

  scm_c_export ("bv->base64url", NULL);
  scm_c_export ("base64url->bv", NULL);
  scm_c_export ("jwt->scm", NULL);
  scm_c_export ("jwt-encode-hs256", NULL);


}
