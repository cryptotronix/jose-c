/* -*- mode: c; c-file-style: "gnu" -*- */
#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <jansson.h>
#include <assert.h>
#include <string.h>
#include "base64url.h"
#include "../libjosec.h"
#include "jwk.h"
#include "jwt.h"
#include <regex.h>

#ifndef JOSEC_HAVE_OPENSSL

int
jwe_encrypt (jwa_t alg, jwa_t enc, const uint8_t *data, size_t len,
             const json_t *kek, const char **jwe)
{
  return -10;
}

int
jwe_decrypt (const json_t *kek, const char *jwe, uint8_t **data, size_t *len)
{
  return -10;
}

#elif JOSEC_HAVE_OPENSSL

#define JWE_AESKW_KEK_SIZE 32
#define JWE_AESKW_WRAPPED_SIZE 40
#define JWE_AESKW_KEY_SIZE 32
#define JWE_A256GCM_IV_SIZE 16
#define JWE_A256GCM_TAG_SIZE 16

#include <openssl/rand.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/aes.h>

#if defined(__GNUC__) && (__GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 6))
#pragma GCC diagnostic push
#endif
#pragma GCC diagnostic ignored "-Wunknown-pragmas"
#pragma GCC diagnostic ignored "-Wpragmas"
#pragma GCC diagnostic ignored "-Winitializer-overrides"
#pragma GCC diagnostic ignored "-Woverride-init"
#pragma GCC diagnostic ignored "-Wcast-qual"
#pragma GCC diagnostic ignored "-Wmissing-field-initializers"

static int
aes_gcm_encrypt(const uint8_t *plaintext, int plaintext_len,
                uint8_t *aad, int aad_len,
                uint8_t *key, uint8_t *iv,
                uint8_t *ciphertext, uint8_t *tag)
{
  EVP_CIPHER_CTX *ctx;
  int len;
  int ciphertext_len;
  int rc;


  /* Create and initialise the context */
  if(!(ctx = EVP_CIPHER_CTX_new()))
    return -1;

  /* Initialise the encryption operation. */
  if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
    {
      rc = -2;
      goto OUT;
    }

  /* Set IV length if default 12 bytes (96 bits) is not appropriate */
  if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 16, NULL))
    {
      rc = -3;
      goto OUT;
    }

  /* Initialise key and IV */
  if(1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv))
    {
      rc = -4;
      goto OUT;
    }

  /* Provide any AAD data. This can be called zero or more times as
   * required
   */
  if(1 != EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len))
    {
      rc = -5;
      goto OUT;
    }

  /* Provide the message to be encrypted, and obtain the encrypted
   * output.
   * EVP_EncryptUpdate can be called multiple times if necessary
   */
  if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
    {
      rc = -6;
      goto OUT;
    }


  ciphertext_len = len;

  /* Finalise the encryption. Normally ciphertext bytes may be
   * written at
   * this stage, but this does not occur in GCM mode
   */
  if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
    {
      rc = -7;
      goto OUT;
    }

  ciphertext_len += len;

  /* Get the tag */
  if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag))
    {
      rc = -8;
      goto OUT;
    }

  rc = ciphertext_len;

 OUT:
  /* Clean up */
  EVP_CIPHER_CTX_free(ctx);

  return rc;
}


static int
aes_gcm_decrypt(uint8_t *ciphertext, int ciphertext_len,
                uint8_t *aad, int aad_len,
                uint8_t *tag,
                uint8_t *key, uint8_t *iv,
                uint8_t *plaintext)
{
  EVP_CIPHER_CTX *ctx;
  int len;
  int plaintext_len;
  int rc = -1;

  /* Create and initialise the context */
  if(!(ctx = EVP_CIPHER_CTX_new()))
    return -1;

  /* Initialise the decryption operation. */
  if(!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
    {
      rc = -2;
      goto OUT;
    }

  /* Set IV length. Not necessary if this is 12 bytes (96 bits) */
  if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 16, NULL))
    {
      rc = -3;
      goto OUT;
    }

  /* Initialise key and IV */
  if(!EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv))
    {
      rc = -4;
      goto OUT;
    }

  /* Provide any AAD data. This can be called zero or more times as
   * required
   */
  if(!EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len))
    {
      rc = -5;
      goto OUT;
    }


  /* Provide the message to be decrypted, and obtain the plaintext
   * output.
   * EVP_DecryptUpdate can be called multiple times if necessary
   */
  if(!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
    {
      rc = -6;
      goto OUT;
    }
  plaintext_len = len;

  /* Set expected tag value. Works in OpenSSL 1.0.1d and later */
  if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag))
    {
      rc = -7;
      goto OUT;
    }

  /* Finalise the decryption. A positive return value indicates
   * success,
   * anything else is a failure - the plaintext is not trustworthy.
   */
  rc = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);

 OUT:
  /* Clean up */
  EVP_CIPHER_CTX_free(ctx);

  if(rc > 0)
    {
      /* Success */
      plaintext_len += len;
      return plaintext_len;

    }
  else
    {
      /* Verify failed */
      return rc;

    }
}

int
jwe_aes_key_wrap(const uint8_t kek[JWE_AESKW_KEK_SIZE],
                 const uint8_t key[JWE_AESKW_KEY_SIZE],
                 uint8_t out[JWE_AESKW_WRAPPED_SIZE])
{
  int rc = -1;
  AES_KEY wctx;

  if (AES_set_encrypt_key(kek, JWE_AESKW_KEK_SIZE * 8, &wctx))
    {
      fprintf (stderr, "%s\n", "Failed to set encrypt key");
      goto OUT;
    }


  rc = AES_wrap_key(&wctx, NULL, out, key, JWE_AESKW_KEY_SIZE);
  if (rc <= 0)
    {
      fprintf (stderr, "%s\n", "Failed to perform key wrap");
      goto OUT;
    }
  else if (JWE_AESKW_WRAPPED_SIZE == rc)
    rc = 0;


 OUT:
  return rc;
}

int
jwe_aes_key_unwrap(const uint8_t kek[JWE_AESKW_KEK_SIZE],
                   const uint8_t wkey[JWE_AESKW_WRAPPED_SIZE],
                   uint8_t out[JWE_AESKW_KEY_SIZE])
{
  int rc = -1;
  AES_KEY wctx;


  if (AES_set_decrypt_key(kek, JWE_AESKW_KEK_SIZE*8, &wctx))
    goto OUT;

  rc = AES_unwrap_key(&wctx, NULL, out, wkey, JWE_AESKW_WRAPPED_SIZE);

 OUT:
  return rc;
}

static int
bytes2b64urljsonstr (const uint8_t *data, size_t len, json_t **out)
{
  assert (data);
  assert (out);

  size_t outlen;
  const char *str;
  int rc = b64url_encode_helper (data, len, &str, &outlen);

  if (rc) goto OUT;

  *out = json_string (str);
  rc = 0;
 OUT:
  free ((void *) str);

  return rc;

}

static json_t *
create_header (jwa_t alg, jwa_t enc)
{
  json_t *hdr = NULL;

  if (A256KW != alg)
    goto OUT;
  if (A256GCM != enc)
    goto OUT;

  hdr = json_object();
  assert (hdr);

  assert (0 == json_object_set (hdr, "alg", json_string ("A256KW")));
  assert (0 == json_object_set (hdr, "enc", json_string ("A256GCM")));

  char *str = json_dumps (hdr, 0);
  int rc;
  json_t *encoded;

  rc = bytes2b64urljsonstr ((const uint8_t *)str, strlen (str), &encoded);
  if (rc) goto OUT;

  json_decref (hdr);
  free (str);
  hdr = encoded;


  OUT:
    return hdr;
}

static int
jwk2aes256kwkey (const json_t *jwk, uint8_t key[JWE_AESKW_KEK_SIZE])
{
  assert (jwk);
  int rc;

  static const char *fmt = "{s:s, s:s, s:s}";

  const char *alg;
  const char *kty;
  const char *k;

  json_error_t jerr;

  rc = json_unpack_ex ((json_t *)jwk, &jerr, JSON_STRICT, fmt,
                       "alg", &alg,
                       "kty", &kty,
                       "k", &k);

  if (rc)
    {
      fprintf (stderr, "Json Error: %s, %s, %d, %d, %d\n",
               jerr.text, jerr.source,
               jerr.line, jerr.column, jerr.position);
      return rc;
    }

  rc = strncmp ("oct", kty, strlen ("oct") + 1);
  if (rc)
    {
      fprintf (stderr, "%s\n", "Not an oct" );
      return rc;
    }

  rc = strncmp ("A256KW", alg, strlen ("A256KW") + 1);
  if (rc)
    {
      fprintf (stderr, "%s\n", "Not A256KW" );
      return rc;
    }

  rc = b64url_decode_helper (k, key, JWE_AESKW_KEK_SIZE);

  return rc;


}



static int
create_cek (const json_t *kek, const uint8_t key[JWE_AESKW_KEY_SIZE],
            json_t **cek)
{
  assert (kek);
  int rc;

  uint8_t raw_kek[JWE_AESKW_KEK_SIZE];
  uint8_t out[JWE_AESKW_WRAPPED_SIZE];

  rc = jwk2aes256kwkey (kek, raw_kek);
  if (rc)
    {
      fprintf (stderr, "%s\n", "Failed to get jwk" );
      return rc;
    }


  rc = jwe_aes_key_wrap(raw_kek, key, out);

  if (rc)
    {
      fprintf (stderr, "%s\n", "Failed to wrap key" );
      return rc;
    }

  rc = bytes2b64urljsonstr (out, JWE_AESKW_WRAPPED_SIZE, cek);

  return rc;
}

static char*
_realloc_zero (char *orig, size_t nl)
{
  size_t ol = strlen(orig);
  assert (nl > ol);
  assert (NULL != orig);

  char *out = realloc (orig, nl);
  assert (out);
  memset (out+ol, 0, nl-ol);

  return out;
}

static const char *
build_jwe (json_t *hdr, json_t *cek, json_t *iv,
           json_t *ciphertext, json_t *tag)

{
  assert (hdr);
  assert (cek);
  assert (iv);
  assert (ciphertext);
  assert (tag);

  size_t l = strlen (json_string_value (hdr));
  size_t tot = l + 2;
  char *tmp = malloc (tot);
  memset (tmp, 0, tot);
  assert (tmp);

  strncpy (tmp, json_string_value (hdr), l);
  strcat (tmp, ".");

  l = strlen (json_string_value (cek));
  tot = tot + l + 2;

  tmp = _realloc_zero (tmp, tot);

  strncat (tmp, json_string_value (cek), l);
  strcat (tmp, ".");

  /* Add iv */
  l = strlen (json_string_value (iv));
  tot = tot + l + 2;

  tmp = _realloc_zero (tmp, tot);
  assert (tmp);
  strncat (tmp, json_string_value (iv), l);
  strcat (tmp, ".");

  /* Add ciphertext */
  l = strlen (json_string_value (ciphertext));
  tot = tot + l + 2;

  tmp = _realloc_zero (tmp, tot);
  assert (tmp);
  strncat (tmp, json_string_value (ciphertext), l);
  strcat (tmp, ".");

  /* Add tag */
  l = strlen (json_string_value (tag));
  tot = tot + l + 1;

  tmp = _realloc_zero (tmp, tot);
  assert (tmp);
  strncat (tmp, json_string_value (tag), l);

  return tmp;


}

int
jwe_encrypt (jwa_t alg, jwa_t enc, const uint8_t *data, size_t len,
             const json_t *kek, const char **jwe)
{
  int rc = -1;
  assert (kek);
  assert (jwe);
  assert (data);

  json_t *hdr = create_header (alg, enc);
  if (NULL == hdr)
    return rc;

  /* Create the CEK */
  static uint8_t raw_cek[JWE_AESKW_KEY_SIZE];
  rc = RAND_bytes (raw_cek, sizeof(raw_cek));
  if (rc != 1)
    {
      goto OUT;
    }

  json_t *cek;
  rc = create_cek (kek, raw_cek, &cek);
  if (rc) goto OUT;

  /* Create an IV */
  static uint8_t raw_iv[JWE_A256GCM_IV_SIZE];
  rc = RAND_bytes (raw_iv, sizeof(raw_iv));
  if (rc != 1)
    {
      goto OUT;
    }

  json_t *iv;
  rc = bytes2b64urljsonstr (raw_iv, JWE_A256GCM_IV_SIZE, &iv);
  if (rc)
    {
      goto OUT;
    }

  /* Produce the cipher text */

  uint8_t *ciphertext = malloc (len);
  assert (ciphertext);

  const char *aad = json_string_value (hdr);
  assert (aad);

  uint8_t raw_tag[JWE_A256GCM_TAG_SIZE];

  size_t outl;
  outl = aes_gcm_encrypt(data, len, (uint8_t *) aad, strlen (aad),
                         raw_cek, raw_iv,
                         ciphertext, raw_tag);
  if (outl != len)
    {
      fprintf (stderr, "%s\n", "len mismatch");
      rc = -2;
      goto CIPHERTEXT;
    }

  rc = 0;

  json_t *cipher;
  rc = bytes2b64urljsonstr (ciphertext, len, &cipher);
  if (rc) goto CIPHERTEXT;


  json_t *tag;
  rc = bytes2b64urljsonstr (raw_tag, JWE_A256GCM_TAG_SIZE, &tag);
  if (rc) goto CIPHERTEXT;


  *jwe = build_jwe (hdr, cek, iv, cipher, tag);

 CIPHERTEXT:
  free ((void *) ciphertext);

 OUT:
  json_decref (hdr);

  return rc;

}

static int
validate_header (const char *hdr, size_t l)
{
  int rc = -1;
  const char *json_hdr;
  json_error_t jerr;

  ssize_t len = base64url_decode_alloc ((const uint8_t *)hdr, l,
                                        (char **)&json_hdr);

  if (len <= 0)
    {
      fprintf (stderr, "%s\n", "Failed to decode header");
      goto OUT;
    }


  json_t *jhdr = json_loads(json_hdr, JSON_DISABLE_EOF_CHECK, &jerr);
  if (NULL == jhdr)
    {
      fprintf (stderr, "%s: %s: %s\n", "Failed to json decode the header",
               jerr.text,
               json_hdr);
      goto OUT;
    }


  static const char *hdr_fmt = "{s:s, s:s}";

  const char *alg;
  const char *enc;


  rc = json_unpack_ex ((json_t *)jhdr, &jerr, JSON_STRICT, hdr_fmt,
                       "alg", &alg,
                       "enc", &enc);

  if (rc)
    {
      fprintf (stderr, "Json Error: %s, %s, %d, %d, %d\n",
               jerr.text, jerr.source,
               jerr.line, jerr.column, jerr.position);
      goto FREE_JSON;
    }

  rc = strncmp (alg, "A256KW", strlen("A256KW"));
  if (rc)
    {
      fprintf (stderr, "%s :%s\n", "Header alg is not A256KW", alg);
      goto FREE_JSON;
    }

  rc = strncmp (enc, "A256GCM", strlen("A256GCM"));
  if (rc)
    {
      fprintf (stderr, "%s :%s\n", "Header enc is not A256GCM", enc);
      goto FREE_JSON;
    }

  rc = 0;

 FREE_JSON:
  json_decref (jhdr);
 OUT:
  free ((void *)json_hdr);

  return rc;
}


int
jwe_decrypt (const json_t *kek, const char *jwe, uint8_t **data, size_t *len)
{
  assert (kek);
  assert (jwe);
  assert (data);
  assert (len);

  int rc = jwt_check_allowed_char (jwe, strlen (jwe));
  if (rc)
    {
      fprintf(stderr, "%s\n", "Not valid jwt characters");
      return rc;
    }

  const char *dots[4];
  rc = jwt_discerptor (jwe, &dots[0], 4);
  if (rc)
    {
      fprintf(stderr, "%s\n", "Invalid JWE format");
      return rc;
    }

  size_t jwel = strlen (jwe);
  /* split out the parts */
  size_t hdrl = dots[0] - &jwe[0];
  const char *hdr = strndup (jwe, hdrl);
  assert (hdr);

  size_t cekl = dots[1] - dots[0] -1;
  const char *cek = strndup (dots[0]+1, cekl);
  assert (cek);

  size_t ivl = dots[2] - dots[1] -1;
  const char *iv = strndup (dots[1]+1, ivl);
  assert (iv);

  size_t ciphertextl = dots[3] - dots[2] -1;
  const char *ciphertext = strndup (dots[2]+1, ciphertextl);
  assert (ciphertext);

  size_t tagl = &jwe[jwel] - dots[3] -1;
  const char *tag = strndup (dots[3]+1, tagl);
  assert (tag);

  /* Validate the header */

  rc = validate_header (hdr, hdrl);
  if (rc)
    {
      fprintf (stderr, "%s\n", "Failed to decode header");
      goto FREE;
    }

  /* Get the cek */
  uint8_t wrapped_cek[JWE_AESKW_WRAPPED_SIZE];
  rc = b64url_decode_helper (cek, wrapped_cek, JWE_AESKW_WRAPPED_SIZE);
  if (rc)
    {
      fprintf (stderr, "%s\n", "Failed to decode CEK");
      rc = -2;
      goto FREE;
    }


  uint8_t raw_kek[JWE_AESKW_KEK_SIZE];
  rc = jwk2aes256kwkey (kek, raw_kek);
  if (rc)
    {
      fprintf (stderr, "%s\n", "Failed to get jwk" );
      rc = -3;
      goto FREE;
    }

  /* Unwrap the CEK */
  uint8_t raw_cek[JWE_AESKW_KEY_SIZE];
  rc = jwe_aes_key_unwrap(raw_kek, wrapped_cek, raw_cek);

  if (JWE_AESKW_KEY_SIZE != rc)
    {
      fprintf (stderr, "%s: %d\n", "Failed unwrap cek", rc );
      goto FREE;
    }
  else
    rc = 0;

  /* Get the IV */
  uint8_t raw_iv[JWE_A256GCM_IV_SIZE];
  rc = b64url_decode_helper (iv, raw_iv, JWE_A256GCM_IV_SIZE);
  if (rc)
    {
      fprintf (stderr, "%s\n", "Invalid IV size");
      goto FREE;
    }

  /* Get the tag */
  uint8_t raw_tag[JWE_A256GCM_TAG_SIZE];
  rc = b64url_decode_helper (tag, raw_tag, JWE_A256GCM_TAG_SIZE);
  if (rc)
    {
      fprintf (stderr, "%s\n", "Invalid tag size");
      goto FREE;
    }

  /* Get the ciphertext */
  const uint8_t *raw_ciphertext;
  ssize_t raw_ciphertextl;

  raw_ciphertextl = base64url_decode_alloc (ciphertext,
                                            ciphertextl,
                                            (char**)&raw_ciphertext);
  if (raw_ciphertextl <= 0)
    {
      rc = -2;
      fprintf (stderr, "%s\n", "Failed to decode ciphertext");
      goto FREE_CIPHER;
    }
  else
    rc = 0;

  /* Make room for the plain text */
  size_t plaintextl = raw_ciphertextl;
  uint8_t *plaintext = malloc (plaintextl + 1);
  assert (plaintext);
  memset (plaintext, 0, plaintextl + 1);

  /* decrypt the ciphertext */
  size_t tmp;
  tmp = aes_gcm_decrypt((uint8_t *)raw_ciphertext, raw_ciphertextl,
                        (uint8_t *)hdr, hdrl,
                        raw_tag,
                        raw_cek,
                        raw_iv,
                        plaintext);

  if (tmp != plaintextl)
    {
      free ((void*) plaintext);
      fprintf (stderr, "%s\n", "Decryption failed");
      rc = -10;
      goto FREE_CIPHER;
    }

  /* Success, assign result */
  *data = plaintext;
  *len = plaintextl;

  rc = 0;


 FREE_CIPHER:
  free ((void *) raw_ciphertext);
 FREE:
  free ((void *)hdr);
  free ((void *) cek);
  free ((void *) iv);
  free ((void *) ciphertext);
  free ((void *) tag);

  return rc;

}



#if defined(__GNUC__) && (__GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 6))
#pragma GCC diagnostic pop
#endif

#endif /* JOSEC_HAVE_OPENSSL */
