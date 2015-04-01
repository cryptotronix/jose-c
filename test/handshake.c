#include "config.h"
#include <stdio.h>
#include <curl/curl.h>
#include <libcryptoauth.h>
#include <jansson.h>
#include "../libjosec.h"
#include <assert.h>
#include <gcrypt.h>
#include "trim.h"


char *a = "http://54.69.3.27:8081/putMicroPodPublicKey?jwt=eyJhbGciOiJFUzI1NiJ9.eyJjaGlwaWQyIjoiMSIsImNoaXBpZDEiOiIzIiwic3ViIjoicG1Xa1dTQkNMNTFCZmtobjc5eFB1S0JLSHpfX0g2Qi1tWTZHOV9laWV1TSIsImNoaXBpZDMiOiIyIiwiYXVkIjoiZG0iLCJwdWJrZXkiOnsiYWxnIjoiRVMyNTYiLCJjcnYiOiJQLTI1NiIsImt0eSI6IkVDIiwidXNlIjoic2lnIiwieSI6ImtfNVFHclRMRGdEaE5RYkxORVZCVWNEWkFFM0V0akdvX2hiclRITUREd2MiLCJ4IjoibTd0Rl90X2s0RlBNNGRKdTIyNExBdFRGUEhibmJqVUxmbWFOTHQ4WXRLZyIsImtpZCI6IjE0Mjc4NTY0NjI2NzkifX0.I9r7ZbzMf70Xy4s0kQPg6ONSrdmRA6-7pW8sLD5xYMKVoqy27hqpJgco8dfJhGNytGKhizXCoe_aK40IcSD-uQ";

char *sub = "pmWkWSBCL51Bfkhn79xPuKBKHz__H6B-mY6G9_eieuM";

char *postkey = "http://54.69.3.27:8081/putMicroPodPublicKey?jwt=";
char *getkey = "http://54.69.3.27:8082/getDeviceManagerPublicKey?jwt=";
char *posthello = "http://54.69.3.27:8083/doHandShakeHandOff?jwt=";
char *postdone = "http://54.69.3.27:8083/doHandShakeHandOff?jwt=";

uint8_t apk[] = {0xDA, 0xBF, 0x38, 0x5B, 0xE2, 0xC4, 0x81, 0x7F, 0x3B, 0x71, 0x70, 0xA0, 0x59, 0xA4, 0xC4, 0x9B, 0xBC, 0x16, 0x41, 0x35, 0x29, 0x7B, 0x6C, 0x20, 0xEB, 0xFA, 0x81, 0x2D, 0x8C, 0x55, 0x9E, 0x16, 0x76, 0x6D, 0xC3, 0x63, 0x3F, 0x43, 0xF6, 0x6B, 0x25, 0xDD, 0xE3, 0xE3, 0xE6, 0x02, 0xCE, 0x7E, 0xCC, 0x91, 0x68, 0xE9, 0x36, 0x99, 0x79, 0x63, 0x06, 0x2D, 0xA1, 0x7A, 0x11, 0x6B, 0x5A, 0xA6};

gcry_sexp_t signing_key;

struct MemoryStruct {
char *memory;
    size_t size;
};

int ecc108_fd;

int
start ()
{
    int fd = lca_atmel_setup ("/dev/i2c-0", 0x60);

    lca_get_random (fd, true);

    struct lca_octet_buffer pubkey =
        lca_gen_ecc_key (fd, 0, false);

    lca_set_log_level (DEBUG);
    lca_print_hex_string ("pubkey", pubkey.ptr, pubkey.len);

    lca_idle (fd);

    ecc108_fd = fd;

    return fd;

}


int
hard_sign (const uint8_t *to_sign, size_t len,
           jwa_t alg, void *cookie,
           uint8_t **out, size_t *out_len)
{
    int fd = ecc108_fd;
    int rc = -1;
    struct lca_octet_buffer hash;
    gcry_sexp_t sig, digest;

    const unsigned int DLEN = gcry_md_get_algo_dlen (GCRY_MD_SHA256);
    hash.ptr = malloc (DLEN);
    hash.len = DLEN;
    assert (NULL != hash.ptr);

    gcry_md_hash_buffer (GCRY_MD_SHA256, hash.ptr, to_sign, len);

    lca_set_log_level (DEBUG);
    lca_print_hex_string ("hash: ", hash.ptr, hash.len);
    lca_set_log_level (INFO);

    lca_wakeup(fd);

    struct lca_octet_buffer r =
        gen_nonce (fd, hash);

    assert (NULL != r.ptr);

    struct lca_octet_buffer s =
        lca_ecc_sign (fd, 0);

    assert (NULL != s.ptr);

    *out = s.ptr;
    *out_len = s.len;

    /* verify sig */
    r =
        gen_nonce (fd, hash);

    assert (NULL != r.ptr);

    struct lca_octet_buffer apkb = lca_make_buffer (sizeof (apk));

    memcpy (apkb.ptr, apk, sizeof(apk));



    assert (lca_ecc_verify (fd, apkb, s));

    lca_idle (fd);

    lca_set_log_level (DEBUG);
    lca_print_hex_string ("Signature: ", s.ptr, s.len);
    lca_set_log_level (INFO);

    printf ("Len: %d\n", s.len);


    return 0;
}

static size_t
WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)
{
    size_t realsize = size * nmemb;
    struct MemoryStruct *mem = (struct MemoryStruct *)userp;

    mem->memory = realloc(mem->memory, mem->size + realsize + 1);
    if(mem->memory == NULL) {
        /* out of memory! */
        printf("not enough memory (realloc returned NULL)\n");
        return 0;
    }

    memcpy(&(mem->memory[mem->size]), contents, realsize);
    mem->size += realsize;
    mem->memory[mem->size] = 0;

    return realsize;
}

int
soft_sign (const uint8_t *to_sign, size_t len,
      jwa_t alg, void *cookie,
      uint8_t **out, size_t *out_len)
{


    int rc = -1;
    uint8_t *hash;
    gcry_sexp_t sig, digest;

    const unsigned int DLEN = gcry_md_get_algo_dlen (GCRY_MD_SHA256);
    hash = malloc (DLEN);
    assert (NULL != hash);

    gcry_md_hash_buffer (GCRY_MD_SHA256, hash, to_sign, len);

    rc = gcry_sexp_build (&digest, NULL,
                          "(data (flags raw)\n"
                          " (value %b))",
                          DLEN, hash);

    if (rc)
        goto OUT;

    if (rc = gcry_pk_sign (&sig, digest, signing_key))
        goto DIG;

    lca_print_sexp (sig);

    struct lca_octet_buffer signature = lca_sig2buf (&sig);

    if (NULL != signature.ptr)
    {
        *out = signature.ptr;
        *out_len = signature.len;
        rc = 0;
    }

    gcry_free (sig);


DIG:
    gcry_free (digest);
OUT:
    free (hash);
    assert (0 == rc);
    return rc;
}

char *
build_key_post (json_t *jwk)
{

    json_t *obj = json_object();

    json_object_set_new(obj, "chipid2", json_string("1"));
    json_object_set_new(obj, "sub", json_string(sub));
    json_object_set_new(obj, "chipid1", json_string("3"));
    json_object_set_new(obj, "aud", json_string("dm"));
    json_object_set_new(obj, "chipid3", json_string("2"));
    json_object_set_new(obj, "pubkey", jwk);

    char * jwt = jwt_encode (obj, ES256, hard_sign);

    return jwt;

}

char *
combine (const char *uri, const char* jwt)
{
    size_t l1, l2, tot;
    char *r;

    l1 = strlen (uri);
    l2 = strlen (jwt);

    tot = l1 + l2 + 1;

    r = malloc (tot);
    assert (NULL != r);

    memset (r, 0, tot);

    strcpy (r, uri);
    strcpy (r + l1, jwt);

    return r;

}

struct MemoryStruct
get (char *uri)
{

    CURL *curl_handle;
    CURLcode res;

    struct MemoryStruct chunk;

    chunk.memory = malloc(1);  /* will be grown as needed by the realloc above */
    chunk.size = 0;    /* no data at this point */

      /* init the curl session */
  curl_handle = curl_easy_init();

  /* specify URL to get */
  curl_easy_setopt(curl_handle, CURLOPT_URL, uri);

  /* send all data to this function  */
  curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);

  /* we pass our 'chunk' struct to the callback function */
  curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, (void *)&chunk);

  /* some servers don't like requests that are made without a user-agent
     field, so we provide one */
  curl_easy_setopt(curl_handle, CURLOPT_USERAGENT, "libcurl-agent/1.0");

  /* get it! */
  res = curl_easy_perform(curl_handle);

  /* check for errors */
  if(res != CURLE_OK) {
    fprintf(stderr, "curl_easy_perform() failed: %s\n",
            curl_easy_strerror(res));
  }
  else {
    /*
     * Now, our chunk.memory points to a memory block that is chunk.size
     * bytes big and contains the remote file.
     *
     * Do something nice with it!
     */
      long rcode;
      curl_easy_getinfo (curl_handle, CURLINFO_RESPONSE_CODE, &rcode);

      printf("Response Code: %lu\n", rcode);
      printf("%lu bytes retrieved\n", (long)chunk.size);
      printf("Got: %s\n", chunk.memory);
  }

  //free(chunk.memory);

  /* cleanup curl stuff */
  curl_easy_cleanup(curl_handle);

  return chunk;

}

json_t *
get_dm_key (const char *jwt)
{
    json_t *header, *claims;
    gcry_sexp_t pubk;

    assert (0 == jwt_split (trim (jwt), &header, &claims));

    json_t * pub = json_object_get (claims, "pubkey");

    assert (0 == jwk2pubkey (pub, &pubk));

    assert (0 == jwt_verify (pub, trim(jwt)));

    return pub;


}

char *
build_hello (char *sub)
{

    uint8_t *nonce = malloc (32);

    gcry_create_nonce (nonce, 32);

    char *bnonce;
    int nl = base64url_encode_alloc (nonce, 32, &bnonce);

    time_t current_time;
    current_time = time(NULL);

    json_t *obj = json_object();



    json_object_set_new(obj, "jti", json_string(bnonce));
    json_object_set_new(obj, "sub", json_string(sub));
    json_object_set_new(obj, "Version", json_integer(1));
    json_object_set_new(obj, "msg_id", json_integer(1));

    json_object_set_new(obj, "iat", json_integer (current_time));
    json_object_set_new(obj, "exp", json_integer (current_time + 60 * 5));


    char * jwt = jwt_encode (obj, ES256, hard_sign);

    assert (NULL != jwt);

    return jwt;
}

char *
build_hello_rsp (char *sub, json_t *hellorsp)
{

    uint8_t *nonce = malloc (32);

    gcry_create_nonce (nonce, 32);

    char *bnonce;
    int nl = base64url_encode_alloc (nonce, 32, &bnonce);

    time_t current_time;
    current_time = time(NULL);

    json_t *obj = json_object();

    double msg_id = json_number_value( json_object_get (hellorsp, "msg_id"));

    const char *snonce = json_string_value( json_object_get (hellorsp, "jti"));

    json_object_set_new(obj, "jti", json_string(bnonce));
    json_object_set_new(obj, "sub", json_string(sub));
    json_object_set_new(obj, "snonce", json_string(snonce));
    json_object_set_new(obj, "Version", json_integer(1));
    json_object_set_new(obj, "msg_id", json_integer(msg_id + 1));

    json_object_set_new(obj, "iat", json_integer (current_time));
    json_object_set_new(obj, "exp", json_integer (current_time + 60 * 5));


    char * jwt = jwt_encode (obj, ES256, hard_sign);

    assert (NULL != jwt);

    return jwt;
}

json_t *
verify_hello (const char *jwt, json_t *pub)
{
    json_t *header, *claims;

    assert (0 == jwt_split (trim (jwt), &header, &claims));
    assert (0 == jwt_verify (pub, trim(jwt)));

    return claims;


}

json_t *
verify_done (const char *jwt, json_t *pub)
{
    json_t *header, *claims;

    assert (0 == jwt_split (trim (jwt), &header, &claims));
    assert (0 == jwt_verify (pub, trim(jwt)));

    return claims;


}


int main(void)
{


    json_t *jwk;
    struct MemoryStruct res;
    struct timeval tval_before, tval_after, tval_result;

    lca_init();

    int fd = start();

    if (lca_load_signing_key ("test_keys/atmel.key", &signing_key))
        return -1;

    jwk = gcry_pubkey2jwk (&signing_key);

    assert (NULL != jwk);

    json_dumpf (jwk, stdout, 0);


    char *m1 = build_key_post (jwk);

    printf ("Post key: %s\n", m1);

    char *b = combine (postkey, m1);
    char *c = combine (getkey, m1);

    /* char *b = malloc (strlen(m1) + strlen(postkey) + 1); */
    /* memset (b, 0, strlen(m1) + strlen(postkey) + 1); */

    /* printf ("here"); */

    /* strcpy (b, postkey); */
    /* strcat (postkey, m1); */



  curl_global_init(CURL_GLOBAL_ALL);


  res = get (b);

  free (res.memory);

  res = get (c);

  json_t *dm_key = get_dm_key (res.memory);

  free (res.memory);

  char *hello = build_hello (sub);

  gettimeofday(&tval_before, NULL);

  char *d = combine (posthello, hello);

  res = get (d);

  json_t *hello_rsp = verify_hello (res.memory, dm_key);
  free (res.memory);

  char *done = build_hello_rsp (sub, hello_rsp);
  char *e = combine (postdone, done);

  res = get (e);

  json_t *done_rsp = verify_done (res.memory, dm_key);
  free (res.memory);

  gettimeofday(&tval_after, NULL);

  free (e);
  free (d);
  free (b);
  free (c);
  /* we're done with libcurl, so clean it up */
  curl_global_cleanup();

  timersub(&tval_after, &tval_before, &tval_result);

  printf("Time elapsed: %ld.%06ld\n", (long int)tval_result.tv_sec, (long int)tval_result.tv_usec);

  return 0;

}
