#ifndef JOSECJWT_H_
#define JOSECJWT_H_

#include <stdint.h>
#include <jansson.h>
#include <gcrypt.h>

void
test_json();

typedef enum
{
    INVALID,
    ES256,
    HS256,
    NONE
} jwa_t;

jwa_t
jwa2enum (const char *str);

/* Sign function pointer
   const uint8_t *data_to_sign,
   size_t dlen,
   jwa_t alg,
   void *cookie,
   uint8_t **out,
   size_t *out_len

*/
typedef int (*sign_funcp)(const uint8_t *, size_t len,
                          jwa_t, void *,
                          uint8_t **, size_t *);


char *
jwt_encode(json_t *claims, jwa_t alg, sign_funcp sfunc);


json_t *
b64url2json (const char *encoded, size_t len);

size_t
json2b64url (const json_t *j, char **out);

int
jwk2pubkey (const json_t *jwk, gcry_sexp_t *pubkey);

int
jws2sig (const char* b64urlsig, gcry_sexp_t *sig);

int
jwt2signinput (const char *jwt, gcry_sexp_t *out);

int
jwt_verify (const json_t *pub_jwk, const char *jwt);

char *
make_signing_input (const json_t* header, const json_t* claims);

int
jwt_split (const char *jwt, json_t **header, json_t **claims);

#endif // LIBJOSECJWT_H_
