#ifndef JOSECJWT_H_
#define JOSECJWT_H_

#include <stdint.h>
#include <jansson.h>
#include <yacl.h>
#include "jwa.h"
#include "../libjosec.h"

char *
jwt_encode_old(json_t *claims, jwa_t alg, sign_funcp sfunc);

json_t *
b64url2json (const char *encoded, size_t len);

size_t
json2b64url (const json_t *j, char **out);

int
jwk2pubkey (const json_t *jwk, uint8_t pubkey[YACL_P256_COORD_SIZE*2]);

int
jws2sig (const char* b64urlsig, uint8_t sig[YACL_P256_COORD_SIZE*2]);

int
jwt2signinput (const char *jwt, uint8_t out[YACL_P256_COORD_SIZE]);

int
jwt_verify (const json_t *pub_jwk, const char *jwt);

char *
make_signing_input (const json_t* header, const json_t* claims);

int
jwt_split (const char *jwt, json_t **header, json_t **claims);

int
jwt_discerptor (const char *jwt, const char **dots, int num_dots);
#endif // LIBJOSECJWT_H_
