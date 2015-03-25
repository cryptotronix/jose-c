#ifndef JOSECJWT_H_
#define JOSECJWT_H_

#include <stdint.h>
#include <jansson.h>

void
test_json();

typedef enum
{
    ES256,
    HS256
} jwa_t;


/* Sign function pointer
   const uint8_t *data_to_sign,
   const uint8_t dlen,
   const uint8_t *key,
   const uint8_t klen,
   uint8_t sign*/
typedef int (*sign_funcp)(const uint8_t *, uint8_t len,
                          const uint8_t *, uint8_t,
                          void *);

char *
jwt_encode(json_t *claims, jwa_t alg, sign_funcp sfunc);


json_t *
b64url2json (char *encoded, size_t len);

size_t
json2b64url (const json_t *j, char **out);

#endif // LIBJOSECJWT_H_
