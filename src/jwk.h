#ifndef JOSECJWK_H_
#define JOSECJWK_H_

#include <gcrypt.h>

json_t *
gcry_pubkey2jwk (gcry_sexp_t * pubkey);



#endif
