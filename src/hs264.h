#ifndef JOSECHS264_H_
#define JOSECHS264_H_

#include "jwt.h"



char *
hs264_encode(const char *signing_input, int si_len,
             const uint8_t *key, int k_len,
             sign_funcp sfunc);



#endif
