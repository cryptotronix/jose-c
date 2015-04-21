#ifndef JOSECJWS_H_
#define JOSECJWS_H_

#include <stdint.h>

char *
jws_append_signing_input (const char* si, int si_len,
                          const uint8_t *sig, int sig_len);

#endif
