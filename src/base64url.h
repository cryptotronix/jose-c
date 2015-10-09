#ifndef b64_h
#define b64_h

#include "config.h"
#include <stddef.h>
#include <stdint.h>
#include <base64.h>
#include <stdlib.h>

// length of data resulting from encoding/decoding
#define base64_encode_length(x) (8 * (((x) + 2) / 6)) + 1
#define base64_decode_length(x) ((((x) + 2) * 6) / 8)

// Encode and malloc out
size_t
base64url_encode_alloc (const uint8_t *data, size_t len, char **out);

ssize_t
base64url_decode_alloc (const uint8_t *data, size_t len, char **out);

#endif
