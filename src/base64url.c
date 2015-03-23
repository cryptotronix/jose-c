/* some very basic public-domain base64 functions */

#include "base64url.h"
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <base64.h>

size_t
base64url_encode (const uint8_t *data, size_t len, char **out)
{
    int i;

    assert(NULL != data);

    size_t s = base64_encode_alloc (data, len, out);

    char *burl = *out;

    for (i = 0; i < s; i++)
    {
        if ('+' == *(burl+i))
            *(burl+i) = '-';
        else if ('/' == *(burl+i))
            *(burl+i) = '_';
        else if ('=' == *(burl+i))
            *(burl+i) = 0;
    }

    return s;
}
