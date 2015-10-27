/* some very basic public-domain base64 functions */

#include "base64url.h"
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <base64.h>
#include <stdlib.h>

size_t
base64url_encode_alloc (const uint8_t *data, size_t len, char **out)
{
    size_t i;

    assert(NULL != data);
    assert(NULL != out);

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

    return strnlen (burl, s);
}


size_t
base64url_decode_alloc (const uint8_t *data, size_t l, char **out)
{
    size_t i, s, pad;
    char *burl;
    size_t len;

    assert(NULL != data);

    len = strnlen ((const char *)data, l);

    pad = len + (4 - len % 4) % 4;

    assert (pad >= len);

    burl = malloc (pad + 1);
    assert (NULL != burl);
    memset (burl, 0, pad + 1);

    strncpy (burl, (const char *)data, len);

    for (i = 0; i < len; i++)
    {
        if ('-' == *(burl+i))
            *(burl+i) = '+';
        else if ('_' == *(burl+i))
            *(burl+i) = '/';
    }

    for (i = 0; i < (pad - len); i++)
    {
        burl[len + i] = '=';
    }

    if (!base64_decode_alloc (burl, pad, out, &s))
    {
        s = 0;
    }

    free (burl);

    return s;
}


int
b64url_encode_helper (const uint8_t *to_enc, size_t inlen,
                      const char **out, size_t *outlen)
{
    assert (to_enc);
    assert (out);
    assert (outlen);

    int rc = -1;

    size_t result = base64url_encode_alloc (to_enc, inlen, (char **)out);

    if (result > 0)
    {
        rc = 0;
        *outlen = result;
    }

    return rc;

}
