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
    int i;

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
    int i;
    size_t s, pad;
    char *burl;
    size_t len;

    assert(NULL != data);

    len = strnlen (data, l);

    pad = len + (4 - len % 4) % 4;

    printf ("\npad: %d len: %d\n", pad, len);

    assert (pad >= len);

    burl = malloc (pad + 1);
    assert (NULL != burl);
    memset (burl, 0, pad + 1);

    strncpy (burl, data, len);

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

    printf ("To b64 decode: %s\n", burl);
    if (!base64_decode_alloc (burl, pad, out, &s))
    {
        printf ("DECODE FAILED\n");
        s = -1;
    }

    free (burl);

    return s;
}
