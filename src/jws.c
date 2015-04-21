#include "config.h"
#include "jws.h"
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <gcrypt.h>
#include "base64url.h"

char *
jws_append_signing_input (const char* si, int si_len,
                          const uint8_t *sig, int sig_len)
{
    char *b64sig;
    size_t b64sig_len;
    char *result;

    assert (si);
    assert (sig);

    b64sig_len = base64url_encode_alloc (sig, sig_len, &b64sig);

    size_t jwt_len = si_len + b64sig_len + 2;

    result = malloc (jwt_len);
    memset (result, 0, jwt_len);
    assert (result);

    strncpy (result, si, si_len);

    result[si_len] = '.';

    strncpy (result + si_len + 1, b64sig, b64sig_len);

    free (b64sig);

    return result;
}

char *
jws2signing_input (const char *jwt)
{
    assert (NULL != jwt);

    char *dot;
    int sign_input_len;
    char *si;

    dot = (char *)memrchr (jwt, (int)'.', strlen(jwt));

    if(NULL == dot)
        return NULL;

    sign_input_len = dot - jwt + 1;

    si = malloc(sign_input_len);
    memset (si, 0, sign_input_len);

    memcpy(si, jwt, dot - jwt);

    return si;
}
