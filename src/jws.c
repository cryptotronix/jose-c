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

    size_t jwt_len = si_len + b64sig_len + 1;

    result = malloc (jwt_len);
    assert (result);

    strncpy (result, si, si_len);
    result[si_len] = '.';

    strncpy (result + si_len + 1, b64sig, b64sig_len);

    free (b64sig);

    return result;
}
