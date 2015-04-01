#include "atecc108.h"
#include <libcryptoauth.h>

int
ecc108_sign (const uint8_t *to_sign, size_t len,
             jwa_t alg, void *cookie,
             uint8_t **out, size_t *out_len)
{

    if (32 != len)
        return -1;

    assert (NULL != to_sign);

    fd = ci2c_atmel_setup (bus, args->address);




    /* Forces a seed update on the RNG */
    struct ci2c_octet_buffer r = get_random (fd, true);

    /* Loading the nonce is the mechanism to load the SHA256
       hash into the device */
    if (load_nonce (fd, file_digest))
    {

        struct ci2c_octet_buffer rsp = ecc_sign (fd, args->key_slot);

        if (NULL != rsp.ptr)
        {
            output_hex (stdout, rsp);
            ci2c_free_octet_buffer (rsp);
            result = HASHLET_COMMAND_SUCCESS;
        }
        else
        {
            fprintf (stderr, "%s\n", "Sign Command failed.");
        }

    }

    ci2c_free_octet_buffer (r);
}
