#include "config.h"
#include <stdlib.h>
#include "../libjosec.h"
#include <jansson.h>
#include <assert.h>
#include <yacl.h>
#include "../src/hs256.h"
#include "soft_crypto.h"
#include "../src/jwk.h"
#include "base64url.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <glib.h>
#include <string.h>

#if defined(__GNUC__) && (__GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 6))
#pragma GCC diagnostic push
#endif
#pragma GCC diagnostic ignored "-Wunknown-pragmas"
#pragma GCC diagnostic ignored "-Wpragmas"
#pragma GCC diagnostic ignored "-Winitializer-overrides"
#pragma GCC diagnostic ignored "-Woverride-init"
#pragma GCC diagnostic ignored "-Wcast-qual"


const char * encoded_jwk = "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU\",\"y\":\"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0\",\"d\":\"jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI\"}";

const char *encoded_jwt =
    "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q";

const char *bad_sig_encoded_jwt =
    "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6Nabc";

const char *jwt_io_hs256_full = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ";

const char *jwt_io_signing_input = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9";

static int
fill_random(uint8_t *ptr, const size_t len)
{
    int rc = -1;
    int fd = open("/dev/urandom", O_RDONLY);
    size_t num = 0;

    if (fd < 0)
        return rc;

    while (num < len)
    {
        rc = read(fd, ptr + num, 1);
        if (rc < 0)
        {
            return rc;
        }
        else
        {
            num += rc;
        }
    }

    close (fd);

    return len;
}

int sign_callback_called = 0;

static int
sign (const uint8_t *to_sign, size_t len,
      jwa_t alg, const jct* jct,
      uint8_t **out, size_t *out_len)
{
    sign_callback_called += 1;

    *out = malloc (64);

    fill_random (*out, 64);
    *out_len = 64;


    return 0;
}


static void test_jwt_creation(void)
{

    /* uint8_t key [32]; */
    /* uint8_t challenge [32]; */

    /* struct lca_octet_buffer k_buf; */
    /* struct lca_octet_buffer c_buf; */
    /* struct lca_octet_buffer result; */


    /* g_assert_int_eq(fill_random(key, sizeof(key)), sizeof(key)); */
    /* g_assert_int_eq(fill_random(challenge, sizeof(challenge)), sizeof(challenge)); */

    /* k_buf.ptr = key; */
    /* k_buf.len = sizeof(key); */

    /* c_buf.ptr = challenge; */
    /* c_buf.len = sizeof(challenge); */

    /* result = lca_soft_hmac256_defaults(c_buf, k_buf, 0); */

    /* g_assert_int_eq(result.len, 32); */

    /* // Verify the result */
    /* g_assert(lca_verify_hmac_defaults(c_buf, result, k_buf, 0)); */

    /* // Try to verify the key, which should fail */
    /* g_assert(!lca_verify_hmac_defaults(c_buf, c_buf, k_buf, 0)); */

    /* // Now let's sign the hmac */

    /* gcry_sexp_t ecc; */

    /* g_assert(lca_gen_soft_keypair (&ecc)); */

    /* struct lca_octet_buffer signature; */

    /* signature = lca_soft_sign(&ecc, result); */


    json_t *obj = json_object();

    json_object_set_new(obj, "Claims", json_integer(42));

    char *str = jwt_encode_old (obj, ES256, sign);

    printf("Result: %s\n", str);


}


static void t_signinput(void)
{
    const char *result = "eyJhbGciOiAibm9uZSJ9.eyJzdWIiOiAiQm9iIn0";

    json_t *head_j = json_object();
    json_object_set_new(head_j, "alg", json_string("none"));

    json_t *claims_j = json_object();
    json_object_set_new(claims_j, "sub", json_string("Bob"));


    char * jwt =
        make_signing_input (head_j, claims_j);

    g_assert (0 == strcmp (result, jwt));




}


static void t_encode(void)
{
    int numtimes = sign_callback_called;

    json_t *claims_j = json_object();
    json_object_set_new(claims_j, "sub", json_string("Bob"));

    char *jwt;



    jwt = jwt_encode_old (claims_j, ES256, sign);

    numtimes += 1;

    g_assert (numtimes == sign_callback_called);
    g_assert (NULL != jwt);

    printf ("Signed JWT: %s\n", jwt);


}



static void test_base64(void)
{
    size_t small = 10, med = 100;
    char *s, *m;

    s = malloc (small);
    m = malloc (med);

    g_assert (small == (size_t)fill_random ((uint8_t *)s, small));
    g_assert (med == (size_t)fill_random ((uint8_t *)m, med));

    char *in, *out;
    size_t in_len, out_len;

    in_len = base64url_encode_alloc ((const uint8_t *)m, med, &in);

    g_assert (in_len > 0);

    printf("Encoded Base64 URL Result (%zu): %s\n", in_len, in);

    out_len = base64url_decode_alloc ((const uint8_t *)in, in_len, &out);

    g_assert (out_len == med);

    g_assert (0 == memcmp (out, m, med));

    free (in);
    free (out);

}


static void t_encode_helper(void)
{
    int med = 100;
    char *m;

    m = malloc (med);

    g_assert (med == fill_random ((uint8_t *)m, med));

    char *in;
    size_t in_len;

    int rc = b64url_encode_helper ((const uint8_t *)m, med, (const char **)&in, &in_len);

    g_assert (0 == rc);

    printf("Encoded Base64 URL Result (%zu): %s\n", in_len, in);

    uint8_t *out = malloc (med);

    rc = b64url_decode_helper (in, out, med);

    g_assert (rc == 0);

    g_assert (0 == memcmp (out, m, med));

    free (in);
    free (out);
}



static void test_b64url2json(void)
{
    const char * encoded = "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9";

    json_t *obj;


    obj = b64url2json (encoded, strlen(encoded));
    g_assert (NULL != obj);

    json_t *a = json_object_get(obj, "sub");
    json_t *b = json_object_get(obj, "name");
    json_t *c = json_object_get(obj, "admin");

    g_assert(0 == strcmp ("1234567890", json_string_value(a)));
    g_assert(0 == strcmp ("John Doe", json_string_value(b)));
    g_assert(json_is_true(c));

    //now try the reverse
    char *out;
    size_t s = json2b64url (obj, &out);

    g_assert (s > 0);

    json_decref (obj);
    free (out);


}



static void test_jwt_verify(void)
{



    //char *ht = "eyJhbGciOiJFUzI1NiJ9";

    json_error_t jerr;
    json_t *jwk = json_loads(encoded_jwk, 0, &jerr);
    char *dot, *dot2, *claims;

    if (!jwk)
        printf("%s\n", jerr.text);

    g_assert (NULL != jwk);

    json_t *j_x = json_object_get(jwk, "x");
    json_t *j_y = json_object_get(jwk, "y");

    g_assert (NULL != j_x);
    g_assert (NULL != j_y);

    printf ("x: %s\n", json_string_value (j_x));

    dot = memchr (encoded_jwt, (int)'.', strlen(encoded_jwt));


    dot2 = memchr (dot + 1, (int)'.', strlen(encoded_jwt));


    g_assert (NULL != dot);
    g_assert (NULL != dot2);

    // b64 decode the header


    json_t *j_header = b64url2json (encoded_jwt, dot - encoded_jwt);
    /* header_len = base64url_decode_alloc (encoded_jwt, dot - encoded_jwt, &header); */

    /* printf("Header %d: %s\n", header_len , header); */

    /* g_assert(header_len > 0); */

    /* json_t *j_header = json_loadb(header, header_len, 0, &jerr); */

    g_assert (NULL != j_header);

    // b64 decode the claims
    size_t claims_len;
    claims_len = base64url_decode_alloc ((const uint8_t *)(dot + 1), dot2 - dot, &claims);

    printf("Claims %zu: %s\n", claims_len , claims);

    g_assert(claims_len > 0);

    json_t *j_claims = json_loadb(claims, claims_len, 0, &jerr);

    if (!j_claims)
        printf("%s\n", jerr.text);

    g_assert (NULL != j_claims);






}


static void t_jwk2pubkey(void)
{

    json_error_t jerr;
    json_t *jwk = json_loads(encoded_jwk, 0, &jerr);

    g_assert (NULL != jwk);

    uint8_t pubkey[YACL_P256_COORD_SIZE*2];

    g_assert (0 == jwk2pubkey (jwk, pubkey));

}


static void t_jwk2sig(void)
{
    const char *b64sig = "DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q";

    uint8_t sig[YACL_P256_COORD_SIZE*2];

    g_assert (0 == jws2sig (b64sig, sig));

}


static void t_jwt2signinput(void)
{

    uint8_t digest[YACL_P256_COORD_SIZE];

    g_assert (0 == jwt2signinput (encoded_jwt, digest));


}


static void t_jwtverfiy(void)
{
    json_error_t jerr;
    json_t *jwk = json_loads(encoded_jwk, 0, &jerr);

    g_assert (NULL != jwk);

    g_assert (0 == jwt_verify (jwk, encoded_jwt));

    g_assert (0 != jwt_verify (jwk, bad_sig_encoded_jwt));
}


static void t_encode_none(void)
{
    const char *result = "eyJhbGciOiAibm9uZSJ9.eyJzdWIiOiAiQm9iIn0.";

    json_t *claims_j = json_object();


    json_object_set_new(claims_j, "sub", json_string("Bob"));

    char *jwt;


    jwt = jwt_encode_old(claims_j, NONE, NULL);

    g_assert (NULL != jwt);

    g_assert (0 == strcmp (result, jwt));
}


static void t_split(void)
{
    const char *jwt = "eyJhbGciOiAibm9uZSJ9.eyJzdWIiOiAiQm9iIn0.";
    json_t *header, *claims;
    int rc;

    rc = jwt_split (jwt, &header, &claims);

    printf("Split rc: %d\n", rc);

    g_assert (0 == rc);
    g_assert (NULL != header);
    g_assert (NULL != claims);

    fprintf (stdout, "%s\n", "Dumping split jwt");
    fprintf (stdout, "%s: ", "Header");
    g_assert (0 == json_dumpf(header, stdout, 0));
    fprintf (stdout, "\n");

    fprintf (stdout, "%s: ", "Claims");
    g_assert (0 == json_dumpf(claims, stdout, 0));
    fprintf (stdout, "\n");

    json_decref (header);
    json_decref (claims);


}


static void t_g2jwk(void)
{
    json_t *jwk;

    uint8_t x[] = {0xD4, 0xF6, 0xA6, 0x73, 0x8D, 0x9B, 0x8D, 0x3A,
                   0x70, 0x75, 0xC1, 0xE4, 0xEE, 0x95, 0x01, 0x5F,
                   0xC0, 0xC9, 0xB7, 0xE4, 0x27, 0x2D, 0x2B, 0xEB,
                   0x66, 0x44, 0xD3, 0x60, 0x9F, 0xC7, 0x81, 0xB7};

    uint8_t y[] = {0x1F, 0x9A, 0x80, 0x72, 0xF5, 0x8C, 0xB6, 0x6A,
                   0xE2, 0xF8, 0x9B, 0xB1, 0x24, 0x51, 0x87, 0x3A,
                   0xBF, 0x7D, 0x91, 0xF9, 0xE1, 0xFB, 0xF9, 0x6B,
                   0xF2, 0xF7, 0x0E, 0x73, 0xAA, 0xC9, 0xA2, 0x83};

    uint8_t d[] = {0x5A, 0x1E, 0xF0, 0x03, 0x51, 0x18, 0xF1, 0x9F,
                   0x31, 0x10, 0xFB, 0x81, 0x81, 0x3D, 0x35, 0x47,
                   0xBC, 0xE1, 0xE5, 0xBC, 0xE7, 0x7D, 0x1F, 0x74,
                   0x47, 0x15, 0xE1, 0xD5, 0xBB, 0xE7, 0x03, 0x78 };

    jwk = jc_eckey2jwk (x, sizeof(x), y, sizeof(y),
                        d, sizeof(d), "P-256",
                        "sig", "1");

    assert (NULL != jwk);

    fprintf (stdout, "%s: ", "JWK");
    g_assert (0 == json_dumpf(jwk, stdout, 0));
    fprintf (stdout, "\n");

    g_assert_cmpstr("EC", ==, json_string_value (json_object_get (jwk, "kty")));
    g_assert_cmpstr("P-256", ==, json_string_value (json_object_get (jwk, "crv")));
    g_assert_cmpstr("sig", ==, json_string_value (json_object_get (jwk, "use")));
    g_assert(NULL != json_string_value (json_object_get (jwk, "x")));
    g_assert(NULL != json_string_value (json_object_get (jwk, "y")));
    g_assert(NULL != json_string_value (json_object_get (jwk, "d")));

    jwk = jc_eckey2jwk (x, sizeof(x), y, sizeof(y),
                        NULL, sizeof(d), "P-256",
                        "sig", "1");

    g_assert(NULL == json_string_value (json_object_get (jwk, "d")));

}



static void t_hs256(void)
{
    const char *hmac_key = "secret";

    char * result =
        hs256_encode(jwt_io_signing_input, strlen(jwt_io_signing_input),
                     (uint8_t *)hmac_key, strlen(hmac_key),
                     NULL);

    g_assert (NULL != result);
    printf ("Calc: %s\n", result);
    printf ("expected: %s\n", jwt_io_hs256_full);

    g_assert (0 == strcmp (result, jwt_io_hs256_full));

    free (result);

}


static void t_external_encode(void)
{
    jose_context_t ctx;
    const char *hmac_key = "secret";
    const char *jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9";

    json_t *header, *claims;
    int rc;

    rc = jwt_split (jwt, &header, &claims);
    g_assert (0 == rc);

    g_assert (0 == jose_create_context (&ctx, NULL, NULL, NULL));

    g_assert (ctx.cookie == NULL);
    /* g_assert ((void *)ctx.verify_func == (void *)jose_soft_verify); */
    /* g_assert ((void *)ctx.sign_func == (void *)jose_soft_sign); */

    g_assert (ctx.key_container[HS256].key == NULL);

    jose_key_t key;
    key.alg_type = HS256;
    key.key = (uint8_t *)hmac_key;
    key.k_len = strlen (hmac_key);

    g_assert (0 == jose_add_key (&ctx, key));

    char *result = jwt_encode(&ctx, claims, HS256);

    g_assert(NULL != result);

    printf ("jwt: %s\n", result);

    g_assert (0 == jwt_verify_sig (&ctx, result, HS256));

    result[10] = 1;

    g_assert (0 != jwt_verify_sig (&ctx, result, HS256));



}



static void t_context(void)
{
    jose_context_t ctx;
    const char *hmac_key = "secret";


    g_assert (0 == jose_create_context (&ctx, NULL, NULL, NULL));

    g_assert (ctx.cookie == NULL);
    g_assert (ctx.sign_func != NULL);

    g_assert (ctx.key_container[HS256].key == NULL);

    jose_key_t key;
    key.alg_type = HS256;
    key.key = (uint8_t *)hmac_key;
    key.k_len = strlen (hmac_key);

    g_assert (0 == jose_add_key (&ctx, key));

    g_assert ((void *)ctx.key_container[HS256].key == (void *)hmac_key);
    g_assert (ctx.key_container[HS256].k_len == strlen (hmac_key));
    g_assert (ctx.key_container[HS256].alg_type == HS256);



}


static void t_alg_none(void)
{
    printf ("In t_alg_none\n");
    json_t *claims_j = json_object();
    json_object_set_new(claims_j, "sub", json_string("Bob"));

    jose_context_t ctx;

    g_assert (0 == jose_create_context (&ctx, NULL, NULL, NULL));
    g_assert (ctx.sign_func != NULL);
    g_assert (ctx.verify_func != NULL);

    char * jwt =
        jwt_encode(&ctx, claims_j, NONE);

    g_assert (NULL != jwt);
    printf ("JWT NONE: %s\n", jwt);

    g_assert ((void *)ctx.verify_func == (void *)jose_soft_verify);

    g_assert (0 == jwt_verify_sig(&ctx, jwt, NONE));


    json_t *h, *c;
    assert (0 == jwt_decode (jwt, &h, &c));

    json_t *sub = json_object_get(c, "sub");
    assert (0 == strcmp (json_string_value (sub), "Bob"));


    json_decref (h);
    json_decref (c);
    json_decref (claims_j);
    json_decref (sub);




}


static void t_msg(void)
{
    const char *json= "{\"aud\": [\"aud\"], \"nbf\": 1430401336, \"exp\": 1430401636,"
        " \"sub\": \"sub\", \"version\": 1, \"kid\": \"none\"}";


    json_t *j = json_loads(json, 0, NULL);

    g_assert (j != NULL);

    jose_context_t ctx;
    g_assert (0 == jose_create_context (&ctx, NULL, NULL, NULL));
    char *jwt = jwt_encode(&ctx, j, NONE);

    g_assert (NULL != jwt);
    printf("jwt t_msg: %s\n", jwt);

    json_decref (j);
    free (jwt);

}


static void t_decode_helper(void)
{
    size_t encode_len;
    uint8_t test[] = {0x01, 0x02, 0x03, 0x04};
    uint8_t cmp[4];
    char *out;

    encode_len = base64url_encode_alloc (test, sizeof(test),
                                         (char **)&out);

    g_assert (encode_len > sizeof (test));

    int rc = b64url_decode_helper (out, cmp, sizeof(cmp));

    g_assert (rc == 0);
    g_assert (0 == memcmp (cmp, test, sizeof(test)));

    rc = b64url_decode_helper (out, cmp, sizeof(cmp) - 1);

    g_assert (rc == sizeof(cmp));


    rc = b64url_decode_helper ((const char *)test, cmp, sizeof(cmp));

    g_assert (rc == -1);

    free (out);


}


static void t_jwk2rawpub(void)
{
    int rc;
    uint8_t pub[YACL_P256_COORD_SIZE*2];
    json_error_t jerr;
    json_t *jwk = json_loads(encoded_jwk, 0, &jerr);

    g_assert (NULL != jwk);
    rc = jwk2rawpub (jwk, pub);

    g_assert (rc == 0);


}


static void t_ecdsa_sign_verify(void)
{
    int rc;
    uint8_t data [] = {0x01, 0x02, 0x03, 0x04};

    json_error_t jerr;
    json_t *jwk = json_loads(encoded_jwk, 0, &jerr);
    char *b64urlsig;

    g_assert (NULL != jwk);

    rc = jwk_ecdsa_sign (data, sizeof(data), jwk, (const char **)&b64urlsig);

    g_assert (rc == 0);

    rc = jwk_ecdsa_verify (data, sizeof(data), b64urlsig, jwk);

    g_assert (rc == 0);

    rc = jwk_ecdsa_verify (data, sizeof(data) - 1, b64urlsig, jwk);

    g_assert (rc != 0);

}


static void t_create_key_pair(void)
{
    json_t *jwk = jwk_create_p256_key_pair ();

    g_assert (NULL != jwk);

    json_t *crv = json_object_get (jwk, "crv");
    json_t *x = json_object_get (jwk, "x");
    json_t *y = json_object_get (jwk, "y");
    json_t *d = json_object_get (jwk, "d");
    json_t *kty = json_object_get (jwk, "kty");

    g_assert (0 == strcmp ("P-256", json_string_value (crv)));
    g_assert (NULL != x);
    g_assert (NULL != y);
    g_assert (NULL != d);
    g_assert (0 == strcmp ("EC", json_string_value (kty)));

    jwk = jwk_create_es256_key_pair();

    crv = json_object_get (jwk, "crv");
    x = json_object_get (jwk, "x");
    y = json_object_get (jwk, "y");
    d = json_object_get (jwk, "d");
    kty = json_object_get (jwk, "kty");
    json_t *alg = json_object_get (jwk, "alg");

    g_assert (0 == strcmp ("P-256", json_string_value (crv)));
    g_assert (NULL != x);
    g_assert (NULL != y);
    g_assert (NULL != d);
    g_assert (0 == strcmp ("EC", json_string_value (kty)));
    g_assert (0 == strcmp ("ES256", json_string_value (alg)));

    /* sign verify for kicks */

    int rc;
    uint8_t data [] = {0x01, 0x02, 0x03, 0x04};

    char *b64urlsig;

    rc = jwk_ecdsa_sign (data, sizeof(data), jwk, (const char **)&b64urlsig);

    g_assert (rc == 0);

    rc = jwk_ecdsa_verify (data, sizeof(data), b64urlsig, jwk);

    g_assert (rc == 0);



}


static void t_es256_encode(void)
{
    jose_context_t ctx;
    const char *jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9";

    json_t *header, *claims;
    int rc;

    rc = jwt_split (jwt, &header, &claims);

    g_assert (0 == rc);

    g_assert (0 == jose_create_context (&ctx, NULL, NULL, NULL));

    json_t *jwk = json_loads(encoded_jwk, 0, NULL);

    g_assert (NULL != jwk);

    g_assert (ctx.cookie == NULL);
    g_assert ((void *)ctx.verify_func == (void *)jose_soft_verify);
    g_assert ((void *)ctx.sign_func == (void *)jose_soft_sign);

    g_assert (ctx.key_container[ES256].key == NULL);

    jose_key_t key;
    key.alg_type = ES256;
    key.key = (uint8_t *)jwk;
    key.k_len = 0;

    g_assert (0 == jose_add_key (&ctx, key));

    char *result = jwt_encode(&ctx, claims, ES256);

    g_assert(NULL != result);

    printf ("jwt es256: %s\n", result);

    g_assert (0 == jwt_verify_sig (&ctx, result, ES256));

    result[10] = 1;

    g_assert (0 != jwt_verify_sig (&ctx, result, ES256));

}


static void t_ecdh(void)
{
    json_t *alice = jwk_create_p256_key_pair ();
    json_t *bob = jwk_create_p256_key_pair ();

    g_assert (NULL != alice);
    g_assert (NULL != bob);

    int rc;

    uint8_t * alice_secret;
    size_t as_len;
    uint8_t * bob_secret;
    size_t bob_len;

    rc = jwa_ecdh (alice, bob, &alice_secret, &as_len);

    g_assert (rc == 0);
    g_assert (as_len == 32);
    g_assert (NULL != alice_secret);

    rc = jwa_ecdh (bob, alice, &bob_secret, &bob_len);

    g_assert (rc == 0);
    g_assert (bob_len == 32);
    g_assert (NULL != bob_secret);

    rc = memcmp (alice_secret, bob_secret, as_len);

    g_assert (0 == rc);



}


static void t_regexp(void)
{
#define NUM_REG_TESTS 3

    const char *jwt1 = "abcd.defgt.adr";
    const char *jwt2 = "abcd.def8gt.adr";
    const char *jwt3 = "abcd-.def8gt_.adr-_";
    const char *jwt4 = "abcd-.def8gt_.";
    const char *jwt5 = "abcd-.def8gt_.=";


    int rc = jwt_check_allowed_char (jwt1, strlen(jwt1));
    g_assert_cmpint (rc, ==, 0);


    rc = jwt_check_allowed_char (jwt2, strlen(jwt2));
    g_assert (0 == rc);

    rc = jwt_check_allowed_char (jwt3, strlen(jwt3));
    g_assert (0 == rc);

    rc = jwt_check_allowed_char (jwt4, strlen(jwt4));
    g_assert (0 == rc);

    rc = jwt_check_allowed_char (jwt5, strlen(jwt5));
    g_assert (0 != rc);

}


static void t_discerptor(void)
{
    const char *jwt1 = "aaa.bbb.ccc";

    const char *dots[20];

    int rc = jwt_discerptor (jwt1, &dots, 2);

    g_assert (rc == 0);

    g_assert ((void *)dots[0] == (void *)&jwt1[3]);
    g_assert ((void *)dots[1] == (void *)&jwt1[7]);

    g_assert (3 == dots[0] - &jwt1[0]);
    rc = jwt_discerptor(jwt1, dots, 1);
    g_assert (rc == -1);


    rc = jwt_discerptor(jwt1, dots, 3);
    g_assert (rc == -2);

}



int
main(int argc, char *argv[])
{
    g_test_init (&argc, &argv, NULL);

    g_test_add_func ("/jwt/test_jwt_creation", test_jwt_creation);
    g_test_add_func ("/jwt/test_base64", test_base64);
    g_test_add_func ("/jwt/test_b64url2json", test_b64url2json);
    g_test_add_func ("/jwt/t_jwk2pubkey", t_jwk2pubkey);
    g_test_add_func ("/jwt/t_jwk2sig", t_jwk2sig);
    g_test_add_func ("/jwt/t_jwt2signinput", t_jwt2signinput);
    g_test_add_func ("/jwt/t_jwtverfiy", t_jwtverfiy);
    g_test_add_func ("/jwt/t_signinput", t_signinput);
    g_test_add_func ("/jwt/t_split", t_split);
    g_test_add_func ("/jwt/t_encode", t_encode);
    g_test_add_func ("/jwt/t_g2jwk", t_g2jwk);
    g_test_add_func ("/jwt/t_hs256", t_hs256);
    g_test_add_func ("/jwt/t_context", t_context);
    g_test_add_func ("/jwt/t_external_encode", t_external_encode);
    g_test_add_func ("/jwt/t_alg_none", t_alg_none);
    g_test_add_func ("/jwt/t_msg", t_msg);
    g_test_add_func ("/jwt/t_decode_helper", t_decode_helper);
    g_test_add_func ("/jwt/t_jwk2rawpub", t_jwk2rawpub);
    g_test_add_func ("/jwt/t_ecdsa_sign_verify", t_ecdsa_sign_verify);
    g_test_add_func ("/jwt/t_create_key_pair", t_create_key_pair);
    g_test_add_func ("/jwt/t_encode_helper", t_encode_helper);
    g_test_add_func ("/jwt/t_es256_encode", t_es256_encode);
    g_test_add_func ("/jwt/t_ecdh", t_ecdh);
    g_test_add_func ("/jwt/t_regexp", t_regexp);
    g_test_add_func ("/jwt/t_discerptor", t_discerptor);


    return g_test_run ();
}


#if defined(__GNUC__) && (__GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 6))
#pragma GCC diagnostic pop
#endif
