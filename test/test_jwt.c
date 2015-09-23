#include "config.h"
#include <check.h>
#include <stdlib.h>
#include "../libjosec.h"
#include <jansson.h>
#include <assert.h>
#include <gcrypt.h>
#include <yacl.h>
#include "../src/hs256.h"
#include "soft_crypto.h"
#include "../src/jwk.h"


const char * encoded_jwk = "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU\",\"y\":\"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0\",\"d\":\"jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI\"}";

const char *encoded_jwt =
    "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q";

const char *bad_sig_encoded_jwt =
    "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6Nabc";

const char *jwt_io_hs256_full = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ";

const char *jwt_io_signing_input = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9";

static int
fill_random(uint8_t *ptr, const int len)
{
    int rc = -1;
    int fd = open("/dev/urandom");
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

    uint8_t *random;

    *out = malloc (64);

    fill_random (*out, 64);
    *out_len = 64;


    return 0;
}


START_TEST(test_jwt_creation)
{

    /* uint8_t key [32]; */
    /* uint8_t challenge [32]; */

    /* struct lca_octet_buffer k_buf; */
    /* struct lca_octet_buffer c_buf; */
    /* struct lca_octet_buffer result; */


    /* ck_assert_int_eq(fill_random(key, sizeof(key)), sizeof(key)); */
    /* ck_assert_int_eq(fill_random(challenge, sizeof(challenge)), sizeof(challenge)); */

    /* k_buf.ptr = key; */
    /* k_buf.len = sizeof(key); */

    /* c_buf.ptr = challenge; */
    /* c_buf.len = sizeof(challenge); */

    /* result = lca_soft_hmac256_defaults(c_buf, k_buf, 0); */

    /* ck_assert_int_eq(result.len, 32); */

    /* // Verify the result */
    /* ck_assert(lca_verify_hmac_defaults(c_buf, result, k_buf, 0)); */

    /* // Try to verify the key, which should fail */
    /* ck_assert(!lca_verify_hmac_defaults(c_buf, c_buf, k_buf, 0)); */

    /* // Now let's sign the hmac */

    /* gcry_sexp_t ecc; */

    /* ck_assert(lca_gen_soft_keypair (&ecc)); */

    /* struct lca_octet_buffer signature; */

    /* signature = lca_soft_sign(&ecc, result); */


    json_t *obj = json_object();

    json_object_set_new(obj, "Claims", json_integer(42));

    char *str = jwt_encode_old (obj, ES256, sign);

    printf("Result: %s\n", str);


}
END_TEST

START_TEST(t_signinput)
{
    const char *result = "eyJhbGciOiAibm9uZSJ9.eyJzdWIiOiAiQm9iIn0";

    json_t *head_j = json_object();
    json_object_set_new(head_j, "alg", json_string("none"));

    json_t *claims_j = json_object();
    json_object_set_new(claims_j, "sub", json_string("Bob"));


    char * jwt =
        make_signing_input (head_j, claims_j);

    ck_assert (0 == strcmp (result, jwt));




}
END_TEST

START_TEST(t_encode)
{
    int numtimes = sign_callback_called;

    json_t *claims_j = json_object();
    json_object_set_new(claims_j, "sub", json_string("Bob"));

    char *jwt;

    mark_point();

    jwt = jwt_encode_old (claims_j, ES256, sign);

    numtimes += 1;

    ck_assert (numtimes == sign_callback_called);
    ck_assert (NULL != jwt);

    printf ("Signed JWT: %s\n", jwt);


}
END_TEST


START_TEST(test_base64)
{
    int small = 10, med = 100;
    char *s, *m;

    s = malloc (small);
    m = malloc (med);

    ck_assert (small == fill_random (s, small));
    ck_assert (med == fill_random (m, med));

    char *in, *out;
    size_t in_len, out_len;

    in_len = base64url_encode_alloc (m, med, &in);

    ck_assert (in_len > 0);

    printf("Encoded Base64 URL Result (%zu): %s\n", in_len, in);

    out_len = base64url_decode_alloc (in, in_len, &out);

    ck_assert (out_len == med);

    ck_assert (0 == memcmp (out, m, med));

    free (in);
    free (out);

}
END_TEST

START_TEST(t_encode_helper)
{
    int med = 100;
    char *m;

    m = malloc (med);

    ck_assert (med == fill_random (m, med));

    char *in;
    size_t in_len;

    int rc = b64url_encode_helper (m, med, (const char **)&in, &in_len);

    ck_assert (0 == rc);

    printf("Encoded Base64 URL Result (%zu): %s\n", in_len, in);

    uint8_t *out = malloc (med);

    rc = b64url_decode_helper (in, out, med);

    ck_assert (rc == 0);

    ck_assert (0 == memcmp (out, m, med));

    free (in);
    free (out);
}
END_TEST


START_TEST(test_b64url2json)
{
    char * encoded = "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9";

    json_t *obj;


    obj = b64url2json (encoded, strlen(encoded));
    ck_assert (NULL != obj);

    json_t *a = json_object_get(obj, "sub");
    json_t *b = json_object_get(obj, "name");
    json_t *c = json_object_get(obj, "admin");

    ck_assert(0 == strcmp ("1234567890", json_string_value(a)));
    ck_assert(0 == strcmp ("John Doe", json_string_value(b)));
    ck_assert(json_is_true(c));

    //now try the reverse
    char *out;
    size_t s = json2b64url (obj, &out);

    ck_assert (s > 0);

    json_decref (obj);
    free (out);


}
END_TEST


START_TEST(test_jwt_verify)
{



    char *ht = "eyJhbGciOiJFUzI1NiJ9";

    json_error_t jerr;
    json_t *jwk = json_loads(encoded_jwk, 0, &jerr);
    char *dot, *dot2, *header, *claims;

    if (!jwk)
        printf("%s\n", jerr.text);

    ck_assert (NULL != jwk);

    json_t *j_x = json_object_get(jwk, "x");
    json_t *j_y = json_object_get(jwk, "y");

    ck_assert (NULL != j_x);
    ck_assert (NULL != j_y);

    printf ("x: %s\n", json_string_value (j_x));

    dot = memchr (encoded_jwt, (int)'.', strlen(encoded_jwt));


    dot2 = memchr (dot + 1, (int)'.', strlen(encoded_jwt));


    ck_assert (NULL != dot);
    ck_assert (NULL != dot2);

    size_t header_len;

    // b64 decode the header


    json_t *j_header = b64url2json (encoded_jwt, dot - encoded_jwt);
    /* header_len = base64url_decode_alloc (encoded_jwt, dot - encoded_jwt, &header); */

    /* printf("Header %d: %s\n", header_len , header); */

    /* ck_assert(header_len > 0); */

    /* json_t *j_header = json_loadb(header, header_len, 0, &jerr); */

    ck_assert (NULL != j_header);

    // b64 decode the claims
    size_t claims_len;
    claims_len = base64url_decode_alloc (dot + 1, dot2 - dot, &claims);

    printf("Claims %zu: %s\n", claims_len , claims);

    ck_assert(claims_len > 0);

    json_t *j_claims = json_loadb(claims, claims_len, 0, &jerr);

    if (!j_claims)
        printf("%s\n", jerr.text);

    ck_assert (NULL != j_claims);






}
END_TEST

START_TEST(t_jwk2pubkey)
{

    json_error_t jerr;
    json_t *jwk = json_loads(encoded_jwk, 0, &jerr);

    ck_assert (NULL != jwk);

    uint8_t pubkey[YACL_P256_COORD_SIZE*2];

    ck_assert (0 == jwk2pubkey (jwk, pubkey));

}
END_TEST

START_TEST(t_jwk2sig)
{
    const char *b64sig = "DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q";

    uint8_t sig[YACL_P256_COORD_SIZE*2];

    ck_assert (0 == jws2sig (b64sig, sig));

}
END_TEST

START_TEST(t_jwt2signinput)
{

    uint8_t digest[YACL_P256_COORD_SIZE];

    ck_assert (0 == jwt2signinput (encoded_jwt, digest));


}
END_TEST

START_TEST(t_jwtverfiy)
{
    json_error_t jerr;
    json_t *jwk = json_loads(encoded_jwk, 0, &jerr);

    ck_assert (NULL != jwk);

    ck_assert (0 == jwt_verify (jwk, encoded_jwt));

    ck_assert (0 != jwt_verify (jwk, bad_sig_encoded_jwt));
}
END_TEST

START_TEST(t_encode_none)
{
    const char *result = "eyJhbGciOiAibm9uZSJ9.eyJzdWIiOiAiQm9iIn0.";

    json_t *claims_j = json_object();


    json_object_set_new(claims_j, "sub", json_string("Bob"));

    char *jwt;


    jwt = jwt_encode_old(claims_j, NONE, NULL);

    ck_assert (NULL != jwt);

    ck_assert (0 == strcmp (result, jwt));
}
END_TEST

START_TEST(t_split)
{
    const char *jwt = "eyJhbGciOiAibm9uZSJ9.eyJzdWIiOiAiQm9iIn0.";
    json_t *header, *claims;
    int rc;

    rc = jwt_split (jwt, &header, &claims);

    printf("Split rc: %d\n", rc);

    ck_assert (0 == rc);
    ck_assert (NULL != header);
    ck_assert (NULL != claims);

    fprintf (stdout, "%s\n", "Dumping split jwt");
    fprintf (stdout, "%s: ", "Header");
    ck_assert (0 == json_dumpf(header, stdout, 0));
    fprintf (stdout, "\n");

    fprintf (stdout, "%s: ", "Claims");
    ck_assert (0 == json_dumpf(claims, stdout, 0));
    fprintf (stdout, "\n");

    json_decref (header);
    json_decref (claims);


}
END_TEST

START_TEST(t_g2jwk)
{
    gcry_sexp_t pubkey;
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
    ck_assert (0 == json_dumpf(jwk, stdout, 0));
    fprintf (stdout, "\n");

    ck_assert_str_eq("EC", json_string_value (json_object_get (jwk, "kty")));
    ck_assert_str_eq("P-256", json_string_value (json_object_get (jwk, "crv")));
    ck_assert_str_eq("sig", json_string_value (json_object_get (jwk, "use")));
    ck_assert(NULL != json_string_value (json_object_get (jwk, "x")));
    ck_assert(NULL != json_string_value (json_object_get (jwk, "y")));
    ck_assert(NULL != json_string_value (json_object_get (jwk, "d")));

    jwk = jc_eckey2jwk (x, sizeof(x), y, sizeof(y),
                        NULL, sizeof(d), "P-256",
                        "sig", "1");

    ck_assert(NULL == json_string_value (json_object_get (jwk, "d")));

}
END_TEST


START_TEST(t_hs256)
{
    char *hmac_key = "secret";

    char * result =
        hs256_encode(jwt_io_signing_input, strlen(jwt_io_signing_input),
                     (uint8_t *)hmac_key, strlen(hmac_key),
                     NULL);

    ck_assert (NULL != result);
    printf ("Calc: %s\n", result);
    printf ("expected: %s\n", jwt_io_hs256_full);

    ck_assert (0 == strcmp (result, jwt_io_hs256_full));

    free (result);

}
END_TEST

START_TEST(t_external_encode)
{
    jose_context_t ctx;
    char *hmac_key = "secret";
    char *jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9";

    json_t *header, *claims;
    int rc;

    rc = jwt_split (jwt, &header, &claims);

    ck_assert (0 == jose_create_context (&ctx, NULL, NULL, NULL));

    ck_assert (ctx.cookie == NULL);
    ck_assert (ctx.verify_func == jose_soft_verify);
    ck_assert (ctx.sign_func == jose_soft_sign);

    ck_assert (ctx.key_container[HS256].key == NULL);

    jose_key_t key;
    key.alg_type = HS256;
    key.key = (uint8_t *)hmac_key;
    key.k_len = strlen (hmac_key);

    ck_assert (0 == jose_add_key (&ctx, key));

    char *result = jwt_encode(&ctx, claims, HS256);

    ck_assert(NULL != result);

    printf ("jwt: %s\n", result);

    ck_assert (0 == jwt_verify_sig (&ctx, result, HS256));

    result[10] = 1;

    ck_assert (0 != jwt_verify_sig (&ctx, result, HS256));



}

END_TEST

START_TEST(t_context)
{
    jose_context_t ctx;
    char *hmac_key = "secret";


    ck_assert (0 == jose_create_context (&ctx, NULL, NULL, NULL));

    ck_assert (ctx.cookie == NULL);
    ck_assert (ctx.sign_func != NULL);

    ck_assert (ctx.key_container[HS256].key == NULL);

    jose_key_t key;
    key.alg_type = HS256;
    key.key = (uint8_t *)hmac_key;
    key.k_len = strlen (hmac_key);

    ck_assert (0 == jose_add_key (&ctx, key));

    ck_assert (ctx.key_container[HS256].key == hmac_key);
    ck_assert (ctx.key_container[HS256].k_len == strlen (hmac_key));
    ck_assert (ctx.key_container[HS256].alg_type == HS256);



}
END_TEST

START_TEST(t_alg_none)
{
    printf ("In t_alg_none\n");
    json_t *claims_j = json_object();
    json_object_set_new(claims_j, "sub", json_string("Bob"));

    jose_context_t ctx;

    ck_assert (0 == jose_create_context (&ctx, NULL, NULL, NULL));
    ck_assert (ctx.sign_func != NULL);
    ck_assert (ctx.verify_func != NULL);

    char * jwt =
        jwt_encode(&ctx, claims_j, NONE);

    ck_assert (NULL != jwt);
    printf ("JWT NONE: %s\n", jwt);

    ck_assert (ctx.verify_func == jose_soft_verify);

    ck_assert (0 == jwt_verify_sig(&ctx, jwt, NONE));


    json_t *h, *c;
    assert (0 == jwt_decode (jwt, &h, &c));

    json_t *sub = json_object_get(c, "sub");
    assert (0 == strcmp (json_string_value (sub), "Bob"));


    json_decref (h);
    json_decref (c);
    json_decref (claims_j);
    json_decref (sub);




}
END_TEST

START_TEST(t_msg)
{
    char *json= "{\"aud\": [\"aud\"], \"nbf\": 1430401336, \"exp\": 1430401636,"
        " \"sub\": \"sub\", \"version\": 1, \"kid\": \"none\"}";


    json_t *j = json_loads(json, 0, NULL);

    ck_assert (j != NULL);

    jose_context_t ctx;
    ck_assert (0 == jose_create_context (&ctx, NULL, NULL, NULL));
    char *jwt = jwt_encode(&ctx, j, NONE);

    ck_assert (NULL != jwt);
    printf("jwt t_msg: %s\n", jwt);

    json_decref (j);
    free (jwt);

}
END_TEST

START_TEST(t_decode_helper)
{
    size_t encode_len;
    uint8_t test[] = {0x01, 0x02, 0x03, 0x04};
    uint8_t cmp[4];
    char *out;

    encode_len = base64url_encode_alloc (test, sizeof(test),
                                         (char **)&out);

    int rc = b64url_decode_helper (out, cmp, sizeof(cmp));

    ck_assert (rc == 0);
    ck_assert (0 == memcmp (cmp, test, sizeof(test)));

    rc = b64url_decode_helper (out, cmp, sizeof(cmp) - 1);

    ck_assert (rc == sizeof(cmp));


    rc = b64url_decode_helper (test, cmp, sizeof(cmp));

    ck_assert (rc == -1);

    free (out);


}
END_TEST

START_TEST(t_jwk2rawpub)
{
    int rc;
    uint8_t pub[YACL_P256_COORD_SIZE*2];
    json_error_t jerr;
    json_t *jwk = json_loads(encoded_jwk, 0, &jerr);

    ck_assert (NULL != jwk);
    rc = jwk2rawpub (jwk, pub);

    ck_assert (rc == 0);


}
END_TEST

START_TEST(t_ecdsa_sign_verify)
{
    int rc;
    uint8_t data [] = {0x01, 0x02, 0x03, 0x04};

    json_error_t jerr;
    json_t *jwk = json_loads(encoded_jwk, 0, &jerr);
    char *b64urlsig;

    ck_assert (NULL != jwk);

    rc = jwk_ecdsa_sign (data, sizeof(data), jwk, (const char **)&b64urlsig);

    ck_assert (rc == 0);

    rc = jwk_ecdsa_verify (data, sizeof(data), b64urlsig, jwk);

    ck_assert (rc == 0);

    rc = jwk_ecdsa_verify (data, sizeof(data) - 1, b64urlsig, jwk);

    ck_assert (rc != 0);

}
END_TEST

START_TEST(t_create_key_pair)
{
    json_t *jwk = jwk_create_p256_key_pair ();

    ck_assert (NULL != jwk);

    json_t *crv = json_object_get (jwk, "crv");
    json_t *x = json_object_get (jwk, "x");
    json_t *y = json_object_get (jwk, "y");
    json_t *d = json_object_get (jwk, "d");
    json_t *kty = json_object_get (jwk, "kty");

    ck_assert (0 == strcmp ("P-256", json_string_value (crv)));
    ck_assert (NULL != x);
    ck_assert (NULL != y);
    ck_assert (NULL != d);
    ck_assert (0 == strcmp ("EC", json_string_value (kty)));

    jwk = jwk_create_es256_key_pair();

    crv = json_object_get (jwk, "crv");
    x = json_object_get (jwk, "x");
    y = json_object_get (jwk, "y");
    d = json_object_get (jwk, "d");
    kty = json_object_get (jwk, "kty");
    json_t *alg = json_object_get (jwk, "alg");

    ck_assert (0 == strcmp ("P-256", json_string_value (crv)));
    ck_assert (NULL != x);
    ck_assert (NULL != y);
    ck_assert (NULL != d);
    ck_assert (0 == strcmp ("EC", json_string_value (kty)));
    ck_assert (0 == strcmp ("ES256", json_string_value (alg)));

    /* sign verify for kicks */

    int rc;
    uint8_t data [] = {0x01, 0x02, 0x03, 0x04};

    json_error_t jerr;
    char *b64urlsig;

    rc = jwk_ecdsa_sign (data, sizeof(data), jwk, (const char **)&b64urlsig);

    ck_assert (rc == 0);

    rc = jwk_ecdsa_verify (data, sizeof(data), b64urlsig, jwk);

    ck_assert (rc == 0);



}
END_TEST

START_TEST(t_es256_encode)
{
    jose_context_t ctx;
    char *jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9";

    json_t *header, *claims;
    int rc;

    rc = jwt_split (jwt, &header, &claims);

    ck_assert (0 == jose_create_context (&ctx, NULL, NULL, NULL));

    json_t *jwk = json_loads(encoded_jwk, 0, NULL);

    ck_assert (NULL != jwk);

    ck_assert (ctx.cookie == NULL);
    ck_assert (ctx.verify_func == jose_soft_verify);
    ck_assert (ctx.sign_func == jose_soft_sign);

    ck_assert (ctx.key_container[ES256].key == NULL);

    jose_key_t key;
    key.alg_type = ES256;
    key.key = (uint8_t *)jwk;
    key.k_len = 0;

    ck_assert (0 == jose_add_key (&ctx, key));

    char *result = jwt_encode(&ctx, claims, ES256);

    ck_assert(NULL != result);

    printf ("jwt es256: %s\n", result);

    ck_assert (0 == jwt_verify_sig (&ctx, result, ES256));

    result[10] = 1;

    ck_assert (0 != jwt_verify_sig (&ctx, result, ES256));

}
END_TEST

Suite * jwt_suite(void)
{
    Suite *s;
    TCase *tc_core;

    s = suite_create("JWT");

    /* Core test case */
    tc_core = tcase_create("Core");

    tcase_add_test(tc_core, test_jwt_creation);
    tcase_add_test(tc_core, test_base64);
    tcase_add_test(tc_core, test_b64url2json);
    tcase_add_test(tc_core, t_jwk2pubkey);
    tcase_add_test(tc_core, t_jwk2sig);
    tcase_add_test(tc_core, t_jwt2signinput);
    tcase_add_test(tc_core, t_jwtverfiy);
    tcase_add_test(tc_core, t_signinput);
    //tcase_add_test(tc_core, t_encode_none);
    tcase_add_test(tc_core, t_split);
    tcase_add_test(tc_core, t_encode);
    tcase_add_test(tc_core, t_g2jwk);
    tcase_add_test(tc_core, t_hs256);
    tcase_add_test(tc_core, t_context);
    tcase_add_test(tc_core, t_external_encode);
    tcase_add_test(tc_core, t_alg_none);
    tcase_add_test(tc_core, t_msg);
    tcase_add_test(tc_core, t_decode_helper);
    tcase_add_test(tc_core, t_jwk2rawpub);
    tcase_add_test(tc_core, t_ecdsa_sign_verify);
    tcase_add_test(tc_core, t_create_key_pair);
    tcase_add_test(tc_core, t_encode_helper);
    //tcase_add_test(tc_core, test_jwt_verify);
    tcase_add_test(tc_core, t_es256_encode);
    suite_add_tcase(s, tc_core);


    return s;
}

int main(void)
{
    int number_failed;
    Suite *s;
    SRunner *sr;

    s = jwt_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
