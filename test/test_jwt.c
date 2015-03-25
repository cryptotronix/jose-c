#include <check.h>
#include <stdlib.h>
#include "../libjosec.h"
#include <jansson.h>
#include <assert.h>
#include <gcrypt.h>


const char * encoded_jwk = "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU\",\"y\":\"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0\",\"d\":\"jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI\"}";

const char *encoded_jwt =
    "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q";

const char *bad_sig_encoded_jwt =
    "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6Nabc";

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

static int
sign (const uint8_t *to_sign, uint8_t slen,
      const uint8_t *key, uint8_t klen, void *cookie)
{
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

    char *str = jwt_encode (obj, ES256, sign);

    printf("Result: %s\n", str);


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

    printf("Encoded Base64 URL Result (%d): %s\n", in_len, in);

    out_len = base64url_decode_alloc (in, in_len, &out);

    ck_assert (out_len == med);

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

    printf("Claims %d: %s\n", claims_len , claims);

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

    gcry_sexp_t pubkey;

    ck_assert (0 == jwk2pubkey (jwk, &pubkey));

}
END_TEST

START_TEST(t_jwk2sig)
{
    const char *b64sig = "DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q";

    gcry_sexp_t sig;

    ck_assert (0 == jws2sig (b64sig, &sig));

}
END_TEST

START_TEST(t_jwt2signinput)
{
    gcry_sexp_t digest;

    ck_assert (0 == jwt2signinput (encoded_jwt, &digest));


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
    //tcase_add_test(tc_core, test_jwt_verify);
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
