#include <check.h>
#include <stdlib.h>
#include "../libjosec.h"
#include <jansson.h>


int fill_random(uint8_t *ptr, const int len)
{
    int rc = -1;
    int fd = open("/dev/urandom");
    size_t num = 0;

    if (fd < 0)
        return rc;

    while (num < len)
    {
        rc = read(fd, ptr + num, len - num);
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

    test_json();

    json_t *obj = json_object();

    json_object_set_new(obj, "Claims", json_integer(42));

    char *str = jwt_encode (obj, ES256, sign);

    printf("Result: %s\n", str);


}
END_TEST

START_TEST(test_base64)
{

    char * str = "Hello";

    int elen = BASE64_LENGTH(strlen(str));
    char * encoded;

    base64_encode_alloc (str, strlen(str), &encoded);

    printf("%s\n", encoded);

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
