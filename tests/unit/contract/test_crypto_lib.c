#include "unity.h"
#include <string.h>
#include "neoc/neoc.h"
#include "neoc/contract/crypto_lib.h"
#include "neoc/neoc_memory.h"

static neoc_crypto_lib_t *lib = NULL;

void setUp(void) {
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, neoc_init());
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, neoc_crypto_lib_create(&lib));
    TEST_ASSERT_NOT_NULL(lib);
}

void tearDown(void) {
    neoc_crypto_lib_free(lib);
    lib = NULL;
    neoc_cleanup();
}

void test_create_null_returns_error(void) {
    TEST_ASSERT_EQUAL_INT(NEOC_ERROR_INVALID_ARGUMENT,
                          neoc_crypto_lib_create(NULL));
}

void test_free_null_is_safe(void) {
    neoc_crypto_lib_free(NULL);
}

void test_sha256_produces_script(void) {
    const uint8_t data[] = {0x01, 0x02, 0x03};
    uint8_t *script = NULL;
    size_t script_len = 0;

    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS,
                          neoc_crypto_lib_sha256(lib, data, sizeof(data),
                                                 &script, &script_len));
    TEST_ASSERT_NOT_NULL(script);
    TEST_ASSERT_TRUE(script_len > 0);
    neoc_free(script);
}

void test_ripemd160_produces_script(void) {
    const uint8_t data[] = {0xAA, 0xBB};
    uint8_t *script = NULL;
    size_t script_len = 0;

    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS,
                          neoc_crypto_lib_ripemd160(lib, data, sizeof(data),
                                                    &script, &script_len));
    TEST_ASSERT_NOT_NULL(script);
    TEST_ASSERT_TRUE(script_len > 0);
    neoc_free(script);
}

void test_murmur32_produces_script(void) {
    const uint8_t data[] = {0x10, 0x20, 0x30, 0x40};
    uint8_t *script = NULL;
    size_t script_len = 0;

    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS,
                          neoc_crypto_lib_murmur32(lib, data, sizeof(data), 0,
                                                   &script, &script_len));
    TEST_ASSERT_NOT_NULL(script);
    TEST_ASSERT_TRUE(script_len > 0);
    neoc_free(script);
}

void test_verify_with_ecdsa_produces_script(void) {
    const uint8_t msg[] = {0x01};
    const uint8_t pubkey[] = {0x02, 0x03};
    const uint8_t sig[] = {0x30, 0x44};
    uint8_t *script = NULL;
    size_t script_len = 0;

    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS,
                          neoc_crypto_lib_verify_with_ecdsa(
                              lib, msg, sizeof(msg),
                              pubkey, sizeof(pubkey),
                              sig, sizeof(sig), 22,
                              &script, &script_len));
    TEST_ASSERT_NOT_NULL(script);
    TEST_ASSERT_TRUE(script_len > 0);
    neoc_free(script);
}

void test_invalid_arguments(void) {
    const uint8_t data[] = {0x01};
    uint8_t *script = NULL;
    size_t script_len = 0;

    TEST_ASSERT_EQUAL_INT(NEOC_ERROR_INVALID_ARGUMENT,
                          neoc_crypto_lib_sha256(NULL, data, 1, &script, &script_len));
    TEST_ASSERT_EQUAL_INT(NEOC_ERROR_INVALID_ARGUMENT,
                          neoc_crypto_lib_sha256(lib, NULL, 1, &script, &script_len));
    TEST_ASSERT_EQUAL_INT(NEOC_ERROR_INVALID_ARGUMENT,
                          neoc_crypto_lib_sha256(lib, data, 1, NULL, &script_len));
    TEST_ASSERT_EQUAL_INT(NEOC_ERROR_INVALID_ARGUMENT,
                          neoc_crypto_lib_sha256(lib, data, 1, &script, NULL));

    TEST_ASSERT_EQUAL_INT(NEOC_ERROR_INVALID_ARGUMENT,
                          neoc_crypto_lib_ripemd160(NULL, data, 1, &script, &script_len));

    TEST_ASSERT_EQUAL_INT(NEOC_ERROR_INVALID_ARGUMENT,
                          neoc_crypto_lib_murmur32(NULL, data, 1, 0, &script, &script_len));
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_create_null_returns_error);
    RUN_TEST(test_free_null_is_safe);
    RUN_TEST(test_sha256_produces_script);
    RUN_TEST(test_ripemd160_produces_script);
    RUN_TEST(test_murmur32_produces_script);
    RUN_TEST(test_verify_with_ecdsa_produces_script);
    RUN_TEST(test_invalid_arguments);
    return UnityEnd();
}
