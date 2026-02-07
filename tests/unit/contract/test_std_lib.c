#include "unity.h"
#include <string.h>
#include "neoc/neoc.h"
#include "neoc/contract/std_lib.h"
#include "neoc/neoc_memory.h"

static neoc_std_lib_t *lib = NULL;

void setUp(void) {
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, neoc_init());
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, neoc_std_lib_create(&lib));
    TEST_ASSERT_NOT_NULL(lib);
}

void tearDown(void) {
    neoc_std_lib_free(lib);
    lib = NULL;
    neoc_cleanup();
}

void test_create_null_returns_error(void) {
    TEST_ASSERT_EQUAL_INT(NEOC_ERROR_INVALID_ARGUMENT,
                          neoc_std_lib_create(NULL));
}

void test_free_null_is_safe(void) {
    neoc_std_lib_free(NULL);
}

void test_serialize_produces_script(void) {
    const uint8_t data[] = {0x01, 0x02, 0x03};
    uint8_t *script = NULL;
    size_t script_len = 0;

    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS,
                          neoc_std_lib_serialize(lib, data, sizeof(data),
                                                &script, &script_len));
    TEST_ASSERT_NOT_NULL(script);
    TEST_ASSERT_TRUE(script_len > 0);
    neoc_free(script);
}

void test_deserialize_produces_script(void) {
    const uint8_t data[] = {0xAA, 0xBB};
    uint8_t *script = NULL;
    size_t script_len = 0;

    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS,
                          neoc_std_lib_deserialize(lib, data, sizeof(data),
                                                   &script, &script_len));
    TEST_ASSERT_NOT_NULL(script);
    TEST_ASSERT_TRUE(script_len > 0);
    neoc_free(script);
}

void test_base64_encode_produces_script(void) {
    const uint8_t data[] = {0x48, 0x65, 0x6C, 0x6C, 0x6F};
    uint8_t *script = NULL;
    size_t script_len = 0;

    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS,
                          neoc_std_lib_base64_encode(lib, data, sizeof(data),
                                                     &script, &script_len));
    TEST_ASSERT_NOT_NULL(script);
    TEST_ASSERT_TRUE(script_len > 0);
    neoc_free(script);
}

void test_base64_decode_produces_script(void) {
    uint8_t *script = NULL;
    size_t script_len = 0;

    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS,
                          neoc_std_lib_base64_decode(lib, "SGVsbG8=",
                                                     &script, &script_len));
    TEST_ASSERT_NOT_NULL(script);
    TEST_ASSERT_TRUE(script_len > 0);
    neoc_free(script);
}

void test_base58_encode_produces_script(void) {
    const uint8_t data[] = {0x00, 0x01, 0x02};
    uint8_t *script = NULL;
    size_t script_len = 0;

    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS,
                          neoc_std_lib_base58_encode(lib, data, sizeof(data),
                                                     &script, &script_len));
    TEST_ASSERT_NOT_NULL(script);
    TEST_ASSERT_TRUE(script_len > 0);
    neoc_free(script);
}

void test_base58_decode_produces_script(void) {
    uint8_t *script = NULL;
    size_t script_len = 0;

    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS,
                          neoc_std_lib_base58_decode(lib, "1A1zP1",
                                                     &script, &script_len));
    TEST_ASSERT_NOT_NULL(script);
    TEST_ASSERT_TRUE(script_len > 0);
    neoc_free(script);
}

void test_itoa_produces_script(void) {
    uint8_t *script = NULL;
    size_t script_len = 0;

    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS,
                          neoc_std_lib_itoa(lib, 255, 10,
                                            &script, &script_len));
    TEST_ASSERT_NOT_NULL(script);
    TEST_ASSERT_TRUE(script_len > 0);
    neoc_free(script);
}

void test_atoi_produces_script(void) {
    uint8_t *script = NULL;
    size_t script_len = 0;

    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS,
                          neoc_std_lib_atoi(lib, "255", 10,
                                            &script, &script_len));
    TEST_ASSERT_NOT_NULL(script);
    TEST_ASSERT_TRUE(script_len > 0);
    neoc_free(script);
}

void test_memory_compare_produces_script(void) {
    const uint8_t a[] = {0x01, 0x02};
    const uint8_t b[] = {0x01, 0x03};
    uint8_t *script = NULL;
    size_t script_len = 0;

    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS,
                          neoc_std_lib_memory_compare(lib,
                              a, sizeof(a), b, sizeof(b),
                              &script, &script_len));
    TEST_ASSERT_NOT_NULL(script);
    TEST_ASSERT_TRUE(script_len > 0);
    neoc_free(script);
}

void test_memory_search_produces_script(void) {
    const uint8_t mem[] = {0x10, 0x20, 0x30, 0x40};
    const uint8_t val[] = {0x20, 0x30};
    uint8_t *script = NULL;
    size_t script_len = 0;

    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS,
                          neoc_std_lib_memory_search(lib,
                              mem, sizeof(mem), val, sizeof(val),
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
                          neoc_std_lib_serialize(NULL, data, 1, &script, &script_len));
    TEST_ASSERT_EQUAL_INT(NEOC_ERROR_INVALID_ARGUMENT,
                          neoc_std_lib_serialize(lib, NULL, 1, &script, &script_len));
    TEST_ASSERT_EQUAL_INT(NEOC_ERROR_INVALID_ARGUMENT,
                          neoc_std_lib_serialize(lib, data, 1, NULL, &script_len));
    TEST_ASSERT_EQUAL_INT(NEOC_ERROR_INVALID_ARGUMENT,
                          neoc_std_lib_serialize(lib, data, 1, &script, NULL));

    TEST_ASSERT_EQUAL_INT(NEOC_ERROR_INVALID_ARGUMENT,
                          neoc_std_lib_base64_decode(NULL, "x", &script, &script_len));
    TEST_ASSERT_EQUAL_INT(NEOC_ERROR_INVALID_ARGUMENT,
                          neoc_std_lib_base64_decode(lib, NULL, &script, &script_len));

    TEST_ASSERT_EQUAL_INT(NEOC_ERROR_INVALID_ARGUMENT,
                          neoc_std_lib_atoi(NULL, "1", 10, &script, &script_len));
    TEST_ASSERT_EQUAL_INT(NEOC_ERROR_INVALID_ARGUMENT,
                          neoc_std_lib_atoi(lib, NULL, 10, &script, &script_len));
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_create_null_returns_error);
    RUN_TEST(test_free_null_is_safe);
    RUN_TEST(test_serialize_produces_script);
    RUN_TEST(test_deserialize_produces_script);
    RUN_TEST(test_base64_encode_produces_script);
    RUN_TEST(test_base64_decode_produces_script);
    RUN_TEST(test_base58_encode_produces_script);
    RUN_TEST(test_base58_decode_produces_script);
    RUN_TEST(test_itoa_produces_script);
    RUN_TEST(test_atoi_produces_script);
    RUN_TEST(test_memory_compare_produces_script);
    RUN_TEST(test_memory_search_produces_script);
    RUN_TEST(test_invalid_arguments);
    return UnityEnd();
}
