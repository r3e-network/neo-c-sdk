#include "unity.h"
#include <string.h>
#include <stdint.h>
#include "neoc/neoc.h"
#include "neoc/contract/contract_management.h"
#include "neoc/neoc_memory.h"

static neoc_contract_management_t *mgmt = NULL;

void setUp(void) {
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, neoc_init());
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, neoc_contract_management_create(&mgmt));
    TEST_ASSERT_NOT_NULL(mgmt);
}

void tearDown(void) {
    neoc_contract_management_free(mgmt);
    mgmt = NULL;
    neoc_cleanup();
}

void test_create_null_returns_error(void) {
    TEST_ASSERT_EQUAL_INT(NEOC_ERROR_INVALID_ARGUMENT,
                          neoc_contract_management_create(NULL));
}

void test_free_null_is_safe(void) {
    neoc_contract_management_free(NULL); /* must not crash */
}

void test_get_minimum_deployment_fee(void) {
    uint64_t fee = 0;
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS,
                          neoc_contract_management_get_minimum_deployment_fee(mgmt, &fee));
    /* Default: 10 GAS = 1_000_000_000 fractions */
    TEST_ASSERT_EQUAL_UINT64(1000000000ULL, fee);
}

void test_get_minimum_deployment_fee_invalid_args(void) {
    uint64_t fee = 0;
    TEST_ASSERT_EQUAL_INT(NEOC_ERROR_INVALID_ARGUMENT,
                          neoc_contract_management_get_minimum_deployment_fee(NULL, &fee));
    TEST_ASSERT_EQUAL_INT(NEOC_ERROR_INVALID_ARGUMENT,
                          neoc_contract_management_get_minimum_deployment_fee(mgmt, NULL));
}

void test_has_method_produces_script(void) {
    neoc_hash160_t hash;
    memset(hash.data, 0xAB, sizeof(hash.data));

    uint8_t *script = NULL;
    size_t script_len = 0;

    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS,
                          neoc_contract_management_has_method(
                              mgmt, &hash, "transfer", 3,
                              &script, &script_len));
    TEST_ASSERT_NOT_NULL(script);
    TEST_ASSERT_TRUE(script_len > 0);

    neoc_free(script);
}

void test_has_method_invalid_args(void) {
    neoc_hash160_t hash;
    memset(hash.data, 0x11, sizeof(hash.data));
    uint8_t *script = NULL;
    size_t script_len = 0;

    TEST_ASSERT_EQUAL_INT(NEOC_ERROR_INVALID_ARGUMENT,
                          neoc_contract_management_has_method(
                              NULL, &hash, "m", 0, &script, &script_len));
    TEST_ASSERT_EQUAL_INT(NEOC_ERROR_INVALID_ARGUMENT,
                          neoc_contract_management_has_method(
                              mgmt, NULL, "m", 0, &script, &script_len));
    TEST_ASSERT_EQUAL_INT(NEOC_ERROR_INVALID_ARGUMENT,
                          neoc_contract_management_has_method(
                              mgmt, &hash, NULL, 0, &script, &script_len));
    TEST_ASSERT_EQUAL_INT(NEOC_ERROR_INVALID_ARGUMENT,
                          neoc_contract_management_has_method(
                              mgmt, &hash, "m", 0, NULL, &script_len));
    TEST_ASSERT_EQUAL_INT(NEOC_ERROR_INVALID_ARGUMENT,
                          neoc_contract_management_has_method(
                              mgmt, &hash, "m", 0, &script, NULL));
}

void test_get_contract_produces_script(void) {
    neoc_hash160_t hash;
    memset(hash.data, 0xCC, sizeof(hash.data));

    uint8_t *script = NULL;
    size_t script_len = 0;

    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS,
                          neoc_contract_management_get_contract(
                              mgmt, &hash, &script, &script_len));
    TEST_ASSERT_NOT_NULL(script);
    TEST_ASSERT_TRUE(script_len > 0);

    neoc_free(script);
}

void test_get_contract_invalid_args(void) {
    neoc_hash160_t hash;
    memset(hash.data, 0x22, sizeof(hash.data));
    uint8_t *script = NULL;
    size_t script_len = 0;

    TEST_ASSERT_EQUAL_INT(NEOC_ERROR_INVALID_ARGUMENT,
                          neoc_contract_management_get_contract(
                              NULL, &hash, &script, &script_len));
    TEST_ASSERT_EQUAL_INT(NEOC_ERROR_INVALID_ARGUMENT,
                          neoc_contract_management_get_contract(
                              mgmt, NULL, &script, &script_len));
    TEST_ASSERT_EQUAL_INT(NEOC_ERROR_INVALID_ARGUMENT,
                          neoc_contract_management_get_contract(
                              mgmt, &hash, NULL, &script_len));
    TEST_ASSERT_EQUAL_INT(NEOC_ERROR_INVALID_ARGUMENT,
                          neoc_contract_management_get_contract(
                              mgmt, &hash, &script, NULL));
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_create_null_returns_error);
    RUN_TEST(test_free_null_is_safe);
    RUN_TEST(test_get_minimum_deployment_fee);
    RUN_TEST(test_get_minimum_deployment_fee_invalid_args);
    RUN_TEST(test_has_method_produces_script);
    RUN_TEST(test_has_method_invalid_args);
    RUN_TEST(test_get_contract_produces_script);
    RUN_TEST(test_get_contract_invalid_args);
    return UnityEnd();
}
