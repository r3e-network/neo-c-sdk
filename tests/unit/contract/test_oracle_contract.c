#include "unity.h"
#include <string.h>
#include "neoc/neoc.h"
#include "neoc/contract/oracle_contract.h"

static neoc_oracle_contract_t *oracle = NULL;

void setUp(void) {
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, neoc_init());
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, neoc_oracle_contract_create(&oracle));
    TEST_ASSERT_NOT_NULL(oracle);
}

void tearDown(void) {
    neoc_oracle_contract_free(oracle);
    oracle = NULL;
    neoc_cleanup();
}

void test_create_null_returns_error(void) {
    TEST_ASSERT_EQUAL_INT(NEOC_ERROR_INVALID_ARGUMENT,
                          neoc_oracle_contract_create(NULL));
}

void test_free_null_is_safe(void) {
    neoc_oracle_contract_free(NULL);
}

void test_get_price_default(void) {
    uint64_t price = 0;
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, neoc_oracle_get_price(oracle, &price));
    /* Default: 0.5 GAS = 50_000_000 fractions */
    TEST_ASSERT_EQUAL_UINT64(50000000ULL, price);
}

void test_set_and_get_price(void) {
    uint64_t price = 0;
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, neoc_oracle_set_price(oracle, 100000000ULL));
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, neoc_oracle_get_price(oracle, &price));
    TEST_ASSERT_EQUAL_UINT64(100000000ULL, price);
}

void test_invalid_arguments(void) {
    uint64_t price = 0;
    TEST_ASSERT_EQUAL_INT(NEOC_ERROR_INVALID_ARGUMENT,
                          neoc_oracle_get_price(NULL, &price));
    TEST_ASSERT_EQUAL_INT(NEOC_ERROR_INVALID_ARGUMENT,
                          neoc_oracle_get_price(oracle, NULL));
    TEST_ASSERT_EQUAL_INT(NEOC_ERROR_INVALID_ARGUMENT,
                          neoc_oracle_set_price(NULL, 10));
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_create_null_returns_error);
    RUN_TEST(test_free_null_is_safe);
    RUN_TEST(test_get_price_default);
    RUN_TEST(test_set_and_get_price);
    RUN_TEST(test_invalid_arguments);
    return UnityEnd();
}
