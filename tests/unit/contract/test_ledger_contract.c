#include "unity.h"
#include <string.h>
#include "neoc/neoc.h"
#include "neoc/contract/ledger_contract.h"
#include "neoc/neoc_memory.h"

static neoc_ledger_contract_t *ledger = NULL;

void setUp(void) {
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, neoc_init());
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, neoc_ledger_contract_create(&ledger));
    TEST_ASSERT_NOT_NULL(ledger);
}

void tearDown(void) {
    neoc_ledger_contract_free(ledger);
    ledger = NULL;
    neoc_cleanup();
}

void test_create_null_returns_error(void) {
    TEST_ASSERT_EQUAL_INT(NEOC_ERROR_INVALID_ARGUMENT,
                          neoc_ledger_contract_create(NULL));
}

void test_free_null_is_safe(void) {
    neoc_ledger_contract_free(NULL);
}

void test_current_hash_produces_script(void) {
    uint8_t *script = NULL;
    size_t script_len = 0;

    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS,
                          neoc_ledger_current_hash(ledger, &script, &script_len));
    TEST_ASSERT_NOT_NULL(script);
    TEST_ASSERT_TRUE(script_len > 0);
    neoc_free(script);
}

void test_current_index_produces_script(void) {
    uint8_t *script = NULL;
    size_t script_len = 0;

    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS,
                          neoc_ledger_current_index(ledger, &script, &script_len));
    TEST_ASSERT_NOT_NULL(script);
    TEST_ASSERT_TRUE(script_len > 0);
    neoc_free(script);
}

void test_get_block_produces_script(void) {
    uint8_t *script = NULL;
    size_t script_len = 0;

    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS,
                          neoc_ledger_get_block(ledger, 42, &script, &script_len));
    TEST_ASSERT_NOT_NULL(script);
    TEST_ASSERT_TRUE(script_len > 0);
    neoc_free(script);
}

void test_get_transaction_produces_script(void) {
    neoc_hash256_t hash;
    memset(hash.data, 0xBB, sizeof(hash.data));

    uint8_t *script = NULL;
    size_t script_len = 0;

    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS,
                          neoc_ledger_get_transaction(ledger, &hash, &script, &script_len));
    TEST_ASSERT_NOT_NULL(script);
    TEST_ASSERT_TRUE(script_len > 0);
    neoc_free(script);
}

void test_get_transaction_height_produces_script(void) {
    neoc_hash256_t hash;
    memset(hash.data, 0xDD, sizeof(hash.data));

    uint8_t *script = NULL;
    size_t script_len = 0;

    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS,
                          neoc_ledger_get_transaction_height(ledger, &hash,
                                                             &script, &script_len));
    TEST_ASSERT_NOT_NULL(script);
    TEST_ASSERT_TRUE(script_len > 0);
    neoc_free(script);
}

void test_invalid_arguments(void) {
    uint8_t *script = NULL;
    size_t script_len = 0;
    neoc_hash256_t hash;
    memset(hash.data, 0x11, sizeof(hash.data));

    TEST_ASSERT_EQUAL_INT(NEOC_ERROR_INVALID_ARGUMENT,
                          neoc_ledger_current_hash(NULL, &script, &script_len));
    TEST_ASSERT_EQUAL_INT(NEOC_ERROR_INVALID_ARGUMENT,
                          neoc_ledger_current_hash(ledger, NULL, &script_len));
    TEST_ASSERT_EQUAL_INT(NEOC_ERROR_INVALID_ARGUMENT,
                          neoc_ledger_current_hash(ledger, &script, NULL));

    TEST_ASSERT_EQUAL_INT(NEOC_ERROR_INVALID_ARGUMENT,
                          neoc_ledger_current_index(NULL, &script, &script_len));

    TEST_ASSERT_EQUAL_INT(NEOC_ERROR_INVALID_ARGUMENT,
                          neoc_ledger_get_block(NULL, 0, &script, &script_len));

    TEST_ASSERT_EQUAL_INT(NEOC_ERROR_INVALID_ARGUMENT,
                          neoc_ledger_get_transaction(NULL, &hash, &script, &script_len));
    TEST_ASSERT_EQUAL_INT(NEOC_ERROR_INVALID_ARGUMENT,
                          neoc_ledger_get_transaction(ledger, NULL, &script, &script_len));

    TEST_ASSERT_EQUAL_INT(NEOC_ERROR_INVALID_ARGUMENT,
                          neoc_ledger_get_transaction_height(NULL, &hash, &script, &script_len));
    TEST_ASSERT_EQUAL_INT(NEOC_ERROR_INVALID_ARGUMENT,
                          neoc_ledger_get_transaction_height(ledger, NULL, &script, &script_len));
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_create_null_returns_error);
    RUN_TEST(test_free_null_is_safe);
    RUN_TEST(test_current_hash_produces_script);
    RUN_TEST(test_current_index_produces_script);
    RUN_TEST(test_get_block_produces_script);
    RUN_TEST(test_get_transaction_produces_script);
    RUN_TEST(test_get_transaction_height_produces_script);
    RUN_TEST(test_invalid_arguments);
    return UnityEnd();
}
