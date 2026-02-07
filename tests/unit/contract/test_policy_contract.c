#include "unity.h"
#include <string.h>
#include "neoc/neoc.h"
#include "neoc/contract/policy_contract.h"
#include "neoc/types/neoc_hash160.h"

static neoc_policy_contract_t *policy = NULL;

static void fill_hash160(neoc_hash160_t *hash, uint8_t seed) {
    for (size_t i = 0; i < sizeof(hash->data); ++i) {
        hash->data[i] = (uint8_t)(seed + i);
    }
}

void setUp(void) {
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, neoc_init());
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, neoc_policy_contract_create(&policy));
    TEST_ASSERT_NOT_NULL(policy);
}

void tearDown(void) {
    neoc_policy_contract_free(policy);
    policy = NULL;
    neoc_cleanup();
}

void test_policy_contract_defaults(void) {
    uint64_t fee = 0;
    uint32_t factor = 0;
    uint32_t price = 0;

    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, neoc_policy_get_fee_per_byte(policy, &fee));
    TEST_ASSERT_EQUAL_UINT64(1000ULL, fee);

    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, neoc_policy_get_exec_fee_factor(policy, &factor));
    TEST_ASSERT_EQUAL_UINT32(30U, factor);

    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, neoc_policy_get_storage_price(policy, &price));
    TEST_ASSERT_EQUAL_UINT32(100000U, price);
}

void test_policy_contract_set_fee_per_byte(void) {
    uint64_t fee = 0;

    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, neoc_policy_set_fee_per_byte(policy, 2048ULL));
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, neoc_policy_get_fee_per_byte(policy, &fee));
    TEST_ASSERT_EQUAL_UINT64(2048ULL, fee);
}

void test_policy_contract_is_blocked_defaults_to_false(void) {
    neoc_hash160_t account;
    bool blocked = true;

    fill_hash160(&account, 0x42);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS,
                          neoc_policy_is_blocked(policy, &account, &blocked));
    TEST_ASSERT_FALSE(blocked);
}

void test_policy_contract_set_exec_fee_factor(void) {
    uint32_t factor = 0;

    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, neoc_policy_set_exec_fee_factor(policy, 50U));
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, neoc_policy_get_exec_fee_factor(policy, &factor));
    TEST_ASSERT_EQUAL_UINT32(50U, factor);
}

void test_policy_contract_set_storage_price(void) {
    uint32_t price = 0;

    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, neoc_policy_set_storage_price(policy, 200000U));
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, neoc_policy_get_storage_price(policy, &price));
    TEST_ASSERT_EQUAL_UINT32(200000U, price);
}

void test_policy_contract_block_unblock_account(void) {
    neoc_hash160_t account;
    fill_hash160(&account, 0x55);

    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, neoc_policy_block_account(policy, &account));
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, neoc_policy_unblock_account(policy, &account));
}

void test_policy_contract_whitelist_fee_contracts(void) {
    neoc_hash160_t *hashes = NULL;
    size_t count = 99;

    /* Default: empty whitelist */
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS,
                          neoc_policy_get_whitelist_fee_contracts(policy, &hashes, &count));
    TEST_ASSERT_EQUAL_UINT(0, count);
    TEST_ASSERT_NULL(hashes);
}

void test_policy_contract_set_whitelist_fee_contract(void) {
    neoc_hash160_t contract_hash;
    fill_hash160(&contract_hash, 0x77);

    /* Add/update whitelist entry */
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS,
                          neoc_policy_set_whitelist_fee_contract(policy,
                                                                 &contract_hash,
                                                                 "transfer",
                                                                 3,
                                                                 0));
    /* Remove whitelist entry */
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS,
                          neoc_policy_remove_whitelist_fee_contract(policy,
                                                                    &contract_hash,
                                                                    "transfer",
                                                                    3));
}

void test_policy_contract_remove_whitelist_fee_contract_invalid_arguments(void) {
    neoc_hash160_t contract_hash;
    fill_hash160(&contract_hash, 0x11);

    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS,
                          neoc_policy_set_whitelist_fee_contract(policy,
                                                                 &contract_hash,
                                                                 "transfer",
                                                                 3,
                                                                 1));

    TEST_ASSERT_EQUAL_INT(NEOC_ERROR_INVALID_ARGUMENT,
                          neoc_policy_remove_whitelist_fee_contract(NULL,
                                                                    &contract_hash,
                                                                    "transfer",
                                                                    3));
    TEST_ASSERT_EQUAL_INT(NEOC_ERROR_INVALID_ARGUMENT,
                          neoc_policy_remove_whitelist_fee_contract(policy,
                                                                    NULL,
                                                                    "transfer",
                                                                    3));
    TEST_ASSERT_EQUAL_INT(NEOC_ERROR_INVALID_ARGUMENT,
                          neoc_policy_remove_whitelist_fee_contract(policy,
                                                                    &contract_hash,
                                                                    NULL,
                                                                    3));
    TEST_ASSERT_EQUAL_INT(NEOC_ERROR_INVALID_ARGUMENT,
                          neoc_policy_remove_whitelist_fee_contract(policy,
                                                                    &contract_hash,
                                                                    "transfer",
                                                                    -1));
}

void test_policy_contract_invalid_arguments(void) {
    uint64_t fee = 0;
    uint32_t factor = 0;
    uint32_t price = 0;
    bool blocked = false;
    neoc_hash160_t account;
    neoc_hash160_t *hashes_p = NULL;
    size_t wl_count = 0;

    fill_hash160(&account, 0x10);

    TEST_ASSERT_EQUAL_INT(NEOC_ERROR_INVALID_ARGUMENT, neoc_policy_contract_create(NULL));
    TEST_ASSERT_EQUAL_INT(NEOC_ERROR_INVALID_ARGUMENT,
                          neoc_policy_get_fee_per_byte(NULL, &fee));
    TEST_ASSERT_EQUAL_INT(NEOC_ERROR_INVALID_ARGUMENT,
                          neoc_policy_get_fee_per_byte(policy, NULL));

    TEST_ASSERT_EQUAL_INT(NEOC_ERROR_INVALID_ARGUMENT,
                          neoc_policy_get_exec_fee_factor(NULL, &factor));
    TEST_ASSERT_EQUAL_INT(NEOC_ERROR_INVALID_ARGUMENT,
                          neoc_policy_get_exec_fee_factor(policy, NULL));

    TEST_ASSERT_EQUAL_INT(NEOC_ERROR_INVALID_ARGUMENT,
                          neoc_policy_get_storage_price(NULL, &price));
    TEST_ASSERT_EQUAL_INT(NEOC_ERROR_INVALID_ARGUMENT,
                          neoc_policy_get_storage_price(policy, NULL));

    TEST_ASSERT_EQUAL_INT(NEOC_ERROR_INVALID_ARGUMENT,
                          neoc_policy_is_blocked(NULL, &account, &blocked));
    TEST_ASSERT_EQUAL_INT(NEOC_ERROR_INVALID_ARGUMENT,
                          neoc_policy_is_blocked(policy, NULL, &blocked));
    TEST_ASSERT_EQUAL_INT(NEOC_ERROR_INVALID_ARGUMENT,
                          neoc_policy_is_blocked(policy, &account, NULL));

    TEST_ASSERT_EQUAL_INT(NEOC_ERROR_INVALID_ARGUMENT,
                          neoc_policy_set_fee_per_byte(NULL, 10));

    TEST_ASSERT_EQUAL_INT(NEOC_ERROR_INVALID_ARGUMENT,
                          neoc_policy_set_exec_fee_factor(NULL, 10));
    TEST_ASSERT_EQUAL_INT(NEOC_ERROR_INVALID_ARGUMENT,
                          neoc_policy_set_storage_price(NULL, 10));

    TEST_ASSERT_EQUAL_INT(NEOC_ERROR_INVALID_ARGUMENT,
                          neoc_policy_block_account(NULL, &account));
    TEST_ASSERT_EQUAL_INT(NEOC_ERROR_INVALID_ARGUMENT,
                          neoc_policy_block_account(policy, NULL));
    TEST_ASSERT_EQUAL_INT(NEOC_ERROR_INVALID_ARGUMENT,
                          neoc_policy_unblock_account(NULL, &account));
    TEST_ASSERT_EQUAL_INT(NEOC_ERROR_INVALID_ARGUMENT,
                          neoc_policy_unblock_account(policy, NULL));

    TEST_ASSERT_EQUAL_INT(NEOC_ERROR_INVALID_ARGUMENT,
                          neoc_policy_get_whitelist_fee_contracts(NULL, &hashes_p, &wl_count));
    TEST_ASSERT_EQUAL_INT(NEOC_ERROR_INVALID_ARGUMENT,
                          neoc_policy_get_whitelist_fee_contracts(policy, NULL, &wl_count));
    TEST_ASSERT_EQUAL_INT(NEOC_ERROR_INVALID_ARGUMENT,
                          neoc_policy_get_whitelist_fee_contracts(policy, &hashes_p, NULL));

    TEST_ASSERT_EQUAL_INT(NEOC_ERROR_INVALID_ARGUMENT,
                          neoc_policy_set_whitelist_fee_contract(NULL,
                                                                 &account,
                                                                 "transfer",
                                                                 3,
                                                                 0));
    TEST_ASSERT_EQUAL_INT(NEOC_ERROR_INVALID_ARGUMENT,
                          neoc_policy_set_whitelist_fee_contract(policy,
                                                                 NULL,
                                                                 "transfer",
                                                                 3,
                                                                 0));
    TEST_ASSERT_EQUAL_INT(NEOC_ERROR_INVALID_ARGUMENT,
                          neoc_policy_set_whitelist_fee_contract(policy,
                                                                 &account,
                                                                 NULL,
                                                                 3,
                                                                 0));
    TEST_ASSERT_EQUAL_INT(NEOC_ERROR_INVALID_ARGUMENT,
                          neoc_policy_set_whitelist_fee_contract(policy,
                                                                 &account,
                                                                 "transfer",
                                                                 -1,
                                                                 0));
    TEST_ASSERT_EQUAL_INT(NEOC_ERROR_INVALID_ARGUMENT,
                          neoc_policy_set_whitelist_fee_contract(policy,
                                                                 &account,
                                                                 "transfer",
                                                                 3,
                                                                 -1));
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_policy_contract_defaults);
    RUN_TEST(test_policy_contract_set_fee_per_byte);
    RUN_TEST(test_policy_contract_is_blocked_defaults_to_false);
    RUN_TEST(test_policy_contract_set_exec_fee_factor);
    RUN_TEST(test_policy_contract_set_storage_price);
    RUN_TEST(test_policy_contract_block_unblock_account);
    RUN_TEST(test_policy_contract_whitelist_fee_contracts);
    RUN_TEST(test_policy_contract_set_whitelist_fee_contract);
    RUN_TEST(test_policy_contract_remove_whitelist_fee_contract_invalid_arguments);
    RUN_TEST(test_policy_contract_invalid_arguments);
    return UnityEnd();
}
