/**
 * @file test_nep6_wallet_struct.c
 * @brief Unit tests converted from NEP6WalletTests.swift
 */

#include "unity.h"
#include <string.h>
#include "neoc/neoc.h"
#include "neoc/neoc_memory.h"
#include "neoc/wallet/nep6_wallet.h"
#include "neoc/wallet/nep6/nep6_wallet.h"
#include "neoc/wallet/nep6/nep6_contract.h"

static neoc_nep6_contract_t* create_test_contract(void) {
    neoc_nep6_parameter_t param = {0};
    param.name = neoc_strdup("signature");
    param.type = NEOC_CONTRACT_PARAM_SIGNATURE;

    neoc_nep6_contract_t *contract = NULL;
    neoc_error_t err = neoc_nep6_contract_create("deadbeef", &param, 1, false, &contract);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    neoc_free(param.name);
    return contract;
}

void setUp(void) {
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, neoc_init());
}

void tearDown(void) {
    neoc_cleanup();
}

void test_nep6_wallet_struct_json_roundtrip(void) {
    neoc_nep6_wallet_struct_t *wallet = NULL;
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS,
                          neoc_nep6_wallet_struct_create("StructWallet", "1.0", &wallet));
    wallet->scrypt.n = 16384;
    wallet->scrypt.r = 8;
    wallet->scrypt.p = 1;

    neoc_nep6_contract_t *contract = create_test_contract();
    neoc_nep6_account_t *account = NULL;
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS,
                          neoc_nep6_account_create("NLnyLtep7jwyq1qhNPkwXbJpurC4jUT8ke",
                                                   "Primary",
                                                   true,
                                                   false,
                                                   "6PYVEi6ZGdsLoCYbbGWqoYef7VWMbKwcew86m5fpxnZRUD8tEjainBgQW1",
                                                   contract,
                                                   &account));
    contract = NULL; // ownership transferred
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS,
                          neoc_nep6_wallet_struct_add_account(wallet, account));

    char *json = NULL;
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS,
                          neoc_nep6_wallet_struct_to_json(wallet, &json));

    neoc_nep6_wallet_struct_t *parsed = NULL;
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS,
                          neoc_nep6_wallet_struct_from_json(json, &parsed));

    TEST_ASSERT_TRUE(neoc_nep6_wallet_struct_equals(wallet, parsed));

    neoc_nep6_wallet_struct_free(parsed);
    neoc_nep6_wallet_struct_free(wallet);
    neoc_free(json);
}

void test_nep6_wallet_struct_manage_accounts_and_extras(void) {
    neoc_nep6_wallet_struct_t *wallet_struct = NULL;
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS,
                          neoc_nep6_wallet_struct_create("RuntimeWallet", "2.0", &wallet_struct));

    neoc_nep6_account_t *account = NULL;
    neoc_nep6_contract_t *contract = create_test_contract();
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS,
                          neoc_nep6_account_create("NWcx4EfYdfqn5jNjDz8AHE6hWtWdUGDdmy",
                                                   "Primary",
                                                   true,
                                                   false,
                                                   "6PYSQWBqZE5oEFdMGCJ3xR7bz6ezz814oKE7GqwB9i5uhtUzkshe9B6YGB",
                                                   contract,
                                                   &account));
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS,
                          neoc_nep6_wallet_struct_add_account(wallet_struct, account));

    // Add extra metadata and read it back
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS,
                          neoc_nep6_wallet_struct_add_extra(wallet_struct, "salt", "NaCl"));
    const char *extra_value = NULL;
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS,
                          neoc_nep6_wallet_struct_get_extra(wallet_struct, "salt", &extra_value));
    TEST_ASSERT_NOT_NULL(extra_value);
    TEST_ASSERT_EQUAL_STRING("NaCl", extra_value);

    // Removing the account should succeed
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS,
                          neoc_nep6_wallet_struct_remove_account(wallet_struct,
                                                                 "NWcx4EfYdfqn5jNjDz8AHE6hWtWdUGDdmy"));

    neoc_nep6_wallet_struct_free(wallet_struct);
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_nep6_wallet_struct_json_roundtrip);
    RUN_TEST(test_nep6_wallet_struct_manage_accounts_and_extras);
    return UnityEnd();
}
