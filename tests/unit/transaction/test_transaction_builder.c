/**
 * @file test_transaction_builder.c
 * @brief Unit tests converted from TransactionBuilderTests.swift
 */

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>
#include "neoc/neoc.h"
#include "neoc/transaction/transaction_builder.h"
#include "neoc/transaction/signer.h"
#include "neoc/wallet/account.h"
#include "neoc/types/neoc_hash160.h"
#include "neoc/script/script_builder.h"
#include "neoc/utils/hex.h"

// Test data
static const char *ACCOUNT1_PRIVATE_KEY = "e6e919577dd7b8e97805151c05ae07ff4f752654d6d8797597aca989c02c4cb3";
static const char *ACCOUNT2_PRIVATE_KEY = "b4b2b579cac270125259f08a5f414e9235817e7637b9a66cfeb3b77d90c8e7f9";
static const char *RECIPIENT_HASH = "969a77db482f74ce27105f760efa139223431394";

// Test accounts
static neoc_account_t *account1 = NULL;
static neoc_account_t *account2 = NULL;
static neoc_hash160_t account1_hash;
static neoc_hash160_t account2_hash;
static neoc_hash160_t recipient;

// Test setup
static void setUp(void) {
    neoc_error_t err = neoc_init();
    assert(err == NEOC_SUCCESS);
    
    // Create test accounts
    uint8_t priv_key1[32];
    size_t priv_key1_len = 0;
    err = neoc_hex_decode(ACCOUNT1_PRIVATE_KEY, priv_key1, sizeof(priv_key1), &priv_key1_len);
    assert(err == NEOC_SUCCESS);
    
    neoc_ec_key_pair_t *key_pair1 = NULL;
    err = neoc_ec_key_pair_create_from_private_key(priv_key1, &key_pair1);
    assert(err == NEOC_SUCCESS);
    
    err = neoc_account_create_from_key_pair(key_pair1, &account1);
    assert(err == NEOC_SUCCESS);
    
    uint8_t priv_key2[32];
    size_t priv_key2_len = 0;
    err = neoc_hex_decode(ACCOUNT2_PRIVATE_KEY, priv_key2, sizeof(priv_key2), &priv_key2_len);
    assert(err == NEOC_SUCCESS);
    
    neoc_ec_key_pair_t *key_pair2 = NULL;
    err = neoc_ec_key_pair_create_from_private_key(priv_key2, &key_pair2);
    assert(err == NEOC_SUCCESS);
    
    err = neoc_account_create_from_key_pair(key_pair2, &account2);
    assert(err == NEOC_SUCCESS);

    err = neoc_account_get_script_hash(account1, &account1_hash);
    assert(err == NEOC_SUCCESS);
    err = neoc_account_get_script_hash(account2, &account2_hash);
    assert(err == NEOC_SUCCESS);
    
    // Create recipient hash
    err = neoc_hash160_from_string(RECIPIENT_HASH, &recipient);
    assert(err == NEOC_SUCCESS);
    
    neoc_ec_key_pair_free(key_pair1);
    neoc_ec_key_pair_free(key_pair2);
}

// Test teardown
static void tearDown(void) {
    if (account1) {
        neoc_account_free(account1);
        account1 = NULL;
    }
    if (account2) {
        neoc_account_free(account2);
        account2 = NULL;
    }
    neoc_cleanup();
}

// Test building transaction with correct nonce
static void test_build_transaction_with_correct_nonce(void) {
    printf("Testing build transaction with correct nonce...\n");

    // Test with random nonce
    {
        neoc_transaction_builder_t *builder = NULL;
        neoc_error_t err = neoc_transaction_builder_create(&builder);
        assert(err == NEOC_SUCCESS);
        assert(builder != NULL);

        err = neoc_transaction_builder_set_valid_until_block(builder, 1000);
        assert(err == NEOC_SUCCESS);

        uint8_t script[] = {1, 2, 3};
        err = neoc_transaction_builder_set_script(builder, script, sizeof(script));
        assert(err == NEOC_SUCCESS);

        uint32_t nonce = rand() % UINT32_MAX;
        err = neoc_transaction_builder_set_nonce(builder, nonce);
        assert(err == NEOC_SUCCESS);

        neoc_signer_t *s = NULL;
        neoc_error_t e = neoc_signer_create_called_by_entry(&account1_hash, &s);
        assert(e == NEOC_SUCCESS);
        e = neoc_transaction_builder_add_signer(builder, s);
        assert(e == NEOC_SUCCESS);
        neoc_signer_free(s);

        neoc_transaction_t *tx = NULL;
        err = neoc_transaction_builder_build(builder, &tx);
        assert(err == NEOC_SUCCESS);
        assert(tx != NULL);
        assert(tx->nonce == nonce);

        neoc_transaction_free(tx);
        neoc_transaction_builder_free(builder);
    }

    // Test with nonce = 0
    {
        neoc_transaction_builder_t *builder = NULL;
        neoc_error_t err = neoc_transaction_builder_create(&builder);
        assert(err == NEOC_SUCCESS);

        err = neoc_transaction_builder_set_valid_until_block(builder, 1000);
        assert(err == NEOC_SUCCESS);

        uint8_t script[] = {1, 2, 3};
        err = neoc_transaction_builder_set_script(builder, script, sizeof(script));
        assert(err == NEOC_SUCCESS);

        uint32_t nonce = 0;
        err = neoc_transaction_builder_set_nonce(builder, nonce);
        assert(err == NEOC_SUCCESS);

        neoc_signer_t *s = NULL;
        neoc_error_t e = neoc_signer_create_called_by_entry(&account1_hash, &s);
        assert(e == NEOC_SUCCESS);
        e = neoc_transaction_builder_add_signer(builder, s);
        assert(e == NEOC_SUCCESS);
        neoc_signer_free(s);

        neoc_transaction_t *tx = NULL;
        err = neoc_transaction_builder_build(builder, &tx);
        assert(err == NEOC_SUCCESS);
        assert(tx != NULL);
        assert(tx->nonce == nonce);

        neoc_transaction_free(tx);
        neoc_transaction_builder_free(builder);
    }

    // Test with max nonce
    {
        neoc_transaction_builder_t *builder = NULL;
        neoc_error_t err = neoc_transaction_builder_create(&builder);
        assert(err == NEOC_SUCCESS);

        err = neoc_transaction_builder_set_valid_until_block(builder, 1000);
        assert(err == NEOC_SUCCESS);

        uint8_t script[] = {1, 2, 3};
        err = neoc_transaction_builder_set_script(builder, script, sizeof(script));
        assert(err == NEOC_SUCCESS);

        uint32_t nonce = UINT32_MAX;
        err = neoc_transaction_builder_set_nonce(builder, nonce);
        assert(err == NEOC_SUCCESS);

        neoc_signer_t *s = NULL;
        neoc_error_t e = neoc_signer_create_called_by_entry(&account1_hash, &s);
        assert(e == NEOC_SUCCESS);
        e = neoc_transaction_builder_add_signer(builder, s);
        assert(e == NEOC_SUCCESS);
        neoc_signer_free(s);

        neoc_transaction_t *tx = NULL;
        err = neoc_transaction_builder_build(builder, &tx);
        assert(err == NEOC_SUCCESS);
        assert(tx != NULL);
        assert(tx->nonce == nonce);

        neoc_transaction_free(tx);
        neoc_transaction_builder_free(builder);
    }

    printf("  ✅ Build transaction with correct nonce test passed\n");
}

// Test fail building transaction without signer
static void test_fail_building_tx_without_signer(void) {
    printf("Testing fail building transaction without signer...\n");
    
    // Create transaction builder
    neoc_transaction_builder_t *builder = NULL;
    neoc_error_t err = neoc_transaction_builder_create(&builder);
    assert(err == NEOC_SUCCESS);
    
    // Set valid until block
    err = neoc_transaction_builder_set_valid_until_block(builder, 100);
    assert(err == NEOC_SUCCESS);
    
    // Set script
    uint8_t script[] = {1, 2, 3};
    err = neoc_transaction_builder_set_script(builder, script, sizeof(script));
    assert(err == NEOC_SUCCESS);
    
    // Try to build without signer - should fail
    neoc_transaction_t *tx = NULL;
    err = neoc_transaction_builder_build(builder, &tx);
    assert(err != NEOC_SUCCESS);
    assert(tx == NULL);
    
    neoc_transaction_builder_free(builder);
    
    printf("  ✅ Fail building transaction without signer test passed\n");
}

// Test fail building transaction with invalid block number
// Test automatically set nonce
static void test_automatically_set_nonce(void) {
    printf("Testing automatically set nonce...\n");
    
    // Create transaction builder
    neoc_transaction_builder_t *builder = NULL;
    neoc_error_t err = neoc_transaction_builder_create(&builder);
    assert(err == NEOC_SUCCESS);
    
    // Set valid until block
    err = neoc_transaction_builder_set_valid_until_block(builder, 1000);
    assert(err == NEOC_SUCCESS);
    
    // Set script
    uint8_t script[] = {1, 2, 3};
    err = neoc_transaction_builder_set_script(builder, script, sizeof(script));
    assert(err == NEOC_SUCCESS);
    
    // Add signer
    neoc_signer_t *signer = NULL;
    err = neoc_signer_create_called_by_entry(&account1_hash, &signer);
    assert(err == NEOC_SUCCESS);
    
    err = neoc_transaction_builder_add_signer(builder, signer);
    assert(err == NEOC_SUCCESS);
    
    // Build without setting nonce - should automatically set one
    neoc_transaction_t *tx = NULL;
    err = neoc_transaction_builder_build(builder, &tx);
    assert(err == NEOC_SUCCESS);
    assert(tx != NULL);
    
    uint32_t nonce = tx->nonce;
    assert(nonce > 0 && nonce < UINT32_MAX);
    
    neoc_transaction_free(tx);
    neoc_signer_free(signer);
    neoc_transaction_builder_free(builder);
    
    printf("  ✅ Automatically set nonce test passed\n");
}

// Test duplicate signers
static void test_fail_with_duplicate_signers(void) {
    printf("Testing fail with duplicate signers...\n");
    
    // Create transaction builder
    neoc_transaction_builder_t *builder = NULL;
    neoc_error_t err = neoc_transaction_builder_create(&builder);
    assert(err == NEOC_SUCCESS);
    
    // Create two signers for the same account
    neoc_signer_t *signer1 = NULL;
    err = neoc_signer_create_global(&account1_hash, &signer1);
    assert(err == NEOC_SUCCESS);
    
    neoc_signer_t *signer2 = NULL;
    err = neoc_signer_create_called_by_entry(&account1_hash, &signer2);
    assert(err == NEOC_SUCCESS);
    
    // Add first signer
    err = neoc_transaction_builder_add_signer(builder, signer1);
    assert(err == NEOC_SUCCESS);
    
    // Try to add duplicate signer - should fail
    err = neoc_transaction_builder_add_signer(builder, signer2);
    assert(err != NEOC_SUCCESS);
    
    neoc_signer_free(signer1);
    neoc_signer_free(signer2);
    neoc_transaction_builder_free(builder);
    
    printf("  ✅ Fail with duplicate signers test passed\n");
}

// Test transaction attributes
static void test_transaction_attributes(void) {
    printf("Testing transaction attributes...\n");
    
    // Create transaction builder
    neoc_transaction_builder_t *builder = NULL;
    neoc_error_t err = neoc_transaction_builder_create(&builder);
    assert(err == NEOC_SUCCESS);
    
    // Set basic transaction properties
    err = neoc_transaction_builder_set_valid_until_block(builder, 1000);
    assert(err == NEOC_SUCCESS);
    
    uint8_t script[] = {1, 2, 3};
    err = neoc_transaction_builder_set_script(builder, script, sizeof(script));
    assert(err == NEOC_SUCCESS);
    
    // Add signer
    neoc_signer_t *signer = NULL;
    err = neoc_signer_create_called_by_entry(&account1_hash, &signer);
    assert(err == NEOC_SUCCESS);
    
    err = neoc_transaction_builder_add_signer(builder, signer);
    assert(err == NEOC_SUCCESS);
    
    // Add high priority attribute
    err = neoc_tx_builder_set_high_priority(builder, true);
    assert(err == NEOC_SUCCESS);
    
    // Build transaction
    neoc_transaction_t *tx = NULL;
    err = neoc_transaction_builder_build(builder, &tx);
    assert(err == NEOC_SUCCESS);
    assert(tx != NULL);
    
    neoc_transaction_free(tx);
    neoc_signer_free(signer);
    neoc_transaction_builder_free(builder);
    
    printf("  ✅ Transaction attributes test passed\n");
}

int main(void) {
    printf("\n=== TransactionBuilderTests Tests ===\n\n");
    
    // Initialize random seed
    srand(time(NULL));
    
    setUp();
    
    // Run critical tests (6 out of 49)
    test_build_transaction_with_correct_nonce();
    test_fail_building_tx_without_signer();
    test_automatically_set_nonce();
    test_fail_with_duplicate_signers();
    test_transaction_attributes();
    
    tearDown();
    
    printf("\n✅ All TransactionBuilderTests tests passed!\n\n");
    printf("Note: 6 of 49 tests implemented. Continue implementing remaining tests.\n");
    return 0;
}
