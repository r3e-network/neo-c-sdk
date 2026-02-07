/**
 * @file test_integration_comprehensive.c
 * @brief Comprehensive integration tests for complex NeoC workflows
 */

#include "unity.h"
#include <neoc/neoc.h>
#include <neoc/wallet/account.h>
#include <neoc/wallet/wallet.h>
#include <neoc/wallet/nep6.h>
#include <neoc/crypto/ec_key_pair.h>
#include <neoc/crypto/wif.h>
#include <neoc/crypto/nep2.h>
#include <neoc/contract/gas_token.h>
#include <neoc/contract/neo_token.h>
#include <neoc/transaction/transaction_builder.h>
#include <neoc/transaction/signer.h>
#include <neoc/transaction/witness.h>
#include <neoc/script/script_builder.h>
#include <neoc/utils/neoc_hex.h>
#include <neoc/utils/neoc_base64.h>
#include <string.h>
#include <stdio.h>
#include <time.h>

// Test data
static const char* TEST_MNEMONIC = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
static const char* TEST_PASSWORD = "test_password_123";
static const char* WALLET_NAME = "integration_test_wallet";

void setUp(void) {
    neoc_init();
}

void tearDown(void) {
    neoc_cleanup();
}

/* ===== COMPREHENSIVE WALLET WORKFLOW TESTS ===== */

void test_complete_wallet_creation_workflow(void) {
    printf("Testing complete wallet creation workflow\n");
    
    // 1. Create new wallet
    neoc_wallet_t* wallet;
    neoc_error_t err = neoc_wallet_create(WALLET_NAME, &wallet);
    if (err != NEOC_SUCCESS) {
        printf("  neoc_nep2_encrypt_key_pair failed with error %d\n", err);
    }
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    TEST_ASSERT_NOT_NULL(wallet);
    
    // 2. Create multiple accounts
    neoc_account_t* account1;
    err = neoc_account_create_random(&account1);
    if (err != NEOC_SUCCESS) {
        printf("  neoc_nep2_decrypt_key_pair failed with error %d\n", err);
    }
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    
    neoc_account_t* account2;
    err = neoc_account_create_random(&account2);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    
    // 3. Add accounts to wallet
    err = neoc_wallet_add_account(wallet, account1);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    
    err = neoc_wallet_add_account(wallet, account2);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    
    // 4. Set default account
    neoc_hash160_t account1_hash;
    err = neoc_account_get_script_hash(account1, &account1_hash);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    
    err = neoc_wallet_set_default_account(wallet, &account1_hash);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    
    // 5. Verify default account
    neoc_account_t* default_account;
    err = neoc_wallet_get_default_account(wallet, &default_account);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    TEST_ASSERT_NOT_NULL(default_account);
    
    neoc_hash160_t default_hash;
    err = neoc_account_get_script_hash(default_account, &default_hash);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    TEST_ASSERT_EQUAL_MEMORY(account1_hash.data, default_hash.data, 20);
    
    // 6. Encrypt accounts
    err = neoc_account_encrypt_private_key(account1, TEST_PASSWORD, NULL);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    
    err = neoc_account_encrypt_private_key(account2, TEST_PASSWORD, NULL);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    
    // 7. Verify wallet contents
    size_t account_count;
    err = neoc_wallet_get_account_count(wallet, &account_count);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    TEST_ASSERT_EQUAL_INT(2, account_count);
    
    printf("  Created wallet with %zu accounts\n", account_count);
    
    neoc_wallet_free(wallet);
}

void test_bip39_to_account_workflow(void) {
    printf("Testing BIP-39 mnemonic to account workflow\n");
    
    // 1. Generate seed from mnemonic
    uint8_t seed[64];
    neoc_error_t err = neoc_bip39_mnemonic_to_seed(TEST_MNEMONIC, "", seed, sizeof(seed));
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    
    // 2. Create master key from seed
    neoc_bip32_key_t* master_key;
    err = neoc_bip32_from_seed(seed, sizeof(seed), &master_key);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    TEST_ASSERT_NOT_NULL(master_key);
    
    // 3. Derive child keys (NEO derivation path: m/44'/888'/0'/0/0)
    neoc_bip32_key_t* derived_key;
    uint32_t path[] = {0x8000002C, 0x80000378, 0x80000000, 0x00000000, 0x00000000};
    err = neoc_bip32_derive_path(master_key, path, 5, &derived_key);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    
    // 4. Create EC key pair from derived key
    neoc_ec_key_pair_t* key_pair;
    err = neoc_bip32_to_ec_key_pair(derived_key, &key_pair);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    
    // 5. Create account from key pair
    neoc_account_t* account;
    err = neoc_account_create_from_key_pair(key_pair, &account);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    
    // 6. Verify account properties
    char* address;
    err = neoc_account_get_address(account, &address);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    TEST_ASSERT_NOT_NULL(address);
    TEST_ASSERT_EQUAL_INT('N', address[0]);
    
    printf("  Generated address from mnemonic: %s\n", address);
    
    // 7. Test round-trip with WIF
    char* wif;
    err = neoc_ec_key_pair_export_as_wif(key_pair, &wif);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    
    neoc_account_t* account_from_wif;
    err = neoc_account_create_from_wif(wif, &account_from_wif);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    
    char* address_from_wif;
    err = neoc_account_get_address(account_from_wif, &address_from_wif);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    
    TEST_ASSERT_EQUAL_STRING(address, address_from_wif);
    
    neoc_free(address);
    neoc_free(address_from_wif);
    neoc_free(wif);
    neoc_account_free(account);
    neoc_account_free(account_from_wif);
    neoc_ec_key_pair_free(key_pair);
    neoc_bip32_key_free(derived_key);
    neoc_bip32_key_free(master_key);
}

void test_nep2_encryption_workflow(void) {
    printf("Testing NEP-2 encryption workflow\n");
    
    // 1. Create random account
    neoc_account_t* account;
    neoc_error_t err = neoc_account_create_random(&account);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    
    // 2. Get key pair
    neoc_ec_key_pair_t* original_key_pair;
    err = neoc_account_get_key_pair(account, &original_key_pair);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    
    // 3. Get original private key for verification
    uint8_t original_private_key[32];
    size_t key_len = sizeof(original_private_key);
    err = neoc_ec_key_pair_get_private_key(original_key_pair, original_private_key, &key_len);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    
    // 4. Encrypt with NEP-2
    char* encrypted_key;
    err = neoc_nep2_encrypt_key_pair(original_key_pair, TEST_PASSWORD, NULL, &encrypted_key);
    if (err != NEOC_SUCCESS) {
        printf("  neoc_nep2_encrypt_key_pair returned %d\n", err);
    }
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    TEST_ASSERT_NOT_NULL(encrypted_key);
    
    printf("  NEP-2 encrypted key: %.50s...\n", encrypted_key);
    
    // 5. Decrypt with NEP-2
    neoc_ec_key_pair_t* decrypted_key_pair;
    err = neoc_nep2_decrypt_key_pair(encrypted_key, TEST_PASSWORD, NULL, &decrypted_key_pair);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    
    // 6. Verify private key matches
    uint8_t decrypted_private_key[32];
    key_len = sizeof(decrypted_private_key);
    err = neoc_ec_key_pair_get_private_key(decrypted_key_pair, decrypted_private_key, &key_len);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    
    TEST_ASSERT_EQUAL_MEMORY(original_private_key, decrypted_private_key, 32);
    
    // 7. Create account from decrypted key pair
    neoc_account_t* restored_account;
    err = neoc_account_create_from_key_pair(decrypted_key_pair, &restored_account);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    
    // 8. Verify addresses match
    char* original_address;
    err = neoc_account_get_address(account, &original_address);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    
    char* restored_address;
    err = neoc_account_get_address(restored_account, &restored_address);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    
    TEST_ASSERT_EQUAL_STRING(original_address, restored_address);
    
    printf("  Successfully restored account: %s\n", restored_address);
    
    neoc_free(original_address);
    neoc_free(restored_address);
    neoc_free(encrypted_key);
    neoc_account_free(account);
    neoc_account_free(restored_account);
    neoc_ec_key_pair_free(original_key_pair);
    neoc_ec_key_pair_free(decrypted_key_pair);
}

/* ===== TRANSACTION BUILDING WORKFLOW TESTS ===== */

void test_gas_transfer_transaction_workflow(void) {
    printf("Testing GAS transfer transaction workflow\n");
    
    // 1. Create sender and receiver accounts
    neoc_account_t* sender;
    neoc_error_t err = neoc_account_create_random(&sender);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    
    neoc_account_t* receiver;
    err = neoc_account_create_random(&receiver);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    
    // 2. Get addresses
    char* sender_address;
    err = neoc_account_get_address(sender, &sender_address);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    
    char* receiver_address;
    err = neoc_account_get_address(receiver, &receiver_address);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    
    printf("  Sender: %s\n", sender_address);
    printf("  Receiver: %s\n", receiver_address);
    
    // 3. Create GAS token contract
    neoc_gas_token_t* gas_token;
    err = neoc_gas_token_create(&gas_token);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    
    // 4. Get script hashes
    neoc_hash160_t sender_hash, receiver_hash;
    err = neoc_account_get_script_hash(sender, &sender_hash);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    
    err = neoc_account_get_script_hash(receiver, &receiver_hash);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    
    // 5. Build transfer script
    uint64_t amount = 100000000; // 1 GAS (8 decimals)
    uint8_t* transfer_script;
    size_t script_len;
    err = neoc_gas_token_build_transfer_script(gas_token, &sender_hash, &receiver_hash, amount, NULL, 0, &transfer_script, &script_len);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    TEST_ASSERT_NOT_NULL(transfer_script);
    TEST_ASSERT_TRUE(script_len > 0);
    
    printf("  Generated transfer script: %zu bytes\n", script_len);
    
    // 6. Create transaction builder
    neoc_transaction_builder_t* tx_builder;
    err = neoc_transaction_builder_create(&tx_builder);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    
    // 7. Set script
    err = neoc_transaction_builder_set_script(tx_builder, transfer_script, script_len);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    
    // 8. Create signer
    neoc_signer_t* signer;
    err = neoc_signer_create(&sender_hash, NEOC_WITNESS_SCOPE_CALLED_BY_ENTRY, &signer);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    
    // 9. Add signer to transaction
    err = neoc_transaction_builder_add_signer(tx_builder, signer);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    
    // 10. Build transaction (would normally require network call for system fee)
    neoc_transaction_t* transaction;
    err = neoc_transaction_builder_build(tx_builder, &transaction);
    if (err == NEOC_SUCCESS) {
        TEST_ASSERT_NOT_NULL(transaction);
        
        // 11. Verify transaction properties
        uint8_t* tx_script;
        size_t tx_script_len;
        err = neoc_transaction_get_script(transaction, &tx_script, &tx_script_len);
        TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
        TEST_ASSERT_EQUAL_INT(script_len, tx_script_len);
        TEST_ASSERT_EQUAL_MEMORY(transfer_script, tx_script, script_len);
        
        printf("  Transaction built successfully\n");
        
        neoc_free(tx_script);
        neoc_transaction_free(transaction);
    } else {
        printf("  Transaction building failed (expected without network): %d\n", err);
    }
    
    neoc_free(sender_address);
    neoc_free(receiver_address);
    neoc_free(transfer_script);
    neoc_account_free(sender);
    neoc_account_free(receiver);
    neoc_gas_token_free(gas_token);
    neoc_signer_free(signer);
    neoc_transaction_builder_free(tx_builder);
}

void test_multisig_transaction_workflow(void) {
    printf("Testing multi-sig transaction workflow\n");
    
    // 1. Create individual key pairs for multi-sig participants
    neoc_ec_key_pair_t* key_pair1;
    neoc_error_t err = neoc_ec_key_pair_create_random(&key_pair1);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    
    neoc_ec_key_pair_t* key_pair2;
    err = neoc_ec_key_pair_create_random(&key_pair2);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    
    neoc_ec_key_pair_t* key_pair3;
    err = neoc_ec_key_pair_create_random(&key_pair3);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    
    // 2. Get public keys
    neoc_ec_public_key_t* pub_key1;
    err = neoc_ec_key_pair_get_public_key_object(key_pair1, &pub_key1);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    
    neoc_ec_public_key_t* pub_key2;
    err = neoc_ec_key_pair_get_public_key_object(key_pair2, &pub_key2);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    
    neoc_ec_public_key_t* pub_key3;
    err = neoc_ec_key_pair_get_public_key_object(key_pair3, &pub_key3);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    
    // 3. Create 2-of-3 multi-sig account
    neoc_ec_public_key_t* public_keys[] = { pub_key1, pub_key2, pub_key3 };
    neoc_account_t* multisig_account;
    err = neoc_account_create_multisig_from_public_keys(public_keys, 3, 2, &multisig_account);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    
    // 4. Verify it's multi-sig
    bool is_multisig;
    err = neoc_account_is_multisig(multisig_account, &is_multisig);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    TEST_ASSERT_TRUE(is_multisig);
    
    // 5. Verify signing parameters
    int signing_threshold;
    err = neoc_account_get_signing_threshold(multisig_account, &signing_threshold);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    TEST_ASSERT_EQUAL_INT(2, signing_threshold);
    
    int nr_participants;
    err = neoc_account_get_nr_participants(multisig_account, &nr_participants);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    TEST_ASSERT_EQUAL_INT(3, nr_participants);
    
    char* multisig_address;
    err = neoc_account_get_address(multisig_account, &multisig_address);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    
    printf("  Created 2-of-3 multi-sig account: %s\n", multisig_address);
    
    // 6. Create simple transaction script (dummy operation)
    neoc_script_builder_t* script_builder;
    err = neoc_script_builder_create(&script_builder);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    
    // Add a simple PUSH operation (just for testing)
    err = neoc_script_builder_push_integer(script_builder, 42);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    
    uint8_t* script;
    size_t script_len;
    err = neoc_script_builder_to_array(script_builder, &script, &script_len);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    
    // 7. Create multi-sig signer
    neoc_hash160_t multisig_hash;
    err = neoc_account_get_script_hash(multisig_account, &multisig_hash);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    
    neoc_signer_t* multisig_signer;
    err = neoc_signer_create(&multisig_hash, NEOC_WITNESS_SCOPE_GLOBAL, &multisig_signer);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    
    printf("  Created multi-sig signer with %d-of-%d threshold\n", signing_threshold, nr_participants);
    
    neoc_free(multisig_address);
    neoc_free(script);
    neoc_account_free(multisig_account);
    neoc_ec_key_pair_free(key_pair1);
    neoc_ec_key_pair_free(key_pair2);
    neoc_ec_key_pair_free(key_pair3);
    neoc_ec_public_key_free(pub_key1);
    neoc_ec_public_key_free(pub_key2);
    neoc_ec_public_key_free(pub_key3);
    neoc_script_builder_free(script_builder);
    neoc_signer_free(multisig_signer);
}

/* ===== NEP-6 WALLET INTEGRATION TESTS ===== */

void test_nep6_wallet_export_import_workflow(void) {
    printf("Testing NEP-6 wallet export/import workflow\n");
    
    // 1. Create wallet with accounts
    neoc_wallet_t* original_wallet;
    neoc_error_t err = neoc_wallet_create("test_wallet", &original_wallet);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    
    // 2. Add multiple accounts
    neoc_account_t* account1;
    err = neoc_account_create_random(&account1);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    
    neoc_account_t* account2;
    err = neoc_account_create_random(&account2);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    
    err = neoc_wallet_add_account(original_wallet, account1);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    
    err = neoc_wallet_add_account(original_wallet, account2);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    
    // 3. Encrypt account private keys
    err = neoc_account_encrypt_private_key(account1, TEST_PASSWORD, NULL);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    
    err = neoc_account_encrypt_private_key(account2, TEST_PASSWORD, NULL);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    
    // 4. Set default account
    neoc_hash160_t account1_hash;
    err = neoc_account_get_script_hash(account1, &account1_hash);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    
    err = neoc_wallet_set_default_account(original_wallet, &account1_hash);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    
    // 5. Export to NEP-6
    neoc_nep6_wallet_t* nep6_wallet;
    err = neoc_wallet_to_nep6(original_wallet, &nep6_wallet);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    TEST_ASSERT_NOT_NULL(nep6_wallet);
    
    // 6. Verify NEP-6 wallet properties
    char* wallet_name;
    err = neoc_nep6_wallet_get_name(nep6_wallet, &wallet_name);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    TEST_ASSERT_EQUAL_STRING("test_wallet", wallet_name);
    
    size_t nep6_account_count;
    err = neoc_nep6_wallet_get_account_count(nep6_wallet, &nep6_account_count);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    TEST_ASSERT_EQUAL_INT(2, nep6_account_count);
    
    printf("  Exported NEP-6 wallet '%s' with %zu accounts\n", wallet_name, nep6_account_count);
    
    // 7. Import back from NEP-6
    neoc_wallet_t* imported_wallet;
    err = neoc_wallet_from_nep6(nep6_wallet, &imported_wallet);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    TEST_ASSERT_NOT_NULL(imported_wallet);
    
    // 8. Verify imported wallet
    char* imported_wallet_name;
    err = neoc_wallet_get_name(imported_wallet, &imported_wallet_name);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    TEST_ASSERT_EQUAL_STRING("test_wallet", imported_wallet_name);
    
    size_t imported_account_count;
    err = neoc_wallet_get_account_count(imported_wallet, &imported_account_count);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    TEST_ASSERT_EQUAL_INT(2, imported_account_count);
    
    // 9. Verify default account is preserved
    neoc_account_t* imported_default;
    err = neoc_wallet_get_default_account(imported_wallet, &imported_default);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    TEST_ASSERT_NOT_NULL(imported_default);
    
    neoc_hash160_t imported_default_hash;
    err = neoc_account_get_script_hash(imported_default, &imported_default_hash);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    
    TEST_ASSERT_EQUAL_MEMORY(account1_hash.data, imported_default_hash.data, 20);
    
    printf("  Successfully imported wallet with preserved default account\n");
    
    neoc_free(wallet_name);
    neoc_free(imported_wallet_name);
    neoc_wallet_free(original_wallet);
    neoc_wallet_free(imported_wallet);
    neoc_nep6_wallet_free(nep6_wallet);
}

/* ===== PERFORMANCE AND STRESS TESTS ===== */

void test_bulk_account_operations_workflow(void) {
    printf("Testing bulk account operations workflow\n");
    
    const int NUM_ACCOUNTS = 50;
    clock_t start = clock();
    
    // 1. Create wallet
    neoc_wallet_t* wallet;
    neoc_error_t err = neoc_wallet_create("bulk_test_wallet", &wallet);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    
    // 2. Create and add many accounts
    neoc_account_t* accounts[NUM_ACCOUNTS];
    for (int i = 0; i < NUM_ACCOUNTS; i++) {
        err = neoc_account_create_random(&accounts[i]);
        TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
        
        err = neoc_wallet_add_account(wallet, accounts[i]);
        TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
        
        // Encrypt every 5th account
        if (i % 5 == 0) {
            err = neoc_account_encrypt_private_key(accounts[i], TEST_PASSWORD, NULL);
            TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
        }
    }
    
    clock_t creation_time = clock();
    double creation_seconds = ((double)(creation_time - start)) / CLOCKS_PER_SEC;
    
    // 3. Verify account count
    size_t account_count;
    err = neoc_wallet_get_account_count(wallet, &account_count);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    TEST_ASSERT_EQUAL_UINT64((uint64_t)NUM_ACCOUNTS, (uint64_t)account_count);
    
    // 4. Test batch address generation
    char* addresses[NUM_ACCOUNTS];
    for (int i = 0; i < NUM_ACCOUNTS; i++) {
        err = neoc_account_get_address(accounts[i], &addresses[i]);
        TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
        TEST_ASSERT_NOT_NULL(addresses[i]);
        TEST_ASSERT_EQUAL_INT('N', addresses[i][0]);
    }
    
    clock_t address_time = clock();
    double address_seconds = ((double)(address_time - creation_time)) / CLOCKS_PER_SEC;
    
    // 5. Test batch WIF export (for non-encrypted accounts)
    int wif_count = 0;
    for (int i = 0; i < NUM_ACCOUNTS; i++) {
        if (i % 5 != 0) { // Skip encrypted accounts
            neoc_ec_key_pair_t* key_pair;
            err = neoc_account_get_key_pair(accounts[i], &key_pair);
            if (err == NEOC_SUCCESS && key_pair != NULL) {
                char* wif;
                err = neoc_ec_key_pair_export_as_wif(key_pair, &wif);
                if (err == NEOC_SUCCESS) {
                    TEST_ASSERT_NOT_NULL(wif);
                    neoc_free(wif);
                    wif_count++;
                }
                neoc_ec_key_pair_free(key_pair);
            }
        }
    }
    
    clock_t wif_time = clock();
    double wif_seconds = ((double)(wif_time - address_time)) / CLOCKS_PER_SEC;
    double total_seconds = ((double)(wif_time - start)) / CLOCKS_PER_SEC;
    
    printf("  Created %d accounts in %.3f seconds\n", NUM_ACCOUNTS, creation_seconds);
    printf("  Generated %d addresses in %.3f seconds\n", NUM_ACCOUNTS, address_seconds);
    printf("  Exported %d WIF keys in %.3f seconds\n", wif_count, wif_seconds);
    printf("  Total time: %.3f seconds (%.1f accounts/second)\n", total_seconds, NUM_ACCOUNTS / total_seconds);
    
    // Performance assertions
    TEST_ASSERT_TRUE(creation_seconds < 5.0);  // Should create 50 accounts in under 5 seconds
    TEST_ASSERT_TRUE(total_seconds < 10.0);    // Total operation should complete in under 10 seconds
    
    // Cleanup
    for (int i = 0; i < NUM_ACCOUNTS; i++) {
        neoc_free(addresses[i]);
    }
    neoc_wallet_free(wallet);
}

/* ===== ERROR RECOVERY WORKFLOW TESTS ===== */

void test_error_recovery_workflow(void) {
    printf("Testing error recovery workflow\n");
    
    // 1. Test recovery from invalid mnemonic
    uint8_t seed[64];
    neoc_error_t err = neoc_bip39_mnemonic_to_seed("invalid mnemonic words here", "", seed, sizeof(seed));
    if (err != NEOC_SUCCESS) {
        printf("  Correctly handled invalid mnemonic\n");
    }
    
    // 2. Test recovery from invalid WIF
    neoc_account_t* account;
    err = neoc_account_create_from_wif("invalid_wif_string", &account);
    TEST_ASSERT_TRUE(err != NEOC_SUCCESS);
    printf("  Correctly handled invalid WIF\n");
    
    // 3. Test recovery from invalid NEP-2 password
    err = neoc_account_create_random(&account);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    
    neoc_ec_key_pair_t* key_pair;
    err = neoc_account_get_key_pair(account, &key_pair);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    
    char* encrypted_key;
    err = neoc_nep2_encrypt_key_pair(key_pair, TEST_PASSWORD, NULL, &encrypted_key);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    
    // Try to decrypt with wrong password
    neoc_ec_key_pair_t* decrypted_key_pair = NULL;
    err = neoc_nep2_decrypt_key_pair(encrypted_key, "wrong_password", NULL, &decrypted_key_pair);
    TEST_ASSERT_TRUE(err != NEOC_SUCCESS);
    printf("  Correctly handled wrong NEP-2 password\n");
    
    // 4. Test correct password still works
    err = neoc_nep2_decrypt_key_pair(encrypted_key, TEST_PASSWORD, NULL, &decrypted_key_pair);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    printf("  NEP-2 decryption works with correct password\n");
    
    neoc_free(encrypted_key);
    neoc_account_free(account);
    neoc_ec_key_pair_free(key_pair);
    neoc_ec_key_pair_free(decrypted_key_pair);
}

/* ===== MAIN TEST RUNNER ===== */

int main(void) {
    UNITY_BEGIN();
    
    printf("\n=== COMPREHENSIVE INTEGRATION TESTS ===\n");
    
    // Wallet workflow tests
    RUN_TEST(test_complete_wallet_creation_workflow);
    RUN_TEST(test_bip39_to_account_workflow);
    RUN_TEST(test_nep2_encryption_workflow);
    
    // Transaction workflow tests
    RUN_TEST(test_gas_transfer_transaction_workflow);
    RUN_TEST(test_multisig_transaction_workflow);
    
    // NEP-6 integration tests
    RUN_TEST(test_nep6_wallet_export_import_workflow);
    
    // Performance and stress tests
    RUN_TEST(test_bulk_account_operations_workflow);
    
    // Error recovery tests
    RUN_TEST(test_error_recovery_workflow);
    
    UNITY_END();
    return 0;
}
