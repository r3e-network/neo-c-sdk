/**
 * @file test_account_comprehensive.c
 * @brief Comprehensive Account tests converted from Swift and extended
 */

#include "unity.h"
#include <neoc/neoc.h>
#include <neoc/wallet/account.h>
#include <neoc/wallet/nep6.h>
#include <neoc/crypto/ec_key_pair.h>
#include <neoc/crypto/wif.h>
#include <neoc/crypto/nep2.h>
#include <neoc/utils/neoc_hex.h>
#include <neoc/utils/neoc_base64.h>
#include <neoc/script/script_builder.h>
#include <neoc/types/neoc_hash160.h>
#include <string.h>
#include <stdio.h>

// Test constants (from Swift TestProperties)
static const char* DEFAULT_ACCOUNT_ADDRESS = "NM7Aky765FG8NhhwtxjXRx7jEL1cnw7PBP";
static const char* DEFAULT_ACCOUNT_SCRIPT_HASH = "69ecca587293047be4c59159bf8bc399985c160d";
static const char* DEFAULT_ACCOUNT_VERIFICATION_SCRIPT = "0c21033a4d051b04b7fc0230d2b1aaedfd5a84be279a5361a7358db665ad7857787f1b4156e7b327";
static const char* DEFAULT_ACCOUNT_PUBLIC_KEY = "033a4d051b04b7fc0230d2b1aaedfd5a84be279a5361a7358db665ad7857787f1b";
static const char* DEFAULT_ACCOUNT_PRIVATE_KEY = "84180ac9d6eb6fba207ea4ef9d2200102d1ebeb4b9c07e2c6a738a42742e27a5";
static const char* DEFAULT_ACCOUNT_ENCRYPTED_PRIVATE_KEY = "6PYM7jHL4GmS8Aw2iEFpuaHTCUKjhT4mwVqdoozGU6sUE25BjV4ePXDdLz";
static const char* DEFAULT_ACCOUNT_WIF = "L1eV34wPoj9weqhGijdDLtVQzUpWGHszXXpdU9dPuh2nRFFzFa7E";
static const char* DEFAULT_ACCOUNT_PASSWORD = "neo";

// Committee account (multi-sig)
static const char* COMMITTEE_ACCOUNT_ADDRESS = "NXXazKH39yNFWWZF5MJ8tEN98VYHwzn7g3";
static const char* COMMITTEE_ACCOUNT_VERIFICATION_SCRIPT = "110c21033a4d051b04b7fc0230d2b1aaedfd5a84be279a5361a7358db665ad7857787f1b11419ed0dc3a";

void setUp(void) {
    neoc_init();
}

void tearDown(void) {
    neoc_cleanup();
}

/* ===== ACCOUNT CREATION TESTS ===== */

void test_create_generic_account(void) {
    printf("Testing generic account creation\n");
    
    neoc_account_t* account;
    neoc_error_t err = neoc_account_create_random(&account);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    TEST_ASSERT_NOT_NULL(account);
    
    // Check that all required properties are set
    char* address;
    err = neoc_account_get_address(account, &address);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    TEST_ASSERT_NOT_NULL(address);
    TEST_ASSERT_TRUE(strlen(address) > 0);
    TEST_ASSERT_EQUAL_INT('N', address[0]); // Neo addresses start with 'N'
    
    uint8_t* verification_script;
    size_t script_len;
    err = neoc_account_get_verification_script(account, &verification_script, &script_len);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    TEST_ASSERT_NOT_NULL(verification_script);
    TEST_ASSERT_TRUE(script_len > 0);
    
    neoc_ec_key_pair_t* key_pair = neoc_account_get_key_pair_ptr(account);
    TEST_ASSERT_NOT_NULL(key_pair);
    
    char* label;
    err = neoc_account_get_label(account, &label);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    TEST_ASSERT_NOT_NULL(label);
    
    bool is_locked;
    err = neoc_account_is_locked(account, &is_locked);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    TEST_ASSERT_FALSE(is_locked);
    
    bool is_default;
    err = neoc_account_is_default(account, &is_default);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    TEST_ASSERT_FALSE(is_default);
    
    bool has_encrypted_key;
    err = neoc_account_has_encrypted_private_key(account, &has_encrypted_key);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    TEST_ASSERT_FALSE(has_encrypted_key);
    
    neoc_free(address);
    neoc_free(verification_script);
    neoc_free(label);
    neoc_account_free(account);
}

void test_init_account_from_existing_key_pair(void) {
    printf("Testing account creation from existing key pair\n");
    
    // Create key pair from known private key
    uint8_t private_key[32];
    size_t decoded_len;
    neoc_error_t err = neoc_hex_decode(DEFAULT_ACCOUNT_PRIVATE_KEY, private_key, sizeof(private_key), &decoded_len);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    
    neoc_ec_key_pair_t* key_pair;
    err = neoc_ec_key_pair_create_from_private_key(private_key, &key_pair);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    
    // Create account from key pair
    neoc_account_t* account;
    err = neoc_account_create_from_key_pair(key_pair, &account);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    TEST_ASSERT_NOT_NULL(account);
    
    // Verify properties
    bool is_multisig;
    err = neoc_account_is_multisig(account, &is_multisig);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    TEST_ASSERT_FALSE(is_multisig);
    
    char* address;
    err = neoc_account_get_address(account, &address);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    TEST_ASSERT_EQUAL_STRING(DEFAULT_ACCOUNT_ADDRESS, address);
    
    char* label;
    err = neoc_account_get_label(account, &label);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    TEST_ASSERT_EQUAL_STRING(DEFAULT_ACCOUNT_ADDRESS, label);
    
    uint8_t* verification_script;
    size_t script_len;
    err = neoc_account_get_verification_script(account, &verification_script, &script_len);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    
    // Convert expected verification script from hex
    uint8_t expected_script[256];
    size_t expected_len;
    err = neoc_hex_decode(DEFAULT_ACCOUNT_VERIFICATION_SCRIPT, expected_script, sizeof(expected_script), &expected_len);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    
    TEST_ASSERT_EQUAL_INT(expected_len, script_len);
    TEST_ASSERT_EQUAL_MEMORY(expected_script, verification_script, script_len);
    
    neoc_free(address);
    neoc_free(label);
    neoc_free(verification_script);
    neoc_account_free(account);
    neoc_ec_key_pair_free(key_pair);
}

void test_account_from_verification_script(void) {
    printf("Testing account creation from verification script\n");
    
    // Create account from verification script
    uint8_t script_bytes[256];
    size_t script_len;
    neoc_error_t err = neoc_hex_decode(DEFAULT_ACCOUNT_VERIFICATION_SCRIPT, script_bytes, sizeof(script_bytes), &script_len);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    
    neoc_account_t* account;
    err = neoc_account_create_from_verification_script(script_bytes, script_len, &account);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    TEST_ASSERT_NOT_NULL(account);
    
    // Verify address matches expected
    char* address;
    err = neoc_account_get_address(account, &address);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    TEST_ASSERT_EQUAL_STRING(DEFAULT_ACCOUNT_ADDRESS, address);
    
    // Verify verification script matches
    uint8_t* retrieved_script;
    size_t retrieved_len;
    err = neoc_account_get_verification_script(account, &retrieved_script, &retrieved_len);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    TEST_ASSERT_EQUAL_INT(script_len, retrieved_len);
    TEST_ASSERT_EQUAL_MEMORY(script_bytes, retrieved_script, script_len);
    
    neoc_free(address);
    neoc_free(retrieved_script);
    neoc_account_free(account);
}

void test_account_from_public_key(void) {
    printf("Testing account creation from public key\n");
    
    // Create public key
    uint8_t public_key_bytes[33];
    size_t decoded_len;
    neoc_error_t err = neoc_hex_decode(DEFAULT_ACCOUNT_PUBLIC_KEY, public_key_bytes, sizeof(public_key_bytes), &decoded_len);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    TEST_ASSERT_EQUAL_INT(33, decoded_len);
    
    neoc_ec_public_key_t* public_key;
    err = neoc_ec_public_key_from_bytes(public_key_bytes, decoded_len, &public_key);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    
    // Create account from public key
    neoc_account_t* account;
    err = neoc_account_create_from_public_key(public_key, &account);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    TEST_ASSERT_NOT_NULL(account);
    
    // Verify address
    char* address;
    err = neoc_account_get_address(account, &address);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    TEST_ASSERT_EQUAL_STRING(DEFAULT_ACCOUNT_ADDRESS, address);
    
    // Verify verification script
    uint8_t* verification_script;
    size_t script_len;
    err = neoc_account_get_verification_script(account, &verification_script, &script_len);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    
    uint8_t expected_script[256];
    size_t expected_len;
    err = neoc_hex_decode(DEFAULT_ACCOUNT_VERIFICATION_SCRIPT, expected_script, sizeof(expected_script), &expected_len);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    
    TEST_ASSERT_EQUAL_INT(expected_len, script_len);
    TEST_ASSERT_EQUAL_MEMORY(expected_script, verification_script, script_len);
    
    neoc_free(address);
    neoc_free(verification_script);
    neoc_account_free(account);
    neoc_ec_public_key_free(public_key);
}

/* ===== MULTI-SIG ACCOUNT TESTS ===== */

void test_create_multisig_account_from_public_keys(void) {
    printf("Testing multi-sig account creation from public keys\n");
    
    // Create public key
    uint8_t public_key_bytes[33];
    size_t decoded_len;
    neoc_error_t err = neoc_hex_decode(DEFAULT_ACCOUNT_PUBLIC_KEY, public_key_bytes, sizeof(public_key_bytes), &decoded_len);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    
    neoc_ec_public_key_t* public_key;
    err = neoc_ec_public_key_from_bytes(public_key_bytes, decoded_len, &public_key);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    
    // Create 1-of-1 multi-sig account
    neoc_ec_public_key_t* public_keys[] = { public_key };
    neoc_account_t* account;
    err = neoc_account_create_multisig_from_public_keys(public_keys, 1, 1, &account);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    TEST_ASSERT_NOT_NULL(account);
    
    // Verify it's multi-sig
    bool is_multisig;
    err = neoc_account_is_multisig(account, &is_multisig);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    TEST_ASSERT_TRUE(is_multisig);
    
    // Verify address (should be committee account address for 1-of-1 with this key)
    char* address;
    err = neoc_account_get_address(account, &address);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    TEST_ASSERT_EQUAL_STRING(COMMITTEE_ACCOUNT_ADDRESS, address);
    char* label;
    err = neoc_account_get_label(account, &label);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    TEST_ASSERT_EQUAL_STRING(COMMITTEE_ACCOUNT_ADDRESS, label);
    
    // Verify verification script
    uint8_t* verification_script;
    size_t script_len;
    err = neoc_account_get_verification_script(account, &verification_script, &script_len);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    
    uint8_t expected_script[256];
    size_t expected_len;
    err = neoc_hex_decode(COMMITTEE_ACCOUNT_VERIFICATION_SCRIPT, expected_script, sizeof(expected_script), &expected_len);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);

    TEST_ASSERT_EQUAL_INT(expected_len, script_len);
    TEST_ASSERT_EQUAL_MEMORY(expected_script, verification_script, script_len);

    TEST_ASSERT_EQUAL_STRING(COMMITTEE_ACCOUNT_ADDRESS, address);
    
    neoc_free(address);
    neoc_free(label);
    neoc_free(verification_script);
    neoc_account_free(account);
    neoc_ec_public_key_free(public_key);
}

void test_create_multisig_account_with_address(void) {
    printf("Testing multi-sig account creation with address only\n");
    
    neoc_account_t* account;
    neoc_error_t err = neoc_account_create_multisig_with_address(COMMITTEE_ACCOUNT_ADDRESS, 4, 7, &account);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    TEST_ASSERT_NOT_NULL(account);
    
    // Verify it's multi-sig
    bool is_multisig;
    err = neoc_account_is_multisig(account, &is_multisig);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    TEST_ASSERT_TRUE(is_multisig);
    
    // Verify signing threshold and participants
    int signing_threshold;
    err = neoc_account_get_signing_threshold(account, &signing_threshold);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    TEST_ASSERT_EQUAL_INT(4, signing_threshold);
    
    int nr_participants;
    err = neoc_account_get_nr_participants(account, &nr_participants);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    TEST_ASSERT_EQUAL_INT(7, nr_participants);
    
    // Verify address
    char* address;
    err = neoc_account_get_address(account, &address);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    TEST_ASSERT_EQUAL_STRING(COMMITTEE_ACCOUNT_ADDRESS, address);
    
    char* label;
    err = neoc_account_get_label(account, &label);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    TEST_ASSERT_EQUAL_STRING(COMMITTEE_ACCOUNT_ADDRESS, label);
    
    // Verification script should be null since we only provided address
    uint8_t* verification_script;
    size_t script_len;
    err = neoc_account_get_verification_script(account, &verification_script, &script_len);
    // This might return null or empty, which is expected for address-only multi-sig
    if (err == NEOC_SUCCESS && verification_script != NULL) {
        neoc_free(verification_script);
    }
    
    neoc_free(address);
    neoc_free(label);
    neoc_account_free(account);
}

/* ===== PRIVATE KEY ENCRYPTION/DECRYPTION TESTS ===== */

void test_encrypt_private_key(void) {
    printf("Testing private key encryption\n");
    
    // Create account from known key pair
    uint8_t private_key[32];
    size_t decoded_len;
    neoc_error_t err = neoc_hex_decode(DEFAULT_ACCOUNT_PRIVATE_KEY, private_key, sizeof(private_key), &decoded_len);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    
    neoc_ec_key_pair_t* key_pair;
    err = neoc_ec_key_pair_create_from_private_key(private_key, &key_pair);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    
    neoc_account_t* account;
    err = neoc_account_create_from_key_pair(key_pair, &account);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    
    // Encrypt private key
    err = neoc_account_encrypt_private_key(account, DEFAULT_ACCOUNT_PASSWORD, NULL);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    
    // Verify encrypted key matches expected
    char* encrypted_key;
    err = neoc_account_get_encrypted_private_key(account, &encrypted_key);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    TEST_ASSERT_NOT_NULL(encrypted_key);
    TEST_ASSERT_EQUAL_STRING(DEFAULT_ACCOUNT_ENCRYPTED_PRIVATE_KEY, encrypted_key);
    
    neoc_free(encrypted_key);
    neoc_account_free(account);
    neoc_ec_key_pair_free(key_pair);
}

void test_fail_encrypt_account_without_private_key(void) {
    printf("Testing encryption failure for account without private key\n");
    
    neoc_account_t* account;
    neoc_error_t err = neoc_account_create_from_address(DEFAULT_ACCOUNT_ADDRESS, &account);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    
    // Try to encrypt - should fail
    err = neoc_account_encrypt_private_key(account, "password", NULL);
    TEST_ASSERT_TRUE(err != NEOC_SUCCESS);
    
    neoc_account_free(account);
}

void test_decrypt_with_standard_scrypt_params(void) {
    printf("Testing private key decryption with standard scrypt params\n");
    
    // Create NEP-6 account with encrypted key
    neoc_nep6_account_t* nep6_account;
    neoc_error_t err = neoc_nep6_account_create(DEFAULT_ACCOUNT_ADDRESS, "", false, false, DEFAULT_ACCOUNT_ENCRYPTED_PRIVATE_KEY, &nep6_account);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    
    // Create account from NEP-6
    neoc_account_t* account;
    err = neoc_account_create_from_nep6(nep6_account, &account);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    
    // Decrypt private key
    err = neoc_account_decrypt_private_key(account, DEFAULT_ACCOUNT_PASSWORD, NULL);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    
    // Verify private key matches expected
    neoc_ec_key_pair_t* key_pair = neoc_account_get_key_pair_ptr(account);
    TEST_ASSERT_NOT_NULL(key_pair);
    
    uint8_t decrypted_key[32];
    size_t key_len = sizeof(decrypted_key);
    err = neoc_ec_key_pair_get_private_key(key_pair, decrypted_key, &key_len);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    
    uint8_t expected_key[32];
    size_t decoded_len;
    err = neoc_hex_decode(DEFAULT_ACCOUNT_PRIVATE_KEY, expected_key, sizeof(expected_key), &decoded_len);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    
    TEST_ASSERT_EQUAL_MEMORY(expected_key, decrypted_key, 32);
    
    // Test decrypting again (should work without issue)
    err = neoc_account_decrypt_private_key(account, DEFAULT_ACCOUNT_PASSWORD, NULL);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    
    neoc_account_free(account);
    neoc_nep6_account_free(nep6_account);
}

void test_fail_decrypting_account_without_encrypted_key(void) {
    printf("Testing decryption failure for account without encrypted key\n");
    
    neoc_account_t* account;
    neoc_error_t err = neoc_account_create_from_address(DEFAULT_ACCOUNT_ADDRESS, &account);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    
    // Try to decrypt - should fail
    err = neoc_account_decrypt_private_key(account, DEFAULT_ACCOUNT_PASSWORD, NULL);
    TEST_ASSERT_TRUE(err != NEOC_SUCCESS);
    
    neoc_account_free(account);
}

/* ===== WIF INTEGRATION TESTS ===== */

void test_create_account_from_wif(void) {
    printf("Testing account creation from WIF\n");
    
    neoc_account_t* account;
    neoc_error_t err = neoc_account_create_from_wif(DEFAULT_ACCOUNT_WIF, &account);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    TEST_ASSERT_NOT_NULL(account);
    
    // Create expected key pair for comparison
    uint8_t expected_private_key[32];
    size_t decoded_len;
    err = neoc_hex_decode(DEFAULT_ACCOUNT_PRIVATE_KEY, expected_private_key, sizeof(expected_private_key), &decoded_len);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    
    neoc_ec_key_pair_t* expected_key_pair;
    err = neoc_ec_key_pair_create_from_private_key(expected_private_key, &expected_key_pair);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    
    // Verify key pair matches
    neoc_ec_key_pair_t* account_key_pair = neoc_account_get_key_pair_ptr(account);
    TEST_ASSERT_NOT_NULL(account_key_pair);
    
    uint8_t account_private_key[32];
    size_t key_len = sizeof(account_private_key);
    err = neoc_ec_key_pair_get_private_key(account_key_pair, account_private_key, &key_len);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    
    TEST_ASSERT_EQUAL_MEMORY(expected_private_key, account_private_key, 32);
    
    // Verify other properties
    char* address;
    err = neoc_account_get_address(account, &address);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    TEST_ASSERT_EQUAL_STRING(DEFAULT_ACCOUNT_ADDRESS, address);
    
    char* label;
    err = neoc_account_get_label(account, &label);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    TEST_ASSERT_EQUAL_STRING(DEFAULT_ACCOUNT_ADDRESS, label);
    
    // Should not have encrypted key initially
    bool has_encrypted;
    err = neoc_account_has_encrypted_private_key(account, &has_encrypted);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    TEST_ASSERT_FALSE(has_encrypted);
    
    // Verify script hash
    neoc_hash160_t script_hash;
    err = neoc_account_get_script_hash(account, &script_hash);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    
    uint8_t expected_script_hash[20];
    err = neoc_hex_decode(DEFAULT_ACCOUNT_SCRIPT_HASH, expected_script_hash, sizeof(expected_script_hash), &decoded_len);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    
    TEST_ASSERT_EQUAL_MEMORY(expected_script_hash, script_hash.data, 20);
    
    // Verify flags
    bool is_default, is_locked;
    err = neoc_account_is_default(account, &is_default);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    TEST_ASSERT_FALSE(is_default);
    
    err = neoc_account_is_locked(account, &is_locked);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    TEST_ASSERT_FALSE(is_locked);
    
    // Verify verification script
    uint8_t* verification_script;
    size_t script_len;
    err = neoc_account_get_verification_script(account, &verification_script, &script_len);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    
    uint8_t expected_verification_script[256];
    size_t expected_script_len;
    err = neoc_hex_decode(DEFAULT_ACCOUNT_VERIFICATION_SCRIPT, expected_verification_script, sizeof(expected_verification_script), &expected_script_len);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    
    TEST_ASSERT_EQUAL_INT(expected_script_len, script_len);
    TEST_ASSERT_EQUAL_MEMORY(expected_verification_script, verification_script, script_len);
    
    neoc_free(address);
    neoc_free(label);
    neoc_free(verification_script);
    neoc_account_free(account);
    neoc_ec_key_pair_free(expected_key_pair);
}

void test_create_account_from_address(void) {
    printf("Testing account creation from address only\n");
    
    neoc_account_t* account;
    neoc_error_t err = neoc_account_create_from_address(DEFAULT_ACCOUNT_ADDRESS, &account);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    TEST_ASSERT_NOT_NULL(account);
    
    char* address;
    err = neoc_account_get_address(account, &address);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    TEST_ASSERT_EQUAL_STRING(DEFAULT_ACCOUNT_ADDRESS, address);
    
    char* label;
    err = neoc_account_get_label(account, &label);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    TEST_ASSERT_EQUAL_STRING(DEFAULT_ACCOUNT_ADDRESS, label);
    
    neoc_hash160_t script_hash;
    err = neoc_account_get_script_hash(account, &script_hash);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    
    uint8_t expected_script_hash[20];
    size_t decoded_len;
    err = neoc_hex_decode(DEFAULT_ACCOUNT_SCRIPT_HASH, expected_script_hash, sizeof(expected_script_hash), &decoded_len);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    
    TEST_ASSERT_EQUAL_MEMORY(expected_script_hash, script_hash.data, 20);
    
    bool is_default, is_locked;
    err = neoc_account_is_default(account, &is_default);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    TEST_ASSERT_FALSE(is_default);
    
    err = neoc_account_is_locked(account, &is_locked);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    TEST_ASSERT_FALSE(is_locked);
    
    // Should not have verification script for address-only account
    uint8_t* verification_script;
    size_t script_len;
    err = neoc_account_get_verification_script(account, &verification_script, &script_len);
    // This might return null or empty, which is expected for address-only accounts
    if (err == NEOC_SUCCESS && verification_script != NULL) {
        neoc_free(verification_script);
    }
    
    neoc_free(address);
    neoc_free(label);
    neoc_account_free(account);
}

/* ===== ACCOUNT STATE MANAGEMENT TESTS ===== */

void test_account_lock_unlock(void) {
    printf("Testing account lock/unlock functionality\n");
    
    neoc_account_t* account;
    neoc_error_t err = neoc_account_create_from_address(DEFAULT_ACCOUNT_ADDRESS, &account);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    
    // Initially should not be locked
    bool is_locked;
    err = neoc_account_is_locked(account, &is_locked);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    TEST_ASSERT_FALSE(is_locked);
    
    // Lock the account
    err = neoc_account_lock(account);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    
    // Verify it's locked
    err = neoc_account_is_locked(account, &is_locked);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    TEST_ASSERT_TRUE(is_locked);
    
    // Unlock the account
    err = neoc_account_unlock(account);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    
    // Verify it's unlocked
    err = neoc_account_is_locked(account, &is_locked);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    TEST_ASSERT_FALSE(is_locked);
    
    neoc_account_free(account);
}

/* ===== MULTISIG DETECTION TESTS ===== */

void test_is_multisig(void) {
    printf("Testing multi-sig account detection\n");
    
    // Regular account should not be multi-sig
    neoc_account_t* regular_account;
    neoc_error_t err = neoc_account_create_from_address(DEFAULT_ACCOUNT_ADDRESS, &regular_account);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    
    bool is_multisig;
    err = neoc_account_is_multisig(regular_account, &is_multisig);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    TEST_ASSERT_FALSE(is_multisig);
    
    // Multi-sig account with address only
    neoc_account_t* multisig_account1;
    err = neoc_account_create_multisig_with_address(COMMITTEE_ACCOUNT_ADDRESS, 1, 1, &multisig_account1);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    
    err = neoc_account_is_multisig(multisig_account1, &is_multisig);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    
    TEST_ASSERT_TRUE(is_multisig);
    
    // Multi-sig account from verification script
    uint8_t committee_script[256];
    size_t script_len;
    err = neoc_hex_decode(COMMITTEE_ACCOUNT_VERIFICATION_SCRIPT, committee_script, sizeof(committee_script), &script_len);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    
    neoc_account_t* multisig_account2;
    err = neoc_account_create_from_verification_script(committee_script, script_len, &multisig_account2);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    
    err = neoc_account_is_multisig(multisig_account2, &is_multisig);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    TEST_ASSERT_TRUE(is_multisig);
    
    // Regular account from verification script should not be multi-sig
    uint8_t regular_script[256];
    err = neoc_hex_decode(DEFAULT_ACCOUNT_VERIFICATION_SCRIPT, regular_script, sizeof(regular_script), &script_len);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    
    neoc_account_t* regular_account2;
    err = neoc_account_create_from_verification_script(regular_script, script_len, &regular_account2);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    
    err = neoc_account_is_multisig(regular_account2, &is_multisig);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    TEST_ASSERT_FALSE(is_multisig);
    
    neoc_account_free(regular_account);
    neoc_account_free(multisig_account1);
    neoc_account_free(multisig_account2);
    neoc_account_free(regular_account2);
}

/* ===== NULL VALUES FOR NON-MULTISIG TESTS ===== */

void test_null_values_when_not_multisig(void) {
    printf("Testing null values for non-multi-sig account\n");
    
    neoc_account_t* account;
    neoc_error_t err = neoc_account_create_from_address(DEFAULT_ACCOUNT_ADDRESS, &account);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    
    int signing_threshold;
    err = neoc_account_get_signing_threshold(account, &signing_threshold);
    // Should fail or return invalid value for non-multisig account
    TEST_ASSERT_TRUE(err != NEOC_SUCCESS || signing_threshold < 0);
    
    int nr_participants;
    err = neoc_account_get_nr_participants(account, &nr_participants);
    // Should fail or return invalid value for non-multisig account
    TEST_ASSERT_TRUE(err != NEOC_SUCCESS || nr_participants < 0);
    
    neoc_account_free(account);
}

/* ===== ERROR HANDLING TESTS ===== */

void test_account_error_handling(void) {
    printf("Testing account error handling\n");
    
    // Test null inputs
    neoc_error_t err = neoc_account_create_random(NULL);
    TEST_ASSERT_TRUE(err != NEOC_SUCCESS);
    
    err = neoc_account_create_from_address(NULL, NULL);
    TEST_ASSERT_TRUE(err != NEOC_SUCCESS);
    
    err = neoc_account_create_from_wif(NULL, NULL);
    TEST_ASSERT_TRUE(err != NEOC_SUCCESS);
    
    // Test invalid WIF
    neoc_account_t* account;
    err = neoc_account_create_from_wif("invalid_wif", &account);
    TEST_ASSERT_TRUE(err != NEOC_SUCCESS);
    
    // Test invalid address
    err = neoc_account_create_from_address("invalid_address", &account);
    TEST_ASSERT_TRUE(err != NEOC_SUCCESS);
    
    // Test null free (should not crash)
    neoc_account_free(NULL);
}

/* ===== MAIN TEST RUNNER ===== */

int main(void) {
    UNITY_BEGIN();
    
    printf("\n=== COMPREHENSIVE ACCOUNT TESTS ===\n");
    
    // Account creation tests
    RUN_TEST(test_create_generic_account);
    RUN_TEST(test_init_account_from_existing_key_pair);
    RUN_TEST(test_account_from_verification_script);
    RUN_TEST(test_account_from_public_key);
    
    // Multi-sig tests
    RUN_TEST(test_create_multisig_account_from_public_keys);
    RUN_TEST(test_create_multisig_account_with_address);
    
    // Private key encryption/decryption tests
    RUN_TEST(test_encrypt_private_key);
    RUN_TEST(test_fail_encrypt_account_without_private_key);
    RUN_TEST(test_decrypt_with_standard_scrypt_params);
    RUN_TEST(test_fail_decrypting_account_without_encrypted_key);
    
    // WIF integration tests
    RUN_TEST(test_create_account_from_wif);
    RUN_TEST(test_create_account_from_address);
    
    // Account state management tests
    RUN_TEST(test_account_lock_unlock);
    
    // Multi-sig detection tests
    RUN_TEST(test_is_multisig);
    
    // Edge case tests
    RUN_TEST(test_null_values_when_not_multisig);
    
    // Error handling tests
    RUN_TEST(test_account_error_handling);
    
    UNITY_END();
    return 0;
}
