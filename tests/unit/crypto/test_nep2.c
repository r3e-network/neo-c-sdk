/**
 * @file test_nep2.c
 * @brief Unit tests converted from NEP2Tests.swift
 */

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include "neoc/neoc.h"
#include "neoc/crypto/nep2.h"
#include "neoc/utils/hex.h"

// Test data from TestProperties.swift
static const char *DEFAULT_PASSWORD = "neo";
static const char *DEFAULT_PRIVATE_KEY = "84180ac9d6eb6fba207ea4ef9d2200102d1ebeb4b9c07e2c6a738a42742e27a5";
static const char *DEFAULT_ENCRYPTED_KEY = "6PYM7jHL4GmS8Aw2iEFpuaHTCUKjhT4mwVqdoozGU6sUE25BjV4ePXDdLz";

// Test setup
static void setUp(void) {
    neoc_error_t err = neoc_init();
    assert(err == NEOC_SUCCESS);
}

// Test teardown
static void tearDown(void) {
    neoc_cleanup();
}

// Test decrypt with default scrypt params
static void test_decrypt_with_default_scrypt_params(void) {
    printf("Testing NEP2 decrypt with default scrypt params...\n");
    
    // Decrypt the encrypted private key
    uint8_t decrypted_private_key[32];
    neoc_error_t err = neoc_nep2_decrypt(
        DEFAULT_ENCRYPTED_KEY,
        DEFAULT_PASSWORD,
        NULL,
        decrypted_private_key,
        sizeof(decrypted_private_key));
    assert(err == NEOC_SUCCESS);
    
    // Convert expected private key from hex
    uint8_t expected_private_key[32];
    size_t expected_len = 0;
    err = neoc_hex_decode(DEFAULT_PRIVATE_KEY, expected_private_key, sizeof(expected_private_key), &expected_len);
    assert(err == NEOC_SUCCESS);
    assert(expected_len == 32);
    
    // Compare decrypted with expected
    assert(memcmp(decrypted_private_key, expected_private_key, 32) == 0);
    
    printf("  ✅ NEP2 decrypt with default scrypt params test passed\n");
}

// Test decrypt with non-default scrypt params
static void test_decrypt_with_non_default_scrypt_params(void) {
    printf("Testing NEP2 decrypt with non-default scrypt params...\n");
    
    // Create non-default scrypt params (N=256, r=1, p=1)
    neoc_nep2_params_t params = {256, 1, 1};
    
    const char *encrypted = "6PYM7jHL3uwhP8uuHP9fMGMfJxfyQbanUZPQEh1772iyb7vRnUkbkZmdRT";
    
    // Decrypt the encrypted private key
    uint8_t decrypted_private_key[32];
    neoc_error_t err = neoc_nep2_decrypt(
        encrypted,
        DEFAULT_PASSWORD,
        &params,
        decrypted_private_key,
        sizeof(decrypted_private_key));
    assert(err == NEOC_SUCCESS);
    
    // Convert expected private key from hex
    uint8_t expected_private_key[32];
    size_t expected_len = 0;
    err = neoc_hex_decode(DEFAULT_PRIVATE_KEY, expected_private_key, sizeof(expected_private_key), &expected_len);
    assert(err == NEOC_SUCCESS);
    assert(expected_len == 32);
    
    // Compare decrypted with expected
    assert(memcmp(decrypted_private_key, expected_private_key, 32) == 0);
    
    printf("  ✅ NEP2 decrypt with non-default scrypt params test passed\n");
}

// Test encrypt with default scrypt params
static void test_encrypt_with_default_scrypt_params(void) {
    printf("Testing NEP2 encrypt with default scrypt params...\n");
    
    // Convert private key from hex
    uint8_t private_key[32];
    size_t private_key_len = 0;
    neoc_error_t err = neoc_hex_decode(DEFAULT_PRIVATE_KEY, private_key, sizeof(private_key), &private_key_len);
    assert(err == NEOC_SUCCESS);
    assert(private_key_len == 32);
    
    char encrypted[128];
    err = neoc_nep2_encrypt(
        private_key,
        DEFAULT_PASSWORD,
        NULL,
        encrypted,
        sizeof(encrypted));
    assert(err == NEOC_SUCCESS);
    assert(strcmp(encrypted, DEFAULT_ENCRYPTED_KEY) == 0);
    
    printf("  ✅ NEP2 encrypt with default scrypt params test passed\n");
}

// Test encrypt with non-default scrypt params
static void test_encrypt_with_non_default_scrypt_params(void) {
    printf("Testing NEP2 encrypt with non-default scrypt params...\n");
    
    // Create non-default scrypt params (N=256, r=1, p=1)
    neoc_nep2_params_t params = {256, 1, 1};
    
    const char *expected = "6PYM7jHL3uwhP8uuHP9fMGMfJxfyQbanUZPQEh1772iyb7vRnUkbkZmdRT";
    
    // Convert private key from hex
    uint8_t private_key[32];
    size_t private_key_len = 0;
    neoc_error_t err = neoc_hex_decode(DEFAULT_PRIVATE_KEY, private_key, sizeof(private_key), &private_key_len);
    assert(err == NEOC_SUCCESS);
    assert(private_key_len == 32);
    
    char encrypted[128];
    err = neoc_nep2_encrypt(
        private_key,
        DEFAULT_PASSWORD,
        &params,
        encrypted,
        sizeof(encrypted));
    assert(err == NEOC_SUCCESS);
    assert(strcmp(encrypted, expected) == 0);
    
    printf("  ✅ NEP2 encrypt with non-default scrypt params test passed\n");
}

int main(void) {
    printf("\n=== NEP2Tests Tests ===\n\n");
    
    setUp();
    
    // Run all tests
    test_decrypt_with_default_scrypt_params();
    test_decrypt_with_non_default_scrypt_params();
    test_encrypt_with_default_scrypt_params();
    test_encrypt_with_non_default_scrypt_params();
    
    tearDown();
    
    printf("\n✅ All NEP2Tests tests passed!\n\n");
    return 0;
}
