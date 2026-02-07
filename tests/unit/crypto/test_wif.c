/**
 * @file test_wif.c
 * @brief Unit tests converted from WIFTests.swift
 */

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <strings.h>
#include "neoc/neoc.h"
#include "neoc/crypto/wif.h"
#include "neoc/utils/neoc_base58.h"
#include "neoc/utils/hex.h"

// Test data
static const char *VALID_WIF = "L25kgAQJXNHnhc7Sx9bomxxwVSMsZdkaNQ3m2VfHrnLzKWMLP13A";
static const char *PRIVATE_KEY_HEX = "9117f4bf9be717c9a90994326897f4243503accd06712162267e77f18b49c3a3";

// Test setup
static void setUp(void) {
    neoc_error_t err = neoc_init();
    assert(err == NEOC_SUCCESS);
}

// Test teardown
static void tearDown(void) {
    neoc_cleanup();
}

// Test valid WIF to private key conversion
static void test_valid_wif_to_private_key(void) {
    printf("Testing valid WIF to private key conversion...\n");
    
    // Convert WIF to private key
    uint8_t *private_key = NULL;
    neoc_error_t err = neoc_wif_to_private_key(VALID_WIF, &private_key);
    assert(err == NEOC_SUCCESS);
    assert(private_key != NULL);
    
    // Convert result to hex for comparison
    char hex_output[65];
    err = neoc_hex_encode(private_key, 32, hex_output, sizeof(hex_output), false, false);
    assert(err == NEOC_SUCCESS);
    
    // Compare with expected private key
    assert(strcasecmp(hex_output, PRIVATE_KEY_HEX) == 0);
    
    neoc_free(private_key);
    printf("  ✅ Valid WIF to private key test passed\n");
}

// Test wrongly sized WIFs
static void test_wrongly_sized_wifs(void) {
    printf("Testing wrongly sized WIFs...\n");
    
    // Test WIF that is too large
    const char *too_large = "L25kgAQJXNHnhc7Sx9bomxxwVSMsZdkaNQ3m2VfHrnLzKWMLP13Ahc7S";
    uint8_t *private_key = NULL;
    neoc_error_t err = neoc_wif_to_private_key(too_large, &private_key);
    assert(err != NEOC_SUCCESS);
    neoc_free(private_key);
    
    // Test WIF that is too small
    const char *too_small = "L25kgAQJXNHnhc7Sx9bomxxwVSMsZdkaNQ3m2VfHrnLzKWML";
    private_key = NULL;
    err = neoc_wif_to_private_key(too_small, &private_key);
    assert(err != NEOC_SUCCESS);
    neoc_free(private_key);
    
    printf("  ✅ Wrongly sized WIFs test passed\n");
}

// Test wrong first byte WIF
static void test_wrong_first_byte_wif(void) {
    printf("Testing wrong first byte WIF...\n");
    
    // Decode the valid WIF
    uint8_t decoded[38];
    size_t decoded_len = 0;
    neoc_error_t err = neoc_base58_decode(VALID_WIF, decoded, sizeof(decoded), &decoded_len);
    assert(err == NEOC_SUCCESS);
    
    // Change the first byte (should be 0x80)
    decoded[0] = 0x81;
    
    // Encode back to base58
    char wrong_first_byte_wif[64];
    err = neoc_base58_encode(decoded, decoded_len, wrong_first_byte_wif, sizeof(wrong_first_byte_wif));
    assert(err == NEOC_SUCCESS);
    
    // Try to convert to private key - should fail
    uint8_t *private_key = NULL;
    err = neoc_wif_to_private_key(wrong_first_byte_wif, &private_key);
    assert(err != NEOC_SUCCESS);
    neoc_free(private_key);
    
    printf("  ✅ Wrong first byte WIF test passed\n");
}

// Test wrong byte 33 WIF
static void test_wrong_byte_33_wif(void) {
    printf("Testing wrong byte 33 WIF...\n");
    
    // Decode the valid WIF
    uint8_t decoded[38];
    size_t decoded_len = 0;
    neoc_error_t err = neoc_base58_decode(VALID_WIF, decoded, sizeof(decoded), &decoded_len);
    assert(err == NEOC_SUCCESS);
    assert(decoded_len == 38); // 1 (version) + 32 (key) + 1 (flag) + 4 (checksum)
    
    // Change byte 33 (compression flag, should be 0x01)
    decoded[33] = 0x00;
    
    // Encode back to base58
    char wrong_byte_33_wif[64];
    err = neoc_base58_encode(decoded, decoded_len, wrong_byte_33_wif, sizeof(wrong_byte_33_wif));
    assert(err == NEOC_SUCCESS);
    
    // Try to convert to private key - should fail
    uint8_t *private_key = NULL;
    err = neoc_wif_to_private_key(wrong_byte_33_wif, &private_key);
    assert(err != NEOC_SUCCESS);
    neoc_free(private_key);
    
    printf("  ✅ Wrong byte 33 WIF test passed\n");
}

// Test valid private key to WIF conversion
static void test_valid_private_key_to_wif(void) {
    printf("Testing valid private key to WIF conversion...\n");
    
    // Convert hex string to bytes
    uint8_t private_key[32];
    size_t private_key_len = 0;
    neoc_error_t err = neoc_hex_decode(PRIVATE_KEY_HEX, private_key, sizeof(private_key), &private_key_len);
    assert(err == NEOC_SUCCESS);
    assert(private_key_len == 32);
    
    // Convert private key to WIF
    char *wif = NULL;
    err = neoc_private_key_to_wif(private_key, &wif);
    assert(err == NEOC_SUCCESS);
    assert(wif != NULL);
    
    // Compare with expected WIF
    assert(strcmp(wif, VALID_WIF) == 0);
    
    free(wif);
    printf("  ✅ Valid private key to WIF test passed\n");
}

// Test wrongly sized private key
static void test_wrongly_sized_private_key(void) {
    printf("Testing wrongly sized private key...\n");
    
    // Create a wrongly sized private key (31 bytes instead of 32)
    const char *wrong_sized_hex = "9117f4bf9be717c9a90994326897f4243503accd06712162267e77f18b49c3";
    uint8_t decoded_key[31];
    size_t wrong_sized_len = 0;
    neoc_error_t err = neoc_hex_decode(wrong_sized_hex, decoded_key, sizeof(decoded_key), &wrong_sized_len);
    assert(err == NEOC_SUCCESS);
    assert(wrong_sized_len == 31);
    
    // Attempt conversion using the actual byte length (should fail)
    char *wif = NULL;
    err = neoc_private_key_to_wif_len(decoded_key, wrong_sized_len, &wif);
    assert(err != NEOC_SUCCESS);
    assert(wif == NULL);
    
    printf("  ✅ Wrongly sized private key test passed\n");
}

int main(void) {
    printf("\n=== WIFTests Tests ===\n\n");
    
    setUp();
    
    // Run all tests
    test_valid_wif_to_private_key();
    test_wrongly_sized_wifs();
    test_wrong_first_byte_wif();
    test_wrong_byte_33_wif();
    test_valid_private_key_to_wif();
    test_wrongly_sized_private_key();
    
    tearDown();
    
    printf("\n✅ All WIFTests tests passed!\n\n");
    return 0;
}
