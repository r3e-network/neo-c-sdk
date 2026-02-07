/**
 * @file test_ec_key_pair.c
 * @brief Unit tests converted from ECKeyPairTests.swift
 */

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <strings.h>
#include "neoc/neoc.h"
#include "neoc/crypto/ec_key_pair.h"
#include "neoc/crypto/wif.h"
#include "neoc/utils/hex.h"
#include "neoc/neoc_memory.h"

// Test data
static const char *ENCODED_POINT = "03b4af8d061b6b320cce6c63bc4ec7894dce107bfc5f5ef5c68a93b4ad1e136816";
static const char *UNCOMPRESSED_POINT = 
    "04b4af8d061b6b320cce6c63bc4ec7894dce107bfc5f5ef5c68a93b4ad1e1368165f4f7fb1c5862465543c06dd5a2aa414f6583f92a5cc3e1d4259df79bf6839c9";

// Test setup
static void setUp(void) {
    neoc_error_t err = neoc_init();
    assert(err == NEOC_SUCCESS);
}

// Test teardown
static void tearDown(void) {
    neoc_cleanup();
}

// Test creating public key from encoded point
static void test_new_public_key_from_point(void) {
    printf("Testing public key from encoded point...\n");
    
    // Convert hex string to bytes
    uint8_t encoded_bytes[33];
    size_t encoded_len = 0;
    neoc_error_t err = neoc_hex_decode(ENCODED_POINT, encoded_bytes, sizeof(encoded_bytes), &encoded_len);
    assert(err == NEOC_SUCCESS);
    assert(encoded_len == 33);
    
    // Create public key
    neoc_ec_public_key_t *public_key = NULL;
    err = neoc_ec_public_key_from_bytes(encoded_bytes, encoded_len, &public_key);
    assert(err == NEOC_SUCCESS);
    assert(public_key != NULL);
    
    // Get encoded compressed form
    uint8_t *compressed = NULL;
    size_t compressed_len = 0;
    err = neoc_ec_public_key_get_encoded(public_key, true, &compressed, &compressed_len);
    assert(err == NEOC_SUCCESS);
    assert(compressed_len == 33);
    assert(memcmp(compressed, encoded_bytes, 33) == 0);
    
    // Convert back to hex and verify
    char hex_output[67];
    err = neoc_hex_encode(compressed, compressed_len, hex_output, sizeof(hex_output), false, false);
    assert(err == NEOC_SUCCESS);
    assert(strcasecmp(hex_output, ENCODED_POINT) == 0);
    
    neoc_free(compressed);
    neoc_ec_public_key_free(public_key);
    printf("  ✅ Public key from point test passed\n");
}

// Test creating public key from uncompressed point
static void test_new_public_key_from_uncompressed_point(void) {
    printf("Testing public key from uncompressed point...\n");
    
    // Convert hex string to bytes
    uint8_t uncompressed_bytes[65];
    size_t uncompressed_len = 0;
    neoc_error_t err = neoc_hex_decode(UNCOMPRESSED_POINT, uncompressed_bytes, sizeof(uncompressed_bytes), &uncompressed_len);
    assert(err == NEOC_SUCCESS);
    assert(uncompressed_len == 65);
    
    // Create public key from uncompressed
    neoc_ec_public_key_t *public_key = NULL;
    err = neoc_ec_public_key_from_bytes(uncompressed_bytes, uncompressed_len, &public_key);
    assert(err == NEOC_SUCCESS);
    assert(public_key != NULL);
    
    // Get compressed form
    uint8_t *compressed = NULL;
    size_t compressed_len = 0;
    err = neoc_ec_public_key_get_encoded(public_key, true, &compressed, &compressed_len);
    assert(err == NEOC_SUCCESS);
    assert(compressed_len == 33);
    
    // Convert to hex and verify it matches expected compressed form
    char hex_output[67];
    err = neoc_hex_encode(compressed, compressed_len, hex_output, sizeof(hex_output), false, false);
    assert(err == NEOC_SUCCESS);
    assert(strcasecmp(hex_output, ENCODED_POINT) == 0);
    
    neoc_free(compressed);
    neoc_ec_public_key_free(public_key);
    printf("  ✅ Public key from uncompressed point test passed\n");
}

// Test creating public key with invalid size
static void test_new_public_key_from_string_with_invalid_size(void) {
    printf("Testing public key with invalid size...\n");
    
    // Create string with invalid size (31 bytes instead of 33)
    char too_small[63]; // 31 bytes * 2 + null terminator
    strncpy(too_small, ENCODED_POINT, 62);
    too_small[62] = '\0';
    
    // Try to decode
    uint8_t invalid_bytes[33];
    size_t invalid_len = 0;
    neoc_error_t err = neoc_hex_decode(too_small, invalid_bytes, sizeof(invalid_bytes), &invalid_len);
    assert(err == NEOC_SUCCESS); // Hex decode should work
    assert(invalid_len == 31); // But size is wrong
    
    // Creating public key should fail
    neoc_ec_public_key_t *public_key = NULL;
    err = neoc_ec_public_key_from_bytes(invalid_bytes, invalid_len, &public_key);
    assert(err != NEOC_SUCCESS);
    assert(public_key == NULL);
    
    printf("  ✅ Invalid size test passed\n");
}

// Test creating public key with 0x prefix
static void test_new_public_key_from_point_with_hex_prefix(void) {
    printf("Testing public key with 0x prefix...\n");
    
    const char *prefixed = "0x03b4af8d061b6b320cce6c63bc4ec7894dce107bfc5f5ef5c68a93b4ad1e136816";
    
    // Skip the 0x prefix
    const char *hex_str = prefixed + 2;
    
    // Convert hex string to bytes
    uint8_t encoded_bytes[33];
    size_t encoded_len = 0;
    neoc_error_t err = neoc_hex_decode(hex_str, encoded_bytes, sizeof(encoded_bytes), &encoded_len);
    assert(err == NEOC_SUCCESS);
    assert(encoded_len == 33);
    
    // Create public key
    neoc_ec_public_key_t *public_key = NULL;
    err = neoc_ec_public_key_from_bytes(encoded_bytes, encoded_len, &public_key);
    assert(err == NEOC_SUCCESS);
    assert(public_key != NULL);
    
    // Get compressed form and verify
    uint8_t *compressed = NULL;
    size_t compressed_len = 0;
    err = neoc_ec_public_key_get_encoded(public_key, true, &compressed, &compressed_len);
    assert(err == NEOC_SUCCESS);
    
    // Convert to hex
    char hex_output[67];
    err = neoc_hex_encode(compressed, compressed_len, hex_output, sizeof(hex_output), false, false);
    assert(err == NEOC_SUCCESS);
    assert(strcasecmp(hex_output, ENCODED_POINT) == 0);
    
    neoc_free(compressed);
    neoc_ec_public_key_free(public_key);
    printf("  ✅ Hex prefix test passed\n");
}

// Test serializing public key
static void test_serialize_public_key(void) {
    printf("Testing public key serialization...\n");
    
    // Convert hex to bytes
    uint8_t encoded_bytes[33];
    size_t encoded_len = 0;
    neoc_error_t err = neoc_hex_decode(ENCODED_POINT, encoded_bytes, sizeof(encoded_bytes), &encoded_len);
    assert(err == NEOC_SUCCESS);
    
    // Create public key
    neoc_ec_public_key_t *public_key = NULL;
    err = neoc_ec_public_key_from_bytes(encoded_bytes, encoded_len, &public_key);
    assert(err == NEOC_SUCCESS);
    assert(public_key != NULL);
    
    // Serialize (toArray equivalent)
    uint8_t *serialized = NULL;
    size_t serialized_len = 0;
    err = neoc_ec_public_key_get_encoded(public_key, true, &serialized, &serialized_len);
    assert(err == NEOC_SUCCESS);
    assert(serialized_len == 33);
    assert(memcmp(serialized, encoded_bytes, 33) == 0);
    
    neoc_free(serialized);
    neoc_ec_public_key_free(public_key);
    printf("  ✅ Serialization test passed\n");
}

// Test deserializing public key
static void test_deserialize_public_key(void) {
    printf("Testing public key deserialization...\n");
    
    const char *hex_data = "036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296";
    
    // Convert hex to bytes
    uint8_t data[33];
    size_t data_len = 0;
    neoc_error_t err = neoc_hex_decode(hex_data, data, sizeof(data), &data_len);
    assert(err == NEOC_SUCCESS);
    assert(data_len == 33);
    
    // Deserialize (from equivalent)
    neoc_ec_public_key_t *public_key = NULL;
    err = neoc_ec_public_key_from_bytes(data, data_len, &public_key);
    assert(err == NEOC_SUCCESS);
    assert(public_key != NULL);
    
    // Verify it was created correctly by re-encoding
    uint8_t *reencoded = NULL;
    size_t reencoded_len = 0;
    err = neoc_ec_public_key_get_encoded(public_key, true, &reencoded, &reencoded_len);
    assert(err == NEOC_SUCCESS);
    assert(memcmp(reencoded, data, 33) == 0);
    
    neoc_free(reencoded);
    neoc_ec_public_key_free(public_key);
    printf("  ✅ Deserialization test passed\n");
}

// Test public key size
static void test_public_key_size(void) {
    printf("Testing public key size...\n");
    
    const char *hex_key = "036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296";
    
    // Convert hex to bytes
    uint8_t key_bytes[33];
    size_t key_len = 0;
    neoc_error_t err = neoc_hex_decode(hex_key, key_bytes, sizeof(key_bytes), &key_len);
    assert(err == NEOC_SUCCESS);
    
    // Create public key
    neoc_ec_public_key_t *public_key = NULL;
    err = neoc_ec_public_key_from_bytes(key_bytes, key_len, &public_key);
    assert(err == NEOC_SUCCESS);
    assert(public_key != NULL);
    
    uint8_t *encoded = NULL;
    size_t encoded_len = 0;
    err = neoc_ec_public_key_get_encoded(public_key, true, &encoded, &encoded_len);
    assert(err == NEOC_SUCCESS);
    assert(encoded_len == 33);
    
    neoc_free(encoded);
    neoc_ec_public_key_free(public_key);
    printf("  ✅ Public key size test passed\n");
}

// Test public key WIF export
static void test_public_key_wif(void) {
    printf("Testing public key WIF export...\n");
    
    const char *private_key_hex = "c7134d6fd8e73d819e82755c64c93788d8db0961929e025a53363c4cc02a6962";
    const char *expected_wif = "L3tgppXLgdaeqSGSFw1Go3skBiy8vQAM7YMXvTHsKQtE16PBncSU";
    
    // Convert private key hex to bytes
    uint8_t private_key[32];
    size_t private_key_len = 0;
    neoc_error_t err = neoc_hex_decode(private_key_hex, private_key, sizeof(private_key), &private_key_len);
    assert(err == NEOC_SUCCESS);
    assert(private_key_len == 32);
    
    // Create key pair from private key
    neoc_ec_key_pair_t *key_pair = NULL;
    err = neoc_ec_key_pair_create_from_private_key(private_key, &key_pair);
    assert(err == NEOC_SUCCESS);
    assert(key_pair != NULL);
    
    // Export as WIF
    char *wif = NULL;
    err = neoc_ec_key_pair_export_as_wif(key_pair, &wif);
    assert(err == NEOC_SUCCESS);
    assert(wif != NULL);
    assert(strcmp(wif, expected_wif) == 0);
    
    free(wif);
    neoc_ec_key_pair_free(key_pair);
    printf("  ✅ WIF export test passed\n");
}

// Test public key comparison
static void test_public_key_comparable(void) {
    printf("Testing public key comparison...\n");
    
    const char *encoded_key2 = "036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296";
    
    // Convert hex strings to bytes
    uint8_t key1_bytes[33], key2_bytes[33], key1_uncompressed_bytes[65];
    size_t key1_len = 0, key2_len = 0, key1_uncompressed_len = 0;
    
    neoc_error_t err = neoc_hex_decode(ENCODED_POINT, key1_bytes, sizeof(key1_bytes), &key1_len);
    assert(err == NEOC_SUCCESS);
    
    err = neoc_hex_decode(encoded_key2, key2_bytes, sizeof(key2_bytes), &key2_len);
    assert(err == NEOC_SUCCESS);
    
    err = neoc_hex_decode(UNCOMPRESSED_POINT, key1_uncompressed_bytes, sizeof(key1_uncompressed_bytes), &key1_uncompressed_len);
    assert(err == NEOC_SUCCESS);
    
    // Create public keys
    neoc_ec_public_key_t *key1 = NULL, *key2 = NULL, *key1_uncompressed = NULL;
    
    err = neoc_ec_public_key_from_bytes(key1_bytes, key1_len, &key1);
    assert(err == NEOC_SUCCESS);
    
    err = neoc_ec_public_key_from_bytes(key2_bytes, key2_len, &key2);
    assert(err == NEOC_SUCCESS);
    
    err = neoc_ec_public_key_from_bytes(key1_uncompressed_bytes, key1_uncompressed_len, &key1_uncompressed);
    assert(err == NEOC_SUCCESS);
    
    uint8_t *key1_comp = NULL, *key2_comp = NULL, *key1_uncompressed_comp = NULL;
    size_t key1_comp_len = 0, key2_comp_len = 0, key1_uncompressed_comp_len = 0;
    err = neoc_ec_public_key_get_encoded(key1, true, &key1_comp, &key1_comp_len);
    assert(err == NEOC_SUCCESS);
    err = neoc_ec_public_key_get_encoded(key2, true, &key2_comp, &key2_comp_len);
    assert(err == NEOC_SUCCESS);
    err = neoc_ec_public_key_get_encoded(key1_uncompressed, true, &key1_uncompressed_comp, &key1_uncompressed_comp_len);
    assert(err == NEOC_SUCCESS);

    int cmp = memcmp(key1_comp, key2_comp, key1_comp_len);
    assert(cmp > 0);
    cmp = memcmp(key1_comp, key1_uncompressed_comp, key1_comp_len);
    assert(cmp == 0);
    cmp = memcmp(key2_comp, key1_comp, key2_comp_len);
    assert(cmp < 0);
    
    neoc_free(key1_comp);
    neoc_free(key2_comp);
    neoc_free(key1_uncompressed_comp);
    neoc_ec_public_key_free(key1);
    neoc_ec_public_key_free(key2);
    neoc_ec_public_key_free(key1_uncompressed);
    
    printf("  ✅ Public key comparison test passed\n");
}

int main(void) {
    printf("\n=== ECKeyPairTests Tests ===\n\n");
    
    setUp();
    
    // Run all tests
    test_new_public_key_from_point();
    test_new_public_key_from_uncompressed_point();
    test_new_public_key_from_string_with_invalid_size();
    test_new_public_key_from_point_with_hex_prefix();
    test_serialize_public_key();
    test_deserialize_public_key();
    test_public_key_size();
    test_public_key_wif();
    test_public_key_comparable();
    
    tearDown();
    
    printf("\n✅ All ECKeyPairTests tests passed!\n\n");
    return 0;
}
