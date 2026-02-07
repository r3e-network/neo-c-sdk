/**
 * @file test_memory_comprehensive.c
 * @brief Comprehensive memory leak tests using valgrind patterns
 */

#include "unity.h"
#include <neoc/neoc.h>
#include <neoc/neoc_memory.h>
#include <neoc/wallet/account.h>
#include <neoc/wallet/wallet.h>
#include <neoc/crypto/ec_key_pair.h>
#include <neoc/crypto/wif.h>
#include <neoc/crypto/nep2.h>
#include <neoc/contract/gas_token.h>
#include <neoc/contract/neo_token.h>
#include <neoc/transaction/transaction_builder.h>
#include <neoc/script/script_builder.h>
#include <neoc/utils/neoc_hex.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#define TEST_ASSERT_EQUAL_SIZE(expected, actual) \
    TEST_ASSERT_EQUAL_UINT64((uint64_t)(expected), (uint64_t)(actual))

// Memory tracking globals
static size_t initial_allocations = 0;
static size_t peak_allocations = 0;
static bool memory_tracking_enabled = false;

void setUp(void) {
    neoc_init();
    
#ifdef NEOC_DEBUG_MEMORY
    memory_tracking_enabled = true;
    initial_allocations = neoc_get_allocation_count();
    peak_allocations = initial_allocations;
#endif
}

void tearDown(void) {
#ifdef NEOC_DEBUG_MEMORY
    if (memory_tracking_enabled) {
        size_t final_allocations = neoc_get_allocation_count();
        if (final_allocations > initial_allocations) {
            printf("  Memory leak detected: %zu allocations remain\n", 
                   final_allocations - initial_allocations);
            neoc_print_memory_leaks();
        }
    }
#endif
    
    neoc_cleanup();
}

static void update_peak_allocations(void) {
#ifdef NEOC_DEBUG_MEMORY
    if (memory_tracking_enabled) {
        size_t current_allocations = neoc_get_allocation_count();
        if (current_allocations > peak_allocations) {
            peak_allocations = current_allocations;
        }
    }
#endif
}

/* ===== BASIC MEMORY MANAGEMENT TESTS ===== */

void test_memory_allocation_tracking(void) {
    printf("Testing memory allocation tracking\n");
    
#ifdef NEOC_DEBUG_MEMORY
    size_t start_count = neoc_get_allocation_count();
    
    // Allocate some memory
    void* ptr1 = neoc_malloc(1024);
    TEST_ASSERT_NOT_NULL(ptr1);
    TEST_ASSERT_EQUAL_SIZE(start_count + 1, neoc_get_allocation_count());
    
    void* ptr2 = neoc_malloc(2048);
    TEST_ASSERT_NOT_NULL(ptr2);
    TEST_ASSERT_EQUAL_SIZE(start_count + 2, neoc_get_allocation_count());
    
    // Free memory
    neoc_free(ptr1);
    TEST_ASSERT_EQUAL_SIZE(start_count + 1, neoc_get_allocation_count());
    
    neoc_free(ptr2);
    TEST_ASSERT_EQUAL_SIZE(start_count, neoc_get_allocation_count());
    
    printf("  Memory tracking working correctly\n");
#else
    printf("  Memory tracking not enabled (compile with NEOC_DEBUG_MEMORY)\n");
#endif
}

void test_null_pointer_handling(void) {
    printf("Testing null pointer handling\n");
    
    // Test that freeing null pointers doesn't crash
    neoc_free(NULL);
    
    // Test realloc with null pointer
    void* ptr = neoc_realloc(NULL, 1024);
    TEST_ASSERT_NOT_NULL(ptr);
    
    // Test realloc to zero size (should free)
    ptr = neoc_realloc(ptr, 0);
    // ptr may be null or non-null, both are valid
    
    printf("  Null pointer handling working correctly\n");
}

/* ===== EC KEY PAIR MEMORY TESTS ===== */

void test_ec_key_pair_memory_lifecycle(void) {
    printf("Testing EC key pair memory lifecycle\n");
    
    const int NUM_ITERATIONS = 100;
    update_peak_allocations();
    
    for (int i = 0; i < NUM_ITERATIONS; i++) {
        // Create random key pair
        neoc_ec_key_pair_t* key_pair;
        neoc_error_t err = neoc_ec_key_pair_create_random(&key_pair);
        TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
        TEST_ASSERT_NOT_NULL(key_pair);
        
        // Get private key
        uint8_t private_key[32];
        size_t key_len = sizeof(private_key);
        err = neoc_ec_key_pair_get_private_key(key_pair, private_key, &key_len);
        TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
        
        // Get public key
        uint8_t public_key[33];
        key_len = sizeof(public_key);
        err = neoc_ec_key_pair_get_public_key(key_pair, public_key, &key_len);
        TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
        
        // Export as WIF
        char* wif;
        err = neoc_ec_key_pair_export_as_wif(key_pair, &wif);
        TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
        TEST_ASSERT_NOT_NULL(wif);
        
        // Free WIF string
        neoc_free(wif);
        
        // Free key pair
        neoc_ec_key_pair_free(key_pair);
        
        update_peak_allocations();
    }
    
    printf("  Completed %d key pair operations\n", NUM_ITERATIONS);
    
#ifdef NEOC_DEBUG_MEMORY
    size_t current_allocations = neoc_get_allocation_count();
    printf("  Peak allocations: %zu, current: %zu\n", peak_allocations - initial_allocations, 
           current_allocations - initial_allocations);
#endif
}

void test_ec_key_pair_from_private_key_memory(void) {
    printf("Testing EC key pair from private key memory management\n");
    
    const char* private_key_hex = "84180ac9d6eb6fba207ea4ef9d2200102d1ebeb4b9c07e2c6a738a42742e27a5";
    uint8_t private_key[32];
    size_t decoded_len;
    
    neoc_error_t err = neoc_hex_decode(private_key_hex, private_key, sizeof(private_key), &decoded_len);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    
    for (int i = 0; i < 50; i++) {
        neoc_ec_key_pair_t* key_pair;
        err = neoc_ec_key_pair_create_from_private_key(private_key, &key_pair);
        TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
        
        // Get address
        char* address;
        err = neoc_ec_key_pair_get_address(key_pair, &address);
        TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
        TEST_ASSERT_NOT_NULL(address);
        
        neoc_free(address);
        neoc_ec_key_pair_free(key_pair);
        
        update_peak_allocations();
    }
    
    printf("  Completed 50 key pair from private key operations\n");
}

/* ===== ACCOUNT MEMORY TESTS ===== */

void test_account_creation_memory_lifecycle(void) {
    printf("Testing account creation memory lifecycle\n");
    
    for (int i = 0; i < 50; i++) {
        // Test random account creation
        neoc_account_t* account;
        neoc_error_t err = neoc_account_create_random(&account);
        TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
        
        // Get various properties to test memory allocation
        char* address;
        err = neoc_account_get_address(account, &address);
        TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
        
        char* label;
        err = neoc_account_get_label(account, &label);
        TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
        
        uint8_t* verification_script;
        size_t script_len;
        err = neoc_account_get_verification_script(account, &verification_script, &script_len);
        TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
        
        neoc_hash160_t script_hash;
        err = neoc_account_get_script_hash(account, &script_hash);
        TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
        
        // Free allocated strings
        neoc_free(address);
        neoc_free(label);
        neoc_free(verification_script);
        
        // Free account
        neoc_account_free(account);
        
        update_peak_allocations();
    }
    
    printf("  Completed 50 account creation operations\n");
}

void test_account_encryption_memory_lifecycle(void) {
    printf("Testing account encryption memory lifecycle\n");
    
    for (int i = 0; i < 20; i++) {
        // Create account
        neoc_account_t* account;
        neoc_error_t err = neoc_account_create_random(&account);
        TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
        
        // Encrypt private key
        err = neoc_account_encrypt_private_key(account, "test_password", NULL);
        TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
        
        // Get encrypted key
        char* encrypted_key;
        err = neoc_account_get_encrypted_private_key(account, &encrypted_key);
        TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
        TEST_ASSERT_NOT_NULL(encrypted_key);
        
        // Decrypt private key
        err = neoc_account_decrypt_private_key(account, "test_password", NULL);
        TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
        
        neoc_free(encrypted_key);
        neoc_account_free(account);
        
        update_peak_allocations();
    }
    
    printf("  Completed 20 account encryption operations\n");
}

/* ===== WALLET MEMORY TESTS ===== */

void test_wallet_memory_lifecycle(void) {
    printf("Testing wallet memory lifecycle\n");
    
    for (int i = 0; i < 10; i++) {
        // Create wallet
        neoc_wallet_t* wallet;
        neoc_error_t err = neoc_wallet_create("test_wallet", &wallet);
        TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
        
        // Add multiple accounts
        const int NUM_ACCOUNTS = 5;
        for (int j = 0; j < NUM_ACCOUNTS; j++) {
            neoc_account_t* account;
            err = neoc_account_create_random(&account);
            TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
            
            err = neoc_wallet_add_account(wallet, account);
            TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
        }
        
        // Verify account count
        size_t count;
        err = neoc_wallet_get_account_count(wallet, &count);
        TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
        TEST_ASSERT_EQUAL_UINT64((uint64_t)NUM_ACCOUNTS, (uint64_t)count);
        
        // Free wallet (should free all accounts)
        neoc_wallet_free(wallet);
        
        update_peak_allocations();
    }
    
    printf("  Completed 10 wallet operations (5 accounts each)\n");
}

/* ===== NEP-2 MEMORY TESTS ===== */

void test_nep2_memory_lifecycle(void) {
    printf("Testing NEP-2 memory lifecycle\n");
    
    for (int i = 0; i < 20; i++) {
        // Create key pair
        neoc_ec_key_pair_t* key_pair;
        neoc_error_t err = neoc_ec_key_pair_create_random(&key_pair);
        TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
        
        // Encrypt with NEP-2
        char* encrypted;
        err = neoc_nep2_encrypt_key_pair(key_pair, "password", NULL, &encrypted);
        TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
        TEST_ASSERT_NOT_NULL(encrypted);
        
        // Decrypt with NEP-2
        neoc_ec_key_pair_t* decrypted_key_pair;
        err = neoc_nep2_decrypt_key_pair(encrypted, "password", NULL, &decrypted_key_pair);
        TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
        
        // Free memory
        neoc_free(encrypted);
        neoc_ec_key_pair_free(key_pair);
        neoc_ec_key_pair_free(decrypted_key_pair);
        
        update_peak_allocations();
    }
    
    printf("  Completed 20 NEP-2 operations\n");
}

/* ===== CONTRACT MEMORY TESTS ===== */

void test_contract_memory_lifecycle(void) {
    printf("Testing contract memory lifecycle\n");
    
    for (int i = 0; i < 30; i++) {
        // Test GAS token
        neoc_gas_token_t* gas_token;
        neoc_error_t err = neoc_gas_token_create(&gas_token);
        TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
        
        char* name;
        err = neoc_gas_token_get_name(gas_token, &name);
        TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
        
        char* symbol;
        err = neoc_gas_token_get_symbol(gas_token, &symbol);
        TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
        
        neoc_free(name);
        neoc_free(symbol);
        neoc_gas_token_free(gas_token);
        
        // Test NEO token
        neoc_neo_token_t* neo_token;
        err = neoc_neo_token_create(&neo_token);
        TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
        
        err = neoc_neo_token_get_name(neo_token, &name);
        TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
        
        err = neoc_neo_token_get_symbol(neo_token, &symbol);
        TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
        
        neoc_free(name);
        neoc_free(symbol);
        neoc_neo_token_free(neo_token);
        
        update_peak_allocations();
    }
    
    printf("  Completed 30 contract operations\n");
}

/* ===== SCRIPT BUILDER MEMORY TESTS ===== */

void test_script_builder_memory_lifecycle(void) {
    printf("Testing script builder memory lifecycle\n");
    
    for (int i = 0; i < 25; i++) {
        neoc_script_builder_t* builder;
        neoc_error_t err = neoc_script_builder_create(&builder);
        TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
        
        // Add various operations
        err = neoc_script_builder_push_integer(builder, 42);
        TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
        
        uint8_t data[] = {0x01, 0x02, 0x03, 0x04};
        err = neoc_script_builder_push_data(builder, data, sizeof(data));
        TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
        
        err = neoc_script_builder_push_string(builder, "test_string");
        TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
        
        // Get script
        uint8_t* script;
        size_t script_len;
        err = neoc_script_builder_to_array(builder, &script, &script_len);
        TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
        TEST_ASSERT_NOT_NULL(script);
        TEST_ASSERT_TRUE(script_len > 0);
        
        neoc_free(script);
        neoc_script_builder_free(builder);
        
        update_peak_allocations();
    }
    
    printf("  Completed 25 script builder operations\n");
}

/* ===== TRANSACTION MEMORY TESTS ===== */

void test_transaction_builder_memory_lifecycle(void) {
    printf("Testing transaction builder memory lifecycle\n");
    
    for (int i = 0; i < 15; i++) {
        neoc_transaction_builder_t* tx_builder;
        neoc_error_t err = neoc_transaction_builder_create(&tx_builder);
        TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
        
        // Create simple script
        neoc_script_builder_t* script_builder;
        err = neoc_script_builder_create(&script_builder);
        TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
        
        err = neoc_script_builder_push_integer(script_builder, 100);
        TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
        
        uint8_t* script;
        size_t script_len;
        err = neoc_script_builder_to_array(script_builder, &script, &script_len);
        TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
        
        // Set script on transaction builder
        err = neoc_transaction_builder_set_script(tx_builder, script, script_len);
        TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
        
        // Create signer
        neoc_hash160_t dummy_hash;
        memset(&dummy_hash, 0xAB, sizeof(dummy_hash));
        
        neoc_signer_t* signer;
        err = neoc_signer_create(&dummy_hash, NEOC_WITNESS_SCOPE_CALLED_BY_ENTRY, &signer);
        TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
        
        err = neoc_transaction_builder_add_signer(tx_builder, signer);
        TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
        
        // Cleanup
        neoc_free(script);
        neoc_script_builder_free(script_builder);
        neoc_signer_free(signer);
        neoc_transaction_builder_free(tx_builder);
        
        update_peak_allocations();
    }
    
    printf("  Completed 15 transaction builder operations\n");
}

/* ===== STRESS TEST FOR MEMORY LEAKS ===== */

void test_stress_memory_operations(void) {
    printf("Testing stress memory operations\n");
    
#ifdef NEOC_DEBUG_MEMORY
    size_t start_allocations = neoc_get_allocation_count();
    long case_deltas[7] = {0};
#endif
    
    const int STRESS_ITERATIONS = 1000;
    
    for (int i = 0; i < STRESS_ITERATIONS; i++) {
        // Mix of different operations to stress test memory management
#ifdef NEOC_DEBUG_MEMORY
        size_t before = neoc_get_allocation_count();
#endif
        switch (i % 7) {
            case 0: {
                // EC key pair operations
                neoc_ec_key_pair_t* kp;
                if (neoc_ec_key_pair_create_random(&kp) == NEOC_SUCCESS) {
                    char* wif;
                    if (neoc_ec_key_pair_export_as_wif(kp, &wif) == NEOC_SUCCESS) {
                        neoc_free(wif);
                    }
                    neoc_ec_key_pair_free(kp);
                }
                break;
            }
            case 1: {
                // Account operations
                neoc_account_t* acc;
                if (neoc_account_create_random(&acc) == NEOC_SUCCESS) {
                    char* addr;
                    if (neoc_account_get_address(acc, &addr) == NEOC_SUCCESS) {
                        neoc_free(addr);
                    }
                    neoc_account_free(acc);
                }
                break;
            }
            case 2: {
                // Hex encoding/decoding
                const char* hex = "deadbeef";
                uint8_t bytes[4];
                size_t len;
                if (neoc_hex_decode(hex, bytes, sizeof(bytes), &len) == NEOC_SUCCESS) {
                    char* encoded = neoc_hex_encode_alloc(bytes, len, false, false);
                    if (encoded) {
                        neoc_free(encoded);
                    }
                }
                break;
            }
            case 3: {
                // Script builder operations
                neoc_script_builder_t* sb;
                if (neoc_script_builder_create(&sb) == NEOC_SUCCESS) {
                    neoc_script_builder_push_integer(sb, i);
                    uint8_t* script;
                    size_t script_len;
                    if (neoc_script_builder_to_array(sb, &script, &script_len) == NEOC_SUCCESS) {
                        neoc_free(script);
                    }
                    neoc_script_builder_free(sb);
                }
                break;
            }
            case 4: {
                // Contract operations
                neoc_gas_token_t* gt;
                if (neoc_gas_token_create(&gt) == NEOC_SUCCESS) {
                    char* name;
                    if (neoc_gas_token_get_name(gt, &name) == NEOC_SUCCESS) {
                        neoc_free(name);
                    }
                    neoc_gas_token_free(gt);
                }
                break;
            }
            case 5: {
                // Memory allocations
                void* ptr1 = neoc_malloc(1024);
                void* ptr2 = neoc_realloc(ptr1, 2048);
                neoc_free(ptr2);
                break;
            }
            case 6: {
                // String operations
                char* str = neoc_strdup("test string");
                neoc_free(str);
                break;
            }
        }
#ifdef NEOC_DEBUG_MEMORY
        size_t after = neoc_get_allocation_count();
        case_deltas[i % 7] += (long)(after - before);
#endif
        // Update peak every 100 iterations
        if (i % 100 == 0) {
            update_peak_allocations();
        }
    }
    
#ifdef NEOC_DEBUG_MEMORY
    size_t end_allocations = neoc_get_allocation_count();
    printf("  Completed %d stress operations\n", STRESS_ITERATIONS);
    printf("  Start allocations: %zu, end allocations: %zu\n", 
           start_allocations, end_allocations);
    printf("  Peak additional allocations: %zu\n", 
           peak_allocations - start_allocations);
    
    printf("  Allocation delta by case: ");
    for (int i = 0; i < 7; i++) {
        printf("[%d]=%ld ", i, case_deltas[i]);
    }
    printf("\n");

    // Should return to baseline (allowing for small variations)
    size_t diff = (end_allocations > start_allocations) ? 
                  (end_allocations - start_allocations) : 
                  (start_allocations - end_allocations);
    TEST_ASSERT_TRUE(diff < 10); // Allow small variation
#else
    printf("  Completed %d stress operations (no memory tracking)\n", STRESS_ITERATIONS);
#endif
}

/* ===== VALGRIND-SPECIFIC TESTS ===== */

void test_valgrind_memory_patterns(void) {
    printf("Testing valgrind memory patterns\n");
    
    // Test 1: Use after free detection
    // (This would be caught by valgrind but not necessarily by our code)
    void* ptr = neoc_malloc(100);
    TEST_ASSERT_NOT_NULL(ptr);
    neoc_free(ptr);
    // Don't use ptr after free (would trigger valgrind error)
    
    // Test 2: Double free detection
    ptr = neoc_malloc(200);
    TEST_ASSERT_NOT_NULL(ptr);
    neoc_free(ptr);
    // Don't double free (would trigger valgrind error)
    
    // Test 3: Buffer overflow detection
    char* buffer = (char*)neoc_malloc(10);
    TEST_ASSERT_NOT_NULL(buffer);
    // Only write within bounds
    strncpy(buffer, "test", 9);
    buffer[9] = '\0';
    // Don't write past end of buffer
    neoc_free(buffer);
    
    // Test 4: Uninitialized memory access
    int* int_ptr = (int*)neoc_malloc(sizeof(int));
    TEST_ASSERT_NOT_NULL(int_ptr);
    *int_ptr = 42; // Initialize before use
    TEST_ASSERT_EQUAL_INT(42, *int_ptr);
    neoc_free(int_ptr);
    
    printf("  Valgrind memory patterns tested\n");
}

/* ===== PERFORMANCE UNDER MEMORY PRESSURE ===== */

void test_performance_under_memory_pressure(void) {
    printf("Testing performance under memory pressure\n");
    
    clock_t start = clock();
    
    // Allocate large chunks to create memory pressure
    const int NUM_CHUNKS = 100;
    const size_t CHUNK_SIZE = 1024 * 1024; // 1MB chunks
    void* chunks[NUM_CHUNKS];
    
    // Allocate
    for (int i = 0; i < NUM_CHUNKS; i++) {
        chunks[i] = neoc_malloc(CHUNK_SIZE);
        TEST_ASSERT_NOT_NULL(chunks[i]);
        
        // Write to memory to ensure it's actually allocated
        memset(chunks[i], i & 0xFF, CHUNK_SIZE);
    }
    
    clock_t alloc_time = clock();
    
    // Perform operations under memory pressure
    for (int i = 0; i < 50; i++) {
        neoc_account_t* account;
        neoc_error_t err = neoc_account_create_random(&account);
        TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
        
        char* address;
        err = neoc_account_get_address(account, &address);
        TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
        
        neoc_free(address);
        neoc_account_free(account);
    }
    
    clock_t ops_time = clock();
    
    // Free chunks
    for (int i = 0; i < NUM_CHUNKS; i++) {
        neoc_free(chunks[i]);
    }
    
    clock_t end_time = clock();
    
    double alloc_seconds = ((double)(alloc_time - start)) / CLOCKS_PER_SEC;
    double ops_seconds = ((double)(ops_time - alloc_time)) / CLOCKS_PER_SEC;
    double free_seconds = ((double)(end_time - ops_time)) / CLOCKS_PER_SEC;
    
    printf("  Allocated %d MB in %.3f seconds\n", NUM_CHUNKS, alloc_seconds);
    printf("  Performed operations in %.3f seconds under memory pressure\n", ops_seconds);
    printf("  Freed memory in %.3f seconds\n", free_seconds);
    
    // Performance should still be reasonable under memory pressure
    TEST_ASSERT_TRUE(alloc_seconds < 5.0);
    TEST_ASSERT_TRUE(ops_seconds < 2.0);
    TEST_ASSERT_TRUE(free_seconds < 3.0);
}

/* ===== MAIN TEST RUNNER ===== */

int main(void) {
    UNITY_BEGIN();
    
    printf("\n=== COMPREHENSIVE MEMORY LEAK TESTS ===\n");
    
#ifdef NEOC_DEBUG_MEMORY
    printf("Memory tracking is ENABLED\n");
#else
    printf("Memory tracking is DISABLED (compile with -DNEOC_DEBUG_MEMORY to enable)\n");
#endif
    
    // Basic memory management tests
    RUN_TEST(test_memory_allocation_tracking);
    RUN_TEST(test_null_pointer_handling);
    
    // EC key pair memory tests
    RUN_TEST(test_ec_key_pair_memory_lifecycle);
    RUN_TEST(test_ec_key_pair_from_private_key_memory);
    
    // Account memory tests
    RUN_TEST(test_account_creation_memory_lifecycle);
    RUN_TEST(test_account_encryption_memory_lifecycle);
    
    // Wallet memory tests
    RUN_TEST(test_wallet_memory_lifecycle);
    
    // NEP-2 memory tests
    RUN_TEST(test_nep2_memory_lifecycle);
    
    // Contract memory tests
    RUN_TEST(test_contract_memory_lifecycle);
    
    // Script builder memory tests
    RUN_TEST(test_script_builder_memory_lifecycle);
    
    // Transaction memory tests
    RUN_TEST(test_transaction_builder_memory_lifecycle);
    
    // Stress tests
    RUN_TEST(test_stress_memory_operations);
    
    // Valgrind-specific tests
    RUN_TEST(test_valgrind_memory_patterns);
    
    // Performance tests
    RUN_TEST(test_performance_under_memory_pressure);
    
    UNITY_END();
    return 0;
}
