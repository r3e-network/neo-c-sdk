/**
 * @file test_neo_constants.c
 * @brief Neo blockchain constants validation tests
 */

#include "unity.h"
#include <neoc/neoc.h>
#include <neoc/contract/smart_contract.h>
#include <neoc/contract/contract_management.h>
#include <neoc/contract/policy_contract.h>
#include <neoc/types/neoc_hash160.h>
#include <neoc/utils/neoc_hex.h>
#include <string.h>
#include <stdio.h>

void setUp(void) {
    neoc_init();
}

void tearDown(void) {
    neoc_cleanup();
}

/* ===== NEO CONSTANTS TESTS ===== */

void test_neo_token_constants(void) {
    const char* expected_neo_hash = NEOC_NEO_TOKEN_HASH_HEX;
    TEST_ASSERT_EQUAL_STRING("ef4073a0f2b305a38ec4050e4d3d28bc40ea63f5", expected_neo_hash);
}

void test_gas_token_constants(void) {
    const char* expected_gas_hash = NEOC_GAS_TOKEN_HASH_HEX;
    TEST_ASSERT_EQUAL_STRING("d2a4cff31913016155e38e474a2c06d08be276cf", expected_gas_hash);
}

void test_address_version(void) {
    // Neo N3 address version should be 0x35 (53 decimal)
    TEST_ASSERT_EQUAL_UINT8(0x35, NEOC_ADDRESS_VERSION);
}

void test_max_transaction_size(void) {
    // Maximum transaction size
    TEST_ASSERT_TRUE(NEOC_MAX_TRANSACTION_SIZE >= 102400); // At least 100KB
    TEST_ASSERT_TRUE(NEOC_MAX_TRANSACTION_SIZE <= 1048576); // At most 1MB
}

void test_max_script_size(void) {
    // Maximum script size
    TEST_ASSERT_TRUE(NEOC_MAX_SCRIPT_SIZE >= 65536); // At least 64KB
    TEST_ASSERT_TRUE(NEOC_MAX_SCRIPT_SIZE <= 1048576); // At most 1MB
}

void test_opcode_values(void) {
    // Test some key opcodes
    #ifdef NEOC_OP_PUSH0
    TEST_ASSERT_EQUAL_UINT8(0x10, NEOC_OP_PUSH0);
    #endif
    
    #ifdef NEOC_OP_PUSH1
    TEST_ASSERT_EQUAL_UINT8(0x11, NEOC_OP_PUSH1);
    #endif
    
    #ifdef NEOC_OP_PUSHDATA1
    TEST_ASSERT_EQUAL_UINT8(0x0C, NEOC_OP_PUSHDATA1);
    #endif
    
    #ifdef NEOC_OP_PUSHDATA2
    TEST_ASSERT_EQUAL_UINT8(0x0D, NEOC_OP_PUSHDATA2);
    #endif
    
    #ifdef NEOC_OP_PUSHDATA4
    TEST_ASSERT_EQUAL_UINT8(0x0E, NEOC_OP_PUSHDATA4);
    #endif
    
    #ifdef NEOC_OP_SYSCALL
    TEST_ASSERT_EQUAL_UINT8(0x41, NEOC_OP_SYSCALL);
    #endif
    
    #ifdef NEOC_OP_RET
    TEST_ASSERT_EQUAL_UINT8(0x40, NEOC_OP_RET);
    #endif
}

void test_crypto_constants(void) {
    // Test crypto-related constants
    TEST_ASSERT_EQUAL_UINT32(32, NEOC_PRIVATE_KEY_SIZE);
    
    TEST_ASSERT_EQUAL_UINT32(33, NEOC_PUBLIC_KEY_SIZE_COMPRESSED);
    
    TEST_ASSERT_EQUAL_UINT32(65, NEOC_PUBLIC_KEY_SIZE_UNCOMPRESSED);
    
    TEST_ASSERT_EQUAL_UINT32(64, NEOC_SIGNATURE_SIZE);
    
    TEST_ASSERT_EQUAL_UINT32(20, NEOC_HASH160_SIZE);
    
    TEST_ASSERT_EQUAL_UINT32(32, NEOC_HASH256_SIZE);
}

void test_address_constants(void) {
    // Test address-related constants
    TEST_ASSERT_TRUE(NEOC_ADDRESS_MAX_LENGTH >= 34);
    TEST_ASSERT_TRUE(NEOC_ADDRESS_MAX_LENGTH <= 64);
    
    TEST_ASSERT_TRUE(NEOC_WIF_MAX_LENGTH >= 52);
    TEST_ASSERT_TRUE(NEOC_WIF_MAX_LENGTH <= 64);
}

static void assert_native_hash(neoc_native_contract_t contract, const char *expected_hex) {
    neoc_hash160_t hash;
    uint8_t canonical_bytes[NEOC_HASH160_SIZE] = {0};
    char actual_hex[NEOC_HASH160_STRING_LENGTH] = {0};

    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, neoc_native_contract_get_hash(contract, &hash));

    /*
     * NeoC stores script hashes in internal byte order for VM usage.
     * Convert to canonical 0x-style display order before comparing against
     * official Neo values.
     */
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS,
                          neoc_hash160_to_little_endian_bytes(&hash,
                                                              canonical_bytes,
                                                              sizeof(canonical_bytes)));
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS,
                          neoc_hex_encode(canonical_bytes,
                                          sizeof(canonical_bytes),
                                          actual_hex,
                                          sizeof(actual_hex),
                                          false,
                                          false));
    TEST_ASSERT_EQUAL_STRING(expected_hex, actual_hex);
}

void test_all_native_contract_hashes_match_neo_v391(void) {
    assert_native_hash(NEOC_NATIVE_CONTRACT_NEO,
                       "ef4073a0f2b305a38ec4050e4d3d28bc40ea63f5");
    assert_native_hash(NEOC_NATIVE_CONTRACT_GAS,
                       "d2a4cff31913016155e38e474a2c06d08be276cf");
    assert_native_hash(NEOC_NATIVE_CONTRACT_POLICY,
                       "cc5e4edd9f5f8dba8bb65734541df7a1c081c67b");
    assert_native_hash(NEOC_NATIVE_CONTRACT_ROLE_MANAGEMENT,
                       "49cf4e5378ffcd4dec034fd98a174c5491e395e2");
    assert_native_hash(NEOC_NATIVE_CONTRACT_ORACLE,
                       "fe924b7cfe89ddd271abaf7210a80a7e11178758");
    assert_native_hash(NEOC_NATIVE_CONTRACT_LEDGER,
                       "da65b600f7124ce6c79950c1772a36403104f2be");
    assert_native_hash(NEOC_NATIVE_CONTRACT_MANAGEMENT,
                       "fffdc93764dbaddd97c48f252a53ea4643faa3fd");
    assert_native_hash(NEOC_NATIVE_CONTRACT_CRYPTO,
                       "726cb6e0cd8628a1350a611384688911ab75f51b");
    assert_native_hash(NEOC_NATIVE_CONTRACT_STD_LIB,
                       "acce6fd80d44e1796aa0c2c625e9e4e0ce39efc0");
}

void test_network_magic_constants_match_neo_n3(void) {
    TEST_ASSERT_EQUAL_HEX32(0x334F454E, NEOC_MAINNET_MAGIC);
    TEST_ASSERT_EQUAL_HEX32(0x334F4554, NEOC_TESTNET_MAGIC);
}

void test_contract_management_has_method_signature_builds(void) {
    neoc_contract_management_t *mgmt = NULL;
    neoc_hash160_t hash = {0};
    uint8_t *script = NULL;
    size_t script_len = 0;

    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, neoc_contract_management_create(&mgmt));
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS,
                          neoc_contract_management_has_method(
                              mgmt,
                              &hash,
                              "verify",
                              0,
                              &script,
                              &script_len));
    TEST_ASSERT_NOT_NULL(script);
    TEST_ASSERT_TRUE(script_len > 0);

    neoc_free(script);
    neoc_contract_management_free(mgmt);
}

void test_policy_whitelist_v391_method_signature_builds(void) {
    neoc_policy_contract_t *policy = NULL;
    neoc_hash160_t contract_hash = {0};

    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, neoc_policy_contract_create(&policy));

    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS,
                          neoc_policy_set_whitelist_fee_contract(policy,
                                                                  &contract_hash,
                                                                  "transfer",
                                                                  3,
                                                                  0));

    neoc_policy_contract_free(policy);
}

/* ===== MAIN TEST RUNNER ===== */

int main(void) {
    UNITY_BEGIN();
    
    printf("\n=== NEO CONSTANTS TESTS ===\n");
    
    RUN_TEST(test_neo_token_constants);
    RUN_TEST(test_gas_token_constants);
    RUN_TEST(test_address_version);
    RUN_TEST(test_max_transaction_size);
    RUN_TEST(test_max_script_size);
    RUN_TEST(test_opcode_values);
    RUN_TEST(test_crypto_constants);
    RUN_TEST(test_address_constants);
    RUN_TEST(test_all_native_contract_hashes_match_neo_v391);
    RUN_TEST(test_network_magic_constants_match_neo_n3);
    RUN_TEST(test_contract_management_has_method_signature_builds);
    RUN_TEST(test_policy_whitelist_v391_method_signature_builds);
    
    UNITY_END();
    return 0;
}
