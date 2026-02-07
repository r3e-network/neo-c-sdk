#include <unity.h>
#include <neoc/neoc.h>
#include <neoc/wallet/account.h>
#include <neoc/transaction/transaction_builder.h>
#include <neoc/crypto/bip39.h>
#include <neoc/script/script_builder.h>
#include <neoc/wallet/nep6.h>
#include <neoc/crypto/ec_key_pair.h>
#include <neoc/protocol/rpc_client.h>
#include <string.h>
#include <stdlib.h>

void setUp(void) {
    neoc_init();
    neoc_crypto_init();
}

void tearDown(void) {
    neoc_cleanup();
}

void test_full_wallet_workflow(void) {
    // Test complete wallet workflow
    
    // 1. Generate mnemonic
    char *mnemonic = NULL;
    neoc_error_t err = neoc_bip39_generate_mnemonic(NEOC_BIP39_STRENGTH_128,
                                                     NEOC_BIP39_LANG_ENGLISH,
                                                     &mnemonic);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    TEST_ASSERT_NOT_NULL(mnemonic);
    
    // 2. Generate seed from mnemonic
    uint8_t seed[64];
    err = neoc_bip39_mnemonic_to_seed(mnemonic, "", seed);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    
    // 3. Create account from seed (simplified - normally would derive keys)
    neoc_account_t *account = NULL;
    err = neoc_account_create("test-account", &account);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    TEST_ASSERT_NOT_NULL(account);
    
    // 4. Get account address
    const char *address = neoc_account_get_address(account);
    TEST_ASSERT_NOT_NULL(address);
    TEST_ASSERT_TRUE(strlen(address) > 0);
    
    // 5. Export to WIF
    char *wif = NULL;
    err = neoc_account_export_wif(account, &wif);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    TEST_ASSERT_NOT_NULL(wif);
    free(wif);
    
    // Clean up
    free(mnemonic);
    neoc_account_free(account);
}

void test_transaction_building_workflow(void) {
    // Test transaction building workflow
    
    // 1. Create account
    neoc_account_t *sender = NULL;
    neoc_error_t err = neoc_account_create("sender", &sender);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    TEST_ASSERT_NOT_NULL(sender);
    
    // 2. Create transaction builder
    neoc_tx_builder_t *builder = NULL;
    err = neoc_tx_builder_create(&builder);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    TEST_ASSERT_NOT_NULL(builder);
    
    // 3. Set transaction properties
    err = neoc_tx_builder_set_version(builder, 0);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    
    err = neoc_tx_builder_set_nonce(builder, 12345);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    
    err = neoc_tx_builder_set_valid_until_block(builder, 1000000);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    
    // 4. Add signer
    err = neoc_tx_builder_add_signer_from_account(builder, sender, 
                                                   NEOC_WITNESS_SCOPE_CALLED_BY_ENTRY);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    
    // 5. Create simple script
    neoc_script_builder_t *script = NULL;
    err = neoc_script_builder_create(&script);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    
    err = neoc_script_builder_push_integer(script, 123);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    
    err = neoc_script_builder_emit(script, NEOC_OP_DROP);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    
    err = neoc_script_builder_emit(script, NEOC_OP_RET);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    
    // 6. Set script in transaction
    uint8_t *script_bytes = NULL;
    size_t script_len = 0;
    err = neoc_script_builder_to_array(script, &script_bytes, &script_len);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    TEST_ASSERT_NOT_NULL(script_bytes);
    
    err = neoc_tx_builder_set_script(builder, script_bytes, script_len);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    
    // 7. Build unsigned transaction
    neoc_transaction_t *tx = NULL;
    err = neoc_tx_builder_build_unsigned(builder, &tx);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    TEST_ASSERT_NOT_NULL(tx);
    
    // 8. Get transaction hash
    neoc_hash256_t tx_hash;
    err = neoc_transaction_get_hash(tx, &tx_hash);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    
    // Clean up
    neoc_free(script_bytes);
    neoc_script_builder_free(script);
    neoc_transaction_free(tx);
    neoc_tx_builder_free(builder);
    neoc_account_free(sender);
}

void test_script_building_workflow(void) {
    // Test script building with various opcodes
    
    neoc_script_builder_t *builder = NULL;
    neoc_error_t err = neoc_script_builder_create(&builder);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    TEST_ASSERT_NOT_NULL(builder);
    
    // Push various data types
    err = neoc_script_builder_push_integer(builder, 42);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    
    err = neoc_script_builder_push_data(builder, (uint8_t*)"Hello Neo", 9);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    
    uint8_t data[] = {0x01, 0x02, 0x03, 0x04};
    err = neoc_script_builder_push_data(builder, data, sizeof(data));
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    
    // Emit various opcodes
    err = neoc_script_builder_emit(builder, NEOC_OP_ADD);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    
    err = neoc_script_builder_emit(builder, NEOC_OP_SUB);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    
    err = neoc_script_builder_emit(builder, NEOC_OP_DUP);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    
    // Convert to bytes
    uint8_t *script_bytes = NULL;
    size_t script_len = 0;
    err = neoc_script_builder_to_array(builder, &script_bytes, &script_len);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    TEST_ASSERT_NOT_NULL(script_bytes);
    TEST_ASSERT_TRUE(script_len > 0);
    
    // Clean up
    neoc_free(script_bytes);
    neoc_script_builder_free(builder);
}

void test_nep17_transfer_workflow(void) {
    // Test NEP-17 token transfer
    
    // Create accounts
    neoc_account_t *from = NULL;
    neoc_error_t err = neoc_account_create("from", &from);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    
    // Get from address
    const char *from_address = neoc_account_get_address(from);
    TEST_ASSERT_NOT_NULL(from_address);
    
    // NEO token hash (simplified - normally would be proper hash)
    neoc_hash160_t neo_hash;
    neoc_hash160_init_zero(&neo_hash);
    memset(neo_hash.data, 0xef, 20); // Dummy NEO hash
    
    // Create NEP-17 transfer
    neoc_tx_builder_t *builder = NULL;
    err = neoc_tx_builder_create_nep17_transfer(
        &neo_hash,
        from,
        from_address,  // Send to self for testing
        100000000,     // 1 NEO
        NULL,
        0,
        &builder
    );
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    TEST_ASSERT_NOT_NULL(builder);
    
    // Build unsigned transaction
    neoc_transaction_t *tx = NULL;
    err = neoc_tx_builder_build_unsigned(builder, &tx);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    TEST_ASSERT_NOT_NULL(tx);
    
    // Clean up
    neoc_transaction_free(tx);
    neoc_tx_builder_free(builder);
    neoc_account_free(from);
}

void test_crypto_operations(void) {
    // Test various crypto operations
    
    // Test SHA256
    uint8_t data[] = "Hello Neo";
    uint8_t hash[32];
    neoc_error_t err = neoc_sha256(data, strlen((char*)data), hash);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    
    // Test Hash256 (double SHA256)
    uint8_t hash256[32];
    err = neoc_hash256(data, strlen((char*)data), hash256);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    
    // Test Hash160
    uint8_t hash160[20];
    err = neoc_hash160(data, strlen((char*)data), hash160);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    
    // Test Base58 encoding
    char base58[128];
    err = neoc_base58_encode(data, strlen((char*)data), base58, sizeof(base58));
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    
    // Test Base58 decoding
    uint8_t decoded[128];
    size_t decoded_len = 0;
    err = neoc_base58_decode(base58, decoded, sizeof(decoded), &decoded_len);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    TEST_ASSERT_EQUAL_INT(strlen((char*)data), decoded_len);
    TEST_ASSERT_EQUAL_MEMORY(data, decoded, decoded_len);
}

void test_rpc_client_creation(void) {
    // Test RPC client creation (without actual network calls)
    
    neoc_rpc_client_t *client = NULL;
    neoc_error_t err = neoc_rpc_client_create("http://localhost:10332", &client);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    TEST_ASSERT_NOT_NULL(client);
    
    // Set timeout
    err = neoc_rpc_client_set_timeout(client, 5000);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    
    // Note: Actual RPC calls would require a running Neo node
    // For integration testing, we just verify the client can be created
    
    neoc_rpc_client_free(client);
}

void test_rpc_submit_block_handles_missing_http_stack(void) {
    neoc_rpc_client_t *client = NULL;
    neoc_error_t err = neoc_rpc_client_create("http://localhost:10332", &client);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    TEST_ASSERT_NOT_NULL(client);

    const uint8_t block_data[] = {0x01, 0x02, 0x03, 0x04};
    bool accepted = true;

    err = neoc_rpc_submit_block(client, block_data, sizeof(block_data), &accepted);

    /*
     * In this test environment libcurl/cJSON may be disabled, so NOT_IMPLEMENTED
     * is acceptable. The key assertion is that this call must not crash.
     */
    TEST_ASSERT_TRUE(err == NEOC_SUCCESS ||
                     err == NEOC_ERROR_NOT_IMPLEMENTED ||
                     err == NEOC_ERROR_NETWORK ||
                     err == NEOC_ERROR_INVALID_FORMAT);

    neoc_rpc_client_free(client);
}

void test_wallet_nep6_workflow(void) {
    // Test NEP-6 wallet operations
    
    // Create wallet
    neoc_nep6_wallet_t *wallet = NULL;
    neoc_error_t err = neoc_nep6_wallet_create("Test Wallet", "1.0", &wallet);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    TEST_ASSERT_NOT_NULL(wallet);
    
    // Create a key pair for the account
    neoc_ec_key_pair_t *key_pair = NULL;
    err = neoc_ec_key_pair_create_random(&key_pair);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    TEST_ASSERT_NOT_NULL(key_pair);
    
    // Get private key bytes from key pair
    uint8_t private_key[32];
    memcpy(private_key, key_pair->private_key->bytes, 32);
    
    // Add account to NEP-6 wallet with encryption
    err = neoc_nep6_wallet_add_account(wallet, private_key, "password123", "account1", true);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    
    // Clean up key pair
    neoc_ec_key_pair_free(key_pair);
    
    // Get account count
    size_t count = neoc_nep6_wallet_get_account_count(wallet);
    TEST_ASSERT_EQUAL_INT(1, count);
    
    // Export to JSON (NEP-6 format)
    char *json = NULL;
    size_t json_len = 0;
    err = neoc_nep6_wallet_to_json(wallet, &json, &json_len);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    TEST_ASSERT_NOT_NULL(json);
    TEST_ASSERT_TRUE(json_len > 0);
    
    // Clean up
    free(json);
    neoc_nep6_wallet_free(wallet);
}

int main(void) {
    UNITY_BEGIN();
    
    RUN_TEST(test_full_wallet_workflow);
    RUN_TEST(test_transaction_building_workflow);
    RUN_TEST(test_script_building_workflow);
    RUN_TEST(test_nep17_transfer_workflow);
    RUN_TEST(test_crypto_operations);
    RUN_TEST(test_rpc_client_creation);
    RUN_TEST(test_rpc_submit_block_handles_missing_http_stack);
    RUN_TEST(test_wallet_nep6_workflow);
    
    return UnityEnd();
}
