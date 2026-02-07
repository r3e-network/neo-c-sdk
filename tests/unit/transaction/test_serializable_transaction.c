#include "unity.h"
#include <stdlib.h>
#include <string.h>
#include "neoc/neoc.h"
#include "neoc/crypto/sha256.h"
#include "neoc/serialization/binary_writer.h"
#include "neoc/transaction/transaction.h"
#include "neoc/transaction/signer.h"
#include "neoc/transaction/witness.h"
#include "neoc/utils/neoc_hex.h"

static neoc_transaction_t *transaction = NULL;

void setUp(void) {
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, neoc_init());
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, neoc_transaction_create(&transaction));
}

void tearDown(void) {
    neoc_transaction_free(transaction);
    transaction = NULL;
    neoc_cleanup();
}

void test_transaction_serialization_and_hash(void) {
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, neoc_transaction_set_version(transaction, 0x01));
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, neoc_transaction_set_nonce(transaction, 42));
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, neoc_transaction_set_system_fee(transaction, 10));
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, neoc_transaction_set_network_fee(transaction, 1));
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, neoc_transaction_set_valid_until_block(transaction, 1000));

    const uint8_t script[] = {0x01, 0x02, 0x03};
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS,
                          neoc_transaction_set_script(transaction, script, sizeof(script)));

    uint8_t buffer[512];
    size_t serialized = 0;
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS,
                          neoc_transaction_serialize(transaction, buffer, sizeof(buffer), &serialized));
    TEST_ASSERT_TRUE(serialized > 0);

    neoc_hash256_t hash_direct;
    neoc_hash256_t hash_cached;
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS,
                          neoc_transaction_calculate_hash(transaction, &hash_direct));
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS,
                          neoc_transaction_get_hash(transaction, &hash_cached));
    TEST_ASSERT_EQUAL_MEMORY(hash_direct.data, hash_cached.data, NEOC_HASH256_SIZE);

    /* Verify transaction hash uses Neo N3 Hash256 (double SHA256 of unsigned bytes). */
    neoc_binary_writer_t *writer = NULL;
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, neoc_binary_writer_create(128, true, &writer));
    TEST_ASSERT_NOT_NULL(writer);

    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, neoc_binary_writer_write_byte(writer, transaction->version));
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, neoc_binary_writer_write_uint32(writer, transaction->nonce));
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, neoc_binary_writer_write_uint64(writer, transaction->system_fee));
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, neoc_binary_writer_write_uint64(writer, transaction->network_fee));
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, neoc_binary_writer_write_uint32(writer, transaction->valid_until_block));
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, neoc_binary_writer_write_var_int(writer, 0)); /* signers */
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, neoc_binary_writer_write_var_int(writer, 0)); /* attributes */
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, neoc_binary_writer_write_var_bytes(writer,
                                                                          transaction->script,
                                                                          transaction->script_len));

    uint8_t *unsigned_bytes = NULL;
    size_t unsigned_len = 0;
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, neoc_binary_writer_to_array(writer, &unsigned_bytes, &unsigned_len));
    TEST_ASSERT_NOT_NULL(unsigned_bytes);
    TEST_ASSERT_TRUE(unsigned_len > 0);

    uint8_t expected_hash[32];
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, neoc_sha256_double(unsigned_bytes, unsigned_len, expected_hash));
    TEST_ASSERT_EQUAL_MEMORY(expected_hash, hash_direct.data, 32);

    uint8_t single_hash[32];
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, neoc_sha256(unsigned_bytes, unsigned_len, single_hash));
    TEST_ASSERT_TRUE(memcmp(single_hash, hash_direct.data, 32) != 0);

    neoc_free(unsigned_bytes);
    neoc_binary_writer_free(writer);
}

static void assert_signer_equal(const neoc_signer_t *a, const neoc_signer_t *b) {
    TEST_ASSERT_NOT_NULL(a);
    TEST_ASSERT_NOT_NULL(b);
    TEST_ASSERT_EQUAL_UINT8(a->scopes, b->scopes);
    TEST_ASSERT_EQUAL_MEMORY(a->account.data, b->account.data, NEOC_HASH160_SIZE);

    TEST_ASSERT_EQUAL_UINT64((uint64_t)a->allowed_contracts_count, (uint64_t)b->allowed_contracts_count);
    for (size_t i = 0; i < a->allowed_contracts_count; i++) {
        TEST_ASSERT_EQUAL_MEMORY(a->allowed_contracts[i].data, b->allowed_contracts[i].data, NEOC_HASH160_SIZE);
    }

    TEST_ASSERT_EQUAL_UINT64((uint64_t)a->allowed_groups_count, (uint64_t)b->allowed_groups_count);
    for (size_t i = 0; i < a->allowed_groups_count; i++) {
        TEST_ASSERT_EQUAL_UINT64((uint64_t)a->allowed_groups_sizes[i], (uint64_t)b->allowed_groups_sizes[i]);
        TEST_ASSERT_EQUAL_MEMORY(a->allowed_groups[i], b->allowed_groups[i], a->allowed_groups_sizes[i]);
    }

    TEST_ASSERT_EQUAL_UINT64((uint64_t)a->rules_count, (uint64_t)b->rules_count);
    for (size_t i = 0; i < a->rules_count; i++) {
        TEST_ASSERT_TRUE(neoc_witness_rule_equals(a->rules[i], b->rules[i]));
    }
}

static void assert_attribute_equal(const neoc_tx_attribute_t *a, const neoc_tx_attribute_t *b) {
    TEST_ASSERT_NOT_NULL(a);
    TEST_ASSERT_NOT_NULL(b);
    TEST_ASSERT_EQUAL_UINT8((uint8_t)a->type, (uint8_t)b->type);
    TEST_ASSERT_EQUAL_UINT64((uint64_t)a->data_len, (uint64_t)b->data_len);
    if (a->data_len > 0) {
        TEST_ASSERT_EQUAL_MEMORY(a->data, b->data, a->data_len);
    }
}

static void assert_witness_equal(const neoc_witness_t *a, const neoc_witness_t *b) {
    TEST_ASSERT_NOT_NULL(a);
    TEST_ASSERT_NOT_NULL(b);
    TEST_ASSERT_EQUAL_UINT64((uint64_t)a->invocation_script_len, (uint64_t)b->invocation_script_len);
    TEST_ASSERT_EQUAL_UINT64((uint64_t)a->verification_script_len, (uint64_t)b->verification_script_len);
    if (a->invocation_script_len > 0) {
        TEST_ASSERT_EQUAL_MEMORY(a->invocation_script, b->invocation_script, a->invocation_script_len);
    }
    if (a->verification_script_len > 0) {
        TEST_ASSERT_EQUAL_MEMORY(a->verification_script, b->verification_script, a->verification_script_len);
    }
}

void test_neoc_init_is_idempotent(void) {
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, neoc_init());
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, neoc_init());

    const uint8_t data[] = {0x01, 0x02, 0x03};
    uint8_t digest[32];
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, neoc_sha256(data, sizeof(data), digest));
}

void test_transaction_deserialize_roundtrip(void) {
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, neoc_transaction_set_version(transaction, 0x00));
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, neoc_transaction_set_nonce(transaction, 0x11223344));
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, neoc_transaction_set_system_fee(transaction, 10));
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, neoc_transaction_set_network_fee(transaction, 5));
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, neoc_transaction_set_valid_until_block(transaction, 123456));

    neoc_hash160_t account_hash;
    neoc_hash160_init_zero(&account_hash);
    for (size_t i = 0; i < NEOC_HASH160_SIZE; i++) {
        account_hash.data[i] = (uint8_t)(i + 1);
    }

    neoc_signer_t *signer = NULL;
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS,
                          neoc_signer_create(&account_hash,
                                             (uint8_t)(NEOC_WITNESS_SCOPE_CUSTOM_CONTRACTS | NEOC_WITNESS_SCOPE_CUSTOM_GROUPS),
                                             &signer));
    TEST_ASSERT_NOT_NULL(signer);

    neoc_hash160_t allowed_contract;
    neoc_hash160_init_zero(&allowed_contract);
    memset(allowed_contract.data, 0xA5, NEOC_HASH160_SIZE);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, neoc_signer_add_allowed_contract(signer, &allowed_contract));

    uint8_t group_pubkey[NEOC_PUBLIC_KEY_SIZE_COMPRESSED];
    memset(group_pubkey, 0x42, sizeof(group_pubkey));
    group_pubkey[0] = 0x02;
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, neoc_signer_add_allowed_group(signer, group_pubkey, sizeof(group_pubkey)));

    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, neoc_transaction_add_signer(transaction, signer));

    const uint8_t attr_data[] = {0xDE, 0xAD, 0xBE, 0xEF};
    neoc_tx_attribute_t *attribute = NULL;
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS,
                          neoc_tx_attribute_create(NEOC_TX_ATTR_NOT_VALID_BEFORE,
                                                  attr_data,
                                                  sizeof(attr_data),
                                                  &attribute));
    TEST_ASSERT_NOT_NULL(attribute);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, neoc_transaction_add_attribute(transaction, attribute));

    const uint8_t script[] = {0x0C, 0x01, 0x41};
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, neoc_transaction_set_script(transaction, script, sizeof(script)));

    const uint8_t invocation[] = {0xAA};
    const uint8_t verification[] = {0xBB, 0xCC};
    neoc_witness_t *witness = NULL;
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS,
                          neoc_witness_create(invocation, sizeof(invocation),
                                              verification, sizeof(verification),
                                              &witness));
    TEST_ASSERT_NOT_NULL(witness);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, neoc_transaction_add_witness(transaction, witness));

    size_t buffer_size = neoc_transaction_get_size(transaction);
    uint8_t *buffer = neoc_malloc(buffer_size);
    TEST_ASSERT_NOT_NULL(buffer);

    size_t serialized = 0;
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS,
                          neoc_transaction_serialize(transaction, buffer, buffer_size, &serialized));
    TEST_ASSERT_TRUE(serialized > 0);

    neoc_transaction_t *roundtrip = NULL;
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, neoc_transaction_deserialize(buffer, serialized, &roundtrip));
    TEST_ASSERT_NOT_NULL(roundtrip);

    TEST_ASSERT_EQUAL_UINT8(transaction->version, roundtrip->version);
    TEST_ASSERT_EQUAL_UINT32(transaction->nonce, roundtrip->nonce);
    TEST_ASSERT_EQUAL_UINT64(transaction->system_fee, roundtrip->system_fee);
    TEST_ASSERT_EQUAL_UINT64(transaction->network_fee, roundtrip->network_fee);
    TEST_ASSERT_EQUAL_UINT32(transaction->valid_until_block, roundtrip->valid_until_block);

    TEST_ASSERT_EQUAL_UINT64((uint64_t)transaction->script_len, (uint64_t)roundtrip->script_len);
    TEST_ASSERT_EQUAL_MEMORY(transaction->script, roundtrip->script, transaction->script_len);

    TEST_ASSERT_EQUAL_UINT64((uint64_t)transaction->signer_count, (uint64_t)roundtrip->signer_count);
    for (size_t i = 0; i < transaction->signer_count; i++) {
        assert_signer_equal(transaction->signers[i], roundtrip->signers[i]);
    }

    TEST_ASSERT_EQUAL_UINT64((uint64_t)transaction->attribute_count, (uint64_t)roundtrip->attribute_count);
    for (size_t i = 0; i < transaction->attribute_count; i++) {
        assert_attribute_equal(transaction->attributes[i], roundtrip->attributes[i]);
    }

    TEST_ASSERT_EQUAL_UINT64((uint64_t)transaction->witness_count, (uint64_t)roundtrip->witness_count);
    for (size_t i = 0; i < transaction->witness_count; i++) {
        assert_witness_equal(transaction->witnesses[i], roundtrip->witnesses[i]);
    }

    size_t buffer_size_roundtrip = neoc_transaction_get_size(roundtrip);
    uint8_t *buffer2 = neoc_malloc(buffer_size_roundtrip);
    TEST_ASSERT_NOT_NULL(buffer2);
    size_t serialized2 = 0;
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS,
                          neoc_transaction_serialize(roundtrip, buffer2, buffer_size_roundtrip, &serialized2));
    TEST_ASSERT_EQUAL_UINT64((uint64_t)serialized, (uint64_t)serialized2);
    TEST_ASSERT_EQUAL_MEMORY(buffer, buffer2, serialized);

    neoc_free(buffer2);
    neoc_transaction_free(roundtrip);
    neoc_free(buffer);
}

void test_transaction_deserialize_known_hex_fixture(void) {
    const char *tx_hex =
        "00443322110000000000000000000000000000000001000000010102030405060708090a0b0c0d0e0f101112131480000201020101aa02bbcc";

    size_t tx_len = 0;
    uint8_t *tx_bytes = neoc_hex_decode_alloc(tx_hex, &tx_len);
    TEST_ASSERT_NOT_NULL(tx_bytes);
    TEST_ASSERT_TRUE(tx_len > 0);

    neoc_transaction_t *parsed = NULL;
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, neoc_transaction_deserialize(tx_bytes, tx_len, &parsed));
    TEST_ASSERT_NOT_NULL(parsed);

    TEST_ASSERT_EQUAL_UINT8(0, parsed->version);
    TEST_ASSERT_EQUAL_UINT32(0x11223344, parsed->nonce);
    TEST_ASSERT_EQUAL_UINT64(0, parsed->system_fee);
    TEST_ASSERT_EQUAL_UINT64(0, parsed->network_fee);
    TEST_ASSERT_EQUAL_UINT32(1, parsed->valid_until_block);
    TEST_ASSERT_EQUAL_UINT64(1, (uint64_t)parsed->signer_count);
    TEST_ASSERT_EQUAL_UINT8(NEOC_WITNESS_SCOPE_GLOBAL, parsed->signers[0]->scopes);
    TEST_ASSERT_EQUAL_UINT64(0, (uint64_t)parsed->attribute_count);
    TEST_ASSERT_EQUAL_UINT64(2, (uint64_t)parsed->script_len);
    TEST_ASSERT_EQUAL_HEX8(0x01, parsed->script[0]);
    TEST_ASSERT_EQUAL_HEX8(0x02, parsed->script[1]);
    TEST_ASSERT_EQUAL_UINT64(1, (uint64_t)parsed->witness_count);

    neoc_hash256_t hash;
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, neoc_transaction_calculate_hash(parsed, &hash));
    char hash_hex[65];
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, neoc_hash256_to_string(&hash, hash_hex, sizeof(hash_hex)));
    TEST_ASSERT_EQUAL_STRING("8e7d81bf51d400b1996e5da4156a67a058caa58c6f9ded12bcc437875a17ea53", hash_hex);

    uint8_t buffer[256];
    size_t serialized = 0;
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, neoc_transaction_serialize(parsed, buffer, sizeof(buffer), &serialized));
    TEST_ASSERT_EQUAL_UINT64((uint64_t)tx_len, (uint64_t)serialized);
    TEST_ASSERT_EQUAL_MEMORY(tx_bytes, buffer, tx_len);

    neoc_transaction_free(parsed);
    neoc_free(tx_bytes);
}

void test_transaction_deserialize_real_tx_hex_env(void) {
    const char *tx_hex = getenv("NEOC_TESTNET_TX_HEX");
    if (!tx_hex || tx_hex[0] == '\0') {
        TEST_IGNORE_MESSAGE("Set NEOC_TESTNET_TX_HEX to a Neo N3 testnet transaction hex to enable this test");
    }

    size_t tx_len = 0;
    uint8_t *tx_bytes = neoc_hex_decode_alloc(tx_hex, &tx_len);
    TEST_ASSERT_NOT_NULL(tx_bytes);
    TEST_ASSERT_TRUE(tx_len > 0);

    neoc_transaction_t *parsed = NULL;
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, neoc_transaction_deserialize(tx_bytes, tx_len, &parsed));
    TEST_ASSERT_NOT_NULL(parsed);

    const char *expected_hash_hex = getenv("NEOC_TESTNET_TXID");
    if (expected_hash_hex && expected_hash_hex[0] != '\0') {
        neoc_hash256_t hash;
        TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, neoc_transaction_calculate_hash(parsed, &hash));
        char hash_hex[65];
        TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, neoc_hash256_to_string(&hash, hash_hex, sizeof(hash_hex)));
        TEST_ASSERT_EQUAL_STRING(expected_hash_hex, hash_hex);
    }

    uint8_t *roundtrip = neoc_malloc(neoc_transaction_get_size(parsed));
    TEST_ASSERT_NOT_NULL(roundtrip);
    size_t written = 0;
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS,
                          neoc_transaction_serialize(parsed, roundtrip, neoc_transaction_get_size(parsed), &written));
    TEST_ASSERT_EQUAL_UINT64((uint64_t)tx_len, (uint64_t)written);
    TEST_ASSERT_EQUAL_MEMORY(tx_bytes, roundtrip, tx_len);

    neoc_free(roundtrip);
    neoc_transaction_free(parsed);
    neoc_free(tx_bytes);
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_transaction_serialization_and_hash);
    RUN_TEST(test_neoc_init_is_idempotent);
    RUN_TEST(test_transaction_deserialize_roundtrip);
    RUN_TEST(test_transaction_deserialize_known_hex_fixture);
    RUN_TEST(test_transaction_deserialize_real_tx_hex_env);
    UNITY_END();
    return 0;
}
