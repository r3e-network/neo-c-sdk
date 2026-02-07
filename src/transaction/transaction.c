#include "neoc/transaction/transaction.h"
#include "neoc/crypto/sha256.h"
#include "neoc/wallet/account.h"
#include "neoc/utils/json.h"
#include "neoc/utils/neoc_hex.h"
#include "neoc/neoc_memory.h"
#include "neoc/serialization/binary_writer.h"
#include "neoc/serialization/binary_reader.h"
#include "neoc/neo_constants.h"
#include "neoc/protocol/core/witnessrule/witness_condition.h"
#include <string.h>
#include <time.h>

static neoc_error_t neoc_tx_attribute_clone_internal(const neoc_tx_attribute_t *source,
                                                     neoc_tx_attribute_t **dest);

static neoc_error_t neoc_transaction_build_serialized(const neoc_transaction_t *transaction,
                                                      bool include_witnesses,
                                                      uint8_t **out_bytes,
                                                      size_t *out_len);

neoc_error_t neoc_transaction_create(neoc_transaction_t **transaction) {
    if (!transaction) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid transaction pointer");
    }
    
    *transaction = neoc_calloc(1, sizeof(neoc_transaction_t));
    if (!*transaction) {
        return neoc_error_set(NEOC_ERROR_MEMORY, "Failed to allocate transaction");
    }
    
    // Set defaults
    (*transaction)->version = 0;
    (*transaction)->nonce = (uint32_t)time(NULL);  // Use timestamp as nonce
    
    return NEOC_SUCCESS;
}

neoc_error_t neoc_transaction_set_version(neoc_transaction_t *transaction, uint8_t version) {
    if (!transaction) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid transaction");
    }
    transaction->version = version;
    return NEOC_SUCCESS;
}

neoc_error_t neoc_transaction_set_nonce(neoc_transaction_t *transaction, uint32_t nonce) {
    if (!transaction) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid transaction");
    }
    transaction->nonce = nonce;
    return NEOC_SUCCESS;
}

neoc_error_t neoc_transaction_set_system_fee(neoc_transaction_t *transaction, uint64_t fee) {
    if (!transaction) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid transaction");
    }
    transaction->system_fee = fee;
    return NEOC_SUCCESS;
}

neoc_error_t neoc_transaction_set_network_fee(neoc_transaction_t *transaction, uint64_t fee) {
    if (!transaction) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid transaction");
    }
    transaction->network_fee = fee;
    return NEOC_SUCCESS;
}

neoc_error_t neoc_transaction_set_valid_until_block(neoc_transaction_t *transaction, uint32_t block) {
    if (!transaction) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid transaction");
    }
    transaction->valid_until_block = block;
    return NEOC_SUCCESS;
}

neoc_error_t neoc_transaction_set_script(neoc_transaction_t *transaction,
                                          const uint8_t *script,
                                          size_t script_len) {
    if (!transaction || !script || script_len == 0) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }
    if (script_len > NEOC_MAX_SCRIPT_SIZE) {
        return neoc_error_set(NEOC_ERROR_INVALID_SIZE, "Script exceeds maximum size");
    }
    
    // Free old script if exists
    if (transaction->script) {
        neoc_free(transaction->script);
    }
    
    // Allocate and copy new script
    transaction->script = neoc_malloc(script_len);
    if (!transaction->script) {
        return neoc_error_set(NEOC_ERROR_MEMORY, "Failed to allocate script");
    }
    
    memcpy(transaction->script, script, script_len);
    transaction->script_len = script_len;
    
    return NEOC_SUCCESS;
}

neoc_error_t neoc_transaction_get_script(const neoc_transaction_t *transaction,
                                         uint8_t **script,
                                         size_t *script_len) {
    if (!transaction || !script || !script_len) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }

    if (!transaction->script || transaction->script_len == 0) {
        *script = NULL;
        *script_len = 0;
        return NEOC_SUCCESS;
    }

    uint8_t *copy = neoc_malloc(transaction->script_len);
    if (!copy) {
        return neoc_error_set(NEOC_ERROR_MEMORY, "Failed to copy transaction script");
    }

    memcpy(copy, transaction->script, transaction->script_len);
    *script = copy;
    *script_len = transaction->script_len;
    return NEOC_SUCCESS;
}

const uint8_t* neoc_transaction_get_script_ptr(const neoc_transaction_t *transaction,
                                               size_t *script_len) {
    if (!transaction) {
        return NULL;
    }
    if (script_len) {
        *script_len = transaction->script_len;
    }
    return transaction->script;
}

neoc_error_t neoc_transaction_add_signer(neoc_transaction_t *transaction,
                                          neoc_signer_t *signer) {
    if (!transaction || !signer) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }
    if (transaction->signer_count >= NEOC_MAX_SIGNERS) {
        return neoc_error_set(NEOC_ERROR_INVALID_SIZE, "Too many transaction signers");
    }
    
    // Check for duplicate signer
    for (size_t i = 0; i < transaction->signer_count; i++) {
        if (memcmp(&transaction->signers[i]->account, &signer->account,
                   sizeof(neoc_hash160_t)) == 0) {
            return neoc_error_set(NEOC_ERROR_INVALID_STATE, "Signer already exists");
        }
    }
    
    // Resize signers array
    size_t new_count = transaction->signer_count + 1;
    neoc_signer_t **new_signers = neoc_realloc(transaction->signers,
                                               new_count * sizeof(neoc_signer_t*));
    if (!new_signers) {
        return neoc_error_set(NEOC_ERROR_MEMORY, "Failed to resize signers");
    }
    
    transaction->signers = new_signers;
    transaction->signers[transaction->signer_count] = signer;
    transaction->signer_count = new_count;
    
    return NEOC_SUCCESS;
}

neoc_error_t neoc_transaction_add_attribute(neoc_transaction_t *transaction,
                                             neoc_tx_attribute_t *attribute) {
    if (!transaction || !attribute) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }
    if (transaction->attribute_count >= NEOC_MAX_TRANSACTION_ATTRIBUTES) {
        return neoc_error_set(NEOC_ERROR_INVALID_SIZE, "Too many transaction attributes");
    }
    
    // Resize attributes array
    size_t new_count = transaction->attribute_count + 1;
    neoc_tx_attribute_t **new_attributes = neoc_realloc(transaction->attributes,
                                                        new_count * sizeof(neoc_tx_attribute_t*));
    if (!new_attributes) {
        return neoc_error_set(NEOC_ERROR_MEMORY, "Failed to resize attributes");
    }
    
    transaction->attributes = new_attributes;
    transaction->attributes[transaction->attribute_count] = attribute;
    transaction->attribute_count = new_count;
    
    return NEOC_SUCCESS;
}

neoc_error_t neoc_transaction_add_witness(neoc_transaction_t *transaction,
                                           neoc_witness_t *witness) {
    if (!transaction || !witness) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }
    if (transaction->witness_count >= NEOC_MAX_WITNESSES) {
        return neoc_error_set(NEOC_ERROR_INVALID_SIZE, "Too many transaction witnesses");
    }
    
    // Resize witnesses array
    size_t new_count = transaction->witness_count + 1;
    neoc_witness_t **new_witnesses = neoc_realloc(transaction->witnesses,
                                                  new_count * sizeof(neoc_witness_t*));
    if (!new_witnesses) {
        return neoc_error_set(NEOC_ERROR_MEMORY, "Failed to resize witnesses");
    }
    
    transaction->witnesses = new_witnesses;
    transaction->witnesses[transaction->witness_count] = witness;
    transaction->witness_count = new_count;
    
    return NEOC_SUCCESS;
}

static neoc_error_t neoc_tx_write_signers(const neoc_transaction_t *transaction,
                                          neoc_binary_writer_t *writer) {
    neoc_error_t err = neoc_binary_writer_write_var_int(writer, transaction->signer_count);
    if (err != NEOC_SUCCESS) {
        return err;
    }

    for (size_t i = 0; i < transaction->signer_count; ++i) {
        neoc_signer_t *signer = transaction->signers[i];
        if (!signer) {
            return neoc_error_set(NEOC_ERROR_INVALID_STATE, "Transaction signer is NULL");
        }
        err = neoc_signer_serialize(signer, writer);
        if (err != NEOC_SUCCESS) {
            return err;
        }
    }

    return NEOC_SUCCESS;
}

static neoc_error_t neoc_tx_attribute_write(const neoc_tx_attribute_t *attribute,
                                            neoc_binary_writer_t *writer) {
    if (!attribute) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Transaction attribute is NULL");
    }

    neoc_error_t err = neoc_binary_writer_write_byte(writer, (uint8_t)attribute->type);
    if (err != NEOC_SUCCESS) {
        return err;
    }

    switch (attribute->type) {
        case NEOC_TX_ATTR_HIGH_PRIORITY:
            if (attribute->data_len != 0) {
                return neoc_error_set(NEOC_ERROR_INVALID_DATA,
                                      "HighPriority attribute must not include payload data");
            }
            return NEOC_SUCCESS;

        case NEOC_TX_ATTR_NOT_VALID_BEFORE:
            if (attribute->data_len != sizeof(uint32_t) || !attribute->data) {
                return neoc_error_set(NEOC_ERROR_INVALID_DATA,
                                      "NotValidBefore attribute payload must be 4 bytes");
            }
            return neoc_binary_writer_write_bytes(writer, attribute->data, attribute->data_len);

        case NEOC_TX_ATTR_CONFLICTS:
            if (attribute->data_len != NEOC_HASH256_SIZE || !attribute->data) {
                return neoc_error_set(NEOC_ERROR_INVALID_DATA,
                                      "Conflicts attribute payload must be 32 bytes");
            }
            return neoc_binary_writer_write_bytes(writer, attribute->data, attribute->data_len);

        case NEOC_TX_ATTR_ORACLE_RESPONSE:
            /* Payload format: uint64 id + uint8 code + var_bytes result (already encoded). */
            if (!attribute->data || attribute->data_len == 0) {
                return neoc_error_set(NEOC_ERROR_INVALID_DATA,
                                      "OracleResponse attribute payload is empty");
            }
            return neoc_binary_writer_write_bytes(writer, attribute->data, attribute->data_len);

        default:
            return neoc_error_set(NEOC_ERROR_INVALID_DATA, "Unknown transaction attribute type");
    }
}

static neoc_error_t neoc_tx_write_attributes(const neoc_transaction_t *transaction,
                                             neoc_binary_writer_t *writer) {
    neoc_error_t err = neoc_binary_writer_write_var_int(writer, transaction->attribute_count);
    if (err != NEOC_SUCCESS) {
        return err;
    }

    for (size_t i = 0; i < transaction->attribute_count; ++i) {
        err = neoc_tx_attribute_write(transaction->attributes[i], writer);
        if (err != NEOC_SUCCESS) {
            return err;
        }
    }

    return NEOC_SUCCESS;
}

static neoc_error_t neoc_tx_write_witnesses(const neoc_transaction_t *transaction,
                                            neoc_binary_writer_t *writer) {
    neoc_error_t err = neoc_binary_writer_write_var_int(writer, transaction->witness_count);
    if (err != NEOC_SUCCESS) {
        return err;
    }

    for (size_t i = 0; i < transaction->witness_count; ++i) {
        uint8_t *witness_bytes = NULL;
        size_t witness_len = 0;
        err = neoc_witness_serialize(transaction->witnesses[i], &witness_bytes, &witness_len);
        if (err != NEOC_SUCCESS) {
            return err;
        }

        err = neoc_binary_writer_write_bytes(writer, witness_bytes, witness_len);
        neoc_free(witness_bytes);
        if (err != NEOC_SUCCESS) {
            return err;
        }
    }

    return NEOC_SUCCESS;
}

static size_t neoc_tx_var_int_size(uint64_t value) {
    if (value < 0xFD) {
        return 1;
    } else if (value <= 0xFFFF) {
        return 3;
    } else if (value <= 0xFFFFFFFF) {
        return 5;
    }
    return 9;
}

static neoc_error_t neoc_transaction_build_serialized(const neoc_transaction_t *transaction,
                                                      bool include_witnesses,
                                                      uint8_t **out_bytes,
                                                      size_t *out_len) {
    if (!transaction || !out_bytes || !out_len) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }

    if (transaction->system_fee > (uint64_t)INT64_MAX || transaction->network_fee > (uint64_t)INT64_MAX) {
        return neoc_error_set(NEOC_ERROR_INVALID_DATA, "Transaction fees exceed int64 range");
    }

    if (transaction->signer_count > NEOC_MAX_SIGNERS ||
        transaction->attribute_count > NEOC_MAX_TRANSACTION_ATTRIBUTES ||
        (include_witnesses && transaction->witness_count > NEOC_MAX_WITNESSES)) {
        return neoc_error_set(NEOC_ERROR_INVALID_SIZE, "Transaction contains too many items");
    }

    if ((transaction->signer_count > 0 && !transaction->signers) ||
        (transaction->attribute_count > 0 && !transaction->attributes) ||
        (include_witnesses && transaction->witness_count > 0 && !transaction->witnesses)) {
        return neoc_error_set(NEOC_ERROR_INVALID_STATE, "Transaction item list is NULL");
    }

    if (transaction->script_len > NEOC_MAX_SCRIPT_SIZE ||
        (transaction->script_len > 0 && !transaction->script)) {
        return neoc_error_set(NEOC_ERROR_INVALID_DATA, "Invalid transaction script");
    }

    neoc_binary_writer_t *writer = NULL;
    neoc_error_t err = neoc_binary_writer_create(256, true, &writer);
    if (err != NEOC_SUCCESS) {
        return err;
    }

    err = neoc_binary_writer_write_byte(writer, transaction->version);
    if (err == NEOC_SUCCESS) {
        err = neoc_binary_writer_write_uint32(writer, transaction->nonce);
    }
    if (err == NEOC_SUCCESS) {
        err = neoc_binary_writer_write_uint64(writer, transaction->system_fee);
    }
    if (err == NEOC_SUCCESS) {
        err = neoc_binary_writer_write_uint64(writer, transaction->network_fee);
    }
    if (err == NEOC_SUCCESS) {
        err = neoc_binary_writer_write_uint32(writer, transaction->valid_until_block);
    }
    if (err == NEOC_SUCCESS) {
        err = neoc_tx_write_signers(transaction, writer);
    }
    if (err == NEOC_SUCCESS) {
        err = neoc_tx_write_attributes(transaction, writer);
    }
    if (err == NEOC_SUCCESS) {
        err = neoc_binary_writer_write_var_bytes(writer,
                                                 transaction->script,
                                                 transaction->script_len);
    }
    if (err == NEOC_SUCCESS && include_witnesses) {
        err = neoc_tx_write_witnesses(transaction, writer);
    }

    if (err == NEOC_SUCCESS) {
        err = neoc_binary_writer_to_array(writer, out_bytes, out_len);
    }

    neoc_binary_writer_free(writer);
    return err;
}

neoc_error_t neoc_transaction_calculate_hash(neoc_transaction_t *transaction,
                                              neoc_hash256_t *hash) {
    if (!transaction || !hash) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }
    
    uint8_t *data = NULL;
    size_t data_len = 0;

    neoc_error_t err = neoc_transaction_build_serialized(transaction, false, &data, &data_len);
    if (err != NEOC_SUCCESS) {
        return err;
    }

    /* Neo N3 transaction hash is Hash256 = SHA256(SHA256(unsigned_data)) */
    err = neoc_sha256_double(data, data_len, hash->data);
    if (err == NEOC_SUCCESS) {
        memcpy(&transaction->hash, hash, sizeof(neoc_hash256_t));
    }

    neoc_free(data);
    return err;
}

neoc_error_t neoc_transaction_get_hash(const neoc_transaction_t *transaction,
                                        neoc_hash256_t *hash) {
    if (!transaction || !hash) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }
    
    // Calculate hash if not already done
    if (neoc_hash256_is_zero(&((neoc_transaction_t*)transaction)->hash)) {
        neoc_error_t err = neoc_transaction_calculate_hash((neoc_transaction_t*)transaction, 
                                                           &((neoc_transaction_t*)transaction)->hash);
        if (err != NEOC_SUCCESS) {
            return err;
        }
    }
    
    *hash = transaction->hash;
    return NEOC_SUCCESS;
}

neoc_error_t neoc_transaction_serialize(const neoc_transaction_t *transaction,
                                         uint8_t *buffer,
                                         size_t buffer_size,
                                         size_t *serialized_size) {
    if (!transaction || !buffer || !serialized_size) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid serialize arguments");
    }

    uint8_t *data = NULL;
    size_t data_len = 0;
    neoc_error_t err = neoc_transaction_build_serialized(transaction, true, &data, &data_len);
    if (err != NEOC_SUCCESS) {
        return err;
    }

    if (data_len > buffer_size) {
        neoc_free(data);
        return neoc_error_set(NEOC_ERROR_BUFFER_TOO_SMALL, "Buffer too small for serialized transaction");
    }

    memcpy(buffer, data, data_len);
    *serialized_size = data_len;
    neoc_free(data);

    return NEOC_SUCCESS;
}

static neoc_error_t neoc_tx_read_signer(neoc_binary_reader_t *reader, neoc_signer_t **out_signer) {
    if (!reader || !out_signer) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid signer deserialize arguments");
    }

    uint8_t account_bytes[sizeof(neoc_hash160_t)];
    neoc_error_t err = neoc_binary_reader_read_bytes(reader, account_bytes, sizeof(account_bytes));
    if (err != NEOC_SUCCESS) {
        return err;
    }

    uint8_t scopes = 0;
    err = neoc_binary_reader_read_byte(reader, &scopes);
    if (err != NEOC_SUCCESS) {
        return err;
    }

    neoc_hash160_t account;
    memcpy(account.data, account_bytes, sizeof(account_bytes));

    neoc_signer_t *signer = NULL;
    err = neoc_signer_create(&account, scopes, &signer);
    if (err != NEOC_SUCCESS) {
        return err;
    }

    if (scopes & NEOC_WITNESS_SCOPE_CUSTOM_CONTRACTS) {
        uint64_t contract_count = 0;
        err = neoc_binary_reader_read_var_int_max(reader, NEOC_MAX_SIGNER_SUBITEMS, &contract_count);
        if (err != NEOC_SUCCESS) {
            neoc_signer_free(signer);
            return err;
        }

        for (uint64_t i = 0; i < contract_count; i++) {
            uint8_t contract_bytes[sizeof(neoc_hash160_t)];
            err = neoc_binary_reader_read_bytes(reader, contract_bytes, sizeof(contract_bytes));
            if (err != NEOC_SUCCESS) {
                neoc_signer_free(signer);
                return err;
            }
            neoc_hash160_t contract_hash;
            memcpy(contract_hash.data, contract_bytes, sizeof(contract_bytes));
            err = neoc_signer_add_allowed_contract(signer, &contract_hash);
            if (err != NEOC_SUCCESS) {
                neoc_signer_free(signer);
                return err;
            }
        }
    }

    if (scopes & NEOC_WITNESS_SCOPE_CUSTOM_GROUPS) {
        uint64_t group_count = 0;
        err = neoc_binary_reader_read_var_int_max(reader, NEOC_MAX_SIGNER_SUBITEMS, &group_count);
        if (err != NEOC_SUCCESS) {
            neoc_signer_free(signer);
            return err;
        }

        for (uint64_t i = 0; i < group_count; i++) {
            uint8_t *group_data = NULL;
            size_t group_len = 0;
            err = neoc_binary_reader_read_var_bytes_max(reader, NEOC_PUBLIC_KEY_SIZE_COMPRESSED, &group_data, &group_len);
            if (err != NEOC_SUCCESS) {
                neoc_signer_free(signer);
                return err;
            }
            err = neoc_signer_add_allowed_group(signer, group_data, group_len);
            neoc_free(group_data);
            if (err != NEOC_SUCCESS) {
                neoc_signer_free(signer);
                return err;
            }
        }
    }

    if (scopes & NEOC_WITNESS_SCOPE_WITNESS_RULES) {
        uint64_t rule_count = 0;
        err = neoc_binary_reader_read_var_int_max(reader, NEOC_MAX_SIGNER_SUBITEMS, &rule_count);
        if (err != NEOC_SUCCESS) {
            neoc_signer_free(signer);
            return err;
        }

        if (rule_count > 0) {
            signer->rules = neoc_calloc((size_t)rule_count, sizeof(neoc_witness_rule_t *));
            if (!signer->rules) {
                neoc_signer_free(signer);
                return neoc_error_set(NEOC_ERROR_MEMORY, "Failed to allocate witness rules");
            }
        }

        for (uint64_t i = 0; i < rule_count; i++) {
            uint8_t action_byte = 0;
            err = neoc_binary_reader_read_byte(reader, &action_byte);
            if (err != NEOC_SUCCESS) {
                neoc_signer_free(signer);
                return err;
            }

            neoc_witness_condition_t *condition = NULL;
            err = neoc_witness_condition_deserialize(reader, &condition);
            if (err != NEOC_SUCCESS) {
                neoc_signer_free(signer);
                return err;
            }

            neoc_witness_rule_t *rule = NULL;
            err = neoc_witness_rule_create((neoc_witness_action_t)action_byte, condition, &rule);
            if (err != NEOC_SUCCESS) {
                neoc_witness_condition_free(condition);
                neoc_signer_free(signer);
                return err;
            }

            signer->rules[(size_t)i] = rule;
        }
        signer->rules_count = (size_t)rule_count;
    }

    *out_signer = signer;
    return NEOC_SUCCESS;
}

static neoc_error_t neoc_tx_read_witness(neoc_binary_reader_t *reader, neoc_witness_t **out_witness) {
    if (!reader || !out_witness) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid witness deserialize arguments");
    }

    uint8_t *invocation = NULL;
    size_t invocation_len = 0;
    neoc_error_t err = neoc_binary_reader_read_var_bytes_max(reader, NEOC_MAX_SCRIPT_SIZE, &invocation, &invocation_len);
    if (err != NEOC_SUCCESS) {
        return err;
    }

    uint8_t *verification = NULL;
    size_t verification_len = 0;
    err = neoc_binary_reader_read_var_bytes_max(reader, NEOC_MAX_SCRIPT_SIZE, &verification, &verification_len);
    if (err != NEOC_SUCCESS) {
        neoc_free(invocation);
        return err;
    }

    neoc_witness_t *witness = NULL;
    err = neoc_witness_create(invocation, invocation_len, verification, verification_len, &witness);

    neoc_free(invocation);
    neoc_free(verification);

    if (err != NEOC_SUCCESS) {
        return err;
    }

    *out_witness = witness;
    return NEOC_SUCCESS;
}

static neoc_error_t neoc_tx_read_attribute(neoc_binary_reader_t *reader,
                                           neoc_tx_attribute_t **out_attribute) {
    if (!reader || !out_attribute) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid attribute deserialize arguments");
    }

    uint8_t type_byte = 0;
    neoc_error_t err = neoc_binary_reader_read_byte(reader, &type_byte);
    if (err != NEOC_SUCCESS) {
        return err;
    }

    neoc_tx_attribute_type_t type = (neoc_tx_attribute_type_t)type_byte;
    switch (type) {
        case NEOC_TX_ATTR_HIGH_PRIORITY:
            return neoc_tx_attribute_create(type, NULL, 0, out_attribute);

        case NEOC_TX_ATTR_NOT_VALID_BEFORE: {
            uint8_t payload[sizeof(uint32_t)];
            err = neoc_binary_reader_read_bytes(reader, payload, sizeof(payload));
            if (err != NEOC_SUCCESS) {
                return err;
            }
            return neoc_tx_attribute_create(type, payload, sizeof(payload), out_attribute);
        }

        case NEOC_TX_ATTR_CONFLICTS: {
            uint8_t payload[NEOC_HASH256_SIZE];
            err = neoc_binary_reader_read_bytes(reader, payload, sizeof(payload));
            if (err != NEOC_SUCCESS) {
                return err;
            }
            return neoc_tx_attribute_create(type, payload, sizeof(payload), out_attribute);
        }

        case NEOC_TX_ATTR_ORACLE_RESPONSE: {
            uint64_t request_id = 0;
            err = neoc_binary_reader_read_uint64(reader, &request_id);
            if (err != NEOC_SUCCESS) {
                return err;
            }

            uint8_t response_code = 0;
            err = neoc_binary_reader_read_byte(reader, &response_code);
            if (err != NEOC_SUCCESS) {
                return err;
            }

            uint8_t *result = NULL;
            size_t result_len = 0;
            err = neoc_binary_reader_read_var_bytes_max(reader, NEOC_MAX_ITEM_SIZE, &result, &result_len);
            if (err != NEOC_SUCCESS) {
                return err;
            }

            neoc_binary_writer_t *writer = NULL;
            err = neoc_binary_writer_create(16 + result_len, true, &writer);
            if (err != NEOC_SUCCESS) {
                neoc_free(result);
                return err;
            }

            err = neoc_binary_writer_write_uint64(writer, request_id);
            if (err == NEOC_SUCCESS) {
                err = neoc_binary_writer_write_byte(writer, response_code);
            }
            if (err == NEOC_SUCCESS) {
                err = neoc_binary_writer_write_var_bytes(writer, result, result_len);
            }

            uint8_t *payload = NULL;
            size_t payload_len = 0;
            if (err == NEOC_SUCCESS) {
                err = neoc_binary_writer_to_array(writer, &payload, &payload_len);
            }

            neoc_binary_writer_free(writer);
            neoc_free(result);

            if (err != NEOC_SUCCESS) {
                neoc_free(payload);
                return err;
            }

            err = neoc_tx_attribute_create(type, payload, payload_len, out_attribute);
            neoc_free(payload);
            return err;
        }

        default:
            return neoc_error_set(NEOC_ERROR_INVALID_DATA, "Unknown transaction attribute type");
    }
}

static neoc_error_t neoc_transaction_deserialize_reader(neoc_binary_reader_t *reader,
                                                        neoc_transaction_t **transaction) {
    if (!reader || !transaction) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid transaction deserialize arguments");
    }

    neoc_transaction_t *tx = NULL;
    neoc_error_t err = neoc_transaction_create(&tx);
    if (err != NEOC_SUCCESS) {
        return err;
    }

    err = neoc_binary_reader_read_byte(reader, &tx->version);
    if (err == NEOC_SUCCESS) {
        err = neoc_binary_reader_read_uint32(reader, &tx->nonce);
    }
    if (err == NEOC_SUCCESS) {
        int64_t sys_fee = 0;
        err = neoc_binary_reader_read_int64(reader, &sys_fee);
        if (err == NEOC_SUCCESS) {
            if (sys_fee < 0) {
                err = neoc_error_set(NEOC_ERROR_INVALID_DATA, "system_fee is negative");
            } else {
                tx->system_fee = (uint64_t)sys_fee;
            }
        }
    }
    if (err == NEOC_SUCCESS) {
        int64_t net_fee = 0;
        err = neoc_binary_reader_read_int64(reader, &net_fee);
        if (err == NEOC_SUCCESS) {
            if (net_fee < 0) {
                err = neoc_error_set(NEOC_ERROR_INVALID_DATA, "network_fee is negative");
            } else {
                tx->network_fee = (uint64_t)net_fee;
            }
        }
    }
    if (err == NEOC_SUCCESS) {
        err = neoc_binary_reader_read_uint32(reader, &tx->valid_until_block);
    }

    uint64_t signer_count = 0;
    if (err == NEOC_SUCCESS) {
        err = neoc_binary_reader_read_var_int_max(reader, NEOC_MAX_SIGNERS, &signer_count);
    }
    if (err == NEOC_SUCCESS && signer_count > 0) {
        tx->signers = neoc_calloc((size_t)signer_count, sizeof(neoc_signer_t *));
        if (!tx->signers) {
            err = neoc_error_set(NEOC_ERROR_MEMORY, "Failed to allocate signers");
        }
    }
    if (err == NEOC_SUCCESS) {
        for (uint64_t i = 0; i < signer_count; i++) {
            neoc_signer_t *signer = NULL;
            err = neoc_tx_read_signer(reader, &signer);
            if (err != NEOC_SUCCESS) {
                break;
            }
            tx->signers[i] = signer;
            tx->signer_count++;
        }
    }

    uint64_t attr_count = 0;
    if (err == NEOC_SUCCESS) {
        err = neoc_binary_reader_read_var_int_max(reader, NEOC_MAX_TRANSACTION_ATTRIBUTES, &attr_count);
    }
    if (err == NEOC_SUCCESS && attr_count > 0) {
        tx->attributes = neoc_calloc((size_t)attr_count, sizeof(neoc_tx_attribute_t *));
        if (!tx->attributes) {
            err = neoc_error_set(NEOC_ERROR_MEMORY, "Failed to allocate attributes");
        }
    }
    if (err == NEOC_SUCCESS) {
        for (uint64_t i = 0; i < attr_count; i++) {
            neoc_tx_attribute_t *attr = NULL;
            err = neoc_tx_read_attribute(reader, &attr);
            if (err != NEOC_SUCCESS) {
                break;
            }
            tx->attributes[i] = attr;
            tx->attribute_count++;
        }
    }

    if (err == NEOC_SUCCESS) {
        err = neoc_binary_reader_read_var_bytes_max(reader, NEOC_MAX_SCRIPT_SIZE, &tx->script, &tx->script_len);
    }

    uint64_t witness_count = 0;
    if (err == NEOC_SUCCESS) {
        err = neoc_binary_reader_read_var_int_max(reader, NEOC_MAX_WITNESSES, &witness_count);
    }
    if (err == NEOC_SUCCESS && witness_count > 0) {
        tx->witnesses = neoc_calloc((size_t)witness_count, sizeof(neoc_witness_t *));
        if (!tx->witnesses) {
            err = neoc_error_set(NEOC_ERROR_MEMORY, "Failed to allocate witnesses");
        }
    }
    if (err == NEOC_SUCCESS) {
        for (uint64_t i = 0; i < witness_count; i++) {
            neoc_witness_t *witness = NULL;
            err = neoc_tx_read_witness(reader, &witness);
            if (err != NEOC_SUCCESS) {
                break;
            }
            tx->witnesses[i] = witness;
            tx->witness_count++;
        }
    }

    if (err != NEOC_SUCCESS) {
        neoc_transaction_free(tx);
        return err;
    }

    *transaction = tx;
    return NEOC_SUCCESS;
}

neoc_error_t neoc_transaction_deserialize(const uint8_t *bytes,
                                           size_t bytes_len,
                                           neoc_transaction_t **transaction) {
    if (!bytes || bytes_len == 0 || !transaction) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid transaction deserialize arguments");
    }

    neoc_binary_reader_t *reader = NULL;
    neoc_error_t err = neoc_binary_reader_create(bytes, bytes_len, &reader);
    if (err != NEOC_SUCCESS) {
        return err;
    }

    neoc_transaction_t *tx = NULL;
    err = neoc_transaction_deserialize_reader(reader, &tx);
    neoc_binary_reader_free(reader);
    if (err != NEOC_SUCCESS) {
        return err;
    }

    *transaction = tx;
    return NEOC_SUCCESS;
}

neoc_transaction_t* neoc_transaction_deserialize_simple(const uint8_t *bytes,
                                                        size_t bytes_len,
                                                        size_t *consumed) {
    if (consumed) {
        *consumed = 0;
    }

    if (!bytes || bytes_len == 0) {
        return NULL;
    }

    neoc_binary_reader_t *reader = NULL;
    neoc_error_t err = neoc_binary_reader_create(bytes, bytes_len, &reader);
    if (err != NEOC_SUCCESS) {
        return NULL;
    }

    neoc_transaction_t *tx = NULL;
    err = neoc_transaction_deserialize_reader(reader, &tx);
    if (err != NEOC_SUCCESS) {
        neoc_binary_reader_free(reader);
        return NULL;
    }

    if (consumed) {
        *consumed = neoc_binary_reader_get_position(reader);
    }
    neoc_binary_reader_free(reader);
    return tx;
}

neoc_error_t neoc_transaction_sign(neoc_transaction_t *transaction,
                                    neoc_account_t *account) {
    if (!transaction || !account) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }
    
    // Calculate transaction hash if not already done
    neoc_hash256_t hash;
    neoc_error_t err = neoc_transaction_calculate_hash(transaction, &hash);
    if (err != NEOC_SUCCESS) {
        return err;
    }
    
    // Sign the hash
    uint8_t *signature = NULL;
    size_t signature_len = 0;
    err = neoc_account_sign(account, hash.data, sizeof(neoc_hash256_t),
                             &signature, &signature_len);
    if (err != NEOC_SUCCESS) {
        return err;
    }
    
    // Get account verification script and public key for witness creation
    // Create witness from account's verification script and signature
    neoc_ec_key_pair_t *key_pair = neoc_account_get_key_pair_ptr(account);
    if (!key_pair) {
        neoc_free(signature);
        return neoc_error_set(NEOC_ERROR_INVALID_STATE, "Account has no key pair");
    }

    uint8_t public_key[65];
    size_t public_key_len = sizeof(public_key);
    err = neoc_ec_key_pair_get_public_key(key_pair, public_key, &public_key_len);
    if (err != NEOC_SUCCESS) {
        neoc_free(signature);
        return err;
    }

    neoc_witness_t *witness = NULL;
    err = neoc_witness_create_from_signature(signature, signature_len,
                                             public_key, public_key_len,
                                             &witness);

    neoc_free(signature);

    if (err != NEOC_SUCCESS) {
        return err;
    }
    
    // Add witness to transaction
    err = neoc_transaction_add_witness(transaction, witness);
    if (err != NEOC_SUCCESS) {
        neoc_witness_free(witness);
        return err;
    }
    
    return NEOC_SUCCESS;
}

neoc_error_t neoc_transaction_sign_multi(neoc_transaction_t *transaction,
                                          const neoc_account_t **accounts,
                                          size_t account_count) {
    if (!transaction || !accounts || account_count == 0) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }
    
    for (size_t i = 0; i < account_count; i++) {
        neoc_error_t err = neoc_transaction_sign(transaction, (neoc_account_t *)accounts[i]);
        if (err != NEOC_SUCCESS) {
            return err;
        }
    }
    
    return NEOC_SUCCESS;
}

size_t neoc_transaction_get_size(const neoc_transaction_t *transaction) {
    if (!transaction) return 0;
    
    size_t size = 0;
    
    // Fixed fields
    size += 1;   // version
    size += 4;   // nonce
    size += 8;   // system fee
    size += 8;   // network fee
    size += 4;   // valid until block
    
    // Signers
    size += neoc_tx_var_int_size(transaction->signer_count);
    for (size_t i = 0; i < transaction->signer_count; i++) {
        size += neoc_signer_get_size(transaction->signers[i]);
    }
    
    // Attributes
    size += neoc_tx_var_int_size(transaction->attribute_count);
    for (size_t i = 0; i < transaction->attribute_count; i++) {
        size += 1; // attribute type
        if (transaction->attributes[i] && transaction->attributes[i]->data_len > 0) {
            size += transaction->attributes[i]->data_len;
        }
    }
    
    // Script
    size += neoc_tx_var_int_size(transaction->script_len);
    size += transaction->script_len;
    
    // Witnesses
    size += neoc_tx_var_int_size(transaction->witness_count);
    for (size_t i = 0; i < transaction->witness_count; i++) {
        size += neoc_witness_get_size(transaction->witnesses[i]);
    }
    
    return size;
}

bool neoc_transaction_verify(const neoc_transaction_t *transaction) {
    (void)transaction;
    // Note: Implement signature verification
    return false;
}

void neoc_transaction_free(neoc_transaction_t *transaction) {
    if (!transaction) return;
    
    // Free signers
    if (transaction->signers) {
        for (size_t i = 0; i < transaction->signer_count; i++) {
            neoc_signer_free(transaction->signers[i]);
        }
        neoc_free(transaction->signers);
        transaction->signers = NULL;
        transaction->signer_count = 0;
    }
    
    // Free attributes
    if (transaction->attributes) {
        for (size_t i = 0; i < transaction->attribute_count; i++) {
            neoc_tx_attribute_free(transaction->attributes[i]);
        }
        neoc_free(transaction->attributes);
    }
    
    // Free script
    if (transaction->script) {
        neoc_free(transaction->script);
    }
    
    // Free witnesses
    if (transaction->witnesses) {
        for (size_t i = 0; i < transaction->witness_count; i++) {
            neoc_witness_free(transaction->witnesses[i]);
        }
        neoc_free(transaction->witnesses);
    }
    
    neoc_free(transaction);
}

neoc_error_t neoc_transaction_clone(const neoc_transaction_t *source,
                                     neoc_transaction_t **clone) {
    if (!source || !clone) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid transaction clone arguments");
    }

    neoc_transaction_t *copy = NULL;
    neoc_error_t err = neoc_transaction_create(&copy);
    if (err != NEOC_SUCCESS || !copy) {
        return err != NEOC_SUCCESS ? err : neoc_error_set(NEOC_ERROR_MEMORY, "Failed to allocate transaction clone");
    }

    copy->version = source->version;
    copy->nonce = source->nonce;
    copy->system_fee = source->system_fee;
    copy->network_fee = source->network_fee;
    copy->valid_until_block = source->valid_until_block;
    copy->hash = source->hash;

    if (source->script && source->script_len > 0) {
        copy->script = neoc_malloc(source->script_len);
        if (!copy->script) {
            neoc_transaction_free(copy);
            return neoc_error_set(NEOC_ERROR_MEMORY, "Failed to clone transaction script");
        }
        memcpy(copy->script, source->script, source->script_len);
        copy->script_len = source->script_len;
    }

    if (source->signer_count > 0 && source->signers) {
        copy->signers = neoc_calloc(source->signer_count, sizeof(neoc_signer_t *));
        if (!copy->signers) {
            neoc_transaction_free(copy);
            return neoc_error_set(NEOC_ERROR_MEMORY, "Failed to allocate signer clones");
        }
        for (size_t i = 0; i < source->signer_count; i++) {
            neoc_error_t clone_err = neoc_signer_copy(source->signers[i], &copy->signers[i]);
            if (clone_err != NEOC_SUCCESS) {
                neoc_transaction_free(copy);
                return clone_err;
            }
        }
        copy->signer_count = source->signer_count;
    }

    if (source->attribute_count > 0 && source->attributes) {
        copy->attributes = neoc_calloc(source->attribute_count, sizeof(neoc_tx_attribute_t *));
        if (!copy->attributes) {
            neoc_transaction_free(copy);
            return neoc_error_set(NEOC_ERROR_MEMORY, "Failed to allocate attribute clones");
        }
        for (size_t i = 0; i < source->attribute_count; i++) {
            neoc_tx_attribute_t *attr_clone = NULL;
            neoc_error_t clone_err = neoc_tx_attribute_clone_internal(source->attributes[i], &attr_clone);
            if (clone_err != NEOC_SUCCESS) {
                neoc_transaction_free(copy);
                return clone_err;
            }
            copy->attributes[i] = attr_clone;
        }
        copy->attribute_count = source->attribute_count;
    }

    if (source->witness_count > 0 && source->witnesses) {
        copy->witnesses = neoc_calloc(source->witness_count, sizeof(neoc_witness_t *));
        if (!copy->witnesses) {
            neoc_transaction_free(copy);
            return neoc_error_set(NEOC_ERROR_MEMORY, "Failed to allocate witness clones");
        }
        for (size_t i = 0; i < source->witness_count; i++) {
            neoc_witness_t *witness_clone = NULL;
            neoc_error_t clone_err = neoc_witness_clone(source->witnesses[i], &witness_clone);
            if (clone_err != NEOC_SUCCESS) {
                neoc_transaction_free(copy);
                return clone_err;
            }
            copy->witnesses[i] = witness_clone;
        }
        copy->witness_count = source->witness_count;
    }

    *clone = copy;
    return NEOC_SUCCESS;
}

static neoc_error_t neoc_tx_attribute_clone_internal(const neoc_tx_attribute_t *source,
                                                     neoc_tx_attribute_t **dest);

neoc_error_t neoc_tx_attribute_create(neoc_tx_attribute_type_t type,
                                       const uint8_t *data,
                                       size_t data_len,
                                       neoc_tx_attribute_t **attribute) {
    if (!attribute) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid attribute pointer");
    }
    
    *attribute = neoc_calloc(1, sizeof(neoc_tx_attribute_t));
    if (!*attribute) {
        return neoc_error_set(NEOC_ERROR_MEMORY, "Failed to allocate attribute");
    }
    
    (*attribute)->type = type;
    
    if (data && data_len > 0) {
        (*attribute)->data = neoc_malloc(data_len);
        if (!(*attribute)->data) {
            neoc_free(*attribute);
            *attribute = NULL;
            return neoc_error_set(NEOC_ERROR_MEMORY, "Failed to allocate attribute data");
        }
        memcpy((*attribute)->data, data, data_len);
        (*attribute)->data_len = data_len;
    }
    
    return NEOC_SUCCESS;
}

void neoc_tx_attribute_free(neoc_tx_attribute_t *attribute) {
    if (!attribute) return;
    
    if (attribute->data) {
        neoc_free(attribute->data);
    }
    
    neoc_free(attribute);
}

static neoc_error_t neoc_tx_attribute_clone_internal(const neoc_tx_attribute_t *source,
                                                     neoc_tx_attribute_t **dest) {
    if (!source || !dest) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid attribute clone arguments");
    }

    return neoc_tx_attribute_create(source->type,
                                    source->data,
                                    source->data_len,
                                    dest);
}

neoc_transaction_t* neoc_transaction_from_json(const char* json_str) {
    if (!json_str) {
        return NULL;
    }
    
    neoc_json_t* json = neoc_json_parse(json_str);
    if (!json) {
        return NULL;
    }
    
    neoc_transaction_t* tx = NULL;
    neoc_error_t err = neoc_transaction_create(&tx);
    if (err != NEOC_SUCCESS || !tx) {
        neoc_json_free(json);
        return NULL;
    }
    
    // Parse basic fields
    double number_value = 0.0;
    if (neoc_json_get_number(json, "version", &number_value) == NEOC_SUCCESS) {
        tx->version = (uint8_t)number_value;
    }
    if (neoc_json_get_number(json, "nonce", &number_value) == NEOC_SUCCESS) {
        tx->nonce = (uint32_t)number_value;
    }
    if (neoc_json_get_number(json, "validuntilblock", &number_value) == NEOC_SUCCESS) {
        tx->valid_until_block = (uint32_t)number_value;
    }
    
    // Parse fees
    const char* sys_fee_str = neoc_json_get_string(json, "sysfee");
    if (sys_fee_str) {
        tx->system_fee = strtoull(sys_fee_str, NULL, 10);
    }
    
    const char* net_fee_str = neoc_json_get_string(json, "netfee");
    if (net_fee_str) {
        tx->network_fee = strtoull(net_fee_str, NULL, 10);
    }
    
    // Parse script
    const char* script_hex = neoc_json_get_string(json, "script");
    if (script_hex) {
        size_t hex_len = strlen(script_hex);
        tx->script_len = hex_len / 2;
        tx->script = neoc_malloc(tx->script_len);
        if (tx->script) {
            neoc_hex_decode(script_hex, tx->script, tx->script_len, &tx->script_len);
        }
    }
    
    // Parse hash if present
    const char* hash_str = neoc_json_get_string(json, "hash");
    if (hash_str) {
        neoc_hash256_from_string(hash_str, &tx->hash);
    }
    
    neoc_json_free(json);
    return tx;
}

char* neoc_transaction_to_json(const neoc_transaction_t* tx) {
    if (!tx) {
        return NULL;
    }
    
    size_t json_size = 4096;
    char* json = neoc_malloc(json_size);
    if (!json) {
        return NULL;
    }
    
    // Convert script to hex
    char* script_hex = NULL;
    if (tx->script && tx->script_len > 0) {
        script_hex = neoc_malloc(tx->script_len * 2 + 1);
        if (script_hex) {
            size_t hex_len = tx->script_len * 2 + 1;
            neoc_hex_encode(tx->script, tx->script_len, script_hex, hex_len, false, false);
        }
    }
    
    // Convert hash to hex
    char hash_str[65];
    neoc_hash256_to_string(&tx->hash, hash_str, sizeof(hash_str));
    
    // Build JSON
    snprintf(json, json_size,
             "{\"hash\":\"%s\",\"version\":%u,\"nonce\":%u,"
             "\"sysfee\":\"%llu\",\"netfee\":\"%llu\","
             "\"validuntilblock\":%u,\"script\":\"%s\","
             "\"signers\":[],\"attributes\":[],\"witnesses\":[]}",
             hash_str,
             tx->version,
             tx->nonce,
             (unsigned long long)tx->system_fee,
             (unsigned long long)tx->network_fee,
             tx->valid_until_block,
             script_hex ? script_hex : "");
    
    if (script_hex) {
        neoc_free(script_hex);
    }
    
    return json;
}
