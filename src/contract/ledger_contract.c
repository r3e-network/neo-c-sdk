/**
 * @file ledger_contract.c
 * @brief NEO Ledger native contract implementation
 */

#include "neoc/contract/ledger_contract.h"
#include "neoc/contract/smart_contract.h"
#include "neoc/script/script_builder.h"
#include "neoc/script/script_builder_full.h"
#include "neoc/neoc_memory.h"
#include "neoc/neoc_error.h"
#include <string.h>

/* Ledger contract hash (little-endian) */
static const uint8_t LEDGER_CONTRACT_HASH[20] = {
    0xda, 0x65, 0xb6, 0x00, 0xf7, 0x12, 0x4c, 0xe6,
    0xc7, 0x99, 0x50, 0xc1, 0x77, 0x2a, 0x36, 0x40,
    0x31, 0x04, 0xf2, 0xbe
};

struct neoc_ledger_contract {
    neoc_smart_contract_t *contract;
};

neoc_error_t neoc_ledger_contract_create(neoc_ledger_contract_t **ledger) {
    if (!ledger) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid ledger pointer");
    }

    *ledger = neoc_calloc(1, sizeof(neoc_ledger_contract_t));
    if (!*ledger) {
        return neoc_error_set(NEOC_ERROR_MEMORY, "Failed to allocate ledger contract");
    }

    neoc_hash160_t script_hash;
    memcpy(script_hash.data, LEDGER_CONTRACT_HASH, 20);

    neoc_error_t err = neoc_smart_contract_create(&script_hash, "Ledger", &(*ledger)->contract);
    if (err != NEOC_SUCCESS) {
        neoc_free(*ledger);
        *ledger = NULL;
        return err;
    }

    return NEOC_SUCCESS;
}

neoc_error_t neoc_ledger_current_hash(neoc_ledger_contract_t *ledger,
                                       uint8_t **script,
                                       size_t *script_len) {
    if (!ledger || !script || !script_len) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }

    neoc_script_builder_t *builder;
    neoc_error_t err = neoc_script_builder_create(&builder);
    if (err != NEOC_SUCCESS) {
        return err;
    }

    neoc_hash160_t script_hash;
    memcpy(script_hash.data, LEDGER_CONTRACT_HASH, 20);

    err = neoc_script_builder_emit_app_call(builder, &script_hash, "currentHash", 0);
    if (err != NEOC_SUCCESS) {
        neoc_script_builder_free(builder);
        return err;
    }

    err = neoc_script_builder_to_array(builder, script, script_len);
    neoc_script_builder_free(builder);
    return err;
}

neoc_error_t neoc_ledger_current_index(neoc_ledger_contract_t *ledger,
                                        uint8_t **script,
                                        size_t *script_len) {
    if (!ledger || !script || !script_len) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }

    neoc_script_builder_t *builder;
    neoc_error_t err = neoc_script_builder_create(&builder);
    if (err != NEOC_SUCCESS) {
        return err;
    }

    neoc_hash160_t script_hash;
    memcpy(script_hash.data, LEDGER_CONTRACT_HASH, 20);

    err = neoc_script_builder_emit_app_call(builder, &script_hash, "currentIndex", 0);
    if (err != NEOC_SUCCESS) {
        neoc_script_builder_free(builder);
        return err;
    }

    err = neoc_script_builder_to_array(builder, script, script_len);
    neoc_script_builder_free(builder);
    return err;
}

neoc_error_t neoc_ledger_get_block(neoc_ledger_contract_t *ledger,
                                    uint32_t index,
                                    uint8_t **script,
                                    size_t *script_len) {
    if (!ledger || !script || !script_len) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }

    neoc_script_builder_t *builder;
    neoc_error_t err = neoc_script_builder_create(&builder);
    if (err != NEOC_SUCCESS) {
        return err;
    }

    err = neoc_script_builder_emit_push_int(builder, (int64_t)index);
    if (err != NEOC_SUCCESS) {
        neoc_script_builder_free(builder);
        return err;
    }

    neoc_hash160_t script_hash;
    memcpy(script_hash.data, LEDGER_CONTRACT_HASH, 20);

    err = neoc_script_builder_emit_app_call(builder, &script_hash, "getBlock", 1);
    if (err != NEOC_SUCCESS) {
        neoc_script_builder_free(builder);
        return err;
    }

    err = neoc_script_builder_to_array(builder, script, script_len);
    neoc_script_builder_free(builder);
    return err;
}

neoc_error_t neoc_ledger_get_transaction(neoc_ledger_contract_t *ledger,
                                          const neoc_hash256_t *hash,
                                          uint8_t **script,
                                          size_t *script_len) {
    if (!ledger || !hash || !script || !script_len) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }

    neoc_script_builder_t *builder;
    neoc_error_t err = neoc_script_builder_create(&builder);
    if (err != NEOC_SUCCESS) {
        return err;
    }

    err = neoc_script_builder_push_data(builder, hash->data, sizeof(hash->data));
    if (err != NEOC_SUCCESS) {
        neoc_script_builder_free(builder);
        return err;
    }

    neoc_hash160_t script_hash;
    memcpy(script_hash.data, LEDGER_CONTRACT_HASH, 20);

    err = neoc_script_builder_emit_app_call(builder, &script_hash, "getTransaction", 1);
    if (err != NEOC_SUCCESS) {
        neoc_script_builder_free(builder);
        return err;
    }

    err = neoc_script_builder_to_array(builder, script, script_len);
    neoc_script_builder_free(builder);
    return err;
}

neoc_error_t neoc_ledger_get_transaction_height(neoc_ledger_contract_t *ledger,
                                                 const neoc_hash256_t *hash,
                                                 uint8_t **script,
                                                 size_t *script_len) {
    if (!ledger || !hash || !script || !script_len) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }

    neoc_script_builder_t *builder;
    neoc_error_t err = neoc_script_builder_create(&builder);
    if (err != NEOC_SUCCESS) {
        return err;
    }

    err = neoc_script_builder_push_data(builder, hash->data, sizeof(hash->data));
    if (err != NEOC_SUCCESS) {
        neoc_script_builder_free(builder);
        return err;
    }

    neoc_hash160_t script_hash;
    memcpy(script_hash.data, LEDGER_CONTRACT_HASH, 20);

    err = neoc_script_builder_emit_app_call(builder, &script_hash, "getTransactionHeight", 1);
    if (err != NEOC_SUCCESS) {
        neoc_script_builder_free(builder);
        return err;
    }

    err = neoc_script_builder_to_array(builder, script, script_len);
    neoc_script_builder_free(builder);
    return err;
}

void neoc_ledger_contract_free(neoc_ledger_contract_t *ledger) {
    if (!ledger) return;

    if (ledger->contract) {
        neoc_smart_contract_free(ledger->contract);
    }

    neoc_free(ledger);
}
