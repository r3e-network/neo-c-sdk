/**
 * @file oracle_contract.c
 * @brief NEO Oracle native contract implementation
 */

#include "neoc/contract/oracle_contract.h"
#include "neoc/contract/smart_contract.h"
#include "neoc/script/script_builder.h"
#include "neoc/script/script_builder_full.h"
#include "neoc/neoc_memory.h"
#include "neoc/neoc_error.h"
#include <string.h>

/* Oracle contract hash (little-endian) */
static const uint8_t ORACLE_CONTRACT_HASH[20] = {
    0xfe, 0x92, 0x4b, 0x7c, 0xfe, 0x89, 0xdd, 0xd2,
    0x71, 0xab, 0xaf, 0x72, 0x10, 0xa8, 0x0a, 0x7e,
    0x11, 0x17, 0x87, 0x58
};

struct neoc_oracle_contract {
    neoc_smart_contract_t *contract;
    uint64_t price;
};

neoc_error_t neoc_oracle_contract_create(neoc_oracle_contract_t **oracle) {
    if (!oracle) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid oracle pointer");
    }

    *oracle = neoc_calloc(1, sizeof(neoc_oracle_contract_t));
    if (!*oracle) {
        return neoc_error_set(NEOC_ERROR_MEMORY, "Failed to allocate oracle contract");
    }

    neoc_hash160_t script_hash;
    memcpy(script_hash.data, ORACLE_CONTRACT_HASH, 20);

    neoc_error_t err = neoc_smart_contract_create(&script_hash, "Oracle", &(*oracle)->contract);
    if (err != NEOC_SUCCESS) {
        neoc_free(*oracle);
        *oracle = NULL;
        return err;
    }

    /* Default mainnet value: 0.5 GAS */
    (*oracle)->price = 50000000;

    return NEOC_SUCCESS;
}

neoc_error_t neoc_oracle_get_price(neoc_oracle_contract_t *oracle,
                                    uint64_t *price) {
    if (!oracle || !price) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }

    /* Build script to call getPrice */
    neoc_script_builder_t *builder;
    neoc_error_t err = neoc_script_builder_create(&builder);
    if (err != NEOC_SUCCESS) {
        return err;
    }

    neoc_hash160_t script_hash;
    memcpy(script_hash.data, ORACLE_CONTRACT_HASH, 20);

    err = neoc_script_builder_emit_app_call(builder, &script_hash, "getPrice", 0);
    if (err != NEOC_SUCCESS) {
        neoc_script_builder_free(builder);
        return err;
    }

    /* Return cached value (would normally execute script via RPC) */
    *price = oracle->price;

    neoc_script_builder_free(builder);
    return NEOC_SUCCESS;
}

neoc_error_t neoc_oracle_set_price(neoc_oracle_contract_t *oracle,
                                    uint64_t price) {
    if (!oracle) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid oracle");
    }

    /* Build script to call setPrice (requires committee signature) */
    neoc_script_builder_t *builder;
    neoc_error_t err = neoc_script_builder_create(&builder);
    if (err != NEOC_SUCCESS) {
        return err;
    }

    err = neoc_script_builder_emit_push_int(builder, price);
    if (err != NEOC_SUCCESS) {
        neoc_script_builder_free(builder);
        return err;
    }

    neoc_hash160_t script_hash;
    memcpy(script_hash.data, ORACLE_CONTRACT_HASH, 20);

    err = neoc_script_builder_emit_app_call(builder, &script_hash, "setPrice", 1);
    if (err != NEOC_SUCCESS) {
        neoc_script_builder_free(builder);
        return err;
    }

    /* Update cached value */
    oracle->price = price;

    neoc_script_builder_free(builder);
    return NEOC_SUCCESS;
}

void neoc_oracle_contract_free(neoc_oracle_contract_t *oracle) {
    if (!oracle) return;

    if (oracle->contract) {
        neoc_smart_contract_free(oracle->contract);
    }

    neoc_free(oracle);
}
