/**
 * @file contract_management.c
 * @brief NEO ContractManagement native contract implementation
 */

#include "neoc/contract/contract_management.h"
#include "neoc/contract/smart_contract.h"
#include "neoc/script/script_builder.h"
#include "neoc/script/script_builder_full.h"
#include "neoc/neoc_memory.h"
#include "neoc/neoc_error.h"
#include <string.h>

// ContractManagement native contract hash (little-endian)
static const uint8_t CONTRACT_MANAGEMENT_HASH[20] = {
    0xff, 0xfd, 0xc9, 0x37, 0x64, 0xdb, 0xad, 0xdd,
    0x97, 0xc4, 0x8f, 0x25, 0x2a, 0x53, 0xea, 0x46,
    0x43, 0xfa, 0xa3, 0xfd
};

struct neoc_contract_management {
    neoc_smart_contract_t *contract;
    uint64_t min_deployment_fee;
};

neoc_error_t neoc_contract_management_create(neoc_contract_management_t **mgmt) {
    if (!mgmt) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid mgmt pointer");
    }

    *mgmt = neoc_calloc(1, sizeof(neoc_contract_management_t));
    if (!*mgmt) {
        return neoc_error_set(NEOC_ERROR_MEMORY, "Failed to allocate contract management");
    }

    neoc_hash160_t script_hash;
    memcpy(script_hash.data, CONTRACT_MANAGEMENT_HASH, 20);

    neoc_error_t err = neoc_smart_contract_create(&script_hash, "ContractManagement",
                                                   &(*mgmt)->contract);
    if (err != NEOC_SUCCESS) {
        neoc_free(*mgmt);
        *mgmt = NULL;
        return err;
    }

    // Default: 10 GAS (1_000_000_000 GAS fractions)
    (*mgmt)->min_deployment_fee = 1000000000;

    return NEOC_SUCCESS;
}

neoc_error_t neoc_contract_management_get_minimum_deployment_fee(
    neoc_contract_management_t *mgmt, uint64_t *fee) {
    if (!mgmt || !fee) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }

    // Build script to call getMinimumDeploymentFee
    neoc_script_builder_t *builder;
    neoc_error_t err = neoc_script_builder_create(&builder);
    if (err != NEOC_SUCCESS) {
        return err;
    }

    neoc_hash160_t script_hash;
    memcpy(script_hash.data, CONTRACT_MANAGEMENT_HASH, 20);

    err = neoc_script_builder_emit_app_call(builder, &script_hash,
                                             "getMinimumDeploymentFee", 0);
    if (err != NEOC_SUCCESS) {
        neoc_script_builder_free(builder);
        return err;
    }

    // Return cached value
    *fee = mgmt->min_deployment_fee;

    neoc_script_builder_free(builder);
    return NEOC_SUCCESS;
}

neoc_error_t neoc_contract_management_has_method(
    neoc_contract_management_t *mgmt, const neoc_hash160_t *hash,
    const char *method, uint32_t param_count,
    uint8_t **script, size_t *script_len) {
    if (!mgmt || !hash || !method || !script || !script_len) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }

    neoc_script_builder_t *builder;
    neoc_error_t err = neoc_script_builder_create(&builder);
    if (err != NEOC_SUCCESS) {
        return err;
    }

    // Push parameters in reverse order: param_count, method, hash
    err = neoc_script_builder_emit_push_int(builder, param_count);
    if (err != NEOC_SUCCESS) {
        neoc_script_builder_free(builder);
        return err;
    }

    err = neoc_script_builder_push_data(builder, (const uint8_t *)method,
                                         strlen(method));
    if (err != NEOC_SUCCESS) {
        neoc_script_builder_free(builder);
        return err;
    }

    err = neoc_script_builder_push_data(builder, hash->data, sizeof(hash->data));
    if (err != NEOC_SUCCESS) {
        neoc_script_builder_free(builder);
        return err;
    }

    neoc_hash160_t script_hash;
    memcpy(script_hash.data, CONTRACT_MANAGEMENT_HASH, 20);

    err = neoc_script_builder_emit_app_call(builder, &script_hash, "hasMethod", 3);
    if (err != NEOC_SUCCESS) {
        neoc_script_builder_free(builder);
        return err;
    }

    err = neoc_script_builder_to_array(builder, script, script_len);
    neoc_script_builder_free(builder);
    return err;
}

neoc_error_t neoc_contract_management_get_contract(
    neoc_contract_management_t *mgmt, const neoc_hash160_t *hash,
    uint8_t **script, size_t *script_len) {
    if (!mgmt || !hash || !script || !script_len) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }

    neoc_script_builder_t *builder;
    neoc_error_t err = neoc_script_builder_create(&builder);
    if (err != NEOC_SUCCESS) {
        return err;
    }

    // Push contract hash parameter
    err = neoc_script_builder_push_data(builder, hash->data, sizeof(hash->data));
    if (err != NEOC_SUCCESS) {
        neoc_script_builder_free(builder);
        return err;
    }

    neoc_hash160_t script_hash;
    memcpy(script_hash.data, CONTRACT_MANAGEMENT_HASH, 20);

    err = neoc_script_builder_emit_app_call(builder, &script_hash, "getContract", 1);
    if (err != NEOC_SUCCESS) {
        neoc_script_builder_free(builder);
        return err;
    }

    err = neoc_script_builder_to_array(builder, script, script_len);
    neoc_script_builder_free(builder);
    return err;
}

void neoc_contract_management_free(neoc_contract_management_t *mgmt) {
    if (!mgmt) return;

    if (mgmt->contract) {
        neoc_smart_contract_free(mgmt->contract);
    }

    neoc_free(mgmt);
}
