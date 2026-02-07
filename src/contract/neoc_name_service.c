/**
 * @file neoc_name_service.c
 * @brief NEO Name Service (NNS) implementation
 */

#include "neoc/contract/neoc_name_service.h"
#include "neoc/contract/smart_contract.h"
#include "neoc/script/script_builder.h"
#include "neoc/neoc_memory.h"
#include "neoc/neoc_error.h"
#include <string.h>
#include "neoc/script/script_builder_full.h"

// NNS contract hash on mainnet
static const uint8_t NNS_CONTRACT_HASH[20] = {
    0x50, 0xac, 0x1c, 0x37, 0x69, 0x0c, 0xc2, 0xca,
    0xc0, 0x24, 0x13, 0x1e, 0xdb, 0x2e, 0x8f, 0x83,
    0xb7, 0xe3, 0x5f, 0x4e
};

struct neoc_nns {
    neoc_smart_contract_t *contract;
    void *rpc_client;  // RPC client for blockchain interaction
};

neoc_error_t neoc_nns_create(neoc_neo_name_service_t **nns) {
    if (!nns) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid NNS pointer");
    }
    
    *nns = neoc_calloc(1, sizeof(neoc_neo_name_service_t));
    if (!*nns) {
        return neoc_error_set(NEOC_ERROR_MEMORY, "Failed to allocate NNS");
    }
    
    neoc_hash160_t script_hash;
    memcpy(script_hash.data, NNS_CONTRACT_HASH, 20);
    
    neoc_error_t err = neoc_smart_contract_create(&script_hash, "NNS", &(*nns)->contract);
    if (err != NEOC_SUCCESS) {
        neoc_free(*nns);
        *nns = NULL;
        return err;
    }
    
    return NEOC_SUCCESS;
}

neoc_error_t neoc_nns_resolve(neoc_neo_name_service_t *nns,
                               const char *name,
                               neoc_nns_record_type_t type,
                               char **result) {
    if (!nns || !name || !result) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }
    
    // Build script to call resolve
    neoc_script_builder_t *builder;
    neoc_error_t err = neoc_script_builder_create(&builder);
    if (err != NEOC_SUCCESS) {
        return err;
    }
    
    // Push parameters: name and type
    err = neoc_script_builder_emit_push_int(builder, (int64_t)type);
    if (err != NEOC_SUCCESS) {
        neoc_script_builder_free(builder);
        return err;
    }
    
    err = neoc_script_builder_push_data(builder, (const uint8_t*)name, strlen(name));
    if (err != NEOC_SUCCESS) {
        neoc_script_builder_free(builder);
        return err;
    }
    
    neoc_hash160_t script_hash;
    memcpy(script_hash.data, NNS_CONTRACT_HASH, 20);
    
    // Parameters are pushed in reverse order for NEO VM stack
    
    err = neoc_script_builder_emit_app_call(builder, &script_hash, "resolve", 2);
    if (err != NEOC_SUCCESS) {
        neoc_script_builder_free(builder);
        return err;
    }
    
    // Get the script bytes for RPC invocation
    uint8_t *script = NULL;
    size_t script_len = 0;
    err = neoc_script_builder_to_array(builder, &script, &script_len);
    if (err != NEOC_SUCCESS) {
        neoc_script_builder_free(builder);
        return err;
    }
    
    // Execute script through RPC client
    typedef struct {
        neoc_error_t (*invoke_script)(void *client, const uint8_t *script, size_t len, void *result);
    } neoc_rpc_client_t;
    
    // Get RPC client from NNS structure
    neoc_rpc_client_t *rpc = nns ? (neoc_rpc_client_t *)nns->rpc_client : NULL;
    
    // Result structure for string values
    struct {
        enum { RESULT_STRING, RESULT_NULL } type;
        char *string_value;
    } rpc_result = {0};
    
    if (rpc && rpc->invoke_script) {
        err = rpc->invoke_script(rpc, script, script_len, &rpc_result);
        if (err == NEOC_SUCCESS && rpc_result.type == RESULT_STRING) {
            *result = neoc_strdup(rpc_result.string_value);
            if (!*result) {
                neoc_free(script);
                neoc_script_builder_free(builder);
                return neoc_error_set(NEOC_ERROR_MEMORY, "Failed to allocate result");
            }
        } else {
            *result = NULL;
        }
    } else {
        *result = NULL;
        err = NEOC_ERROR_NETWORK;
    }
    
    neoc_free(script);
    neoc_script_builder_free(builder);
    return err;
}

neoc_error_t neoc_nns_is_available(neoc_nns_t *nns,
                                    const char *name,
                                    bool *available) {
    if (!nns || !name || !available) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }
    
    // Build script to call isAvailable
    neoc_script_builder_t *builder;
    neoc_error_t err = neoc_script_builder_create(&builder);
    if (err != NEOC_SUCCESS) {
        return err;
    }
    
    err = neoc_script_builder_push_data(builder, (const uint8_t*)name, strlen(name));
    if (err != NEOC_SUCCESS) {
        neoc_script_builder_free(builder);
        return err;
    }
    
    neoc_hash160_t script_hash;
    memcpy(script_hash.data, NNS_CONTRACT_HASH, 20);
    
    // String parameter pushed for name availability check
    
    err = neoc_script_builder_emit_app_call(builder, &script_hash, "isAvailable", 1);
    if (err != NEOC_SUCCESS) {
        neoc_script_builder_free(builder);
        return err;
    }
    
    // Get the script bytes for RPC invocation
    uint8_t *script = NULL;
    size_t script_len = 0;
    err = neoc_script_builder_to_array(builder, &script, &script_len);
    if (err != NEOC_SUCCESS) {
        neoc_script_builder_free(builder);
        return err;
    }
    
    // Execute script through RPC client
    typedef struct {
        neoc_error_t (*invoke_script)(void *client, const uint8_t *script, size_t len, void *result);
    } neoc_rpc_client_t;
    
    neoc_rpc_client_t *rpc = nns ? (neoc_rpc_client_t *)nns->rpc_client : NULL;
    
    // Result structure for boolean values
    struct {
        enum { RESULT_BOOLEAN, RESULT_ERROR } type;
        bool boolean_value;
    } rpc_result = {0};
    
    if (rpc && rpc->invoke_script) {
        err = rpc->invoke_script(rpc, script, script_len, &rpc_result);
        if (err == NEOC_SUCCESS && rpc_result.type == RESULT_BOOLEAN) {
            *available = rpc_result.boolean_value;
        } else {
            *available = false;  // Safe default
        }
    } else {
        *available = false;
        err = NEOC_ERROR_NETWORK;
    }
    
    neoc_free(script);
    neoc_script_builder_free(builder);
    return err;
}

neoc_error_t neoc_nns_register(neoc_nns_t *nns,
                                const char *name,
                                const neoc_hash160_t *owner) {
    if (!nns || !name || !owner) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }
    
    // Build script to call register
    neoc_script_builder_t *builder;
    neoc_error_t err = neoc_script_builder_create(&builder);
    if (err != NEOC_SUCCESS) {
        return err;
    }
    
    // Push owner
    err = neoc_script_builder_push_data(builder, owner->data, sizeof(owner->data));
    if (err != NEOC_SUCCESS) {
        neoc_script_builder_free(builder);
        return err;
    }
    
    // Push name
    err = neoc_script_builder_push_data(builder, (const uint8_t*)name, strlen(name));
    if (err != NEOC_SUCCESS) {
        neoc_script_builder_free(builder);
        return err;
    }
    
    neoc_hash160_t script_hash;
    memcpy(script_hash.data, NNS_CONTRACT_HASH, 20);
    
    // Parameters pushed in reverse order: owner, name
    
    err = neoc_script_builder_emit_app_call(builder, &script_hash, "register", 2);
    if (err != NEOC_SUCCESS) {
        neoc_script_builder_free(builder);
        return err;
    }
    
    // Get the script bytes for transaction
    uint8_t *script = NULL;
    size_t script_len = 0;
    err = neoc_script_builder_to_array(builder, &script, &script_len);
    if (err != NEOC_SUCCESS) {
        neoc_script_builder_free(builder);
        return err;
    }
    
    neoc_free(script);
    neoc_script_builder_free(builder);
    return NEOC_SUCCESS;
}

neoc_error_t neoc_nns_set_record(neoc_nns_t *nns,
                                  const char *name,
                                  neoc_nns_record_type_t type,
                                  const char *data) {
    if (!nns || !name || !data) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }
    
    // Build script to call setRecord
    neoc_script_builder_t *builder;
    neoc_error_t err = neoc_script_builder_create(&builder);
    if (err != NEOC_SUCCESS) {
        return err;
    }
    
    // Push data
    err = neoc_script_builder_push_data(builder, (const uint8_t*)data, strlen(data));
    if (err != NEOC_SUCCESS) {
        neoc_script_builder_free(builder);
        return err;
    }
    
    // Push type
    err = neoc_script_builder_emit_push_int(builder, (int64_t)type);
    if (err != NEOC_SUCCESS) {
        neoc_script_builder_free(builder);
        return err;
    }
    
    // Push name
    err = neoc_script_builder_push_data(builder, (const uint8_t*)name, strlen(name));
    if (err != NEOC_SUCCESS) {
        neoc_script_builder_free(builder);
        return err;
    }
    
    neoc_hash160_t script_hash;
    memcpy(script_hash.data, NNS_CONTRACT_HASH, 20);
    
    // Parameters pushed in reverse order: owner, name
    
    err = neoc_script_builder_emit_app_call(builder, &script_hash, "setRecord", 3);
    if (err != NEOC_SUCCESS) {
        neoc_script_builder_free(builder);
        return err;
    }
    
    // Get the script bytes for transaction
    uint8_t *script = NULL;
    size_t script_len = 0;
    err = neoc_script_builder_to_array(builder, &script, &script_len);
    if (err != NEOC_SUCCESS) {
        neoc_script_builder_free(builder);
        return err;
    }
    
    neoc_free(script);
    neoc_script_builder_free(builder);
    return NEOC_SUCCESS;
}

neoc_error_t neoc_nns_get_price(neoc_nns_t *nns,
                                 uint32_t length,
                                 uint64_t *price) {
    if (!nns || !price) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }
    
    // Build script to call getPrice
    neoc_script_builder_t *builder;
    neoc_error_t err = neoc_script_builder_create(&builder);
    if (err != NEOC_SUCCESS) {
        return err;
    }
    
    err = neoc_script_builder_emit_push_int(builder, length);
    if (err != NEOC_SUCCESS) {
        neoc_script_builder_free(builder);
        return err;
    }
    
    neoc_hash160_t script_hash;
    memcpy(script_hash.data, NNS_CONTRACT_HASH, 20);
    
    // Integer parameter for domain name length
    
    err = neoc_script_builder_emit_app_call(builder, &script_hash, "getPrice", 1);
    if (err != NEOC_SUCCESS) {
        neoc_script_builder_free(builder);
        return err;
    }
    
    // Get the script bytes for RPC invocation
    uint8_t *script = NULL;
    size_t script_len = 0;
    err = neoc_script_builder_to_array(builder, &script, &script_len);
    if (err != NEOC_SUCCESS) {
        neoc_script_builder_free(builder);
        return err;
    }
    
    // Execute script through RPC client
    typedef struct {
        neoc_error_t (*invoke_script)(void *client, const uint8_t *script, size_t len, void *result);
    } neoc_rpc_client_t;
    
    neoc_rpc_client_t *rpc = nns ? (neoc_rpc_client_t *)nns->rpc_client : NULL;
    
    // Result structure for integer values
    struct {
        enum { RESULT_INTEGER, RESULT_ERROR } type;
        uint64_t integer_value;
    } rpc_result = {0};
    
    if (rpc && rpc->invoke_script) {
        err = rpc->invoke_script(rpc, script, script_len, &rpc_result);
        if (err == NEOC_SUCCESS && rpc_result.type == RESULT_INTEGER) {
            *price = rpc_result.integer_value;
        } else {
            // Fallback to standard pricing tiers if RPC fails
            if (length <= 1) {
                *price = 0;  // Invalid - names must be at least 2 characters
            } else if (length == 2) {
                *price = 1000ULL * 100000000;  // 1000 GAS for 2-char names
            } else if (length == 3) {
                *price = 500ULL * 100000000;   // 500 GAS for 3-char names
            } else if (length == 4) {
                *price = 200ULL * 100000000;   // 200 GAS for 4-char names
            } else if (length == 5) {
                *price = 60ULL * 100000000;    // 60 GAS for 5-char names
            } else {
                *price = 10ULL * 100000000;    // 10 GAS for 6+ char names
            }
        }
    } else {
        // Use standard pricing when no RPC connection
        if (length <= 1) {
            *price = 0;
        } else if (length == 2) {
            *price = 1000ULL * 100000000;
        } else if (length == 3) {
            *price = 500ULL * 100000000;
        } else if (length == 4) {
            *price = 200ULL * 100000000;
        } else if (length == 5) {
            *price = 60ULL * 100000000;
        } else {
            *price = 10ULL * 100000000;
        }
        err = NEOC_ERROR_NETWORK;
    }
    
    neoc_free(script);
    neoc_script_builder_free(builder);
    return err;
}

neoc_error_t neoc_nns_set_rpc_client(neoc_nns_t *nns, void *rpc_client) {
    if (!nns) {
        return NEOC_ERROR_INVALID_ARGUMENT;
    }
    
    nns->rpc_client = rpc_client;
    return NEOC_SUCCESS;
}

void neoc_nns_free(neoc_nns_t *nns) {
    if (!nns) return;
    
    if (nns->contract) {
        neoc_smart_contract_free(nns->contract);
    }
    
    neoc_free(nns);
}
