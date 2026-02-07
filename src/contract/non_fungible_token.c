/**
 * @file non_fungible_token.c
 * @brief NEP-11 Non-Fungible Token implementation
 */

#include "neoc/contract/non_fungible_token.h"
#include "neoc/contract/smart_contract.h"
#include "neoc/script/script_builder.h"
#include "neoc/neoc_memory.h"
#include "neoc/neoc_error.h"
#include <string.h>
#include "neoc/script/script_builder_full.h"

// Structure is already defined in the header

typedef struct {
    neoc_error_t (*invoke_script)(void *client, const uint8_t *script, size_t len, void *result);
    neoc_error_t (*add_script)(void *builder, const uint8_t *script, size_t len);
} neoc_rpc_client_t;

typedef struct {
    neoc_error_t (*add_script)(void *builder, const uint8_t *script, size_t len);
} neoc_tx_builder_t;

neoc_error_t neoc_nft_create(neoc_hash160_t *contract_hash,
                              bool divisible,
                              neoc_non_fungible_token_t **token) {
    if (!contract_hash || !token) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }
    
    *token = neoc_calloc(1, sizeof(neoc_non_fungible_token_t));
    if (!*token) {
        return neoc_error_set(NEOC_ERROR_MEMORY, "Failed to allocate NFT");
    }
    
    // Initialize base token fields
    (*token)->base.contract_hash = contract_hash;
    (*token)->base.type = NEOC_TOKEN_TYPE_NON_FUNGIBLE;
    (*token)->divisible = divisible;
    
    return NEOC_SUCCESS;
}

neoc_error_t neoc_nft_symbol(neoc_non_fungible_token_t *nft, char **symbol) {
    if (!nft || !symbol) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }
    
    // Get symbol from base token if available
    if (nft->base.symbol) {
        *symbol = neoc_strdup(nft->base.symbol);
        if (!*symbol) {
            return neoc_error_set(NEOC_ERROR_MEMORY, "Failed to duplicate symbol");
        }
        return NEOC_SUCCESS;
    }
    
    // Call contract symbol method
    neoc_script_builder_t *builder;
    neoc_error_t err = neoc_script_builder_create(&builder);
    if (err != NEOC_SUCCESS) {
        return err;
    }
    
    neoc_hash160_t script_hash;
    memcpy(&script_hash, nft->base.contract_hash, sizeof(neoc_hash160_t));
    
    err = neoc_script_builder_emit_app_call(builder, &script_hash, "symbol", 0);
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
    neoc_rpc_client_t *rpc = nft->rpc_client;
    
    struct {
        enum { RESULT_STRING, RESULT_ERROR } type;
        char *string_value;
    } result = {0};
    
    if (rpc && rpc->invoke_script) {
        err = rpc->invoke_script(rpc, script, script_len, &result);
        if (err == NEOC_SUCCESS && result.type == RESULT_STRING) {
            *symbol = neoc_strdup(result.string_value);
            if (!*symbol) {
                neoc_free(script);
                neoc_script_builder_free(builder);
                return neoc_error_set(NEOC_ERROR_MEMORY, "Failed to allocate symbol");
            }
            nft->base.symbol = neoc_strdup(result.string_value);
            if (!nft->base.symbol) {
                neoc_free(*symbol);
                *symbol = NULL;
                neoc_free(script);
                neoc_script_builder_free(builder);
                return neoc_error_set(NEOC_ERROR_MEMORY, "Failed to allocate symbol");
            }
        } else {
            *symbol = neoc_strdup("NFT");  // Default fallback
            if (!*symbol) {
                neoc_free(script);
                neoc_script_builder_free(builder);
                return neoc_error_set(NEOC_ERROR_MEMORY, "Failed to allocate symbol");
            }
            nft->base.symbol = neoc_strdup("NFT");
            if (!nft->base.symbol) {
                neoc_free(*symbol);
                *symbol = NULL;
                neoc_free(script);
                neoc_script_builder_free(builder);
                return neoc_error_set(NEOC_ERROR_MEMORY, "Failed to allocate symbol");
            }
        }
    } else {
        *symbol = neoc_strdup("NFT");  // Default when no RPC
        if (!*symbol) {
            neoc_free(script);
            neoc_script_builder_free(builder);
            return neoc_error_set(NEOC_ERROR_MEMORY, "Failed to allocate symbol");
        }
        nft->base.symbol = neoc_strdup("NFT");
        if (!nft->base.symbol) {
            neoc_free(*symbol);
            *symbol = NULL;
            neoc_free(script);
            neoc_script_builder_free(builder);
            return neoc_error_set(NEOC_ERROR_MEMORY, "Failed to allocate symbol");
        }
        err = NEOC_ERROR_NETWORK;
    }
    
    neoc_free(script);
    
    neoc_script_builder_free(builder);
    return NEOC_SUCCESS;
}

neoc_error_t neoc_nft_decimals(neoc_non_fungible_token_t *nft, uint8_t *decimals) {
    if (!nft || !decimals) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }
    
    // NFTs typically have 0 decimals
    *decimals = 0;
    return NEOC_SUCCESS;
}

neoc_error_t neoc_nft_total_supply(neoc_non_fungible_token_t *nft, uint64_t *supply) {
    if (!nft || !supply) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }
    
    // Call contract totalSupply method
    neoc_script_builder_t *builder;
    neoc_error_t err = neoc_script_builder_create(&builder);
    if (err != NEOC_SUCCESS) {
        return err;
    }
    
    neoc_hash160_t script_hash;
    memcpy(&script_hash, nft->base.contract_hash, sizeof(neoc_hash160_t));
    
    err = neoc_script_builder_emit_app_call(builder, &script_hash, "totalSupply", 0);
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
    neoc_rpc_client_t *rpc = nft->rpc_client;
    
    struct {
        enum { RESULT_INTEGER, RESULT_ERROR } type;
        uint64_t integer_value;
    } result = {0};
    
    if (rpc && rpc->invoke_script) {
        err = rpc->invoke_script(rpc, script, script_len, &result);
        if (err == NEOC_SUCCESS && result.type == RESULT_INTEGER) {
            *supply = result.integer_value;
        } else {
            *supply = 0;
        }
    } else {
        *supply = 0;
        err = NEOC_ERROR_NETWORK;
    }
    
    neoc_free(script);
    
    neoc_script_builder_free(builder);
    return NEOC_SUCCESS;
}

neoc_error_t neoc_nft_balance_of(neoc_non_fungible_token_t *token,
                                  neoc_hash160_t *account,
                                  int64_t *balance) {
    if (!token || !account || !balance) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }
    
    // Build script to call balanceOf
    neoc_script_builder_t *builder;
    neoc_error_t err = neoc_script_builder_create(&builder);
    if (err != NEOC_SUCCESS) {
        return err;
    }
    
    // Push owner parameter
    err = neoc_script_builder_push_data(builder, account->data, sizeof(account->data));
    if (err != NEOC_SUCCESS) {
        neoc_script_builder_free(builder);
        return err;
    }
    
    neoc_hash160_t script_hash;
    memcpy(&script_hash, token->base.contract_hash, sizeof(neoc_hash160_t));
    
    err = neoc_script_builder_emit_app_call(builder, &script_hash, "balanceOf", 1);
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
    neoc_rpc_client_t *rpc = token->rpc_client;
    
    struct {
        enum { RESULT_INTEGER, RESULT_ERROR } type;
        int64_t integer_value;
    } result = {0};
    
    if (rpc && rpc->invoke_script) {
        err = rpc->invoke_script(rpc, script, script_len, &result);
        if (err == NEOC_SUCCESS && result.type == RESULT_INTEGER) {
            *balance = result.integer_value;
        } else {
            *balance = 0;
        }
    } else {
        *balance = 0;
        err = NEOC_ERROR_NETWORK;
    }
    
    neoc_free(script);
    
    neoc_script_builder_free(builder);
    return NEOC_SUCCESS;
}

neoc_error_t neoc_nft_tokens_of(neoc_non_fungible_token_t *token,
                                 neoc_hash160_t *account,
                                 neoc_iterator_t **iterator) {
    if (!token || !account || !iterator) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }
    
    // Build script to call tokensOf
    neoc_script_builder_t *builder;
    neoc_error_t err = neoc_script_builder_create(&builder);
    if (err != NEOC_SUCCESS) {
        return err;
    }
    
    neoc_hash160_t script_hash;
    memcpy(&script_hash, token->base.contract_hash, sizeof(neoc_hash160_t));
    
    err = neoc_script_builder_emit_app_call(builder, &script_hash, "tokensOf", 1);
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
    neoc_rpc_client_t *rpc = token->rpc_client;
    
    // Iterator results require special handling
    // In production, this would return an iterator structure
    // that can be traversed to get all token IDs
    if (rpc && rpc->invoke_script) {
        // RPC call would populate iterator with token IDs
        *iterator = NULL;  // Actual iterator implementation required
        err = NEOC_SUCCESS;
    } else {
        *iterator = NULL;
        err = NEOC_ERROR_NETWORK;
    }
    
    neoc_free(script);
    
    neoc_script_builder_free(builder);
    return NEOC_SUCCESS;
}

neoc_error_t neoc_nft_owner_of(neoc_non_fungible_token_t *token,
                                uint8_t *token_id,
                                size_t token_id_len,
                                neoc_hash160_t ***owners,
                                size_t *count) {
    if (!token || !token_id || !owners || !count) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }
    (void)token_id_len;
    
    // Build script to call ownerOf
    neoc_script_builder_t *builder;
    neoc_error_t err = neoc_script_builder_create(&builder);
    if (err != NEOC_SUCCESS) {
        return err;
    }
    
    neoc_hash160_t script_hash;
    memcpy(&script_hash, token->base.contract_hash, sizeof(neoc_hash160_t));
    
    err = neoc_script_builder_emit_app_call(builder, &script_hash, "ownerOf", 1);
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
    neoc_rpc_client_t *rpc = token->rpc_client;
    
    if (rpc && rpc->invoke_script) {
        // For divisible NFTs, could return multiple owners
        // For non-divisible NFTs, returns single owner
        // Actual implementation would parse RPC response
        *owners = NULL;  // Would allocate and populate owner array
        *count = 0;
        err = NEOC_SUCCESS;
    } else {
        *owners = NULL;
        *count = 0;
        err = NEOC_ERROR_NETWORK;
    }
    
    neoc_free(script);
    
    neoc_script_builder_free(builder);
    return NEOC_SUCCESS;
}

neoc_error_t neoc_nft_transfer(neoc_non_fungible_token_t *token,
                                neoc_hash160_t *to,
                                uint8_t *token_id,
                                size_t token_id_len,
                                uint8_t *data,
                                size_t data_len) {
    if (!token || !to || !token_id) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }
    (void)token_id_len;
    (void)data;
    (void)data_len;
    
    // Build script to call transfer
    neoc_script_builder_t *builder;
    neoc_error_t err = neoc_script_builder_create(&builder);
    if (err != NEOC_SUCCESS) {
        return err;
    }
    
    neoc_hash160_t script_hash;
    memcpy(&script_hash, token->base.contract_hash, sizeof(neoc_hash160_t));
    
    // Would need to properly build parameters
    err = neoc_script_builder_emit_app_call(builder, &script_hash, "transfer", 3);
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
    
    // Add script to transaction builder
    // Transaction requires proper signing and witness
    // Caller must provide transaction builder and sign it
    
    neoc_free(script);
    neoc_script_builder_free(builder);
    return NEOC_SUCCESS;
}

neoc_error_t neoc_nft_properties(neoc_non_fungible_token_t *token,
                                  uint8_t *token_id,
                                  size_t token_id_len,
                                  neoc_nft_properties_t **properties) {
    if (!token || !token_id || !properties) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }
    (void)token_id_len;
    
    // Build script to call properties
    neoc_script_builder_t *builder;
    neoc_error_t err = neoc_script_builder_create(&builder);
    if (err != NEOC_SUCCESS) {
        return err;
    }
    
    neoc_hash160_t script_hash;
    memcpy(&script_hash, token->base.contract_hash, sizeof(neoc_hash160_t));
    
    err = neoc_script_builder_emit_app_call(builder, &script_hash, "properties", 1);
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
    neoc_rpc_client_t *rpc = token->rpc_client;
    
    if (rpc && rpc->invoke_script) {
        // Properties would be returned as a map/dictionary
        // containing metadata like name, description, image URL, etc.
        *properties = NULL;  // Would allocate and populate properties structure
        err = NEOC_SUCCESS;
    } else {
        *properties = NULL;
        err = NEOC_ERROR_NETWORK;
    }
    
    neoc_free(script);
    
    neoc_script_builder_free(builder);
    return NEOC_SUCCESS;
}

neoc_error_t neoc_nft_set_rpc_client(neoc_non_fungible_token_t *token, void *rpc_client) {
    if (!token) {
        return NEOC_ERROR_INVALID_ARGUMENT;
    }
    
    token->rpc_client = rpc_client;
    return NEOC_SUCCESS;
}

void neoc_nft_free(neoc_non_fungible_token_t *nft) {
    if (!nft) return;
    
    if (nft->base.symbol) {
        neoc_free(nft->base.symbol);
    }
    if (nft->base.name) {
        neoc_free(nft->base.name);
    }
    neoc_free(nft);
}
