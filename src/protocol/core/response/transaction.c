/**
 * @file transaction.c
 * @brief Transaction response implementation for Neo RPC calls
 * 
 * This file implements the Transaction response functionality based on the Swift source:
 * protocol/core/response/Transaction.swift
 */

#include <string.h>
#include <stdlib.h>
#include "neoc/protocol/core/response/transaction.h"
#include "neoc/neoc_memory.h"
#include "neoc/neoc_error.h"
#include "neoc/utils/json.h"
#include "neoc/utils/neoc_hex.h"
#include "neoc/types/hash256.h"
#include "neoc/types/hash160.h"
#include "neoc/utils/hex.h"

/**
 * @brief Create a new transaction response structure
 */
neoc_error_t neoc_transaction_response_create(neoc_transaction_response_t **response) {
    if (response == NULL) {
        return NEOC_ERROR_INVALID_ARGUMENT;
    }
    
    *response = (neoc_transaction_response_t *)neoc_malloc(sizeof(neoc_transaction_response_t));
    if (*response == NULL) {
        return NEOC_ERROR_OUT_OF_MEMORY;
    }
    
    // Initialize all fields to zero/NULL
    memset(*response, 0, sizeof(neoc_transaction_response_t));
    
    return NEOC_SUCCESS;
}

/**
 * @brief Free a transaction response structure
 */
void neoc_transaction_response_free(neoc_transaction_response_t *response) {
    if (response == NULL) {
        return;
    }
    
    // Free dynamically allocated strings
    if (response->sender) {
        neoc_free(response->sender);
    }
    
    if (response->sys_fee) {
        neoc_free(response->sys_fee);
    }
    
    if (response->net_fee) {
        neoc_free(response->net_fee);
    }
    
    if (response->script) {
        neoc_free(response->script);
    }
    
    // Free signers array
    if (response->signers) {
        for (size_t i = 0; i < response->signers_count; i++) {
            neoc_signer_free(response->signers[i]);
        }
        neoc_free(response->signers);
    }
    
    // Free attributes array
    if (response->attributes) {
        for (size_t i = 0; i < response->attributes_count; i++) {
            neoc_transaction_attribute_free(response->attributes[i]);
        }
        neoc_free(response->attributes);
    }
    
    // Free witnesses array
    if (response->witnesses) {
        for (size_t i = 0; i < response->witnesses_count; i++) {
            neoc_witness_free(response->witnesses[i]);
        }
        neoc_free(response->witnesses);
    }
    
    // Free optional fields
    if (response->block_hash) {
        neoc_free(response->block_hash);
    }
    
    if (response->confirmations) {
        neoc_free(response->confirmations);
    }
    
    if (response->block_time) {
        neoc_free(response->block_time);
    }
    
    if (response->vm_state) {
        neoc_free(response->vm_state);
    }
    
    // Free the structure itself
    neoc_free(response);
}

/**
 * @brief Initialize a transaction response with parameters
 */
neoc_error_t neoc_transaction_response_init(neoc_transaction_response_t *response,
                                           const neoc_hash256_t *hash,
                                           uint32_t size,
                                           uint32_t version,
                                           uint32_t nonce,
                                           const char *sender,
                                           const char *sys_fee,
                                           const char *net_fee,
                                           uint32_t valid_until_block,
                                           neoc_signer_t **signers,
                                           size_t signers_count,
                                           neoc_transaction_attribute_t **attributes,
                                           size_t attributes_count,
                                           const char *script,
                                           neoc_witness_t **witnesses,
                                           size_t witnesses_count) {
    if (response == NULL || hash == NULL) {
        return NEOC_ERROR_INVALID_ARGUMENT;
    }
    
    // Copy hash
    memcpy(&response->hash, hash, sizeof(neoc_hash256_t));
    
    // Set simple values
    response->size = size;
    response->version = version;
    response->nonce = nonce;
    response->valid_until_block = valid_until_block;
    response->signers_count = signers_count;
    response->attributes_count = attributes_count;
    response->witnesses_count = witnesses_count;
    
    // Copy sender
    if (sender) {
        response->sender = neoc_strdup(sender);
        if (response->sender == NULL) {
            return NEOC_ERROR_OUT_OF_MEMORY;
        }
    }
    
    // Copy sys_fee
    if (sys_fee) {
        response->sys_fee = neoc_strdup(sys_fee);
        if (response->sys_fee == NULL) {
            neoc_free(response->sender);
            response->sender = NULL;
            return NEOC_ERROR_OUT_OF_MEMORY;
        }
    }
    
    // Copy net_fee
    if (net_fee) {
        response->net_fee = neoc_strdup(net_fee);
        if (response->net_fee == NULL) {
            neoc_free(response->sender);
            neoc_free(response->sys_fee);
            response->sender = NULL;
            response->sys_fee = NULL;
            return NEOC_ERROR_OUT_OF_MEMORY;
        }
    }
    
    // Copy script
    if (script) {
        response->script = neoc_strdup(script);
        if (response->script == NULL) {
            neoc_free(response->sender);
            neoc_free(response->sys_fee);
            neoc_free(response->net_fee);
            response->sender = NULL;
            response->sys_fee = NULL;
            response->net_fee = NULL;
            return NEOC_ERROR_OUT_OF_MEMORY;
        }
    }
    
    // Copy signers
    if (signers && signers_count > 0) {
        response->signers = (neoc_signer_t **)neoc_malloc(signers_count * sizeof(neoc_signer_t *));
        if (response->signers == NULL) {
            neoc_free(response->sender);
            neoc_free(response->sys_fee);
            neoc_free(response->net_fee);
            neoc_free(response->script);
            response->sender = NULL;
            response->sys_fee = NULL;
            response->net_fee = NULL;
            response->script = NULL;
            return NEOC_ERROR_OUT_OF_MEMORY;
        }
        
        for (size_t i = 0; i < signers_count; i++) {
            neoc_error_t err = neoc_signer_copy(signers[i], &response->signers[i]);
            if (err != NEOC_SUCCESS) {
                // Free previously copied signers
                for (size_t j = 0; j < i; j++) {
                    neoc_signer_free(response->signers[j]);
                }
                neoc_free(response->signers);
                response->signers = NULL;
                
                // Free other allocated strings
                neoc_free(response->sender);
                neoc_free(response->sys_fee);
                neoc_free(response->net_fee);
                neoc_free(response->script);
                response->sender = NULL;
                response->sys_fee = NULL;
                response->net_fee = NULL;
                response->script = NULL;
                
                return err;
            }
        }
    }
    
    // Copy attributes
    if (attributes && attributes_count > 0) {
        response->attributes = (neoc_transaction_attribute_t **)neoc_malloc(attributes_count * sizeof(neoc_transaction_attribute_t *));
        if (response->attributes == NULL) {
            // Free signers
            if (response->signers) {
                for (size_t i = 0; i < response->signers_count; i++) {
                    neoc_signer_free(response->signers[i]);
                }
                neoc_free(response->signers);
                response->signers = NULL;
            }
            
            // Free other allocated strings
            neoc_free(response->sender);
            neoc_free(response->sys_fee);
            neoc_free(response->net_fee);
            neoc_free(response->script);
            response->sender = NULL;
            response->sys_fee = NULL;
            response->net_fee = NULL;
            response->script = NULL;
            
            return NEOC_ERROR_OUT_OF_MEMORY;
        }
        
        for (size_t i = 0; i < attributes_count; i++) {
            response->attributes[i] = neoc_transaction_attribute_clone(attributes[i]);
            if (response->attributes[i] == NULL) {
                // Free previously copied attributes
                for (size_t j = 0; j < i; j++) {
                    neoc_transaction_attribute_free(response->attributes[j]);
                }
                neoc_free(response->attributes);
                response->attributes = NULL;
                
                // Free signers
                if (response->signers) {
                    for (size_t j = 0; j < response->signers_count; j++) {
                        neoc_signer_free(response->signers[j]);
                    }
                    neoc_free(response->signers);
                    response->signers = NULL;
                }
                
                // Free other allocated strings
                neoc_free(response->sender);
                neoc_free(response->sys_fee);
                neoc_free(response->net_fee);
                neoc_free(response->script);
                response->sender = NULL;
                response->sys_fee = NULL;
                response->net_fee = NULL;
                response->script = NULL;
                
                return NEOC_ERROR_OUT_OF_MEMORY;
            }
        }
    }
    
    // Copy witnesses
    if (witnesses && witnesses_count > 0) {
        response->witnesses = (neoc_witness_t **)neoc_malloc(witnesses_count * sizeof(neoc_witness_t *));
        if (response->witnesses == NULL) {
            // Free attributes
            if (response->attributes) {
                for (size_t i = 0; i < response->attributes_count; i++) {
                    neoc_transaction_attribute_free(response->attributes[i]);
                }
                neoc_free(response->attributes);
                response->attributes = NULL;
            }
            
            // Free signers
            if (response->signers) {
                for (size_t i = 0; i < response->signers_count; i++) {
                    neoc_signer_free(response->signers[i]);
                }
                neoc_free(response->signers);
                response->signers = NULL;
            }
            
            // Free other allocated strings
            neoc_free(response->sender);
            neoc_free(response->sys_fee);
            neoc_free(response->net_fee);
            neoc_free(response->script);
            response->sender = NULL;
            response->sys_fee = NULL;
            response->net_fee = NULL;
            response->script = NULL;
            
            return NEOC_ERROR_OUT_OF_MEMORY;
        }
        
        for (size_t i = 0; i < witnesses_count; i++) {
            neoc_witness_t *cloned_witness;
            neoc_error_t clone_err = neoc_witness_clone(witnesses[i], &cloned_witness);
            if (clone_err == NEOC_SUCCESS) {
                response->witnesses[i] = cloned_witness;
            } else {
                response->witnesses[i] = NULL;
            }
            if (response->witnesses[i] == NULL) {
                // Free previously copied witnesses
                for (size_t j = 0; j < i; j++) {
                    neoc_witness_free(response->witnesses[j]);
                }
                neoc_free(response->witnesses);
                response->witnesses = NULL;
                
                // Free attributes
                if (response->attributes) {
                    for (size_t j = 0; j < response->attributes_count; j++) {
                        neoc_transaction_attribute_free(response->attributes[j]);
                    }
                    neoc_free(response->attributes);
                    response->attributes = NULL;
                }
                
                // Free signers
                if (response->signers) {
                    for (size_t j = 0; j < response->signers_count; j++) {
                        neoc_signer_free(response->signers[j]);
                    }
                    neoc_free(response->signers);
                    response->signers = NULL;
                }
                
                // Free other allocated strings
                neoc_free(response->sender);
                neoc_free(response->sys_fee);
                neoc_free(response->net_fee);
                neoc_free(response->script);
                response->sender = NULL;
                response->sys_fee = NULL;
                response->net_fee = NULL;
                response->script = NULL;
                
                return NEOC_ERROR_OUT_OF_MEMORY;
            }
        }
    }
    
    return NEOC_SUCCESS;
}

/**
 * @brief Set optional block hash for transaction response
 */
neoc_error_t neoc_transaction_response_set_block_hash(neoc_transaction_response_t *response,
                                                     const neoc_hash256_t *block_hash) {
    if (response == NULL) {
        return NEOC_ERROR_INVALID_ARGUMENT;
    }
    
    if (block_hash) {
        response->block_hash = (neoc_hash256_t *)neoc_malloc(sizeof(neoc_hash256_t));
        if (response->block_hash == NULL) {
            return NEOC_ERROR_OUT_OF_MEMORY;
        }
        memcpy(response->block_hash, block_hash, sizeof(neoc_hash256_t));
    }
    
    return NEOC_SUCCESS;
}

/**
 * @brief Set optional confirmations for transaction response
 */
neoc_error_t neoc_transaction_response_set_confirmations(neoc_transaction_response_t *response,
                                                        uint32_t confirmations) {
    if (response == NULL) {
        return NEOC_ERROR_INVALID_ARGUMENT;
    }
    
    response->confirmations = (uint32_t *)neoc_malloc(sizeof(uint32_t));
    if (response->confirmations == NULL) {
        return NEOC_ERROR_OUT_OF_MEMORY;
    }
    *response->confirmations = confirmations;
    
    return NEOC_SUCCESS;
}

/**
 * @brief Set optional block time for transaction response
 */
neoc_error_t neoc_transaction_response_set_block_time(neoc_transaction_response_t *response,
                                                     uint64_t block_time) {
    if (response == NULL) {
        return NEOC_ERROR_INVALID_ARGUMENT;
    }
    
    response->block_time = (uint64_t *)neoc_malloc(sizeof(uint64_t));
    if (response->block_time == NULL) {
        return NEOC_ERROR_OUT_OF_MEMORY;
    }
    *response->block_time = block_time;
    
    return NEOC_SUCCESS;
}

/**
 * @brief Set optional VM state for transaction response
 */
neoc_error_t neoc_transaction_response_set_vm_state(neoc_transaction_response_t *response,
                                                   neoc_vm_state_t vm_state) {
    if (response == NULL) {
        return NEOC_ERROR_INVALID_ARGUMENT;
    }
    
    response->vm_state = (neoc_vm_state_t *)neoc_malloc(sizeof(neoc_vm_state_t));
    if (response->vm_state == NULL) {
        return NEOC_ERROR_OUT_OF_MEMORY;
    }
    *response->vm_state = vm_state;
    
    return NEOC_SUCCESS;
}

/**
 * @brief Clone a transaction response structure
 */
neoc_error_t neoc_transaction_response_clone(const neoc_transaction_response_t *source,
                                            neoc_transaction_response_t **dest) {
    if (source == NULL || dest == NULL) {
        return NEOC_ERROR_INVALID_ARGUMENT;
    }
    
    neoc_error_t err = neoc_transaction_response_create(dest);
    if (err != NEOC_SUCCESS) {
        return err;
    }
    
    // Copy all fields using the init function for the main fields
    err = neoc_transaction_response_init(*dest,
                                        &source->hash,
                                        source->size,
                                        source->version,
                                        source->nonce,
                                        source->sender,
                                        source->sys_fee,
                                        source->net_fee,
                                        source->valid_until_block,
                                        source->signers,
                                        source->signers_count,
                                        source->attributes,
                                        source->attributes_count,
                                        source->script,
                                        source->witnesses,
                                        source->witnesses_count);
    
    if (err != NEOC_SUCCESS) {
        neoc_transaction_response_free(*dest);
        *dest = NULL;
        return err;
    }
    
    // Copy optional fields
    if (source->block_hash) {
        err = neoc_transaction_response_set_block_hash(*dest, source->block_hash);
        if (err != NEOC_SUCCESS) {
            neoc_transaction_response_free(*dest);
            *dest = NULL;
            return err;
        }
    }
    
    if (source->confirmations) {
        err = neoc_transaction_response_set_confirmations(*dest, *source->confirmations);
        if (err != NEOC_SUCCESS) {
            neoc_transaction_response_free(*dest);
            *dest = NULL;
            return err;
        }
    }
    
    if (source->block_time) {
        err = neoc_transaction_response_set_block_time(*dest, *source->block_time);
        if (err != NEOC_SUCCESS) {
            neoc_transaction_response_free(*dest);
            *dest = NULL;
            return err;
        }
    }
    
    if (source->vm_state) {
        err = neoc_transaction_response_set_vm_state(*dest, *source->vm_state);
        if (err != NEOC_SUCCESS) {
            neoc_transaction_response_free(*dest);
            *dest = NULL;
            return err;
        }
    }
    
    return NEOC_SUCCESS;
}

/**
 * @brief Parse transaction response from JSON string
 */
neoc_error_t neoc_transaction_response_from_json(const char *json_str,
                                                neoc_transaction_response_t **response) {
    if (json_str == NULL || response == NULL) {
        return NEOC_ERROR_INVALID_ARGUMENT;
    }
    
    // Create the response structure
    neoc_error_t err = neoc_transaction_response_create(response);
    if (err != NEOC_SUCCESS) {
        return err;
    }
    
    // Parse JSON
    neoc_json_t* json = neoc_json_parse(json_str);
    if (!json) {
        neoc_transaction_response_free(*response);
        *response = NULL;
        return NEOC_ERROR_INVALID_JSON;
    }
    
    // Extract hash
    const char* hash_str = neoc_json_get_string(json, "hash");
    if (hash_str) {
        neoc_hash256_from_string(hash_str, &(*response)->hash);
    }
    
    // Extract numeric fields
    (*response)->size = (uint32_t)neoc_json_get_number(json, "size");
    (*response)->version = (uint32_t)neoc_json_get_number(json, "version");
    (*response)->nonce = (uint32_t)neoc_json_get_number(json, "nonce");
    (*response)->valid_until_block = (uint32_t)neoc_json_get_number(json, "validuntilblock");
    
    // Extract string fields
    const char* sender = neoc_json_get_string(json, "sender");
    if (sender) {
        (*response)->sender = neoc_strdup(sender);
    }
    
    const char* sys_fee = neoc_json_get_string(json, "sysfee");
    if (sys_fee) {
        (*response)->sys_fee = neoc_strdup(sys_fee);
    }
    
    const char* net_fee = neoc_json_get_string(json, "netfee");
    if (net_fee) {
        (*response)->net_fee = neoc_strdup(net_fee);
    }
    
    const char* script = neoc_json_get_string(json, "script");
    if (script) {
        (*response)->script = neoc_strdup(script);
    }
    
    // Extract optional fields
    const char* block_hash_str = neoc_json_get_string(json, "blockhash");
    if (block_hash_str) {
        (*response)->block_hash = neoc_malloc(sizeof(neoc_hash256_t));
        if ((*response)->block_hash) {
            neoc_hash256_from_string(block_hash_str, (*response)->block_hash);
        }
    }
    
    double confirmations = neoc_json_get_number(json, "confirmations");
    if (confirmations >= 0) {
        (*response)->confirmations = neoc_malloc(sizeof(uint32_t));
        if ((*response)->confirmations) {
            *(*response)->confirmations = (uint32_t)confirmations;
        }
    }
    
    double block_time = neoc_json_get_number(json, "blocktime");
    if (block_time >= 0) {
        (*response)->block_time = neoc_malloc(sizeof(uint64_t));
        if ((*response)->block_time) {
            *(*response)->block_time = (uint64_t)block_time;
        }
    }
    
    neoc_json_free(json);
    
    return NEOC_SUCCESS;
}

/**
 * @brief Convert transaction response to JSON string
 */
neoc_error_t neoc_transaction_response_to_json(const neoc_transaction_response_t *response,
                                              char **json_str) {
    if (response == NULL || json_str == NULL) {
        return NEOC_ERROR_INVALID_ARGUMENT;
    }
    
    // Calculate required buffer size
    size_t json_size = 4096; // Initial size
    char* json = neoc_malloc(json_size);
    if (!json) {
        return NEOC_ERROR_OUT_OF_MEMORY;
    }
    
    // Convert hash to hex string
    char hash_str[65];
    neoc_hash256_to_string(&response->hash, hash_str, sizeof(hash_str));
    
    // Build JSON string
    int offset = snprintf(json, json_size,
                         "{\"hash\":\"%s\",\"size\":%u,\"version\":%u,\"nonce\":%u,"
                         "\"sender\":\"%s\",\"sysfee\":\"%s\",\"netfee\":\"%s\","
                         "\"validuntilblock\":%u,\"script\":\"%s\"",
                         hash_str,
                         response->size,
                         response->version,
                         response->nonce,
                         response->sender ? response->sender : "",
                         response->sys_fee ? response->sys_fee : "0",
                         response->net_fee ? response->net_fee : "0",
                         response->valid_until_block,
                         response->script ? response->script : "");
    
    // Add optional fields
    if (response->block_hash) {
        char block_hash_str[65];
        neoc_hash256_to_string(response->block_hash, block_hash_str, sizeof(block_hash_str));
        offset += snprintf(json + offset, json_size - offset,
                          ",\"blockhash\":\"%s\"", block_hash_str);
    }
    
    if (response->confirmations) {
        offset += snprintf(json + offset, json_size - offset,
                          ",\"confirmations\":%u", *response->confirmations);
    }
    
    if (response->block_time) {
        offset += snprintf(json + offset, json_size - offset,
                          ",\"blocktime\":%llu", (unsigned long long)*response->block_time);
    }
    
    // Add arrays (simplified - empty for now)
    offset += snprintf(json + offset, json_size - offset,
                      ",\"signers\":[],\"attributes\":[],\"witnesses\":[]");
    
    // Close JSON object
    snprintf(json + offset, json_size - offset, "}");
    
    *json_str = json;
    
    return NEOC_SUCCESS;
}
