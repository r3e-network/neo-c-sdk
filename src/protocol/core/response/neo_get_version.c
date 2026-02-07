/**
 * @file neo_get_version.c
 * @brief Neo getversion RPC response implementation
 * 
 * Based on Swift source: protocol/core/response/NeoGetVersion.swift
 * Implements Neo node version information handling and parsing
 */

#include "../../../../include/neoc/neoc_error.h"
#include "../../../../include/neoc/neoc_memory.h"
#include "../../../../include/neoc/protocol/core/response/neo_get_version.h"
#include "../../../../include/neoc/utils/json.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#ifdef HAVE_CJSON
#include <cjson/cJSON.h>
#endif

/**
 * @brief Create Neo version structure
 */
neoc_error_t neoc_neo_version_create(neoc_neo_version_t **version) {
    if (!version) {
        return NEOC_ERROR_INVALID_PARAM;
    }
    
    *version = NULL;
    
    neoc_neo_version_t *new_version = neoc_malloc(sizeof(neoc_neo_version_t));
    if (!new_version) {
        return NEOC_ERROR_OUT_OF_MEMORY;
    }
    
    // Initialize all fields to zero/NULL
    memset(new_version, 0, sizeof(neoc_neo_version_t));
    
    *version = new_version;
    return NEOC_SUCCESS;
}

/**
 * @brief Set basic version information
 */
neoc_error_t neoc_neo_version_set_basic_info(neoc_neo_version_t *version,
                                              uint32_t tcp_port,
                                              uint32_t ws_port,
                                              uint32_t nonce,
                                              const char *user_agent) {
    if (!version) {
        return NEOC_ERROR_INVALID_PARAM;
    }
    
    version->tcp_port = tcp_port;
    version->ws_port = ws_port;
    version->nonce = nonce;
    
    // Free existing user agent and set new one
    if (version->user_agent) {
        neoc_free(version->user_agent);
    }
    
    if (user_agent) {
        version->user_agent = neoc_strdup(user_agent);
        if (!version->user_agent) {
            return NEOC_ERROR_OUT_OF_MEMORY;
        }
    } else {
        version->user_agent = NULL;
    }
    
    return NEOC_SUCCESS;
}

/**
 * @brief Set protocol configuration
 */
neoc_error_t neoc_neo_version_set_protocol_config(neoc_neo_version_t *version,
                                                   uint32_t network,
                                                   uint32_t address_version,
                                                   uint32_t ms_per_block,
                                                   uint32_t max_transactions_per_block,
                                                   uint32_t memory_pool_max_transactions,
                                                   uint32_t max_trace_results,
                                                   uint64_t initial_gas_distribution) {
    if (!version) {
        return NEOC_ERROR_INVALID_PARAM;
    }
    
    version->protocol.network = network;
    version->protocol.address_version = address_version;
    version->protocol.ms_per_block = ms_per_block;
    version->protocol.max_transactions_per_block = max_transactions_per_block;
    version->protocol.memory_pool_max_transactions = memory_pool_max_transactions;
    version->protocol.max_trace_results = max_trace_results;
    version->protocol.initial_gas_distribution = initial_gas_distribution;
    
    return NEOC_SUCCESS;
}

/**
 * @brief Set valid signers array
 */
neoc_error_t neoc_neo_version_set_valid_signers(neoc_neo_version_t *version,
                                                 const char **signers,
                                                 size_t count) {
    if (!version) {
        return NEOC_ERROR_INVALID_PARAM;
    }
    
    // Free existing signers
    if (version->protocol.valid_signers) {
        for (size_t i = 0; i < version->protocol.valid_signers_count; i++) {
            neoc_free(version->protocol.valid_signers[i]);
        }
        neoc_free(version->protocol.valid_signers);
        version->protocol.valid_signers = NULL;
        version->protocol.valid_signers_count = 0;
    }
    
    if (signers && count > 0) {
        version->protocol.valid_signers = neoc_malloc(sizeof(char*) * count);
        if (!version->protocol.valid_signers) {
            return NEOC_ERROR_OUT_OF_MEMORY;
        }
        
        // Copy each signer string
        for (size_t i = 0; i < count; i++) {
            if (signers[i]) {
                version->protocol.valid_signers[i] = neoc_strdup(signers[i]);
                if (!version->protocol.valid_signers[i]) {
                    // Clean up on failure
                    for (size_t j = 0; j < i; j++) {
                        neoc_free(version->protocol.valid_signers[j]);
                    }
                    neoc_free(version->protocol.valid_signers);
                    version->protocol.valid_signers = NULL;
                    return NEOC_ERROR_OUT_OF_MEMORY;
                }
            } else {
                version->protocol.valid_signers[i] = NULL;
            }
        }
        
        version->protocol.valid_signers_count = count;
    }
    
    return NEOC_SUCCESS;
}

/**
 * @brief Set committee members array
 */
neoc_error_t neoc_neo_version_set_committee_members(neoc_neo_version_t *version,
                                                     const char **members,
                                                     size_t count) {
    if (!version) {
        return NEOC_ERROR_INVALID_PARAM;
    }
    
    // Free existing committee members
    if (version->protocol.committee_members) {
        for (size_t i = 0; i < version->protocol.committee_members_count; i++) {
            neoc_free(version->protocol.committee_members[i]);
        }
        neoc_free(version->protocol.committee_members);
        version->protocol.committee_members = NULL;
        version->protocol.committee_members_count = 0;
    }
    
    if (members && count > 0) {
        version->protocol.committee_members = neoc_malloc(sizeof(char*) * count);
        if (!version->protocol.committee_members) {
            return NEOC_ERROR_OUT_OF_MEMORY;
        }
        
        // Copy each member string
        for (size_t i = 0; i < count; i++) {
            if (members[i]) {
                version->protocol.committee_members[i] = neoc_strdup(members[i]);
                if (!version->protocol.committee_members[i]) {
                    // Clean up on failure
                    for (size_t j = 0; j < i; j++) {
                        neoc_free(version->protocol.committee_members[j]);
                    }
                    neoc_free(version->protocol.committee_members);
                    version->protocol.committee_members = NULL;
                    return NEOC_ERROR_OUT_OF_MEMORY;
                }
            } else {
                version->protocol.committee_members[i] = NULL;
            }
        }
        
        version->protocol.committee_members_count = count;
    }
    
    return NEOC_SUCCESS;
}

/**
 * @brief Set seed list array
 */
neoc_error_t neoc_neo_version_set_seed_list(neoc_neo_version_t *version,
                                             const char **seeds,
                                             size_t count) {
    if (!version) {
        return NEOC_ERROR_INVALID_PARAM;
    }
    
    // Free existing seed list
    if (version->protocol.seed_list) {
        for (size_t i = 0; i < version->protocol.seed_list_count; i++) {
            neoc_free(version->protocol.seed_list[i]);
        }
        neoc_free(version->protocol.seed_list);
        version->protocol.seed_list = NULL;
        version->protocol.seed_list_count = 0;
    }
    
    if (seeds && count > 0) {
        version->protocol.seed_list = neoc_malloc(sizeof(char*) * count);
        if (!version->protocol.seed_list) {
            return NEOC_ERROR_OUT_OF_MEMORY;
        }
        
        // Copy each seed string
        for (size_t i = 0; i < count; i++) {
            if (seeds[i]) {
                version->protocol.seed_list[i] = neoc_strdup(seeds[i]);
                if (!version->protocol.seed_list[i]) {
                    // Clean up on failure
                    for (size_t j = 0; j < i; j++) {
                        neoc_free(version->protocol.seed_list[j]);
                    }
                    neoc_free(version->protocol.seed_list);
                    version->protocol.seed_list = NULL;
                    return NEOC_ERROR_OUT_OF_MEMORY;
                }
            } else {
                version->protocol.seed_list[i] = NULL;
            }
        }
        
        version->protocol.seed_list_count = count;
    }
    
    return NEOC_SUCCESS;
}

/**
 * @brief Get user agent string
 */
const char* neoc_neo_version_get_user_agent(const neoc_neo_version_t *version) {
    if (!version) {
        return NULL;
    }
    
    return version->user_agent;
}

/**
 * @brief Get network magic number
 */
uint32_t neoc_neo_version_get_network(const neoc_neo_version_t *version) {
    if (!version) {
        return 0;
    }
    
    return version->protocol.network;
}

/**
 * @brief Get milliseconds per block
 */
uint32_t neoc_neo_version_get_ms_per_block(const neoc_neo_version_t *version) {
    if (!version) {
        return 0;
    }
    
    return version->protocol.ms_per_block;
}

/**
 * @brief Get max transactions per block
 */
uint32_t neoc_neo_version_get_max_transactions_per_block(const neoc_neo_version_t *version) {
    if (!version) {
        return 0;
    }
    
    return version->protocol.max_transactions_per_block;
}

/**
 * @brief Get valid signers
 */
neoc_error_t neoc_neo_version_get_valid_signers(const neoc_neo_version_t *version,
                                                 const char ***signers,
                                                 size_t *count) {
    if (!version || !signers || !count) {
        return NEOC_ERROR_INVALID_PARAM;
    }
    
    *signers = (const char**)version->protocol.valid_signers;
    *count = version->protocol.valid_signers_count;
    
    return NEOC_SUCCESS;
}

/**
 * @brief Get committee members
 */
neoc_error_t neoc_neo_version_get_committee_members(const neoc_neo_version_t *version,
                                                     const char ***members,
                                                     size_t *count) {
    if (!version || !members || !count) {
        return NEOC_ERROR_INVALID_PARAM;
    }
    
    *members = (const char**)version->protocol.committee_members;
    *count = version->protocol.committee_members_count;
    
    return NEOC_SUCCESS;
}

/**
 * @brief Check if node supports specific protocol version
 *
 * Parses the user_agent string (e.g. "/Neo:3.9.1/") to extract the node
 * version and compares it against the required version.
 */
bool neoc_neo_version_supports_protocol(const neoc_neo_version_t *version,
                                         const char *required_version) {
    if (!version || !required_version) {
        return false;
    }

    int req_major = 0, req_minor = 0, req_patch = 0;
    if (sscanf(required_version, "%d.%d.%d", &req_major, &req_minor, &req_patch) < 2) {
        return false;
    }

    /* Extract version from user_agent (format: "/Neo:X.Y.Z/") */
    if (version->user_agent) {
        const char *colon = strstr(version->user_agent, ":");
        if (colon) {
            int ua_major = 0, ua_minor = 0, ua_patch = 0;
            if (sscanf(colon + 1, "%d.%d.%d", &ua_major, &ua_minor, &ua_patch) >= 2) {
                if (ua_major > req_major) return true;
                if (ua_major == req_major && ua_minor > req_minor) return true;
                if (ua_major == req_major && ua_minor == req_minor &&
                    ua_patch >= req_patch) return true;
                return false;
            }
        }
        /* Fallback: substring match */
        if (strstr(version->user_agent, required_version)) {
            return true;
        }
    }

    return false;
}

/**
 * @brief Set validators count (v3.9.1)
 */
neoc_error_t neoc_neo_version_set_validators_count(neoc_neo_version_t *version,
                                                    uint32_t count) {
    if (!version) {
        return NEOC_ERROR_INVALID_PARAM;
    }
    version->protocol.validators_count = count;
    return NEOC_SUCCESS;
}

/**
 * @brief Add a hardfork entry (v3.9.1)
 */
neoc_error_t neoc_neo_version_add_hardfork(neoc_neo_version_t *version,
                                            const char *name,
                                            uint32_t block_height) {
    if (!version || !name) {
        return NEOC_ERROR_INVALID_PARAM;
    }

    size_t new_count = version->protocol.hardforks_count + 1;
    neoc_hardfork_t *new_arr = neoc_malloc(sizeof(neoc_hardfork_t) * new_count);
    if (!new_arr) {
        return NEOC_ERROR_OUT_OF_MEMORY;
    }

    /* Copy existing entries */
    if (version->protocol.hardforks && version->protocol.hardforks_count > 0) {
        memcpy(new_arr, version->protocol.hardforks,
               sizeof(neoc_hardfork_t) * version->protocol.hardforks_count);
    }

    /* Add new entry */
    new_arr[new_count - 1].name = neoc_strdup(name);
    if (!new_arr[new_count - 1].name) {
        neoc_free(new_arr);
        return NEOC_ERROR_OUT_OF_MEMORY;
    }
    new_arr[new_count - 1].block_height = block_height;

    /* Swap in new array (old entries' strings are now owned by new_arr) */
    if (version->protocol.hardforks) {
        neoc_free(version->protocol.hardforks);
    }
    version->protocol.hardforks = new_arr;
    version->protocol.hardforks_count = new_count;

    return NEOC_SUCCESS;
}

/**
 * @brief Free hardfork entry resources (does not free the struct itself)
 */
void neoc_hardfork_cleanup(neoc_hardfork_t *hardfork) {
    if (!hardfork) return;
    if (hardfork->name) {
        neoc_free(hardfork->name);
        hardfork->name = NULL;
    }
}

/**
 * @brief Copy Neo version structure
 */
neoc_error_t neoc_neo_version_copy(const neoc_neo_version_t *source,
                                    neoc_neo_version_t **copy) {
    if (!source || !copy) {
        return NEOC_ERROR_INVALID_PARAM;
    }
    
    *copy = NULL;
    
    // Create new version
    neoc_error_t error = neoc_neo_version_create(copy);
    if (error != NEOC_SUCCESS) {
        return error;
    }
    
    neoc_neo_version_t *dest = *copy;
    
    // Copy basic info
    error = neoc_neo_version_set_basic_info(dest, source->tcp_port, source->ws_port,
                                             source->nonce, source->user_agent);
    if (error != NEOC_SUCCESS) {
        neoc_neo_version_free(dest);
        *copy = NULL;
        return error;
    }
    
    // Copy protocol config
    error = neoc_neo_version_set_protocol_config(dest,
                                                  source->protocol.network,
                                                  source->protocol.address_version,
                                                  source->protocol.ms_per_block,
                                                  source->protocol.max_transactions_per_block,
                                                  source->protocol.memory_pool_max_transactions,
                                                  source->protocol.max_trace_results,
                                                  source->protocol.initial_gas_distribution);
    if (error != NEOC_SUCCESS) {
        neoc_neo_version_free(dest);
        *copy = NULL;
        return error;
    }
    
    // Copy arrays
    if (source->protocol.valid_signers_count > 0) {
        error = neoc_neo_version_set_valid_signers(dest,
                                                    (const char**)source->protocol.valid_signers,
                                                    source->protocol.valid_signers_count);
        if (error != NEOC_SUCCESS) {
            neoc_neo_version_free(dest);
            *copy = NULL;
            return error;
        }
    }
    
    if (source->protocol.committee_members_count > 0) {
        error = neoc_neo_version_set_committee_members(dest,
                                                        (const char**)source->protocol.committee_members,
                                                        source->protocol.committee_members_count);
        if (error != NEOC_SUCCESS) {
            neoc_neo_version_free(dest);
            *copy = NULL;
            return error;
        }
    }
    
    if (source->protocol.seed_list_count > 0) {
        error = neoc_neo_version_set_seed_list(dest,
                                                (const char**)source->protocol.seed_list,
                                                source->protocol.seed_list_count);
        if (error != NEOC_SUCCESS) {
            neoc_neo_version_free(dest);
            *copy = NULL;
            return error;
        }
    }

    /* Copy v3.9.1 fields */
    dest->protocol.validators_count = source->protocol.validators_count;

    for (size_t i = 0; i < source->protocol.hardforks_count; i++) {
        error = neoc_neo_version_add_hardfork(dest,
                                               source->protocol.hardforks[i].name,
                                               source->protocol.hardforks[i].block_height);
        if (error != NEOC_SUCCESS) {
            neoc_neo_version_free(dest);
            *copy = NULL;
            return error;
        }
    }

    return NEOC_SUCCESS;
}

/**
 * @brief Free Neo version structure
 */
void neoc_neo_version_free(neoc_neo_version_t *version) {
    if (!version) {
        return;
    }
    
    // Free user agent
    if (version->user_agent) {
        neoc_free(version->user_agent);
    }
    
    // Free hardfork entries (v3.9.1)
    if (version->protocol.hardforks) {
        for (size_t i = 0; i < version->protocol.hardforks_count; i++) {
            neoc_hardfork_cleanup(&version->protocol.hardforks[i]);
        }
        neoc_free(version->protocol.hardforks);
    }

    // Free protocol arrays
    if (version->protocol.valid_signers) {
        for (size_t i = 0; i < version->protocol.valid_signers_count; i++) {
            if (version->protocol.valid_signers[i]) {
                neoc_free(version->protocol.valid_signers[i]);
            }
        }
        neoc_free(version->protocol.valid_signers);
    }
    
    if (version->protocol.committee_members) {
        for (size_t i = 0; i < version->protocol.committee_members_count; i++) {
            if (version->protocol.committee_members[i]) {
                neoc_free(version->protocol.committee_members[i]);
            }
        }
        neoc_free(version->protocol.committee_members);
    }
    
    if (version->protocol.seed_list) {
        for (size_t i = 0; i < version->protocol.seed_list_count; i++) {
            if (version->protocol.seed_list[i]) {
                neoc_free(version->protocol.seed_list[i]);
            }
        }
        neoc_free(version->protocol.seed_list);
    }
    
    neoc_free(version);
}

/**
 * @brief Create version response
 */
neoc_error_t neoc_neo_get_version_response_create(int id,
                                                   neoc_neo_version_t *result,
                                                   const char *error,
                                                   int error_code,
                                                   neoc_neo_get_version_response_t **response) {
    if (!response) {
        return NEOC_ERROR_INVALID_PARAM;
    }
    
    *response = NULL;
    
    neoc_neo_get_version_response_t *new_response = neoc_malloc(sizeof(neoc_neo_get_version_response_t));
    if (!new_response) {
        return NEOC_ERROR_OUT_OF_MEMORY;
    }
    
    // Initialize response
    new_response->jsonrpc = neoc_strdup("2.0");
    if (!new_response->jsonrpc) {
        neoc_free(new_response);
        return NEOC_ERROR_OUT_OF_MEMORY;
    }
    
    new_response->id = id;
    new_response->result = result;
    new_response->error_code = error_code;
    
    if (error) {
        new_response->error = neoc_strdup(error);
        if (!new_response->error) {
            neoc_free(new_response->jsonrpc);
            neoc_free(new_response);
            return NEOC_ERROR_OUT_OF_MEMORY;
        }
    } else {
        new_response->error = NULL;
    }
    
    *response = new_response;
    return NEOC_SUCCESS;
}

/**
 * @brief Free version response
 */
void neoc_neo_get_version_response_free(neoc_neo_get_version_response_t *response) {
    if (!response) {
        return;
    }
    
    if (response->jsonrpc) {
        neoc_free(response->jsonrpc);
    }
    
    if (response->error) {
        neoc_free(response->error);
    }
    
    if (response->result) {
        neoc_neo_version_free(response->result);
    }
    
    neoc_free(response);
}

static neoc_error_t neoc_append_string_item(char ***items,
                                            size_t *count,
                                            const char *value) {
    if (!items || !count || !value) {
        return NEOC_ERROR_INVALID_PARAM;
    }

    size_t new_count = *count + 1;
    char **new_items = neoc_malloc(sizeof(char *) * new_count);
    if (!new_items) {
        return NEOC_ERROR_OUT_OF_MEMORY;
    }

    for (size_t i = 0; i < *count; i++) {
        new_items[i] = (*items)[i];
    }

    new_items[new_count - 1] = neoc_strdup(value);
    if (!new_items[new_count - 1]) {
        neoc_free(new_items);
        return NEOC_ERROR_OUT_OF_MEMORY;
    }

    if (*items) {
        neoc_free(*items);
    }

    *items = new_items;
    *count = new_count;
    return NEOC_SUCCESS;
}

neoc_error_t neoc_neo_version_set_protocol_info(neoc_neo_version_t *version,
                                                 uint32_t network,
                                                 uint32_t address_version,
                                                 uint32_t ms_per_block,
                                                 uint32_t max_transactions_per_block,
                                                 uint32_t memory_pool_max_transactions,
                                                 uint32_t max_trace_results,
                                                 uint64_t initial_gas_distribution) {
    return neoc_neo_version_set_protocol_config(version,
                                                network,
                                                address_version,
                                                ms_per_block,
                                                max_transactions_per_block,
                                                memory_pool_max_transactions,
                                                max_trace_results,
                                                initial_gas_distribution);
}

neoc_error_t neoc_neo_version_add_valid_signer(neoc_neo_version_t *version,
                                                const char *signer) {
    if (!version || !signer) {
        return NEOC_ERROR_INVALID_PARAM;
    }

    return neoc_append_string_item(&version->protocol.valid_signers,
                                   &version->protocol.valid_signers_count,
                                   signer);
}

neoc_error_t neoc_neo_version_add_committee_member(neoc_neo_version_t *version,
                                                    const char *member) {
    if (!version || !member) {
        return NEOC_ERROR_INVALID_PARAM;
    }

    return neoc_append_string_item(&version->protocol.committee_members,
                                   &version->protocol.committee_members_count,
                                   member);
}

neoc_error_t neoc_neo_version_add_seed_node(neoc_neo_version_t *version,
                                             const char *seed) {
    if (!version || !seed) {
        return NEOC_ERROR_INVALID_PARAM;
    }

    return neoc_append_string_item(&version->protocol.seed_list,
                                   &version->protocol.seed_list_count,
                                   seed);
}

bool neoc_neo_get_version_response_is_success(const neoc_neo_get_version_response_t *response) {
    return response && response->error == NULL && response->error_code == 0;
}

uint32_t neoc_neo_get_version_response_get_network(const neoc_neo_get_version_response_t *response) {
    if (!response || !response->result) {
        return 0;
    }

    return response->result->protocol.network;
}

static uint32_t neoc_read_u32_field(const neoc_json_t *object, const char *name) {
    int64_t value = 0;
    if (neoc_json_get_int(object, name, &value) == NEOC_SUCCESS && value >= 0) {
        return (uint32_t)value;
    }

    return 0;
}

static uint64_t neoc_read_u64_field(const neoc_json_t *object, const char *name) {
    int64_t value = 0;
    if (neoc_json_get_int(object, name, &value) == NEOC_SUCCESS && value >= 0) {
        return (uint64_t)value;
    }

    return 0;
}

static neoc_error_t neoc_add_json_string_array(neoc_json_t *parent,
                                                const char *name,
                                                char **values,
                                                size_t count) {
    if (!parent || !name) {
        return NEOC_ERROR_INVALID_PARAM;
    }

    neoc_json_t *array = neoc_json_create_array();
    if (!array) {
        return NEOC_ERROR_OUT_OF_MEMORY;
    }

#ifdef HAVE_CJSON
    for (size_t i = 0; i < count; i++) {
        if (!values || !values[i]) {
            continue;
        }

        cJSON *item = cJSON_CreateString(values[i]);
        if (!item) {
            neoc_json_free(array);
            return NEOC_ERROR_OUT_OF_MEMORY;
        }

        if (neoc_json_array_add(array, (neoc_json_t *)item) != NEOC_SUCCESS) {
            cJSON_Delete(item);
            neoc_json_free(array);
            return NEOC_ERROR_OUT_OF_MEMORY;
        }
    }
#else
    (void)values;
    (void)count;
#endif

    if (neoc_json_add_object(parent, name, array) != NEOC_SUCCESS) {
        neoc_json_free(array);
        return NEOC_ERROR_OUT_OF_MEMORY;
    }

    return NEOC_SUCCESS;
}

static neoc_error_t neoc_add_json_hardforks(neoc_json_t *parent,
                                             const neoc_hardfork_t *hardforks,
                                             size_t count) {
    if (!parent) {
        return NEOC_ERROR_INVALID_PARAM;
    }

    neoc_json_t *array = neoc_json_create_array();
    if (!array) {
        return NEOC_ERROR_OUT_OF_MEMORY;
    }

    for (size_t i = 0; i < count; i++) {
        if (!hardforks || !hardforks[i].name) {
            continue;
        }

        neoc_json_t *item = neoc_json_create_object();
        if (!item) {
            neoc_json_free(array);
            return NEOC_ERROR_OUT_OF_MEMORY;
        }

        if (neoc_json_add_string(item, "name", hardforks[i].name) != NEOC_SUCCESS ||
            neoc_json_add_int(item, "blockheight", (int64_t)hardforks[i].block_height) != NEOC_SUCCESS) {
            neoc_json_free(item);
            neoc_json_free(array);
            return NEOC_ERROR_OUT_OF_MEMORY;
        }

        if (neoc_json_array_add(array, item) != NEOC_SUCCESS) {
            neoc_json_free(item);
            neoc_json_free(array);
            return NEOC_ERROR_OUT_OF_MEMORY;
        }
    }

    if (neoc_json_add_object(parent, "hardforks", array) != NEOC_SUCCESS) {
        neoc_json_free(array);
        return NEOC_ERROR_OUT_OF_MEMORY;
    }

    return NEOC_SUCCESS;
}

neoc_error_t neoc_neo_get_version_response_to_json(const neoc_neo_get_version_response_t *response,
                                                    char **json_string) {
    if (!response || !json_string) {
        return NEOC_ERROR_INVALID_PARAM;
    }

    *json_string = NULL;

#ifndef HAVE_CJSON
    return NEOC_ERROR_NOT_IMPLEMENTED;
#else
    neoc_json_t *root = neoc_json_create_object();
    if (!root) {
        return NEOC_ERROR_OUT_OF_MEMORY;
    }

    if (response->jsonrpc) {
        neoc_json_add_string(root, "jsonrpc", response->jsonrpc);
    } else {
        neoc_json_add_string(root, "jsonrpc", "2.0");
    }
    neoc_json_add_int(root, "id", response->id);

    if (response->error) {
        neoc_json_t *error = neoc_json_create_object();
        if (!error) {
            neoc_json_free(root);
            return NEOC_ERROR_OUT_OF_MEMORY;
        }
        neoc_json_add_int(error, "code", response->error_code);
        neoc_json_add_string(error, "message", response->error);
        neoc_json_add_object(root, "error", error);
    } else if (response->result) {
        neoc_json_t *result = neoc_json_create_object();
        neoc_json_t *protocol = neoc_json_create_object();
        if (!result || !protocol) {
            if (result) {
                neoc_json_free(result);
            }
            if (protocol) {
                neoc_json_free(protocol);
            }
            neoc_json_free(root);
            return NEOC_ERROR_OUT_OF_MEMORY;
        }

        neoc_json_add_int(result, "tcpport", response->result->tcp_port);
        neoc_json_add_int(result, "wsport", response->result->ws_port);
        neoc_json_add_int(result, "nonce", response->result->nonce);
        if (response->result->user_agent) {
            neoc_json_add_string(result, "useragent", response->result->user_agent);
        }

        neoc_json_add_int(protocol, "network", response->result->protocol.network);
        neoc_json_add_int(protocol, "addressversion", response->result->protocol.address_version);
        neoc_json_add_int(protocol, "msperblock", response->result->protocol.ms_per_block);
        neoc_json_add_int(protocol,
                          "maxtransactionsperblock",
                          response->result->protocol.max_transactions_per_block);
        neoc_json_add_int(protocol,
                          "memorypoolmaxtransactions",
                          response->result->protocol.memory_pool_max_transactions);
        neoc_json_add_int(protocol,
                          "maxtraceableblocks",
                          response->result->protocol.max_trace_results);
        neoc_json_add_int(protocol,
                          "maxtraceresults",
                          response->result->protocol.max_trace_results);
        neoc_json_add_int(protocol,
                          "initialgasdistribution",
                          (int64_t)response->result->protocol.initial_gas_distribution);
        neoc_json_add_int(protocol,
                          "validatorscount",
                          response->result->protocol.validators_count);

        if (neoc_add_json_string_array(protocol,
                                       "validators",
                                       response->result->protocol.valid_signers,
                                       response->result->protocol.valid_signers_count) != NEOC_SUCCESS ||
            neoc_add_json_string_array(protocol,
                                       "standbycommittee",
                                       response->result->protocol.committee_members,
                                       response->result->protocol.committee_members_count) != NEOC_SUCCESS ||
            neoc_add_json_string_array(protocol,
                                       "seedlist",
                                       response->result->protocol.seed_list,
                                       response->result->protocol.seed_list_count) != NEOC_SUCCESS ||
            neoc_add_json_hardforks(protocol,
                                    response->result->protocol.hardforks,
                                    response->result->protocol.hardforks_count) != NEOC_SUCCESS) {
            neoc_json_free(protocol);
            neoc_json_free(result);
            neoc_json_free(root);
            return NEOC_ERROR_OUT_OF_MEMORY;
        }

        neoc_json_add_object(result, "protocol", protocol);
        neoc_json_add_object(root, "result", result);
    }

    *json_string = neoc_json_to_string(root);
    neoc_json_free(root);
    if (!*json_string) {
        return NEOC_ERROR_OUT_OF_MEMORY;
    }

    return NEOC_SUCCESS;
#endif
}

#ifdef HAVE_CJSON
static neoc_error_t neoc_parse_string_array(const neoc_json_t *array,
                                            neoc_neo_version_t *version,
                                            neoc_error_t (*add_fn)(neoc_neo_version_t *, const char *)) {
    if (!array || !version || !add_fn) {
        return NEOC_ERROR_INVALID_PARAM;
    }

    if (!neoc_json_is_array(array)) {
        return NEOC_SUCCESS;
    }

    size_t count = neoc_json_array_size(array);
    for (size_t i = 0; i < count; i++) {
        const cJSON *item = (const cJSON *)neoc_json_array_get(array, i);
        if (!item || !cJSON_IsString(item) || !item->valuestring) {
            continue;
        }

        neoc_error_t error = add_fn(version, item->valuestring);
        if (error != NEOC_SUCCESS) {
            return error;
        }
    }

    return NEOC_SUCCESS;
}

static neoc_error_t neoc_parse_hardforks(const neoc_json_t *array,
                                          neoc_neo_version_t *version) {
    if (!array || !version) {
        return NEOC_ERROR_INVALID_PARAM;
    }

    if (!neoc_json_is_array(array)) {
        return NEOC_SUCCESS;
    }

    size_t count = neoc_json_array_size(array);
    for (size_t i = 0; i < count; i++) {
        const cJSON *item = (const cJSON *)neoc_json_array_get(array, i);
        if (!item || !cJSON_IsObject(item)) {
            continue;
        }

        const cJSON *name = cJSON_GetObjectItemCaseSensitive(item, "name");
        const cJSON *height = cJSON_GetObjectItemCaseSensitive(item, "blockheight");
        if (!name || !cJSON_IsString(name) || !name->valuestring ||
            !height || !cJSON_IsNumber(height) || height->valuedouble < 0) {
            continue;
        }

        neoc_error_t error = neoc_neo_version_add_hardfork(version,
                                                           name->valuestring,
                                                           (uint32_t)height->valuedouble);
        if (error != NEOC_SUCCESS) {
            return error;
        }
    }

    return NEOC_SUCCESS;
}
#endif

neoc_error_t neoc_neo_get_version_response_from_json(const char *json_string,
                                                      neoc_neo_get_version_response_t **response) {
    if (!json_string || !response) {
        return NEOC_ERROR_INVALID_PARAM;
    }

    *response = NULL;

#ifndef HAVE_CJSON
    return NEOC_ERROR_NOT_IMPLEMENTED;
#else
    neoc_json_t *root = neoc_json_parse(json_string);
    if (!root) {
        return NEOC_ERROR_INVALID_FORMAT;
    }

    neoc_neo_get_version_response_t *parsed = neoc_calloc(1, sizeof(neoc_neo_get_version_response_t));
    if (!parsed) {
        neoc_json_free(root);
        return NEOC_ERROR_OUT_OF_MEMORY;
    }

    const char *jsonrpc = neoc_json_get_string(root, "jsonrpc");
    parsed->jsonrpc = neoc_strdup(jsonrpc ? jsonrpc : "2.0");
    if (!parsed->jsonrpc) {
        neoc_json_free(root);
        neoc_neo_get_version_response_free(parsed);
        return NEOC_ERROR_OUT_OF_MEMORY;
    }

    int64_t id_value = 0;
    if (neoc_json_get_int(root, "id", &id_value) == NEOC_SUCCESS) {
        parsed->id = (int)id_value;
    }

    neoc_json_t *error_obj = neoc_json_get_object(root, "error");
    if (error_obj) {
        int64_t error_code = 0;
        if (neoc_json_get_int(error_obj, "code", &error_code) == NEOC_SUCCESS) {
            parsed->error_code = (int)error_code;
        }
        const char *message = neoc_json_get_string(error_obj, "message");
        if (message) {
            parsed->error = neoc_strdup(message);
            if (!parsed->error) {
                neoc_json_free(root);
                neoc_neo_get_version_response_free(parsed);
                return NEOC_ERROR_OUT_OF_MEMORY;
            }
        }
    }

    neoc_json_t *result_obj = neoc_json_get_object(root, "result");
    if (!result_obj && neoc_json_get_object(root, "protocol")) {
        result_obj = root;
    }

    if (result_obj) {
        neoc_neo_version_t *version = NULL;
        neoc_error_t error = neoc_neo_version_create(&version);
        if (error != NEOC_SUCCESS) {
            neoc_json_free(root);
            neoc_neo_get_version_response_free(parsed);
            return error;
        }

        error = neoc_neo_version_set_basic_info(version,
                                                neoc_read_u32_field(result_obj, "tcpport"),
                                                neoc_read_u32_field(result_obj, "wsport"),
                                                neoc_read_u32_field(result_obj, "nonce"),
                                                neoc_json_get_string(result_obj, "useragent"));
        if (error != NEOC_SUCCESS) {
            neoc_neo_version_free(version);
            neoc_json_free(root);
            neoc_neo_get_version_response_free(parsed);
            return error;
        }

        neoc_json_t *protocol = neoc_json_get_object(result_obj, "protocol");
        if (!protocol) {
            protocol = result_obj;
        }

        uint32_t max_trace = neoc_read_u32_field(protocol, "maxtraceresults");
        if (max_trace == 0U) {
            max_trace = neoc_read_u32_field(protocol, "maxtraceableblocks");
        }

        error = neoc_neo_version_set_protocol_info(version,
                                                   neoc_read_u32_field(protocol, "network"),
                                                   neoc_read_u32_field(protocol, "addressversion"),
                                                   neoc_read_u32_field(protocol, "msperblock"),
                                                   neoc_read_u32_field(protocol, "maxtransactionsperblock"),
                                                   neoc_read_u32_field(protocol, "memorypoolmaxtransactions"),
                                                   max_trace,
                                                   neoc_read_u64_field(protocol, "initialgasdistribution"));
        if (error != NEOC_SUCCESS) {
            neoc_neo_version_free(version);
            neoc_json_free(root);
            neoc_neo_get_version_response_free(parsed);
            return error;
        }

        neoc_neo_version_set_validators_count(version,
                                              neoc_read_u32_field(protocol, "validatorscount"));

        neoc_json_t *validators = neoc_json_get_array(protocol, "validators");
        if (!validators) {
            validators = neoc_json_get_array(protocol, "validsigners");
        }
        if (validators) {
            error = neoc_parse_string_array(validators, version, neoc_neo_version_add_valid_signer);
            if (error != NEOC_SUCCESS) {
                neoc_neo_version_free(version);
                neoc_json_free(root);
                neoc_neo_get_version_response_free(parsed);
                return error;
            }
        }

        neoc_json_t *committee = neoc_json_get_array(protocol, "standbycommittee");
        if (!committee) {
            committee = neoc_json_get_array(protocol, "committee");
        }
        if (committee) {
            error = neoc_parse_string_array(committee, version, neoc_neo_version_add_committee_member);
            if (error != NEOC_SUCCESS) {
                neoc_neo_version_free(version);
                neoc_json_free(root);
                neoc_neo_get_version_response_free(parsed);
                return error;
            }
        }

        neoc_json_t *seedlist = neoc_json_get_array(protocol, "seedlist");
        if (seedlist) {
            error = neoc_parse_string_array(seedlist, version, neoc_neo_version_add_seed_node);
            if (error != NEOC_SUCCESS) {
                neoc_neo_version_free(version);
                neoc_json_free(root);
                neoc_neo_get_version_response_free(parsed);
                return error;
            }
        }

        neoc_json_t *hardforks = neoc_json_get_array(protocol, "hardforks");
        if (hardforks) {
            error = neoc_parse_hardforks(hardforks, version);
            if (error != NEOC_SUCCESS) {
                neoc_neo_version_free(version);
                neoc_json_free(root);
                neoc_neo_get_version_response_free(parsed);
                return error;
            }
        }

        parsed->result = version;
        if (!parsed->error) {
            parsed->error_code = 0;
        }
    }

    neoc_json_free(root);
    *response = parsed;
    return NEOC_SUCCESS;
#endif
}
