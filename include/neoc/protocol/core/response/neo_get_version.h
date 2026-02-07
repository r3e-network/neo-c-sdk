/**
 * @file neo_get_version.h
 * @brief Neo node version information response
 * 
 * Based on Swift source: protocol/core/response/NeoGetVersion.swift
 * Response structure for getversion RPC call
 */

#ifndef NEOC_PROTOCOL_CORE_RESPONSE_NEO_GET_VERSION_H
#define NEOC_PROTOCOL_CORE_RESPONSE_NEO_GET_VERSION_H

#include "neoc/neoc_error.h"
#include "neoc/neoc_memory.h"
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Hardfork entry for Neo protocol version tracking
 *
 * Neo v3.9.1 added hardfork information to the getversion response.
 */
typedef struct {
    char *name;                          /**< Hardfork name (e.g. "HF_Aspidochelone") */
    uint32_t block_height;              /**< Block height at which hardfork activates */
} neoc_hardfork_t;

/**
 * @brief Neo node version information
 *
 * Contains comprehensive version and protocol information about the Neo node.
 * Updated for Neo N3 v3.9.1 compatibility.
 */
typedef struct {
    uint32_t tcp_port;                   /**< TCP port for P2P network */
    uint32_t ws_port;                    /**< WebSocket port */
    uint32_t nonce;                      /**< Random nonce */
    char *user_agent;                    /**< Node user agent string */
    struct {
        uint32_t network;                /**< Network magic number */
        uint32_t address_version;        /**< Address version byte */
        uint32_t ms_per_block;           /**< Milliseconds per block */
        uint32_t max_transactions_per_block; /**< Max transactions per block */
        uint32_t memory_pool_max_transactions; /**< Memory pool max size */
        uint32_t max_trace_results;      /**< Maximum trace results */
        uint64_t initial_gas_distribution; /**< Initial GAS distribution */
        uint32_t validators_count;       /**< Number of consensus validators (v3.9.1) */
        neoc_hardfork_t *hardforks;      /**< Hardfork entries (v3.9.1) */
        size_t hardforks_count;          /**< Number of hardfork entries */
        char **valid_signers;            /**< Valid signers array */
        size_t valid_signers_count;      /**< Number of valid signers */
        char **committee_members;        /**< Committee members */
        size_t committee_members_count;  /**< Number of committee members */
        char **seed_list;                /**< Seed node list */
        size_t seed_list_count;          /**< Number of seed nodes */
    } protocol;
} neoc_neo_version_t;

/**
 * @brief Complete response for getversion RPC call
 * 
 * Standard JSON-RPC response structure containing version information
 */
typedef struct {
    char *jsonrpc;                       /**< JSON-RPC version ("2.0") */
    int id;                              /**< Request ID */
    neoc_neo_version_t *result;          /**< Version result (NULL if error) */
    char *error;                         /**< Error message (NULL if success) */
    int error_code;                      /**< Error code (0 if success) */
} neoc_neo_get_version_response_t;

/**
 * @brief Create Neo version structure
 * 
 * @param version Output version structure (caller must free)
 * @return NEOC_SUCCESS on success, error code otherwise
 */
neoc_error_t neoc_neo_version_create(neoc_neo_version_t **version);

/**
 * @brief Set basic version information
 * 
 * @param version The version structure
 * @param tcp_port TCP port
 * @param ws_port WebSocket port
 * @param nonce Random nonce
 * @param user_agent User agent string
 * @return NEOC_SUCCESS on success, error code otherwise
 */
neoc_error_t neoc_neo_version_set_basic_info(neoc_neo_version_t *version,
                                              uint32_t tcp_port,
                                              uint32_t ws_port,
                                              uint32_t nonce,
                                              const char *user_agent);

/**
 * @brief Set protocol information
 * 
 * @param version The version structure
 * @param network Network magic number
 * @param address_version Address version byte
 * @param ms_per_block Milliseconds per block
 * @param max_transactions_per_block Max transactions per block
 * @param memory_pool_max_transactions Memory pool max size
 * @param max_trace_results Max trace results
 * @param initial_gas_distribution Initial GAS distribution
 * @return NEOC_SUCCESS on success, error code otherwise
 */
neoc_error_t neoc_neo_version_set_protocol_info(neoc_neo_version_t *version,
                                                 uint32_t network,
                                                 uint32_t address_version,
                                                 uint32_t ms_per_block,
                                                 uint32_t max_transactions_per_block,
                                                 uint32_t memory_pool_max_transactions,
                                                 uint32_t max_trace_results,
                                                 uint64_t initial_gas_distribution);

/**
 * @brief Add valid signer to protocol information
 * 
 * @param version The version structure
 * @param signer Valid signer address
 * @return NEOC_SUCCESS on success, error code otherwise
 */
neoc_error_t neoc_neo_version_add_valid_signer(neoc_neo_version_t *version,
                                                const char *signer);

/**
 * @brief Add committee member to protocol information
 * 
 * @param version The version structure
 * @param member Committee member public key
 * @return NEOC_SUCCESS on success, error code otherwise
 */
neoc_error_t neoc_neo_version_add_committee_member(neoc_neo_version_t *version,
                                                    const char *member);

/**
 * @brief Add seed node to protocol information
 * 
 * @param version The version structure
 * @param seed Seed node address
 * @return NEOC_SUCCESS on success, error code otherwise
 */
neoc_error_t neoc_neo_version_add_seed_node(neoc_neo_version_t *version,
                                             const char *seed);

/**
 * @brief Set validators count (v3.9.1)
 *
 * @param version The version structure
 * @param count Number of consensus validators
 * @return NEOC_SUCCESS on success, error code otherwise
 */
neoc_error_t neoc_neo_version_set_validators_count(neoc_neo_version_t *version,
                                                    uint32_t count);

/**
 * @brief Add a hardfork entry (v3.9.1)
 *
 * @param version The version structure
 * @param name Hardfork name (e.g. "HF_Aspidochelone")
 * @param block_height Activation block height
 * @return NEOC_SUCCESS on success, error code otherwise
 */
neoc_error_t neoc_neo_version_add_hardfork(neoc_neo_version_t *version,
                                            const char *name,
                                            uint32_t block_height);

/**
 * @brief Free hardfork entry resources
 *
 * @param hardfork The hardfork entry to free (does not free the struct itself)
 */
void neoc_hardfork_cleanup(neoc_hardfork_t *hardfork);

/**
 * @brief Create version response
 * 
 * @param id Request ID
 * @param result Version result (can be NULL for error response)
 * @param error Error message (can be NULL for success response)
 * @param error_code Error code (0 for success)
 * @param response Output response (caller must free)
 * @return NEOC_SUCCESS on success, error code otherwise
 */
neoc_error_t neoc_neo_get_version_response_create(int id,
                                                   neoc_neo_version_t *result,
                                                   const char *error,
                                                   int error_code,
                                                   neoc_neo_get_version_response_t **response);

/**
 * @brief Parse version response from JSON
 * 
 * @param json_string JSON response string
 * @param response Output parsed response (caller must free)
 * @return NEOC_SUCCESS on success, error code otherwise
 */
neoc_error_t neoc_neo_get_version_response_from_json(const char *json_string,
                                                      neoc_neo_get_version_response_t **response);

/**
 * @brief Convert version response to JSON
 * 
 * @param response The response to convert
 * @param json_string Output JSON string (caller must free)
 * @return NEOC_SUCCESS on success, error code otherwise
 */
neoc_error_t neoc_neo_get_version_response_to_json(const neoc_neo_get_version_response_t *response,
                                                    char **json_string);

/**
 * @brief Check if response indicates success
 * 
 * @param response The response to check
 * @return True if response is successful
 */
bool neoc_neo_get_version_response_is_success(const neoc_neo_get_version_response_t *response);

/**
 * @brief Get network type from version response
 * 
 * @param response The version response
 * @return Network magic number, or 0 if error
 */
uint32_t neoc_neo_get_version_response_get_network(const neoc_neo_get_version_response_t *response);

/**
 * @brief Check if node supports specific protocol version
 * 
 * @param version The version structure
 * @param required_version Required protocol version
 * @return True if supported
 */
bool neoc_neo_version_supports_protocol(const neoc_neo_version_t *version,
                                         const char *required_version);

/**
 * @brief Copy Neo version structure
 * 
 * @param source Source version
 * @param copy Output copied version (caller must free)
 * @return NEOC_SUCCESS on success, error code otherwise
 */
neoc_error_t neoc_neo_version_copy(const neoc_neo_version_t *source,
                                    neoc_neo_version_t **copy);

/**
 * @brief Free Neo version structure
 * 
 * @param version The version to free
 */
void neoc_neo_version_free(neoc_neo_version_t *version);

/**
 * @brief Free version response
 * 
 * @param response The response to free
 */
void neoc_neo_get_version_response_free(neoc_neo_get_version_response_t *response);

#ifdef __cplusplus
}
#endif

#endif /* NEOC_PROTOCOL_CORE_RESPONSE_NEO_GET_VERSION_H */
