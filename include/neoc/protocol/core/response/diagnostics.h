/**
 * @file diagnostics.h
 * @brief Diagnostics structure for contract execution analysis
 * 
 * Converted from Swift source: protocol/core/response/Diagnostics.swift
 * Provides diagnostic information about contract invocations and storage changes.
 */

#ifndef NEOC_PROTOCOL_CORE_RESPONSE_DIAGNOSTICS_H
#define NEOC_PROTOCOL_CORE_RESPONSE_DIAGNOSTICS_H

#include "neoc/neoc_error.h"
#include "neoc/neoc_memory.h"
#include "neoc/types/hash160.h"
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declaration for recursive structure */
typedef struct neoc_invoked_contract neoc_invoked_contract_t;

/**
 * @brief Invoked contract structure (recursive)
 * 
 * Represents a contract that was invoked during execution,
 * including any contracts it subsequently invoked.
 */
struct neoc_invoked_contract {
    neoc_hash160_t *hash;               /**< Contract hash */
    neoc_invoked_contract_t *invoked_contracts; /**< Array of sub-invoked contracts */
    size_t invoked_contracts_count;     /**< Number of sub-invoked contracts */
};

/**
 * @brief Storage change structure
 * 
 * Represents a change to contract storage during execution.
 */
typedef struct {
    char *state;                        /**< Change state ("Changed", "Added", "Deleted") */
    char *key;                          /**< Storage key as hex string */
    char *value;                        /**< Storage value as hex string */
} neoc_storage_change_t;

/**
 * @brief Diagnostics structure
 * 
 * Contains diagnostic information about contract execution,
 * including invoked contracts and storage changes.
 */
typedef struct {
    neoc_invoked_contract_t *invoked_contracts; /**< Root invoked contract */
    neoc_storage_change_t *storage_changes;     /**< Array of storage changes */
    size_t storage_changes_count;               /**< Number of storage changes */
} neoc_diagnostics_t;

/* ========== Invoked Contract Functions ========== */

/**
 * @brief Create a new invoked contract
 * 
 * @param hash Contract hash
 * @param invoked_contracts Array of sub-invoked contracts (can be NULL)
 * @param invoked_contracts_count Number of sub-invoked contracts
 * @param contract Output pointer for the created contract (caller must free)
 * @return NEOC_SUCCESS on success, error code on failure
 */
neoc_error_t neoc_invoked_contract_create(
    const neoc_hash160_t *hash,
    const neoc_invoked_contract_t *invoked_contracts,
    size_t invoked_contracts_count,
    neoc_invoked_contract_t **contract
);

/**
 * @brief Free an invoked contract (recursive)
 * 
 * @param contract Contract to free (can be NULL)
 */
void neoc_invoked_contract_free(
    neoc_invoked_contract_t *contract
);

/**
 * @brief Create a copy of an invoked contract (deep copy)
 * 
 * @param src Source contract to copy
 * @param dest Output pointer for the copied contract (caller must free)
 * @return NEOC_SUCCESS on success, error code on failure
 */
neoc_error_t neoc_invoked_contract_copy(
    const neoc_invoked_contract_t *src,
    neoc_invoked_contract_t **dest
);

/* ========== Storage Change Functions ========== */

/**
 * @brief Create a new storage change
 * 
 * @param state Change state string
 * @param key Storage key as hex string
 * @param value Storage value as hex string
 * @param change Output pointer for the created change (caller must free)
 * @return NEOC_SUCCESS on success, error code on failure
 */
neoc_error_t neoc_storage_change_create(
    const char *state,
    const char *key,
    const char *value,
    neoc_storage_change_t **change
);

/**
 * @brief Free a storage change
 * 
 * @param change Change to free (can be NULL)
 */
void neoc_storage_change_free(
    neoc_storage_change_t *change
);

/**
 * @brief Create a copy of a storage change
 * 
 * @param src Source change to copy
 * @param dest Output pointer for the copied change (caller must free)
 * @return NEOC_SUCCESS on success, error code on failure
 */
neoc_error_t neoc_storage_change_copy(
    const neoc_storage_change_t *src,
    neoc_storage_change_t **dest
);

/* ========== Diagnostics Functions ========== */

/**
 * @brief Create new diagnostics
 * 
 * @param invoked_contracts Root invoked contract
 * @param storage_changes Array of storage changes (can be NULL)
 * @param storage_changes_count Number of storage changes
 * @param diagnostics Output pointer for the created diagnostics (caller must free)
 * @return NEOC_SUCCESS on success, error code on failure
 */
neoc_error_t neoc_diagnostics_create(
    const neoc_invoked_contract_t *invoked_contracts,
    const neoc_storage_change_t *storage_changes,
    size_t storage_changes_count,
    neoc_diagnostics_t **diagnostics
);

/**
 * @brief Free diagnostics
 * 
 * @param diagnostics Diagnostics to free (can be NULL)
 */
void neoc_diagnostics_free(
    neoc_diagnostics_t *diagnostics
);

/**
 * @brief Clone diagnostics (deep copy)
 *
 * @param diagnostics Diagnostics to clone
 * @return Newly allocated diagnostics on success, NULL on failure
 */
neoc_diagnostics_t* neoc_diagnostics_clone(
    const neoc_diagnostics_t *diagnostics
);

/**
 * @brief Parse diagnostics from JSON string
 * 
 * @param json_str JSON string containing diagnostics data
 * @param diagnostics Output pointer for the parsed diagnostics (caller must free)
 * @return NEOC_SUCCESS on success, error code on failure
 */
neoc_error_t neoc_diagnostics_from_json(
    const char *json_str,
    neoc_diagnostics_t **diagnostics
);

/**
 * @brief Convert diagnostics to JSON string
 * 
 * @param diagnostics Diagnostics to convert
 * @param json_str Output pointer for JSON string (caller must free)
 * @return NEOC_SUCCESS on success, error code on failure
 */
neoc_error_t neoc_diagnostics_to_json(
    const neoc_diagnostics_t *diagnostics,
    char **json_str
);

/**
 * @brief Get total number of contracts invoked (recursive count)
 * 
 * @param contract Root invoked contract
 * @return Total number of contracts invoked
 */
size_t neoc_invoked_contract_get_total_count(
    const neoc_invoked_contract_t *contract
);

/**
 * @brief Check if a specific contract was invoked
 * 
 * @param contract Root invoked contract
 * @param target_hash Hash to search for
 * @return true if contract was invoked, false otherwise
 */
bool neoc_invoked_contract_contains_hash(
    const neoc_invoked_contract_t *contract,
    const neoc_hash160_t *target_hash
);

#ifdef __cplusplus
}
#endif

#endif /* NEOC_PROTOCOL_CORE_RESPONSE_DIAGNOSTICS_H */
