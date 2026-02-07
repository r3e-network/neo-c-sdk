/**
 * @file policy_contract.h
 * @brief Complete implementation for policy_contract
 */

#ifndef NEOC_policy_contract_H_GUARD
#define NEOC_policy_contract_H_GUARD

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "neoc/neoc_error.h"
#include "neoc/types/neoc_hash160.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Policy contract opaque type
 */
typedef struct neoc_policy_contract neoc_policy_contract_t;

/**
 * @brief Create policy contract instance
 * 
 * @param policy Output policy contract (caller must free)
 * @return NEOC_SUCCESS on success, error code otherwise
 */
neoc_error_t neoc_policy_contract_create(neoc_policy_contract_t **policy);

/**
 * @brief Get fee per byte
 * 
 * @param policy Policy contract instance
 * @param fee Output fee per byte
 * @return NEOC_SUCCESS on success, error code otherwise
 */
neoc_error_t neoc_policy_get_fee_per_byte(neoc_policy_contract_t *policy,
                                           uint64_t *fee);

/**
 * @brief Get execution fee factor
 * 
 * @param policy Policy contract instance
 * @param factor Output execution fee factor
 * @return NEOC_SUCCESS on success, error code otherwise
 */
neoc_error_t neoc_policy_get_exec_fee_factor(neoc_policy_contract_t *policy,
                                              uint32_t *factor);

/**
 * @brief Get storage price
 * 
 * @param policy Policy contract instance
 * @param price Output storage price
 * @return NEOC_SUCCESS on success, error code otherwise
 */
neoc_error_t neoc_policy_get_storage_price(neoc_policy_contract_t *policy,
                                            uint32_t *price);

/**
 * @brief Set fee per byte
 *
 * Updates the cached fee per byte value (committee operation placeholder).
 *
 * @param policy Policy contract instance
 * @param fee New fee per byte
 * @return NEOC_SUCCESS on success, error code otherwise
 */
neoc_error_t neoc_policy_set_fee_per_byte(neoc_policy_contract_t *policy,
                                           uint64_t fee);

/**
 * @brief Check if account is blocked
 * 
 * @param policy Policy contract instance
 * @param account Account to check
 * @param blocked Output blocked status
 * @return NEOC_SUCCESS on success, error code otherwise
 */
neoc_error_t neoc_policy_is_blocked(neoc_policy_contract_t *policy,
                                     const neoc_hash160_t *account,
                                     bool *blocked);

/**
 * @brief Set execution fee factor (committee operation)
 */
neoc_error_t neoc_policy_set_exec_fee_factor(neoc_policy_contract_t *policy,
                                              uint32_t factor);

/**
 * @brief Set storage price (committee operation)
 */
neoc_error_t neoc_policy_set_storage_price(neoc_policy_contract_t *policy,
                                            uint32_t price);

/**
 * @brief Block an account (committee operation)
 *
 * Note: In Neo v3.9.1, blocking an account also clears its votes.
 */
neoc_error_t neoc_policy_block_account(neoc_policy_contract_t *policy,
                                        const neoc_hash160_t *account);

/**
 * @brief Unblock an account (committee operation)
 */
neoc_error_t neoc_policy_unblock_account(neoc_policy_contract_t *policy,
                                          const neoc_hash160_t *account);

/**
 * @brief Get whitelist fee contracts (v3.9.1)
 *
 * Returns the list of contract hashes that are exempt from system fee.
 *
 * @param policy Policy contract instance
 * @param hashes Output array of contract hashes (caller must free with neoc_free)
 * @param count Output number of hashes
 * @return NEOC_SUCCESS on success, error code otherwise
 */
neoc_error_t neoc_policy_get_whitelist_fee_contracts(neoc_policy_contract_t *policy,
                                                      neoc_hash160_t **hashes,
                                                      size_t *count);

/**
 * @brief Set whitelist fee contract entry (v3.9.1, committee operation)
 *
 * Adds/updates a whitelist entry identified by `(contract, method, arg_count)`
 * and assigns a fixed fee.
 *
 * @param policy Policy contract instance
 * @param contract_hash Target contract hash
 * @param method Target method name
 * @param arg_count Target method argument count
 * @param fixed_fee Fixed fee to apply (0 allowed)
 * @return NEOC_SUCCESS on success, error code otherwise
 */
neoc_error_t neoc_policy_set_whitelist_fee_contract(neoc_policy_contract_t *policy,
                                                     const neoc_hash160_t *contract_hash,
                                                     const char *method,
                                                     int32_t arg_count,
                                                     int64_t fixed_fee);

/**
 * @brief Remove whitelist fee contract entry (v3.9.1, committee operation)
 *
 * Removes a whitelist entry identified by `(contract, method, arg_count)`.
 *
 * @param policy Policy contract instance
 * @param contract_hash Target contract hash
 * @param method Target method name
 * @param arg_count Target method argument count
 * @return NEOC_SUCCESS on success, error code otherwise
 */
neoc_error_t neoc_policy_remove_whitelist_fee_contract(neoc_policy_contract_t *policy,
                                                        const neoc_hash160_t *contract_hash,
                                                        const char *method,
                                                        int32_t arg_count);

/**
 * @brief Free policy contract
 * 
 * @param policy Policy contract to free
 */
void neoc_policy_contract_free(neoc_policy_contract_t *policy);

#ifdef __cplusplus
}
#endif

#endif // NEOC_policy_contract_H_GUARD
