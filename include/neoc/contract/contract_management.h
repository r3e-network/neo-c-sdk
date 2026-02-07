/**
 * @file contract_management.h
 * @brief NEO ContractManagement native contract wrapper
 */

#ifndef NEOC_CONTRACT_MANAGEMENT_H_GUARD
#define NEOC_CONTRACT_MANAGEMENT_H_GUARD

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "neoc/neoc_error.h"
#include "neoc/types/neoc_hash160.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief ContractManagement contract opaque type
 */
typedef struct neoc_contract_management neoc_contract_management_t;

/**
 * @brief Create ContractManagement contract instance
 *
 * @param mgmt Output contract management instance (caller must free)
 * @return NEOC_SUCCESS on success, error code otherwise
 */
neoc_error_t neoc_contract_management_create(neoc_contract_management_t **mgmt);

/**
 * @brief Get minimum deployment fee
 *
 * @param mgmt ContractManagement instance
 * @param fee Output minimum deployment fee in GAS fractions
 * @return NEOC_SUCCESS on success, error code otherwise
 */
neoc_error_t neoc_contract_management_get_minimum_deployment_fee(
    neoc_contract_management_t *mgmt, uint64_t *fee);

/**
 * @brief Check if a contract has a specific method
 *
 * Builds a script that invokes the "hasMethod" operation on the
 * ContractManagement native contract.
 *
 * @param mgmt ContractManagement instance
 * @param hash Script hash of the contract to query
 * @param method Method name to check
 * @param param_count Expected parameter count of the method
 * @param script Output script bytes (caller must free)
 * @param script_len Output script length
 * @return NEOC_SUCCESS on success, error code otherwise
 */
neoc_error_t neoc_contract_management_has_method(
    neoc_contract_management_t *mgmt, const neoc_hash160_t *hash,
    const char *method, uint32_t param_count,
    uint8_t **script, size_t *script_len);

/**
 * @brief Get contract state by script hash
 *
 * Builds a script that invokes the "getContract" operation on the
 * ContractManagement native contract.
 *
 * @param mgmt ContractManagement instance
 * @param hash Script hash of the contract to query
 * @param script Output script bytes (caller must free)
 * @param script_len Output script length
 * @return NEOC_SUCCESS on success, error code otherwise
 */
neoc_error_t neoc_contract_management_get_contract(
    neoc_contract_management_t *mgmt, const neoc_hash160_t *hash,
    uint8_t **script, size_t *script_len);

/**
 * @brief Free ContractManagement contract instance
 *
 * @param mgmt Instance to free
 */
void neoc_contract_management_free(neoc_contract_management_t *mgmt);

#ifdef __cplusplus
}
#endif

#endif // NEOC_CONTRACT_MANAGEMENT_H_GUARD
