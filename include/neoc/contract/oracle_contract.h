/**
 * @file oracle_contract.h
 * @brief NEO Oracle native contract wrapper
 */

#ifndef NEOC_ORACLE_CONTRACT_H_GUARD
#define NEOC_ORACLE_CONTRACT_H_GUARD

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "neoc/neoc_error.h"
#include "neoc/types/neoc_hash160.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Oracle contract opaque type
 */
typedef struct neoc_oracle_contract neoc_oracle_contract_t;

/**
 * @brief Create oracle contract instance
 *
 * @param oracle Output oracle contract (caller must free)
 * @return NEOC_SUCCESS on success, error code otherwise
 */
neoc_error_t neoc_oracle_contract_create(neoc_oracle_contract_t **oracle);

/**
 * @brief Get oracle request price
 *
 * @param oracle Oracle contract instance
 * @param price Output price in GAS fractions
 * @return NEOC_SUCCESS on success, error code otherwise
 */
neoc_error_t neoc_oracle_get_price(neoc_oracle_contract_t *oracle,
                                    uint64_t *price);

/**
 * @brief Set oracle request price (committee operation)
 *
 * @param oracle Oracle contract instance
 * @param price New price in GAS fractions
 * @return NEOC_SUCCESS on success, error code otherwise
 */
neoc_error_t neoc_oracle_set_price(neoc_oracle_contract_t *oracle,
                                    uint64_t price);

/**
 * @brief Free oracle contract
 *
 * @param oracle Oracle contract to free
 */
void neoc_oracle_contract_free(neoc_oracle_contract_t *oracle);

#ifdef __cplusplus
}
#endif

#endif /* NEOC_ORACLE_CONTRACT_H_GUARD */
