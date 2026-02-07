/**
 * @file ledger_contract.h
 * @brief NEO Ledger native contract wrapper
 */

#ifndef NEOC_LEDGER_CONTRACT_H_GUARD
#define NEOC_LEDGER_CONTRACT_H_GUARD

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "neoc/neoc_error.h"
#include "neoc/types/neoc_hash160.h"
#include "neoc/types/neoc_hash256.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Ledger contract opaque type
 */
typedef struct neoc_ledger_contract neoc_ledger_contract_t;

/**
 * @brief Create ledger contract instance
 *
 * @param ledger Output ledger contract (caller must free)
 * @return NEOC_SUCCESS on success, error code otherwise
 */
neoc_error_t neoc_ledger_contract_create(neoc_ledger_contract_t **ledger);

/**
 * @brief Build script for currentHash
 *
 * Returns the hash of the latest block in the blockchain.
 *
 * @param ledger Ledger contract instance
 * @param script Output script bytes (caller must free)
 * @param script_len Output script length
 * @return NEOC_SUCCESS on success, error code otherwise
 */
neoc_error_t neoc_ledger_current_hash(neoc_ledger_contract_t *ledger,
                                       uint8_t **script,
                                       size_t *script_len);

/**
 * @brief Build script for currentIndex
 *
 * Returns the index (height) of the latest block in the blockchain.
 *
 * @param ledger Ledger contract instance
 * @param script Output script bytes (caller must free)
 * @param script_len Output script length
 * @return NEOC_SUCCESS on success, error code otherwise
 */
neoc_error_t neoc_ledger_current_index(neoc_ledger_contract_t *ledger,
                                        uint8_t **script,
                                        size_t *script_len);

/**
 * @brief Build script for getBlock by index
 *
 * @param ledger Ledger contract instance
 * @param index Block index (height)
 * @param script Output script bytes (caller must free)
 * @param script_len Output script length
 * @return NEOC_SUCCESS on success, error code otherwise
 */
neoc_error_t neoc_ledger_get_block(neoc_ledger_contract_t *ledger,
                                    uint32_t index,
                                    uint8_t **script,
                                    size_t *script_len);

/**
 * @brief Build script for getTransaction by hash
 *
 * @param ledger Ledger contract instance
 * @param hash Transaction hash
 * @param script Output script bytes (caller must free)
 * @param script_len Output script length
 * @return NEOC_SUCCESS on success, error code otherwise
 */
neoc_error_t neoc_ledger_get_transaction(neoc_ledger_contract_t *ledger,
                                          const neoc_hash256_t *hash,
                                          uint8_t **script,
                                          size_t *script_len);

/**
 * @brief Build script for getTransactionHeight by hash
 *
 * @param ledger Ledger contract instance
 * @param hash Transaction hash
 * @param script Output script bytes (caller must free)
 * @param script_len Output script length
 * @return NEOC_SUCCESS on success, error code otherwise
 */
neoc_error_t neoc_ledger_get_transaction_height(neoc_ledger_contract_t *ledger,
                                                 const neoc_hash256_t *hash,
                                                 uint8_t **script,
                                                 size_t *script_len);

/**
 * @brief Free ledger contract
 *
 * @param ledger Ledger contract to free
 */
void neoc_ledger_contract_free(neoc_ledger_contract_t *ledger);

#ifdef __cplusplus
}
#endif

#endif /* NEOC_LEDGER_CONTRACT_H_GUARD */
