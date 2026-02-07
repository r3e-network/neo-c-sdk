/**
 * @file contract_parameter.h
 * @brief Backwards compatible contract parameter helpers
 *
 * The NeoC SDK uses the canonical contract parameter representation from
 * `neoc/contract/contract_parameter.h`. This header preserves older helper
 * creation APIs that were previously exposed under `neoc/types/`.
 */

#ifndef NEOC_TYPES_CONTRACT_PARAMETER_H
#define NEOC_TYPES_CONTRACT_PARAMETER_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#include "neoc/neoc_error.h"
#include "neoc/types/contract_parameter_type.h"
#include "neoc/contract/contract_parameter.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Legacy helper to create a contract parameter from a raw value.
 *
 * This function exists for backwards compatibility. For new code, prefer the
 * typed constructors in `neoc/contract/contract_parameter.h`.
 *
 * @param type Parameter type
 * @param name Optional parameter name
 * @param value Parameter value bytes or string (depending on type)
 * @param value_size Size of @p value
 * @param param Output parameter (caller must free with neoc_contract_parameter_free)
 * @return NEOC_SUCCESS on success, error code otherwise
 */
neoc_error_t neoc_contract_parameter_create(neoc_contract_parameter_type_t type,
                                           const char *name,
                                           const void *value,
                                           size_t value_size,
                                           neoc_contract_parameter_t **param);

/**
 * @brief Free a contract parameter allocated by neoc_contract_parameter_create.
 *
 * This is an alias for neoc_contract_param_free().
 */
void neoc_contract_parameter_free(neoc_contract_parameter_t *param);

neoc_error_t neoc_contract_parameter_create_bool(bool value, neoc_contract_parameter_t **param);
neoc_error_t neoc_contract_parameter_create_int(int64_t value, neoc_contract_parameter_t **param);
neoc_error_t neoc_contract_parameter_create_string(const char *value, neoc_contract_parameter_t **param);
neoc_error_t neoc_contract_parameter_create_bytes(const uint8_t *value,
                                                  size_t len,
                                                  neoc_contract_parameter_t **param);

#ifdef __cplusplus
}
#endif

#endif /* NEOC_TYPES_CONTRACT_PARAMETER_H */

