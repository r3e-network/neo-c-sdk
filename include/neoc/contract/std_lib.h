/**
 * @file std_lib.h
 * @brief NEO StdLib native contract wrapper
 */

#ifndef NEOC_STD_LIB_H_GUARD
#define NEOC_STD_LIB_H_GUARD

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "neoc/neoc_error.h"
#include "neoc/types/neoc_hash160.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief StdLib contract opaque type
 */
typedef struct neoc_std_lib neoc_std_lib_t;

/**
 * @brief Create StdLib contract instance
 *
 * @param lib Output StdLib contract (caller must free)
 * @return NEOC_SUCCESS on success, error code otherwise
 */
neoc_error_t neoc_std_lib_create(neoc_std_lib_t **lib);

/**
 * @brief Build invocation script for serialize
 *
 * @param lib StdLib contract instance
 * @param data Data to serialize
 * @param data_len Length of data
 * @param script Output script bytes (caller must free)
 * @param script_len Output script length
 * @return NEOC_SUCCESS on success, error code otherwise
 */
neoc_error_t neoc_std_lib_serialize(neoc_std_lib_t *lib,
                                    const uint8_t *data, size_t data_len,
                                    uint8_t **script, size_t *script_len);

/**
 * @brief Build invocation script for deserialize
 *
 * @param lib StdLib contract instance
 * @param data Data to deserialize
 * @param data_len Length of data
 * @param script Output script bytes (caller must free)
 * @param script_len Output script length
 * @return NEOC_SUCCESS on success, error code otherwise
 */
neoc_error_t neoc_std_lib_deserialize(neoc_std_lib_t *lib,
                                      const uint8_t *data, size_t data_len,
                                      uint8_t **script, size_t *script_len);

/**
 * @brief Build invocation script for jsonSerialize
 *
 * @param lib StdLib contract instance
 * @param data Data to JSON-serialize
 * @param data_len Length of data
 * @param script Output script bytes (caller must free)
 * @param script_len Output script length
 * @return NEOC_SUCCESS on success, error code otherwise
 */
neoc_error_t neoc_std_lib_json_serialize(neoc_std_lib_t *lib,
                                         const uint8_t *data, size_t data_len,
                                         uint8_t **script, size_t *script_len);

/**
 * @brief Build invocation script for jsonDeserialize
 *
 * @param lib StdLib contract instance
 * @param json_str JSON string to deserialize
 * @param script Output script bytes (caller must free)
 * @param script_len Output script length
 * @return NEOC_SUCCESS on success, error code otherwise
 */
neoc_error_t neoc_std_lib_json_deserialize(neoc_std_lib_t *lib,
                                            const char *json_str,
                                            uint8_t **script, size_t *script_len);

/**
 * @brief Build invocation script for base64Encode
 *
 * @param lib StdLib contract instance
 * @param data Data to encode
 * @param data_len Length of data
 * @param script Output script bytes (caller must free)
 * @param script_len Output script length
 * @return NEOC_SUCCESS on success, error code otherwise
 */
neoc_error_t neoc_std_lib_base64_encode(neoc_std_lib_t *lib,
                                         const uint8_t *data, size_t data_len,
                                         uint8_t **script, size_t *script_len);

/**
 * @brief Build invocation script for base64Decode
 *
 * @param lib StdLib contract instance
 * @param encoded Base64-encoded string to decode
 * @param script Output script bytes (caller must free)
 * @param script_len Output script length
 * @return NEOC_SUCCESS on success, error code otherwise
 */
neoc_error_t neoc_std_lib_base64_decode(neoc_std_lib_t *lib,
                                         const char *encoded,
                                         uint8_t **script, size_t *script_len);

/**
 * @brief Build invocation script for base58Encode
 *
 * @param lib StdLib contract instance
 * @param data Data to encode
 * @param data_len Length of data
 * @param script Output script bytes (caller must free)
 * @param script_len Output script length
 * @return NEOC_SUCCESS on success, error code otherwise
 */
neoc_error_t neoc_std_lib_base58_encode(neoc_std_lib_t *lib,
                                         const uint8_t *data, size_t data_len,
                                         uint8_t **script, size_t *script_len);

/**
 * @brief Build invocation script for base58Decode
 *
 * @param lib StdLib contract instance
 * @param encoded Base58-encoded string to decode
 * @param script Output script bytes (caller must free)
 * @param script_len Output script length
 * @return NEOC_SUCCESS on success, error code otherwise
 */
neoc_error_t neoc_std_lib_base58_decode(neoc_std_lib_t *lib,
                                         const char *encoded,
                                         uint8_t **script, size_t *script_len);

/**
 * @brief Build invocation script for itoa
 *
 * @param lib StdLib contract instance
 * @param value Integer value to convert
 * @param base Numeric base for conversion
 * @param script Output script bytes (caller must free)
 * @param script_len Output script length
 * @return NEOC_SUCCESS on success, error code otherwise
 */
neoc_error_t neoc_std_lib_itoa(neoc_std_lib_t *lib,
                                int64_t value, uint32_t base,
                                uint8_t **script, size_t *script_len);

/**
 * @brief Build invocation script for atoi
 *
 * @param lib StdLib contract instance
 * @param str String to convert
 * @param base Numeric base for conversion
 * @param script Output script bytes (caller must free)
 * @param script_len Output script length
 * @return NEOC_SUCCESS on success, error code otherwise
 */
neoc_error_t neoc_std_lib_atoi(neoc_std_lib_t *lib,
                                const char *str, uint32_t base,
                                uint8_t **script, size_t *script_len);

/**
 * @brief Build invocation script for memoryCompare
 *
 * @param lib StdLib contract instance
 * @param a First buffer
 * @param a_len Length of first buffer
 * @param b Second buffer
 * @param b_len Length of second buffer
 * @param script Output script bytes (caller must free)
 * @param script_len Output script length
 * @return NEOC_SUCCESS on success, error code otherwise
 */
neoc_error_t neoc_std_lib_memory_compare(neoc_std_lib_t *lib,
                                          const uint8_t *a, size_t a_len,
                                          const uint8_t *b, size_t b_len,
                                          uint8_t **script, size_t *script_len);

/**
 * @brief Build invocation script for memorySearch
 *
 * @param lib StdLib contract instance
 * @param mem Memory buffer to search in
 * @param mem_len Length of memory buffer
 * @param value Value to search for
 * @param value_len Length of value
 * @param script Output script bytes (caller must free)
 * @param script_len Output script length
 * @return NEOC_SUCCESS on success, error code otherwise
 */
neoc_error_t neoc_std_lib_memory_search(neoc_std_lib_t *lib,
                                         const uint8_t *mem, size_t mem_len,
                                         const uint8_t *value, size_t value_len,
                                         uint8_t **script, size_t *script_len);

/**
 * @brief Free StdLib contract instance
 *
 * @param lib StdLib contract to free
 */
void neoc_std_lib_free(neoc_std_lib_t *lib);

#ifdef __cplusplus
}
#endif

#endif /* NEOC_STD_LIB_H_GUARD */
