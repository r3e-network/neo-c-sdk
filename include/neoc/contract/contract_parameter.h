#ifndef NEOC_CONTRACT_PARAMETER_H
#define NEOC_CONTRACT_PARAMETER_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "neoc/neoc_error.h"
#include "neoc/types/contract_parameter_type.h"
#include "neoc/types/neoc_hash160.h"
#include "neoc/types/neoc_hash256.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef neoc_contract_parameter_type_t neoc_contract_param_type_t;

/**
 * @brief Contract parameter value union
 */
typedef union {
    bool boolean_value;
    int64_t integer_value;
    struct {
        uint8_t *data;
        size_t len;
    } byte_array;
    char *string_value;
    neoc_hash160_t hash160;
    neoc_hash256_t hash256;
    struct {
        uint8_t data[33];  // Compressed public key
    } public_key;
    struct {
        uint8_t data[64];  // Signature r + s
    } signature;
    struct {
        struct neoc_contract_parameter_t **items;
        size_t count;
    } array;
    struct {
        struct neoc_contract_parameter_t **keys;
        struct neoc_contract_parameter_t **values;
        size_t count;
    } map;
    void *interop_interface;
} neoc_contract_param_value_t;

/**
 * @brief Contract parameter structure
 */
typedef struct neoc_contract_parameter_t {
    char *name;                          // Optional parameter name
    neoc_contract_param_type_t type;     // Parameter type
    neoc_contract_param_value_t value;   // Parameter value
} neoc_contract_parameter_t;

/**
 * @brief Create a contract parameter with any type
 * 
 * @param value The value
 * @param param Output parameter (caller must free)
 * @return NEOC_SUCCESS on success, error code otherwise
 */
neoc_error_t neoc_contract_param_create_any(void *value,
                                             neoc_contract_parameter_t **param);

/**
 * @brief Create a boolean contract parameter
 * 
 * @param value The boolean value
 * @param param Output parameter (caller must free)
 * @return NEOC_SUCCESS on success, error code otherwise
 */
neoc_error_t neoc_contract_param_create_boolean(bool value,
                                                 neoc_contract_parameter_t **param);

/**
 * @brief Create an integer contract parameter
 * 
 * @param value The integer value
 * @param param Output parameter (caller must free)
 * @return NEOC_SUCCESS on success, error code otherwise
 */
neoc_error_t neoc_contract_param_create_integer(int64_t value,
                                                 neoc_contract_parameter_t **param);

/**
 * @brief Create a byte array contract parameter
 * 
 * @param data The byte array data
 * @param len Length of the data
 * @param param Output parameter (caller must free)
 * @return NEOC_SUCCESS on success, error code otherwise
 */
neoc_error_t neoc_contract_param_create_byte_array(const uint8_t *data, size_t len,
                                                    neoc_contract_parameter_t **param);

/**
 * @brief Create a string contract parameter
 * 
 * @param value The string value
 * @param param Output parameter (caller must free)
 * @return NEOC_SUCCESS on success, error code otherwise
 */
neoc_error_t neoc_contract_param_create_string(const char *value,
                                                neoc_contract_parameter_t **param);

/**
 * @brief Create a Hash160 contract parameter
 * 
 * @param hash The Hash160 value
 * @param param Output parameter (caller must free)
 * @return NEOC_SUCCESS on success, error code otherwise
 */
neoc_error_t neoc_contract_param_create_hash160(const neoc_hash160_t *hash,
                                                 neoc_contract_parameter_t **param);

/**
 * @brief Create a Hash256 contract parameter
 * 
 * @param hash The Hash256 value
 * @param param Output parameter (caller must free)
 * @return NEOC_SUCCESS on success, error code otherwise
 */
neoc_error_t neoc_contract_param_create_hash256(const neoc_hash256_t *hash,
                                                 neoc_contract_parameter_t **param);

/**
 * @brief Create a public key contract parameter
 * 
 * @param public_key The public key (33 bytes compressed)
 * @param param Output parameter (caller must free)
 * @return NEOC_SUCCESS on success, error code otherwise
 */
neoc_error_t neoc_contract_param_create_public_key(const uint8_t public_key[33],
                                                    neoc_contract_parameter_t **param);

/**
 * @brief Create a signature contract parameter
 * 
 * @param signature The signature (64 bytes)
 * @param param Output parameter (caller must free)
 * @return NEOC_SUCCESS on success, error code otherwise
 */
neoc_error_t neoc_contract_param_create_signature(const uint8_t signature[64],
                                                   neoc_contract_parameter_t **param);

/**
 * @brief Create an array contract parameter
 * 
 * @param items Array of contract parameters
 * @param count Number of items
 * @param param Output parameter (caller must free)
 * @return NEOC_SUCCESS on success, error code otherwise
 */
neoc_error_t neoc_contract_param_create_array(neoc_contract_parameter_t **items,
                                               size_t count,
                                               neoc_contract_parameter_t **param);

/**
 * @brief Create a map contract parameter
 * 
 * @param keys Array of key parameters
 * @param values Array of value parameters
 * @param count Number of key-value pairs
 * @param param Output parameter (caller must free)
 * @return NEOC_SUCCESS on success, error code otherwise
 */
neoc_error_t neoc_contract_param_create_map(neoc_contract_parameter_t **keys,
                                             neoc_contract_parameter_t **values,
                                             size_t count,
                                             neoc_contract_parameter_t **param);

/**
 * @brief Set the name of a contract parameter
 * 
 * @param param The parameter
 * @param name The name to set
 * @return NEOC_SUCCESS on success, error code otherwise
 */
neoc_error_t neoc_contract_param_set_name(neoc_contract_parameter_t *param,
                                           const char *name);

/**
 * @brief Get the JSON representation of parameter type
 * 
 * @param type The parameter type
 * @return String representation of the type
 */
const char* neoc_contract_param_type_to_string(neoc_contract_param_type_t type);

/**
 * @brief Serialize contract parameter to bytes
 * 
 * @param param The parameter
 * @param bytes Output bytes (caller must free)
 * @param bytes_len Output length
 * @return NEOC_SUCCESS on success, error code otherwise
 */
neoc_error_t neoc_contract_param_serialize(const neoc_contract_parameter_t *param,
                                            uint8_t **bytes,
                                            size_t *bytes_len);

/**
 * @brief Free a contract parameter
 * 
 * @param param The parameter to free
 */
void neoc_contract_param_free(neoc_contract_parameter_t *param);

#ifdef __cplusplus
}
#endif

#endif // NEOC_CONTRACT_PARAMETER_H
