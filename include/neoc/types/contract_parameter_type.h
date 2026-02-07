/**
 * @file contract_parameter_type.h
 * @brief Contract parameter type definitions
 */

#ifndef NEOC_CONTRACT_PARAMETER_TYPE_H
#define NEOC_CONTRACT_PARAMETER_TYPE_H

#include <stdint.h>
#include <stdbool.h>
#include "neoc/neoc_error.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Contract parameter types
 */
typedef enum neoc_contract_parameter_type {
    NEOC_CONTRACT_PARAM_ANY = 0x00,
    NEOC_CONTRACT_PARAM_BOOLEAN = 0x10,
    NEOC_CONTRACT_PARAM_INTEGER = 0x11,
    NEOC_CONTRACT_PARAM_BYTE_ARRAY = 0x12,
    NEOC_CONTRACT_PARAM_STRING = 0x13,
    NEOC_CONTRACT_PARAM_HASH160 = 0x14,
    NEOC_CONTRACT_PARAM_HASH256 = 0x15,
    NEOC_CONTRACT_PARAM_PUBLIC_KEY = 0x16,
    NEOC_CONTRACT_PARAM_SIGNATURE = 0x17,
    NEOC_CONTRACT_PARAM_ARRAY = 0x20,
    NEOC_CONTRACT_PARAM_MAP = 0x22,
    NEOC_CONTRACT_PARAM_INTEROP_INTERFACE = 0x30,
    NEOC_CONTRACT_PARAM_VOID = 0xff
} neoc_contract_parameter_type_t;

/* Backwards compatibility aliases (old enum constant names) */
#define NEOC_PARAM_TYPE_ANY NEOC_CONTRACT_PARAM_ANY
#define NEOC_PARAM_TYPE_BOOLEAN NEOC_CONTRACT_PARAM_BOOLEAN
#define NEOC_PARAM_TYPE_INTEGER NEOC_CONTRACT_PARAM_INTEGER
#define NEOC_PARAM_TYPE_BYTE_ARRAY NEOC_CONTRACT_PARAM_BYTE_ARRAY
#define NEOC_PARAM_TYPE_STRING NEOC_CONTRACT_PARAM_STRING
#define NEOC_PARAM_TYPE_HASH160 NEOC_CONTRACT_PARAM_HASH160
#define NEOC_PARAM_TYPE_HASH256 NEOC_CONTRACT_PARAM_HASH256
#define NEOC_PARAM_TYPE_PUBLIC_KEY NEOC_CONTRACT_PARAM_PUBLIC_KEY
#define NEOC_PARAM_TYPE_SIGNATURE NEOC_CONTRACT_PARAM_SIGNATURE
#define NEOC_PARAM_TYPE_ARRAY NEOC_CONTRACT_PARAM_ARRAY
#define NEOC_PARAM_TYPE_MAP NEOC_CONTRACT_PARAM_MAP
#define NEOC_PARAM_TYPE_INTEROP_INTERFACE NEOC_CONTRACT_PARAM_INTEROP_INTERFACE
#define NEOC_PARAM_TYPE_VOID NEOC_CONTRACT_PARAM_VOID

#define NEOC_CONTRACT_PARAM_TYPE_ANY NEOC_CONTRACT_PARAM_ANY
#define NEOC_CONTRACT_PARAM_TYPE_BOOLEAN NEOC_CONTRACT_PARAM_BOOLEAN
#define NEOC_CONTRACT_PARAM_TYPE_INTEGER NEOC_CONTRACT_PARAM_INTEGER
#define NEOC_CONTRACT_PARAM_TYPE_BYTE_ARRAY NEOC_CONTRACT_PARAM_BYTE_ARRAY
#define NEOC_CONTRACT_PARAM_TYPE_STRING NEOC_CONTRACT_PARAM_STRING
#define NEOC_CONTRACT_PARAM_TYPE_HASH160 NEOC_CONTRACT_PARAM_HASH160
#define NEOC_CONTRACT_PARAM_TYPE_HASH256 NEOC_CONTRACT_PARAM_HASH256
#define NEOC_CONTRACT_PARAM_TYPE_PUBLIC_KEY NEOC_CONTRACT_PARAM_PUBLIC_KEY
#define NEOC_CONTRACT_PARAM_TYPE_SIGNATURE NEOC_CONTRACT_PARAM_SIGNATURE
#define NEOC_CONTRACT_PARAM_TYPE_ARRAY NEOC_CONTRACT_PARAM_ARRAY
#define NEOC_CONTRACT_PARAM_TYPE_MAP NEOC_CONTRACT_PARAM_MAP
#define NEOC_CONTRACT_PARAM_TYPE_INTEROP_INTERFACE NEOC_CONTRACT_PARAM_INTEROP_INTERFACE
#define NEOC_CONTRACT_PARAM_TYPE_VOID NEOC_CONTRACT_PARAM_VOID

/**
 * Get string representation of parameter type
 */
const char* neoc_contract_parameter_type_to_string(neoc_contract_parameter_type_t type);

/**
 * Parse parameter type from string
 */
neoc_error_t neoc_contract_parameter_type_from_string(const char *str,
                                                       neoc_contract_parameter_type_t *type);

/**
 * Check if type is valid
 */
bool neoc_contract_parameter_type_is_valid(neoc_contract_parameter_type_t type);

/**
 * Get byte value of parameter type
 */
uint8_t neoc_contract_parameter_type_to_byte(neoc_contract_parameter_type_t type);

/**
 * Parse parameter type from byte
 */
neoc_error_t neoc_contract_parameter_type_from_byte(uint8_t byte,
                                                     neoc_contract_parameter_type_t *type);

#ifdef __cplusplus
}
#endif

#endif // NEOC_CONTRACT_PARAMETER_TYPE_H
