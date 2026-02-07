#ifndef NEOC_CONTRACT_NEF_H
#define NEOC_CONTRACT_NEF_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "neoc/types/hash256.h"

#ifdef __cplusplus
extern "C" {
#endif

// Contract NEF structure (NEO Executable Format)
// Forward declaration - actual definition in contract_response_types.h
typedef struct neoc_contract_nef neoc_contract_nef_t;

// Note: neoc_contract_nef_create is defined in contract_response_types.h

// Free contract NEF
void neoc_contract_nef_free(neoc_contract_nef_t* nef);

// Dispose contract NEF contents without freeing the struct (for embedded instances).
void neoc_contract_nef_dispose(neoc_contract_nef_t* nef);

// Clone contract NEF
neoc_contract_nef_t* neoc_contract_nef_clone(const neoc_contract_nef_t* nef);

// Compare contract NEFs
bool neoc_contract_nef_equals(
    const neoc_contract_nef_t* a,
    const neoc_contract_nef_t* b
);

// Parse from JSON
neoc_contract_nef_t* neoc_contract_nef_from_json(const char* json_str);

// Convert to JSON
char* neoc_contract_nef_to_json(const neoc_contract_nef_t* nef);

// Serialize to bytes
uint8_t* neoc_contract_nef_serialize(const neoc_contract_nef_t* nef, size_t* out_length);

// Deserialize from bytes
neoc_contract_nef_t* neoc_contract_nef_deserialize(const uint8_t* data, size_t length);

// Calculate checksum
uint32_t neoc_contract_nef_calculate_checksum(const neoc_contract_nef_t* nef);

// Validate NEF
bool neoc_contract_nef_validate(const neoc_contract_nef_t* nef);

#ifdef __cplusplus
}
#endif

#endif // NEOC_CONTRACT_NEF_H
