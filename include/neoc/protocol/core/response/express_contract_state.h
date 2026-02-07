#ifndef NEOC_EXPRESS_CONTRACT_STATE_H
#define NEOC_EXPRESS_CONTRACT_STATE_H

#include <stdbool.h>
#include "neoc/types/hash160.h"

#ifdef __cplusplus
extern "C" {
#endif

// Forward declaration
typedef struct neoc_contract_manifest neoc_contract_manifest_t;

// Express contract state structure
typedef struct neoc_express_contract_state {
    neoc_hash160_t hash;
    neoc_contract_manifest_t* manifest;
} neoc_express_contract_state_t;

// Create express contract state
neoc_express_contract_state_t* neoc_express_contract_state_create(
    const neoc_hash160_t* hash,
    const neoc_contract_manifest_t* manifest
);

// Free express contract state
void neoc_express_contract_state_free(neoc_express_contract_state_t* state);

// Clone express contract state
neoc_express_contract_state_t* neoc_express_contract_state_clone(
    const neoc_express_contract_state_t* state
);

// Compare express contract states
bool neoc_express_contract_state_equals(
    const neoc_express_contract_state_t* a,
    const neoc_express_contract_state_t* b
);

// Parse from JSON
neoc_express_contract_state_t* neoc_express_contract_state_from_json(const char* json_str);

// Convert to JSON
char* neoc_express_contract_state_to_json(const neoc_express_contract_state_t* state);

#ifdef __cplusplus
}
#endif

#endif // NEOC_EXPRESS_CONTRACT_STATE_H
