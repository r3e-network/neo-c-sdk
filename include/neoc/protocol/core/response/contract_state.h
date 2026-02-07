#ifndef NEOC_CONTRACT_STATE_H
#define NEOC_CONTRACT_STATE_H

#include <stdbool.h>
#include "express_contract_state.h"
#include "contract_nef.h"
#include "neoc/protocol/stack_item.h"

#ifdef __cplusplus
extern "C" {
#endif

// Contract state structure (inherits from express_contract_state)
// Forward declaration - actual definition in contract_response_types.h
typedef struct neoc_contract_state neoc_contract_state_t;

// Contract identifiers structure
typedef struct neoc_contract_identifiers {
    int id;
    neoc_hash160_t hash;
} neoc_contract_identifiers_t;

// Note: neoc_contract_state_create is defined in contract_response_types.h

// Free contract state
void neoc_contract_state_free(neoc_contract_state_t* state);

// Clone contract state
neoc_contract_state_t* neoc_contract_state_clone(const neoc_contract_state_t* state);

// Note: neoc_contract_state_equals is defined in contract_response_types.h

// Parse from JSON
neoc_contract_state_t* neoc_contract_state_from_json(const char* json_str);

// Convert to JSON
char* neoc_contract_state_to_json(const neoc_contract_state_t* state);

// Contract identifiers functions
neoc_contract_identifiers_t* neoc_contract_identifiers_from_stack_item(
    const neoc_stack_item_t* stack_item
);

void neoc_contract_identifiers_free(neoc_contract_identifiers_t* identifiers);

bool neoc_contract_identifiers_equals(
    const neoc_contract_identifiers_t* a,
    const neoc_contract_identifiers_t* b
);

#ifdef __cplusplus
}
#endif

#endif // NEOC_CONTRACT_STATE_H
