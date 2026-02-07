#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "../../../include/neoc/protocol/response/express_contract_state.h"
#include "../../../include/neoc/protocol/contract_response_types.h"
#include "../../../include/neoc/contract/contract_manifest.h"
#include "../../../include/neoc/neoc_memory.h"
#include "../../../include/neoc/utils/json.h"

// Create express contract state
neoc_express_contract_state_t* neoc_express_contract_state_create(
    const neoc_hash160_t* hash,
    const neoc_contract_manifest_t* manifest) {
    
    if (!hash || !manifest) {
        return NULL;
    }
    
    neoc_express_contract_state_t* state = neoc_malloc(sizeof(neoc_express_contract_state_t));
    if (!state) {
        return NULL;
    }
    
    // Copy hash
    memcpy(&state->hash, hash, sizeof(neoc_hash160_t));
    
    // Deep copy manifest using the proper clone function
    state->manifest = neoc_contract_manifest_clone(manifest);
    if (!state->manifest) {
        neoc_free(state);
        return NULL;
    }
    
    return state;
}

// Free express contract state
void neoc_express_contract_state_free(neoc_express_contract_state_t* state) {
    if (!state) {
        return;
    }
    
    if (state->manifest) {
        neoc_contract_manifest_free(state->manifest);
    }
    
    neoc_free(state);
}

// Clone express contract state
neoc_express_contract_state_t* neoc_express_contract_state_clone(
    const neoc_express_contract_state_t* state) {
    
    if (!state) {
        return NULL;
    }
    
    return neoc_express_contract_state_create(&state->hash, state->manifest);
}

// Compare express contract states
bool neoc_express_contract_state_equals(
    const neoc_express_contract_state_t* a,
    const neoc_express_contract_state_t* b) {
    
    if (!a && !b) return true;
    if (!a || !b) return false;
    
    // Compare hashes
    if (memcmp(&a->hash, &b->hash, sizeof(neoc_hash160_t)) != 0) {
        return false;
    }
    
    // Compare manifests
    bool equal = false;
    neoc_error_t err = neoc_contract_manifest_equals(a->manifest, b->manifest, &equal);
    if (err != NEOC_SUCCESS) {
        return false;
    }
    return equal;
}

// Parse from JSON
neoc_express_contract_state_t* neoc_express_contract_state_from_json(const char* json_str) {
    if (!json_str) {
        return NULL;
    }
    
    // Parse JSON
    neoc_json_t* json = neoc_json_parse(json_str);
    if (!json) {
        return NULL;
    }
    
    neoc_express_contract_state_t* state = NULL;
    
    // Get hash
    const char* hash_str = neoc_json_get_string(json, "hash");
    if (!hash_str) {
        neoc_json_free(json);
        return NULL;
    }
    
    neoc_hash160_t hash;
    if (neoc_hash160_from_string(hash_str, &hash) != NEOC_SUCCESS) {
        neoc_json_free(json);
        return NULL;
    }
    
    // Parse manifest from JSON
    neoc_contract_manifest_t manifest = {0};
    neoc_json_t *manifest_json = neoc_json_get_object(json, "manifest");
    if (manifest_json) {
        // Parse manifest fields
        const char *name = neoc_json_get_string(manifest_json, "name");
        if (name) {
            manifest.name = neoc_strdup(name);
        }
        
        // Parse ABI
        neoc_json_t *abi_json = neoc_json_get_object(manifest_json, "abi");
        if (abi_json) {
            // Parse methods array
            neoc_json_t *methods = neoc_json_get_array(abi_json, "methods");
            if (methods) {
                manifest.abi.method_count = neoc_json_array_size(methods);
                if (manifest.abi.method_count > 0) {
                    manifest.abi.methods = neoc_calloc(manifest.abi.method_count, sizeof(neoc_contract_method_t));
                    for (size_t i = 0; i < manifest.abi.method_count; i++) {
                        neoc_json_t *method = neoc_json_array_get(methods, i);
                        if (method) {
                            const char *method_name = neoc_json_get_string(method, "name");
                            if (method_name) {
                                manifest.abi.methods[i].name = neoc_strdup(method_name);
                            }
                        }
                    }
                }
            }
            
            // Parse events array
            neoc_json_t *events = neoc_json_get_array(abi_json, "events");
            if (events) {
                manifest.abi.event_count = neoc_json_array_size(events);
                if (manifest.abi.event_count > 0) {
                    manifest.abi.events = neoc_calloc(manifest.abi.event_count, sizeof(neoc_contract_event_t));
                    for (size_t i = 0; i < manifest.abi.event_count; i++) {
                        neoc_json_t *event = neoc_json_array_get(events, i);
                        if (event) {
                            const char *event_name = neoc_json_get_string(event, "name");
                            if (event_name) {
                                manifest.abi.events[i].name = neoc_strdup(event_name);
                            }
                        }
                    }
                }
            }
        }
        
        // Parse supported standards
        neoc_json_t *standards = neoc_json_get_array(manifest_json, "supportedstandards");
        if (standards) {
            manifest.supported_standards_count = neoc_json_array_size(standards);
            if (manifest.supported_standards_count > 0) {
                manifest.supported_standards = neoc_calloc(manifest.supported_standards_count, sizeof(char*));
                for (size_t i = 0; i < manifest.supported_standards_count; i++) {
                    neoc_json_t *value = neoc_json_array_get(standards, i);
                    const char *standard = value ? neoc_json_get_string(value, NULL) : NULL;
                    if (standard) {
                        manifest.supported_standards[i] = neoc_strdup(standard);
                    }
                }
            }
        }
    }
    
    state = neoc_express_contract_state_create(&hash, &manifest);
    
    neoc_json_free(json);
    return state;
}

// Convert to JSON
char* neoc_express_contract_state_to_json(const neoc_express_contract_state_t* state) {
    if (!state) {
        return NULL;
    }
    
    // Create JSON string
    char hash_str[41];
    neoc_hash160_to_string(&state->hash, hash_str, sizeof(hash_str));
    
    char* manifest_json = NULL;
    size_t manifest_json_len = 0;
    neoc_error_t err = neoc_contract_manifest_to_json(state->manifest, &manifest_json, &manifest_json_len);
    if (err != NEOC_SUCCESS || !manifest_json) {
        return NULL;
    }
    
    // Calculate required buffer size
    size_t json_size = strlen("{\"hash\":\"\",\"manifest\":}") + 
                       strlen(hash_str) + 
                       strlen(manifest_json) + 1;
    
    char* json = neoc_malloc(json_size);
    if (!json) {
        neoc_free(manifest_json);
        return NULL;
    }
    
    snprintf(json, json_size, "{\"hash\":\"%s\",\"manifest\":%s}", 
             hash_str, manifest_json);
    
    neoc_free(manifest_json);
    return json;
}
